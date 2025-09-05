// SPDX-License-Identifier: GPL-2.0+
/*
 * PCI Express Hot Plug Controller Driver
 *
 * Copyright (C) 1995,2001 Compaq Computer Corporation
 * Copyright (C) 2001 Greg Kroah-Hartman (greg@kroah.com)
 * Copyright (C) 2001 IBM Corp.
 * Copyright (C) 2003-2004 Intel Corporation
 *
 * All rights reserved.
 *
 * Send feedback to <greg@kroah.com>, <kristen.c.accardi@intel.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/smp_lock.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>
#include <linux/pci.h>
#include "../pci.h"
#include "pciehp.h"

static void interrupt_event_handler(struct work_struct *work);

static int queue_interrupt_event(struct slot *p_slot, u32 event_type)
void pciehp_queue_interrupt_event(struct slot *p_slot, u32 event_type)
{
	struct event_info *info;

	info = kmalloc(sizeof(*info), GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	info->event_type = event_type;
	info->p_slot = p_slot;
	INIT_WORK(&info->work, interrupt_event_handler);

	schedule_work(&info->work);

	return 0;
}

u8 pciehp_handle_attention_button(struct slot *p_slot)
{
	u32 event_type;

	/* Attention Button Change */
	dbg("pciehp:  Attention button interrupt received.\n");

	/*
	 *  Button pressed - See if need to TAKE ACTION!!!
	 */
	info("Button pressed on Slot(%s)\n", p_slot->name);
	event_type = INT_BUTTON_PRESS;

	queue_interrupt_event(p_slot, event_type);

	return 0;
}

u8 pciehp_handle_switch_change(struct slot *p_slot)
{
	u8 getstatus;
	u32 event_type;

	/* Switch Change */
	dbg("pciehp:  Switch interrupt received.\n");

	p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	if (getstatus) {
		/*
		 * Switch opened
		 */
		info("Latch open on Slot(%s)\n", p_slot->name);
		event_type = INT_SWITCH_OPEN;
	} else {
		/*
		 *  Switch closed
		 */
		info("Latch close on Slot(%s)\n", p_slot->name);
		event_type = INT_SWITCH_CLOSE;
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
}

u8 pciehp_handle_presence_change(struct slot *p_slot)
{
	u32 event_type;
	u8 presence_save;

	/* Presence Change */
	dbg("pciehp:  Presence/Notify input change.\n");

	/* Switch is open, assume a presence change
	 * Save the presence state
	 */
	p_slot->hpc_ops->get_adapter_status(p_slot, &presence_save);
	if (presence_save) {
		/*
		 * Card Present
		 */
		info("Card present on Slot(%s)\n", p_slot->name);
		event_type = INT_PRESENCE_ON;
	} else {
		/*
		 * Not Present
		 */
		info("Card not present on Slot(%s)\n", p_slot->name);
		event_type = INT_PRESENCE_OFF;
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
}

u8 pciehp_handle_power_fault(struct slot *p_slot)
{
	u32 event_type;

	/* power fault */
	dbg("pciehp:  Power fault interrupt received.\n");

	if ( !(p_slot->hpc_ops->query_power_fault(p_slot))) {
		/*
		 * power fault Cleared
		 */
		info("Power fault cleared on Slot(%s)\n", p_slot->name);
		event_type = INT_POWER_FAULT_CLEAR;
	} else {
		/*
		 *   power fault
		 */
		info("Power fault on Slot(%s)\n", p_slot->name);
		event_type = INT_POWER_FAULT;
		info("power fault bit %x set\n", 0);
	}

	queue_interrupt_event(p_slot, event_type);

	return 1;
	if (!info) {
		ctrl_err(p_slot->ctrl, "dropped event %d (ENOMEM)\n", event_type);
		return;
	}

	INIT_WORK(&info->work, interrupt_event_handler);
	info->event_type = event_type;
	info->p_slot = p_slot;
	queue_work(p_slot->wq, &info->work);
}

/* The following routines constitute the bulk of the
   hotplug controller logic
 */

static void set_slot_off(struct controller *ctrl, struct slot * pslot)
{
	/* turn off slot, turn on Amber LED, turn off Green LED if supported*/
	if (POWER_CTRL(ctrl)) {
		if (pslot->hpc_ops->power_off_slot(pslot)) {
			err("%s: Issue of Slot Power Off command failed\n",
			    __func__);
			return;
		}
	}

	/*
	 * After turning power off, we must wait for at least 1 second
	 * before taking any action that relies on power having been
	 * removed from the slot/adapter.
	 */
	msleep(1000);

	if (PWR_LED(ctrl))
		pslot->hpc_ops->green_led_off(pslot);

	if (ATTN_LED(ctrl)) {
		if (pslot->hpc_ops->set_attention_status(pslot, 1)) {
			err("%s: Issue of Set Attention Led command failed\n",
			    __func__);
			return;
		}
	}
static void set_slot_off(struct controller *ctrl, struct slot *pslot)
{
	/* turn off slot, turn on Amber LED, turn off Green LED if supported*/
	if (POWER_CTRL(ctrl)) {
		pciehp_power_off_slot(pslot);

		/*
		 * After turning power off, we must wait for at least 1 second
		 * before taking any action that relies on power having been
		 * removed from the slot/adapter.
		 */
		msleep(1000);
	}

	pciehp_green_led_off(pslot);
	pciehp_set_attention_status(pslot, 1);
}

/**
 * board_added - Called after a board has been added to the system.
 * @p_slot: &slot where board is added
 *
 * Turns power on for the board.
 * Configures board.
 */
static int board_added(struct slot *p_slot)
{
	int retval = 0;
	struct controller *ctrl = p_slot->ctrl;

	dbg("%s: slot device, slot offset, hp slot = %d, %d ,%d\n",
			__func__, p_slot->device,
			ctrl->slot_device_offset, p_slot->hp_slot);

	if (POWER_CTRL(ctrl)) {
		/* Power on slot */
		retval = p_slot->hpc_ops->power_on_slot(p_slot);
	struct pci_bus *parent = ctrl->pcie->port->subordinate;

	if (POWER_CTRL(ctrl)) {
		/* Power on slot */
		retval = pciehp_power_on_slot(p_slot);
		if (retval)
			return retval;
	}

	if (PWR_LED(ctrl))
		p_slot->hpc_ops->green_led_blink(p_slot);

	/* Wait for ~1 second */
	msleep(1000);

	/* Check link training status */
	retval = p_slot->hpc_ops->check_lnk_status(ctrl);
	if (retval) {
		err("%s: Failed to check link status\n", __func__);
		set_slot_off(ctrl, p_slot);
		return retval;
	}

	/* Check for a power fault */
	if (p_slot->hpc_ops->query_power_fault(p_slot)) {
		dbg("%s: power fault detected\n", __func__);
		retval = POWER_FAILURE;
	pciehp_green_led_blink(p_slot);

	/* Check link training status */
	retval = pciehp_check_link_status(ctrl);
	if (retval) {
		ctrl_err(ctrl, "Failed to check link status\n");
		goto err_exit;
	}

	/* Check for a power fault */
	if (ctrl->power_fault_detected || pciehp_query_power_fault(p_slot)) {
		ctrl_err(ctrl, "Slot(%s): Power fault\n", slot_name(p_slot));
		retval = -EIO;
		goto err_exit;
	}

	retval = pciehp_configure_device(p_slot);
	if (retval) {
		err("Cannot add device 0x%x:%x\n", p_slot->bus,
		    p_slot->device);
		goto err_exit;
	}

	/*
	 * Some PCI Express root ports require fixup after hot-plug operation.
	 */
	if (pcie_mch_quirk)
		pci_fixup_device(pci_fixup_final, ctrl->pci_dev);
	if (PWR_LED(ctrl))
  		p_slot->hpc_ops->green_led_on(p_slot);

		ctrl_err(ctrl, "Cannot add device at %04x:%02x:00\n",
			 pci_domain_nr(parent), parent->number);
		if (retval != -EEXIST)
		if (retval != -EEXIST) {
			ctrl_err(ctrl, "Cannot add device at %04x:%02x:00\n",
				 pci_domain_nr(parent), parent->number);
			goto err_exit;
		}
	}

	pciehp_green_led_on(p_slot);
	pciehp_set_attention_status(p_slot, 0);
	return 0;

err_exit:
	set_slot_off(ctrl, p_slot);
	return retval;
}

/**
 * remove_board - Turns off slot and LEDs
 * @p_slot: slot where board is being removed
 */
static void remove_board(struct slot *p_slot)
{
	int retval = 0;
	int retval;
	struct controller *ctrl = p_slot->ctrl;

	pciehp_unconfigure_device(p_slot);

	dbg("In %s, hp_slot = %d\n", __func__, p_slot->hp_slot);

	if (POWER_CTRL(ctrl)) {
		/* power off slot */
		retval = p_slot->hpc_ops->power_off_slot(p_slot);
		if (retval) {
			err("%s: Issue of Slot Disable command failed\n",
			    __func__);
			return retval;
		}
	}

	/*
	 * After turning power off, we must wait for at least 1 second
	 * before taking any action that relies on power having been
	 * removed from the slot/adapter.
	 */
	msleep(1000);

	if (PWR_LED(ctrl))
		/* turn off Green LED */
		p_slot->hpc_ops->green_led_off(p_slot);

	if (POWER_CTRL(ctrl)) {
		pciehp_power_off_slot(p_slot);

		/*
		 * After turning power off, we must wait for at least 1 second
		 * before taking any action that relies on power having been
		 * removed from the slot/adapter.
		 */
		msleep(1000);
	}

	/* turn off Green LED */
	pciehp_green_led_off(p_slot);
}

static int pciehp_enable_slot(struct slot *slot);
static int pciehp_disable_slot(struct slot *slot);

void pciehp_request(struct controller *ctrl, int action)
{
	struct power_work_info *info =
		container_of(work, struct power_work_info, work);
	struct slot *p_slot = info->p_slot;

	mutex_lock(&p_slot->lock);
	switch (p_slot->state) {
	case POWEROFF_STATE:
		mutex_unlock(&p_slot->lock);
		dbg("%s: disabling bus:device(%x:%x)\n",
		    __func__, p_slot->bus, p_slot->device);
		pciehp_disable_slot(p_slot);
		mutex_lock(&p_slot->lock);
		p_slot->state = STATIC_STATE;
		break;
	case POWERON_STATE:
		mutex_unlock(&p_slot->lock);
		if (pciehp_enable_slot(p_slot) &&
		    PWR_LED(p_slot->ctrl))
			p_slot->hpc_ops->green_led_off(p_slot);
		mutex_lock(&p_slot->lock);
		p_slot->state = STATIC_STATE;
	int ret;

	switch (info->req) {
	case DISABLE_REQ:
		mutex_lock(&p_slot->hotplug_lock);
		pciehp_disable_slot(p_slot);
		mutex_unlock(&p_slot->hotplug_lock);
		mutex_lock(&p_slot->lock);
		p_slot->state = STATIC_STATE;
		mutex_unlock(&p_slot->lock);
		break;
	case ENABLE_REQ:
		mutex_lock(&p_slot->hotplug_lock);
		ret = pciehp_enable_slot(p_slot);
		mutex_unlock(&p_slot->hotplug_lock);
		if (ret)
			pciehp_green_led_off(p_slot);
		mutex_lock(&p_slot->lock);
		p_slot->state = STATIC_STATE;
		mutex_unlock(&p_slot->lock);
		break;
	default:
		break;
	}
	mutex_unlock(&p_slot->lock);

	kfree(info);
}

void pciehp_queue_pushbutton_work(struct work_struct *work)
{
	struct slot *p_slot = container_of(work, struct slot, work.work);
	struct power_work_info *info;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err("%s: Cannot allocate memory\n", __func__);
		return;
	}
	info->p_slot = p_slot;
	INIT_WORK(&info->work, pciehp_power_thread);
static void pciehp_queue_power_work(struct slot *p_slot, int req)
{
	struct power_work_info *info;

	p_slot->state = (req == ENABLE_REQ) ? POWERON_STATE : POWEROFF_STATE;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ctrl_err(p_slot->ctrl, "no memory to queue %s request\n",
			 (req == ENABLE_REQ) ? "poweron" : "poweroff");
		return;
	}
	info->p_slot = p_slot;
	INIT_WORK(&info->work, pciehp_power_thread);
	info->req = req;
	queue_work(p_slot->wq, &info->work);
	atomic_or(action, &ctrl->pending_events);
	if (!pciehp_poll_mode)
		irq_wake_thread(ctrl->pcie->irq, ctrl);
}

void pciehp_queue_pushbutton_work(struct work_struct *work)
{
	struct slot *p_slot = container_of(work, struct slot, work.work);
	struct controller *ctrl = p_slot->ctrl;

	mutex_lock(&p_slot->lock);
	switch (p_slot->state) {
	case BLINKINGOFF_STATE:
		p_slot->state = POWEROFF_STATE;
		break;
	case BLINKINGON_STATE:
		p_slot->state = POWERON_STATE;
		break;
	default:
		goto out;
	}
	queue_work(pciehp_wq, &info->work);
 out:
	mutex_unlock(&p_slot->lock);
}

static int update_slot_info(struct slot *slot)
{
	struct hotplug_slot_info *info;
	int result;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	slot->hpc_ops->get_power_status(slot, &(info->power_status));
	slot->hpc_ops->get_attention_status(slot, &(info->attention_status));
	slot->hpc_ops->get_latch_status(slot, &(info->latch_status));
	slot->hpc_ops->get_adapter_status(slot, &(info->adapter_status));

	result = pci_hp_change_slot_info(slot->hotplug_slot, info);
	kfree (info);
	return result;
}

		pciehp_queue_power_work(p_slot, DISABLE_REQ);
		pciehp_request(ctrl, DISABLE_SLOT);
		break;
	case BLINKINGON_STATE:
		pciehp_request(ctrl, PCI_EXP_SLTSTA_PDC);
		break;
	default:
		break;
	}
	mutex_unlock(&p_slot->lock);
}

void pciehp_handle_button_press(struct slot *p_slot)
{
	struct controller *ctrl = p_slot->ctrl;

	mutex_lock(&p_slot->lock);
	switch (p_slot->state) {
	case STATIC_STATE:
		p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
		if (getstatus) {
			p_slot->state = BLINKINGOFF_STATE;
			info("PCI slot #%s - powering off due to button "
			     "press.\n", p_slot->name);
		} else {
			p_slot->state = BLINKINGON_STATE;
			info("PCI slot #%s - powering on due to button "
			     "press.\n", p_slot->name);
		}
		/* blink green LED and turn off amber */
		if (PWR_LED(ctrl))
			p_slot->hpc_ops->green_led_blink(p_slot);
		if (ATTN_LED(ctrl))
			p_slot->hpc_ops->set_attention_status(p_slot, 0);

		schedule_delayed_work(&p_slot->work, 5*HZ);
		pciehp_get_power_status(p_slot, &getstatus);
		if (getstatus) {
	case OFF_STATE:
	case ON_STATE:
		if (p_slot->state == ON_STATE) {
			p_slot->state = BLINKINGOFF_STATE;
			ctrl_info(ctrl, "Slot(%s): Powering off due to button press\n",
				  slot_name(p_slot));
		} else {
			p_slot->state = BLINKINGON_STATE;
			ctrl_info(ctrl, "Slot(%s) Powering on due to button press\n",
				  slot_name(p_slot));
		}
		/* blink green LED and turn off amber */
		pciehp_green_led_blink(p_slot);
		pciehp_set_attention_status(p_slot, 0);
		schedule_delayed_work(&p_slot->work, 5 * HZ);
		break;
	case BLINKINGOFF_STATE:
	case BLINKINGON_STATE:
		/*
		 * Cancel if we are still blinking; this means that we
		 * press the attention again before the 5 sec. limit
		 * expires to cancel hot-add or hot-remove
		 */
		info("Button cancel on Slot(%s)\n", p_slot->name);
		dbg("%s: button cancel\n", __func__);
		cancel_delayed_work(&p_slot->work);
		if (p_slot->state == BLINKINGOFF_STATE) {
			if (PWR_LED(ctrl))
				p_slot->hpc_ops->green_led_on(p_slot);
		} else {
			if (PWR_LED(ctrl))
				p_slot->hpc_ops->green_led_off(p_slot);
		}
		if (ATTN_LED(ctrl))
			p_slot->hpc_ops->set_attention_status(p_slot, 0);
		info("PCI slot #%s - action canceled due to button press\n",
		     p_slot->name);
		ctrl_info(ctrl, "Button cancel on Slot(%s)\n", slot_name(p_slot));
		ctrl_info(ctrl, "Slot(%s): Button cancel\n", slot_name(p_slot));
		cancel_delayed_work(&p_slot->work);
		if (p_slot->state == BLINKINGOFF_STATE) {
			p_slot->state = ON_STATE;
			pciehp_green_led_on(p_slot);
		} else {
			p_slot->state = OFF_STATE;
			pciehp_green_led_off(p_slot);
		}
		pciehp_set_attention_status(p_slot, 0);
		ctrl_info(ctrl, "Slot(%s): Action canceled due to button press\n",
			  slot_name(p_slot));
		p_slot->state = STATIC_STATE;
		break;
	case POWEROFF_STATE:
	case POWERON_STATE:
		/*
		 * Ignore if the slot is on power-on or power-off state;
		 * this means that the previous attention button action
		 * to hot-add or hot-remove is undergoing
		 */
		info("Button ignore on Slot(%s)\n", p_slot->name);
		update_slot_info(p_slot);
		break;
	default:
		warn("Not a valid state\n");
		ctrl_info(ctrl, "Button ignore on Slot(%s)\n", slot_name(p_slot));
		ctrl_info(ctrl, "Slot(%s): Button ignored\n",
			  slot_name(p_slot));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Ignoring invalid state %#x\n",
			 slot_name(p_slot), p_slot->state);
		break;
	}
}

/*
 * Note: This function must be called with slot->lock held
 */
static void handle_surprise_event(struct slot *p_slot)
{
	u8 getstatus;
	struct power_work_info *info;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err("%s: Cannot allocate memory\n", __func__);
		return;
	}
	info->p_slot = p_slot;
	INIT_WORK(&info->work, pciehp_power_thread);

	p_slot->hpc_ops->get_adapter_status(p_slot, &getstatus);
	if (!getstatus)
		p_slot->state = POWEROFF_STATE;
	else
		p_slot->state = POWERON_STATE;

	queue_work(pciehp_wq, &info->work);

	pciehp_get_adapter_status(p_slot, &getstatus);
	if (!getstatus)
		pciehp_queue_power_work(p_slot, DISABLE_REQ);
	else
		pciehp_queue_power_work(p_slot, ENABLE_REQ);
}

/*
 * Note: This function must be called with slot->lock held
 */
static void handle_link_event(struct slot *p_slot, u32 event)
{
	struct controller *ctrl = p_slot->ctrl;

	switch (p_slot->state) {
	case BLINKINGON_STATE:
	case BLINKINGOFF_STATE:
		cancel_delayed_work(&p_slot->work);
		/* Fall through */
	case STATIC_STATE:
		pciehp_queue_power_work(p_slot, event == INT_LINK_UP ?
					ENABLE_REQ : DISABLE_REQ);
		break;
	case POWERON_STATE:
		if (event == INT_LINK_UP) {
			ctrl_info(ctrl, "Slot(%s): Link Up event ignored; already powering on\n",
				  slot_name(p_slot));
		} else {
			ctrl_info(ctrl, "Slot(%s): Link Down event queued; currently getting powered on\n",
				  slot_name(p_slot));
			pciehp_queue_power_work(p_slot, DISABLE_REQ);
		}
		break;
	case POWEROFF_STATE:
		if (event == INT_LINK_UP) {
			ctrl_info(ctrl, "Slot(%s): Link Up event queued; currently getting powered off\n",
				  slot_name(p_slot));
			pciehp_queue_power_work(p_slot, ENABLE_REQ);
		} else {
			ctrl_info(ctrl, "Slot(%s): Link Down event ignored; already powering off\n",
				  slot_name(p_slot));
		}
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Ignoring invalid state %#x\n",
			 slot_name(p_slot), p_slot->state);
		break;
	}
}

static void interrupt_event_handler(struct work_struct *work)
{
	struct event_info *info = container_of(work, struct event_info, work);
	struct slot *p_slot = info->p_slot;
	struct controller *ctrl = p_slot->ctrl;

	mutex_lock(&p_slot->lock);
	switch (info->event_type) {
	case INT_BUTTON_PRESS:
		handle_button_press_event(p_slot);
		break;
	case INT_POWER_FAULT:
		if (!POWER_CTRL(ctrl))
			break;
		if (ATTN_LED(ctrl))
			p_slot->hpc_ops->set_attention_status(p_slot, 1);
		if (PWR_LED(ctrl))
			p_slot->hpc_ops->green_led_off(p_slot);
		break;
	case INT_PRESENCE_ON:
	case INT_PRESENCE_OFF:
		if (!HP_SUPR_RM(ctrl))
			break;
		dbg("Surprise Removal\n");
		update_slot_info(p_slot);
		handle_surprise_event(p_slot);
		break;
	default:
		update_slot_info(p_slot);
		pciehp_set_attention_status(p_slot, 1);
		pciehp_green_led_off(p_slot);
		break;
	case INT_PRESENCE_ON:
		pciehp_queue_power_work(p_slot, ENABLE_REQ);
		break;
	case INT_PRESENCE_OFF:
		/*
		 * Regardless of surprise capability, we need to
		 * definitely remove a card that has been pulled out!
		 */
		pciehp_queue_power_work(p_slot, DISABLE_REQ);
		break;
	case INT_LINK_UP:
	case INT_LINK_DOWN:
		handle_link_event(p_slot, info->event_type);
		break;
	default:
		break;
	}
	mutex_unlock(&p_slot->lock);
}

void pciehp_handle_disable_request(struct slot *slot)
{
	struct controller *ctrl = slot->ctrl;

	mutex_lock(&slot->lock);
	switch (slot->state) {
	case BLINKINGON_STATE:
	case BLINKINGOFF_STATE:
		cancel_delayed_work(&slot->work);
		break;
	}
	slot->state = POWEROFF_STATE;
	mutex_unlock(&slot->lock);

	ctrl->request_result = pciehp_disable_slot(slot);
}

void pciehp_handle_presence_or_link_change(struct slot *slot, u32 events)
{
	struct controller *ctrl = slot->ctrl;
	bool link_active;
	u8 present;

	/*
	 * If the slot is on and presence or link has changed, turn it off.
	 * Even if it's occupied again, we cannot assume the card is the same.
	 */
	mutex_lock(&slot->lock);
	switch (slot->state) {
	case BLINKINGOFF_STATE:
		cancel_delayed_work(&slot->work);
		/* fall through */
	case ON_STATE:
		slot->state = POWEROFF_STATE;
		mutex_unlock(&slot->lock);
		if (events & PCI_EXP_SLTSTA_DLLSC)
			ctrl_info(ctrl, "Slot(%s): Link Down\n",
				  slot_name(slot));
		if (events & PCI_EXP_SLTSTA_PDC)
			ctrl_info(ctrl, "Slot(%s): Card not present\n",
				  slot_name(slot));
		pciehp_disable_slot(slot);
		break;
	default:
		mutex_unlock(&slot->lock);
		break;
	}

	/* Turn the slot on if it's occupied or link is up */
	mutex_lock(&slot->lock);
	pciehp_get_adapter_status(slot, &present);
	link_active = pciehp_check_link_active(ctrl);
	if (!present && !link_active) {
		mutex_unlock(&slot->lock);
		return;
	}

	switch (slot->state) {
	case BLINKINGON_STATE:
		cancel_delayed_work(&slot->work);
		/* fall through */
	case OFF_STATE:
		slot->state = POWERON_STATE;
		mutex_unlock(&slot->lock);
		if (present)
			ctrl_info(ctrl, "Slot(%s): Card present\n",
				  slot_name(slot));
		if (link_active)
			ctrl_info(ctrl, "Slot(%s): Link Up\n",
				  slot_name(slot));
		ctrl->request_result = pciehp_enable_slot(slot);
		break;
	default:
		mutex_unlock(&slot->lock);
		break;
	}
}

static int __pciehp_enable_slot(struct slot *p_slot)
{
	u8 getstatus = 0;
	int rc;

	/* Check to see if (latch closed, card present, power off) */
	mutex_lock(&p_slot->ctrl->crit_sect);

	rc = p_slot->hpc_ops->get_adapter_status(p_slot, &getstatus);
	if (rc || !getstatus) {
		info("%s: no adapter on slot(%s)\n", __func__,
		     p_slot->name);
		mutex_unlock(&p_slot->ctrl->crit_sect);
		return -ENODEV;
	}
	if (MRL_SENS(p_slot->ctrl)) {
		rc = p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
		if (rc || getstatus) {
			info("%s: latch open on slot(%s)\n", __func__,
			     p_slot->name);
			mutex_unlock(&p_slot->ctrl->crit_sect);
	struct controller *ctrl = p_slot->ctrl;

	pciehp_get_adapter_status(p_slot, &getstatus);
	if (!getstatus) {
		ctrl_info(ctrl, "Slot(%s): No adapter\n", slot_name(p_slot));
		return -ENODEV;
	}
	if (MRL_SENS(p_slot->ctrl)) {
		pciehp_get_latch_status(p_slot, &getstatus);
		if (getstatus) {
			ctrl_info(ctrl, "Slot(%s): Latch open\n",
				  slot_name(p_slot));
			return -ENODEV;
		}
	}

	if (POWER_CTRL(p_slot->ctrl)) {
		rc = p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
		if (rc || getstatus) {
			info("%s: already enabled on slot(%s)\n", __func__,
			     p_slot->name);
			mutex_unlock(&p_slot->ctrl->crit_sect);
		pciehp_get_power_status(p_slot, &getstatus);
		if (getstatus) {
			ctrl_info(ctrl, "Slot(%s): Already enabled\n",
				  slot_name(p_slot));
			return 0;
		}
	}

	p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);

	rc = board_added(p_slot);
	if (rc) {
		p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
	}

	update_slot_info(p_slot);

	mutex_unlock(&p_slot->ctrl->crit_sect);
	return rc;
}


int pciehp_disable_slot(struct slot *p_slot)
{
	u8 getstatus = 0;
	int ret = 0;
	pciehp_get_latch_status(p_slot, &getstatus);

	rc = board_added(p_slot);
	if (rc)
		pciehp_get_latch_status(p_slot, &getstatus);

	return rc;
	return board_added(p_slot);
}

static int pciehp_enable_slot(struct slot *slot)
{
	struct controller *ctrl = slot->ctrl;
	int ret;

	pm_runtime_get_sync(&ctrl->pcie->port->dev);
	ret = __pciehp_enable_slot(slot);
	if (ret && ATTN_BUTTN(ctrl))
		pciehp_green_led_off(slot); /* may be blinking */
	pm_runtime_put(&ctrl->pcie->port->dev);

	mutex_lock(&slot->lock);
	slot->state = ret ? OFF_STATE : ON_STATE;
	mutex_unlock(&slot->lock);

	return ret;
}

static int __pciehp_disable_slot(struct slot *p_slot)
{
	u8 getstatus = 0;
	struct controller *ctrl = p_slot->ctrl;

	if (!p_slot->ctrl)
		return 1;

	/* Check to see if (latch closed, card present, power on) */
	mutex_lock(&p_slot->ctrl->crit_sect);

	if (!HP_SUPR_RM(p_slot->ctrl)) {
		ret = p_slot->hpc_ops->get_adapter_status(p_slot, &getstatus);
		if (ret || !getstatus) {
			info("%s: no adapter on slot(%s)\n", __func__,
			     p_slot->name);
			mutex_unlock(&p_slot->ctrl->crit_sect);
			return -ENODEV;
		}
	}

	if (MRL_SENS(p_slot->ctrl)) {
		ret = p_slot->hpc_ops->get_latch_status(p_slot, &getstatus);
		if (ret || getstatus) {
			info("%s: latch open on slot(%s)\n", __func__,
			     p_slot->name);
			mutex_unlock(&p_slot->ctrl->crit_sect);
			return -ENODEV;
		}
	}

	if (POWER_CTRL(p_slot->ctrl)) {
		ret = p_slot->hpc_ops->get_power_status(p_slot, &getstatus);
		if (ret || !getstatus) {
			info("%s: already disabled slot(%s)\n", __func__,
			     p_slot->name);
			mutex_unlock(&p_slot->ctrl->crit_sect);
	if (POWER_CTRL(p_slot->ctrl)) {
		pciehp_get_power_status(p_slot, &getstatus);
		if (!getstatus) {
			ctrl_info(ctrl, "Slot(%s): Already disabled\n",
				  slot_name(p_slot));
			return -EINVAL;
		}
	}

	ret = remove_board(p_slot);
	update_slot_info(p_slot);

	mutex_unlock(&p_slot->ctrl->crit_sect);
	return ret;
	return remove_board(p_slot);
	remove_board(p_slot);
	return 0;
}

static int pciehp_disable_slot(struct slot *slot)
{
	struct controller *ctrl = slot->ctrl;
	int ret;

	pm_runtime_get_sync(&ctrl->pcie->port->dev);
	ret = __pciehp_disable_slot(slot);
	pm_runtime_put(&ctrl->pcie->port->dev);

	mutex_lock(&slot->lock);
	slot->state = OFF_STATE;
	mutex_unlock(&slot->lock);

	return ret;
}

int pciehp_sysfs_enable_slot(struct slot *p_slot)
{
	struct controller *ctrl = p_slot->ctrl;

	mutex_lock(&p_slot->lock);
	switch (p_slot->state) {
	case BLINKINGON_STATE:
	case OFF_STATE:
		mutex_unlock(&p_slot->lock);
		retval = pciehp_enable_slot(p_slot);
		mutex_lock(&p_slot->hotplug_lock);
		retval = pciehp_enable_slot(p_slot);
		mutex_unlock(&p_slot->hotplug_lock);
		mutex_lock(&p_slot->lock);
		p_slot->state = STATIC_STATE;
		break;
		/*
		 * The IRQ thread becomes a no-op if the user pulls out the
		 * card before the thread wakes up, so initialize to -ENODEV.
		 */
		ctrl->request_result = -ENODEV;
		pciehp_request(ctrl, PCI_EXP_SLTSTA_PDC);
		wait_event(ctrl->requester,
			   !atomic_read(&ctrl->pending_events));
		return ctrl->request_result;
	case POWERON_STATE:
		info("Slot %s is already in powering on state\n",
		     p_slot->name);
		break;
	case BLINKINGOFF_STATE:
	case POWEROFF_STATE:
		info("Already enabled on slot %s\n", p_slot->name);
		break;
	default:
		err("Not a valid state on slot %s\n", p_slot->name);
		ctrl_info(ctrl, "Slot %s is already in powering on state\n",
		ctrl_info(ctrl, "Slot(%s): Already in powering on state\n",
			  slot_name(p_slot));
		break;
	case BLINKINGOFF_STATE:
	case ON_STATE:
	case POWEROFF_STATE:
		ctrl_info(ctrl, "Slot(%s): Already enabled\n",
			  slot_name(p_slot));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Invalid state %#x\n",
			 slot_name(p_slot), p_slot->state);
		break;
	}
	mutex_unlock(&p_slot->lock);

	return -ENODEV;
}

int pciehp_sysfs_disable_slot(struct slot *p_slot)
{
	struct controller *ctrl = p_slot->ctrl;

	mutex_lock(&p_slot->lock);
	switch (p_slot->state) {
	case BLINKINGOFF_STATE:
	case ON_STATE:
		mutex_unlock(&p_slot->lock);
		pciehp_request(ctrl, DISABLE_SLOT);
		wait_event(ctrl->requester,
			   !atomic_read(&ctrl->pending_events));
		return ctrl->request_result;
	case POWEROFF_STATE:
		info("Slot %s is already in powering off state\n",
		     p_slot->name);
		break;
	case BLINKINGON_STATE:
	case POWERON_STATE:
		info("Already disabled on slot %s\n", p_slot->name);
		break;
	default:
		err("Not a valid state on slot %s\n", p_slot->name);
		ctrl_info(ctrl, "Slot %s is already in powering off state\n",
		ctrl_info(ctrl, "Slot(%s): Already in powering off state\n",
			  slot_name(p_slot));
		break;
	case BLINKINGON_STATE:
	case OFF_STATE:
	case POWERON_STATE:
		ctrl_info(ctrl, "Slot(%s): Already disabled\n",
			  slot_name(p_slot));
		break;
	default:
		ctrl_err(ctrl, "Slot(%s): Invalid state %#x\n",
			 slot_name(p_slot), p_slot->state);
		break;
	}
	mutex_unlock(&p_slot->lock);

	return -ENODEV;
}
