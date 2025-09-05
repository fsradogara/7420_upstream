/*
 * LEDs driver for GPIOs
 *
 * Copyright (C) 2007 8D Technologies inc.
 * Raphael Assenat <raph@8d.com>
 * Copyright (C) 2008 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/leds.h>
#include <linux/workqueue.h>

#include <asm/gpio.h>

struct gpio_led_data {
	struct led_classdev cdev;
	unsigned gpio;
	struct work_struct work;
	u8 new_level;
	u8 can_sleep;
	u8 active_low;
	int (*platform_gpio_blink_set)(unsigned gpio,
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/slab.h>

struct gpio_led_data {
	struct led_classdev cdev;
	struct gpio_desc *gpiod;
	u8 can_sleep;
	u8 blinking;
	gpio_blink_set_t platform_gpio_blink_set;
};

static inline struct gpio_led_data *
			cdev_to_gpio_led_data(struct led_classdev *led_cdev)
{
	struct gpio_led_data	*led_dat =
		container_of(work, struct gpio_led_data, work);

	gpio_set_value_cansleep(led_dat->gpio, led_dat->new_level);
	struct gpio_led_data *led_dat =
		container_of(work, struct gpio_led_data, work);

	if (led_dat->blinking) {
		led_dat->platform_gpio_blink_set(led_dat->gpiod,
					led_dat->new_level, NULL, NULL);
		led_dat->blinking = 0;
	} else
		gpiod_set_value_cansleep(led_dat->gpiod, led_dat->new_level);
	return container_of(led_cdev, struct gpio_led_data, cdev);
}

static void gpio_led_set(struct led_classdev *led_cdev,
	enum led_brightness value)
{
	struct gpio_led_data *led_dat = cdev_to_gpio_led_data(led_cdev);
	int level;

	if (value == LED_OFF)
		level = 0;
	else
		level = 1;

	if (led_dat->active_low)
		level = !level;

	/* Setting GPIOs with I2C/etc requires a task context, and we don't
	 * seem to have a reliable way to know if we're already in one; so
	 * let's just assume the worst.
	 */
	if (led_dat->can_sleep) {
		led_dat->new_level = level;
		schedule_work(&led_dat->work);
	} else
		gpio_set_value(led_dat->gpio, level);
	if (led_dat->blinking) {
		led_dat->platform_gpio_blink_set(led_dat->gpiod, level,
						 NULL, NULL);
		led_dat->blinking = 0;
	} else {
		if (led_dat->can_sleep)
			gpiod_set_value_cansleep(led_dat->gpiod, level);
		else
			gpiod_set_value(led_dat->gpiod, level);
	}
}

static int gpio_led_set_blocking(struct led_classdev *led_cdev,
	enum led_brightness value)
{
	gpio_led_set(led_cdev, value);
	return 0;
}

static int gpio_blink_set(struct led_classdev *led_cdev,
	unsigned long *delay_on, unsigned long *delay_off)
{
	struct gpio_led_data *led_dat = cdev_to_gpio_led_data(led_cdev);

	return led_dat->platform_gpio_blink_set(led_dat->gpio, delay_on, delay_off);
}

static int gpio_led_probe(struct platform_device *pdev)
{
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct gpio_led *cur_led;
	struct gpio_led_data *leds_data, *led_dat;
	int i, ret = 0;

	if (!pdata)
		return -EBUSY;

	leds_data = kzalloc(sizeof(struct gpio_led_data) * pdata->num_leds,
				GFP_KERNEL);
	if (!leds_data)
		return -ENOMEM;

	for (i = 0; i < pdata->num_leds; i++) {
		cur_led = &pdata->leds[i];
		led_dat = &leds_data[i];

		ret = gpio_request(cur_led->gpio, cur_led->name);
		if (ret < 0)
			goto err;

		led_dat->cdev.name = cur_led->name;
		led_dat->cdev.default_trigger = cur_led->default_trigger;
		led_dat->gpio = cur_led->gpio;
		led_dat->can_sleep = gpio_cansleep(cur_led->gpio);
		led_dat->active_low = cur_led->active_low;
		if (pdata->gpio_blink_set) {
			led_dat->platform_gpio_blink_set = pdata->gpio_blink_set;
			led_dat->cdev.blink_set = gpio_blink_set;
		}
		led_dat->cdev.brightness_set = gpio_led_set;
		led_dat->cdev.brightness = LED_OFF;

		gpio_direction_output(led_dat->gpio, led_dat->active_low);

		INIT_WORK(&led_dat->work, gpio_led_work);

		ret = led_classdev_register(&pdev->dev, &led_dat->cdev);
		if (ret < 0) {
			gpio_free(led_dat->gpio);
			goto err;
		}
	}

	platform_set_drvdata(pdev, leds_data);

	return 0;

err:
	if (i > 0) {
		for (i = i - 1; i >= 0; i--) {
			led_classdev_unregister(&leds_data[i].cdev);
			cancel_work_sync(&leds_data[i].work);
			gpio_free(leds_data[i].gpio);
		}
	}

	kfree(leds_data);

	return ret;
}

static int __devexit gpio_led_remove(struct platform_device *pdev)
{
	int i;
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct gpio_led_data *leds_data;

	leds_data = platform_get_drvdata(pdev);

	for (i = 0; i < pdata->num_leds; i++) {
		led_classdev_unregister(&leds_data[i].cdev);
		cancel_work_sync(&leds_data[i].work);
		gpio_free(leds_data[i].gpio);
	}

	kfree(leds_data);

	return 0;
}

#ifdef CONFIG_PM
static int gpio_led_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct gpio_led_data *leds_data;
	int i;

	leds_data = platform_get_drvdata(pdev);

	for (i = 0; i < pdata->num_leds; i++)
		led_classdev_suspend(&leds_data[i].cdev);

	return 0;
}

static int gpio_led_resume(struct platform_device *pdev)
{
	struct gpio_led_platform_data *pdata = pdev->dev.platform_data;
	struct gpio_led_data *leds_data;
	int i;

	leds_data = platform_get_drvdata(pdev);

	for (i = 0; i < pdata->num_leds; i++)
		led_classdev_resume(&leds_data[i].cdev);

	return 0;
}
#else
#define gpio_led_suspend NULL
#define gpio_led_resume NULL
#endif

static struct platform_driver gpio_led_driver = {
	.probe		= gpio_led_probe,
	.remove		= __devexit_p(gpio_led_remove),
	.suspend	= gpio_led_suspend,
	.resume		= gpio_led_resume,
	.driver		= {
		.name	= "leds-gpio",
		.owner	= THIS_MODULE,
	},
};

static int __init gpio_led_init(void)
{
	return platform_driver_register(&gpio_led_driver);
}

static void __exit gpio_led_exit(void)
{
	platform_driver_unregister(&gpio_led_driver);
}

module_init(gpio_led_init);
module_exit(gpio_led_exit);

MODULE_AUTHOR("Raphael Assenat <raph@8d.com>");
	led_dat->blinking = 1;
	return led_dat->platform_gpio_blink_set(led_dat->gpiod, GPIO_LED_BLINK,
						delay_on, delay_off);
}

static int create_gpio_led(const struct gpio_led *template,
	struct gpio_led_data *led_dat, struct device *parent,
	struct device_node *np, gpio_blink_set_t blink_set)
{
	int ret, state;

	led_dat->gpiod = template->gpiod;
	if (!led_dat->gpiod) {
		/*
		 * This is the legacy code path for platform code that
		 * still uses GPIO numbers. Ultimately we would like to get
		 * rid of this block completely.
		 */
		unsigned long flags = GPIOF_OUT_INIT_LOW;

		/* skip leds that aren't available */
		if (!gpio_is_valid(template->gpio)) {
			dev_info(parent, "Skipping unavailable LED gpio %d (%s)\n",
					template->gpio, template->name);
			return 0;
		}

		if (template->active_low)
			flags |= GPIOF_ACTIVE_LOW;

		ret = devm_gpio_request_one(parent, template->gpio, flags,
					    template->name);
		if (ret < 0)
			return ret;

		led_dat->gpiod = gpio_to_desc(template->gpio);
		if (!led_dat->gpiod)
			return -EINVAL;
	}

	led_dat->cdev.name = template->name;
	led_dat->cdev.default_trigger = template->default_trigger;
	led_dat->can_sleep = gpiod_cansleep(led_dat->gpiod);
	if (!led_dat->can_sleep)
		led_dat->cdev.brightness_set = gpio_led_set;
	else
		led_dat->cdev.brightness_set_blocking = gpio_led_set_blocking;
	led_dat->blinking = 0;
	if (blink_set) {
		led_dat->platform_gpio_blink_set = blink_set;
		led_dat->cdev.blink_set = gpio_blink_set;
	}
	if (template->default_state == LEDS_GPIO_DEFSTATE_KEEP) {
		state = gpiod_get_value_cansleep(led_dat->gpiod);
		if (state < 0)
			return state;
	} else {
		state = (template->default_state == LEDS_GPIO_DEFSTATE_ON);
	}
	led_dat->cdev.brightness = state ? LED_FULL : LED_OFF;
	if (!template->retain_state_suspended)
		led_dat->cdev.flags |= LED_CORE_SUSPENDRESUME;
	if (template->panic_indicator)
		led_dat->cdev.flags |= LED_PANIC_INDICATOR;
	if (template->retain_state_shutdown)
		led_dat->cdev.flags |= LED_RETAIN_AT_SHUTDOWN;

	ret = gpiod_direction_output(led_dat->gpiod, state);
	if (ret < 0)
		return ret;

	return devm_of_led_classdev_register(parent, np, &led_dat->cdev);
}

struct gpio_leds_priv {
	int num_leds;
	struct gpio_led_data leds[];
};

static inline int sizeof_gpio_leds_priv(int num_leds)
{
	return sizeof(struct gpio_leds_priv) +
		(sizeof(struct gpio_led_data) * num_leds);
}

static struct gpio_leds_priv *gpio_leds_create(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fwnode_handle *child;
	struct gpio_leds_priv *priv;
	int count, ret;

	count = device_get_child_node_count(dev);
	if (!count)
		return ERR_PTR(-ENODEV);

	priv = devm_kzalloc(dev, sizeof_gpio_leds_priv(count), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	device_for_each_child_node(dev, child) {
		struct gpio_led_data *led_dat = &priv->leds[priv->num_leds];
		struct gpio_led led = {};
		const char *state = NULL;
		struct device_node *np = to_of_node(child);

		ret = fwnode_property_read_string(child, "label", &led.name);
		if (ret && IS_ENABLED(CONFIG_OF) && np)
			led.name = np->name;
		if (!led.name) {
			fwnode_handle_put(child);
			return ERR_PTR(-EINVAL);
		}

		led.gpiod = devm_fwnode_get_gpiod_from_child(dev, NULL, child,
							     GPIOD_ASIS,
							     led.name);
		if (IS_ERR(led.gpiod)) {
			fwnode_handle_put(child);
			return ERR_CAST(led.gpiod);
		}

		fwnode_property_read_string(child, "linux,default-trigger",
					    &led.default_trigger);

		if (!fwnode_property_read_string(child, "default-state",
						 &state)) {
			if (!strcmp(state, "keep"))
				led.default_state = LEDS_GPIO_DEFSTATE_KEEP;
			else if (!strcmp(state, "on"))
				led.default_state = LEDS_GPIO_DEFSTATE_ON;
			else
				led.default_state = LEDS_GPIO_DEFSTATE_OFF;
		}

		if (fwnode_property_present(child, "retain-state-suspended"))
			led.retain_state_suspended = 1;
		if (fwnode_property_present(child, "retain-state-shutdown"))
			led.retain_state_shutdown = 1;
		if (fwnode_property_present(child, "panic-indicator"))
			led.panic_indicator = 1;

		ret = create_gpio_led(&led, led_dat, dev, np, NULL);
		if (ret < 0) {
			fwnode_handle_put(child);
			return ERR_PTR(ret);
		}
		led_dat->cdev.dev->of_node = np;
		priv->num_leds++;
	}

	return priv;
}

static const struct of_device_id of_gpio_leds_match[] = {
	{ .compatible = "gpio-leds", },
	{},
};

MODULE_DEVICE_TABLE(of, of_gpio_leds_match);

static int gpio_led_probe(struct platform_device *pdev)
{
	struct gpio_led_platform_data *pdata = dev_get_platdata(&pdev->dev);
	struct gpio_leds_priv *priv;
	int i, ret = 0;

	if (pdata && pdata->num_leds) {
		priv = devm_kzalloc(&pdev->dev,
				sizeof_gpio_leds_priv(pdata->num_leds),
					GFP_KERNEL);
		if (!priv)
			return -ENOMEM;

		priv->num_leds = pdata->num_leds;
		for (i = 0; i < priv->num_leds; i++) {
			ret = create_gpio_led(&pdata->leds[i], &priv->leds[i],
					      &pdev->dev, NULL,
					      pdata->gpio_blink_set);
			if (ret < 0)
				return ret;
		}
	} else {
		priv = gpio_leds_create(pdev);
		if (IS_ERR(priv))
			return PTR_ERR(priv);
	}

	platform_set_drvdata(pdev, priv);

	return 0;
}

static void gpio_led_shutdown(struct platform_device *pdev)
{
	struct gpio_leds_priv *priv = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < priv->num_leds; i++) {
		struct gpio_led_data *led = &priv->leds[i];

		if (!(led->cdev.flags & LED_RETAIN_AT_SHUTDOWN))
			gpio_led_set(&led->cdev, LED_OFF);
	}
}

static struct platform_driver gpio_led_driver = {
	.probe		= gpio_led_probe,
	.shutdown	= gpio_led_shutdown,
	.driver		= {
		.name	= "leds-gpio",
		.of_match_table = of_gpio_leds_match,
	},
};

module_platform_driver(gpio_led_driver);

MODULE_AUTHOR("Raphael Assenat <raph@8d.com>, Trent Piepho <tpiepho@freescale.com>");
MODULE_DESCRIPTION("GPIO LED driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:leds-gpio");
