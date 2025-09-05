/*
 * ac97.c  --  ALSA Soc AC97 codec support
 *
 * Copyright 2005 Wolfson Microelectronics PLC.
 * Author: Liam Girdwood
 *         liam.girdwood@wolfsonmicro.com or linux@wolfsonmicro.com
 * Author: Liam Girdwood <lrg@slimlogic.co.uk>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 * Generic AC97 support.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/ac97_codec.h>
#include <sound/initval.h>
#include <sound/soc.h>
#include "ac97.h"

#define AC97_VERSION "0.6"

static int ac97_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_device *socdev = rtd->socdev;
	struct snd_soc_codec *codec = socdev->codec;

	int reg = (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
		  AC97_PCM_FRONT_DAC_RATE : AC97_PCM_LR_ADC_RATE;
	return snd_ac97_set_rate(codec->ac97, reg, runtime->rate);
}

#define STD_AC97_RATES (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_11025 |\
		SNDRV_PCM_RATE_22050 | SNDRV_PCM_RATE_44100 |\
		SNDRV_PCM_RATE_48000)

struct snd_soc_dai ac97_dai = {
	.name = "AC97 HiFi",
	.type = SND_SOC_DAI_AC97,

static const struct snd_soc_dapm_widget ac97_widgets[] = {
	SND_SOC_DAPM_INPUT("RX"),
	SND_SOC_DAPM_OUTPUT("TX"),
};

static const struct snd_soc_dapm_route ac97_routes[] = {
	{ "AC97 Capture", NULL, "RX" },
	{ "TX", NULL, "AC97 Playback" },
};

static int ac97_prepare(struct snd_pcm_substream *substream,
			struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct snd_ac97 *ac97 = snd_soc_component_get_drvdata(component);

	int reg = (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
		  AC97_PCM_FRONT_DAC_RATE : AC97_PCM_LR_ADC_RATE;
	return snd_ac97_set_rate(ac97, reg, substream->runtime->rate);
}

static const struct snd_soc_dai_ops ac97_dai_ops = {
	.prepare	= ac97_prepare,
};

static struct snd_soc_dai_driver ac97_dai = {
	.name = "ac97-hifi",
	.playback = {
		.stream_name = "AC97 Playback",
		.channels_min = 1,
		.channels_max = 2,
		.rates = STD_AC97_RATES,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,},
		.rates = SNDRV_PCM_RATE_KNOT,
		.formats = SND_SOC_STD_AC97_FMTS,},
	.capture = {
		.stream_name = "AC97 Capture",
		.channels_min = 1,
		.channels_max = 2,
		.rates = STD_AC97_RATES,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,},
	.ops = {
		.prepare = ac97_prepare,},
};
EXPORT_SYMBOL_GPL(ac97_dai);

static unsigned int ac97_read(struct snd_soc_codec *codec,
	unsigned int reg)
{
	return soc_ac97_ops.read(codec->ac97, reg);
}

static int ac97_write(struct snd_soc_codec *codec, unsigned int reg,
	unsigned int val)
{
	soc_ac97_ops.write(codec->ac97, reg, val);
	return 0;
}

static int ac97_soc_probe(struct platform_device *pdev)
{
	struct snd_soc_device *socdev = platform_get_drvdata(pdev);
	struct snd_soc_codec *codec;
	struct snd_ac97_bus *ac97_bus;
	struct snd_ac97_template ac97_template;
	int ret = 0;

	printk(KERN_INFO "AC97 SoC Audio Codec %s\n", AC97_VERSION);

	socdev->codec = kzalloc(sizeof(struct snd_soc_codec), GFP_KERNEL);
	if (!socdev->codec)
		return -ENOMEM;
	codec = socdev->codec;
	mutex_init(&codec->mutex);

	codec->name = "AC97";
	codec->owner = THIS_MODULE;
	codec->dai = &ac97_dai;
	codec->num_dai = 1;
	codec->write = ac97_write;
	codec->read = ac97_read;
	INIT_LIST_HEAD(&codec->dapm_widgets);
	INIT_LIST_HEAD(&codec->dapm_paths);

	/* register pcms */
	ret = snd_soc_new_pcms(socdev, SNDRV_DEFAULT_IDX1, SNDRV_DEFAULT_STR1);
	if (ret < 0)
		goto err;

	/* add codec as bus device for standard ac97 */
	ret = snd_ac97_bus(codec->card, 0, &soc_ac97_ops, NULL, &ac97_bus);
	if (ret < 0)
		goto bus_err;

	memset(&ac97_template, 0, sizeof(struct snd_ac97_template));
	ret = snd_ac97_mixer(ac97_bus, &ac97_template, &codec->ac97);
	if (ret < 0)
		goto bus_err;

	ret = snd_soc_register_card(socdev);
	if (ret < 0)
		goto bus_err;
	return 0;

bus_err:
	snd_soc_free_pcms(socdev);

err:
	kfree(socdev->codec->reg_cache);
	kfree(socdev->codec);
	socdev->codec = NULL;
	return ret;
}

static int ac97_soc_remove(struct platform_device *pdev)
{
	struct snd_soc_device *socdev = platform_get_drvdata(pdev);
	struct snd_soc_codec *codec = socdev->codec;

	if (!codec)
		return 0;

	snd_soc_free_pcms(socdev);
	kfree(socdev->codec->reg_cache);
	kfree(socdev->codec);
		.rates = SNDRV_PCM_RATE_KNOT,
		.formats = SND_SOC_STD_AC97_FMTS,},
	.ops = &ac97_dai_ops,
};

static int ac97_soc_probe(struct snd_soc_component *component)
{
	struct snd_ac97 *ac97;
	struct snd_ac97_bus *ac97_bus;
	struct snd_ac97_template ac97_template;
	int ret;

	/* add codec as bus device for standard ac97 */
	ret = snd_ac97_bus(component->card->snd_card, 0, soc_ac97_ops,
			   NULL, &ac97_bus);
	if (ret < 0)
		return ret;

	memset(&ac97_template, 0, sizeof(struct snd_ac97_template));
	ret = snd_ac97_mixer(ac97_bus, &ac97_template, &ac97);
	if (ret < 0)
		return ret;

	snd_soc_component_set_drvdata(component, ac97);

	return 0;
}

#ifdef CONFIG_PM
static int ac97_soc_suspend(struct platform_device *pdev, pm_message_t msg)
{
	struct snd_soc_device *socdev = platform_get_drvdata(pdev);

	snd_ac97_suspend(socdev->codec->ac97);
static int ac97_soc_suspend(struct snd_soc_codec *codec)
static int ac97_soc_suspend(struct snd_soc_component *component)
{
	struct snd_ac97 *ac97 = snd_soc_component_get_drvdata(component);

	snd_ac97_suspend(ac97);

	return 0;
}

static int ac97_soc_resume(struct platform_device *pdev)
{
	struct snd_soc_device *socdev = platform_get_drvdata(pdev);

	snd_ac97_resume(socdev->codec->ac97);
static int ac97_soc_resume(struct snd_soc_codec *codec)
static int ac97_soc_resume(struct snd_soc_component *component)
{

	struct snd_ac97 *ac97 = snd_soc_component_get_drvdata(component);

	snd_ac97_resume(ac97);

	return 0;
}
#else
#define ac97_soc_suspend NULL
#define ac97_soc_resume NULL
#endif

struct snd_soc_codec_device soc_codec_dev_ac97 = {
	.probe = 	ac97_soc_probe,
	.remove = 	ac97_soc_remove,
	.suspend =	ac97_soc_suspend,
	.resume =	ac97_soc_resume,
};
EXPORT_SYMBOL_GPL(soc_codec_dev_ac97);
static struct snd_soc_codec_driver soc_codec_dev_ac97 = {
static const struct snd_soc_codec_driver soc_codec_dev_ac97 = {
	.probe = 	ac97_soc_probe,
	.suspend =	ac97_soc_suspend,
	.resume =	ac97_soc_resume,

	.component_driver = {
		.dapm_widgets		= ac97_widgets,
		.num_dapm_widgets	= ARRAY_SIZE(ac97_widgets),
		.dapm_routes		= ac97_routes,
		.num_dapm_routes	= ARRAY_SIZE(ac97_routes),
	},
static const struct snd_soc_component_driver soc_component_dev_ac97 = {
	.probe			= ac97_soc_probe,
	.suspend		= ac97_soc_suspend,
	.resume			= ac97_soc_resume,
	.dapm_widgets		= ac97_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(ac97_widgets),
	.dapm_routes		= ac97_routes,
	.num_dapm_routes	= ARRAY_SIZE(ac97_routes),
	.idle_bias_on		= 1,
	.use_pmdown_time	= 1,
	.endianness		= 1,
	.non_legacy_dai_naming	= 1,
};

static int ac97_probe(struct platform_device *pdev)
{
	return devm_snd_soc_register_component(&pdev->dev,
			&soc_component_dev_ac97, &ac97_dai, 1);
}

static int ac97_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver ac97_codec_driver = {
	.driver = {
		.name = "ac97-codec",
	},

	.probe = ac97_probe,
	.remove = ac97_remove,
};

module_platform_driver(ac97_codec_driver);

MODULE_DESCRIPTION("Soc Generic AC97 driver");
MODULE_AUTHOR("Liam Girdwood");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ac97-codec");
