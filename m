Return-Path: <kasan-dev+bncBC7OBJGL2MHBB34PS2AAMGQEU4LKFBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id CD9922FA0B3
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 14:06:55 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id f23sf4275682ljg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 05:06:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610975215; cv=pass;
        d=google.com; s=arc-20160816;
        b=qSe9Y9KrWt11Ktai0cqfcqc9TavGeYz6bZ50ksKUmAee6Tj3A1AY+IuNbAIc3xbvsB
         V/WeZeLDX/nT/un+8QtZg8uVJW1jTCHQz+BVC4JLV2YkxvmI6vpDh8ls2cQ5cDyGd5fB
         VDan0tEsG7oKwbdoeSzv8M17cVJOFxr8tH/N4kSK0CmzjqGN95D0Vjsuc2n1uhN6C49x
         5ax9Oe6yDjawMG3kZjOTFIJ+mXPGJcivu5kLpo+wVdUQ0z7hOSlfsTILJVwlLGLAblsi
         mCcS8qSOilQeZmaFl1B8jtO2uuN0NK8kkEleqbHLa1BJuxYYdcnY8F/TVNNxFiv5zQO5
         yOmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fH0+WUioWk5fGcWnmLuSJYrvK1GTUf05rzbphExkiHU=;
        b=u1/rzkM8utkXE4LDYMh9A+W2l0AQRcXg8Qy15aHLpZdThWMUdvpfYBKpdhOAb6io06
         3CAaMRLHw4Cn1c7Tk7URz9x9f9xxwiU8VXzLbQEqSkJ4Mk6qwUds02GR+eKFDi+OUvBT
         uCUaG0bB/delJ+NwNqc9zHOx5QcFZHKypqK1NVlS1zLNG6cZf5mcLLNnWXPUO4nwH4yX
         Rh3djMHjm7VOnJdiZ4quZOjwk2uBTxvf4vPA8sKIzrCC2jWhRzKBreCZqrhiKMwbRRjC
         tm/lu8OQq5To4u+lFuU41F2IcBusnFerrhKD0siaLrfwW7n/5Trs1iXVDByzx+VG21yb
         vFNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekhROC2a;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fH0+WUioWk5fGcWnmLuSJYrvK1GTUf05rzbphExkiHU=;
        b=UyW4NK0sgnLqs6q72+CslnumCgKmjEd8DkBgk1Biu15IeClO5RXMpHX2CaSZc2R3XB
         4AELMEGpJ8TiAko9o38BZpQ0VN0LHyTf+dq8c0VTSQejBnAizcKSvIrH3f0wTqUFa72q
         ADlYzGwXcBzWRU7ptN1sOX+kDwBdOaFQk8UCMl6Q72FL5t+a6QXttDv3oNBon6G07Gqp
         OcRloxLlemGtymwmaWU4wfDw4Hy9sYTksyQT/+Qt3/pY8dJ1XNlN8gthcphTd0b97Nfc
         MWSENZaZep5H+CIn8lQadGnnVrFekfRBZ3TO9W+hlOatrvkukQree2QL1wWDCHU+eugS
         w87A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fH0+WUioWk5fGcWnmLuSJYrvK1GTUf05rzbphExkiHU=;
        b=hHOfpulw8B7Z0X02ZRn9bdAP5ns0DaSP9R4FLx/tKki5uPrQDGD9hFQS6mb5m2kVaR
         1mDIFcruAhmZoKyFm1sGGtly+DjDttSwtLVDKDCU4iljHY2ajq0+e+/YBs6Fhkd6gs1y
         LFiYmXXdy3DplsFPe4y7bLHSZwr4EsJOtCGyv+qfizwdfXGmiCkvjcSceBj4XSdJqB82
         uSVapZpGZf53k02RePG+blEtPffWaWmF4SdF/XgxytyjuH7y2X7dt7NKLaraascyJs/u
         4eNECJKCKUnCpK1MOdI0VrCXxyqKi+GrAZNXAAfEjetvKbGtXMxXzWYkCIpfRjTWUsIB
         BPOg==
X-Gm-Message-State: AOAM531027CGxHeQEqWiM1qGEnvf64tHJJsz5/1gnWJW8mTZF98e/HVu
	4VvkArGooUDEbBIpDPnMx6s=
X-Google-Smtp-Source: ABdhPJzphkFBd/8oZJxBchwal1pOBxleuutZE7/0IMOVV9bilKudAx5TLSMJfMlsBOrQ7Tss4SskKQ==
X-Received: by 2002:a19:7e89:: with SMTP id z131mr10816807lfc.2.1610975215401;
        Mon, 18 Jan 2021 05:06:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2830250lfu.3.gmail; Mon,
 18 Jan 2021 05:06:54 -0800 (PST)
X-Received: by 2002:a05:6512:39c9:: with SMTP id k9mr8726317lfu.432.1610975214185;
        Mon, 18 Jan 2021 05:06:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610975214; cv=none;
        d=google.com; s=arc-20160816;
        b=Od/OHp1w2ozMhPN56IoLnNRqjyVqzfWNzdwt456b0YX3eMkeNYHiXodHUOklrOyNXo
         no9Dn61OWxfcxp0SADH6M4aT+GUykKosJJ0Pdl0/GM5JYByFJUV9cA5eX4Vp7WPEQq7B
         Lq7Za5FbZuuNDB18hBCdI/Gq9cl85ngedIVwSEgrBhVh3TTntKgqJUhXdH1bVoFHcYU8
         ka+10OfOmUb8/xfTlqLKeYcyOz1D/HAKkzDl9IYRqXKof6fZ+2mtDvkTHVPLfoaobKL5
         eqFLTUHMwzbQGilMQv/vdKiT6bYMNY/awxJhSrb3aUOdAJF9MVECkM94yJZJPSA6maCH
         aoiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cKlyhU48mWEpYzjNOoia+4brb6Khl72pdXiLf43hFhE=;
        b=PfgpXqlvKdOQsAaFyQTGSMyZXFtYuwg7aHPP8ggQX4XgNBfTPeI/siZKKz+dP3XfoQ
         AD5M6YyDDXOju24nXJa1t5trBuSoxU2/Omc0HLhsBA60oW8CUHuBgZbT3zDGZV4qDlnG
         pm0pix6TH/It/oRq/ClfeiD9TpUFlghx9Abfbjpmpd3830RFmyReCu61eeEeQMMHoXGS
         bpU7BLrUTpxke8fS3pAPXLCfw6O8hczOA/IxnueSp/rMJoH9AaotaaTXrxjcnigEpJMI
         Yb99izJfslw8i9r6qWx1oqKelNx2/PwUXmXQjyW6JvcptwgUxXCx32WPUaKc8K1928gM
         LSlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekhROC2a;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id f21si892441lfe.9.2021.01.18.05.06.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 05:06:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id c5so16393215wrp.6
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 05:06:54 -0800 (PST)
X-Received: by 2002:a5d:4241:: with SMTP id s1mr25922028wrr.269.1610975213753;
        Mon, 18 Jan 2021 05:06:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id x128sm26669557wmb.29.2021.01.18.05.06.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Jan 2021 05:06:52 -0800 (PST)
Date: Mon, 18 Jan 2021 14:06:47 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: fix HW_TAGS boot parameters
Message-ID: <YAWH56mMdRf7uPBB@elver.google.com>
References: <4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ekhROC2a;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Fri, Jan 15, 2021 at 07:53PM +0100, Andrey Konovalov wrote:
> The initially proposed KASAN command line parameters are redundant.
> 
> This change drops the complex "kasan.mode=off/prod/full" parameter
> and adds a simpler kill switch "kasan=off/on" instead. The new parameter
> together with the already existing ones provides a cleaner way to
> express the same set of features.
> 
> The full set of parameters with this change:
> 
> kasan=off/on             - whether KASAN is enabled
> kasan.fault=report/panic - whether to only print a report or also panic
> kasan.stacktrace=off/on  - whether to collect alloc/free stack traces
> 
> Default values:
> 
> kasan=on
> kasan.fault=report
> kasan.stacktrace=on  (if CONFIG_DEBUG_KERNEL=y)
> kasan.stacktrace=off (otherwise)
> 
> Link: https://linux-review.googlesource.com/id/Ib3694ed90b1e8ccac6cf77dfd301847af4aba7b8
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Thanks for the simplification.

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 27 +++--------
>  mm/kasan/hw_tags.c                | 77 +++++++++++++------------------
>  2 files changed, 38 insertions(+), 66 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 0fc3fb1860c4..1651d961f06a 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -160,29 +160,14 @@ intended for use in production as a security mitigation. Therefore it supports
>  boot parameters that allow to disable KASAN competely or otherwise control
>  particular KASAN features.
>  
> -The things that can be controlled are:
> +- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>  
> -1. Whether KASAN is enabled at all.
> -2. Whether KASAN collects and saves alloc/free stacks.
> -3. Whether KASAN panics on a detected bug or not.
> +- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
> +  traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
> +  ``off``).
>  
> -The ``kasan.mode`` boot parameter allows to choose one of three main modes:
> -
> -- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
> -- ``kasan.mode=prod`` - only essential production features are enabled
> -- ``kasan.mode=full`` - all KASAN features are enabled
> -
> -The chosen mode provides default control values for the features mentioned
> -above. However it's also possible to override the default values by providing:
> -
> -- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
> -					(default: ``on`` for ``mode=full``,
> -					 otherwise ``off``)
> -- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
> -					 (default: ``report``)
> -
> -If ``kasan.mode`` parameter is not provided, it defaults to ``full`` when
> -``CONFIG_DEBUG_KERNEL`` is enabled, and to ``prod`` otherwise.
> +- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> +  report or also panic the kernel (default: ``report``).
>  
>  For developers
>  ~~~~~~~~~~~~~~
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 55bd6f09c70f..e529428e7a11 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -19,11 +19,10 @@
>  
>  #include "kasan.h"
>  
> -enum kasan_arg_mode {
> -	KASAN_ARG_MODE_DEFAULT,
> -	KASAN_ARG_MODE_OFF,
> -	KASAN_ARG_MODE_PROD,
> -	KASAN_ARG_MODE_FULL,
> +enum kasan_arg {
> +	KASAN_ARG_DEFAULT,
> +	KASAN_ARG_OFF,
> +	KASAN_ARG_ON,
>  };
>  
>  enum kasan_arg_stacktrace {
> @@ -38,7 +37,7 @@ enum kasan_arg_fault {
>  	KASAN_ARG_FAULT_PANIC,
>  };
>  
> -static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> +static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>  
> @@ -52,26 +51,24 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  /* Whether panic or disable tag checking on fault. */
>  bool kasan_flag_panic __ro_after_init;
>  
> -/* kasan.mode=off/prod/full */
> -static int __init early_kasan_mode(char *arg)
> +/* kasan=off/on */
> +static int __init early_kasan_flag(char *arg)
>  {
>  	if (!arg)
>  		return -EINVAL;
>  
>  	if (!strcmp(arg, "off"))
> -		kasan_arg_mode = KASAN_ARG_MODE_OFF;
> -	else if (!strcmp(arg, "prod"))
> -		kasan_arg_mode = KASAN_ARG_MODE_PROD;
> -	else if (!strcmp(arg, "full"))
> -		kasan_arg_mode = KASAN_ARG_MODE_FULL;
> +		kasan_arg = KASAN_ARG_OFF;
> +	else if (!strcmp(arg, "on"))
> +		kasan_arg = KASAN_ARG_ON;
>  	else
>  		return -EINVAL;
>  
>  	return 0;
>  }
> -early_param("kasan.mode", early_kasan_mode);
> +early_param("kasan", early_kasan_flag);
>  
> -/* kasan.stack=off/on */
> +/* kasan.stacktrace=off/on */
>  static int __init early_kasan_flag_stacktrace(char *arg)
>  {
>  	if (!arg)
> @@ -113,8 +110,8 @@ void kasan_init_hw_tags_cpu(void)
>  	 * as this function is only called for MTE-capable hardware.
>  	 */
>  
> -	/* If KASAN is disabled, do nothing. */
> -	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
> +	/* If KASAN is disabled via command line, don't initialize it. */
> +	if (kasan_arg == KASAN_ARG_OFF)
>  		return;
>  
>  	hw_init_tags(KASAN_TAG_MAX);
> @@ -124,43 +121,28 @@ void kasan_init_hw_tags_cpu(void)
>  /* kasan_init_hw_tags() is called once on boot CPU. */
>  void __init kasan_init_hw_tags(void)
>  {
> -	/* If hardware doesn't support MTE, do nothing. */
> +	/* If hardware doesn't support MTE, don't initialize KASAN. */
>  	if (!system_supports_mte())
>  		return;
>  
> -	/* Choose KASAN mode if kasan boot parameter is not provided. */
> -	if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
> -		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> -			kasan_arg_mode = KASAN_ARG_MODE_FULL;
> -		else
> -			kasan_arg_mode = KASAN_ARG_MODE_PROD;
> -	}
> -
> -	/* Preset parameter values based on the mode. */
> -	switch (kasan_arg_mode) {
> -	case KASAN_ARG_MODE_DEFAULT:
> -		/* Shouldn't happen as per the check above. */
> -		WARN_ON(1);
> -		return;
> -	case KASAN_ARG_MODE_OFF:
> -		/* If KASAN is disabled, do nothing. */
> +	/* If KASAN is disabled via command line, don't initialize it. */
> +	if (kasan_arg == KASAN_ARG_OFF)
>  		return;
> -	case KASAN_ARG_MODE_PROD:
> -		static_branch_enable(&kasan_flag_enabled);
> -		break;
> -	case KASAN_ARG_MODE_FULL:
> -		static_branch_enable(&kasan_flag_enabled);
> -		static_branch_enable(&kasan_flag_stacktrace);
> -		break;
> -	}
>  
> -	/* Now, optionally override the presets. */
> +	/* Enable KASAN. */
> +	static_branch_enable(&kasan_flag_enabled);
>  
>  	switch (kasan_arg_stacktrace) {
>  	case KASAN_ARG_STACKTRACE_DEFAULT:
> +		/*
> +		 * Default to enabling stack trace collection for
> +		 * debug kernels.
> +		 */
> +		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> +			static_branch_enable(&kasan_flag_stacktrace);
>  		break;
>  	case KASAN_ARG_STACKTRACE_OFF:
> -		static_branch_disable(&kasan_flag_stacktrace);
> +		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
>  		break;
>  	case KASAN_ARG_STACKTRACE_ON:
>  		static_branch_enable(&kasan_flag_stacktrace);
> @@ -169,11 +151,16 @@ void __init kasan_init_hw_tags(void)
>  
>  	switch (kasan_arg_fault) {
>  	case KASAN_ARG_FAULT_DEFAULT:
> +		/*
> +		 * Default to no panic on report.
> +		 * Do nothing, kasan_flag_panic keeps its default value.
> +		 */
>  		break;
>  	case KASAN_ARG_FAULT_REPORT:
> -		kasan_flag_panic = false;
> +		/* Do nothing, kasan_flag_panic keeps its default value. */
>  		break;
>  	case KASAN_ARG_FAULT_PANIC:
> +		/* Enable panic on report. */
>  		kasan_flag_panic = true;
>  		break;
>  	}
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YAWH56mMdRf7uPBB%40elver.google.com.
