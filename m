Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6PNROAAMGQEQLN4G2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id A6C9C2F8D8A
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 15:23:54 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id v187sf10161631ybv.21
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:23:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610807033; cv=pass;
        d=google.com; s=arc-20160816;
        b=HeORz6m3VrVfjF2GmFWDXHPrdxVbX0Ev9CJNRIIwLo6v8x7454f/mlHa75DnATLj+i
         rwXHBJhVQJpcG5CArKnFRdX5GxDmUSjgkCLkT+rV5M5Q8CWXufEqVSXxg30spoWfzpcb
         coSTyu0c67d36IaJRGE9Qy5dQ62oYs/64XwA8PdH5eF3nmFx9MvoiMdUwvwFUlYXq6/b
         0lC+uLIQRMFEDfDAg46N+S4k+tY+U5NTf1NG2E6WIA9IlGGpuc776X1SBML3cySo7Fnq
         gSZXf5J3EVj1H5g2bpJ2UUep0QV3XhDtKaDpXKMBdYvbG73rH9ci/PweU5F4RuGvdI5S
         vhHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=EJbUbASLfgLMeGX4OmKXtshUz6PN26pSdeQXjEV/3Cg=;
        b=BrSiB/Oxj/2lL94m20S7+zyq9gW1d5YFdfuK6+Hc1fQ3H8FgxdBedkP7nzn5BIkLJg
         vsb3j9iQmUd//2YK8Cfa3+ZFRj9cvdQbg8qHeXVEP2daaB24+g/3Cde5zPJ+I/kOuMEY
         e2wHMVTvapAMeIRbSlk5bsrylx0odOYFFJdD9eaZ/ruqBGB0gGPsUURuvW/hR0BBQtP4
         XgSgzqQ5D5nR+6UB3G4aiuwDwmOSLaF7zqqnLZnc4bg8mjFFA9yafj5OkSB1cngs9hd2
         Y7JogK5rQHePcCvJU0L2kg2a8LV6UmWaoV7Vc7YiQG7VmwvdZIqaFl84BLu8ay2k4K66
         y/SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EJbUbASLfgLMeGX4OmKXtshUz6PN26pSdeQXjEV/3Cg=;
        b=UXraYj4KEzFgKdKESmVBSMWYVqEo2nswztRPIRk4pZ0zCYh/rTe1434CtUXWsryKHV
         ASG7q8Sn1UA2NhX6UUx0Stlyw+KtY3V2hUS5jsf9ii8VkkuzHnp5n5YWFLBuNuRisk3J
         hreN5v7TOHvqr2f15auJa6mEZ56IxZqKRzW/hf40ddbMt/eAH8crNo030ltD/CMMTsni
         Cc4MzRP4IUiwpIDPAgweLIBkLSN77pDGwwy57+x9kVOywgPcZgtoi8g7c65+tDsd8P8H
         1hghUFWJ0YY5Hg3RU2p2ACkpuiKCYcPHhwaHd7RipMsM2i/Fjwe8XPiBbFjP2tNqFBDX
         iFTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EJbUbASLfgLMeGX4OmKXtshUz6PN26pSdeQXjEV/3Cg=;
        b=IuADRKzYvc/h5ZoIXcCcWifTWIPSWNr/CtkGo+yC5KtMJvTki+RkNyKfE1iemJJhIa
         Kav/zFr22GWZL/YMm3fCTKUB+RZd9railW+a3y/zRXNp6fMz+nEF2OSf27Vcc3x/iLdB
         cr59gWk9hYVtoig5joVqizyPzFI0bR5pSIUSXRbk0qcZqIWYZ957GGToCO5YdNsjcQy9
         +mDey4BkdyQaBA0K4aanaXsIkRTA0qH3bG26AJhCvVUYCyDQr0fYhoJTJNHVEVpxuw5Z
         uSxkbBjgOo/gsUC6NLUjtMvEMPaLHBKa+pTvZWbQASgXoDoyD/LI/96OU2DhiT3nkIc3
         PAOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jbHifoJEZHsDnDVU1xmdTPP0HEjXTe9hHSw4b0RWnei+4umyS
	OxFQznCsni5m9rBwKcsGjFY=
X-Google-Smtp-Source: ABdhPJxYFdRSxcoVFiGwXJ+ERcCWtS2pTluowiJjbrZPZRZpBkhprbh4kPUhZNIDiEX9qo7/GhT7Ow==
X-Received: by 2002:a25:cc86:: with SMTP id l128mr17054209ybf.239.1610807033711;
        Sat, 16 Jan 2021 06:23:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:42d2:: with SMTP id p201ls4126470yba.8.gmail; Sat, 16
 Jan 2021 06:23:53 -0800 (PST)
X-Received: by 2002:a25:e7d5:: with SMTP id e204mr24878609ybh.375.1610807033230;
        Sat, 16 Jan 2021 06:23:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610807033; cv=none;
        d=google.com; s=arc-20160816;
        b=XN2Ur2L6BuzTi+r7Og0wwPq5XwijvaDltGAvwcEW6AWyunEJy8Ty9nYE3VRT2kKxQI
         9EcF8YDOOAao918WSz9gyGVQPxJAVPwwhOdv8suryCZIA5lfNjCcawVbc71C4L8xEfOt
         PnQ5rRFavbvlQhHdscsGJzTDgoZbvDHAUH+w+ru+GtkYVH1dkUMu6VS1+Y4++Mo/+bC3
         1ceKseoy0Dl0RhfTTQZE22Lzyjr5/9A6VnrwKKIWaFAH8aTyH7K08yQp5C1yYOGD9Mry
         8gMV+XmjDsUFLiYp5qrNX/ouBfmcEharVBQiGNXVtemlPIME1gUzSrmBXOlx7swJuuWV
         SU7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=e395wiELXpPQn77zb/Py/6rwf7pHg/zkPCAw8xC29W4=;
        b=jbC1rpeyhH2M5Zgy9zIFQ38n7oZtfCUCsCT5LvBTvqoH1oqep7b4+mf5wYrWOfWD1f
         cYNXAP/C1ww6g46PAYR9C2ziQ2HqPxIBjfEwZ/91L+/Wa7vwbuK8NOIFFCo2XoOU++aw
         tFI5E3EC7yDCwAxnClqMRsrSL5Tu1WHgvQYe1LQKcfxqoyphNRG4LIJu6f62S7O4LVDZ
         PwUTM9zUcIbjxSExFe7UoAbyI2lqBo0I1GespOmYfc9C+IhJP39ymS2tKUvkiXoO6I+9
         RKQ8eIviKT7VxGn5lbrQb7Zqv6it9P8CkjsJMfmtyECKjm062+IwZctFuItgZcXLc05d
         5u9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r12si1113270ybc.3.2021.01.16.06.23.53
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 06:23:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D70F11396;
	Sat, 16 Jan 2021 06:23:52 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BD9563F719;
	Sat, 16 Jan 2021 06:23:49 -0800 (PST)
Subject: Re: [PATCH] kasan: fix HW_TAGS boot parameters
To: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <83972adc-420b-ca38-3672-b39a5618bd32@arm.com>
Date: Sat, 16 Jan 2021 14:27:37 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/15/21 6:53 PM, Andrey Konovalov wrote:
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

Since it is a fix could you please add the "Fixes:" tag.

Otherwise:

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

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
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83972adc-420b-ca38-3672-b39a5618bd32%40arm.com.
