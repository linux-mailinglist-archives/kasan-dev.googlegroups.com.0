Return-Path: <kasan-dev+bncBDXZVT534IJRB47PRPCQMGQE43ATEGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D4CBBB29E70
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:53:12 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce8fa3b1sf1958970fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 02:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755510772; cv=pass;
        d=google.com; s=arc-20240605;
        b=XGOORnignyp0oZVSyZSEW1xVoOdW4zunHue+gk77Lmh7vVzxWT8jkD1kPAoIhmHma0
         4EhSx5MunnkfPnOj06bljNQLKjQ7ATBr8Bm1+8Swttl0qzcjti72mCEMdwcJWAc5iy8A
         wH9SITOAhAyEtR6FuHjywj/BQo5mYBWsp+oj2c9kPkd7O2gBUe6SHME/7C485UU+KuDT
         RAAUY8vp7gbVB0I47iqovy7ulT4FmVCrR1LC/NnbwL8Q/KjpZ5ox2ivOL/3xkftqun4a
         Z8cBdKeV9KbWszTUQFgwuHgDLJn0ti+mtyvH65FBXK9uLAan7So9jRE/Vpp31t79chUa
         58+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=nExhOnNvOz7XoAtjimN5y+T0ujwKzZgycf6VREXg7SU=;
        fh=xqMJ7qdbqCOQIU2lqHzuzg0dD1vgG+HLXjSdWBCHNBQ=;
        b=ewshvSwB0zIBfqnh2WCTgRw5Ja5MPkDt9YxJlldXkFgmUz9aqUNIenRH8NG8oaJwGT
         AV+HSoJceL5PdvQyJrd/vKMf8Q3Knwu5M2t3TzjzyWkPQSURO4R0IliManT8k67GqT3I
         T/4XVFYtWH7jXt+Fx2v2/O83o8TWNhYOyyHXzSEBo164fslWYP237WyBf0fYuhoALHAD
         ELeKlS5QRNa2qPIjiIcZqoryd7TqhGKoRfCcTOLVwINFFKYuEwwyJSwfy8jJs8Eoluvd
         gTQpYICO4OsA4ED7hcLI70De0x5DiClTEK1o6GspnnhseEaYRq/faGbOtWRrX4JX71BU
         WT9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ben.horgan@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ben.horgan@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755510772; x=1756115572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nExhOnNvOz7XoAtjimN5y+T0ujwKzZgycf6VREXg7SU=;
        b=opu0XjdWUL5yh83Odzs25gLH/WUN3CltW4SNnkX7xZOuO1ifzt33tiM3OYPHU/kf56
         K9A6mCl+LrznIYIVXVIg5yOvxxAdYkhwRWAZUfb08lliMnoghIfnWt4Iwt3+kdZXz5VL
         59EaGAet2V/uWpYhQErLvaa8SYJz6jdN6vWO7hyd3rys8eZbjiLhSCe0GF+l7/Cv9OUD
         dSb7C+EYtrpW7MFN5niUm5bvZlQJmrcMcnkQID4XcFWR4iDSkEmrlQUX21oHUa803VhX
         uZ94Ztc2DwPrPqk5bV6xMF5dLOTqWx/hJvKwkGMzVJheGrrxcFrOAUQ7Oinmbbgiuiot
         M4LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755510772; x=1756115572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nExhOnNvOz7XoAtjimN5y+T0ujwKzZgycf6VREXg7SU=;
        b=rwW3cWZEZACOQNuadkBlxHhpfr/tm9J32GqkfJFLI5GOjGA9+CjInyykRAGkQ1psKj
         c45+Z/7dQOxlkmQHr6R3x1QZ129NiWQjvi7DoCPD6x4Co/qf+/xY2kuyturDB43kyFcv
         Zr8fPjw0alTzhD+80TtNoozix0qfdbR1L8Yu9WJhwc8d0xJAT1AS5Brh4ZuyNoH4uaGj
         tWITXWaf0U/XAx11JdQ4xhl4p4IUIarqL+XoI/Y4Y2uzEIBiBTPSsWFCpnYO7Dm7TO5N
         d875DkI1iSEQ6EwFx9uSYLF7ZLqADW5Q5icRrKoU4BHlc59ZKcQ766F/I05W5rfmweH8
         A2wA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2oXIA3DR5vMRg9ud1P2WwdxZgmX9xZ8zehQJssdnNnGm0Qa5a7Qh2UfLLu83QmHgyEb3LEw==@lfdr.de
X-Gm-Message-State: AOJu0YzHCLuZAEdpC5drsaUsWsDxUnAIbXXUz00OKbjh7fgF4Hwy4MyM
	yPVG2qBW+UhkJrH/vLMXcIX5c1FJg+IhjCaiD7rMnccCKoTwOj+aAbE1
X-Google-Smtp-Source: AGHT+IFznnR6jLxayBkHvB9zyCWDW/iCESsC1X4F6FK3JpTGUpO5TjYlt6ilRWUmwgDBZVhSH5GmyQ==
X-Received: by 2002:a05:6871:5821:b0:30c:b54:ed77 with SMTP id 586e51a60fabf-310be633195mr5212747fac.19.1755510771749;
        Mon, 18 Aug 2025 02:52:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfMR+yMgiE6Re1ym2cZK74Wbv25y16Ho8NeipwihhDIXQ==
Received: by 2002:a05:6871:4b0e:b0:30b:7ec0:8afb with SMTP id
 586e51a60fabf-30cce448836ls1296238fac.2.-pod-prod-04-us; Mon, 18 Aug 2025
 02:52:50 -0700 (PDT)
X-Received: by 2002:a05:6830:6309:b0:742:fc4d:6615 with SMTP id 46e09a7af769-7439ba900aamr4928845a34.18.1755510770523;
        Mon, 18 Aug 2025 02:52:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755510770; cv=none;
        d=google.com; s=arc-20240605;
        b=VFJDhhVhfPz3iV7fE74XhThzy6escE7YUf/zDoWqdc7JHP3l+9o6MF+gdCmm9AiEep
         ARNT/Bau1ZZYq1sZfPgAB6L75gB8zneeNFYEAYbzfSssOyp6SPLWQf5UfmPTaUtWdkY5
         Pi11tFAzMClCPvyC4GVE10st8UhYDd2YAQYTYPhsA7vF3wst2N0k/Tc4vc6w2XrWEkdk
         4sfvpfK/VuSlvlhoN44wLbp0xXDnMBc7TvBAuzWesxu5V4w/0ePk3fPaHIzH7scCNpgn
         XRkgLDLl3Ai/ZkDM9DxidUWlBsy4w+STYRvT/hsKIS8Tn3zj9zUDOzuGQ+mKlVxx9dzU
         xXaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=vAyGMsNO5MqtCEuECkJvS2htOljGLG6x5/G5la1l6Vs=;
        fh=uepVbQbKL9ezqxKJSkDZZIsqzT+gxHTFoDaGvNyuePA=;
        b=NJfr39Ly1cPJ5X1plJxQnUgKiPdbhpjHdxo29V1Lv3gfSkCe8zSNvGz+uLGzApKwLI
         DTgBufI+HnIEiXAkA2jXmMpKqe3zpx/yfZe328Uz7Li51e2aA92E4Nv8KvyMasTCl4l0
         f7pb7qLyo3O8Hjy3ekmdYIm+dlK72lGXzmYqBxteo9y/Yiaifr3RKpvh/HoEUDCgdhH5
         y3xNug5hC5AJ/U688z5zE9FRp0IclSP8csouss6rKWH1ptoVzRPjyfiT3R9g9eWW9ZI+
         Ms6twzZZhKz5UAUVp4A5GjQae3SkjObCMGUPOrl4ss67/kXZd00aGrsKCz6mwdcrNoy5
         Y4YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ben.horgan@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ben.horgan@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-74392039538si360167a34.4.2025.08.18.02.52.50
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Aug 2025 02:52:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of ben.horgan@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C8C0A1596;
	Mon, 18 Aug 2025 02:52:41 -0700 (PDT)
Received: from [10.1.196.46] (e134344.arm.com [10.1.196.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 09BE63F63F;
	Mon, 18 Aug 2025 02:52:45 -0700 (PDT)
Message-ID: <2736fe09-ef37-408c-ba53-a8e492dcc3e8@arm.com>
Date: Mon, 18 Aug 2025 10:52:44 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 1/2] kasan/hw-tags: introduce kasan.write_only option
To: Yeoreum Yun <yeoreum.yun@arm.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
 will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com,
 jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org,
 kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org,
 oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org,
 hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
 yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
References: <20250818075051.996764-1-yeoreum.yun@arm.com>
 <20250818075051.996764-2-yeoreum.yun@arm.com>
Content-Language: en-US
From: Ben Horgan <ben.horgan@arm.com>
In-Reply-To: <20250818075051.996764-2-yeoreum.yun@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: ben.horgan@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ben.horgan@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ben.horgan@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Hi Yeoreum,

On 8/18/25 08:50, Yeoreum Yun wrote:
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN write only mode based on this feature.
> 
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
> 
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=on", KASAN checks write operation only otherwise
> KASAN checks all operations.
> 
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>   Documentation/dev-tools/kasan.rst  |  3 ++
>   arch/arm64/include/asm/memory.h    |  1 +
>   arch/arm64/include/asm/mte-kasan.h |  6 ++++
>   arch/arm64/kernel/cpufeature.c     |  2 +-
>   arch/arm64/kernel/mte.c            | 18 ++++++++++
>   mm/kasan/hw_tags.c                 | 54 ++++++++++++++++++++++++++++--
>   mm/kasan/kasan.h                   |  7 ++++
>   7 files changed, 88 insertions(+), 3 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 0a1418ab72fd..fe1a1e152275 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
>     Asymmetric mode: a bad access is detected synchronously on reads and
>     asynchronously on writes.
>   
> +- ``kasan.write_only=off`` or ``kasan.write_only=on`` controls whether KASAN
> +  checks the write (store) accesses only or all accesses (default: ``off``)
> +
>   - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
>     allocations (default: ``on``).
>   
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 5213248e081b..f1505c4acb38 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>   #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
>   #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
>   #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
> +#define arch_enable_tag_checks_write_only()	mte_enable_kernel_store_only()
>   #define arch_suppress_tag_checks_start()	mte_enable_tco()
>   #define arch_suppress_tag_checks_stop()		mte_disable_tco()
>   #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 2e98028c1965..0f9b08e8fb8d 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
>   void mte_enable_kernel_sync(void);
>   void mte_enable_kernel_async(void);
>   void mte_enable_kernel_asymm(void);
> +int mte_enable_kernel_store_only(void);
>   
>   #else /* CONFIG_ARM64_MTE */
>   
> @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
>   {
>   }
>   
> +static inline int mte_enable_kernel_store_only(void)
> +{
> +	return -EINVAL;
> +}
> +
>   #endif /* CONFIG_ARM64_MTE */
>   
>   #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index 9ad065f15f1d..505bd56e21a2 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2920,7 +2920,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
>   	{
>   		.desc = "Store Only MTE Tag Check",
>   		.capability = ARM64_MTE_STORE_ONLY,
> -		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
> +		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
>   		.matches = has_cpuid_feature,
>   		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>   	},
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e773844889..cd5452eb7486 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -157,6 +157,24 @@ void mte_enable_kernel_asymm(void)
>   		mte_enable_kernel_sync();
>   	}
>   }
> +
> +int mte_enable_kernel_store_only(void)
> +{
> +	/*
> +	 * If the CPU does not support MTE store only,
> +	 * the kernel checks all operations.
> +	 */
> +	if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
> +		return -EINVAL;
Would it be better to make this function return void and add a static 
key in the manner of mte_async_or_asymm_mode, perhaps 
mte_store_only_mode? This information could then be used to help 
determine whether it is required to enable and disable tco in 
__get_kernel_nofault() and load_unaligned_zeropad(). The function 
signature would also match that of the other hw_enable_tag_...().

> +
> +	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
> +			 SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
> +	isb();
> +
> +	pr_info_once("MTE: enabled stonly mode at EL1\n");
nit: stonly can be expanded to store only
> +
> +	return 0;
> +}
>   #endif
>   
>   #ifdef CONFIG_KASAN_HW_TAGS
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..df67b48739b4 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
>   	KASAN_ARG_VMALLOC_ON,
>   };
>   
> +enum kasan_arg_write_only {
> +	KASAN_ARG_WRITE_ONLY_DEFAULT,
> +	KASAN_ARG_WRITE_ONLY_OFF,
> +	KASAN_ARG_WRITE_ONLY_ON,
> +};
> +
>   static enum kasan_arg kasan_arg __ro_after_init;
>   static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>   static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> +static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
>   
>   /*
>    * Whether KASAN is enabled at all.
> @@ -67,6 +74,8 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>   #endif
>   EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>   
> +static bool kasan_flag_write_only;
> +
>   #define PAGE_ALLOC_SAMPLE_DEFAULT	1
>   #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
>   
> @@ -141,6 +150,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
>   }
>   early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
>   
> +/* kasan.write_only=off/on */
> +static int __init early_kasan_flag_write_only(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
> +	else if (!strcmp(arg, "on"))
> +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_ON;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.write_only", early_kasan_flag_write_only);
> +
>   static inline const char *kasan_mode_info(void)
>   {
>   	if (kasan_mode == KASAN_MODE_ASYNC)
> @@ -257,15 +283,26 @@ void __init kasan_init_hw_tags(void)
>   		break;
>   	}
>   
> +	switch (kasan_arg_write_only) {
> +	case KASAN_ARG_WRITE_ONLY_DEFAULT:
> +	case KASAN_ARG_WRITE_ONLY_OFF:
> +		kasan_flag_write_only = false;
> +		break;
> +	case KASAN_ARG_WRITE_ONLY_ON:
> +		kasan_flag_write_only = true;
> +		break;
> +	}
> +
>   	kasan_init_tags();
>   
>   	/* KASAN is now initialized, enable it. */
>   	static_branch_enable(&kasan_flag_enabled);
>   
> -	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
> +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s\n",
>   		kasan_mode_info(),
>   		str_on_off(kasan_vmalloc_enabled()),
> -		str_on_off(kasan_stack_collection_enabled()));
> +		str_on_off(kasan_stack_collection_enabled()),
> +		str_on_off(kasan_arg_write_only));
>   }
>   
>   #ifdef CONFIG_KASAN_VMALLOC
> @@ -392,6 +429,13 @@ void kasan_enable_hw_tags(void)
>   		hw_enable_tag_checks_asymm();
>   	else
>   		hw_enable_tag_checks_sync();
> +
> +	if (kasan_arg_write_only == KASAN_ARG_WRITE_ONLY_ON &&
> +	    hw_enable_tag_checks_write_only()) {
> +		kasan_arg_write_only == KASAN_ARG_WRITE_ONLY_OFF;
> +		kasan_flag_write_only = false;
> +		pr_warn_once("System doesn't support write-only option. Disable it\n");
> +	}
>   }
>   
>   #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> @@ -404,4 +448,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
>   }
>   EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
>   
> +VISIBLE_IF_KUNIT bool kasan_write_only_enabled(void)
> +{
> +	return kasan_flag_write_only;
> +}
> +EXPORT_SYMBOL_IF_KUNIT(kasan_write_only_enabled);
> +
>   #endif
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..c1490136c96b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -428,6 +428,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>   #define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
>   #define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
>   #define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
> +#define hw_enable_tag_checks_write_only()	arch_enable_tag_checks_write_only()
>   #define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
>   #define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
>   #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
> @@ -437,11 +438,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>   			arch_set_mem_tag_range((addr), (size), (tag), (init))
>   
>   void kasan_enable_hw_tags(void);
> +bool kasan_write_only_enabled(void);
>   
>   #else /* CONFIG_KASAN_HW_TAGS */
>   
>   static inline void kasan_enable_hw_tags(void) { }
>   
> +static inline bool kasan_write_only_enabled(void)
> +{
> +	return false;
> +}
> +
>   #endif /* CONFIG_KASAN_HW_TAGS */
>   
>   #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)

Thanks,

Ben

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2736fe09-ef37-408c-ba53-a8e492dcc3e8%40arm.com.
