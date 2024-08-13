Return-Path: <kasan-dev+bncBC7PZX4C3UKBBVOA5S2QMGQEFEPU5OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3635950091
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 10:59:02 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-428040f49f9sf37768455e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 01:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723539542; cv=pass;
        d=google.com; s=arc-20160816;
        b=fdBoo6DWDWcPwB+QWKcNMNxjDAeUlh1Rw4fVAp0UqbJcMTH6pEXSETyao/NLANO0Zo
         V7WK3A0QRVaL5x+5huxII1r82+Zmf/2k1IlZXNicRGbRdLBZEJ91kLI6bjTSU5mbT60+
         LcPKWrM/TBsaoq7wVcoGnzWS+yUWfOuXhZP4D92auVGGXf9nttpyedhG5kRl5Rv69piy
         lZ758u+XPPGytW5RtQl8wlRrsOdUGskE5Bj7d/llQI3rgNxUaT5Zf21BNn4MozA7M2+r
         JzobBNLL9k3XveFdmuEbVWppRyF4dzgmJY/j/K2asFZJWEKcxz6yO5EGCiptf84VL036
         ZJ8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=l4aL8Q8s3Mo+Rhi01esyUOjBaCw3k8f2vqYX5FF/9sU=;
        fh=46O1HcWz/LVvG81EWPHUlNG0nnC9GUVq+gO4NDvMsLo=;
        b=cArNT+5+422K7BpX+jPyaOivD0fPbqbnmoEKPh0dqXtDz+33WBvxzhXyR0GJApD8/D
         sGf0Tlw7Uvi8peSPGpj7pA5yl9FPKsHOJqkUSLqAGcIXy2Nd8jp5q/mYe1Jlca0FFLp9
         QjKkAvj3LTVKNrXv7P/mCLwPaHlSFHhorv771merPg5dxJe21fS9lIBrdx2gnb69pVxh
         GItDx6qAWEQNA49nd6CKt9Rai1gOUmxdaH4O81vJORBnuOPvrFFzmI02F/3D51fGZef+
         XdWW836CEv+X1SUTTFkibELDgCHhyzLFODKOLKDVXVM6Ca26eHVe+d6vjjez3Urvk+uz
         iREg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.201 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723539542; x=1724144342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l4aL8Q8s3Mo+Rhi01esyUOjBaCw3k8f2vqYX5FF/9sU=;
        b=DvmLb7fMCRDvOYkL4lnQvusBLsCrfUtVWfWzDT2fUuhlxOy3UvjOw+nR6319fsaalK
         J3CpcyeOak499kRGJPL8gDwZvjgrY2DW2EQnWX4ridR7mlXGx3ZD2C6Eh6HXo2m/VtG5
         GOSoj9dZTcNXSkrrzaVgmllG+7vhtf13kvOIT0bVMxiA0U8vQ+jOOJQyIJW10bcNTVEK
         cXdAy/Gt2rUdT/ySVFgosg66KIJ9q5GC2qN2PfQzI/dg+zrI0tlJynAN6GDm+jkP8dzI
         a8LdEWokdosdRdmgieh+wpd4JKCF7sLToyswxSLFhhwJQuAzGcDRuDf35+1NlAFjXdWz
         7uHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723539542; x=1724144342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l4aL8Q8s3Mo+Rhi01esyUOjBaCw3k8f2vqYX5FF/9sU=;
        b=YZPq/DX9wV0Ru5I6+TrKhqPTc4SHaZOgnzd9nycbw75XcLAxJD9Fwy1mCy6JRWaODd
         W7KYmx3BaolcLby8OTCgDzji5St1JAgGD5/xuOStIMUHbqNNHxyeMaOuGmQg+2+ci4gZ
         pfzfvG+DuqXNcBRzZbCP47UQ7HWbemuGqsx+uTeQjPBWR1kla8NZ1leLt7Vty8oRdoAQ
         /jDdiof+WD3W7ieGTHrR4PLFJoSKI2YdN0o4PuWNtbY9hom9oLp1IzzdznOhhm057LBR
         hXBOcCX3nXzUgGhQycFdHdMG8puuJNR5NPxH/uyYotby/NLRPoTMCCwQdvBmXz/xDIu0
         0i0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4kBVOmjSTlYjQcbG4GvLzAW0HdKGi6k8ocaWBAmQIGne6TDUDpyyWO1rPL3iowrRGm23Dprhg02IZDWVOztDP4IChlmvg+w==
X-Gm-Message-State: AOJu0YxmDuKMPPogW62LInAC6KEtfc6F6IM21Mjxh82MgMs03zBvQF+y
	Sxa+YZINanYOL8TmZeklqRxzyWVwIfu3DR7W4Ne328t7c2HqK2oF
X-Google-Smtp-Source: AGHT+IEIDmBFcoqSISDkxOHnK2jNlNqdmdwcZWKuQY2ARSSJHQ9e1TYUpvbhcBacwsIU8Jyi8oLmHA==
X-Received: by 2002:a05:600c:3147:b0:426:6f81:d235 with SMTP id 5b1f17b1804b1-429d480c135mr24863785e9.15.1723539541718;
        Tue, 13 Aug 2024 01:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3baa:b0:426:6982:f5de with SMTP id
 5b1f17b1804b1-4290918e871ls25046555e9.1.-pod-prod-08-eu; Tue, 13 Aug 2024
 01:58:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuJmQj+C7NGY0fK3dSanV8r7qtwA2x5XTDQu4nTyJYtj5ZXAuE/lbAn1KvWevYB61lyj60qPlLByEbkVDlLFwdF1oIYc/+GkTpgg==
X-Received: by 2002:a05:600c:3547:b0:426:6773:17 with SMTP id 5b1f17b1804b1-429d486fe90mr19107495e9.30.1723539539430;
        Tue, 13 Aug 2024 01:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723539539; cv=none;
        d=google.com; s=arc-20160816;
        b=y9ZiLHQY0iMA+0whSuxVHUWaJ7srGSmFBBKSUysO8pgJVQzq7teM7ypnpV4nPtAXk0
         w7azf7krVkGRcCUXDcnLckqME3j0G5q97lBdls0+OkyftDFNPAiC+aYq/sR1+FgnxjWG
         48C/XOTbBh7jCP5CcoCJUfNoJlItLDhs+5wmrGn6sQBjhAarK4+Cx09SEzRynYw0K7nC
         yeJkumFX93lJajgM8VzZJynEJPUpVPUolbIYkmmHQIAYVpMqnoTADsRcjHplTCegfhTo
         u6M5Wgr6HBY5eo1Ivmyly0u/yt4t7jfIOQAjXj1HyH9EBZU1x1y0/EIfQnGA9QfWeema
         yxxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=JZVhBRH2OXTOpl6xLSnMMEoK7nsMOOP9pK/VNab/JPQ=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=Sls22x2+H1nZAuZn2lxtaofSlc7264hKv73NEP/SppD2F33+GEaXVxxChBE6hpGQIj
         2vrafyFpQ1pPLTe22oX0GY0H3+PF2M3Qkv8m5u4g3OYYCnVDLb72vru/0WyVBrDbDUCT
         WLpZ2b7u9Tx6vlzKHta4/YtjU0lLHZ8uZ0cIZHmjMaISSCsfj7ruvmGLa/LoLrsRjMS+
         4x6SIZSSLLgIudq4hyHRO4iRsV7047dsIjCF8Up1WusdtUB1kbuKFgO/eNdYMOQcAtlF
         sL1VedcZRI75WoY/Ua5nt8Ul3jbWgkZJ8q/zcXeDRlRniIgPFWGMbQe+9EWmjUFzwAIK
         wfRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.201 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay8-d.mail.gandi.net (relay8-d.mail.gandi.net. [217.70.183.201])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4290c72f036si2145885e9.0.2024.08.13.01.58.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 Aug 2024 01:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 217.70.183.201 as permitted sender) client-ip=217.70.183.201;
Received: by mail.gandi.net (Postfix) with ESMTPSA id A192E1BF207;
	Tue, 13 Aug 2024 08:58:56 +0000 (UTC)
Message-ID: <440ca2a7-9dfb-45cd-8331-a8d0afff47d0@ghiti.fr>
Date: Tue, 13 Aug 2024 10:58:55 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 04/10] riscv: Add support for userspace pointer masking
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-5-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20240625210933.1620802-5-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 217.70.183.201 as permitted
 sender) smtp.mailfrom=alex@ghiti.fr
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

Hi Samuel,

On 25/06/2024 23:09, Samuel Holland wrote:
> RISC-V supports pointer masking with a variable number of tag bits
> (which is called "PMLEN" in the specification) and which is configured
> at the next higher privilege level.
>
> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
> so userspace can request a lower bound on the  number of tag bits and
> determine the actual number of tag bits. As with arm64's
> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
> thread-scoped, inherited on clone() and fork() and cleared on execve().
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v2:
>   - Rebase on riscv/linux.git for-next
>   - Add and use the envcfg_update_bits() helper function
>   - Inline flush_tagged_addr_state()
>
>   arch/riscv/Kconfig                 | 11 ++++
>   arch/riscv/include/asm/processor.h |  8 +++
>   arch/riscv/include/asm/switch_to.h | 11 ++++
>   arch/riscv/kernel/process.c        | 99 ++++++++++++++++++++++++++++++
>   include/uapi/linux/prctl.h         |  3 +
>   5 files changed, 132 insertions(+)
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index b94176e25be1..8f9980f81ea5 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -505,6 +505,17 @@ config RISCV_ISA_C
>   
>   	  If you don't know what to do here, say Y.
>   
> +config RISCV_ISA_POINTER_MASKING
> +	bool "Smmpm, Smnpm, and Ssnpm extensions for pointer masking"
> +	depends on 64BIT
> +	default y
> +	help
> +	  Add support for the pointer masking extensions (Smmpm, Smnpm,
> +	  and Ssnpm) when they are detected at boot.
> +
> +	  If this option is disabled, userspace will be unable to use
> +	  the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
> +
>   config RISCV_ISA_SVNAPOT
>   	bool "Svnapot extension support for supervisor mode NAPOT pages"
>   	depends on 64BIT && MMU
> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
> index 0838922bd1c8..4f99c85d29ae 100644
> --- a/arch/riscv/include/asm/processor.h
> +++ b/arch/riscv/include/asm/processor.h
> @@ -194,6 +194,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
>   #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)	riscv_set_icache_flush_ctx(arg1, arg2)
>   extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long per_thread);
>   
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
> +long get_tagged_addr_ctrl(struct task_struct *task);
> +#define SET_TAGGED_ADDR_CTRL(arg)	set_tagged_addr_ctrl(current, arg)
> +#define GET_TAGGED_ADDR_CTRL()		get_tagged_addr_ctrl(current)
> +#endif
> +
>   #endif /* __ASSEMBLY__ */
>   
>   #endif /* _ASM_RISCV_PROCESSOR_H */
> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
> index 9685cd85e57c..94e33216b2d9 100644
> --- a/arch/riscv/include/asm/switch_to.h
> +++ b/arch/riscv/include/asm/switch_to.h
> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return false; }
>   #define __switch_to_fpu(__prev, __next) do { } while (0)
>   #endif
>   
> +static inline void envcfg_update_bits(struct task_struct *task,
> +				      unsigned long mask, unsigned long val)
> +{
> +	unsigned long envcfg;
> +
> +	envcfg = (task->thread.envcfg & ~mask) | val;
> +	task->thread.envcfg = envcfg;
> +	if (task == current)
> +		csr_write(CSR_ENVCFG, envcfg);
> +}
> +
>   static inline void __switch_to_envcfg(struct task_struct *next)
>   {
>   	asm volatile (ALTERNATIVE("nop", "csrw " __stringify(CSR_ENVCFG) ", %0",
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index e4bc61c4e58a..dec5ccc44697 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -7,6 +7,7 @@
>    * Copyright (C) 2017 SiFive
>    */
>   
> +#include <linux/bitfield.h>
>   #include <linux/cpu.h>
>   #include <linux/kernel.h>
>   #include <linux/sched.h>
> @@ -171,6 +172,10 @@ void flush_thread(void)
>   	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
>   	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
>   #endif
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
> +#endif

if (IS_ENABLED(CONFIG_RISCV_ISA_POINTER_MASKING) && 
riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))


>   }
>   
>   void arch_release_task_struct(struct task_struct *tsk)
> @@ -233,3 +238,97 @@ void __init arch_task_cache_init(void)
>   {
>   	riscv_v_setup_ctx_cache();
>   }
> +
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +static bool have_user_pmlen_7;
> +static bool have_user_pmlen_16;
> +
> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
> +{
> +	unsigned long valid_mask = PR_PMLEN_MASK;
> +	struct thread_info *ti = task_thread_info(task);
> +	unsigned long pmm;
> +	u8 pmlen;
> +
> +	if (is_compat_thread(ti))
> +		return -EINVAL;
> +
> +	if (arg & ~valid_mask)
> +		return -EINVAL;
> +
> +	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
> +	if (pmlen > 16) {
> +		return -EINVAL;
> +	} else if (pmlen > 7) {
> +		if (have_user_pmlen_16)
> +			pmlen = 16;
> +		else
> +			return -EINVAL;
> +	} else if (pmlen > 0) {
> +		/*
> +		 * Prefer the smallest PMLEN that satisfies the user's request,
> +		 * in case choosing a larger PMLEN has a performance impact.
> +		 */
> +		if (have_user_pmlen_7)
> +			pmlen = 7;
> +		else if (have_user_pmlen_16)
> +			pmlen = 16;
> +		else
> +			return -EINVAL;
> +	}
> +
> +	if (pmlen == 7)
> +		pmm = ENVCFG_PMM_PMLEN_7;
> +	else if (pmlen == 16)
> +		pmm = ENVCFG_PMM_PMLEN_16;
> +	else
> +		pmm = ENVCFG_PMM_PMLEN_0;
> +
> +	envcfg_update_bits(task, ENVCFG_PMM, pmm);
> +
> +	return 0;
> +}
> +
> +long get_tagged_addr_ctrl(struct task_struct *task)
> +{
> +	struct thread_info *ti = task_thread_info(task);
> +	long ret = 0;
> +
> +	if (is_compat_thread(ti))
> +		return -EINVAL;
> +
> +	switch (task->thread.envcfg & ENVCFG_PMM) {
> +	case ENVCFG_PMM_PMLEN_7:
> +		ret |= FIELD_PREP(PR_PMLEN_MASK, 7);
> +		break;
> +	case ENVCFG_PMM_PMLEN_16:
> +		ret |= FIELD_PREP(PR_PMLEN_MASK, 16);
> +		break;
> +	}


No need for the |=


> +
> +	return ret;
> +}


In all the code above, I'd use a macro for 7 and 16, something like 
PMLEN[7|16]?


> +
> +static bool try_to_set_pmm(unsigned long value)
> +{
> +	csr_set(CSR_ENVCFG, value);
> +	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
> +}
> +
> +static int __init tagged_addr_init(void)
> +{
> +	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +		return 0;
> +
> +	/*
> +	 * envcfg.PMM is a WARL field. Detect which values are supported.
> +	 * Assume the supported PMLEN values are the same on all harts.
> +	 */
> +	csr_clear(CSR_ENVCFG, ENVCFG_PMM);
> +	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
> +	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);


Shouldn't this depend on the satp mode? sv57 does not allow 16bits for 
the tag.


> +
> +	return 0;
> +}
> +core_initcall(tagged_addr_init);


Any reason it's not called from setup_arch()? I see the vector extension 
does the same; just wondering if we should not centralize all this early 
extensions decisions in setup_arch() (in my Zacas series, I choose the 
spinlock implementation in setup_arch()).


> +#endif	/* CONFIG_RISCV_ISA_POINTER_MASKING */
> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
> index 35791791a879..6e84c827869b 100644
> --- a/include/uapi/linux/prctl.h
> +++ b/include/uapi/linux/prctl.h
> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>   # define PR_MTE_TAG_MASK		(0xffffUL << PR_MTE_TAG_SHIFT)
>   /* Unused; kept only for source compatibility */
>   # define PR_MTE_TCF_SHIFT		1
> +/* RISC-V pointer masking tag length */
> +# define PR_PMLEN_SHIFT			24
> +# define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)


I don't understand the need for this shift, can't userspace pass the 
pmlen value directly without worrying about this?


>   
>   /* Control reclaim behavior when allocating memory */
>   #define PR_SET_IO_FLUSHER		57

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/440ca2a7-9dfb-45cd-8331-a8d0afff47d0%40ghiti.fr.
