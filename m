Return-Path: <kasan-dev+bncBDHJX64K2UNBBTVVR23QMGQENZMIGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id BF88597768E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:52:15 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7a9a85e4a85sf86613885a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 18:52:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726192334; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJTWE1eZEoWaXq3/NA3OTb59qTUi2IPIRDmhgT98BmEriJiMgBHsa1mmlctzKjrHi9
         pdODVbGyTJj1i4t7rGH7BVm9L3ygfA3MH7NIYIESBtVFLWbZJLQLmYPULNe5AgVXLkRz
         Sr0WNW5WtL1fKGm84fOq0NGcpqdKshX+GYHKjHPwTuuPk7L3zA2wEOumHojVpqpDa5+Q
         3uWakKc5g1/kWaCrl+JbnplISBPQVTGdxiBTaqLYqeho1nUnjegr8E7XjfuMx17duC+q
         mVcRpBL0u3DrSYqX4Hg0W+HBTaBugBcOZk59V2Km+QQ0i7M/XXgpUW5wUyyikhYna4As
         wu8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qzFkDjk3kkAmiP4wEVYK3qZpEP8FgbbqenbpCu/p+aU=;
        fh=vSs5NidQf6nfJOo498mNKkO5lzYTi0nd60JzsjVrJZw=;
        b=ExxtSGC4hCD1Fswgp5JbznvyCZusEz0BVxbfY2n2dtXrGPY0dwBtTEgr1lai1cGPxv
         jhBRMmGvGjaqRdWmYxL8xVfsJN18YMkcbz/IYazlY9fxh4iojcea7jb/u/FhEl5qADtC
         FqkfDuDKBci86uK6+9zAQuh1BeaoU5hAtjGdXRJ8e9FX8E2PZclMDtR4Atd3wT+wDZSQ
         kn10Q9aBAJVKZkP/c1WHE9foLrlmZGb1YJO1z0MMjK45ZzhHTh+/4NK0XKzzibu/Nloo
         u4FNDzHewVC0mJjVnmaSn5tDfFbWM5tlfEDtAuE7l5nzGdSmLJl9vNpsfwqKoyxABtZV
         +z5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=smANQyPq;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726192334; x=1726797134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qzFkDjk3kkAmiP4wEVYK3qZpEP8FgbbqenbpCu/p+aU=;
        b=Sc4kjSwUo/NF6x821Q4p7TONsuJafra7w4+G1+27023xLyQo8Y8Bwb6tV8ERZdtbrS
         4nOx5UHJDdUxp/WKBhTjZlCuBI8BMxYp4BTCQYCbJMSUtPscn6YbUf48M0ya5YqeFlp1
         oCC0SQmDu1c1bkD6EZGN8yRY9TnVLO1088StVDBW3FO0cj3jZ+m3iBvl6f3ev1+FR7Ka
         P8AtQ5N0C8O98w56WWA467wirgbsghdHrw+R9vEClrpl7QB1PCjY7rV14/Av46O4agLp
         ULRSuzGPWHYG9ymm/qdaXex2T+luIV+ridxAfxROKgB0YL0UoPGvDoMu5s8iPrUJl/Qs
         aERg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726192334; x=1726797134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qzFkDjk3kkAmiP4wEVYK3qZpEP8FgbbqenbpCu/p+aU=;
        b=guX/saCbPB4jqSNh0FPu990ww7DCBXIilq2G/oATyhv1DIjr6WtZeDLmqX+3E0hn6E
         HLBia5sbukDkehOTpGyoD7tOmlFhm5MYG8ggeneNGsFdIbgD3B5bTgRSKTaFbR34QBA7
         l59LSybkNVc74do7e46erj+yB0y5j6AVRNq/ANFrI0MRdAmFLFk6mgO7WwgH7Y6d/nLP
         w3z6xsk5gJX94xHzvyXIGRE2943CO1bYF3OAq/M6CQXgJ4QcsnmxOt4pi6wXf9Y0DmCr
         3+/9EME3gJxrT+Lnc78aQYrYe0G5XSQPVBP+2+f+0u0iEycZwE2rbW7dBVMwph18cyiZ
         Ukuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1pMP52Ov4Gx/9sgBt9JslrkZkVyt09x1XoRqm/uR1w8ZAaG+VNvmoHW9qxJkhnD/go9kdQg==@lfdr.de
X-Gm-Message-State: AOJu0Ywhtw55Srh48SrswnClI9JcRfFsXiNwrOo9S61Z3+r4FnQ2u6yR
	npKsrkTjtzeuSNhZ5WQxiFe5oSvR3I7bIibLVquViohpEAVV7clM
X-Google-Smtp-Source: AGHT+IEvyZ4ZIkJ4aKJwXBiJQfmB8+yxaQ4ANLwHqGxOK+8qUTtErq32amhsHvoWyKmr2UIb7E2c8A==
X-Received: by 2002:a05:6214:5f0c:b0:6c3:508a:fec6 with SMTP id 6a1803df08f44-6c57dfa3455mr18979036d6.17.1726192334290;
        Thu, 12 Sep 2024 18:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c0e:b0:6bd:735f:a70e with SMTP id
 6a1803df08f44-6c5733293b4ls27302646d6.0.-pod-prod-06-us; Thu, 12 Sep 2024
 18:52:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAUnbuCv+AfnioxHfovwhnzgsBRdJANCZjoSds12+HpPQeIfzbk/Od6MPZI+vOd6fE2taieQtb9us=@googlegroups.com
X-Received: by 2002:a05:620a:450a:b0:7a9:bc9b:b38 with SMTP id af79cd13be357-7ab30ddd0ecmr171700785a.66.1726192333423;
        Thu, 12 Sep 2024 18:52:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726192333; cv=none;
        d=google.com; s=arc-20240605;
        b=RGnSeXXNbDQ2MfpZwte/FUsDJOYPPq2zFDFs60WvSzQPAu9OLqu2vCib8CehbfeamP
         19ZhjRwbnxPeQUlSU/AGigQl2327mMpQSh5gKIMijIgKAA8+cDrfs9fQ6rEWnsCSUSU2
         762rTE4u5M+TlH1dZVPnWPUhAeAbba3090BHH3+umi/9KBsCXtlzdw6EGpc9anqtbR7j
         ULHodflICzy2LRvlAY7rxPp5RioyS/MchUSddhud+tek36P7K4AH2WTz/D+xaawfAccT
         DXCTO9dBriTc+c5q//4uPLsgSlvNKKJkajenYcEBe24oh8gO4qhowfTkxW/vcE0Hutzk
         eodA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=k+ges+VvxmrgdZD6nkY5IuumPBlR6fNV3QrQLoSkcjs=;
        fh=XPp2aYJikmkXaT6Pn7327vkkdbLPq1LSjryY1MfHohQ=;
        b=ftJEgNqXW0w4AG/GP6VbE7DJQbm6AvEi02DLFNAbxBSMZHfh1s+KVAaXsUT2f+bgrz
         HBnyvK1znpYL1e2JLzds5GLXNDZS9PJoXD+ohw/nGO7yWd053QOkPeVf0b6g0fg+I7Dt
         vW5KLTNf4qhZ+1qTbZbN5lKnCYeQlZEY7ImDjQwlX191XkxgIhjtgJvMWR9JMow/Oknr
         1HjnH2cv5TwBWh961Aq04oDwoS/fCPlxB/oq7kzxvbZWfk7/lKQTUUpY2eHcg8X6//QJ
         L4biqjHqaMajBsUiM12ikCXc26HoTa+NzHxN13saoMwbcOYnDCP/YPMFssVs/xZFps+S
         c8hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=smANQyPq;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a794855csi50423485a.2.2024.09.12.18.52.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 18:52:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2da4ea59658so420340a91.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 18:52:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVyRdTYT/ui5soA2vz2XdNUZYselg1+QWuLgIHfCSCKXCLAEh7quHYgbnwNCnIMS7EkwT/IHit5Ge8=@googlegroups.com
X-Received: by 2002:a17:90b:1e4c:b0:2d3:dd48:992c with SMTP id 98e67ed59e1d1-2dbb9e47099mr1670673a91.23.1726192332239;
        Thu, 12 Sep 2024 18:52:12 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2dbb9d953a6sm407052a91.56.2024.09.12.18.52.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 18:52:11 -0700 (PDT)
Date: Thu, 12 Sep 2024 18:52:09 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 04/10] riscv: Add support for userspace pointer masking
Message-ID: <ZuOayQEfZZeDWW7b@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-5-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-5-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=smANQyPq;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:26PM -0700, Samuel Holland wrote:
> RISC-V supports pointer masking with a variable number of tag bits
> (which is called "PMLEN" in the specification) and which is configured
> at the next higher privilege level.
> 
> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
> so userspace can request a lower bound on the number of tag bits and
> determine the actual number of tag bits. As with arm64's
> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
> thread-scoped, inherited on clone() and fork() and cleared on execve().
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>

> ---
> 
> Changes in v4:
>  - Switch IS_ENABLED back to #ifdef to fix riscv32 build
> 
> Changes in v3:
>  - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
>    since it only controls the userspace part of pointer masking
>  - Use IS_ENABLED instead of #ifdef when possible
>  - Use an enum for the supported PMLEN values
>  - Simplify the logic in set_tagged_addr_ctrl()
> 
> Changes in v2:
>  - Rebase on riscv/linux.git for-next
>  - Add and use the envcfg_update_bits() helper function
>  - Inline flush_tagged_addr_state()
> 
>  arch/riscv/Kconfig                 | 11 ++++
>  arch/riscv/include/asm/processor.h |  8 +++
>  arch/riscv/include/asm/switch_to.h | 11 ++++
>  arch/riscv/kernel/process.c        | 91 ++++++++++++++++++++++++++++++
>  include/uapi/linux/prctl.h         |  3 +
>  5 files changed, 124 insertions(+)
> 
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 0f3cd7c3a436..817437157138 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -512,6 +512,17 @@ config RISCV_ISA_C
>  
>  	  If you don't know what to do here, say Y.
>  
> +config RISCV_ISA_SUPM
> +	bool "Supm extension for userspace pointer masking"
> +	depends on 64BIT
> +	default y
> +	help
> +	  Add support for pointer masking in userspace (Supm) when the
> +	  underlying hardware extension (Smnpm or Ssnpm) is detected at boot.
> +
> +	  If this option is disabled, userspace will be unable to use
> +	  the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
> +
>  config RISCV_ISA_SVNAPOT
>  	bool "Svnapot extension support for supervisor mode NAPOT pages"
>  	depends on 64BIT && MMU
> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
> index 586e4ab701c4..5c4d4fb97314 100644
> --- a/arch/riscv/include/asm/processor.h
> +++ b/arch/riscv/include/asm/processor.h
> @@ -200,6 +200,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
>  #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)	riscv_set_icache_flush_ctx(arg1, arg2)
>  extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long per_thread);
>  
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
> +long get_tagged_addr_ctrl(struct task_struct *task);
> +#define SET_TAGGED_ADDR_CTRL(arg)	set_tagged_addr_ctrl(current, arg)
> +#define GET_TAGGED_ADDR_CTRL()		get_tagged_addr_ctrl(current)
> +#endif
> +
>  #endif /* __ASSEMBLY__ */
>  
>  #endif /* _ASM_RISCV_PROCESSOR_H */
> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
> index 9685cd85e57c..94e33216b2d9 100644
> --- a/arch/riscv/include/asm/switch_to.h
> +++ b/arch/riscv/include/asm/switch_to.h
> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return false; }
>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>  #endif
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
>  static inline void __switch_to_envcfg(struct task_struct *next)
>  {
>  	asm volatile (ALTERNATIVE("nop", "csrw " __stringify(CSR_ENVCFG) ", %0",
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index e4bc61c4e58a..f39221ab5ddd 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -7,6 +7,7 @@
>   * Copyright (C) 2017 SiFive
>   */
>  
> +#include <linux/bitfield.h>
>  #include <linux/cpu.h>
>  #include <linux/kernel.h>
>  #include <linux/sched.h>
> @@ -171,6 +172,10 @@ void flush_thread(void)
>  	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
>  	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
>  #endif
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
> +#endif
>  }
>  
>  void arch_release_task_struct(struct task_struct *tsk)
> @@ -233,3 +238,89 @@ void __init arch_task_cache_init(void)
>  {
>  	riscv_v_setup_ctx_cache();
>  }
> +
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +enum {
> +	PMLEN_0 = 0,
> +	PMLEN_7 = 7,
> +	PMLEN_16 = 16,
> +};
> +
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
> +	/*
> +	 * Prefer the smallest PMLEN that satisfies the user's request,
> +	 * in case choosing a larger PMLEN has a performance impact.
> +	 */
> +	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
> +	if (pmlen == PMLEN_0)
> +		pmm = ENVCFG_PMM_PMLEN_0;
> +	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
> +		pmm = ENVCFG_PMM_PMLEN_7;
> +	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
> +		pmm = ENVCFG_PMM_PMLEN_16;
> +	else
> +		return -EINVAL;
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
> +		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
> +		break;
> +	case ENVCFG_PMM_PMLEN_16:
> +		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_16);
> +		break;
> +	}
> +
> +	return ret;
> +}
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
> +
> +	return 0;
> +}
> +core_initcall(tagged_addr_init);
> +#endif	/* CONFIG_RISCV_ISA_SUPM */
> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
> index 35791791a879..6e84c827869b 100644
> --- a/include/uapi/linux/prctl.h
> +++ b/include/uapi/linux/prctl.h
> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>  # define PR_MTE_TAG_MASK		(0xffffUL << PR_MTE_TAG_SHIFT)
>  /* Unused; kept only for source compatibility */
>  # define PR_MTE_TCF_SHIFT		1
> +/* RISC-V pointer masking tag length */
> +# define PR_PMLEN_SHIFT			24
> +# define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
>  
>  /* Control reclaim behavior when allocating memory */
>  #define PR_SET_IO_FLUSHER		57
> -- 
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOayQEfZZeDWW7b%40ghost.
