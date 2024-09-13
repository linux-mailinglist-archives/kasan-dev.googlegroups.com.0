Return-Path: <kasan-dev+bncBDHJX64K2UNBBU6OR23QMGQELW4ZN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D474B9776FF
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 04:45:41 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-82cf2a9da36sf39923239f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 19:45:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726195540; cv=pass;
        d=google.com; s=arc-20240605;
        b=N6Vk/IU+32ATxgsmHafzC9JnO5sGnlSKfX2FREAUas/sP60klpnsXEEkaWETOGZbPK
         H4rFRjjcg/6uTgbxy8UjtE+dg/EX5Um7SuWjDwliBBpXPOwo77mE1eFzBXDB95ozbgkr
         oF0S2xAWbnsKn6Q1TihuTvkDa/aHxvQwfkGy6JTIoXGQf6L8oXIz46kjy0ctghShrm5K
         zQ8AyRDcVvEXPPSd40Vxs7LRm80qG5R/o/3LQoLai7PqAFJxtoALBcmPEtubgb7XB0s+
         99zUkaguDqG8y0BHgCTuJIUbvBQscLiuBmRMlocVZ2TtVw+aoLvHDTS4YUKDpYxpXdYB
         g9pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6Wp2u1FWckDt6vF1Ssna4frn3hIgvXx1weHUyWjY42s=;
        fh=hfYLF1SdOIaAVhnE87SzlX1XGrP+rtPv5w+b/Nz9TVk=;
        b=RU+gb+8yooNx/gSiVdTZ7bzlKeLg5I9f+Kdnml5en216T0hFHLrVTdw90OjVznYX9c
         +b59j2VfsXhR8upo4RLOsWPGtAIkZtR0yItvWl4gaxz7c7WgZ1VF0rG5SEvSEQKmrzHR
         ek9U5r7JihWWfsI54JvjYZ8K2KSrfUJN2Ko1XMUPLyzAx9iZJakD8r+O0gmkCYoENV17
         8HoP3xSF6liiei4FyayGEXkBdUDR7MkbO1jGoRIKQUrDQjX57WqFnh4y4Yzt5yXtgRUu
         VX9Yb2Gj5RP/M17yPArP5LnICYVrtY4jIHupLGREXoDEdUGohzhIaYQ5p7UpsciSUCcK
         CRvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=17gSRlTa;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726195540; x=1726800340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6Wp2u1FWckDt6vF1Ssna4frn3hIgvXx1weHUyWjY42s=;
        b=VeIWqfS+PmnW05wOYlikHFDN5tgVVQuslNkdpmm4g/zwQu8C3srzjvIpyQ03tI8dlB
         NR5im56pwDTC2SBBRfMOQ96vuoVDrW9y+DsEWK5bdGHTPc+L1bAMqAIheY/JadVHJ4tD
         7EymuTdNiN48tlsdVfINY7ki3GA85VeH8iy1rDV3u59c4fu3yhjB6PGiYhWqQEIUak+/
         BLnnaiakFwS7G7+tP7O+uJQCD7c87q0gFzoi7m280wcN/YqF9FEzRiv/ImASL+fss0Pb
         NBV7l8PFapEIUuCaLpfc8PYjc78RBDWK7xVV4IQiY1lO+7XEfbYdqRWPe3qsh0U0udfj
         C0FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726195540; x=1726800340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6Wp2u1FWckDt6vF1Ssna4frn3hIgvXx1weHUyWjY42s=;
        b=fCdiht09HJNKv+EEJ/nGJ4C+g7iivUlqRFrdqZ/t+zKn9CS7uwF1yRNZk4sdEtqoIg
         kd+nulEC+D0q8Lv9joyUZw1P31mwA+3kOtn6ex0PAVI4DajaaCiwWuIUVMiBzP6hKV5g
         OCeu9B6CpRUzuW0jjD0NvoM5kITsKUaK9Pn8ni7YTmK29aQVASKJEYEJ3UZv6m+wJQgJ
         bcPmmZAK/aBp/FM32QpsbDAucHl22iOcYhCOtlg6SWGiToWJdqtBs1J4oTkHhJaANOkZ
         oeguJ9JTLMQdB5sevwA/TbwXpUAuGsySwRzjWse1/qxBQc+b/N1BxMoUs6GdkEEo1uAz
         UzOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLMxSM+K5vdmJIPxkFNddrNb95R5b8ZLFMhUKEBbXRFehHCf6VdVpn5v4QC0Y3zywYlKS5fQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPHDsvcPRzBokFWBkPl5eNJBjxrTGqpTNcovr5mrudC5jYnHIx
	i6G+cryLqGBJgQrqOYu4cj04LK4Ypa8B7ByP+oEHy5pl1I3FwBFl
X-Google-Smtp-Source: AGHT+IG68xa3eAmvMO8TuMmXVJl3eWV+N6SxXgEip4twR1qMgjZbnmpjD6/q1mMhnUYEJwNWuDFLNw==
X-Received: by 2002:a05:6e02:1a81:b0:39d:637f:97bc with SMTP id e9e14a558f8ab-3a08b66273amr12888875ab.0.1726195539961;
        Thu, 12 Sep 2024 19:45:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c05:b0:39f:5580:46d2 with SMTP id
 e9e14a558f8ab-3a08423fe0bls8746315ab.1.-pod-prod-06-us; Thu, 12 Sep 2024
 19:45:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgRz4fst0epbTDzhyeJYT6PaWKpirPOdR5STIy+2TJhTuhvq5mKZq7HOwOjWZRzJ0sO4xZ3PjVCVI=@googlegroups.com
X-Received: by 2002:a05:6e02:214b:b0:3a0:378a:884b with SMTP id e9e14a558f8ab-3a08b6f87c3mr11129285ab.3.1726195538968;
        Thu, 12 Sep 2024 19:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726195538; cv=none;
        d=google.com; s=arc-20240605;
        b=lyAQzf5/5XNrsBpXRaJJ5q1eu5BYE/S7gZ9H06eJ5IaIwQWang+uasq8vouvAaHp8t
         sZ+CVvuVvqtaNb68+xfc3O3NYpADEaT7m5Xtkw2iYFFH1HvIRWZmmXHIpEgmQld1k7dt
         RWJ3wqv3pW+20mXC9xmK0929HrrOPizOu/nOZvzOF44eAcsOU7b9diPGELJ/IBZnN6oo
         XhmPJ17eeIFFQvgYA2nDYlyfVuxhwu0vJ5HONtnW/ZVyawoF5jjDA/1gFrq4KwmhG2LW
         M0MpmFAhS/XMx5Tdwp7hucOwMa+uw8PsyCSZ07gJlUpd0jFGUz8L8YuHMdbbIoiu28pP
         yIEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y1niUQMAjIcOEbieRDodT+etD4uCaJKnhIQMt3IM13c=;
        fh=GIppzwLvSMDqWNgjg1qj3U2lq0Z7tTG9qTfiEjY9aQI=;
        b=fVGZ1Z1WyBtR/e41s870v6CaabDbqcFE+pp+aEg5fDT7uyjb1VgPQaydgYpgReaNUA
         eUmHJVRAVzVG+rTIsg21zpOZDJkQTdirF8NNXQl3WpRXfhLLv/EBqiHOujGhv+1bCFCW
         DsLSbB25tFu2eOUyMyKdi0vy3pt9SmKzj3PpIyOehkA/drXDTOghxnYgQI229B8++UrH
         DftgOeS0hCTshTqzQfZyLuf7zyYRsN/V6lTiSggx8kgf9X8GDP0MmogTG5n7dk3JNByx
         bNqdGb51VJTaRNTrCDA5kZrqBRuvTznQIY5/NtEBFPq2hUBn/pKtg7Hb2rAyY6oHCZ1K
         3Siw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=17gSRlTa;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a058fff597si5666035ab.1.2024.09.12.19.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 19:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-2d87a0bfaa7so423143a91.2
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 19:45:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUlAiTVUJ2GC6nV5C3gIfjOHdb5YCd8+N8dmY1ULXn6vJWuMtv23ZlaxLLHkXvsyl7Bkg5YHs4pze0=@googlegroups.com
X-Received: by 2002:a17:90b:1c0b:b0:2d3:d45b:9e31 with SMTP id 98e67ed59e1d1-2dbb9dc6216mr1690564a91.2.1726195538225;
        Thu, 12 Sep 2024 19:45:38 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2dbb9ca7a9asm465752a91.26.2024.09.12.19.45.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 19:45:37 -0700 (PDT)
Date: Thu, 12 Sep 2024 19:45:34 -0700
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
Subject: Re: [PATCH v4 05/10] riscv: Add support for the tagged address ABI
Message-ID: <ZuOnTvgMv2b/ki9e@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-6-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-6-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=17gSRlTa;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
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

On Wed, Aug 28, 2024 at 06:01:27PM -0700, Samuel Holland wrote:
> When pointer masking is enabled for userspace, the kernel can accept
> tagged pointers as arguments to some system calls. Allow this by
> untagging the pointers in access_ok() and the uaccess routines. The
> uaccess routines must peform untagging in software because U-mode and
> S-mode have entirely separate pointer masking configurations. In fact,
> hardware may not even implement pointer masking for S-mode.
> 
> Since the number of tag bits is variable, untagged_addr_remote() needs
> to know what PMLEN to use for the remote mm. Therefore, the pointer
> masking mode must be the same for all threads sharing an mm. Enforce
> this with a lock flag in the mm context, as x86 does for LAM. The flag
> gets reset in init_new_context() during fork(), as the new mm is no
> longer multithreaded.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---

Not necessary, but what do you think about adding riscv to include/uapi/linux/prctl.h:

/* Tagged user address controls for arm64 */
#define PR_SET_TAGGED_ADDR_CTRL		55
#define PR_GET_TAGGED_ADDR_CTRL		56
# define PR_TAGGED_ADDR_ENABLE		(1UL << 0)

Also looks like this last line should probably be under SET rather than
GET.

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>

> 
> Changes in v4:
>  - Combine __untagged_addr() and __untagged_addr_remote()
> 
> Changes in v3:
>  - Use IS_ENABLED instead of #ifdef when possible
>  - Implement mm_untag_mask()
>  - Remove pmlen from struct thread_info (now only in mm_context_t)
> 
> Changes in v2:
>  - Implement untagged_addr_remote()
>  - Restrict PMLEN changes once a process is multithreaded
> 
>  arch/riscv/include/asm/mmu.h         |  7 +++
>  arch/riscv/include/asm/mmu_context.h | 13 +++++
>  arch/riscv/include/asm/uaccess.h     | 43 ++++++++++++++--
>  arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
>  4 files changed, 126 insertions(+), 10 deletions(-)
> 
> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
> index c9e03e9da3dc..1cc90465d75b 100644
> --- a/arch/riscv/include/asm/mmu.h
> +++ b/arch/riscv/include/asm/mmu.h
> @@ -25,9 +25,16 @@ typedef struct {
>  #ifdef CONFIG_BINFMT_ELF_FDPIC
>  	unsigned long exec_fdpic_loadmap;
>  	unsigned long interp_fdpic_loadmap;
> +#endif
> +	unsigned long flags;
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	u8 pmlen;
>  #endif
>  } mm_context_t;
>  
> +/* Lock the pointer masking mode because this mm is multithreaded */
> +#define MM_CONTEXT_LOCK_PMLEN	0
> +
>  #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
>  #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
>  
> diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
> index 7030837adc1a..8c4bc49a3a0f 100644
> --- a/arch/riscv/include/asm/mmu_context.h
> +++ b/arch/riscv/include/asm/mmu_context.h
> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
>  static inline void activate_mm(struct mm_struct *prev,
>  			       struct mm_struct *next)
>  {
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	next->context.pmlen = 0;
> +#endif
>  	switch_mm(prev, next, NULL);
>  }
>  
> @@ -30,11 +33,21 @@ static inline int init_new_context(struct task_struct *tsk,
>  #ifdef CONFIG_MMU
>  	atomic_long_set(&mm->context.id, 0);
>  #endif
> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
> +		clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
>  	return 0;
>  }
>  
>  DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
>  
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +#define mm_untag_mask mm_untag_mask
> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
> +{
> +	return -1UL >> mm->context.pmlen;
> +}
> +#endif
> +
>  #include <asm-generic/mmu_context.h>
>  
>  #endif /* _ASM_RISCV_MMU_CONTEXT_H */
> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
> index 72ec1d9bd3f3..fee56b0c8058 100644
> --- a/arch/riscv/include/asm/uaccess.h
> +++ b/arch/riscv/include/asm/uaccess.h
> @@ -9,8 +9,41 @@
>  #define _ASM_RISCV_UACCESS_H
>  
>  #include <asm/asm-extable.h>
> +#include <asm/cpufeature.h>
>  #include <asm/pgtable.h>		/* for TASK_SIZE */
>  
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +static inline unsigned long __untagged_addr_remote(struct mm_struct *mm, unsigned long addr)
> +{
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
> +		u8 pmlen = mm->context.pmlen;
> +
> +		/* Virtual addresses are sign-extended; physical addresses are zero-extended. */
> +		if (IS_ENABLED(CONFIG_MMU))
> +			return (long)(addr << pmlen) >> pmlen;
> +		else
> +			return (addr << pmlen) >> pmlen;
> +	}
> +
> +	return addr;
> +}
> +
> +#define untagged_addr(addr) ({							\
> +	unsigned long __addr = (__force unsigned long)(addr);			\
> +	(__force __typeof__(addr))__untagged_addr_remote(current->mm, __addr);	\
> +})
> +
> +#define untagged_addr_remote(mm, addr) ({					\
> +	unsigned long __addr = (__force unsigned long)(addr);			\
> +	mmap_assert_locked(mm);							\
> +	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);		\
> +})
> +
> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
> +#else
> +#define untagged_addr(addr) (addr)
> +#endif
> +
>  /*
>   * User space memory access functions
>   */
> @@ -130,7 +163,7 @@ do {								\
>   */
>  #define __get_user(x, ptr)					\
>  ({								\
> -	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
> +	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>  	long __gu_err = 0;					\
>  								\
>  	__chk_user_ptr(__gu_ptr);				\
> @@ -246,7 +279,7 @@ do {								\
>   */
>  #define __put_user(x, ptr)					\
>  ({								\
> -	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
> +	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>  	__typeof__(*__gu_ptr) __val = (x);			\
>  	long __pu_err = 0;					\
>  								\
> @@ -293,13 +326,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
>  static inline unsigned long
>  raw_copy_from_user(void *to, const void __user *from, unsigned long n)
>  {
> -	return __asm_copy_from_user(to, from, n);
> +	return __asm_copy_from_user(to, untagged_addr(from), n);
>  }
>  
>  static inline unsigned long
>  raw_copy_to_user(void __user *to, const void *from, unsigned long n)
>  {
> -	return __asm_copy_to_user(to, from, n);
> +	return __asm_copy_to_user(untagged_addr(to), from, n);
>  }
>  
>  extern long strncpy_from_user(char *dest, const char __user *src, long count);
> @@ -314,7 +347,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
>  {
>  	might_fault();
>  	return access_ok(to, n) ?
> -		__clear_user(to, n) : n;
> +		__clear_user(untagged_addr(to), n) : n;
>  }
>  
>  #define __get_kernel_nofault(dst, src, type, err_label)			\
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index f39221ab5ddd..6e9c84a41c29 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -204,6 +204,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
>  	unsigned long tls = args->tls;
>  	struct pt_regs *childregs = task_pt_regs(p);
>  
> +	/* Ensure all threads in this mm have the same pointer masking mode. */
> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
> +		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
> +
>  	memset(&p->thread.s, 0, sizeof(p->thread.s));
>  
>  	/* p->thread holds context to be restored by __switch_to() */
> @@ -249,10 +253,16 @@ enum {
>  static bool have_user_pmlen_7;
>  static bool have_user_pmlen_16;
>  
> +/*
> + * Control the relaxed ABI allowing tagged user addresses into the kernel.
> + */
> +static unsigned int tagged_addr_disabled;
> +
>  long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>  {
> -	unsigned long valid_mask = PR_PMLEN_MASK;
> +	unsigned long valid_mask = PR_PMLEN_MASK | PR_TAGGED_ADDR_ENABLE;
>  	struct thread_info *ti = task_thread_info(task);
> +	struct mm_struct *mm = task->mm;
>  	unsigned long pmm;
>  	u8 pmlen;
>  
> @@ -267,16 +277,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>  	 * in case choosing a larger PMLEN has a performance impact.
>  	 */
>  	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
> -	if (pmlen == PMLEN_0)
> +	if (pmlen == PMLEN_0) {
>  		pmm = ENVCFG_PMM_PMLEN_0;
> -	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
> +	} else if (pmlen <= PMLEN_7 && have_user_pmlen_7) {
> +		pmlen = PMLEN_7;
>  		pmm = ENVCFG_PMM_PMLEN_7;
> -	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
> +	} else if (pmlen <= PMLEN_16 && have_user_pmlen_16) {
> +		pmlen = PMLEN_16;
>  		pmm = ENVCFG_PMM_PMLEN_16;
> -	else
> +	} else {
>  		return -EINVAL;
> +	}
> +
> +	/*
> +	 * Do not allow the enabling of the tagged address ABI if globally
> +	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
> +	 * is disabled for userspace.
> +	 */
> +	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
> +		return -EINVAL;
> +
> +	if (!(arg & PR_TAGGED_ADDR_ENABLE))
> +		pmlen = PMLEN_0;
> +
> +	if (mmap_write_lock_killable(mm))
> +		return -EINTR;
> +
> +	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
> +		mmap_write_unlock(mm);
> +		return -EBUSY;
> +	}
>  
>  	envcfg_update_bits(task, ENVCFG_PMM, pmm);
> +	mm->context.pmlen = pmlen;
> +
> +	mmap_write_unlock(mm);
>  
>  	return 0;
>  }
> @@ -289,6 +324,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>  	if (is_compat_thread(ti))
>  		return -EINVAL;
>  
> +	/*
> +	 * The mm context's pmlen is set only when the tagged address ABI is
> +	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
> +	 */
>  	switch (task->thread.envcfg & ENVCFG_PMM) {
>  	case ENVCFG_PMM_PMLEN_7:
>  		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
> @@ -298,6 +337,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>  		break;
>  	}
>  
> +	if (task->mm->context.pmlen)
> +		ret |= PR_TAGGED_ADDR_ENABLE;
> +
>  	return ret;
>  }
>  
> @@ -307,6 +349,24 @@ static bool try_to_set_pmm(unsigned long value)
>  	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
>  }
>  
> +/*
> + * Global sysctl to disable the tagged user addresses support. This control
> + * only prevents the tagged address ABI enabling via prctl() and does not
> + * disable it for tasks that already opted in to the relaxed ABI.
> + */
> +
> +static struct ctl_table tagged_addr_sysctl_table[] = {
> +	{
> +		.procname	= "tagged_addr_disabled",
> +		.mode		= 0644,
> +		.data		= &tagged_addr_disabled,
> +		.maxlen		= sizeof(int),
> +		.proc_handler	= proc_dointvec_minmax,
> +		.extra1		= SYSCTL_ZERO,
> +		.extra2		= SYSCTL_ONE,
> +	},
> +};
> +
>  static int __init tagged_addr_init(void)
>  {
>  	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> @@ -320,6 +380,9 @@ static int __init tagged_addr_init(void)
>  	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
>  	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
>  
> +	if (!register_sysctl("abi", tagged_addr_sysctl_table))
> +		return -EINVAL;
> +
>  	return 0;
>  }
>  core_initcall(tagged_addr_init);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOnTvgMv2b/ki9e%40ghost.
