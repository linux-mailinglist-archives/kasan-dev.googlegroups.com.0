Return-Path: <kasan-dev+bncBC7PZX4C3UKBBT4R6O2QMGQEPRBXTEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E286951E2E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 17:10:10 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-52efcb739adsf7201712e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 08:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723648209; cv=pass;
        d=google.com; s=arc-20160816;
        b=om4wOi5CcqFLbtoQau/mEMaIGh1GhyNwpPeq8BC/EJuML0ZIkQgzCXKJyomd01/xbp
         BowITJeapiSXa3dRKDB566wLyVjhb5jGxRJQJ38FcI7EqwK615v1Vydx+n7+zzIHTMbS
         +KqBq8Cl56F+QN8kxd1xqQ9SISl/Zo2Z9s43OYLZsDPtZW9j3F3nDr97joyMI3kG/s67
         8zwdf0zwHW6ZKMjr4V52TLLO9LFmc2iXPrTe4htPuXbJBbtI/GK/ZUe5AjfTNCjW6VOP
         Nl0hXEGdPLJrNdw2SZjImOGSdkdXlj1xDx8HANA2YTfJTKIZDHwX8q+oSoDh2pJ0b/SX
         ODQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Tk1k21kyBVZQ1GxEDHydiIlLFeywlzInduo5rrNWhfA=;
        fh=HgJ6C7TvNx11j+b3tCi0bGZt9tspAlsoHO02qQ0vLZc=;
        b=PfYOwITucmACeSigxuSf6ZwvG+fNKBy+pgPQqHWdJPaWe8B1KZ7om+QHsB7gonJtIQ
         f9GAy51z8uSIK0FJRA6M8y0GN1m6IkFBLQXrBstzaB6l0Rr7/JHZJmC71KVIP9SQeFQx
         9bA4zHa8/+B93AiqlerAYPcV8Yisr9E1sbUOtggjOEgTljbK4FziXCE6snU7GefLprPp
         FMS7ESXizXAm6mN+I8SVO/BU6JDok1HUQet/ellXCbD6idCIxZQjP2yw9OU4iZxhZnPU
         cN+vRfusawR7waUow3IoGTqlO/ZZpK73nZ7Ocnu+QKJpDSbegeq/ILUpuA1oYP+OI7bY
         My/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723648209; x=1724253009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tk1k21kyBVZQ1GxEDHydiIlLFeywlzInduo5rrNWhfA=;
        b=HRBe+MbxdXJ4qBurjIuadCFNRBBnJ04IFBA4LjJ0DInMpXFiKZS1NKTSSE6ZVAwfGe
         G+8B2czRCXA4HeudQ7INJ836VQu4HPn6INOaHutyIKHKvqM+roIQNXLd2IITWMJb9vW7
         1xZFt61/pNhPcTS/hkCM+NiuS/DLocTSrQkXVB9JfYdWdLL9OrnA1pUdy4EKPi2NUW1d
         hu2g25vwW3xQB4lygZzbZDfQkeaywa44FdQKhw/GbsZy3mFC9mbwppcJ6lT/IPjZQfiy
         ykjut3lXwS3ZObTJP4WvHAbUr7TNE/CL/urVVAXepy2fE3j5KRuNEvf0jDSA88qkW1hx
         Gj1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723648209; x=1724253009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Tk1k21kyBVZQ1GxEDHydiIlLFeywlzInduo5rrNWhfA=;
        b=Z2lznzHGYbvBWpbFUZEJRPAih/kV7+JSFUfz3dGf3vVYDBWzfBBQKPicHPNcVyBisa
         I2+3seREPMKwYrBnJpahT3+Fnjd7l5reCG4DUUkRQoVsdKK2czzUyRdX6lVYOZV4Wq2l
         2lRQUgnwAvBXjubQ1Gqa8UskAsOx8ttqvLbiwY9iCkrLwZ9m/FDRuehqnKJm5Zyqz8Yd
         RptMoeYg5cZNtttXJQZGVXFA2uns2GJkDg75ws4BpJFHR0h7kbB0MU1VhRupunzMA86A
         Hhv737lT9qMJ9yGFf2BW9GWKFmK7vQRiGV98fR0dertq4+DM3C6/ls3pS1FdBpKwHBHH
         Anug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIcGzN3lkjqRHkDtASMd2MnH7UG48UhhMtX0RKfswRGziIhmOsmcBZERll83xIEfGT4I8ltKetzn6fUFoNpRjB3TGhqlr+9w==
X-Gm-Message-State: AOJu0YxFQRcV1czxY/sncf63DCTIuScecbeAcDBtwlQr+6l++zefwnuJ
	PLwc9nLJMVZ5zgwr7vW4tES92rpmog4FeHN0MzhhvNkD3iu+R1jd
X-Google-Smtp-Source: AGHT+IEZw2P1A3hrg6WpQXwkN6cE9wMnyjngTuMmd74mT9kYB/oqocZDpzLnHWzz57SR+/xVBKeYJA==
X-Received: by 2002:a05:6512:2303:b0:530:ae0a:ab7a with SMTP id 2adb3069b0e04-532eda7926dmr1696076e87.17.1723648208233;
        Wed, 14 Aug 2024 08:10:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c12:b0:426:6f5a:9b6e with SMTP id
 5b1f17b1804b1-4290919adebls32035465e9.2.-pod-prod-07-eu; Wed, 14 Aug 2024
 08:10:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAwZZWe+HbrFcTtID44npA0he8+SB9bDVEbynHCvSE5TG4gnSyBq9jC0i8geqBn9/EVgT6LgHPDzoarGoAOBg11pfwb8e/Skvb1g==
X-Received: by 2002:a05:600c:1e0c:b0:426:6f38:8974 with SMTP id 5b1f17b1804b1-429dd22f3eemr20595595e9.6.1723648206068;
        Wed, 14 Aug 2024 08:10:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723648206; cv=none;
        d=google.com; s=arc-20240605;
        b=FT8IMVVxUwB0NfG0SPUToDYisIm42xJrQH8smE6+PgbRpFTZJhTg5zhNKHbDPoK/M3
         e477EG93+VEx/HyjHJhdVLzS6cLjNh2+5DfZPmgdJz1swOP23iPFiZ7t1B1FEp9Muk19
         RphwvOg65anoZ7WeGozhAIUYGhJhmJhq6cxoNtJuRa+vGrmc/PXoHLUdTgSNonGj6KaZ
         UgWHtiGgRrXCAh41Kzg5VmuLABb3YC77iNSHCM6LxlJTEFpp/iYUzhJ6Fj2rgQ69yVa5
         rtkgFA/boFqQsws9uytCYXBXKAOQqtQ5d015KfBsPkr+JdAQWa+NeAy5nBPIks2KX7AG
         ukuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Haix9TDRxZqtC1yF7jF4uiN7GeNq4OAW7M9nuG0S6Rk=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=JQl+F+tF/BVAqYo9P/JD+u+Ukh+BvL54GguA4WaNe0v/Jz25JNcf2nJium4DqC0Cme
         D1YNrrqfCwiHlPhv74BoUqePz+/W5jqF8wydRbsGvFzM/DGy3MJNWNe2sFexKQQfO37A
         QPXfNHlB8SI3EUVOW1c9A889C0MzxFX/3YuhVlUR7MB2XIFVdT/rLit55tALeGssU/mg
         N+XuQCe67ABjq5M9CNNzninZqL3RQwdAauO6+OGhsAjEwXQKL3jKGmjIXSB7UTkospi7
         6oETOcMXKUKMEr5Gn7rrVykia+i0+J9Et4l0cXxEAcMgCjyDoser6uiD3UvEd/sAgoPF
         7wig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [2001:4b98:dc4:8::224])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429d782ff34si1076145e9.0.2024.08.14.08.10.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 14 Aug 2024 08:10:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) client-ip=2001:4b98:dc4:8::224;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 069D6E000B;
	Wed, 14 Aug 2024 15:10:02 +0000 (UTC)
Message-ID: <35e8386f-854a-48d5-8c03-7a53f8ca3292@ghiti.fr>
Date: Wed, 14 Aug 2024 17:10:02 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/10] riscv: Add support for the tagged address ABI
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
References: <20240814081437.956855-1-samuel.holland@sifive.com>
 <20240814081437.956855-6-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20240814081437.956855-6-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
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

On 14/08/2024 10:13, Samuel Holland wrote:
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
>
> Changes in v3:
>   - Use IS_ENABLED instead of #ifdef when possible
>   - Implement mm_untag_mask()
>   - Remove pmlen from struct thread_info (now only in mm_context_t)
>
> Changes in v2:
>   - Implement untagged_addr_remote()
>   - Restrict PMLEN changes once a process is multithreaded
>
>   arch/riscv/include/asm/mmu.h         |  7 +++
>   arch/riscv/include/asm/mmu_context.h | 13 +++++
>   arch/riscv/include/asm/uaccess.h     | 58 ++++++++++++++++++++--
>   arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
>   4 files changed, 141 insertions(+), 10 deletions(-)
>
> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
> index c9e03e9da3dc..1cc90465d75b 100644
> --- a/arch/riscv/include/asm/mmu.h
> +++ b/arch/riscv/include/asm/mmu.h
> @@ -25,9 +25,16 @@ typedef struct {
>   #ifdef CONFIG_BINFMT_ELF_FDPIC
>   	unsigned long exec_fdpic_loadmap;
>   	unsigned long interp_fdpic_loadmap;
> +#endif
> +	unsigned long flags;
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	u8 pmlen;
>   #endif
>   } mm_context_t;
>   
> +/* Lock the pointer masking mode because this mm is multithreaded */
> +#define MM_CONTEXT_LOCK_PMLEN	0
> +
>   #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
>   #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
>   
> diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
> index 7030837adc1a..8c4bc49a3a0f 100644
> --- a/arch/riscv/include/asm/mmu_context.h
> +++ b/arch/riscv/include/asm/mmu_context.h
> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
>   static inline void activate_mm(struct mm_struct *prev,
>   			       struct mm_struct *next)
>   {
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	next->context.pmlen = 0;
> +#endif
>   	switch_mm(prev, next, NULL);
>   }
>   
> @@ -30,11 +33,21 @@ static inline int init_new_context(struct task_struct *tsk,
>   #ifdef CONFIG_MMU
>   	atomic_long_set(&mm->context.id, 0);
>   #endif
> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
> +		clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
>   	return 0;
>   }
>   
>   DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
>   
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +#define mm_untag_mask mm_untag_mask
> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
> +{
> +	return -1UL >> mm->context.pmlen;
> +}
> +#endif
> +
>   #include <asm-generic/mmu_context.h>
>   
>   #endif /* _ASM_RISCV_MMU_CONTEXT_H */
> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
> index 72ec1d9bd3f3..6416559232a2 100644
> --- a/arch/riscv/include/asm/uaccess.h
> +++ b/arch/riscv/include/asm/uaccess.h
> @@ -9,8 +9,56 @@
>   #define _ASM_RISCV_UACCESS_H
>   
>   #include <asm/asm-extable.h>
> +#include <asm/cpufeature.h>
>   #include <asm/pgtable.h>		/* for TASK_SIZE */
>   
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +static inline unsigned long __untagged_addr(unsigned long addr)
> +{
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
> +		u8 pmlen = current->mm->context.pmlen;
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
> +#define untagged_addr(addr) ({						\
> +	unsigned long __addr = (__force unsigned long)(addr);		\
> +	(__force __typeof__(addr))__untagged_addr(__addr);		\
> +})
> +
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


I should have mentioned that in v2: now that you removed the thread_info 
pmlen field, __untagged_addr_remote() and __untagged_addr() are almost 
the same, can you merge them?

Thanks!

Alex


> +
> +#define untagged_addr_remote(mm, addr) ({				\
> +	unsigned long __addr = (__force unsigned long)(addr);		\
> +	mmap_assert_locked(mm);						\
> +	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);	\
> +})
> +
> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
> +#else
> +#define untagged_addr(addr) (addr)
> +#endif
> +
>   /*
>    * User space memory access functions
>    */
> @@ -130,7 +178,7 @@ do {								\
>    */
>   #define __get_user(x, ptr)					\
>   ({								\
> -	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
> +	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>   	long __gu_err = 0;					\
>   								\
>   	__chk_user_ptr(__gu_ptr);				\
> @@ -246,7 +294,7 @@ do {								\
>    */
>   #define __put_user(x, ptr)					\
>   ({								\
> -	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
> +	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>   	__typeof__(*__gu_ptr) __val = (x);			\
>   	long __pu_err = 0;					\
>   								\
> @@ -293,13 +341,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
>   static inline unsigned long
>   raw_copy_from_user(void *to, const void __user *from, unsigned long n)
>   {
> -	return __asm_copy_from_user(to, from, n);
> +	return __asm_copy_from_user(to, untagged_addr(from), n);
>   }
>   
>   static inline unsigned long
>   raw_copy_to_user(void __user *to, const void *from, unsigned long n)
>   {
> -	return __asm_copy_to_user(to, from, n);
> +	return __asm_copy_to_user(untagged_addr(to), from, n);
>   }
>   
>   extern long strncpy_from_user(char *dest, const char __user *src, long count);
> @@ -314,7 +362,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
>   {
>   	might_fault();
>   	return access_ok(to, n) ?
> -		__clear_user(to, n) : n;
> +		__clear_user(untagged_addr(to), n) : n;
>   }
>   
>   #define __get_kernel_nofault(dst, src, type, err_label)			\
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index 1280a7c4a412..f4d8e5c3bb84 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -203,6 +203,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
>   	unsigned long tls = args->tls;
>   	struct pt_regs *childregs = task_pt_regs(p);
>   
> +	/* Ensure all threads in this mm have the same pointer masking mode. */
> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
> +		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
> +
>   	memset(&p->thread.s, 0, sizeof(p->thread.s));
>   
>   	/* p->thread holds context to be restored by __switch_to() */
> @@ -248,10 +252,16 @@ enum {
>   static bool have_user_pmlen_7;
>   static bool have_user_pmlen_16;
>   
> +/*
> + * Control the relaxed ABI allowing tagged user addresses into the kernel.
> + */
> +static unsigned int tagged_addr_disabled;
> +
>   long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>   {
> -	unsigned long valid_mask = PR_PMLEN_MASK;
> +	unsigned long valid_mask = PR_PMLEN_MASK | PR_TAGGED_ADDR_ENABLE;
>   	struct thread_info *ti = task_thread_info(task);
> +	struct mm_struct *mm = task->mm;
>   	unsigned long pmm;
>   	u8 pmlen;
>   
> @@ -266,16 +276,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>   	 * in case choosing a larger PMLEN has a performance impact.
>   	 */
>   	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
> -	if (pmlen == PMLEN_0)
> +	if (pmlen == PMLEN_0) {
>   		pmm = ENVCFG_PMM_PMLEN_0;
> -	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
> +	} else if (pmlen <= PMLEN_7 && have_user_pmlen_7) {
> +		pmlen = PMLEN_7;
>   		pmm = ENVCFG_PMM_PMLEN_7;
> -	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
> +	} else if (pmlen <= PMLEN_16 && have_user_pmlen_16) {
> +		pmlen = PMLEN_16;
>   		pmm = ENVCFG_PMM_PMLEN_16;
> -	else
> +	} else {
>   		return -EINVAL;
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
>   	envcfg_update_bits(task, ENVCFG_PMM, pmm);
> +	mm->context.pmlen = pmlen;
> +
> +	mmap_write_unlock(mm);
>   
>   	return 0;
>   }
> @@ -288,6 +323,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>   	if (is_compat_thread(ti))
>   		return -EINVAL;
>   
> +	/*
> +	 * The mm context's pmlen is set only when the tagged address ABI is
> +	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
> +	 */
>   	switch (task->thread.envcfg & ENVCFG_PMM) {
>   	case ENVCFG_PMM_PMLEN_7:
>   		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
> @@ -297,6 +336,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>   		break;
>   	}
>   
> +	if (task->mm->context.pmlen)
> +		ret |= PR_TAGGED_ADDR_ENABLE;
> +
>   	return ret;
>   }
>   
> @@ -306,6 +348,24 @@ static bool try_to_set_pmm(unsigned long value)
>   	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
>   }
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
>   static int __init tagged_addr_init(void)
>   {
>   	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> @@ -319,6 +379,9 @@ static int __init tagged_addr_init(void)
>   	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
>   	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
>   
> +	if (!register_sysctl("abi", tagged_addr_sysctl_table))
> +		return -EINVAL;
> +
>   	return 0;
>   }
>   core_initcall(tagged_addr_init);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35e8386f-854a-48d5-8c03-7a53f8ca3292%40ghiti.fr.
