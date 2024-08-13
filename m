Return-Path: <kasan-dev+bncBC7PZX4C3UKBBGUK5W2QMGQE42MW3JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9008E9503C8
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 13:35:56 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2f1752568cfsf64278081fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 04:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723548956; cv=pass;
        d=google.com; s=arc-20160816;
        b=p3sNnIzYyyIe+ICiIQvMOIH1rYhEZp9J7f60Ojknu3MMU9rwt/Jyl4lFHJYjEpybQh
         IzElmKuM8TAkpKlaw6VHtp16f+BA7VKNmI/D1fuuiiRyTzy90CouJzT47BfCdfngOOJp
         /sLiFQPlUXhsYMMfGyspNX1ETVZMkSs1vXBF4rbXlfmKb/bktaq9q/PsZ6TImMe9SQvi
         CrBtpSA2O5RolI/W/wP+Cb0OeRihOkiIAJKwy+Ucw8EbUpULA8FL5ywXwMFS0HUKPZLy
         XsuAWISXDiKiDhs9rwvnqTqBRmtHO3UCsFWjUzPG6AwbDs2FGRTtgZzh4Xx6c2Lz9Nb5
         z34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tXtNjm2omeYFdxjvIjk06BRs3CpEfhloZ06IAUR8PCY=;
        fh=stAH6FuPVmDnjLFaLhhotvE2TM5P/eBcUUUdVtJgrUM=;
        b=VEu3gKcamQ6+kGYSQqUz/IxrvOJUToBxHsdo2hMaKlmu7GrQ5PFTs9Ny38xnNfCQNH
         jPpScBb8ngeQGxMsXijM9LFZVOOupfzcr0YWVgctoOIrFXNuORM8XsCxFJuFBjsvvJsF
         /GsyljU7DaPyCtfK/Vi6tJ2fUBWC8TEZ4TMYJ5lOuureaOze+TFZ0ixttz2KkR5uv9nu
         m9uiT3PMPdkUZr7eNZkfpB2Y/5+gz1uf3UEwt9VvCLRDFp4hB6kJuqWwtYCQI/dYKcKF
         anc1tcgs6SnNTrOZJXtNCljG/dOTljQw2MrrFD5qmfw8k5mDtpc9C8ccCN1TNuYxNuWX
         KRXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723548956; x=1724153756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tXtNjm2omeYFdxjvIjk06BRs3CpEfhloZ06IAUR8PCY=;
        b=fJv/LGY9yy8FNJK3KNH7O/tbtR2tR/am0u1NO0kvMuJ4eg4TWI3dAZSy1wZmlRJRpu
         BbmAhlguFbisY90KWH1J9pNXDAyZ+1sABIoq8eCqa3hnflXiffLWNaxiqWw6UKbNYqBY
         Xm3TczLFIl2FDB37Yhc9S3kgrAv0COEiGuW0SYOVLXblP7ZAHU7q2RGR5agOnpc1VrUW
         tIOht7CumQEtQ2jcwKBqTT/6WY0fnFwAc4eqmtOc9tRVmADfXQXQ53m+19LmkrQnELls
         umHpbqZppXzOf4z6Xor19o3n3FRU7icKTlifysfH89l3ku3l0zxLqgHXpgNRFIuZQFCe
         2aDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723548956; x=1724153756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tXtNjm2omeYFdxjvIjk06BRs3CpEfhloZ06IAUR8PCY=;
        b=nPmENyjfurp4ljMmLNui/dDVyDP9O3IovNEV23NFk+4IV8kGbRQmP1cG1p7oFG4K+Z
         pS5sMB/200g3hH0fMNjIfbeugpqz+iO/eM3SX0Nt6C+EjuygsrDB1XP4uIYuwP3umgbn
         /MmRBgtGDhBbpQBkX9wyS72w32Rulevs34QOQm/qxgL2J4Ix0vqITzxlMa+rSezaHZ/g
         wukp5I0cJFEIjQ2+DmA0f914tJfUhYrZ2aUVb8SFGRySO6ZpBuJxIfoOglrygjgJoK4h
         kRT0eeixcsrYD1A4fTmXK9rF3759GcWHUMuMTkBeqmT3HKMh+LGSawOwPGrK+MxHEPjy
         d1tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQ1Bc8krnuUy0u6QbkNSfOZtT6lZJWgDGlCkkEocJbfaY0rbOTSvYWkM7bJEKkq1hBTaYEhKSGnUE47tE4XRlo3AMAje/l+w==
X-Gm-Message-State: AOJu0Yy1LjcI2XyCH5z4fIN62+/s0y1rmE79JLNCFoJCVauXiiLAxzOf
	5f1tXOgYn+5Pwl2AxRz3aws2CYpkoFdd6Pmiut0NnRq4+Hp7OSp9
X-Google-Smtp-Source: AGHT+IGgU1f6Ja3itgUTEg9DRAdFcT0vnBkoady/TttX/ZLDHxz/4DO8niZnbJfdajAToh8Rzk/L7A==
X-Received: by 2002:a2e:9bc2:0:b0:2f2:9bef:10bb with SMTP id 38308e7fff4ca-2f2b7156b51mr20702971fa.22.1723548955196;
        Tue, 13 Aug 2024 04:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2203:0:b0:2ef:2eec:5052 with SMTP id 38308e7fff4ca-2f19bc583fbls4182991fa.1.-pod-prod-03-eu;
 Tue, 13 Aug 2024 04:35:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWr94yKQH0yo8BBrlxM6AlG/lBzngRwEZaivRYNsQHNrSbrd0OeDaWbOHLia7OCRuPHbrzI3mhDJ8rUp32pPc1BuVdltCBZYQvYMA==
X-Received: by 2002:a2e:a550:0:b0:2f1:8622:dc6b with SMTP id 38308e7fff4ca-2f2b7132fd7mr28255371fa.1.1723548952626;
        Tue, 13 Aug 2024 04:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723548952; cv=none;
        d=google.com; s=arc-20160816;
        b=jmumK0Ju5dFC0Y2+Tt0u5zLNnQ0458AlAvaKXqubHXkPXc8GHjmtOxKR8bT8gEEPfM
         k/mZNKJ9JB8o9n4YV8Y6HbhABYnXEBRIhjv0cSEy7uAy0SHNFP2+wmLxIOPSyg3+tjgx
         QeJ1/A4ye6UgL8eeNqTLS6RQuHljsV8eyEh7tLYPkIfhcP9eNm0AyHFmeH+vQCi16JNv
         LXfsd0tTqVtptEsxtYH8TGaiWfo4xMuGqGeLiyPC/3ROU4YIo80GAWomiRl/jOZzMZsA
         B8nfb2w3cWW0yxxIBw2m5avFixZ4drZ0/jPln+Z9e3ZET4EEwVQyKXOwgFB36W1xlWuX
         Pmiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=W/ONv/4+8Syyqjkk1KCaBAXR9NKx95lRx78SWilOfwo=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=mWAJZkEkD0i1j8Aa9y4hDV8sg73PNrtBSm38JinKyBIzh/lFKwwQwo2e3XqQDlIPRy
         8CQIoW02gQBcYCKOMu48Dcr7wrdt6rwP9HcrXa5k86kGKxlhLP9fHy08NJdKxJ+n3WRL
         TsqV6FbLTZZF1pinLzCzh5rA0pgSfmuD/lxjqQsMimfRwMD0y6sLi5V2r+3NvujEoS0b
         R2e5CCdkRdqJcZbyYgyIun7ECzJzCgp6qQ9j1JOhicnRfhF5hxlQydCopAGivOUADGbU
         Hx1Uq18i8uvLrfYBKnUE3O1FJrCY7QfDnTQOQdBXxy+VkmKDkAs4wzak6cgEsub+i7Ts
         YGNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay8-d.mail.gandi.net (relay8-d.mail.gandi.net. [2001:4b98:dc4:8::228])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5bd1a5d73aasi230006a12.3.2024.08.13.04.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 Aug 2024 04:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as permitted sender) client-ip=2001:4b98:dc4:8::228;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 96AB61BF204;
	Tue, 13 Aug 2024 11:35:50 +0000 (UTC)
Message-ID: <1faba7e8-903d-40f5-8285-1b309d7b9410@ghiti.fr>
Date: Tue, 13 Aug 2024 13:35:50 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 05/10] riscv: Add support for the tagged address ABI
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
 <20240625210933.1620802-6-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20240625210933.1620802-6-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::228 as
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

Hi Samuel,

On 25/06/2024 23:09, Samuel Holland wrote:
> When pointer masking is enabled for userspace, the kernel can accept
> tagged pointers as arguments to some system calls. Allow this by
> untagging the pointers in access_ok() and the uaccess routines. The
> uaccess routines must peform untagging in software because U-mode and
> S-mode have entirely separate pointer masking configurations. In fact,
> hardware may not even implement pointer masking for S-mode.


Would it make sense to have a fast path when S-mode and U-mode PMLENs 
are equal?


>
> Since the number of tag bits is variable, untagged_addr_remote() needs
> to know what PMLEN to use for the remote mm. Therefore, the pointer
> masking mode must be the same for all threads sharing an mm. Enforce
> this with a lock flag in the mm context, as x86 does for LAM.The flag gets reset in init_new_context() during fork(), as the new mm is no
> longer multithreaded.
>
> Unlike x86, untagged_addr() gets pmlen from struct thread_info instead
> of a percpu variable, as this both avoids context switch overhead and
> loads the value more efficiently.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v2:
>   - Implement untagged_addr_remote()
>   - Restrict PMLEN changes once a process is multithreaded
>
>   arch/riscv/include/asm/mmu.h         |  7 +++
>   arch/riscv/include/asm/mmu_context.h |  6 +++
>   arch/riscv/include/asm/thread_info.h |  3 ++
>   arch/riscv/include/asm/uaccess.h     | 58 +++++++++++++++++++++--
>   arch/riscv/kernel/process.c          | 69 +++++++++++++++++++++++++++-
>   5 files changed, 136 insertions(+), 7 deletions(-)
>
> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
> index 947fd60f9051..361a9623f8c8 100644
> --- a/arch/riscv/include/asm/mmu.h
> +++ b/arch/riscv/include/asm/mmu.h
> @@ -26,8 +26,15 @@ typedef struct {
>   	unsigned long exec_fdpic_loadmap;
>   	unsigned long interp_fdpic_loadmap;
>   #endif
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	unsigned long flags;
> +	u8 pmlen;
> +#endif
>   } mm_context_t;
>   
> +/* Lock the pointer masking mode because this mm is multithreaded */
> +#define MM_CONTEXT_LOCK_PMLEN	0
> +
>   #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
>   #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
>   
> diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
> index 7030837adc1a..62a9f76cf257 100644
> --- a/arch/riscv/include/asm/mmu_context.h
> +++ b/arch/riscv/include/asm/mmu_context.h
> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
>   static inline void activate_mm(struct mm_struct *prev,
>   			       struct mm_struct *next)
>   {
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	next->context.pmlen = 0;
> +#endif
>   	switch_mm(prev, next, NULL);
>   }
>   
> @@ -29,6 +32,9 @@ static inline int init_new_context(struct task_struct *tsk,
>   {
>   #ifdef CONFIG_MMU
>   	atomic_long_set(&mm->context.id, 0);
> +#endif
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
>   #endif
>   	return 0;
>   }
> diff --git a/arch/riscv/include/asm/thread_info.h b/arch/riscv/include/asm/thread_info.h
> index 5d473343634b..cd355f8a550f 100644
> --- a/arch/riscv/include/asm/thread_info.h
> +++ b/arch/riscv/include/asm/thread_info.h
> @@ -60,6 +60,9 @@ struct thread_info {
>   	void			*scs_base;
>   	void			*scs_sp;
>   #endif
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	u8			pmlen;
> +#endif
>   };
>   
>   #ifdef CONFIG_SHADOW_CALL_STACK
> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
> index 72ec1d9bd3f3..153495997bc1 100644
> --- a/arch/riscv/include/asm/uaccess.h
> +++ b/arch/riscv/include/asm/uaccess.h
> @@ -9,8 +9,56 @@
>   #define _ASM_RISCV_UACCESS_H
>   
>   #include <asm/asm-extable.h>
> +#include <asm/cpufeature.h>
>   #include <asm/pgtable.h>		/* for TASK_SIZE */
>   
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +static inline unsigned long __untagged_addr(unsigned long addr)
> +{
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
> +		u8 pmlen = current->thread_info.pmlen;


Why don't we use mm->pmlen? I don't see the need to introduce this 
variable that mirrors what is in mm already but I may be missing something.


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
> index dec5ccc44697..7bd445dade92 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -173,8 +173,10 @@ void flush_thread(void)
>   	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
>   #endif
>   #ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> -	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
>   		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
> +		current->thread_info.pmlen = 0;
> +	}
>   #endif
>   }
>   
> @@ -204,6 +206,12 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
>   	unsigned long tls = args->tls;
>   	struct pt_regs *childregs = task_pt_regs(p);
>   
> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
> +	/* Ensure all threads in this mm have the same pointer masking mode. */
> +	if (p->mm && (clone_flags & CLONE_VM))
> +		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
> +#endif
> +
>   	memset(&p->thread.s, 0, sizeof(p->thread.s));
>   
>   	/* p->thread holds context to be restored by __switch_to() */
> @@ -243,10 +251,16 @@ void __init arch_task_cache_init(void)
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
> @@ -277,6 +291,14 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>   			return -EINVAL;
>   	}
>   
> +	/*
> +	 * Do not allow the enabling of the tagged address ABI if globally
> +	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
> +	 * is disabled for userspace.
> +	 */
> +	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
> +		return -EINVAL;
> +
>   	if (pmlen == 7)
>   		pmm = ENVCFG_PMM_PMLEN_7;
>   	else if (pmlen == 16)
> @@ -284,7 +306,22 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>   	else
>   		pmm = ENVCFG_PMM_PMLEN_0;
>   
> +	if (!(arg & PR_TAGGED_ADDR_ENABLE))
> +		pmlen = 0;
> +
> +	if (mmap_write_lock_killable(mm))
> +		return -EINTR;
> +
> +	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
> +		mmap_write_unlock(mm);
> +		return -EBUSY;
> +	}
> +
>   	envcfg_update_bits(task, ENVCFG_PMM, pmm);
> +	task->mm->context.pmlen = pmlen;
> +	task->thread_info.pmlen = pmlen;
> +
> +	mmap_write_unlock(mm);
>   
>   	return 0;
>   }
> @@ -297,6 +334,13 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>   	if (is_compat_thread(ti))
>   		return -EINVAL;
>   
> +	if (task->thread_info.pmlen)
> +		ret = PR_TAGGED_ADDR_ENABLE;
> +
> +	/*
> +	 * The task's pmlen is only set if the tagged address ABI is enabled,
> +	 * so the effective PMLEN must be extracted from envcfg.PMM.
> +	 */
>   	switch (task->thread.envcfg & ENVCFG_PMM) {
>   	case ENVCFG_PMM_PMLEN_7:
>   		ret |= FIELD_PREP(PR_PMLEN_MASK, 7);
> @@ -315,6 +359,24 @@ static bool try_to_set_pmm(unsigned long value)
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
> @@ -328,6 +390,9 @@ static int __init tagged_addr_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1faba7e8-903d-40f5-8285-1b309d7b9410%40ghiti.fr.
