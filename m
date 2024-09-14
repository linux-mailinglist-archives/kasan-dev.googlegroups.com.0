Return-Path: <kasan-dev+bncBDHJX64K2UNBBJUASS3QMGQE2I7XD6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 50816978D0F
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 05:16:56 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e1cfb9d655esf4821853276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 20:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726283815; cv=pass;
        d=google.com; s=arc-20240605;
        b=BuKC4wklUWE1V6NdtFYxHlcxz0tU9yrSV3GtCJ31QkQ4k7ufczk0M7XGBEwoh9KYP1
         xy8z+972q2jF6lD3muMYDl8yrjkvwSfmf7jfA8lZNjKbflbavPhqn3Z2d7hiaJHq9cVQ
         2Uk9YVjWrmQQeVY3AeQ773lz9Id0S+OKBw11IjI5zUqrKNg+BMOrxMmbriduHkN/79cg
         YtdttPvA16iPThWdSXVe2kwDvwUtgoUHOMo0XR/cZ6hgaCXibYp+ipQgrgz1O2BGEQq3
         xZM2Z8YMWuu0hNx4XRzhB8lQoIsWYNufH33EAvPhFXLelBm9UhuV0BJ00DlD6315hOy+
         sk3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xNvj5CkrmlBZkQeKo/VBjEvJF9JwU13wlPBrnu+lweE=;
        fh=SKIYmY1kmEyTtrW9odEQ77yN1d0oUi5j4cHJuUGTSFY=;
        b=TP8rvIPul5G7tmnlR4OHPZZ0CQVNUMWv4LdPRSQaAQkUWxzzik+9nTGfcDEFf7yvs2
         5n8Sx76g2fYK5cE6pZLoXNsr5dgz7Z86gzRxN+QxN8Q1rcr3S9nwUNEZkG8wPsvKp8bN
         i3zg8BonaIsAr0FKY8ni1QW5UHTvNmOaX5hQb1jdD1fZsklQUK2npz5326238q+8iPw/
         ZPV8PRwm1yDN7GEiObIlkfrnqwetLhrl/klSt2m4ZpA/YrFHN8negi+EqRhRowLR190R
         iVCGlULelsQrTBDzqn6WnpZ3fBzWdGzwQpoCrTxvgu875TRK0yqfBHl8LtJ13qvbjZgK
         v16A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=XbifMi6j;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726283815; x=1726888615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xNvj5CkrmlBZkQeKo/VBjEvJF9JwU13wlPBrnu+lweE=;
        b=GIKTtcZ/xI6gjTC90MyaoWnuEftV/+5q/V3RSa/A/gzD3UVcr79/x7aXGkJInjKHAy
         yoLiNj1QZMz4ztYZ1Aoj9A34rXcet/jHlOYCoMwbb661AjGpDj/lyje0VLI2o3HD3K3Y
         fUAPa8eA02fn6R1QYPjtzeDmW6pTZGxKac41JbBPAImFJy9XrnNe5kK0Vk4DwvjriZmv
         b6AbKkUv1sWnEwyoVnsNjrRidR5jO6mFOLFWuOqWbnfX6Wy0jBu+LnnEZVS/TIrWhUYx
         xlJdKoZ2gm2YnUG8fvcMyjLgrh6ssyu+gCcMPP3p3eQPMXoHefCJcQA8qCotJGUc0ALf
         EW3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726283815; x=1726888615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xNvj5CkrmlBZkQeKo/VBjEvJF9JwU13wlPBrnu+lweE=;
        b=VsDYK3y30cIt8/9hqiPZgtbhNPunfpM2pgsV+h33OTzErP1DT0fYqeT5HNk/ucHI/Q
         COUS6h/G32SeJGlXb9FwTf8gnNa+eUhMQSvPy1DICM2GyOvKvhJsELhAPAe4a8mZSVSl
         WAdIbZIR9L3Zrh4HNl8jc9oEitLBoRpDUuN+vjcRJWh+YIVP/dmt8MfKD6EF6xl18dVQ
         DISsVq6CbG/VXCsJG5Qw/yuBkCTVg18bmXWv/BVwoqYlQluoZ6O8YaTFa/VDLSmeYv/v
         A/AuqxKWaPa95Kg8yvXPgJFlsV42WJFC6QUX8xZ7CzLFJstdLRbmYbJtekAwG4T43O04
         uwyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXs4kzJRt9GSfQUCDMmyqLeyxOieh9H+U7ZvXF+ITqzXei61HJjospOY/oUBOgzTCBm4YuocA==@lfdr.de
X-Gm-Message-State: AOJu0YxiZ+ADY2SqOUGlvh71oh1ibrdyxxCmhbYMBt0TbG9OnmhufVzG
	xOPKssugj31vZl+tqJhK9xN+ybpTNzhJWExkHcKo2Bx4owew2bmD
X-Google-Smtp-Source: AGHT+IGoJUH3As8eGR44+GCYmffhY2AGpYEwaXO+k6oiLUjwoKQyansWO8q6eyAjZJkG0knb2G8gCQ==
X-Received: by 2002:a05:6902:144d:b0:e1d:8ab0:b233 with SMTP id 3f1490d57ef6-e1d9dc2e31cmr7106840276.37.1726283814902;
        Fri, 13 Sep 2024 20:16:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:723:b0:e0b:be54:a76d with SMTP id
 3f1490d57ef6-e1d9d23856fls3516964276.0.-pod-prod-09-us; Fri, 13 Sep 2024
 20:16:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9W+V6KLo34F1FlQ9DL/bAAs7qtXo6fjLow8vmI0ncpv3RKbcFfeT9apGR8C3xsaqfHixTmY6awc4=@googlegroups.com
X-Received: by 2002:a05:6902:2842:b0:e1d:8a07:8831 with SMTP id 3f1490d57ef6-e1d9dc47d90mr7226367276.47.1726283813964;
        Fri, 13 Sep 2024 20:16:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726283813; cv=none;
        d=google.com; s=arc-20240605;
        b=ZyMISL1BLlMlAc1/m6IieqfeBXVX2dujMt/OGTH7K42uSOeRYpKj1vYoCGBDaSl5Px
         eo05Yw6y47BstqrwX8y2UVffjVUQu7OXjxBn6RFtgUC1O7Dq3GC3aszEiEXxj9vAbMq3
         LnhIAvt07OfjHtejN/ZcoTAgvTtBvnrZw0c+kDeNmYm35PahSaMQOXwAhdhAC/JS9GO7
         4InuQgsHo6xJYCTDibilBw9xWwBdRUsg1Ym8hmdeDthQzC1XBIdSHd8sQzVDSj+T/Kjs
         d748ejKGgTcL8ZsOSVysLpE+lLFhYQzzhWuN2WfVkciDF/JQ+/hs3ef2d7ScT/Rl4pic
         mAVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pqSG34lfAi5Ne7X3rbX1qyEXlbGL1aFEHIudrGSJLbo=;
        fh=PozyOTWL11en9hg+ZEoy6+DDDmnjWAYJAWvfKXAXPDA=;
        b=dVShlSJ467WpNkL2AOP+1y4L6Y4v5quRg8TVn3otZzS2K7kgQ1eI/i7L8i4uvFhlUN
         Rjj0pJMcqjJlvr8qZNESHKOSNEfRHVehyfkWgb35gBbE/v+6BDWj5zBu4qJ9wYB81HHB
         L/olJGFogpmSRA111ww7y+EGm7rUYOXrN/22d8qp8vemp+1aevsQVD07OKHR1/ALIdxR
         FHCrdaejtzXjQ7ddRWAQRa2fHBIRQ9v6c9QGzsr9i1T6/vVBsIlsGNsr4SNIY+6+L1Z0
         3wqZZ7T+weqGmaOpvuvic3oIciXQZXA56qRsaCrGjqZ0/0EflTEsNnE4wadKsPt/QlsU
         x3Yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=XbifMi6j;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1dc1389d1asi33127276.2.2024.09.13.20.16.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 20:16:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-2059204f448so26380935ad.0
        for <kasan-dev@googlegroups.com>; Fri, 13 Sep 2024 20:16:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfvGOIkuOFqu+H3NsZwA3H6RZEpGnzQEa+6JHX+UnDs6leBtbj9zRwQmptdgkoG5Lu5DlWzU3fMz4=@googlegroups.com
X-Received: by 2002:a17:902:ecce:b0:206:8db4:481b with SMTP id d9443c01a7336-2076e39b262mr137995475ad.32.1726283812529;
        Fri, 13 Sep 2024 20:16:52 -0700 (PDT)
Received: from ghost ([2601:647:6700:64d0:3152:a1c7:6cdc:8eeb])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d27ffsm2756785ad.121.2024.09.13.20.16.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Sep 2024 20:16:51 -0700 (PDT)
Date: Fri, 13 Sep 2024 20:16:48 -0700
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
Message-ID: <ZuUAIPZBl6EWomb6@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-6-samuel.holland@sifive.com>
 <ZuOnTvgMv2b/ki9e@ghost>
 <b5b1b654-b603-4e22-ae9c-b712e4d6babe@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b5b1b654-b603-4e22-ae9c-b712e4d6babe@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=XbifMi6j;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
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

On Fri, Sep 13, 2024 at 09:57:05PM -0500, Samuel Holland wrote:
> Hi Charlie,
> 
> On 2024-09-12 9:45 PM, Charlie Jenkins wrote:
> > On Wed, Aug 28, 2024 at 06:01:27PM -0700, Samuel Holland wrote:
> >> When pointer masking is enabled for userspace, the kernel can accept
> >> tagged pointers as arguments to some system calls. Allow this by
> >> untagging the pointers in access_ok() and the uaccess routines. The
> >> uaccess routines must peform untagging in software because U-mode and
> >> S-mode have entirely separate pointer masking configurations. In fact,
> >> hardware may not even implement pointer masking for S-mode.
> >>
> >> Since the number of tag bits is variable, untagged_addr_remote() needs
> >> to know what PMLEN to use for the remote mm. Therefore, the pointer
> >> masking mode must be the same for all threads sharing an mm. Enforce
> >> this with a lock flag in the mm context, as x86 does for LAM. The flag
> >> gets reset in init_new_context() during fork(), as the new mm is no
> >> longer multithreaded.
> >>
> >> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >> ---
> > 
> > Not necessary, but what do you think about adding riscv to include/uapi/linux/prctl.h:
> > 
> > /* Tagged user address controls for arm64 */
> > #define PR_SET_TAGGED_ADDR_CTRL		55
> > #define PR_GET_TAGGED_ADDR_CTRL		56
> > # define PR_TAGGED_ADDR_ENABLE		(1UL << 0)
> 
> Yes, I'll add this in v5.
> 
> > Also looks like this last line should probably be under SET rather than
> > GET.
> 
> The same bit fields are used for both prctl() functions, so I think the current
> grouping is okay (compare PR_RISCV_V_GET_CONTROL).

Oh perfect, I had missed that when I briefly looked.

> 
> Regards,
> Samuel
> 
> > Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
> > Tested-by: Charlie Jenkins <charlie@rivosinc.com>
> > 
> >>
> >> Changes in v4:
> >>  - Combine __untagged_addr() and __untagged_addr_remote()
> >>
> >> Changes in v3:
> >>  - Use IS_ENABLED instead of #ifdef when possible
> >>  - Implement mm_untag_mask()
> >>  - Remove pmlen from struct thread_info (now only in mm_context_t)
> >>
> >> Changes in v2:
> >>  - Implement untagged_addr_remote()
> >>  - Restrict PMLEN changes once a process is multithreaded
> >>
> >>  arch/riscv/include/asm/mmu.h         |  7 +++
> >>  arch/riscv/include/asm/mmu_context.h | 13 +++++
> >>  arch/riscv/include/asm/uaccess.h     | 43 ++++++++++++++--
> >>  arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
> >>  4 files changed, 126 insertions(+), 10 deletions(-)
> >>
> >> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
> >> index c9e03e9da3dc..1cc90465d75b 100644
> >> --- a/arch/riscv/include/asm/mmu.h
> >> +++ b/arch/riscv/include/asm/mmu.h
> >> @@ -25,9 +25,16 @@ typedef struct {
> >>  #ifdef CONFIG_BINFMT_ELF_FDPIC
> >>  	unsigned long exec_fdpic_loadmap;
> >>  	unsigned long interp_fdpic_loadmap;
> >> +#endif
> >> +	unsigned long flags;
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +	u8 pmlen;
> >>  #endif
> >>  } mm_context_t;
> >>  
> >> +/* Lock the pointer masking mode because this mm is multithreaded */
> >> +#define MM_CONTEXT_LOCK_PMLEN	0
> >> +
> >>  #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
> >>  #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
> >>  
> >> diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
> >> index 7030837adc1a..8c4bc49a3a0f 100644
> >> --- a/arch/riscv/include/asm/mmu_context.h
> >> +++ b/arch/riscv/include/asm/mmu_context.h
> >> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
> >>  static inline void activate_mm(struct mm_struct *prev,
> >>  			       struct mm_struct *next)
> >>  {
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +	next->context.pmlen = 0;
> >> +#endif
> >>  	switch_mm(prev, next, NULL);
> >>  }
> >>  
> >> @@ -30,11 +33,21 @@ static inline int init_new_context(struct task_struct *tsk,
> >>  #ifdef CONFIG_MMU
> >>  	atomic_long_set(&mm->context.id, 0);
> >>  #endif
> >> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
> >> +		clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
> >>  	return 0;
> >>  }
> >>  
> >>  DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
> >>  
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +#define mm_untag_mask mm_untag_mask
> >> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
> >> +{
> >> +	return -1UL >> mm->context.pmlen;
> >> +}
> >> +#endif
> >> +
> >>  #include <asm-generic/mmu_context.h>
> >>  
> >>  #endif /* _ASM_RISCV_MMU_CONTEXT_H */
> >> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
> >> index 72ec1d9bd3f3..fee56b0c8058 100644
> >> --- a/arch/riscv/include/asm/uaccess.h
> >> +++ b/arch/riscv/include/asm/uaccess.h
> >> @@ -9,8 +9,41 @@
> >>  #define _ASM_RISCV_UACCESS_H
> >>  
> >>  #include <asm/asm-extable.h>
> >> +#include <asm/cpufeature.h>
> >>  #include <asm/pgtable.h>		/* for TASK_SIZE */
> >>  
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +static inline unsigned long __untagged_addr_remote(struct mm_struct *mm, unsigned long addr)
> >> +{
> >> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
> >> +		u8 pmlen = mm->context.pmlen;
> >> +
> >> +		/* Virtual addresses are sign-extended; physical addresses are zero-extended. */
> >> +		if (IS_ENABLED(CONFIG_MMU))
> >> +			return (long)(addr << pmlen) >> pmlen;
> >> +		else
> >> +			return (addr << pmlen) >> pmlen;
> >> +	}
> >> +
> >> +	return addr;
> >> +}
> >> +
> >> +#define untagged_addr(addr) ({							\
> >> +	unsigned long __addr = (__force unsigned long)(addr);			\
> >> +	(__force __typeof__(addr))__untagged_addr_remote(current->mm, __addr);	\
> >> +})
> >> +
> >> +#define untagged_addr_remote(mm, addr) ({					\
> >> +	unsigned long __addr = (__force unsigned long)(addr);			\
> >> +	mmap_assert_locked(mm);							\
> >> +	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);		\
> >> +})
> >> +
> >> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
> >> +#else
> >> +#define untagged_addr(addr) (addr)
> >> +#endif
> >> +
> >>  /*
> >>   * User space memory access functions
> >>   */
> >> @@ -130,7 +163,7 @@ do {								\
> >>   */
> >>  #define __get_user(x, ptr)					\
> >>  ({								\
> >> -	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
> >> +	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
> >>  	long __gu_err = 0;					\
> >>  								\
> >>  	__chk_user_ptr(__gu_ptr);				\
> >> @@ -246,7 +279,7 @@ do {								\
> >>   */
> >>  #define __put_user(x, ptr)					\
> >>  ({								\
> >> -	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
> >> +	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
> >>  	__typeof__(*__gu_ptr) __val = (x);			\
> >>  	long __pu_err = 0;					\
> >>  								\
> >> @@ -293,13 +326,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
> >>  static inline unsigned long
> >>  raw_copy_from_user(void *to, const void __user *from, unsigned long n)
> >>  {
> >> -	return __asm_copy_from_user(to, from, n);
> >> +	return __asm_copy_from_user(to, untagged_addr(from), n);
> >>  }
> >>  
> >>  static inline unsigned long
> >>  raw_copy_to_user(void __user *to, const void *from, unsigned long n)
> >>  {
> >> -	return __asm_copy_to_user(to, from, n);
> >> +	return __asm_copy_to_user(untagged_addr(to), from, n);
> >>  }
> >>  
> >>  extern long strncpy_from_user(char *dest, const char __user *src, long count);
> >> @@ -314,7 +347,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
> >>  {
> >>  	might_fault();
> >>  	return access_ok(to, n) ?
> >> -		__clear_user(to, n) : n;
> >> +		__clear_user(untagged_addr(to), n) : n;
> >>  }
> >>  
> >>  #define __get_kernel_nofault(dst, src, type, err_label)			\
> >> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> >> index f39221ab5ddd..6e9c84a41c29 100644
> >> --- a/arch/riscv/kernel/process.c
> >> +++ b/arch/riscv/kernel/process.c
> >> @@ -204,6 +204,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
> >>  	unsigned long tls = args->tls;
> >>  	struct pt_regs *childregs = task_pt_regs(p);
> >>  
> >> +	/* Ensure all threads in this mm have the same pointer masking mode. */
> >> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
> >> +		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
> >> +
> >>  	memset(&p->thread.s, 0, sizeof(p->thread.s));
> >>  
> >>  	/* p->thread holds context to be restored by __switch_to() */
> >> @@ -249,10 +253,16 @@ enum {
> >>  static bool have_user_pmlen_7;
> >>  static bool have_user_pmlen_16;
> >>  
> >> +/*
> >> + * Control the relaxed ABI allowing tagged user addresses into the kernel.
> >> + */
> >> +static unsigned int tagged_addr_disabled;
> >> +
> >>  long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
> >>  {
> >> -	unsigned long valid_mask = PR_PMLEN_MASK;
> >> +	unsigned long valid_mask = PR_PMLEN_MASK | PR_TAGGED_ADDR_ENABLE;
> >>  	struct thread_info *ti = task_thread_info(task);
> >> +	struct mm_struct *mm = task->mm;
> >>  	unsigned long pmm;
> >>  	u8 pmlen;
> >>  
> >> @@ -267,16 +277,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
> >>  	 * in case choosing a larger PMLEN has a performance impact.
> >>  	 */
> >>  	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
> >> -	if (pmlen == PMLEN_0)
> >> +	if (pmlen == PMLEN_0) {
> >>  		pmm = ENVCFG_PMM_PMLEN_0;
> >> -	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
> >> +	} else if (pmlen <= PMLEN_7 && have_user_pmlen_7) {
> >> +		pmlen = PMLEN_7;
> >>  		pmm = ENVCFG_PMM_PMLEN_7;
> >> -	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
> >> +	} else if (pmlen <= PMLEN_16 && have_user_pmlen_16) {
> >> +		pmlen = PMLEN_16;
> >>  		pmm = ENVCFG_PMM_PMLEN_16;
> >> -	else
> >> +	} else {
> >>  		return -EINVAL;
> >> +	}
> >> +
> >> +	/*
> >> +	 * Do not allow the enabling of the tagged address ABI if globally
> >> +	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
> >> +	 * is disabled for userspace.
> >> +	 */
> >> +	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
> >> +		return -EINVAL;
> >> +
> >> +	if (!(arg & PR_TAGGED_ADDR_ENABLE))
> >> +		pmlen = PMLEN_0;
> >> +
> >> +	if (mmap_write_lock_killable(mm))
> >> +		return -EINTR;
> >> +
> >> +	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
> >> +		mmap_write_unlock(mm);
> >> +		return -EBUSY;
> >> +	}
> >>  
> >>  	envcfg_update_bits(task, ENVCFG_PMM, pmm);
> >> +	mm->context.pmlen = pmlen;
> >> +
> >> +	mmap_write_unlock(mm);
> >>  
> >>  	return 0;
> >>  }
> >> @@ -289,6 +324,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
> >>  	if (is_compat_thread(ti))
> >>  		return -EINVAL;
> >>  
> >> +	/*
> >> +	 * The mm context's pmlen is set only when the tagged address ABI is
> >> +	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
> >> +	 */
> >>  	switch (task->thread.envcfg & ENVCFG_PMM) {
> >>  	case ENVCFG_PMM_PMLEN_7:
> >>  		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
> >> @@ -298,6 +337,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
> >>  		break;
> >>  	}
> >>  
> >> +	if (task->mm->context.pmlen)
> >> +		ret |= PR_TAGGED_ADDR_ENABLE;
> >> +
> >>  	return ret;
> >>  }
> >>  
> >> @@ -307,6 +349,24 @@ static bool try_to_set_pmm(unsigned long value)
> >>  	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
> >>  }
> >>  
> >> +/*
> >> + * Global sysctl to disable the tagged user addresses support. This control
> >> + * only prevents the tagged address ABI enabling via prctl() and does not
> >> + * disable it for tasks that already opted in to the relaxed ABI.
> >> + */
> >> +
> >> +static struct ctl_table tagged_addr_sysctl_table[] = {
> >> +	{
> >> +		.procname	= "tagged_addr_disabled",
> >> +		.mode		= 0644,
> >> +		.data		= &tagged_addr_disabled,
> >> +		.maxlen		= sizeof(int),
> >> +		.proc_handler	= proc_dointvec_minmax,
> >> +		.extra1		= SYSCTL_ZERO,
> >> +		.extra2		= SYSCTL_ONE,
> >> +	},
> >> +};
> >> +
> >>  static int __init tagged_addr_init(void)
> >>  {
> >>  	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> >> @@ -320,6 +380,9 @@ static int __init tagged_addr_init(void)
> >>  	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
> >>  	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
> >>  
> >> +	if (!register_sysctl("abi", tagged_addr_sysctl_table))
> >> +		return -EINVAL;
> >> +
> >>  	return 0;
> >>  }
> >>  core_initcall(tagged_addr_init);
> >> -- 
> >> 2.45.1
> >>
> >>
> >> _______________________________________________
> >> linux-riscv mailing list
> >> linux-riscv@lists.infradead.org
> >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuUAIPZBl6EWomb6%40ghost.
