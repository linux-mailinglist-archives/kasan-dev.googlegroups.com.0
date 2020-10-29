Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR7G5P6AKGQEJTNRRPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A0ADC29F23B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 17:52:24 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id j10sf2546091pgc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 09:52:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603990343; cv=pass;
        d=google.com; s=arc-20160816;
        b=TWkL4A5T6ykz0Uq6RZrr84k7jeN8+uykiC6wEyQdWVfCVXV6rKSqdXqjE+U8xSS7Rf
         xoRpcQ2N4eJIsFsBWtDXQiWkLu6bFDVfR4xH6+fwZy56l4Fp247pBNacL92aSBisnUGu
         XEq/Hfd++VWJX7XvGr0zIrLeyyN8Xo76OXbephigVaiu9N/fBq4nKMSfqQcGT0LxgQjG
         cth6lXNHy3kbgL8jDwLGcLCcGqreSePEe53ThFXElQQ+ieA1ZBgzAUE/SfQoZleNK+x3
         30PB28RdKKK5Zpf8E3qidKmPw+In/NT5JwgXBlc4e+NBk3e5o0H9LmxQn6YmdQ5n2Hsa
         qDLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E06DiIaI5dSfnDzviLVsqcPyJo6ob1k8cd7E0eEoMcw=;
        b=e4x/vdf/CkPGwmlIjphiskrf0vRF30q6qpIx5w2j8/0a+vo98ZyhYCDA8uFuzimVLG
         YxUb+xljiXsD+JkGlEIvswm3pqNzqpHTWK9k/mttniNJ3QrdzXmzKUq5mIvhVBiZrApk
         uUC75m4vrD9g9oDQDzbtoDCQ5n7uduvjLIEiEZIuBxb30YcfBMzvBfaVg4AIHsmqeZg1
         3tpnjEhSmyASBNvnn/goLceqordJUWVKDWiMHQAudxvpIHJ84P7eVB6NkvlTWvTlEMs0
         1XX/U+N3L61OCf56BzHYBPzFmZGHmTYUurlx+Lw9HTHCTuPxhXu2eANago4zHxRP6omM
         b3Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lTkAVN1I;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E06DiIaI5dSfnDzviLVsqcPyJo6ob1k8cd7E0eEoMcw=;
        b=DxssV0lifgRAh1tH5xMyaZ8h83iA7NEvGSs3UapHRb711JQFXz6vFZpdaKUYEU3N6V
         wsY3d/Y6olVEQk2eDxR2McF3yc0XuKiqhC/0Vx9ZfLHxBbZlt2CMbw+4XKiUC7E+tVCY
         wDOaIL+n2mlULcIppjPbnfJUfEC97toj9sUqvs1VD79+S/x2rg1HIviGfXu8x2042khX
         mY8DtOmvnLB+enmtOq2STpb5QTOTfO4JOAw/K6fPAgAVov95DKj2ZLhin18GlCg8ou9P
         xciMWfpAZmmgWCx2Q0/spryUo70jqNpG1Uj8wd8/dS3zuhgJOJ9xehgojcaEVZu5VPTK
         r07g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E06DiIaI5dSfnDzviLVsqcPyJo6ob1k8cd7E0eEoMcw=;
        b=UBBQt03Kn7+2n2xIecMApq0pLGw+SQZPxQfTsQ88BUaSh54OJAACGS2bp4v4/d4WjC
         r0J96+JFAYl+eOHyzY9Xm44HxJahHWngycDuJBP93vMCEKdI0lY9m+gkw1cY4QH/YuXv
         WBpoAooWt43inBe2b+D23Lhqpn30AGPLD89TPSFYIDJCPtPrq1SmSFX9n6SBxMTNlnJg
         USTPfg2c+BvgAVXioCCeO5mxwZO8wGQohCFXiCdIj8HEyd1mIuqLBxJK3g+CwErtr0ac
         yUW965FQQVWQkGNYzeDjuCB/+Tkmu4KCRDu7dayEo+66DN98AEMiTU9GmC220EZC2Cbg
         vR7A==
X-Gm-Message-State: AOAM531qCXT6Ke7ZU0rYs14GYSeAXDG7PYGiqMZet13dtE3o4batfV2D
	t+P4i2a1p0rD9MFIWQPhEyk=
X-Google-Smtp-Source: ABdhPJwj45AX8pFtmwQINWxXm2yz6Q8nIAZQCsLY6ApFwSgf1fTPcf7hwRjSdiv7cDApbVeqfMZjrw==
X-Received: by 2002:a62:528c:0:b029:160:193:76bc with SMTP id g134-20020a62528c0000b0290160019376bcmr5095150pfb.24.1603990343357;
        Thu, 29 Oct 2020 09:52:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1536774plr.3.gmail; Thu, 29
 Oct 2020 09:52:22 -0700 (PDT)
X-Received: by 2002:a17:90a:aa15:: with SMTP id k21mr637917pjq.169.1603990342561;
        Thu, 29 Oct 2020 09:52:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603990342; cv=none;
        d=google.com; s=arc-20160816;
        b=JLh0yiZDy6tTDduWJoQPW44uILyTW/glqz6LUeW5x+tRSCetjby+Ars/GaoyH3ICPl
         hscoMeTvrPFWUHdu2HC6nK9nJrkiSHwNOXEUa2crqi0XygENzIgFHFaf9lW0wKwFG2tx
         9/SfqqLZTCSAl/cf48X0fo3EjUrCoywtmI/p1LlnuKgmXZA//6nIxyB0mFHcv//j3mD0
         D65Q0Kq2n/LcEkLtE5QG74z9My8O3o4j9pRBm5AEW0ZQ8SkHjcARnWrWyB1gfN6itJrC
         +6KbsFu8+9FI4XvMN7MN3Fivc4HZiLInmI6MPtm5P9I1BsDLMqmKNZhoXmnrBCQuFDme
         km1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z84dO34gfl99F5MNenPSh6+wKNbdWfjMSfVr1uk1Zcc=;
        b=Shm3jEsI1dK2xyIvyymi2Xm/fCUzhQmlx9WjRP33cHd04UcGx4+lGo9d8LoqdTI57b
         pMvJKmzCCtxck4Pd/Q17nmuxCB7v3enksX48Bfq4ExFGmeYarPLjkZBcQ9v2u5uPI2Ww
         CQrZzf9pnNfq4G9yDDptu/yotALEOezaRvwsqHsNDqb8lRc65U/g1slSwi+qBfxZwM96
         zWjYAY48MSWG+AbJryHznhbXVwHNFp43zI5kGtltuNy4kJWywR1INcIzek2caHZK9Jhd
         KICgymMPd8DL5kQ4oN35Xmi4QW3liRqaPr1wl35XqYGD7XeBPqqjPyrLV/x3vSxR9NJy
         9KmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lTkAVN1I;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id t13si221037ply.2.2020.10.29.09.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 09:52:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id r186so2852265pgr.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 09:52:22 -0700 (PDT)
X-Received: by 2002:a17:90a:f293:: with SMTP id fs19mr664418pjb.41.1603990342099;
 Thu, 29 Oct 2020 09:52:22 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com> <33c0811d707356b7b267b2de41b55b2728940723.1602535397.git.andreyknvl@google.com>
 <CACT4Y+ZyaqdYic_K6Mj9RcvO+23OQ0q2Pe-c3YS1zMW4j1woQw@mail.gmail.com>
In-Reply-To: <CACT4Y+ZyaqdYic_K6Mj9RcvO+23OQ0q2Pe-c3YS1zMW4j1woQw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 17:52:11 +0100
Message-ID: <CAAeHK+yARu1Qh46DPbfs4h37yHPAVgx6r8r=86L6jfHD3up8-g@mail.gmail.com>
Subject: Re: [PATCH v5 08/40] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lTkAVN1I;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 28, 2020 at 11:07 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 12, 2020 at 10:45 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >
> > When MTE is present, the GCR_EL1 register contains the tags mask that
> > allows to exclude tags from the random generation via the IRG instruction.
> >
> > With the introduction of the new Tag-Based KASAN API that provides a
> > mechanism to reserve tags for special reasons, the MTE implementation
> > has to make sure that the GCR_EL1 setting for the kernel does not affect
> > the userspace processes and viceversa.
> >
> > Save and restore the kernel/user mask in GCR_EL1 in kernel entry and exit.
> >
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> > ---
> > Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
> > ---
> >  arch/arm64/include/asm/mte-def.h   |  1 -
> >  arch/arm64/include/asm/mte-kasan.h |  6 +++++
> >  arch/arm64/include/asm/mte.h       |  2 ++
> >  arch/arm64/kernel/asm-offsets.c    |  3 +++
> >  arch/arm64/kernel/cpufeature.c     |  3 +++
> >  arch/arm64/kernel/entry.S          | 41 ++++++++++++++++++++++++++++++
> >  arch/arm64/kernel/mte.c            | 22 +++++++++++++---
> >  7 files changed, 74 insertions(+), 4 deletions(-)
> >
> > diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
> > index 8401ac5840c7..2d73a1612f09 100644
> > --- a/arch/arm64/include/asm/mte-def.h
> > +++ b/arch/arm64/include/asm/mte-def.h
> > @@ -10,6 +10,5 @@
> >  #define MTE_TAG_SHIFT          56
> >  #define MTE_TAG_SIZE           4
> >  #define MTE_TAG_MASK           GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> > -#define MTE_TAG_MAX            (MTE_TAG_MASK >> MTE_TAG_SHIFT)
> >
> >  #endif /* __ASM_MTE_DEF_H  */
> > diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> > index 3a70fb1807fd..a4c61b926d4a 100644
> > --- a/arch/arm64/include/asm/mte-kasan.h
> > +++ b/arch/arm64/include/asm/mte-kasan.h
> > @@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
> >  u8 mte_get_random_tag(void);
> >  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> >
> > +void mte_init_tags(u64 max_tag);
>
> This should be marked as __init?

Makes sense. I'll add this change into the other series together with
the patch that marks kasan_init_tags() as __init.

>
>
> >  #else /* CONFIG_ARM64_MTE */
> >
> >  static inline u8 mte_get_ptr_tag(void *ptr)
> > @@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >         return addr;
> >  }
> >
> > +static inline void mte_init_tags(u64 max_tag)
> > +{
> > +}
> > +
> >  #endif /* CONFIG_ARM64_MTE */
> >
> >  #endif /* __ASSEMBLY__ */
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index cf1cd181dcb2..d02aff9f493d 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -18,6 +18,8 @@
> >
> >  #include <asm/pgtable-types.h>
> >
> > +extern u64 gcr_kernel_excl;
> > +
> >  void mte_clear_page_tags(void *addr);
> >  unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
> >                                       unsigned long n);
> > diff --git a/arch/arm64/kernel/asm-offsets.c b/arch/arm64/kernel/asm-offsets.c
> > index 7d32fc959b1a..dfe6ed8446ac 100644
> > --- a/arch/arm64/kernel/asm-offsets.c
> > +++ b/arch/arm64/kernel/asm-offsets.c
> > @@ -47,6 +47,9 @@ int main(void)
> >  #ifdef CONFIG_ARM64_PTR_AUTH
> >    DEFINE(THREAD_KEYS_USER,     offsetof(struct task_struct, thread.keys_user));
> >    DEFINE(THREAD_KEYS_KERNEL,   offsetof(struct task_struct, thread.keys_kernel));
> > +#endif
> > +#ifdef CONFIG_ARM64_MTE
> > +  DEFINE(THREAD_GCR_EL1_USER,  offsetof(struct task_struct, thread.gcr_user_excl));
> >  #endif
> >    BLANK();
> >    DEFINE(S_X0,                 offsetof(struct pt_regs, regs[0]));
> > diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> > index eca06b8c74db..e76634ad5bc7 100644
> > --- a/arch/arm64/kernel/cpufeature.c
> > +++ b/arch/arm64/kernel/cpufeature.c
> > @@ -1721,6 +1721,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
> >
> >         /* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
> > +               /* Enable the kernel exclude mask for random tags generation */
> > +               write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
> > +
> >                 /* Enable MTE Sync Mode for EL1 */
> >                 sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> >                 isb();
> > diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> > index ff34461524d4..eeaac91021bf 100644
> > --- a/arch/arm64/kernel/entry.S
> > +++ b/arch/arm64/kernel/entry.S
> > @@ -175,6 +175,43 @@ alternative_else_nop_endif
> >  #endif
> >         .endm
> >
> > +       .macro mte_set_gcr, tmp, tmp2
> > +#ifdef CONFIG_ARM64_MTE
> > +       /*
> > +        * Calculate and set the exclude mask preserving
> > +        * the RRND (bit[16]) setting.
> > +        */
> > +       mrs_s   \tmp2, SYS_GCR_EL1
> > +       bfi     \tmp2, \tmp, #0, #16
> > +       msr_s   SYS_GCR_EL1, \tmp2
> > +       isb
> > +#endif
> > +       .endm
> > +
> > +       .macro mte_set_kernel_gcr, tmp, tmp2
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +alternative_if_not ARM64_MTE
> > +       b       1f
> > +alternative_else_nop_endif
> > +       ldr_l   \tmp, gcr_kernel_excl
> > +
> > +       mte_set_gcr \tmp, \tmp2
> > +1:
> > +#endif
> > +       .endm
> > +
> > +       .macro mte_set_user_gcr, tsk, tmp, tmp2
> > +#ifdef CONFIG_ARM64_MTE
> > +alternative_if_not ARM64_MTE
> > +       b       1f
> > +alternative_else_nop_endif
> > +       ldr     \tmp, [\tsk, #THREAD_GCR_EL1_USER]
> > +
> > +       mte_set_gcr \tmp, \tmp2
> > +1:
> > +#endif
> > +       .endm
> > +
> >         .macro  kernel_entry, el, regsize = 64
> >         .if     \regsize == 32
> >         mov     w0, w0                          // zero upper 32 bits of x0
> > @@ -214,6 +251,8 @@ alternative_else_nop_endif
> >
> >         ptrauth_keys_install_kernel tsk, x20, x22, x23
> >
> > +       mte_set_kernel_gcr x22, x23
> > +
> >         scs_load tsk, x20
> >         .else
> >         add     x21, sp, #S_FRAME_SIZE
> > @@ -332,6 +371,8 @@ alternative_else_nop_endif
> >         /* No kernel C function calls after this as user keys are set. */
> >         ptrauth_keys_install_user tsk, x0, x1, x2
> >
> > +       mte_set_user_gcr tsk, x0, x1
> > +
> >         apply_ssbd 0, x0, x1
> >         .endif
> >
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index a9f03be75cef..ca8206b7f9a6 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -23,6 +23,8 @@
> >  #include <asm/ptrace.h>
> >  #include <asm/sysreg.h>
> >
> > +u64 gcr_kernel_excl __ro_after_init;
> > +
> >  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
> >  {
> >         pte_t old_pte = READ_ONCE(*ptep);
> > @@ -121,6 +123,17 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >         return ptr;
> >  }
> >
> > +void mte_init_tags(u64 max_tag)
> > +{
> > +       /*
> > +        * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> > +        * This conversion is required to extract the MTE tag from a KASAN one.
> > +        */
> > +       u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);
> > +
> > +       gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> > +}
> > +
> >  static void update_sctlr_el1_tcf0(u64 tcf0)
> >  {
> >         /* ISB required for the kernel uaccess routines */
> > @@ -156,7 +169,11 @@ static void update_gcr_el1_excl(u64 excl)
> >  static void set_gcr_el1_excl(u64 excl)
> >  {
> >         current->thread.gcr_user_excl = excl;
> > -       update_gcr_el1_excl(excl);
> > +
> > +       /*
> > +        * SYS_GCR_EL1 will be set to current->thread.gcr_user_excl value
> > +        * by mte_set_user_gcr() in kernel_exit,
> > +        */
> >  }
> >
> >  void flush_mte_state(void)
> > @@ -182,7 +199,6 @@ void mte_thread_switch(struct task_struct *next)
> >         /* avoid expensive SCTLR_EL1 accesses if no change */
> >         if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
> >                 update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> > -       update_gcr_el1_excl(next->thread.gcr_user_excl);
> >  }
> >
> >  void mte_suspend_exit(void)
> > @@ -190,7 +206,7 @@ void mte_suspend_exit(void)
> >         if (!system_supports_mte())
> >                 return;
> >
> > -       update_gcr_el1_excl(current->thread.gcr_user_excl);
> > +       update_gcr_el1_excl(gcr_kernel_excl);
> >  }
> >
> >  long set_mte_ctrl(struct task_struct *task, unsigned long arg)
> > --
> > 2.28.0.1011.ga647a8990f-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByARu1Qh46DPbfs4h37yHPAVgx6r8r%3D86L6jfHD3up8-g%40mail.gmail.com.
