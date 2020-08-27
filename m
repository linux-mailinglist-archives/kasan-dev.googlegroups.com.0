Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJWWT35AKGQE5GVVBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E855D25453C
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:46:31 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id o184sf4182065pfb.12
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598532390; cv=pass;
        d=google.com; s=arc-20160816;
        b=hE7KEYDJE5YlvznHhfx/dQppUqoZ19yRYY8BtrXHVUn1tk8LkmDwDMLrDLmPAXo4EO
         8RQVb1KBOj7FWYT7XtB+tT2itSF30jZ9rzWgB4D+Dpd5ijtfif/rKyl8MsXqeMV/DPMA
         iZPeeEJ8fvew9C10cnxa+e52tjD0mysLHl5DvUc+B/R2RqpWPS21QrtLx+t9X2ROqeyd
         fjEIcjv+9HMZD/a0jlh7mHI7zhVyMqKlOpMbkAByZ/uvF3HMtm7DxwGp5gfkuu2UzQu2
         S1/RTMJzlWbt2ULp3Gaa5ysO69PVrP4uYeCchw4/N04682eqEwGjptTyXfx3pxTCWivg
         HTUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fsvu0P8BEUmUOKB+1KD6oEUvONkky02+N0gRjYjZZ3U=;
        b=vcPksXPOHYhsAxHzPvchslsV1+zmIJbcNKdYlVOuTT7dXiRd0+/smLm0bLA64J4p3V
         qlBncB5L1brfddFVwzJyEuQbncwHLmexm5RSRG6WLaI0qbIukblB3Ft//5dEuSKB1+GS
         6ajD5Pw+7X5uuI6HT3eoyIyFjmYlhZOdq3D6xDTzUxbszw1nWdMPvfdK3FS0ExoP0mTD
         64b2xpVWINJgVjq4rY3mGPBZ2qI3dFZ/65xoMC67RphxjnG6sX1bh4cvNCEBpesEWs8D
         B/noKEPhY8oEjCJE/pXAVsoTRQ1pWl0s8in7ISJaxKocGBbPYIez0R0xSkeAguC/rb4Z
         FYzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gdEkfTqR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsvu0P8BEUmUOKB+1KD6oEUvONkky02+N0gRjYjZZ3U=;
        b=gXpnfee20GU8unvdwIgual2s/NTw5kHAWG9kAwoEqfJkByLoL/Xhk4+1LygiaYDJB8
         +YGvOWPXPWSy/EPeNQqMt+SXVS4AETUWX+OE443ELrcMpFcw3u7pu8c46VXSW52urRdt
         8y00NQcUkVpN6647vTp7R36cNXLOLwt+4PzZoIyAI9wJ7HRxFddJXkccLk/cJvDtX1qm
         0ASlL+NLdiffBgUFEJLmRdafwKPZ3zEe3Fwg3j9mn+w9vijZRLo29TZwogkO/WT2kjmF
         MmtgNxrCvT3LqnnfRINXijTGEr2DxD/Fdc+8YICMVAgO8wBNrgAhBPbWkrc0EqfCNwkC
         diPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsvu0P8BEUmUOKB+1KD6oEUvONkky02+N0gRjYjZZ3U=;
        b=JkwYK11MJ8dmC0/Ta006S8VXkIUlZT3jZQ9LERiaZ4ptS/EZwSRebIPLcyud3iJTxB
         yqU2WtCuwSEfwk3UCwP4/ez5NcH9bxT9++zeAYci0HvotLTZP0e8fRnTJulQxXwajJCX
         xO/rDIx3ud0L4MSbyoIhxMLNWyWY0PQKlM3ZBiFxzF3XW6/fOg+aNgs81UbjoyKofSsY
         //3JLWXR6RWETgiFS02kiZqQeGFFTEU1J8gvQ6kNb2tRXhuf4IDtJknfZR2rzTzK2htL
         ZpzhQcK+xyHuu2ITRmRF+IwCP1Y/qmz0BxWqULOfNpGvOku0LakZCi1vjEdbfYTfQIfE
         t79Q==
X-Gm-Message-State: AOAM530MKkxJi8QjORq6fVdX149boBuSnqz7r4+3Y+Noj6oQWarLxYvA
	nO+TgEvedr7w6QV9xJFKExE=
X-Google-Smtp-Source: ABdhPJyKU6mVsziTbDtTxukuQQUY+yJVKYP0DPxmv9PwzT6jvpmixXirWRfTp2ZUX8nA42nqW5nx3w==
X-Received: by 2002:a63:df01:: with SMTP id u1mr13328873pgg.401.1598532390646;
        Thu, 27 Aug 2020 05:46:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b602:: with SMTP id b2ls1168239pls.11.gmail; Thu, 27
 Aug 2020 05:46:30 -0700 (PDT)
X-Received: by 2002:a17:90a:eb15:: with SMTP id j21mr10904332pjz.83.1598532390202;
        Thu, 27 Aug 2020 05:46:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598532390; cv=none;
        d=google.com; s=arc-20160816;
        b=AOXBBXqKwlwI47g33XXj/WGgduiux/nzsN7WMsaHYRVFugOO0BR4PI9aR9y6LT3uBP
         mF/iWmFJWs8sTO9ZzdcRZdJ7xaLalWyX4zpYzYVpxc1Q4tjPCl6nsp25mh8xLGtTUTeP
         VCvzkx+M1E5kvgFVxC7boShd2AClg8JUVTBgbVQd/8rWsJh67oz9lZdY4L2997Jzh69k
         tzrFelE/TiWvUfwgkuhWnqvDLtLdlkYwDwVCjeKR7TxGHoshPTnKoIrSm+UNtWB4dH1d
         X5vco64eM+VC6yVxUY2vLHhlNXItIbOzaJYLO6R+NU6tDBBM4TfJW5nIHYwcvwtajOpW
         S4pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BHmZEvhLEtaO7aqOAe1Kz0vxpzzyDph3TU1ME4obtnc=;
        b=mWzo/+tpHaGFxqIlkp2Eu/6f/4RWpRGVFt9iDddNesqVhS/pKhAaCMV8qu6MlCIqJS
         6bBLndzWS7S+9Mzb6jQeHo4C4KMU7s8ht2v6NcviV7ty1t7414PTxDRx2G/9f7qKUDMV
         T9ViVdKaoHktjt9wzpovboSLS/8LRTYggYAkypr+ntlAbrTOy7sn7JEz7997q9mJZ4QD
         19SWM8cu18IPAeYS7kcouAiiU6CUalkOaVOjEjBDXnJxLrMNuoZkmTwFWzRNFi38CS2l
         RIJOmnKmavb8cFO0HFmjJd1MPICAzUfaD8akuMoG3bGpO4lUNPf/n8g5QYqK4UIP9eFX
         TgXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gdEkfTqR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id bg1si111572plb.5.2020.08.27.05.46.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:46:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id kx11so2530724pjb.5
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:46:30 -0700 (PDT)
X-Received: by 2002:a17:90a:2d82:: with SMTP id p2mr9503738pjd.166.1598532389629;
 Thu, 27 Aug 2020 05:46:29 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia>
In-Reply-To: <20200827093808.GB29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:46:18 +0200
Message-ID: <CAAeHK+xFzMRLuYtPV4gsb5FByFLp0Czt2+kokYKnp+L3kQwKvg@mail.gmail.com>
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gdEkfTqR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
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

On Thu, Aug 27, 2020 at 11:38 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index 1c99fcadb58c..733be1cb5c95 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -5,14 +5,19 @@
> >  #ifndef __ASM_MTE_H
> >  #define __ASM_MTE_H
> >
> > -#define MTE_GRANULE_SIZE     UL(16)
> > +#include <asm/mte_asm.h>
>
> So the reason for this move is to include it in asm/cache.h. Fine by
> me but...
>
> >  #define MTE_GRANULE_MASK     (~(MTE_GRANULE_SIZE - 1))
> >  #define MTE_TAG_SHIFT                56
> >  #define MTE_TAG_SIZE         4
> > +#define MTE_TAG_MASK         GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> > +#define MTE_TAG_MAX          (MTE_TAG_MASK >> MTE_TAG_SHIFT)
>
> ... I'd rather move all these definitions in a file with a more
> meaningful name like mte-def.h. The _asm implies being meant for .S
> files inclusion which isn't the case.

Sounds good, I'll leave fixing this and other arm64-specific comments
to Vincenzo. I'll change KASAN code to use mte-def.h once I have
patches where this file is renamed.

>
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index eb39504e390a..e2d708b4583d 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
> >       return ret;
> >  }
> >
> > +u8 mte_get_mem_tag(void *addr)
> > +{
> > +     if (system_supports_mte())
> > +             addr = mte_assign_valid_ptr_tag(addr);
>
> The mte_assign_valid_ptr_tag() is slightly misleading. All it does is
> read the allocation tag from memory.
>
> I also think this should be inline asm, possibly using alternatives.
> It's just an LDG instruction (and it saves us from having to invent a
> better function name).
>
> > +
> > +     return 0xF0 | mte_get_ptr_tag(addr);
> > +}
> > +
> > +u8 mte_get_random_tag(void)
> > +{
> > +     u8 tag = 0xF;
> > +
> > +     if (system_supports_mte())
> > +             tag = mte_get_ptr_tag(mte_assign_random_ptr_tag(NULL));
>
> Another alternative inline asm with an IRG instruction.
>
> > +
> > +     return 0xF0 | tag;
> > +}
> > +
> > +void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> > +{
> > +     void *ptr = addr;
> > +
> > +     if ((!system_supports_mte()) || (size == 0))
> > +             return addr;
> > +
> > +     tag = 0xF0 | (tag & 0xF);
> > +     ptr = (void *)__tag_set(ptr, tag);
> > +     size = ALIGN(size, MTE_GRANULE_SIZE);
>
> I think aligning the size is dangerous. Can we instead turn it into a
> WARN_ON if not already aligned? At a quick look, the callers of
> kasan_{un,}poison_memory() already align the size.
>
> > +
> > +     mte_assign_mem_tag_range(ptr, size);
> > +
> > +     /*
> > +      * mte_assign_mem_tag_range() can be invoked in a multi-threaded
> > +      * context, ensure that tags are written in memory before the
> > +      * reference is used.
> > +      */
> > +     smp_wmb();
> > +
> > +     return ptr;
>
> I'm not sure I understand the barrier here. It ensures the relative
> ordering of memory (or tag) accesses on a CPU as observed by other CPUs.
> While the first access here is setting the tag, I can't see what other
> access on _this_ CPU it is ordered with.
>
> > +}
> > +
> >  static void update_sctlr_el1_tcf0(u64 tcf0)
> >  {
> >       /* ISB required for the kernel uaccess routines */
> > diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> > index 03ca6d8b8670..8c743540e32c 100644
> > --- a/arch/arm64/lib/mte.S
> > +++ b/arch/arm64/lib/mte.S
> > @@ -149,3 +149,44 @@ SYM_FUNC_START(mte_restore_page_tags)
> >
> >       ret
> >  SYM_FUNC_END(mte_restore_page_tags)
> > +
> > +/*
> > + * Assign pointer tag based on the allocation tag
> > + *   x0 - source pointer
> > + * Returns:
> > + *   x0 - pointer with the correct tag to access memory
> > + */
> > +SYM_FUNC_START(mte_assign_valid_ptr_tag)
> > +     ldg     x0, [x0]
> > +     ret
> > +SYM_FUNC_END(mte_assign_valid_ptr_tag)
> > +
> > +/*
> > + * Assign random pointer tag
> > + *   x0 - source pointer
> > + * Returns:
> > + *   x0 - pointer with a random tag
> > + */
> > +SYM_FUNC_START(mte_assign_random_ptr_tag)
> > +     irg     x0, x0
> > +     ret
> > +SYM_FUNC_END(mte_assign_random_ptr_tag)
>
> As I said above, these two can be inline asm.
>
> > +
> > +/*
> > + * Assign allocation tags for a region of memory based on the pointer tag
> > + *   x0 - source pointer
> > + *   x1 - size
> > + *
> > + * Note: size is expected to be MTE_GRANULE_SIZE aligned
> > + */
> > +SYM_FUNC_START(mte_assign_mem_tag_range)
> > +     /* if (src == NULL) return; */
> > +     cbz     x0, 2f
> > +     /* if (size == 0) return; */
>
> You could skip the cbz here and just document that the size should be
> non-zero and aligned. The caller already takes care of this check.
>
> > +     cbz     x1, 2f
> > +1:   stg     x0, [x0]
> > +     add     x0, x0, #MTE_GRANULE_SIZE
> > +     sub     x1, x1, #MTE_GRANULE_SIZE
> > +     cbnz    x1, 1b
> > +2:   ret
> > +SYM_FUNC_END(mte_assign_mem_tag_range)
>
> --
> Catalin
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827093808.GB29264%40gaia.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxFzMRLuYtPV4gsb5FByFLp0Czt2%2BkokYKnp%2BL3kQwKvg%40mail.gmail.com.
