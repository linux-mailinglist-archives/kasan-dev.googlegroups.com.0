Return-Path: <kasan-dev+bncBD52JJ7JXILRB5EGSCCQMGQESNAXQ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 561F4387F4F
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 20:12:06 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id x24-20020aa784d80000b02902dd5846d381sf3089806pfn.20
        for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 11:12:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621361524; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp2Oi/afGsni5qSXb1Dfiiu5dtap/9vfr+hBrK2fPL6385k401ji3GNeVf3Chbk+KG
         uvxOcPK0juW4vQt4k2eqImTAJ6l7Wa6uyJ8+wmEhXoa3T6Tf8fUzfmP/byzhpf3ksvxl
         EP/R37cv+KgDQqZ/Nsw1wMHi0TXg2LZTNlnxpHbTl8ubwntm35sKe/1fo3peHai9mDc/
         lhgAuPG4xKxaZ6jQ5OYbRclk6Q1brkxPD3GTuUY4HbMtlNe3in9F9aeY4vNsPBvadI8L
         47Ot1I/iK+8Ud1uCveiOwAgQnLpHDLqmlMw+nN1y0j8bSxDYtctz51z8RE0n2XFLfG4L
         RU1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Me3lKKiALwsV55uz6OmwYeCt+bJsLUYqYeDJ2HE/LpI=;
        b=IeU/8eMbVvFtCuFX4X3TkDrLKBCIbuONfahIVg/KUIOQXuCwXYVNt9eJK29pQMT/Xl
         dMwUwRaI8P8mJGEaS5DnsUvrCP0AUPTkP7BxR/fAuFLCtUgVMf62MOYJ2K/VGNQCRtN2
         9QCLj8Wd98d014M02Rh6/DubSu702yBKBjyaagvZ0xnsXEdQhecUcznsJBdeCN9OkMlU
         CYi/EQKwoEJMW/bxSB5g2nXDdkQ+9Zh/YCowB86yWG5vdkFvUd5We36gyLjQPyD6rY5F
         EQpzsG3CjfFAtn+bd6y+Oh6FxWaklyASw272y7OMWPd6l+xqxx0ouxBDFzwMsjl7b/LL
         vGqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SPI3jgv8;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Me3lKKiALwsV55uz6OmwYeCt+bJsLUYqYeDJ2HE/LpI=;
        b=VWpq99u2Wwlgdvx5l6/w95i5ohpSF6Gos3TNMBgNTnXtT0YgfSaLiLiUvweeiu5vI5
         wnFP/lMtOyH78kAUZqeQz6VtQvdID9PYtyfeRVnubbZ285VWaJmRL2bYrbdGWcHHNx3k
         5/8DFdXhmkuwFhS1lnbio6rPMUt3UCrdp75uYpEBqzAa8ZY2qktXtvWFNEiybZF7fLNj
         IKctPUbuaUaE35skGUbXduFhGo7ZuczHINycxW2sk25ik4MW6/dtZO7esUasgdUQGXaF
         CP332OWbujt1TQSCiSrOJfXVVUrt2w1SQjRgjO0Lv6JsiJHXN/XCqdn4eVxlka0zRn19
         /V4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Me3lKKiALwsV55uz6OmwYeCt+bJsLUYqYeDJ2HE/LpI=;
        b=Iq8FDMZQyQBUYUYHZPAM8tLoqdldFpcu4L8FTg4316er8bCnTZHQZ1B8yFav/DoLUp
         TukDiX9ED25sdtKqprSteEy0F53N5ti3xkAF5qjXkKZez05efs0uDcBdoOE1XfCBSa3D
         9PfIC7u44yoHtNx+MkoFeMzMYxq7JIZ+bDRiZx0fgYigvRUQv197/wnfW3ZELkst4wBv
         c9K+C5Sg62Dt/ys8Yt18iGRSmnR4yuyDWhvjUgQA0tkUcO0l/0mLqXwzDfyPvYlzYONI
         fQXWMhGEfR0b1rlHKjsPohf3iNla0+dRFXGWoDHS08pSwcDHfoPJqhnDoBt6vQ6Aik0c
         bRJw==
X-Gm-Message-State: AOAM532FzrijHKBUDQfxB/U4jvsB6TvuvtA4rYgeIPWE1XF8Q3RCYcsg
	uBRZKktrH2BePCkd1NWpMNQ=
X-Google-Smtp-Source: ABdhPJx0ih4xyFaPwUq2ULIomSvMBiAcSlfFEY/NpAR1F5KTVCxBBF3ukQLD1bIDz9LxR58AiVeJYg==
X-Received: by 2002:a17:90a:ab90:: with SMTP id n16mr6335577pjq.223.1621361524756;
        Tue, 18 May 2021 11:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e2d0:: with SMTP id fr16ls2011359pjb.2.canary-gmail;
 Tue, 18 May 2021 11:12:04 -0700 (PDT)
X-Received: by 2002:a17:90a:6285:: with SMTP id d5mr6808249pjj.3.1621361524185;
        Tue, 18 May 2021 11:12:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621361524; cv=none;
        d=google.com; s=arc-20160816;
        b=ZYY5Z/ebp5gJ9ELhaL1qVslvnITBO7rLehisujipS+b9veTGdyBXQiR0rkT4cSPNnK
         ma7RXA1ShfQHIl20BMY1W4BMVptvLS8WhGCrT6fD/MGlggnFXk0vqSE50L+8ZXgY1h/F
         aXO5iDnNVptDHXcEGFhUhk/B6Q4U0ZE88P1LkL4EGBpbH22+/l3yHQvU0hErgbriesjR
         W8FPDtImDDJkYBDbutNRYfSG+cTlbxJgwjmo23mTQSPwmMq445+VabV97ZZBvXeO75XY
         ziH3mmZwzqKghDGfTNSIxXTQcr7vZ8UJj5/EuUNLJASGGCoaORXuPhMywsNtdB+bNS7d
         7qXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dQ9zaCOp8oqQrD+fHP3Fdg+K1ve8YEQcFRk+aoot2Bg=;
        b=ihgYxsZwJ7fvIkbDg2eh8OPhpbUB/TfQRYANLJUP0Yd8rB9/SaxcxfHY343EdVTKjV
         iCWcJ8du+kvwMOgM4K8LomOV/T+dohXZzrAJSlIvEmWlFZqu1b+Sf4SlCN3Y14ACDlKH
         hZfsoF1R4otL+lo9icH3ZPCQpelTIRF4zSoXhLFJ8lqne47BiF7B2acV2R8buS/S9u3b
         MS3p1hOPLbZSq3+UxvL0ZH2Yt+jFkW5obhi6YMFfzvm3nguLzykPnWyj1DpC3Eq/J/c2
         LzYQj+MF4ni8F4IeQHJFyHVkwrKUEN3bg0XVrHzD5a2bs0jEA33Evk0LQ8WTPjC7rNYO
         h0qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SPI3jgv8;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id i3si248996pjk.1.2021.05.18.11.12.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 May 2021 11:12:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id g11so5941325ilq.3
        for <kasan-dev@googlegroups.com>; Tue, 18 May 2021 11:12:04 -0700 (PDT)
X-Received: by 2002:a05:6e02:f50:: with SMTP id y16mr5297315ilj.61.1621361523434;
 Tue, 18 May 2021 11:12:03 -0700 (PDT)
MIME-Version: 1.0
References: <20210517235546.3038875-1-eugenis@google.com> <20210518174439.GA28491@arm.com>
In-Reply-To: <20210518174439.GA28491@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 May 2021 11:11:52 -0700
Message-ID: <CAMn1gO5TmJZ4M4EyQ60VMc2-acUZSYkaB9M0C9kOv_dXQe54Ug@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: speed up mte_set_mem_tag_range
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will@kernel.org>, 
	Steven Price <steven.price@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SPI3jgv8;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12e as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, May 18, 2021 at 10:44 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Mon, May 17, 2021 at 04:55:46PM -0700, Evgenii Stepanov wrote:
> > Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.
> >
> > The first cacheline is always tagged using STG/STZG even if the address is
> > cacheline-aligned, as benchmarks show it is faster than a conditional
> > branch.
> [...]
> > diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> > index ddd4d17cf9a0..e29a0e2ab35c 100644
> > --- a/arch/arm64/include/asm/mte-kasan.h
> > +++ b/arch/arm64/include/asm/mte-kasan.h
> > @@ -48,45 +48,7 @@ static inline u8 mte_get_random_tag(void)
> >       return mte_get_ptr_tag(addr);
> >  }
> >
> > -/*
> > - * Assign allocation tags for a region of memory based on the pointer tag.
> > - * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> > - * size must be non-zero and MTE_GRANULE_SIZE aligned.
> > - */
> > -static inline void mte_set_mem_tag_range(void *addr, size_t size,
> > -                                             u8 tag, bool init)
>
> With commit 2cb34276427a ("arm64: kasan: simplify and inline MTE
> functions") you wanted this inlined for performance. Does this not
> matter much that it's now out of line?
>
> > diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
> > index d31e1169d9b8..c06ada79a437 100644
> > --- a/arch/arm64/lib/Makefile
> > +++ b/arch/arm64/lib/Makefile
> > @@ -18,3 +18,5 @@ obj-$(CONFIG_CRC32) += crc32.o
> >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
> >
> >  obj-$(CONFIG_ARM64_MTE) += mte.o
> > +
> > +obj-$(CONFIG_KASAN_HW_TAGS) += mte-kasan.o
> > diff --git a/arch/arm64/lib/mte-kasan.S b/arch/arm64/lib/mte-kasan.S
> > new file mode 100644
> > index 000000000000..9f6975e2af60
> > --- /dev/null
> > +++ b/arch/arm64/lib/mte-kasan.S
> > @@ -0,0 +1,63 @@
> > +/* SPDX-License-Identifier: GPL-2.0-only */
> > +/*
> > + * Copyright (C) 2021 Google Inc.
> > + */
> > +#include <linux/const.h>
> > +#include <linux/linkage.h>
> > +
> > +#include <asm/mte-def.h>
> > +
> > +     .arch   armv8.5-a+memtag
> > +
> > +     .macro  __set_mem_tag_range, stg, gva, start, size, linesize, tmp1, tmp2, tmp3
> > +     add     \tmp3, \start, \size
> > +     cmp     \size, \linesize, lsl #1
> > +     b.lt    .Lsmtr3_\@
>
> We could do with some comments here. Why the lsl #1? I think I get it
> but it would be good to make this more readable.
>
> It may be easier if you placed it in a file on its own (as it is now but
> with a less generic file name) and use a few .req instead of the tmpX.
> You can use the macro args only for the stg/gva.

Yes, I think we could use more comments and .req here, like the
userspace version of this function that we use in Scudo:
https://cs.android.com/android/platform/superproject/+/master:external/scudo/standalone/memtag.h;l=150;drc=34c8857fef28eab205c22cbfb4bfda2f848e5a80

> > +
> > +     sub     \tmp1, \linesize, #1
> > +     bic     \tmp2, \tmp3, \tmp1
> > +     orr     \tmp1, \start, \tmp1
> > +
> > +.Lsmtr1_\@:
> > +     \stg    \start, [\start], #MTE_GRANULE_SIZE
> > +     cmp     \start, \tmp1
> > +     b.lt    .Lsmtr1_\@
> > +
> > +.Lsmtr2_\@:
> > +     dc      \gva, \start
> > +     add     \start, \start, \linesize
> > +     cmp     \start, \tmp2
> > +     b.lt    .Lsmtr2_\@
> > +
> > +.Lsmtr3_\@:
> > +     cmp     \start, \tmp3
> > +     b.ge    .Lsmtr4_\@
> > +     \stg    \start, [\start], #MTE_GRANULE_SIZE
> > +     b       .Lsmtr3_\@
> > +.Lsmtr4_\@:
> > +     .endm
>
> If we want to get the best performance out of this, we should look at
> the memset implementation and do something similar. In principle it's
> not that far from a memzero, though depending on the microarchitecture
> it may behave slightly differently.

For Scudo I compared our storeTags implementation linked above against
__mtag_tag_zero_region from the arm-optimized-routines repository
(which I think is basically an improved version of that memset
implementation rewritten to use STG and DC GZVA), and our
implementation performed better on the hardware that we have access
to.

> Anyway, before that I wonder if we wrote all this in C + inline asm
> (three while loops or maybe two and some goto), what's the performance
> difference? It has the advantage of being easier to maintain even if we
> used some C macros to generate gva/gzva variants.

I'm not sure I agree that it will be easier to maintain. Due to the
number of "unusual" instructions required here it seems more readable
to have the code in pure assembly than to require readers to switch
contexts between C and asm. If we did move it to inline asm then I
think it should basically be a large blob of asm like the Scudo code
that I linked.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO5TmJZ4M4EyQ60VMc2-acUZSYkaB9M0C9kOv_dXQe54Ug%40mail.gmail.com.
