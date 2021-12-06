Return-Path: <kasan-dev+bncBDW2JDUY5AORBUHYXGGQMGQEK5ECP6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id B7D9546A931
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:10:41 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id q198-20020a25d9cf000000b005f7a6a84f9fsf21555072ybg.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:10:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825040; cv=pass;
        d=google.com; s=arc-20160816;
        b=q+KySEafd0xyZf1MPHXeZd5r6ISEP8+Gf7Ltr2ht1/utjop3EHD+4xKt+T2/QFWTXs
         84+cAPqphzu/VNLI8yGuLC1EctZvTwq07oI4HmjCONJFSmZzoNNqUvQvzjFmFXfnvo8k
         w3RpB2bAes6as9P7XjSF1YkL/ZtXWZKK6HRxFB/CSWcwNSfxD6B3f737j3ai3myoaUG8
         U5qeE4v01GFVuWmsKpaxZw6dwx263H7h5kafu2SnmEIIt0GJxK1yHhWSAC2SoBOWhdY4
         lb4F05t2/PouoM7U3wccSLglFVl5jMNUK5FvlHCbUxNK4JSiHFjsdk5o1AnnPHlhTSce
         GZbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=AJolZANH0A+3mniWdrcOzl51NkWvGPNOXgmbOR1Om3M=;
        b=1ItZbDbBZwqYHLU4XQyzlAj0dXLvhalpmg4fKGrV7fbcrtwn4ymPneYHC/8C/0xNAU
         oavtyLLLLIxsFdQnsVeMlgEEf2FaAOfPq0glhVVj4jP8WeJy+bqHucuC6//XDDjJcfC2
         wistbKzp46Jkc5cxlO3Do/vetjKMPVl6YN/C+jNNH1ETeE3UL83efsaBKiyCPqwcWGRF
         q27aONeByVm4QypUPMq4nR28HzQbX1uZDl2PlwoyJGbklftaFWty7C+E2niTFBGodgUH
         tIOeuxBvPhAGQ3tnXvEhg4Jqm+ML9BmBbOR8/ylURUDn+uTJkIZvyqftga10JUBPtfPq
         16NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mwEsGhvX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AJolZANH0A+3mniWdrcOzl51NkWvGPNOXgmbOR1Om3M=;
        b=XEa4qw2SVFpL0MrZBFeCL0rwk4+Awv4EARQqLpdWN7p/jfBiO0NdZX/jlYtltKgvYG
         9Nz13HwGCPmRyApTkJ4JTlZQtTTADkib8jcPzT9f3YpQr5B11UMmP6LNkwwLZf2EphL7
         ka3OldVydUImwrGnDAyC4ISHdfUnf2bX6jY7WVOumsF56t4lQBvw2GknQ0d0rQiCxYhQ
         0pOI162miFsc9XptjVDicrGCEOK/NXpFTILOkj3ZjujcPDxQ6QvLV2p5mo+dFae0lFQh
         IVbzbs//YyYRTJ1X41UCqhKl6PrcJ/9MR73xxhBtPj7ShJdNnIbOi5taXalG1cXejk0c
         aeJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AJolZANH0A+3mniWdrcOzl51NkWvGPNOXgmbOR1Om3M=;
        b=fcHaMT/ue1EiMjVOJYw+dVfPePAsnp3wQNNnPdMwUdK7y8AMze1sps+fH3KswYhWNb
         eDBETXm9ygy5BiDguMXLG6HIdmxPOCvCGQwFHcS9bfwYPR2UQEkZkSCJ/moFtcvPxWRN
         Cfohjoq178429rGxmhOW5VCfL2wOmVNJFJPMTApMfRNgTg9rl8xol0i0N6EQY3YiVbw3
         uhYTZB+KyBFLE2qkC3N7BJ6tT7judLtdqBMpKfdhrbhfRPR1kN6M6DNv/hFTDnteVESl
         tJmFb5roZektIqGiRTPy3jbCcCrHQXo/kpbXXVuTdqBb3BGpbavBHAivrWnYIa0JxooH
         cb/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AJolZANH0A+3mniWdrcOzl51NkWvGPNOXgmbOR1Om3M=;
        b=m0NAhQSrbN6uteB4jgF21RBhwaW3eijpL4wVfIq1DhSz6mnAnLrx/fmo0t7WZqz3ey
         /GAojhyy/3haQbLCvIyfmcz/dGGeWJ3z60qt59rzQskdu4GOUd/ofzMVReMh+imirzUS
         7ieaG/4k3VMniog4C8vQGJuVwEe6oiz15/D/rLXU7VzM1CBG+P5z6AnkaUGg1+crbSkT
         Gs+CQn1A+mptn5N0XshnZCFQ+wDVR5TfBc4SktuR/7NptCGA9h2Hy0lyvvJtz3B9h92i
         8mQnpDqKIYBrRIIL7R1ICrpGUQTFqf0PWob61rdMX5dtLLlloufDFIwtxhV/Krr0SqrE
         uYjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302C+6KLaNovqiLwN4VM4HotZOgzfAxrEtgckmV6MFfJk/kv353
	xsPcfRVcRR+JAHTdoSHRU6o=
X-Google-Smtp-Source: ABdhPJxlptqieKHsE4MtOGI0ABRb5XlyqVDyi3lmczRnhwxIskC56u0XiEfF97+/x4MGg3dH8IHpjg==
X-Received: by 2002:a25:6645:: with SMTP id z5mr47109496ybm.127.1638825040636;
        Mon, 06 Dec 2021 13:10:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6b04:: with SMTP id g4ls15617265ybc.4.gmail; Mon, 06 Dec
 2021 13:10:40 -0800 (PST)
X-Received: by 2002:a25:bf87:: with SMTP id l7mr43524393ybk.687.1638825040237;
        Mon, 06 Dec 2021 13:10:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825040; cv=none;
        d=google.com; s=arc-20160816;
        b=udV75JLnVQnGSSX78qd/K4oce3daqgZH/JRrGH5i+JARbCQh9+S8cONm7s8da1dzdN
         Oc742zbozBISZlmYpyZsJtwJYWIObhEJEGENB4ayOK7O2/zhzDK16TelKT4CAn4XsecW
         rQcIf1xbGy7JhiHqlLGs3fNgtPoUZ1ZH39PR8+UsCKWEY/V0avlGNzrR6RMAyR6I7toI
         d6SV/6rDmymw79p79RXunw3VC1kt0GC/dMeSI4ADxcOcz5p62gMQI14EJzbWgZsWLIli
         1U/7gyAZVmZ5ccmK7cSlVwGg5WUsnrefVJMDdOyIOC7OC7nRPzV8SlGfGaVJbtbBz/rE
         l7WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kwRwUjyY6hc655acCUnran3GDnVqWndaVhYkx0l7k24=;
        b=zWyi+tf4WWj5KjSoICDNgI6LPdC+9nL8FwTn1etsYfoYz1dk2WhJs0021x0ks0aAb4
         9GrVODdzZia4TxvNFcfWSGWcXBO82IyCzWz2vjWBOXMcvXtSyIxr17cs3a0ZMFsagAwy
         3uMeuTZI/IwTa0DDp5xqiOHg4ztTU7cDvXuJCnhdzRUgirnFhK30O1HKti+7t4snvKZu
         hajYSwm9egJk6FvnLApnFShHYnI17GbzLUoTQ0LT/gJWpBpHxaKAaBflPF0R2ghvu5vk
         KkGXzbbrIPvTafjzpqJmGNGYl+sRhAC4USDHOiSyY6xfcP+7sl9zX07HBF6owTqr6W1O
         K/Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mwEsGhvX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id e33si710800ybi.2.2021.12.06.13.10.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:10:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id p23so14542429iod.7
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:10:40 -0800 (PST)
X-Received: by 2002:a5e:d502:: with SMTP id e2mr38338219iom.118.1638825039996;
 Mon, 06 Dec 2021 13:10:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
 <Yadd+oOVYSOPoWMS@elver.google.com>
In-Reply-To: <Yadd+oOVYSOPoWMS@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:10:29 +0100
Message-ID: <CA+fCnZdJCCRNLWD0QdgrXTocwDMroQ_MsBNi36N3JBG-UiVNvw@mail.gmail.com>
Subject: Re: [PATCH 29/31] kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mwEsGhvX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Dec 1, 2021 at 12:35 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > vmalloc tagging support for HW_TAGS KASAN is now complete.
> >
> > Allow enabling CONFIG_KASAN_VMALLOC.
>
> This actually doesn't "allow" enabling it, it unconditionally enables it
> and a user can't disable CONFIG_KASAN_VMALLOC.
>
> I found some background in acc3042d62cb9 why arm64 wants this.

Indeed. Will adjust the description in v2.

> > Also adjust CONFIG_KASAN_VMALLOC description:
> >
> > - Mention HW_TAGS support.
> > - Remove unneeded internal details: they have no place in Kconfig
> >   description and are already explained in the documentation.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  arch/arm64/Kconfig |  3 +--
> >  lib/Kconfig.kasan  | 20 ++++++++++----------
> >  2 files changed, 11 insertions(+), 12 deletions(-)
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index c05d7a06276f..5981e5460c51 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -205,8 +205,7 @@ config ARM64
> >       select IOMMU_DMA if IOMMU_SUPPORT
> >       select IRQ_DOMAIN
> >       select IRQ_FORCED_THREADING
> > -     select KASAN_VMALLOC if KASAN_GENERIC
> > -     select KASAN_VMALLOC if KASAN_SW_TAGS
> > +     select KASAN_VMALLOC
>
> This produces the following warning when making an arm64 defconfig:
>
>  | WARNING: unmet direct dependencies detected for KASAN_VMALLOC
>  |   Depends on [n]: KASAN [=n] && HAVE_ARCH_KASAN_VMALLOC [=y]
>  |   Selected by [y]:
>  |   - ARM64 [=y]
>  |
>  | WARNING: unmet direct dependencies detected for KASAN_VMALLOC
>  |   Depends on [n]: KASAN [=n] && HAVE_ARCH_KASAN_VMALLOC [=y]
>  |   Selected by [y]:
>  |   - ARM64 [=y]
>
> To unconditionally select KASAN_VMALLOC, it should probably be
>
>         select KASAN_VMALLOC if KASAN

Will fix in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdJCCRNLWD0QdgrXTocwDMroQ_MsBNi36N3JBG-UiVNvw%40mail.gmail.com.
