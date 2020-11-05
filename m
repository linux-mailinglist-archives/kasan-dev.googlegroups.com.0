Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5XOSD6QKGQELBPM2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 19D342A84F5
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:33:43 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id o135sf2374172ybc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:33:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597622; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vbme2UiBf47IyPriWtaDhrloSAwtTzdUwKDOdujv04AzraneVJ2IK622OArTrgWIGq
         R91GEgCv/YF2aMV2b9vNJ1A6XvTtHPUppaT3idiiX6uUZBO3fofm8uJHy36YGVWuRvpV
         6lf5Etev7baixQJmsmtUhu7FIwTpauW3yBeIf444DpZ6Rp9ZbR6tfGawfviqpuqU3h+i
         dmKfK5Y5pJe5yYDYV8yv6FX6EwGXDT9F0ZIRSAYFoH7gNi+xvUeGsUb+hpAMtwCoV3YQ
         Qesay3fw8Qtuq0t5/8UYpuWyoVIbEI+xQt2sGSrjuen1Jv6JMxNSTHxmvjgwbdTq3LWo
         UuDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IVtzrdXPIPj4nh4/Q6is4JdGNa0EJg9xRtHt3KRgIxo=;
        b=aqjknRUPlBq8yDpr90B5eWDxIi2t3UHjHO/tLetlpjzI0TUjoZ7qokmfF0QiahoR1v
         jUaotouonpUa1U5MnfEaCJRfM3wtwarsA2yEeSFum0NQvp1CGyMYJkuFdKqEnheXfmIs
         ic8ekIUKr7qPCuMmhv/w6fze7xobva2qkj1Ba4Pwse3EeqdNh1wHG+m1tXAiZi5hgvf6
         h9CWUnCbq8RY9dBnGfSiXNPG8mLQq3x/K8gGiWFWbGaYYPZQh3M3EM6kHfe+7x18du0H
         /MhaocmzCOcXJlYC+pyS7OR5eq15EdVLtv0P6cPvqu5XQuLVC+u/ge1F4Z/FKCC+iZuU
         cVxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QdBdy/rU";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVtzrdXPIPj4nh4/Q6is4JdGNa0EJg9xRtHt3KRgIxo=;
        b=DOGMqOwFj6yIuZVBwTG7ALnmiscTvUTsZJ8aQLODgPZToOXHSM9ntIDJHXaqCvnaCE
         oVPfppib51oFThJTcopFdBUD4n5C8M/eqgNamYo0AgqXsK2eL1/DmHRy6yIqhpKu+try
         Yr9n0XhgrnPuRlb7QyPzhi2HauBTuBpEpnE3yxS7w0C+P9cFSPGI/E9qVD6+jaltuWCr
         A4lXlpVnh+Fg5N8NNHUSGztoKcMzLJOlGC05Ja3+2ZgvmO08hmLS1cvioUDfwuXLXJpE
         s2Kmkd1YlAVbi6YRoGD8AC5hxMm+Cpp7S1DVZGqLl2rQQxDxDhaHt3xMBnKwSJVNBVHU
         u+7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVtzrdXPIPj4nh4/Q6is4JdGNa0EJg9xRtHt3KRgIxo=;
        b=jvonWGh94O4px9N9SuWWYCtz572eT6T6e1dPdoGB0GS2O5le0eaye3BSydXL270aWb
         g1SytTc3P7cnq8d9b9aAUzWUjBrrt9nHu+hQwp5g6DEIfCPmdFHjZ3H70MXHDNzpitOJ
         gBbMcBWg7fu8H9be+IY4D0ALf10BLrcU4OoDjfYpIMwX9DeHLV4BvFhxDPPxVRNobSwO
         LV9rcTICX+4cge//XnEmQBaVjsmbyVEPJTNvAhF6ElotZlFC/qZevqrGmYSx/SMdMEqY
         V+7+KG5ruYUNm2+PgGIm8qDGHDHVym+i0AxrCEukTS4NE0zvFpfmG/Yjx5exdOARyox4
         xD1A==
X-Gm-Message-State: AOAM532ZUK1pK7mZ2C7yF7+M58PkwK36hFNv97ODoqsSz38aZZV84PIc
	miQ7Yk6z8qzEKk4aK3z44Xw=
X-Google-Smtp-Source: ABdhPJyKgcqyx7HAq5EYSc3p3+zrzQDmyUvLksJiUF30+yn7rh9HX5lLrs5qBIXSAImfbBBQIYDHSw==
X-Received: by 2002:a25:9244:: with SMTP id e4mr5222403ybo.252.1604597622196;
        Thu, 05 Nov 2020 09:33:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:4e3:: with SMTP id w3ls1238052ybs.2.gmail; Thu, 05
 Nov 2020 09:33:41 -0800 (PST)
X-Received: by 2002:a25:84ce:: with SMTP id x14mr5375081ybm.512.1604597621662;
        Thu, 05 Nov 2020 09:33:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597621; cv=none;
        d=google.com; s=arc-20160816;
        b=NjEnBUW7H0NEMqsNDPhqy267MJ2Ikyx27xSXAjt8eXiEVdDZV3Ju39DE+nU2q+0pIf
         qIlZ0y0cbj5Um1l1mqHH+J5H0ZsGdsJy3tWcXugMyHAdLE8rIUfkiVSypV4zV51d7wbW
         Ec7ODc8SNoMNhEnhQ8Ekzcq1zvxbw4rv9o6tjwiLnEXghGUlpP1Zm0dacLpIfwrHJVyT
         yq60Gqm60cfh8CYemtpeW7da/u14MkTVZfQxxsSpxqYUVO5F7f0L/rhwzxeZHLU2vptb
         nnbSs0TM/FGBOzHeygGDfwIiXJDpySmY2+YlosA/CUwlp/6ixLGyccH828SaF7eexDvz
         6CzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rQWq0sb98R2Ibe1tm3jlGBdH5UxkZHIm/WcOlmsUUNY=;
        b=BhUFWhVrPglW2MFG6qiZDtJwQzQsni5CrhQ1da/fP9hQ1cuUQuFGhdbvgU7LTXEcZz
         5i0EHVZbmLkHv8Okfu889V1+Lv85CTT/5uFgtGbJtomLFyx0+JLqgpzCzK+uASZojIa9
         PPuCwA5pb5xffSlk4nkzj29kf6oltOcTOgcvnnPHczUFkqkxP49jGU7GoOc/9kixTaX4
         kxMkYrpBfA/lB+zrrQEFMlIUqbV7SlngS+j4ZKMmJWf2VGzcg1P+ouE51GXvaAaSQf1A
         gQFCYEpzmmhRUfTUu0utDKbtjD52GdjCSIB5Hfbe54cj8xLJd5Q+GtdDZP2aI73cXQ1u
         ISnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QdBdy/rU";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id y4si7419ybr.2.2020.11.05.09.33.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:33:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id f12so425936pjp.4
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 09:33:41 -0800 (PST)
X-Received: by 2002:a17:90a:17a6:: with SMTP id q35mr3446803pja.41.1604597620750;
 Thu, 05 Nov 2020 09:33:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
 <20201105173033.GF30030@gaia>
In-Reply-To: <20201105173033.GF30030@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 18:33:28 +0100
Message-ID: <CAAeHK+ywMBwWQmNbcJFhQDggHdi1fzOsoUGrM=6_-7m6n47oTg@mail.gmail.com>
Subject: Re: [PATCH v8 32/43] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="QdBdy/rU";       spf=pass
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

On Thu, Nov 5, 2020 at 6:30 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Nov 05, 2020 at 12:18:47AM +0100, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index 14b0c19a33e3..cc7e0f8707f7 100644
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
> >       pte_t old_pte = READ_ONCE(*ptep);
> > @@ -123,6 +125,23 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >
> >  void __init mte_init_tags(u64 max_tag)
> >  {
> > +     static bool gcr_kernel_excl_initialized = false;
> > +
> > +     if (!gcr_kernel_excl_initialized) {
> > +             /*
> > +              * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> > +              * This conversion extracts an MTE tag from a KASAN tag.
> > +              */
> > +             u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
> > +                                          max_tag), 0);
> > +
> > +             gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> > +             gcr_kernel_excl_initialized = true;
> > +     }
> > +
> > +     /* Enable the kernel exclude mask for random tags generation. */
> > +     write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>
> Same question as on a previous patch. Is SYS_GCR_EL1 written on the
> other registers via cpu_enable_mte()?

You mean for other CPUs? mte_init_tags() is called for each CPU if
that's what you mean. Otherwise, please clarify the question.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BywMBwWQmNbcJFhQDggHdi1fzOsoUGrM%3D6_-7m6n47oTg%40mail.gmail.com.
