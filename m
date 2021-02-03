Return-Path: <kasan-dev+bncBCU4TIPXUUFRB3G25OAAMGQEKJYNYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id C45E930E2A1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 19:37:33 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id d9sf215938uaf.18
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 10:37:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612377453; cv=pass;
        d=google.com; s=arc-20160816;
        b=NDjaGqaAo9yAZJk7zDlsd7zkIhwezPSeB209zmiA8wUPKwatAcrxg/LARPrpiskQbG
         Z7gzAzEUazY21EKgVZ9GM9mk1h89R8lGl9FadozHccL+wSTHJ0RNkr+OsewUYgJuk7Yo
         X9KE27E7uYkDy90Gq+CszEz3JeFjlszn70jJq6jPKcGLyJD2gTRJ0p8RSPucVe/OokXA
         pgUbA0eDuKjPq8FqA3EVQVpP+3vq6SHen66+UfQ1sw7o0XbU3ZBQfceZv1GWd93SgmJ9
         8oAVeHD2SrszgEaj50IZ0L4ERnnHixvZXEc4S+dBhBU+riLGCzAX0TuT25+HfuSd/wee
         aWAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=6zAxZNulotG/VWV+vQYaxSKCbQvjLVoT2arcGQu44KE=;
        b=DgPeXNTwHf4wZbWxCk3fO/XfjkAXRyt53CQx/vgHekCDBLJyodeHninwaDYLjGNy0s
         YyEWxahAue3eQffvBp705dpM6bkcfDr1vFywRnoxPJOp8ZUJAoj7nIs1XFCe0t2IXk/O
         8EMccTOdnqgBPoeb3B9Ky/+3wplMa854sNOOjTQwVSUKeoOR2XYAWK7JYdBfCYQU1zn2
         rZ1dxx4VFUU+NwBm3eC2Giyji2YVXUXLBgp8JhCbswVxX9eq7i7enArhKOuh6ftLWelJ
         u8VRWx2Lb+8R7Es4YefrG2bzjj8m5mmkY0+BxtXqReRPuy+neakrhi3zmNzIi09jIJiB
         aZPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UKpOsqrX;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6zAxZNulotG/VWV+vQYaxSKCbQvjLVoT2arcGQu44KE=;
        b=Z42pSVqY8supgCzEZTqd/TZh4d+d5y88n4FeAmKcLYG6PIznKa2qWPlYwltrJkc6d5
         7cC83h/hNiB/7lSrs182MzNhwDKMrs7bpU9kc2rfjG45QB3BVBD0FwA1FZ2oocHe4gum
         cmX70r9yLCDDwcPUn6+A6VVaZIdWAhNi+SpWjV0VtDO7vQJaLzw+Q/UpNsNf10kQtTXx
         wIycnC+xkLl3KOd3mDXC8EFblBVuMOGMYczOf1ukacj6yLeS2qbZZlV7ujk9rnVDtImd
         j5H5/MZbFWI08fEtLvzkwVv3+e/koh3opzJ3S9qNOSzj/fx4O6IOVPyyqtKPm0oeU/A5
         9FoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6zAxZNulotG/VWV+vQYaxSKCbQvjLVoT2arcGQu44KE=;
        b=Sp39c+vFfswUsZzTHas0zRCL3KLMPyQ2kKWd6IEbifNOibcnv2qOA6OBQ2ckiF3FfC
         Xpn1eG71WOG7fJxV44EJcMVNYJypkMNHrv5tLEQRlQqSTRcqtNhhKAnNsXEeAFRTDoC3
         ZsvBwwro6l3T42FFUVqJxtt/xEnVEpaHBQrqanu73P3AjPBea/squLGKZACEd+0B2Vu4
         reggdnqc14L7wQSt6fjvnjwY46ESCjyP3i3WdqnJv8Tx1+IkBvxxQmRkopclefbIdpum
         BewRVWoyFPYaFiIEWZwJxL9zmBYVim8L/vvqODqB/qCvdBmJ60kL5SENiPfBRdm7vlcu
         wuyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309fWmVdjSujeJHeKuTa3rIGjyh1CFL0a7XaGgpY2wZxHJY9lro
	pBe7GgYMI7g9XIQY0u3QgCw=
X-Google-Smtp-Source: ABdhPJwiZ1FNV6EVlsKdLj1haImC89RFEsAQeOVyBl3ws23mTDe86gGsC0qqqz4y3Lp94P/tUP1BVQ==
X-Received: by 2002:a67:681:: with SMTP id 123mr2768461vsg.53.1612377452676;
        Wed, 03 Feb 2021 10:37:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3641:: with SMTP id s1ls241627uad.10.gmail; Wed, 03 Feb
 2021 10:37:32 -0800 (PST)
X-Received: by 2002:ab0:65d4:: with SMTP id n20mr2968650uaq.99.1612377452214;
        Wed, 03 Feb 2021 10:37:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612377452; cv=none;
        d=google.com; s=arc-20160816;
        b=FqRiHRuO94XapRhFxbzaPnOmT0s0oGLmFR3HR30PJbPls4Dihp5vgG4pjFENiha9zT
         xCPa8sd0Uiia7+XkR4Rxg0Zmwkpntz1S+M7rqH64z4z62H6G2AYorXw0kVtG1bnDGqyt
         elIxWq+SQdbjUjkxZWuKo3vZeMyowk/qQn9V6iluStxs7LjeFnKiAzKixNnzdVI5xvCJ
         tE8Ya2uPF4gtmZR52vY+xmaY9SaPGGTZ46V+Qr5d9p7pMx1pzJuecCaZOSLOwSzP0iT1
         GXcoegFvJ2srCW667SiXV2q08k92wFrt2xu1gkclIYNv346in5GeLiiB0UFq/5YiR74C
         Ii8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bAALbYOfjJARvQhh0rM+pe3DOci0ySDthRNOsR1TUAw=;
        b=oMYXM7J4wCwcYVc43bFssIoQJLfXSt8OCq2wfN7crzdjXswHYagqVyzNg//5iXthmF
         x8m19wzNiJNpqxVOdbLrff1WduHffOGSvcbkLOOiqvWI61IA5XcQLvTVzFECIyQy9PPE
         kPalYTJ5UZ4839M454THW5MKatQPWp6eB36hfeQBAYrax0h/ewWxtQPbJgJqBLMQhbwj
         ixYtMJW9JUVA8E4IVFCBwoCw+CDbGnpXJiruJjs/k5M7f+h43HTuFX8qj4XtIwWH0Sx9
         NNZIz4qqYa2Olqyp1k6rrsbkuCAqykN7sx/1a2Rbc63DcXQoD0Vs06vxrbGJI6kkrQWp
         eo6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UKpOsqrX;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si199287vsn.1.2021.02.03.10.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 10:37:32 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BB6D064F61
	for <kasan-dev@googlegroups.com>; Wed,  3 Feb 2021 18:37:30 +0000 (UTC)
Received: by mail-oi1-f175.google.com with SMTP id h192so944982oib.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 10:37:30 -0800 (PST)
X-Received: by 2002:aca:ea0b:: with SMTP id i11mr2899751oih.33.1612377449888;
 Wed, 03 Feb 2021 10:37:29 -0800 (PST)
MIME-Version: 1.0
References: <20210109103252.812517-1-lecopzer@gmail.com> <20210109103252.812517-2-lecopzer@gmail.com>
In-Reply-To: <20210109103252.812517-2-lecopzer@gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Wed, 3 Feb 2021 19:37:18 +0100
X-Gmail-Original-Message-ID: <CAMj1kXEMOeCZTvNqPPk-uL5iA7hx7SFPwkq3Oz3yYefn=tVnPQ@mail.gmail.com>
Message-ID: <CAMj1kXEMOeCZTvNqPPk-uL5iA7hx7SFPwkq3Oz3yYefn=tVnPQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Brown <broonie@kernel.org>, Guenter Roeck <linux@roeck-us.net>, Mike Rapoport <rppt@kernel.org>, 
	Tyler Hicks <tyhicks@linux.microsoft.com>, Robin Murphy <robin.murphy@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UKpOsqrX;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sat, 9 Jan 2021 at 11:33, Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
>
> Like how the MODULES_VADDR does now, just not to early populate
> the VMALLOC_START between VMALLOC_END.
> similarly, the kernel code mapping is now in the VMALLOC area and
> should keep these area populated.
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>


This commit log text is a bit hard to follow. You are saying that the
vmalloc region is *not* backed with zero shadow or any default mapping
at all, right, and everything gets allocated on demand, just like is
the case for modules?

> ---
>  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
>  1 file changed, 18 insertions(+), 5 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d8e66c78440e..39b218a64279 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
>  {
>         u64 kimg_shadow_start, kimg_shadow_end;
>         u64 mod_shadow_start, mod_shadow_end;
> +       u64 vmalloc_shadow_start, vmalloc_shadow_end;
>         phys_addr_t pa_start, pa_end;
>         u64 i;
>
> @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
>         mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
>         mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
>
> +       vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> +       vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> +


This and the below seems overly complicated, given that VMALLOC_START
== MODULES_END. Can we simplify this?

>         /*
>          * We are going to perform proper setup of shadow memory.
>          * At first we should unmap early shadow (clear_pgds() call below).
> @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
>
>         kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
>                                    (void *)mod_shadow_start);
> -       kasan_populate_early_shadow((void *)kimg_shadow_end,
> -                                  (void *)KASAN_SHADOW_END);
> +       if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> +               kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> +                                           (void *)KASAN_SHADOW_END);
> +               if (vmalloc_shadow_start > mod_shadow_end)
> +                       kasan_populate_early_shadow((void *)mod_shadow_end,
> +                                                   (void *)vmalloc_shadow_start);
> +
> +       } else {
> +               kasan_populate_early_shadow((void *)kimg_shadow_end,
> +                                           (void *)KASAN_SHADOW_END);
> +               if (kimg_shadow_start > mod_shadow_end)
> +                       kasan_populate_early_shadow((void *)mod_shadow_end,
> +                                                   (void *)kimg_shadow_start);
> +       }
>
> -       if (kimg_shadow_start > mod_shadow_end)
> -               kasan_populate_early_shadow((void *)mod_shadow_end,
> -                                           (void *)kimg_shadow_start);
>
>         for_each_mem_range(i, &pa_start, &pa_end) {
>                 void *start = (void *)__phys_to_virt(pa_start);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEMOeCZTvNqPPk-uL5iA7hx7SFPwkq3Oz3yYefn%3DtVnPQ%40mail.gmail.com.
