Return-Path: <kasan-dev+bncBD63HSEZTUIBB3WO4L7QKGQEMVRONAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E8A492EF795
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:41:51 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q13sf6870898pll.10
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:41:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610131310; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQ79WhOOlEFBlNllc3gtnYpTAGxX5GMCc65kxLH7uEr1FpcSMM2Snz9jkGYXcFv0j4
         8Kbyd/k0rx1vFGeruCD3TO427eNK3GylXLR4zG23ZvbaVhnFTCxaBLP0cYwpPH0Bt656
         2IQjw9Kbis6h62NkYXWDt0ZHX9QNRrOev8DVnz6KpbH17ll+a69UuE6vQGXaiXeEeIiS
         g0eyuIYZhR4uB6/r32zvMRijoMk51ysZI77yGchv1/DUIGf12t75ogbWR5yCAw2O9wx1
         mo6tpVrweBozHSD/JLeIxnlqT9CDhEhLvRJM56zi5Lp1dRaW8RyqFW14blbAbhFpxKv3
         k2aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=WXEn1DBhnpAKRmadhtkk1pv1WwgqpWTucZbIYVCvj2w=;
        b=eed70sxNjGxESJ4VACiQKXFwbSFI1tQ5OhGXSeGBj1QDRt5WXKOBiwL4RU48l0NHfg
         AE2PnMeePLN0xN0GxjtkQ/cJyWLqBifY8oLgq4ufTi00NupM52Su9sjizh2aBLdlKhJf
         DbGudWl0badKgyrx/fkC1lD3ibAAsyNaOoZwxohgwKP+yk0LzbRyfma0KLXIgS1IZnzP
         rjMs4K3IVPrAdie21MWOGnboT70x2d/Lr5I1S3PaJZyY5VdhdJzOAdMCUvrKP3603h9M
         Mhcwm+LZl5wZN9PFQIOlFjSB/1qxY0GPdqsKcUFokoeeevr4SuWa6vSCQIGw1CuIFweS
         ns/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IKNY7oVK;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WXEn1DBhnpAKRmadhtkk1pv1WwgqpWTucZbIYVCvj2w=;
        b=emNVjJ5HiZNkTeYe8HlNn9oxQx+DtplkslSQuvcSfYMkbtMYKSgLbuHrbxR6nlEYs8
         u944l+Py378RmYWdW+esG2ZsinloBGpkg0+g9GZdQ4GKzqiw2AuHrwXGBqcCf9xfxDQl
         qr7kx31yxV0qUndWiXmzgZ3iG1cHsksZPt2TTbExvA4ybS469xE4PCXRSjTwOAEWd+ku
         6do6iyxW6dZNjA/H+nvFN0jspKVaEO19BvstptdZ55wgZ2aFOatI3k54X8Of54MUrIFj
         l4cKBYdonEIGzu4HESMlYW4LXaRsLmkCyNZQU0yIiHJd7b7R7OwTP5Zp1AoRLNmpNS81
         v1vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WXEn1DBhnpAKRmadhtkk1pv1WwgqpWTucZbIYVCvj2w=;
        b=AQnHXMs1GmfoKIrYIAABjLFmz66y7RIrGQszcmefQRiCM4dEjvx4sh3r/LTRh35u8I
         FFg07FX3ViFOibvV1yoDF8et4ccBwAt2C2o0cmH2LMVDnhMHrWIdLolv7LnYZiiw0tzr
         0LebjK/987ZLzym6ohTf6Xu6GGkB7BVKdam8hHJY1/39fg+wkImdT2C9pcRjF+d2HJXI
         4gfoaZVliOEMwTPKMkRchzTaj57qWIV4BjcpHAvynQa/pUVgzrSwQTJnvAZwFrQqm7zg
         5+tQHqWXVqj8TslyEJZ0/+0cHgx3HZFw/CL1fzURjwcO1Ke/ltp+0E340DrK1n+h4J8l
         vCJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FOoFPmJAFipF38MSZdKcYo72lQSBMOLO/1vO1B4PQIujhLNpN
	VmN41A0UVLQ9riHinoFsJ3w=
X-Google-Smtp-Source: ABdhPJxC7zkcGulT5hVp1V84JbMuP1SMPlqA93/hdX2ix69eSOnZv+0zVoWKD4mgXrsQmRwHibzPIA==
X-Received: by 2002:a17:902:a412:b029:db:cf5a:8427 with SMTP id p18-20020a170902a412b02900dbcf5a8427mr5187418plq.48.1610131310394;
        Fri, 08 Jan 2021 10:41:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9286:: with SMTP id j6ls4272248pfa.7.gmail; Fri, 08 Jan
 2021 10:41:49 -0800 (PST)
X-Received: by 2002:aa7:97bc:0:b029:19e:18c7:76b with SMTP id d28-20020aa797bc0000b029019e18c7076bmr4972499pfq.23.1610131309784;
        Fri, 08 Jan 2021 10:41:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610131309; cv=none;
        d=google.com; s=arc-20160816;
        b=wmecILVsiy8HxC+7e2VufL9fWjggXIzjW2sPlVEDMQNH0jIrvAB1+KwhvUcrT171HD
         xO1rxfHKLKKaEMa5yGAGi6kvTX1VAe4oryqFTnn1pegNJh1HDXXA59eiNMGO5qWAhGnz
         tevjEy97R25JZ76l4d1iyVM3OWNxEnIR7znzt5/GLpEJKAj8FgV7BJIZb7L10p20CjPt
         /qFheGjyni6D5okxYidQQNdoLvNC91OEoLDbzrvx/575hCXaWzmrUX7f0Fz6hY/Dpo/r
         AtLtvlh1oYbyC5+Cu2wCyh99BabYCwJC8gWserKDdy1c57MaB2RjSIaawYfyR07sGhVf
         p+Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s0xo2zsw+GpO9VZuhQQKG6ToBw775sdcaTyHeJMHeME=;
        b=LpOZzGogreI7SqZ3UzB1eAS1TKYEXRXirbe19pxzV/POeq06fAp4IkYxu8p0r6SDJv
         FuJe8sTygJsEIBGDyno7NAxdi1fEY3KmzMeaMtO1UmzFQ2ANNXE1yjWtWjtuAW8v+uWm
         RcZQT1AZzpLGXUBsoX3r2Nygk5ZPE6WhKsRDxzZ+jWQ1wV7Eo+6UNNnXyOXoijabnnhe
         ohR6EHDtVnApRwd45wKYRcNBuKKNbIW5XUOTHw4BZWadEj43RIchgqpUSeJRQGflqYkB
         hdAtzvfXyyazkttUu3o6UFl2GTIbZbdpYiknVs6fgWvi2t1yaXplvrzMsPV9h+1IUOB9
         mzGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IKNY7oVK;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b18si768540pls.1.2021.01.08.10.41.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:41:49 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 56D9423A9D
	for <kasan-dev@googlegroups.com>; Fri,  8 Jan 2021 18:41:49 +0000 (UTC)
Received: by mail-oi1-f169.google.com with SMTP id q25so12377661oij.10
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:41:49 -0800 (PST)
X-Received: by 2002:aca:d98a:: with SMTP id q132mr3228281oig.33.1610131308441;
 Fri, 08 Jan 2021 10:41:48 -0800 (PST)
MIME-Version: 1.0
References: <20210103171137.153834-1-lecopzer@gmail.com> <CAAeHK+y=vEuSe-LFOhxkEu4x0Dy2jYts18R0V6Pbv1-5Cwg9_g@mail.gmail.com>
In-Reply-To: <CAAeHK+y=vEuSe-LFOhxkEu4x0Dy2jYts18R0V6Pbv1-5Cwg9_g@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 8 Jan 2021 19:41:37 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHFOQMV_4pYp9u9u++2jjQbHuLU95KeJTzrWXZWQTe_Tg@mail.gmail.com>
Message-ID: <CAMj1kXHFOQMV_4pYp9u9u++2jjQbHuLU95KeJTzrWXZWQTe_Tg@mail.gmail.com>
Subject: Re: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Lecopzer Chen <lecopzer@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Lecopzer Chen <lecopzer.chen@mediatek.com>, yj.chiang@mediatek.com, 
	linux-mediatek@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dan Williams <dan.j.williams@intel.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IKNY7oVK;       spf=pass
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

On Fri, 8 Jan 2021 at 19:31, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Sun, Jan 3, 2021 at 6:12 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
> >
> > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > by not to populate the vmalloc area except for kimg address.
> >
> > Test environment:
> >     4G and 8G Qemu virt,
> >     39-bit VA + 4k PAGE_SIZE with 3-level page table,
> >     test by lib/test_kasan.ko and lib/test_kasan_module.ko
> >
> > It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL,
> > but not test for HW_TAG(I have no proper device), thus keep
> > HW_TAG and KASAN_VMALLOC mutual exclusion until confirming
> > the functionality.
> >
> >
> > [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
> >
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
>
> Hi Lecopzer,
>
> Thanks for working on this!
>
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
>
> for the series along with the other two patches minding the nit in patch #3.
>
> Will, Catalin, could you please take a look at the arm changes?
>
> Thanks!
>


If vmalloc can now be backed with real shadow memory, we no longer
have to keep the module region in its default location when KASLR and
KASAN are both enabled.

So the check on line 164 in arch/arm64/kernel/kaslr.c should probably
be updated to reflect this change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHFOQMV_4pYp9u9u%2B%2B2jjQbHuLU95KeJTzrWXZWQTe_Tg%40mail.gmail.com.
