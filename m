Return-Path: <kasan-dev+bncBDW2JDUY5AORBMG7SOKQMGQELSAJJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C1EC547756
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 21:40:34 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id b6-20020a252e46000000b0065d5168f3f0sf1986997ybn.21
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 12:40:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654976433; cv=pass;
        d=google.com; s=arc-20160816;
        b=MDjHKm62q5e2ArFqFZZbwRk2EVOSJ5ijIhBu8N8oqhFsb7A477K6NN7GEkB8Wu1HrQ
         DdM1zkk7oKscK8y1XTo+s9XlNm+7lnvdp6zFZCG/U0xN+2ExSOkXI1LOUDUeaaaEqRyj
         Js18JYf5w7kn6FihXX95LquOZZCfrv0qNbDBy8VVuEHHRIxA0im9D2B8piZlY4OfXqw2
         Gg5tt0fc25gZZhCshFhbSA16HnEw1AS8cC+hOTFcy3+/629RlNZ+5gelpYnj34tsmOx8
         7Oy07ySogkpXN2IgNurwPbV+u3tRXQQTJXAko6gaP8M6f0C/7pst61Oaw0s1Q1g5C55u
         Sw8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=OuNVJFjASJWuWeV3SlTP88Jy3hZWM3elDLn0LcSH4lc=;
        b=R7l3qL5FRGMMKEgSFUiuotkkK+OEhtdOlO2KdK/aIfKCmYZBXEwkB16TrXvdhS8qGd
         3iwOOe20sR4+ijwKuKd0a1bosB3YFRKkh0y7bROJdsTGR7m80ALc1yTeZium1VhaLCzc
         qmZodS7QC+CMV/x6av2GYf2eL610IWLQ+RapCEckBrZI5TdufQuxltTd/YcnQeOwH3K2
         ylXpQ0BcK+AMzlc6Wfk81/cZ+mTMREA4vPFX1AKFFH/js8cI6IVgV4xctfvQwbzqeXtw
         Y+Bw8Im2bWM/6vJ6ec880D8ymxeToZu25jS3tkS1o7bkWhCFIvWUpFoMgH+BgNsJrB9N
         nPnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=H3jVLSQg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuNVJFjASJWuWeV3SlTP88Jy3hZWM3elDLn0LcSH4lc=;
        b=HRlWDceQrzkUg2HNU9M8A9vGrbFGTKAE1CNv+jdvXG09IEWi3ZLuaxwsE5hVkqT/uw
         xSrUliMykq3xnABkfnhXQ8KUN968F0jgHSNmfOXKJd9LvBcztXbf/ANAQ9M3CnSXAsCJ
         B4MWk3MNYHyzDCc2EIls2xja67e7caJtbUmNFxzjckX4/70b1ppVQGTahccSec2nhBXy
         /sLDR2t9YuhMqLWUyViGk+oc3DCumpDLQrlzQ8lraJcKEkNWuif97pbJw68ZhtGnwwZu
         rQWH3vRJsbnx+hXTVVnDMePHTmXUwinVwwUNw+f94UtCrSjW9MZt+B4FAR0A78ymPIN6
         HRUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuNVJFjASJWuWeV3SlTP88Jy3hZWM3elDLn0LcSH4lc=;
        b=UzYSFeuyYXtFJ6ieuDUYJ5JSZ32xIa64tiOgH5bjz8n5PyDT7r7MOiKEmP+WsHscYC
         mvaoBLSybvAIDql+XWAgiDDKrDMejzOXUrvZTNz9Sqz7QlLqdqY33/qfKb3rr9ME5X6O
         6Me9DlxTqB417nyREC8c6ZW/kMYYfEhAiOKWRx8FkAWxpGo4oFx/O3DSKdOpRkt1N75a
         OBVvV0UGmdTvshUU6yownEN6UcqPYMo1OyqSFCtLG+83bk7/eFgvquM1X2WXg77ZWech
         iak6GdiD9Aa4QiynCjZA74b74OQLdn9wkeupk93zVCR2gZn/LJuXmYDTGGw75cGy3BO3
         /vXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuNVJFjASJWuWeV3SlTP88Jy3hZWM3elDLn0LcSH4lc=;
        b=mCtADGP4TMDZbSivysu9ptiAb6H1Ro5AZ/wnKz70e9kySV3eCVFveiVKRkHERT4Rbf
         3xIJMHk+4joJ9pzDkgvp2qcgNdrdD3bbQygKDuf687vCG62AISv4eQJfE+j8+cnKXBKo
         pZ1lwsVqy0bzaKuh+mCGaQJCJjivLlYD6aqZVurfsch6BgvGLcW2gFHgw0QiNh7moxDG
         HmMyVvl1Eryqiv0eO+kb2tI5ePh6yZ+FOLX8wmiDgV7xvmdEpgIN5scOb2jllRu3gFiC
         TwTT/uqauWJOwkqSRk0KGsPPcTvbAD0IFabnLR5FoIJZkNS0yVbhE7eip8+dBpjCO+GU
         2vzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/5AubC35AsPnfrlemIf33CkJkUH4W1dAKHMXdWI6IP/4w0XEO
	Eg001Pg8A3SHmW7BFpwHyNA=
X-Google-Smtp-Source: ABdhPJxE97XR3U3gIFZI9yyz9MUNLuJ7JHEaoR2rSY0pyn0gSLJUZ+hlZe7NNmvp+1bsgwhuLO92vQ==
X-Received: by 2002:a5b:ccc:0:b0:664:8c0c:f6c5 with SMTP id e12-20020a5b0ccc000000b006648c0cf6c5mr3561616ybr.537.1654976433000;
        Sat, 11 Jun 2022 12:40:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:134c:0:b0:30d:8627:7e66 with SMTP id 73-20020a81134c000000b0030d86277e66ls1098190ywt.10.gmail;
 Sat, 11 Jun 2022 12:40:32 -0700 (PDT)
X-Received: by 2002:a0d:e084:0:b0:314:b0c:5dc2 with SMTP id j126-20020a0de084000000b003140b0c5dc2mr1835142ywe.411.1654976432499;
        Sat, 11 Jun 2022 12:40:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654976432; cv=none;
        d=google.com; s=arc-20160816;
        b=TQt2YkK4CULMEuH21rRSBc46khblSl56fWSS9MWNXCAW8laMbwZu/cIrb4/sltZ//h
         alIOd7EFldPgh8nLwXH9Rs0O2KamfH93W0kDQXABEg4pObO8RdFSwNugQCZg/zDgLcuZ
         O1YbYFRGrBqFB1qgo/Bg3FsZ6VV9gU5PVT0zcvm6FzBa+hej8pESTYisJyIKVGI7DnTd
         dLBmJACeCC5ms25MX+BN95/iuBz+PLxaVFOUgxN7e87hriP7Yn3oQwWATmAHHPN2yRgp
         lyMnyssvQF2hq0ABxu5iIdN8oA77Y7e+9Rd7VU/Iuops18r+7KOWS+dgaefdu1eXuU2m
         QL1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D/iWT1ffpAiqKeZEKWNPE0TbgJINcSFHsUDvoFFTC2Q=;
        b=TTOMGTTJv3jQ6wpDtJ+LfWSWHQsdnwf6n/1W6OEuPojtNznGJXwQFFOK2dmZwfw0/g
         EFIjbc9zS/twIkmuyWqV5VTLB5MrUebtoRollRBqf5Mm2D/sN0N8Ass6DOZRnoOU3rFu
         8eWynoR0/EZy4fhao83ZJuE1ACtDjcxrs8WlW6zUys9B9/KAMpNlwYmuCnm+1TreMrE+
         e6AsQKJwGeTcFNGp6d+u7dAGpDjqtwWF89pGOjoi9g92Be0aGmxp9QFG/Wmf+gelw8iR
         z49TZC32cjpaTivGkS4hU3sRwvPRuAkxhr6Q3i14rjT1hp9vGUiz9wCEPyV094plopJo
         EthA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=H3jVLSQg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id h138-20020a25d090000000b0066472d2d476si190759ybg.4.2022.06.11.12.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Jun 2022 12:40:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id y16so1607539ili.13
        for <kasan-dev@googlegroups.com>; Sat, 11 Jun 2022 12:40:32 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c2a:b0:2d1:9e4c:203d with SMTP id
 m10-20020a056e021c2a00b002d19e4c203dmr27203069ilh.235.1654976432141; Sat, 11
 Jun 2022 12:40:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com> <20220610152141.2148929-5-catalin.marinas@arm.com>
In-Reply-To: <20220610152141.2148929-5-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Jun 2022 21:40:21 +0200
Message-ID: <CA+fCnZfRUgjM72VXXVEROHTJ3iB54n45o9x+BU6WZxS7ROnNTw@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] arm64: kasan: Revert "arm64: mte: reset the page
 tag in page->flags"
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=H3jVLSQg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f
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

On Fri, Jun 10, 2022 at 5:21 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> This reverts commit e5b8d9218951e59df986f627ec93569a0d22149b.
>
> Pages mapped in user-space with PROT_MTE have the allocation tags either
> zeroed or copied/restored to some user values. In order for the kernel
> to access such pages via page_address(), resetting the tag in
> page->flags was necessary. This tag resetting was deferred to
> set_pte_at() -> mte_sync_page_tags() but it can race with another CPU
> reading the flags (via page_to_virt()):
>
> P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
>                                   Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
>                                   Rtags=0   // fault
>
> Since now the post_alloc_hook() function resets the page->flags tag when
> unpoisoning is skipped for user pages (including the __GFP_ZEROTAGS
> case), revert the arm64 commit calling page_kasan_tag_reset().
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> ---
>  arch/arm64/kernel/hibernate.c | 5 -----
>  arch/arm64/kernel/mte.c       | 9 ---------
>  arch/arm64/mm/copypage.c      | 9 ---------
>  arch/arm64/mm/mteswap.c       | 9 ---------
>  4 files changed, 32 deletions(-)
>
> diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
> index 2e248342476e..af5df48ba915 100644
> --- a/arch/arm64/kernel/hibernate.c
> +++ b/arch/arm64/kernel/hibernate.c
> @@ -300,11 +300,6 @@ static void swsusp_mte_restore_tags(void)
>                 unsigned long pfn = xa_state.xa_index;
>                 struct page *page = pfn_to_online_page(pfn);
>
> -               /*
> -                * It is not required to invoke page_kasan_tag_reset(page)
> -                * at this point since the tags stored in page->flags are
> -                * already restored.
> -                */
>                 mte_restore_page_tags(page_address(page), tags);
>
>                 mte_free_tag_storage(tags);
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 57b30bcf9f21..7ba4d6fd1f72 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -48,15 +48,6 @@ static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>         if (!pte_is_tagged)
>                 return;
>
> -       page_kasan_tag_reset(page);
> -       /*
> -        * We need smp_wmb() in between setting the flags and clearing the
> -        * tags because if another thread reads page->flags and builds a
> -        * tagged address out of it, there is an actual dependency to the
> -        * memory access, but on the current thread we do not guarantee that
> -        * the new page->flags are visible before the tags were updated.
> -        */
> -       smp_wmb();
>         mte_clear_page_tags(page_address(page));
>  }
>
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 0dea80bf6de4..24913271e898 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,15 +23,6 @@ void copy_highpage(struct page *to, struct page *from)
>
>         if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>                 set_bit(PG_mte_tagged, &to->flags);
> -               page_kasan_tag_reset(to);
> -               /*
> -                * We need smp_wmb() in between setting the flags and clearing the
> -                * tags because if another thread reads page->flags and builds a
> -                * tagged address out of it, there is an actual dependency to the
> -                * memory access, but on the current thread we do not guarantee that
> -                * the new page->flags are visible before the tags were updated.
> -                */
> -               smp_wmb();
>                 mte_copy_page_tags(kto, kfrom);
>         }
>  }
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index a9e50e930484..4334dec93bd4 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,15 +53,6 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
>         if (!tags)
>                 return false;
>
> -       page_kasan_tag_reset(page);
> -       /*
> -        * We need smp_wmb() in between setting the flags and clearing the
> -        * tags because if another thread reads page->flags and builds a
> -        * tagged address out of it, there is an actual dependency to the
> -        * memory access, but on the current thread we do not guarantee that
> -        * the new page->flags are visible before the tags were updated.
> -        */
> -       smp_wmb();
>         mte_restore_page_tags(page_address(page), tags);
>
>         return true;

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfRUgjM72VXXVEROHTJ3iB54n45o9x%2BBU6WZxS7ROnNTw%40mail.gmail.com.
