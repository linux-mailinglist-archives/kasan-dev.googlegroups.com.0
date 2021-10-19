Return-Path: <kasan-dev+bncBDY7XDHKR4OBBWNOXOFQMGQEI3QJVCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C81E3433874
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 16:34:02 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id on18-20020a17090b1d1200b001a04d94fd9fsf1577784pjb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 07:34:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634654041; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cw/9osQPpkvwixYKD/jqQUDskm9tRnqf64hcveCb8BOFdKLKHs4Lktyv12B/fvmk/m
         KORMjDB7RnGnZflv6rUxWVK/ZfEydG+7KyXBMPHmiSmnwU9fi2Hcw7LqDBfa5d6pEg6m
         K1Q3HvXHp5p6lDp+Vt5wT/8UigGWYSy9vG87QiH3qKQ5RvZ9HuW6ByDqnPLUhoENTsA4
         c0X8By2BgJJjtUUNn4W9I35cR9usZl1AbgybTkZMfwYg/saDNeV6bg8DGkvZLQHA6dZO
         FAHuqnplHzRzOL6Ggjy4bgOnGuOqh1lcvMB0HyDw6F8Xzt7VaEdI2vMT7grXCcuksBwr
         A35Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=bALdbGSwQUOXLKIZhlqwGBiQOY8UPBd82ifGj4poEeo=;
        b=wwDDGmlv7dOTDKbZ8ObTNP+Czh0wf5VKrhwnUdRREyHB1uMRfJdnq9XYITtzIyxxEM
         NCbPOGYF1SCPOx3RtuK//bbrVvdPw47Oi2ZZT3kydM2nz85Em67czJZ+6o17lHlhzTBD
         ZaFhaJ4sf+f/zSWk/Y/HKAgSIGHGwrEgvNZQVuD/BdN1STTx0N0NMXhh9FH99PCJKyC1
         AGKeXNjQ8AKKOxuwLP9f+Ayi/eL9P97hiMcW7PtnXK0LzBCMcl+PteN8hDuKBdIV/qc1
         gEf/fGTcXtJgayJdmRnMfSfps4UB0wlww2I04+grPiJgYVCB9Knq3apKaGCTRR7OvXur
         W5jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bALdbGSwQUOXLKIZhlqwGBiQOY8UPBd82ifGj4poEeo=;
        b=BN4YEVO3ayKGOk1s0YW+i+xaG4tfwyRNB27yDMScJOut/PJAM56TNzQbzUIAjqmC9F
         syzW1k90NHnlRKqLpjAVqb1Q82gLTie48mMGeHjUOIKhgMPvNaDmk4wDmCzCuLoZy8Ci
         8SXQMaER4WtSh7tLZiafK2a/NlN+04B1jQqfGtRQ3edMFjVkZJX4gu/QCBf2wjOv2AIq
         QwiygegtxpHHOX13GUUZk+8DPk6k1D8E1d7PxUiLoCdrhDwzUtlsNU5gtQgWWyZzNNPF
         S2Zb9y/3dgOQPlTFIk75Gz7rao0sr5KIlFe0KCmbwUIEtnbsdkCvL+9sOtNfmvN6koMj
         GCTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bALdbGSwQUOXLKIZhlqwGBiQOY8UPBd82ifGj4poEeo=;
        b=6zk8rUtVyl46uh1ZO4MpSwQH/M8459RM2U3Vq9ZUwJV86saRinXFovC4mPrvy1NwBG
         KJtg8/NZvW1PzqjnnuK1capyekZM3LcxUl0GKvqbPLHjS2QNs0vuVlCIPD894QUEDUHp
         +aVtfrb/5Gw0qo+KLn9wkAh1+/14P5xBN3esQhg43dpx3shtA0OnfOOSisZoZORy1RFm
         GQ0zhevHrklPtCfu+2mbKcgCS6MS5C4CerThtArjSmL2S4u1aZdnwQ0Ef+532SeLaYwn
         dBhP2iPwWtvPhAQcd/15AXsD0Sl4U/kChNhLecFhtzb+cbCdJXvp2uOABDgz+xBV3/BS
         /nmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XT25JITsbJ97hXv50OOx7R0NMmdwJoX37ruDQZnsHsZwfNg57
	bLlh5XZLF1rJocnIQbDL5yg=
X-Google-Smtp-Source: ABdhPJzIxwRfYlNuvz+2eQYl5nO4D4gfAnA4xIEYvKnsNHvqwhTr7MPx1mdyts+4yxswP9/rimNatA==
X-Received: by 2002:a17:90b:8a:: with SMTP id bb10mr255796pjb.149.1634654041501;
        Tue, 19 Oct 2021 07:34:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4bce:: with SMTP id p14ls7363069pgr.8.gmail; Tue, 19 Oct
 2021 07:34:01 -0700 (PDT)
X-Received: by 2002:a05:6a00:84b:b0:44d:afcc:3577 with SMTP id q11-20020a056a00084b00b0044dafcc3577mr248592pfk.42.1634654040895;
        Tue, 19 Oct 2021 07:34:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634654040; cv=none;
        d=google.com; s=arc-20160816;
        b=mH2836cA+F5nlcjrDGeZz5eZNQk+ZbTKDmHEjxtGkjFhLPe6FR67pvdQUP3ElTqqjP
         U7sd3OiFJYZPelkSFYn//c0vPEcmKSqzW/hNK8/eCD1Bxvh9hZVh19FQ9WTFHwRZ2TM3
         ieGu/bzZlB35b9+ARbVgdZOlIvMkyzUwCVOKR+337Jc1cGFdu7jwfIhEJ9mFpI9gBp59
         tWsobDG/bYEZfHyasDRibi9Jbu7x0rVBD6ceCreUufxUbtSquQQfUb55v9DUeNu9YYVn
         vAegQPKQp9RtgOr8X1gJ9+hhiaR4GLsElragyu4mXCQguyg5p9Y16heXNAyBU3mPA+hC
         3NEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=gVp5v1fQrInGDZPpJM3a6+olAD2lofJveHIY4Fst878=;
        b=S8MvHTo6XKngaUK8k2sAnssxqAdErc0FE0ckktxAYLITL61pHGt/U23m1P+D0hAumn
         z+bxSef+7P/7rTkSGgJu0oC1Yan73t3A1QSgOh0zdh0ZWl2pWRzLbL43GvtuPXWnMRhL
         wbK3OX4iAeYMRXN0zWUBfnI1OZUx5Dz31lQJea0l79LL9grlBb2pBqFdWTTBD/gy1rVR
         35FSNBcWyPCLXVgQR1PmvjrhoGNw+Z6+5eu3HI6MVZo95JQgyp1ceh6nAveurcF/UMUy
         C29CSxgqBYRyS8ZAF+qOd5NIS5wdevv6IFFJ/Ww1/NIH+JaWLNn2GfpkZwJifPb5l8vM
         LCug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id p18si1298402plr.1.2021.10.19.07.34.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Oct 2021 07:34:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 3f142819df124a0f9138aa1412034745-20211019
X-UUID: 3f142819df124a0f9138aa1412034745-20211019
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1270553496; Tue, 19 Oct 2021 22:33:55 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Tue, 19 Oct 2021 22:33:54 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 Oct 2021 22:33:53 +0800
Message-ID: <294ac8c4fa2e7fcad8376a82193b8e2430a4032a.camel@mediatek.com>
Subject: Re: [PATCH] kasan: add kasan mode messages when kasan init
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, "Will
 Deacon" <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>, Chinwen Chang
 =?UTF-8?Q?=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?= <chinwen.chang@mediatek.com>,
	Yee Lee =?UTF-8?Q?=28=E6=9D=8E=E5=BB=BA=E8=AA=BC=29?= <Yee.Lee@mediatek.com>,
	Nicholas Tang =?UTF-8?Q?=28=E9=84=AD=E7=A7=A6=E8=BC=9D=29?=
	<nicholas.tang@mediatek.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>
Date: Tue, 19 Oct 2021 22:33:54 +0800
In-Reply-To: <CANpmjNMMQUHhFTdaqfx6HErnv0aXkCJn+eBGN-kfeznN8H+f3g@mail.gmail.com>
References: <20211019120413.20807-1-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNMMQUHhFTdaqfx6HErnv0aXkCJn+eBGN-kfeznN8H+f3g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-10-19 at 22:14 +0800, Marco Elver wrote:
> On Tue, 19 Oct 2021 at 14:04, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > There are multiple kasan modes. It make sense that we add some
> > messages
> > to know which kasan mode is when booting up. see [1].
> > 
> > Link: 
> > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=212195__;!!CTRNKA9wMg0ARbw!374SjX0W47zTqp1xJyIg9CW0T7ggAT1rr981lIRBjQhUk2_495ltG_ZkiW6jmeVDBvu_UA$
> > $  [1]
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> 
> Looks good, however, you need to rebase to -next because of "kasan:
> Extend KASAN mode kernel parameter"...

Thanks Marco.
I will send the v2.

> 
> > ---
> >  arch/arm64/mm/kasan_init.c | 2 +-
> >  mm/kasan/hw_tags.c         | 4 +++-
> >  mm/kasan/sw_tags.c         | 2 +-
> >  3 files changed, 5 insertions(+), 3 deletions(-)
> > 
> > diff --git a/arch/arm64/mm/kasan_init.c
> > b/arch/arm64/mm/kasan_init.c
> > index 61b52a92b8b6..b4e78beac285 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -293,7 +293,7 @@ void __init kasan_init(void)
> >         kasan_init_depth();
> >  #if defined(CONFIG_KASAN_GENERIC)
> >         /* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags().
> > */
> > -       pr_info("KernelAddressSanitizer initialized\n");
> > +       pr_info("KernelAddressSanitizer initialized (generic)\n");
> >  #endif
> >  }
> > 
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 05d1e9460e2e..3e28ecbe1d8f 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -168,7 +168,9 @@ void __init kasan_init_hw_tags(void)
> >                 break;
> >         }
> > 
> > -       pr_info("KernelAddressSanitizer initialized\n");
> > +       pr_info("KernelAddressSanitizer initialized (hw-tags,
> > mode=%s, stacktrace=%s)\n",
> > +               kasan_flag_async ? "async" : "sync",
> 
> ... which means this will have a 3rd option "asymm".

Thanks for the reminder.

> 
> > +               kasan_stack_collection_enabled() ? "on" : "off");
> >  }
> > 
> >  void kasan_alloc_pages(struct page *page, unsigned int order,
> > gfp_t flags)
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index bd3f540feb47..77f13f391b57 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
> >         for_each_possible_cpu(cpu)
> >                 per_cpu(prng_state, cpu) = (u32)get_cycles();
> > 
> > -       pr_info("KernelAddressSanitizer initialized\n");
> > +       pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
> >  }
> > 
> >  /*
> > --
> > 2.18.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/294ac8c4fa2e7fcad8376a82193b8e2430a4032a.camel%40mediatek.com.
