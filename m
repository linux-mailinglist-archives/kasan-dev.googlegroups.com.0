Return-Path: <kasan-dev+bncBDY7XDHKR4OBB2USX6FQMGQELNSHGQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 295C3434620
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 09:46:52 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id b19-20020a4a3413000000b002b6d6a9dff5sf2763790ooa.14
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 00:46:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634716011; cv=pass;
        d=google.com; s=arc-20160816;
        b=N+i5FkQj7/wn2uEF41UqzE3m15aeWme8CpfJ8xHanXaVIj4wizsdQPv40t+oDAoYQ3
         n9mw93UaeyStaLXjJ5xezTFDOW1zzpeGuq3bWMXn8BWra4N//tOFYycx3FnjzFU4oQiP
         CD3ajueeWXuWnnpnO/jY4qkJknO9btdzYGOHFStTZ9GSXPnfI6QePbisumX89qM1w1/6
         5BqwlpgOh8GS/QW03U6ZG8RnyBjCKJ+UvQ3VcSRSoOfbLzFoDuuLxqru2BdsydN33/Wx
         QlbnqPCW5X8vk4kcmLptLO4Tka+6BqHXqEcofFtFM4W4arGRqsWOswUQRruaGVOM/4Sd
         lRpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=GDgxSjS88LKB2cuTqo8WvgHQde0ByZcBm635dj31b9s=;
        b=OO72BdeOjMuZMegXzY4SNKaqEpg9q6tunu1agNfntQwHkMYjvOIqZAuxWPoC+7HEPQ
         exIR7530Kb7rnWPvVYv685iD8IpRiPgBW+VlifHSUml3pQHNKT/Rm9BRL9lSXHUaYkbA
         cXHwQD/KN9s1yhyU8W+tZtJEE+hBfaYULAjRHnODYHK1gfpFKIbbDNfe4p2B0oKmtGPQ
         I7h1tBMOzX7FM7tYU91mhafXGv09UEPuQEYzPn8VxyQA7hqrEfovPIjKiP1tlixUGGB8
         GOlxdgc9CmwncofRSI5s7yKNALQ4sOWO9YBljwvO8Rr9z8KrHyK/RLd1MoI57gms1Mym
         dMFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GDgxSjS88LKB2cuTqo8WvgHQde0ByZcBm635dj31b9s=;
        b=PLIBi5Q+S0lcmPfvt1ESEUF8Sld0F5k7aYINjslBkxLPnII89A1xbuq8d3U445dYki
         NeEoTTdRpwa1+IZ/OuJkgnl6lYPmidCh1aFqCbrQLbLAm7pVbVdowJAv7m8T7KthLcG/
         gVv6b73gCDfCCnjGGiVQ2KYjjsgONkhtkNYLkfI70g4+467b6xNu9RjpVKKgoY8dioCy
         FhxfQfCNdvD3GRk7kKLR74p6AddDNvgZRTPNjKA4G1h7qM054tKD1dWrDMbRI3GrPG8q
         /ybErR8p8soThcn33o4U7iUazwUKIXt7QMsRiB+GyseHkAsLbj5/b3ivSyXgTGATlsTh
         Gybg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GDgxSjS88LKB2cuTqo8WvgHQde0ByZcBm635dj31b9s=;
        b=BmOSoxH1/J5lQTDDgcP8ZIq9vvPnWRIDxwEAoeiUTqRGCOhCWQjsf9kLAR/dC+OheZ
         T1jIDNRvZkxC3M4kDHX22kDOHelX+Kn7Us2w+jZFr9Sy66ZisiFsrP47nUvzYNi3YoKC
         oYygsF404w8mJFnOJ6p2xhlDOY8SE4lRCTcNgdrUkssyTNiQem3/EpGKH4PJPlid2lEZ
         JnOOkZpIcPUJYANZB8ozC9LJttTps4MasQpuE/46tWWb1qGGVfrbd4lpUYKJcPmiKejC
         XTJW1TH2GlaGOHWYv+WuaQOvUKMZ6hEOx0FT6D6u7s1DIk6l2W00RbMeYdRFNk0zVkQt
         x7Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wO7hihZqfsRC8qMcuJ75JYXAjIz8d0u6i2p1lSALIvLsom9Yc
	yH/zPkSKbiNY7MmyHW0eGAM=
X-Google-Smtp-Source: ABdhPJz7RMGt/RKQ3mYygjxt1h+oUq1GKcrFRL0VHSq5WuQCEAoI1ZSiqrP46DkGFZLLHnwArnFm5g==
X-Received: by 2002:a05:6830:23ac:: with SMTP id m12mr9859422ots.357.1634716010817;
        Wed, 20 Oct 2021 00:46:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:356:: with SMTP id h22ls423468ote.5.gmail; Wed, 20
 Oct 2021 00:46:50 -0700 (PDT)
X-Received: by 2002:a05:6830:4c8:: with SMTP id s8mr1086226otd.359.1634716010482;
        Wed, 20 Oct 2021 00:46:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634716010; cv=none;
        d=google.com; s=arc-20160816;
        b=GXYUlERWW2PxV/pycDNxvwfF7V9CYOWdo1cd9GtvQ6GMv0OM6drl11QGzm03orgo68
         3M/CKXXlje+OkOpGUE1wIKpJZy1GigfDnySuBgqXpwnOtT2mO46KONdsYwyzWOuHFUnx
         JUFg9UZBeDrKN1fEF7erL2A0s/R00UsHlRVJumFnD+pVLhFDLTNAbvbioa9BsinrloS3
         h82NHE/RQ4Xf8z70gJ+oosi58VrtPlpq+JstqwNIZG/90KWyfjcABnSndjedseVJiAYQ
         J2oovon2t7c0/nkYysHc7O/vmMgWubZ5dhRnbChC66vSriyevvG0HYGZHPaRytDVl4kn
         lBig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=26QuId4hJCn4piktDCW1s4WEHrK9FVM2POMNNriOPPs=;
        b=OyVriCDS8rkzi82o86Oj6mlpn4y0dZnQovAoZ8i7SMmy4n69gKRf5Fghm1hgdE8zuW
         aoJ8ZkHYiUpN6Oi3UKn7yfDXx6tUrLtBR3WUwvWH6nAs1YeftX+45FqA/s5Xilu/oSe1
         3ed72GCH5ZyO416DZ+L/MQbwhzzJDC6YH8FlFOGjLEkMumy0M4W86er4Rg+7zPKzOs2y
         5HOYZvkQ/tcUM/L/O8qWMvH1clu+GgMS+97AByRBa/3M6S0L5jOe1DzE9FSTCMbqzjKg
         HkAdgn1gCz6tYrT44/kNhwRZGsHGncQcKN2E1ZjU3zH4oqDCPoY8GPpqrvHzMjvGtCSb
         ypcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id b132si115725oif.1.2021.10.20.00.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Oct 2021 00:46:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 391e0a9f321e4572aaeb44daab13c9a6-20211020
X-UUID: 391e0a9f321e4572aaeb44daab13c9a6-20211020
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2121538419; Wed, 20 Oct 2021 15:46:46 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Wed, 20 Oct 2021 15:46:41 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 20 Oct
 2021 15:46:40 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 Oct 2021 15:46:40 +0800
Message-ID: <c0d7c2aa14cc569d5ad95dc750bb6cc1727a042c.camel@mediatek.com>
Subject: Re: [PATCH v2] kasan: add kasan mode messages when kasan init
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
Date: Wed, 20 Oct 2021 15:46:40 +0800
In-Reply-To: <CANpmjNNxQRM5rSxcdxNOicpOvwQ=vsutQO3j1hUmGAfS9+pQDA@mail.gmail.com>
References: <20211020061248.13270-1-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNNxQRM5rSxcdxNOicpOvwQ=vsutQO3j1hUmGAfS9+pQDA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Wed, 2021-10-20 at 15:23 +0800, Marco Elver wrote:
> On Wed, 20 Oct 2021 at 08:13, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > There are multiple kasan modes. It makes sense that we add some
> > messages
> > to know which kasan mode is when booting up. see [1].
> > 
> > Link: 
> > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=212195__;!!CTRNKA9wMg0ARbw!yylpqk8mnd0N8w6pn4Mn4sIeu-GGlKXcA4I4yXlmstFsuqmpkhaM2V_uu2c6oPMFpZRqoQ$
> > $  [1]
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > ---
> > change since v2:
> >  - Rebase to linux-next
> >  - HW-tags based mode need to consider asymm mode
> >  - Thanks for Marco's suggestion
> > 
> >  arch/arm64/mm/kasan_init.c |  2 +-
> >  mm/kasan/hw_tags.c         |  4 +++-
> >  mm/kasan/kasan.h           | 10 ++++++++++
> >  mm/kasan/sw_tags.c         |  2 +-
> >  4 files changed, 15 insertions(+), 3 deletions(-)
> > 
> > diff --git a/arch/arm64/mm/kasan_init.c
> > b/arch/arm64/mm/kasan_init.c
> > index 5b996ca4d996..6f5a6fe8edd7 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -309,7 +309,7 @@ void __init kasan_init(void)
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
> > index dc892119e88f..1d5c89c7cdfe 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -177,7 +177,9 @@ void __init kasan_init_hw_tags(void)
> >                 break;
> >         }
> > 
> > -       pr_info("KernelAddressSanitizer initialized\n");
> > +       pr_info("KernelAddressSanitizer initialized (hw-tags,
> > mode=%s, stacktrace=%s)\n",
> > +               kasan_mode_info(),
> > +               kasan_stack_collection_enabled() ? "on" : "off");
> >  }
> > 
> >  void kasan_alloc_pages(struct page *page, unsigned int order,
> > gfp_t flags)
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index aebd8df86a1f..387ed7b6de37 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -36,6 +36,16 @@ static inline bool
> > kasan_sync_fault_possible(void)
> >  {
> >         return kasan_mode == KASAN_MODE_SYNC || kasan_mode ==
> > KASAN_MODE_ASYMM;
> >  }
> > +
> > +static inline const char *kasan_mode_info(void)
> > +{
> > +       if (kasan_mode == KASAN_MODE_ASYNC)
> > +               return "async";
> > +       else if (kasan_mode == KASAN_MODE_ASYMM)
> > +               return "asymm";
> > +       else
> > +               return "sync";
> > +}
> 
> This creates an inconsistency, because for
> kasan_stack_collection_enabled(), kasan_async_fault_possible(), and
> kasan_sync_fault_possible() there are !KASAN_HW_TAGS stubs.
> 
> A stub for kasan_mode_info() if !KASAN_HW_TAGS appears useless
> though,
> and I wouldn't know what its return value should be.
> 
> Do you expect this helper to be used outside hw_tags.c? If not,
> perhaps just move it into hw_tags.c.

The helper will be used only in hw_tags.c.
I will move it into hw_tags.c in v3.

Thanks.

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c0d7c2aa14cc569d5ad95dc750bb6cc1727a042c.camel%40mediatek.com.
