Return-Path: <kasan-dev+bncBD4L7DEGYINBB445RSDQMGQE3H7GDIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1CD43BBDE8
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 15:53:56 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id q2-20020a92d4020000b02901effd8a8dbdsf10688220ilm.14
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 06:53:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625493235; cv=pass;
        d=google.com; s=arc-20160816;
        b=HxzIp+B63iBwGlnohM6gOCjWzRMuYiVO025ROxoBb6RHblCSOcUdClqOuXgGfM/Mb1
         lxmKLyc4L9dL3ucRtau1GwIF9vvtg2Ovmfu40PXFpFHVG0g+1xwpQtQOPQVTPEyKPGCT
         i6Wby9nKB5X2FCzWkaxin8fZgnNczwMdb681ZPeANCCbUmMfER9zoxN6mkfn9JqtsO/0
         Tjqg6kSlg3LC2UNMa/gSbZC/CAgqoNAuXTYNS1HZwdNA+A8yJNxLdfr/MQ/moQ5KFbSQ
         nPpQaKpKWxT/O91UWjThXhufcNuLPirfC+2D4p85GEgeyLudw6sj9tdIqtkB4gwf4+r2
         GB3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=5McR8xP2gIKhIC8/pk4P4jld3/SHAaPv2UidzYnIuys=;
        b=Tf/jqdguPEbKmflrSTOaxywpTKpWozU9l1cCYd0ke/rXxHI/hVT3VKDbvtX5xDxdub
         BfQuc5BpzJ/xweHxv4rtg4hrtzf1UzA2tVEZa/0TX6a+7BtAZYp7v+DHV5r1pXOthfkW
         oqJQZXK05qK8s4Pi1eMF94iSo6m97lj6b4vzPDYY45fxJydTl2b/XGzI1OLyq0qUF5TA
         wcvoFOeFBLnqYfJataWMNlKsCFf4unAtJkvU9A4wITQR6dlW6zXEMJDFf7SH9fQozD95
         QeObwA1Egvl3z29UikxezVdVBfiXmvryAkEKtQG8yLysTGTqI04jt/T/0avsHhTXXFMK
         wETw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=dPu98Bde;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5McR8xP2gIKhIC8/pk4P4jld3/SHAaPv2UidzYnIuys=;
        b=fXKZiOAEqBeAz6dWopNR9NYGPPM5C8d/5KwsGjFOZSkjc6tNAf5hMdGjwygB3zcNai
         K1LbPtRnUW3K+xwQR9/skNUa4jyfdXg/Ve9NgIP0AEkSnWFey4KeoBZaP2sDEy8EH8d1
         2+7iGzYbisa+Enw3aWs/cEJJkMXpeI2qitzNog7834QOxYFgszg+8huZ+kV+MCcNDhXc
         nVUOxTMpQUh9VR8B1V91E+SfFfJ/8f7mmq2Sj2HkLJI66S0Lgvuw3TYNwbG79Jpb0Oaw
         FHiMkdGt73wA+9C1K0UmHQ63iMC+gTepjRPWCSQ5Niu5huWJ/yPm/i4EL8uTSAgWpC3i
         t6CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5McR8xP2gIKhIC8/pk4P4jld3/SHAaPv2UidzYnIuys=;
        b=XPDzeGnHLNSR+4u6AWDN8PfMK4gQvBLjkJD0zz2cyTfOmYCFa55j7pdrNZAoC//+Hs
         UMkArKxHa3gEiW4lehrbNEBktXyknJHeLk2XwbutuT3E0/02vohROSQAfiiBkfGcUwT7
         bcbcRWQ81M+kZempiXdJiMh5sm2U3HhxlV6+tJWYlekjMVQzcBae9bpFSko9pLkxnsjO
         O4zcr9o5BF2SfBVBwEXKjQWyGk3HXVUSadx+xrm50YZ4cJrAzAYT4iQxl+//9a2h/2+f
         /H5djnHi5ejPgKIq6Y4WJ4TH8Hy/R+bMC8m6kEVhz/jBofYBSXyG9F/pla4m8whqY6sJ
         aWGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GBAC3SlIbKEB3igZQIgnkdlp3Wb8NNC+EKBNUxI4jDfhQfUvk
	25ISfbMuZIWYY+0TT7UyNME=
X-Google-Smtp-Source: ABdhPJwfv1xmCGUBJjTvbjZwycyGL8HOWzmB3KWOXPMWgFoAtiKB1Wqbq67ONELIWbWB5i9+lhgSsA==
X-Received: by 2002:a5e:980c:: with SMTP id s12mr8048958ioj.128.1625493235778;
        Mon, 05 Jul 2021 06:53:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:22cb:: with SMTP id j11ls2675037jat.5.gmail; Mon,
 05 Jul 2021 06:53:55 -0700 (PDT)
X-Received: by 2002:a05:6638:3819:: with SMTP id i25mr6052226jav.44.1625493235491;
        Mon, 05 Jul 2021 06:53:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625493235; cv=none;
        d=google.com; s=arc-20160816;
        b=r9dQ5Kt/nNtNs/Z67bJpbA32Xv/Y6KpzIa1nFQRbjHAts9sTO7mdDjq4N2orIz+nnr
         ReAru7ErZ3Jq7+ZUDEVvL4QdBdEvd2PTu828Hm3jrKE/yCL5KyML/yH205zUSMl7rNt/
         rQdJD/9chtgOwLUKOUTwzoVTszd8kvS/uSSzNujLiiKZKsmsjOQ57g0Ua4KROgaZiZGy
         URxyrzZRSfF8yu0p4FixWuek2y8op2+8HEbRRv/X5sW9p4gvW4vUTcX8+E+6FkByZhwv
         rnKcBa7WWep/yXohZFaxfJGNcGJdBFJVFbQiPs1urfgrp74s/Z4jIkpylxFRbuUXhaV8
         xgOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=tWi3mQSz+Lkgh0l0iwDGIwHxWLR6tJfo9WaRVowuGB8=;
        b=SPfBvEj+yWh/VDw8YF/U+KRwnexaEsQMoVt2we3YC+wldMVmSxE698vV46Z/O3hv58
         SOC+3QauN2qS1vX17dCD6f2+WHbEvGy6hIGprYhdYDcinxvBko0VKB54rLtssp/UA5Cl
         dRkKN3HlsoICQkP+Fk7M12ANbc/WeU47AlGozjt44Vp1VVTmZR8OXtIstxQvHYZc6rmF
         M/KkamPOjJ8JNANR68KFe+gMeQ2XDrEm1dZoQic3I30kRa1Tq3gnYN8jgkgWhhHIQzz/
         LSP8KSmPoHfcqbXYUam/15Qdgw2816DFEsCsD8gA25UO8G83cUtuoBTtkYRXlXWFUiid
         dqqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=dPu98Bde;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id x4si1274966iof.3.2021.07.05.06.53.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 06:53:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 47d8e4c82a8649c0bb9cd813dff420bc-20210705
X-UUID: 47d8e4c82a8649c0bb9cd813dff420bc-20210705
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1313421630; Mon, 05 Jul 2021 21:53:48 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 5 Jul 2021 21:53:47 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 5 Jul 2021 21:53:47 +0800
Message-ID: <da9034e02d0a2b5ce5fae01403a881e4d637ab16.camel@mediatek.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at
 DEBUG
From: Yee Lee <yee.lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
CC: LKML <linux-kernel@vger.kernel.org>, <nicholas.tang@mediatek.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, <chinwen.chang@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KASAN" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Date: Mon, 5 Jul 2021 21:53:47 +0800
In-Reply-To: <CA+fCnZfKAZuy9oyDpTgNUTcNz5gnfHpJK5WN-yBNDV5VF8cq0g@mail.gmail.com>
References: <20210705103229.8505-1-yee.lee@mediatek.com>
	 <20210705103229.8505-3-yee.lee@mediatek.com>
	 <CA+fCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A@mail.gmail.com>
	 <CANpmjNNXbszUL4M+-swi7k28h=zuY-KTfw+6W90hk2mgxr8hRQ@mail.gmail.com>
	 <CA+fCnZfKAZuy9oyDpTgNUTcNz5gnfHpJK5WN-yBNDV5VF8cq0g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=dPu98Bde;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
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

Thank you, Macro. I thought members in "suggested-by" would be put in
the list as well... And thank you guys for the review these days. 


@Andrew Motom
Hi Andrew, 

Could you help to push the patches? We are dealing with the issue and 
would backport to Android porject right after the action.
Appreciated!


BR,
Yee 


On Mon, 2021-07-05 at 13:23 +0200, Andrey Konovalov wrote:
> On Mon, Jul 5, 2021 at 1:18 PM Marco Elver <elver@google.com> wrote:
> > 
> > On Mon, 5 Jul 2021 at 13:12, Andrey Konovalov <andreyknvl@gmail.com
> > > wrote:
> > [...]
> > > > +       /*
> > > > +        * Explicitly initialize the memory with the precise
> > > > object size to
> > > > +        * avoid overwriting the SLAB redzone. This disables
> > > > initialization in
> > > > +        * the arch code and may thus lead to performance
> > > > penalty. The penalty
> > > > +        * is accepted since SLAB redzones aren't enabled in
> > > > production builds.
> > > > +        */
> > > > +       if (__slub_debug_enabled() &&
> > > 
> > > What happened to slub_debug_enabled_unlikely()? Was it renamed?
> > > Why? I
> > > didn't receive patch #1 of v6 (nor of v5).
> > 
> > Somebody had the same idea with the helper:
> > https://lkml.kernel.org/r/YOKsC75kJfCZwySD@elver.google.com
> > and Matthew didn't like the _unlikely() prefix.
> > 
> > Which meant we should just move the existing helper introduced in
> > the
> > merge window.
> > 
> > Patch 1/2: 
> > https://lkml.kernel.org/r/20210705103229.8505-2-yee.lee@mediatek.com
> 
> Got it. Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da9034e02d0a2b5ce5fae01403a881e4d637ab16.camel%40mediatek.com.
