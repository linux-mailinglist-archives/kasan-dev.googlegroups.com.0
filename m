Return-Path: <kasan-dev+bncBAABBU4JX7VQKGQECLTKJVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 504F1A850A
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 16:06:13 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id i187sf1362889pfc.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 07:06:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567605972; cv=pass;
        d=google.com; s=arc-20160816;
        b=RszhH4WjYlSSl3uxGM0J1SpRSbbLzJE1dsR+y4yg+4NZJJm+M2zx+o27E6pcGnskfO
         +M1fQdcIVGXw2qtJ++3kr+21fIPrluPcrM/qGeeV5s5qNsBwKqZ6ZpBhPPFaClkKyDEU
         /r962z190ogOQcM6SC1UbU0+880tAM1m2LO3zN0Mxzo/NcyQF6B9MR1Wh9pnzY4KQXwd
         sVCZbUeDRcqa/4c8okhpctHSBoGPUGfpH62gr6WO4u3DVhyvPgDc9x0OFD9LaygbU4ia
         UAjMjXrStbjea0bGmR4tyaWJ5qiuSMe3mmGEYlEDLwSwF6zMowt0YWy6DhxUWHgMX2hE
         hWZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=FRyfpHXDT2GE0yQCicO+0tZeGNTzUa9TMwmr5OVVESM=;
        b=C12M6xS+KuicWpa7a1nzwW3sCvfWdk8/1cL9ZAcUwe5TWNjN7zzi1tdbcasWF6RmCc
         aLkbkobFlJyRf95U994GMv20SwP2mhx2oF/oes8I+bQ+aGKihQKgxQu3rR57B9Jbxy+p
         Hz8hK2RUWnXYbLmnmsORxx9Kzj27psTh0lTObIn41UaAzWbEmDIzftDkrd2BTfsccdNG
         OYkaMQdQ4fIxP+blJu4+OsBI6V/lwfEi2vBGrxeIpP7kw65xlExEXSVbkfxzZFFuRNYw
         S57LWv8ifW5gfB/8T+fmdpVDPrYmWo+LfV63pKaW1qzsV2lTpxx7PSEvHudH6w/T8YPZ
         xOWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FRyfpHXDT2GE0yQCicO+0tZeGNTzUa9TMwmr5OVVESM=;
        b=lHNFSaSDUvAi445n7EokVNd9Ez9vwrs8/2BM2pU4dzyhSDCURLf1GFrO8qwJTwnkj8
         YD8lkTOZxIiNLXuKaV+dfwYcjnCaV2CKtim+c6rO2LN8/ccHPVN1e2eyt81U0SGZi4IS
         wps28ZcfpWE5zuP6l3ZhwNqMrnK2bQYlRiw1UeLq+7Zl26CF8jQEOHi10MFmsV6GXOSf
         /o5LEqxsbu+OZVfbuKXOM40Bm0dkpzs25YwQd2xMUSH+5OYrGtBHshMLVAngPwOmjd7i
         KUm4TSjUu2UNmpJRddjlhgR4G6oD1+a5q5l0rNWNHHsOWiTIYQiOY43t6+q7DpOIIxXb
         wOqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FRyfpHXDT2GE0yQCicO+0tZeGNTzUa9TMwmr5OVVESM=;
        b=LfhOQPkrMOiTFWcOBtLiU2M9+ZAm2FcmIBLwGd/HHHiqzaBbhpX4Q+K5im/6mTjkqT
         zuabtZ2AhuLKAmjqGFyVYVKiLrsxXh5tMM2KWizAZbHCRjKtqCKRa19kHXQ6rdmjT1VT
         vvXGe2o5yaWrNJgRdrKbAVnBiEbMaX0/vSDIpMc1fU0eId+IpVSa6f0chsNxKMkD8X+X
         uqNd/EXLhl4gDahditERR6XGzTsZI2VS1c2pNbSRet1Izcd5nGNQkW1kLFSuTilDIrOR
         SMz7iHQ79lmpHOPfW3UBzoXK75yVMOJB2ulV3zmgHMVH1EGc9hL2adYPqCeu4a1A/sPA
         OpDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXe6s25eYKxoaKebkgDGsVzz9nZk3cUmSZs5H+OU0wOHwP1AP/W
	4Xz2AQwXELUrcEIKldr6kAw=
X-Google-Smtp-Source: APXvYqyZ/VeOq0sQ2tKWwhnvYBnT23jVeHNTkJ3Ekzh/5RPZaH4YxX7o6BzmHCIjcvE8ZBoF+dhY0g==
X-Received: by 2002:a17:90a:24a8:: with SMTP id i37mr5139830pje.123.1567605971910;
        Wed, 04 Sep 2019 07:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:644a:: with SMTP id y71ls5349657pfb.9.gmail; Wed, 04 Sep
 2019 07:06:11 -0700 (PDT)
X-Received: by 2002:a62:ae17:: with SMTP id q23mr15581356pff.62.1567605971663;
        Wed, 04 Sep 2019 07:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567605971; cv=none;
        d=google.com; s=arc-20160816;
        b=VeqVF8oFxtj7T/CPi8o5vmpadoBiJBIgWtDcNCbhPYaaz/eUwR3C+8TdCe2YY1c8ao
         Wh/E/uNZWZlNyBKNHu7hCRWIXbaToU0tRfLqx3kh0paJAn9Z6uOeeCDNjfRu/suiHDBq
         CEU18bqQi+3Z4q2+LOiT/enMZGqPp9snPlYq/7rjsea+pbddU4GzB9dYUq8g1tXNQcEh
         WJOIbvfGAk98+eBUy8EA6vjcr2Oxe096G6l2CCc7vaAixZL3DbxOkHu7NQfnxlez40Ln
         gRK7cxa5kUjrNn/sD3FhQJiedWtlhM631mXe/Dd0RjAOQuoyIin2SKbEJ/13W16DPLdu
         NSTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=IuDKnoKMd0F9fvFaFVZc+Lwcanh2TGjIEnM1OccvSgU=;
        b=EnNtPIus//LyKzqsUbg7lUUBo+OUG7lQ68QgapwULwDQHA7x0yxJUnCDWz0CcwWmxf
         Ui3qjMj8K/qkOGQf/DZ55GiRggXapq74O+eL6eaEqfNi6Qocl5/i5c2zdRxXP1MFlaEF
         iOimPSMyXS/cnoKHKzcCHWYm82kN41UGdIuKLhb4JIeluO10bpFfTxkiEJm+IGDFPwFv
         jwjSBlSZckFJP+YgYeYkwcQ1fpXan+bPE3BDTf+PgT4xkG9H+gmBrBICD6DN3ZPbYL/9
         UzmFyAQ60E1oW3MU5ycYu2I3amr+vnj89Oz2EZCoxWQdF1kDF8fCaRqOjdWkwNGYMKJ6
         SVcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id c6si694879pls.5.2019.09.04.07.06.09
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Sep 2019 07:06:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: f362c8a6c104411aa10ef7ebe1987d5b-20190904
X-UUID: f362c8a6c104411aa10ef7ebe1987d5b-20190904
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2107079500; Wed, 04 Sep 2019 22:06:06 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 22:06:05 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 22:06:04 +0800
Message-ID: <1567605965.32522.14.camel@mtksdccf07>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Wed, 4 Sep 2019 22:06:05 +0800
In-Reply-To: <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

On Wed, 2019-09-04 at 14:49 +0200, Vlastimil Babka wrote:
> On 9/4/19 8:51 AM, Walter Wu wrote:
> > This patch is KASAN report adds the alloc/free stacks for page allocator
> > in order to help programmer to see memory corruption caused by page.
> > 
> > By default, KASAN doesn't record alloc/free stack for page allocator.
> > It is difficult to fix up page use-after-free issue.
> > 
> > This feature depends on page owner to record the last stack of pages.
> > It is very helpful for solving the page use-after-free or out-of-bound.
> > 
> > KASAN report will show the last stack of page, it may be:
> > a) If page is in-use state, then it prints alloc stack.
> >    It is useful to fix up page out-of-bound issue.
> 
> I expect this will conflict both in syntax and semantics with my series [1] that
> adds the freeing stack to page_owner when used together with debug_pagealloc,
> and it's now in mmotm. Glad others see the need as well :) Perhaps you could
> review the series, see if it fulfils your usecase (AFAICS the series should be a
> superset, by storing both stacks at once), and perhaps either make KASAN enable
> debug_pagealloc, or turn KASAN into an alternative enabler of the functionality
> there?
> 
> Thanks, Vlastimil
> 
> [1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/t/#u
> 
Thanks your information.
We focus on the smartphone, so it doesn't enable
CONFIG_TRANSPARENT_HUGEPAGE, Is it invalid for our usecase?
And It looks like something is different, because we only need last
stack of page, so it can decrease memory overhead.
I will try to enable debug_pagealloc(with your patch) and KASAN, then we
see the result.

Thanks.
Walter 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567605965.32522.14.camel%40mtksdccf07.
