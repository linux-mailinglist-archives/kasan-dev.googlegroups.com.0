Return-Path: <kasan-dev+bncBAABBBNW33VQKGQEQFLFIVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DF20AEAD0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 14:45:58 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id a6sf18573951qkl.10
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 05:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568119557; cv=pass;
        d=google.com; s=arc-20160816;
        b=yC/6EsBTW468U47VHQ8v/4+rnMFSfaxR0B6knvRHCzGD+mRac2ltprUAzWVZ7TzMdY
         PQQCRLpPe/LwP1+uCeY+xZqxpmRzUGVibOUwS/B80spFUcz1XBM0id7IVqWHjwweUkEB
         atUs/WmYVegjD9qmAxqM7HDpd4CQMAAqBkThsXKAwHet4eebnWDtIVwntTl5WLwiT+dl
         L87C6MImvWRjJ6Ci7RXjpuYhRSsD+LhwkR4PxJR8bCMM9ylnftJXY8DJbS5etWG3Sopm
         5OhJt7XAgHplaG7M5PjZtDS1UczR0tkkXFrLclO7M7QSjPoJl0hzJ0wHrqK7cWEdUe8H
         jjwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=6NPHiXYbscZ4GkiwD0HCNeCeWU7LAMWvrFOcUWF/Rm8=;
        b=ajxeBsYAIZiuXKkw0fcHnLXN6//ydxia89XgEsJfsXAmFC3rRa6GbF55g0L93Rj2Qc
         /WaxQV9zFKJZrTYoi5f1eB4cq62wqua3eE2ru9F9u8GmCfQcR5PVwMdEBYQ1EY4oKu7E
         GR1Ic+khBgwwl/aXr2QdAd3e22w6vYwHuxdIEgs6G1sFh3cvaeDmR9OEhYaHNB59j0h8
         JNyhlPl0wRK2VhlFM7hTAFWebY5OoCGXyrIgIYKyJZa6tN7C/g6g7jYglwJec7CC4tbQ
         YY7duE27Phq81rHxRZkfk2u+WOjSBk/XyraqdRjodSi3EQAJEjd2NXYFAN+q1vPUTKjX
         oSJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6NPHiXYbscZ4GkiwD0HCNeCeWU7LAMWvrFOcUWF/Rm8=;
        b=CeKwa5T/Rt5tfKXfzNkpvZ6/ndyHcDhzZk9rIl0B+OilIeHY+jV1zxMuxrjwEl9JM/
         JjemmmTcfDC6Gzen6HkfC4e0A/bfyj9sqKG+AqtaeKvJX8noVt0Ugy8IF+tE3YBakXhC
         +xipI5naUj7LMhf/Q+bASIZUO1Y88nJBGmUlWUhHLBinLJ11sOMGbFxqMl5EnLhfVLU5
         f3W08c4RgWkVzHRHw7ceOl5I3RX2RR76Yjv/Fc0v7lux1hpxeDPlBo0AGAsLKiXc366F
         H5otDQGm1oyO4/ijnhH3Tyj+CdX+KItm4CYNUBXcainZ3jeupuY6cF89bm2OtbklVZlQ
         ocCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6NPHiXYbscZ4GkiwD0HCNeCeWU7LAMWvrFOcUWF/Rm8=;
        b=JN2wUl5z3D5C40E+c9kRlrJ//Q95N5TbHT8IS0okSyA7nIx+VawLUGKXBElF4wyfaC
         S/2zhZ+GoHolU9FzM1KtuQXWYE9RdlPe8Mj0yn5H/6KG/UqWilKfEDkRMhPAot4RZPJh
         ThvZBdLrVLwsGK3wlwXTNFlgH9V5lyXxU2lboXh0JD245XHgJYW7+4n5E9QO9seEUHX6
         S34tWozX3PJmnlMG3uwjSBOHKPJwEzNRGc+EI3cZsaa+CwOHB5MR3maP7gk6Cl2TQkA9
         oyEeUkmY6Tk+ZZ7n+rdKVTXHmab0W1w9ByIK3qRKa0PSbiKregtad6oSwbDNnaskYC8r
         iNPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX7UggeArPhvTgK3PpEAOhIrKaZOpBCTuYiDghZGNfVehGZYqmv
	GHjYGHyYlo8JbAlog51ZIy8=
X-Google-Smtp-Source: APXvYqwTV4SOKi+p0uHjh9TJwA1iQTJFilSex+bQj/915EZwaIrWcQ32HguUh71ReYzetAA2Qed4yQ==
X-Received: by 2002:a05:620a:1669:: with SMTP id d9mr7630064qko.309.1568119557233;
        Tue, 10 Sep 2019 05:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eb0d:: with SMTP id j13ls2223635qvp.7.gmail; Tue, 10 Sep
 2019 05:45:57 -0700 (PDT)
X-Received: by 2002:a0c:9952:: with SMTP id i18mr11390696qvd.202.1568119556982;
        Tue, 10 Sep 2019 05:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568119556; cv=none;
        d=google.com; s=arc-20160816;
        b=jpTEPVKRHm6w8GuEum9DsnWPpuRf8GM/QKZZYtPsHHPa+eYN+iyOPHNZcYScduenmU
         bQAmynXjGjhoa8NJ6hG98urjXgjuhNx1dPwxqLvo5DAItg062qYsF+32lyDIiZLD9toz
         NdA8+TPzqiimniIdA0OUHf3SXdlZdwaVK7rAcc6CkXyUJ40W3KMgK4LZH6CWylz/poHJ
         sdsYka5Tw8dz9WkxA2Cj740KAmzdCtuHb8BjNfdTbvvE3U+kDmgDOKsNgFxiQ09IquV/
         Kcl+FKYZOpA8UjvXp6n0qS+/gSEecAdvS4EEtgny9MkXrrE6nE3aKWvJ2aP0UiLR8wPc
         vXrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=vlWw1M3LXgnwiv3zH+SHSc3ZfA1azSNCp4eZpkqxscE=;
        b=vqTl5TNYCkNcqhNvIgyg7PMEIc61pZPJGZL622dE4RxNg/Zb9lT0d8QtCWNUxC1qib
         GjljtFLMQDP3FktAVovHqfKTVCtuRe6pwSBOHOLI0v2dg6vmSHV6SC6XIVN8St2FZy9n
         Dgw+c0N/UVu/K+yBkdcrzsQBLKozABZ0Xtf5BsFj0BVDoXna1lDjAlE5ZwP6J4WVWHux
         DhUdZrDoYvclihMDJemp4v5O65j+lRpnxiz//QmC3/XWb7P2qWLYhx+Fcb1+1PlVtPec
         EdlAjWeHlL15yXihC7LYs77shGcmKEBAySfZC5OeT2XtT5DCWbrX9M5Mbac8XeqPaBBP
         G38A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id r43si934169qtj.0.2019.09.10.05.45.55
        for <kasan-dev@googlegroups.com>;
        Tue, 10 Sep 2019 05:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ea7760d474544bb18f6fd74ca1614a77-20190910
X-UUID: ea7760d474544bb18f6fd74ca1614a77-20190910
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1580390971; Tue, 10 Sep 2019 20:45:50 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 10 Sep 2019 20:45:48 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 10 Sep 2019 20:45:48 +0800
Message-ID: <1568119549.24886.18.camel@mtksdccf07>
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page
 allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, "Andrey
 Konovalov" <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>, "Thomas
 Gleixner" <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>, Qian Cai
	<cai@lca.pw>, <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 10 Sep 2019 20:45:49 +0800
In-Reply-To: <4faedb4d-f16c-1917-9eaa-b0f9c169fa50@suse.cz>
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
	 <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
	 <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
	 <4faedb4d-f16c-1917-9eaa-b0f9c169fa50@suse.cz>
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

On Tue, 2019-09-10 at 13:53 +0200, Vlastimil Babka wrote:
> On 9/10/19 12:50 PM, Andrey Ryabinin wrote:
> > 
> > 
> > For slab objects we memorize both alloc and free stacks. You'll never know in advance what information will be usefull
> > to fix an issue, so it usually better to provide more information. I don't think we should do anything different for pages.
> 
> Exactly, thanks.
> 
> > Given that we already have the page_owner responsible for providing alloc/free stacks for pages, all that we should in KASAN do is to
> > enable the feature by default. Free stack saving should be decoupled from debug_pagealloc into separate option so that it can be enabled
> > by KASAN and/or debug_pagealloc.
> 
> Right. Walter, can you do it that way, or should I?
> 
> Thanks,
> Vlastimil

I will send new patch v3.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568119549.24886.18.camel%40mtksdccf07.
