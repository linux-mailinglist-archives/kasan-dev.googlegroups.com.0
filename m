Return-Path: <kasan-dev+bncBAABBNPRXTTQKGQEQJFXS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 44BD82EA6B
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2019 03:58:14 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id n4sf2269200ioc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 18:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559181493; cv=pass;
        d=google.com; s=arc-20160816;
        b=tv1VLxkDrrRL5HJ2NQ/Q3vRyez4nL1V7r99Jum9NIvAXjtIzj4LJE1xc3zVJNB9Vi3
         H0r56ORDyavMZm0HXamE0L71PjsMDWsii9rVFHpwUAYqII/vqK62RJ0P1eGwqWmj+Jo2
         iHLjMw4mFoX4rHj2Ys4GWmQ/98yTtCvl9vUXYFKhABtA5MIUe4OOUZd+13m14dhzUVPb
         QiXvu72E68c2UYVipziQ8ZNSNaBLZPSoAjBKn/EUOeqGhvUM2JJId8xGK6IauGbM2+AP
         Ab33ugOKRZBYWWlv7Rv7dft0s33Rw977FHA6Dcz4vUjxobt88kJlhQouN+XibzWuHr0u
         89kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=U0MZKS1jmo/IE2gNIiZaiPxHBZOrS4aoNj6C0567euM=;
        b=qZBUNdiDPTtA+5S44U8LPCX6CuSKNCDbC38Vd823nB6CfDGTiGTzn1KOY1OvM1p9Nl
         sOmFl9yGKzL0IWjvvNv593W/N8Hxaymf4fiRLJCMAgQ7ah+gcEVKLd1PnAwEG9rOAXVj
         PdArvvKdEXwms2MFft4c+TTK5VE+vE4zW1105+wky1S/ZT4pZHPtj0CmcngA7Af2xxfB
         WpzNIOJ8WeL70VOWFm93oH6HgZ2y6XTRG45bhf1zXyuMS9fB63Ut9/RLRMSXDKRJ/OKD
         hPKBhzik/bGvDIKkB4lKzRA5H8eStmnTRgOB3iw4Le/HiqHGebB3THzZ3YlqzuWOsH1A
         ezJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U0MZKS1jmo/IE2gNIiZaiPxHBZOrS4aoNj6C0567euM=;
        b=YyP2rwnUDLRZ04bvZA24V8DYx6LFeVux5t1PzIqz0+UA8X2/NRo9oNw+2mhJTz2lON
         quSmEfUBHWbU/YWzPoyoC7CWbRMw66sM50co4cbQVJfo3OwlX0Zt0VvUNfQyXi5NCZZx
         bpJ5cwwQk0TtUQB3hoRTiOtNSUdz21B8zgKMccCr4Kdx+EFCRhIIEwJ/WKhmLLVqixNn
         4KCFZQKUnwW6PL1vNYpJMw7RcTgYoRGGzR3Vr91M7tuSkkscydR0EV94SkH22glTQpaU
         kaLGFCzS+wAT6LRXb1jVbFGHiXV4EB/Ri3G/3ckwi7hf5tP1tAfdsFVdidyECCaxDf2V
         svLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U0MZKS1jmo/IE2gNIiZaiPxHBZOrS4aoNj6C0567euM=;
        b=Pi9LtGWjgE/bI16ghMHsW5nCeMGt48VnJjSdWJb2sfePpHVidGFZwy0yewlFYCfs+x
         qxm1WgKVclXehWB3OFqL0yhed0rSkrRINVSQjTtwKNFxOaNmd+64aRNbC156Y22nqZ55
         rG1q3LTTPc4dLNPsJe5jC9F3C+ulEmuTtaM+fQihC1gUXXrOff73kLvcQKdxs7ayYskN
         iFYD8wrB8ZeVVCHn69fB7RcWCV7gm/nD4xqHiaHTRUdDDAx1lpE5adgvxFVejX9CcCHf
         8Axdnbvh2pE7RmqaPH0rZlS4Np4zOuiCY/bpNWifz13NBzNjCghpqAavejNT7NDat81+
         tbLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWhP61dVQ3QbEiHcfD1JR5muLlgXDXhbEVoEQTbtSd5EZqYaoHa
	II3ybiNcHFhFn2UsgHF/Sks=
X-Google-Smtp-Source: APXvYqwucI9SlhXrr23yaHM0fUUnMFIsgZzxG2xD88DbpgjcnZLrO2jl1E0ZKEjYPzOqgUGA+zGtGg==
X-Received: by 2002:a5d:8181:: with SMTP id u1mr864531ion.303.1559181493074;
        Wed, 29 May 2019 18:58:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f613:: with SMTP id n19ls719062ioh.5.gmail; Wed, 29 May
 2019 18:58:12 -0700 (PDT)
X-Received: by 2002:a5d:9518:: with SMTP id d24mr874619iom.21.1559181492860;
        Wed, 29 May 2019 18:58:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559181492; cv=none;
        d=google.com; s=arc-20160816;
        b=bpH5zGICQLuA4cBKFBZ6xtUMnZGxUIsfeR3mwEQkILZpinY9MNLYpVFnQyh/QktMVt
         KXA/XdqM7MFx6sZzilQ1Lq5XvK/Jw1sQ8WvuoR00GyxCfUT2G+7o9585ck8HFgRnWkmk
         Etf7oSTm1S0Nj/0PC1fzKjlo7ojd53RqAxp8tBKKT98EdGEHndRwJn1cR/VuGk15T3aT
         2AmxkZUhRA7R64F7Vc5vAu6QceQ/s7Qh9m6B5/e4B1DOrukZGe945tnMlnQn3NJX1Ekb
         nmsXS5JHmjQ86c6qcK/Z+DoEVQ9YhVqli+jE4xXHeYO2r9Vedy2NQLKd/7CszMSA1n6H
         uO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=XXsLOZQadxBhSzd1txFxmx/ksVLxTCP4p3VJFs76yBk=;
        b=MTN/sOXAuolbLKM6M3EXthHkwIPwtUXfL+NlHuIJIjZqabCvJm0GEH9IKXU/3WNsHr
         KTdSAna/KzWbFOjDYNjqQ3rvNHjXYoNvE2lLcKUv0FYq3hmPnDNYaTHyV67sAfXzEREd
         3NEF56O0+wanXVYAur6ZOqJ0LrFiHsSg4eHmKF4YdHfryBthZ2eSTE+0O+1Pn45Kiu+I
         NaV0uhds4rKeSkMNYXCWEjY33nMsmBwSirNGNN7soHKLGkd/z1E/B3nUnr9x1vwNX8oO
         atjiBee374v8AYxCEQcKFXlVkpdlIqKo8WrTHtb38CVflwfH9Cap0uIKaLEoi5UEFIqW
         25/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id y3si50341ioy.2.2019.05.29.18.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 18:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 06101ce5e0844a43a15a98856ac9e508-20190530
X-UUID: 06101ce5e0844a43a15a98856ac9e508-20190530
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 117967436; Thu, 30 May 2019 09:58:03 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 30 May 2019 09:58:02 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 30 May 2019 09:58:02 +0800
Message-ID: <1559181482.24427.18.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Miles
 Chen" <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, "Linux ARM"
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>, "Catalin Marinas" <catalin.marinas@arm.com>
Date: Thu, 30 May 2019 09:58:02 +0800
In-Reply-To: <CACT4Y+ZwXsBk8VqvDOJGMqrbVjuZ-HfC9RG4LpgRC-9WqmQJVw@mail.gmail.com>
References: <1559027797-30303-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+aCnODuffR7PafyYispp_U+ZdY1Dr0XQYvmghkogLJzSw@mail.gmail.com>
	 <1559122529.17186.24.camel@mtksdccf07>
	 <CACT4Y+ZwXsBk8VqvDOJGMqrbVjuZ-HfC9RG4LpgRC-9WqmQJVw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Wed, 2019-05-29 at 12:00 +0200, Dmitry Vyukov wrote:
> > > There can be multiple qobjects in the quarantine associated with the
> > > address, right? If so, we need to find the last one rather then a
> > > random one.
> > >
> > The qobject includes the address which has tag and range, corruption
> > address must be satisfied with the same tag and within object address
> > range, then it is found in the quarantine.
> > It should not easy to get multiple qobjects have the same tag and within
> > object address range.
> 
> Yes, using the tag for matching (which I missed) makes the match less likely.
> 
> But I think we should at least try to find the newest object in
> best-effort manner.
We hope it, too.

> Consider, both slab and slub reallocate objects in LIFO manner and we
> don't have a quarantine for objects themselves. So if we have a loop
> that allocates and frees an object of same size a dozen of times.
> That's enough to get a duplicate pointer+tag qobject.
> This includes:
> 1. walking the global quarantine from quarantine_tail backwards.
It is ok.

> 2. walking per-cpu lists in the opposite direction: from tail rather
> then from head. I guess we don't have links, so we could change the
> order and prepend new objects from head.
> This way we significantly increase chances of finding the right
> object. This also deserves a comment mentioning that we can find a
> wrong objects.
> 
The current walking per-cpu list direction is from head to trail. we
will modify the direction and find the newest object.


> > > Why don't we allocate qlist_object and qlist_node in a single
> > > allocation? Doing 2 allocations is both unnecessary slow and leads to
> > > more complex code. We need to allocate them with a single allocations.
> > > Also I think they should be allocated from a dedicated cache that opts
> > > out of quarantine?
> > >
> > Single allocation is good suggestion, if we only has one allocation.
> > then we need to move all member of qlist_object to qlist_node?
> >
> > struct qlist_object {
> >     unsigned long addr;
> >     unsigned int size;
> >     struct kasan_alloc_meta free_track;
> > };
> > struct qlist_node {
> >     struct qlist_object *qobject;
> >     struct qlist_node *next;
> > };
> 
> I see 2 options:
> 1. add addr/size/free_track to qlist_node under ifdef CONFIG_KASAN_SW_TAGS
> 2. or probably better would be to include qlist_node into qlist_object
> as first field, then allocate qlist_object and cast it to qlist_node
> when adding to quarantine, and then as we iterate quarantine, we cast
> qlist_node back to qlist_object and can access size/addr.
> 
Choice 2 looks better, We first try it.

> 
> > We call call ___cache_free() to free the qobject and qnode, it should be
> > out of quarantine?
> 
> This should work.

Thanks your good suggestion.
We will implement those solution which you suggested to the second
edition.


Thanks,
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1559181482.24427.18.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
