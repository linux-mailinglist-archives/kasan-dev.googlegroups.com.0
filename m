Return-Path: <kasan-dev+bncBDY7XDHKR4OBB37TQSEAMGQEBU57DFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id B19E53D8C71
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 13:05:20 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id b18-20020a6780120000b029025c048b9aefsf322553vsd.9
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 04:05:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627470319; cv=pass;
        d=google.com; s=arc-20160816;
        b=DloZnzS0lfWvG8koSuBjBWjB8XPiipiyVtgmRgw6RsN14ViUbPhURWge4kQY0yDJcT
         KS40hC8GkVzFd6mBgeAfN+36uw2jSUxNpETHxkog/9Wzv/SNUKGJ5emvQgJOMXdHe5AS
         gGiQRCRmogphDYXsQUUHOw4q+QpdoNzEaY4PkgqpVmInc+g8+Od2T4jqOQbziHRCND7e
         YLWx6DhC//bdDt26eTwSDIPrMVruc+Nif6+yskqgcH5Eo0r1vTFyf//z/h4Ubh3sxNeb
         zhvScE3n9PjninKGS1pM7ZsfvNffh1LCLe9jlNxgoPQ8fn15lZ9p75s0YfSbt1aVtX+z
         TsVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=ukykrPDnRsBYsuVC5Y1TMRfaXpEP8f/hhYKFaKoMY2Y=;
        b=McLQMJVg9NjyRwwSIUVR5o2yRCYJmsCwv2ofxv4t/TrfFXC3pYQ0gNCLB8vr+xW/IB
         CQRRzTtjLsY0PrfyCv2MBPqdBkCg6CMD0aOPvN+XHf02Y73GrIjZ5ekWPujqPZ7n4H1v
         w1hIjnxm0vJVE31epUkQKTzmjq4bFO4+EppUpPORe0UOyaTY/P+62edsddX+5yxuw0gc
         9atU6BYkVJx5bnyb/oo1/4HsB/gdMv5RiJ9kLBDpp4dBSI/N1w8RBl3MOluHSsitTn+y
         mFTlI/pEDwoYETmKUiKYFijXb64kF6oFaX7XyHX+F7x3etb8zL0wLEsnW87umLf/QkHL
         df/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="dTE4L/rS";
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ukykrPDnRsBYsuVC5Y1TMRfaXpEP8f/hhYKFaKoMY2Y=;
        b=DTCSTsVeAq7IyIAvoJIC0zsOSeN6ohWHMc2i26n/1O6CnKqegz0aw4VYBECQ/NiS5C
         NENiZqmI//14E6yO7oZnMMrSt/bRyAnuMEvWzTxWCCyjoPwSuuYruphAY4+ExzPML6W9
         5zJCb65FKbtckYrSOZTgS6VH3Ri7scFBZqJnFB8U5uf6KrfrmTHZE1z1hrPkjsdDEhtr
         7JbepOYghuOKB5Ueo3vnoml+Df3B05wYEOpFb3advRyGyBmpZrKYCTem47l7QEDQsAZ9
         0oK+wjve8VgHF/Vd91O+v6FXiNBCM9osGhwGkcuhNg+40KAyZVaJDeJZ9C5GZhr4t4nV
         DvZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ukykrPDnRsBYsuVC5Y1TMRfaXpEP8f/hhYKFaKoMY2Y=;
        b=sFZ9HFUQZ3gMk4pg2T9gIcyk1d0zK1xy5mwaaroUTPTC3RGUYy84b7APrhvIgEC8mZ
         jlJ6aBVm1NAzP0uwcnBIwgVeIk4xyTE21dvkAUp+YwCZAOPR78v3/7c6jmzf8gVy+nqa
         U3mCnmVoKeF+s8s6PnJakz9cA2mvv363vO9Q4a7Moeg6TGw3z7jgSxA251dVH3lhiiAe
         Vs/grfP/WxPY2Qg/qeJHPJM+DsF5WBPhkBK1hsucKxvxvWMs1B6QoZn9PK817w6H1OPM
         a+mcIwsWq0n8wHsLTsxuwdQofWqM8hlCGWtfaKnOPhIcmV1ztjYmFqKYMHI3vTq6f9ef
         nvkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zt8OSDYAAxsDKn85tQORzbG4nCqL3GwOYNDOGqbUJCP/es6zN
	aGoKKfvAX1kUHSYKCNkVxV8=
X-Google-Smtp-Source: ABdhPJyxOVltPbgbUg5O+DhEgq+IUK4YO/+OYP3366LTmphaDNHepqk5GURrLRQrpNd/gwuAlPk4jQ==
X-Received: by 2002:a67:e8d2:: with SMTP id y18mr20762507vsn.37.1627470319684;
        Wed, 28 Jul 2021 04:05:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e3ac:: with SMTP id j12ls281271vsm.2.gmail; Wed, 28 Jul
 2021 04:05:19 -0700 (PDT)
X-Received: by 2002:a67:3108:: with SMTP id x8mr20809892vsx.35.1627470313562;
        Wed, 28 Jul 2021 04:05:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627470313; cv=none;
        d=google.com; s=arc-20160816;
        b=e6KDT8cq7JbwIC0PHbyqG1L5iUcJaOPT13oFXDxwewNAg8Np6kgcBY+melWGCzjFJA
         CqEo/dRN1YSM8cZcAsuV+dZIF9ksJGftPFX0JLlpjfdx6gaI/3jojXARZ5O5bjMDe2Eb
         NR4GXdObwwJpvYIkIOY9qcIuQRzOreK119exWPOe+9Mh5VxNUj0Jz47zQ0fdAqPP5oLW
         BwN85n7w0Q4C0KAVV5NkqNeZFMZXAsShyoJxVrkrmDiGJaf3K9sqbBQQYMAG3kcWxXVc
         ZAXRhJYZfhhboa+KB3Lyae9kS3u0V5bKGJV7cqmK6loIavDOB7JGpJMOV/yIJZhVbWlF
         M1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=WuS5SPNVr0wzahpzgVixyvQu00cdYARn5gVWREstKDg=;
        b=G43KKuapZ9TXN7mvP1iJ8j0HGv7iI2wvfHUYjiIEncytVITjBTl+A5Op3uyvOfsPpB
         NOga51dW1ZYYlkCF+1dWlYRgCzD+JAntmVqDuGNLAE6kpAOchExiNJ5y88Geqn05DW7M
         WBZWylHbMdR7LhXrJVbguJpnfOBEgXn50uf+Fakq9SOTujxWYa6/RQTTvZFkSSEkWHr8
         V7CPtRoEiL+DV/Sq2ZOgg5AygZV3mrk6dBwTp0C2NX49dZ9FyAGvzUMOwR8we2rtXYpV
         SpPF+N9ygJAaJ2Fr/pEESzRFzIUBMidZ/purJKibUFZoYJVtoCC20kXh0/ZGAvuZ0L+o
         0P+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="dTE4L/rS";
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id i21si666960vko.5.2021.07.28.04.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 04:05:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 8226f3546cc7485da802ac7adf75906a-20210728
X-UUID: 8226f3546cc7485da802ac7adf75906a-20210728
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 2119956149; Wed, 28 Jul 2021 19:05:09 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 28 Jul 2021 19:05:07 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 28 Jul 2021 19:05:07 +0800
Message-ID: <29f4844b1af163b0ec463fccbc9b902b3150f5c1.camel@mediatek.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Marco Elver <elver@google.com>, Nicholas Tang
	<nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, "Chinwen Chang"
	<chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <Kuan-Ying.Lee@mediatek.com>
Date: Wed, 28 Jul 2021 19:05:07 +0800
In-Reply-To: <20210727192217.GV13920@arm.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
	 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
	 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
	 <20210727192217.GV13920@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="dTE4L/rS";       spf=pass
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

On Tue, 2021-07-27 at 20:22 +0100, Catalin Marinas wrote:
> On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> > On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > > +Cc Catalin
> > > 
> > > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > > Kuan-Ying.Lee@mediatek.com> wrote:
> > > > 
> > > > Hardware tag-based KASAN doesn't use compiler instrumentation,
> > > > we
> > > > can not use kasan_disable_current() to ignore tag check.
> > > > 
> > > > Thus, we need to reset tags when accessing metadata.
> > > > 
> > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > 
> > > This looks reasonable, but the patch title is not saying this is
> > > kmemleak, nor does the description say what the problem is. What
> > > problem did you encounter? Was it a false positive?
> > 
> > kmemleak would scan kernel memory to check memory leak.
> > When it scans on the invalid slab and dereference, the issue
> > will occur like below.
> > 
> > So I think we should reset the tag before scanning.
> > 
> > # echo scan > /sys/kernel/debug/kmemleak
> > [  151.905804]
> > ==================================================================
> > [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> > [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> > [  151.909656] Pointer tag: [f7], memory tag: [fe]
> 
> It would be interesting to find out why the tag doesn't match.
> Kmemleak
> should in principle only scan valid objects that have been allocated
> and
> the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID, so
> it
> either goes past the size of the object (into the red zone) or it
> still
> accesses the object after it was marked as freed but before being
> released from kmemleak.
> 
> With slab, looking at __cache_free(), it calls kasan_slab_free()
> before
> ___cache_free() -> kmemleak_free_recursive(), so the second scenario
> is
> possible. With slub, however, slab_free_hook() first releases the
> object
> from kmemleak before poisoning it. Based on the stack dump, you are
> using slub, so it may be that kmemleak goes into the object red
> zones.
> 
> I'd like this clarified before blindly resetting the tag.

This kasan issue only happened on hardware tag-based kasan mode.
Because kasan_disable_current() works for generic and sw tag-based
kasan.

HW tag-based kasan depends on slub so slab will not hit this
issue.
I think we can just check if HW tag-based kasan is enabled or not
and decide to reset the tag as below.

if (kasan_has_integrated_init()) // slub case, hw-tag kasan
	pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
else
	pointer = *ptr; // slab

Is this better or any other suggestions?
Any suggestion is appreciated.

Thanks,
Kuan-Ying Lee

> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29f4844b1af163b0ec463fccbc9b902b3150f5c1.camel%40mediatek.com.
