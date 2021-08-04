Return-Path: <kasan-dev+bncBDY7XDHKR4OBBI6MVCEAMGQERHKDPNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id E45F23DFB14
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 07:31:16 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id o2-20020a05620a1102b02903b9ade0af31sf1420554qkk.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Aug 2021 22:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628055076; cv=pass;
        d=google.com; s=arc-20160816;
        b=FywKPvDh5Rp2vfufDV1SUMbqT2Vb9lxMWfVzWfPFEpMISnp/xASxzvl/OznE2Pc4mU
         tJ2aIQUzh2D7dhMD+hAvFjQ7RlfU0IqxFdrQjtsouUA3odw/CJikjRFY/cK3xK1B3+jn
         qDPVkXCcZa5xzptbC/uA52VQ+3AV7sMuAe2D3Ji5QMnuWIs/6AbQoXJbiFIBq7k+qnvw
         CHF9qwU3OyVxjKH06MLKdLAdLh6oW+m4lJidQZMba/e+uVn0W55dLzg7dOwy7wq+fyNj
         +PpppKlJuiErEGkK72mOeN9P7PQy4ETn5q/dZi2WodDRABXGwVoKFOJhB47bFY3mofoX
         VgOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=g6PRhEY0PUqLRkiImXcOrKbpyxkbW3m/JEarcbMcpFs=;
        b=GZDJw4zns0CK8107DNdWI8x5NJMx6I3V/b6P3eykPqWaEcXPAnHGYk74zHERCGZJke
         k7CJd8kV0+XoYocZJmHJBp7mbITahha4+NEiRiQWVqCURi7oGdUc28VJMRienu7FWZyd
         dXD+Kwvy5pNnaetxJGOZr/20I/O5LGGmPvRS+BKO+PqczTDxbcbryd+dqXJBK7yMCzeN
         F3yprnQrtfO9vzjzt46GZk44nA8GZQXSxmW+5PhDeaDeTb+GOxPrOMBYI2U65wJ10RdK
         CqAj0RWk3MJTTXh8IzAkvoRSF/TuAg82kwgTn5PNj+dutLRDb2nXR+SMK0ISppQZDxi6
         9PjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=J8LdfLK6;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6PRhEY0PUqLRkiImXcOrKbpyxkbW3m/JEarcbMcpFs=;
        b=PVxt4z2xw5O4zKkbCFlr1QDN03crGaBHBBhqxuf21nv/gR5+/OGBTSw53Tg+UvvwqA
         nCEcxL2AAlHjsVOwdmfgXS28NbEg8uwxU7r2wkx06E8OBWt24uW2QM3/W7FzECrRiPWI
         t8kurt0CzHacFljeMuttZ1X9t4dfhZqVp+o24d8God0T79f8Y7gYWCjzrYrw1nf7cpp+
         rGRJFOZ9JLI1J4vb9bCKnUOwfux8tJkdsKXWxu4fxV04aeZXnR+Gc3lBITQgck+QiP/a
         /8NTJMepe9LFD+IQoG8piRwgkqGj31MeNcatNxVFwfum3Dw0LvVEd8AOTs4k4MlEaMyO
         w7zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6PRhEY0PUqLRkiImXcOrKbpyxkbW3m/JEarcbMcpFs=;
        b=i/f/+RSrjDPXDeZLm/LfFKAgpoQZv/k2ENl+OuYXN9v9C3P31VlT9r7Bc2rdQFMja5
         CIe9xlO7Bx0HLsSjUbSXVDr9k07j2rTk9TFGk1oEJt48qesz8D2cvbcMdiofPDGdWecI
         1cE4UQp9rgtofH7bZYRifBICFC09DKkOa5WuvTgdpNpGGQnYmOEtaT3gEu6P0Xh9l5vi
         nZ6yjJxAEjitVblE55mE3kAevbtcRvyOshLXKU7Ggk7C2xnwPjZT05VCWlejSbepE8q7
         NWX12A/+/MtkvSvjNfUPC6NYeGepEr1muYVdLrdG4i4I6SdM3tuPsuWCh9OKgNv1zFE8
         s4/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53053oCihNNe61Sgnwr9qUBfflCF+kOfykw46UbGSlWdRuTlnbfY
	B+16E1PUdMHzoKYbBV+XRrg=
X-Google-Smtp-Source: ABdhPJwgjFx/+UQhmfaUepq6g8J9nPv4+ZBQjDzwDdomVKAHd5nlhW4YkvR9wgXo0x8iwinwsMzBuw==
X-Received: by 2002:a05:620a:903:: with SMTP id v3mr23836626qkv.235.1628055076053;
        Tue, 03 Aug 2021 22:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ecc1:: with SMTP id o1ls381206qvq.0.gmail; Tue, 03 Aug
 2021 22:31:15 -0700 (PDT)
X-Received: by 2002:a05:6214:c6d:: with SMTP id t13mr5712437qvj.22.1628055075620;
        Tue, 03 Aug 2021 22:31:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628055075; cv=none;
        d=google.com; s=arc-20160816;
        b=GgMIxMDh0lsuMWi+cxWPKLxgu1JATI8mUZUiclDH2Vz3uszeg+/sq6T0tu5h+5JK9c
         ZhMl/9syn2oQMvoguTZV6/zXAkwMR4YWXgUgsoHT6Hjxc5Y6X9+wRsRtwkSsmFXVf/nG
         ovsLXqeQNj5yiK+QCHwI7uqFaqccgo0I2rnzv/54jyZo9NvFwRg8kLFdj+HcFmXnUyyN
         GQunu3A3uxiD9bPABBRxsX187pP+4MjaT1SZxYlZDCCW+VYw04H0GYBtNwWIatO54GsQ
         pLa/LPo2R7OCaiButrYJe6BrtrNDMavDsaRBgigsfsfUUSKgoIBvFqxbQjewtI+2AD9L
         BOUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=nbXYjxVU9fU2eATKlueXsHPNx3eT6r3T8BtKOjcV62g=;
        b=xz4yMho5aHqzypQwsRG+rqU1chnE0dBay8sIgcxE+FbaQQJB3afDyXG361WPg5/yNN
         kos0q5x7xNinJjKaatXdg7wAZ7ZFK8X9yTPKZk8OQG3gF3Y929SCtuqDBqb//mQE2VG4
         jHMAzZYYCOM8v9SeHrnUQ08lJfR8dXC/PrgXU2dPoGBf9iGlMFXD5hYQ398q+eMMyzMc
         X4KGT15Om+R7MhUHQI7hrbRe4vw+xuWdcVUcvNr/VcJhKo+8Cr7gEIJYeCRMJi5iRC8H
         9TpPXBaCIkHbroeQClYdqsuJpRKrVip9dAfun87xN5obdiGjHrMcUkZ440uTUJwjcl5E
         tq/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=J8LdfLK6;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id n2si78593qkg.5.2021.08.03.22.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Aug 2021 22:31:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: c8fac120f9044cdf9d7f065f0c30488c-20210804
X-UUID: c8fac120f9044cdf9d7f065f0c30488c-20210804
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1503093172; Wed, 04 Aug 2021 13:31:09 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 13:31:08 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 13:31:08 +0800
Message-ID: <bbba73eb31ac508792d2b8e0971229f3660e7847.camel@mediatek.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
From: kuan.ying lee <kuan-ying.lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Catalin Marinas
	<catalin.marinas@arm.com>
CC: Marco Elver <elver@google.com>, Nicholas Tang
	<nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, "Andrew Morton"
	<akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>, <kuan-ying.lee@mediatek.com>
Date: Wed, 4 Aug 2021 13:31:08 +0800
In-Reply-To: <CA+fCnZdprormHJHHuEMC07+OnHdC9MLb9PLpBnE1P9TvrVisfw@mail.gmail.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
	 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
	 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
	 <20210727192217.GV13920@arm.com>
	 <CA+fCnZdprormHJHHuEMC07+OnHdC9MLb9PLpBnE1P9TvrVisfw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=J8LdfLK6;       spf=pass
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

On Fri, 2021-07-30 at 16:57 +0200, Andrey Konovalov wrote:
> On Tue, Jul 27, 2021 at 9:22 PM Catalin Marinas <
> catalin.marinas@arm.com> wrote:
> > 
> > On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> > > On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > > > +Cc Catalin
> > > > 
> > > > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > > > Kuan-Ying.Lee@mediatek.com> wrote:
> > > > > 
> > > > > Hardware tag-based KASAN doesn't use compiler
> > > > > instrumentation, we
> > > > > can not use kasan_disable_current() to ignore tag check.
> > > > > 
> > > > > Thus, we need to reset tags when accessing metadata.
> > > > > 
> > > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > > 
> > > > This looks reasonable, but the patch title is not saying this
> > > > is
> > > > kmemleak, nor does the description say what the problem is.
> > > > What
> > > > problem did you encounter? Was it a false positive?
> > > 
> > > kmemleak would scan kernel memory to check memory leak.
> > > When it scans on the invalid slab and dereference, the issue
> > > will occur like below.
> > > 
> > > So I think we should reset the tag before scanning.
> > > 
> > > # echo scan > /sys/kernel/debug/kmemleak
> > > [  151.905804]
> > > =================================================================
> > > =
> > > [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> > > [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> > > [  151.909656] Pointer tag: [f7], memory tag: [fe]
> > 
> > It would be interesting to find out why the tag doesn't match.
> > Kmemleak
> > should in principle only scan valid objects that have been
> > allocated and
> > the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID,
> > so it
> > either goes past the size of the object (into the red zone) or it
> > still
> > accesses the object after it was marked as freed but before being
> > released from kmemleak.
> > 
> > With slab, looking at __cache_free(), it calls kasan_slab_free()
> > before
> > ___cache_free() -> kmemleak_free_recursive(), so the second
> > scenario is
> > possible. With slub, however, slab_free_hook() first releases the
> > object
> > from kmemleak before poisoning it. Based on the stack dump, you are
> > using slub, so it may be that kmemleak goes into the object red
> > zones.
> > 
> > I'd like this clarified before blindly resetting the tag.
> 
> AFAIK, kmemleak scans the whole object including the leftover redzone
> for kmalloc-allocated objects.
> 
> Looking at the report, there are 11 0xf7 granules, which amounts to
> 176 bytes, and the object is allocated from the kmalloc-256 cache. So
> when kmemleak accesses the last 256-176 bytes, it causes faults, as
> those are marked with KASAN_KMALLOC_REDZONE == KASAN_TAG_INVALID ==
> 0xfe.
> 
> Generally, resetting tags in kasan_disable/enable_current() section
> should be fine to suppress MTE faults, provided those sections had
> been added correctly in the first place.

Thanks Andrey for explanation.
I will refine commit and upload v2.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bbba73eb31ac508792d2b8e0971229f3660e7847.camel%40mediatek.com.
