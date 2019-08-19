Return-Path: <kasan-dev+bncBDUJHMNZY4KRBMHL5LVAKGQEJBES4DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AEF2992743
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:44:00 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id f11sf2229500edn.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:44:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566225840; cv=pass;
        d=google.com; s=arc-20160816;
        b=udWraJX2W23Y5aDtxWZP4WwzRgvXQG6TgezJFX5ONW2I9wOW27W8fiQnxgfEDwMQnR
         OnxXi9qwg6WzC3SQ6uKxd78UyqObJsQEwQjfra3g/K6atF7EDeRTJzN8w74kysS6OeJT
         KBE1rQgjX2BAJewpd/4XdHbiarBR5ZbI0P+N7WpHNg6NylBXApdre5C+8bEaMKtrIrln
         YlSjV1auSfgch9Dz6MnbmdiYsT3GatAkhn98HzyQOs7rKgzpI9GsFvJF66UmCRW/fjkj
         fKYLO+zlWCkJG5IOVMZxD9hHxkUQSvIax1ksQDGT+uTRyXWvmhQTpiUGAG24Rklykk62
         rl/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gJuzVWWkqMH4dWznqNMtMPgFvWEfxCbYe/SEXJqw1KU=;
        b=zOUjjhuUDG9NzCqj1xnIWoOvkpCbh/tDTIwT+eZN0f9sjysWJH0auBGoeNxpQpaUMK
         4reUsThz4apgUEG7cXuKnw9ilYoQPext9SWDBLNL0q3TAGeiZXEkV1XyLp4DrgJQ2PHg
         EPX2FYqs9KKMTCxRLU/H8hqWklJeh8ITvEPaQTnxRquX1nhEkoxGmN6lzlCTfEwotx2o
         MUJsshmsp/IZnAOfJ4qdNdt/AFjcXL65oY/aAk6yx5FmpVs7a3BX1vIkgVyfqehH4sOJ
         yx4/NMYQqJqAj2KA02mrBNSKmd8ExhnDQ1EeqwWHms9fek59ih252bT2gQMy51h9/MCx
         HXJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of will.deacon@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=will.deacon@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gJuzVWWkqMH4dWznqNMtMPgFvWEfxCbYe/SEXJqw1KU=;
        b=Jh1bxGJPN7/jKO/dGWPIBQzPeLKQfyBcfZs+WGQAXINZoKR5qsoQjBpW/odj3gqVEg
         oMgsLKlJbL+k6WnnLKNR7OTP+LEC0VSnlnluwSbyWH8J6OCApdnCsWRgq8O8aj2NB1a9
         Ld3O7zTskS+Ukv00dPg0SbP3dYvVsA0ARpmts2ZFJfItpj8aygglRk9FM7h+h6PCkXw6
         obBgSBBkruXIy5FTN9FHbv/8B5I1pURU2Fk8UhIQmIlXadaDP0p4lrrNkqe2ry+GL+L4
         ZvwKClFATso2YDjmuTOEy69X0Fb/Ug93qGVu0s8oZXz7/4cZm/xQvuxg9a9YDuSjXrND
         ZQ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gJuzVWWkqMH4dWznqNMtMPgFvWEfxCbYe/SEXJqw1KU=;
        b=NNonLPBNqhIWpAw8B20eaDNH8dUPO15WkUMEVr6ocLljNvwDqi2uqbiWBsygVNwhGx
         L8D+JtOxfWLiVMw25xvge6dCGoZlDXgNoBIkNNyyvFPMfSOlJYGlfbn86LeWfuRGA9ys
         3bAuTkSjWv/x0nLZRoR3TF9joGtfqMkbRWtY78OWmRbSN9HW+XBh77l3LoP5QG02vbTr
         bnOSmjBScBKN/op+aMcXgki62YujCTdC5Pcrzqcd6dAYBq6m6A1MfNkJci/Wn4FhI531
         bI8oW/Jf4p5NYI9+HQ96yDYW16nwu1uRTSd4/QSi7mLzj09V9ViOG0RaaIfOvUMR+Kix
         iWAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVA9yGp2aYvEUqDlp+aQ22A3FPSZnqUGdRBMJs6EvOXjOwuFA/Y
	OC+NPF/GJZ63H/zvVVPVNoA=
X-Google-Smtp-Source: APXvYqwlylFqDS/zcTkXcVsCPI7IWENBvVTdouEEZ3yu1UFlKdnr7IcwAnCQQOSITh0qZJAHH+2mdg==
X-Received: by 2002:a17:906:454d:: with SMTP id s13mr21065032ejq.159.1566225840405;
        Mon, 19 Aug 2019 07:44:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:e604:: with SMTP id y4ls2436398edm.16.gmail; Mon, 19 Aug
 2019 07:43:59 -0700 (PDT)
X-Received: by 2002:a50:b66f:: with SMTP id c44mr25522684ede.171.1566225839953;
        Mon, 19 Aug 2019 07:43:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566225839; cv=none;
        d=google.com; s=arc-20160816;
        b=CdUR/08t1MlZleIMrEjP78BzgYzkohcezEqvThnQFTI1S3Tj0ngkIsZXRdL5BzUJFx
         FmEKnmug87F+blYBrMFGyAbTq8TbLW/evyzoosmg8MiaTk/Bfhgp8cPW5kLZjYzhUHlK
         YeFtC9DIRsEP6/y3Uvz6ELTAyxWkGYLesI3MrYaIZqy9LGkNv3SLUntR4S5auUY/VPOw
         yzJMT2lI6++2gHWdW3hx+/OFqg27NI9uUASGCtBIbTk0hCbW9qCV5vgaSknQMAqK9h+8
         kRljozt9MsxlvFs7RzdWlvcAbZ0vPKYOa6YTwrse0EQHdqnQCfQa2vAp/UX+zToboyfG
         iWdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=cCwCGUdJ1nk2+g+4IdqtqU9ek217DGUyA3IMPVMeB6A=;
        b=hS+OeS39s7RHOSIoi/tkU6nOKWRlmWQjovAU83l34HvXgWMc0sOSY+GT6q/ztOzXAk
         IYX1WRgbUvosXs1lZqWZM3nnJBghPDODdQrM+s9mbjRLwKJomRvPX8IJDIp2G2LajBMI
         E/7+Gbfz42chIR+hq6GeHhb1PyyCQUcCtLqy8mKGOb4o0rs4HS0VkD1E5ObFas1pSLW2
         Z0yEwT66fBR44h6FT6JuD1NA+4iUXo3dvBTbNuz3CxiXrSirb4izx5t9tI/7MTSGryMt
         U1smljnkY7+kSdsxTeIc2Oc428ZPnNKUK2stq6sayaL0NhUCl54INcYtaMK+1AuhU0s6
         N0LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of will.deacon@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=will.deacon@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s30si710237eda.4.2019.08.19.07.43.59
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 07:43:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of will.deacon@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2BF7928;
	Mon, 19 Aug 2019 07:43:59 -0700 (PDT)
Received: from fuggles.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 293DC3F718;
	Mon, 19 Aug 2019 07:43:57 -0700 (PDT)
Date: Mon, 19 Aug 2019 15:43:55 +0100
From: Will Deacon <will.deacon@arm.com>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Will Deacon <will@kernel.org>, Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Walter Wu <walter-zh.wu@mediatek.com>, wsd_upstream@mediatek.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mediatek@lists.infradead.org,
	Alexander Potapenko <glider@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819144355.GD14981@fuggles.cambridge.arm.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
 <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
 <20190819142238.2jobs6vabkp2isg2@willie-the-truck>
 <1ac7eb3e-156f-218c-8c5a-39a05dd46d55@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1ac7eb3e-156f-218c-8c5a-39a05dd46d55@arm.com>
User-Agent: Mutt/1.11.1+86 (6f28e57d73f2) ()
X-Original-Sender: will.deacon@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of will.deacon@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=will.deacon@arm.com
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

On Mon, Aug 19, 2019 at 03:35:16PM +0100, Robin Murphy wrote:
> On 19/08/2019 15:22, Will Deacon wrote:
> > On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
> > > On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
> > > > 
> > > > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > > > > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > > > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > > > > > 
> > > > > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > > > > memory corruption.
> > > > > > 
> > > > > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > > > > in this area, but I /thought/ they were only needed after the support for
> > > > > > 52-bit virtual addressing in the kernel.
> > > > > 
> > > > > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > > > > the arm64 for-next/core branch. I think this is a latent issue, and
> > > > > people are only just starting to test with KASAN_SW_TAGS.
> > > > > 
> > > > > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > > > > virt->page->virt, losing the per-object tag in the process.
> > > > > 
> > > > > Our page_to_virt() seems to get a per-page tag, but this only makes
> > > > > sense if you're dealing with the page allocator, rather than something
> > > > > like SLUB which carves a page into smaller objects giving each object a
> > > > > distinct tag.
> > > > > 
> > > > > Any round-trip of a pointer from SLUB is going to lose the per-object
> > > > > tag.
> > > > 
> > > > Urgh, I wonder how this is supposed to work?
> > > > 
> > > > If we end up having to check the KASAN shadow for *_to_virt(), then why
> > > > do we need to store anything in the page flags at all? Andrey?
> > > 
> > > As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
> > > pagealloc") we should only save a non-0xff tag in page flags for non
> > > slab pages.
> > 
> > Thanks, that makes sense. Hopefully the patch from Andrey R will solve
> > both of the reported splats, since I'd not realised they were both on the
> > kfree() path.
> > 
> > > Could you share your .config so I can reproduce this?
> > 
> > This is in the iopgtable code, so it's probably pretty tricky to trigger
> > at runtime unless you have the write IOMMU hardware, unfortunately.
> 
> If simply freeing any entry from the l2_tables cache is sufficient, then the
> short-descriptor selftest should do the job, and that ought to run on
> anything (modulo insane RAM layouts).

Ok, so that would be defconfig + CONFIG_IOMMU_IO_PGTABLE_ARMV7S +
CONFIG_IOMMU_IO_PGTABLE_ARMV7S_SELFTEST + KASAN...

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819144355.GD14981%40fuggles.cambridge.arm.com.
