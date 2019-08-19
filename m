Return-Path: <kasan-dev+bncBDAZZCVNSYPBBNPB5LVAKGQE4CXON7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A5AA92688
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:22:46 +0200 (CEST)
Received: by mail-yw1-xc40.google.com with SMTP id a12sf3300887ywm.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:22:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566224565; cv=pass;
        d=google.com; s=arc-20160816;
        b=UpxA8Giz1M89MHyNSqy4sZ1m0SN0CN7iQOv0mXXYHPsYq4CXCJVZtPfynULy9hNPTU
         DuJNwXJhTzRjSMt18tqabbYEnB0ud2CPB5gNkMFHimpec+xoGtnej6gPQ3n3rouKdiZI
         ZxHDg/X2HozwgrtPnwg7KlXipsR2q70mvpOYILvlk7YROxfYQXIO82LSvctqIW7Yu+X4
         V9jawHYV/YNdjEGKzXfSwWOsEqWkKo8VrG8DiRg0GsbvpuYJO655fVSsoVQ1eZ1iAzGJ
         Wji8pwY0CzV+HHD4+BWqgK6V+pqGx6V3ze/DyPymE7gg/uT9ml9k6vVWseFlorLBqxu1
         Uw3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ztYd6niUot7ZRSr3Fy4+ErFxHZg0oDMF34AOEJhOjH8=;
        b=uL/ZFGMBu7En3AnOHRzIgSlB9tPC7Zz5cSr3GwuXSnYX0dR/Ql9jb1yBSE41mWWa68
         Cp60AARR28Ya1FEVw1jMltuHlDKGOFgfIe951BpI799EhXgbuRTlK50UiIpNOqqLB/fa
         oc4o+Ax8fMP6PXfT7T5ct8810AJap5pnON6wx4F7lAEsDV9BdDAz1gJqMR+x68PRd3UI
         uDySV5iaAaSWAByMB8iUB/vS0TrC2oW1oZ53bPiGq4wnEZlDmdPdZk8MULyBkKaToTFr
         kq6WUbyDjzFcWzo1uHkpix99fI6K9Ysl3I23di9Ugeg3J4h14/ilSvrgqR8UvZZmYx6l
         tt/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Pj+ZW3B1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ztYd6niUot7ZRSr3Fy4+ErFxHZg0oDMF34AOEJhOjH8=;
        b=UzyCj3Lh2i7ou65RmW9fiDcAwUrtOztkn1gwNrGZsBPOtcB8c1KmEJiABZO0AFLR8C
         zfeHZ+uYYwcnX5SZKbhxt9UVNgtbjE8VXFJxDukRBB4OkGSouoJZZraQOcXh63a9gOuv
         mxcDQf02LLFkfAmDqVgqVooEnwtCRWlMzApOGWipF+4ah0mjLjOInm1oqAAwM5SELTwP
         5NThpjI3yE4AxLhQ2S7NAfQw8rBkczg/tB30E1imsTCXKuEE8UpnoIsjU4pECO72X+jS
         ihgl+BiiVmWPnJv9db5puIt57FU8+ATg8p7WyHO7BgKeizHQW1FtM2nc4xljFzPNkW/3
         CPxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ztYd6niUot7ZRSr3Fy4+ErFxHZg0oDMF34AOEJhOjH8=;
        b=Fzimtro8m3L5TcOErI1YSCDEdI/Rbcr3svz8+Y2Zg+h56ytOI5dLaXQpAvgIzCVtNK
         PdK495upw3zDpw3M0M+sadXcpPVcayAgczi7+BlKS9RUK/Y0ic6X/eKO3i4BJ8B2iVdC
         KKdhPe4GhQFA85f/Na8zqKROSGXXu2SKUbb57mw1rIKi9vZwMNzjbjZP+htlf3/zp+TX
         WZIo0cTO1o+rEEEE/2PndZCLWNsKN/nFkaHL1V+F0FuKghDWoSRwLlxUDz7elbyGD5IZ
         meCGhpIlraeJKzCbJJuIsY3pCvC8BNghAik/ekqApAFAKflUbbBUpVxWhwQoSqulrhZN
         zy1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOMHwJmFB6Yt/z2Jd1SXO8reiywyWNH7DfNL3LahBEx/KN0DoG
	LVn9Aa1tcZe9+pF9yrRiqXc=
X-Google-Smtp-Source: APXvYqztoImC6zgR/p2eVlKKyYBt3zh4Bi/AZ+uO22jhST9oqStHZb0qqrazkeEfe5TVmknt1vvVIQ==
X-Received: by 2002:a25:410b:: with SMTP id o11mr16810440yba.330.1566224565590;
        Mon, 19 Aug 2019 07:22:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:210a:: with SMTP id h10ls2493398ybh.5.gmail; Mon, 19 Aug
 2019 07:22:45 -0700 (PDT)
X-Received: by 2002:a5b:7c8:: with SMTP id t8mr16446084ybq.113.1566224565315;
        Mon, 19 Aug 2019 07:22:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566224565; cv=none;
        d=google.com; s=arc-20160816;
        b=m8733Wxg9gVN/eKCPd5Ythh7mTgf890Ho/6EmSGti9PfdnLkgxWTTW7pjTSvYD/fAl
         SlClJBpirQdaWtHcaHYFXE4wR4Mt/64RigQP+PgtuSk0SweZrFbFFRQURnHVNI9oavUC
         J4gKsKOoxW4HMGKqmXkAz+REsAfFeWVytCCtJkWUlHiz4o+lztlLnDjb+hH8qlW9NKyY
         KGyLIiEMcTPVPAst3C1j/WXFZHgA04aF+sSJLYFcyn7LlYgIK6SM0LL4QRpLFSKyXgSA
         R3D9Kby2woO9a7/uVf69aECe+pUiYC4F2KPkB9Ul0A2NhoR8cjMDSNSmncNBRVcgu20J
         T2CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0bNvdVFvKAFbQ1A2SSTiK4Xb9TTs9IDNzTSnasr7bh8=;
        b=jGM5n5q6BS4o7WfnweQMgPbbom0yWbXtrzkZGtAM52Qs8Yj7DakwXMKP8NBLQXyCU+
         Bu4fZK+GYo9nwk6nknUc7MTFANV6GH89sn9lE1nnZtvm8WwqyKYnWuImodPUkR4zv6Xa
         Y8Xoc3QS9Mf2Mc+EhgtICn245fJNapicYm1NDFCeSbVji8wwRb2FzGo8pq7UQVmOp6sp
         gb4RADz33Ypp6TP4cEdXkpwBbaR91dzUzfo540JkbhO9ZvZL31uTTZvVAfLxz/DGzVTY
         5qcexZ0IuhWq7JOZjqy5r/GP3lKF67JkPMt1FPPwlxwGEslNkBTPD0ZyTGEPsm2Cen3J
         UETw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Pj+ZW3B1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o3si444920yba.5.2019.08.19.07.22.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 07:22:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id EAEF820651;
	Mon, 19 Aug 2019 14:22:41 +0000 (UTC)
Date: Mon, 19 Aug 2019 15:22:38 +0100
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	wsd_upstream@mediatek.com, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mediatek@lists.infradead.org,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819142238.2jobs6vabkp2isg2@willie-the-truck>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
 <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Pj+ZW3B1;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
> On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
> >
> > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > > >
> > > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > > memory corruption.
> > > >
> > > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > > in this area, but I /thought/ they were only needed after the support for
> > > > 52-bit virtual addressing in the kernel.
> > >
> > > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > > the arm64 for-next/core branch. I think this is a latent issue, and
> > > people are only just starting to test with KASAN_SW_TAGS.
> > >
> > > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > > virt->page->virt, losing the per-object tag in the process.
> > >
> > > Our page_to_virt() seems to get a per-page tag, but this only makes
> > > sense if you're dealing with the page allocator, rather than something
> > > like SLUB which carves a page into smaller objects giving each object a
> > > distinct tag.
> > >
> > > Any round-trip of a pointer from SLUB is going to lose the per-object
> > > tag.
> >
> > Urgh, I wonder how this is supposed to work?
> >
> > If we end up having to check the KASAN shadow for *_to_virt(), then why
> > do we need to store anything in the page flags at all? Andrey?
> 
> As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
> pagealloc") we should only save a non-0xff tag in page flags for non
> slab pages.

Thanks, that makes sense. Hopefully the patch from Andrey R will solve
both of the reported splats, since I'd not realised they were both on the
kfree() path.

> Could you share your .config so I can reproduce this?

This is in the iopgtable code, so it's probably pretty tricky to trigger
at runtime unless you have the write IOMMU hardware, unfortunately.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819142238.2jobs6vabkp2isg2%40willie-the-truck.
