Return-Path: <kasan-dev+bncBDAZZCVNSYPBB6GK5LVAKGQEQZSEA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7075592514
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 15:34:49 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id t2sf2028863plq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 06:34:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566221688; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZVftGmWWSGZsLizi6JPpL027145XfnkZVs7PTorovn2E1NwBExZ8XK0+HktJwLX6V
         pibEFADxguwspi2ppAYeidCV0+zTyJI8bEDMnVHvjaTdvz8vmvUr/Hvmz1+3Z0Vu4x83
         dAtn3jFpFy+LTq0JQGlBOPOR16TSKYuJIGF4+83532hqtWiqmE6dXjIbjfk/hQ1M3otR
         3+ALchFZmrTlKX0J9uMb5d1x4PTk8PKYgtJOBnTPdhhi5OBGulIW+HQ0LBYORKfTXgm9
         LL+ewEDE+5hR+t5iORIXijxxAtUZQ7IhhvAwDg5ZTq3M/SUg/+DXEWNGNaUeZJtDZuI8
         q64g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=AyXWPHRukODZoTliHzjhONY0Sfj7Zi1PoWUFWwO5zgM=;
        b=BLC2chmVPsiJK2zolYTjOO+/AOPV1puZ6+fgUYihu1LQTAnkUAAi7nMa2qjlDfEvjs
         Tiy3Mdq9k7pAAJ30d62OfKJzeohET0BBqaI7Jlap6qGd+LIQyHafJcHAJAcwmLOyrv+h
         6jCDBcs1ukoRzd8SMij5ZqkwI6hFqWty/tJRasTTmIL2ksC/KH7LoO4RrrT7Nfs+g3YZ
         ImHnc3bFjSl0YU/xvqcxWBXfigBrGl2Ms+x11zMykUYpUnnhSPWsOvoSzG0S5xJwf/hh
         MZ3mMedj5ri9m93FJGxbVwPzRU92DuCFPudGl4lOnxH6zsoaFYZ3ge8V2rBoM48A/EXF
         JI8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mAkOdid7;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AyXWPHRukODZoTliHzjhONY0Sfj7Zi1PoWUFWwO5zgM=;
        b=ZDZOymAogUCykby5JzQy066lA6EtP/KLAdMFq+9Z30Ve40iUKHJLmxiHJY7vmCCTaF
         N4WIibQtEBK06ZlEKdWOfuL3WD9Ut9oji0kHIRoRXdMJtOMGPJ/TYgWZjTa3/jC7exdj
         u4aEEKA/EzbPEAE0G3p3h4svdxoNXL1CDf/kOzn7hduuj9YO7xq+6KyhxqFfoYJB4AXY
         QWpsua8HoR22R3dOJQLYiklaW6ACAKe5RAesaMBC6QOv4k9U1ePwgrS61WHloWPIECR5
         nfhAkiQXRfU78oXe/rQsMFg2IeNVLSgAO+q1tTmcXDF3vGQwdUYAyZtYGmC8boVvtClS
         VMmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AyXWPHRukODZoTliHzjhONY0Sfj7Zi1PoWUFWwO5zgM=;
        b=VYU3cKnZZtEq8qWqC7wFbEgoFOLxSgwW7X6jupTFCKbeeZuVbWujGpGDTxuStiBca4
         A/Tk6Wvkpyz7kkLx0CuOrGvmF+xKosfKxYCtN1RVT3O7VrQnx/PgnE1MB9NXDRXsiqew
         v5UdejvT/v6xBvVSyo0HKR28VLOg6cmjC/Ny5bMcr76TtHYU5dewpq9FHnOfcwr5E5qa
         k633RNRNCjiAjSU1p2/wwLl+ssFUH3tdhXnS0sENxDWufgXpslk/jHptJTxkujTJtiAG
         IAfmxa1M//PK33GeKN9F6BaxGezJ+sSaCyQC2M6af/OXhTULZ8wG3sGxVVffhUsqunpJ
         nhww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUN1pmSdQK+yifhrL7Y7AQifEyhWeIJzVTwVuEuh08E8og2afJ6
	bRpcRb70R4Sifs19I5T+Pog=
X-Google-Smtp-Source: APXvYqyA0xKSIfX2mMStE4mZ7m6Dl1uY90Cu4dUNSxD+qg/fFifvCkgy2LZOREJcVfOQsg0OY7yw/Q==
X-Received: by 2002:a17:902:a404:: with SMTP id p4mr2237714plq.185.1566221688182;
        Mon, 19 Aug 2019 06:34:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:db53:: with SMTP id u19ls3397268pjx.3.gmail; Mon, 19
 Aug 2019 06:34:47 -0700 (PDT)
X-Received: by 2002:a17:902:3:: with SMTP id 3mr13507706pla.41.1566221687874;
        Mon, 19 Aug 2019 06:34:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566221687; cv=none;
        d=google.com; s=arc-20160816;
        b=zZX3jOv9mXOk38movctkrDWXNQwFuAGDSRdGPi/EO3mCaE0Xm7QP1s//KZWb1PQRCI
         naIinCrr07U2vNU+TRuRTvqpf/rxJdzQVPm5KnAI2C7kadtw5sIU2JBGJ0ulBVEFcQKN
         EHwud25NAtwC96koJAT6UpSH5szcCejtJThsXAhj/AOlu+JDKT41KZP4Fd9bPefM6C2u
         t3cvy/jgCAj0AabEqBOWxiUFJwbOpuHm+kU3qLuv7QE1yRj9ahjLmcoVYZfB4jmEZLP5
         +jyc3nsxXPBm1QQu4rSxyNZtAwYCilUv/bjQtnTeDtaziYNV0Abps+5Gx8RF+yf+q768
         ix3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pk5oeETTspbM2Xu8ms+3yCnr7yu2efWo8trV1ib5KgU=;
        b=lAUt7Hx3MMXYTt/Fcv5nSUYRC93XG1elRPev5eJcekylqKvpZrqbPzlxN5AUrlY6ZO
         C8j5Cq4RmgRyP/lvoIGpUsHGEZ36V7DW54gvo4feIo5GAbEyBN9EP0nLhFDRABtzGWMH
         siv9fv5FwC+fLxRPi9ysyXH+3gI2O3N56khPFVvmgkZ87ZHSgvGbcBSFuBpo/smxLtPD
         C9TlBJgBQ2JXxRyqx8lcDz7JT9xdkabzEBQGwLQi9V7fktP3V0SLGNjWFKgG0pVUWQKK
         8Xo6BUqTjfABO432LqRq6HkiQu9KP8wjDDbLDu72jzJyIt6QZ33AEMDkSqx1e+tbbrti
         OL7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mAkOdid7;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j6si466124pjt.0.2019.08.19.06.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 06:34:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3BF452085A;
	Mon, 19 Aug 2019 13:34:45 +0000 (UTC)
Date: Mon, 19 Aug 2019 14:34:42 +0100
From: Will Deacon <will@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>, wsd_upstream@mediatek.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190819132347.GB9927@lakrids.cambridge.arm.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=mAkOdid7;       spf=pass
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

On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > 
> > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > its original pointer tag in order to avoid kasan report an incorrect
> > > memory corruption.
> > 
> > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > in this area, but I /thought/ they were only needed after the support for
> > 52-bit virtual addressing in the kernel.
> 
> I'm seeing similar issues in the virtio blk code (splat below), atop of
> the arm64 for-next/core branch. I think this is a latent issue, and
> people are only just starting to test with KASAN_SW_TAGS.
> 
> It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> virt->page->virt, losing the per-object tag in the process.
> 
> Our page_to_virt() seems to get a per-page tag, but this only makes
> sense if you're dealing with the page allocator, rather than something
> like SLUB which carves a page into smaller objects giving each object a
> distinct tag.
> 
> Any round-trip of a pointer from SLUB is going to lose the per-object
> tag.

Urgh, I wonder how this is supposed to work?

If we end up having to check the KASAN shadow for *_to_virt(), then why
do we need to store anything in the page flags at all? Andrey?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819133441.ejomv6cprdcz7hh6%40willie-the-truck.
