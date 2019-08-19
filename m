Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLWZ5LVAKGQEITNVBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F60925EB
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:05:35 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id b9sf3803304qti.20
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:05:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566223534; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAIEyhTF1aCh7sojQRZsUik7XyGI6m6+dIrO/ST5Qn/EbopP/z3Wm0ieiv96BAIOhE
         cyNlwRaoPbD8rXmIIm8/gUHk+l1RbbE2Mdl4rzLMdaMhvJWixl+HKs/Cyns7cf9rh5QS
         VlRf7MKGPCbs74IWcHCiyfiyNK9qm83UMd8zbbOA+7WGFBaIUFu9+1awpTlhWTfdwJpQ
         hb0WPaEfGgZu6FVU4HZZ9Y2k1OEnNfsVr58Kn6+o/3xxgzzKWreeF1jf5ZwNbyxxD8pj
         RvIw149FSTaFMs9Tqhf1yuLxOzIZREmYBcUe8e9E2T1NBkgSxV6N+CWEnQu6z4r+JtYm
         GlZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IIoR2hRSjCCBmCm1RYb3WfZj95zMyB/AubkvEjJRVaM=;
        b=EQSculRL4xT1DtCHOrE1o9DOjRYVBOHudUzfW4a0mBXujZDG35dO99YFOmcqvFo9VJ
         gv9AeYDxX5auLMpP3Uq9WjjaVWbPQGd2y/18Cm1Y+it4UBFWg2/vsoOhbGYo+H8+JkCk
         GT6F84jBh8R9X5r/0Q+dphR7HP3pU+8uYFRorw7x2afwKtUKW6YZ0ZSPRdpa6L4GQFJJ
         SJ6jmwuyV88xQD5XhpPwaDqtQXmMTQ0kbXhc7j+N1iEYv+kHfCGBZSqCdt8//80w4dfj
         YOgEkxdLx7QV5oqwtoMDcXNLa3hKR3y7GBKwOBI3+EfdDDWQ40ARAiGCkXHcbxncqORc
         pHxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NdMgf9Mv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IIoR2hRSjCCBmCm1RYb3WfZj95zMyB/AubkvEjJRVaM=;
        b=Hj0VP0PHP7b5coN3CoXtOEV5WF5dGSRclmeNBonuBED4TXB6QiYpxQEh82KdnaDlF5
         xzsWjX44uyTJH2knTTRcvQZKg2AZH+bSj7NmtbB9MSCkocnsnY8if634aYWp4gQ1yX+w
         gBCarCuR4wLbdV0db1V+tOPqfF08bUV9EqgzpuEK3F4GwvjuDFFPp/Qe+BAvOexbnOJV
         6iARiYJrZIG/M0NxBPCMIKzLXfkGvPC6Op6W72KScT76c1KvbKbnPqieP+h5iRRLewh4
         ZtOI9A/nn7T+RacVoDH1VOeU36Sjdwa6yoqtM+znd+3RkBp6o/jpzwnOqKypDOpwEdZv
         xifw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IIoR2hRSjCCBmCm1RYb3WfZj95zMyB/AubkvEjJRVaM=;
        b=LQtdho1HOPq4If+Hl48Fq3m7rF15k0xiZg7DzMcyxNrCALW+gKvIIFs71fI9tDLdxA
         T2ojx6h5E6ugb0t2xfjbREoyMHXpi1eKlGwK73TFzvIg+Aq7A7LGAKCyUB8LEWFaXooE
         CoCtD1mVMBveB9W2wAnmhyDyGod0u4YwyWiE4qcqVn4IxqDC9CsfDP+y9h4dEKn0ol3o
         fopW1mMiMMrBt38DJVgaIA1N8uAsEvkvg7ZUFPOxIHKfChINpDumYVZWuv9nX7QtlBSR
         hGwMWKLUHJ7wbTnu0YLPC2EW3qqZ+suNYDPP/fP3k/Py9FC3aesaSJniOf1WaieJK9Bo
         Jf/w==
X-Gm-Message-State: APjAAAVXPSbIiepYwTFR+6jlhfh49IRwAIwDLAAjUbeGwWHvchZ+1LEF
	0ij6ez8FWrIALWnKkjHMHBw=
X-Google-Smtp-Source: APXvYqw1p7HbwjQg2DSrGleLPJZXRiMui1AuEwPWB3tnDYf6RPOf5tM9Re8MaI3xFlb1C2dpRHVR5g==
X-Received: by 2002:a37:b982:: with SMTP id j124mr20727558qkf.251.1566223534243;
        Mon, 19 Aug 2019 07:05:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9d4f:: with SMTP id g76ls4476551qke.0.gmail; Mon, 19 Aug
 2019 07:05:34 -0700 (PDT)
X-Received: by 2002:a37:4b42:: with SMTP id y63mr21272423qka.450.1566223534014;
        Mon, 19 Aug 2019 07:05:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566223534; cv=none;
        d=google.com; s=arc-20160816;
        b=ms8ghsYcA3lZpRJaG41y+hY0eC1Thqv33a7sGh7Uaz6Laq/FURJL5224pa1VlMdKZe
         kk/Wc4gy6IKHgsjhtc6tjMF3bL3dJMqyHz9ukL4qZwtd48mZI8jBXMR7WAcVwQw0KviR
         0IdPdsore2niJzHInwp86yPr3H8vPCgPl65IodGegKwn145nspFakpxtLL5FTqQdf3zf
         9fk/kl7dflryVRJwEZ5JlTY9zFRIiKk7TecBeFiIiID490fYBOkLuWL64/xBz70ymBAR
         n9DhNbkLeiJfFz55XGDU09yqoSJkHZDTxJpiPU4hdgRAkxTF9bk/+wGiuH2K212AvgQt
         qgaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T3UxKUOZ72VWnnQkB3XywWd1zjsE0svXI0cagmUyoZs=;
        b=wnh/kn9T8xQ0hyayu8LXk0vzq7HdPpwflSyqnre4sdS0wWlKOuT+QhsKfpbyEbJSqN
         +m+/QK5Aj4q0UsuTHsPECxPTCrBxhdyAjwxp1M0ODzuYpNq1A+/7OQY0RQ9+E0I6IvFl
         odpbXzWu8E/j8IATFw1DstPiWpzwaUvYEg35YgTr5MW1zy+mzhz4O/LWYgcoQ1lkyKPI
         YN8ozRs9k8sCaMFiHTm6qiqCendyJcoH9+Wqj3gyK0JCfwjzvqRmRnCIna7qdfMgtK0r
         yV3PPYIuSxG8ddJQSQV2Zqz++3b3SiLaW3+8E4l33BskJc2skEd0TgWL89/ttb19VFdF
         Cdjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NdMgf9Mv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v19si632016qth.1.2019.08.19.07.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2019 07:05:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id w26so1223165pfq.12
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 07:05:33 -0700 (PDT)
X-Received: by 2002:a17:90a:c20f:: with SMTP id e15mr20524366pjt.123.1566223533317;
 Mon, 19 Aug 2019 07:05:33 -0700 (PDT)
MIME-Version: 1.0
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck> <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
In-Reply-To: <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Aug 2019 16:05:22 +0200
Message-ID: <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
To: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, wsd_upstream@mediatek.com, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-mediatek@lists.infradead.org, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NdMgf9Mv;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
>
> On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > >
> > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > memory corruption.
> > >
> > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > in this area, but I /thought/ they were only needed after the support for
> > > 52-bit virtual addressing in the kernel.
> >
> > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > the arm64 for-next/core branch. I think this is a latent issue, and
> > people are only just starting to test with KASAN_SW_TAGS.
> >
> > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > virt->page->virt, losing the per-object tag in the process.
> >
> > Our page_to_virt() seems to get a per-page tag, but this only makes
> > sense if you're dealing with the page allocator, rather than something
> > like SLUB which carves a page into smaller objects giving each object a
> > distinct tag.
> >
> > Any round-trip of a pointer from SLUB is going to lose the per-object
> > tag.
>
> Urgh, I wonder how this is supposed to work?
>
> If we end up having to check the KASAN shadow for *_to_virt(), then why
> do we need to store anything in the page flags at all? Andrey?

As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
pagealloc") we should only save a non-0xff tag in page flags for non
slab pages.

Could you share your .config so I can reproduce this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt%3D3oQ%40mail.gmail.com.
