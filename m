Return-Path: <kasan-dev+bncBAABBP4732MAMGQENXQ7MEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 440FA5AF375
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 20:21:58 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id bn39-20020a05651c17a700b0026309143eeesf3907250ljb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 11:21:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662488512; cv=pass;
        d=google.com; s=arc-20160816;
        b=oCthVI6aX0//nTmmG/L7M73J83l5xLOrNRR4nhFDeTHXYuB3aJz+IQAbx6RbgJ9Gh/
         ZFIBO/Jd2IxxQWInBqdhIy5GtK3XsQHKP9zVO6hySll6uCXGqsBjIHt1D3VDaAjaHr07
         Y5yHnakupWG822XlzKaLJeptMke7a0uNDorR0IiAyCxBZkrIcukokIw1uwwfiiutKtaQ
         CXk4/9kw/oSpOFB1sdpBApji8TL4arQBlWbqdHUP+dCAyq37ZkeY3BQ+Bkf9B0X6ckvl
         3/W5cf9rv4jflHYmEeksqmDb+Uy3yl/5WiPFAo6Yf9iQjb9yKqnk00xDfbGWG+jicYBW
         ZDHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=W2iFzxcxW+FK4kq3JBRKN+O6k8V16ZmHv4y9YrSB/EI=;
        b=jHN59rfiiHzCWv1OnJBQ0xolO4Pq29Ze+kDH9R9grW4krt2WHc+3S7eaesoRYcYh2K
         S9a19sPYSvO5WTGoO8NBUV2aEyC/C6sGeBl0QIUUADNKdy4fBbLmSy/qWS0NeqwdckB5
         D6CXzk+cL3f1gRfjsoHDI5siO5u8YPDKrr9zfCoD18iGEr5qDh4sW1GzgJ0AKxgn353F
         Ypa1SBlWzo5A8rSvCnkBCK6X9FoT/9K/NBpnNzhUHWoO7qaVI4gwHMMeEtia7ofb1l/e
         qjNzOsA0vX3eBx2mhO1tEmvtd7XUZLtARJkc/E1tOfo5ccnt3xfHtlJdvJn61PC84ixi
         fkEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="e2VD/Hci";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=W2iFzxcxW+FK4kq3JBRKN+O6k8V16ZmHv4y9YrSB/EI=;
        b=OLFavhAV3NVtm3b0tojCqOYvg12cC9ixapYLpuawkuk7w9o9N8BP964Mu++squCwo3
         CNezPHZbOYd+sQnlWpzPolFJo63ItQGlupQp121EOu5rbrrwpcjQMcEHTLzcBIRnSIff
         9HWViJ9WYoM7Z5eB2vdIz2MW2KYMHmfSZPyrtvLUiLSgE+PDSlEbuj3AGLrKkUOpziXI
         jBV8gI3yly4A3MvhxJ8JaFHIxloH+cTE39+NSrN0IM3nQGkfVI0yL8vySBYOX52BwvhM
         e8xRDFrcq/lKGgSxT4stc+bV4LrTFvRWZt/rGQW4Ap3Wd5oPDaubGgNgadlEVIKOVEMy
         RPFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=W2iFzxcxW+FK4kq3JBRKN+O6k8V16ZmHv4y9YrSB/EI=;
        b=yv6/X6155CprXtVufHGmbhsUfW2FHdDX8851JiZqPwj6T0RbkXvadHRv7tX1avf1iV
         4A/1ULudfEJSs2ZwKsc7EIceMlybufIF3Pn+HsK04PJS/e8Q/uh4hWX227LGy4L/qRwv
         oyIm/QH87fHZfYAdYQM/o75b6/qMvrEefWVE845yaaHrOTMJz8nhejXpwg08N+XsfShr
         HP20X4dmurMMsO0twZbix3rYj4STPZK01HFOzYeIklzkg5+1XkY4SHCq2Fu88e2CIB9a
         BFLuJOfjkSu/CzXItmuW4r47vc8onJr6XZSnSqahPHp43GbW7qwyd6RhtU8PLmutu8RL
         epGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3yIXyKKac7ja4ZqCiTqLYxZny2tO8rErVcl03hH+8tmk5zBQMn
	bRUaJ6jIZN1I9Pn+KAjaQtA=
X-Google-Smtp-Source: AA6agR7nEbn12q8fHOUiJDBl5f7iLgCmkxvEMrKiF/aWXn8yQlHo3TJXX+aVyFjnT3dDvNGcmJZhRw==
X-Received: by 2002:ac2:4e15:0:b0:48b:3ad2:42c8 with SMTP id e21-20020ac24e15000000b0048b3ad242c8mr20278790lfr.391.1662488512153;
        Tue, 06 Sep 2022 11:21:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc19:0:b0:268:a975:d226 with SMTP id b25-20020a2ebc19000000b00268a975d226ls2123833ljf.7.-pod-prod-gmail;
 Tue, 06 Sep 2022 11:21:51 -0700 (PDT)
X-Received: by 2002:a2e:9605:0:b0:26a:8d41:1df7 with SMTP id v5-20020a2e9605000000b0026a8d411df7mr2339125ljh.77.1662488511303;
        Tue, 06 Sep 2022 11:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662488511; cv=none;
        d=google.com; s=arc-20160816;
        b=OyWLhCvMva+xqgcJvFUIa7bkS/+mRcQsTVCnboQxBXBVkEJBb683sep/zOHsGklRfd
         09Ed3oaSjpW2b6rE5qu+9Nh2TCyzYeMyL018qVHURPMAbi0rxwLY8A75fixhHO18IMJO
         /fALKoGGUscZSh0UiDGWSqIb86eryyPhKI/CxUhtvDqTVBHnBZxHaQxjC4rPz8/W0A9n
         55o/ppjJOYBhg14gBUKc1/pN+uqI0JypE1U9IKAagnxS4EaeiMEl8fiLLzp9D/xijoIx
         C0IyWU9gPySxBMwGKYJCGM41wrKnrlC6A8W538YR4hRcR2H9biLs4ZB0MU1j8IJgXAzh
         BBqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=/bRlcVcrWdQKJLJipKk17c91ZfuMwNoEsJqygzANM10=;
        b=OIfKkxD4K1i3YgDYMwHYEWgRm/EKnsr5xjrOd+dMm9qeVzS8xgHitrMBWz7uNFokQQ
         W48SOXI1FhGtmGMg6OUahk1/348E3++BZBWsow3CceuRRinw8UrUwLkmMyp1hmAvJZle
         FgY9FTp41VDGF5ADqHIooT35abtSFjoe7ej+VKzAYhOAXGbK9Bo1VianFLs6DIDWFevF
         yu2IGSjmpR1bF6+zbiOAAgpF6+qzzUVswBzdP8Jm05wVBBLec3CtxO8pOXgjT7mFuE1z
         9JwKkA+FaZQFtsbmIskQCklOIYe5tC5Y2ij7Nb0prQ+Hc26Rbd8X+3WF2KjAYDaYLRPM
         1w/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="e2VD/Hci";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id c17-20020a056512075100b0048b38f379d7si543584lfs.0.2022.09.06.11.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Sep 2022 11:21:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Tue, 6 Sep 2022 14:20:58 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220906182058.iijmpzu4rtxowy37@kmo-framework>
References: <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="e2VD/Hci";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Sep 06, 2022 at 09:23:31AM +0200, Michal Hocko wrote:
> On Mon 05-09-22 19:46:49, Kent Overstreet wrote:
> > On Mon, Sep 05, 2022 at 10:49:38AM +0200, Michal Hocko wrote:
> > > This is really my main concern about this whole work. Not only it adds a
> > > considerable maintenance burden to the core MM because
> > 
> > [citation needed]
> 
> I thought this was clear from the email content (the part you haven't
> quoted here). But let me be explicit one more time for you.
> 
> I hope we can agree that in order for this kind of tracking to be useful
> you need to cover _callers_ of the allocator or in the ideal world
> the users/owner of the tracked memory (the later is sometimes much
> harder/impossible to track when the memory is handed over from one peer
> to another).
> 
> It is not particularly useful IMO to see that a large portion of the
> memory has been allocated by say vmalloc or kvmalloc, right?  How
> much does it really tell you that a lot of memory has been allocated
> by kvmalloc or vmalloc? Yet, neither of the two is handled by the
> proposed tracking and it would require additional code to be added and
> _maintained_ to cover them. But that would be still far from complete,
> we have bulk allocator, mempools etc.

Of course - and even a light skimming of the patch set would see it does indeed
address this. We still have to do vmalloc and percpu memory allocations, but
slab is certainly handled and that's the big one.

> As pointed above this just scales poorly and adds to the API space. Not
> to mention that direct use of alloc_tag_add can just confuse layers
> below which rely on the same thing.

It might help you make your case if you'd say something about what you'd like
better.

Otherwise, saying "code has to be maintained" is a little bit like saying water
is wet, and we're all engineers here, I think we know that :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220906182058.iijmpzu4rtxowy37%40kmo-framework.
