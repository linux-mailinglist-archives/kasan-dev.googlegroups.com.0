Return-Path: <kasan-dev+bncBAABB5UKX2MAMGQEC4ECHGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 871A95A8289
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:59:51 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id d4-20020a2e9284000000b0025e0f56d216sf4164888ljh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:59:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661961591; cv=pass;
        d=google.com; s=arc-20160816;
        b=OXuhxXuqzfLcTiAf8m3WXpVfVzphzXIMaX1/omV7VerxohQXmnX943KFPn/O34Xx3B
         la61fp1khEpEgVr/CtMy06PixcgGIz69lynAl8RfUqZQxoAuWACVtxSeN5/Pv1RG91pw
         TpSaQk0xT2TxrWFIihtpDYw7z4wVpEPtAwoLCQZC2SsrAG8z0ii/zdqKGODw4dHdFeQQ
         gxXDbTMpOemwDCBS3/Iyfxt9k8AxywLKaI7v4WQtFrqrktdydj6+iQnpRHNOILMy+jwh
         rFIUJxfGkN6H8U0OEKJBNJz2p1SkeJieNRi3nA/AEd8Fk6nfpYlyAfK7dvo0rrZiexwN
         lE0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YUlMnMZAIrtZeIBe0IHKTQViUiLU1BA/zjU23/CuRCE=;
        b=rjJps3GXLKWnEJPzI0jJerO7/1wmdtrpDhod4BTIXV1hdrP6yVZJ6kJNUw+GTWhQV7
         qUTFkv/0bAJUjp0KDZvY/PprZt7PYdY1wL++auOs7YiAm6hlsS0SUJ6M2eOKk9M5mWkf
         5V4btZlYth0r1HVUzrZGCOBNcRgIvhqy5SxLuh2/eT3Fwy2PIfs+HzQnXlYgV3geB/zz
         4l2oTyQGoG0Iloj4TmHsOaEEuLvjZUi++V0a52iB4a3+H8taS5O6oMLGqpKL/zr0oOhp
         vCb1ZjLDSUdSqT/LZaZ3IHW7BcJiRbqiSmhKj+bjz7hgZfLALog6wlwTVyTWI6HuXEjS
         MY4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GKQv6dES;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=YUlMnMZAIrtZeIBe0IHKTQViUiLU1BA/zjU23/CuRCE=;
        b=OZHKdYV0AszKIw0EWEzAYpBqBJDHFF8Ig5YkyG1pj3qKfuqppwCjSeWdcp5rYt00Bh
         cWFx5ZUsNn1upxF8EAdqpIy6EsseeQjtE6CmnxuxmEXMEcIjLXEvyjVhzawcnACwgT75
         GYkfOOouESBUIqBd4jjKJ2efDSeBgZQ9MYhYuyLsNrzSE+h4hqkqJ2veC7UWtSkAX6cP
         qU/SaX2A8TrBXV2BCHN72A1C3V6qRiqmWm6DjRp2uYpOoZ3J8+4gjB4owj63ofvd89TH
         yksl7UhjmYrKIIJaGNv+W6OoHV0jNCN3pYqz7OuaCQsGZ0u5qhP6yEeYhq3sdi1/pDGM
         FlHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=YUlMnMZAIrtZeIBe0IHKTQViUiLU1BA/zjU23/CuRCE=;
        b=WpKVQ4GZEbqOgSxvbBLOC6Sw8+3hVxbkRW78tYqAysb1BTJ8Rw2oGmxA0FSlcPwlRp
         oJttmmgHeayxz0LeR9Kw7XMQ64Emc10UaMwWMLvlED1DcMAY5ZWi92gtisztvgb4sisE
         4X/9Tp3GONS+HxhpyEVsjm2qGNUtFQh35LFt51QJRU07PMYtjAG/ZMDCCGcmmqnyw+l/
         dVkFrScpwAugLsgA5lO5ZPZVY4MxGvxdme1hjzQaRbn5HyKKlfUvz1zIfgl5DjmZ9/8A
         BQu4zbvUeB6EUhD6dVZgk4tCPxoFE/Wm7Y1rnQHmzl51TVeiNnLjZ5REssVcKfRNogL9
         WW7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Wjb9fw8EDYTGIXYThD2Iq10hhYgtjo7/LSbmOVvTHurIIfj/i
	R6Xargc6NVNgwb7PwOmGOzc=
X-Google-Smtp-Source: AA6agR43GZMF6b6bRPgG9iHAJbC9oqT6XiLNeiQkaCQ5bSOOpSsdUXrlmf4wofVwawYecMcKLFEQYA==
X-Received: by 2002:a05:6512:3b2c:b0:494:7661:1a01 with SMTP id f44-20020a0565123b2c00b0049476611a01mr3409326lfv.58.1661961590918;
        Wed, 31 Aug 2022 08:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bcc1:0:b0:261:ccd8:c60 with SMTP id z1-20020a2ebcc1000000b00261ccd80c60ls2717329ljp.10.-pod-prod-gmail;
 Wed, 31 Aug 2022 08:59:50 -0700 (PDT)
X-Received: by 2002:a05:651c:244:b0:253:ecad:a4ee with SMTP id x4-20020a05651c024400b00253ecada4eemr8081810ljn.21.1661961590032;
        Wed, 31 Aug 2022 08:59:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661961590; cv=none;
        d=google.com; s=arc-20160816;
        b=XFvz/HkBbZUeWkLooHVur5DCaAukJaNtEk+b2bSV4m7OGXJdLC/BAfLMPMtvn4Ctv4
         VBn+d2Uo09tW43/GtF9WihmE8tAQStHVjUh2+W5Cf7weY6eEe9nW+NSEcm/ugAOJ4WfG
         fGzRJp3B6/y8RkOTiXRDeyJ07myKcEsFJk7HAZxxy414HO16nuigQBYjFaE4YiOAkTeE
         ilFIs3iWhocx84rAHh0oK/ehlD5DgmlcBmQBDW9kT9qfrPnaw81CLgo5TCPInD8C5X+w
         c1PrqF2TbFkdWQmgUgb7HJM8oTB4IEv7i2gVJCk2THrhGGmSAlyIi6ly7wj0P0jtN987
         20Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=8eQR8jMOxB0pUJLRgI0y5+reUXpRdgSKiz76DZMbpZA=;
        b=hXHAyaeXz8BfEc1rbGvau6mDIOGjzqRThMaxUfDNqcvSEEMZK9g0ZHmjxNWXemgLey
         Ocux+UOFWntp5IwTdEqAgCHLIBtx0MbDgXK+33GQVHdfVdBtoGlyqg3QSfEEUrce7XCf
         SPW3fk7Wj2hN5lq32tiuPCfqQzw3JUsTxwyMGSwyGa1sxfmF/7i0XezOHGgTA1thHvd9
         S9Tql6XQNKc6f5fDd5ElWDuFuTR+7rmJRSGN1dX0uBIPRsKxnL4scrDRhcgHWRM0sdC1
         6hsNNDYrAnaaTGXVfoW3uTnw59WhAnuf6xH65P1XSOdS9joPwh7tLBSbUzTygBKyLcX6
         hBhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GKQv6dES;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id z25-20020a2eb539000000b00268889719fdsi133478ljm.4.2022.08.31.08.59.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 08:59:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
Date: Wed, 31 Aug 2022 11:59:41 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Mel Gorman <mgorman@suse.de>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220831155941.q5umplytbx6offku@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831101948.f3etturccmp5ovkl@suse.de>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GKQv6dES;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Aug 31, 2022 at 11:19:48AM +0100, Mel Gorman wrote:
> On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
> > On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> > > On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > > > ===========================
> > > > Code tagging framework
> > > > ===========================
> > > > Code tag is a structure identifying a specific location in the source code
> > > > which is generated at compile time and can be embedded in an application-
> > > > specific structure. Several applications of code tagging are included in
> > > > this RFC, such as memory allocation tracking, dynamic fault injection,
> > > > latency tracking and improved error code reporting.
> > > > Basically, it takes the old trick of "define a special elf section for
> > > > objects of a given type so that we can iterate over them at runtime" and
> > > > creates a proper library for it.
> > > 
> > > I might be super dense this morning, but what!? I've skimmed through the
> > > set and I don't think I get it.
> > > 
> > > What does this provide that ftrace/kprobes don't already allow?
> > 
> > You're kidding, right?
> 
> It's a valid question. From the description, it main addition that would
> be hard to do with ftrace or probes is catching where an error code is
> returned. A secondary addition would be catching all historical state and
> not just state since the tracing started.

Catching all historical state is pretty important in the case of memory
allocation accounting, don't you think?

Also, ftrace can drop events. Not really ideal if under system load your memory
accounting numbers start to drift.

> It's also unclear *who* would enable this. It looks like it would mostly
> have value during the development stage of an embedded platform to track
> kernel memory usage on a per-application basis in an environment where it
> may be difficult to setup tracing and tracking. Would it ever be enabled
> in production? Would a distribution ever enable this? If it's enabled, any
> overhead cannot be disabled/enabled at run or boot time so anyone enabling
> this would carry the cost without never necessarily consuming the data.

The whole point of this is to be cheap enough to enable in production -
especially the latency tracing infrastructure. There's a lot of value to
always-on system visibility infrastructure, so that when a live machine starts
to do something wonky the data is already there.

What we've built here this is _far_ cheaper than anything that could be done
with ftrace.

> It might be an ease-of-use thing. Gathering the information from traces
> is tricky and would need combining multiple different elements and that
> is development effort but not impossible.
> 
> Whatever asking for an explanation as to why equivalent functionality
> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.

I think perhaps some of the expectation should be on the "ftrace for
everything!" people to explain a: how their alternative could be even built and
b: how it would compare in terms of performance and ease of use.

Look, I've been a tracing user for many years, and it has its uses, but some of
the claims I've been hearing from tracing/bpf people when any alternative
tooling is proposed sound like vaporware and bullshitting.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831155941.q5umplytbx6offku%40moria.home.lan.
