Return-Path: <kasan-dev+bncBAABBUFFYSMAMGQE3ZBYQ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id CAEB15AA0B9
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 22:15:12 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id c5-20020a7bc005000000b003a63a3570f2sf9572wmb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 13:15:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662063312; cv=pass;
        d=google.com; s=arc-20160816;
        b=sGVsOZgSGNWR85iID5HfadfNDO+EQUqps/57y6Gi79LGcINR3KUY3ZdEJ8rn41/lLK
         fLPgXIn1huZ8u+fPSQSTIgqKaQGD+jdiKnM+cAnrWCvxuvVjRqFdKwtdCSgq5LVlJN+k
         nTa+NWTwLDpqFM9mnmCrMVkZkpifGAcWYRIeagK7TZpnI4+p+hWLN0QV7ozsGaDnkM9i
         RxRfXoZc1V4wjAsKCLiG9ItQ6+QXfjIsfgGRbykT1j0dPhopOcRGVAGr1pV3YEEnnkeN
         jJZOBWKGzK/WFoL/AzVL0Lkye6XVRVlAgL/EE55LcD9d9Iqk4cN0iNZDOEbhV44PPNno
         ooPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=J4yrsxp/LCDJYG/tV6ikAL4s5oWIlRlkOIRG9wZeERE=;
        b=rgF3F6PS7qXpiv1mq5H97tmDkUFykUhGEmrdbr6bBGG/okQ11Ghth4oCXYhna1M0qp
         /G8o6TDTHazsUC0TuJj1TPt2VDfeaoKYaHIKMBwEbbixMH/0KLIZRnODLcH0rf3m2wrJ
         Ndq6naB2zIh50nPnNL3FolPBOjpCfJvLeAL//nrcd9yuhtTzQLBhh+txDBGT2IZeUeRM
         cYrOz0jdCJym7iHOKDdkgt3EQgXbEZeqUa6zmON+8IeTl25CmpTR4Inais+OIm7XK2Z5
         +viAuUSbNReGEvBy/T8C4KBSCUULPI6HwtCyw0rEr4aYLHNYmpcxW6MMKuVHtnM9a9q5
         JtAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GZmX8EgK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=J4yrsxp/LCDJYG/tV6ikAL4s5oWIlRlkOIRG9wZeERE=;
        b=CILZWxf/s/WcVS4St9HPF8+tIP9qGq5FpnRx5wg9TYNPDoeBwPAja7++mBEQBIr3uG
         ZkOK0wiLQJmNU1S2A0XVmGqmJ4hOdi2xpTMlpfDzs181x5oN8UXXHmn35VLgKt/OxCVS
         ADjHdS0Ki1+ONB4m6Q5l7aj4TqdC+zTuD8wYhs6jb72U/6HQTUNzmzSQDa9C7EMaV/NH
         5iwfvQngEv1Kciv5w+VILOJgWDeAE/gSNawas3mgryaKHTnyTKp70pNMVwV3506xG1Aj
         EG1u0BID79EvmwqxNmFWAPJi0nJFuKn0lwlsBCBElEPMVsfO3QdRdwjRPKF2Z1DcAtBW
         muSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=J4yrsxp/LCDJYG/tV6ikAL4s5oWIlRlkOIRG9wZeERE=;
        b=BphE+PdF8KV5YdKOrAl11klNR0R3ISDVFikQf9PU9CpPTOP7NcfJOiDGnXC9vjjUpJ
         mM8aqOmELGRkEfeEKQyP5jvKr8rZQqs8CCNwHVtGl+JLz+lChLNrVzDQ5lLyS6OoyHke
         /uwsg+IMmlg9o6yOIWSTZElfTM6DEuss+7LZP9TU0ED04e1VrAHkO8ESPwmqIr2e/jw8
         b/J21o4hickkO5fwwn8V+xpj+0clAHclvfKmI77o954LYklS8faFySq2Tjm9ddhNLbj3
         Y8IhlRqPXs05innoExqjRs/0bb1p8rD0mIvW6QwOkFXH1rKvAuCYfBxs/slXR0mHk1kI
         828Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1W91JbbfMxojCcfdHLmAcrxSNphB2Rf94p2bEQYEJrznuFJWyv
	Mx/rwq8TmtnQ9qJHBzkzahY=
X-Google-Smtp-Source: AA6agR5wy3ehEon4eprUkB4HeTRTtAmWbeq3lxkf1j05wpffOhMd2CgjvS1TRCN8gRfSD+WfLZ3A2w==
X-Received: by 2002:a5d:6f11:0:b0:225:735f:e9b0 with SMTP id ay17-20020a5d6f11000000b00225735fe9b0mr15130947wrb.709.1662063312396;
        Thu, 01 Sep 2022 13:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c059:0:b0:3a6:6268:8eae with SMTP id u25-20020a7bc059000000b003a662688eaels1065956wmc.0.-pod-prod-gmail;
 Thu, 01 Sep 2022 13:15:11 -0700 (PDT)
X-Received: by 2002:a7b:c4d5:0:b0:3a6:161b:4d77 with SMTP id g21-20020a7bc4d5000000b003a6161b4d77mr475205wmk.87.1662063311737;
        Thu, 01 Sep 2022 13:15:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662063311; cv=none;
        d=google.com; s=arc-20160816;
        b=c3yKDqjAHP0OD3MS3k/iWN03HvQVhfvy1RFvthJl9N3TgSnR0yewL66ZncwW8jg7zu
         yp0aXIxgxFV8vAKc2lJwXE+MYXEqeLSB76ehXlFql+O+wEr3AQHSfCJoC8JSYy51qP1n
         P8T/xi9dqtu/LHpfsMKTVVejwGDzY/16CKakKGN5D9d0H+E4icolCFZBPlDPoDC0XQ7K
         YNF3K4FX0krNImCcYZWWgF05CVqGRHUibD5pkL/PvBO5WMeTdjMippUjw0Kz1Aot7BJ2
         yrCMuVMsHYtSq581WNwjlOPW7pcffH+j8x6eamCGYhsni3fbN7D9j7fo/M4E0F9z94FQ
         +iHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=x2NMOlEzDduOKU3OG0hkVY/eZ9DnomVtYyGkujvYMfQ=;
        b=c9IqFfkR/Yq1Hzq80Oi8InWAfjGO8a36NWWhOtcNhRZ74sQf5TIq1VLdG+CNGsaa63
         sq1dBQvmeC1DzBprfZHFsVIvBTOMknBgSTZpciXRLCGOODgJtcmy/OloM4r3KUWsBFMW
         bsraQEasbXhjnA/l36adrylBYHC9U7eh8iCH4XA9M56ED+aLCkR7omPv++83HeSX9zDb
         1zY8X05bMihuKpcKiRGGlQQN8WtN+SWak0j2W86LcICH09FpHt3vRQlEEPxhCGEQHKwz
         Kl1bABMTAuKD1BCWxM59l4CFDL4YzT7yysgP4eHostjHlrnE7eSmGSaFf9nirv7o2BUZ
         0rPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GZmX8EgK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id cc18-20020a5d5c12000000b00226df38c2f0si528191wrb.4.2022.09.01.13.15.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 13:15:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 16:15:02 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>,
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
Message-ID: <20220901201502.sn6223bayzwferxv@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GZmX8EgK;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
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

On Thu, Sep 01, 2022 at 12:39:11PM -0700, Suren Baghdasaryan wrote:
> kmemleak is known to be slow and it's even documented [1], so I hope I
> can skip that part. For page_owner to provide the comparable
> information we would have to capture the call stacks for all page
> allocations unlike our proposal which allows to do that selectively
> for specific call sites. I'll post the overhead numbers of call stack
> capturing once I'm finished with profiling the latest code, hopefully
> sometime tomorrow, in the worst case after the long weekend.

To expand on this further: we're stashing a pointer to the alloc_tag, which is
defined at the allocation callsite. That's how we're able to decrement the
proper counter on free, and why this beats any tracing based approach - with
tracing you'd instead have to correlate allocate/free events. Ouch.

> > Yes, tracking back the call trace would be really needed. The question
> > is whether this is really prohibitively expensive. How much overhead are
> > we talking about? There is no free lunch here, really.  You either have
> > the overhead during runtime when the feature is used or on the source
> > code level for all the future development (with a maze of macros and
> > wrappers).

The full call stack is really not what you want in most applications - that's
what people think they want at first, and why page_owner works the way it does,
but it turns out that then combining all the different but related stack traces
_sucks_ (so why were you saving them in the first place?), and then you have to
do a separate memory allocate for each stack track, which destroys performance.

> 
> Will post the overhead numbers soon.
> What I hear loud and clear is that we need a kernel command-line kill
> switch that mitigates the overhead for having this feature. That seems
> to be the main concern.
> Thanks,

After looking at this more I don't think we should commit just yet - there's
some tradeoffs to be evaluated, and maybe the thing to do first will be to see
if we can cut down on the (huge!) number of allocation interfaces before adding
more complexity.

The ideal approach, from a performance POV, would be to pass a pointer to the
alloc tag to kmalloc() et. all, and then we'd have the actual accounting code in
one place and use a jump label to skip over it when this feature is disabled.

However, there are _many, many_ wrapper functions in our allocation code, and
this approach is going to make the plumbing for the hooks quite a bit bigger
than what we have now - and then, do we want to have this extra alloc_tag
parameter that's not used when CONFIG_ALLOC_TAGGING=n? It's a tiny cost for an
extra unused parameter, but it's a cost - or do we get rid of that with some
extra macro hackery (eww, gross)?

If we do the boot parameter before submission, I think we'll have something
that's maybe not strictly ideal from a performance POV when
CONFIG_ALLOC_TAGGING=y but boot parameter=n, but it'll introduce the minimum
amount of macro insanity.

What we should be able to do pretty easily is discard the alloc_tag structs when
the boot parameter is disabled, because they're in special elf sections and we
already do that (e.g. for .init).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901201502.sn6223bayzwferxv%40moria.home.lan.
