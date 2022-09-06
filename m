Return-Path: <kasan-dev+bncBCKMR55PYIGBBQH43OMAMGQESHIJ6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id CE1705AE1C4
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 10:01:04 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id c6-20020adfa706000000b00222c3caa23esf2032399wrd.15
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 01:01:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662451264; cv=pass;
        d=google.com; s=arc-20160816;
        b=qfXC4o59hHnujx/rsjkRpdCyJbPxO8LWHMBuqxHmtMOVGZ/G771r4VyVA3Ppg6yyXg
         LOpclPu0BuXxwi/FQs9DpUvJMcHkwgV3l8S9k/pJnX2IarcXqRRIrkAmlevGjNuw2NmO
         1PcOcRXoirWIawybgZ4laUlsQeGGLfIrjS10EledvE2OzPU3yrn4tGOpcMd2CqAwOnAw
         BzsixhpFUSiuWmr2db4I5G8OE8dKGPSq7YYb1OT2nkwCZkf5f8/7C2D8/cHDJ3SG6hMB
         K0urtdy0ZxJvtOuT2FCAV6bHqh+Jn3/nBlacZO4PcAkzbtX7ByyANg1DQctWaHSiUE+b
         2UvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Y8zccVtZ3mIjgmFUEEwJTfy7w/KJjq80yLjNLGCFQrY=;
        b=aljv4mTP5nDAxusNdWthPaLGCfJmmew7wpIvWacTQG7M2aUg6kXiw6DK+YX77p5DCX
         3HEOjEdIBTxngX1Jgre4AD5yQc2MW3I3bEzxQfELTSyx/Hah2nPupdrTBnhzbdRoPv9Z
         0o31s7Ymz2WYdiPsAykilQ57lmr+ad/YO+uxa6yOBDqYwxBuUGgT4p07umct6KIFjAr0
         5KszH3HSij/e0ixMv52ZQqhhPkvpwP6m6jWR7q6nWv2sElH/92t29JMVSYGNIHCuowjD
         bc9suxtqJ9GE203CN4WGr9daFCWeGLjrsPXiGUbho4yoICelkcw7yG/tzq3C0uSPW3yz
         Ih0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pD+ASQHS;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=Y8zccVtZ3mIjgmFUEEwJTfy7w/KJjq80yLjNLGCFQrY=;
        b=lGiTpP8tNRgmAYQfgS8pKCKrYqOi2DANEdulxvXQh5R8ZDzoeURhXK+PrHyczUDMc5
         +BOzvetoaVcAMaphmI1Z2pKYyyfkL9fU0pS7oJ3PidThHwoJsDp/pwanSr2oUFgJPZI2
         hoUOYtr60Kw7gkvwl03Drc/oq6WLc/10XptlrnN70u2Yl8niHe73OjsXa3jaD0+/nnfO
         +ZqRADF046NC2EVa3bejVTTBby935LOdpkL34iPTZ88Ac/7nMaHSzmUvBXGnBttjpkLu
         mB9M6mUXNtIV3RSa9+5pJK7fqV53UqVNnSsAlU7gphxcdTz5MBsPnUdx3/F0dTY9Gcbj
         dRog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=Y8zccVtZ3mIjgmFUEEwJTfy7w/KJjq80yLjNLGCFQrY=;
        b=NWYcDHtYI8vYMFcGZd40NeELArjFfwFUP+pDS5ydUwmA3hLuetOAxfMSDrQRKGR85l
         NnoOyVaLZpfyvxmWtwNSxBv88zUN9lvDxXbk0S2k7P17KikBvZLqPYfbzGP/QmWkZaAk
         LWWTroFf4PwBTfHVsXxQTc7o/5CCtmGtvF2Cd9IVN4NlQ72TWsHBrFaDdX8J5iCgwoNv
         N55JUnWTXdRZnlMy11oA5DT1wGONGNtlROEfrYc3Z6GPZWyslPXYN+TKvoXTPICysmdk
         wIicLrbWzLPYNBqg/AxAB1vKlwYc8lWfAdKmkf/ghYSlmrOb5pD4s9ofqVfJTsF5Xtmm
         f1HA==
X-Gm-Message-State: ACgBeo3tZL2zvgr76MNkMgZit0CeN/j/uuBwCHYEY8VZ2aFi0DYBycbF
	zN/rAlznJ/5cneXFUIm8FLM=
X-Google-Smtp-Source: AA6agR6fry80jQ6nq2hV7AbfGW64JwfzBP1Ek0lsfuFzJNdGPep+04tR5OeWamVWHGOg2JNbPsaC9w==
X-Received: by 2002:a05:600c:4f92:b0:3a6:cc5:e616 with SMTP id n18-20020a05600c4f9200b003a60cc5e616mr12782985wmq.53.1662451264445;
        Tue, 06 Sep 2022 01:01:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls1928766wrh.3.-pod-prod-gmail;
 Tue, 06 Sep 2022 01:01:03 -0700 (PDT)
X-Received: by 2002:adf:db85:0:b0:225:2d24:9455 with SMTP id u5-20020adfdb85000000b002252d249455mr27473368wri.711.1662451263157;
        Tue, 06 Sep 2022 01:01:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662451263; cv=none;
        d=google.com; s=arc-20160816;
        b=o9FcWzNx4ZrEGAB4OD34FlkONtmbtIkgWjLxcj3N2GwTqbVYkBlb8DXPy5sriLSulP
         IU0ADmfqxxrUWmotvRFXsT+Rbi/XuFaQmUIb/u2jVztFtzcO1+j+/g56uQ5yUgeVL1uc
         qCuCILmyTm69o/iASnnW2DIUbUGQuIWBwY7V/pP59jFPtUriUxALAMEBJvutGuKbEflR
         YlCsS7nFzrJ+BuEDH2ViA6OCKRF8dyIIP2SyE87ke57HYT7zkJnypkQOwl+c8OHiKotC
         /5i4ri4QtB9m5XZK11bMoUvxDVf/Cm0dzmEC4ZkQ5QS95LD77mpQSi0FN8dEWwSbPgT6
         mTww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LykPbpb5bX1WhruUNGP1sKPZqUQwdvS2N9veeSktZmY=;
        b=Ir/ncNuvReLfRsiFxNDdLD55xQM66pk3UTn93voEyptflWcWGgdokd2R4dF4piQLl3
         V5h/AOpzMzYXo+HVjFMOBxh0olH73+wIzgF5JedeG86M5SpyOsv63owmMiX5xyG1TkLn
         JYXlbpA5r1QZXWyRq4Hg97QkUgbwzNeb62yIOuFwfhLjpHR1A3B+/DoGVfDuVO3U78WY
         2Eai3txG4fiVlCZpvNYp8l7SzvXDKnd9yvgTt1aBl7jU2fmplBIeqZRR5vMbDK3d8cPs
         JMIuUaioJjb8+fH4xeY0wRDhv0IqRGDovfoAaPwTDiz7/DjjsVh53Z2VEr6IwU4SXxQH
         srcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pD+ASQHS;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id bp28-20020a5d5a9c000000b00226f006a4eesi654601wrb.7.2022.09.06.01.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Sep 2022 01:01:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 933D21F969;
	Tue,  6 Sep 2022 08:01:02 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 631BD13A7A;
	Tue,  6 Sep 2022 08:01:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id WQy1Fz7+FmM9RAAAMHmgww
	(envelope-from <mhocko@suse.com>); Tue, 06 Sep 2022 08:01:02 +0000
Date: Tue, 6 Sep 2022 10:01:01 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <Yxb+PWN9kbfHSN8T@dhcp22.suse.cz>
References: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
 <CAJuCfpHJsfe172YUQbOqkkpNEEF7B6pJZuWnMa2BsdZwwEGKmA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpHJsfe172YUQbOqkkpNEEF7B6pJZuWnMa2BsdZwwEGKmA@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=pD+ASQHS;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 05-09-22 11:03:35, Suren Baghdasaryan wrote:
> On Mon, Sep 5, 2022 at 1:12 AM Michal Hocko <mhocko@suse.com> wrote:
> >
> > On Sun 04-09-22 18:32:58, Suren Baghdasaryan wrote:
> > > On Thu, Sep 1, 2022 at 12:15 PM Michal Hocko <mhocko@suse.com> wrote:
> > [...]
> > > > Yes, tracking back the call trace would be really needed. The question
> > > > is whether this is really prohibitively expensive. How much overhead are
> > > > we talking about? There is no free lunch here, really.  You either have
> > > > the overhead during runtime when the feature is used or on the source
> > > > code level for all the future development (with a maze of macros and
> > > > wrappers).
> > >
> > > As promised, I profiled a simple code that repeatedly makes 10
> > > allocations/frees in a loop and measured overheads of code tagging,
> > > call stack capturing and tracing+BPF for page and slab allocations.
> > > Summary:
> > >
> > > Page allocations (overheads are compared to get_free_pages() duration):
> > > 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> > > 8.8% lookup_page_ext
> > > 1237% call stack capture
> > > 139% tracepoint with attached empty BPF program
> >
> > Yes, I am not surprised that the call stack capturing is really
> > expensive comparing to the allocator fast path (which is really highly
> > optimized and I suspect that with 10 allocation/free loop you mostly get
> > your memory from the pcp lists). Is this overhead still _that_ visible
> > for somehow less microoptimized workloads which have to take slow paths
> > as well?
> 
> Correct, it's a comparison with the allocation fast path, so in a
> sense represents the worst case scenario. However at the same time the
> measurements are fair because they measure the overheads against the
> same meaningful baseline, therefore can be used for comparison.

Yes, I am not saying it is an unfair comparision. It is just not a
particularly practical one for real life situations. So I am not sure
you can draw many conclusions from that. Or let me put it differently.
There is not real point comparing the code tagging and stack unwiding
approaches because the later is simply more complex because it collects
more state. The main question is whether that additional state
collection is too expensive to be practically used.
 
> > Also what kind of stack unwinder is configured (I guess ORC)? This is
> > not my area but from what I remember the unwinder overhead varies
> > between ORC and FP.
> 
> I used whatever is default and didn't try other mechanisms. Don't
> think the difference would be orders of magnitude better though.
> 
> >
> > And just to make it clear. I do realize that an overhead from the stack
> > unwinding is unavoidable. And code tagging would logically have lower
> > overhead as it performs much less work. But the main point is whether
> > our existing stack unwiding approach is really prohibitively expensive
> > to be used for debugging purposes on production systems. I might
> > misremember but I recall people having bigger concerns with page_owner
> > memory footprint than the actual stack unwinder overhead.
> 
> That's one of those questions which are very difficult to answer (if
> even possible) because that would depend on the use scenario. If the
> workload allocates frequently then adding the overhead will likely
> affect it, otherwise might not be even noticeable. In general, in
> pre-production testing we try to minimize the difference in
> performance and memory profiles between the software we are testing
> and the production one. From that point of view, the smaller the
> overhead, the better. I know it's kinda obvious but unfortunately I
> have no better answer to that question.

This is clear but it doesn't really tell whether the existing tooling is
unusable for _your_ or any specific scenarios. Because when we are
talking about adding quite a lot of code and make our allocators APIs
more complicated to track the state then we should carefully weigh the
benefit and the cost. As replied to other email I am really skeptical
this patchset is at the final stage and the more allocators get covered
the more code we have to maintain. So there must be a very strong reason
to add it.

> For the memory overhead, in my early internal proposal with assumption
> of 10000 instrumented allocation call sites, I've made some
> calculations for an 8GB 8-core system (quite typical for Android) and
> ended up with the following:
> 
>                                     per-cpu counters      atomic counters
> page_ext references     16MB                      16MB
> slab object references   10.5MB                   10.5MB
> alloc_tags                      900KB                    312KB
> Total memory overhead 27.4MB                  26.8MB

I do not really think this is all that interesting because the major
memory overhead contributors (page_ext and objcg are going to be there
with other approaches that want to match alloc and free as that clearly
requires to store the allocator objects somewhere).

> so, about 0.34% of the total memory. Our implementation has changed
> since then and the number might not be completely correct but it
> should be in the ballpark.
> I just checked the number of instrumented calls that we currently have
> in the 6.0-rc3 built with defconfig and it's 165 page allocation and
> 2684 slab allocation sites. I readily accept that we are probably
> missing some allocations and additional modules can also contribute to
> these numbers but my guess it's still less than 10000 that I used in
> my calculations.

yes, in the current implementation you are missing most indirect users
of the page allocator as stated elsewhere so the usefulness can be
really limited. A better coverege will not increase the memory
consumption much but it will add an additional maintenance burden that
will scale with different usecases.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxb%2BPWN9kbfHSN8T%40dhcp22.suse.cz.
