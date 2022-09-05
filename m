Return-Path: <kasan-dev+bncBC7OD3FKWUERBA7U3CMAMGQEUE7PLMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id B98FC5AD8BC
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 20:03:49 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 15-20020a63020f000000b0041b578f43f9sf4674363pgc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 11:03:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662401028; cv=pass;
        d=google.com; s=arc-20160816;
        b=KHDwDkmBqnWbV0SclZKWvMSqUVndsMA+hdcdPrkGoHWWVdOA5dXIajij4oC7iL7foP
         FtFpjtopNdehuXFmjZisFF8QEHzX99n7mvautTfBTZFwYvg6p2GbQPF2nagn2CbUxTWR
         3U9co+bDZ4UNyTgMPylFbCbWDdkaCTqO4e4YSf03JK6FZb5M9o/1G5njdb/UAJ8lfQpL
         PQFehHJP7yY8u4L8DgQtuSPMIU7D6EX06TdvWSeNnb/UwF/h1xQoTXNVO4Rs7+zxHK28
         Puu1IXKl6GZR227Iiij0avu6QoKS8/uR+Wzdyeu5pDKAImOyXmlmdkRXN1nB6O7Y7ghh
         x4Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0xDTugKsB7IPvDS3q/zSLvGuF92QE2Y/kQD7d9wQJD0=;
        b=h/IOg6Tjnq0+jbwY32Ura5bQgMsnWX5PM/Q70K4/IAdPa0m8XtF9HyslrptjQWkVpi
         9QRgGTjscLPILa4uVQ1xfYEgdxPJuUpWc9Zi3027SLaJlSH5QZ4UAdfrcL70YxD9b35X
         Jfy/o3H1BFqexIaEwicp+Y3Q6XY4rinUR7Dfm+YBL66FCkmWoogYO4oAJorJbRJVqxaW
         3+12CUlF7hd8wg1qzTdjI/uW+pFnxMZ3flR62gtIFx65HkHHZsEZay7/QvkaxH/LEGTo
         jV1zhGikgoIWRNagqEAkUmYrdeeG+L/tQQwMq5/ZREGRD8676mBCtapxi8kK3MLRNvgL
         9K1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cPF8g7Tq;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=0xDTugKsB7IPvDS3q/zSLvGuF92QE2Y/kQD7d9wQJD0=;
        b=aioJvCvqb2gaF8Ja0LXeo3v2/1YI5Lm73Zhuq1EbIIprJjqYmu0OdzVNwWjKun++rt
         jrQs48uS7nmwE0k4uJqnruu/E+lGhcebgQ06JKCq1Uaz1PlD/R01OrIi+zype88FesUo
         TLkPP6bUH7yWTbu2zEANXZSLVSB9oacusBCEu44UZmmx4p4KS4Lr9P9nBQCqrG4Bx76p
         tdZOTYPaaloyT0Jc5BojN4eEilLOMl/rqLWvTu19Mh16UskFlKZ38tvf4yYI8Ns0C6vy
         +dWYap1VJDs8LUqJFIj8cDGx7ct/gm4GPacTI2VFnx85islhDaDEIUiWPXN3zJg8LXax
         cB/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=0xDTugKsB7IPvDS3q/zSLvGuF92QE2Y/kQD7d9wQJD0=;
        b=oFCDvgsfbBAE3BRuHidDOQusBSPMLsqKLuejEW9Z8Z3W60fvvdLY3rpvDBYTxv6VM7
         SNE1RNRJQSo8IS620c0fQIrNq7dllA8EV/orYJFUpGLCtfTqXnSwy4b/ewtyQfcG7m0o
         xRMRNVILRaMDmi04phvumW+EVpdbRASbhYknsAOUQEymLK85s9ZuPbukBxXsx/7tOpSj
         CFN5mnznrSTL7YIdl3RVT3zyZdlxw53Ebq8P49aDIyDy7/1k2azCJR9a2DBTz3g29Zq5
         0SXDyCBMTg2wl8FPyd2i1XvgvpnrpP3LXbru3Di4n0TVBQr4cBsBT4j3T26uf7mbJWjf
         N63A==
X-Gm-Message-State: ACgBeo3sxWbneScDPJCqCEknj55UcX6CwsjUnL/Tjds7e/HyzX4jAGP8
	/0+u+0Y6rYbjJdSgyyEwQR8=
X-Google-Smtp-Source: AA6agR7EuDmUwsxBCede5n1iyGksVwD3R8mZJUYm40pDEUZHJJnv+kB5xMx54TlbH9llenkJwhT+fQ==
X-Received: by 2002:a62:7b4f:0:b0:537:dcaf:acf1 with SMTP id w76-20020a627b4f000000b00537dcafacf1mr47524740pfc.58.1662401027925;
        Mon, 05 Sep 2022 11:03:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d58a:b0:16c:2ae8:5b94 with SMTP id
 k10-20020a170902d58a00b0016c2ae85b94ls8171039plh.0.-pod-prod-gmail; Mon, 05
 Sep 2022 11:03:47 -0700 (PDT)
X-Received: by 2002:a17:90a:c789:b0:1fa:6bc0:77f6 with SMTP id gn9-20020a17090ac78900b001fa6bc077f6mr21333817pjb.1.1662401027124;
        Mon, 05 Sep 2022 11:03:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662401027; cv=none;
        d=google.com; s=arc-20160816;
        b=CjvQ5UwNzq6heXOdjBOceVlOgXxsiLvX3b8ILNOnLXgPDLLoVd39E2k3ObTINIFNQb
         AicC2QGGJ/bbqWVbAfHGPBohbd2goMz7CBqxUqqoodo2mLvjKfuuM4ybAw+0PCYK8BrZ
         3mJjTmNcSPDIQMrDBxu2Ceo2rGEd2Jy9vraWBioNY1GrV4Riz48ojFGjgXt4ejpiigpw
         E8Dm5+bp0aqNKULNkpQR84OjimYh3szl7JoOwJmjZiSfuybSxFYITRvoZiE9vDmbOxTa
         xv80veToQsfnHubiPJySu4FoBGT2zjmkjMkmUnUtpkMWkyyCTZhYuzeHiuDh948xkGzq
         ckvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T67TRgbvL4Ai6kaNg3fck6vcoHVKT+0s4pwJ/NSZTGA=;
        b=Q6Mox/Na8tqs8g/MTdH+1//TCxjBsO9bCagV7OKxYs4PpWi6PvRhDRAn9GOwUfSe38
         U7P+dEeuMm+bHfPx/zruenuL7qzyoWcoGxd+ed4mcCzhzmshpuHqUCebcDZpjA6caM35
         7kEI6mNwiI5yYmgeX4cB5u0aJwR1M7gezA1/ysc25gr8lc+lKvaW/X9VO8GY5xQdEanq
         LGctJ9x8eB5YnFQkgLSN2Ww+qYu4MD0qLX2QwosqHp/KSGVl9Iz5K4oQzTBjE3BbxSzF
         3wrTZk0pIYs7CehRQ/9grbPgRBFYlV2VfP403YITIbjxgs24UCXqocEPhw/cntpsJqQa
         JwwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cPF8g7Tq;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id n19-20020a056a0007d300b0052d5f21fa66si594191pfu.1.2022.09.05.11.03.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 11:03:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id k9so1765186ils.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 11:03:47 -0700 (PDT)
X-Received: by 2002:a05:6e02:1ba8:b0:2eb:7d50:5fb8 with SMTP id
 n8-20020a056e021ba800b002eb7d505fb8mr14014798ili.296.1662401026346; Mon, 05
 Sep 2022 11:03:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz> <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
In-Reply-To: <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Sep 2022 11:03:35 -0700
Message-ID: <CAJuCfpHJsfe172YUQbOqkkpNEEF7B6pJZuWnMa2BsdZwwEGKmA@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Michal Hocko <mhocko@suse.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cPF8g7Tq;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::134 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Sep 5, 2022 at 1:12 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Sun 04-09-22 18:32:58, Suren Baghdasaryan wrote:
> > On Thu, Sep 1, 2022 at 12:15 PM Michal Hocko <mhocko@suse.com> wrote:
> [...]
> > > Yes, tracking back the call trace would be really needed. The question
> > > is whether this is really prohibitively expensive. How much overhead are
> > > we talking about? There is no free lunch here, really.  You either have
> > > the overhead during runtime when the feature is used or on the source
> > > code level for all the future development (with a maze of macros and
> > > wrappers).
> >
> > As promised, I profiled a simple code that repeatedly makes 10
> > allocations/frees in a loop and measured overheads of code tagging,
> > call stack capturing and tracing+BPF for page and slab allocations.
> > Summary:
> >
> > Page allocations (overheads are compared to get_free_pages() duration):
> > 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> > 8.8% lookup_page_ext
> > 1237% call stack capture
> > 139% tracepoint with attached empty BPF program
>
> Yes, I am not surprised that the call stack capturing is really
> expensive comparing to the allocator fast path (which is really highly
> optimized and I suspect that with 10 allocation/free loop you mostly get
> your memory from the pcp lists). Is this overhead still _that_ visible
> for somehow less microoptimized workloads which have to take slow paths
> as well?

Correct, it's a comparison with the allocation fast path, so in a
sense represents the worst case scenario. However at the same time the
measurements are fair because they measure the overheads against the
same meaningful baseline, therefore can be used for comparison.

>
> Also what kind of stack unwinder is configured (I guess ORC)? This is
> not my area but from what I remember the unwinder overhead varies
> between ORC and FP.

I used whatever is default and didn't try other mechanisms. Don't
think the difference would be orders of magnitude better though.

>
> And just to make it clear. I do realize that an overhead from the stack
> unwinding is unavoidable. And code tagging would logically have lower
> overhead as it performs much less work. But the main point is whether
> our existing stack unwiding approach is really prohibitively expensive
> to be used for debugging purposes on production systems. I might
> misremember but I recall people having bigger concerns with page_owner
> memory footprint than the actual stack unwinder overhead.

That's one of those questions which are very difficult to answer (if
even possible) because that would depend on the use scenario. If the
workload allocates frequently then adding the overhead will likely
affect it, otherwise might not be even noticeable. In general, in
pre-production testing we try to minimize the difference in
performance and memory profiles between the software we are testing
and the production one. From that point of view, the smaller the
overhead, the better. I know it's kinda obvious but unfortunately I
have no better answer to that question.

For the memory overhead, in my early internal proposal with assumption
of 10000 instrumented allocation call sites, I've made some
calculations for an 8GB 8-core system (quite typical for Android) and
ended up with the following:

                                    per-cpu counters      atomic counters
page_ext references     16MB                      16MB
slab object references   10.5MB                   10.5MB
alloc_tags                      900KB                    312KB
Total memory overhead 27.4MB                  26.8MB

so, about 0.34% of the total memory. Our implementation has changed
since then and the number might not be completely correct but it
should be in the ballpark.
I just checked the number of instrumented calls that we currently have
in the 6.0-rc3 built with defconfig and it's 165 page allocation and
2684 slab allocation sites. I readily accept that we are probably
missing some allocations and additional modules can also contribute to
these numbers but my guess it's still less than 10000 that I used in
my calculations.
I don't claim that 0.34% overhead is low enough to be always
acceptable, just posting the numbers to provide some reference points.

> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHJsfe172YUQbOqkkpNEEF7B6pJZuWnMa2BsdZwwEGKmA%40mail.gmail.com.
