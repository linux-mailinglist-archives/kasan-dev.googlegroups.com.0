Return-Path: <kasan-dev+bncBC7OD3FKWUERB24LYCMAMGQE3AI2ZVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 746005A8A42
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 03:07:57 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id h5-20020a056e021d8500b002eb09a4f7e6sf7983603ila.14
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 18:07:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661994476; cv=pass;
        d=google.com; s=arc-20160816;
        b=We1OjTlgnIs7mucFiophvqVlijfa+giLJA9LePvvPYCfUGOK6/76eCjqEG4scx5C1V
         opFIqgjnQEd/wEBP+hv07TmNDQjPsLQN7DwuGrwDsDtg4EDmHgANBvSqN1XsPiyeun8V
         Pbx+VBzCwE/toHhSuumzEbxC77Br3lbQWOtXdj+gldmRiRfpCA22iFuBxamZptQrU3cz
         N5rYNbVov8HmIrM/wZUlhLpHT8iFj5tP0s27TjgIeN89R+Xoxarxu+hFURZXC4x5zoKx
         l1Gv14MKJQmj8m5pHZKCriw6alPuBpPKUDDCs2pq6gPWcPwL/QLM5P7+wQ+qKQaC4osx
         jklg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j1l/7MCqoQFLOXYFF+WQebMegAyW1mmt7CTx4zoi1u8=;
        b=RGWvRIqf6QkKxIPe95bWTNsfEyb/GyBqt0N7yCCB4sRma7RMiet4r8en5S5cnGrynH
         7joXPt9dCrIQZv6n8/s2Ay7lXO8pSvBgv8rs8cBv+jJ1DpoQhgs6Rd8rd/y9wUO76hGw
         +0bp41Yrn3rp3rOJUkka1ChtdJ0T/SK2pUtAYEDXPG91LR2+9SpQ0bKZWXn35SWbXejo
         cNCcukIDjW6odO1Hx6xbAfHPVBeBvehaGom+56DFr5wCS8UgPoAQ5AzhKmnyg707hIUZ
         onBTRxz9lEhNXnY/9XjS4QyK/lve/9Y1hQ/h1Hs76U7jhHTjIyHV9AP1XbBcKe57dJK4
         4IQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FN6oNUdW;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=j1l/7MCqoQFLOXYFF+WQebMegAyW1mmt7CTx4zoi1u8=;
        b=ew134ouG/7xIosm/4ld5qZgmGr6ubFRHyGQ8fmNq+mc5I8OciVDExxerv1LtgyRl6E
         HclJEDBtB8pTdKbtpVd9ubHWJ8q47Jg3tAjaJOUQNancw5X33skz0ltFs7d0br+iwcVT
         IA43xARnMJjrTNUbWQ2NE+8wEFJ8dQQ20CdE3na+1NAwwvLlUZ+3I+uk4uEbt0U9HDjJ
         i19Q9CbWozLukMvmOYwYFV0L0+Dit2Kd5CSpVngEAtqM3302sBVas4bM0ZTEozK/rCku
         BH4jZS3YONty7X2D14i5uE1JIS6FaBAfj8mqazz5xzYM5TEl7ftxBs2a9rqadYGsUo+Z
         FVww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=j1l/7MCqoQFLOXYFF+WQebMegAyW1mmt7CTx4zoi1u8=;
        b=myxu7GMnbgs4FUvf/FzHHfIfHvnpuCrlZM4Pd66sIlvWE+IyZUXZ2nO8a9HHJART8T
         OrM/T3vgQNsD1UmHCMHcXq+WpR5dtwH5autMLsOk2a+PaOR+NMUeKfzed6tBFp5m4ujy
         Uki8DPBHJwq1sgYm+iCm1wz9W0xM4Ky9/MtNoBYAA2Ar9YBSXf5Z+oT2RL/v4EMunaKl
         EgpQGRmYFhJMA6CwE7j98zpPcqLE7fHhF09GT+E/yVTLYn2HAnAVGYc+WD2SmOtf82fZ
         1AOBDDJlW8JfFoKTwlSWsA6W3rT54Ht6wAfhwC4J7GuAW3U5O7PgoD1koJruaK6/MU26
         bggQ==
X-Gm-Message-State: ACgBeo2q7rvF5Tyo0pItJEMuC9fBBxYXc5sOkXmNjmRHN2TLDAzv5kIR
	ucQh6z/tiWZLWr9PASjnREI=
X-Google-Smtp-Source: AA6agR4L6l+5u6JHahh+Coiw3tWypQxmtrCrCt3j+r8SNojwOEk60MhQ3Sez/ItnhAXZQRcM1WdutA==
X-Received: by 2002:a5d:9da9:0:b0:689:51d2:9ab8 with SMTP id ay41-20020a5d9da9000000b0068951d29ab8mr14208707iob.184.1661994475967;
        Wed, 31 Aug 2022 18:07:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a183:0:b0:349:e63e:93 with SMTP id n3-20020a02a183000000b00349e63e0093ls117677jah.9.-pod-prod-gmail;
 Wed, 31 Aug 2022 18:07:55 -0700 (PDT)
X-Received: by 2002:a05:6638:130e:b0:346:8a34:377a with SMTP id r14-20020a056638130e00b003468a34377amr16490789jad.302.1661994475263;
        Wed, 31 Aug 2022 18:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661994475; cv=none;
        d=google.com; s=arc-20160816;
        b=QmTRWX0d/N5ZSZg14p6KNyZCQ76xtiw7eCVZnAL5FKnJmgzRyF6++IMjIiDQn+NgwT
         6L17s0fqxGlPZcW2tlw2hPC8QGPjJ+g6DhOE8wVVPbyxz0y7N1fwZV9ZpIub+e8an1sp
         JLu+zNeNYuKsCpWt62zwslxk9lG9pUVupXsWhjCPrJ/Q0MwBNLlRjjuiplipgoKzhE0x
         YAcx0BQEt4D6E3gg8/yACBflXNcyvXte+269jy+QfhPpFUKD455+dT6f28txVeo3r97c
         l3lgHuZ/eqraGmRT6Ze94byYqOilhSwc5DI9bd/rxS0IF27K6wqQ8MF+5Yc72bpqGEIW
         GTfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MRPzoJhQ6jRX3IlC8DX7IgvLpQbZlMnsgnvZKuuei8w=;
        b=kLR/z7LrKShgkAZx0b06RFeBtxCZYB0R6Sb711eo2mfA+GyLqjy3lqKBT2NYiYkavh
         5UmiPYwepXgrpXOBw3BJqHhdXxjjn3jLzYHJTawOHRdxODBQVoNRdYNWN45pOoit7B9k
         dkTuNt4hxoRlIzXvnia07dySgTPqyLSUTeh20z9l27GoK/Lt7aGIa3/Ob120q1cc3fX+
         xUuHXLsV54e9df2ERXquM1JigFBFeRXvi+XATeMTd2tGCGMPIXerkJ2a+nb8q5xfw9N0
         eLe2iHd59As85bxIP3qI10dk1t96m4zabp5POe6GKNFJdtkESqb/UDAaN/XdjYCVC7PD
         Q8fA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FN6oNUdW;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id m8-20020a5e8d08000000b00684c9b5bc7asi869326ioj.1.2022.08.31.18.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 18:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id j204so6586124ybj.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 18:07:55 -0700 (PDT)
X-Received: by 2002:a05:6902:4c7:b0:69a:9e36:debe with SMTP id
 v7-20020a05690204c700b0069a9e36debemr14531815ybs.543.1661994474639; Wed, 31
 Aug 2022 18:07:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-11-surenb@google.com>
 <20220831101103.fj5hjgy3dbb44fit@suse.de> <20220831174629.zpa2pu6hpxmytqya@moria.home.lan>
In-Reply-To: <20220831174629.zpa2pu6hpxmytqya@moria.home.lan>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 18:07:43 -0700
Message-ID: <CAJuCfpGxxzHT7X+q2zzu+WRrmyjLsT+RMJ7+LFOECtFuXvt3gA@mail.gmail.com>
Subject: Re: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Andrew Morton <akpm@linux-foundation.org>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	dvyukov@google.com, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FN6oNUdW;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, Aug 31, 2022 at 10:46 AM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Wed, Aug 31, 2022 at 11:11:03AM +0100, Mel Gorman wrote:
> > On Tue, Aug 30, 2022 at 02:48:59PM -0700, Suren Baghdasaryan wrote:
> > > Redefine alloc_pages, __get_free_pages to record allocations done by
> > > these functions. Instrument deallocation hooks to record object freeing.
> > >
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > +#ifdef CONFIG_PAGE_ALLOC_TAGGING
> > > +
> > >  #include <linux/alloc_tag.h>
> > >  #include <linux/page_ext.h>
> > >
> > > @@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
> > >             alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
> > >  }
> > >
> > > +/*
> > > + * Redefinitions of the common page allocators/destructors
> > > + */
> > > +#define pgtag_alloc_pages(gfp, order)                                      \
> > > +({                                                                 \
> > > +   struct page *_page = _alloc_pages((gfp), (order));              \
> > > +                                                                   \
> > > +   if (_page)                                                      \
> > > +           alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > > +   _page;                                                          \
> > > +})
> > > +
> >
> > Instead of renaming alloc_pages, why is the tagging not done in
> > __alloc_pages()? At least __alloc_pages_bulk() is also missed. The branch
> > can be guarded with IS_ENABLED.
>
> It can't be in a function, it has to be in a wrapper macro.

Ah, right. __FILE__, __LINE__ and others we use to record the call
location would point to include/linux/gfp.h instead of the location
allocation is performed at.

>
> alloc_tag_add() is a macro that defines a static struct in a special elf
> section. That struct holds the allocation counters, and putting it in a special
> elf section is how the code to list it in debugfs finds it.
>
> Look at the dynamic debug code for prior precedence for this trick in the kernel
> - that's how it makes pr_debug() calls dynamically controllable at runtime, from
> debugfs. We're taking that method and turning it into a proper library.
>
> Because all the counters are statically allocated, without even a pointer deref
> to get to them in the allocation path (one pointer deref to get to them in the
> deallocate path), that makes this _much, much_ cheaper than anything that could
> be done with tracing - cheap enough that I expect many users will want to enable
> it in production.
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an email to kernel-team+unsubscribe@android.com.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGxxzHT7X%2Bq2zzu%2BWRrmyjLsT%2BRMJ7%2BLFOECtFuXvt3gA%40mail.gmail.com.
