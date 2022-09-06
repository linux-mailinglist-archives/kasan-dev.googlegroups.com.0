Return-Path: <kasan-dev+bncBC7OD3FKWUERBWOR3WMAMGQE6ZZHJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 163295AEEF4
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 17:35:55 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id g63-20020a636b42000000b004305794e112sf6004423pgc.20
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 08:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662478553; cv=pass;
        d=google.com; s=arc-20160816;
        b=kHUOmFuj6dSHiK6IhayPdz4iEpzldb6+amX9I5hGDdYE9Tte20Tz4JZCmK7PCSFOmC
         MU6t8bxPIzMelMHMMmI7GbCjIRV5vFy4w18qYivGjNV+NI2HPcCq97D+W/huvx8mBQoU
         05zRLUmTuhsVKRMY/yCJssV3crbyXvowDMsEHU0f7Kcrtbh75eYg2zO17OT2NNE+6TiH
         vuGrNXqzB9zplrbRFgzannchyDUK/RidoVZvjTDY6ybp1vErSFkNDg2F4IjlmXCJbVvW
         9ivfc0O1aFkuy3Lhl+FQtVjV5oWJ050rNb4bGA0RjdWFzwfUDYK750cg8VIpAAEbV3Qy
         S9cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ASNpV0jjIo/yhqhmv3wkoq/uq5D2/9lmlrv/QMcrXe0=;
        b=VccINP1TaT4kLY3uJnCOJiJajovpt8VgW5dnHNNcyUZ0A1JtKUiUDA/U8LxUk+VHIR
         sMGsssQucw1PtfNkeVu6pwCzNpdBaTuIdW/N3xDbmoq4lV/YKmmML6xRiNXc7lKXlTqK
         SkIOU1sV9utyTvDQ/IFgV7YOPsEgd0rSx2wr3mBhkRIeWLpyDuBEeVvgcmwajiaOu097
         Xts5n1GTDnWKb2Sfx5xzuGgCYl7TBbetRd1ctNSwXnfmiPQKUe49nN3THND22/xsMBZu
         Ejtp+QmGKXqV+dspH5mfj14/WusUO7/3X5/2zSuFNq6+nf2Blv3N3pvdFE6Ay0NqKU+i
         k6Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o3N3QM1f;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=ASNpV0jjIo/yhqhmv3wkoq/uq5D2/9lmlrv/QMcrXe0=;
        b=XsP7IrWgZlrg+snw8JfsO7tAvszYBKC7YrF+uAxZ6CFX5CujcQVBHS74VRc6VUCYrr
         UpUtDuGF9DlSktsu8PwskTSUfcrqMPLqgbE0r0Az7UUFzuAw+wpJ/LPrBBeMswxQ4Dh3
         khj+cDLHb9JRzx3WJV3cR5HjUGukq6U3qCNwoUVi/AeWXcMT825at0WVs4UFXS6hTIDU
         MtrW/GsT4IUAJoyjKAzyieB1W0B4d387ujrKCRL11WpfNCy8+Y5IBUP2z33dBPUt1aZ4
         M9hErFDfsDz+S9IQHQWW8SvfEJW/Rc9eaS1qzX/NMQhBNfjLyTCtb5HcSAgc4RotpM4O
         +N9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=ASNpV0jjIo/yhqhmv3wkoq/uq5D2/9lmlrv/QMcrXe0=;
        b=RdY43LHh3C+h/Q+PzZ06YGn9Hf/ovNgmdkNCeX7FXca1tJvX9CMmOSQIEFqF+tGav0
         QvkQnSffgVXnnv4UP0YIADYdV4JATUmOVUxhIpjTh2nvCk1leS4PMZj9ZA6I5+plOs3r
         vfwvi9pGxdUAyIC3jZBb8M8xpvmsPo75CPn/Jzn86a+u2NRmpfynNWQwnO21zpYmAJ/c
         UxUVO6j4AUgIjIF30CNadepjQbUuFO9txKSLKD4XBeMZ4ayIOOsdsnrDEopAoQ5k5GSL
         tW4TINd3gb9O6rt/4Sh08fnyyWIQxB1FBWFZgJNkW3m4nzrgY9N/V9ZjtKsxIBirx4Xn
         fz0g==
X-Gm-Message-State: ACgBeo2ipCMW8yT5tjDENWxvQdj/l3BxyepVxFxuBIMGs6zC2aMJqRbG
	4c31DIeK+GwiURDfM+IszhI=
X-Google-Smtp-Source: AA6agR6lf6R+USv6P4Ty9Dr2RMrL6HO793gx+juTFXcv64U2OfZhn7W38pT/yPVuQaFVfvmnZJOFeQ==
X-Received: by 2002:a63:5916:0:b0:41d:2c8c:7492 with SMTP id n22-20020a635916000000b0041d2c8c7492mr46116527pgb.81.1662478553635;
        Tue, 06 Sep 2022 08:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a408:b0:200:ad58:5263 with SMTP id
 y8-20020a17090aa40800b00200ad585263ls440217pjp.1.-pod-control-gmail; Tue, 06
 Sep 2022 08:35:53 -0700 (PDT)
X-Received: by 2002:a17:90a:4a0e:b0:1fe:1c89:a6b7 with SMTP id e14-20020a17090a4a0e00b001fe1c89a6b7mr25532449pjh.239.1662478552888;
        Tue, 06 Sep 2022 08:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662478552; cv=none;
        d=google.com; s=arc-20160816;
        b=t7vcCaCvRV3GXQV0QAB102MYqLv4m35qbe/zgyaqzr31x6H2vQZHJAUsjiE9uiBSgS
         kNFrQbBlWDqj4FqBeVV8oex+a67k/sKXcwg8+IO+ZIOTaZsjsrD4/gicqPSko/UO5tzJ
         +5d9bWECQmMlQ4kig8sY47wE1wU5+NXnbymHl6BISIQX/tV9Nvyn1iy9l/xt6Q6tPkqC
         KxJ7MUTDj5XxWI7nbeKljagFfA6GoCJPWm4tFRqInTeyuqu5LAFB1h7UMEhdKz5rPMO5
         hkq61nzvcGbw7xYQwoh44sF0QXT6BVxaGaFgLo7lt8o4upgGctvxj1betGB6M0kf4qdn
         OMoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GqM67eToD1ny8VVx70XQz+yqa9cCdNaLyhnIUfKzWx0=;
        b=EbjSLX86ItQFQRpTzO8/b0JTPPH0dLge2u0rDH9o30Tb6ZfvQp/o3UmE8bqW9+jlq8
         Y2ajIST/wo/41av1NV8OO/2ZSkWs7W2udtfrZJQNZSdJPGZiOJuriF5KAFC4gey8lwM/
         TLqPzrvZKPrcfIc4wdLGqcy4dvSHh/oGHy7NS+wxx2JIIH6YZegu0CJaJXH01+Y/1Z1v
         N3ASe3JXaewepHOcodrq06QcIYUIH6VopmBPJsKf/wP4TYzEjb/XKPcDA1OlANkDMqPz
         lWKfffnM8kxXNglI+2z/5hNY/EcKITkZb1SHnGnJ3W+rZZPTh5pC/bzBOqCN+FL+0Ksf
         e09Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o3N3QM1f;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id m9-20020a170902f64900b00176b883091asi401995plg.6.2022.09.06.08.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Sep 2022 08:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id z72so9181412iof.12
        for <kasan-dev@googlegroups.com>; Tue, 06 Sep 2022 08:35:52 -0700 (PDT)
X-Received: by 2002:a02:740b:0:b0:349:bcdd:ca20 with SMTP id
 o11-20020a02740b000000b00349bcddca20mr30610852jac.110.1662478551322; Tue, 06
 Sep 2022 08:35:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de> <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan> <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <YxWvbMYLkPoJrQyr@dhcp22.suse.cz> <CAJuCfpHJsfe172YUQbOqkkpNEEF7B6pJZuWnMa2BsdZwwEGKmA@mail.gmail.com>
 <Yxb+PWN9kbfHSN8T@dhcp22.suse.cz>
In-Reply-To: <Yxb+PWN9kbfHSN8T@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Sep 2022 08:35:40 -0700
Message-ID: <CAJuCfpGeEc9_fTCCRj9DtwQEu3u0fecc4DJuOjZzrTPfnNbOKw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=o3N3QM1f;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d36 as
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

On Tue, Sep 6, 2022 at 1:01 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Mon 05-09-22 11:03:35, Suren Baghdasaryan wrote:
> > On Mon, Sep 5, 2022 at 1:12 AM Michal Hocko <mhocko@suse.com> wrote:
> > >
> > > On Sun 04-09-22 18:32:58, Suren Baghdasaryan wrote:
> > > > On Thu, Sep 1, 2022 at 12:15 PM Michal Hocko <mhocko@suse.com> wrote:
> > > [...]
> > > > > Yes, tracking back the call trace would be really needed. The question
> > > > > is whether this is really prohibitively expensive. How much overhead are
> > > > > we talking about? There is no free lunch here, really.  You either have
> > > > > the overhead during runtime when the feature is used or on the source
> > > > > code level for all the future development (with a maze of macros and
> > > > > wrappers).
> > > >
> > > > As promised, I profiled a simple code that repeatedly makes 10
> > > > allocations/frees in a loop and measured overheads of code tagging,
> > > > call stack capturing and tracing+BPF for page and slab allocations.
> > > > Summary:
> > > >
> > > > Page allocations (overheads are compared to get_free_pages() duration):
> > > > 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> > > > 8.8% lookup_page_ext
> > > > 1237% call stack capture
> > > > 139% tracepoint with attached empty BPF program
> > >
> > > Yes, I am not surprised that the call stack capturing is really
> > > expensive comparing to the allocator fast path (which is really highly
> > > optimized and I suspect that with 10 allocation/free loop you mostly get
> > > your memory from the pcp lists). Is this overhead still _that_ visible
> > > for somehow less microoptimized workloads which have to take slow paths
> > > as well?
> >
> > Correct, it's a comparison with the allocation fast path, so in a
> > sense represents the worst case scenario. However at the same time the
> > measurements are fair because they measure the overheads against the
> > same meaningful baseline, therefore can be used for comparison.
>
> Yes, I am not saying it is an unfair comparision. It is just not a
> particularly practical one for real life situations. So I am not sure
> you can draw many conclusions from that. Or let me put it differently.
> There is not real point comparing the code tagging and stack unwiding
> approaches because the later is simply more complex because it collects
> more state. The main question is whether that additional state
> collection is too expensive to be practically used.

You asked me to provide the numbers in one of your replies, that's what I did.

>
> > > Also what kind of stack unwinder is configured (I guess ORC)? This is
> > > not my area but from what I remember the unwinder overhead varies
> > > between ORC and FP.
> >
> > I used whatever is default and didn't try other mechanisms. Don't
> > think the difference would be orders of magnitude better though.
> >
> > >
> > > And just to make it clear. I do realize that an overhead from the stack
> > > unwinding is unavoidable. And code tagging would logically have lower
> > > overhead as it performs much less work. But the main point is whether
> > > our existing stack unwiding approach is really prohibitively expensive
> > > to be used for debugging purposes on production systems. I might
> > > misremember but I recall people having bigger concerns with page_owner
> > > memory footprint than the actual stack unwinder overhead.
> >
> > That's one of those questions which are very difficult to answer (if
> > even possible) because that would depend on the use scenario. If the
> > workload allocates frequently then adding the overhead will likely
> > affect it, otherwise might not be even noticeable. In general, in
> > pre-production testing we try to minimize the difference in
> > performance and memory profiles between the software we are testing
> > and the production one. From that point of view, the smaller the
> > overhead, the better. I know it's kinda obvious but unfortunately I
> > have no better answer to that question.
>
> This is clear but it doesn't really tell whether the existing tooling is
> unusable for _your_ or any specific scenarios. Because when we are
> talking about adding quite a lot of code and make our allocators APIs
> more complicated to track the state then we should carefully weigh the
> benefit and the cost. As replied to other email I am really skeptical
> this patchset is at the final stage and the more allocators get covered
> the more code we have to maintain. So there must be a very strong reason
> to add it.

The patchset is quite complete at this point. Instrumenting new
allocators takes 3 lines of code, see how kmalloc_hooks macro is used
in https://lore.kernel.org/all/20220830214919.53220-17-surenb@google.com/

>
> > For the memory overhead, in my early internal proposal with assumption
> > of 10000 instrumented allocation call sites, I've made some
> > calculations for an 8GB 8-core system (quite typical for Android) and
> > ended up with the following:
> >
> >                                     per-cpu counters      atomic counters
> > page_ext references     16MB                      16MB
> > slab object references   10.5MB                   10.5MB
> > alloc_tags                      900KB                    312KB
> > Total memory overhead 27.4MB                  26.8MB
>
> I do not really think this is all that interesting because the major
> memory overhead contributors (page_ext and objcg are going to be there
> with other approaches that want to match alloc and free as that clearly
> requires to store the allocator objects somewhere).

You mentioned that memory consumption in the page_owner approach was
more important overhead, so I provided the numbers for that part of
the discussion.

>
> > so, about 0.34% of the total memory. Our implementation has changed
> > since then and the number might not be completely correct but it
> > should be in the ballpark.
> > I just checked the number of instrumented calls that we currently have
> > in the 6.0-rc3 built with defconfig and it's 165 page allocation and
> > 2684 slab allocation sites. I readily accept that we are probably
> > missing some allocations and additional modules can also contribute to
> > these numbers but my guess it's still less than 10000 that I used in
> > my calculations.
>
> yes, in the current implementation you are missing most indirect users
> of the page allocator as stated elsewhere so the usefulness can be
> really limited. A better coverege will not increase the memory
> consumption much but it will add an additional maintenance burden that
> will scale with different usecases.

Your comments in the last two letters about needing the stack tracing
and covering indirect users of the allocators makes me think that you
missed my reply here:
https://lore.kernel.org/all/CAJuCfpGZ==v0HGWBzZzHTgbo4B_ZBe6V6U4T_788LVWj8HhCRQ@mail.gmail.com/.
I messed up with formatting but hopefully it's still readable. The
idea of having two stage tracking - first one very cheap and the
second one more in-depth I think should address your concerns about
indirect users.
Thanks,
Suren.

> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGeEc9_fTCCRj9DtwQEu3u0fecc4DJuOjZzrTPfnNbOKw%40mail.gmail.com.
