Return-Path: <kasan-dev+bncBC7OD3FKWUERB2PV3CMAMGQERVYZSOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 689C85AD8CA
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 20:07:39 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id bq19-20020a05620a469300b006c097741d3dsf7290147qkb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 11:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662401257; cv=pass;
        d=google.com; s=arc-20160816;
        b=a88qEDjWX0QqpFzfA/+hRTrNQKla6N0qppex2j//vEm7b1cbdQbfnQX6tF9oeAXiXQ
         Yn2C0NU+2Mr7NGCzGVgu4vkiV9tY0IDz0HCWvVRWOznQ/gpIx0YvQ8RbtfGI2vcuCJK9
         RWS33inxlnS9IVGN29T5+qr++0rI8hnYiP/1EyWlVPHVvol1CBTu5PPRqo6Ex5fur9ua
         CJxwUSlhDywcb5cSWLOpc2RRjDwlQ98MCp+JLezArFJhV6UIzyD4w/UMDV6YDKkiRKxT
         091lg+YPQQad62zyc3w7DLvEm5/lDc1dHOADyZ7tRpCDiqwZAW3ZDq+MXy9TXgKL0Kh/
         S23g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TuQ2bxXeAPy8wVugWmnVllvb8O/H3rAdEa8k8rd2Nxo=;
        b=KKSvgNvs3RazbISrysXKRO1+NM2RU21qOZ9ZKGwuTFZIdoHfdLUyhn80i2f5OCV7tL
         aMaLfVwXC5bIvBi8A5pSmJ2loyKvLppiGY08xWFREXyzfoMgiuDw9Z+O4/Km9fCLlIwM
         rW4OOuovY7S5P6a0Nx9VgoXu9qxU4cfkvf2Dfu4Fetozq+Xv6D/TddpbUjG969gXRCHE
         HN6/gUf0AWQk9OaX5MAJdP3M3FY2VMGurzQTSBeYTiJpVf98BPCECmsvsTy0FaVMRE/O
         TYyfUAbnTc5w5EHxau0NsTyr62gqAHOnQwgpvppTF6gs8qjT0S/sWKK4JLPlOQryevyu
         tarA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P1Rb3fVw;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=TuQ2bxXeAPy8wVugWmnVllvb8O/H3rAdEa8k8rd2Nxo=;
        b=ZG23uUxK/9MFNP+8arMuXP/SjlGNuLHLBdED8qQwyg6Kr1G9UVPEze3hfUkZGOcpMr
         ug7kDsLkEM1sHaJMmUjjlJDv9MehC5nWYMlEWJJZZbnmpY3vTTTjde/ItVV89dzbXNpw
         pFkvphufh0mG99N8xrztg86kj57hRC9ldt0BfKxhV5+yBsUlqSHEWRLzht92STc/8smz
         ICPypYIdd/rhcNYiCtfrCVYDqdxJZfDNn0p33vAflHcvDGx7EnsNQ9LP2U4P/zlMALxd
         2bN33xLM/hgMOAoYvEmJDRc7R1R2I6/19ojf++7oQv2fHQlDsuFFe003pG+RaO9VVJRL
         1j2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=TuQ2bxXeAPy8wVugWmnVllvb8O/H3rAdEa8k8rd2Nxo=;
        b=VllCpvvOlZMdktn6G26FZlBzhI4kVb4yOh9XnLikIiRMzTZq6DTIHp13UkaV7AFbzn
         0jXoufn7cUwcV6TUoaKjZ1dlqqfdJCg0HaRgX5U5XpHvAi4pXgIR9NzkCn93+/AvlH9T
         iDXWtUMT/wbL4VVJ7myQAewR66T1fHtRmRlYazVPQmwC28P71iWHJtvHQ6xXv53e/O1U
         GKAyhnmCvy4UjGtw+0wS/peJjxTmTaMRV/s/kT+3i9QT8j0h71rPQxjQl8krEH8b1rUm
         xmUZN+NRFGSxIe4+4D9c9Hli5KYukombM1HT856hecueaED8bhSfxTgDxJSCVGP9Y24T
         rv8g==
X-Gm-Message-State: ACgBeo1beOrCmFsJlV7rW4/Qvm1WpDnG3joz92jT7re7qFvfqslai4O9
	oRKYIc5GOXJ+SjkVu0NZm3Y=
X-Google-Smtp-Source: AA6agR4N6AsA5zgMpIKHPgoNXKH6e0W3m+F0mK33bd3YY5amU8rmTpO/v4tUlY68BXAUJQFJQcp1nA==
X-Received: by 2002:a05:620a:280b:b0:6b6:5a6c:9acf with SMTP id f11-20020a05620a280b00b006b65a6c9acfmr33582761qkp.749.1662401257642;
        Mon, 05 Sep 2022 11:07:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4ac8:b0:342:fcdc:2d4d with SMTP id
 fx8-20020a05622a4ac800b00342fcdc2d4dls8545849qtb.10.-pod-prod-gmail; Mon, 05
 Sep 2022 11:07:37 -0700 (PDT)
X-Received: by 2002:a05:622a:30d:b0:343:63d1:3751 with SMTP id q13-20020a05622a030d00b0034363d13751mr40552960qtw.679.1662401257141;
        Mon, 05 Sep 2022 11:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662401257; cv=none;
        d=google.com; s=arc-20160816;
        b=UMhn8DrtNUXa4l62kICLx9Vxq8fetK/otzYvr1IB83DrlRny/6p87J4v5ni8tDgE37
         2PYLqdLpJrQFglbiH+fyInA8G2k3zAqF504wmRqj+bNnFer3dyRGbOGC2O+/oSlzMi/f
         JKx/G2Kj5IfGhbpm4sOSnVLG4g6QHZp32b7sdKkiwNKFdpWY3C8wFRvyh0+f1U/suC/p
         LY7CrhBLF4o7vH+38SIipV5PNHIMGGQIHbXPpHlx3hlB3quhV1rcYFSkG3Xycaba5mgv
         9fI7HHDbUEH3SuvkWPe3LyQQzA1EIAjOn6zKPEWkeVguXHstDZdTp7BL0Y1mGaVRdIrZ
         9LOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bum5cdqCm4gIf+I6AQy+wa1rXRQMNTd23PbVP2YAzEs=;
        b=X7a2rDdRur13G/G6T+ixSnW0AjBjB1kwXKg9gBwteIqWSeTHbPCd4NP/gYDYHRwMjc
         VbetyVw91wmZ4gSTHkzhbBJ4Fc/5gWxPqTUDy2P/zDtQRmVXHKjBLDSj6h4X6hVDjkhc
         J6Rcbj5T1yEFiAW2XnVf95Be43OS+Cvegkt6zF4l9SgqLMbRMHV9zJ1e9aO8vlOcsYUf
         XjfUrSEFU/VUjeHuQyhaFBUL0seUZnHuKmh2WvxCNPQlKsYdoNKbuG1SfDKEW/PIEQLD
         2gcE0ag4TZ/qOynVONNJ28jGzdeWKb4hofWmpyQqXWDr318aHRq0Yw73M9IVWHRzFydp
         /kiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P1Rb3fVw;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id 10-20020a05620a070a00b006bbaf443db8si479735qkc.1.2022.09.05.11.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 11:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id 62so7291888iov.5
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 11:07:37 -0700 (PDT)
X-Received: by 2002:a05:6638:1492:b0:34c:d42:ac2f with SMTP id
 j18-20020a056638149200b0034c0d42ac2fmr13910620jak.305.1662401256621; Mon, 05
 Sep 2022 11:07:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz> <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <YxWvbMYLkPoJrQyr@dhcp22.suse.cz> <CANpmjNOYNWSSiV+VzvzBAeDJX+c1DRP+6jedKMt3gLNg8bgWKA@mail.gmail.com>
In-Reply-To: <CANpmjNOYNWSSiV+VzvzBAeDJX+c1DRP+6jedKMt3gLNg8bgWKA@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Sep 2022 11:07:25 -0700
Message-ID: <CAJuCfpF4Meeo5b=ZTGe+YDCd9-jJ+WUazpJzaq7stOu2=1oP9Q@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
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
 header.i=@google.com header.s=20210112 header.b=P1Rb3fVw;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::d29 as
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

On Mon, Sep 5, 2022 at 1:58 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, 5 Sept 2022 at 10:12, Michal Hocko <mhocko@suse.com> wrote:
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
> >
> > Also what kind of stack unwinder is configured (I guess ORC)? This is
> > not my area but from what I remember the unwinder overhead varies
> > between ORC and FP.
> >
> > And just to make it clear. I do realize that an overhead from the stack
> > unwinding is unavoidable. And code tagging would logically have lower
> > overhead as it performs much less work. But the main point is whether
> > our existing stack unwiding approach is really prohibitively expensive
> > to be used for debugging purposes on production systems. I might
> > misremember but I recall people having bigger concerns with page_owner
> > memory footprint than the actual stack unwinder overhead.
>
> This is just to point out that we've also been looking at cheaper
> collection of the stack trace (for KASAN and other sanitizers). The
> cheapest way to unwind the stack would be a system with "shadow call
> stack" enabled. With compiler support it's available on arm64, see
> CONFIG_SHADOW_CALL_STACK. For x86 the hope is that at one point the
> kernel will support CET, which newer Intel and AMD CPUs support.
> Collecting the call stack would then be a simple memcpy.

Thanks for the note Marco! I'll check out the CONFIG_SHADOW_CALL_STACK
on Android.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpF4Meeo5b%3DZTGe%2BYDCd9-jJ%2BWUazpJzaq7stOu2%3D1oP9Q%40mail.gmail.com.
