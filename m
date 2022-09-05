Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPXU22MAMGQEJ7247DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1258C5ACE57
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 10:58:40 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id x25-20020a4a3959000000b0044896829889sf3178333oog.17
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 01:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662368319; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOkivk9/sp/5a2/sPQnWDr6Ckht102oCNZzEcxNh/GVorm8lIa6K7Q264eVdjZOPKT
         Csv4zrEjinkBBkU5hbxiLdwVFRL1cooNAJ8ffZNZFoGPrIy52ajGRBscF6M0EWlE78oj
         odKBaX/0k7cdBUCwoDx70tzxzHfJFDyzYIBgUMJx2h543z5J2QbxDGDYILFxiNFKuoRO
         GCcawCH0yp4qsqoSjBdBqDJaAS19YI5O+hiwvHGKlyupaJjLB9G3+hyY400GW9kErs8y
         bLIZ7sn97s3wfLaJxscmzwQnXWF9S6bawlNUw1T2Ba6x7xyA5VBciCiB58LPV+Vvyqyu
         FYEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2tJvSsDNomRcJmVtN7KzmOwjUzkxRu7UE6hBalsPbV8=;
        b=HRdjSycLYoZjScTsEeYezEDRfB9lhqP3o0ukGff36irmjqgCLJrini8jfAmz4iCuEe
         yAdM0NQCIaz36avbrothKgKyS8p8grz1SUHFZ7wPbvyp7df2rrQBxx+8bZg6PQWHJzLz
         4c9FPD3O236heGwSqX0e2q5ONIyJYQRcCwN9AS5rkKIu+41sjWMzM8lasQgrmreNNmIB
         40Nk73QpQVaZp67qMOYA9W6vmPfxAHRRyI6FvDONfbExvJ5k1WlsiPs4hlDprPiNk6Eu
         XJxMK/QTsMc25t7yc/+SESw+vyrYKQR12/sd13a0zRLg1tK07+heNnf0IuF6mX0Fw8iw
         y35A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z8sZwX0U;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=2tJvSsDNomRcJmVtN7KzmOwjUzkxRu7UE6hBalsPbV8=;
        b=El1ITeCSepNQ6qCoWfpMm2SXFM/LJSfR7baQjdL0yIazk16VyVZTsvFbWUg2cOxa2i
         eBIxhbJlNvXfUNiEHiNpB0okfzz+MSXX1W6IrdmdcVJIDpVceQQxcP+edglNIaakoCrH
         BpLoJ5lgiLSVrnPote4u8Z+jyeZFgkCtPhyjlbn0qL+SISYZvx8oCvG74M4zzlo9l+Zs
         SRO/LDC8113NPVVtj9vuV1u+6MTHbTzTo56oPMVKW3kMKkB9Q6fJK9vILUHaCM5Fli0s
         5bYnhP9WI/G6tPp89XxPJyXp2uy3FQTGqNwFR8YweSzSRi/TJgjCr6ATnqpzdlAfGdcf
         j7Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=2tJvSsDNomRcJmVtN7KzmOwjUzkxRu7UE6hBalsPbV8=;
        b=twY0ynxnwqZPs35X2AoB4/dAF+YYWsEJ7myYC6ouftih4MhciWjS5kQCLS5gsLBhQF
         XazKhWbB20jJgbu3ovKnXvKQxcBZagfhAhtPxpbxbLc9q+SKl02NT5Ml0OaZ+Wb7GG5Y
         97ItRhBAlpZknCULSkTccHm4OATJORAXMGTyZxI7mNjAv+Kz4znN7gere1e+OYBM0ehR
         BGshNmyfgkIyH9+9KRFAsgH+s4g12fNKHlrHVmv8I/TW39FAVAykjc859FGb5Z9BEhhZ
         kJoTGxTO3b2LIyo/mFJU1wZ6QhbOBEn+/Ur68OsvxSMAP+mccb5/cw8s2KUax6Hyz/Uw
         6UnA==
X-Gm-Message-State: ACgBeo2h03ClRSNDvQlK9dcC65DGkI8e9EnVNutoR8DCNq9vbTEvGpr3
	gE9WiIzynfBXWlQyHgQhkjI=
X-Google-Smtp-Source: AA6agR5N8BqPFQLRQOJAwE0X3LpqnzEn99rvHodcr4Mbrk+Jxnai2wm2aJXKXd5Vg192EtwLJQ+sWA==
X-Received: by 2002:a05:6870:15c9:b0:101:cdac:3887 with SMTP id k9-20020a05687015c900b00101cdac3887mr8141230oad.35.1662368318803;
        Mon, 05 Sep 2022 01:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3492:b0:11e:7a1d:b272 with SMTP id
 n18-20020a056870349200b0011e7a1db272ls4223956oah.7.-pod-prod-gmail; Mon, 05
 Sep 2022 01:58:38 -0700 (PDT)
X-Received: by 2002:a05:6870:8917:b0:127:8962:ccb6 with SMTP id i23-20020a056870891700b001278962ccb6mr651530oao.221.1662368318290;
        Mon, 05 Sep 2022 01:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662368318; cv=none;
        d=google.com; s=arc-20160816;
        b=QahD83k/13bYrZiKsFg5xmf9nsofx0FgcslUidzSPiMrk+kzFh9ZKn9nqNiemlTPKA
         UhVgTOA58B/8nvsDoh+f5XDzWalmBfGSg8aebAZrC+WiDE6QjQ2qjhqrtHhYfWYSm9D9
         THD4/ZSRuitvwL4GW2cNN+RtDmiaTxueH8RdusWkkJE2ql7j8d+Jm6XBAmAIkax6p3/V
         Ii1nu6Yf02OsdXLFVE0DzveqnV6s+QlsFcwNcf9tmxaL9zbnsdxVNJLHskSD7SW/mYTM
         gtjUGBw5RuQr9YYrdixp2W8AYbe8PNxAQhjybLr7m066r39rikiTMb+WyVRR2TQSossM
         +lZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mcscb+4yg14w1rBiRtYpdW9I8YuY8tTeWXrlK9wFWrU=;
        b=GfxHojvLwbaYHFxRoxn48ndLudfg9E9dbAyqYEOR9lTbkM/txG1mG6NDZZ1j0jyFZY
         RdpfJWC6cJzodtyVbd66xEv8jLZFdDNn0nt5vmPy3XioHZdbW+f8UHD2Gs0/dDTHvapV
         dU+kXlLFreNryIXG9no9NT3qr0cR62FrlZ4CJnGhzNuGRNLcwNvWdwnPD6QnA/9qvhgU
         NRbT9sOm2pf4CgI+ivkZgJqfv5+ErfcGAdijprKfqLzV1xIbmHBRAAlOdc4+oNINFxVW
         EAOQo7+ROu/rKAZa9yzB5iaDpIsOcYSvN6nnFBY8jRuo/V0UXew6aW91OPiWl52SYLzG
         RplQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z8sZwX0U;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id c36-20020a05687047a400b0010c5005e1c8si1544354oaq.3.2022.09.05.01.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 01:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-333a4a5d495so64173787b3.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 01:58:38 -0700 (PDT)
X-Received: by 2002:a81:bb41:0:b0:328:fd1b:5713 with SMTP id
 a1-20020a81bb41000000b00328fd1b5713mr38838381ywl.238.1662368317652; Mon, 05
 Sep 2022 01:58:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz> <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
In-Reply-To: <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Sep 2022 10:58:01 +0200
Message-ID: <CANpmjNOYNWSSiV+VzvzBAeDJX+c1DRP+6jedKMt3gLNg8bgWKA@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Kent Overstreet <kent.overstreet@linux.dev>, 
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Z8sZwX0U;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 5 Sept 2022 at 10:12, Michal Hocko <mhocko@suse.com> wrote:
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
>
> Also what kind of stack unwinder is configured (I guess ORC)? This is
> not my area but from what I remember the unwinder overhead varies
> between ORC and FP.
>
> And just to make it clear. I do realize that an overhead from the stack
> unwinding is unavoidable. And code tagging would logically have lower
> overhead as it performs much less work. But the main point is whether
> our existing stack unwiding approach is really prohibitively expensive
> to be used for debugging purposes on production systems. I might
> misremember but I recall people having bigger concerns with page_owner
> memory footprint than the actual stack unwinder overhead.

This is just to point out that we've also been looking at cheaper
collection of the stack trace (for KASAN and other sanitizers). The
cheapest way to unwind the stack would be a system with "shadow call
stack" enabled. With compiler support it's available on arm64, see
CONFIG_SHADOW_CALL_STACK. For x86 the hope is that at one point the
kernel will support CET, which newer Intel and AMD CPUs support.
Collecting the call stack would then be a simple memcpy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOYNWSSiV%2BVzvzBAeDJX%2Bc1DRP%2B6jedKMt3gLNg8bgWKA%40mail.gmail.com.
