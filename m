Return-Path: <kasan-dev+bncBC7OD3FKWUERB24UYSMAMGQEXINMWPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A05E95AA035
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 21:39:24 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id be26-20020a056602379a00b0068b50a068basf9475500iob.11
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 12:39:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662061163; cv=pass;
        d=google.com; s=arc-20160816;
        b=bdKRpbloBkMhJ2rld37wrqktvxLOcjOgozE6RBwRACrnWsnnvT2ytnAmL+sjsTAF/i
         XGe+Zyiaa5+V1cEpus/eN7o9YLTUA+L9OQiBUtVQbPKskXF4GMolT2tQgm1SiCgNbvTM
         KYNZ5l9Ah6874954zDyrZ0+fFAx4TNTqqSEdjAvbOwiZyU9mSv2qcdFGRoo7neB8i9hA
         dexN36cLau6cE0l/dhv1wUxoVzD0co8Kd6QHF/3EUolgbmQy4SY2lZ3J0HLmh5CPtltf
         lSECXV0XkfbPOvADs87J39jrYcbvTvLFY4P+pOIfNH2s8CkXgUMihTK7gc0ci+N0kPAu
         fzhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Dqou5hE8TKuznfZCkQ2l2gOhE66BsckwaN4QP/6lG5I=;
        b=kxu3rdjl1NawyycaZINrlRkbYjEPJLqczsr4Vn38xQ90xMe8wpiyKOxX0aRlH91HQn
         oviU2LB9Ab5EP9KgCXkHx5TB+FVPQU8CNijWdDznBRXaENkCazeIzkJDu7v2DvufTiKw
         0LtjL4LW3LjkGL766UNh52Gax7SdmudCXdvCrR4R4zZrM9wKgZ+Nf7lm2SwjIlME06UR
         HCG5+NPOpTf+0emAy81HabjpFaLdu9RlmtHpPtWHpbTYCCuCSShECWosuT1lgoTnnL3R
         eO2TcSPIeV0D/KErpQvVlus8T8rIeafcvv8THvG7c9hfEPC/18aJgxXYB/JdePikySF9
         otug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lG3CtwEr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=Dqou5hE8TKuznfZCkQ2l2gOhE66BsckwaN4QP/6lG5I=;
        b=M6xL7Vp3Lnvy0R9P/0vMPHjTTZ6BCmXBdXVsFqDr1/VyNbZsn/i9tqnOO5lKuBKGuF
         lygaIdN6El8CZISCEQoUtTVwk6qljKGRUeTRyNdzRIE7hJJNc5ejeRkG6Z5zma9XNndO
         6VxLl8/F1qQ2cZJuTgH53fDlcog4fgBtnpihMWUBt8c/qDLONid7hYZ+KFu9q+z2RWbb
         n/lN2pI60yKZw5gsCp7w0lAR4kdlvMgqNT+L8kmyq18EK9g7Qgf1X2qqxXn11pLp3Bqp
         pkVQ0AO4KtIw30eUWfmzowXKy/0sB2PfcIJ6xB76ZTGuWjelKNF0QTXhCN/fYek7Akj4
         pdWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Dqou5hE8TKuznfZCkQ2l2gOhE66BsckwaN4QP/6lG5I=;
        b=Mq9WS7qj9GaNxKJfNkM7Q7QhGuNu8Z/GHTSKigKSHcGy4LoNsK2NJqsvtKDTjtuJRI
         FjMZGorVx6znkWr1UuE9qOCkSUZCsLdccDmog3rifLjaQc6i/hyPZYR5JIVIAbR0FAY+
         Lq5YRgZPAOx3ldITm4U/WlCPK56TXSpcxvBXk4u3SvFRXhiGNebTo8KMmyDMqWBbxAdc
         LwoJ3YZdzVJRV6IxwTDkGpRLxosegQz9YIs4pDFguF2YHenwg5o7p2H7VtL3Kq494GFu
         aF+PLilKHocQcOg8S4ggx2CqjvoGX/FPNncFEbknGGSxoF2Zn2Lt2VBfE69SDyhOXWIv
         gjjw==
X-Gm-Message-State: ACgBeo0tmQCF0XT81l/6G/976zNFlNm5ahVJknpGpxdS6mBOopOsQQxA
	UqitElyeupObjDIceln+iIE=
X-Google-Smtp-Source: AA6agR50qEAEkNT89Hw4FTvxXcAWYcVllUaZOVsCrgQPE8J6BoUAvST4V/98lcJG0H2iebnDL0n6oA==
X-Received: by 2002:a92:7006:0:b0:2ea:14e7:e51a with SMTP id l6-20020a927006000000b002ea14e7e51amr18005837ilc.270.1662061163533;
        Thu, 01 Sep 2022 12:39:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d0c:b0:2ea:a98a:7748 with SMTP id
 g12-20020a056e020d0c00b002eaa98a7748ls716585ilj.3.-pod-prod-gmail; Thu, 01
 Sep 2022 12:39:23 -0700 (PDT)
X-Received: by 2002:a05:6e02:19ca:b0:2df:68c:4a6d with SMTP id r10-20020a056e0219ca00b002df068c4a6dmr17606970ill.32.1662061163098;
        Thu, 01 Sep 2022 12:39:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662061163; cv=none;
        d=google.com; s=arc-20160816;
        b=BDH+6cexw5SlQs8t/hCMv6pYvQB5/njaJdtoGcEsCE2xQIhadDdIKMhRsC+SzZ0grv
         jc0n93wLQd4pJks4RtMvBwucukkNvRs+CQx+IjSquTw4atylg+4Ti5NNSyi1Gl/luowk
         M27Gqu+DaTh2ZJGvO/Z+fZPJ3NzHYnOhq13rPsyMmv2st7B6jh0fWKKT1IxZljj//xIX
         rhkLV+crVPBCIlH08e3OY6Qabuh1m/mHJ8AKG4HHw+UTHcKqHjKJ+TbYIVZ2A/nEEZVm
         xW3A/4HdGH7ST/ruVcoxdvwy4iHvixMIiZr5plN4QwFawxi7YyOqLZK1ulyABvoDdp8H
         TGZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rw5PRlxl7tO0yi2f42RcudRuneYpC4HLzAgnvXZWG5E=;
        b=DP3QxqYmANxc/9FX/ByeI0oYG839UE4cUVPNQvU5F7d0zS2GDw7CVpUuL2pnB7yEjE
         XD12GLoKqki+/IfrthG98L7c00Xc7e7ooEPOuHwP0Zk5jksLBbA9OFUSUciqxyGG/GNK
         AxS34YLV8kbuF3paJwZP5mdlHJ9dPTBRDtg4Pwgv7Bxswnn+1egO/656AzFce5VSFcWY
         vgsswSWIdEVyVNQbUTwiixGfEBwtajXuqG6YMgSvIEGt6BrtozZ3YF5wqYzoA44EuJb8
         7aWtro0cvqdkdHgWnKESHfvx1N/TbGHw318FYy9INdZWiCMMd1GBsQk/LbbyX93NNwYm
         hrYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lG3CtwEr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id b13-20020a056e02184d00b002e8ece90ea6si8104ilv.1.2022.09.01.12.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 12:39:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-3321c2a8d4cso347344187b3.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 12:39:23 -0700 (PDT)
X-Received: by 2002:a0d:d850:0:b0:340:d2c0:b022 with SMTP id
 a77-20020a0dd850000000b00340d2c0b022mr21758237ywe.469.1662061162404; Thu, 01
 Sep 2022 12:39:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz> <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
In-Reply-To: <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 12:39:11 -0700
Message-ID: <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=lG3CtwEr;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Sep 1, 2022 at 12:15 PM Michal Hocko <mhocko@suse.com> wrote:
>
> On Thu 01-09-22 08:33:19, Suren Baghdasaryan wrote:
> > On Thu, Sep 1, 2022 at 12:18 AM Michal Hocko <mhocko@suse.com> wrote:
> [...]
> > > So I find Peter's question completely appropriate while your response to
> > > that not so much! Maybe ftrace is not the right tool for the intented
> > > job. Maybe there are other ways and it would be really great to show
> > > that those have been evaluated and they are not suitable for a), b) and
> > > c) reasons.
> >
> > That's fair.
> > For memory tracking I looked into using kmemleak and page_owner which
> > can't match the required functionality at an overhead acceptable for
> > production and pre-production testing environments.
>
> Being more specific would be really helpful. Especially when your cover
> letter suggests that you rely on page_owner/memcg metadata as well to
> match allocation and their freeing parts.

kmemleak is known to be slow and it's even documented [1], so I hope I
can skip that part. For page_owner to provide the comparable
information we would have to capture the call stacks for all page
allocations unlike our proposal which allows to do that selectively
for specific call sites. I'll post the overhead numbers of call stack
capturing once I'm finished with profiling the latest code, hopefully
sometime tomorrow, in the worst case after the long weekend.

>
> > traces + BPF I
> > haven't evaluated myself but heard from other members of my team who
> > tried using that in production environment with poor results. I'll try
> > to get more specific information on that.
>
> That would be helpful as well.

Ack.

>
> > > E.g. Oscar has been working on extending page_ext to track number of
> > > allocations for specific calltrace[1]. Is this 1:1 replacement? No! But
> > > it can help in environments where page_ext can be enabled and it is
> > > completely non-intrusive to the MM code.
> >
> > Thanks for pointing out this work. I'll need to review and maybe
> > profile it before making any claims.
> >
> > >
> > > If the page_ext overhead is not desirable/acceptable then I am sure
> > > there are other options. E.g. kprobes/LivePatching framework can hook
> > > into functions and alter their behavior. So why not use that for data
> > > collection? Has this been evaluated at all?
> >
> > I'm not sure how I can hook into say alloc_pages() to find out where
> > it was called from without capturing the call stack (which would
> > introduce an overhead at every allocation). Would love to discuss this
> > or other alternatives if they can be done with low enough overhead.
>
> Yes, tracking back the call trace would be really needed. The question
> is whether this is really prohibitively expensive. How much overhead are
> we talking about? There is no free lunch here, really.  You either have
> the overhead during runtime when the feature is used or on the source
> code level for all the future development (with a maze of macros and
> wrappers).

Will post the overhead numbers soon.
What I hear loud and clear is that we need a kernel command-line kill
switch that mitigates the overhead for having this feature. That seems
to be the main concern.
Thanks,
Suren.

[1] https://docs.kernel.org/dev-tools/kmemleak.html#limitations-and-drawbacks

>
> Thanks!
> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw%40mail.gmail.com.
