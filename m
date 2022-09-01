Return-Path: <kasan-dev+bncBC7OD3FKWUERBA4EYWMAMGQEDQ5DK7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EE4D5AA3C9
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:36:37 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id z6-20020ac875c6000000b0034454b14c91sf331903qtq.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:36:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662075396; cv=pass;
        d=google.com; s=arc-20160816;
        b=zA4K9hA3MN4YCCvpaLAVMTjEZGFvkGRGhOpPEkAjPxuV56HiLdnifj5vdTj5gDTTwE
         m2d7rweVIWDkNUTPvDCj8bRoD0d8/XhRv5xBpXuni4jvz7tvPNSbivhmvxgdeHWHPXN7
         GSe8p+BCJriVnAMbzLabp6pBDiLyLcmWqYuL5Fx3I7hIZJA7H/zCqt84rW1MQrX9ihsn
         RftvVHv9Pc28BcLYfhyiobQg0h4zVRISSbbQvwyynay1TY9ft6n5k3NRQ5D2vrJ2rkuI
         3uBYPUi2wScUc/etsEvHSapZiHRAzfMuCi0VOaklt7Wru6C1NiCiO7gUIjTK7Y3C7+s3
         RL5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IgtZMMDciMz2g/YVlKyYl3WsQi5WjUArq9JYRUo8Awk=;
        b=brX0kMtDLONz0nziFLp8L34dcxlfhCakEnuFJBVrC7w8JVPBn0iqWukz/V4k4R6GnW
         Yh3FBOxejfzBtXw0e9GeM5ae+flZbCCj3bmfh9MN2xc7axIR7GVGxGF6LvXDWVLB0VJK
         X5EFOl/dbFVya0wdXiKBrJSutt+n2FSSCQhsg7r9u9ya+NmjTuydHy8bWBwIOfXpzXum
         V29Hlz44I5kRzfH3V8kDpIn0+CH87dDlNXAZzlpBmORJPeuviEr/samsORDUSbFS8Bjz
         2Nfo+bO1x2L4FfKnudvaB5SPem3KrfEU4LMlJsaFhebMGxnpbPN1p6nqR3njZu6XBoRp
         sB5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QPtBN+jZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=IgtZMMDciMz2g/YVlKyYl3WsQi5WjUArq9JYRUo8Awk=;
        b=EEAXtrramM97avHhFz4mY0huezDY79EQgh4xY3gj/WcsKbIejQs5JCntjXdDUw5l7Z
         l+fHHfC19iQUeWRQgkalcMwh1vZXFTNkfIU83/KCm513zxFVq5jLroK9oA7ha1uJk8nw
         tcan5hC7V9IZKuPVyQp3J6Gd1WEDDQcYBheCa7sAHidtg4yfpLvjeZzdNqnI4EnGkOZh
         wl1hMHCqNo1T7yq5Wj0aEmNgn5lJ0IS+FrEgN8EzFu6oznhjP9LTlXBfM5fYoSZZ+k0p
         jBYTXAdUtltxrGEjL6GFjViA3PP6Wr3c8nzBxIUc83GXIG+/6vRko5vUE7skdN2gEIUM
         cOBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=IgtZMMDciMz2g/YVlKyYl3WsQi5WjUArq9JYRUo8Awk=;
        b=n1p+dGbluOxdc2DImZU0m/Dzo85M9dI49bmM0ZMUDyi4AlUU7wovVuhKokiJHM/W4L
         DjF67Vzzmf+3aOrPOm81Kw01+TpwVP1YmSag6GxCzbN0rpv4buwuUOT4lpNEokCh3oaY
         u9SHdGT/xMJAFmLXYirE9J+8z1dxdmbCaPvD8VkoamRGzJtp/Ni2K5Tgt6xLBQ3bx9gb
         IMX8Tn4hr/V0aS4BZgyHAweVWlG2zAHqi2CUFtLXy65IDPkaJEf0K51wDGFCPqM4WEKy
         UJG3zyLsffu1rKo6Mv5U+xotFGNNRXSpBNoaJDnml5Hwmj1+d3EwHh55FquQWALnDo3a
         Xe4Q==
X-Gm-Message-State: ACgBeo2coMCJK2e/g1vTHDbUMg2eNwR/kYdsToU5BKVAiDZl02IHYuV5
	q9LD/74TyoQ7Ojc+3HPi+5I=
X-Google-Smtp-Source: AA6agR4YIiwDfhe79QHjmtfeqopjqBH1o13mrsX8rRQHWcLM6AIoxgWhgCjcfzbpj4Um41UAFGeZvA==
X-Received: by 2002:a05:620a:ecf:b0:6bb:a38:43cb with SMTP id x15-20020a05620a0ecf00b006bb0a3843cbmr21446016qkm.742.1662075396052;
        Thu, 01 Sep 2022 16:36:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:158d:b0:6bb:2e5:9ab3 with SMTP id
 d13-20020a05620a158d00b006bb02e59ab3ls2525024qkk.3.-pod-prod-gmail; Thu, 01
 Sep 2022 16:36:35 -0700 (PDT)
X-Received: by 2002:a05:620a:24d5:b0:6bb:bed6:18d3 with SMTP id m21-20020a05620a24d500b006bbbed618d3mr21664305qkn.271.1662075395542;
        Thu, 01 Sep 2022 16:36:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662075395; cv=none;
        d=google.com; s=arc-20160816;
        b=bVwcQyD0gZSBoq+eFE/+2O4a0WNRBy1sWTEzzAy3KscHev3dKdWjkj75TCR1h+P1/X
         HVt6ZAKz6nSiQD7d51mRubYwN9Q/evYWNgEPlTKlCD8wCynHPD6toPQExybZLGfpZvi3
         SVam2r0yL6sXc0fIoSsNw6fB3HHM/uG4uoe5sdDxtJliVcEU3GozCBewxUaVy94WT/iR
         sHGrdBxgZF3jty4yUvnyTc2mrKVImTND9AdE1/oCgR3UF6AtczQZ9ERRRot7pM5rVCr7
         zQhsfPqNhfH0EWK/zf65jkX74hhIs6YknYNlsUZvEMMEeO190RPc8vloHyxd5ly5mljg
         BIKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5pc1SgOf8Owl6sShRuirH1QWrWtPdJIgt3qepozMpkE=;
        b=tgwooT3dqzdLf1Ibn6PTm6sf4T9funYuZhJlbsi9ING6M0seEbxAODPgQ9oyH5fOp0
         GoIV5yFpLAcWfmeHTZdK7eyU6T4ZSt2NoQDnc3Vd5IGk+l2OK+6fBEtGEvXAroXVjQSv
         Qyz6K1ERHdbWFW/tQKEMlXzoU0LHXt1LNrpd8wGU6SQYebeeoIyuF92TYmSJd76FYOK3
         TyM0+2o/nQu3IcgGhlTmSXS2FDhiMxFNhzjcyb4qi8uSPF/r51Ql8KI/7E2WUYk67+Fd
         NonXkr3xC4J0HMiu6Bmxo2G/QDNPUZwfzaMTX2H+pTAYr+7Jb53tI6r+T6tMHO3bWlG1
         4awA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QPtBN+jZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id ci8-20020a05622a260800b0031ecf06e367si7252qtb.1.2022.09.01.16.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 16:36:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-340f82c77baso2442577b3.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 16:36:35 -0700 (PDT)
X-Received: by 2002:a0d:c981:0:b0:330:dc03:7387 with SMTP id
 l123-20020a0dc981000000b00330dc037387mr25216063ywd.380.1662075395130; Thu, 01
 Sep 2022 16:36:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car> <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
In-Reply-To: <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 16:36:23 -0700
Message-ID: <CAJuCfpF=67THWzoE+TGW_VbBHMRvuC5BVVGnkLPmKtG3ZuS2Jw@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Yosry Ahmed <yosryahmed@google.com>, 
	Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Johannes Weiner <hannes@cmpxchg.org>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QPtBN+jZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c
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

On Thu, Sep 1, 2022 at 3:54 PM Roman Gushchin <roman.gushchin@linux.dev> wrote:
>
> On Thu, Sep 01, 2022 at 06:37:20PM -0400, Kent Overstreet wrote:
> > On Thu, Sep 01, 2022 at 03:27:27PM -0700, Roman Gushchin wrote:
> > > On Wed, Aug 31, 2022 at 01:56:08PM -0700, Yosry Ahmed wrote:
> > > > This is very interesting work! Do you have any data about the overhead
> > > > this introduces, especially in a production environment? I am
> > > > especially interested in memory allocations tracking and detecting
> > > > leaks.
> > >
> > > +1
> > >
> > > I think the question whether it indeed can be always turned on in the production
> > > or not is the main one. If not, the advantage over ftrace/bpf/... is not that
> > > obvious. Otherwise it will be indeed a VERY useful thing.
> >
> > Low enough overhead to run in production was my primary design goal.
> >
> > Stats are kept in a struct that's defined at the callsite. So this adds _no_
> > pointer chasing to the allocation path, unless we've switch to percpu counters
> > at that callsite (see the lazy percpu counters patch), where we need to deref
> > one percpu pointer to save an atomic.
> >
> > Then we need to stash a pointer to the alloc_tag, so that kfree() can find it.
> > For slab allocations this uses the same storage area as memcg, so for
> > allocations that are using that we won't be touching any additional cachelines.
> > (I wanted the pointer to the alloc_tag to be stored inline with the allocation,
> > but that would've caused alignment difficulties).
> >
> > Then there's a pointer deref introduced to the kfree() path, to get back to the
> > original alloc_tag and subtract the allocation from that callsite. That one
> > won't be free, and with percpu counters we've got another dependent load too -
> > hmm, it might be worth benchmarking with just atomics, skipping the percpu
> > counters.
> >
> > So the overhead won't be zero, I expect it'll show up in some synthetic
> > benchmarks, but yes I do definitely expect this to be worth enabling in
> > production in many scenarios.
>
> I'm somewhat sceptical, but I usually am. And in this case I'll be really happy
> to be wrong.
>
> On a bright side, maybe most of the overhead will come from few allocations,
> so an option to explicitly exclude them will do the trick.
>
> I'd suggest to run something like iperf on a fast hardware. And maybe some
> io_uring stuff too. These are two places which were historically most sensitive
> to the (kernel) memory accounting speed.

Thanks for the suggestions, Roman. I'll see how I can get this done.
I'll have to find someone with access to fast hardware (Android is not
great for that) and backporting the patchset to the supported kernel
version. Will do my best.
Thanks,
Suren.

>
> Thanks!
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an email to kernel-team+unsubscribe@android.com.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpF%3D67THWzoE%2BTGW_VbBHMRvuC5BVVGnkLPmKtG3ZuS2Jw%40mail.gmail.com.
