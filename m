Return-Path: <kasan-dev+bncBC7OD3FKWUERBJH3YCMAMGQEDADNFAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86DD75A8D09
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 07:05:42 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id m11-20020a17090a3f8b00b001fabfce6a26sf722215pjc.4
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 22:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662008741; cv=pass;
        d=google.com; s=arc-20160816;
        b=bwJtZlvw7heekOLSsayDKvXkW8p5sFPyuJ1NSoDbetry4/b3znpn3wtWVb/apDRntN
         yof7pnaF8Y5JualwRIf0zZLrJaO2y1Co1WOht7Y/uGWlxqcdxJ2cKahMjCZ8Br5a3Gjg
         MN2MjQnzM8skG0cqgvpUKGZP80wX90N3YpNgCJ9+WX8YRQ741rS6sxOOCgxKQfbZUFJz
         LdoSJcOPlFJrIWwCn1tXQ7RXMV4zn1i4r4v4zCzdSJhRV07aciiLPCfxzqyCj+ROXnzl
         f8X+0kI2okapND6KYDmqpToRMbD8mrjjDfAtBK/qAL4+kkI7Zd5bi3pFdhM4gpnQB0QQ
         /TAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fhq6pRKNts7dU49FuN7aEysaE2j+uk5XMQqgBrYoE90=;
        b=mqLYlSwDpD/nUOWkKk82K8YDBIomA7V5/6BkQY23895RDNcVgqMMLZkXtlLM9Nz6YG
         gQbITNiJfr/4is9BVbh09uqZ/WPShnXc/Qa49NNNCJbDclvJLu2TLASovJ1om6GSXn8K
         Pdd+Yd4IWQy2q0iyIlljNZmdXodCXMLcyL9s9k7h2g9iScXzE2cZaKnM5TEoI+4f7PXH
         7qv7SatSFkOUO8kAUBPUyZ9bIewrlhYyt4aJVKAOUFjmgVLPalhl73OY3NKYHpoRejh5
         xPUitQd1XW26ATnBfgVEMMn5rDu+xcm5g4ruMCi954rw569ykT6OMKIEQFdlWNg37Zvl
         Ppaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UnvyXVMI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=Fhq6pRKNts7dU49FuN7aEysaE2j+uk5XMQqgBrYoE90=;
        b=rjY35UQi5xq3VkP2LYdqn7Ls9u9d35rwNlRUnErmPVTvJX6LMGMzsqMo7ZOdYYYe+/
         vHk9/tLKKDHC5lXnC0SUvaRONbuZ0rQjj/C8mq7Z1QPJElGAOT/aDfC2zxPT3fdU6pFQ
         rqsumW+JN2D8SWfo0TzZQ4BC54u4oFU8FE9OMqQdVMX0VuNLW4zLgJdseWe39kmJus9a
         i8sfwrSC53c3Mp0sRLhbJOI8b4Qzni0o3e4H6RrXerN6gL0HIVTgfp3I74TDBGm35bs4
         JTAwz42mt4RViUnTo3M7JN7jvwcnwpTOBHHzroAdDLwQlmEmGFQrYmqJG8K/JLQflCmw
         SOaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=Fhq6pRKNts7dU49FuN7aEysaE2j+uk5XMQqgBrYoE90=;
        b=QftW0JyDYj15I1t9usE6GcmVqjvrh2+TXdk5bWVMhXMjgrgF4/S3UCzP1DXqkKqbbB
         F4JdJRcusybkaYSaB52i0LB2cg9eT9/vLRakV+fffFOPRctD2OO3NpGfn0C+tPVasx+f
         LrB8FCWgyEnFz9+Y1Cy64XFq+f/ajmNoNC0M5RmGxtnwTcSt+gdPqnTYg7/hDcJ8pRdI
         DinYhZgoYwOJ27htdcsYP42WOqIzqQRMfRekQP8MjKskcD4vFp7mO4h4koUY2Wg/9E7A
         483WCs2J+yEEDc7fyDltXFpfd0Oc0lTgDlkOHblHzGcjWOk1Irm4l+PJi8BiQ/cGFiiI
         R26w==
X-Gm-Message-State: ACgBeo0Ou/2sHjNdra3zMCHfCR6HIHxpMuWNN4Ao+hUsxktFL75O5KK6
	eOYNjYiikEtuLkOF1hIRhoE=
X-Google-Smtp-Source: AA6agR7jL7Mx6gE4khKTjzWA6Qsj5ZurH/HlWFaJWMTtRdYGFWdWWer3nFUNOV3dOiC1j7HOK2q7Tw==
X-Received: by 2002:a17:903:11d0:b0:171:2cbc:3d06 with SMTP id q16-20020a17090311d000b001712cbc3d06mr28016270plh.142.1662008741014;
        Wed, 31 Aug 2022 22:05:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8d:b0:1fd:c959:dbcc with SMTP id
 z13-20020a17090abd8d00b001fdc959dbccls835365pjr.1.-pod-control-gmail; Wed, 31
 Aug 2022 22:05:40 -0700 (PDT)
X-Received: by 2002:a17:902:a705:b0:172:ecca:8d2d with SMTP id w5-20020a170902a70500b00172ecca8d2dmr29230110plq.27.1662008740282;
        Wed, 31 Aug 2022 22:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662008740; cv=none;
        d=google.com; s=arc-20160816;
        b=TWG2aV6SEm1Jft867ZS6cZAwj1lnI/6JwR0WOq7QsLVqkI8dgqG/fe3QzCOoYKXm69
         HlsqUb0ECPPisaNPj18oz2e+saSUISsm/Zabp+IXIU5jwr6Nev0gft5iIlEAmUMwLOR1
         3GX0kSQWKUosMHuncNlfl4z3ZhydjGmEY06wx3X7/mH//jTBZRgka9vrgX2VxfVX2MHA
         sun/1Oa/tpz4ThI1jkbG51wzpojRKALdTaiNnVIwC/Jy70Wg1FYUpMpRAXzt5GZ6sXDO
         Bwz+NoyqWUx51UTpGFU+yckGjFErClGdBh5oEqjbjkEQncxYwglUt4XEVBw3bDOsJ/DE
         1fog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ktZOhU9M+eiBxoPfSKrBwsk5VZxY64ML34Vei/rqz2s=;
        b=z+KU+NJYT+o6ZLc2Nvf/4mIbiUOXvVEyIWcF+DCE8VY48f1IDUoR3jxTPKu0X8uMDA
         ENfNtFyR7BrdAAZb/gqOid1zUE5OfC5WNE195FywvpO90uDT/TFWkzqAsgNSLsrdReAC
         I/bxOHUvwrer1iLn9jBtdezn0ufmGMMEN1S+THnasVJsBjedNYzFyVSb4Qy8Mtkrpj1+
         3b2y2FzRRxGnfSbuX/SceWzDXeH92JazWX9yjYfaoQB3oDwlU1Fcoke6w1BCU3bAsTp4
         /mnloquljAyNNjoiYS1YOm3Isq1e1B9xUygGX5EyBdK4sJs5JIWMZmIVUiWxi9/mezJ2
         Xc9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UnvyXVMI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id n19-20020a056a0007d300b0052d5f21fa66si765599pfu.1.2022.08.31.22.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 22:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-3376851fe13so326210867b3.6
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 22:05:40 -0700 (PDT)
X-Received: by 2002:a81:a04c:0:b0:340:4c27:dfc6 with SMTP id
 x73-20020a81a04c000000b003404c27dfc6mr20996289ywg.507.1662008739346; Wed, 31
 Aug 2022 22:05:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <YxA6pCu0YNIiXkHf@localhost.localdomain>
In-Reply-To: <YxA6pCu0YNIiXkHf@localhost.localdomain>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 22:05:28 -0700
Message-ID: <CAJuCfpGxB0z1V1Vau3bXF9eHZVHnANdA7keMzCLUK+_gN6+HeA@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Oscar Salvador <osalvador@suse.de>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, ytcoode@gmail.com, 
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
 header.i=@google.com header.s=20210112 header.b=UnvyXVMI;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132
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

On Wed, Aug 31, 2022 at 9:52 PM Oscar Salvador <osalvador@suse.de> wrote:
>
> On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > ===========================
> > Code tagging framework
> > ===========================
> > Code tag is a structure identifying a specific location in the source code
> > which is generated at compile time and can be embedded in an application-
> > specific structure. Several applications of code tagging are included in
> > this RFC, such as memory allocation tracking, dynamic fault injection,
> > latency tracking and improved error code reporting.
> > Basically, it takes the old trick of "define a special elf section for
> > objects of a given type so that we can iterate over them at runtime" and
> > creates a proper library for it.
> >
> > ===========================
> > Memory allocation tracking
> > ===========================
> > The goal for using codetags for memory allocation tracking is to minimize
> > performance and memory overhead. By recording only the call count and
> > allocation size, the required operations are kept at the minimum while
> > collecting statistics for every allocation in the codebase. With that
> > information, if users are interested in mode detailed context for a
> > specific allocation, they can enable more in-depth context tracking,
> > which includes capturing the pid, tgid, task name, allocation size,
> > timestamp and call stack for every allocation at the specified code
> > location.
> > Memory allocation tracking is implemented in two parts:
> >
> > part1: instruments page and slab allocators to record call count and total
> > memory allocated at every allocation in the source code. Every time an
> > allocation is performed by an instrumented allocator, the codetag at that
> > location increments its call and size counters. Every time the memory is
> > freed these counters are decremented. To decrement the counters upon free,
> > allocated object needs a reference to its codetag. Page allocators use
> > page_ext to record this reference while slab allocators use memcg_data of
> > the slab page.
> > The data is exposed to the user space via a read-only debugfs file called
> > alloc_tags.
>
> Hi Suren,
>
> I just posted a patch [1] and reading through your changelog and seeing your PoC,
> I think we have some kind of overlap.
> My patchset aims to give you the stacktrace <-> relationship information and it is
> achieved by a little amount of extra code mostly in page_owner.c/ and lib/stackdepot.
>
> Of course, your works seems to be more complete wrt. the information you get.
>
> I CCed you in case you want to have a look
>
> [1] https://lkml.org/lkml/2022/9/1/36

Hi Oscar,
Thanks for the note. I'll take a look most likely on Friday and will
follow up with you.
Thanks,
Suren.

>
> Thanks
>
>
> --
> Oscar Salvador
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGxB0z1V1Vau3bXF9eHZVHnANdA7keMzCLUK%2B_gN6%2BHeA%40mail.gmail.com.
