Return-Path: <kasan-dev+bncBC7OD3FKWUERBNUAX2MAMGQEYOYX3VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CF65A815A
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:37:27 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id x64-20020a9d20c6000000b006372db8b20bsf7655044ota.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661960246; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCpu1zNmLv+p/wRDfC4aPYre9dGm9Fo61Mc3v1Qu/tfeq5DyDkbP80g2WvFb/JsG17
         rtaXHlKyPcvqx4YViAxQURwEZr/nywv/Li8BdgLNyFjl4JE20SOi8nuJI6JDDcaan6Tu
         49X8ECBN/ECHtshiHW0faTzktdnhxbl+g5XyeB3V8MNSthUrwNJ3kH8wRHQYcx9ezvVx
         YAb8Xkvc+jJ+veGDfYvnBGw2ujQO76eaOynVBWzj09BRVSFv7UbNrZ9KufaPOshQ98H1
         mqfBZBiN/Uc3cuomAdqEp05WhV9Ys1UHJfMMzUnxUnGyqeyxrmk1xkxtvaFrXq6tAYUK
         dD7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MnJQeSrrb8uWGceoutI83hoqamyIJsnLJc/QtUAa94Q=;
        b=loKGhWflWWrBlkDOr5W21gSIh6jrSU4JZU7nNGsUyk0Ok/cceT4aBaajRYlETGQ5Vs
         BqDmGLzMTimtTv5gsZbLprYsB3M8nJ/PUgbH6RrKPKWeeJgnM/j6jihaxl1H2r8ZfUit
         svUxRM/72C1XsQ1i+zKjor8QgmSHo+93c7pHcg6CeMIBiemxDHvsKL5GWYnI1xYzj1b5
         l85FWPZ+gIV5y5JxCoanWgJ6gPeoebOpzLdY3ccbcp+DSMdRFLptDom6KRTYtwHjnUN3
         JkrPhQcpwF22z4RliKTylq0gh3NizlbzcCZI+Z9GtQ7aWGYnqLVBzNGxIs4tYcew/xbU
         fsag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q4yt7LQZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=MnJQeSrrb8uWGceoutI83hoqamyIJsnLJc/QtUAa94Q=;
        b=MGhcC5E0DNgtPZtl1/NIE9ANxxX1xOVIsZBZLrBnKWyPYdWGcovpzLiae/NMxmL+fQ
         jKeEpZquNV/RUCGzRoaTmYzvERcWj/b+zAIN8LMLDvAyveU7ukqqKT8cRYTIp1z4v7DG
         0pzo7eawUzZmOxcafa4O6fDOQD7gD4xEwB0hY9O+eHcVJQarQtIYZUog/6dmedWjou+T
         r0q2hEicnowtZN43SK0W4dlTix9d98NeHxeuC5OnkZTF7uJnOJ3Mw43DTIRsV9xUXjoX
         soeLyu6qJiB+YZxMPhANHWfpydDHoK0+czph17IeNp3OMePNZ2FrcO+tFoh4i2FrgQts
         H7Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=MnJQeSrrb8uWGceoutI83hoqamyIJsnLJc/QtUAa94Q=;
        b=DMElHcBVdB0hCV533pukd3/l5RO2jDpQz6kpHUZEIq3h/uNFp6W8fWekjK/ZWzEkaZ
         ApJI2NchGS0P2fO78AgZm13e7PRXu0X2Jw3ZdGCC+7old8jrtJ70JgNN+2r3zsGXm8zi
         pVZuFLFarv9VFLrPH8QkulfkUBlzqw6yQ2+K+ELu8h8Sav5j7acQEpFPvhjgytNatUyP
         wXTNu4i/2PoCual6JQCuJEu4C+wvldwCwR8abnylE5uOi8ZoQGYtnpEVNCIHxX4SYEY+
         KccNLw1ilOB2o1U0OMIApUGFopiNmMXTxC/f9PA6o6QB3JI3sFjQW33SkD3lmKsAEoa2
         oYPQ==
X-Gm-Message-State: ACgBeo3fTQB80yfq3sK1l55fROQmfSdXH9TiH9JmcsG6k7b7sGAmNIpy
	aleLotTQzZEnhsippyvfEGQ=
X-Google-Smtp-Source: AA6agR4CpaxqHZOxkfY+IFfs6xhqDqQcc8rGCpl26jZs73801kBF/FsowluxNXk8yhx1kGCVBc59wg==
X-Received: by 2002:a05:6830:1b7c:b0:637:2583:47fe with SMTP id d28-20020a0568301b7c00b00637258347femr10655620ote.231.1661960246423;
        Wed, 31 Aug 2022 08:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e142:b0:10c:41e7:bfd9 with SMTP id
 z2-20020a056870e14200b0010c41e7bfd9ls428195oaa.2.-pod-prod-gmail; Wed, 31 Aug
 2022 08:37:26 -0700 (PDT)
X-Received: by 2002:a05:6870:700f:b0:11c:fb0d:4a20 with SMTP id u15-20020a056870700f00b0011cfb0d4a20mr1727717oae.97.1661960246050;
        Wed, 31 Aug 2022 08:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661960246; cv=none;
        d=google.com; s=arc-20160816;
        b=yCYPruFMdD0bvuCiu7qpgUsj/2CzvvwcOGXKY1bK+lvmrYojK0XlO7zam5BbCaHQhR
         lWh5vSfvomgtIBsPa5G3mKM7V4SAFWxD6JkTwGK/khZxss+olkCkbMzha7pBfctzT77t
         nQqQLsZ3DAam4HZmqlsblZDv02Xb2hiijecKKwTsChL8/AjxCkj7vayQH4ob2CQiO3qK
         jIUpV1zk0SKIwGCZ1BvwubEWY07kS0mndulLVwMr3ZDZFtQaQrZ8ZF1Pn11QBztQOHG0
         unjG+3snlSnD9crTZGZl9a6ALpOOAy3JAeIi5SkX6v61ej8qjCJhXSMzh3tEHiYB3/t/
         ihZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z5bWT124P9msiKtHJxXWtamGxGE9nU7NFSbNkXeVir4=;
        b=X701dnzszvoB09lSULkUC2DqY5YAY4+G3TZA/jBM6nwxfc453alUrydouf6OJNEnch
         HUyJRD+tQIcxuiElFUYm0FWR1VcVr9g6KTAJOwHcr/roJhYv/V42qu0qnj4CiHdMn3yY
         8iim7AyqT9W1ua0u+31/7hqi3idccRJG9d997J+bApngfnSS0vilGjR1VUifqCD3UlWF
         Om6vKKyQD/D4/x3GreYt8mkLUKglFxhAx1m/CNChfqcH2fsW3oNwTvVE1sXOy7Q3g9IL
         tfF95/vYam4IEt1L/g+AkudWx8YCNTdvyJQPMvaK5/Ad+eDTaliM0oVi+DE95TZRGt6Q
         zXFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q4yt7LQZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id t133-20020aca5f8b000000b0033a351b0b4asi819115oib.3.2022.08.31.08.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-32a09b909f6so311656137b3.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:37:26 -0700 (PDT)
X-Received: by 2002:a81:7784:0:b0:33d:ca62:45f5 with SMTP id
 s126-20020a817784000000b0033dca6245f5mr18452862ywc.180.1661960245620; Wed, 31
 Aug 2022 08:37:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-4-surenb@google.com>
 <20220831100249.f2o27ri7ho4ma3pe@suse.de>
In-Reply-To: <20220831100249.f2o27ri7ho4ma3pe@suse.de>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:37:14 -0700
Message-ID: <CAJuCfpHpBCUma_=AdTQ+UkfSkfkov2JbKfxLdp5K9_MoonkT7g@mail.gmail.com>
Subject: Re: [RFC PATCH 03/30] Lazy percpu counters
To: Mel Gorman <mgorman@suse.de>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
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
 header.i=@google.com header.s=20210112 header.b=q4yt7LQZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b
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

On Wed, Aug 31, 2022 at 3:02 AM Mel Gorman <mgorman@suse.de> wrote:
>
> On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This patch adds lib/lazy-percpu-counter.c, which implements counters
> > that start out as atomics, but lazily switch to percpu mode if the
> > update rate crosses some threshold (arbitrarily set at 256 per second).
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>
> Why not use percpu_counter? It has a per-cpu counter that is synchronised
> when a batch threshold (default 32) is exceeded and can explicitly sync
> the counters when required assuming the synchronised count is only needed
> when reading debugfs.

The intent is to use atomic counters for places that are not updated very often.
This would save memory required for the counters. Originally I had a config
option to choose which counter type to use but with lazy counters we sacrifice
memory for performance only when needed while keeping the other counters
small.

>
> --
> Mel Gorman
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHpBCUma_%3DAdTQ%2BUkfSkfkov2JbKfxLdp5K9_MoonkT7g%40mail.gmail.com.
