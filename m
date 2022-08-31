Return-Path: <kasan-dev+bncBC7OD3FKWUERBTFJX6MAMGQEMNZQOJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id D74B15A882F
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 23:38:21 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id t25-20020a4a7619000000b0044a8eef0d7dsf7444735ooc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 14:38:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661981900; cv=pass;
        d=google.com; s=arc-20160816;
        b=FBcmSgn0YabcH3Wv20JFaxUb3QmoyrEsLzCQLJl2vv/GpZ1e2DXJDhjInjgvtQIMeB
         ozTWQOLFqoKTLLh64HANiRw+/QEur0NPMdJf1GU/S9mc/waZdrqDOdeoWnmeJ4Mtffj6
         3+ZcTLCQyovbWzJnEJgM2TvwqTGwXCaELRIum9iTf9YNOn2q+ZVjeT+ZVuG382P8ZQ0g
         ooCpPSX7s8xT3B+C3z2MkkmQfBA1US3zcheH2ki60X3ST+jo+SKM4LCFAssQz5o3Ixuf
         GfnQIVd7cVIeuNBVsEOXWwxAXayhC+uF1B8C+jWcIS7NiO0Uivwwc8k5Ti7cFx9AfcHL
         bcnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J42u8iX1pnCUMkVKrWVGvjTCwmBttpNsh+xH9w2/4vo=;
        b=D6KRZTUFRJytmcJA5Cq3qSidKboVqMiDdRrvnEqHWCXg5CCoCzLJWhJkVmq0oI1Asu
         YRICNLhh7iELQyC4L04x9uEBkTpFx+1/myV5mYN5HpTDZOsNDle6LYI2AL6eh2F8uwlV
         whSDPhz12YHwkvPmY6Zvh5409IPk/wepH16hcwp5zBGM7uh15nx8Xsct1otMXMuGkS2q
         skoTOIhX4U6cFYKgIzjyxtZOyMyjNn8kGtfJfVVm6KVTfDfhbl5fpL3gqgoTZDS+abCx
         XX0ZRIc8NTUcnShKV32l1yLHqk1w81FjbF9S62pkrEGdiS7DuC2wk9VR9AsX4KMh9zKI
         niOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kAtSEhj7;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=J42u8iX1pnCUMkVKrWVGvjTCwmBttpNsh+xH9w2/4vo=;
        b=PJBEWlWMVMMEm0wiR+CKussndu2KdhszEdrMa6sl/9rcXt5ksvQ/SqGmjASsa6aTN0
         kRm/8P6itKtdJVIISEPXUE+wByUurzP9q3lE0tNKBQ9n3Lv77wY4lvHkOHswB0lrjhw9
         TwUz0PiD9D5JWsl8zljHLPZgA2Kfp531GGZTvedQAuuYadZb63ZUoI9Fac4M4XmIJCfJ
         nlKR7vM/OjaednpCB99Uxid0n45FY+v17RxWeoR5l3vnmZ5+OE2auJHyrRU1c36OFOOt
         MTlsQ5B7jN54vZT2qDiCjLl420z0knKF1Cdhn+fhUFnX7MJ3AjIXcbV9wNY/hg1Lt8YF
         qf4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=J42u8iX1pnCUMkVKrWVGvjTCwmBttpNsh+xH9w2/4vo=;
        b=5c3PkamKcolg7sJyVUXOI+Zl4nGSftIpf4Px2zIVCaHb4RnxKSkWvYkEVZfz2IBK18
         xEAqIcBgdGsygMbeIkHcqlWX+s5uBx6FxC+R1Ov4mSoqDCUfyFnXIb3Gr6fQYWZSrh3/
         18Vbi3mI5GCioy7V9uua7Zxbe9ggz4jsb8oXsxMg8lNTcX/G0/vC/UOAyh7luWcFliDT
         jvYRNZn/S7myJnoMk/5tchC7MjY7jM1e41VnXP1M/z2RQ/+ofpu71UZvojfyn1hDZeEU
         3MQD/hQIkhQbnTKcTIP1LtgYNv/fxHHUb4yvedNtngE79455l4WVyqaC2s12vHswse4a
         4b0w==
X-Gm-Message-State: ACgBeo0OMBMD7N36IcW6HA98Plwtx6TD/2YIINdzQTjo7tFPZHZcsEiq
	A1s2vqrKJ5oRlXlru5ryqVc=
X-Google-Smtp-Source: AA6agR6N8x2+s6ehw3lP5DM1lovEbpIAn41FZbhY8OGEpdb2tD4GrW1c6MJ4hYypFNY4pm9fvRhFjg==
X-Received: by 2002:a05:6870:c897:b0:11b:de9f:57c2 with SMTP id er23-20020a056870c89700b0011bde9f57c2mr2389222oab.267.1661981900595;
        Wed, 31 Aug 2022 14:38:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:80b:b0:11e:4e2a:2481 with SMTP id
 fw11-20020a056870080b00b0011e4e2a2481ls78465oab.4.-pod-prod-gmail; Wed, 31
 Aug 2022 14:38:20 -0700 (PDT)
X-Received: by 2002:a05:6870:41c1:b0:11f:ccb4:309d with SMTP id z1-20020a05687041c100b0011fccb4309dmr2700129oac.40.1661981900235;
        Wed, 31 Aug 2022 14:38:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661981900; cv=none;
        d=google.com; s=arc-20160816;
        b=czT8170nsFNphTZzlVyZjw1PEYgHqSD83ZetvikF7BEg1JaTtXbiM5fWKxi8fkSr1+
         mWz0gAcXZ8Zcyi62tAYULTR/iuMfmm9ylEuc2USlUTZD40nXZy753wEz6J4zciHMs7z/
         8pMbC9qH8Igu6nyoUz1mVw4PqaupEVgODv95kF5ElcM+v/gyO04lfQOaElb5TsYXT34h
         30cQs3hXJMiSHXe57eWYaO89ozgYB0AIPMk4ADbXEdMWPaGANuGYAbKvE2e21l2qGq1H
         fy5vkymWHUK4tA1XTWNrTSegZmYLm8zMceB4k92WomRzAfAlJukiEBsrrBmfa4h//dec
         8Hyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6E7G6kJMNs5Us6NEnCBcT2HO6AKiMVb4bH/0vpPA/4U=;
        b=H5kC4de9Eyg4Iig8vv0Whc8VY/OHXBa8Oel3vnkWGEzfH15asspq8Sk4HFVMSzYcZI
         RvdDZo+nfWqn5/6BRFmEyKK0PjKG4KkbIF5rJE0+c1FhzCyDRLokGgsyNVt3IwgoM+GJ
         DFaIS65DfD18Mb102IllD+0IN48mX/nH87K5RQlgnEMcCD4tJQg9HUp6zgiwMv/FD2vt
         B353pwJ/4YcISsqzZ05Ttd/YZhIPPF1NBatX4023h5B8rQjz7mNwMRnvS56V9izPoyc7
         i8+CKdQz1AUIw2v/C0+SqpnsStrVivuEcjuPpNCiqjM6pN3YcjeZ/ujTCZtIOk9JGpXk
         syvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kAtSEhj7;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1732494oao.5.2022.08.31.14.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 14:38:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-33da3a391d8so319759487b3.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 14:38:20 -0700 (PDT)
X-Received: by 2002:a81:85c3:0:b0:33d:a4d9:4599 with SMTP id
 v186-20020a8185c3000000b0033da4d94599mr19726685ywf.237.1661981899638; Wed, 31
 Aug 2022 14:38:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
In-Reply-To: <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 14:38:08 -0700
Message-ID: <CAJuCfpELZBoM8uG9prkra1sJ7tDiy_eF9TwetXSSN3XDssp8CQ@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Yosry Ahmed <yosryahmed@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
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
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	dvyukov@google.com, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kAtSEhj7;       spf=pass
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

On Wed, Aug 31, 2022 at 1:56 PM Yosry Ahmed <yosryahmed@google.com> wrote:
>
> On Wed, Aug 31, 2022 at 12:02 PM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> > > On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > > > Whatever asking for an explanation as to why equivalent functionality
> > > > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> > >
> > > Fully agreed and this is especially true for a change this size
> > > 77 files changed, 3406 insertions(+), 703 deletions(-)
> >
> > In the case of memory allocation accounting, you flat cannot do this with ftrace
> > - you could maybe do a janky version that isn't fully accurate, much slower,
> > more complicated for the developer to understand and debug and more complicated
> > for the end user.
> >
> > But please, I invite anyone who's actually been doing this with ftrace to
> > demonstrate otherwise.
> >
> > Ftrace just isn't the right tool for the job here - we're talking about adding
> > per callsite accounting to some of the fastest fast paths in the kernel.
> >
> > And the size of the changes for memory allocation accounting are much more
> > reasonable:
> >  33 files changed, 623 insertions(+), 99 deletions(-)
> >
> > The code tagging library should exist anyways, it's been open coded half a dozen
> > times in the kernel already.
> >
> > And once we've got that, the time stats code is _also_ far simpler than doing it
> > with ftrace would be. If anyone here has successfully debugged latency issues
> > with ftrace, I'd really like to hear it. Again, for debugging latency issues you
> > want something that can always be on, and that's not cheap with ftrace - and
> > never mind the hassle of correlating start and end wait trace events, builting
> > up histograms, etc. - that's all handled here.
> >
> > Cheap, simple, easy to use. What more could you want?
> >
>
> This is very interesting work! Do you have any data about the overhead
> this introduces, especially in a production environment? I am
> especially interested in memory allocations tracking and detecting
> leaks.

I had the numbers for my previous implementation, before we started using the
lazy percpu counters but that would not apply to the new implementation. I'll
rerun the measurements and will post the exact numbers in a day or so.

> (Sorry if you already posted this kind of data somewhere that I missed)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpELZBoM8uG9prkra1sJ7tDiy_eF9TwetXSSN3XDssp8CQ%40mail.gmail.com.
