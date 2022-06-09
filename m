Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ7LQ6KQMGQEKQKB7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E42FE544DAA
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 15:29:39 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id z7-20020a170906434700b007108b59c212sf6600509ejm.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 06:29:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654781379; cv=pass;
        d=google.com; s=arc-20160816;
        b=RibHQI9AyVYIVjbYiF+iouFfPljbJySI00611VwmeiZ7lRYIoyl8Cu1XApbWiKiGr6
         cyshWtbY6bFA1NbtkQBWfcCehQYFdzFtsGGs9Q6hViMIWLDaKe2aWYvv8/4JshQ+7CXB
         N2eBbNEx2Nvb+hXFTQPDl7YH6KVcgUqbbpTPCFiDCS1qt4U4J19U/yNS8p5PBBoGB/nD
         Dt0SYoPenLxQyIuBKfloGODs2oYzf46DdCIQmo8DSRh29aY2iI/WRbNNgC0qwL1FOfQ2
         QTrJm1KlwZARXC/iJP9nUZqE4JDBHFnqeSBTjEMvax3YC6VtTs4PauXpY6bvwQeG1Y6W
         s4QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+/YIPlXMTe1S73N4HvDVP0exBPYWUWaExKzhsoq7Ucs=;
        b=Hpuwt92IOISe+U2zR2OTyWhrHB0wtQ+ogqwxtID1kpRFtwFYHzI2Oh8wLRYxSvOqIL
         AxVCDDxN01yHcGKO/zt8+ctRf/5IkKRwFI/Tjl5GQtcBq8YRzsGMTnSDApsVGkmixLnr
         vtybOhqButeN9cuzD9ZFpBIR9argOtWCYC2RW2QWeCwB/w+bjDTV8JHBNKYwoYi3PrbS
         67RjMW8xUX9SLH7desptv4Rrh/L4YIAKFcIpEIMqF064t38oZUQL+ep+VH/p8UGEYIdW
         NaOzNT0vtWt6epwnma5vV9JUOTl/NoG2Q8JuFWs2G6yB4Ar3hxHNy3KR6I0wEmrtFvf8
         KC5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=llsDjVZg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+/YIPlXMTe1S73N4HvDVP0exBPYWUWaExKzhsoq7Ucs=;
        b=t+tcj1UQpgIN8mxpBEfgKDXh79lDJXmRdbjDxyGwDtX/p+WzSNeSy/yoNrKy4L2Jds
         9NFA5i0rlCj+0TqRPKdHipjFQxHmDT08VqtS6I6qJeBmstebsxQVj0zWJpt+QVyYYYWK
         bUuUPO4NQHc1OefbnBwwIFqvj4rUgFqLTuiTfgNrT1dtydvEP8bM8jeKyYu33LYctnow
         JflokvxGE+RNRoV6F9ykROzJE8XKienbgU1Tish8dFlEH8PRrDDNoDELhl92FkmytIF+
         vVwCCGHwi5TWOtXaZU7v1lk4APY8dfnOkuMpvh2qG/6IDJvcpVuubP2ebkEklsGrZYHN
         bgfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+/YIPlXMTe1S73N4HvDVP0exBPYWUWaExKzhsoq7Ucs=;
        b=lz1xgNIvT9yCUWmFyftOBbFPXZbb1Blvck7AywMZdV9Z6bF+tJuAaJTPswKk7hQo74
         kJHup3DWbgKkufH6xX9LR9R8Wxf8vC5CUEZUGPCasDgKPlU+TEmVLnaZknMyl/4FYi4I
         n2ZsWKX4BHgG+60mpf3UZsIKN16G+O4KIxd6wgyq5bF2/PNe2zxhdatQ+Hg6d5D3dmRh
         PPgXoU6IQZiMFcXrC3O51vDBo9ycXhtNEvqa8xEztHMaQOlO0JJ8PHs7CL0kzLRPVqW2
         iO0az9CFhciO4UEn1iZeIIu086q4YYenwv9PpEqrVLOWhMkSFeaJPxcncDsKIN46IpPv
         S53Q==
X-Gm-Message-State: AOAM530ShNEQr37PHNfmKnFSZUM8+EqmBU1ntbS4kpH0w96a8T2OjCQF
	zBz3WVf1xftiHwKYMs+4OHM=
X-Google-Smtp-Source: ABdhPJzRAlInT3T883wVeBj9HNVG/qr5efVShsbS2M81MaBk08hmPhOVHGvJZKu675/5xwxtMeQx3A==
X-Received: by 2002:a17:907:96ab:b0:711:f0a8:8fdc with SMTP id hd43-20020a17090796ab00b00711f0a88fdcmr9191725ejc.359.1654781379320;
        Thu, 09 Jun 2022 06:29:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:294a:b0:42b:31b9:2087 with SMTP id
 ed10-20020a056402294a00b0042b31b92087ls1966727edb.2.gmail; Thu, 09 Jun 2022
 06:29:37 -0700 (PDT)
X-Received: by 2002:a05:6402:51d4:b0:42f:b38d:dbb9 with SMTP id r20-20020a05640251d400b0042fb38ddbb9mr34051836edd.255.1654781377630;
        Thu, 09 Jun 2022 06:29:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654781377; cv=none;
        d=google.com; s=arc-20160816;
        b=bvSbD15/3u5RHiKN4JsipswtNMo+/0Ko3HR6xxB3uD4F2QwO57o0Yw+rvsdxe6sMto
         dPjyyN9tXel9QU/GqEddYs/AHWLZ6YfDVeb+vJbMciYdhQ2Qgo6VSHGsX6CznUWHk8hB
         aRK3pg1f1Nc+VQsxq42JST+blTdYWN8ukk9JiFuDy5ksamq8LKwYN4YnQgW4/8vLSYZ4
         suANWqiabGOJYD3lOxMaUmyH4yBcQPYYHaxOk4VH54ae+4NBINaHy2J6BQTKEAFY37av
         gj9AQIf95FHc7yI4eCe3sbXT7mb9Y42DVIan6pjYCErdOOCRHCShMaHa9pdPe6FBb+yZ
         xt/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rjMuIRUcb0cPQvXILDOIo+coVEcP/6ZTYygCO+zLwZI=;
        b=s87cdnzJ75GRGZXO/XV/tS/WUgN+DAbHtn8QVyfSyPfhAcnTNWT7H9ykvI1axthnUN
         fJA6GI9+4kAsSGwCBeXtUSgsv0gzPGjsBh1UY4RKiIK8d7Ag29PNjEsL3qaPSI1qWk5C
         pJe6POs4azt+PRTau93MEes1AybFVzpB2il//0NfhcX5eODFEZyrzuwrBCcam9nY/xXy
         kok4S8Jht5Lq5ViL3stIf75pxWhT43IeLYTxNQyV8HVFI2TWqwnEZLqPvJ2B1sJxW/CI
         ponDbhleWNKfNxprtF3mpy9j6zaD+auA0+Kd6UoKDWAeZR2BZfDPC99bz4hs3pNc7B9J
         b0ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=llsDjVZg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id q24-20020aa7d458000000b0042d687c85d2si1277643edr.0.2022.06.09.06.29.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 06:29:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id x6-20020a1c7c06000000b003972dfca96cso1269333wmc.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 06:29:37 -0700 (PDT)
X-Received: by 2002:a7b:c057:0:b0:39c:4579:42e1 with SMTP id u23-20020a7bc057000000b0039c457942e1mr3381516wmc.102.1654781377037;
        Thu, 09 Jun 2022 06:29:37 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
        by smtp.gmail.com with ESMTPSA id bg20-20020a05600c3c9400b0039c15861001sm26391486wmb.21.2022.06.09.06.29.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 06:29:36 -0700 (PDT)
Date: Thu, 9 Jun 2022 15:29:29 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, x86@kernel.org,
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 6/8] perf/hw_breakpoint: Reduce contention with large
 number of tasks
Message-ID: <YqH1uUtWHkFr/jDY@elver.google.com>
References: <20220609113046.780504-1-elver@google.com>
 <20220609113046.780504-7-elver@google.com>
 <CACT4Y+aHZ4RTsz_SY=U5NKRWR1M4f0cy1WdepJyBGkbYy7_=TA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aHZ4RTsz_SY=U5NKRWR1M4f0cy1WdepJyBGkbYy7_=TA@mail.gmail.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=llsDjVZg;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Thu, Jun 09, 2022 at 03:03PM +0200, Dmitry Vyukov wrote:
[...]
> > -/* Serialize accesses to the above constraints */
> > -static DEFINE_MUTEX(nr_bp_mutex);
> > +/*
> > + * Synchronizes accesses to the per-CPU constraints; users of data in bp_cpuinfo
> > + * must acquire bp_cpuinfo_lock as writer to get a stable snapshot of all CPUs'
> > + * constraints. Modifications without use may only acquire bp_cpuinfo_lock as a
> > + * reader, but must otherwise ensure modifications are never lost.
> > + */
> 
> I can't understand this comment.
> Modifications need to acquire in read mode, while only users must
> acquire in write mode. Shouldn't it be the other way around? What is
> "Modifications without use"?

Right, maybe this comment needs tweaking.

The main rules are -- the obvious ones:

	 - plain reads are ok with just a read-lock (target is task,
	   reading 'cpu_pinned');

	 - plain writes need a write-lock (target is CPU, writing
	   'cpu_pinned');

the not so obvious one:

	- "modification without use" are the increment/decrement of
	  tsk_pinned done if the target is a task; in this case, we can
	  happily allow concurrent _atomic_ increments/decrements from
	  different tasks as long as there is no "use" i.e. read the
	  value and check it to make a decision if there is space or not
	  (this is only done by CPU targets).

So the main idea is that the rwlock when held as a reader permits these
"modifications without use" concurrently by task targets, but will block
a CPU target wishing to get a stable snapshot until that acquires the
rwlock as a writer.

The modifications done by task targets are done on atomic variables, so
we never loose any increments/decrements, but while these modifications
are going on, the global view of tsk_pinned may be inconsistent.
However, we know that once a CPU target acquires the rwlock as a writer,
there will be no more "readers" -- or rather any task targets that can
update tsk_pinned concurrently -- and therefore tsk_pinned must be
stable once we acquire the rwlock as a writer.

I'll have to think some more how to best update the comment...

> > +static DEFINE_RWLOCK(bp_cpuinfo_lock);
> > +
> > +/*
> > + * Synchronizes accesses to the per-task breakpoint list in task_bps_ht. Since
> > + * rhltable synchronizes concurrent insertions/deletions, independent tasks may
> > + * insert/delete concurrently; therefore, a mutex per task would be sufficient.
> > + *
> > + * To avoid bloating task_struct with infrequently used data, use a sharded
> > + * mutex that scales with number of CPUs.
> > + */
> > +static DEFINE_PER_CPU(struct mutex, task_sharded_mtx);
> > +
> > +static struct mutex *get_task_sharded_mtx(struct perf_event *bp)
> > +{
> > +       int shard;
> > +
> > +       if (!bp->hw.target)
> > +               return NULL;
> > +
> > +       /*
> > +        * Compute a valid shard index into per-CPU data.
> > +        */
> > +       shard = task_pid_nr(bp->hw.target) % nr_cpu_ids;
> > +       shard = cpumask_next(shard - 1, cpu_possible_mask);
> > +       if (shard >= nr_cpu_ids)
> > +               shard = cpumask_first(cpu_possible_mask);
> > +
> > +       return per_cpu_ptr(&task_sharded_mtx, shard);
> > +}
> > +
> > +static struct mutex *bp_constraints_lock(struct perf_event *bp)
> > +{
> > +       struct mutex *mtx = get_task_sharded_mtx(bp);
> > +
> > +       if (mtx) {
> > +               mutex_lock(mtx);
> > +               read_lock(&bp_cpuinfo_lock);
> 
> Is NR_CPUS == 1 case still important to optimize? I guess with small
> VMs it may be important again.
> If so, we could just write-lock bp_cpuinfo_lock always if NR_CPUS == 1.

Not sure, I guess it's easy to add the check for NR_CPUS==1.

[...]
> > @@ -397,12 +497,11 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
> >
> >  void release_bp_slot(struct perf_event *bp)
> >  {
> > -       mutex_lock(&nr_bp_mutex);
> > +       struct mutex *mtx = bp_constraints_lock(bp);
> >
> >         arch_unregister_hw_breakpoint(bp);
> 
> If I understand this correctly, this can weaken protection for
> arch_unregister_hw_breakpoint() and __modify_bp_slot(). Previously
> they were globally serialized, but now several calls can run in
> parallel. Is it OK?

__modify_bp_slot() just calls __release_bp_slot() and
__reserve_bp_slot() which is related to constraints accounting, and is
all internal to hw_breakpoint.

Only ppc overrides some of the sea arch_ functions. In arch/powerpc:
arch_unregister_hw_breakpoint() looks like it only accesses
bp->ctx->task, so that looks ok; however, looks like
arch_release_bp_slot() might want its own lock because it mutates a
list, but that lock wants to be in powerpc code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqH1uUtWHkFr/jDY%40elver.google.com.
