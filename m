Return-Path: <kasan-dev+bncBCS2NBWRUIFBBE5RWOXAMGQE4WXYOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ACBC854C4C
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 16:13:24 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-5621dacfa59sf21706a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 07:13:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707923603; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZ+ZWLmIu+W52jyAN2GkH/5I4Cnnz98znDNderiVWCp0HUmRDuhO4gBY+WXIigMdIU
         SV+KA5z4uq0B8C7lIewyucG86IpMMX0vJXHlfEXHHcZgTOMjse0DflEXyElIHsbcmN+P
         KnVrvteArL5emPq6wZvfZi+U07bArjewQEmNBS5bj/mPJ7ptNQEf6zLWFCUowFHgOoHl
         iSmqTzM94oXRW3yB2t890eNCAMyI6380u5Rq6hoA09IufkQi/FP/Hrxn+UX+rgmtYgEa
         9oTe0mFmYvyaOycY/fkmVVAUvaT5NJLTGheH1uLz/LXbi0KO51gOmAn7mMrVZsy2Lv4K
         +upg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+WABt28AVSeme7QXJaIlWe/tAD0Jg92aLZTkUCcfIxI=;
        fh=m7zgAezENEt6NC5LJGkofSX1gd1nV5VBPvX3xh3ZbS0=;
        b=y6MTsHDKEMNh830uruEX0Yej/l07OpSgHE7moEYbDuQgD2SzI43RHJJj84A09Up49G
         OgpOuRXIruHtz2e9lD9Xd09aX7j8fUYqzJ38E9wcIQ4XU72PBft27vFhRQkTGlh7nGqk
         W2hi1+8Fa9wbOuuIQEkuiun038frzTlRRHidfPrSpO6QCGWgwJu9yrzhK3U9dZPU8z8e
         owXWQGxjDN2VofcABdAb5VtN18P4t6ki8tWi8mWkrz5QN11H+SoYmlCunX4xhg9S81/A
         TM8Gs3NVxivTXajDBCshAQW/h6osvUmsKlm43qEZacOX08xsk92fEd6nx+tog0lhztgA
         91Nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QqnVFzdf;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707923603; x=1708528403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+WABt28AVSeme7QXJaIlWe/tAD0Jg92aLZTkUCcfIxI=;
        b=QV/3cQZknVElbphQHY2fUrKFYRuoT9AWbYmD1bcoH9ZBzhyJMh2Kdd32VT0/S3HDiF
         Wcuon9gkSsBZGbft5ck4U9JkNY4cnvEqsAb0oMAW+3lbq/ZcA1wkTdWWTQTrLR478mEK
         FRTDFAq6eXLtOwvTNXSDDUiBsb7uZP5DsbLbC7FfFIsos/i0rWiHwdWUD0IL7F2ew5Rg
         dWk/UUCKUH6B123a0Lu6vo2Oe1sXQV2Fs35tabil6NqFuizaD0RG5JsiP29ZeexawJ5a
         QxDHOk/u8xonb6X0Lbc7EEFGVO+H93LKxo73h/fMZO+0i/a+fIQZCQG0oo7PQbmwZVBS
         E74A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707923603; x=1708528403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+WABt28AVSeme7QXJaIlWe/tAD0Jg92aLZTkUCcfIxI=;
        b=j40D17eWtVlyio6ykfUE7itT2e7P84hk29cX2jM8tVba6Yj+G1L4EOTSiRYxV30LvN
         7lED0N+BtRqnaoqI3d7yWS0uLfGoLYcF2DbUEsLaGBzHhm9vs34GyYpq9LX2o6k5qkGy
         R7NprOkX8uhZ4XeGCKJlBc33m89zMl1vcCcBVoSnNCqp/UQERzVaFAzV6o3N8WAPFf/H
         dNphRGr0mcBBRdJWP3uM+WrwHh6Di0449JHZhPmMhk84TKg9IbA9Ddtma1viN2qmcMnN
         wFhdYBr94OjybQIhhks9fhrJoEeb0Rd9Mtc4xdPXEmLdGO3je3h9eM476B78dWR1Fq6o
         BnFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWE3WGJKuh72GQ9CdTkxSOtFZ6WXiAYnBljzdYBnLG+lBUZ8RChyjqof3wFRwgz+GAfeF83YOqkQyjbrmZJ0etsNBPoIZXCfQ==
X-Gm-Message-State: AOJu0YyQOAIRrY456peWcFpcyXpK5zy6crZ7TlPo9hWmBaAvgJq0HX+s
	hBTrtp458i/FSwfbX3MSe0PpZPxXddAMhXT4af61ZpU/LC4KTAK7
X-Google-Smtp-Source: AGHT+IEqM4umAzqAnClFAEVQc/wyNgp1Fr7p8aLQfzbkHCHbhgpfrq66Z3OJQDnec41EH5q/LlXqug==
X-Received: by 2002:a50:8d13:0:b0:560:1a1:eb8d with SMTP id s19-20020a508d13000000b0056001a1eb8dmr180658eds.7.1707923603312;
        Wed, 14 Feb 2024 07:13:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:448d:b0:561:63b4:b06a with SMTP id
 er13-20020a056402448d00b0056163b4b06als1291192edb.2.-pod-prod-00-eu; Wed, 14
 Feb 2024 07:13:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMi/snTSnYbU41aoo7KAglsmYBjTQe8MjpJJGA3p/Iwyj+dnY7ABi81UjkWyrAn2dko7CwCp0O3MzNJ8Apoyb8CvydxZJTNrhAZg==
X-Received: by 2002:a05:6402:c4f:b0:561:f2b1:a68 with SMTP id cs15-20020a0564020c4f00b00561f2b10a68mr1913797edb.20.1707923601503;
        Wed, 14 Feb 2024 07:13:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707923601; cv=none;
        d=google.com; s=arc-20160816;
        b=v0zHR2qHIi/nEP9TM+2AjiOTD2A5Y7+dBUV7u+H5SaClfbSJApRR8cpJM53oBQZh0v
         Z1V2MXooKSRt8Olk5qQ11By0IkVh6RsRkbqA2zZOOF/nFwdof6Zvu57xx9bgJFQcbmk+
         fxcxGbEshPwkuv2Hc8rgR+VGMtRPUEqgC0R5mbnBOA0iZzEQk3bQAfvrTQiQTvZlAUhZ
         7Zs6HHuAuq2siEt+7t5txRkn9gaMMdoZOCJjqyXUFSOTcAVakHdfNQftlwHaBYXuoZPB
         PbncxRg2lt8EwJX7mMe0JZiJD7r929Nn4bPINVLzgruiSuqfejHK6O8LS0pmk7uz7AHf
         mzOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=PY07zx4xo5DT+YIldZdwTzLPFVE7nIythW2Rrqykp1E=;
        fh=1zpsX7fHGCRtkiXBj4gnEAikcAh0Vx+qDbnuxUwmFsY=;
        b=FQ5dC67ZdokHtxixGnRIBtTBIq5cOJYXzoFm/5C1rNc/ld0WX9kGmDdcDxVvsBmec+
         eSKLASBhi19zwtoWnJkQigeGsjayrXa0pLau0gOmAK2sEMNqQARpbZ1Uhu52yR1x2FIQ
         xBvShnvcfQXu9hSCA0Qg/SsiAruqPTxf0wXAFKzkc1kn6pHbvlYYN1k2qxDViEWjC0zM
         jfShIro5/rCcwPyYc0l60vLZTbLTlNxASA8YfkZNhIzhce2Saoq9eXCjHpXswnW2kYRM
         qqIXyiqv00LbY/70tf4n+8HX2XQOIj16CRjac6OWqyzX1brF45vkZQQv2xaWyUqwbKiY
         WikQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QqnVFzdf;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCXi3rraYqP85hrZfEE/tH1grMHVzAnzHqRsNwlmtJIvb6bqoAgFk6jEATMWKDFZ69X38h0KPpjtoARLEy94ag3HVjj6DQcTNnktOw==
Received: from out-178.mta0.migadu.com (out-178.mta0.migadu.com. [2001:41d0:1004:224b::b2])
        by gmr-mx.google.com with ESMTPS id y3-20020a50bb03000000b0056385533e54si79693ede.2.2024.02.14.07.13.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 07:13:21 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) client-ip=2001:41d0:1004:224b::b2;
Date: Wed, 14 Feb 2024 10:13:09 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Matthew Wilcox <willy@infradead.org>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <lkozkbcucokzaicygwn7ym2cmmdt6bwyrluxb7ka7ygnrgyyfh@ktvirhq3hrtn>
References: <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
 <ZczVcOXtmA2C3XX8@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZczVcOXtmA2C3XX8@casper.infradead.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=QqnVFzdf;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Feb 14, 2024 at 03:00:00PM +0000, Matthew Wilcox wrote:
> On Tue, Feb 13, 2024 at 06:08:45PM -0500, Kent Overstreet wrote:
> > This is what instrumenting an allocation function looks like:
> > 
> > #define krealloc_array(...)                     alloc_hooks(krealloc_array_noprof(__VA_ARGS__))
> > 
> > IOW, we have to:
> >  - rename krealloc_array to krealloc_array_noprof
> >  - replace krealloc_array with a one wrapper macro call
> > 
> > Is this really all we're getting worked up over?
> > 
> > The renaming we need regardless, because the thing that makes this
> > approach efficient enough to run in production is that we account at
> > _one_ point in the callstack, we don't save entire backtraces.
> 
> I'm probably going to regret getting involved in this thread, but since
> Suren already decided to put me on the cc ...
> 
> There might be a way to do it without renaming.  We have a bit of the
> linker script called SCHED_TEXT which lets us implement
> in_sched_functions().  ie we could have the equivalent of
> 
> include/linux/sched/debug.h:#define __sched             __section(".sched.text")
> 
> perhaps #define __memalloc __section(".memalloc.text")
> which would do all the necessary magic to know where the backtrace
> should stop.

Could we please try to get through the cover letter before proposing
alternatives? I already explained there why we need the renaming.

In addition, you can't create the per-callsite codetag with linker
magic; you nede the macro for that.

Instead of citing myself again, I'm just going to post what I was
working on last night for the documentation directory:

.. SPDX-License-Identifier: GPL-2.0

===========================
MEMORY ALLOCATION PROFILING
===========================

Low overhead (suitable for production) accounting of all memory allocations,
tracked by file and line number.

Usage:
kconfig options:
 - CONFIG_MEM_ALLOC_PROFILING
 - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
 - CONFIG_MEM_ALLOC_PROFILING_DEBUG
   adds warnings for allocations that weren't accounted because of a
   missing annotation

sysctl:
  /proc/sys/vm/mem_profiling

Runtime info:
  /proc/allocinfo

Example output:
  root@moria-kvm:~# sort -h /proc/allocinfo|tail
   3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_inode
   3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_stack_node
   3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_ext
   4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_collapse_alloc_folio
   10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc_rqs
   14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_alloc_noprof
   26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_alloc_noprof
   64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_init
   98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio_alloc_noprof
    125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page


Theory of operation:

Memory allocation profiling builds off of code tagging, which is a library for
declaring static structs (that typcially describe a file and line number in
some way, hence code tagging) and then finding and operating on them at runtime
- i.e. iterating over them to print them in debugfs/procfs.

To add accounting for an allocation call, we replace it with a macro
invocation, alloc_hooks(), that
 - declares a code tag
 - stashes a pointer to it in task_struct
 - calls the real allocation function
 - and finally, restores the task_struct alloc tag pointer to its previous value.

This allows for alloc_hooks() calls to be nested, with the most recent one
taking effect. This is important for allocations internal to the mm/ code that
do not properly belong to the outer allocation context and should be counted
separately: for example, slab object extension vectors, or when the slab
allocates pages from the page allocator.

Thus, proper usage requires determining which function in an allocation call
stack should be tagged. There are many helper functions that essentially wrap
e.g. kmalloc() and do a little more work, then are called in multiple places;
we'll generally want the accounting to happen in the callers of these helpers,
not in the helpers themselves.

To fix up a given helper, for example foo(), do the following:
 - switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
 - rename it to foo_noprof()
 - define a macro version of foo() like so:
   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/lkozkbcucokzaicygwn7ym2cmmdt6bwyrluxb7ka7ygnrgyyfh%40ktvirhq3hrtn.
