Return-Path: <kasan-dev+bncBCS2NBWRUIFBBB5436RAMGQECMCRUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D2A36F9A85
	for <lists+kasan-dev@lfdr.de>; Sun,  7 May 2023 19:21:12 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4ec817fb123sf1862496e87.3
        for <lists+kasan-dev@lfdr.de>; Sun, 07 May 2023 10:21:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683480071; cv=pass;
        d=google.com; s=arc-20160816;
        b=urwfOAYxlUErCeIGQgXJCb05XPN39C0MUNf8rf3j5qlhV9GwCqcy9zc++ipWA/IbGZ
         6sRRg+SWqnB0I5jZ+Xt1uJo5blqWyf6BrTmMLFlVyvJnQ5k/kMkbXe4NnI4zCI5vhW99
         1l5V8hgCoORwRPEwZ4kg/Im1m9WIYOogoqSCABKAagGCyzKZvmpqnrBeRlX8zpk8t41q
         SDf49CUjfL14ML9YJ5bg7eU9bsLTxSl7yg9/DCeX35QoWeczLp67Ooa5rAIufMjWWoff
         hxOfpEie5Xtk+ZByXEf7si4zuw+BMc0ljsDkM24tgMwrxhLTf6J7gxUBwqz8rEAFcqUF
         iIKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4QnlTxu8/twKwmV1u0i8Rg9jZ20JkWBSj0n805s2flE=;
        b=m3g+m4O53qsn11fcBZTO3ZUZeSE5c2nTfG/uYFcbh0D88itH31ya1NppI3tZnm0Jlh
         jJpa12bopmkUJQ32xAmTX0aM6mKsIXIWxQYjEwT37LMEQVxeAp+pWiQJp2ijJAWT2vzL
         VfjR3NzwXbqTV0YsSFxjyd7DXlu9bofTg9apalbbGXP4TFAxe5rINYMqQM7078UOKdz6
         o5SsWxseSVOIq+R2PMxaKejK1mrWoYpqqKAVH6rqwbzI16uP4nH1uOEN0108NfmgG9If
         y+1xUQn5jNjPYvEcN22kinsD2e3vcTApkzjnvfDLL5wW6AiCfpgzqn78BC21sLuyOLqI
         My7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t9HPg37z;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683480071; x=1686072071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4QnlTxu8/twKwmV1u0i8Rg9jZ20JkWBSj0n805s2flE=;
        b=IGPmLhYtoxC+Cc1wqEL9Vn0lLjQkgPzNB5LHG89d00YOO+9GTDYG1in2Xtqd4BucpL
         BohPMo8qcv1lecl3cgNjX6UiQetBu0GKFerTq06DiKJZSq4B0oNSKhnN4p87lTAv7Pzp
         ZGAz0JCINFk6SjuA58X9VxnnjkfIzCA/sBcW1Oiew6Zs5VxF4GNBKH6m5hhuLJv443Es
         534LauuBwcOE24BY4QTFGJjoU5VcPU9DKv/i1Dnl1tjWkslnAd514KLMuieeW3nZNLWO
         dG0H6hUyLGKY9dd9lByv/5hko8cuU0yDEmQ7wyM9BS/0wed9TpXti0pxDnJfEn9e3fI9
         WvGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683480071; x=1686072071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4QnlTxu8/twKwmV1u0i8Rg9jZ20JkWBSj0n805s2flE=;
        b=jF+S8KvPEKOaZiV2MTCr6iVw0uQPiq+pUzWYASEZXDtqDXoTHb4t7ylDv1PEH9vutA
         hhAzxnnvgrDmBzGENwWGvWa+GvzamVAd8kGvi42XA4iL+fVe8HaKTdmWgz/asi/OxK5e
         UxPVmQ5v0/Cr55iPfxz8z63wdMSnW1JpdRhy8U25d1o4WNIbhEiLsWszOwvka2jHh8dI
         uUudMdXxqlUrD+c3Fo0q7KcRFaP6rfjrrmpfPzjFO/glGoSBGqPOsY6WkioqgTs5yeyv
         +uKIthph4Fvdb7jxpPdeUFXYyJlAfcNolHBaHe4hg/v0cwLfrqnNwc3u3COKAUSTYz50
         nJ0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzBDU3D5DxStv7eITxg+jaJVERXT6b7Oc0jWyfxrdgrmkTSWgdb
	W/cIakpZiYVdofCcmISbcfM=
X-Google-Smtp-Source: ACHHUZ5/90RSkkPx6ZTKtZVc15KX8nhYiuQvBMAP+n26nrNZTu8VqdZilmVlJG3seogTH+iJjs5VXA==
X-Received: by 2002:ac2:5108:0:b0:4ec:a218:4f92 with SMTP id q8-20020ac25108000000b004eca2184f92mr1857025lfb.9.1683480071248;
        Sun, 07 May 2023 10:21:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c2:b0:4ed:c108:7214 with SMTP id
 k2-20020a05651239c200b004edc1087214ls3602785lfu.3.-pod-prod-gmail; Sun, 07
 May 2023 10:21:09 -0700 (PDT)
X-Received: by 2002:ac2:5df6:0:b0:4ef:f38a:6718 with SMTP id z22-20020ac25df6000000b004eff38a6718mr1847318lfq.13.1683480069818;
        Sun, 07 May 2023 10:21:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683480069; cv=none;
        d=google.com; s=arc-20160816;
        b=jsgDfj+NqpDWryHdbDwxsehvqjcQJiQkI9dgoyM6fcXNc5Av51dz7a3K8xSEDzzCwH
         1noszFgVEjfdu/uZPu5K+hSAzM2WZTNzL6OBpEbOaPaYl64hmPZHRk4D2gDdMj3HCE2r
         MiujiTAg05IylIlXkIL69MPV+2gjSDJ8xB40XPq0C5eRPq2Li03rH4dbtVjr0/e55jzA
         VAh2op/afMAp3kGqZrbLkG7wENQHzFkBWXs5r+eIBWItvKsrWEUDVaCu6vihAPHrkR9C
         V92WRBQmxKdLE5UAMKhaP57vPhWG3zMXB+gt/xMp0gByOxOOjuzsklGKaqc64cYki1YM
         OCXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=hurdbnJwUJqK07Lm+4BMc/GcG+c58gJSfQAtVR+cBkY=;
        b=BEJfh0dNxTXtRvly7MzKeJmQejfvRz76l5gdsjbrJoB0LwEg3klezfTQOyG/YFkr5O
         t6Q8Q5/zIVl9EkWqcpCHUMOvO9KPR6WCVgh/qek3FkSlfcZMFirTxZ515nefXSLVHzXu
         mJQUrNl9NIrZO7IdR6qFrercFxc2P7pXkQPw+9lSS8kBAiiRWhC2NrppcunKm5LPMoSN
         ear4MXXAinL24JnJdx7zpVDAPtYjQMOTU3C9jLlmyFaRTffEPOADg1TWUD6xjbKRA9bl
         VwfdVC68CDuQd7LsqqhPR6P8kq0k/a/3yZbzrsqGyxvmW3PEf1Xo2NJYZbsN9kKzcExS
         PAyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t9HPg37z;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-48.mta0.migadu.com (out-48.mta0.migadu.com. [2001:41d0:1004:224b::30])
        by gmr-mx.google.com with ESMTPS id d29-20020a0565123d1d00b004dd8416c0d6si465872lfv.0.2023.05.07.10.21.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 May 2023 10:21:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::30 as permitted sender) client-ip=2001:41d0:1004:224b::30;
Date: Sun, 7 May 2023 13:20:55 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFfd99w9vFTftB8D@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=t9HPg37z;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, May 04, 2023 at 11:07:22AM +0200, Michal Hocko wrote:
> No. I am mostly concerned about the _maintenance_ overhead. For the
> bare tracking (without profiling and thus stack traces) only those
> allocations that are directly inlined into the consumer are really
> of any use. That increases the code impact of the tracing because any
> relevant allocation location has to go through the micro surgery. 
> 
> e.g. is it really interesting to know that there is a likely memory
> leak in seq_file proper doing and allocation? No as it is the specific
> implementation using seq_file that is leaking most likely. There are
> other examples like that See?

So this is a rather strange usage of "maintenance overhead" :)

But it's something we thought of. If we had to plumb around a _RET_IP_
parameter, or a codetag pointer, it would be a hassle annotating the
correct callsite.

Instead, alloc_hooks() wraps a memory allocation function and stashes a
pointer to a codetag in task_struct for use by the core slub/buddy
allocator code.

That means that in your example, to move tracking to a given seq_file
function, we just:
 - hook the seq_file function with alloc_hooks
 - change the seq_file function to call non-hooked memory allocation
   functions.

> It would have been more convincing if you had some numbers at hands.
> E.g. this is a typical workload we are dealing with. With the compile
> time tags we are able to learn this with that much of cost. With a dynamic
> tracing we are able to learn this much with that cost. See? As small as
> possible is a rather vague term that different people will have a very
> different idea about.

Engineers don't prototype and benchmark everything as a matter of
course, we're expected to have the rough equivealent of a CS education
and an understanding of big O notation, cache architecture, etc.

The slub fast path is _really_ fast - double word non locked cmpxchg.
That's what we're trying to compete with. Adding a big globally
accessible hash table is going to tank performance compared to that.

I believe the numbers we already posted speak for themselves. We're
considerably faster than memcg, fast enough to run in production.

I'm not going to be switching to a design that significantly regresses
performance, sorry :)

> TBH I am much more concerned about the maintenance burden on the MM side
> than the actual code tagging itslef which is much more self contained. I
> haven't seen other potential applications of the same infrastructure and
> maybe the code impact would be much smaller than in the MM proper. Our
> allocator API is really hairy and convoluted.

You keep saying "maintenance burden", but this is a criticism that can
be directed at _any_ patchset that adds new code; it's generally
understood that that is the accepted cost for new functionality.

If you have specific concerns where you think we did something that
makes the code harder to maintain, _please point them out in the
appropriate patch_. I don't think you'll find too much - the
instrumentation in the allocators simply generalizes what memcg was
already doing, and the hooks themselves are a bit boilerplaty but hardly
the sort of thing people will be tripping over later.

TL;DR - put up or shut up :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFfd99w9vFTftB8D%40moria.home.lan.
