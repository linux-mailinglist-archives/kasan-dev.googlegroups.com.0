Return-Path: <kasan-dev+bncBAABBXHQYSMAMGQEKUQFN7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 08DB85AA35B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 00:55:30 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37fesf239648ljo.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 15:55:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662072924; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0FXQhjBsiNaTOrspaN7Fxr9sJKx5nTDNaXNJfAx0YO8GVk20evtW+qDjidDStOIZb
         svYB3ESpCuNjtQfmpFDIk00PoefSU9GRrkuFu8S+X6bMsQplRehImm9an6hPcalAWFtH
         m+7YS4izY8OjeSuw/Ui6YiMuFF0zL3d5RldYuWe3nnkqERpyewdgt449AnOVrt/J6+mq
         8DvxxOJF+ZnUKBMQbROhh3+ZTK4v6G2hCtRtM9wLTao8Vfw0YBcxtPKKeGidWyqsWKeD
         G1cHKveXxzgxWBsYuF3VirhQQosqA6R7yD9hmD3hGDIXkEZF0kw0e5yl1dhiJPX3W+6a
         7CDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/r5kTQikxu3/Cth/RpxfJbppObB3uOXwo8Z2l+Onx6I=;
        b=ZIevuJEZml0GGyfSBzjCaOVPvLfqfEjVscfpYkPaviFtRL2CJDdlBT4/x9AnD/Fh5z
         4y+t1DPcGg9QfqTP5C1C+tnIQdjMu1GWAtZfE3VkEq4f5bOQkSFGEyDEdB6R20NO5fo1
         kIrnitCvNKZz1P2YoicO+SylDy3NFQF79AbZG9KLPN0yBjJdEdHEv/d1KgvuMighRkTy
         qAu+rqHdHMDyXiqUlJBwxjeixqzE2wSToSJwLPK0kd0IO8B38SHcRw+YZdtsrMt0Za9f
         fdPOlHbgoPF14lK1d01N/wr2YlTO7E5AwjYBcU67cldg+ivStzncEgySU3G/xuwraCeh
         x/VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fj1UwT1L;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=/r5kTQikxu3/Cth/RpxfJbppObB3uOXwo8Z2l+Onx6I=;
        b=rL4rR3p7890E26npue9ngN/x2kxrxqODRpzTCRXn8eW0AFVhM4ihAQG9ewLQMntvFI
         IBDWe4fS5ZCFnnpZTT3d7E3v5oMBYz95I63NssQhgJVyPDU1n4a66DiGIHaIL1SX7uhZ
         ugtnyecX7bNwc4SLh5JUBTqXX6kmKrb39gVHpthye5X722P4/oHW21H5gnkwHNswq9jC
         TOEuTBqZPUKrnRsvQPfoexsnzMA/r16XNHczug05ekyHqKbWuT+ZVltICHfca3/RHxPM
         U/l61IHt1kYs6elw/VqtfVXvUCTi8olP1XrsmOf5QOTPlm0QMq1jrTsBe+WKwRF8VgCf
         yRXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=/r5kTQikxu3/Cth/RpxfJbppObB3uOXwo8Z2l+Onx6I=;
        b=O4J8CB4hF7NPiUKbXkkhrleItOIUiND1125Bdzz3M251fiX1YZ1CCWcM341dpmAfGv
         WgzlSuAABcTYMBcE/F51eHblLHg9MJsqyGJgM7y5g4aEQVjiU8GgjP50sZKX1ea46w+4
         jXh1Qi4YbzkNQacggSsFfMSlMvADdEn14+gA4+9jmGf2BWtZ8wpZXqe/E072X3QnUee2
         WmoaUUgE4VcXucR4Ib361fmv93rNiukk1gKB7TyhxFNL5TggcuktYTYjHV55z0hvrrMV
         GMOQqDu2QWHc2OsEaLj7Vqi3Dgt2/4xWSNPllYJjQpPUYOYGbpVRathtBHR2eDT7rYTy
         oLqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3X+WEVQhUXZGg9RopOFBDyZ8noygOvG7zKr8tNEn1CLtDZWU69
	bChDv/PUnYZxyTPdIyYZFpY=
X-Google-Smtp-Source: AA6agR5kilyRZX+1NLZQ5JX4g2v33mtd1wlV9t9FiQ7xCW05IOKVeYiwnX222440maqnSkYWDR5uXA==
X-Received: by 2002:a2e:b601:0:b0:268:49b4:b780 with SMTP id r1-20020a2eb601000000b0026849b4b780mr3382223ljn.506.1662072924555;
        Thu, 01 Sep 2022 15:55:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3fa:b0:494:799f:170 with SMTP id
 n26-20020a05651203fa00b00494799f0170ls238064lfq.0.-pod-prod-gmail; Thu, 01
 Sep 2022 15:55:23 -0700 (PDT)
X-Received: by 2002:a05:6512:3f0e:b0:48a:5edd:99b2 with SMTP id y14-20020a0565123f0e00b0048a5edd99b2mr10743819lfa.124.1662072923660;
        Thu, 01 Sep 2022 15:55:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662072923; cv=none;
        d=google.com; s=arc-20160816;
        b=Dw0fH6EwLvT/jG5Zuv3YOtjrJshVm8RqxYr3hiXHbOfH7KY019xMZ0LxZfszFXQhV0
         VYpWCz3i9SjkBWc79hOsDK43jP29YkfyMXA5tvP1EbudzeJWkv013IlUywXi3bx3OMBY
         RJRK1IBEc6riopa87dvnPnvUIQBuR5hLTtdRpKG7Fq4TAEP+semflEO3Y6Pu6YuXMOXE
         hjL6ns8yvTWnEbC9/T+4AAG/Q3QIzVq0YI3TNZTYaYlb4O4460Z5j7tE21XLzVv1byGG
         0M1FumMdxCFLuDggvVB4IqyioJDIpKOjI6hFfidUPQGcfd73zSQx9giBCsLWSfVoFbjn
         HjSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=bm+owKdXaA8Za4y2gNPpxqBECptJMMdY3T6zMUdS1uA=;
        b=vXaXuw5R56xLMR1BscKE3l3QVg0s69GEhhP6ZZYotQTO71J7FjLicGffr0AhkDnhv/
         T3N1VsdOehn1bKgy8dmrpcD9zkM2916YQhNolbk+zPT9aU/wa4jA0/ov4Cb2mL5bqJpH
         J0KwCKHWdJbgPWM3NB0zrZ6iZksd5Zah7RHJ/C6RuAjfLwmani5YVUI2BGPqOIEnsdbC
         RInQheZ+mRdnQHONiXrCtgUh2oGoj3fnBYXQhhUuoWK7Uy2N7GszFVOm8xT52vEzuhL9
         iI0Zy8piPamPDT8yU407kLDjE/b2WIM5cA5zEHAuGcJVDOjPr0XWiY2LKQESKW8kbMjj
         hRNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fj1UwT1L;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s7-20020a2eb8c7000000b00268889719fdsi16209ljp.4.2022.09.01.15.55.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 15:55:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 18:55:15 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com,
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com,
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com,
	dvyukov@google.com, shakeelb@google.com, songmuchun@bytedance.com,
	arnd@arndb.de, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901225515.ogg7pyljmfzezamr@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
 <20220901173844.36e1683c@gandalf.local.home>
 <20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
 <20220901183430.120311ce@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901183430.120311ce@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Fj1UwT1L;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Sep 01, 2022 at 06:34:30PM -0400, Steven Rostedt wrote:
> On Thu, 1 Sep 2022 17:54:38 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> > 
> > So this looks like it's gotten better since I last looked, but it's still not
> > there yet.
> > 
> > Part of the problem is that the tracepoints themselves are in the wrong place:
> > your end event is when a task is woken up, but that means spurious wakeups will
> 
> The end event is when a task is scheduled onto the CPU. The start event is
> the first time it is woken up.

Yeah, that's not what I want. You're just tracing latency due to having more
processes runnable than CPUs.

I don't care about that for debugging, though! I specifically want latency at
the wait_event() level, and related - every time a process blocked _on some
condition_, until that condition became true. Not until some random, potentially
spurious wakeup.


> Not the prettiest thing to read. But hey, we got the full stack of where
> these latencies happened!

Most of the time I _don't_ want full stacktraces, though!

That means I have a ton more output to sort through, and the data is far more
expensive to collect.

I don't know why it's what people go to first - see the page_owner stuff - but
that doesn't get used much either because the output is _really hard to sort
through_.

Most of the time, just a single file and line number is all you want - and
tracing has always made it hard to get at that.


> Yes, it adds some overhead when the events are triggered due to the
> stacktrace code, but it's extremely useful information.
> 
> > 
> > So, it looks like tracing has made some progress over the past 10 years,
> > but for debugging latency issues it's still not there yet in general. I
> 
> I call BS on that statement. Just because you do not know what has been
> added to the kernel in the last 10 years (like you had no idea about
> seq_buf and that was added in 2014) means to me that you are totally
> clueless on what tracing can and can not do.
> 
> It appears to me that you are too focused on inventing your own wheel that
> does exactly what you want before looking to see how things are today. Just
> because something didn't fit your needs 10 years ago doesn't mean that it
> can't fit your needs today.

...And the ad hominem attacks start.

Steve, I'm not attacking you, and there's room enough in this world for the both
of us to be doing our thing creating new and useful tools.

> I'm already getting complaints from customers/users that are saying there's
> too many tools in the toolbox already. (Do we use ftrace/perf/bpf?). The
> idea is to have the tools using mostly the same infrastructure, and not be
> 100% off on its own, unless there's a clear reason to invent a new wheel
> that several people are asking for, not just one or two.

I would like to see more focus on usability.

That means, in a best case scenario, always-on data collection that I can just
look at, and it'll already be in the format most likely to be useful.

Surely you can appreciate the usefulness of that..?

Tracing started out as a tool for efficiently getting lots of data out of the
kernel, and it's great for that. But I think your focus on the cool thing you
built may be blinding you a bit to alternative approaches...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901225515.ogg7pyljmfzezamr%40moria.home.lan.
