Return-Path: <kasan-dev+bncBAABBJ6UYSMAMGQE2YTRLPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C3E105AA1C4
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 23:54:48 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id z11-20020a2eb52b000000b00261d940ce36sf184530ljm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 14:54:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662069288; cv=pass;
        d=google.com; s=arc-20160816;
        b=OOqS6wNlRejFPz/VUNLoq0uFKA6VzuSHS7G/zFp8VZF6iheNDUMf7ijEWi7OV8F7Ay
         e9Xh269OWkZSzjgZzg8EQVrkJ6wv8HIkv44ktRtIch91xli1HuNSeg0P1JrrE3p7UOjX
         Wh/FvA9kWB27V6EjMosYC2TbipTJuKmOTvP9Mp5wz9670eSxj1DFNWZRKM2uxRoU+FiU
         CRXEiUKFpdF7mQzBe/SB3OCTH9Tnd5jBEflvyysOlirwKY/53POzlO/TeHPcODDki1M/
         KXphcRWiR66JQqKKvqK/PiWfDsUhXwQzvbRDGOAMZEFFN5yTovfLT+PNxse4lf29LvnQ
         08iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Em0YV2kKNaVcXCrxuwnO4WPg0dRdNaWVw/dwsMivzhs=;
        b=kIk1wkf9hTjmIOaFO5YAUqpjUFhTuyBXlzU4+QZfqxEF0iLdDFEa9F+vNt9PmYQ7Ef
         iZefQZuhVIiLExGTl32es8hjAlj0yhkYIeUwQ+U0/LeemJfq+g6uWzoms82eTr5wmHdZ
         7rJi1hYnsEA+Da9PX/VlRMXdBBSByehVbSwNgaJrAuWwZGGYVaFaDG+zgqJauh8CgNzq
         JY03PVck34MBcEnaPKqGOMKM9O5tK6kif6UTNk1A/p5uAjMeRlr4r9/sN1kKxVHfbLXs
         Km8DDW6xfHfCLwvSwwMYCtI/CE0YbMulDXplpjgGLBZqIlcqkSq2ss9yCbrpoBfT6Av4
         oYtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Twh7nBps;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=Em0YV2kKNaVcXCrxuwnO4WPg0dRdNaWVw/dwsMivzhs=;
        b=ZnA5RJS7phk61iE+zFD9qmO4HGir0biZKw1WtDG+FDOMSNwGpje13pNeDo6iSOv1fw
         50Mdru0CzoB4T27d9CMuqoSlocikqAZzIbigdVZ5MJI2xwC9r3ZPxD+MdbyUwnr5dbYm
         VdvAnht7+OitxFXGuTzQQ73b1y/x+2zIGFzgyUVJmBFc1rKIFIpM6QUjW4mQxcnlpbSf
         4vdo7uwqX7z6DUrp0rdOZrcjLOXozxtGuzZwSWcrH8Nb9o1soMtLkippVG8nBZaRK5On
         jW1oJHIRI0VNmq73kGBx4jWbmtGqWO0gOmuVA7NAkCmSPvh+stbOrjcQFDc7UsEDb/2b
         G1Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Em0YV2kKNaVcXCrxuwnO4WPg0dRdNaWVw/dwsMivzhs=;
        b=d9uWlQcBgz215oyJqqYSI+ECBfGWoSIL0tWkCf/2+uvzXNBuPQKTVflCWjwZiNop9B
         2gfqY6wmagOZMIRic8sKxpxHKWEsPzH6ynYL+JXL6s7AbC0kf/mqfcYofKwrPVJ+eBd7
         mSk/W5C/DkkAf1e5sIzQWZ7DfnxLuY+pUskxY42Qcl8drStbUmWYyNu5emlCVPsjvpIb
         0/12LpU7GFk6zTnjxBgfECBhuvN7+wc/g3bYYq+NIQMMsvLhTX82PQCiejwki+4lp45A
         bQdm/HWpM563p51PlhTXESp73kUIrHq4pZidUmZr3aT4SxMKnGWzfrmkA9uf4XrUZDwj
         a3Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0N3Yn6BUSSYHzN9r+wsUDS2sBSzfezjHqWWu74576s4a0yYFa1
	2U9EBPsHA4atc6Jy7tz/kJQ=
X-Google-Smtp-Source: AA6agR7XAeKDt56RjhOp90vwccpQbtImnKtIHHHUah9CAOT//CUHuy+kek1Nqfvt3IzODvhp/Uli5A==
X-Received: by 2002:a05:6512:3f1:b0:494:961b:4900 with SMTP id n17-20020a05651203f100b00494961b4900mr2851227lfq.436.1662069288048;
        Thu, 01 Sep 2022 14:54:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a236:0:b0:261:b5e5:82b6 with SMTP id i22-20020a2ea236000000b00261b5e582b6ls534879ljm.9.-pod-prod-gmail;
 Thu, 01 Sep 2022 14:54:47 -0700 (PDT)
X-Received: by 2002:a2e:a78f:0:b0:25f:dedf:efb8 with SMTP id c15-20020a2ea78f000000b0025fdedfefb8mr10581543ljf.317.1662069287132;
        Thu, 01 Sep 2022 14:54:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662069287; cv=none;
        d=google.com; s=arc-20160816;
        b=ZKKDkx/cc3H2qs5In+yKsLstDawip02aMwIp6I904yzf5e6kUUX+PhG6eNF+PnSfY1
         lyF2CpLzCQUtqIYCYz0SDK4saW/hz37VyhaUseuZ9OoztIKmIRtC98Wz5zBMCJtCcYHD
         hJhZncr3ytNL9w/6+Vy7QmLEqmifze9+IyrWfxuYGj1lvkqvMyZP/GyIG0ZKPV+yJlQd
         Mn4S/n3jjkRPVZtdQWHFls0vBxhuwUtDDalSs73Vt8tJFncg3GNUWbChZcUrfSKZJmQ6
         trxxAWcVUY8aVmnpMExvxPF9A45djr1ZUjnYlWrzSYNOEBcyNlatbnQFX1QlzT/Esdma
         oXkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=cwEaHM2MLzWFSTyYX5D3U7h9xVWN0G5HRpYdRjufwn0=;
        b=pcVVXNQnODTCIJJtcjsiNWk1kQ67RnvHXQGzvBJ4m+qVz6yqh9ix6i9pgbWqUeGXhb
         Yae1ndPB+Cq5+/hBO9IlTPpR1olL0kK//PoZar9csZt5g5d894Mg3nF1DQ8/6LW6+S2A
         z8z2DGWhHnl52UHYPlFIhEbFrEZZ1l6UmmdlcIq/maDXV+EuqBKybthfrZ9VyiyJrW1r
         h/f6gfGBi5xN40jN7t47FZ7eAOo6owpm8M+UAWPxtA66kxUJp6HcfRPMVWWieMNQiL8T
         x3z/cV2uLcWu8ycTzTFGOcX8nYY15MmybfSgbkT4T8orR/nG/35CICIWR1oo8RrWl6Vx
         ePiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Twh7nBps;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s3-20020a056512202300b0049469c093b9si6989lfs.5.2022.09.01.14.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 14:54:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 17:54:38 -0400
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
Message-ID: <20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
 <20220901173844.36e1683c@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901173844.36e1683c@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Twh7nBps;       spf=pass
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

On Thu, Sep 01, 2022 at 05:38:44PM -0400, Steven Rostedt wrote:
> On Tue, 30 Aug 2022 14:49:16 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
> 
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > This adds the ability to easily instrument code for measuring latency.
> > To use, add the following to calls to your code, at the start and end of
> > the event you wish to measure:
> > 
> >   code_tag_time_stats_start(start_time);
> >   code_tag_time_stats_finish(start_time);
> 
> So you need to modify the code to see what you want?

Figuring out the _correct_ place to measure is often a significant amount of the
total effort.

Having done so once, why not annotate that in the source code?

> For function length you could just do something like this:
> 
>  # cd /sys/kernel/tracing
>  # echo __skb_wait_for_more_packets > set_ftrace_filter
>  # echo 1 > function_profile_enabled
>  # cat trace_stat/function*
>   Function                               Hit    Time            Avg             s^2
>   --------                               ---    ----            ---             ---
>   __skb_wait_for_more_packets              1    0.000 us        0.000 us        0.000 us    
>   Function                               Hit    Time            Avg             s^2
>   --------                               ---    ----            ---             ---
>   __skb_wait_for_more_packets              1    74.813 us       74.813 us       0.000 us    
>   Function                               Hit    Time            Avg             s^2
>   --------                               ---    ----            ---             ---
>   Function                               Hit    Time            Avg             s^2
>   --------                               ---    ----            ---             ---
> 
> The above is for a 4 CPU machine. The s^2 is the square of the standard
> deviation (makes not having to do divisions while it runs).
> 
> But if you are looking for latency between two events (which can be kprobes
> too, where you do not need to rebuild your kernel):
> 
> From: https://man.archlinux.org/man/sqlhist.1.en
> which comes in: https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
>   if not already installed on your distro.
> 
>  # sqlhist -e -n wakeup_lat 'select end.next_comm as comm,start.pid,start.prio,(end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as delta from sched_waking as start join sched_switch as end on start.pid = end.next_pid where start.prio < 100'
> 
> The above creates a synthetic event called "wakeup_lat" that joins two
> events (sched_waking and sched_switch) when the pid field of sched_waking
> matches the next_pid field of sched_switch. When there is a match, it will
> trigger the wakeup_lat event only if the prio of the sched_waking event is
> less than 100 (which in the kernel means any real-time task). The
> wakeup_lat event will record the next_comm (as comm field), the pid of
> woken task and the time delta in microseconds between the two events.

So this looks like it's gotten better since I last looked, but it's still not
there yet.

Part of the problem is that the tracepoints themselves are in the wrong place:
your end event is when a task is woken up, but that means spurious wakeups will
cause one wait_event() call to be reported as multiple smaller waits, not one
long wait - oops, now I can't actually find the thing that's causing my
multi-second delay.

Also, in your example you don't have it broken out by callsite. That would be
the first thing I'd need for any real world debugging.

So, it looks like tracing has made some progress over the past 10 years, but
for debugging latency issues it's still not there yet in general. I will
definitely remember function latency tracing the next time I'm doing performance
work, but I expect that to be far too heavy to enable on a live server.

This thing is only a couple hundred lines of code though, so perhaps tracing
shouldn't be the only tool in our toolbox :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901215438.gy3bgqa4ghhm6ztm%40moria.home.lan.
