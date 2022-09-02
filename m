Return-Path: <kasan-dev+bncBCU73AEHRQBBBWMZYWMAMGQEAMZYMTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A2C45AA43F
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 02:22:51 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id g19-20020a056512119300b00492d83ae1d5sf150914lfr.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 17:22:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662078170; cv=pass;
        d=google.com; s=arc-20160816;
        b=gfFj4xgHmG63E82UYDsB8SekmGEymbOthEnIph115SWKh+dLcik1WbDv43pS5Bl+JN
         6/LF0cvixESmKb65k7MkVnlXS/kNnetEW2+oOiGq6xfYXOlARnocLDv8V992S7nfPmoH
         DYsPiVl7hMOOfmNNLJ7yyW4IOUyDEO0k6mCsBcDbTEYNmt9s7t3T9gEyoq3lkk2p4LSo
         hzLxwniq6A+VRduzUxZX5qvVhKnAOh0dM3v+N4ImODuvCh+C4w2QTtGYs+U3e6OPSJ1n
         ubSrn9Ub0/m40bF3btCCo4HimJpGo9e4uqyDDoH+j7PxTFZF34C3NQAD3mN2JQUdFfN/
         KdEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3BePKJqsKDZsUmA9OCPu+d0/FnVn9xymN+bl+gd9AmQ=;
        b=dmSJZYwA1KAoaoI+11kQ0t83TaIxKhJtfJ249ZIR7Mb7P/Ft/zxV4a/napALz4GAX8
         UZcovmzzXWEcosxVZpcc6tCyRw3ZD2THk5MHqKYeONVTVoNAatblaL98gKyR7C66dFb3
         9veYWaUxWXgsAhofZK5pnMjy1lx8K/sTSkOlwtTGtxSZbhxeZLD1RLUN7zibf1uO7TAj
         w1FqTXL9nMxXqSflKoU+meaRqRcgrl5wzi2luirn6ZgDIWghpnY48f8Q7XK/m0VhrKCO
         kJ8KDl9ioYcIWCkV79M0+ajhfaXxoPJ13zsp/orFyw3Ycv5zhf3dILhFYudmgVas7hgR
         BHvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=3BePKJqsKDZsUmA9OCPu+d0/FnVn9xymN+bl+gd9AmQ=;
        b=PE3o8UHWVClmqSfmYTtCSZ7NmhNQlxmaKi11gtc2hPeeMzhTEyBlRLZw0rEv/4TI4m
         odmMLB/zJFbaOpvm6i0Kr8u0LUOYBoBYmwiKL53zodgLu18ogWAzLddmqMdSedQMGTPN
         8MZEburOw22x7iRqcBJ+vUKfTNesl5nLf1oqyE/WNthJht8r6ezbPlbNVMbrMb8dTruv
         3LzBto6Mn1S/m+9NhiQ30KBdalmem5HaYnc7WpDxgRwc7r74e+X03xfPPwMCOgJO4JlQ
         GOptZjzFK6n7SICuwTmMKBYDd/KSW/04LI8oiBxd01B1R4NuAlPaYAQjZzUgOZ64L0tF
         K89w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=3BePKJqsKDZsUmA9OCPu+d0/FnVn9xymN+bl+gd9AmQ=;
        b=WCSlb1xjJ7rIUSBU6SH5YTbuP0zhTca09PtNEVl/ltP9clQyM8ihgbtjNKg2GX5I9P
         1XW05vJ0dUPetDL5EPeWwjPyJlLUVGrAdxMTsfCoP5lpHYMB04mY8k5FviyJhK9U1q52
         01Ji3qqe31uK27sNtgsIfh74R8B8UJ+Hl8gyw2WTCNtyN3aE/GBOMqX/OLyRnONl6uOM
         G7moDS714mEQDQpNg7pR8CCfFs/AdAA3a3RjEe/TLCwVGGcmGYx7LyNjx9Ir4RKoifHr
         r62rZ9jSMZxX+NpJxtZzdsdW95GVB8t6iCCRhwnhoF6hLWSobk4o+F/Oj1H1dwOLJf+6
         HSJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3SYsgiIuoM84rdadX6k2KSwECTqCAokbRsJo7444qKMV3bddVH
	/eha7eTiY2vjS7jWxjKaBoE=
X-Google-Smtp-Source: AA6agR4Aq9oebRlVTk2wnK34Yj8hct8hz3htSO02u8z1XleQS18SECtbqAyXFpAAibrOiOJcwwKDzA==
X-Received: by 2002:a05:6512:1399:b0:486:2ae5:be71 with SMTP id p25-20020a056512139900b004862ae5be71mr10943829lfa.246.1662078170301;
        Thu, 01 Sep 2022 17:22:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls370328lfo.1.-pod-prod-gmail;
 Thu, 01 Sep 2022 17:22:48 -0700 (PDT)
X-Received: by 2002:a05:6512:168a:b0:492:ca8a:ae6f with SMTP id bu10-20020a056512168a00b00492ca8aae6fmr12264579lfb.533.1662078168808;
        Thu, 01 Sep 2022 17:22:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662078168; cv=none;
        d=google.com; s=arc-20160816;
        b=utkJ/Q4MOWXXMDC/N8GBEJIZR9Lx+4qF97ElybSGQETH60wfiDYH/v5dvuzQUsm03K
         8gDv9lRi/AykaiaJhW3uksU2z7BbPw+kC7Y+gux99wPTyaOnIMoi8x/9ncd4TcuiWzIw
         Dm4jVNweATvn33JiCDXmGNPlbscjOmdZqMUJmbpnR/5SWaR8273kEFxCsUsVC45HDsG/
         q9/q1n/pggiVY5E9Vvym7lQME8q2RUUXbWpjcOwyGZdScYlciC9v4Hc617M4zstvv6m0
         fZRFujT9w44wiBTnmhcQgYBtRrW2REu6XL0CKgW2zyq6/OlLSYHmwB7f+hbTCq3BFksk
         2mHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=splmNXP6gB9pzywRsbHHNQLvnDQojNf2k4oIJI4w1yM=;
        b=V0clG+5e0GgFgOjsbyEeP5GZVCiSNUh5NLgZrPCCdsMowrWce1bkc/k4NKHlbX5EHb
         yjl0h6wxRp8Ko+GATtN6blh991GnfMacidW6e0WB72z+zcFxB/A+ZmDJDbJ11+3WWZNn
         TWBQ7SLc6gxsfye0ckRFek60J2OBiAL1XsPav4hDxW1bJMrW5z03Or0hg0aukWmk4Xyj
         B6ySXAC6xBvK7HDUj7pQczRp6z2OB9HiRe9MB2o3u3gvOQkNZwugc7l2i+jR5mzrYSbk
         oEOmvId+pGAqw5yYoXu0Om9DnUsh5EuvX3OTZqh0dmVdXRSNdTgUmxrUBDp+QOMVOG5t
         6VeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id x20-20020a056512079400b00492ea683e72si23086lfr.2.2022.09.01.17.22.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 17:22:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 800D3B825DB;
	Fri,  2 Sep 2022 00:22:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7C920C433D6;
	Fri,  2 Sep 2022 00:22:40 +0000 (UTC)
Date: Thu, 1 Sep 2022 20:23:11 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
 jbaron@akamai.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
 iommu@lists.linux.dev, kasan-dev@googlegroups.com,
 io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
 xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
 linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901202311.546a53b5@gandalf.local.home>
In-Reply-To: <20220901225515.ogg7pyljmfzezamr@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-28-surenb@google.com>
	<20220901173844.36e1683c@gandalf.local.home>
	<20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
	<20220901183430.120311ce@gandalf.local.home>
	<20220901225515.ogg7pyljmfzezamr@moria.home.lan>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
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

On Thu, 1 Sep 2022 18:55:15 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Thu, Sep 01, 2022 at 06:34:30PM -0400, Steven Rostedt wrote:
> > On Thu, 1 Sep 2022 17:54:38 -0400
> > Kent Overstreet <kent.overstreet@linux.dev> wrote:  
> > > 
> > > So this looks like it's gotten better since I last looked, but it's still not
> > > there yet.
> > > 
> > > Part of the problem is that the tracepoints themselves are in the wrong place:
> > > your end event is when a task is woken up, but that means spurious wakeups will  
> > 
> > The end event is when a task is scheduled onto the CPU. The start event is
> > the first time it is woken up.  
> 
> Yeah, that's not what I want. You're just tracing latency due to having more
> processes runnable than CPUs.
> 
> I don't care about that for debugging, though! I specifically want latency at
> the wait_event() level, and related - every time a process blocked _on some
> condition_, until that condition became true. Not until some random, potentially
> spurious wakeup.

Ideally this would be better if we could pass the stack trace from one
event to the next, but that wouldn't be too hard to implement. It just
needs to be done.

But anyway:

 # echo 'p:wait prepare_to_wait_event' > /sys/kernel/tracing/kprobe_events

// created an event on prepare_to_wait_event as that's usually called just
// before wait event.

 # sqlhist -e -n wait_sched 'select start.common_pid as pid,(end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as delta from wait as start join sched_switch as end on start.common_pid = end.prev_pid where end.prev_state & 3'

// Create a "wait_sched" event that traces the time between the
// prepare_to_wait_event call and the scheduler. Only trigger it if the
// schedule happens in the interruptible or uninterruptible states.

 # sqlhist -e -n wake_sched 'select start.pid,(end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as delta2 from wait_sched as start join sched_switch as end on start.pid = end.next_pid where start.delta < 50'

// Now attach the wait_event to the sched_switch where the task gets
// scheduled back in. But we are only going to care if the delta between
// the prepare_to_wait_event and the schedule is less that 50us. This is a
// hack to just care about where a prepare_to_wait_event was done just before
// scheduling out.

 # echo 'hist:keys=pid,delta2.buckets=10:sort=delta2' > /sys/kernel/tracing/events/synthetic/wake_sched/trigger

// Now we are going to look at the deltas that the task was sleeping for an
// event. But this just gives pids and deltas.

 # echo 'hist:keys=pid,stacktrace if delta < 50' >> /sys/kernel/tracing/events/synthetic/wait_sched/trigger

// And this is to get the backtraces of where the task was. This is because
// the stack trace is not available at the schedule in, because the
// sched_switch can only give the stack trace of when a task schedules out.
// Again, this is somewhat a hack.

 # cat /sys/kernel/tracing/events/synthetic/wake_sched/hist
# event histogram
#
# trigger info: hist:keys=pid,delta2.buckets=10:vals=hitcount:sort=delta2.buckets=10:size=2048 [active]
#

{ pid:       2114, delta2: ~ 10-19 } hitcount:          1
{ pid:       1389, delta2: ~ 160-169 } hitcount:          1
{ pid:       1389, delta2: ~ 660-669 } hitcount:          1
{ pid:       1389, delta2: ~ 1020-1029 } hitcount:          1
{ pid:       1189, delta2: ~ 500020-500029 } hitcount:          1
{ pid:       1189, delta2: ~ 500030-500039 } hitcount:          1
{ pid:       1195, delta2: ~ 500030-500039 } hitcount:          2
{ pid:       1189, delta2: ~ 500040-500049 } hitcount:         10
{ pid:       1193, delta2: ~ 500040-500049 } hitcount:          3
{ pid:       1197, delta2: ~ 500040-500049 } hitcount:          3
{ pid:       1195, delta2: ~ 500040-500049 } hitcount:          9
{ pid:       1190, delta2: ~ 500050-500059 } hitcount:         55
{ pid:       1197, delta2: ~ 500050-500059 } hitcount:         51
{ pid:       1191, delta2: ~ 500050-500059 } hitcount:         61
{ pid:       1198, delta2: ~ 500050-500059 } hitcount:         56
{ pid:       1195, delta2: ~ 500050-500059 } hitcount:         48
{ pid:       1192, delta2: ~ 500050-500059 } hitcount:         54
{ pid:       1194, delta2: ~ 500050-500059 } hitcount:         50
{ pid:       1196, delta2: ~ 500050-500059 } hitcount:         57
{ pid:       1189, delta2: ~ 500050-500059 } hitcount:         48
{ pid:       1193, delta2: ~ 500050-500059 } hitcount:         52
{ pid:       1194, delta2: ~ 500060-500069 } hitcount:         12
{ pid:       1191, delta2: ~ 500060-500069 } hitcount:          2
{ pid:       1190, delta2: ~ 500060-500069 } hitcount:          7
{ pid:       1198, delta2: ~ 500060-500069 } hitcount:          9
{ pid:       1193, delta2: ~ 500060-500069 } hitcount:          6
{ pid:       1196, delta2: ~ 500060-500069 } hitcount:          5
{ pid:       1192, delta2: ~ 500060-500069 } hitcount:          9
{ pid:       1197, delta2: ~ 500060-500069 } hitcount:          9
{ pid:       1195, delta2: ~ 500060-500069 } hitcount:          6
{ pid:       1189, delta2: ~ 500060-500069 } hitcount:          6
{ pid:       1198, delta2: ~ 500070-500079 } hitcount:          1
{ pid:       1192, delta2: ~ 500070-500079 } hitcount:          2
{ pid:       1193, delta2: ~ 500070-500079 } hitcount:          3
{ pid:       1194, delta2: ~ 500070-500079 } hitcount:          2
{ pid:       1191, delta2: ~ 500070-500079 } hitcount:          3
{ pid:       1190, delta2: ~ 500070-500079 } hitcount:          1
{ pid:       1196, delta2: ~ 500070-500079 } hitcount:          1
{ pid:       1193, delta2: ~ 500080-500089 } hitcount:          1
{ pid:       1192, delta2: ~ 500080-500089 } hitcount:          1
{ pid:       1196, delta2: ~ 500080-500089 } hitcount:          2
{ pid:       1194, delta2: ~ 500090-500099 } hitcount:          1
{ pid:       1197, delta2: ~ 500090-500099 } hitcount:          1
{ pid:       1193, delta2: ~ 500090-500099 } hitcount:          1
{ pid:         61, delta2: ~ 503910-503919 } hitcount:          1
{ pid:         61, delta2: ~ 503920-503929 } hitcount:          1
{ pid:         61, delta2: ~ 503930-503939 } hitcount:          1
{ pid:         61, delta2: ~ 503960-503969 } hitcount:         15
{ pid:         61, delta2: ~ 503970-503979 } hitcount:         18
{ pid:         61, delta2: ~ 503980-503989 } hitcount:         20
{ pid:         61, delta2: ~ 504010-504019 } hitcount:          2
{ pid:         61, delta2: ~ 504020-504029 } hitcount:          1
{ pid:         61, delta2: ~ 504030-504039 } hitcount:          2
{ pid:         58, delta2: ~ 43409960-43409969 } hitcount:          1

Totals:
    Hits: 718
    Entries: 54
    Dropped: 0

The above is useless without the following:

# cat /sys/kernel/tracing/events/synthetic/wait_sched/hist 
# event histogram
#
# trigger info: hist:keys=pid:vals=hitcount:__arg_1618_2=pid,__arg_1618_3=common_timestamp.usecs:sort=hitcount:size=2048:clock=global if delta < 10 [active]
#

{ pid:        612 } hitcount:          1
{ pid:        889 } hitcount:          2
{ pid:       1389 } hitcount:          3
{ pid:         58 } hitcount:          3
{ pid:       2096 } hitcount:          5
{ pid:         61 } hitcount:        145
{ pid:       1196 } hitcount:        151
{ pid:       1190 } hitcount:        151
{ pid:       1198 } hitcount:        153
{ pid:       1197 } hitcount:        153
{ pid:       1195 } hitcount:        153
{ pid:       1194 } hitcount:        153
{ pid:       1191 } hitcount:        153
{ pid:       1192 } hitcount:        153
{ pid:       1189 } hitcount:        153
{ pid:       1193 } hitcount:        153

Totals:
    Hits: 1685
    Entries: 16
    Dropped: 0


# event histogram
#
# trigger info: hist:keys=pid,stacktrace:vals=hitcount:sort=hitcount:size=2048 if delta < 10 [active]
#

{ pid:       1389, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         pipe_read+0x318/0x420
         new_sync_read+0x18b/0x1a0
         vfs_read+0xf5/0x190
         ksys_read+0xab/0xe0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:          3
{ pid:       1189, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:         61, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         schedule_timeout+0x88/0x160
         kcompactd+0x364/0x3f0
         kthread+0x141/0x170
         ret_from_fork+0x22/0x30
} hitcount:         28
{ pid:       1194, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1197, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1198, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1191, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1196, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1192, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1195, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1190, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28
{ pid:       1193, stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule+0x72/0x110
         read_events+0x119/0x190
         do_io_getevents+0x72/0xe0
         __x64_sys_io_getevents+0x59/0xc0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
} hitcount:         28

Totals:
    Hits: 311
    Entries: 12
    Dropped: 0

Now we just need a tool to map the pids of the delta histogram to the pids
of the stack traces to figure out where the issues may happen.

The above is just to show that there's a lot of infrastructure already
there that does a lot of this work, but needs improvement. My theme to this
email is to modify what's there to make it work for you before just doing
everything from scratch, and then we have a bunch of stuff that only does
what we want, but is not flexible to do what others may want.

> 
> 
> > Not the prettiest thing to read. But hey, we got the full stack of where
> > these latencies happened!  
> 
> Most of the time I _don't_ want full stacktraces, though!

We could easily add a feature to limit how much you want to trace. Perhaps even
a skip level. That is, add skip and depth options to the stacktrace field.

> 
> That means I have a ton more output to sort through, and the data is far more
> expensive to collect.

That's what user space tools are for ;-)

> 
> I don't know why it's what people go to first - see the page_owner stuff - but
> that doesn't get used much either because the output is _really hard to sort
> through_.
> 
> Most of the time, just a single file and line number is all you want - and
> tracing has always made it hard to get at that.

Because we would need to store too much dwarf information in the kernel to
do so. But user space could do this for you with the function/offset
information.

> 
> 
> > Yes, it adds some overhead when the events are triggered due to the
> > stacktrace code, but it's extremely useful information.
> >   
> > > 
> > > So, it looks like tracing has made some progress over the past 10
> > > years, but for debugging latency issues it's still not there yet in
> > > general. I  
> > 
> > I call BS on that statement. Just because you do not know what has been
> > added to the kernel in the last 10 years (like you had no idea about
> > seq_buf and that was added in 2014) means to me that you are totally
> > clueless on what tracing can and can not do.
> > 
> > It appears to me that you are too focused on inventing your own wheel
> > that does exactly what you want before looking to see how things are
> > today. Just because something didn't fit your needs 10 years ago
> > doesn't mean that it can't fit your needs today.  
> 
> ...And the ad hominem attacks start.

Look, you keep making comments about the tracing infrastructure that you
clearly do not understand. And that is pretty insulting. Sorry, I'm not
sure you realize this, but those comments do turn people off and their
responses will start to become stronger.

> 
> Steve, I'm not attacking you, and there's room enough in this world for
> the both of us to be doing our thing creating new and useful tools.

You seem to push back hard when people suggest improving other utilities
to suite your needs.

> 
> > I'm already getting complaints from customers/users that are saying
> > there's too many tools in the toolbox already. (Do we use
> > ftrace/perf/bpf?). The idea is to have the tools using mostly the same
> > infrastructure, and not be 100% off on its own, unless there's a clear
> > reason to invent a new wheel that several people are asking for, not
> > just one or two.  
> 
> I would like to see more focus on usability.

Then lets make the current tools more usable. For example, the synthetic
event kernel interface is horrible. It's an awesome feature that wasn't
getting used due to the interface. This is why I created "sqlhist". It's
now really easy to create synthetic events with that tool. I agree, focus
on usability, but that doesn't always mean to create yet another tool. This
reminds me of:

   https://xkcd.com/927/


> 
> That means, in a best case scenario, always-on data collection that I can
> just look at, and it'll already be in the format most likely to be useful.
> 
> Surely you can appreciate the usefulness of that..?

I find "runtime turn on and off" better than "always on". We have
static_branches today (aka jump labels). I would strongly suggest using
them. You get them automatically from tracepoints . Even sched_stats are
using these.

> 
> Tracing started out as a tool for efficiently getting lots of data out of
> the kernel, and it's great for that. But I think your focus on the cool
> thing you built may be blinding you a bit to alternative approaches...

I actually work hard to have the tracing infrastructure help out other
approaches. perf and bpf use the ftrace infrastructure because it is
designed to be modular. Nothing is "must be the ftrace way". I'm not against
the new features you are adding, I just want you to make a little more
effort in incorporating other infrastructures (and perhaps even improving
that infrastructure) to suite your needs.

If ftrace, perf, bpf can't do what you want, take a harder look to see if
you can modify them to do so.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901202311.546a53b5%40gandalf.local.home.
