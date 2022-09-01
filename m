Return-Path: <kasan-dev+bncBCU73AEHRQBBBXXGYSMAMGQEDOOGR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id EDC9C5AA320
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 00:34:07 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id o43-20020ab0596e000000b0038421e4c7desf247856uad.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 15:34:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662071646; cv=pass;
        d=google.com; s=arc-20160816;
        b=LweJAAhpyKIewpYJRDbyx4IaggrEty9EEUssuegTZ58kWNxSjhAp/75RyVDB6Qd0cB
         u2dJbjElbMtSQDvd2b+oOU/LohqpKzIezPc11el7gYmABDzI9J6HMYwu+weCZou+YzvO
         nOiJKaeZvmHHKo8DKZsWvoSpGhfwNVYP0bimrFhhRwhr46BX0/tBZI3UL0YFT0ZnNRfL
         DjVo+1shFe3w7GheSbBbge4mcE6S8cD7olOz4s2kvYCaSXzRTkAmTFK8zGG6SuJMeSII
         wsNeWZUTWEpylhXYVPSQee6q2dxSpzGybBOHt57a/C4hFlIIWntPAxtscB/XW3DZlKeG
         5sdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pN6pBFBWdEpR/UibX4K4wWlAsXzMpLWW73AbB0GnFj0=;
        b=p/G8gjq6bjl00GeQBmkXM3xHvXeP9oPfQ68dLkf4XRM94K8s+zLoybQNCxCpfg8idy
         CGt7JoR28MI9MeJ7JCBaVHTrEXpyYc3fibeAionhIseqDeIomI7XYrtHh4gi6n11wGWt
         CpZbDTl7TrOZtT7Tl3GuRVgAIfU1Es+5ax8uz6FYv1qxTJp3ObTdtNKLlm/ChUIgTjEY
         2wavNd2/+iHHE26e0+9EFyVg4kz2GmwkULfeC0pgD1UyK5sLXRPnObarfSwjSMYHGwd1
         rgCbSHSzZOvc9L9jDHzC+GiPhvzQ9+6QPJ3ZIjXfaewtb+4Igsjim26M3l+bSjTpw69S
         C5BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=pN6pBFBWdEpR/UibX4K4wWlAsXzMpLWW73AbB0GnFj0=;
        b=YUAA3FNmfI8l+Kiq2G9Z++emWUiGzQbr/XyjQUSHET8LovlGmWik5MYox9XFlgpE7D
         q2byuiYFnrqT2twdmZXMkTPIUipOvDDom+ZOwYkb/uKZLhtIUcUHs6iyVa707rtsSji9
         DZVkpy6TJQpp46A/7WCp94+EMbUcyJDHPbJjIFFrgBi6frz5mCe9u4ZwjOrj9H01DAmA
         f+7qrLvi+TeqhJSIkuUsknkZ/JZsPXTOi6kQYu03JJUZ8+89NI2P/t6lxMv2gCjP6rCP
         rUyvl80EjSIG49Wk9QtAk9piOqQw89m3Bf7Fd7L+4JZll9i0zeE6NvaWjnUSvKVBH8jR
         EiqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pN6pBFBWdEpR/UibX4K4wWlAsXzMpLWW73AbB0GnFj0=;
        b=5ryQnJTlLaZcjRAP0+7rppBinLJruiZxI3L0uhkV9xw3zGAGIYNv/wSEcD5tuaZ6hL
         CLYQqtN0MdCow3NpPuCCBUZqM1c0NmeymkVRuu6sG+eZniGRHDPMdVWDpiMywVYjoxI9
         ywmyhsdB8YZsVlLaWzoqgOFPw+PjY92ByDRSUzcnqLDBpik4gAX54THmIamNN03UZNZB
         EAlWV6BFvBcQEO9TFIuufQIiLWDrqjpFw1JTUJeMrALGRT+oovFRAXPsstWvulB78sET
         5tl8v+bqLvFD3Uarn96eStx1QrzH2lzIuQXyrgevVhn4XF3Ftk+aQHecmia6+tyJAY16
         xHig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0lEFuJNZmYJrXlnd15VKrguvkB3iAKiLxZpK4CvlNc7Gx9ne1b
	XvAz5wBmjlkBrLk26c3z3co=
X-Google-Smtp-Source: AA6agR6DZgfUHNS2uvFIBY03tUczjHzS2ifVJST6z/Kjg2MPZ61xQVeXC0LbH98Y3o9dDQ0HpOsKlw==
X-Received: by 2002:a1f:bd0e:0:b0:394:9da0:2449 with SMTP id n14-20020a1fbd0e000000b003949da02449mr5422413vkf.4.1662071646694;
        Thu, 01 Sep 2022 15:34:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c50b:0:b0:390:72fa:8274 with SMTP id e11-20020a67c50b000000b0039072fa8274ls629826vsk.11.-pod-prod-gmail;
 Thu, 01 Sep 2022 15:34:06 -0700 (PDT)
X-Received: by 2002:a67:ea0b:0:b0:391:7da:9d76 with SMTP id g11-20020a67ea0b000000b0039107da9d76mr6021587vso.84.1662071646062;
        Thu, 01 Sep 2022 15:34:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662071646; cv=none;
        d=google.com; s=arc-20160816;
        b=bo7qVlg7rGni70d8qpXXrRdYa6m6qml0lNgTyFjOnigkwPDo+o4ZcSMxmdnoRDtL6e
         UCfo4BmJRIuQt9TYgxB8eUAP8u/1Ed4JUkTTy+Mew5LpPn6uzQ+3+wJQpioeCFKBuIZa
         7FQm2W7ZYLfN/rygiAsCUfuF+eGnz09ERF4jp4RRTIMu/5+AWnbrrt5AFnMhUwEp0GWY
         f38scAPaeZ2RXnTi5XEPifrdAc1e9r/81C4ED2pt8Xv9ZwCOEaj6KpL+C/mK+K03264b
         QrNTOF46pySyhJJyN7gBA7ccXwTKSvcAOpbo7txMbJYfNdFj4oT/9jPD6EWgom6L1yqH
         82HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=FJWa6vjNRrko2wTbpjS3pF1fZSwWblEIFvsYjrvv2kY=;
        b=bb7vIkOMHHIyCkOp3ltCwrECqOTL9JLaScJNvhtKyn+0a6SrbJ9PWMBg+8JMT13gGh
         h+GToV5+2jS2Vqle6+Fq8TJfpY+P6mfGA9EG1mGvTqaszQo+RtLQ8vvGq8RRStHSRogu
         stAvfx4I7yUs+sRDLarxbY+NPqmlfj7MgbkvhoM/2IUPe4y6qUbJbtj1CjT18LTKxwt5
         O0YAOu0VY+i33opIOtRp5FkIzO+eVPBV7qTs4aXySh/+hdO086su74bfZAGJhD6R9cAw
         ahBnYL/KbbuBkK0khC1mqhv3Qi9MYXUily6jn7zRJhpZK+LrerB5GSWk5Ed7JhYdTBr1
         bZLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ba42-20020a056130042a00b0039f9be3edebsi26385uab.2.2022.09.01.15.34.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 15:34:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7F34562017;
	Thu,  1 Sep 2022 22:34:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9A46C433C1;
	Thu,  1 Sep 2022 22:33:59 +0000 (UTC)
Date: Thu, 1 Sep 2022 18:34:30 -0400
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
Message-ID: <20220901183430.120311ce@gandalf.local.home>
In-Reply-To: <20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-28-surenb@google.com>
	<20220901173844.36e1683c@gandalf.local.home>
	<20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
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

On Thu, 1 Sep 2022 17:54:38 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> So this looks like it's gotten better since I last looked, but it's still not
> there yet.
> 
> Part of the problem is that the tracepoints themselves are in the wrong place:
> your end event is when a task is woken up, but that means spurious wakeups will

The end event is when a task is scheduled onto the CPU. The start event is
the first time it is woken up.

> cause one wait_event() call to be reported as multiple smaller waits, not one
> long wait - oops, now I can't actually find the thing that's causing my
> multi-second delay.
> 
> Also, in your example you don't have it broken out by callsite. That would be
> the first thing I'd need for any real world debugging.

OK, how about this (currently we can only have 3 keys, but you can create
multiple histograms on the same event).

 # echo 'hist:keys=comm,stacktrace,delta.buckets=10:sort=delta' > /sys/kernel/tracing/events/synthetic/wakeup_lat/trigger

(notice the "stacktrace" in the keys)

# cat /sys/kernel/tracing/events/synthetic/wakeup_lat/hist
# event histogram
#
# trigger info: hist:keys=comm,stacktrace,delta.buckets=10:vals=hitcount:sort=delta.buckets=10:size=2048 [active]
#

{ comm: migration/2                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: migration/5                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: migration/1                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: migration/7                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: migration/0                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         start_kernel+0x595/0x5be
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: migration/4                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: rtkit-daemon                                      , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         preempt_schedule_common+0x2d/0x70
         preempt_schedule_thunk+0x16/0x18
         _raw_spin_unlock_irq+0x2e/0x40
         eventfd_write+0xc8/0x290
         vfs_write+0xc0/0x2a0
         ksys_write+0x5f/0xe0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
, delta: ~ 10-19} hitcount:          1
{ comm: migration/6                                       , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 10-19} hitcount:          7
{ comm: rtkit-daemon                                      , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 20-29} hitcount:          1
{ comm: rtkit-daemon                                      , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         preempt_schedule_common+0x2d/0x70
         preempt_schedule_thunk+0x16/0x18
         _raw_spin_unlock_irq+0x2e/0x40
         eventfd_write+0xc8/0x290
         vfs_write+0xc0/0x2a0
         ksys_write+0x5f/0xe0
         do_syscall_64+0x3b/0x90
         entry_SYSCALL_64_after_hwframe+0x61/0xcb
, delta: ~ 30-39} hitcount:          1
{ comm: rtkit-daemon                                      , stacktrace:
         event_hist_trigger+0x290/0x2b0
         event_triggers_call+0x52/0xe0
         trace_event_buffer_commit+0x193/0x240
         trace_event_raw_event_sched_switch+0x120/0x180
         __traceiter_sched_switch+0x39/0x50
         __schedule+0x310/0x700
         schedule_idle+0x26/0x40
         do_idle+0xb4/0xd0
         cpu_startup_entry+0x19/0x20
         secondary_startup_64_no_verify+0xc2/0xcb
, delta: ~ 40-49} hitcount:          1

Totals:
    Hits: 53
    Entries: 11
    Dropped: 0


Not the prettiest thing to read. But hey, we got the full stack of where
these latencies happened!

Yes, it adds some overhead when the events are triggered due to the
stacktrace code, but it's extremely useful information.

> 
> So, it looks like tracing has made some progress over the past 10 years,
> but for debugging latency issues it's still not there yet in general. I

I call BS on that statement. Just because you do not know what has been
added to the kernel in the last 10 years (like you had no idea about
seq_buf and that was added in 2014) means to me that you are totally
clueless on what tracing can and can not do.

It appears to me that you are too focused on inventing your own wheel that
does exactly what you want before looking to see how things are today. Just
because something didn't fit your needs 10 years ago doesn't mean that it
can't fit your needs today.


> will definitely remember function latency tracing the next time I'm doing
> performance work, but I expect that to be far too heavy to enable on a
> live server.

I run it on production machines all the time. With the filtering in place
it has very little overhead. Mostly in the noise. The best part is that it
has practically zero overhead (but can add some cache pressure) when it's
off, and can be turned on at run time.

The tracing infrastructure is very modular, you can use parts of it that
you need, without the overhead of other parts. Like you found out this week
that tracepoints are not the same as trace events. Because tracepoints are
just a hook in the code that anything can attach to (that's what Daniel's
RV work does). Trace events provide the stored data to be recorded.

I will note that the current histogram code overhead has increased due to
retpolines, but I have code to convert them from indirect calls to direct
calls via a switch statement which drops the overhead by 20%!

  https://lore.kernel.org/all/20220823214606.344269352@goodmis.org/


> 
> This thing is only a couple hundred lines of code though, so perhaps
> tracing shouldn't be the only tool in our toolbox :)

I'm already getting complaints from customers/users that are saying there's
too many tools in the toolbox already. (Do we use ftrace/perf/bpf?). The
idea is to have the tools using mostly the same infrastructure, and not be
100% off on its own, unless there's a clear reason to invent a new wheel
that several people are asking for, not just one or two.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901183430.120311ce%40gandalf.local.home.
