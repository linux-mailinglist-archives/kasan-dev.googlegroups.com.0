Return-Path: <kasan-dev+bncBCU73AEHRQBBBS6MYSMAMGQECCMIWLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A8695AA192
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 23:38:23 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id b10-20020a05622a020a00b003437e336ca7sf132607qtx.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 14:38:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662068300; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIN2NA1xVOZqq4wqZMknJIfItoI1rH0ZTXFAl+1UvhbdEmO1c/y+NYzFAI6YGgPYSX
         YS+MW70xKZj3bez71OMiE0Rvy4F5v/7ZBIByAhG3ACHgQcqW8VAeUdZIQlwrmGQBEb0R
         uTJbMX/pAygE8ChD0gmcMvq0q9BzmuYuRx0Q3zJY2cccPZUDNJiUF3Vf88VAJLokIgSa
         rkOJzHcH+kO3FqUNHGYjUxSVRx6YhLOV+StvYqTBBrQweMW56jyO36iSNKZChb+7AHHG
         L+Czl1eCXeQHxtV5CNxEh9sPYufoARzjDI6fagRI/9wbzCyLTRYsJCSZkWXTzrl472WW
         MGZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ej9HKwb6qU8R80Ju4mu8DXHzMWX4aCRNPx9/YA03L10=;
        b=BGXYzPEMJLunU3xOSQX7iv83eZndts/Di1xj53kg8MOeKnsoH9iEf8wTzZn8R46E/4
         94Ckx9EWdCeBHEq5bCjwNf7cgB/rqktOiQVLOLxWwsHJ9QEd4GRaE8EIDuOLsX+gdsMO
         I+GFnMsL0XfNnBorT10Up8y7kfL8sd1D8/FnSGnuMC94bD8cBBGIKFyk25toCjnubw2e
         xOfw2H9kuKVLo+kQFxYcC0gfjI7MI1mt7bEepmgWE183bV9ThVvfz++vqiGmdEptVCaC
         IsWNHiRpbDhAh0a/3RwV/Jz4VU7jNK65kL3/8/nOlD20E9hSG7EiM7BFT3G2SzcnqLqR
         r6WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=ej9HKwb6qU8R80Ju4mu8DXHzMWX4aCRNPx9/YA03L10=;
        b=r59aXeRiO4FpznZY+YVt+YEhFlzafYm8B6jKYM2z8nINgFWisG4ArRdkl5h6b1g6lf
         GkMln0aONX0ACncaFYzMCSO8OHvDRlLiN8P38/XY7Fimy9ntW2MNFxWaCXXHzGTmFvjB
         iG8JR8qZl9gT3rVn+QTH68AToPnPRBBZiLrQdLMqp9CBsoR8IzsHOmB9wdyvvgg/4X4D
         d0MruQj+dRI8Aq7wYyAE8qhSEIEijTMV9Jf5w680ZPLtm8io9OI0tL+v0l0y+HwSZEuz
         +rUpklOnC/QBOjLNnLdzASEx/seEXPZ7/PqYwzfTvu+LtiHLSnMZB13hS8nPvao8hWKa
         2XQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ej9HKwb6qU8R80Ju4mu8DXHzMWX4aCRNPx9/YA03L10=;
        b=xorECb2OmrpHY+0vPTDJkD8htfF8PljDGK71W9FX4MdGpZfHt48pX4o//Fx5W7Qy3V
         xusg9ZeTHEbC3NC2MXu9kc13zfzI0Bnfm+XxyueUdkxcxK2LCbQZ4FwZ7Y+gQxrOkwkA
         sYYJOJmPfwc8CwGKGgpfcZ8hni13jGqDiHJ5QUZCmtvtuSHcJD/Zi12APLzePpP15xEb
         BAqTBbcp4MQyGxwousXJrbBjL2UCxsMKa0Tfu4r94TlOKqXrBvMHYFlo0uZgudXZh0U1
         JTlI8Yu/9/DVYFuBagTvXQ9xhWdr3JiqJ464bz0hk48C6HkQVCtz/X7GHK4Rr4B7uwot
         lVHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3NXiq0HJmueBR1197CYM60nmxRRCUkoyLjdQ659RZqz6Xovx1S
	fwnQ4lk5kh5UisqocgyEXmg=
X-Google-Smtp-Source: AA6agR7sDdWIb6FDo3AvlFbcFE/ciDoDZglpGEgWv4BC5TMSwfgjpFXvGY0gU06wba36/o8h8aUNuA==
X-Received: by 2002:ad4:5aa4:0:b0:499:c0f:4436 with SMTP id u4-20020ad45aa4000000b004990c0f4436mr15964193qvg.24.1662068300001;
        Thu, 01 Sep 2022 14:38:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1e0f:b0:343:4bc:65d4 with SMTP id
 br15-20020a05622a1e0f00b0034304bc65d4ls2390995qtb.1.-pod-prod-gmail; Thu, 01
 Sep 2022 14:38:19 -0700 (PDT)
X-Received: by 2002:a05:622a:1194:b0:343:7547:9e12 with SMTP id m20-20020a05622a119400b0034375479e12mr25671865qtk.654.1662068299339;
        Thu, 01 Sep 2022 14:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662068299; cv=none;
        d=google.com; s=arc-20160816;
        b=IEQ4rUJaucyDV468BUYOzo+8aqW64jua1N6gBk0MaDetn2Q0eMs2N8ajbQolcjF973
         +lzhhS5lQnvkXwWJNV83IQRtFkUbzT6KZJQrzyM/FWT3VL0Km+mkhvlwM7JtWruJaHTr
         s3PxuAZJhDrcZK2Flb658QMtrzAAnedzl3kCIUc6ygWBUzvVCHKypigNCCudYnxzXega
         5J6uEeztdwZeLtAzW5S96WAqSvRmg0lCyC3/8fJ870HUqumT8Bjk9F6jpHM6uuSI9JFE
         TX2JIuRlfnZGKbjqyqO4xnJlPuKF0fHLPLQxFwegFAsmq8Mk8Rb5NOP3necMVmVTj3Cx
         oXLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Zrp1KYeQiKfBRiNUn9cvJB0DCIzwdh4tOoSfhQweczE=;
        b=QNx6TaQ5245OrCBZJSnGWopFV2DrPPiPNfsF1egPbRCgdUXjZq76kS7qQV3aCucDeg
         bR/KHGRHd1IroR3sexjygC5/U940kb3Q1gj1xMIQzMDKrvX+q4Q5hG7Y/VylaRrWchvy
         8OJk7ifU51urN61z/vJMzi2Rj5zFFcmz9fmL7O33pUiP8LtaUGoKPxsFPGLP0e7nsByF
         +pnTHANOZjx7AMy8O9TWNZjskYsmUrncvRt7AMMyePed9tZlmGqEmRQ6AySUE+doY1BP
         gs9PoVQ/XbMTp72zdmeE5ja3NB8Nt7mEoR6atbl7wHeMCULBjzSXNBI9AvnhiGbNnHlu
         /8Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j27-20020ac84c9b000000b00344e41c5e4bsi641749qtv.5.2022.09.01.14.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 14:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DBB5561F73;
	Thu,  1 Sep 2022 21:38:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 13146C433D6;
	Thu,  1 Sep 2022 21:38:12 +0000 (UTC)
Date: Thu, 1 Sep 2022 17:38:44 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901173844.36e1683c@gandalf.local.home>
In-Reply-To: <20220830214919.53220-28-surenb@google.com>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-28-surenb@google.com>
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

On Tue, 30 Aug 2022 14:49:16 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This adds the ability to easily instrument code for measuring latency.
> To use, add the following to calls to your code, at the start and end of
> the event you wish to measure:
> 
>   code_tag_time_stats_start(start_time);
>   code_tag_time_stats_finish(start_time);

So you need to modify the code to see what you want?

> 
> Stastistics will then show up in debugfs under
> /sys/kernel/debug/time_stats, listed by file and line number.
> 
> Stastics measured include weighted averages of frequency, duration, max
> duration, as well as quantiles.
> 
> This patch also instruments all calls to init_wait and finish_wait,
> which includes all calls to wait_event. Example debugfs output:
> 
> fs/xfs/xfs_trans_ail.c:746 module:xfs func:xfs_ail_push_all_sync
> count:          17
> rate:           0/sec
> frequency:      2 sec
> avg duration:   10 us
> max duration:   232 us
> quantiles (ns): 128 128 128 128 128 128 128 128 128 128 128 128 128 128 128
> 
> lib/sbitmap.c:813 module:sbitmap func:sbitmap_finish_wait
> count:          3
> rate:           0/sec
> frequency:      4 sec
> avg duration:   4 sec
> max duration:   4 sec
> quantiles (ns): 0 4288669120 4288669120 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048
> 
> net/core/datagram.c:122 module:datagram func:__skb_wait_for_more_packets
> count:          10
> rate:           1/sec
> frequency:      859 ms
> avg duration:   472 ms
> max duration:   30 sec
> quantiles (ns): 0 12279 12279 15669 15669 15669 15669 17217 17217 17217 17217 17217 17217 17217 17217

For function length you could just do something like this:

 # cd /sys/kernel/tracing
 # echo __skb_wait_for_more_packets > set_ftrace_filter
 # echo 1 > function_profile_enabled
 # cat trace_stat/function*
  Function                               Hit    Time            Avg             s^2
  --------                               ---    ----            ---             ---
  __skb_wait_for_more_packets              1    0.000 us        0.000 us        0.000 us    
  Function                               Hit    Time            Avg             s^2
  --------                               ---    ----            ---             ---
  __skb_wait_for_more_packets              1    74.813 us       74.813 us       0.000 us    
  Function                               Hit    Time            Avg             s^2
  --------                               ---    ----            ---             ---
  Function                               Hit    Time            Avg             s^2
  --------                               ---    ----            ---             ---

The above is for a 4 CPU machine. The s^2 is the square of the standard
deviation (makes not having to do divisions while it runs).

But if you are looking for latency between two events (which can be kprobes
too, where you do not need to rebuild your kernel):

From: https://man.archlinux.org/man/sqlhist.1.en
which comes in: https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
  if not already installed on your distro.

 # sqlhist -e -n wakeup_lat 'select end.next_comm as comm,start.pid,start.prio,(end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as delta from sched_waking as start join sched_switch as end on start.pid = end.next_pid where start.prio < 100'

The above creates a synthetic event called "wakeup_lat" that joins two
events (sched_waking and sched_switch) when the pid field of sched_waking
matches the next_pid field of sched_switch. When there is a match, it will
trigger the wakeup_lat event only if the prio of the sched_waking event is
less than 100 (which in the kernel means any real-time task). The
wakeup_lat event will record the next_comm (as comm field), the pid of
woken task and the time delta in microseconds between the two events.

 # echo 'hist:keys=comm,prio,delta.buckets=10:sort=delta' > /sys/kernel/tracing/events/synthetic/wakeup_lat/trigger

The above starts a histogram tracing the name of the woken task, the
priority and the delta (but placing the delta in buckets of size 10, as we
do not need to see every latency number).

 # chrt -f 20 sleep 1

Force something to be woken up that is interesting.

 # cat /sys/kernel/tracing/events/synthetic/wakeup_lat/hist
# event histogram
#
# trigger info: hist:keys=comm,prio,delta.buckets=10:vals=hitcount:sort=delta.buckets=10:size=2048 [active]
#

{ comm: migration/5                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: migration/2                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: sleep                                             , prio:         79, delta: ~ 10-19 } hitcount:          1
{ comm: migration/7                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: migration/4                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: migration/6                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: migration/1                                       , prio:          0, delta: ~ 10-19 } hitcount:          2
{ comm: migration/0                                       , prio:          0, delta: ~ 10-19 } hitcount:          1
{ comm: migration/2                                       , prio:          0, delta: ~ 20-29 } hitcount:          1
{ comm: migration/0                                       , prio:          0, delta: ~ 20-29 } hitcount:          1

Totals:
    Hits: 11
    Entries: 10
    Dropped: 0

That is a histogram of the wakeup latency of all real time tasks that woke
up. Oh, and it does not drop events unless the number of entries is bigger
than the size of the count of buckets, which I haven't actually
encountered, as there's 2048 buckets. But you can make it bigger with the
"size" attribute in the creation of the histogram.

-- Steve




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901173844.36e1683c%40gandalf.local.home.
