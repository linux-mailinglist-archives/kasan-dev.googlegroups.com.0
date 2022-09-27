Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCO2ZOMQMGQE23ZGOGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 999215EC2B6
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 14:31:07 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id z18-20020a2e9652000000b0026c17cc5a45sf2554288ljh.21
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 05:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664281866; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hz5PpXyrmwLofMYrATNEN9f/8umkRvehdQPNStRTlHcoDvpWkVekc1tKGYzvfyXXbN
         MCbPqgp8NOIzCr9xSq6/xaXMe7wmJYATccq9Kazlvr38lf2yvfrgF675HtCvXI6j5ef0
         V64LikMuMwTT1J6Xm77z+xSSk1NafgozQDl9fbPEOv0kb3iV63TKxcsNhfDhaNvwvvt+
         0eEzv90dxKWiFUY7MzBS1NPya5lqLatOQZJ8fgeTwULBJ3/1MTqT+6V17g6vgSCfjk+X
         8Pb26Cl67d6zYZAk+NB6pqIVafV+R280S0o2pTfkyzVPOrMTVXGMGNZmERiAn8XBFtaa
         j+Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zSxnKVvp1eQQxGUkJIWS2GgOCVj1379dxfWcTu564Lc=;
        b=gB/39Oxrbke0mn42DKSTK0nlKmvrucJBMm/BUDgoucmKNqzenBH3O0g/vSZ9X5IK2b
         qxqLMIcyap1/b+Kordxqyh7eN3UBfDB0wdu0Ny1FVgE4nY3xBZsYydsS8D1zh9jrsd5r
         ExpwqqAw5m1UyuxhmZbE7ENHEdsVu666M5iCb95nFe2VxL0GvXyH9sdoOM1/AR7bWBhN
         n8vUrHmUYbTpbY0qo8j0a/NqE29iyRPwKaEceAJIsmZc0i+R0Ts7S2dKHLSnJjp9U+pa
         I/Fv8oEEDbhzSq1YI2OHR1UFT1tab7FJhqh5ffwz0wEJM0AoU8JG34ElAHs2YcVX/5XV
         u6Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="T/uniFHO";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=zSxnKVvp1eQQxGUkJIWS2GgOCVj1379dxfWcTu564Lc=;
        b=cj7TRrIk0WUpKdPaSzCs7gscyEkJVEXVlkB8vQ9MbfKXLgPKItRleovx8gXCHyzpb+
         tiOQo7MtMgma4JUuhTElsKW2MoxBAQ6F4nxfnCBt+TEiNZiYkeOW1UAh50m5B6sl6Ghx
         gNfaBkNOL5PZKcSSKGQt7wVpfiwD0LBSO+vsKmJDpNF5rPMJXtgvu+MdNQh4OiQnrW3w
         JMP/0lBbi0t8Twu2mALrXbigWYI/LPE2PlAoEoo9gAX4vYPT5EUiu45ajU1VDrEun/EV
         SvU67bs0ybVu+IOcJEeJxiCZ+9+rQ2jwHq/RCcQwIoMoRTW+T9dZ5fxGpNeaDgrozbKl
         URGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=zSxnKVvp1eQQxGUkJIWS2GgOCVj1379dxfWcTu564Lc=;
        b=rdd6iExm64RYqT03uGhA39f57bAl9bu+OkXZ//opHboFW6K9EZdACeAvTigRJpWZff
         +uE3c3S/VlKEytN/Yyyomcl+Pmpc+a3I3ZGv3yiDwrTOkgaAr9CUVT+RAUKddw8ezA9F
         Uq8m8r96rwCejXh4KbegMxHZlmzS5miL7loDaNFMTk1W1x9XBYhcFY9AfejRYSV1QaTh
         8Mo19YEirbDZRsjWgpdFJd/85ACm3wO4NRtJ4OBi2NcOuRVRVoJclGqzMMpnOrfOrfDA
         sIPFkiVm/a0YJ92SBmsLJZ8CQrbPQRUZMigRURZ+nF1HRs2lfmj7maXJa9XDG59WW2WH
         gU+w==
X-Gm-Message-State: ACrzQf05MRztEv+jZCXEVDhxqM7TxyCSByleIpS+q71E0U0GlvzdtBHZ
	3tpZyHg+BfeI6Q9HKEBfndY=
X-Google-Smtp-Source: AMsMyM5V9zM/8A4SgsiSv0mXcuwo8uYe+gYl34nzZ37Hvzc1bdVy6lDbyqULFCIQjnf7oWm6zqNL4g==
X-Received: by 2002:ac2:4f03:0:b0:495:ec98:bcac with SMTP id k3-20020ac24f03000000b00495ec98bcacmr10760344lfr.339.1664281865918;
        Tue, 27 Sep 2022 05:31:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8601:0:b0:26c:215b:964d with SMTP id a1-20020a2e8601000000b0026c215b964dls419645lji.11.-pod-prod-gmail;
 Tue, 27 Sep 2022 05:31:04 -0700 (PDT)
X-Received: by 2002:a05:651c:2212:b0:26c:2baf:652e with SMTP id y18-20020a05651c221200b0026c2baf652emr10133790ljq.84.1664281864424;
        Tue, 27 Sep 2022 05:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664281864; cv=none;
        d=google.com; s=arc-20160816;
        b=H2+B3FXE4Bceutyd++3x79K2UDdbjl+lhHS322uJjQOoXHAs42NLGNyw3vxZDS30w+
         nS4tcnjC9Tae19MHpC8Kpz8X4DYIdLJtWsfloRJiCLNSAYHqbGYs5sDTl8xRZ37ORIX/
         PTxEXXemoi7Oi2aQWlOG4HOyvgWJPuNKGgyHKIgYwihCv/J1l+CmwwgoLehCShjkN26d
         6MOubUq9DR0R1Y9y/RAiqgciuFHpoA2dEMGVkDTJWO0LrUNBLsPEYSfkKZPJ/mqckVIZ
         5PrD0xagoJdRGBKbHAnrHH2x3lu+ayAkNoIjT35j/rMWb0J+LTyaFsFRCWS3FRY0V3PQ
         w7vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5ft9ZKgcoilbmvfkfl9ZpGjG19NwykRqtF901VdwZnw=;
        b=y5v8Zz8UI+K8AdcmHpxkZiXKp87THAcpHF1Mnbvy67BTuvaGg8M4emWzQa2f9ZQv3Z
         GDDrBBFp1TDyUZJ1BPi2bl8IoeeGZbONWIexaKm8lZ2a9w3qgcNLNQU34XN/Y5PmO2Mn
         fzeFuITCEHSptcbzVV2KRaEdbBOEvbkWyHaw+M6fv/tD5BuWHXTy9xCp2yjyE4N2apD7
         7il+QGisWkqRE74ODHVqLwR1B+4bYEDYxkznEuwj1FrJZtAtaQuoaKXXWy0w1U/wzo+7
         pfR1zd6BB11MV1SJqohE3Eez17x5zWlMZpeW2zDnwMWGD3zb8nfMozRJNmxryZOezXtp
         NeMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="T/uniFHO";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id v16-20020ac25930000000b0049ade2c22e5si62249lfi.9.2022.09.27.05.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 05:31:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id u24so12974769edb.9
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 05:31:04 -0700 (PDT)
X-Received: by 2002:a05:6402:1554:b0:457:375e:7289 with SMTP id p20-20020a056402155400b00457375e7289mr11645505edx.171.1664281863992;
        Tue, 27 Sep 2022 05:31:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
        by smtp.gmail.com with ESMTPSA id bc25-20020a056402205900b0044ef2ac2650sm1141168edb.90.2022.09.27.05.31.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 05:31:03 -0700 (PDT)
Date: Tue, 27 Sep 2022 14:30:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <YzLtAG2bfRJ/vFRu@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220927121322.1236730-1-elver@google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="T/uniFHO";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as
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

On Tue, Sep 27, 2022 at 02:13PM +0200, Marco Elver wrote:
> Due to the implementation of how SIGTRAP are delivered if
> perf_event_attr::sigtrap is set, we've noticed 3 issues:
> 
> 	1. Missing SIGTRAP due to a race with event_sched_out() (more
> 	   details below).
> 
> 	2. Hardware PMU events being disabled due to returning 1 from
> 	   perf_event_overflow(). The only way to re-enable the event is
> 	   for user space to first "properly" disable the event and then
> 	   re-enable it.
> 
> 	3. The inability to automatically disable an event after a
> 	   specified number of overflows via PERF_EVENT_IOC_REFRESH.
> 
> The worst of the 3 issues is problem (1), which occurs when a
> pending_disable is "consumed" by a racing event_sched_out(), observed as
> follows:
> 
> 		CPU0			| 	CPU1
> 	--------------------------------+---------------------------
> 	__perf_event_overflow()		|
> 	 perf_event_disable_inatomic()	|
> 	  pending_disable = CPU0	| ...
> 	  				| _perf_event_enable()
> 					|  event_function_call()
> 					|   task_function_call()
> 					|    /* sends IPI to CPU0 */
> 	<IPI>				| ...
> 	 __perf_event_enable()		+---------------------------
> 	  ctx_resched()
> 	   task_ctx_sched_out()
> 	    ctx_sched_out()
> 	     group_sched_out()
> 	      event_sched_out()
> 	       pending_disable = -1
> 	</IPI>
> 	<IRQ-work>
> 	 perf_pending_event()
> 	  perf_pending_event_disable()
> 	   /* Fails to send SIGTRAP because no pending_disable! */
> 	</IRQ-work>
> 
> In the above case, not only is that particular SIGTRAP missed, but also
> all future SIGTRAPs because 'event_limit' is not reset back to 1.
> 
> To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
> of a separate 'pending_sigtrap', no longer using 'event_limit' and
> 'pending_disable' for its delivery.
> 
> During testing, this also revealed several more possible races between
> reschedules and pending IRQ work; see code comments for details.
> 
> Doing so makes it possible to use 'event_limit' normally (thereby
> enabling use of PERF_EVENT_IOC_REFRESH), perf_event_overflow() no longer
> returns 1 on SIGTRAP causing disabling of hardware PMUs, and finally the
> race is no longer possible due to event_sched_out() not consuming
> 'pending_disable'.
> 
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Debugged-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/perf_event.h |  2 +
>  kernel/events/core.c       | 85 ++++++++++++++++++++++++++++++++------
>  2 files changed, 75 insertions(+), 12 deletions(-)
> 
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index 907b0e3f1318..dff3430844a2 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -740,8 +740,10 @@ struct perf_event {
>  	int				pending_wakeup;
>  	int				pending_kill;
>  	int				pending_disable;
> +	int				pending_sigtrap;
>  	unsigned long			pending_addr;	/* SIGTRAP */
>  	struct irq_work			pending;
> +	struct irq_work			pending_resched;
>  
>  	atomic_t			event_limit;
>  
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 75f5705b6892..df90777262bf 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -2527,6 +2527,14 @@ event_sched_in(struct perf_event *event,
>  	if (event->attr.exclusive)
>  		cpuctx->exclusive = 1;
>  
> +	if (event->pending_sigtrap) {
> +		/*
> +		 * The task and event might have been moved to another CPU:
> +		 * queue another IRQ work. See perf_pending_event_sigtrap().
> +		 */
> +		WARN_ON_ONCE(!irq_work_queue(&event->pending_resched));

One question we had is if it's possible for an event to be scheduled in,
immediately scheduled out, and then scheduled in on a 3rd CPU. I.e. we'd
still be in trouble if we can do this:

	CPU0
	sched-out
		CPU1
		sched-in
		sched-out
			CPU2
			sched-in

without any IRQ work ever running. Some naive solutions so the
pending_resched IRQ work isn't needed, like trying to send a signal
right here (or in event_sched_out()), don't work because we've seen
syzkaller produce programs where there's a pending event and then the
scheduler moves the task; because we're in the scheduler we can deadlock
if we try to send the signal here.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzLtAG2bfRJ/vFRu%40elver.google.com.
