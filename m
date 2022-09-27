Return-Path: <kasan-dev+bncBDBK55H2UQKRBDH6ZSMQMGQEJPUFOWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id EB5145ECC13
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 20:21:01 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id m8-20020a2e97c8000000b0026c5b3be434sf2876666ljj.13
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 11:21:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664302861; cv=pass;
        d=google.com; s=arc-20160816;
        b=wwVD7pCt0n4LDh3PuznbvkDQz8b5zpWdNWyjpmfg0hha1HTe3RctNNg3t+1cL38DQi
         LeuEs6UCbYVovDkfVTbGVPHKTtNtQl4b+trIjm9H6EUpzrTflGRFF1zEAezDAOYwP2dn
         94SfIi2XitDkxy5YwJfZ49GlrB/EQTGglkcOGUv5d5TTgWXgl7TZd4sJNqQgQ55dtrAG
         DO48T7s8mug7u0mBdVWAshKIBYUgeS2g8z+m7lR4NvGj7PVHXwQDewnrOgTPx5S2sFNG
         BTwx4vJfGZPfLaF+p3BUF06E++j8qDYxIqUrEri/AL9p4YOOoQ/7yaDXw3X4WkHkJMfS
         VbEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mLL0AZuBRgHGl++aVjPtDMbCp1YyR/hIIpd2Ma4htZg=;
        b=Vps30UVFGiSxt+IYo+on7TlK7GgsWlwgBwugwgomFEuccPZOxOpu3AH4LDuR9npyoy
         vCh9dkGbzESExrMZiPivWZj8gjyeoFUgSRUAcpI3Bp15f7Oz21NJH2vN/+IvIQLTvu9z
         TN7wdq4r+a/vNNrIzvVU9DO9G4RvSQwvVIpYbsZ+xW/42bb8KVSrGLhK316oBSaS7u0I
         rs0Ifhlut+sb2mr6n2Ug2QsjEAIsk9sqnMbUF0VfLNnlDq1BEDCPOzu7ZF55PFmbKBaM
         a0AIAGcVS0urUQJ2PgCoMOAc+09XVPE1+pG/iU2+IMHmY7dcWHt4ngukbZ8v9YO25KIR
         TCbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZrYQtozP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=mLL0AZuBRgHGl++aVjPtDMbCp1YyR/hIIpd2Ma4htZg=;
        b=ee5Ksz4iTp8UTAh92Y4uyLGjuSANOWlGQmoXNKYMeC6ZGfTkLJ56QiNgCICPw65ldd
         BFPCGWaNp5aEL9EQY5DGrbTbJnLu3rD5bZpuWMekvD/0jjWOz7yRzJq9To23j/1izftK
         Fe6aGdRA6I+WbCpqqZqKAxNnHwWbkWUdAx6pkp+UnRXm8rooCg8VW7MLiN2MgJRP44Fm
         ZVPvH2QIBXQjfWNHuPVd95vFN/ygPwFXhT5nRNZRUxbmz1PwSWdMnTqe6n/3I1b5kKm/
         KFpsodQUEE5dZC8n2EN3gXkr2uzhx8neJDROLgVjBblLR2u5pWksxxI8X4ysmnWgBC+H
         Wv7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=mLL0AZuBRgHGl++aVjPtDMbCp1YyR/hIIpd2Ma4htZg=;
        b=X+Qcoo4kud2FYMTrV/HNPJ6qbzaT7z+lHKf4mbWsYna8qfl0bo5/1xHNwOjRRaXo20
         y2Lwhoq+E4PLpdryecSImiyfhqrde9SO1kXIclGAA1w8voSdUchzPXr/dFgRcFsW2VuP
         blrDfRTXYIMZ5wrB3W0rVVEFGhzTm3JaRnH24M1A2a60n1ReZyo1Ufe8Eq6FNkitVm7X
         7K5WCLv/mvevwwe86dNVSIo0ZiiK9DocMSApm05vbeM+WYIexOLFatyPi4EMvvUuWAeg
         OFSwQCzRtPNc3i4PDnXx5oK3tF5LsrveooiV+WjQwMbZvytoEHYTak6qE3kTRQat0g4F
         0Pgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2jeilmRhXqHu+tzFqBCvmleEJsWKaJuznOSAWwK4W7IbA6xpYO
	qLcFRWL/z7TQI9bZwmnoiY4=
X-Google-Smtp-Source: AMsMyM7kvOU1Bgutst1ECr8Jhuq5SxfbSKKyq/T8U8yVUdw987lI3FyBvRUQ9E7LZ7sPs2HGRUj+LA==
X-Received: by 2002:ac2:5a46:0:b0:498:f53b:d19a with SMTP id r6-20020ac25a46000000b00498f53bd19amr12452540lfn.674.1664302860845;
        Tue, 27 Sep 2022 11:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c9:0:b0:26b:e503:5058 with SMTP id x9-20020a2ea7c9000000b0026be5035058ls619948ljp.5.-pod-prod-gmail;
 Tue, 27 Sep 2022 11:20:59 -0700 (PDT)
X-Received: by 2002:a2e:b608:0:b0:26a:d179:8ecd with SMTP id r8-20020a2eb608000000b0026ad1798ecdmr10200877ljn.405.1664302859283;
        Tue, 27 Sep 2022 11:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664302859; cv=none;
        d=google.com; s=arc-20160816;
        b=pUN7n0Njs2scz8vUrnd+j2yTr2OyHmppHjhx9VM3SaVSNoti5Nvazs0frCead3Smf+
         qmClsdq3jPKIul8vF7Ux5doxStff6Lv2w6XMAoYnvFvKjXP/F4gPrBqbMlg2iFJYmlqs
         0z61W4XT1Ad2lsBdtb/LY0WkMXfH0BahBO1Gu4dNhY+VN/lJXom+DV6AWixP9jm0/z28
         WrAK0vrAdZYHoH24g8/0HeFdKydadl6vlZJjunYMcvXg6dwntafemCEupT45RSyJNMwi
         /iVoEQCHW4aVF1Pu46Tp05OruGrMwUaj99O7Zs7miT/6uMZXymL/Y0R1/Urv3znZtA6G
         XcnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BmhIzH6QeLzG1HzDb0h4B8ArGPxAu7f6HvFWMpAiIac=;
        b=AhY8t4rocLWfa89URNSom/3ucZb/OHhqVtWfRLHxlOtOJ6EWhDh/+k7G+w5BA/cuLo
         Pp10P8VDOg5Vk0nH3WyTT1i1swv3m2vSO2AOSQfK0/t9sfppBuLoxTvYohOvVDX826WL
         x4DuiJ5Y0dLuzOUV136bBLKnZGkfqMrGWNTLTk4qOu3Lz3TQOg2KAkwFBsd7qga8S0T9
         6w4tGw4jexRSQs/fxz0EpVRmfNfj8UWNJkFoeqQY5D077LbGwgIhVF6TJ0Bj6D8tVqQW
         dLjsU/JbltPZPxTD7i4du5uas8DiL68B3Lg+InjhYCS3tKTaYzjf62t/e66UH/HXkNTm
         ypEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZrYQtozP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id j15-20020a056512108f00b0048b38f379d7si96541lfg.0.2022.09.27.11.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 11:20:58 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1odFCR-00GMHf-3C; Tue, 27 Sep 2022 18:20:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DE8B530007E;
	Tue, 27 Sep 2022 20:20:53 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 951302BE05B2C; Tue, 27 Sep 2022 20:20:53 +0200 (CEST)
Date: Tue, 27 Sep 2022 20:20:53 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220927121322.1236730-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ZrYQtozP;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Sep 27, 2022 at 02:13:22PM +0200, Marco Elver wrote:
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

Perhaps use task_work_add() for this case? That runs on the
return-to-user path, so then it doesn't matter how many reschedules
happen in between.

The only concern is that task_work_add() uses kasan_record_aux_stack()
which obviously isn't NMI clean, so that would need to get removed or
made conditional.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzM/BUsBnX18NoOG%40hirez.programming.kicks-ass.net.
