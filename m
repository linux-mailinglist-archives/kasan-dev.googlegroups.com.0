Return-Path: <kasan-dev+bncBCALX3WVYQORBCPN7CDAMGQEWQVS4SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E713B9844
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 23:41:30 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id q10-20020a056214018ab029027751ec9742sf4861668qvr.7
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jul 2021 14:41:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625175689; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+9HeWXRZAuSwCMEvlN+KUssCpecRZBa1tTZJ8qJVxjto2lHvuP4nKi5ePDBMg+Nz1
         eUJH0vJZlyUjsd6OwPwaGc0IseYdO4zkgmlPlj+BmyqG0uc4Z41wNs3IJa4uZPWT8SHh
         TVRtJIPUNK3Hl3IeHhapzhxhPGmd0A6TuS52++5BvPQ3sYmS6YiYbmZo04j9DkeKDwxK
         4/ntKAdNXm4hNDujoSYIAbpsX8aRF2/e/XCjavDEOHuI0mpgHMkSvoLNRjRNq++69yLo
         tzZV6BaW+vYFhfE/bn0RYSwoRSDr48SGohW1ArmXyMNQZ3etBRpcdhq04TtgijCcA7l+
         n5Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=e4wUpw84RUrlAfDVbfdKVU3dwBnd/NPfxK1jCaJbDw4=;
        b=bgHSiE+bfrgFDLQ5GNTlpy+2a6trF4KSQZoXyYLiuH8g0AnMRzQQLA/nWMZbVIrNBI
         YWpR3AGa5crv7NX0EYzGXsRGlmoZBrebDSH9DW0kq5kKpJ9X2x1r8BGZyh90/ZczTTMv
         iZvNOP47PSG2wMx0kp1io8GjbbbfBAkQc8jh/2aGoJN87mIrkNmK2wX1l2W3qVDxJtaA
         xI0Pmde29IHv0u8LG7pg65kwkdl7mtNht5+K0m2L0ESMYZEtFTSz8C+i/Ik7YfaRFuMq
         bs9V9PyOx2InWr4gdOFPOj19QbDA5Br9d63fQJT2+9RqN1Rl460hXoBO+ZOQn8/vg09m
         tbWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e4wUpw84RUrlAfDVbfdKVU3dwBnd/NPfxK1jCaJbDw4=;
        b=HniYV0iej/w5HvoGpW3exlbJQcXVrTv5p7X9f2MBrKcBoamphh7fiN8LbbMhBNSg5u
         6weVN/nfVZazCgB2EaK2sKs0BMzHCh3O5QpvFP5mvyDHvVTElXgGi3cPOxP8ltuPpugV
         hpaVVUJwMamcPpBOWL6Lfhl0Aw8irtABMv0XaZsVGsOP25BqaiArpTa2jAVPWJsSeeB0
         4chIs0IS5/23U+8xwENtZvuz3193d8dEuJLQyQXpbEJwJFroD4/Jt7qZNtCXlaR39jtl
         ODQQSGy5QWJNkdMmdYMI4jFeXxM8HYKp1nP1dCOPt5inmkJE8ojk/VrO1kitxkAK2Bhg
         8d+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e4wUpw84RUrlAfDVbfdKVU3dwBnd/NPfxK1jCaJbDw4=;
        b=jPVJTfMtldZo/62w7sovagIhZy5G21nMySKYIY2XiifSh2XaA1K/SmEegllUVh24RE
         P7JL0/dkGS8ZZb2Ji9FhjJnFjnxbZtZ9kO6s6rE07WPhiAj48l8nJUqQ8p2xFR6f6ab7
         gpKh6rs0p6BbMb5PnvslyQP1FYkpaESAJScCI7v5a12VlBW+Wu6Z4UVKGzZADwOJw66Y
         iFp6uhCJolJ0ZslStrVQbcSSViQSJV7aeEE3JoPEO9XJrE0LlKP0OGw7lE2bnX0Cjfqx
         PKJ3m24Yf6AQ1j8yPSyMhK3HxW6QwfsUFkdSOde629GSUEerXJGzC8LHVJfkXMOCpNV2
         frbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ayx560JIkBE8wBhFcXU6jjPhHk/XuOC/Q1MXKjnBsfApA9sRY
	t8PGW2Agjzgq5N61bUuIbIg=
X-Google-Smtp-Source: ABdhPJygATRy0d80ecOV08mC2W6j2tcHCekaGSySIq86YQeGPeSaXfiE9SBWTBJ2e7uroy9XPQ+VOg==
X-Received: by 2002:a37:a643:: with SMTP id p64mr2175638qke.344.1625175689305;
        Thu, 01 Jul 2021 14:41:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7a9a:: with SMTP id x26ls3385559qtr.7.gmail; Thu, 01 Jul
 2021 14:41:28 -0700 (PDT)
X-Received: by 2002:ac8:5b0d:: with SMTP id m13mr2012983qtw.364.1625175688900;
        Thu, 01 Jul 2021 14:41:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625175688; cv=none;
        d=google.com; s=arc-20160816;
        b=aW7C+mQF0YfjCHDQlBY2nQw/K1zU/JtCw1IUe4HF2iUvL5hSScohG0AYFVcCtuWYNz
         u5gvDD9Y+k/M6vaeXDE8JAbY53HYBtb2+Rd8kCl8QTh1oizEp+EnJcoGD5oWmxF+s65H
         9mRfGdToZ220cE2N0Vp/8lIAXRfbb8/NCD01GXRpaXUdrlVWSuYi0Tmxlkcg5DJSYplT
         oHKzD1V0FVO3BfhfL9O9h4fjVI2BsQ1AU4fhazkUeELoJ1xWlnCnZ4s1eL5ihWgbqeWA
         kZKTr53k/s1cjCJnETuq3OSVR+m24uAIAnFRldQ97B81RaTAXoEuImjuP2SwnRz8B6kx
         nW6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=jKsr1jd8Yg3mbEluBVHHfr5kZU+Yhh/ckJqTa3DD0uM=;
        b=INR+P1iyrDD1RODBunYPNa35k7OsydTioGfchmxDLdRnnzjMTKa5GPq4HEdwo8H2sl
         Bq636CBotuYtPZB6CQgI7heIrFViXUYvwVn2JzTB/9RQo+mHb6b4Mps3ZGYwznJM3bIX
         K0wvSEH/5GTX6o22Hs2+L7aAzg2XKD2Pl5wb4CMsWkK6zspaLSNjQqYxy8Xv6A7eSbe7
         ppr90Ucg7jLQxtdgjMEASiu7G0tSSqZn+RhCz9XgCFV+s8YJ/hsKGZ8SPDNPY6u1LkoR
         yXcq3+6KLeJpmnPx8sd0xdPVR7L1fEDuFXgJsdP2KuNjzimHdMLGwUCEFiETDFF9JyJP
         dJ1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id v14si102068qtp.2.2021.07.01.14.41.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Jul 2021 14:41:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lz4R2-00CqTz-JP; Thu, 01 Jul 2021 15:41:24 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:51614 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lz4R1-00CJeQ-F2; Thu, 01 Jul 2021 15:41:24 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org,  tglx@linutronix.de,  mingo@kernel.org,  kasan-dev@googlegroups.com,  linux-kernel@vger.kernel.org,  mingo@redhat.com,  acme@kernel.org,  mark.rutland@arm.com,  alexander.shishkin@linux.intel.com,  jolsa@redhat.com,  namhyung@kernel.org,  linux-perf-users@vger.kernel.org,  omosnace@redhat.com,  serge@hallyn.com,  linux-security-module@vger.kernel.org,  stable@vger.kernel.org,  Dmitry Vyukov <dvyukov@google.com>
References: <20210701083842.580466-1-elver@google.com>
Date: Thu, 01 Jul 2021 16:41:15 -0500
In-Reply-To: <20210701083842.580466-1-elver@google.com> (Marco Elver's message
	of "Thu, 1 Jul 2021 10:38:43 +0200")
Message-ID: <87h7hdn24k.fsf@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lz4R1-00CJeQ-F2;;;mid=<87h7hdn24k.fsf@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+7+SbuL4vTLyI6IaqmY8TWPh1qYr3dYsI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4941]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 503 ms - load_scoreonly_sql: 0.08 (0.0%),
	signal_user_changed: 11 (2.3%), b_tie_ro: 10 (1.9%), parse: 1.23
	(0.2%), extract_message_metadata: 4.7 (0.9%), get_uri_detail_list: 2.0
	(0.4%), tests_pri_-1000: 4.4 (0.9%), tests_pri_-950: 1.34 (0.3%),
	tests_pri_-900: 1.09 (0.2%), tests_pri_-90: 129 (25.7%), check_bayes:
	128 (25.4%), b_tokenize: 9 (1.8%), b_tok_get_all: 9 (1.8%),
	b_comp_prob: 2.8 (0.5%), b_tok_touch_all: 104 (20.7%), b_finish: 0.82
	(0.2%), tests_pri_0: 327 (65.0%), check_dkim_signature: 0.92 (0.2%),
	check_dkim_adsp: 2.7 (0.5%), poll_dns_idle: 0.74 (0.1%), tests_pri_10:
	2.2 (0.4%), tests_pri_500: 12 (2.4%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH v2] perf: Require CAP_KILL if sigtrap is requested
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

Marco Elver <elver@google.com> writes:

> If perf_event_open() is called with another task as target and
> perf_event_attr::sigtrap is set, and the target task's user does not
> match the calling user, also require the CAP_KILL capability.
>
> Otherwise, with the CAP_PERFMON capability alone it would be possible
> for a user to send SIGTRAP signals via perf events to another user's
> tasks. This could potentially result in those tasks being terminated if
> they cannot handle SIGTRAP signals.
>
> Note: The check complements the existing capability check, but is not
> supposed to supersede the ptrace_may_access() check. At a high level we
> now have:
>
> 	capable of CAP_PERFMON and (CAP_KILL if sigtrap)
> 		OR
> 	ptrace_may_access() // also checks for same thread-group and uid

Is there anyway we could have a comment that makes the required
capability checks clear?

Basically I see an inlined version of kill_ok_by_cred being implemented
without the comments on why the various pieces make sense.

Certainly ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS) should not
be a check to allow writing/changing a task.  It needs to be
PTRACE_MODE_ATTACH_REALCREDS, like /proc/self/mem uses.

Now in practice I think your patch probably has the proper checks in
place for sending a signal but it is far from clear.

Eric


> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Cc: <stable@vger.kernel.org> # 5.13+
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Drop kill_capable() and just check CAP_KILL (reported by Ondrej Mosnacek).
> * Use ns_capable(__task_cred(task)->user_ns, CAP_KILL) to check for
>   capability in target task's ns (reported by Ondrej Mosnacek).
> ---
>  kernel/events/core.c | 15 ++++++++++++++-
>  1 file changed, 14 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index fe88d6eea3c2..43c99695dc3f 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -12152,10 +12152,23 @@ SYSCALL_DEFINE5(perf_event_open,
>  	}
>  
>  	if (task) {
> +		bool is_capable;
> +
>  		err = down_read_interruptible(&task->signal->exec_update_lock);
>  		if (err)
>  			goto err_file;
>  
> +		is_capable = perfmon_capable();
> +		if (attr.sigtrap) {
> +			/*
> +			 * perf_event_attr::sigtrap sends signals to the other
> +			 * task. Require the current task to have CAP_KILL.
> +			 */
> +			rcu_read_lock();
> +			is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
> +			rcu_read_unlock();
> +		}
> +
>  		/*
>  		 * Preserve ptrace permission check for backwards compatibility.
>  		 *
> @@ -12165,7 +12178,7 @@ SYSCALL_DEFINE5(perf_event_open,
>  		 * perf_event_exit_task() that could imply).
>  		 */
>  		err = -EACCES;
> -		if (!perfmon_capable() && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
> +		if (!is_capable && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
>  			goto err_cred;
>  	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h7hdn24k.fsf%40disp2133.
