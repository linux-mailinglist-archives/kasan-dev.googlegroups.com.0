Return-Path: <kasan-dev+bncBCU73AEHRQBBBL6K576QKGQE6NHTESY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1819D2C105E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 17:37:05 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id t13sf11629414plo.16
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 08:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606149423; cv=pass;
        d=google.com; s=arc-20160816;
        b=UrmTbFhInVW76xiqmN9OnSHUZ70z2/NN3jT7nIa1Iae+qrvVKOsGStmftIUYT3bazM
         f0mJk5xgzg21874lYbp7RxI6C+1b4SYMaF/irm+ZzL2uAEQdkJcEkN3H5l8oryneNLOv
         5MUoTVjw3cn3jHnjAh0TaP6dq9LhIBNEv8ynMOjfB277Py9H/D0qwHgBl6c4QsJx/DwO
         dIlVGGOGgZTJvAWaAet0Nzuo3sRx6fBUG55TUXVw0dnWg3oR0gVNxbj1BoFzAToVSeHa
         0S/fbZU0e99jdbJFd67GoelysWKs2PeHSiDGDuuCWmEFQ/pdAv9PgiruSFWh1wn5a8w7
         6NQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Ya1Fg+A6y3XEzRfktpWZgkKRJlIM82n9DtJFTqW2GPQ=;
        b=jEk4HeMmDl76IBMpdJtRYn9S6D9P9vfyP+IHCDLrox+0txgp3muH91VDyOPpEJWQxi
         vNPXIytugSL9gfiS7ePAuNNm+JTWYMnH/AUtsYPNXjsL5Bj5kuNyhki73H3ICN+cuCgv
         kUWJVGbPeGc6f0rrbW6Y6kkrA/F6dqAYBriSf7Ew5+1NC5OXtz+qq3P5kBN+tGAJLyQ+
         avFGMDvdktJyWDzNmu/xSnsApupenA0ZSDZhSrDsKmPd8+QXUFKclrwgyB+GOCFCbEw7
         l4AmBaXZ3oWODSrkbZhi2ixZ0oTOS6NJqmzvBZtVymw98VoX4LVbjBMz9LJA8Au3ERIm
         NToA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya1Fg+A6y3XEzRfktpWZgkKRJlIM82n9DtJFTqW2GPQ=;
        b=ED07DEB7Ht+s8cggwdC9ZXw6AUI8Nm8bW57icyT3m7kP3vdKOxkPTda0panUl3Com8
         WpK3t/C9qq3DlYhZ+B1yIWdDiHooQlOxdlYpwvlWd4U/2hdEKaZMNU+I0i2ruTZ9r2g4
         e3O8FUqrWqgGh0NRHCbiD5rR59ZlBAKRFf7BLQmi44zI/4YWH7sRJo1Mgrn/4vvxgKYv
         8r7tJym0c2UHOVwmp3EkNooVh7IPRsbqzwre9ft3rQCDUEpVJnJAiiVntADvJQWTSwwe
         OUoNmbuJ2Eg4nJA5Zps6hB2nP5XHVR2HNrcIJwgt5r0frw0rp3t8Cfinjxc6g959qcdS
         JZSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya1Fg+A6y3XEzRfktpWZgkKRJlIM82n9DtJFTqW2GPQ=;
        b=GspLBRx79Ov+vAwsJfnG/iuf9c4XgbOCNQl/ZUKyPHIeNUjhX8HmNzUZ1U6nDl9BUu
         D4Pdp7x1j12wS8DXG/JlTUpVhAS4hu0lMmC6jhXDYvGQ/3gcfrsUg0GooPdICLsPIutp
         LOZSww3ck0QcbAgnYN/EsdgOktuT9lwfOB1QQVKkCw0mLcSjXLqgdY9InIv9+bQE5EYs
         QIU/zHvTSYNepA8Lt/T4VRstQe3K5CmF/ihp4TsVZ0n28SfVcNbNi60qSSiFWa4fIQ5h
         OrMnVHcHWS403FYftBegbT5hN3r6XpfXJurcva5Li15oS9DaIv+tQ8Ety4rH1A4Rsebx
         KvzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530d3Uc7CjoZFhMoxydkeNIN8iLNMW8S7qkbzUwTceor/XASQc6m
	/6I/q3KnCB/sZKlFt7N3OWA=
X-Google-Smtp-Source: ABdhPJyMDCPyvF4Qdjs2ENhNhIFg8HCBDSbnic+4MEZidFG4cHg1g6WDn05NLnFibKEJuMsM7yDB+w==
X-Received: by 2002:a17:90a:c796:: with SMTP id gn22mr605497pjb.234.1606149423832;
        Mon, 23 Nov 2020 08:37:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8495:: with SMTP id k143ls5235762pfd.11.gmail; Mon, 23
 Nov 2020 08:37:03 -0800 (PST)
X-Received: by 2002:a63:131a:: with SMTP id i26mr271313pgl.232.1606149423305;
        Mon, 23 Nov 2020 08:37:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606149423; cv=none;
        d=google.com; s=arc-20160816;
        b=VX3i0z0zLRHY/OCqku6TmVDYtMIXD8vRMKGCmxPDCLCl6KpfVVL+a+ME4jab1v7v+A
         FOctE1vcrraSXYnwdIBCRoiwok4yphVyCwW+yuf5+nq/anu9HryNcbZe5fGFtfzFm5q9
         aYHJqOpO2YcN24p0uVYsEzxslEA/weQ+zigaHqi7p5w49b6/aOWTLL7turH3TDyfDx3O
         pKE8XIoaI2hNy6vi6TCd869uYfPMrwlcybN+EQ3M5P/DbHZncrXlf6YQCh5l/8RGvAYo
         gSH+wtpZ16otUfUrTDEkFrVgSIFv0mziTODmXBHxFFDmgU+vfyPsoidpaz1jqpgo55+2
         0xvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=w02U79IgXoVR1Ne73goXhCfX1BoyC+I10BFjRBFSuHo=;
        b=A0qaxr9IZ7o98g5sHjGYykIMvQLzaVOl0LhO2XmciPHrvqm8FQWnhOekWqEmfTtYdV
         KXv3UnHQcbEzLg1olVuF0GHFkM0ayY2T7Tp5su1BZ7qTrhYk3sLX92mBuopFnzYwxfwF
         5OPmHnHLWeFHgTYEpE1evKLxM4BOc4O8c4qF3bqF3Pp2byvM3HVOMjdfzAnYKSbHWx2t
         LvMre8EHbGJg8J7piuOJJ0kj5BUnDen/I9FhuKh/anTYgKQ/TOZshkWEHMxrDCnUHK2d
         d/Z/GUgF7jYmmjZR+qV9p5UeGrmVEfh0AKXT/7yFiNJVJ12ar7T568WlKhLOiU9924TN
         ZYmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s12si276567pjq.3.2020.11.23.08.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 08:37:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 649D220665;
	Mon, 23 Nov 2020 16:37:01 +0000 (UTC)
Date: Mon, 23 Nov 2020 11:36:59 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201123113659.3d1fd866@gandalf.local.home>
In-Reply-To: <20201123112812.19e918b3@gandalf.local.home>
References: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
	<20201112161439.GA2989297@elver.google.com>
	<20201112175406.GF3249@paulmck-ThinkPad-P72>
	<20201113175754.GA6273@paulmck-ThinkPad-P72>
	<20201117105236.GA1964407@elver.google.com>
	<20201117182915.GM1437@paulmck-ThinkPad-P72>
	<20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201120142734.75af5cd6@gandalf.local.home>
	<20201123152720.GA2177956@elver.google.com>
	<20201123112812.19e918b3@gandalf.local.home>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
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

On Mon, 23 Nov 2020 11:28:12 -0500
Steven Rostedt <rostedt@goodmis.org> wrote:

> I noticed:
> 
> 
> [  237.650900] enabling event benchmark_event
> 
> In both traces. Could you disable CONFIG_TRACEPOINT_BENCHMARK and see if
> the issue goes away. That event kicks off a thread that spins in a tight
> loop for some time and could possibly cause some issues.
> 
> It still shouldn't break things, we can narrow it down if it is the culprit.

And it probably is the issue because that thread will never sleep! It runs
a loop of:


static int benchmark_event_kthread(void *arg)
{
	/* sleep a bit to make sure the tracepoint gets activated */
	msleep(100);

	while (!kthread_should_stop()) {

		trace_do_benchmark();

		/*
		 * We don't go to sleep, but let others run as well.
		 * This is basically a "yield()" to let any task that
		 * wants to run, schedule in, but if the CPU is idle,
		 * we'll keep burning cycles.
		 *
		 * Note the tasks_rcu_qs() version of cond_resched() will
		 * notify synchronize_rcu_tasks() that this thread has
		 * passed a quiescent state for rcu_tasks. Otherwise
		 * this thread will never voluntarily schedule which would
		 * block synchronize_rcu_tasks() indefinitely.
		 */
		cond_resched_tasks_rcu_qs();
	}

	return 0;
}


Did something change, where that "cond_resched_tasks_rcu_qs()" doesn't let
things progress on ARM64?

I noticed that you have PREEMPT enabled so this will only be preempted when
its schedule time runs out and something else wants to run. How would that
affect other threads?

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123113659.3d1fd866%40gandalf.local.home.
