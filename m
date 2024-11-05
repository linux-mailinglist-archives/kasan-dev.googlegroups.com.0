Return-Path: <kasan-dev+bncBCU73AEHRQBBBUMQVG4QMGQEHSHMQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 363D19BD25A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 17:31:16 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2e2c3338a9dsf7205353a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 08:31:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730824274; cv=pass;
        d=google.com; s=arc-20240605;
        b=cxCw7z4lXVqZueio5pksnPydehL8c58vSUdFG3ANwDBnq/4i7388ADGnW4TMwOkkBC
         G2TOZYshvXZBz3bBujwpbfe/jX2sNRp0f0zHJKJInAVzb6WeaJkwckk5UYF8WrVgmIrO
         QhmR/aRuSQI4GxvDrSuPnFmnnx8/PqGW5NOimhcz2BbqxMoVSzD7Ncda+IChD9n+YqM7
         /FUm3e6x6IFVaMYxpxjnZfENbnuARn1cz4Q6i0tqLmyeXHM7cittQ6MWIXW7MEHacarg
         Ejldi6V+l3i9+7hZ9s+z4s6Lj2iG725Xc0DNGV6/wRmcKUjWnx9/O54Db94obeP0vuFW
         VFPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YbJSst4oHMLctIFfOTkkb+PSXPXGJA3oD0EjKJUJaaQ=;
        fh=MND6D+mpvPTcrsEtZ07df2iL6lOUVucjYu0lwmIiEc0=;
        b=WvQhCUnSiHhcV5Tf46dWLb3CWG5398JFHQwh4Jkyu1yqRNmcqhwyIeOTnXtmFCV6tO
         d87fa13btseXwlnRph5lep0Z1BQC9r/3GmO+DlIbHWKA/imSPzZH+pAuX7mRV/tjvJeu
         EPw58m2O0EbGypUgPJvu/r2ofDz8qCZXqMEV+H5ngmV0VXBZtgNxliEGltsu8g8JeV9i
         od04bjUpfN52zqh9fyawBz+3VXMIi0Y99BtirA0kM2wkXNr1SVEf3hGXkms85pYV+FtJ
         bERhg1rwYAVpElOSLy9nJKwxCWNyJyysAjZLB70cXylXloL0ZBqSWB6ABV5NnqFQ3+Ym
         LTRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730824274; x=1731429074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YbJSst4oHMLctIFfOTkkb+PSXPXGJA3oD0EjKJUJaaQ=;
        b=Cu08QIjErLd8oTFZMjgN04b32xbkDdk0NEULjyMSytYMPadG8cRQeNJjxFJbYjKfNe
         V79YELl+v7BsF8Fr+b3RMNSXiQhO2MjxRRHy7GhwvlqkZPOGNzVDVe8lxNLMeGXjIUL9
         yGk0vgbebzmC+yBQ6k32f25dkuWKDFeVcHEZhmAJaBd4P1tzYsUVkAQRyPR6fdGCHE2n
         XbYP9Oe2MQnur5l5ahc/fI86tSyRebo/lsg4C2+gmRe5dQyqpkFERFDsWh5Qh/Qgouck
         DmbHFP30gzl+bDQYBwJ/S5SiuKrkspE02uGY81dhNEn6SHW0L8QUC3Uzzhm29a01kacw
         ttfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730824274; x=1731429074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YbJSst4oHMLctIFfOTkkb+PSXPXGJA3oD0EjKJUJaaQ=;
        b=rdT/LRK8r9Wg2RMinvqU3KzpV84gVNYqtdXHdBbXvFi3mDzKZsfCcHFwCR1vLoVcl6
         qFLYtYosX+5/xl7aKNJfq1ceye7o0eIwlKan2AIsswECRnaMkZ0VfWG+/BjEDNREo3pr
         VDINrsFkxOk6cl8uwq00JCrXAVjvUYG7xh0jJjVlI6RCqCkj4mmE/mMGsOAcsEyJEdMD
         VdXtNjCCo4sjyuDlN6bv4WVYNiAi4/eAGSrDR6sqcnfNJ/4+f3kTkStGgJE4gQBwbiwS
         IxPq2DblC+g8HGO0ItU1n+ala8tiBKyWV4//iFMXaB+yLr5EvcQ/MVKb/NHAsm85ptdF
         RU7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/km43NrEE443mjq+8e9q8wIuoycnLLvr4Qt9Kl1eY/mXZx/hcQHTHuAnJZH/5Dd4bBJzQyg==@lfdr.de
X-Gm-Message-State: AOJu0YwCPaEufu9YxYVHbWfspu3rjvbg6IqLAzyH2UEfVGrEDYxl0x6y
	5Afu0s7dl+/mF+EL8mie5Huji9uipMlEDSoAy6duEg7e1xycVhSq
X-Google-Smtp-Source: AGHT+IFTU9c7BCZ4qvINhZDy15+9Af1cFWyIDbjckmYLavLxJ7dchEksvi52F+3E0NRcZsQr/H54UA==
X-Received: by 2002:a17:90b:1e06:b0:2e2:c14c:9c63 with SMTP id 98e67ed59e1d1-2e93c1f558cmr21438916a91.40.1730824274313;
        Tue, 05 Nov 2024 08:31:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c50:b0:2e7:8a36:a9b7 with SMTP id
 98e67ed59e1d1-2e93b1334c4ls2114588a91.1.-pod-prod-03-us; Tue, 05 Nov 2024
 08:31:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfnj4xi7G9nK1WETXFIvgL3R1w42ktpKUJq2OkZnp7C938807vMXR0mG5LQCylvPqNkyNJnX/EbYc=@googlegroups.com
X-Received: by 2002:a17:90b:3c42:b0:2e2:d1aa:e11c with SMTP id 98e67ed59e1d1-2e93c1f2e90mr25038044a91.34.1730824272716;
        Tue, 05 Nov 2024 08:31:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730824272; cv=none;
        d=google.com; s=arc-20240605;
        b=cLCPO60oGmnylW9GxXuimdejj1l4aatxNZXxgEwbfT1mjKw4tr5kD/kIqCZmKosnPy
         YfwpuWLCKUbSOZJtaJOUNMjpYEG0NN0Jy0Dy6KLvywa5gujBEi8leDdHgUKMilGKR+qy
         iJGpDWCdf2YklokIV65ACaTOjncJwp00pk86TIG0Dype2IhpkmJKVctcwqJPvev1yTfj
         YU/QtAaHNVg/D1JMzi59OQ1OLwsCuueNMnSJKICLGO2m4XVLShy0GedkGJVVlMz03Vk9
         M66BFz4WZ6cjMpY3RUsBzFN9pwoBfg3B7xUAig2OjsVG7SrI18PTKugKXvaGsxoozKVr
         5PCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Db/qUsq9g/eJrE1wvZaCpX+oeOWYnJQ0lVHeVO4At/I=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=dfAQLuqAdhhjQKn5rnMPUd4aJE6xV98Iv2RNdpZUuKdaqi7KOVPc6JYZG1jQcXAa1X
         KAy0hh1VnRQuU5IM6ftR+s5DeGvwae0vBYHTlbYl+hh5o5sMJAoN2G3ddvnkhNOErI48
         8CdXHnkh7yrKHOzndTNmHKL1WCvtJFEJRnyTe5ngl6pK5opx3a7n4Vfb0I6aa0yW3aMm
         KkCKX6nTleWu1oxQyHiQ441nL38zomOPgT40TW7AW8MZ1vdVTXCFA1KlJw/u/I3rS2Tl
         q8Sn7nm6+l63szgecqLqp41af1kjZdnJrdiipuYvt9vKmZ/kFe6FsaodgEz7HDOGupCr
         2ZjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98ca386b7si210594a91.1.2024.11.05.08.31.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 08:31:12 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 61AFB5C5466;
	Tue,  5 Nov 2024 16:30:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 910B2C4CECF;
	Tue,  5 Nov 2024 16:31:10 +0000 (UTC)
Date: Tue, 5 Nov 2024 11:31:11 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241105113111.76c46806@gandalf.local.home>
In-Reply-To: <20241105133610.1937089-1-elver@google.com>
References: <20241105133610.1937089-1-elver@google.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
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

On Tue,  5 Nov 2024 14:34:05 +0100
Marco Elver <elver@google.com> wrote:

> prctl() is a complex syscall which multiplexes its functionality based
> on a large set of PR_* options. Currently we count 64 such options. The
> return value of unknown options is -EINVAL, and doesn't distinguish from
> known options that were passed invalid args that also return -EINVAL.
> 
> To understand if programs are attempting to use prctl() options not yet
> available on the running kernel, provide the task_prctl_unknown
> tracepoint.
> 
> Note, this tracepoint is in an unlikely cold path, and would therefore
> be suitable for continuous monitoring (e.g. via perf_event_open).
> 
> While the above is likely the simplest usecase, additionally this
> tracepoint can help unlock some testing scenarios (where probing
> sys_enter or sys_exit causes undesirable performance overheads):
> 
>   a. unprivileged triggering of a test module: test modules may register a
>      probe to be called back on task_prctl_unknown, and pick a very large
>      unknown prctl() option upon which they perform a test function for an
>      unprivileged user;
> 
>   b. unprivileged triggering of an eBPF program function: similar
>      as idea (a).
> 
> Example trace_pipe output:
> 
>   <...>-366     [004] .....   146.439400: task_prctl_unknown: pid=366 comm=a.out option=1234 arg2=101 arg3=102 arg4=103 arg5=104

          ^^^                                                       ^^^

> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/trace/events/task.h | 43 +++++++++++++++++++++++++++++++++++++
>  kernel/sys.c                |  3 +++
>  2 files changed, 46 insertions(+)
> 
> diff --git a/include/trace/events/task.h b/include/trace/events/task.h
> index 47b527464d1a..ab711e581094 100644
> --- a/include/trace/events/task.h
> +++ b/include/trace/events/task.h
> @@ -56,6 +56,49 @@ TRACE_EVENT(task_rename,
>  		__entry->newcomm, __entry->oom_score_adj)
>  );
>  
> +/**
> + * task_prctl_unknown - called on unknown prctl() option
> + * @task:	pointer to the current task
> + * @option:	option passed
> + * @arg2:	arg2 passed
> + * @arg3:	arg3 passed
> + * @arg4:	arg4 passed
> + * @arg5:	arg5 passed
> + *
> + * Called on an unknown prctl() option.
> + */
> +TRACE_EVENT(task_prctl_unknown,
> +
> +	TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> +		 unsigned long arg4, unsigned long arg5),
> +
> +	TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> +
> +	TP_STRUCT__entry(
> +		__field(	pid_t,		pid		)

Why record the pid that is already recorded by the event header?

> +		__string(	comm,		task->comm	)

I'm also surprised that the comm didn't show in the trace_pipe. I've
updated the code so that it should usually find it. But saving it here may
not be a big deal.

-- Steve

> +		__field(	int,		option)
> +		__field(	unsigned long,	arg2)
> +		__field(	unsigned long,	arg3)
> +		__field(	unsigned long,	arg4)
> +		__field(	unsigned long,	arg5)
> +	),
> +
> +	TP_fast_assign(
> +		__entry->pid = task->pid;
> +		__assign_str(comm);
> +		__entry->option = option;
> +		__entry->arg2 = arg2;
> +		__entry->arg3 = arg3;
> +		__entry->arg4 = arg4;
> +		__entry->arg5 = arg5;
> +	),
> +
> +	TP_printk("pid=%d comm=%s option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
> +		  __entry->pid, __get_str(comm), __entry->option,
> +		  __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
> +);
> +
>  #endif
>  
>  /* This part must be outside protection */
> diff --git a/kernel/sys.c b/kernel/sys.c
> index 4da31f28fda8..dd0a71b68558 100644
> --- a/kernel/sys.c
> +++ b/kernel/sys.c
> @@ -75,6 +75,8 @@
>  #include <asm/io.h>
>  #include <asm/unistd.h>
>  
> +#include <trace/events/task.h>
> +
>  #include "uid16.h"
>  
>  #ifndef SET_UNALIGN_CTL
> @@ -2785,6 +2787,7 @@ SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
>  		error = RISCV_SET_ICACHE_FLUSH_CTX(arg2, arg3);
>  		break;
>  	default:
> +		trace_task_prctl_unknown(me, option, arg2, arg3, arg4, arg5);
>  		error = -EINVAL;
>  		break;
>  	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105113111.76c46806%40gandalf.local.home.
