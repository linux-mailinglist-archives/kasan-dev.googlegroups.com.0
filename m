Return-Path: <kasan-dev+bncBCR6PUHQH4IKRQNTXEDBUBDPT2GYU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id E37519C0A4C
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:45:45 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-6ea8794f354sf20467887b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:45:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730994344; cv=pass;
        d=google.com; s=arc-20240605;
        b=NHsvmIDNfWL9dh+FvIrvqaX0D44lIh9Ycc9H/+Ix8XiVBRqx59zCB/ioQurFmhz6SS
         bpn/3plazqb9coMaSamWpps7VwE4BVFawtEpM8EYwcMXDXGaoBC7dHp8MBxhKojYC7eM
         uKyDQhqm4VmyPqy6J5B5BiLvgGmYX/KJ0XWuO6ApAMLjEx313py4PDXncNjXrCzVNFgw
         B/jgdsOgFG20x9i/adahcRTPSXZSk+hfDXI+19FLvPOGhl1kEAc+dtOzLJPkV55cHBly
         h3zmJht40V9bVLL604wp7m7Qa6FVccp9GhCD0h4zMOKCcZLuN2uKYiPOidx/17vfkjhy
         4C0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Yor+3zbDYYaI0Jugaz1iz1DCPQycxdXiMaWrAWY+zrc=;
        fh=XKQ5uzOXlOGey1HIY9bmt8pX56eP2zofUavCMJlEXQo=;
        b=lrDK3+PX8HuEzKjyJQssqhQ3hcMEMMcf8ObZDoDjxk57ShYBLDx1gfR0e0JHCwFZkK
         vPIVq1etQHOLzAxZXclOc0kGydumsl6oh8n7jBHH/Ft/cdJqoSN37NBgFwrE/YaABnlI
         ikmXeAFQcUv2zqgK53Lcj//KSLez+XyH+v7/AM5B4lFGOpq0Z0y0bGRgNpdqIVHfrixU
         jBJ+Ry+zehLPi0cu1Aw2l1iNTibBKcvJNuTZ2uZQVgvy6kj+xXaLxTvAxSALYXytnNhG
         jsUNV8FYIlUqwi0T4Xff9A2ozNH4ywEWs2IWYHv8Mc5tvQtVE2fDOXU4unpOAmF2MHUj
         VPUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=vXQCeu7q;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730994344; x=1731599144; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Yor+3zbDYYaI0Jugaz1iz1DCPQycxdXiMaWrAWY+zrc=;
        b=D94XD2c5eWsQto1y48D5HsmHhWq4/CMgnBeXfdMhi9yykcEBF4zlCwTRjQvGLaI1O1
         HSapiqtImlMoAKZ5mcjF/GyjvyqEYjKqSwVf94UDd67zlXc8mhFtOYS/OtNR2YZHQ5C5
         +o6WVG46svYNkzkXkAnP0c/W+i55gvBS5BBPVT/WyrG2ems2WloOc+Daq+bljYP8pw8h
         FPYh2KSLPwydkjzkC6MVW5KbudlddtJ/+mFI+NKKB/gTq+93l8t3F9bI9lT+Nd5IlXe6
         xO8SgmVPuI9tI5EFmEzu5gocho7NrnRkdW63n3iAmw/iFUrkMCwKJ8rNSAo3XCqmTjMy
         aMug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730994344; x=1731599144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Yor+3zbDYYaI0Jugaz1iz1DCPQycxdXiMaWrAWY+zrc=;
        b=fIMI1tfODensvX7xrMMN0fyPPwmkvYm2W7MTeLeFGQ6rrSGvxMFBmQFYVfVrwiBXfC
         E9IvRyEpTp/BAyqpC+S2jf5TJlmoac4euo3xwMdhV7bfSo4vZ/9eK1diCxk07+pKdYXt
         YKNL+s7TPLuXg2NTbi6J1aqysLuqxRXQn9tPxA/9Gl2lOWu6BhJZTmkdDaKggEp+iGYZ
         or6ijjCDCj5QT7Y5lMjqslhdZC2mYxTTNr1elt92n1Eb8xI9EmHmjAmG9OWpXTRwJoG2
         ThLZws1ucbuRzqJA/u8tica8aTEV3hc4ZnUiwTFNWCA4iM7im1JKslld1c15d3C5gNBN
         WWmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUa9y/aMFMZ7+XL6JYvA5a+ORe7TiVs5y7XD6w1OxYHqVF16XPeZB2cQJQLhhIhS+t3x+q6Pg==@lfdr.de
X-Gm-Message-State: AOJu0Ywx5Cml0t1Bkyl7EiOAjW+T6Swa3qcovlYHsuS724PEhdMfLwYY
	U4QjJAWoxKNWuYZ8y9ZjDQ4wqO6mh1aDXOGwDAq/D+rrvrWzYJ+s
X-Google-Smtp-Source: AGHT+IH0pnrUcMEPRUsbggTUHRkBbWZWzjJJ5qkpGTwsO75U314BK5dmn2iFhemE1IKKHAZbsUbB0Q==
X-Received: by 2002:a5b:94f:0:b0:e20:16b9:ad68 with SMTP id 3f1490d57ef6-e330266e5e7mr17147581276.45.1730994344492;
        Thu, 07 Nov 2024 07:45:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:4af:b0:e2b:b91d:c66b with SMTP id
 3f1490d57ef6-e336800f655ls417587276.0.-pod-prod-06-us; Thu, 07 Nov 2024
 07:45:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWITFjw1aIZ+gtwAw1RvHu6UuDyD6/NU9/SgFpzJnkUTUKqY/3RDUR3B5/m9ga4Ng9ujajl5Axss4I=@googlegroups.com
X-Received: by 2002:a05:6902:1083:b0:e30:c011:86db with SMTP id 3f1490d57ef6-e330266cba0mr20927473276.39.1730994343266;
        Thu, 07 Nov 2024 07:45:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730994343; cv=none;
        d=google.com; s=arc-20240605;
        b=FOlVCyDCWKAH9XSSYsmrjC1If52PnfNxrPvgX2Auk48Mop6LDf/EAacmA9ge301yJ0
         lOltHTAg14abdWZ/DzBP37t4fkTPfBEaUQqMi5j9U8LhKLPaTAkxReiVQ4I9ncLa4v7Z
         DiXL7J+gglzTRMaEf8VeNZbVWTuc6kuY0DsUBqHNNTnZGcHXxPwg8F/Y4BJyYB0gOty5
         29hs6vzZlvou3prxgp+LAhOjLoZeRZ+2P1VjgpSePWbiIzyal4XQhcSYhA5OgIAkAl4g
         34dKVpvznStiseEtK5DNSlHBpBxs2/2RIEmLatD5NvTpvutXLaBBIzF/elJWm3AWd+Ap
         nsnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9gH9B1MESfb2kha2KFPe5mNElVoPQ0GouvkNCrsAMdk=;
        fh=H16veCM6qzpxo++LSZ0Gn0OAbeXr36AeDOwNSzHEQ1c=;
        b=PpTBExivxeihLULck79NcunoCaAYRFCKtiRq157BSiiKePpWjkBvTFLNdOpBYcAInl
         5KUrw0v6WydATuqjToo7wGN6Ki5Oa8dqtanhgFkxqseuPmRdhhe7ODObPyzjjY73GnlR
         mno+1EFa4lq32+ngac+PW+w37kkPLT6YwOMOG233wzOyeMdmEaJ+U8mEIu60Vroyc4/A
         OUjFPaOdFvoPShYM+eaw+Rvv41p4OJ0otOjXoTchHr2iNkNnXRMAHGfrgkzHNuvTLAUr
         /hADsPHuWX8jXmNjOk/I0IW74vn4uYqv2QAV1qIpsdP3XkdfDvUG5ZT94HnxyxWAjXzU
         GbFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=vXQCeu7q;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from smtpout.efficios.com (smtpout.efficios.com. [2607:5300:203:b2ee::31e5])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e336ee0dd5bsi78266276.1.2024.11.07.07.45.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 07:45:43 -0800 (PST)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) client-ip=2607:5300:203:b2ee::31e5;
Received: from [172.16.0.134] (96-127-217-162.qc.cable.ebox.net [96.127.217.162])
	by smtpout.efficios.com (Postfix) with ESMTPSA id 4Xkmck1TPYzxTL;
	Thu,  7 Nov 2024 10:45:42 -0500 (EST)
Message-ID: <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
Date: Thu, 7 Nov 2024 10:44:12 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>,
 Kees Cook <keescook@chromium.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <20241107122648.2504368-1-elver@google.com>
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Content-Language: en-US
In-Reply-To: <20241107122648.2504368-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=smtpout1 header.b=vXQCeu7q;       spf=pass
 (google.com: domain of mathieu.desnoyers@efficios.com designates
 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
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

On 2024-11-07 07:25, Marco Elver wrote:
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
>    a. unprivileged triggering of a test module: test modules may register a
>       probe to be called back on task_prctl_unknown, and pick a very large
>       unknown prctl() option upon which they perform a test function for an
>       unprivileged user;
> 
>    b. unprivileged triggering of an eBPF program function: similar
>       as idea (a).
> 
> Example trace_pipe output:
> 
>    test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
> 

My concern is that we start adding tons of special-case
tracepoints to the implementation of system calls which
are redundant with the sys_enter/exit tracepoints.

Why favor this approach rather than hooking on sys_enter/exit ?

Thanks,

Mathieu

> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Remove "pid" in trace output (suggested by Steven).
> ---
>   include/trace/events/task.h | 41 +++++++++++++++++++++++++++++++++++++
>   kernel/sys.c                |  3 +++
>   2 files changed, 44 insertions(+)
> 
> diff --git a/include/trace/events/task.h b/include/trace/events/task.h
> index 47b527464d1a..9202cb2524c4 100644
> --- a/include/trace/events/task.h
> +++ b/include/trace/events/task.h
> @@ -56,6 +56,47 @@ TRACE_EVENT(task_rename,
>   		__entry->newcomm, __entry->oom_score_adj)
>   );
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
> +		__string(	comm,		task->comm	)
> +		__field(	int,		option)
> +		__field(	unsigned long,	arg2)
> +		__field(	unsigned long,	arg3)
> +		__field(	unsigned long,	arg4)
> +		__field(	unsigned long,	arg5)
> +	),
> +
> +	TP_fast_assign(
> +		__assign_str(comm);
> +		__entry->option = option;
> +		__entry->arg2 = arg2;
> +		__entry->arg3 = arg3;
> +		__entry->arg4 = arg4;
> +		__entry->arg5 = arg5;
> +	),
> +
> +	TP_printk("comm=%s option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
> +		  __get_str(comm), __entry->option,
> +		  __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
> +);
> +
>   #endif
>   
>   /* This part must be outside protection */
> diff --git a/kernel/sys.c b/kernel/sys.c
> index 4da31f28fda8..dd0a71b68558 100644
> --- a/kernel/sys.c
> +++ b/kernel/sys.c
> @@ -75,6 +75,8 @@
>   #include <asm/io.h>
>   #include <asm/unistd.h>
>   
> +#include <trace/events/task.h>
> +
>   #include "uid16.h"
>   
>   #ifndef SET_UNALIGN_CTL
> @@ -2785,6 +2787,7 @@ SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
>   		error = RISCV_SET_ICACHE_FLUSH_CTX(arg2, arg3);
>   		break;
>   	default:
> +		trace_task_prctl_unknown(me, option, arg2, arg3, arg4, arg5);
>   		error = -EINVAL;
>   		break;
>   	}

-- 
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5b7defe4-09db-491e-b2fb-3fb6379dc452%40efficios.com.
