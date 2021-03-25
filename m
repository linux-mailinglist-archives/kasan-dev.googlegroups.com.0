Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ6A6OBAMGQEHWGZFZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 966503499FC
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 20:11:00 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id v29sf3497826ljd.23
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 12:11:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616699460; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYHaU68Xb8FET5y6HRfT3UwsOAlAHZrFkq5L1bL5FjuscsrIUwUoRQvZLvC8+H/txV
         8sXctrvrEjh7npMCRsDq1U3/DhiKazIfoOmEWIOOE6ZY1wz3c92xViOPAg8rFmFe6JIv
         Fp/kv9qZdOBumPgB22HfjWn0vvJDd8QWv4rV4G0QeWN811CBCk2lfAWs9sQ94okEekXR
         CvQVVq5MfNj3l7KQ5gpuq6uRYL92vbax7y21RFA5h2hA7utXzBOL6LhWQyyjBoy6TYJQ
         DWL0u330Z4IWBI2tjNqNUDNgy9Imq3u9MmIpPYTm2Ntbbl2ScqTGeBOyieb06BttX1oJ
         k/6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Q1fe8VCnCQGiPmXSW3uGqrDLnVygsPlmPU2jW7OUiFA=;
        b=uxy6BPK0p6EOc3V5SwMT6Xn+aqj6P8mx3MOLXVs1Wp+iG1MGXTuB7c/IsMRXvB53Qr
         VQILwg2o5qyCswc/oCzmX//8X1zP02AvIpuOwR4gJVG3lTocBi4h2lat8SYZYkHS9LxM
         G7f4b00KaKNB4bZazniSERrC97k2jBjaNr7bID7XaGlfwK0xJQXqt4yJnWY1oRW1FFgl
         L+he2N1FFA/yl7RsU66u/Kb0pu38CnCbQacC3OZn7ADR2VvlEPc06ikMnERBhcxD8xG6
         KzF7K5T5HXQ/iUerAEHR7eFeVsLnz+bCL7IO9KQD1dz4ZJ88hxCcngCaFR52RqPdQ48H
         8z4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bSWH/ycg";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Q1fe8VCnCQGiPmXSW3uGqrDLnVygsPlmPU2jW7OUiFA=;
        b=XokX9Lp31x6jenFOfPMtpczpjhWe7cXIyFQIODmoWxXnPBvNt83MwW6teSVytzVfkG
         KkApbKAn9881Gv7pDwmHwFD8K/hb4RXhP+9o3umoG4Ad8DBpC7o1TrGV660s1MyYAFpY
         Kk6y8hfMWXSZC1s9ZdgCVF0+jKd41vHVvoaGk9aMLzBj3dw0sMvzDPaFWaGAgrbK/A9E
         6YVHjfoLVz+pC7R1gbaz3ukpiXbgW30Mq4pYYVHJC3oTjpUCNna8z3V/DdrCFJbslJL2
         4dUU62g3jpUIePp4+KF3EN4esrmjj7QbOawmBKXxNyVwPN7pQ+uXVVlUo+xnuwuQVoYU
         tDtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q1fe8VCnCQGiPmXSW3uGqrDLnVygsPlmPU2jW7OUiFA=;
        b=fUI4Mq2hjQUbcvpfcKyU+LO57DxWUabMLY5bAxk9mDvyTDYVoDshMEfxhKCtNCH78A
         1S0GeY4j9YNOJbe+EKqGluoGezN2MhEgo0NT1PrHJxtJ4xsSHVCwbKV/D3j9IVloUpfp
         SonLi9yRnKRQZJKLf9keKvJzmFLYzwd92AMSYl7oPQnqdqIXkJIPp90n18FPpA6rSZW8
         zktPfr8OXmze1Ae+wDQwVkNT+oArlC1gYEyTz8e9aEOY8EBNYGhWk1S+Aa4C4k54JEzX
         QwKdziJrJrA24SEwAQOmCaBFDv88c12QP8SYPfNodL5BLY6MEOT49y9VN6UWm1zhf0Mh
         lbxg==
X-Gm-Message-State: AOAM530kVVi2x82tfgGkc+ttwrA5n2zKox0IVjH2paXlf30GUuqrZRzn
	zmRfm2l9d9rX9W9ro5E8D4s=
X-Google-Smtp-Source: ABdhPJyfsj7S6gQtReRXjtECXTrZys+8gpCMuKsPv4muGYd7jpwXr7aEJ4vwJsjcjFZNUrQUFehrAQ==
X-Received: by 2002:a2e:2a44:: with SMTP id q65mr6910106ljq.238.1616699460134;
        Thu, 25 Mar 2021 12:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls1682025lff.3.gmail; Thu, 25
 Mar 2021 12:10:59 -0700 (PDT)
X-Received: by 2002:a19:ee16:: with SMTP id g22mr5798815lfb.513.1616699458935;
        Thu, 25 Mar 2021 12:10:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616699458; cv=none;
        d=google.com; s=arc-20160816;
        b=0QBh0WUqHSpP4fdXW29q2DVk2E2SpG5yYj7vlSRDf8JSw+WdnhO0BhSAy9cMjD4ueo
         fJ5Y4GfXi4aqaGgGwdUzrojWP9jUGD4FoHjAwuphu29lzn7LraBsJto8lAHhupVRisIK
         2DQtky4LR1O6tHY3LR0wSW0rBCm48EpyC5W+kOxslA+RhdkMKZhI1Au3hQyLY5VQrWKI
         2IOdwlFOI7woywNBvFrf0bAitrUwXwHJ8J9oMBpG+bk82bT78h8BusTICR13aPZBCP8e
         aQtuvO2VjFRpJuCirImkcQkz70uFmYinhhfkaCgQTEamDnv25XMzNNcLf11vViCCDz8U
         KUdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Xjvw4hFvgpXEdEyLOwCoYu7tEGHrW0NPxhD9uHWiJU4=;
        b=kp8ywJ3fVqheGrsdfalz3oUdm+u6kARkAo0eTsPlU7cLgl99+Bq4XTfddIlgidcbp9
         urNKiNxO4IrImWRa7X83UL3mM7A6sevWWQlJ4VEdZ0odbqTPMNMNLMys2HECyBWnfncg
         S20hp3D3e55XNIXl7pYbOy15kqJynl76HiXb3opvZS9sDu7u7l5YVib3tQYINhKssvMi
         53H9h3jb7UJ1zumFoj+XUUhA5t4Qiq6A/5AZT9bgU+RvFT0wvugOcvUKSbY1PG4pB0c3
         adA8f35rHVWncQuQVz1xE5/005uDiIceCn7Rm/lE+L5HgmIHjDP9Z3Vsp+efJuipp++r
         YFjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bSWH/ycg";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id i30si339530lfj.6.2021.03.25.12.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 12:10:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id a132-20020a1c668a0000b029010f141fe7c2so3733307wmc.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 12:10:58 -0700 (PDT)
X-Received: by 2002:a1c:7209:: with SMTP id n9mr9680498wmc.132.1616699458252;
        Thu, 25 Mar 2021 12:10:58 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:248e:270b:f7ab:435d])
        by smtp.gmail.com with ESMTPSA id r10sm8011391wmh.45.2021.03.25.12.10.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 12:10:57 -0700 (PDT)
Date: Thu, 25 Mar 2021 20:10:51 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v3 01/11] perf: Rework perf_event_exit_event()
Message-ID: <YFzgO0AhGFODmgc1@elver.google.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-2-elver@google.com>
 <YFxjJam0ErVmk99i@elver.google.com>
 <YFy3qI65dBfbsZ1z@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFy3qI65dBfbsZ1z@elver.google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="bSWH/ycg";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Thu, Mar 25, 2021 at 05:17PM +0100, Marco Elver wrote:
[...]
> > syzkaller found a crash with stack trace pointing at changes in this
> > patch. Can't tell if this is an old issue or introduced in this series.
> 
> Yay, I found a reproducer. v5.12-rc4 is good, and sadly with this patch only we
> crash. :-/
> 
> Here's a stacktrace with just this patch applied:
> 
> | BUG: kernel NULL pointer dereference, address: 00000000000007af
[...]
> | RIP: 0010:task_pid_ptr kernel/pid.c:324 [inline]
> | RIP: 0010:__task_pid_nr_ns+0x112/0x240 kernel/pid.c:500
[...]
> | Call Trace:
> |  perf_event_pid_type kernel/events/core.c:1412 [inline]
> |  perf_event_pid kernel/events/core.c:1421 [inline]
> |  perf_event_read_event+0x78/0x1d0 kernel/events/core.c:7406
> |  sync_child_event kernel/events/core.c:12404 [inline]
> |  perf_child_detach kernel/events/core.c:2223 [inline]
> |  __perf_remove_from_context+0x14d/0x280 kernel/events/core.c:2359
> |  perf_remove_from_context+0x9f/0xf0 kernel/events/core.c:2395
> |  perf_event_exit_event kernel/events/core.c:12442 [inline]
> |  perf_event_exit_task_context kernel/events/core.c:12523 [inline]
> |  perf_event_exit_task+0x276/0x4c0 kernel/events/core.c:12556
> |  do_exit+0x4cd/0xed0 kernel/exit.c:834
> |  do_group_exit+0x4d/0xf0 kernel/exit.c:922
> |  get_signal+0x1d2/0xf30 kernel/signal.c:2777
> |  arch_do_signal_or_restart+0xf7/0x750 arch/x86/kernel/signal.c:789
> |  handle_signal_work kernel/entry/common.c:147 [inline]
> |  exit_to_user_mode_loop kernel/entry/common.c:171 [inline]
> |  exit_to_user_mode_prepare+0x113/0x190 kernel/entry/common.c:208
> |  irqentry_exit_to_user_mode+0x6/0x30 kernel/entry/common.c:314
> |  asm_exc_general_protection+0x1e/0x30 arch/x86/include/asm/idtentry.h:571

I spun up gdb, and it showed me this:

| #0  perf_event_read_event (event=event@entry=0xffff888107cd5000, task=task@entry=0xffffffffffffffff)
|     at kernel/events/core.c:7397
									^^^ TASK_TOMBSTONE
| #1  0xffffffff811fc9cd in sync_child_event (child_event=0xffff888107cd5000) at kernel/events/core.c:12404
| #2  perf_child_detach (event=0xffff888107cd5000) at kernel/events/core.c:2223
| #3  __perf_remove_from_context (event=event@entry=0xffff888107cd5000, cpuctx=cpuctx@entry=0xffff88842fdf0c00,
|     ctx=ctx@entry=0xffff8881073cb800, info=info@entry=0x3 <fixed_percpu_data+3>) at kernel/events/core.c:2359
| #4  0xffffffff811fcb9f in perf_remove_from_context (event=event@entry=0xffff888107cd5000, flags=flags@entry=3)
|     at kernel/events/core.c:2395
| #5  0xffffffff81204526 in perf_event_exit_event (ctx=0xffff8881073cb800, event=0xffff888107cd5000)
|     at kernel/events/core.c:12442
| #6  perf_event_exit_task_context (ctxn=0, child=0xffff88810531a200) at kernel/events/core.c:12523
| #7  perf_event_exit_task (child=0xffff88810531a200) at kernel/events/core.c:12556
| #8  0xffffffff8108838d in do_exit (code=code@entry=11) at kernel/exit.c:834
| #9  0xffffffff81088e4d in do_group_exit (exit_code=11) at kernel/exit.c:922

and therefore synthesized this fix on top:

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 57de8d436efd..e77294c7e654 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -12400,7 +12400,7 @@ static void sync_child_event(struct perf_event *child_event)
 	if (child_event->attr.inherit_stat) {
 		struct task_struct *task = child_event->ctx->task;
 
-		if (task)
+		if (task && task != TASK_TOMBSTONE)
 			perf_event_read_event(child_event, task);
 	}
 
which fixes the problem. My guess is that the parent and child are both
racing to exit?

Does that make any sense?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFzgO0AhGFODmgc1%40elver.google.com.
