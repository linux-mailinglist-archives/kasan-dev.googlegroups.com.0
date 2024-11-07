Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXEWK4QMGQEM3RYQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 82A4E9C05B4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 13:26:56 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-288b904d3d3sf777099fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 04:26:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730982415; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ke7dx74138ywNu8XzUmaNrphCNowC/hRp8ujRn5ULhxVuHimmmBUssj8DOH0ixSX6y
         MT1QCr1AL+GtT0WGn25bQy21+dJY4lCLQyKJHRpx33/QlWGhUuWYtnbXACIlnACgrS+w
         vyK2hwAR1E/ppnuoRtgxsYOt7nVcFYxA7j9EOUYVw6G0bu30XYiOKNLRwUM+0WmMG8o3
         6nhA0KzkeXMu0C8UuAQ8jZ2nHeXw5NxFpN4W1EbLjMbH0NZQnn60MjqLM+6JyIYeuY+y
         eh6MwNpzVsAj8dd9hL7xcxiK81qW453N8y2XnztSjwb0I03fbOIpEELQDrrqikIP5ww+
         aGhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=co5MQHJkIdnsX+fq7ncr12IIPog68VYt6/ZyOftcq5o=;
        fh=4gD3j2d91g5VDv3vzNfi5mH7EN1FMkXZjn0eRhCApy4=;
        b=REa+AFtpa3SMOP51Akj4teo2ONC9tVVO/6TGv4iwv1A/aNizak4Tyt7+v6KMGIonkS
         /CDXlQT0i9L8kQKQI5e20HR8nnZJnSOmNGRQHzRHuZDxqT2Y896KRnAWsUFHvNfrtpnX
         mE2F71Yog72EHc/75QPjTbqdPZfVCEXwJ0EriyWIQIrZH8rh+wLd/Hze2C23c9XCvj9W
         zoW15vnjwRDDsWryjpumozo795KQPeyZXx1Kr9SJqZqDimStVsyevMHCPz5UpQK61j1f
         eSIpUieqRaA9wwhns2yL10ggZt6YqCtVTEtyduvBIxLoe9jizefVhd3iiYWi6vYAxnJp
         k8aA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d6kmBaWi;
       spf=pass (google.com: domain of 3dbiszwukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DbIsZwUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730982415; x=1731587215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=co5MQHJkIdnsX+fq7ncr12IIPog68VYt6/ZyOftcq5o=;
        b=d7Eb08t1+c8m3wJi6rqoK9ESUV8DAoTf2OxEvylKeaLLTZ49cwOUeKw3uzzOj8h+UQ
         8WiKde5HDD0N3x0HD1JQHUSR7LPlApkDZc8sIKsoRYsNzcHJ41n5AmewifSNxI2ZAT6R
         mdUQf0NfrKIeqKItUV3HURIT9wF6tZUAoJ5/Y8wLDIDl9XbSHdEtOD0x8My0VuPsfS6b
         KCim9qlsnTrVK/i1v8hunUk/WGfr1W14O2i30IanyL5dEyonqqWeEUIQq70x61Tp589T
         TLloJ7DCvWoYtVfSH3Fj8qw7vio6r1JBpQy9dfuogDYR6fSj8/bN+yzaz52VvvoRGn2p
         VD2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730982415; x=1731587215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=co5MQHJkIdnsX+fq7ncr12IIPog68VYt6/ZyOftcq5o=;
        b=OyuVe98CwnUQX5vSo2ZgFJ+y9bLBUNCzlSMt2AdutfzaO2a82X1oU9KWIqer3bFi4D
         Vt4SJ8saBGBLABeKYyYKSZmUHqpG5PAyhx+kwmzrl2SSVpgSCrtRRAZpIRjx4y36YmET
         Y6yfp9uI8pBZ8Z82GhLISfvIMkSWXEoKb60/8WDjF9Ow+ixTo0Mssp47J6kxt1KgR43G
         9ECzdum81rjNIINtts3v+j7JPv9wh5MvVYjWqKgFeZo1pTx0447evoEy2qIcNWkXdl12
         /npClqjkDPWNnXUo1VMdVRkubRuyXDg17bnb7rBUxwEDt4C1xCaItVlkTOEdMMAq+7nW
         yp2Q==
X-Forwarded-Encrypted: i=2; AJvYcCXYINXScLnR+gTmaRgbuJWA/36uNv9UBk7MJPekZMq/QFTTCnJkqK+kLbxy+K4U+endDwYvxw==@lfdr.de
X-Gm-Message-State: AOJu0YyC7rVsAe7acMMb9wActMI9hBisTBbrd2cUcs4kEE4Cfjctlevp
	XHz1FOpoxAU0L/knNr7tquXlFuYPaev/Cc+0u7vclVMvunSTSv4A
X-Google-Smtp-Source: AGHT+IH9O3y8wR2ag/jeaxm+9OJ1TKZKcQnHNlLKoDqgKd0OiMxgniWuOJDpYivpukIGxz5DKwQcmQ==
X-Received: by 2002:a05:6871:4a0c:b0:291:e24:55fa with SMTP id 586e51a60fabf-2910e249220mr21198828fac.35.1730982414882;
        Thu, 07 Nov 2024 04:26:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c69f:b0:277:ef03:8cc7 with SMTP id
 586e51a60fabf-29541016b9cls859849fac.1.-pod-prod-08-us; Thu, 07 Nov 2024
 04:26:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVYZbeoXzaBlTKt4PEzZ8N/S54MI3wXskq1DYi8TR80yjanyM935fSq6sjNf6AKLD8RPeokSedvlLM=@googlegroups.com
X-Received: by 2002:a05:6870:391e:b0:27c:a414:b907 with SMTP id 586e51a60fabf-29051dc64e1mr39029216fac.33.1730982413788;
        Thu, 07 Nov 2024 04:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730982413; cv=none;
        d=google.com; s=arc-20240605;
        b=W08ly/zSOPRePOErVXNm84ahnUNlSyvl/fSUVbt5TsCpC80pGT+ysaVqXhX5SAkmZR
         /0tLxkQX55xEqh/awLamnLP4S0QJQF3U6uxI8pXPsLlP2/LxcafLfOYpkh+TAVoG0cZN
         rX77j8nmNlP7bhF8WYcoWaqwbk3rUoHTnRc6ookP7zFLprW9H3JE1GpFyU2t14SqGwOS
         RWTSeJqw4JjlzUlYNQkpLHeFAU/udHFGq71c/ldL03F7I3X8A1nXWUSY9Vpm1h1C6Mkz
         FDb0Fwu2NOnV3gVV3JfG9Fc4aiVRXrOXn8C71LOiXeYXsop2gTslMcU5P5IBcB6r5zeI
         X8bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=CeVyxMRNAu4YKoFjlmD4iAHOUci1C9nw6Nm/olK2Dyk=;
        fh=9BbRIP7CYtIyl9ZP5a/BTds8zKGcrm+QYsR+nT5TemI=;
        b=cs2S7mwPHo/nUbMHraxeBCdjBNXZF5946VB3fDy6HqQaAF8mj14VFfx5NTXA7iYp6v
         bVN88gZcKUA/UAHNKgrJL7GnpiegHO+sVNmdlxk7HPF9t6Fg6B40qdFW+5UZCB1wTDcO
         CobpaE5chwO+gQT9oBzoX7GrnshpUr3uj3pw2/CrT9F8lRlmaPM5oxqZD9kADQgWLUNI
         6xSgLzrcNwLHoDDHOldsb4AyCu/WI7GVLrTw2M3LFdszcxfMIdMvyef+f6e37y+vbxNj
         PZosLDaYWP5KjSFmBVEB5blxK73Yz2mU2pEn704iYwGpBl6Tkm9+t2R5S2ItcfVOKnvI
         gETA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d6kmBaWi;
       spf=pass (google.com: domain of 3dbiszwukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DbIsZwUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-29546ff1263si72173fac.3.2024.11.07.04.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 04:26:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dbiszwukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6eaa08a6fdbso14969957b3.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 04:26:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZCg7NunQy+xmGxtqfmwzNvmddPVQ3TMnvwBu3kCgmu6wex+DjcYd4eOZR0ZWLvt6GNDqGcfNba4E=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8fd5:be93:a8c0:7566])
 (user=elver job=sendgmr) by 2002:a05:690c:2906:b0:6ea:4983:7cbd with SMTP id
 00721157ae682-6ead60d4cedmr11427b3.7.1730982413177; Thu, 07 Nov 2024 04:26:53
 -0800 (PST)
Date: Thu,  7 Nov 2024 13:25:47 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.199.ga7371fff76-goog
Message-ID: <20241107122648.2504368-1-elver@google.com>
Subject: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Steven Rostedt <rostedt@goodmis.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>, 
	linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=d6kmBaWi;       spf=pass
 (google.com: domain of 3dbiszwukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DbIsZwUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

prctl() is a complex syscall which multiplexes its functionality based
on a large set of PR_* options. Currently we count 64 such options. The
return value of unknown options is -EINVAL, and doesn't distinguish from
known options that were passed invalid args that also return -EINVAL.

To understand if programs are attempting to use prctl() options not yet
available on the running kernel, provide the task_prctl_unknown
tracepoint.

Note, this tracepoint is in an unlikely cold path, and would therefore
be suitable for continuous monitoring (e.g. via perf_event_open).

While the above is likely the simplest usecase, additionally this
tracepoint can help unlock some testing scenarios (where probing
sys_enter or sys_exit causes undesirable performance overheads):

  a. unprivileged triggering of a test module: test modules may register a
     probe to be called back on task_prctl_unknown, and pick a very large
     unknown prctl() option upon which they perform a test function for an
     unprivileged user;

  b. unprivileged triggering of an eBPF program function: similar
     as idea (a).

Example trace_pipe output:

  test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove "pid" in trace output (suggested by Steven).
---
 include/trace/events/task.h | 41 +++++++++++++++++++++++++++++++++++++
 kernel/sys.c                |  3 +++
 2 files changed, 44 insertions(+)

diff --git a/include/trace/events/task.h b/include/trace/events/task.h
index 47b527464d1a..9202cb2524c4 100644
--- a/include/trace/events/task.h
+++ b/include/trace/events/task.h
@@ -56,6 +56,47 @@ TRACE_EVENT(task_rename,
 		__entry->newcomm, __entry->oom_score_adj)
 );
 
+/**
+ * task_prctl_unknown - called on unknown prctl() option
+ * @task:	pointer to the current task
+ * @option:	option passed
+ * @arg2:	arg2 passed
+ * @arg3:	arg3 passed
+ * @arg4:	arg4 passed
+ * @arg5:	arg5 passed
+ *
+ * Called on an unknown prctl() option.
+ */
+TRACE_EVENT(task_prctl_unknown,
+
+	TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
+		 unsigned long arg4, unsigned long arg5),
+
+	TP_ARGS(task, option, arg2, arg3, arg4, arg5),
+
+	TP_STRUCT__entry(
+		__string(	comm,		task->comm	)
+		__field(	int,		option)
+		__field(	unsigned long,	arg2)
+		__field(	unsigned long,	arg3)
+		__field(	unsigned long,	arg4)
+		__field(	unsigned long,	arg5)
+	),
+
+	TP_fast_assign(
+		__assign_str(comm);
+		__entry->option = option;
+		__entry->arg2 = arg2;
+		__entry->arg3 = arg3;
+		__entry->arg4 = arg4;
+		__entry->arg5 = arg5;
+	),
+
+	TP_printk("comm=%s option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
+		  __get_str(comm), __entry->option,
+		  __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
+);
+
 #endif
 
 /* This part must be outside protection */
diff --git a/kernel/sys.c b/kernel/sys.c
index 4da31f28fda8..dd0a71b68558 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -75,6 +75,8 @@
 #include <asm/io.h>
 #include <asm/unistd.h>
 
+#include <trace/events/task.h>
+
 #include "uid16.h"
 
 #ifndef SET_UNALIGN_CTL
@@ -2785,6 +2787,7 @@ SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
 		error = RISCV_SET_ICACHE_FLUSH_CTX(arg2, arg3);
 		break;
 	default:
+		trace_task_prctl_unknown(me, option, arg2, arg3, arg4, arg5);
 		error = -EINVAL;
 		break;
 	}
-- 
2.47.0.199.ga7371fff76-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107122648.2504368-1-elver%40google.com.
