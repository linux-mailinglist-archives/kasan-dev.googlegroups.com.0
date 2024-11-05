Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW56VC4QMGQEHVBOV5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D14469BCDFB
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 14:36:29 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2fb515e5080sf31897241fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 05:36:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730813789; cv=pass;
        d=google.com; s=arc-20240605;
        b=iviOEpV0wsX1DqVng4axfCOrAkwC8B3X4cAaLAI03BDL29PARH3+G6p3IVF7QUSfWS
         Zi9sblO1hH2gxoz5pqzwc8mku3pQV5PaLbAhDjsWfAkZrTOUr8bNx8idHXWal5aDPlTP
         XwAapBWHbhrSxtacmpJvVjbtG9j1/cph4WUV3U4Sj5UvQXXpH/BBTm9FIsRQ0efq3XGa
         aMSOOD6xW0igaM+pO/RNkt4aMFkSEfdrKg+NbIDgumx51Pvs339cCok+yGoovkELFr+9
         qYiAjUUcnJEVjSwC6EAwdMMKUJge7mGcgFFif+2OxF5Hu4MfC3mVaZsnEJXCM+X7OP9t
         FPYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=crHAObZPw1+MhNSZalzdtd+x6hxPPbn6zDklS7yOaVc=;
        fh=MaZQL+kUqgLtoFHj0mAjakNc21iagz7wg1OojgTZ+Zk=;
        b=I3DI0Xq6Ap0MHdYp3cQUY0Gp/Mnwr2EBamUHgvxajq/APY44Nrnb1Gr51k/lHN21jP
         q0Y04Qamtbs8CJDSjMtdekjEifJj1KnpTiZbVrVlNnoN3uPu9yXOqV1m4CMFiJNsMmTX
         xi/v+0WfCv/8PWNr3b3NWon7/8yjBZTJ24Nk+GkjjlYs+L7ijocvkXIfdjfXdf75FNeS
         RvGNC3sQUt4ZZyn9KZzjXv6sYQ8nXCxt5sBGSJgzIKSd0WSnk7ChGB+pjBsmKqZO3rrm
         ZUtKSyZkQSiKhP9H8o/lLWt90S/Pr/Yp8fA6XwiGgE3eSvKiGcVodF2w3+1pNP3RfZTe
         HHPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TQNexxKm;
       spf=pass (google.com: domain of 3wb8qzwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WB8qZwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730813789; x=1731418589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=crHAObZPw1+MhNSZalzdtd+x6hxPPbn6zDklS7yOaVc=;
        b=B1FC8AMXs5GuUHOmXpbcrY5q0bpstWhw00iOSxvHeZ3y2pznamkCH+kFOo4sXdTy70
         yo7LyimSiEmAlE6HwSimEBOSodoDXrDpQqf96yOvqoEKy0SChc2Okl0jY7ttzRUs+gz9
         kNoSnE1kwVXvCt4+ionNZdAM2r3kWMt24X1wv6Ez9Z97UPJQckNU5aSmHqVUi63AO+Fg
         9Z7gWdMC3EvQpkvU/3kBXA64+exH2FZ7JV6J+Nec2b2ILwd81uHcx5FFgkADxo0PFG2a
         ziwjkNdIv0P2aWnOLTY+yI8wSPsi2Le924pCRixEOvNgO9wgi5S+JHc4IWlJ8NYKl4rW
         VA8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730813789; x=1731418589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=crHAObZPw1+MhNSZalzdtd+x6hxPPbn6zDklS7yOaVc=;
        b=g/8nFWqVPg4SV9mfQ+7q3ropePBMOT7D4NsmVXLJtmASlPMskJO4rs6rAJ+AhaE5Xy
         Dftpeax+k1IejyrogHnE0lRd86JlTKhcjK2uJSq8Zf2GdObczGm3vzOhIjrkEJWnymP6
         rl3EgDS4kBbwER0SMFJyznZeCdPEcVAjNBlJph/V6fCdz0gep2A4BIKIEGT9I9XP75Pj
         YcaWzsVnAX9GPq9LYQQ48PCG/3k4kY2PdvXhobcKYJQGwDrr4UqaKKz6aGN76WnDDxUN
         RNn7zbJWEsS4IDWtHJGuoeUa7WfnDDKSXlAgxXHICvFSvJbIrEzstwmEqsyJOowGZYOK
         vZzw==
X-Forwarded-Encrypted: i=2; AJvYcCVW9mfmOB2NoM1FQDxWAZM8SNQZAMr2o6+/FK+LbTRa6/CXWKZD6Y+Km0uNi8tsjkVcLFbGaA==@lfdr.de
X-Gm-Message-State: AOJu0Yw8vcB/q5RGMvwm+EdcJMaFfKCCe8TAoIeiSNYWK1eEiMpgdyNH
	S1JYEvGl2uBkvtpmHW+o3V9KuYxC5Dug7EuOgGdmcPK3pzHwYG+t
X-Google-Smtp-Source: AGHT+IHKuRUP3gqMwoWsvGmbRzX17lWMi4yCOjPEW0UDxAGwUwoIa8tfGiUJtwD0xYboxg4McGg4Uw==
X-Received: by 2002:a05:651c:160f:b0:2f7:64b9:ff90 with SMTP id 38308e7fff4ca-2fedb7964a1mr71060231fa.9.1730813788158;
        Tue, 05 Nov 2024 05:36:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a83:0:b0:2f3:ee66:7ce with SMTP id 38308e7fff4ca-2fdeb638665ls10197991fa.1.-pod-prod-04-eu;
 Tue, 05 Nov 2024 05:36:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDJpeYHtdLY6FSrvBXcwCU8SCsyZaNXCmb5kitu4Yhy1UGMA9gwVa2iUOIsd2x2ueph1p3nl1Sx2s=@googlegroups.com
X-Received: by 2002:a2e:a98b:0:b0:2fa:cdd1:4f16 with SMTP id 38308e7fff4ca-2fedb7a2a1dmr67990561fa.14.1730813785348;
        Tue, 05 Nov 2024 05:36:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730813785; cv=none;
        d=google.com; s=arc-20240605;
        b=QZogR+M7No1dtaI8lQwGRhxuluMFGQDpBSjCS0mXFgs3qViEkqP/8BFKTA3uOp0y3F
         Jcti48XjDMHcqbKw805ev1U5eNe2aXOnaU3pq/QrZjqBQpT53OxmKUhytI/o7uz1Ab8y
         M2KBbIKuAXcJRqTWz3poK6IpwZjwc+ysNu+EIl8mfu2j8MViCRN8Lbim1UH012PiP75l
         sy738Djdvrg7SqzMaAtkVPy+hHuXe1SwmqCoOz2krfbtaqNniBlTzgpfnrCTALKtyh2V
         HJqUJc7fbT+yUjC51YFZnfTmOkWSFVcevVltvTcu8aozIljNazbH4oYHlfqcNrcpg7je
         t0SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Q96ispV8rCEDjpMmWoKujMwIU41P/PM6SRfoGhF4WFA=;
        fh=j2mq6p4x+b6dkbE1tnXTd2eptB2vzlWx/2WqWQ6cgDM=;
        b=f4payeT0qRJFeF5yJ3rORKL9lKEqNxVqNKfUaLzd0uRL59yq2OIkkMpCSYNkBTFu2a
         bRj1DaAkptFDlfxX0oECybTocUcQc/10M/7+UJjrea2OEVhQva8Wd7B49xVQHWu1mMoU
         BB8EI9ILYMKA90o2UbW2oQTYenooPKhbKRKJJifdZM6dX1zb6aGR24qKVUkdXYUR2RBG
         M7NWPYMkU+rmJwrJNPdhIQxDfjepLXfFSQ0geyIf+ZCivIe1X4HWSLrys1GQMkJwWpxX
         t37aY03yl0eTEtdE8jGdAr1LgYpd7qlqlTQMCpORDe0CTNsUCb0osKa7XyszYh6Wci2L
         r5Vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TQNexxKm;
       spf=pass (google.com: domain of 3wb8qzwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WB8qZwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fdef8dcbafsi2816781fa.8.2024.11.05.05.36.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 05:36:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wb8qzwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-37d5ca5bfc8so2624412f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 05:36:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUVIPAGoV+Ug9jQye9jQGPo6xkVmUI/gJprmTHDrlE9aOFbSHAj1oExMK7qvKDvE6/mRT4c/XFyrws=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3bed:38bc:b99e:8acb])
 (user=elver job=sendgmr) by 2002:adf:f00b:0:b0:374:cc7a:d8e0 with SMTP id
 ffacd0b85a97d-381be7d0165mr8626f8f.7.1730813784559; Tue, 05 Nov 2024 05:36:24
 -0800 (PST)
Date: Tue,  5 Nov 2024 14:34:05 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.199.ga7371fff76-goog
Message-ID: <20241105133610.1937089-1-elver@google.com>
Subject: [PATCH] tracing: Add task_prctl_unknown tracepoint
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
 header.i=@google.com header.s=20230601 header.b=TQNexxKm;       spf=pass
 (google.com: domain of 3wb8qzwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WB8qZwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

  <...>-366     [004] .....   146.439400: task_prctl_unknown: pid=366 comm=a.out option=1234 arg2=101 arg3=102 arg4=103 arg5=104

Signed-off-by: Marco Elver <elver@google.com>
---
 include/trace/events/task.h | 43 +++++++++++++++++++++++++++++++++++++
 kernel/sys.c                |  3 +++
 2 files changed, 46 insertions(+)

diff --git a/include/trace/events/task.h b/include/trace/events/task.h
index 47b527464d1a..ab711e581094 100644
--- a/include/trace/events/task.h
+++ b/include/trace/events/task.h
@@ -56,6 +56,49 @@ TRACE_EVENT(task_rename,
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
+		__field(	pid_t,		pid		)
+		__string(	comm,		task->comm	)
+		__field(	int,		option)
+		__field(	unsigned long,	arg2)
+		__field(	unsigned long,	arg3)
+		__field(	unsigned long,	arg4)
+		__field(	unsigned long,	arg5)
+	),
+
+	TP_fast_assign(
+		__entry->pid = task->pid;
+		__assign_str(comm);
+		__entry->option = option;
+		__entry->arg2 = arg2;
+		__entry->arg3 = arg3;
+		__entry->arg4 = arg4;
+		__entry->arg5 = arg5;
+	),
+
+	TP_printk("pid=%d comm=%s option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
+		  __entry->pid, __get_str(comm), __entry->option,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105133610.1937089-1-elver%40google.com.
