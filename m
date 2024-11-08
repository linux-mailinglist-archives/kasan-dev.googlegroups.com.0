Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XOW64QMGQE3ZRKJ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B56839C1C3A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 12:35:10 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e33152c8225sf4306017276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 03:35:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731065706; cv=pass;
        d=google.com; s=arc-20240605;
        b=W1bFHXhIM8EJcDs6aTCfnyVw4CEeKzcoj9mXJzChe8f5eWSzhU/DpV9zDOKK5KH22h
         bYClX25OCh1rLtUkyh6Mmut9j0v+Lnt9gVCfdaBw0bRMRno/owlc0YIKqSpHsCAFuNof
         FKIsxyrXKNo9troscOqWudJp1AhWZwtpwzeXuhRYiOnLOssurL6hVhechAW1rSTcSQLb
         LI1xTehI1lSLJCs3JJKblJAcJUGAMO8S6ABDEqOIaYBDguecSe8pfwNhTW5V/VBwPI0x
         dGk4noPtV6AABCDeLK8mW3J5/TjGpUwnpcDFMNDeshw7i7FuEtfHWqaJZmLGjw/tBG6e
         7wHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=VTmOyi3bfXLsH22ruMYFVZuJc9z/2VxDnqeXV/e4OvM=;
        fh=TTvXs5ywZP85d2srHhhsprUTiIuAomgj4UMD3b1Twzs=;
        b=QTPjWCt7UKpATZ1CCnaC/LR4apt1/eTWKTPMkTFpzYX8rkoxXxeClJ77NwVx3QJPnK
         2CE3uf1o/4GAoBhl2C8GOGc9/iLJqQIVdAhtQX8RbwuVk36K/ZUnjcoFcrNmV93MQqZU
         h9nzbB6LOL9ALvUKbXtLPUiDwAaynD4mlqThzIUxTxA8bStSYxPQMD9zwXNgdQJ6Hj46
         Lhi2pGXUvDjmpbaDDo6dpJhGrMTIpNOZCe7uvOs60sIs5g0MbKtRyVRBJkm9aRIcN4EJ
         tEU8Ge+kXs/VrW9ox5B2ji8hWExWgAeONoEud5ZPup43p5f3oPpMZIbasmrj6u9UbqvB
         CEJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SVWrGR/A";
       spf=pass (google.com: domain of 3apctzwukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3aPctZwUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731065706; x=1731670506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VTmOyi3bfXLsH22ruMYFVZuJc9z/2VxDnqeXV/e4OvM=;
        b=cfMGKk9K4I0+MXU9NWKFxvVFUb8eTcEbZjNcpUiDQhuifHyLbUJ/9IUf2Z6c+irY1r
         x+R8vxylKklKEx88yIAkqaHP8tfVRbKDiiSrVBKXUbRox6wkQ/FlaAKLcsy2SVzoGTdN
         uyclMKXzpVVnFWZ9CJZhFxOqudL6yWKUNiu96TO7+8Vv1ApiF9ACRmRITpKLBMXDPJul
         zvgG65KKBZ+N/Wvm5/uzz+K5IAG9Yjvr6AKysMgJbJf2X6sWgCGJhpk19lClGdNnPtTX
         ePIDa6xVyWyUwVGFlj3qjPSgk+JSACSC7NAmt0a3ZzfUN3jfQz16o0i4No34gVA8sd3s
         z9EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731065706; x=1731670506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VTmOyi3bfXLsH22ruMYFVZuJc9z/2VxDnqeXV/e4OvM=;
        b=KAph0T5HZGUcMo+7gotILJQ/782Q4vMIkNz5Z7UmzcEuu4/tVee4frxHhjQUiThui0
         qcMbfWfd9Bo8tCtBm3zdpx9FfTndjfsqdd3v2JLwbV1NQgP0tfcS45FiJ9nt3P1//MlC
         h6p18hPx3x00OFpb6oyd4xgWfo3iJwn9ppFlvYZbSMobXu3mDPkuF0/HSOaBfIG5I3DS
         L71w4rmhZyOHRy9HvWzDBuyzk4bnCUDQafsAm/QZyGPDoo68r0RWHt4Wbk7a4A+5pyki
         pKq++ruY/V73e2DLmdCQxmm2LddHdOPAmQTPokvz25QkEZdK5+Gb5u69k9lFHSvQuXcE
         I/XQ==
X-Forwarded-Encrypted: i=2; AJvYcCVCaON2sLRBj9U9yEIW8dHAouFacJLl04EPLRAQ4Q6dMD4wXhtsXiikUeM7ix3Y0ids+eLk8w==@lfdr.de
X-Gm-Message-State: AOJu0YyS9el2l8ZywMTzWvUqLMA56HWRN7WopqAbDtET/1Agfq1wPO5J
	ciT3ZeQ6I+DLLPVfaPidI5IWLTavJZJSWvlqAgQu0beYHX8DpKA7
X-Google-Smtp-Source: AGHT+IFPR37gOHSD8NolzzpWzFErfBw8fxEK1qwsgYgSk8e2MD3uAk/w/nW9WLRfSZcmAdam9RBpzg==
X-Received: by 2002:a05:6902:18ca:b0:e30:d975:6567 with SMTP id 3f1490d57ef6-e337f844803mr2849658276.5.1731065706255;
        Fri, 08 Nov 2024 03:35:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:3298:b0:e2e:426f:a681 with SMTP id
 3f1490d57ef6-e33684ee4d4ls502241276.1.-pod-prod-04-us; Fri, 08 Nov 2024
 03:35:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVdGnKwt0hXjZMblJd9A8YzdSx89mkOkxkKEJiqPIbZ/yv3V7ACXrNpYP3HRhizysEFYwU9v7TNmO0=@googlegroups.com
X-Received: by 2002:a05:690c:6086:b0:6e3:3007:249d with SMTP id 00721157ae682-6eadddad8a4mr26558277b3.25.1731065705003;
        Fri, 08 Nov 2024 03:35:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731065704; cv=none;
        d=google.com; s=arc-20240605;
        b=Qodm5wkJnmDuzvs3MkIgUzEgHX/XPIMr+TktEUq7lWIySt8p+p0ylGH4jrPV9+OWfd
         D3BFw7r5zOMQc9g4AiSIYnjJceVxOdX5vaKomFO1198LsMnPGJJo49OvNfBUXjmrpqU7
         mBBD59ewaEfux1UR9hgZc91IvPDJGRq+pMjrhG8NMzi2vrHfrarx7j5y2BSW3E4/+1ut
         Qo9Vu2lAZYRJ+YPYVZFmeW6h0DWZzqwiGqCOiKcey+gM+Fm8e4UGvjEA+6v+38j8y6FW
         4l1r4Ri8kjf4wIbdP5J+dVNTBeJJN4o3IkAPaulfs9DPfT9SAsh709IWjtJ8VcDnowBY
         1bFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=D42rLpD50SsNXuzg8LivD2CtXeeoEvwN95ZboPt7X8w=;
        fh=mDTOI9Q3/tPiY0TOuTbwrGO4YPXhbKO8hG0IIWl8ras=;
        b=YqEtbn52ZP6LtTZUc0vI6dyjJd8rKvnnZbPRc9DAaAou+Cap3yipZjHKvhOhpSpzQP
         liYA5ZwJGjooftNl+APXU5eQrgoYj8AnYt1nD/oP2wFpGnc8HLlXfDvBeA0u0TFNTNsA
         VtlioDOc13Pwgw3QCABmRe1psaM49xLu4y8xZBhDRdsAaHM44effu90vpaP1HH4HuIhR
         p612JiYfFpNLozrrqWXAFjX9gBqIGeAV4rY8DtTzpxFTGzhOFmKz4xuAdHA58o/3wm3N
         4SSh3MiEZEYIrquilcelL9zOiIRMlAcIPvyTOPNEYhxQRf4tHS53/IQTdC3tdi2t8lhO
         SruQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SVWrGR/A";
       spf=pass (google.com: domain of 3apctzwukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3aPctZwUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6d39622170csi1566156d6.1.2024.11.08.03.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Nov 2024 03:35:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3apctzwukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6ea86f1df79so39131517b3.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Nov 2024 03:35:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW8rjA18vVCpJJ3Bp++H0LLtFNsSwR4jiHzdeuuaS7kku5jC4sPyHNjZKNnyyjAtx1MejriOrS+3lI=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1d41:9aa5:8c04:911])
 (user=elver job=sendgmr) by 2002:a0d:e703:0:b0:64a:e220:bfb5 with SMTP id
 00721157ae682-6eaddd87123mr145677b3.1.1731065704476; Fri, 08 Nov 2024
 03:35:04 -0800 (PST)
Date: Fri,  8 Nov 2024 12:34:24 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.277.g8800431eea-goog
Message-ID: <20241108113455.2924361-1-elver@google.com>
Subject: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
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
 header.i=@google.com header.s=20230601 header.b="SVWrGR/A";       spf=pass
 (google.com: domain of 3apctzwukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3aPctZwUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

  test-380     [001] .....    78.142904: task_prctl_unknown: option=1234 arg2=101 arg3=102 arg4=103 arg5=104

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Remove "comm".

v2:
* Remove "pid" in trace output (suggested by Steven).
---
 include/trace/events/task.h | 37 +++++++++++++++++++++++++++++++++++++
 kernel/sys.c                |  3 +++
 2 files changed, 40 insertions(+)

diff --git a/include/trace/events/task.h b/include/trace/events/task.h
index 47b527464d1a..209d315852fb 100644
--- a/include/trace/events/task.h
+++ b/include/trace/events/task.h
@@ -56,6 +56,43 @@ TRACE_EVENT(task_rename,
 		__entry->newcomm, __entry->oom_score_adj)
 );
 
+/**
+ * task_prctl_unknown - called on unknown prctl() option
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
+	TP_PROTO(int option, unsigned long arg2, unsigned long arg3,
+		 unsigned long arg4, unsigned long arg5),
+
+	TP_ARGS(option, arg2, arg3, arg4, arg5),
+
+	TP_STRUCT__entry(
+		__field(	int,		option)
+		__field(	unsigned long,	arg2)
+		__field(	unsigned long,	arg3)
+		__field(	unsigned long,	arg4)
+		__field(	unsigned long,	arg5)
+	),
+
+	TP_fast_assign(
+		__entry->option = option;
+		__entry->arg2 = arg2;
+		__entry->arg3 = arg3;
+		__entry->arg4 = arg4;
+		__entry->arg5 = arg5;
+	),
+
+	TP_printk("option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
+		  __entry->option, __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
+);
+
 #endif
 
 /* This part must be outside protection */
diff --git a/kernel/sys.c b/kernel/sys.c
index 4da31f28fda8..b366cef102ec 100644
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
+		trace_task_prctl_unknown(option, arg2, arg3, arg4, arg5);
 		error = -EINVAL;
 		break;
 	}
-- 
2.47.0.277.g8800431eea-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108113455.2924361-1-elver%40google.com.
