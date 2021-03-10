Return-Path: <kasan-dev+bncBC7OBJGL2MHBB66EUKBAMGQE7FKNP4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 455E7333A43
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:42:05 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id a6sf8611288plm.17
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:42:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372924; cv=pass;
        d=google.com; s=arc-20160816;
        b=vzqQT8v7OkLzE249QAW0V88C8BttSwnZsgOqKx04NLoOWWC91s9s2LE3ieApZwzg7E
         2PhE269n7qH+MMTubbVqEL+2Mhzujoh178hD/ouXyNbVzUk7ZKjjz8K4CyX8BD2xyRHN
         YQ2niWF76GSVcpyC+8rS8xKpE7CW21mAzFLCzlFILCQxqohVxHKklxLKQMuBcdf4ClC9
         zDzpIMh+7je5eAfp22iCN2g2KDuoHFTxNtM1vj2uG/VKF1ac/KEnpnN3Sa/ictBdf/OT
         sEaOQIFR4u7BeX7dPXY3pNCzuq/uFBZCVqFEEJfbuiKQZfdjK9PgLojR+gg8NogfB3a7
         y3FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qtYbiaQP6pN5R8XIJKOtAmpIldiFVcQ8zudas2m6GeI=;
        b=UJUAOBd9DDhYOTlexFyld/vW6mCgyveKoiA4rLhkvDF2dVbFLQHwfboyBdwYSROzUq
         K+Zyee7vzHJp+27o90RIZzpxxWmZyOWSfYW4DdRFhlQpz/IQDOwrhcGEJ/vo4Bo7OJgQ
         KaByDyPi3EXeT2H/Yfbwr9+E/OUdwm8yhYoBEuxGXSYwcUzwLkLMGQyMOGHeyxqB5npI
         Cu1KhzqA1mgk/OwQJ/c7jasDTY+vZfFqwC9kz7QY7U2JA7vFASyQJZCc/VfcbyFdfVcv
         siebKYfiEOprrURcSi0feOpUE6MQ0zj0VfEa7mmzS4NJ1K+SJ5qZBJhQc9X2jRiYAYSt
         vd2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mybq0plU;
       spf=pass (google.com: domain of 3eqjiyaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3eqJIYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qtYbiaQP6pN5R8XIJKOtAmpIldiFVcQ8zudas2m6GeI=;
        b=AfPORuPmucM42aqg8flFy8JVfNcTr+49uQcZ8dWCzbQ0z4s3QvjVA1SZtjiJ22besK
         PLVxXG3ybvHqD/JARN5YIumTExQKaeOCpIGrBDYn/eQ1ZLsZcOPxfbyJEzLHPl6zbmMZ
         wq8+tO4WltrDoxHAVkbJPkEuSWouriA6UyC257Q/bSTzfRtT5ObHpgHxdADvuPdr2zwd
         LpOl5L/x4awkgnrOU/eTCWAVGBgtdiFQcEPv9D1KN2v93mAiefyOeWPRtMOAQHIGIcrw
         HGxMqZVaGL+kAfzA4bBHPI2pqELxGdgW85JYttOLJsas3ZPEFCmRZOslxMpygJtQ6zLg
         NUGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qtYbiaQP6pN5R8XIJKOtAmpIldiFVcQ8zudas2m6GeI=;
        b=t48B8wYq/ukJ+CDzS3TOS1pl51XAZf6yRMiXryANJ6e6nQZD+MTq/Njvm+W0gngEAz
         nArQnq7U0ppwtAWBKbufK10ToePPRxrOvzflxPBmNZiTrMBJENHyuqopy4yw2wRGFrpq
         tOmbhWmcQIUzILXxlbwWBmbZ67uvAhJJqZMOEEEFmOzY+pFyBr6/IlTTABU8z+TYzbkh
         z4Epw82+mSrKAIaLHlSRfX/Xfe1FEgXkEB/vndQ/vf3ZGt9G9yq4rg+wX1YixQefRSPi
         MIHOFx+K2+pGDoEoWSNBhbUgc1uh4rtCT0yKKkdTLyL3BdRv42YkSDLvFEICd4TfTiJI
         Z1DQ==
X-Gm-Message-State: AOAM533B0DCs2YrGQkxupVAdzuwEGLowGcBAjuIaIFV5MROSaKp486Gq
	5BWgQeWc8+b6iAPSI5DtRJU=
X-Google-Smtp-Source: ABdhPJxcX9OQUbamKPtov0s6oHeKFi6RDZhvPo/tXgdHrby7nVF6B2DMhnoPSSfz0ud0XsGJiQnAkA==
X-Received: by 2002:a17:90a:a481:: with SMTP id z1mr2924165pjp.161.1615372923777;
        Wed, 10 Mar 2021 02:42:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9106:: with SMTP id k6ls1279108pjo.0.canary-gmail;
 Wed, 10 Mar 2021 02:42:03 -0800 (PST)
X-Received: by 2002:a17:902:7208:b029:e6:52f3:aabd with SMTP id ba8-20020a1709027208b02900e652f3aabdmr2443267plb.74.1615372923153;
        Wed, 10 Mar 2021 02:42:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372923; cv=none;
        d=google.com; s=arc-20160816;
        b=RpiqIown/+768cKj5jhe/FByGrhan2cjjGn5BnKZRDJNj6NMI78S6LJj75gogJvSwu
         dbdauO7Ggj9RvB1id533RSYzxBSVpaDHkZLUQYP6La9tYVDpAWMLI4ktQNS6vPI88sPW
         CWInqNUA/rQeWIKIm+Ptt1pZhMt6Pa/NmyVV9CXqBZlEw37/N1TsPeVCp8ALLv8w2cNJ
         Q6JR1py2faZiB9VFQjUB1IppNQ+gasliONiAtlZy+ZTTjF2wYBioRUs8twmsCv4eZM8l
         vIOY9Z9uGu1eRd1qj32clZ7jmnVi02sWh0ciCL73kaqi3yF9jJAQ6EOoRnF/KYTWY7V7
         NV2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=MwMG/Kl+Surl9jPDmtCK7rCt1fJ8HAEyxyLN1urbLCM=;
        b=TeXfjvAY+2jb+bV4sqSr6Ilv6XN5K615HHzU12387+CG90ikwu/zZspAWZAB2di8gS
         q2uiaDUkPwRLx1FUuajVhzskR7tgU/LIPIimp7ChB4TpOdA2AfQn4IQlEZQdeXnbaO6Q
         gsQrjFhhLYGzdcLzSpPsE2sVC/EfnKw+Xd/B25iwG3QP12sGVhNG1WtNcQQauaMSRlRp
         KetMc+VJz3tY7Omq4/j7NNWc1cpYeX3FAfmpU+Pv7bwMyuvdPEZfNB0dgDqXgteufxCQ
         HdmME2RwuUB6cIA4dVCIjWNouT0m/mlGk0inLQNs9yWYOuAP/2gTkQEQGRrrgR5sMD44
         NQHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mybq0plU;
       spf=pass (google.com: domain of 3eqjiyaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3eqJIYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id j6si377425pjg.0.2021.03.10.02.42.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:42:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3eqjiyaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id b78so12385470qkg.13
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:42:03 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:ad4:5a14:: with SMTP id ei20mr2068906qvb.1.1615372922271;
 Wed, 10 Mar 2021 02:42:02 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:36 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-6-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 5/8] perf/core: Add support for SIGTRAP on perf events
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mybq0plU;       spf=pass
 (google.com: domain of 3eqjiyaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3eqJIYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Adds bit perf_event_attr::sigtrap, which can be set to cause events to
send SIGTRAP (with si_code TRAP_PERF) to the task where the event
occurred. To distinguish perf events and allow user space to decode
si_perf (if set), the event type is set in si_errno.

The primary motivation is to support synchronous signals on perf events
in the task where an event (such as breakpoints) triggered.

Link: https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use atomic_set(&event_count, 1), since it must always be 0 in
  perf_pending_event_disable().
* Implicitly restrict inheriting events if sigtrap, but the child was
  cloned with CLONE_CLEAR_SIGHAND, because it is not generally safe if
  the child cleared all signal handlers to continue sending SIGTRAP.
---
 include/uapi/linux/perf_event.h |  3 ++-
 kernel/events/core.c            | 28 +++++++++++++++++++++++++++-
 2 files changed, 29 insertions(+), 2 deletions(-)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 8c5b9f5ad63f..3a4dbb1688f0 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -391,7 +391,8 @@ struct perf_event_attr {
 				build_id       :  1, /* use build id in mmap2 events */
 				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
 				remove_on_exec :  1, /* event is removed from task on exec */
-				__reserved_1   : 27;
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 26;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index bc9e6e35e414..e70c411b0b16 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6328,6 +6328,17 @@ void perf_event_wakeup(struct perf_event *event)
 	}
 }
 
+static void perf_sigtrap(struct perf_event *event)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_code = TRAP_PERF;
+	info.si_errno = event->attr.type;
+	force_sig_info(&info);
+}
+
 static void perf_pending_event_disable(struct perf_event *event)
 {
 	int cpu = READ_ONCE(event->pending_disable);
@@ -6337,6 +6348,13 @@ static void perf_pending_event_disable(struct perf_event *event)
 
 	if (cpu == smp_processor_id()) {
 		WRITE_ONCE(event->pending_disable, -1);
+
+		if (event->attr.sigtrap) {
+			atomic_set(&event->event_limit, 1); /* rearm event */
+			perf_sigtrap(event);
+			return;
+		}
+
 		perf_event_disable_local(event);
 		return;
 	}
@@ -11367,6 +11385,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 	event->state		= PERF_EVENT_STATE_INACTIVE;
 
+	if (event->attr.sigtrap)
+		atomic_set(&event->event_limit, 1);
+
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
@@ -11645,6 +11666,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	if (attr->remove_on_exec && attr->enable_on_exec)
 		return -EINVAL;
 
+	if (attr->sigtrap && !attr->remove_on_exec)
+		return -EINVAL;
+
 out:
 	return ret;
 
@@ -12874,7 +12898,9 @@ inherit_task_group(struct perf_event *event, struct task_struct *parent,
 	struct perf_event_context *child_ctx;
 
 	if (!event->attr.inherit ||
-	    (event->attr.inherit_thread && !(clone_flags & CLONE_THREAD))) {
+	    (event->attr.inherit_thread && !(clone_flags & CLONE_THREAD)) ||
+	    /* Do not inherit if sigtrap and signal handlers were cleared. */
+	    (event->attr.sigtrap && (clone_flags & CLONE_CLEAR_SIGHAND))) {
 		*inherited_all = 0;
 		return 0;
 	}
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-6-elver%40google.com.
