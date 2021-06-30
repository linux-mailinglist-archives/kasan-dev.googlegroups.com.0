Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ7W6CDAMGQEOK6BHCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 631EE3B8024
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 11:37:44 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id b9-20020a2ebc090000b02901759363ccd9sf568693ljf.4
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 02:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625045863; cv=pass;
        d=google.com; s=arc-20160816;
        b=VAc3RITear2dNyOLkJYdhnqPhLuWVAp5Q3KpWGx7E6ycGN9rd6jw95mkPobeYCSs+K
         rNNUpfEQQLBMiDW9uYS1YoxKVQMYfbmrzyZfUSkni8p0m15TcUqFg3yl5JJG1yfwHqIC
         t5oi2DAbAJPTeqXNujN2wO8LNb75Vri3z442VERLFjz6KJzaVGZZyCoC0gvb80r5Hn8e
         UYgduGtgBV80JVSZga7LxBHfozhmpgYwTRFWY3Pp4zOIMXFJfFcWzgcbPE7xM3klzPgy
         dgfjqbLvJ4ZQuZEn0Up93w1YIVtCQ3uKG70jLg9Crt8BmI3qz+X3Vcqw7I8ZchW8vDKx
         k8GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pko3r3R6f5rmKANp8Ox06YvCZspHYSwr7HdoiIYSwsE=;
        b=BpNn/2579GOFUPhOJo9Slcbsug+DuI3o1vSsqu6hn2GBVHTznC+yEX2eqw231nh0tI
         gBTDITY7QEorh8QCpdQivJhoxvBuPteNmj4pqMhJ7m4yOp83NHV4YBtXT+58SYvddoWU
         JO/kTUQPua7LzQXdkhbcZoMEuCTppdjQ0v0NFpgRD+u6Xm78QIHr6v/ZbAmj5CCvjplL
         0B4wtqLzUQ0LyfQOVVUE50+pDLSeuqz3/ToPxLefEM6rskezTNVypi2KExf3SfrXEgtC
         rr7oQS5OkEuww6SBRBIPpuOB+dq5o7nK/waYLvdotsBsfxysXcwpe71HJXiT6YfNXCbR
         ZziA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hOGR+88o;
       spf=pass (google.com: domain of 3ztvcyaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTvcYAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pko3r3R6f5rmKANp8Ox06YvCZspHYSwr7HdoiIYSwsE=;
        b=DNPnvgPFdHH1m0ap9fF/tplfW3ravtCJ0qkvRprTUG/i5Eg+xh6RyE9NhLEGZaINm7
         qb/vbDf80n4df4e2vGlwh6WWkb3HWBksJVvy1YTPJTlR26BmD93ek3V630tOyPTHMXMP
         tbyiQke34oOgMgO7d24M2qq7R6T9QWd000TRaZKA9TzCSWa05ahsvNOMcKrhtvVwbPQ2
         AFg4RFd3Nr+UqXe9lamFYYP4S1tLQM01S8kIKklLCDdSvaD33G/zpjfO0YBp5XObA1qQ
         eWF+UUyUDWdNzV7cpESa8DuAhRZ1So1Lhmp2GtLQSrX2D0hrF9poF7YHOB1kubfZLa6k
         mjUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pko3r3R6f5rmKANp8Ox06YvCZspHYSwr7HdoiIYSwsE=;
        b=iyFsatAOpQ8pSJ6OZKlLU/rzCS6tbsemXRfwAT2gWm7od18wFPYryn2zwdGldwH8yi
         J0A3nOwn59IYjyEu6YVyN8Rj3yuc57zf7OYhJKXTBgMax8+aVGEB/uPwPoAO2yxmDY3i
         tjbwCMhO+ad9hnI1uIt7P0li4JPrKiVmU73xHYvvSw+2ys5MwFWLIDWUcgrQ1ormhy1j
         Ndeohd3pErmxVGotaEgUs8GS2Leq8urFzVNuCWKfktojFuGhOKbmETkFc5Ao+z9J6Md6
         CUxDPc/oEyEHXiob24xMi+fD5RBFYbHvj/FmXwrL4fxPbsiqyF8JQPXYgNawu8xZ6sK4
         5itQ==
X-Gm-Message-State: AOAM5319dDp5D+B4Axh/Xajg81KLywm8cMX6chBP6myNRK13RNBLnSgt
	8jUKvpNnG9WS+THI3kfJwY8=
X-Google-Smtp-Source: ABdhPJzwgwkrymLgX4NlA2iLS3fePCSZNDYpcO04fe4OL7yeHbiWI2X9oxcumMvkUDjzpTx0YR3j/A==
X-Received: by 2002:a05:6512:2283:: with SMTP id f3mr26088703lfu.632.1625045863867;
        Wed, 30 Jun 2021 02:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7617:: with SMTP id r23ls271182ljc.5.gmail; Wed, 30 Jun
 2021 02:37:42 -0700 (PDT)
X-Received: by 2002:a05:651c:201e:: with SMTP id s30mr7413533ljo.364.1625045862661;
        Wed, 30 Jun 2021 02:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625045862; cv=none;
        d=google.com; s=arc-20160816;
        b=xnv4Np4xNSG0Guvw8Z87eKBv1AFyyiiT4W2nobibIpSBz1xya2mVO6VTgDsOLJYc16
         FQnZE7RB/h8hZ0M3BxkBXX4wHhVYDFjB021dOdlIbqOfnKf5Yyij9RbRlM4J56M5fDsP
         X5Ga1NaZce2XfKMeoPkb3Eh4ZqDwhuw+CvLe2cmLK2Hmm9TnWfi0UEgJ2x3tdryfjw4a
         /96deuc+S6TQ7HDb2FI3kThOc+v/O4Ry8q4IwyPc4zyv91n9fGMKQd2KdJl3P+Po6JyV
         tlrbvAdo90sAUuiy3DNeKPrgK0GSqtWx7HVNhjuC+ow7RVL8P+VR4h79Kj94IjwZn0fC
         IGfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=JhgrCS9Vj640V8x1cFNbO5yNaZtMM+Zz5JPkP+NN88k=;
        b=q3OkZXCH7ymHhF5ZNga7IHsbBkhdVUP2OnTi1TA80++RzlckU7RH1iPjkpgGCGZS7r
         Wfjk/WzJOBsr6UgWN4dXI/wiKFR3ivtGxphCzCf6qEq9ZNYy5nKQAT4ZsMvraWheSEAw
         qq3z8H0Ul3xzhMeQWZZYHbAupEWBOTCdW0fcZXl77FGwF27+kFdTWRqIg/wCyTNa7S3p
         DdRdJbO6M+MfmBBhzytcK8MYbb7sLR0qUvjUHvIeNNdoGRrXvzrMNvzmdq8aT0DZnCJR
         sLXYIEkdmuUgcqEpiJqKI1Ufjc3EIhgZmpnFIiZ+Oy31eWNEHIYtkWm1d+UHSSrBcrjE
         EfHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hOGR+88o;
       spf=pass (google.com: domain of 3ztvcyaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTvcYAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e14si639043ljn.2.2021.06.30.02.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 02:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ztvcyaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b3-20020a05600018a3b029011a84f85e1cso652795wri.10
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 02:37:42 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:d0e2:84e5:6f2a:9752])
 (user=elver job=sendgmr) by 2002:a1c:e486:: with SMTP id b128mr3501221wmh.58.1625045861994;
 Wed, 30 Jun 2021 02:37:41 -0700 (PDT)
Date: Wed, 30 Jun 2021 11:37:09 +0200
Message-Id: <20210630093709.3612997-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH] perf: Require CAP_KILL if sigtrap is requested
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org
Cc: tglx@linutronix.de, mingo@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, serge@hallyn.com, mingo@redhat.com, 
	acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com, 
	jolsa@redhat.com, namhyung@kernel.org, linux-security-module@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, Eric Biederman <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hOGR+88o;       spf=pass
 (google.com: domain of 3ztvcyaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ZTvcYAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

If perf_event_open() is called with another task as target and
perf_event_attr::sigtrap is set, and the target task's user does not
match the calling user, also require the CAP_KILL capability.

Otherwise, with the CAP_PERFMON capability alone it would be possible
for a user to send SIGTRAP signals via perf events to another user's
tasks. This could potentially result in those tasks being terminated if
they cannot handle SIGTRAP signals.

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/capability.h |  5 +++++
 kernel/events/core.c       | 13 ++++++++++++-
 2 files changed, 17 insertions(+), 1 deletion(-)

diff --git a/include/linux/capability.h b/include/linux/capability.h
index 65efb74c3585..1c6be4743dbe 100644
--- a/include/linux/capability.h
+++ b/include/linux/capability.h
@@ -264,6 +264,11 @@ static inline bool bpf_capable(void)
 	return capable(CAP_BPF) || capable(CAP_SYS_ADMIN);
 }
 
+static inline bool kill_capable(void)
+{
+	return capable(CAP_KILL) || capable(CAP_SYS_ADMIN);
+}
+
 static inline bool checkpoint_restore_ns_capable(struct user_namespace *ns)
 {
 	return ns_capable(ns, CAP_CHECKPOINT_RESTORE) ||
diff --git a/kernel/events/core.c b/kernel/events/core.c
index fe88d6eea3c2..1ab4bc867531 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -12152,10 +12152,21 @@ SYSCALL_DEFINE5(perf_event_open,
 	}
 
 	if (task) {
+		bool is_capable;
+
 		err = down_read_interruptible(&task->signal->exec_update_lock);
 		if (err)
 			goto err_file;
 
+		is_capable = perfmon_capable();
+		if (attr.sigtrap) {
+			/*
+			 * perf_event_attr::sigtrap sends signals to the other
+			 * task. Require the current task to have CAP_KILL.
+			 */
+			is_capable &= kill_capable();
+		}
+
 		/*
 		 * Preserve ptrace permission check for backwards compatibility.
 		 *
@@ -12165,7 +12176,7 @@ SYSCALL_DEFINE5(perf_event_open,
 		 * perf_event_exit_task() that could imply).
 		 */
 		err = -EACCES;
-		if (!perfmon_capable() && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
+		if (!is_capable && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
 			goto err_cred;
 	}
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210630093709.3612997-1-elver%40google.com.
