Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEMNRODQMGQE76XHATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FFC53BB988
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 10:45:06 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id l21-20020a0560000235b029013564642c78sf359702wrz.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 01:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625474705; cv=pass;
        d=google.com; s=arc-20160816;
        b=AeMjUOpNlEAd6DubgWJaH3J0qVlOCr9gRxpfGaILS3er5wOKEdxPFUXfGqtDSLKKPH
         Zax6J4hK3lEbc1Poy6Loti9YgVuP5Jt4I1b0piFSWPzvjVSYuVsknMfrr3UwI0Clm0gH
         rtxNEga7U6Vdyy6Sfh7EoIcCLjGno4yb9tnas1OtuY8MJhsC8e3kF2VcSxblPtEIy2ah
         ZD9xIedWZh9hq1HdcMkVZTJoqW+kZtk1K6FRf8erNoDrIUSMCvPKgINqp1x0xk81c0nE
         rVshTANCPiK8+QLs0qlMMFbfJBrjWyCt/FQHzfx1ZUMW6RwlYsRi2KbZnPZ0F+1eqZOE
         4Vrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=EasE8F0HxN5rcZLp6CELz4C4NPr+iTPaor0F3N158/A=;
        b=A8ZM83Eq4WqJHCzzLM/ay7VUQOSt+409R5tt4DDpXewmssRBBKYJMCk3Imx49vTPvD
         FPBbtrGFLLM+mOlxw4hgdmcMUTlcj+Zqst32GouYXo7Qaw98lS0U8pPVFHp3YumFF+bL
         lHnkfgz0fGbWUsgw9/M0Y/yXMKPmC6VTJDLzeuhk5TjkHmzl3+KDqdccBLnFikDirTOo
         +YBJKM7kIadRYATGXq2v7EBaxfUgnL169jX9WeVleahqtjriWZVKZO/g8WNV2ttclOQl
         VEInY257g6uuonTxxB6RPDy/fiAaxhQYyfHnb00M6Bl7SBwn5h0RkwOEc+q4HzobNuS5
         ghwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vN2Y2GrX;
       spf=pass (google.com: domain of 3kmbiyaukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3kMbiYAUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EasE8F0HxN5rcZLp6CELz4C4NPr+iTPaor0F3N158/A=;
        b=T8lukr9KETHfmGydYGrDHGOYBWJb6scNlJ1PqxymnNPhvKjJW4kvg6O2/IGfksE9db
         XE5LIICqhTAsYDvRzHuc31+GUd5UE6cU49jLh8jKXxXUH2B05fDopek3e8S5zYrHwrUG
         sr8tTcFZJgWzk9FN48Lh8gdkLd/2b4hwWP++D1Hdx/1v5NPYmIFOjo6Sdr9+1MM4Ip1q
         2qUHbmGYO7KMBvQ+Lu3y8GJCuTSEutOISDEJEPrqNqVSZsqGvxPCVlGKyR1UFvNswQEH
         lwbNacGEUPjuG/6zdj/w372kgJbGmg8Jhs3ebiz+5zW0JcyEkiEV27Qaj8TlTyh/AhIX
         yRKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EasE8F0HxN5rcZLp6CELz4C4NPr+iTPaor0F3N158/A=;
        b=PNN2uIYpytznxcFXAVKj/p0nPfBtp85XcmZThhmEhWaPYNCmzfhPEk5hGmEzHJIsry
         fYZpJYXhojIwb6zHcVVjNkv5fcALfXyD5Z9VN381ETyi6apk8tlUlwvzrb8IT1445P2W
         JxLdpHwegzE8j5MxaJFSG6g6R/1sGNi7Huebs4E7peBCu8qhNTdOOu+bnUq4VVdgfR/F
         BM4tVW6GHak7kVXQf/3rLlqNs3hIizoI8DnZUGe/BbeV3QFYt6TIvhmAdT1QmjYTTomr
         EXF+TmsjYnr8jQYwm9c2jG2iFZnsVyBt41AH23FVG3XTpPJeCJ7RABu0iobbZfOVqxTn
         Z0Hw==
X-Gm-Message-State: AOAM531zrsng8eK+SwAELkqrLTGqpxHj0V/tRtGZ/xfdG2W5B5aqUJaM
	iZMq/hPPruxNppG+jntogkM=
X-Google-Smtp-Source: ABdhPJzF/U+nXfcJMTUW3i9Kp4himMoA5FeAS/1FqExfIWFCeW+PWbffQndp20xzPDJoxN833jxVFA==
X-Received: by 2002:adf:cd8e:: with SMTP id q14mr14362328wrj.192.1625474705813;
        Mon, 05 Jul 2021 01:45:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb9a:: with SMTP id m26ls9003348wmi.3.canary-gmail; Mon,
 05 Jul 2021 01:45:04 -0700 (PDT)
X-Received: by 2002:a05:600c:2cd2:: with SMTP id l18mr13273866wmc.142.1625474704867;
        Mon, 05 Jul 2021 01:45:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625474704; cv=none;
        d=google.com; s=arc-20160816;
        b=VAAzUgBtBiHUCqDch9HWi2N/xyzLeuFpUAjCnAKqjcd8qrkv+20lD0NqBtmwtcNVRd
         4XitA4w7a+OJ76VmkGqJMr9Gg4t3xixcQAGcBqVjl5G4NY81RjB/YpweASmkzJkGmhe7
         twV1hPWhkTnFItHx97X8QlCL1uxZGIAWh/3FFh/TSGfknf4uIZ8AMfNMP+cyozO73gG8
         jePBj7nlO8tNMtW7PmMv6X17yxLVarotDspBL6GI4c1LI6kxyvV9/YV1FEiRE2M7SXpt
         SBso3Oa1X86Hmbf69dzcJyumbB1B3OrC00TOjORfeu8+G5QEimFDRA+BbD0bUTFRT3YZ
         5fgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XT1F6bsaZFgcmmxxyjZZuJTZD371QBzAaF2qKad4ZRA=;
        b=ufpB8vgrf27z25kzvV9lpskU3tKg6FJ1KPPPsxOVBC7kxclBAfB7L8r28+xwpk5XQ2
         t90nkNI+6GrJoFUsXIzTLeTctvphnnDN+FmNcd+3fWnSYngt6MXNert81fcyqA6iI8Nd
         JO9hlZObsxjez7KnixQhOJGhJFfODaMtfte92OdSLb6wQ0UngJ3eHxXnWZoMT7FYpLS0
         C1Y8QoTSN07jjy27sqIx3cLsp5V5iLeNnshF/yaR2gkVRet5RSDQzw9jRN6rXF6NT/nq
         7lqv0O5oyAOcI54pW0kFAePsqmsiGYfzJ3wT06bkCCt18hiyFnQmvoNGRllhjgxogjuj
         xTAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vN2Y2GrX;
       spf=pass (google.com: domain of 3kmbiyaukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3kMbiYAUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id m27si386166wms.0.2021.07.05.01.45.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 01:45:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kmbiyaukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id u2-20020a2e91c20000b029017f236536ceso5227276ljg.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 01:45:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dddd:647c:7745:e5f7])
 (user=elver job=sendgmr) by 2002:a19:6d01:: with SMTP id i1mr10104024lfc.422.1625474704103;
 Mon, 05 Jul 2021 01:45:04 -0700 (PDT)
Date: Mon,  5 Jul 2021 10:44:52 +0200
Message-Id: <20210705084453.2151729-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH v3 1/2] perf: Fix required permissions if sigtrap is requested
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org
Cc: tglx@linutronix.de, mingo@kernel.org, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com, 
	alexander.shishkin@linux.intel.com, jolsa@redhat.com, namhyung@kernel.org, 
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com, omosnace@redhat.com, 
	serge@hallyn.com, linux-security-module@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vN2Y2GrX;       spf=pass
 (google.com: domain of 3kmbiyaukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3kMbiYAUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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
match the calling user, also require the CAP_KILL capability or
PTRACE_MODE_ATTACH permissions.

Otherwise, with the CAP_PERFMON capability alone it would be possible
for a user to send SIGTRAP signals via perf events to another user's
tasks. This could potentially result in those tasks being terminated if
they cannot handle SIGTRAP signals.

Note: The check complements the existing capability check, but is not
supposed to supersede the ptrace_may_access() check. At a high level we
now have:

	capable of CAP_PERFMON and (CAP_KILL if sigtrap)
		OR
	ptrace_may_access(...) // also checks for same thread-group and uid

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Cc: <stable@vger.kernel.org> # 5.13+
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Upgrade ptrace mode check to ATTACH if attr.sigtrap, otherwise it's
  possible to change the target task (send signal) even if only read
  ptrace permissions were granted (reported by Eric W. Biederman).

v2: https://lkml.kernel.org/r/20210701083842.580466-1-elver@google.com
* Drop kill_capable() and just check CAP_KILL (reported by Ondrej Mosnacek).
* Use ns_capable(__task_cred(task)->user_ns, CAP_KILL) to check for
  capability in target task's ns (reported by Ondrej Mosnacek).

v1: https://lkml.kernel.org/r/20210630093709.3612997-1-elver@google.com
---
 kernel/events/core.c | 25 ++++++++++++++++++++++++-
 1 file changed, 24 insertions(+), 1 deletion(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index fe88d6eea3c2..f79ee82e644a 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -12152,10 +12152,33 @@ SYSCALL_DEFINE5(perf_event_open,
 	}
 
 	if (task) {
+		unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
+		bool is_capable;
+
 		err = down_read_interruptible(&task->signal->exec_update_lock);
 		if (err)
 			goto err_file;
 
+		is_capable = perfmon_capable();
+		if (attr.sigtrap) {
+			/*
+			 * perf_event_attr::sigtrap sends signals to the other
+			 * task. Require the current task to also have
+			 * CAP_KILL.
+			 */
+			rcu_read_lock();
+			is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
+			rcu_read_unlock();
+
+			/*
+			 * If the required capabilities aren't available, checks
+			 * for ptrace permissions: upgrade to ATTACH, since
+			 * sending signals can effectively change the target
+			 * task.
+			 */
+			ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
+		}
+
 		/*
 		 * Preserve ptrace permission check for backwards compatibility.
 		 *
@@ -12165,7 +12188,7 @@ SYSCALL_DEFINE5(perf_event_open,
 		 * perf_event_exit_task() that could imply).
 		 */
 		err = -EACCES;
-		if (!perfmon_capable() && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
+		if (!is_capable && !ptrace_may_access(task, ptrace_mode))
 			goto err_cred;
 	}
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705084453.2151729-1-elver%40google.com.
