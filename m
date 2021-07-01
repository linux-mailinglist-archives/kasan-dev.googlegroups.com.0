Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE776WDAMGQEAG4IT3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 940BE3B8EFA
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 10:40:55 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id r19-20020a92c5b30000b02901f175acc987sf632102ilt.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jul 2021 01:40:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625128852; cv=pass;
        d=google.com; s=arc-20160816;
        b=TgzJjmsXxpOGfd9JSS/hymSwxMsJqEHaVBn/r6qtTdr0xqpX/+vZRaw+CQ/STkRkVI
         Fyo3Yj3j5e5ltZITSbMkNIV1sfML+012hC8f0EyxNCCIoZGEdYoon/niz05Afi2fme2P
         kBor14YFirvgSvH9WtsdCaB1OCUC7B88wVzD/o8IaZ6pZIcmKoSoj26V4IpXOyXi9duk
         VWnBs7iAXcIsa3+C2ZtRE7cwD65+v6iQVAss+16H5FH7q2dXobbwbDXhrzPKZ6M4EJ64
         +fQLNc9U7w3aSQpjXpAf7rI9XlD0bOD5j7t6K3NLSH+yQ9ZOy1U7n8eP+hGAZgwmlmTu
         1w4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=fIp86VGCGb7mXQw/oAhEVk1mtG8bdrMLmR6TC+7VAmQ=;
        b=l0BJPFeSif3oGmKRBx5uftHN2AvTZvOFECjLAtgQ7vVcuGYWpzZEaepkiNKu4+4z56
         oOcreaTDgddDWL3kSJpc8XGuK1omGfjUitMRDXrkw+x2arbZ7sn+48ElcwUC3+iDq4lO
         tN3VqWjgi/z7q38pJvcXSJiG0+ayHnVYsq2U05WNoK3r1cNNiq+SJkX+FVvZSbwtoRdX
         x5SOOOv73vK2/s1HTB7DGsrR26OYk9JfMf7WxDuAty5LIVWtNNummgJx4hOodSIaMjbL
         xYpQKDYqCLZBPU2bbSEzbRqGY3bSC+jAkA53uECn2yoVpYA5sueIPrmY9mEHioEWpxEd
         LglA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FMpj5Jxu;
       spf=pass (google.com: domain of 3kn_dyaukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3kn_dYAUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fIp86VGCGb7mXQw/oAhEVk1mtG8bdrMLmR6TC+7VAmQ=;
        b=XD5GUYFfcxTqRRrNb/WqebUJMaswd1+bG4hfbrwowZyFnhk8Aq6i2gNqgVE+6jG0/x
         qQ4SQ7MLXx3dYTeCLsDV9R1EM6VymIYo9oZ/2Z1ETjeAlo06GeiIDX6x7oJDEL5Ft31v
         Rir9niYF881W0pF3QNd3QX7MHSunnN0sB2zRpkgWXmfR+jdTFjK5ZtGTbK6pQessk58y
         maIdDaXU9lalq2lwWgFKG5OoGYqNRl573UwCeTeXD8J4BefUDEvCjxI1kzQ8NnYDqWQh
         LP90zOkLU5GfITXWnHa8OM1fnC2WoT8B9raqjq535EdlCcF9k5IABKDGwkugDPBxACDM
         w3uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fIp86VGCGb7mXQw/oAhEVk1mtG8bdrMLmR6TC+7VAmQ=;
        b=snFP8hYs77K9ssHi3L6M+9XyVt7bsKqRDyyCzQ6PHb601qpHAA3Mr2G4hrSWUfRRu9
         up4cdclaTFsMDJeKlT+e0Lmdpi3zbDdcALCfhfar73savuk800kmukwjIYgAp4lVKVBS
         D7m4far3Yx0R24wYe+ZC4AJYN31PxUs5SHDmh8W/GpeQLLnFPFQLlNlH43sPhWz866Dx
         buO6xestG1qWN1RI4tGhMMbw+4rvuGNroDbneAqfl37+Fd8R2ssOAj09prwtKXHnyAE6
         7CztnxTgaM1cdw6yNKUooOSUHENddXM6mE2wobpzXBg6ytDcAReovEQOcTaPf10bhia5
         4bNQ==
X-Gm-Message-State: AOAM530PoH0/ePyqlslwXDRCwuUKlk6LK5bwR0ymYZgUzsLzSOfj6oL0
	X+ca3kRvlZkM1L+roGCkXBg=
X-Google-Smtp-Source: ABdhPJz59sKJiGjVAzbjJlAUNGvIoHU7PWKiB3mhzc0UgGB99S0OSCfZd2WfTmtXIQEgvREj7kLxQA==
X-Received: by 2002:a5d:914a:: with SMTP id y10mr11823213ioq.140.1625128851216;
        Thu, 01 Jul 2021 01:40:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2c12:: with SMTP id w18ls1010605iov.9.gmail; Thu,
 01 Jul 2021 01:40:50 -0700 (PDT)
X-Received: by 2002:a05:6602:2017:: with SMTP id y23mr11135180iod.137.1625128850869;
        Thu, 01 Jul 2021 01:40:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625128850; cv=none;
        d=google.com; s=arc-20160816;
        b=bhevvX1X9HMwFAGiYjyoD+OupiM0jbt6IUPaXPX2PODUERYF5pbD2Zwxj8sUz+rnVG
         fAmcig0bDx3IqFSwCswYpNXEVm2C+Rcr5ICTA7Wns/haluh+3uMIxr0YhJRij2ZDKaAx
         sMXBwUI4ks9xqXziFCMoFcAdlA/xhBpZFGKBB1LiB92n5lBX0b5PJoxCVReK69cPJg06
         UiFJrRM5x/lRYWQO7NHK77OkE11qwoXvfCGR05L/hqnshojJiwkSyA8Hf5qksGSs5ZMO
         AzCgP30LmHvbdIK9p7L5/B4pq3Y3oubvT8QDLC4pUT1kp2D8SdOwRewT4HPaH/LzH4v4
         3Wcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=5iHoNZMOeP6TxsWwP/0krCRRwCbLGs4FQeU+EZRnVpw=;
        b=z3RqMGGcK3Jo98womAsTkH060JFqbI8rCQcQNC14vG8gJseVeEYN2AmEqlkenikNOV
         bc67tiAZvMg/dBtWA44nJ+8a4MOSqlFNCZKeXv/L4b2+5YI6UcadiVb15EC0AvKsekfv
         /uqr68WBMRSL8DQwxrYDA95UaDZvt5HEfI0PPYovHIcSUdf0TPLnojfCfQL1qBIDamFD
         4vUHh99t2ZBdr1kztlj+Bgw47VcL1SqolR6SAsljH+YLl4mgBujSae2fp8+tR4lMNviK
         NY5a1LE0hr/1h6ZtbiL6BcaZmWBK5JKrdtPwf1DwMDOnRrssnMIl4TJFi+9Zvwn8mAmt
         i7TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FMpj5Jxu;
       spf=pass (google.com: domain of 3kn_dyaukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3kn_dYAUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id b16si726797iow.0.2021.07.01.01.40.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Jul 2021 01:40:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kn_dyaukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id c3-20020a37b3030000b02903ad0001a2e8so3728318qkf.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Jul 2021 01:40:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:8b0e:c57f:ff29:7e4])
 (user=elver job=sendgmr) by 2002:ad4:4ba4:: with SMTP id i4mr34049163qvw.42.1625128850422;
 Thu, 01 Jul 2021 01:40:50 -0700 (PDT)
Date: Thu,  1 Jul 2021 10:38:43 +0200
Message-Id: <20210701083842.580466-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH v2] perf: Require CAP_KILL if sigtrap is requested
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org
Cc: tglx@linutronix.de, mingo@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, mingo@redhat.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@redhat.com, 
	namhyung@kernel.org, linux-perf-users@vger.kernel.org, ebiederm@xmission.com, 
	omosnace@redhat.com, serge@hallyn.com, linux-security-module@vger.kernel.org, 
	stable@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FMpj5Jxu;       spf=pass
 (google.com: domain of 3kn_dyaukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3kn_dYAUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Note: The check complements the existing capability check, but is not
supposed to supersede the ptrace_may_access() check. At a high level we
now have:

	capable of CAP_PERFMON and (CAP_KILL if sigtrap)
		OR
	ptrace_may_access() // also checks for same thread-group and uid

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Cc: <stable@vger.kernel.org> # 5.13+
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Drop kill_capable() and just check CAP_KILL (reported by Ondrej Mosnacek).
* Use ns_capable(__task_cred(task)->user_ns, CAP_KILL) to check for
  capability in target task's ns (reported by Ondrej Mosnacek).
---
 kernel/events/core.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index fe88d6eea3c2..43c99695dc3f 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -12152,10 +12152,23 @@ SYSCALL_DEFINE5(perf_event_open,
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
+			rcu_read_lock();
+			is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
+			rcu_read_unlock();
+		}
+
 		/*
 		 * Preserve ptrace permission check for backwards compatibility.
 		 *
@@ -12165,7 +12178,7 @@ SYSCALL_DEFINE5(perf_event_open,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210701083842.580466-1-elver%40google.com.
