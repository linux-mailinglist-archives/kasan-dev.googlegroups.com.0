Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4DRSLAMGQEMSGZIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22650565936
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:04 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id e8-20020ac24e08000000b0047fad5770d2sf3157875lfr.17
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947163; cv=pass;
        d=google.com; s=arc-20160816;
        b=kLLOWO5lTujZzOFIWZm3NEJXlcAEKx1LN3GxLhRpD9cgmmSC2EwlzvQupv+rCA4/OG
         NqkB9/rssZpAhstD7K/hOONW45p1be8d6ZCX0wbp/HXGxqEKwhqlAS3JEK3OIUOIyI3z
         QSsKsNJalmzLAQ9pn7hoi6BWdz8lVMhlzzyh0O4EfzXd1/AfH7ndnSWvEaYJ/rhlupO0
         MFTozTEHBEkF7yWucR03WYcxu+aylFaani1jmV2pZlJZxVjsQmGJWx831gU4J6w2/TiB
         jBEKW5/YZtx1YhyjLI5pGYv4DWKbvzRdf/81kis9np8kHLPAcQcphgruVBwMq+1af6gK
         bx7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LwgRRcMaj7skEgMO/SP5Yk/lca+UpItHS4p6gr7WRKo=;
        b=WQpwvB1bdErHsto/FnY1p1jWnwYN4HoLED8Mygzmi4570TJDQ4/IJp1nbbYPr4Ystc
         RL3mAfas99xyNNBmafS4I+9KuAnD5N0ZG8X8X4BpgDo0LLKeTODcoGts2iQdXc78SdSs
         akoTDhImhccCqpnIz1OL8A2m4XqJ1Y6RGcR47k+nR5tZqkBKEdLdhS+sVVnmxAOTTY8U
         xY7jM4FA4c5lQMeYnxeiE3Tghbcj5ScyPtES9DxaYJKJfFKWmZLtNyuXE8J0EnT1AX1B
         +AcoJ9qZMSjEQcqRyH/cqC7erPLiKmf/YNXSSlwZ0MzRekyavned1BzhryaO3KFYxbpC
         wv3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c7LZpgpH;
       spf=pass (google.com: domain of 32qhdygukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32QHDYgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LwgRRcMaj7skEgMO/SP5Yk/lca+UpItHS4p6gr7WRKo=;
        b=t/cskw03JyKDhBlUiDBJM9IiYJYfgmRjPXZQcZJgLfqmJXbvjoBgerCjVgBPMDDHCl
         3shdy3knfvstKauEzFKTc4wC915dtRRUoXVcufi76u5Mntg9UqqUc6pW0DXhQyxo+hVR
         8ASWVCUz4kSrQq6n64FPhcW0bA4VBljtZIwUvUXD3Hu3xFJKIQsfh7bBfKcMNypNAHSQ
         UWatL2Ilsq5EJj/NUGw/72pHQvtoed7E1yx8vYfZaxgQyLXjCUMis7bZho1lB8JonS4q
         9beIjnSKJ5k4PKG5mtWhBeNjfHTP4eaeI3tU+MDSkxS12jG7iExjOuG+/3VUntYE7XPn
         /5sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LwgRRcMaj7skEgMO/SP5Yk/lca+UpItHS4p6gr7WRKo=;
        b=hIHGzVuJpBhek9q9OA7N9/uFgcG9x4IqTl7P6W1Stko+H+moc3NoZs+0QhUf7ie9LA
         LT6yTLUTyCGd9VqQyjPkBHQFpn17mEISI0MDZ5LjHLtrZqN2uKWYtPajfJxXRta81udH
         qDeJi3EIJYZHxu7pYGJDkxgerDIginYT1J/6gP2YRVhjZJcUT89Qd8jALvi2+qMNBI1m
         iLLbBKKryx2qCK2exwMCO9mJ3EAznKvvVbTdpOsw83rsY5fWVXZ4uB511HiaQZts0+Oz
         tuyAgzZyXEvk6hKlSPBOMR4uVfSXqy0BJhx8F1Wdr5/p05asG3ztz63X6EQskOG++pUa
         SQsA==
X-Gm-Message-State: AJIora/rJYkzRIXdk2lvOjVtt7rqmsF2GrpvpbUBk+KComBAs7GvkrjJ
	fwX/fGbkC/U1o5P6uFH+68I=
X-Google-Smtp-Source: AGRyM1uFwFMuKFvuIbYi9ONJJ1BAxV9kF2kxqe/dOQhE0sUi7ep4n+ocS/c1vZr3eg2ih9rEj3BgFA==
X-Received: by 2002:a05:6512:1103:b0:482:dbb9:c64 with SMTP id l3-20020a056512110300b00482dbb90c64mr595594lfg.346.1656947163447;
        Mon, 04 Jul 2022 08:06:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9948:0:b0:25b:c0c2:7dec with SMTP id r8-20020a2e9948000000b0025bc0c27decls3875873ljj.11.gmail;
 Mon, 04 Jul 2022 08:06:02 -0700 (PDT)
X-Received: by 2002:a2e:a58c:0:b0:25a:89da:cb88 with SMTP id m12-20020a2ea58c000000b0025a89dacb88mr17613346ljp.485.1656947161956;
        Mon, 04 Jul 2022 08:06:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947161; cv=none;
        d=google.com; s=arc-20160816;
        b=KDn2zT3Z3zxVKM17/7uiHtor+CI76ttv07vL5zJZpYxe/yyNSUXIRBrX3v+18GVavV
         SZqmqZWoxpmpsoz727knPAHwajSGzQv6w9XAvJ2jWM0JHsrKHjkjOEus3p/6vS3lDda+
         N9RNOcZvW22xb5Ft0hN6MjqQ5LMh9kFCVrHX4fwzD5LG681WXkIgxuJk0NrGxFcFTpuI
         gHl4WNibUyq3SvQ9UUFT+NT8/ILs4GLmuIOHhRNZfbQiKJ225799xHW5ZMY5dKJv0o8c
         7G7gSW+1+DnI6HB5EPJeP8fj7fnHOQoxGINNlwo0K6VErjXIboHXlmglPHbguN5E0G9/
         khew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0mVGJO2my8t1HZTqH29Koygvc/XGcDZ6vWpb1jdDT4o=;
        b=BTzhU1gBGOUVPXwcJbSaj92lulVQomCWm7VZvl1ElRQg8CexIPOkPTFMLCB+41ykV5
         itmkanKYzVSK8PNvxduNQ6aPUPIcXT20VWiLk76jiTa9Cq8vLHKmbcCDq6Q0uDZwvmYc
         ySLSyc4EZJiIehf0Y53iqV+aya5Sg53umJM/VX3NFcSGZYmYGhEjRgZuzBhrWhJ89IS7
         9wbZuBObyHffbaQYGH/VoXQnJrFuZ0ChAHGs1FW2+zTymjTPSJmC2nt2/mXWhBAqIX9K
         GoOHTCxmaZF3y0zrYdJjN9Graw1v9/GgG0zWxVqcMz4+QDgVPZxzIet2FvIxYKP4b4N3
         B0oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c7LZpgpH;
       spf=pass (google.com: domain of 32qhdygukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32QHDYgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k27-20020a2ea27b000000b0025d2c310ccesi23001ljm.2.2022.07.04.08.06.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32qhdygukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hq41-20020a1709073f2900b00722e5ad076cso2159796ejc.20
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:aa7:cd17:0:b0:435:bd7e:2efb with SMTP id
 b23-20020aa7cd17000000b00435bd7e2efbmr40768145edw.180.1656947161289; Mon, 04
 Jul 2022 08:06:01 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:02 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-3-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 02/14] perf/hw_breakpoint: Provide hw_breakpoint_is_used()
 and use in test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=c7LZpgpH;       spf=pass
 (google.com: domain of 32qhdygukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32QHDYgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Provide hw_breakpoint_is_used() to check if breakpoints are in use on
the system.

Use it in the KUnit test to verify the global state before and after a
test case.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* New patch.
---
 include/linux/hw_breakpoint.h      |  3 +++
 kernel/events/hw_breakpoint.c      | 29 +++++++++++++++++++++++++++++
 kernel/events/hw_breakpoint_test.c | 12 +++++++++++-
 3 files changed, 43 insertions(+), 1 deletion(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index 78dd7035d1e5..a3fb846705eb 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -74,6 +74,7 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
+extern bool hw_breakpoint_is_used(void);
 
 extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
@@ -121,6 +122,8 @@ register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
 unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)	{ }
+static inline bool hw_breakpoint_is_used(void)		{ return false; }
+
 static inline int
 reserve_bp_slot(struct perf_event *bp)			{return -ENOSYS; }
 static inline void release_bp_slot(struct perf_event *bp) 		{ }
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index f32320ac02fd..fd5cd1f9e7fc 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -604,6 +604,35 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * hw_breakpoint_is_used - check if breakpoints are currently used
+ *
+ * Returns: true if breakpoints are used, false otherwise.
+ */
+bool hw_breakpoint_is_used(void)
+{
+	int cpu;
+
+	if (!constraints_initialized)
+		return false;
+
+	for_each_possible_cpu(cpu) {
+		for (int type = 0; type < TYPE_MAX; ++type) {
+			struct bp_cpuinfo *info = get_bp_info(cpu, type);
+
+			if (info->cpu_pinned)
+				return true;
+
+			for (int slot = 0; slot < nr_slots[type]; ++slot) {
+				if (info->tsk_pinned[slot])
+					return true;
+			}
+		}
+	}
+
+	return false;
+}
+
 static struct notifier_block hw_breakpoint_exceptions_nb = {
 	.notifier_call = hw_breakpoint_exceptions_notify,
 	/* we need to be notified first */
diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
index 433c5c45e2a5..5ced822df788 100644
--- a/kernel/events/hw_breakpoint_test.c
+++ b/kernel/events/hw_breakpoint_test.c
@@ -294,7 +294,14 @@ static struct kunit_case hw_breakpoint_test_cases[] = {
 static int test_init(struct kunit *test)
 {
 	/* Most test cases want 2 distinct CPUs. */
-	return num_online_cpus() < 2 ? -EINVAL : 0;
+	if (num_online_cpus() < 2)
+		return -EINVAL;
+
+	/* Want the system to not use breakpoints elsewhere. */
+	if (hw_breakpoint_is_used())
+		return -EBUSY;
+
+	return 0;
 }
 
 static void test_exit(struct kunit *test)
@@ -308,6 +315,9 @@ static void test_exit(struct kunit *test)
 		kthread_stop(__other_task);
 		__other_task = NULL;
 	}
+
+	/* Verify that internal state agrees that no breakpoints are in use. */
+	KUNIT_EXPECT_FALSE(test, hw_breakpoint_is_used());
 }
 
 static struct kunit_suite hw_breakpoint_test_suite = {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-3-elver%40google.com.
