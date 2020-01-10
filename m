Return-Path: <kasan-dev+bncBC7OBJGL2MHBB34O4PYAKGQEU4DPQDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 831A1137661
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:50:23 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id d8sf1305472wrq.12
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:50:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578682223; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pq+mLq3pdouVylEPHVeLTdUIHl/y/whC7uUm+mwWObI6tT/MUBy9au6STp3E1sgbbO
         wjcEwG7Zhym8iIuVNcGdFvP/5HtCxMtT0Dv3uTZzAquAqjtuEsqhziV5ANg1irtOFYl7
         B9tkrcpebqK085hE8LxCfsPhPvcIQBos4gRvBeXD9MHCjCAlMzq2UJvRKlIqCEfxLya+
         mymHH6pyscWyS+VRb0UXXAijAptVsBOWh9V3GJxrt9HP/jJFs9hUbvxrzbUtLa7Bq3oi
         GpYHQbtOzEiDJT6zjB2m0fxEYbrWmd56984f1sUQrXeD6kNtGEoID3h/InVBj0wI8aUZ
         duAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=QED3TrH8JgpMNoFystHTh7UbrtVl7RqFyrKVoXPR8Vc=;
        b=IIKMcHgPI69yxRBkfgEs9lP2LneUTZypjnKkFJKh2xmYs5Ril/3Zog5pecTSGFp346
         j33J13aqn5+3dV/N3zRj2g9dXIvy2pslF9HBv2avrmSv9iOGzL5oTrgQUhHF146cp0Ko
         HDcoNvBD/RV9molIYtClpWhhhfyiOvtlQxI850UA4UAnbt8PqP0sK5lOjDVG/mkI2CD8
         tvbKTay9qZ6XfPBa3k7oiaqX3zKRaJFGQg+q/t0KsoDejdeBjMdTuJBKQQVGUlvLHE0e
         VdhFgvnVaq5UI7hz7JmhGlp5uUTnGBCCLj/wQTnxGkLxaeu3+jA6hPuOSW4EOe3a9qSv
         UBmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WHxhhjXo;
       spf=pass (google.com: domain of 3bccyxgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bccYXgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QED3TrH8JgpMNoFystHTh7UbrtVl7RqFyrKVoXPR8Vc=;
        b=XgImKPCxAhIEhrBFxwGJn7SYBi5DOIxa9G9MdR8FEaMsFD57UgASDeZQDR9bPX6RId
         NeMqdzgrq+nmV9cMIahmKYcsb4cYNAOIKfNdX7lbofU3Ufuy5Ox+sHlCjPKoeX5aBj6h
         vHwvL1MWqmpRgsAQ/OmPwurj5SUhpG27bMQ/YxbXR9GOEN06+8LsBkfh0eKYqN8a5S5H
         35V42H/2a3HxcHxICa3aUHU0WyyQIgYDcR0IRWlSBH/LLvBU6vPCFa9IsfClkcGf2w4t
         U+2v2l45feDgfjFRSowsddibWLsjR/Yxzraa+KG2bPjcgBwG7j4OKCDVuuf/0d3Fxka6
         GeUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QED3TrH8JgpMNoFystHTh7UbrtVl7RqFyrKVoXPR8Vc=;
        b=o/KCVtMP+8U0cYMdIugsvRkh6M58c3bjOyVtFbT+Y3ZjzJDJ+U7WMVzG2G4FdZtiFX
         9kBpU1W3HvDcV/6Mm6CHL4e8cLGimyYqILDhV3NNpkJ8u8AgOQ8TGZTWUIru+qkMKyUO
         7V1akv5PC89kDeRr/v/VSEr6gVs/nNwlps1GghnKDhdd+2Ax0kZtTltYYCGklXHqj7dv
         UXrWoa5hu2cmHvNasolpCs0gY49ByO/d/848JvpajBseirTaKxgm0/8Df0ei5ofRugzQ
         kGKGOdXYZilmPWA8ks1EeJ1WAaDFtoeq8U/1s7652oUiz7tsU0HsPHSaF/vL8zKrcJlp
         X5yA==
X-Gm-Message-State: APjAAAXH11aP8FC0vMM0VkWZ+Jy+iGTDOtauTvTeOMvdAYKD+vba4BXd
	5aecq0fvX7qgvqAahuECESE=
X-Google-Smtp-Source: APXvYqwtugiJOAFr1gmUAOP8d/T0wz3gHcAwS/oWcZlrA7+w60ifBVc5rVIkQVdbY9BjXq6FrO9Ydg==
X-Received: by 2002:a7b:c1d8:: with SMTP id a24mr5872106wmj.130.1578682223172;
        Fri, 10 Jan 2020 10:50:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf15:: with SMTP id l21ls2973118wmg.0.canary-gmail; Fri,
 10 Jan 2020 10:50:22 -0800 (PST)
X-Received: by 2002:a05:600c:305:: with SMTP id q5mr5895544wmd.167.1578682222379;
        Fri, 10 Jan 2020 10:50:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578682222; cv=none;
        d=google.com; s=arc-20160816;
        b=mLo2/W/fF7srkDJvjOL8SvaymEQ1XbliiJT2ND17t/fqyFv5mA/FV26bk/R7nsz7G2
         PmzIv4mW9kQBQUXF5BY/GWRiGaGBqvrB+TK/ezRBSBHqphVLdetydJ164mgIiQuIOLiW
         Df3IxrTDb/u9hxr7dANrKPGKyWcJ+G6ucX8nWYqRo8Se10dvnQbUWKoF7eXATqeSnT++
         qOgkeV8rGyyzPReQDFeViGml1Qs/qDBGtg4GgBO7ICfy+zOws9okqQFkAed+u246bVlz
         qZFEc4cAOVDNXh5b298LCMziKO3998oHgu+sX3TnkKMjxlA1mWm0TbxuIsuuJm0LQJ9q
         TVAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/Lh/zF2uA+n8XDLeCYrzLNAj4+xfQxSFBEMLGQviSxg=;
        b=VPixeggGSub6ZR9my5iGf0nRTTvBVXFt8CxbB8Xse7JMmapQoAqs1KJ3HYzGFqEEti
         DCjrL3DqVL/psKZSnqejzaogOFb82Dm4qZiVdBbMRoWNdU5MDNmIO3swLzkg99h3HFqo
         oWafuBE/KL1r1GeVY4aU6HD/Kc77Tc/xCVOVIEr2Kgb284spm5k1Zw2l9s+/d0Ddasif
         dQHQ1wOpMXtPO5QabhdewdJPHPCB34gAZvDDUCXrjljGLITb77i2XHXDk4tzqy89fLNY
         2r5CLqhdIE+Bzmwt2XU89wvIDLEwkYVwvbtEOJrIxr03Qdw1vaSk+h20w+qpww43iuF8
         loDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WHxhhjXo;
       spf=pass (google.com: domain of 3bccyxgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bccYXgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y13si104262wrs.0.2020.01.10.10.50.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:50:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bccyxgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w6so1298214wrm.16
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:50:22 -0800 (PST)
X-Received: by 2002:a5d:49c7:: with SMTP id t7mr4770998wrs.369.1578682221829;
 Fri, 10 Jan 2020 10:50:21 -0800 (PST)
Date: Fri, 10 Jan 2020 19:48:33 +0100
In-Reply-To: <20200110184834.192636-1-elver@google.com>
Message-Id: <20200110184834.192636-2-elver@google.com>
Mime-Version: 1.0
References: <20200110184834.192636-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu v2 1/2] kcsan: Show full access type in report
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WHxhhjXo;       spf=pass
 (google.com: domain of 3bccyxgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bccYXgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

This commit adds access-type information to KCSAN's reports as follows:
"read", "read (marked)", "write", and "write (marked)".

Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c   | 15 ++++++++-------
 kernel/kcsan/kcsan.h  |  2 +-
 kernel/kcsan/report.c | 43 ++++++++++++++++++++++++++++---------------
 3 files changed, 37 insertions(+), 23 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4d4ab5c5dc53..87bf857c8893 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -255,7 +255,7 @@ static inline unsigned int get_delay(void)
 
 static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 					    size_t size,
-					    bool is_write,
+					    int type,
 					    atomic_long_t *watchpoint,
 					    long encoded_watchpoint)
 {
@@ -276,7 +276,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	flags = user_access_save();
 
 	if (consumed) {
-		kcsan_report(ptr, size, is_write, true, raw_smp_processor_id(),
+		kcsan_report(ptr, size, type, true, raw_smp_processor_id(),
 			     KCSAN_REPORT_CONSUMED_WATCHPOINT);
 	} else {
 		/*
@@ -292,8 +292,9 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 }
 
 static noinline void
-kcsan_setup_watchpoint(const volatile void *ptr, size_t size, bool is_write)
+kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 {
+	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	atomic_long_t *watchpoint;
 	union {
 		u8 _1;
@@ -415,13 +416,13 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, bool is_write)
 		 * No need to increment 'data_races' counter, as the racing
 		 * thread already did.
 		 */
-		kcsan_report(ptr, size, is_write, size > 8 || value_change,
+		kcsan_report(ptr, size, type, size > 8 || value_change,
 			     smp_processor_id(), KCSAN_REPORT_RACE_SIGNAL);
 	} else if (value_change) {
 		/* Inferring a race, since the value should not have changed. */
 		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
-			kcsan_report(ptr, size, is_write, true,
+			kcsan_report(ptr, size, type, true,
 				     smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
 	}
@@ -455,10 +456,10 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	 */
 
 	if (unlikely(watchpoint != NULL))
-		kcsan_found_watchpoint(ptr, size, is_write, watchpoint,
+		kcsan_found_watchpoint(ptr, size, type, watchpoint,
 				       encoded_watchpoint);
 	else if (unlikely(should_watch(ptr, type)))
-		kcsan_setup_watchpoint(ptr, size, is_write);
+		kcsan_setup_watchpoint(ptr, size, type);
 }
 
 /* === Public interface ===================================================== */
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index d3b9a96ac8a4..8492da45494b 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -103,7 +103,7 @@ enum kcsan_report_type {
 /*
  * Print a race report from thread that encountered the race.
  */
-extern void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
+extern void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 			 bool value_change, int cpu_id, enum kcsan_report_type type);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 0eea05a3135b..9f503ca2ff7a 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -24,7 +24,7 @@
 static struct {
 	const volatile void	*ptr;
 	size_t			size;
-	bool			is_write;
+	int			access_type;
 	int			task_pid;
 	int			cpu_id;
 	unsigned long		stack_entries[NUM_STACK_ENTRIES];
@@ -41,8 +41,10 @@ static DEFINE_SPINLOCK(report_lock);
  * Special rules to skip reporting.
  */
 static bool
-skip_report(bool is_write, bool value_change, unsigned long top_frame)
+skip_report(int access_type, bool value_change, unsigned long top_frame)
 {
+	const bool is_write = (access_type & KCSAN_ACCESS_WRITE) != 0;
+
 	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && is_write &&
 	    !value_change) {
 		/*
@@ -63,9 +65,20 @@ skip_report(bool is_write, bool value_change, unsigned long top_frame)
 	return kcsan_skip_report_debugfs(top_frame);
 }
 
-static inline const char *get_access_type(bool is_write)
+static const char *get_access_type(int type)
 {
-	return is_write ? "write" : "read";
+	switch (type) {
+	case 0:
+		return "read";
+	case KCSAN_ACCESS_ATOMIC:
+		return "read (marked)";
+	case KCSAN_ACCESS_WRITE:
+		return "write";
+	case KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "write (marked)";
+	default:
+		BUG();
+	}
 }
 
 /* Return thread description: in task or interrupt. */
@@ -112,7 +125,7 @@ static int sym_strcmp(void *addr1, void *addr2)
 /*
  * Returns true if a report was generated, false otherwise.
  */
-static bool print_report(const volatile void *ptr, size_t size, bool is_write,
+static bool print_report(const volatile void *ptr, size_t size, int access_type,
 			 bool value_change, int cpu_id,
 			 enum kcsan_report_type type)
 {
@@ -124,7 +137,7 @@ static bool print_report(const volatile void *ptr, size_t size, bool is_write,
 	/*
 	 * Must check report filter rules before starting to print.
 	 */
-	if (skip_report(is_write, true, stack_entries[skipnr]))
+	if (skip_report(access_type, true, stack_entries[skipnr]))
 		return false;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
@@ -132,7 +145,7 @@ static bool print_report(const volatile void *ptr, size_t size, bool is_write,
 						other_info.num_stack_entries);
 
 		/* @value_change is only known for the other thread */
-		if (skip_report(other_info.is_write, value_change,
+		if (skip_report(other_info.access_type, value_change,
 				other_info.stack_entries[other_skipnr]))
 			return false;
 	}
@@ -170,7 +183,7 @@ static bool print_report(const volatile void *ptr, size_t size, bool is_write,
 	switch (type) {
 	case KCSAN_REPORT_RACE_SIGNAL:
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(other_info.is_write), other_info.ptr,
+		       get_access_type(other_info.access_type), other_info.ptr,
 		       other_info.size, get_thread_desc(other_info.task_pid),
 		       other_info.cpu_id);
 
@@ -181,14 +194,14 @@ static bool print_report(const volatile void *ptr, size_t size, bool is_write,
 
 		pr_err("\n");
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(is_write), ptr, size,
+		       get_access_type(access_type), ptr, size,
 		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
 		       cpu_id);
 		break;
 
 	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
 		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(is_write), ptr, size,
+		       get_access_type(access_type), ptr, size,
 		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
 		       cpu_id);
 		break;
@@ -223,7 +236,7 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
  * required for the report type, simply acquires report_lock and returns true.
  */
 static bool prepare_report(unsigned long *flags, const volatile void *ptr,
-			   size_t size, bool is_write, int cpu_id,
+			   size_t size, int access_type, int cpu_id,
 			   enum kcsan_report_type type)
 {
 	if (type != KCSAN_REPORT_CONSUMED_WATCHPOINT &&
@@ -243,7 +256,7 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 
 		other_info.ptr			= ptr;
 		other_info.size			= size;
-		other_info.is_write		= is_write;
+		other_info.access_type		= access_type;
 		other_info.task_pid		= in_task() ? task_pid_nr(current) : -1;
 		other_info.cpu_id		= cpu_id;
 		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
@@ -302,14 +315,14 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 	goto retry;
 }
 
-void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
+void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		  bool value_change, int cpu_id, enum kcsan_report_type type)
 {
 	unsigned long flags = 0;
 
 	kcsan_disable_current();
-	if (prepare_report(&flags, ptr, size, is_write, cpu_id, type)) {
-		if (print_report(ptr, size, is_write, value_change, cpu_id, type) && panic_on_warn)
+	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
+		if (print_report(ptr, size, access_type, value_change, cpu_id, type) && panic_on_warn)
 			panic("panic_on_warn set ...\n");
 
 		release_report(&flags, type);
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200110184834.192636-2-elver%40google.com.
