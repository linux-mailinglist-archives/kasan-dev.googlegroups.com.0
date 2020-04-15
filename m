Return-Path: <kasan-dev+bncBAABBJ5H3X2AKGQEQ7K43UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 340191AB0CA
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:17 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id b19sf712635otq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975656; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7haA6q7qtz2QlTecGWCx4pLWvGpnnkmmGVWtozOg8pHvEHtMr6kvWn/x3YQa1OyEe
         wWE4iPpPvvsITjhdn3vqkpZPi9e2ZILP2bIhguH5HP/8hyQO915SIqgh3je4JNk0blwa
         KFsL1h7FxnrClCK5FxnXvV4Rc1eK5IJUAb6hdN6dhgfeg3JfgHyDYGJHEfQqb45XlwoB
         GWcEE89IQqCRaF+d7EsbOpN8DPoQl+ZRjzyAhCNOlJPkgPOhk37n5d8DWCOWz+ki2yYc
         iOzTMMGBGcjcvg3ERCAnk02+jmxhbi8LHsGg34wKXBh68jLi9PUCM5d3Kuz6e+WUB4aB
         nWjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=NyQz8BAS9mSs5ch0jk3ejuS3V2Ko/VjtfxAVI4pgYqg=;
        b=mJQeZ9JrT9HffsAEeLLuTIjOxiprPGu8JM1/cJecmTeZwsmS+YWQTYosoVHegj84WU
         onYqrBchW1qD5fvxp+Sm/hXYSX1vZ3T1S5Z0Zbh7eQIgxqT2u3UluZjF4Lb3Hnapgh3W
         IWNgn2YygEDFlMay4qXiFQW6gj1yYer1w3EHzhr0b53ybDFatls/MFDjM3JWQYM2v4On
         jCoJl1MfZo8eZNuxb/JCS/68zLm5Bf+/wHBONCTMxOVzs2C3f/4EM0E1dVUYqk8hrjzQ
         mEgx7kDvp7YhibG90iL8r6HB+zrVwMitp3OBWem7hiep7on0dKQ9OrxmS29Hw3iw0TcK
         jNOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PVxueU0J;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NyQz8BAS9mSs5ch0jk3ejuS3V2Ko/VjtfxAVI4pgYqg=;
        b=P3PZpfPab1N70JDNZDF/JjrtnGYkD9UEsFJTbZSozzCBjfH3v7sSKpClELQwfsLWWG
         fDcpT4/RsDTPwkbxQlrbqhzhHv2adMhTCoP4LlIltySJJzCqySPG6cJKdERipBfOpQuK
         nXWw6UcbvB3hlpQEEXWuWneGz6w2CcNmnCeQsYE1SebVtcI3+fAv2kDHjWwDynE9YQ7j
         DS8b3/pNvTiA0pZT1VoHA9etwKT8J93F4wMSvdaH0v3rK/yUe7KdRLk8vu/9TiSYHiQ7
         bxZw6g+nNlMjllXnP1Ivcbtm5sij1PvCQemfQzRgVCnCJfdRrCpfwmpUK5wfN9saQ8U3
         NI3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NyQz8BAS9mSs5ch0jk3ejuS3V2Ko/VjtfxAVI4pgYqg=;
        b=Smn5bLmDwGLUfR+oHmlJDJlS3dm/e6GM+2cMeLkfhZx5HU5IZjTv2fWaMFJjOvGLZd
         RmtiZedjNJtMqLjfPFfwcHsLKOrYGqHTCH98v4Kht7rchydA937XceUS/ry25pO3JCAj
         Ppbm1AehK1nHUzTXDzJsjg668l8trwREHzB2wKpsdUcZH/MAg0CCY+OiPkoliFqg+/RT
         ertozsdxj7hPkWvknsuM+jt3ZrpIgQmtGhECXk5MNYUYd9dEGYchVbLQDMK8r5pd5+ka
         ejirLNvYCvIVj1ru0k9EcEHBMwZt09hjDCTGcvjv6MHXL8s/5xEu6g5Bs9OnncqvhzAi
         kSZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYy6D4lSORjUeM2oJGtmAdgleQTAeJOTJLnCnkgd51zX4lppDUh
	9J3EeFey28u+2z7SWjjnnyA=
X-Google-Smtp-Source: APiQypIEPARytw7Csyxvt+WMLnCcTNhHbVt59ZF/id9B0GxT9RKKo2R9laEqZFu3ypzfHYhCs9Tg6g==
X-Received: by 2002:a4a:890b:: with SMTP id f11mr23654355ooi.85.1586975656019;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7312:: with SMTP id e18ls1163013otk.4.gmail; Wed, 15 Apr
 2020 11:34:15 -0700 (PDT)
X-Received: by 2002:a05:6830:1b7a:: with SMTP id d26mr13413148ote.120.1586975655669;
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975655; cv=none;
        d=google.com; s=arc-20160816;
        b=jhnvhRWvE/VrV/ZKpzs1BUIw5L+9toPjztAt1yN1jaqOnm7t9PgtND+dAzIoK92Z1B
         87EFn+kgzSFsfZsOclgc6bdIucvAIks6WVY8quuQVjOKOj8f/+AYIet7J4uYVGlxRSAh
         a1C+t6sYFgKnP/AKcCkVdw4FsnY2GW1kautK6OJJPw669AQYBYCgayuHweD5P5NVU6cz
         vME9ciZowxFOlDy++8f7MUGorb5ZJftxbmuopq+gWJQnfIiR3yPARolMRX/+4CL9WYhB
         lqMzx2jRmc2Lt5799qcBCVF1Gsfbpnh2bFRRUFT6YITtPLImsXrmBpCAhSy4IyOmRU7e
         06kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=HDzaBgeIAgPJuXdFt3UakVqFaPGfnHn19svuw645R2k=;
        b=DcnJzyA+lX27l9mqqXhCG1u0djnGrJCpx7M0HK2tUKqjdjmuTrhsmPaCWURxuGBr1n
         ZYX5yybpmF1xl893tqj26Nlaosm5G9ah9OyjLpYR24gyccOZLBX1Mgtd2O0qeF5iggs5
         RNr4Lf5Zvqckwfiw4nXYfCcTszSUYNNRRWd2i2wzVbZd5vSoVY3jfrZlKMj6QKIDmfbR
         cI69Bv6SCNHAth7bivGlITkZhLtp3/j0e8HWgTRLQdnzySpZQN+QG6aVOT/5r4hNJuNi
         cfb1iFk30fnyryZJgrknaOqmPllYYKRLcQjJgYzdhz/3bkvbm+5yBkYM3y8juYSUsauz
         WnFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PVxueU0J;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w11si549061ooc.0.2020.04.15.11.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B5CB221734;
	Wed, 15 Apr 2020 18:34:14 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH v4 tip/core/rcu 07/15] kcsan: Introduce report access_info and other_info
Date: Wed, 15 Apr 2020 11:34:03 -0700
Message-Id: <20200415183411.12368-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PVxueU0J;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Improve readability by introducing access_info and other_info structs,
and in preparation of the following commit in this series replaces the
single instance of other_info with an array of size 1.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c   |   6 +--
 kernel/kcsan/kcsan.h  |   2 +-
 kernel/kcsan/report.c | 147 +++++++++++++++++++++++++-------------------------
 3 files changed, 77 insertions(+), 78 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index ee82008..f1c3862 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -321,7 +321,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	flags = user_access_save();
 
 	if (consumed) {
-		kcsan_report(ptr, size, type, true, raw_smp_processor_id(),
+		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
 			     KCSAN_REPORT_CONSUMED_WATCHPOINT);
 	} else {
 		/*
@@ -500,8 +500,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
 			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
 
-		kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
-			     KCSAN_REPORT_RACE_SIGNAL);
+		kcsan_report(ptr, size, type, value_change, KCSAN_REPORT_RACE_SIGNAL);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
@@ -511,7 +510,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
 			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
-				     raw_smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
 	}
 
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index e282f8b..6630dfe 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -135,7 +135,7 @@ enum kcsan_report_type {
  * Print a race report from thread that encountered the race.
  */
 extern void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-			 enum kcsan_value_change value_change, int cpu_id,
+			 enum kcsan_value_change value_change,
 			 enum kcsan_report_type type);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 18f9d3b..de234d1 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -19,18 +19,23 @@
  */
 #define NUM_STACK_ENTRIES 64
 
+/* Common access info. */
+struct access_info {
+	const volatile void	*ptr;
+	size_t			size;
+	int			access_type;
+	int			task_pid;
+	int			cpu_id;
+};
+
 /*
  * Other thread info: communicated from other racing thread to thread that set
  * up the watchpoint, which then prints the complete report atomically. Only
  * need one struct, as all threads should to be serialized regardless to print
  * the reports, with reporting being in the slow-path.
  */
-static struct {
-	const volatile void	*ptr;
-	size_t			size;
-	int			access_type;
-	int			task_pid;
-	int			cpu_id;
+struct other_info {
+	struct access_info	ai;
 	unsigned long		stack_entries[NUM_STACK_ENTRIES];
 	int			num_stack_entries;
 
@@ -52,7 +57,9 @@ static struct {
 	 * that populated @other_info until it has been consumed.
 	 */
 	struct task_struct	*task;
-} other_info;
+};
+
+static struct other_info other_infos[1];
 
 /*
  * Information about reported races; used to rate limit reporting.
@@ -238,7 +245,7 @@ static const char *get_thread_desc(int task_id)
 }
 
 /* Helper to skip KCSAN-related functions in stack-trace. */
-static int get_stack_skipnr(unsigned long stack_entries[], int num_entries)
+static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
 {
 	char buf[64];
 	int skip = 0;
@@ -279,9 +286,10 @@ static void print_verbose_info(struct task_struct *task)
 /*
  * Returns true if a report was generated, false otherwise.
  */
-static bool print_report(const volatile void *ptr, size_t size, int access_type,
-			 enum kcsan_value_change value_change, int cpu_id,
-			 enum kcsan_report_type type)
+static bool print_report(enum kcsan_value_change value_change,
+			 enum kcsan_report_type type,
+			 const struct access_info *ai,
+			 const struct other_info *other_info)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
@@ -297,9 +305,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 		return false;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
-		other_skipnr = get_stack_skipnr(other_info.stack_entries,
-						other_info.num_stack_entries);
-		other_frame = other_info.stack_entries[other_skipnr];
+		other_skipnr = get_stack_skipnr(other_info->stack_entries,
+						other_info->num_stack_entries);
+		other_frame = other_info->stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
 		if (skip_report(value_change, other_frame))
@@ -321,13 +329,13 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 		 */
 		cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
 		pr_err("BUG: KCSAN: %s in %ps / %ps\n",
-		       get_bug_type(access_type | other_info.access_type),
+		       get_bug_type(ai->access_type | other_info->ai.access_type),
 		       (void *)(cmp < 0 ? other_frame : this_frame),
 		       (void *)(cmp < 0 ? this_frame : other_frame));
 	} break;
 
 	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
-		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(access_type),
+		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(ai->access_type),
 		       (void *)this_frame);
 		break;
 
@@ -341,30 +349,28 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	switch (type) {
 	case KCSAN_REPORT_RACE_SIGNAL:
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(other_info.access_type), other_info.ptr,
-		       other_info.size, get_thread_desc(other_info.task_pid),
-		       other_info.cpu_id);
+		       get_access_type(other_info->ai.access_type), other_info->ai.ptr,
+		       other_info->ai.size, get_thread_desc(other_info->ai.task_pid),
+		       other_info->ai.cpu_id);
 
 		/* Print the other thread's stack trace. */
-		stack_trace_print(other_info.stack_entries + other_skipnr,
-				  other_info.num_stack_entries - other_skipnr,
+		stack_trace_print(other_info->stack_entries + other_skipnr,
+				  other_info->num_stack_entries - other_skipnr,
 				  0);
 
 		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
-			print_verbose_info(other_info.task);
+			print_verbose_info(other_info->task);
 
 		pr_err("\n");
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(access_type), ptr, size,
-		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
-		       cpu_id);
+		       get_access_type(ai->access_type), ai->ptr, ai->size,
+		       get_thread_desc(ai->task_pid), ai->cpu_id);
 		break;
 
 	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
 		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
-		       get_access_type(access_type), ptr, size,
-		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
-		       cpu_id);
+		       get_access_type(ai->access_type), ai->ptr, ai->size,
+		       get_thread_desc(ai->task_pid), ai->cpu_id);
 		break;
 
 	default:
@@ -386,22 +392,23 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	return true;
 }
 
-static void release_report(unsigned long *flags, enum kcsan_report_type type)
+static void release_report(unsigned long *flags, struct other_info *other_info)
 {
-	if (type == KCSAN_REPORT_RACE_SIGNAL)
-		other_info.ptr = NULL; /* mark for reuse */
+	if (other_info)
+		other_info->ai.ptr = NULL; /* Mark for reuse. */
 
 	spin_unlock_irqrestore(&report_lock, *flags);
 }
 
 /*
- * Sets @other_info.task and awaits consumption of @other_info.
+ * Sets @other_info->task and awaits consumption of @other_info.
  *
  * Precondition: report_lock is held.
  * Postcondition: report_lock is held.
  */
-static void
-set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
+static void set_other_info_task_blocking(unsigned long *flags,
+					 const struct access_info *ai,
+					 struct other_info *other_info)
 {
 	/*
 	 * We may be instrumenting a code-path where current->state is already
@@ -418,7 +425,7 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
 	 */
 	int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
 
-	other_info.task = current;
+	other_info->task = current;
 	do {
 		if (is_running) {
 			/*
@@ -438,19 +445,19 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
 		spin_lock_irqsave(&report_lock, *flags);
 		if (timeout-- < 0) {
 			/*
-			 * Abort. Reset other_info.task to NULL, since it
+			 * Abort. Reset @other_info->task to NULL, since it
 			 * appears the other thread is still going to consume
 			 * it. It will result in no verbose info printed for
 			 * this task.
 			 */
-			other_info.task = NULL;
+			other_info->task = NULL;
 			break;
 		}
 		/*
 		 * If @ptr nor @current matches, then our information has been
 		 * consumed and we may continue. If not, retry.
 		 */
-	} while (other_info.ptr == ptr && other_info.task == current);
+	} while (other_info->ai.ptr == ai->ptr && other_info->task == current);
 	if (is_running)
 		set_current_state(TASK_RUNNING);
 }
@@ -460,9 +467,8 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
  * acquires the matching other_info and returns true. If other_info is not
  * required for the report type, simply acquires report_lock and returns true.
  */
-static bool prepare_report(unsigned long *flags, const volatile void *ptr,
-			   size_t size, int access_type, int cpu_id,
-			   enum kcsan_report_type type)
+static bool prepare_report(unsigned long *flags, enum kcsan_report_type type,
+			   const struct access_info *ai, struct other_info *other_info)
 {
 	if (type != KCSAN_REPORT_CONSUMED_WATCHPOINT &&
 	    type != KCSAN_REPORT_RACE_SIGNAL) {
@@ -476,18 +482,14 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 
 	switch (type) {
 	case KCSAN_REPORT_CONSUMED_WATCHPOINT:
-		if (other_info.ptr != NULL)
+		if (other_info->ai.ptr)
 			break; /* still in use, retry */
 
-		other_info.ptr			= ptr;
-		other_info.size			= size;
-		other_info.access_type		= access_type;
-		other_info.task_pid		= in_task() ? task_pid_nr(current) : -1;
-		other_info.cpu_id		= cpu_id;
-		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
+		other_info->ai = *ai;
+		other_info->num_stack_entries = stack_trace_save(other_info->stack_entries, NUM_STACK_ENTRIES, 1);
 
 		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
-			set_other_info_task_blocking(flags, ptr);
+			set_other_info_task_blocking(flags, ai, other_info);
 
 		spin_unlock_irqrestore(&report_lock, *flags);
 
@@ -498,37 +500,31 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 		return false;
 
 	case KCSAN_REPORT_RACE_SIGNAL:
-		if (other_info.ptr == NULL)
+		if (!other_info->ai.ptr)
 			break; /* no data available yet, retry */
 
 		/*
 		 * First check if this is the other_info we are expecting, i.e.
 		 * matches based on how watchpoint was encoded.
 		 */
-		if (!matching_access((unsigned long)other_info.ptr &
-					     WATCHPOINT_ADDR_MASK,
-				     other_info.size,
-				     (unsigned long)ptr & WATCHPOINT_ADDR_MASK,
-				     size))
+		if (!matching_access((unsigned long)other_info->ai.ptr & WATCHPOINT_ADDR_MASK, other_info->ai.size,
+				     (unsigned long)ai->ptr & WATCHPOINT_ADDR_MASK, ai->size))
 			break; /* mismatching watchpoint, retry */
 
-		if (!matching_access((unsigned long)other_info.ptr,
-				     other_info.size, (unsigned long)ptr,
-				     size)) {
+		if (!matching_access((unsigned long)other_info->ai.ptr, other_info->ai.size,
+				     (unsigned long)ai->ptr, ai->size)) {
 			/*
 			 * If the actual accesses to not match, this was a false
 			 * positive due to watchpoint encoding.
 			 */
-			kcsan_counter_inc(
-				KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
+			kcsan_counter_inc(KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
 
 			/* discard this other_info */
-			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
+			release_report(flags, other_info);
 			return false;
 		}
 
-		access_type |= other_info.access_type;
-		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
+		if (!((ai->access_type | other_info->ai.access_type) & KCSAN_ACCESS_WRITE)) {
 			/*
 			 * While the address matches, this is not the other_info
 			 * from the thread that consumed our watchpoint, since
@@ -561,15 +557,11 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 			 * data, and at this point the likelihood that we
 			 * re-report the same race again is high.
 			 */
-			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
+			release_report(flags, other_info);
 			return false;
 		}
 
-		/*
-		 * Matching & usable access in other_info: keep other_info_lock
-		 * locked, as this thread consumes it to print the full report;
-		 * unlocked in release_report.
-		 */
+		/* Matching access in other_info. */
 		return true;
 
 	default:
@@ -582,10 +574,19 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 }
 
 void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-		  enum kcsan_value_change value_change, int cpu_id,
+		  enum kcsan_value_change value_change,
 		  enum kcsan_report_type type)
 {
 	unsigned long flags = 0;
+	const struct access_info ai = {
+		.ptr		= ptr,
+		.size		= size,
+		.access_type	= access_type,
+		.task_pid	= in_task() ? task_pid_nr(current) : -1,
+		.cpu_id		= raw_smp_processor_id()
+	};
+	struct other_info *other_info = type == KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
+					? NULL : &other_infos[0];
 
 	/*
 	 * With TRACE_IRQFLAGS, lockdep's IRQ trace state becomes corrupted if
@@ -596,19 +597,19 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	lockdep_off();
 
 	kcsan_disable_current();
-	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
+	if (prepare_report(&flags, type, &ai, other_info)) {
 		/*
 		 * Never report if value_change is FALSE, only if we it is
 		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
 		 * be done once we know the full stack trace in print_report().
 		 */
 		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
-				print_report(ptr, size, access_type, value_change, cpu_id, type);
+				print_report(value_change, type, &ai, other_info);
 
 		if (reported && panic_on_warn)
 			panic("panic_on_warn set ...\n");
 
-		release_report(&flags, type);
+		release_report(&flags, other_info);
 	}
 	kcsan_enable_current();
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-7-paulmck%40kernel.org.
