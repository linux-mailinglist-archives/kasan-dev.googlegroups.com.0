Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO5ZZHZQKGQE6I7C6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FC2C18A1AB
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Mar 2020 18:39:08 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id q10sf17612935ioh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Mar 2020 10:39:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584553147; cv=pass;
        d=google.com; s=arc-20160816;
        b=0H+ekcUNOOHm/GLE+NAeyVEp3egG14mdZ6Bacix7SAoBqZTbnMGxy5vS33zjd4XS14
         9qozANeqLFZAGskHXgHe2MHrpi9iLYzI1+3PQj5BOayeoTDXZTgfNNfD5NOBwv7Li1qQ
         SiMNljie5vi/9Kw+mkmi8Xe4nFvJxvf6t6Xod9JGyb3rUHbtStNyIL6mYoAhu5MzAteB
         ZEvwq2DPtB1pEGwS3RpEepYqq228sD6XfHrOehYZN3eAr6aUIPU4NV8O5t4XtwV7Wvyz
         dwavjPGH/jJuLFCt+yfMxFkCvqFZx2cO8DfNHGotgyy+8u9F2h2LF5JlqQyL2ty26I2Z
         q3eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Hgu2I3Pd5kU30O2XTDY3+ujczDpprFk3itjJ2Y3/z80=;
        b=UBzEBkqaq+F7aEspyYqo2gRqDnesLpB1fx/wwvyEV3G5TNnUSdm6eBlA38fjsp5bJr
         g2p63vqSnJWdoXe1ThUq9TGawg+I13Cl78V2Ke+OJ4k8cIINNmpjuxPpefwy0LgvBBxq
         VYC4pZvV344UJLqvz4T8kcatQoKgZozFXCYrG9KM3V6lTgoeEJfmjERjQZPIdPoF/a8i
         iX2GxyMdQfZ9qzPU3Tr8fJ2AdsZ7Houz1+gNj6SzQbr9XOyfcQpzEAJ+JqrJk3/U+g9K
         f5qUfc5kiiFGH+0CTp0F0EwYlL8ZKMI9b+u6yJ0ZsD1CmuJDwjkCXfiUR4Jm+36aQO/R
         KMsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RQ4t2B2J;
       spf=pass (google.com: domain of 3uvxyxgukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3uVxyXgUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Hgu2I3Pd5kU30O2XTDY3+ujczDpprFk3itjJ2Y3/z80=;
        b=oJEdI//7Z/Uw2A0i1ySLNKp46HxRgSrD6oJUFC4+q2/LucQCMwF8SSp59qV+jv1bSF
         wfUTfREp/wQ2BTr+qBSYvj7N2k4m0EgBZ1Y8Cy96badw105u6cf0sKtTYeliS+3+ZhS6
         9qcY9LEyQFwzUewIx0vJBVn2P2BHggBK+5fLs7L5/H8dT8QpwbjjzxfupX0CfKKrQjiH
         74L1RpHgDYtA2+Tc6dGKMbXbXQZM0K4/maJ2m/9RmdwgT77giKzNmr3ZDzo927F2Kjxu
         0hogCj87yS8rigHN2VhOlDiB3P5bTsFFYkRTdR/T/UJRA/uflO7ZTNsWnEZiUYOTbeG/
         oR7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hgu2I3Pd5kU30O2XTDY3+ujczDpprFk3itjJ2Y3/z80=;
        b=AqLmfzgu0N6P8LJ1wDHhBJOMxxr6WS90q6gjR6aQgUX8zZsHgc0c2gfshUce3Qtksv
         8B5PdN6vc86qgFvfU3t9gJIBVPr0XcTRSLM1Y/3xFh0kU3e8EcVyFgvWN5nhvbpdw2KP
         IA6kC/eoJVFNc6AO+BoBAQ1MQGvQKPsCjp7EscC992rDRWcQ5M6t8agtfyP5XtF8Ddyt
         E9K5AcLxz+aJHyuWsoRtiHKQ+iT7a7CMhzFahITVj09e1O+8pFjvK1qRrdXDKOl/WIv+
         dpkWyeqWr/+OJxnB5s2GC0eMuMgZlRIry5rgdWQOC2BqNoBAS/7wa0peKOUQWvQJW68l
         xElQ==
X-Gm-Message-State: ANhLgQ1rDwZf//r0bXDQj8dMxQotTeigQDhYhKbo4HXsxEOkgzX0+G+B
	841nKbcsVSBs1hvU/NQ0Sdg=
X-Google-Smtp-Source: ADFU+vtudVHjqB+JhxY6FwOCAMPQI/NFa+QipI5h7FqVnkMpevACZQ4h9dvw4SH2L3r5r9/WjdzjpA==
X-Received: by 2002:a92:1310:: with SMTP id 16mr5379074ilt.45.1584553147087;
        Wed, 18 Mar 2020 10:39:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cf36:: with SMTP id s22ls3246546jar.10.gmail; Wed, 18
 Mar 2020 10:39:06 -0700 (PDT)
X-Received: by 2002:a02:caba:: with SMTP id e26mr5401032jap.77.1584553146646;
        Wed, 18 Mar 2020 10:39:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584553146; cv=none;
        d=google.com; s=arc-20160816;
        b=eujHnWB3ukomzsO6oQ1D/bhxlkJKlx1VzH/3xvg6RmL5bKYLAA07yu+sOqc3VSaDeV
         D+xKESuYxt1szsY0ABq5wqGymcMnDRSdsQn6PaYYOUAcm7GR86nHm+MdEnTdyEhyiQj4
         RPd+o9vOYnUMiSKtcusnkuC/hqEckWlCubwqTIN53msmIvm+yFd3H70/Ojx0PEoElUMi
         KESvEg/5tL1mTbZTY7WpGVaZyyaAuAUJE8zq71di15hVVytqM+qTJg880uCjy2J9T1vL
         oCR8s1u9XWzHb94FA6rQz+AVYMe5LVtu4nV4kiQmMZAf/xpKW7i4Qbm3uwkEtWEub6/l
         VrmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=dKI8slPoJDoe7pZ2NQs89Vum1ML0bIAK3za3KYbKvGE=;
        b=0pchRhBkZhvWilZ3uX+AhSvMZAN0paw4puEJUYczK26Dd0cgaL7crAv2suU3i79Z0K
         nnSeEaZTSNm/NDXIbWHADt0uYHLJJ1BeJFADSgKbHmuek1Dr1AnQPVGEfzGShUeUw9w4
         M7c5tnxa8qIBVdQPTAzdjNkxzRfm9Z/Ik0Du9zQJCPy1QZ52X39Wy5vENuzIJc8ifl7W
         4OfTiJEzDnezbBq7HijFw/CSGqlPoXNZG1LPgKmB0uGce9jXF+Gt6A8ZYfZJOAabJtjB
         qIeqy+oXiKRBKPliU12gBEnQdY425MDH688mdOXLOaxuYJWho4yY+Cd9+NcMA6K1Dzc1
         l/aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RQ4t2B2J;
       spf=pass (google.com: domain of 3uvxyxgukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3uVxyXgUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x949.google.com (mail-ua1-x949.google.com. [2607:f8b0:4864:20::949])
        by gmr-mx.google.com with ESMTPS id r16si258913iot.3.2020.03.18.10.39.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Mar 2020 10:39:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uvxyxgukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) client-ip=2607:f8b0:4864:20::949;
Received: by mail-ua1-x949.google.com with SMTP id z18so3570891uap.23
        for <kasan-dev@googlegroups.com>; Wed, 18 Mar 2020 10:39:06 -0700 (PDT)
X-Received: by 2002:ab0:1158:: with SMTP id g24mr3711309uac.71.1584553145967;
 Wed, 18 Mar 2020 10:39:05 -0700 (PDT)
Date: Wed, 18 Mar 2020 18:38:44 +0100
Message-Id: <20200318173845.220793-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.1.481.gfbce0eb801-goog
Subject: [PATCH 1/2] kcsan: Introduce report access_info and other_info
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RQ4t2B2J;       spf=pass
 (google.com: domain of 3uvxyxgukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3uVxyXgUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
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

Improve readability by introducing access_info and other_info structs,
and in preparation of the following commit in this series replaces the
single instance of other_info with an array of size 1.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c   |   6 +-
 kernel/kcsan/kcsan.h  |   2 +-
 kernel/kcsan/report.c | 147 +++++++++++++++++++++---------------------
 3 files changed, 77 insertions(+), 78 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index ee8200835b60..f1c38620e3cf 100644
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
index e282f8b5749e..6630dfe32f31 100644
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
index 18f9d3bc93a5..de234d1c1b3d 100644
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
2.25.1.481.gfbce0eb801-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200318173845.220793-1-elver%40google.com.
