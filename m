Return-Path: <kasan-dev+bncBAABBN5GTLZQKGQEPDCGIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31D5717E7C7
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:25 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id b10sf3404958qto.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780664; cv=pass;
        d=google.com; s=arc-20160816;
        b=j1G0D/08X505tc3K6QaQzLOpmXOvi4R/Z1krCqWG7lFfHl8J0/eRp+0pySJimor63u
         3YAvq6B0Ax536WZoL9PKPJdQoElOra+vhlj/cauLdlw1XJeppseNY7nNbbEeDiytNLEL
         IdRZ6Zj3VP/Gf4uhzGA4JMzb7Es7oiZftWFGyUomx2dGs7CLX7mEgDi44odbkE5jKdh7
         DlES4iWZ6/OWf1J64rdamX/SVQhQqWQ2vm0VtUyGrCBRT/ONeLQQZVxNczSUBS7Q4LO7
         dobixfMdiLYCG4d6fozpQqgfHF0fN2NM1ICyEIeY3tIw67kHElgDXwGNhHrJQPkTA7KO
         uR+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=+tb85Qf0UGmxO7LchY7k/ewbSaVa7EbADIejZi/ysaM=;
        b=0QGLQOW+95+jgpJMSL/lBMRbr0xQk4kIEcF3GNvhKTwdmjq3ia7F4XRsIyrbZateW+
         eDHPIO+2u5wvphEb02EKeaSyJFDqARt48Gbw0SylQ6jAPP3HqIiOaURyT9N4NNZhVVlV
         Cp4cae6rfzxJd7ggn3lUe4cOSkWHcXCQsqE0HpCPlgtyIAlKUxWSc9cge5q0vA+cr7+t
         9j8OQBVrk1NC4b6hH5EaVpMJCUlvwbiGUKOqTG8TfBJ5HnINqEYtPvE0MMcLAefbUY0o
         8VG9nluLGBXdNJC0C8hQciAK4A3LFGcBpBwD+gnDlanTp0etsLMMnTsitCWVHcTG9SQ4
         OIUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="D/XKQ7Z0";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tb85Qf0UGmxO7LchY7k/ewbSaVa7EbADIejZi/ysaM=;
        b=f9wfK3Xahri1rUhX5lkBlqXxvl5o1ZJ6vKxxyLU+KFfh5HMT5tyP4gVQmRMJ4j3bhd
         Xm60bxMFZpCiEGkFmEGBdiM4Dcj5aR5uvNgOxIKFcf2M0Glfz1aO3VaQHrgO4OTn70zs
         T58pWeTBXEeAx7yzbyUZW5gSi4bFSbcilgnHqi7dv4KfZXKRv0KUSCZcgBaw3/zz2ww8
         dWvE6+BF3AQE05nXAfAV3fgHf7kJxf/2BVOActxF6Y6vPPbnOP5bnOHtTlVmogCjRk8U
         IGaPojKTD2EszU9uNzq0buYW6zbc1Ac5+opBF3GjDJ2dtP2pPYeZtkyA7piVCIJex6ki
         0t6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tb85Qf0UGmxO7LchY7k/ewbSaVa7EbADIejZi/ysaM=;
        b=tqrQjfDpJpcIuVCzSnYZSLZv8FbyqpBUjHLL+kwKGkCZFjW/paqnir/aSzjNtpe7B8
         FQYvV9RWaDdegb8wxMK/pjo41azFBHeEBFnpw0Qg5btxdZUqdyMhfQveQbUPSZnThkNP
         +Yrn5NIDBhvqKIYb7p9JyLk2i/3HO1I/UM27n7+2kWWjJGa5bqmSWe8OgCTw0bJ7+1fG
         8wG3x3Qkgj2izZz4nNWIbp8s88VL+vubXseQzcCR9ypBNSqM//SD80PsGwFdXWL88nSr
         cOBlV5/Bd1jXCq15Bzq+iA5M2HJRAcopZhU720yadBYf5WuoQJScSSl8otPt8KwCXh2K
         tNFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3YEAcrI1ARIULco5/t6B0jCaF3K8ZAadymbt+DwnPh6UPyykOZ
	tcIApt/dcvJpPjF71uZ0ckM=
X-Google-Smtp-Source: ADFU+vv+ADAkXUNpGaAsQG0pUk+W18+qkj6R7iJiGTbRiEqIK3U1HJntpb20RnTSDyCh8Eg3MOqHKw==
X-Received: by 2002:ac8:6a13:: with SMTP id t19mr15796672qtr.70.1583780663988;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6714:: with SMTP id b20ls4660124qkc.5.gmail; Mon, 09 Mar
 2020 12:04:23 -0700 (PDT)
X-Received: by 2002:a37:3c9:: with SMTP id 192mr16665787qkd.330.1583780663648;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780663; cv=none;
        d=google.com; s=arc-20160816;
        b=ZVdq1AP82m15PzYYRaKCUZyxqpAkgBomwMolT757UET95SZT1hwZ1A0SYQChuHVZlK
         3z4EsPdbo8LfN+CMUTvlt4mLo684a8nRzWVkaLT5zeCarM+t5UKX5Vm7SnbuuPxrKS1e
         Eur9zKGEhDxgBy2gB9d2SnnCg3CQ3MvQ/awlY3vbC4MjzPQ966WaXfjP/urMvLv41FQe
         V7LDg+VslwSRIJobVDNcfGlNBnZNUhnOORCSAqWJ4fr5NjRoWRkl1/rhCqjIHKhqvJVp
         zQCcDZ/L68pHWPeOK9Dmn+SpD2qDSfrQDWzRJHR9PsrgTYVvvth1ec8F10NVnT/k6aX3
         7jXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=9r84v2PFyIYRDRfzsjLI85txIQspijuXwuu826o7MXg=;
        b=G8mdWnKvsnTT3fgN2V/zUiEGtoubTSulmMwbQUMABIg2CRZ0HZ6907qy68bayZeYcQ
         KOt+C1geHJdZZesd9YqS7GsjU+HWxbvuT9MP5FVCTsd/6L9ndKd3MJSh2WY/y9GCF4wx
         1/Crv0viBJlgOinJWj1dBt/2G9KuvFTGa+pH8s3Qj/Wy3ESgeyFsAXB3mb8M3VcRLFQ6
         rp5d33BNGdRNuPgSaT28LtEDYYC8ZaVQAN0seHEF5n3PKuqzGk4tc1ipWWychiRlk8lx
         KgPLnLHEsf75IWlVUtySh/yrTUrtZJJC39zzYJiicvZ748ntqbOJWvK6RCV/fkqa7y1r
         Ax3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="D/XKQ7Z0";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w10si576933qtn.1.2020.03.09.12.04.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5EC5B222D9;
	Mon,  9 Mar 2020 19:04:22 +0000 (UTC)
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
Subject: [PATCH kcsan 02/32] kcsan: Show full access type in report
Date: Mon,  9 Mar 2020 12:03:50 -0700
Message-Id: <20200309190420.6100-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="D/XKQ7Z0";       spf=pass
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
index 4d4ab5c..87bf857 100644
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
index d3b9a96..8492da4 100644
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
index 0eea05a..9f503ca 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-2-paulmck%40kernel.org.
