Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6UK3XYAKGQELUFYSGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC32C135C9D
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 16:23:38 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 7sf574335wmf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 07:23:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578583418; cv=pass;
        d=google.com; s=arc-20160816;
        b=AzCJxNWlnMTRAhx7ivRNN3eRbMvyjrQijAieNQRqZH+RnP2Ze/5W23o5DWTmVBy4Ed
         LffVQJK4WM96pSOt/XihG2m+1ghKLb36WRyTToizOZ6hxGEqBotW/o9c/7FU/NQf/x1U
         yGtAU29KpfcONhoIYIi1mGBdROkHA9NQrWvH8haeiDjJFg3BNRivIDrUyCpzSoTL5JRP
         /aCriSNfgC3zfEME6oKFUeTseWUW8uWhviDKqbesBFjGr2cXWU/Y+h0DCuDuSzmllCch
         WJEnHNrCr9ngwV824YAWnOUXGudritelBda2zzPsyeJbhvwUTVwWq6rSHjMLAbpVFMZr
         Nl8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=I+tbXx3H5IcFp+3OIIJ1svEagXPL82DG9EHZDztOkRs=;
        b=FTtPUoF2u+C1S9/Z+Sy7F2vrmL/F9GuIGD3MKhroFv7ddUKLCvusfrrP0H+2kk0mEV
         /L15meG+y68Ksx09csOdT9AcVzXhPFiVOAxiYW0OPXKfDTRcst4Jy/bUpIMUPPTkqUMx
         Tfs+RW//6eJgsWtG6cY2KpXIvBzT9ldgcKfqrovmm+xZhvP+0LMqEGkS/APjcNn3hAop
         tA2dh6PlSPLp9yXkgG0oHFbOs9R41wrKXXSXNqrALe/QQA/D5o/VARkOWtYPUtLnhiHE
         DtB05YrJV6K0Gcqcea0Ue95XObZKdqwfckUwRYygDdgflkhFk0vHD6xFCdB7Yikbsbra
         gZDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YFVOVJQJ;
       spf=pass (google.com: domain of 3euuxxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eUUXXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I+tbXx3H5IcFp+3OIIJ1svEagXPL82DG9EHZDztOkRs=;
        b=c3b9AuyHFwKNKN520kiKYMvs4Ze2fEKzTf4ue4ojd3uWJLUIrDWh9o3ZQwBtHhTlwX
         6bbIZZzot1w3Jz04T4qlJqzs63B2vbGX8/qLlU6W8tx9f1q/HXC2Urx9YbXXHiWgz5bQ
         /V6jmftwZLR9Vzm1FCzqf6rZ6LyB+4DTgi76g9BQZNCJDCzogexGKeohguUb4O4YXCrY
         QPl4lQEfY6ONrzThNtwcyQvJ1CE6JYfoToKUOA+po+p08KZLoX1Pyoj7P6JhAVLBiteO
         1zNXCdq4MkxL1dy7YE+mfsb956EcWhssQrGY/NKfkztG7LXjC/22/DgSJKJ4chfROJLM
         UTLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I+tbXx3H5IcFp+3OIIJ1svEagXPL82DG9EHZDztOkRs=;
        b=SxrzUky8Z5hSwYUlhPMAu7SRppJ02oDBqZ+fHvLHGWgILFe44//jFOSSQZEnTFPMPX
         OIgPtN3YjtQN37Wfgk20PBf3HHeoWh0EU5WdaC1FkQ88LNYMJWi1kA0S8ZsZ6kp9eOnr
         7CLDHR4W6Yuu6mjWGy3ZnUvJdBn7ClZPuW1TcCEMOjKnmrjkV9+L1ceYf+FygiZYXUqJ
         9rdE/McNUGYunDDcc4eXzJ73Xu8wcJ8LWYNGau2mta3FI8vJvnb/XISXmq5VP9uMg8WL
         PpockHtuch8AQLxPJ6k/7bZcvbnp1D9HRFZNqUKXgVIoSCd1t+chGNH26xrlU+TRSAhZ
         4+rA==
X-Gm-Message-State: APjAAAXaooAB+NmJUXBo1DeqKP/ACOhnCM5XNkP6LfRFyQ4BAyGnmptw
	4Dp3qG/WP57ZJiwJ95DP8sM=
X-Google-Smtp-Source: APXvYqwZKeOgJzg1WcKfjv+1bthZyuV8FUgqFl7gH7u59DJhyDVY7JEac4fmJYtbchbCVcVRMHapdA==
X-Received: by 2002:a5d:6708:: with SMTP id o8mr11708076wru.296.1578583418579;
        Thu, 09 Jan 2020 07:23:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c76b:: with SMTP id x11ls963312wmk.3.gmail; Thu, 09 Jan
 2020 07:23:37 -0800 (PST)
X-Received: by 2002:a7b:c7d4:: with SMTP id z20mr5996891wmk.42.1578583417960;
        Thu, 09 Jan 2020 07:23:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578583417; cv=none;
        d=google.com; s=arc-20160816;
        b=IIkR+yK40WVsyC5KVZ3dPgvO0o3mPhb4XumC4caaYuyoqV2uiY9kca/udMU60X4lcU
         MQIN3lRv9+4Uou+SV03be+/xHqS8mbujk9Ar6kWemcRmboRLqdDhtoI5vZEFVQNiNvxp
         DVJR9dMjs0KUrMyzBgQxlChylB70aazWBhLsubzyZdLSIV0CUlhtvVPwid+3LTBMbWmp
         ObeWTX/Tv9LNgoz+Q7TJyufxGeshMx0fciGKaXPCvI/kza+eC4wHxbJVqwenPi36oqyA
         t2gWaQ0tXVXQNzQxUxCaHp6zDXj5Qi/D8CHOw15OJle5EkUQjVts77mlxXPwNYN6zI4H
         07+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=jq0KfymqHCwAzpI6yM9iLGY3LYJxpSimWAtJZq35DB8=;
        b=pTT+eG6Lf7o/nFgr7768uWa1o2louGOsFSt+7epmla4vREhge4zhF+Kbrh2BpqKXcL
         OVbj4tQTbh6TasDfQ1SkeygxZ54CN2zc8me2mvT1a1lnD5RtIftUaHt6I8BBZ2holnx+
         NdoYzWB/g8YYJqG6jriyw/pu7NEf9lKlo0JhJVqH5pObl1D7kZw+04w1fNo6Zfyj544y
         eOuPqdxnuwzW+J8Xx5RWBKen8t7iyO9rpIidjqWmuEElY1fYhweRRuU6SCp7TGKGV48f
         ysjOFGetHYGySavX/q+CAR//2SDpbSVK6ScVLm1ZaWNIAGxkvixEe4Nys7qBqK0L628a
         h9Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YFVOVJQJ;
       spf=pass (google.com: domain of 3euuxxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eUUXXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u9si312893wri.3.2020.01.09.07.23.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 07:23:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3euuxxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id k18so3018295wrw.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 07:23:37 -0800 (PST)
X-Received: by 2002:a5d:5704:: with SMTP id a4mr11552160wrv.198.1578583417361;
 Thu, 09 Jan 2020 07:23:37 -0800 (PST)
Date: Thu,  9 Jan 2020 16:23:21 +0100
In-Reply-To: <20200109152322.104466-1-elver@google.com>
Message-Id: <20200109152322.104466-2-elver@google.com>
Mime-Version: 1.0
References: <20200109152322.104466-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu 1/2] kcsan: Show full access type in report
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YFVOVJQJ;       spf=pass
 (google.com: domain of 3euuxxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eUUXXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

This change adds support for showing the complete access type in the
report. Currently the following access types can be shown:
  "read", "read (marked)", "write", "write (marked)".

Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109152322.104466-2-elver%40google.com.
