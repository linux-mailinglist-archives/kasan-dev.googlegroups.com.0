Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75D3OBQMGQEWVTQX4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EDCA35F271
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:29:03 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id c15-20020a5d63cf0000b02900ffc164a0ccsf930338wrw.13
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:29:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399743; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLXpDuT7tVfbqY1hrQTHhRfvZzPb4uxk53M03C/9l5Z+VLZdaKiiw14OHdIYR210wE
         0XddWHtW7f1UVv6+ZRk07m8bnkB/XdzNcB7boQmWlmaJEpXQ4H8NuwOZPjD5q3wkeN1Y
         XpUTp9chtNfU844npVjj3RMdvp36vJq/5Fukw6Na7szy3GHTN4BrXWSgVj7gYSkTYXvo
         umgCsqqoZSFB6fBXustsGxRpIhNQZTMydqurQca/fD61/sirg+oQoOypznaE7xMtTQIN
         ktrU9b1HMT6gVVo63HVlosfSr0/+mFWgSV2VYH8f/H5qPnlJm1aZmVuVfNqw5xgFV8Nb
         4NHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xztgQHQr7dNBIfedHLpGnM1170XeLdWRCnoGKC+wvG4=;
        b=ZdvRKd2W2Fuj7+GJmTvKtzkdX/SKDwRNvZsXX+tFwz2dAaofJjN2cClRYASKv3hwCA
         4XEYa+OUWcii3i4UlFkgdlWjrWkcBZernH2PPdYxqokJuyW8g5kInFVodWhwo1wPnEXd
         sNplVV7p938VTtKtRGh2gQ8E6Y9gVJkANFTNrL04mdzmKk64acOcTR4e/Sxpyv0VroGV
         0Ywd+YEPi2N0FkmqBkxVQELe+h+D2HdHWkSts6BSNqFfJRnMB35KuC4t6vaGLsYQHoXm
         JkT0LD/nFXi7rsUN0tbrCQqfjXZXd/X9zSXNeZ2JFAbP1W7n/2CyX8e++3d+CpuMUqfO
         mCeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ou/B/TmT";
       spf=pass (google.com: domain of 3_df2yaukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3_dF2YAUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xztgQHQr7dNBIfedHLpGnM1170XeLdWRCnoGKC+wvG4=;
        b=g6Nfnj/KEHSMECCCYub+hQz6hGFbRMkYefZyDuoKRpvmQ6pp4Mnfz4BXAh4NKWqlD1
         bigpI7JWAetuDL//RPvYeCcwnQgNNir3E6T6weCWHixvuyebs8JiBttQbVnedZT2h9eI
         uBKFqqq6Wv/3Al2sz6z90xz6IXyEpyrfFl7LUF7OHyrEVhZrI8NiPCcX3S/lRhfGArof
         k0OLj0FXtols5v1M1bYhM8Wzu/RwChg+cbjDhcjBOd+xXoOABDhQoovjJaSR/2vIcC/i
         3fcV2sAp/VRwZX4s+2Vqj/Izw8YC3uIbqkxlR4vnEcBiuigXNWqpr2hymaDEgWc/y5Yu
         Ct0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xztgQHQr7dNBIfedHLpGnM1170XeLdWRCnoGKC+wvG4=;
        b=D7as/BqZfOo25Oj4V9VkB4jxGjn9O5wk39rwXXz4W2F3yAS1XN41u0PMdbpreqjVHF
         pklRt5BEp1VjVwk+YjjJWicvQ6/s7H7+iD/MSiX5SSTKzmB2sXZEBeAgFlF3pg/QUoIm
         xda35fDgxFLc2CiUy67mJNQ+hAJSSSZW3heYNIOX1831+8X5ya1MewAp4GIZRs2B1MJt
         ZLN++ADUo2itjDmZWscChtgvFvxIkqOtDA+WDVrhm5wCf5NyQ/70fC+nD+8HGjsznhCA
         /DKv6RCoi7IA5wkT/AlnW07QS871xeH0ADZcb5YQqZ+Tv2+/PDZQS+BNNFlBX4S31Qzs
         iZGQ==
X-Gm-Message-State: AOAM531lb/Mo3aNlTteOHEAva6ZPv0iYP3FG0hrbDc/a44ODC8W3CIaF
	WVPFaoXJ93S2p4je6wS1kVY=
X-Google-Smtp-Source: ABdhPJxYeLkgU0gNWQNXkN80QCaQtds0gbip9tv4BmwusDta798dY6KaTncoxMVRCUA2n+hJCP4zGw==
X-Received: by 2002:a7b:cb04:: with SMTP id u4mr2536726wmj.122.1618399743178;
        Wed, 14 Apr 2021 04:29:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:24d4:: with SMTP id k203ls980121wmk.0.canary-gmail; Wed,
 14 Apr 2021 04:29:02 -0700 (PDT)
X-Received: by 2002:a1c:2b05:: with SMTP id r5mr2480905wmr.107.1618399742212;
        Wed, 14 Apr 2021 04:29:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399742; cv=none;
        d=google.com; s=arc-20160816;
        b=WCdhb72zT6lWHkJSPSmLxYS/gKwDTtXMP31RFhU0j0CYCwxQdQq+/nxr8Y3pxYQNd3
         baJGH9gDD5G5v/RlQjDDjTL6zHgeLDB6xQ/8z9PXvx8NnSZTHNiwNPd1ETDLzX9Jl6OG
         69E9GiSrA40vD4BBJOlFI4D3DqP4nrewpmXXYL3xZymYh0e87rF4reh5WIbd5lxyqVfH
         H/KbWVfE1uUxLH9QWfhQQ102ntdKlu5jIHsdpZGzGLE53OQxfhSA3s6J3P9lnn7gZV7Z
         cY85f1nsMrQ5cB/ziIQgbkA8WUgmHVnlG4PpmsKcCL9dRad/1ONhKzPkGCi40W47FX1t
         4HJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ynSDj0gr7BYAa8rgkGogbZ/dJW9wUhiWNxksecLrupI=;
        b=eSXejYHysT2J+51GxXiiTTIBH3lBZyRA4Dv0aR1lOxXgcVsJf4OabR7Kj5LzoLFtun
         iv/HBsxsLNK1TRceeb7SfJY8kjgIztojGO4/IhB7tdxviE3t5uR+gTQabw2hkUrNiuwx
         9wEeMb0zIBIl+FkC3Yh8S04pj3XCDZwpHYsaJCCUwtloeu/iHQNRx/9ufwn1CDsAPl0+
         pBReMlW1JodHe7cETtRDzPvxSQ4hzvf5Zw6yDv0Rm+H3/0wD1XK/0QNjNp8OmYyfAV74
         fT2Fw029uo+ZZd6nZYjzzDodVdwUVUoRq6xuHJ2jdwgEIG/zcnlbUtSiskD+W//eJFEX
         YDXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ou/B/TmT";
       spf=pass (google.com: domain of 3_df2yaukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3_dF2YAUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e17si192134wrx.1.2021.04.14.04.29.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:29:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_df2yaukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id i5-20020aa7dd050000b02903830cafa575so1741403edv.6
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:29:02 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a17:906:3d62:: with SMTP id
 r2mr36491433ejf.488.1618399741876; Wed, 14 Apr 2021 04:29:01 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:24 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-9-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 8/9] kcsan: Report observed value changes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ou/B/TmT";       spf=pass
 (google.com: domain of 3_df2yaukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3_dF2YAUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

When a thread detects that a memory location was modified without its
watchpoint being hit, the report notes that a change was detected, but
does not provide concrete values for the change. Knowing the concrete
values can be very helpful in tracking down any racy writers (e.g. as
specific values may only be written in some portions of code, or under
certain conditions).

When we detect a modification, let's report the concrete old/new values,
along with the access's mask of relevant bits (and which relevant bits
were modified). This can make it easier to identify potential racy
writers. As the snapshots are at most 8 bytes, we can only report values
for acceses up to this size, but this appears to cater for the common
case.

When we detect a race via a watchpoint, we may or may not have concrete
values for the modification. To be helpful, let's attempt to log them
when we do as they can be ignored where irrelevant.

The resulting reports appears as follows, with values zero-padded to the
access width:

| ==================================================================
| BUG: KCSAN: data-race in el0_svc_common+0x34/0x25c arch/arm64/kernel/syscall.c:96
|
| race at unknown origin, with read to 0xffff00007ae6aa00 of 8 bytes by task 223 on cpu 1:
|  el0_svc_common+0x34/0x25c arch/arm64/kernel/syscall.c:96
|  do_el0_svc+0x48/0xec arch/arm64/kernel/syscall.c:178
|  el0_svc arch/arm64/kernel/entry-common.c:226 [inline]
|  el0_sync_handler+0x1a4/0x390 arch/arm64/kernel/entry-common.c:236
|  el0_sync+0x140/0x180 arch/arm64/kernel/entry.S:674
|
| value changed: 0x0000000000000000 -> 0x0000000000000002
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 1 PID: 223 Comm: syz-executor.1 Not tainted 5.8.0-rc3-00094-ga73f923ecc8e-dirty #3
| Hardware name: linux,dummy-virt (DT)
| ==================================================================

If an access mask is set, it is shown underneath the "value changed"
line as "bits changed: 0x<bits changed> with mask 0x<non-zero mask>".

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
[ elver@google.com: align "value changed" and "bits changed" lines,
  which required massaging the message; do not print bits+mask if no
  mask set. ]
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c   |  5 +++--
 kernel/kcsan/kcsan.h  |  6 ++++--
 kernel/kcsan/report.c | 31 ++++++++++++++++++++++++++-----
 3 files changed, 33 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 6fe1513e1e6a..26709ea65c71 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -557,7 +557,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		kcsan_report_known_origin(ptr, size, type, value_change,
-					  watchpoint - watchpoints);
+					  watchpoint - watchpoints,
+					  old, new, access_mask);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
@@ -566,7 +567,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
-			kcsan_report_unknown_origin(ptr, size, type);
+			kcsan_report_unknown_origin(ptr, size, type, old, new, access_mask);
 	}
 
 	/*
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 572f119a19eb..f36e25c497ed 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -129,12 +129,14 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
  * thread.
  */
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx);
+			       enum kcsan_value_change value_change, int watchpoint_idx,
+			       u64 old, u64 new, u64 mask);
 
 /*
  * No other thread was observed to race with the access, but the data value
  * before and after the stall differs. Reports a race of "unknown origin".
  */
-void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type);
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
+				 u64 old, u64 new, u64 mask);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 50cee2357885..e37e4386f86d 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -327,7 +327,8 @@ static void print_verbose_info(struct task_struct *task)
 
 static void print_report(enum kcsan_value_change value_change,
 			 const struct access_info *ai,
-			 const struct other_info *other_info)
+			 const struct other_info *other_info,
+			 u64 old, u64 new, u64 mask)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
@@ -407,6 +408,24 @@ static void print_report(enum kcsan_value_change value_change,
 	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
 		print_verbose_info(current);
 
+	/* Print observed value change. */
+	if (ai->size <= 8) {
+		int hex_len = ai->size * 2;
+		u64 diff = old ^ new;
+
+		if (mask)
+			diff &= mask;
+		if (diff) {
+			pr_err("\n");
+			pr_err("value changed: 0x%0*llx -> 0x%0*llx\n",
+			       hex_len, old, hex_len, new);
+			if (mask) {
+				pr_err(" bits changed: 0x%0*llx with mask 0x%0*llx\n",
+				       hex_len, diff, hex_len, mask);
+			}
+		}
+	}
+
 	/* Print report footer. */
 	pr_err("\n");
 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
@@ -584,7 +603,8 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx)
+			       enum kcsan_value_change value_change, int watchpoint_idx,
+			       u64 old, u64 new, u64 mask)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
 	struct other_info *other_info = &other_infos[watchpoint_idx];
@@ -608,7 +628,7 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 	 * be done once we know the full stack trace in print_report().
 	 */
 	if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-		print_report(value_change, &ai, other_info);
+		print_report(value_change, &ai, other_info, old, new, mask);
 
 	release_report(&flags, other_info);
 out:
@@ -616,7 +636,8 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 	kcsan_enable_current();
 }
 
-void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
+				 u64 old, u64 new, u64 mask)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
 	unsigned long flags;
@@ -625,7 +646,7 @@ void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int acce
 	lockdep_off(); /* See kcsan_report_known_origin(). */
 
 	raw_spin_lock_irqsave(&report_lock, flags);
-	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL);
+	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL, old, new, mask);
 	raw_spin_unlock_irqrestore(&report_lock, flags);
 
 	lockdep_on();
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-9-elver%40google.com.
