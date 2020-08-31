Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 057332580AB
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:11 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id i14sf4497703otc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897890; cv=pass;
        d=google.com; s=arc-20160816;
        b=kdbSNSwiifEoSYBDFFkV+GqR9IFnRrUVHGhHxUN7v/Yn6dfO6HpL0A0CJgeILBORDp
         y8f/5sz2w+GzyhtXmOgcXp4c4WGsOSZYi5iSHmr5rANj397gftotWoMfMmliaxIe3Hy7
         Okm5dESL+UGNXXWc8iBn7r7TV8A4BeVmLDaa4r/jRaKgV/kZ6A8nErTIudmZfGa0phzW
         HfFXHKylRAdiWjZip+S8GrpS2jcfGzyfIilYzJlp/WJ6ojBbNkBOyDC95+e20GBnuMHw
         lAimeEuHe5Rucn+aKbOg1k+Kshd3WYm4j2/IIFrx7xETYRWnODHoNAsg7q2N+NXQVt55
         zgGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=6j34vcF7UIViSBz+WMUGdBlURKnisa2ORRdwlLNa4II=;
        b=pgQOeMxe0ppNjtMOMrx+iFSpavNuunyRyVSXnlOCFCitWP8VAfVQCGNFXNc/YHZ3Xl
         +YAe4gbenJiA/MQT3/W/S9/Fb1q3ng1GZ+YTZoeFXM0+FsKh3WPG9Mp6sDMif0oTZ13m
         ugTW1wUi9WSpPAqG/5yOxM+NEds8BdfFzdMAV/+kfBkuVXupMEbM1fkIjUDdbqWGZkq3
         fQPtGuv9LZCHm938qFxt7+LwzVsevoi9agzJU69lTEtjl7UEP0mxTZIucqjXheVnsCyG
         HNTuKaPFsNOIGnt9r2NZjS6IDOEW2eEaXW0y1ohTBdT5qJEnBBsHma/0pI0IDK8r3/QO
         Kpsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JNSS9nUV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6j34vcF7UIViSBz+WMUGdBlURKnisa2ORRdwlLNa4II=;
        b=mycvUMEK7CJwKLXhJjqE3/volVN3GFNTxs6qRPDKQrWnBJtmdwIRYs/MGLHxcoQptI
         84Ih7+5LQKSTPd67APPhf/OnUL2jWW/65fgSZ3Tcoj40I43lymj8jc5U+RdqRYxN2+8z
         VNqrcJ8EN3U/Hqc0dYQcooK9+CAh2X2+WomEzbpDLaFj47BtcgqLzYOOVol5pnFoCMVN
         nIQFkpfXX30uhxvF8vIdKotGh/EP85UY7/WV1sWMqjMCzPcivCN9HEPHEv6hcOwCYZkH
         05wA4iKqCOlGncUe4zWxsiz0AQAjO4dFLpuGjKJJLtjCHtR78QA3dNJDZmViEda4Qdgr
         y+Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6j34vcF7UIViSBz+WMUGdBlURKnisa2ORRdwlLNa4II=;
        b=REO2VwfhqHD7Z8vI/GMQTQvQM9GAzdhEOj0fkodEe407xIWMraEKeRWub4OH7yNm99
         wyY+YGIxOA1G3Tuw6foIRz+GalN/TLZ0iL4SizsgAsv+8d2OZ8rguapqzr4+ehzJ3JWy
         qvZ2pa02ioWMoh/fgUs3imrR28sney0kHb1Wwx1WbJC/H/f/c294xSavtUXQI5JP/8m2
         Zgf30YA7k9mopj6R+s3cOXtUjexw9ANodxKisVUzyz1MdPPz0/TXG9Vwu0+80PIGItW4
         zdUVPtuVzcxDPVrQEIBLetEKnfJo4Jl5iPpm0jLK08yK//gnvjpRiKF65ib+e3wWqQpg
         mQ5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Bm2fFoNyOJ6uGqc0EvtzH6Qm6Yh5wBCoy1T8vAeOZQzSPysMj
	y1i6R1K+cEMM6erNsmHz15k=
X-Google-Smtp-Source: ABdhPJzdhn9pjUNakPFz9COLjDJrr64EURLsVNBLNtKLo/Ufb0avXnCIsWLdTa8tlIE7qx8SMjaItA==
X-Received: by 2002:a9d:7656:: with SMTP id o22mr1648233otl.109.1598897889942;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:31d1:: with SMTP id x200ls462028oix.7.gmail; Mon, 31 Aug
 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:aca:550d:: with SMTP id j13mr399267oib.58.1598897889604;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=t5s6MJwG10njuJPY7y80OQDiqdU+KiSgco5EA2TbYjzOs7clllXvldnCYFGDG6mS8Q
         gNo8arCZJRtbcmzwpirsGx1JOeoMLzjsulnJxr1/4ofP0hHF6TUb0tGNVTpX72cEiFKx
         S8AYtYUMvTsVtiz/DyHLo3eDBZq01yCVUgbIQdANHK2Rm98/Okp/mTv3UvdmoVYjLU73
         QNH7TWrL8YR1jgDwatA0BrTfTdOUcOCKbvP1bzMWEMRiwqqpvtWPc1uiMwWzhQS3b5dp
         8FgIO1nOpiBCKxV97IQMWHogAQH/uWYvfHQojTgZGkFGInrJqiSANtmPk1OzPDFQjm1W
         h3dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=FcT3vSomM/aOhNQ8U12RJc0LAqVsej6eBQxocV0dEkM=;
        b=RVukGYG76XJL/S31HW+SsPQFv0C/B3QO9uB1MDm/WW8etsy/tVIb7JhAHylM0klvtZ
         SoQLWXBUC9iH/rGkKNzzym8BTk7FMjCnvbS5uJEwwn31yV2xHFFRv5grDJbJAwQRHYf/
         AyWy3RDmw5JH3pX29fXEawSta03ZxMsbT6IT1hFV81x8rfMVGiAsAMbxiLMp/tkZkP+v
         j+ydqujcd5Xaz3UmmTMTeB+kL4l81/TOMCzrAnu/2O3sHAsjs5meceJUXlvl19Rcsul8
         BxXts6ZIl6SBCAQG/8Wrk1ut4yu3s/kYwMePGz5rNf6zxzB6lhhxKa9kXLVXPNCXRrw4
         VR4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JNSS9nUV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l19si215924oih.2.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E0EDE21707;
	Mon, 31 Aug 2020 18:18:08 +0000 (UTC)
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
Subject: [PATCH kcsan 17/19] kcsan: Optimize debugfs stats counters
Date: Mon, 31 Aug 2020 11:18:03 -0700
Message-Id: <20200831181805.1833-17-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=JNSS9nUV;       spf=pass
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

Remove kcsan_counter_inc/dec() functions, as they perform no other
logic, and are no longer needed.

This avoids several calls in kcsan_setup_watchpoint() and
kcsan_found_watchpoint(), as well as lets the compiler warn us about
potential out-of-bounds accesses as the array's size is known at all
usage sites at compile-time.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c    | 22 +++++++++++-----------
 kernel/kcsan/debugfs.c | 21 +++++----------------
 kernel/kcsan/kcsan.h   | 12 ++++++------
 kernel/kcsan/report.c  |  2 +-
 4 files changed, 23 insertions(+), 34 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index b176400..8a1ff605 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -367,13 +367,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 		 * already removed the watchpoint, or another thread consumed
 		 * the watchpoint before this thread.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_REPORT_RACES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_REPORT_RACES]);
 	}
 
 	if ((type & KCSAN_ACCESS_ASSERT) != 0)
-		kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 	else
-		kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_DATA_RACES]);
 
 	user_access_restore(flags);
 }
@@ -414,7 +414,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 
 	if (!check_encodable((unsigned long)ptr, size)) {
-		kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_UNENCODABLE_ACCESSES]);
 		goto out;
 	}
 
@@ -434,12 +434,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * with which should_watch() returns true should be tweaked so
 		 * that this case happens very rarely.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_NO_CAPACITY);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_NO_CAPACITY]);
 		goto out_unlock;
 	}
 
-	kcsan_counter_inc(KCSAN_COUNTER_SETUP_WATCHPOINTS);
-	kcsan_counter_inc(KCSAN_COUNTER_USED_WATCHPOINTS);
+	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_SETUP_WATCHPOINTS]);
+	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
 
 	/*
 	 * Read the current value, to later check and infer a race if the data
@@ -541,16 +541,16 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * increment this counter.
 		 */
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
-			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		kcsan_report(ptr, size, type, value_change, KCSAN_REPORT_RACE_SIGNAL,
 			     watchpoint - watchpoints);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
-		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN]);
 		if (is_assert)
-			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
 			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
@@ -563,7 +563,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * reused after this point.
 	 */
 	remove_watchpoint(watchpoint);
-	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
+	atomic_long_dec(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
 out_unlock:
 	if (!kcsan_interrupt_watcher)
 		local_irq_restore(irq_flags);
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 6c4914f..3c8093a 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -17,10 +17,7 @@
 
 #include "kcsan.h"
 
-/*
- * Statistics counters.
- */
-static atomic_long_t counters[KCSAN_COUNTER_COUNT];
+atomic_long_t kcsan_counters[KCSAN_COUNTER_COUNT];
 static const char *const counter_names[] = {
 	[KCSAN_COUNTER_USED_WATCHPOINTS]		= "used_watchpoints",
 	[KCSAN_COUNTER_SETUP_WATCHPOINTS]		= "setup_watchpoints",
@@ -53,16 +50,6 @@ static struct {
 };
 static DEFINE_SPINLOCK(report_filterlist_lock);
 
-void kcsan_counter_inc(enum kcsan_counter_id id)
-{
-	atomic_long_inc(&counters[id]);
-}
-
-void kcsan_counter_dec(enum kcsan_counter_id id)
-{
-	atomic_long_dec(&counters[id]);
-}
-
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
  * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
@@ -206,8 +193,10 @@ static int show_info(struct seq_file *file, void *v)
 
 	/* show stats */
 	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
-	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i)
-		seq_printf(file, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));
+	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i) {
+		seq_printf(file, "%s: %ld\n", counter_names[i],
+			   atomic_long_read(&kcsan_counters[i]));
+	}
 
 	/* show filter functions, and filter type */
 	spin_lock_irqsave(&report_filterlist_lock, flags);
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 2948001..8d4bf34 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -8,6 +8,7 @@
 #ifndef _KERNEL_KCSAN_KCSAN_H
 #define _KERNEL_KCSAN_KCSAN_H
 
+#include <linux/atomic.h>
 #include <linux/kcsan.h>
 #include <linux/sched.h>
 
@@ -34,6 +35,10 @@ void kcsan_restore_irqtrace(struct task_struct *task);
  */
 void kcsan_debugfs_init(void);
 
+/*
+ * Statistics counters displayed via debugfs; should only be modified in
+ * slow-paths.
+ */
 enum kcsan_counter_id {
 	/*
 	 * Number of watchpoints currently in use.
@@ -86,12 +91,7 @@ enum kcsan_counter_id {
 
 	KCSAN_COUNTER_COUNT, /* number of counters */
 };
-
-/*
- * Increment/decrement counter with given id; avoid calling these in fast-path.
- */
-extern void kcsan_counter_inc(enum kcsan_counter_id id);
-extern void kcsan_counter_dec(enum kcsan_counter_id id);
+extern atomic_long_t kcsan_counters[KCSAN_COUNTER_COUNT];
 
 /*
  * Returns true if data races in the function symbol that maps to func_addr
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index bf1d594..d3bf87e 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -559,7 +559,7 @@ static bool prepare_report_consumer(unsigned long *flags,
 		 * If the actual accesses to not match, this was a false
 		 * positive due to watchpoint encoding.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ENCODING_FALSE_POSITIVES]);
 		goto discard;
 	}
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-17-paulmck%40kernel.org.
