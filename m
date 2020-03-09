Return-Path: <kasan-dev+bncBAABBO5GTLZQKGQE2UXRZTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 91B6117E7D4
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:28 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id n16sf7091260pgl.7
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780667; cv=pass;
        d=google.com; s=arc-20160816;
        b=gGtdOOlUEoxzoYARiu0SFfxoUmh1AvYZvPO+vboL3OThiimEENP+96WQmlG6hWoIAA
         c8FbtEeDcjqAI/1qu3jlN9A1f/9rgC/R81J54ufqC2KsobR0clC/D/NEPO+vmIvsOGXz
         q1ouAeBK6if4aGn/RCy/D0zR3G1jiT+sDe+nOCPKWRBRCfxs8G+JkWPVEWpnmx34RFge
         qIZG8ZZcwvDTxl8wnri6VM6SETcIKKvhW+VcBNoJwCfgLuKK3aXIYprn2x5GgQ5Cuk+j
         cSumdbKHfCv2r2DBY2N5AKjTpMPoLEIWrUi2w4Z2awwlTZpDp+bwtS7ebAb9z9dJlkM9
         K8IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=7tu+Rz+5LDYpoljnPCBW7d6ZYcYu/D2zf+fY1bTgMgE=;
        b=F3SBCnFijcOvdWbI+8VMEauqdjVGvjCMpuHXssD2mi1SbMWzlHFSwN8I+pzdnTp0fs
         9mKgLbaqHKu+hj4Ygwsj0RsxvUdiDE6Iar7uPEtdL99mE7j9TEQ6knHH2jH2KnW/P3k5
         uFQyVykTTFqRzdmjzWqR59j+QtIl+H8eSp/0w+lqLcfVitebCdUVJcWDEMHsNgRV5ZN1
         4RSw1JNfrWcTRpshFFkayEMmtDOiyRqln26fcXkYLt4QAwYrMa5UPNg6YGLmRvjMYTtP
         Jh0xPN1YfUx+9nvWyBCvz9fsEXM+kwy2pund9TpFu4k619/ZuoW89CFmRhGyDN17hJ9w
         A6cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gI9orPO8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7tu+Rz+5LDYpoljnPCBW7d6ZYcYu/D2zf+fY1bTgMgE=;
        b=ma49qwVFs3bQjXCEpetd2EkMy9s26u116napOqSIjNjvl2P4nSuRk+H+R6fMNmNF7r
         l1o6JCz0nxb96l181D7RA+XbSOjGyDak7L0L5VPk4EzIi2I6tMJ7boG5/E/O2ksOTv/1
         WsDEOiRv2Y1J3MfR81ffPb+w4pt8EgAHGeJgH/kqnPaJAnRViDbL5A4ejUR6kJUcp0xU
         hVQtSgbCFQwEFvUJ2eZlBFNdOzT9lb8JUogygsVxZD9CQii6BK4cLxo63uTFGDt/O4r6
         2uUFSo2+6jMix1+35uK1FoIU9s2RXqAnwR0QfmY5eNcYmyavAJkeW9o2FXwojWM/XPeh
         qKWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7tu+Rz+5LDYpoljnPCBW7d6ZYcYu/D2zf+fY1bTgMgE=;
        b=cwU02elGZpILMRwlLI0WbLP9Xq4JG7m+yHRJcYogeK6y0c/0VWhGLvznP9D/Fe5YhT
         v6qRCJscLS5YitFN8iLAcCvi0d8OgYHZXFrhoumquuHH4TqxmmHbiAjWnUGO61l1RzQG
         ejH1mrpew3KeMItGKsrMZohZgFtuFK5gcmq1QSKj/AoxNbDzDvSpIOJaKmh6hnPrkFbr
         DCwZ/BWWZmSIttXJpUdBC6fKAw4VC3hKF4VN15Ma2oCwXo7sSZHaD70PPV5XRa1vBC/q
         olxYwzTlxlAuTCaLp15X6A2pk1E1esLtPq6W4Tf64O5B0JRgmJUxU2Yr/FGFT6xwGxsT
         kjjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ35wSNdycU1VaF6IWdjuH5T7gAt6w7ff+aXYV0qbZoKtPEylhMF
	DblwYwvn+gcp2KfbimuaFEI=
X-Google-Smtp-Source: ADFU+vtMvuOVRng6usI0XynvG8tZCXIqQD5OF0UckuZ3ERvubXxMmN2687kMyyhmwXymgWy5+OBhTg==
X-Received: by 2002:a17:90a:8c8a:: with SMTP id b10mr466050pjo.51.1583780667305;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7618:: with SMTP id k24ls1155319pll.4.gmail; Mon, 09
 Mar 2020 12:04:27 -0700 (PDT)
X-Received: by 2002:a17:902:5ac9:: with SMTP id g9mr17619146plm.125.1583780666954;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780666; cv=none;
        d=google.com; s=arc-20160816;
        b=iSTHDpYcX5S1Nl5D9QwwkBt1yNYd+bafnbOHrnC5HuWTVO6JIrwVdtoRC7NCirDgAo
         JJNnUcAeiyTNLAoSVtau7PMfdbK2MXsbVXZmmfnUTqVfXL95UeIdwsGrzs0LqXZFnvv7
         /j2PzuIvd0jDKPxejPkZ7YtIgMFxDXLQywIYJXRlATre1Vs6McFXX2GRzIQgyO7BQ6a6
         M1dRnyO6ge+ocUaa1WnkWpTJz7MKklfYT4O74URARpJ7w2mBWjID8hIFN8i/ZRUM4hTd
         8BKwq0Yjuok6aqcK9ynEVFxadr6PqiKkg34Bj6nrGOI84+iRPo0Dh3W7DC7iZKT3GBse
         qdlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=l1oJTceACW2Ram5YdqfcMZvjr574AoIwvlIjW1xUbCc=;
        b=Da6ya3Mt2lgxsGogmwTk+uUbzxN7jYuuh/xKj6qJTA6saKUc1DhfRnZLyAHAdLnjvp
         vGFUdlQ6PctdX5kdSeeSQU53l4Z4CngtD+iGoy3s81kM5VkJ2pcmf/MSn0M0AVYfbATd
         AyGRpb1hKv3cVuNvWgacVcyJgQBkP1JbPEI6ILiCIg/fF3bnXDnJVC0ltxQkxyAy65gS
         mDyqHc+EKjBDdQswwVQtUTbXMak3flUh4Lq4Q63k+O7flk17frdqz8pRKGxPrJpoWg82
         ovWkbnyS/lqrjhCkuqTDMTyG2+RnwS/pEQDXu3PJP1G8WSlXCRYgAcvggAeS+2y5y3XU
         mrmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gI9orPO8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q197si772628pfc.5.2020.03.09.12.04.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9267A24671;
	Mon,  9 Mar 2020 19:04:26 +0000 (UTC)
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
Subject: [PATCH kcsan 18/32] kcsan: Add test to generate conflicts via debugfs
Date: Mon,  9 Mar 2020 12:04:06 -0700
Message-Id: <20200309190420.6100-18-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gI9orPO8;       spf=pass
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

Add 'test=<iters>' option to KCSAN's debugfs interface to invoke KCSAN
checks on a dummy variable. By writing 'test=<iters>' to the debugfs
file from multiple tasks, we can generate real conflicts, and trigger
data race reports.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c | 51 +++++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 46 insertions(+), 5 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index a9dad44..9bbba0e 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -6,6 +6,7 @@
 #include <linux/debugfs.h>
 #include <linux/init.h>
 #include <linux/kallsyms.h>
+#include <linux/sched.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/sort.h>
@@ -69,9 +70,9 @@ void kcsan_counter_dec(enum kcsan_counter_id id)
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
  * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
- * debugfs file.
+ * debugfs file. This will not generate any conflicts, and tests fast-path only.
  */
-static void microbenchmark(unsigned long iters)
+static noinline void microbenchmark(unsigned long iters)
 {
 	cycles_t cycles;
 
@@ -81,18 +82,52 @@ static void microbenchmark(unsigned long iters)
 	while (iters--) {
 		/*
 		 * We can run this benchmark from multiple tasks; this address
-		 * calculation increases likelyhood of some accesses overlapping
-		 * (they still won't conflict because all are reads).
+		 * calculation increases likelyhood of some accesses
+		 * overlapping. Make the access type an atomic read, to never
+		 * set up watchpoints and test the fast-path only.
 		 */
 		unsigned long addr =
 			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
-		__kcsan_check_read((void *)addr, sizeof(long));
+		__kcsan_check_access((void *)addr, sizeof(long), KCSAN_ACCESS_ATOMIC);
 	}
 	cycles = get_cycles() - cycles;
 
 	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
 }
 
+/*
+ * Simple test to create conflicting accesses. Write 'test=<iters>' to KCSAN's
+ * debugfs file from multiple tasks to generate real conflicts and show reports.
+ */
+static long test_dummy;
+static noinline void test_thread(unsigned long iters)
+{
+	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
+	cycles_t cycles;
+
+	/* We may have been called from an atomic region; reset context. */
+	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
+
+	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
+
+	cycles = get_cycles();
+	while (iters--) {
+		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
+		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
+		ASSERT_EXCLUSIVE_WRITER(test_dummy);
+		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
+
+		/* not actually instrumented */
+		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
+	}
+	cycles = get_cycles() - cycles;
+
+	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
+
+	/* restore context */
+	current->kcsan_ctx = ctx_save;
+}
+
 static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
 {
 	const unsigned long a = *(const unsigned long *)rhs;
@@ -242,6 +277,12 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
+	} else if (!strncmp(arg, "test=", sizeof("test=") - 1)) {
+		unsigned long iters;
+
+		if (kstrtoul(&arg[sizeof("test=") - 1], 0, &iters))
+			return -EINVAL;
+		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
 		set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-18-paulmck%40kernel.org.
