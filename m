Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60D652580A7
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:10 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id j20sf5799326ybt.10
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fl1j+ukpGuqJpIJVofMa8vn5X44j3vIOYeTUe4w2Vo7NLXCH67EAAzsuUltx/YJng0
         b1A6339GFx3/jgtCXjgJlmdU1nXUnmiO0TAXnw7ce9GQAy4weyaUhRS2mp53PW7Yo06N
         Kde3xuBXfAKCRfyKQyHdulUyTolzPQ6ynT/zbr32r28cxrTx2MG/RsKo3208I5Gwlace
         mv92Ey8kDhn3nPXo/NVllwOs0x5gOhc17Am7nhAuiDoJrvN4iu8hXFmDlAVIXl5UlfIn
         OJPVbQlQ94PmMkWsvFqo1aAg5dmuWMo8c+jSj/DeoJP7LntcAPUeuFyzylpWQizyfIeO
         m6/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Fs03go3v9viHNEGfTdA2mC6hpKN8DAxdVcgzG5aDj8I=;
        b=dYpErORsrhC3243Q4m/DUiIgLRLBh3JmiXrETR09bMUf0bIwHX2j673bQ07CAOCD+D
         TelwdkA8rW5rWFotVGxK7ZpQPH2lj7z7ERbgzicnoqVyRBpLLnpO3bo0x3d2uGCKMhK0
         F9MBbD7B7qLsm6J4Q0SEM+roYrOE4dYLOPrUz/iU3GlyHDC9kh5rePayGXthSNvrkxdS
         flSZLgEMfAp/HYAMCH9/1XyXcVRPGdsZZ9yJTgKkRAX89mUCyGb//gtpUQr6A1BCHKN4
         YRWLskJBCxZrWtLhb/hDCMPSPCvU2Z3Q0ZAuRX+WPR8kZjsjnJSc8Ju+do+MYnYjkuNu
         +sIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iJyQwhZJ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fs03go3v9viHNEGfTdA2mC6hpKN8DAxdVcgzG5aDj8I=;
        b=GueEI34ZWLofno1WOt21qISYioNv/TaokRl8TMSaC92mJYeOWPmx8JYKKjES1+Gmd4
         N4sz7ItsjQB4uZ4B712yHZoJVfAvZDCVL/xKSnRkQerQCxYO8RekPfhDl11NXJYXGSRY
         RJiZtnf3Uqwy4V85Oxcvi+ClOTWDfr8mjcAyRDGv4XlALu0UecBNkAX3DgRP5sWajg7u
         iXoLpZfcbdO4Ydy8h0KQSbUBvfi1DngkJXwne5CqFi4DE9tFG8ne+tiw0dl2KhqFLFmT
         UWlqVgCk3X34zko27Wwai7kvFXDRdxASK0AbD5w0k7de6c5FYPC0a8+M5S9Cnn5vMdFt
         Hp2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fs03go3v9viHNEGfTdA2mC6hpKN8DAxdVcgzG5aDj8I=;
        b=pctYUtpIUNrtBx37N0pURafKVYrqquIUJEcu7FMruE0Bohw1zBYzrvOIhtlaFndO7m
         z18poYZDp9uSHvtHwmbzCPgP/vNy8zUexqgH676KsKwzJSJeLFcG15au6ZdP+p7PZIWg
         NTcwgz0BPzTjzv8/zH0P5mgmy6FreLAi7xUx1dSvXKIUJI1QSQhJUOJozch5wt9p3dS7
         +PoA+s306lur2m6JPgAS8a9wWZR1D1Qkvof5qn+H1WNTCemAsGLB7fMArcsvP90my570
         /X0IdFnkoScKYQvyX+2qSiDAn37jLZFR6uOlAAULLBmvLAjWZiOvRNE4v1KxcvIZD99m
         4dnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iyfSeKqvt9Xsf1WWtwOxq4EwRZR4wo546PHP5rryG0vGHsD7T
	5/cIFDXgaGkpb4/lOLsClQU=
X-Google-Smtp-Source: ABdhPJwDuhOaqPry+UY1dKqYBaHVDG8V0AbpohXCtZw4g3+/y5tIxPV5EoBzSC8oyJc7MIXmUMCTxw==
X-Received: by 2002:a25:ac63:: with SMTP id r35mr3889574ybd.298.1598897889382;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:70d:: with SMTP id k13ls3429289ybt.9.gmail; Mon, 31
 Aug 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:a25:6a41:: with SMTP id f62mr4173493ybc.498.1598897889083;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=yBAY8SbDf3MLtCK+3hwB7FCWPYPT4e4DJppkQK4G0Q3Ij5qtuUwMjCe1Wpdi+4INQq
         tfJEDuDb60neHHK9NQaT7dq/m10lcSeXznHvLVAeu/PVQ7t7KmldYyt4kYTplnf4VJu1
         K7tpDUCRkFcdyVdklcBmR5hoMvf6eLG96+q0ZimRe8w+gZFFmQKB5M/HUmt0BXs5whVs
         XeQcSCSmrT5CPhlXK01IekJOFE/W8z45mtiNYiquTm09gnUmz/OfF03huMFGKh2ndM89
         M627i2wfLGbgn85jpcQU4rC6PWizU/+FJ1zx+GMOMy3ZqY7EQnf3R3YGsmp/pqwl9IW0
         +X2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=wJAU0Sy6pChknxcteA9DbtWDWGHpCHjXBMJmxh1RsWY=;
        b=urW7DOD7JE/GCg1UO6Lx4jJ3bfaH4y2eDQ4PjhisxMX8u63bUM6y3+jsoflkeMKnZE
         pL6/qbmGTEGiyGbdrhHNuIeBSeUGWwCOc+CKhILC26v1kLFcryLQ4B+vhmdvh4Eis0nK
         fhyO8kzFK7p0JTXwDqpLY6TdXwiDLh2JGpY0zTBQnyJdkEVKjfUOcZSwRmKH8om2vYQt
         yAIky5psutDO3SzcPWwnWv5z65VfplagQRYWD83YrKaFj7pAqP9LCRYm17fWMJzJrr7u
         unbdeWCin2J+fKFDSGj33j/oUyg8O20xKNL7QBOYGs/Mnd8uwtrwXK/WLXCW5z1pB4dx
         zlUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iJyQwhZJ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y18si460535ybk.3.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4A73A20EDD;
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
Subject: [PATCH kcsan 13/19] kcsan: Simplify constant string handling
Date: Mon, 31 Aug 2020 11:17:59 -0700
Message-Id: <20200831181805.1833-13-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=iJyQwhZJ;       spf=pass
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

Simplify checking prefixes and length calculation of constant strings.
For the former, the kernel provides str_has_prefix(), and the latter we
should just use strlen("..") because GCC and Clang have optimizations
that optimize these into constants.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c | 8 ++++----
 kernel/kcsan/report.c  | 4 ++--
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 3a9566a..116bdd8 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -300,16 +300,16 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		WRITE_ONCE(kcsan_enabled, true);
 	} else if (!strcmp(arg, "off")) {
 		WRITE_ONCE(kcsan_enabled, false);
-	} else if (!strncmp(arg, "microbench=", sizeof("microbench=") - 1)) {
+	} else if (str_has_prefix(arg, "microbench=")) {
 		unsigned long iters;
 
-		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
+		if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
-	} else if (!strncmp(arg, "test=", sizeof("test=") - 1)) {
+	} else if (str_has_prefix(arg, "test=")) {
 		unsigned long iters;
 
-		if (kstrtoul(&arg[sizeof("test=") - 1], 0, &iters))
+		if (kstrtoul(&arg[strlen("test=")], 0, &iters))
 			return -EINVAL;
 		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 3e83a69..bf1d594 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -279,8 +279,8 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 		cur = strnstr(buf, "kcsan_", len);
 		if (cur) {
-			cur += sizeof("kcsan_") - 1;
-			if (strncmp(cur, "test", sizeof("test") - 1))
+			cur += strlen("kcsan_");
+			if (!str_has_prefix(cur, "test"))
 				continue; /* KCSAN runtime function. */
 			/* KCSAN related test. */
 		}
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-13-paulmck%40kernel.org.
