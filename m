Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ5HR74QKGQEWUNGEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D98D2340F9
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:44 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id u26sf5312733lfk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183463; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYhUEhWAa94EUop2kDbhjvEkyQATSphik7K3BP3m5XLsnMNzePeBtDxGiEy00AxazR
         wnbavuIq4Q1zcgNeIhm1zamVVNqllTwYdnW0lA+4te/H8j4gUYX7Alp+0rafrb2tUdrK
         ZI3TWlLBnGftMtD0HapggY2WBZ+0riEnN4/T+3AICvvR7aYfMXsX5xkShHN9YCQy/XOh
         UcRyGaixOmsLUVyn9KVW+pCadIvyhgBTAIDthpMYrJuctGkvOE/XNRVp1ADiGrNOMsZH
         bjL5plh0xFoKe4qUs7QAL2gabV7H+o2TqDLaZ4Xxj+fGgQ+oQ5Uev9upjXWqBfK2c5zE
         Qu9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Qb7p/sxajLulqYGc9rbQ56EUjL9J6qHpTVzAEt9YqoI=;
        b=boh8AcmSiqTzLuMeyMz3I0lDYODePF/qJDrEo9kwTWuq1n2pEi5xgpdt0TA4e5iU0g
         Llb1Apk6ePVrdJuQHQLvWxMM5Ini3pTkExsiDYNHTtg7mhfjEsvUHZWQk7K+4h6HOe2y
         8MrUOd6ZF5V47yTfhfIgb+/VMYJ5C5KjtYU6+XlWOs2Zd6XGW0LfRY5Nt6xfDaIBMB9F
         P9KuLblPnbEcv4jqvsOsX3dOtc5ldVJtnhYjEycaQAEhe9CgFvyOl1Euf81HWCJY8KNX
         baM6D1ZPdR8KI3k2yL+q8pEZI7Um5BifKs6ppUr5jDrRVw3CVckJ0nGULqZqc4rAVXnq
         E9tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KBNkJXi1;
       spf=pass (google.com: domain of 3ptmjxwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ptMjXwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qb7p/sxajLulqYGc9rbQ56EUjL9J6qHpTVzAEt9YqoI=;
        b=LHedRzVroEZv/yy8VtOLSZZgPj6vJP92sutK/8//Aetl2Fkbo2inlnIlirjtnJuMbX
         201pKD/Tq4dPqQjhse+JBIt4J4E/9tSFSmMQ2rXi371mOKGzVL8j8miB1F8do/KQOFog
         pUtjr0uFaCLfnVsqHj4FsFs97OiNMXz4erDHkv9lpwPwf4A9nAQYNXsiZTW7EsjX1HEO
         iPCuAfYNk6Y4vNQBo+LfiLfOT9et+j33MQLyd+sVDolnUve6S2zysDUEZrJrCDtHNy4m
         ihnVctKGSEfcl4Wx5o2mgViqmeQvt4KD6HSFypE5BJzZmSqJRtCV1zX+yQjK3O0+e0k1
         8Ntg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qb7p/sxajLulqYGc9rbQ56EUjL9J6qHpTVzAEt9YqoI=;
        b=SekmJCvd2BA+UXLVry8dYgoSnuWJUlOzsFJH9TSd5I1Efw4X49lpvAtSZHYX0fS0jP
         faCBhuGXx1mYgDNcKFZUi+nc1H/dCdES8392onHoWbFOBWCNqOBgww+eh/7N/3V6fGty
         gZr4K/q3b+x3VyWSL1oJHzgVVkdFGnOG7gRzpKm5nqiTa8jwI3pASUI1wuPIH9EMCStK
         zJ/aZwPnjucIO5Rws8JyHwNCfmImP831WeKUX5o8e5wA1yWRuA3MSctowtZfOWFfhubJ
         3ZMWsuDCKORvsKP+2SQDSELo8wJtwYAsb9BWVZ74RCPz9oTgn1jmi4frjL/mWddiRbhy
         UNdw==
X-Gm-Message-State: AOAM530s6fA//k6HYcxL8/cMR1NnWGmur2l4xhIf98C0AwTy42XNeWjj
	JKVMTgGsMfdutJLRb+pgG34=
X-Google-Smtp-Source: ABdhPJzU2hX/Q/KsOETHZhyVzQUwOGLx9HIP2RiVhra7JrEoqE/WXVtgYl5B1Itii70qcItpK4hGaw==
X-Received: by 2002:a05:651c:91:: with SMTP id 17mr1389127ljq.173.1596183463758;
        Fri, 31 Jul 2020 01:17:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:60e:: with SMTP id 14ls2645044lfg.0.gmail; Fri, 31 Jul
 2020 01:17:43 -0700 (PDT)
X-Received: by 2002:ac2:5468:: with SMTP id e8mr1390227lfn.83.1596183462946;
        Fri, 31 Jul 2020 01:17:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183462; cv=none;
        d=google.com; s=arc-20160816;
        b=KQllIJ2VctjnBSRZAq4flk+aAddf5kteWwnEtivXw8IySib+Z/tpSLOWIY+CIC858z
         43bt0REqdxuiS9vh9xNGOqAletYfp0F8qwUlGbZMLiB//l38XcvTwrSr+IpUMjhKNnVG
         uHSsDboWrkcDQLx2aiPtDcAQDXQIw5zuac4qRdh278dtR5+5EYeAsof+t2hGeeV28DXX
         eHoeCg6w2njYmtS6luIojXlP6kT7gMQHYs2MvxSOBAzuSvmYaS5yplUjsgcBG3taQMNt
         xb7e8zxSQtbh4WYDtUl4z02xnIwvkB+v0p6sqn1lz5aLPMwc7WuuTMvu/KxACaOQX9w/
         yfAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Q7wuseCeY0GhAAgPgxPYT/xWCEF/meAm12cc8azYGg8=;
        b=bVjbjpCJ40h9ch9/bCpJAK1Uhnhb4m49wop3R4YSa1fUNL0mFzw5XRX9BhuMi87Jld
         eOjqCXZjh7UJ3hn6W7+XkZArTJhsliYMMCsyMXUmNvbLAioZQ2zoEiUpvi35+IAbXKov
         fRCbFdDgt6djSl5TRr65hi6l4kgjdpxCIkFwKuqMObRJ/kJnmC47nJEJAmIAxCr8QM1k
         5Dw9VbBtpdaQqlhzsM/iRvNbO4FFFFVy0fa2tZ4BE++OHd48pBKcLvykIb+WYCKuW/bX
         aki6bbb324Re5g/zPeh+mFJ3zdzs80NzhkedQuknRmxYk7g8nt8crIhC+5dM45Z4Uw3A
         LVCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KBNkJXi1;
       spf=pass (google.com: domain of 3ptmjxwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ptMjXwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 141si287079lfh.4.2020.07.31.01.17.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ptmjxwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id t30so8043297edi.12
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:42 -0700 (PDT)
X-Received: by 2002:a17:906:38d8:: with SMTP id r24mr2769495ejd.341.1596183462236;
 Fri, 31 Jul 2020 01:17:42 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:21 +0200
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
Message-Id: <20200731081723.2181297-4-elver@google.com>
Mime-Version: 1.0
References: <20200731081723.2181297-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 3/5] kcsan: Remove debugfs test command
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KBNkJXi1;       spf=pass
 (google.com: domain of 3ptmjxwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ptMjXwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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

Remove the debugfs test command, as it is no longer needed now that we
have the KUnit+Torture based kcsan-test module. This is to avoid
confusion around how KCSAN should be tested, as only the kcsan-test
module is maintained.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 66 ------------------------------------------
 1 file changed, 66 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 116bdd8f050c..de1da1b01aa4 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -98,66 +98,6 @@ static noinline void microbenchmark(unsigned long iters)
 	current->kcsan_ctx = ctx_save;
 }
 
-/*
- * Simple test to create conflicting accesses. Write 'test=<iters>' to KCSAN's
- * debugfs file from multiple tasks to generate real conflicts and show reports.
- */
-static long test_dummy;
-static long test_flags;
-static long test_scoped;
-static noinline void test_thread(unsigned long iters)
-{
-	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
-	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
-	cycles_t cycles;
-
-	/* We may have been called from an atomic region; reset context. */
-	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
-
-	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
-	pr_info("test_dummy@%px, test_flags@%px, test_scoped@%px,\n",
-		&test_dummy, &test_flags, &test_scoped);
-
-	cycles = get_cycles();
-	while (iters--) {
-		/* These all should generate reports. */
-		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
-		ASSERT_EXCLUSIVE_WRITER(test_dummy);
-		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
-
-		ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
-		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
-
-		ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
-		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
-
-		/* not actually instrumented */
-		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
-		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
-
-		test_flags ^= CHANGE_BITS; /* generate value-change */
-		__kcsan_check_write(&test_flags, sizeof(test_flags));
-
-		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
-		{
-			/* Should generate reports anywhere in this block. */
-			ASSERT_EXCLUSIVE_WRITER_SCOPED(test_scoped);
-			ASSERT_EXCLUSIVE_ACCESS_SCOPED(test_scoped);
-			BUG_ON(!current->kcsan_ctx.scoped_accesses.prev);
-			/* Unrelated accesses. */
-			__kcsan_check_access(&cycles, sizeof(cycles), 0);
-			__kcsan_check_access(&cycles, sizeof(cycles), KCSAN_ACCESS_ATOMIC);
-		}
-		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
-	}
-	cycles = get_cycles() - cycles;
-
-	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
-
-	/* restore context */
-	current->kcsan_ctx = ctx_save;
-}
-
 static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
 {
 	const unsigned long a = *(const unsigned long *)rhs;
@@ -306,12 +246,6 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
-	} else if (str_has_prefix(arg, "test=")) {
-		unsigned long iters;
-
-		if (kstrtoul(&arg[strlen("test=")], 0, &iters))
-			return -EINVAL;
-		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
 		set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-4-elver%40google.com.
