Return-Path: <kasan-dev+bncBAABBKFH3X2AKGQEJ5EESCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 16A4F1AB0CC
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:18 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id q4sf691191otn.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975657; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0ihCxxqZp2PvzAXJyWLI3DTzgHmq9vlrvzc2Ov1oc4jiXRujRCzC/7hcTpH32ZVLm
         2ocaa6MfKN4OZJLBkzBaRMhfkoOWeY1tk76nZWLpX9l3x3wY925b/VIqKXNC8YIJg/5M
         +cdqGDElsfVm44g2YqHr71Juet46rna9s6UHiaEVatYZpPxK/Q4x6Zk4PuQxOzvtJOJE
         cEvWriyW6qP84SDJ4SMmrooIaZukMrMmCcZTLgCsfi6iFHDXy+SPfeIuwwr4PnoZQ/w/
         9MtKXKwFcHnb811tqyQVtTPmAntuudvsKRx8ufeK5fk9dQCYVmKrMoxUViHUsAC2evJF
         7wiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=wO3jWRRkNO0ZungTEOeTk0q6ogRqYt0MOXtb1+4zW6Q=;
        b=B6vBK3ixraVgJmOIZe8PS9rz539Gx2RdRZ18r7szE/xJSaPkekPFcr1it8CbTeNiy/
         /qoD7dpQj+IWAiX+7NJUk3fnvfEOg7a43r6764EHwYJG4Asz4FOhUedUUSw+H4Wo4r11
         6P3hp5Yq1vAF4al2xKBQE4p6c91V+yeV5XPbXue4Oy8BPqFFAbto8mpzqsmnymFwVQ+L
         DWbiIN6YfPA5gux39Av7JF24AHZPeKyRA3mf/Nb5lDmjLOpPlTYZlNj6AgBhZWgifNL0
         6VWQ8RLF2X5kAWHDmZ2FKRkA1vMQq4whJyruG4l8xYgDveV6YTREdMI+UmD10Ao/3z3j
         jtGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=C7Tzypjb;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wO3jWRRkNO0ZungTEOeTk0q6ogRqYt0MOXtb1+4zW6Q=;
        b=WvuzoBgmCUSiQPAPtHfPYz2yfIjiDm5EIdztdQyJgtd4AEnI5rfBnvYox2b4Ij+vr1
         utWaj124FBQTD7mn9HTtb/H6gzIdmoNYCPilWJaBAo4OeaGLauXMIksKED1FPdXv5rqX
         Bd2JnNoFaYF56Fu176LMepQBI63NrAp7CbNTJyNSSu+NWqxDi/V8tkDBsZ6rijYPmkOp
         1XfK11Wcex+NDFVapfZUT2n6lNkLLVKXnGVfZdV9SbQcnI8Bc19snh6CiwDdi0j0WKLk
         JJv3ruTM18W4uJLdHFuXnNuPoQfF/aP2KU0ohAK0egkaGu7/XsqaanQ3TIGvmtLExwKX
         AZFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wO3jWRRkNO0ZungTEOeTk0q6ogRqYt0MOXtb1+4zW6Q=;
        b=KSKJ7Fl5yY6uOdjcUi+Byb50vJh52rcZxSVqpFIk5ss9ACVIWGRYzWJu1fetz1Gfpj
         eWaCkFSp1zxE7+KK/mRTTjzW0aMNkfLPCPFCTpMbUja1Ci3xPCtQJ77pkXofASCohxon
         gx/fFvJ8C2qKjHcbIfr8bSbR4eRaUAHHFQIrbQzMBWiYYkcl6zJ5ulRVnkscD+cdXwo3
         BxCBIG77p/jVRtOz4XI+5uD6Vp68SbLqdtfPGf9eGfIm1eS29H6tOOrW3HH9lO2JyN4U
         b285S++1++3hryP/E32fOSgR+tHe2Wh9vVf3abJ3Nh1AQbWkLWmmdqJmhIu6i46CvZ0B
         ECUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub2vPQwqky5uc/8z4lSAQwW1D8oL4abfup6dwk0QnAWLAqvEJFy
	9SIugSsv87RUMU5tMAZ8a9g=
X-Google-Smtp-Source: APiQypLMC0gMVA1eLj+WCyjAPsIiObltkzC9VDCbTgvSe1yUVGii6HFS+t/FAWVsc3DKiFFcIoliiw==
X-Received: by 2002:a9d:544:: with SMTP id 62mr23670860otw.355.1586975656987;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6e97:: with SMTP id a23ls875368otr.2.gmail; Wed, 15 Apr
 2020 11:34:16 -0700 (PDT)
X-Received: by 2002:a9d:7d85:: with SMTP id j5mr24137965otn.143.1586975656658;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975656; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+PLusDHK0PGqHn35yl5T7RYjLPSwivyUjx4st9q7pVWinwQTyP+86euvB7N/MbdH8
         q5M5chEO8eDmQ0MZKJ40/+otdvrHP0dS8uQZyIEsbiZBvuQVmsvwmdiAsu892Qf4atxE
         1O7Bl7QRuqjO4oWj6Di3lI5YxEnQpS+jNI9seqQF8zDdIUYKTcXVpt+K+AKXbeFH1OIW
         OQcNDThlodcgQKaR+XGxJQNg58NoTiJvXSzAzj99vX8pqqV9eS8pPHKuHYmIrFpuDxJ1
         upZdM18hhxGyrhEB7ZYOusUUjrMWGuZUk43I9cfjDDM9BEon4pSEqKS0D3+6zitNJ/AR
         A6ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=h40MrQTvZ3vtTBXlYgSxbdwKwbapxnHlpCszpNlgi6Q=;
        b=xn2QJtQ1PZBQEpTvoLQx/Q8kZ9+yvsPHWYBJbcI13KB3bIJqNv263q0EON1NJAPZnP
         giiDI4HR+J4KDDjN5rS8fyXfHbFcthEpgQerpXNfSv/Ek+XYZnq7MyDhe5QL6x8RG17F
         QrvBj/EjdLsur0Sa5rsaTYiuEK8uM4AWfHESk5blip4MZzaQHQehyRfmSozvB3/zHyHk
         D+jY8xpVs52A/hRi5p6UfS47mgk8Dv2ILtVAH3lVU8zl+d6/UJ6h6aJBOmVPYndW3X15
         AqSVbfUuJ6bokDKGxHmGG44qU0HrjZ30IqZpyeUfxwp+Z1tGAEYlgMk7HNIJQ4EmK2n3
         enDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=C7Tzypjb;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w11si549068ooc.0.2020.04.15.11.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CED5321775;
	Wed, 15 Apr 2020 18:34:15 +0000 (UTC)
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
Subject: [PATCH v4 tip/core/rcu 11/15] kcsan: Introduce scoped ASSERT_EXCLUSIVE macros
Date: Wed, 15 Apr 2020 11:34:07 -0700
Message-Id: <20200415183411.12368-11-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=C7Tzypjb;       spf=pass
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

Introduce ASSERT_EXCLUSIVE_*_SCOPED(), which provide an intuitive
interface to use the scoped-access feature, without having to explicitly
mark the start and end of the desired scope. Basing duration of the
checks on scope avoids accidental misuse and resulting false positives,
which may be hard to debug. See added comments for usage.

The macros are implemented using __attribute__((__cleanup__(func))),
which is supported by all compilers that currently support KCSAN.

Suggested-by: Boqun Feng <boqun.feng@gmail.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst |  3 +-
 include/linux/kcsan-checks.h      | 73 ++++++++++++++++++++++++++++++++++++++-
 kernel/kcsan/debugfs.c            | 16 ++++++++-
 3 files changed, 89 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 52a5d6f..f4b5766 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -238,7 +238,8 @@ are defined at the C-language level. The following macros can be used to check
 properties of concurrent code where bugs would not manifest as data races.
 
 .. kernel-doc:: include/linux/kcsan-checks.h
-    :functions: ASSERT_EXCLUSIVE_WRITER ASSERT_EXCLUSIVE_ACCESS
+    :functions: ASSERT_EXCLUSIVE_WRITER ASSERT_EXCLUSIVE_WRITER_SCOPED
+                ASSERT_EXCLUSIVE_ACCESS ASSERT_EXCLUSIVE_ACCESS_SCOPED
                 ASSERT_EXCLUSIVE_BITS
 
 Implementation Details
diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index b24253d..101df7f 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -234,11 +234,63 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  *		... = READ_ONCE(shared_foo);
  *	}
  *
+ * Note: ASSERT_EXCLUSIVE_WRITER_SCOPED(), if applicable, performs more thorough
+ * checking if a clear scope where no concurrent writes are expected exists.
+ *
  * @var: variable to assert on
  */
 #define ASSERT_EXCLUSIVE_WRITER(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
 
+/*
+ * Helper macros for implementation of for ASSERT_EXCLUSIVE_*_SCOPED(). @id is
+ * expected to be unique for the scope in which instances of kcsan_scoped_access
+ * are declared.
+ */
+#define __kcsan_scoped_name(c, suffix) __kcsan_scoped_##c##suffix
+#define __ASSERT_EXCLUSIVE_SCOPED(var, type, id)                               \
+	struct kcsan_scoped_access __kcsan_scoped_name(id, _)                  \
+		__kcsan_cleanup_scoped;                                        \
+	struct kcsan_scoped_access *__kcsan_scoped_name(id, _dummy_p)          \
+		__maybe_unused = kcsan_begin_scoped_access(                    \
+			&(var), sizeof(var), KCSAN_ACCESS_SCOPED | (type),     \
+			&__kcsan_scoped_name(id, _))
+
+/**
+ * ASSERT_EXCLUSIVE_WRITER_SCOPED - assert no concurrent writes to @var in scope
+ *
+ * Scoped variant of ASSERT_EXCLUSIVE_WRITER().
+ *
+ * Assert that there are no concurrent writes to @var for the duration of the
+ * scope in which it is introduced. This provides a better way to fully cover
+ * the enclosing scope, compared to multiple ASSERT_EXCLUSIVE_WRITER(), and
+ * increases the likelihood for KCSAN to detect racing accesses.
+ *
+ * For example, it allows finding race-condition bugs that only occur due to
+ * state changes within the scope itself:
+ *
+ * .. code-block:: c
+ *
+ *	void writer(void) {
+ *		spin_lock(&update_foo_lock);
+ *		{
+ *			ASSERT_EXCLUSIVE_WRITER_SCOPED(shared_foo);
+ *			WRITE_ONCE(shared_foo, 42);
+ *			...
+ *			// shared_foo should still be 42 here!
+ *		}
+ *		spin_unlock(&update_foo_lock);
+ *	}
+ *	void buggy(void) {
+ *		if (READ_ONCE(shared_foo) == 42)
+ *			WRITE_ONCE(shared_foo, 1); // bug!
+ *	}
+ *
+ * @var: variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_WRITER_SCOPED(var)                                    \
+	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_ASSERT, __COUNTER__)
+
 /**
  * ASSERT_EXCLUSIVE_ACCESS - assert no concurrent accesses to @var
  *
@@ -258,6 +310,9 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  *		release_for_reuse(obj);
  *	}
  *
+ * Note: ASSERT_EXCLUSIVE_ACCESS_SCOPED(), if applicable, performs more thorough
+ * checking if a clear scope where no concurrent accesses are expected exists.
+ *
  * Note: For cases where the object is freed, `KASAN <kasan.html>`_ is a better
  * fit to detect use-after-free bugs.
  *
@@ -267,9 +322,25 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
 
 /**
+ * ASSERT_EXCLUSIVE_ACCESS_SCOPED - assert no concurrent accesses to @var in scope
+ *
+ * Scoped variant of ASSERT_EXCLUSIVE_ACCESS().
+ *
+ * Assert that there are no concurrent accesses to @var (no readers nor writers)
+ * for the entire duration of the scope in which it is introduced. This provides
+ * a better way to fully cover the enclosing scope, compared to multiple
+ * ASSERT_EXCLUSIVE_ACCESS(), and increases the likelihood for KCSAN to detect
+ * racing accesses.
+ *
+ * @var: variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_ACCESS_SCOPED(var)                                    \
+	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT, __COUNTER__)
+
+/**
  * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
  *
- * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var).
+ * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER().
  *
  * Assert that there are no concurrent writes to a subset of bits in @var;
  * concurrent readers are permitted. This assertion captures more detailed
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 72ee188..1a08664 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -110,6 +110,7 @@ static noinline void microbenchmark(unsigned long iters)
  */
 static long test_dummy;
 static long test_flags;
+static long test_scoped;
 static noinline void test_thread(unsigned long iters)
 {
 	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
@@ -120,7 +121,8 @@ static noinline void test_thread(unsigned long iters)
 	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
 
 	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
-	pr_info("test_dummy@%px, test_flags@%px\n", &test_dummy, &test_flags);
+	pr_info("test_dummy@%px, test_flags@%px, test_scoped@%px,\n",
+		&test_dummy, &test_flags, &test_scoped);
 
 	cycles = get_cycles();
 	while (iters--) {
@@ -141,6 +143,18 @@ static noinline void test_thread(unsigned long iters)
 
 		test_flags ^= CHANGE_BITS; /* generate value-change */
 		__kcsan_check_write(&test_flags, sizeof(test_flags));
+
+		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
+		{
+			/* Should generate reports anywhere in this block. */
+			ASSERT_EXCLUSIVE_WRITER_SCOPED(test_scoped);
+			ASSERT_EXCLUSIVE_ACCESS_SCOPED(test_scoped);
+			BUG_ON(!current->kcsan_ctx.scoped_accesses.prev);
+			/* Unrelated accesses. */
+			__kcsan_check_access(&cycles, sizeof(cycles), 0);
+			__kcsan_check_access(&cycles, sizeof(cycles), KCSAN_ACCESS_ATOMIC);
+		}
+		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
 	}
 	cycles = get_cycles() - cycles;
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-11-paulmck%40kernel.org.
