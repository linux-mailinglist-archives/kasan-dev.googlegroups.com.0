Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2ET53ZQKGQESN2OTZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D72192E73
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 17:42:18 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id cg7sf2231881qvb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 09:42:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585154537; cv=pass;
        d=google.com; s=arc-20160816;
        b=TF5BnoGZwX5iIOJ0LC8Vmq9iKXjHcufWnNsf8f6PGqnjSvkor7Wr9/DUCkHpxOkcGY
         1sSWzPPcF5xyAsHAAC4t53pIFIixGBJlQyfjMYlEdhanekKlkg93QNZrQDSMZoVvoVfu
         dxVcQogt72IEYtYzCkHuvh9TjcELXqwbTYbKOocukgnQ7IlMl479oFpHgyC+QnHziBBI
         AGB6F5VXvoICvsFcKFUkwchJnuZBeUw7HvzewPmw0U7tlSBrXjRfmuYtX/5UjzHBHhvA
         19Lx/qFbOfVn5lJ+/J25B7ESFI/9SMC2SA9uGlQ4k9FMel65nORlEnAMJHDerTah8uES
         wAFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qubkJnNUlCBshFbnXFUsD8mB36cC68CWFLaNfaA3Twg=;
        b=Bhe+loQFyXerrf6nbj+sDCQ0O+9i7tqoBMwCYxzEIPQC0UOPgOCL77+T/snjcp5orA
         nR0KbfujA2Lk1cZ3IvHniGEGdETRQH0jYumSXVtJhszKtHw7krq2c/Y20l2iUQpqd9ji
         2ftLo/TaYxzih4prw+tIQXLsEnpwfxdgjrKAX4l630x2vvoFShyDoZH8STACXpaeBBGi
         Ky+/1yUleVxLxSKUKtUlLScIdthQrDoMbpKLQ/suxFJfLibcdzkZmywlRLBKd9PNAHAG
         SijAM4OMds22AI5gCQxER0rXbtOivLj1uAVPFbDY4NAArkW29trtWbkfcu13cNF0dSLh
         z4yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IyrqcL2W;
       spf=pass (google.com: domain of 354l7xgukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=354l7XgUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qubkJnNUlCBshFbnXFUsD8mB36cC68CWFLaNfaA3Twg=;
        b=hHrN9RmvIiv/RTUrK/XeEzRbFdeFqSTAbhq2OD6oP5RbkMsNchr6OgbZowYLbgRd0K
         T8H9L44VLlPIFe9IzDyvClr+vTu6TfFFZkZ8j2CZeNF6XxHMIVgvz3SOUvElkp3Dxn71
         ClzSDYihjYQCrf1WF/IaQa2axii5N8GYs8VLJrhwdoENRaNFdKumhp3JxW0ztWFNh9aA
         KgxkJ6KgEJPiggEC6iMgFG8ArHmtnsKSmUBLKWt+x3TPwzOd2KeaixsnGC4VOfk1JLPP
         4gPc5IizHIHfXQMvPcf61VfUFTkJC9WoWhRxRzUYfsti30RyHILKRhhkUAEvWRCLiy/Z
         cu7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qubkJnNUlCBshFbnXFUsD8mB36cC68CWFLaNfaA3Twg=;
        b=MHq/SCEvzBTLPL4X/Ng27odbxi9EhsrRH9JhLFlH0/wGj5QRVgjMT23piAhOCJe59C
         YOaDwm7FwyG+rJ3gPC6Pg+j32FGL6ofxODzo/aTpgYn40rmSNtO86cMMrCoEOAT8zFRU
         FuqFQXcMI+JcbbSEZbV9eTLM67PhrBR7n3CXbSTFg0f2oZwiZFRUD/XhnoGO9fY3JjMw
         xAElUiavH076QMWaUFSEeromDU5zKdH+0ROOVfyQ91r/HAFoJTBIPm4tjH3jlUyKuosV
         HpG7pzZK+Q8oaFS1OVFhZi6QQA/GR4t2TL1SyaiPJNsEcTf69EbRW+V7CxP9ipzAcz7i
         ZTdg==
X-Gm-Message-State: ANhLgQ0kR0hQIs7VUjNMXFKKveykip3mrlj2rCXF8do8v7RB+TdPRo2S
	iHbsZp8NIO4T64no9rgpe6M=
X-Google-Smtp-Source: ADFU+vtGaW7jpEfUKAkjoKp7AXt4ROvq0tF385Nqe1xfdkkX9y28cyrfnN9ZVqHO5KPxpDzqXZrLJg==
X-Received: by 2002:a05:6214:1449:: with SMTP id b9mr4050400qvy.217.1585154537061;
        Wed, 25 Mar 2020 09:42:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6542:: with SMTP id z63ls1151439qkb.3.gmail; Wed, 25 Mar
 2020 09:42:16 -0700 (PDT)
X-Received: by 2002:a37:bec5:: with SMTP id o188mr3790837qkf.165.1585154536335;
        Wed, 25 Mar 2020 09:42:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585154536; cv=none;
        d=google.com; s=arc-20160816;
        b=xBpjUS8lb8WRKDBxXAtIMI+TEClgBraVufEY3/RRhcGIWwstFpqNwqAvYMCMH07v/J
         IYB7DLKKpA5OcxCk3IMAEZJ+CJGsiUTbTjpPI7l3WkMbJT7dNHaXIeIFZWINpIg/ZwJM
         WkuARrJ/mhlVfsS3RKpJHXFqVVmj1OmZe2j9WntjfNq+SkYrRPAlg15va5q01cnMg9Sp
         2bx4o6hZ949kPwSsVFVIvrLVMIMzFD9AKwOeGL6seEBPcLNd1pEr7NDUbjpXNAlMS3h+
         U11LW74XUoqpmhz3VzsRaOp2sZF5Z9YSR7VGfg4oIzT2IcNquVnM3HZ9c3YEi6zuIkI7
         0e8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=m4FmRkj8j7tARDEb0nuSvSohZqoEFWL11PIMBnp/yZI=;
        b=a2weHvrlroS01cRBDtleh34h4IIfyEGMN66JVdbS2LdWka989AVQEoh+C2RIv0Uz6+
         mGzUwSZejnQqGuAKsotXKHYeXlBNNM7Wx3gHtKLhQbJAH0WLXG50hj9MjRWb0eO+lkhe
         IHP4/g3i8J7xVd/8fMB7h0aNdortQtPEz42s05kLhnDoeTiOMDH5Q+4ZJqxnwFiWeDwg
         OqV0zXRWb/xdMYhZUIPZxvn2fc0I5LBYzHDvlaA4S4VAmaP7jxwW1eIJTKk3g3ODyYbB
         /EaZDwvr5JDzQ65NVYAJV+JL0NIBNK0CMFEue3Ap2CEzWJXWo6TULSHxLSRVWOnq3unM
         be/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IyrqcL2W;
       spf=pass (google.com: domain of 354l7xgukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=354l7XgUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id z126si1350280qkd.2.2020.03.25.09.42.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Mar 2020 09:42:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 354l7xgukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id l29so2418726qtu.11
        for <kasan-dev@googlegroups.com>; Wed, 25 Mar 2020 09:42:16 -0700 (PDT)
X-Received: by 2002:a37:d0e:: with SMTP id 14mr3902756qkn.310.1585154535926;
 Wed, 25 Mar 2020 09:42:15 -0700 (PDT)
Date: Wed, 25 Mar 2020 17:41:58 +0100
In-Reply-To: <20200325164158.195303-1-elver@google.com>
Message-Id: <20200325164158.195303-3-elver@google.com>
Mime-Version: 1.0
References: <20200325164158.195303-1-elver@google.com>
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [PATCH 3/3] kcsan: Introduce scoped ASSERT_EXCLUSIVE macros
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IyrqcL2W;       spf=pass
 (google.com: domain of 354l7xgukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=354l7XgUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

Introduces ASSERT_EXCLUSIVE_*_SCOPED() which provide an intuitive
interface to use the scoped-access feature, without having to explicitly
mark the start and end of the desired scope. Basing duration of the
checks on scope avoids accidental misuse and resulting false positives,
which may be hard to debug. See added comments for usage.

The macros are implemented using __attribute__((__cleanup__(func))),
which is supported by all compilers that currently support KCSAN.

Suggested-by: Boqun Feng <boqun.feng@gmail.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst |  3 +-
 include/linux/kcsan-checks.h      | 73 ++++++++++++++++++++++++++++++-
 kernel/kcsan/debugfs.c            | 16 ++++++-
 3 files changed, 89 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 52a5d6fb9701..f4b5766f12cc 100644
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
index b24253d3a442..101df7f46d89 100644
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
@@ -266,10 +321,26 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
 
+/**
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
 /**
  * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
  *
- * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var).
+ * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER().
  *
  * Assert that there are no concurrent writes to a subset of bits in @var;
  * concurrent readers are permitted. This assertion captures more detailed
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 72ee188ebc54..1a08664a7fab 100644
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
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200325164158.195303-3-elver%40google.com.
