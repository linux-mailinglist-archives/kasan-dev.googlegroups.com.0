Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVXZSO6QMGQEHEJAHUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 23B34A2B04E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:01 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43626224274sf7381445e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865880; cv=pass;
        d=google.com; s=arc-20240605;
        b=IKXctjhYxs7+6lqtzxhLPxLNqDvC17a4HW9EXRXQvZ0zxy7GNXM/FUoSEBrg0BVxVq
         ZP9dH3z6eO2HL8VyKK9eRoQIPAO64pShHELA6Yur/hZ3FUA6v/m3n6Z3Sn3LkSJzd2MA
         3NHPgzGdkGGmZWteyVVCx6vNF+BHxr1EvB+XWBRVKwV7a/zfv/msF0BZwyf06apGP6G2
         BQROL4BZfULXP0Z+7Jrqor/joShjkuAC5+EGFKDz1+DmLYVmN/EE+Tb+I2BT5NF6LyWl
         NFF4TZ7zv98WgJDRZ3ZxCDVC3ZEU/r5uZs9VZ5qQDGqmPooDnMW23lw04/X8f2/rPPdo
         cmTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6GaCiB75NHdlnjHJ9HK63GTOncyPVn5XnCtMRJEjmbc=;
        fh=d77Hzo8+7yxl5mOvLOZePDsLCX1QdtdFy7CdNOz0TuU=;
        b=NPqITlGVx/G1y7rVUow7Pylgvq/vraG4eY/hER7S0N/d50UfOBTb10dwFMfV38bOXp
         R+6oQcX2UUhfrubxjPJK3Xf9NbrMuYxPnIml1DtTf6JoAlWTd2oPGcNNGfyUhucL4mUY
         7YzP+e9M0NQG4VeOvQ/ha3TUHmAG1BpeIL0jFBkOc4eg8dtIsJmZVhOo/+/M6PlJXKUL
         aDI9pHa0Vhc81GxOoSLLkuoH8+zYv1N2wzJyF0ByOD8x0v1iPtVUa60c1liPy3FdVqE7
         bMR9TQ6JhRlBaiSKrdZ2AmdE2aqpcabWZu9awGGiV7RGMvPuOBaZQpaLN3tZEaVPNVRP
         oz8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pMjYaUL4;
       spf=pass (google.com: domain of 30_ykzwukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30_ykZwUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865880; x=1739470680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6GaCiB75NHdlnjHJ9HK63GTOncyPVn5XnCtMRJEjmbc=;
        b=uwm4cKnmuYmmgcyQSxRyBfxhvLJW1doyvYzEIf7bgjDOMqvFMlhan4rzZ8l2uRozZd
         jgg1SLf1d62iLMZJ8yqRZ70DPKu6tLa7Tb+r/00dr5nF0MP9cMTjOt6zcThJUXJ7wJDi
         eBrwMP3LzoqfUqj30fQVlbxXYDlyZyuZFqh0LPjlk1uCZvGJQxLI5dD3UKd92eLOYzUO
         PFayKsHy+JP5tmXa/X2OSNe8nexBv3PC7x8e9w/7Z90Q8A9zOpOUojwWtM2wg3pF54z6
         56uo/vawF0TEdFumbiWYnt8ca1O3HLaJ7mER9EFqo8PdAali0xO9I1A8xBBV6RTFA2mG
         NQIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865880; x=1739470680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6GaCiB75NHdlnjHJ9HK63GTOncyPVn5XnCtMRJEjmbc=;
        b=PrzasHFoi54rol2n3TiTzkyZ6tQy7C3xPy+btxREo4XCWIchPrwYear9+wPHuOzAma
         pKc7U4zamVlP0JqlKUPflwsN5u/0fN4lNwEVE6TQzoPJGtu7kj6cl+doMxtEnIirjKC9
         pdEmCqERSYT4Fu0ySiUBPrbcxgif0ruaEDcjF3ZRKS3gdPyseAKj2smeXwfVD2E7Yx6u
         NRnZMXxauvvOQseqdHUB92ZMeNc6f8PgzgdgMoLM7eLfTWV39sZtvh8L3eQko23VmEc0
         Hopr8V9oE3pl8riF91tuuOOA7w3GNp4w+qGxSwp69TDBzZtLUrBhCtHCjeAKzKZ5Eg6X
         lIPA==
X-Forwarded-Encrypted: i=2; AJvYcCUBHT8iHA+v7gUgUp4M2uxqs4Cg75ntqXO3EktGar1A7pnNg2YzN/GnO1I+ZzRngAvVvBnqeQ==@lfdr.de
X-Gm-Message-State: AOJu0YyXAC8PRdAmgak0hLrr0c+UJqy3jkLIVj+qUHFFUyNdR9r05A9C
	vNne31KbFg6oi0AfjwtKEvEeG7WTmPdxO1lJd8j8rg5sG0P51hpL
X-Google-Smtp-Source: AGHT+IGJhLOdQBtCF+1kyUMUcRLfKUKitk47WzJCQjSurG7vhB2zMG+DraB7UfNcS0aKtjOU9pnqtQ==
X-Received: by 2002:a05:600c:4586:b0:436:840b:261c with SMTP id 5b1f17b1804b1-439249abc22mr3442595e9.19.1738865879157;
        Thu, 06 Feb 2025 10:17:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c406:0:b0:436:1e38:a5dd with SMTP id 5b1f17b1804b1-43924cd99b8ls238255e9.1.-pod-prod-04-eu;
 Thu, 06 Feb 2025 10:17:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW2uiKCE1SP7Zxj4zKvbO/LsUOTSdcw3O0e6Lgot0nReiiW6mUNimFlHbCvwU/ih6acYzljzsEBNXI=@googlegroups.com
X-Received: by 2002:a05:600c:354a:b0:434:f82b:c5e6 with SMTP id 5b1f17b1804b1-4392497e9ddmr3252325e9.1.1738865876324;
        Thu, 06 Feb 2025 10:17:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865876; cv=none;
        d=google.com; s=arc-20240605;
        b=QN9QdLJJizdoKBg911gGflDu9Yk9sMj4YRLOU5Q/AyZkpy1hZL2kgGntIN9p4NbRbu
         WtyqIwopVCbl7SbmIjnHRxOt8V6dHlmYZ4sPYBb9qry/uuTGWE2lUwuAX1RV9oAsz3aD
         PURTWtuIlPfdd6cXRxuu7VI2etibUf8sH8dp7FJnPYThgYWsV5L5EKaSWgDs31YjQ96O
         bavTKCsnzIyhGTQR17n5mAhDriys7VA44uPt9N8scQOJZcpDTtogNyOHNjhLBo2JFVre
         oJRKaR9GmKKYzEmwCQ+MER4NO/ItexbDrr+N7gAZlF43asHJWgf/Xv1m3lX9qvkKt5Se
         QyGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NkeMRttk3RYqT58NIYnzD7f2BrALmFrVkg1AkAEzinM=;
        fh=s5UDaYhiCB5I+tnhTkYeJWXERWbVEFuFnOfhHvAOXCg=;
        b=Cyzt2vzcUgczUm8HWNLXr/3fO9iqBEo8soexcS0Emtur1BlXGekpjnv5Zue9yY3oFb
         n1o7ngxl1jNrQ8QJZA4XGBBezV4Lz1uDUSbZ2sInKICpJ3ipC+Y4TfThkHieXmsZ2W1s
         FazspbEnzMzdPfTMKAe9dzBl7n/8jr7CzKPC+xD5D4WQmBEnmqTuH5bK54ouUr5932tU
         eJ2EO0mmx+U8y1VPRK9MX3EASotEbma7IuEt0/cK3aeuW7FtfLJHcfHCHnX9nXLyp2re
         Ijm+dJx5soxSZQ+XA47Xqb73TQtkSwqqJ8eLjx4WyE8QQPiKLF5D6b6ykICvYxdiuqIY
         G/oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pMjYaUL4;
       spf=pass (google.com: domain of 30_ykzwukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30_ykZwUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde1c789si50965f8f.5.2025.02.06.10.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 30_ykzwukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5dcef33edc8so1097600a12.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/A8B2cODa4tgq0StT1iVZfdN5tnjKdYzRuB1qqamdcDjjbXKOZ/6FLmYYuy4efkhoQBrBO3LmdL0=@googlegroups.com
X-Received: from edat29.prod.google.com ([2002:a05:6402:241d:b0:5dc:764b:8e16])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:2801:b0:5dc:d31a:398d
 with SMTP id 4fb4d7f45d1cf-5de450059cbmr548326a12.10.1738865875912; Thu, 06
 Feb 2025 10:17:55 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:58 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-5-elver@google.com>
Subject: [PATCH RFC 04/24] compiler-capability-analysis: Add test stub
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pMjYaUL4;       spf=pass
 (google.com: domain of 30_ykzwukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30_ykZwUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add a simple test stub where we will add common supported patterns that
should not generate false positive of each new supported capability.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.debug              | 14 ++++++++++++++
 lib/Makefile                   |  3 +++
 lib/test_capability-analysis.c | 18 ++++++++++++++++++
 3 files changed, 35 insertions(+)
 create mode 100644 lib/test_capability-analysis.c

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 801ad28fe6d7..b76fa3dc59ec 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2764,6 +2764,20 @@ config LINEAR_RANGES_TEST
 
 	  If unsure, say N.
 
+config CAPABILITY_ANALYSIS_TEST
+	bool "Compiler capability-analysis warnings test"
+	depends on EXPERT
+	help
+	  This builds the test for compiler-based capability analysis. The test
+	  does not add executable code to the kernel, but is meant to test that
+	  common patterns supported by the analysis do not result in false
+	  positive warnings.
+
+	  When adding support for new capabilities, it is strongly recommended
+	  to add supported patterns to this test.
+
+	  If unsure, say N.
+
 config CMDLINE_KUNIT_TEST
 	tristate "KUnit test for cmdline API" if !KUNIT_ALL_TESTS
 	depends on KUNIT
diff --git a/lib/Makefile b/lib/Makefile
index d5cfc7afbbb8..1dbb59175eb0 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -394,6 +394,9 @@ obj-$(CONFIG_CRC_KUNIT_TEST) += crc_kunit.o
 obj-$(CONFIG_SIPHASH_KUNIT_TEST) += siphash_kunit.o
 obj-$(CONFIG_USERCOPY_KUNIT_TEST) += usercopy_kunit.o
 
+CAPABILITY_ANALYSIS_test_capability-analysis.o := y
+obj-$(CONFIG_CAPABILITY_ANALYSIS_TEST) += test_capability-analysis.o
+
 obj-$(CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED) += devmem_is_allowed.o
 
 obj-$(CONFIG_FIRMWARE_TABLE) += fw_table.o
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
new file mode 100644
index 000000000000..a0adacce30ff
--- /dev/null
+++ b/lib/test_capability-analysis.c
@@ -0,0 +1,18 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * Compile-only tests for common patterns that should not generate false
+ * positive errors when compiled with Clang's capability analysis.
+ */
+
+#include <linux/build_bug.h>
+
+/*
+ * Test that helper macros work as expected.
+ */
+static void __used test_common_helpers(void)
+{
+	BUILD_BUG_ON(capability_unsafe(3) != 3); /* plain expression */
+	BUILD_BUG_ON(capability_unsafe((void)2; 3;) != 3); /* does not swallow semi-colon */
+	BUILD_BUG_ON(capability_unsafe((void)2, 3) != 3); /* does not swallow commas */
+	capability_unsafe(do { } while (0)); /* works with void statements */
+}
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-5-elver%40google.com.
