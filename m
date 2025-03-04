Return-Path: <kasan-dev+bncBC7OBJGL2MHBB74NTO7AMGQE7JYTGDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CF42A4D7F4
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:21 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5495f6428bdsf1232113e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080320; cv=pass;
        d=google.com; s=arc-20240605;
        b=BZJTkOD39qpO8L4Kq9K2JozMVG0ue/9azl6BCkF55uAeS95IwDIhKNfQhFCPN9EuEO
         QqfrewK//NbeTwWCnX1RXrs+sTLs9pcSgp5pKZn0y0ikeuObZxTqV3dbP26YujZyzypU
         WFqur+wf8t2AawG5XYT6SGOYk7tExy0kgGiAhjygH9/3CRZYLxk2hKW4+eI4Qhm1wqpJ
         zM/eWjjAB79dzlVCeA6MV0cjyMiuSmER3B3xalBLUzYmcWUF5ySmSNFP2xirlGyaMFG0
         bnq+XNv5JdkdnYVN5Qke5RHh4J9MygB3HuOQRoeiWeV5CA+k2m0wHoQghG8fWdsOjhBC
         1nLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=b/UBaaoMnhC9/avt3S+p8SupNQLmxqV2Lc+zcwXO4Bc=;
        fh=9srtEAA3i/g4twGlpi2MDFo02xxDCcsDjbH4YdGHcJo=;
        b=TFW65u6kCIDur+G/+qIu93mbI8rr/SAwr5t6iQ2SweietGxZykfiaZw1WaODTEzuep
         kplFbC5GOdqi54+BVgSEc+4lWJZdZUjymgsuRdwe67v10L92rK57t9rre4iDEaYLcVCt
         fm2SA794Dlt3Sk746Mwst0yI6tkLRoiKP3HmTHti3nP6S5s/p1Oz0AY3tua4wXvmCrFZ
         QnwhOloS2K9O0J7daeFmpS3g5ZHhEBqSowlo64ANYNjRfKOLH1yvHmSiBJuf4uk5reDs
         bOq7/0s60V2oTDvn65Z7JYuHJihMYtJc1DRQS4I70FFglgpzI2TUtL9ec/dkozdydLXb
         CfIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=114mFSvh;
       spf=pass (google.com: domain of 3_mbgzwukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_MbGZwUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080320; x=1741685120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b/UBaaoMnhC9/avt3S+p8SupNQLmxqV2Lc+zcwXO4Bc=;
        b=tZ9zkD4f3lHP8nf9EpD29xcxcUdqBd9qaFO2/hVFShnLrssR6s3lsSh9wWHjPJaT+q
         +vVQb3qLyZrDfCbZRMVOpNCYAs4RJfd+q54vpcqGj7mRAhctSjMMUqt7F9aUVlmPVndH
         vYw38DKef7lo+Nv5EGmLbEiuw27sn/1R6Yfof597bPWKiS6NX4vKoMAlh5UwOjxpCWKd
         D9MCG/Zv1JWgXFfSeriP0E7w3xLh1ZDqs069XfU8aZgBY8B1K9yB6LjAJktDLHY2NI4U
         XxzSOCWqaznK/fK8lm96KyNpgI99jo6rQlHXjgv7UNuwL4xMOLic88GesK4QuOuutrhJ
         pXfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080320; x=1741685120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b/UBaaoMnhC9/avt3S+p8SupNQLmxqV2Lc+zcwXO4Bc=;
        b=wdgmT7BaJ2SMJ/46OhCa5PBKmXsNTr0+ZKk/WQqKV9EYaImSuUjbUflCCzNh5gfJuG
         1KD9XsPeFlHi6e15jQ+OcDVyKbHsPUF11q4yW9ZoluVb6cajRC8HAN1Ixo6OSJESRTQs
         4mDf5x1lEJCiGQ2XsIkI6JnQj+e+R+rA02Pk/yt/K4azTwWuiNwOXd0QryTPWnzH21D1
         TCwHVnzBKQELBn0uj0oAqwvK19uNtXA7jyjLMgeDs0XTe4BNpf7r6JjM5u3JhtAZRNBo
         V5jhTd0qkvmRotRZCZdwmkZ+MrcbJeP6f6def1M9sJu06jE9C1hMnopu23+tgnXj+UVB
         6RFw==
X-Forwarded-Encrypted: i=2; AJvYcCVRJeFmc70tOTCPuN7H1ZhjsRzG107uutPRqQyWQY58bDyWMrov7glb/eBoJ9vaQtuYurLTWA==@lfdr.de
X-Gm-Message-State: AOJu0YwD2OquRdonFAZbkod5axw2Y5aGfxV6yTjnskNKJ0SMYhy1y1Lg
	2sxUkKJgCllpqbzK5dwznsbbm6U1rfa+Dy3OI/y8OObgXfO0rcGV
X-Google-Smtp-Source: AGHT+IH6iaFqAC2wRkvvzLRRJFTC2xM0IT40+GdSinko34sR7WvZESKjzV6iqy6FQNyarQz3SUy3jA==
X-Received: by 2002:a05:6512:3b11:b0:545:2e5d:f3f3 with SMTP id 2adb3069b0e04-5494c36eeecmr5436893e87.46.1741080320103;
        Tue, 04 Mar 2025 01:25:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHnDm0I2kfrjAMxKolDa5CfbThi84u/fDL0GKHRLEQ/lg==
Received: by 2002:a05:6512:e97:b0:549:5b63:f30e with SMTP id
 2adb3069b0e04-5495b63f437ls572988e87.0.-pod-prod-01-eu; Tue, 04 Mar 2025
 01:25:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeo8mCXC/87rhLZLugdfz5lO1JFneFxug+NEkKjuwgGvDPZKxkuVs0tL3lV/Yy+93qMREimgZO3Ls=@googlegroups.com
X-Received: by 2002:a05:6512:281a:b0:549:7394:2ce5 with SMTP id 2adb3069b0e04-54973943099mr1918982e87.41.1741080317517;
        Tue, 04 Mar 2025 01:25:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080317; cv=none;
        d=google.com; s=arc-20240605;
        b=EwbtPAvlshxnpym6W6xHIAMqo/vg9CcwAnpQ7NypJ+Q4lT+PrePJ8SHqdjlC3rkRei
         eL8YlyXBkynkh62lQW6LsQq/vGVd7TrGrgs5H5qtvditKlQDuilIpk1tXDt3KXXznQdr
         4nVOtoGUe5nXNQz7wYa1bdyKWgGBks915wck7PkmKOTGgkonmHrkgHHWDDvx4h3g+LRF
         Lh1FDi1YRR8BAzAYQFfKOyvfyt6aaFPN2wVvv3aF5zLjNylzlsaUHDjHZpRw6Q7BzFLS
         bAqqku6WLIG47hbvwA0lDNd9P0FiWEBc8fQqqPhgodYItL5Dnd6SWY0OtAPoY2nCH9/+
         1FBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=pBc/zi9P1R3Zwtykno3mWYwrt7ORJZX5qCpzJBRDBb8=;
        fh=a9448r7TbwnZzOaqwK9ueHDJlJusDRVVvAARcl+FFv0=;
        b=f8/pj9LuR98/8sCXQKsdSkiQh1gPPAxj3TwpXRM9B83Usfui9W0NqWY2pyurpoPNYH
         vPAtLAEyWEiZWFks1a83nhwcr3nO6R2BGVFvXHuR4SpRj7Z3waGoJ/h42o3x2wBkGcG4
         Q9r9t/Ple8NLiCSUM48Sbv8TOQtJBbI3h8MrqZGeELhs7fHK/3wRxTe66g7slHDlEOIL
         UZ7NfX3E6YRFsuHMxS4/LJLZ49W4swcSU/a+zTDnO2dkIvPGU7IC9rxVAi/4NCZdz1kO
         x3X9UE5QvreIVLdvaR82aPl76zt2CCgT+VMb1fXhZUn4eP25OG0dPZygqPwNntPhRpyR
         P0zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=114mFSvh;
       spf=pass (google.com: domain of 3_mbgzwukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_MbGZwUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5495b519153si227835e87.0.2025.03.04.01.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_mbgzwukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-390e003c1easo2439786f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX8Y2lmbRPoEsKWPdLC9iWxXWgnXzktkA0jg2ogrGStg3DjhcGxfC3zXApr9gCTfWDpTcqMERvBlH0=@googlegroups.com
X-Received: from wmbfp9.prod.google.com ([2002:a05:600c:6989:b0:43b:c927:5a4d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:186c:b0:390:f0ff:2c10
 with SMTP id ffacd0b85a97d-3911561abacmr1839931f8f.19.1741080316822; Tue, 04
 Mar 2025 01:25:16 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:02 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-4-elver@google.com>
Subject: [PATCH v2 03/34] compiler-capability-analysis: Add test stub
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=114mFSvh;       spf=pass
 (google.com: domain of 3_mbgzwukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_MbGZwUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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
index f30099051294..8abaf7dab3f8 100644
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-4-elver%40google.com.
