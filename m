Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGXGSXFAMGQEL7OQ5DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 44244CD0935
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:32 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-430f5dcd4cdsf905490f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159131; cv=pass;
        d=google.com; s=arc-20240605;
        b=bCCDEpEbbralHxJEaup6weMFORaXmrxcwi7uxLpgrSV14li+pghkUpAd1QZfAjMw2L
         Ukr5XAO7T/mNzkLZ5EeO2Mb3liWAuC3fpv/M6kkX9wir5JOZQdiLeKQ4cAG8Qpx+lvBH
         G1Tor+ZFXm9oGUyMbbCCR/RTB5TQvvGqpz2WTUOAOwFjebN7bkOa0hIXT6vs/GShLtQG
         hZve14zLg1M23S+uhdR2tKNAurLn3XQxNuZ3c97jvKWYyCizLsB8ni9x8IpP++W1H4WX
         Kr+qwA1V0I2mbm4u9+XRMN+kpoibFGUtbMzC0puzhfdr0tKbAKp8RLz3SklBnkom1yt7
         G6IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+hLE8e/jRd6Z9HI6BNusBg4pOOWjSyTGJvzNyDhoZ/E=;
        fh=Rt3YyfgrSZsKF8LqYnAcv2KirTIHDmi64MCAo0dZmzw=;
        b=ktk/3Ih6E3HCVhbmxb+MJGyLptxeCZJakr/a1DJ0mBvNAa3Gbpviccx7vpiy9pKR8x
         M7VoF6S4+YREQ59B6IR9gqq8x3YDD8a4WV48hSvzvkd8BgL4i6gt7cxQM0/qrnsGp6ie
         BFZ7AAk8c/Kfq+CUhR1gusokrJ16tiPzXoR4SUH9mNRUKe8JqPcO/h7MP4BMtdYn5Ksz
         WNRtq53kqjC9UHyvdXCSPo0091CC0ZoJyySUFkTnes0vHFsaEvxNNtKDl9T2Rl7nYkol
         UjbGDuzoJBxIxvHFMUZVhNxtEuyUIr47Tu01X2P2Ljez9JNYWIrLPzNmwlK4Srlg6pff
         X0Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DmjlFtIf;
       spf=pass (google.com: domain of 3f3nfaqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3F3NFaQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159131; x=1766763931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+hLE8e/jRd6Z9HI6BNusBg4pOOWjSyTGJvzNyDhoZ/E=;
        b=OS/UFKBRHnv9+xLYe8bR+fqBER0HeDYFmGE5ws8O3fdrEf5wD/qJroHX+BmHXO//li
         anJPjCZ+OymlvR9dLF1JmynPAVElWERQeOqmD+0WK/jkEjQA5WnRqyOBLYiTohRwuU6O
         D2+U99UOMeBoU7cOxRbQKWq1uPSzmZTgEPs9JETp5I2EdbRC0R55OerFsVl0R5RIqEa2
         gwMMORCwSFIkuDRIYjkrbkf46xkTKsP8O5ontP62bbvBcGEQr10GhcQy+4TtoZY655jf
         yQX/BofBCbK3P3mlqNaYDHnkE44pBWPiJcmzqsDi9B46q7EBThLAyCPHAWlBGCD9HDrk
         kZlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159131; x=1766763931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+hLE8e/jRd6Z9HI6BNusBg4pOOWjSyTGJvzNyDhoZ/E=;
        b=U/xGQWKy2FmEKtl/HKmfronDDg0VX+s6GzUDhn9zppZyWuNMyTxB0IG522dx81A31B
         3yOkAtIv6ixNjqWLfTuQ46vEZXlXpqZ3EcC5O6QBeElQ05zGh0lamqLbT9uU2mbkFkuI
         MRt6+a8dE43Mr/xQKNa2wZAf0JfjVVsDqUr1efJhslMl3+ZM0js9ist0l5sGEpQnmEov
         SxAAzMkqZKMg06RWVGgMp9m8YtFURWWziFnh/XAiAIt8nuCXNZRAYpeHzeKebK53uE75
         GkOr7pXZy9650QST1cCu3QUyi0Dg7bfhIvzmwcDuLeObpD5jWD3KJgSrRzvU3WsPzPky
         33Eg==
X-Forwarded-Encrypted: i=2; AJvYcCWsZYS3nDLY5Lhk8taUF9+uH17QyD5W757M+HSYg7g6dTAueIDF1SyF54pTl9dFQDsy9+IO1A==@lfdr.de
X-Gm-Message-State: AOJu0YymW8TaMzX2Psn+uQF1dSsQONMHmXfEdpcwH+uj0JsSj481KTB4
	Nzlr5/viSP/nhIw6U++WuNaZpHew0uPOg941ksyAmcoFknv8sfz2+rdL
X-Google-Smtp-Source: AGHT+IGVrOy3JX1OBwE//8SyyEMxvc9EE9/Jw1YYHQLSRLAUQ84utpxwHpdO/vui0r4Nhwss+HTsOA==
X-Received: by 2002:a5d:5888:0:b0:42b:47da:c313 with SMTP id ffacd0b85a97d-4324e4c165emr3758212f8f.3.1766159131547;
        Fri, 19 Dec 2025 07:45:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbtEEhoKimz7R63MZm9VHyTG/heovtQwW6odnzUOOzneQ=="
Received: by 2002:a5d:5f89:0:b0:426:f2f7:295c with SMTP id ffacd0b85a97d-42fb2c6a661ls3774740f8f.1.-pod-prod-04-eu;
 Fri, 19 Dec 2025 07:45:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWb2by8Mg7sjsr52KIol1NGqX8IKJGfvXCJwhDH4HmRalx14s66v09q3JWzxlJ5wROzXM5t1j4fG34=@googlegroups.com
X-Received: by 2002:a5d:5d0d:0:b0:430:fdc8:8bbd with SMTP id ffacd0b85a97d-4324e4faa9amr3657659f8f.41.1766159128795;
        Fri, 19 Dec 2025 07:45:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159128; cv=none;
        d=google.com; s=arc-20240605;
        b=em21jsHsZF25xmYbF4UwgZHb2lUqDj5rQzV/bXZwl8qYtcmudQCPH9jyT+PYTclmQe
         bBBZJ4x7mGkJJrMEGcTcVYJzC/llsF12YEAOO1IoHjhXn/+nEATaqlYYceT9y4NIOloy
         szTOWy/Thg13Q+C8dDvAHfv1EOMsz8hNvvLfnFLaa3t0/sY39pQf9pjRkPEuBsYkkutW
         kYRdJ85Guj1EpGoLEclD0js+W+5Tg+d7dawu5QToRAH4klioBBV6AFLTHQcIGAvhqP+4
         w3pqVSl4BqLpoopfX3VUc7flFeUVNp1mXECfWfmdymEOe72UGBf7l0dJLtTSE1z4oOGx
         vhzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZIbRhS5yAElvokIR1MvQQLNlZ/WUUA5jS9gYnuf7mNE=;
        fh=YuKQe9kt+L3zoxwfBXM9FRKaN+e36kbHbDtQedIQLJE=;
        b=PiKC0ww3OGGf52faqN8G0JezDjbBVZ0oWGcG1u8UwvAj6viLFzmO+FJryjQNIHnhuO
         TXXHbmwLbVUniJFo8TfYy4JSRwtRIEYFi8576Oy/TEOsxhgreX4ldu1SkPBCU3SHrH/7
         IFnjYaQsoeI/mzMa9CNd1w+Z0namZhbl3WChNL3DfNPAcQapyNxcyZG3PCWHHsGGTZGJ
         TD63ujWeLQV45BBAgF0fwM+2xgNDJ42fEYcYPbDygU8HPcZH51fvBOF/84JewNe7IoSa
         rRNMwcNOZ0NSnjNbfkTlRXoVIw9J9i79SHf6SLQEgLYWhwuJYnSpma/7N8PvrdHT4LRl
         mE1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DmjlFtIf;
       spf=pass (google.com: domain of 3f3nfaqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3F3NFaQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324ea21b1csi39528f8f.4.2025.12.19.07.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3f3nfaqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-430fcf10287so1391064f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXkKPopY047hVnVLXiOXttQQeUAH5AHzqy9hNSY6wXrJ9n0EbSE1ansaiN9P0smYXCs5X5pUWXiSc0=@googlegroups.com
X-Received: from wrbfu3.prod.google.com ([2002:a05:6000:25e3:b0:431:37f:7ba1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:5d09:0:b0:42f:a025:92b3
 with SMTP id ffacd0b85a97d-4324e4c0dd4mr3283947f8f.2.1766159127887; Fri, 19
 Dec 2025 07:45:27 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:52 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-4-elver@google.com>
Subject: [PATCH v5 03/36] compiler-context-analysis: Add test stub
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DmjlFtIf;       spf=pass
 (google.com: domain of 3f3nfaqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3F3NFaQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
should not generate false positives for each new supported context lock.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.
---
 lib/Kconfig.debug           | 14 ++++++++++++++
 lib/Makefile                |  3 +++
 lib/test_context-analysis.c | 18 ++++++++++++++++++
 3 files changed, 35 insertions(+)
 create mode 100644 lib/test_context-analysis.c

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index cd557e7653a4..8ca42526ee43 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2835,6 +2835,20 @@ config LINEAR_RANGES_TEST
 
 	  If unsure, say N.
 
+config CONTEXT_ANALYSIS_TEST
+	bool "Compiler context-analysis warnings test"
+	depends on EXPERT
+	help
+	  This builds the test for compiler-based context analysis. The test
+	  does not add executable code to the kernel, but is meant to test that
+	  common patterns supported by the analysis do not result in false
+	  positive warnings.
+
+	  When adding support for new context locks, it is strongly recommended
+	  to add supported patterns to this test.
+
+	  If unsure, say N.
+
 config CMDLINE_KUNIT_TEST
 	tristate "KUnit test for cmdline API" if !KUNIT_ALL_TESTS
 	depends on KUNIT
diff --git a/lib/Makefile b/lib/Makefile
index aaf677cf4527..89defefbf6c0 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -331,4 +331,7 @@ obj-$(CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED) += devmem_is_allowed.o
 
 obj-$(CONFIG_FIRMWARE_TABLE) += fw_table.o
 
+CONTEXT_ANALYSIS_test_context-analysis.o := y
+obj-$(CONFIG_CONTEXT_ANALYSIS_TEST) += test_context-analysis.o
+
 subdir-$(CONFIG_FORTIFY_SOURCE) += test_fortify
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
new file mode 100644
index 000000000000..68f075dec0e0
--- /dev/null
+++ b/lib/test_context-analysis.c
@@ -0,0 +1,18 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * Compile-only tests for common patterns that should not generate false
+ * positive errors when compiled with Clang's context analysis.
+ */
+
+#include <linux/build_bug.h>
+
+/*
+ * Test that helper macros work as expected.
+ */
+static void __used test_common_helpers(void)
+{
+	BUILD_BUG_ON(context_unsafe(3) != 3); /* plain expression */
+	BUILD_BUG_ON(context_unsafe((void)2; 3) != 3); /* does not swallow semi-colon */
+	BUILD_BUG_ON(context_unsafe((void)2, 3) != 3); /* does not swallow commas */
+	context_unsafe(do { } while (0)); /* works with void statements */
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-4-elver%40google.com.
