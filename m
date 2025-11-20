Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIO37TEAMGQENRSWWLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20489C74B9F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:02:59 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-37a46947317sf4604361fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:02:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763650978; cv=pass;
        d=google.com; s=arc-20240605;
        b=DMsGwAfxz+1QMF7EvnymkCj23OFU1JL3OtPyfTLFGWoisHRMDJwZRvpX+joEEXcFVq
         l11jnEVKWYmRm03U03l3PcZrtTqS7wdBPdMlKS8YpKjeBDN2+c/mspkGqUS/xWCB7aTy
         YsaIt0TfrT0Ark5SfdZdTyVZE4JTq16NR9I9+0+cUwWgv4VtmS1ZgQIgBk5YXS4PhOR8
         KjoCHLtCSF5NzE65vWu+Zmq399/IMDYPezG1+vUik02ZrA7UP1tJu+GfdTk/IvZ71swF
         YYIb+T67E5z5wCPT5Vxrbl32OpBTHaoVlsMVd0dtpbME4XFeSTXUxtiOU+u3PtUgoRvG
         RXQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6SXH+Oh4a9vtvfF8trrPAiL9jzAJ6TMhMlIK4hZIApI=;
        fh=LKFuVLGpW5spyUVcWC0wy8cy2zdUanPr0YX8BtMfx8g=;
        b=Wg9qLOu4QOmLrEftWQy/RE4kTHnP5Zz51snyViINfofyS9Ib+MC+WlUgq/18dWG5mD
         9LAeMeNNvL6HkTf5spAxz7qAgQkO1Rp7YWkplxRH6Abi9vhf1tfw0cZHGFSVRMwwM48x
         4gVfxDqeRtroz+LAG/jhlWTclFfhBQ0ay6f73veVMihFSnkjGzYG1iiAwLHzAfxZguPq
         AhkjpKiyVfTe+FrbfaFLBEWTgpb9kE75LwSEk7cSS2qVtD2CMP4pvv6QnbYimtR2kXWm
         /99tq/4Ij+cwcm/dWiLotzIdwJGzfgD0pRRE28PWx0xZrX+xrCfTgxHQTJf8GHyPYCMo
         9hWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bn69nF7x;
       spf=pass (google.com: domain of 3ns0faqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nS0faQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763650978; x=1764255778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6SXH+Oh4a9vtvfF8trrPAiL9jzAJ6TMhMlIK4hZIApI=;
        b=N67/TvHG4kRTFvpxMWhlXOK+q0ZJW/Fgkx5GFClbpg5F7IfnH4F7MGRlNE6qCGlyN7
         0IdY7c/cfAkHzHZ+eN8ycdPNrwdwqTJvCKbAVJ2KjzFUxkUA6I/NhgxIGvnliyz4Dy0e
         0GkfnmsSAWRHX/UWPZvdBlFkCHNnSSE14mr8O5j1PbdtxrV0KYDaLWDq3IksWTE9ne/F
         yjjnxvOf0MRlh4Y4FG0RuD0Gq7UYSa1uKGO0zBg7oksgMLmbMaEtgYLQjzJH9IJg8Ils
         szrQGeCOW4q7Zyvvrc1S6yK066ugZWzUuzjGf5Gjp1UjCGCnotrMWOLZ+Gr2erxFry8m
         waDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763650978; x=1764255778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6SXH+Oh4a9vtvfF8trrPAiL9jzAJ6TMhMlIK4hZIApI=;
        b=OAGnXqnUzkfv6Lj70W+2TZWtPGgPLXdyeJBhnz6ytA9M8h5gFPSqc7Tn6LaFUck5OM
         LKJRMT99Q/o7HRYDeQ+roQNZTFZnm/Vq4P4dBqVHPgC9XHuOrVPb3tyVmOaByb9lwKhh
         XSVWv+Nt/P5lHh/GlE0uu3tLjDG6m6LzwwiPL9fHBypqhvHtO+HkHyn7diiZz1RVoMOb
         IpqqDvMhK4ZDN/Kjmd5Q6PJCpXEnPaR+SCsZAU5Zq6jaocDkQrS0GFl6SJzQ6/MgCRJR
         tBwZtzrXn7Vp7Ysu2t8qV3SEY1uL+5EktCsZ5BtUrY+1QsmF2ldBbU1bBqzYY79X5TMu
         iTEg==
X-Forwarded-Encrypted: i=2; AJvYcCWoyDlSb+ooM233nQBMu2CTE8pNpNp5W+u1vfjg1tlsQmXUwtXFtJz4gPcIUp1G2Qb00u1T6w==@lfdr.de
X-Gm-Message-State: AOJu0YzrFPU2KrYqqr3IuA/tMV272sHfj6Q1NAIZccKLX0fk15n+ca4r
	X0/aV9RwpfWOgdJXHE6J5iagcSpukbAEAJvcISkXodWzptQJSgXo0PFG
X-Google-Smtp-Source: AGHT+IFhtRsCJTr9xV8Ix/060L7gtfSNJvO97zbDhuD2OCWExa6UjVSeTNGeC2p3fjpnZHQj9EUbOQ==
X-Received: by 2002:a05:651c:3041:b0:37b:991a:543b with SMTP id 38308e7fff4ca-37cc68cb4c0mr9181281fa.36.1763650977894;
        Thu, 20 Nov 2025 07:02:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b63pjZGZdPHOlfRLjLYMgguOIBsiG8jlKx6XVohCyvbg=="
Received: by 2002:a05:651c:e08:b0:376:34ae:d65e with SMTP id
 38308e7fff4ca-37cc6940395ls773641fa.0.-pod-prod-09-eu; Thu, 20 Nov 2025
 07:02:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWqBYZaKulVxMyvbDINmWpv9DJFqT/lhOXBF4GzYhUsEyI1RjywKPbeYeaIQZRUy3gzqfgDnQyftIU=@googlegroups.com
X-Received: by 2002:a2e:3217:0:b0:37b:b849:31c3 with SMTP id 38308e7fff4ca-37cc68d1bd9mr8700141fa.44.1763650974242;
        Thu, 20 Nov 2025 07:02:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763650974; cv=none;
        d=google.com; s=arc-20240605;
        b=jehpJjokPNQBu5jWpRj72NdtLK8XsRmflktvKRjl4BNyY/qZCWkRQt+VnYew5Nxj9o
         x4b9YeiE29j6CfqXAr+9VlnhQJifd6sBhVylHSRZMPopd0AXDKgUgP6JFF6b1zd9jktg
         zEoupRtWgbLgHb+Y4uyLPIaYwb8VEm2aDteOwYy7a3d/VRGjchZmOF/lIjtLMnVVubrd
         3WgP+lqu16p4aqiKUV23udEiCcsBMR56+0OKfP1tl+KQtgb+vFHuZUgq5AGojSBV0c+i
         HXsJTNT9WwbXNJSJIdLJURYJUSscZd+PokfG9sbt8GxsZTG2sLa2Of80EZ73LMbH8OCY
         svzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lIkqaT4GZQQ8I2xtRoztfiZr8q25ife+cBqIcslh3gQ=;
        fh=9wWexT8/rVaptdlJgOsOzBbyXrsp41EEQ3TkxKH3z+0=;
        b=UPRqrLuZQPE3n7h0XGBWbH5ht9sdGqf+B86wsegAD4CVR1Ohn3MzZq8bdV219A7Idn
         6pd3AJD/67xweVZXHw87ZfHAYaCziYCjNIQRcQ39oPp6QomNfMqQ6HA62mEj/5uyXY7Q
         n5U+9OB73LnXvwZEoJNOTIP2myldIzr8jxltWPee/grFkUmNCDNt9w5QjKm2m0sCmRgW
         5tCiclfUyQaYx/boRtVetRDPOdXdU0TGsJTaBalCzQNw9hZl4auAGbxgT435cDGvFOQ1
         fSb7v4q7+e9u9D+/VymMrt46klc4a6N2LoRzr5d0B6qUyl37s9EKL6JQfbcuPzPywAFR
         KdDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bn69nF7x;
       spf=pass (google.com: domain of 3ns0faqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nS0faQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6aa3ff5si445751fa.0.2025.11.20.07.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:02:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ns0faqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775fcf67d8so10369895e9.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:02:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU/rCFDnMz3GkSHxnbAQ2Mi5/ySkhLfko1GDbIV1YUUve+2qKqHiPLNDBAeMadiGd9h+4brvTkI2cA=@googlegroups.com
X-Received: from wmrm14.prod.google.com ([2002:a05:600c:37ce:b0:46e:4c7c:5162])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:470d:b0:477:9cdb:e32e
 with SMTP id 5b1f17b1804b1-477b8a50e80mr28447795e9.9.1763650973180; Thu, 20
 Nov 2025 07:02:53 -0800 (PST)
Date: Thu, 20 Nov 2025 15:49:05 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120145835.3833031-5-elver@google.com>
Subject: [PATCH v4 03/35] compiler-context-analysis: Add test stub
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
 header.i=@google.com header.s=20230601 header.b=Bn69nF7x;       spf=pass
 (google.com: domain of 3ns0faqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nS0faQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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
should not generate false positive of each new supported context guard.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
---
 lib/Kconfig.debug           | 14 ++++++++++++++
 lib/Makefile                |  3 +++
 lib/test_context-analysis.c | 18 ++++++++++++++++++
 3 files changed, 35 insertions(+)
 create mode 100644 lib/test_context-analysis.c

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 696e2a148a15..0c499d22407c 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2833,6 +2833,20 @@ config LINEAR_RANGES_TEST
 
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
+	  When adding support for new context guards, it is strongly recommended
+	  to add supported patterns to this test.
+
+	  If unsure, say N.
+
 config CMDLINE_KUNIT_TEST
 	tristate "KUnit test for cmdline API" if !KUNIT_ALL_TESTS
 	depends on KUNIT
diff --git a/lib/Makefile b/lib/Makefile
index 1ab2c4be3b66..59ed5f881bcb 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -329,4 +329,7 @@ obj-$(CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED) += devmem_is_allowed.o
 
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120145835.3833031-5-elver%40google.com.
