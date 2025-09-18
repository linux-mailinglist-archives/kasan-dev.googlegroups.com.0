Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVDWDDAMGQEVJSYZ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9668CB84F69
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:39 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-45f29c99f99sf6097995e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204339; cv=pass;
        d=google.com; s=arc-20240605;
        b=IoUtFJYCaGknQEjG6VrscTjU8kC52m73ywwiu1zQJC/RX8LQvx44UKr3ctQPjyvCF9
         bkqdmyPqLIlnMQhtyJiyy45bbTyngMTGKEhRgEVAhRNqBO5UMom7oG3uhuL5EU1qFMSL
         rf2atoyttCYSBEHgVArMhNkKMhAFVcPXNZdQ2YPR7q4LDPG+3Go3r0RSnNeY/sQcUoTU
         DUbT7MnqL3iYPHA4LzVfaUMs9JxWOGUai6Rn6wXxaaefzHUAAZRHO/Sajrg8WbpS+Txk
         WFaQtcqwe/2mB4vgxk9bOdFv9tnOcGwhdPft6uepY4jlqCaEEFtKC8SqtjZ9Gg+sGzt2
         bIMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Fn6NGDQhlj3BTU6CTkHoh6Lj7V3XD+mJ60dQw85OxxA=;
        fh=yyk83Y4IoyAgMuL6TmT+nuOPc1lB98BCxkMPug0TxRY=;
        b=JmvRtgK3L0nm5GIo5c2P8bZYUi8+7n4ZdaKTJxXsMxmAE48szgHM6k6aUruM5COXHS
         RRWGuvMWIulTtOyKxURlM60G6JiI2ELI88gcBCfII9q/GuO+3kUsSwGOIAPS1E/ilD08
         IBtHMltIwWxtbZ9ZmLcgsMYRkEaG0sgqhWfLHIMDT16MRVfHPR+vUO544ACjfRjxQEVo
         S3tHT49/Dpozfm202WpCnZXMszR0uzUu81RsUz1zgtz5CVp2ieY6PpX73o3w2ECurbLV
         Sl835yqqPwHaGqEzPLOj9RSdLhOV+k8Lhm1+UKtiR4AANfOKSKz6wwoa184WBZg4Qo9u
         gt8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D0wNz6D8;
       spf=pass (google.com: domain of 3rhhmaaukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rhHMaAUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204339; x=1758809139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Fn6NGDQhlj3BTU6CTkHoh6Lj7V3XD+mJ60dQw85OxxA=;
        b=CsBhRfI+QdbCmF9P9uM4GklbK9frC2f4LNhHLLml4iTwvEAraGi8lvSg7eLWqFovVk
         /axiF5A+uxARVrJeg5q9L9RzIwbqn9TwySGlggFPrkJHzmmfvJX9mWuNesZ5TTVxbkGb
         jsJpV5Mr+K1aEnOp5V7OMDn8e/U2Gn4s0ZgYynBZpxwNu03A5SwQPc1w+Z4VEWGSWzNj
         83QsVM0E9HniNGBU1+8E30MZhKp3IEYHTmx3PCEzPuERCfg/AOLj4O+ViofOENL44rpN
         xSa/j3kJ8En9J4R5lJ2vs6S3ZyS6E4eSVrJT2ExIVtd+Uv8VLpCVS83qwLRHRChqpmZS
         B61g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204339; x=1758809139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fn6NGDQhlj3BTU6CTkHoh6Lj7V3XD+mJ60dQw85OxxA=;
        b=Y/nQl9QKEe55Qw0+sDPtUxEQ8BtCw0hsF97icXDuBrNmLESMpTWG+ciH9vm1McJ/y7
         mzkw2LWL92dQPiTMY/eWeHshwsk3aG041GRji/LfPWAVxsAHwgwMR3lNQ/lZh2qDLZZ/
         mOEXQl9QdCnYaLvM/9W1Av7h05D1yaT7Ich0I9HOLVQC2BkEj+1PTEtq4SCIHO9J79TX
         cQ1AT80Suwa/I2ppUphst8aOCwmeaRtTMlH2w7RTp6WkXZ5Z5R0AcIujf93ynjoad1TN
         D1yaJPESTshHR3FKFs1MAtfiLs+wea0KfKPvi3dWirufOqPHX+xMJNJt7CYk+tQjbreA
         IaWw==
X-Forwarded-Encrypted: i=2; AJvYcCXu2OK3WsEthsEiJAezSl/Xetnx72KIp3g+Rno0Q6J/NftNX4RmYz14yeooQ53a0qU3PdkkqA==@lfdr.de
X-Gm-Message-State: AOJu0YwAbodU5q7lZpRFT4FlMioyYShSxRHHshyf1vW6WIEUx0uZ2nG1
	UabgD21y868aLnkgUuDVe7wCdQcDR2XUizeX+lqX6R9iJGd7CTQNFXV0
X-Google-Smtp-Source: AGHT+IGoyZgTmJq0JcrZnZYZfMoK1zsar0iYblzV2KcXYtAbB0vuC4bbSia/Opsnxc1lWwTgqksl0Q==
X-Received: by 2002:a05:600c:1e8c:b0:456:29da:bb25 with SMTP id 5b1f17b1804b1-46205adf58emr58309235e9.19.1758204338621;
        Thu, 18 Sep 2025 07:05:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6KA1RG/N877Q9IbejUX1ufSqObWkCPamzpJXlh10msfg==
Received: by 2002:a5d:5d0f:0:b0:3b7:8ddc:8784 with SMTP id ffacd0b85a97d-3ee106a3dd1ls391279f8f.1.-pod-prod-03-eu;
 Thu, 18 Sep 2025 07:05:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVk+kD9tX9pJ8X5WyefhOdHJpoY5Mu5xJeHI+9Tu0Vn2912OT7xLdbBJxxW86SGiE+yCOZLrI6jN8o=@googlegroups.com
X-Received: by 2002:a05:6000:3109:b0:3ec:d7c4:25d5 with SMTP id ffacd0b85a97d-3ecdfa44f97mr5232955f8f.50.1758204335375;
        Thu, 18 Sep 2025 07:05:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204335; cv=none;
        d=google.com; s=arc-20240605;
        b=Y+FgnzMYOvd/xu7avVKHfuwyYgewVSlDc28cHZKjleCLSxT1OTscVBs9nrSrFU23NI
         NDB3VHNhTKyVN2W4dLssxIqfU81eRPKHpsjbi1IzkiU7/eAcABMDxzBg1+hYXK0Kzr+d
         xv9qZ36YGZOqR/SW09b6Gfd58JHtEVYRWAlxVTNw/SHeE1dZA6iQgmFUe1D9T5Af91z6
         Q2ZPIMtMEjV2GipIkXz2HnP/rXf/ME3FTJ0ISv7PEGl8iD58pAspnaWH/XDD9J92bBPz
         8nbKkpsWQFPFvGOWuGnrSdo/zrZVOSb9SRc6qvOWVL9S7EjkYniJkRe0hgoWzg2dCvq7
         sQ1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GRwMz0bPjU6VOADE1reTzyKkaNRl/lw6aWShINvk68c=;
        fh=7HX6GUv2knU6Lyn6heJpXXudVKCgh80Xy6u+BSiFpHI=;
        b=Uk67rVytjMHScrtj8uI329x5SBJj4yvBawSHXIiX7WdEkmtwFGNf7/jVtxqymNvC6P
         GZ3vitqs1JtJRgcTd9WBDdpL9OMbeOG7XMKKld8Jzx3Y8NDRIv9KZcdG9xEYhyYOnE1X
         /UZnZMcHkmrDKSJOTY7xgSGOOugYYslGu1ilLHaryEvnWhxeuKZW/EGEG/ehJ6bY67Y8
         gP5XRcUkYLeQbZ2P41p9GWEGqTSCh33M/BLAI6WwLml2kHiQ6xq45RFW3zJWj/tg+NdC
         ojtoqDuJX6adW7m/oOA7Se/DbnvCFLMTFHq6nqkketVnz9LUZV3Vqj+0j1JuHQyVl3tg
         T0hA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D0wNz6D8;
       spf=pass (google.com: domain of 3rhhmaaukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rhHMaAUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbc677asi41416f8f.7.2025.09.18.07.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rhhmaaukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-b07c2924d53so96075566b.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMrZMz4SP3d6FwLc9IGiKlZnP3zWtBaQ4gO4mvEAJh9WBIs7GWuabyPdYKyg4ngkgEBStVbVmNJRQ=@googlegroups.com
X-Received: from ejctl10.prod.google.com ([2002:a17:907:c30a:b0:b0b:a3bb:15d1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:2d8d:b0:b11:3760:9596
 with SMTP id a640c23a62f3a-b1bba5d1389mr603989266b.60.1758204334564; Thu, 18
 Sep 2025 07:05:34 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:14 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-4-elver@google.com>
Subject: [PATCH v3 03/35] compiler-capability-analysis: Add test stub
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D0wNz6D8;       spf=pass
 (google.com: domain of 3rhhmaaukcu8v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rhHMaAUKCU8v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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
index 57e09615f88d..ac024861930f 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2813,6 +2813,20 @@ config LINEAR_RANGES_TEST
 
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
index 392ff808c9b9..e677cb5cc777 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -332,4 +332,7 @@ obj-$(CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED) += devmem_is_allowed.o
 
 obj-$(CONFIG_FIRMWARE_TABLE) += fw_table.o
 
+CAPABILITY_ANALYSIS_test_capability-analysis.o := y
+obj-$(CONFIG_CAPABILITY_ANALYSIS_TEST) += test_capability-analysis.o
+
 subdir-$(CONFIG_FORTIFY_SOURCE) += test_fortify
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-4-elver%40google.com.
