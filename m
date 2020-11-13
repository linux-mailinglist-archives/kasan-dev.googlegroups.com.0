Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFMMXT6QKGQE7LVSJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 81E082B2834
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:57 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id u9sf4005127wmb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305877; cv=pass;
        d=google.com; s=arc-20160816;
        b=FNJnSd48D47nUOO4PLvxpZzMxDL3mZyzi/0KyGpvOif4HRRDSH582WWI7Lveq0GNFu
         i2IkKaqgjQGkBz6Dnz0+mUmNKcRDvxepogvDUnQAa57NwQaxElNvVNED1tkNFC14/yRh
         aX44hfBzVKOtmx10SsD/rVO9X3Z2kBDpLRzZMIY3Z+E3VvHgCGTMf62R4i3EqlsJM2xO
         Q10nEE96WEHSvRzpk1UdGKNp+N6E3xrt+tTahoYSyDn3iwQQKRTjtEqKqWiqMGAuV9nr
         Is729xoaTQ+arh+FBm8pujJgxdjuP1o1bECcMWUbsAC2/8lenO6BjcY0Zw3b5FvNhm/8
         MqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dtDoQPB18uRcyd4ZIRBlGdIxma+kSANHzXy3oHyoHpA=;
        b=aXAL7Ywa08pPDYcXKxn+iikHcH2fp6zYkkAc61/Toys5L7yAQyGsaeZEamtSJJxfr5
         jQeOE448kS+PhZjyW3ZKuAk3oU3KmDWRQz9acMAIKm6dzIy7Iovlm/Yo4VmZhS0RUZDZ
         /3c7GTRKNYDGtxRMm56bbRCrTfaE3yjWE3JrOWn/kYAcGJSvnUWYc2pI3K+LF6ALQChH
         FTnmqxhFuAvPeEfQ1RiLwVLU8YmknLHlWdss8ZEid2MI8vAUYqRivHWpfJ/g2XrDCxqi
         aeX22igcxAxeqy0RFvexMDm5ha1lvXtVYWqe8xLYtjBXJrVRFTSSCakodgW3icby5Hbv
         VJsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="anvVrn5/";
       spf=pass (google.com: domain of 3faavxwokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FAavXwoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dtDoQPB18uRcyd4ZIRBlGdIxma+kSANHzXy3oHyoHpA=;
        b=akcXxtnzvoLVA86DKoFG57SMZFNsKEMW+h3OiaPLZuPykWAqfVv0OJ4Tto/P68LoNS
         VaVCjADi29FCNI+gLXFKWxxfCMg694pV1ET7lazUCvtPmsSm6usJ9h9XTrrCNMi2kvGD
         7R4kUb4U/YlxYgmrgCNCZ1wkFJPuMTJ7fJxDtUvXRM6t4v1AK0kBpVpD4X/hnE+Mxsyj
         6LX6Km29h6fyGhZ/PE5DeCqGGc+2pViGywDMl+Y6hdFNMHkLY6bKofvIU6YkzhyzYBIi
         WNJr8Q/LgkDT1XtoG6hFPa/lwYDImu1baL+ePJVsnCNMDa3tc6ZxejupEBu02sszwvmL
         mgWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dtDoQPB18uRcyd4ZIRBlGdIxma+kSANHzXy3oHyoHpA=;
        b=kjVVzeodZjMcD+uynFyUdtTbHeDrh7du05OdywEoRUxJksV3D2mVE8wCLqSapSkfP5
         MCYGgGGGiEEKZksXGXpvRgq0t/4b/rwPt8OO0F4EChMhW7p7toFGRbJyvcsWRKeGhK4J
         DNsCng7HRZrrkGSi5D24vetaZ01ghHSu0Qp7RiU32vXf8VNI9jr2NpAVYQtX8QFQAJR8
         Pz2MikIgun+AYUgX5eSnKi2+26zNuv2NFZ8w+JaWlL24xfb4t9Vh77c+ggEGo1TrUnT3
         aIs3d3DYajeiQscbNDAqSF3Jfgt5MDJGloRMkWSAx+oBEaNkG0mX0K6248WTwmRL04BO
         c3fA==
X-Gm-Message-State: AOAM5328DTDd0OJ0Ir6uYSZT91MqYa+mVvOiSK+mZ2L+f2qbAQ5VG+mG
	Ju27RzjK2/llQ83Rf5t3EAY=
X-Google-Smtp-Source: ABdhPJw+y++EJAst0KM1fXN3NxxAVVC7VcYwM1+DxWu6vRR0qdsiqktjLH8MxqOcHPz9J8Iog2qYQQ==
X-Received: by 2002:adf:fc48:: with SMTP id e8mr6345595wrs.313.1605305877274;
        Fri, 13 Nov 2020 14:17:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls7240522wrn.3.gmail; Fri, 13 Nov
 2020 14:17:56 -0800 (PST)
X-Received: by 2002:adf:9407:: with SMTP id 7mr6483669wrq.182.1605305876421;
        Fri, 13 Nov 2020 14:17:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305876; cv=none;
        d=google.com; s=arc-20160816;
        b=M7peQZUJM+EvypPb7Q6522qeqJ4sT8CUK4ZFLm//+H+6PjOYf3SYZQb+e0qoLqu0TO
         7PF4OafLKMIu2c/Gt2wp8KZYpqgvt1WpGzdJd2tsgCe49Ina7uFXbvcJrouBHsA1xQYP
         3McqJyqnVrnHfFBWMPnTaV0U1n+pmqBtMkQf8nudtQN12TbbAtTPevk3ea8KG0ZsDnPP
         8DR+wxVKCh5GeOaityxxpPGEHQNoecPI8swGg1YqhQ1UdWWksEqJ2GmwJsNa7qIuigNl
         DjpWNb7jvAqArjMrm9owhm4f4hJQ5rS/XMA8fs674lO8BbeIcP769IbVyPfk5SW3O5hY
         8QMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5qMij167ClOELbqeSBDKfuvF2LQUPsW2wggzZGec9i4=;
        b=Zaq4zzt+tY4O0JiFIhr/XQlaZljX+3RsRw9g8KwH0/J3SGM5J2mIa7g9+t8cZPRdAY
         Mrm9p7GjK3TAGBfcaNqgs0bZIWcvxebnepanTxJs4fp5OwL4kDwBNIsvnVExauyHk8YR
         6HhPmLnXgmPaaiYsI2p11TjQyPIoNpn4eGzDZ12uEjH8wVoQPoxpeD+DaYgPpjR4bIZu
         TY0/6o9HYxirkqSnFeMaGNjgyTYo309+b/P/9vBpe4Rip1EW0WN1KH94tr4LWZPd9zei
         HBhIOlY2uZcM47a+NM2qTmM7jwxTQJ6qeWxtb5fGNxxXkY3RS8V3HDuWe/j/2T5WAw83
         A2iA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="anvVrn5/";
       spf=pass (google.com: domain of 3faavxwokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FAavXwoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j199si407391wmj.0.2020.11.13.14.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3faavxwokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y2so4686666wrl.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:56 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:c58f:: with SMTP id
 m15mr6387961wrg.144.1605305876026; Fri, 13 Nov 2020 14:17:56 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:10 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <f27ec2ab08b8a5c3e3bf1056c7e270d484153cfa.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 42/42] kselftest/arm64: Check GCR_EL1 after context switch
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="anvVrn5/";       spf=pass
 (google.com: domain of 3faavxwokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FAavXwoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

This test is specific to MTE and verifies that the GCR_EL1 register
is context switched correctly.

It spawns 1024 processes and each process spawns 5 threads. Each thread
writes a random setting of GCR_EL1 through the prctl() system call and
reads it back verifying that it is the same. If the values are not the
same it reports a failure.

Note: The test has been extended to verify that even SYNC and ASYNC mode
setting is preserved correctly over context switching.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Ia917684a2b8e5f29e705ca5cbf360b010df6f61e
---
 tools/testing/selftests/arm64/mte/Makefile    |   2 +-
 .../arm64/mte/check_gcr_el1_cswitch.c         | 155 ++++++++++++++++++
 2 files changed, 156 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c

diff --git a/tools/testing/selftests/arm64/mte/Makefile b/tools/testing/selftests/arm64/mte/Makefile
index 2480226dfe57..0b3af552632a 100644
--- a/tools/testing/selftests/arm64/mte/Makefile
+++ b/tools/testing/selftests/arm64/mte/Makefile
@@ -1,7 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
 # Copyright (C) 2020 ARM Limited
 
-CFLAGS += -std=gnu99 -I.
+CFLAGS += -std=gnu99 -I. -lpthread
 SRCS := $(filter-out mte_common_util.c,$(wildcard *.c))
 PROGS := $(patsubst %.c,%,$(SRCS))
 
diff --git a/tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c b/tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c
new file mode 100644
index 000000000000..de5066aca097
--- /dev/null
+++ b/tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c
@@ -0,0 +1,155 @@
+// SPDX-License-Identifier: GPL-2.0
+// Copyright (C) 2020 ARM Limited
+
+#define _GNU_SOURCE
+
+#include <errno.h>
+#include <pthread.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <time.h>
+#include <unistd.h>
+#include <sys/auxv.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/types.h>
+#include <sys/wait.h>
+
+#include "kselftest.h"
+#include "mte_common_util.h"
+
+#define PR_SET_TAGGED_ADDR_CTRL 55
+#define PR_GET_TAGGED_ADDR_CTRL 56
+# define PR_TAGGED_ADDR_ENABLE  (1UL << 0)
+# define PR_MTE_TCF_SHIFT	1
+# define PR_MTE_TCF_NONE	(0UL << PR_MTE_TCF_SHIFT)
+# define PR_MTE_TCF_SYNC	(1UL << PR_MTE_TCF_SHIFT)
+# define PR_MTE_TCF_ASYNC	(2UL << PR_MTE_TCF_SHIFT)
+# define PR_MTE_TCF_MASK	(3UL << PR_MTE_TCF_SHIFT)
+# define PR_MTE_TAG_SHIFT	3
+# define PR_MTE_TAG_MASK	(0xffffUL << PR_MTE_TAG_SHIFT)
+
+#include "mte_def.h"
+
+#define NUM_ITERATIONS		1024
+#define MAX_THREADS		5
+#define THREAD_ITERATIONS	1000
+
+void *execute_thread(void *x)
+{
+	pid_t pid = *((pid_t *)x);
+	pid_t tid = gettid();
+	uint64_t prctl_tag_mask;
+	uint64_t prctl_set;
+	uint64_t prctl_get;
+	uint64_t prctl_tcf;
+
+	srand(time(NULL) ^ (pid << 16) ^ (tid << 16));
+
+	prctl_tag_mask = rand() & 0xffff;
+
+	if (prctl_tag_mask % 2)
+		prctl_tcf = PR_MTE_TCF_SYNC;
+	else
+		prctl_tcf = PR_MTE_TCF_ASYNC;
+
+	prctl_set = PR_TAGGED_ADDR_ENABLE | prctl_tcf | (prctl_tag_mask << PR_MTE_TAG_SHIFT);
+
+	for (int j = 0; j < THREAD_ITERATIONS; j++) {
+		if (prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_set, 0, 0, 0)) {
+			perror("prctl() failed");
+			goto fail;
+		}
+
+		prctl_get = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+
+		if (prctl_set != prctl_get) {
+			ksft_print_msg("Error: prctl_set: 0x%lx != prctl_get: 0x%lx\n",
+						prctl_set, prctl_get);
+			goto fail;
+		}
+	}
+
+	return (void *)KSFT_PASS;
+
+fail:
+	return (void *)KSFT_FAIL;
+}
+
+int execute_test(pid_t pid)
+{
+	pthread_t thread_id[MAX_THREADS];
+	int thread_data[MAX_THREADS];
+
+	for (int i = 0; i < MAX_THREADS; i++)
+		pthread_create(&thread_id[i], NULL,
+			       execute_thread, (void *)&pid);
+
+	for (int i = 0; i < MAX_THREADS; i++)
+		pthread_join(thread_id[i], (void *)&thread_data[i]);
+
+	for (int i = 0; i < MAX_THREADS; i++)
+		if (thread_data[i] == KSFT_FAIL)
+			return KSFT_FAIL;
+
+	return KSFT_PASS;
+}
+
+int mte_gcr_fork_test(void)
+{
+	pid_t pid;
+	int results[NUM_ITERATIONS];
+	pid_t cpid;
+	int res;
+
+	for (int i = 0; i < NUM_ITERATIONS; i++) {
+		pid = fork();
+
+		if (pid < 0)
+			return KSFT_FAIL;
+
+		if (pid == 0) {
+			cpid = getpid();
+
+			res = execute_test(cpid);
+
+			exit(res);
+		}
+	}
+
+	for (int i = 0; i < NUM_ITERATIONS; i++) {
+		wait(&res);
+
+		if (WIFEXITED(res))
+			results[i] = WEXITSTATUS(res);
+		else
+			--i;
+	}
+
+	for (int i = 0; i < NUM_ITERATIONS; i++)
+		if (results[i] == KSFT_FAIL)
+			return KSFT_FAIL;
+
+	return KSFT_PASS;
+}
+
+int main(int argc, char *argv[])
+{
+	int err;
+
+	err = mte_default_setup();
+	if (err)
+		return err;
+
+	ksft_set_plan(1);
+
+	evaluate_test(mte_gcr_fork_test(),
+		"Verify that GCR_EL1 is set correctly on context switch\n");
+
+	mte_restore_setup();
+	ksft_print_cnts();
+
+	return ksft_get_fail_cnt() == 0 ? KSFT_PASS : KSFT_FAIL;
+}
+
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f27ec2ab08b8a5c3e3bf1056c7e270d484153cfa.1605305705.git.andreyknvl%40google.com.
