Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3W4QD6QKGQEUS7CDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A4C42A2F2F
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:06:07 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id b6sf6558590wrn.17
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:06:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333167; cv=pass;
        d=google.com; s=arc-20160816;
        b=VrnamjH8hGTlP/tkqZZ9yA1Cf0pU3SUV0Cf0RPkZxzjQhVs5QIZCNmffAEn9/VCTAJ
         KdRpmLPHJuP59C1Aex43ulwpCDyEA/wkx0kCak1GMMGQqCbyMe22olKR/7bCgjkJcF8Q
         pfzaFhKKCUmlCu3zTxbqIPs7AchCTv718BFPirf9yTWvBnZLU/umOWRTrz7EYxzcR9Qi
         cJaKXKWrXBP7A75gdiXdYohD+45A9EQQoO7589lluDTaQzJ7W9z8cxbgB0Cr9o4/1BZa
         DsVyJqNld+BiUgAnGvpf+F2C+O6kUdQZcPnFFBRyX3WCSINeIPKpozUeY4tiVDnMRpnp
         wiAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=21AifCaGqESOfx4o26WtBWr2W2FyFX7dmXB7joZdiHA=;
        b=sRfR1QpI2T32jfxurRzchuNSSKdSwJ0BKgNsObgiHcrw4C6FcaK404Lllv7HLxRhUD
         JK3KYeEdGkzVNaJId46jkZe9/NBiBc2IDCU1hmFduVftUY5ZFleBBPQRZYiUz4/COBeg
         2+f5zqUmMeMzU1gR2Kv87GchzxCa7grdVuHmBIqkcWgQr8FvNDKqpvzm3PNze/THPx8a
         fqJGa5OqTxo8gb0YUrIOLWYBsTBJmBdfrssgYp+3OvOVXk8KPXov2/xXl6q6xoLzRVd9
         1fyRYvKle8OcCaeeDVbwoCr8b/jzQyaHkbh8G+ht5EBp670J7HVt0CSQi0bsXyenaUtP
         eEqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i9OgmUra;
       spf=pass (google.com: domain of 3bs6gxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bS6gXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=21AifCaGqESOfx4o26WtBWr2W2FyFX7dmXB7joZdiHA=;
        b=UCkPDzLrQ7hoPzNw5jGFgKV+y/2w05LtyI6rINOWNJlSlqzV33UXkbgAHrLQ/VVotv
         9Lc/NfZoTwBSOCE7fdMohUjdMdkKkcpjRWjvacGaMCXayl4QTW5wuQFwb8xUPm6iX7to
         PhFobTPLB6SbXCQmHM4HOn3PKRMZmE0z/CiUP/cU3ZdsLXdLQn2Y7ymm1uq/bC8e++WB
         dqNYKwNoIn61Ue27A3lHUT9lU4ua31brFfxFYaZD5tsHKJdfgGdEGv+ZVkkKECo/1Y3Q
         k22sn9mFTFob9MKD+uGVO+b55MtF5/Bqa99wgBRDLvf5vEBIHq/H1rTWAE0jLhGTdKtz
         a4GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=21AifCaGqESOfx4o26WtBWr2W2FyFX7dmXB7joZdiHA=;
        b=SC7cu5rvHkVQ3ZOyNuFpnV3HfWrNPJjOd4B8RpZfdBtbmHeJuMo9iV5VTPkFK66WkK
         UfVRxYGhN3XX+Se6n4cwHPofxoh4nYvKDZdBIbz/oYa+8gOCe06hALKa/XDNSUkpXVmM
         vlJfUxtUdTKvCKGpV4rUaVGPB7WAsT3JjXIH4OBcBCxT1z7WnLLeJk1IavVcwPKnF/OW
         cR4w4SXNK1aPgHyIFw0qejv4ghTtUJ6ebiurzWEHJm57jQRjdcnOhYn/l3r96lsWBKuD
         /XIF0UkylaPlczRLQQNBOQOfCc2YbTZXRM+04jKjcQu5mDVBBvSdTxf40vlcx1PeDHyG
         b6TA==
X-Gm-Message-State: AOAM5315PTT/3CgfYHhuS7af1P+pYGmxiKfqKS5vSPqzCoDjBRSBuMt7
	nhajZti//Eqsv5zQspDhvmo=
X-Google-Smtp-Source: ABdhPJxJEz6mYPIyqvUAcl3IeJ+RX7JmUO/I78OC8SWyLXx6KRK1ROWd1Ibebg7syOtF2wiQKfy3RA==
X-Received: by 2002:a5d:66c9:: with SMTP id k9mr22968962wrw.158.1604333167078;
        Mon, 02 Nov 2020 08:06:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf0f:: with SMTP id l15ls8943wmg.0.experimental-gmail;
 Mon, 02 Nov 2020 08:06:06 -0800 (PST)
X-Received: by 2002:a7b:cc94:: with SMTP id p20mr8476003wma.100.1604333166012;
        Mon, 02 Nov 2020 08:06:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333166; cv=none;
        d=google.com; s=arc-20160816;
        b=UlRcBv0A4oHngp6BTxxnI9bNQd06SSadH/rN/LrscHmy2zaMHXVE5iR+ZiP2MP6UJf
         cHZ1p4ZJdPpQGCJUdfB+/QTNCTzgCOp308FiMJX25b2lCpQFHzm2gG1cRy/nXrE5KD1c
         WUFsyNziEt9CL0Wtgm+e0FDlM46EeiorLMmVVPVh9LiF5Tu2a8E1AAc7K7mPzlAn1ncS
         WCUcU2dET8GOgiXPeFLdqXPCcPiaEHPtTotoe8YF1AAjzEsJ5ADSyQK8qOYqR5qljwwn
         XArwRuur25Sn5GzUpZs1HMpY6LXs5SjioepphEPJslpU2oh3UiXAMPqRiwUyPV9qtH3H
         nWug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DyRPETqC+6C7nrnJCiEiYsvRb/HkPFaD35372QKa3Vk=;
        b=xdhibOzuctDdrBIXMhJrXlOKNgd4XLbKziqi3BAcmtEGvDH0QWauFEBhRGXkiz/EwM
         KqJt3DtbrvJG2cYpiBqI4lXS7S+aoRqhxp/4sBOeF2BA2Nr4qkfrBCJfkhSt1EB2t43V
         Baj+1Ts03z/7hRbn6O2GY8fFlBAoPd7dvl1wUp9iwfT4uV/ZF2rCLZlSnwvbUS3qhhlN
         ffpW5MZ42cb+k9EuOMdabDksbvWpDXuNSfGNL9OEvmg+CF0c7ERvfgVXXu0n4m3Nt6q/
         24mXDihS54utIDdtfpkzFTmi81Del2YxPniT2bfWCztvgpO13CKxJYK/5hF89Da+OdZY
         Ixgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i9OgmUra;
       spf=pass (google.com: domain of 3bs6gxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bS6gXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f131si294777wme.1.2020.11.02.08.06.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:06:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bs6gxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f11so6585579wro.15
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:06:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9a83:: with SMTP id
 c125mr16775191wme.116.1604333165725; Mon, 02 Nov 2020 08:06:05 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:21 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <8acb10b144678de32f1ec8fb5ed6c92246967285.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 41/41] kselftest/arm64: Check GCR_EL1 after context switch
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i9OgmUra;       spf=pass
 (google.com: domain of 3bs6gxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bS6gXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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

It spawn 1024 processes and each process spawns 5 threads. Each thread
writes a random setting of GCR_EL1 through the prctl() system call and
reads it back verifying that it is the same. If the values are not the
same it reports a failure.

Note: The test has been extended to verify that even SYNC and ASYNC mode
setting is preserved correctly over context switching.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: Ia917684a2b8e5f29e705ca5cbf360b010df6f61e
---
 tools/testing/selftests/arm64/mte/Makefile    |   2 +-
 .../arm64/mte/check_gcr_el1_cswitch.c         | 152 ++++++++++++++++++
 2 files changed, 153 insertions(+), 1 deletion(-)
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
index 000000000000..55e33d96794c
--- /dev/null
+++ b/tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c
@@ -0,0 +1,152 @@
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
+	prctl_tag_mask = rand() % 0xffff;
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
+int mte_gcr_fork_test()
+{
+	pid_t pid[NUM_ITERATIONS];
+	int results[NUM_ITERATIONS];
+	pid_t cpid;
+	int res;
+
+	for (int i = 0; i < NUM_ITERATIONS; i++) {
+		pid[i] = fork();
+
+		if (pid[i] == 0) {
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
+		if(WIFEXITED(res))
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8acb10b144678de32f1ec8fb5ed6c92246967285.1604333009.git.andreyknvl%40google.com.
