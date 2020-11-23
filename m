Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIFO6D6QKGQEYU6EQ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AF762C1564
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:10:08 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id d2sf145551wmd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:10:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162208; cv=pass;
        d=google.com; s=arc-20160816;
        b=QSBlZLr5O9daK5N1L9iEkiOVMsWa3h9b12jAn/UslMnaVy2XuaMP7P2skWc4JKXa7x
         Tc+YtIbhlySup1+s8f/tGHj0VJfrQH08PPP32TOM8EMBT5QSp4u0xnTg5wObdDeL5Af1
         CXc16a4pc3+ycCIg0E3UGLqfbqGyLP+mdjfUO6N2v0WaHO2MefAkAjC0+/Aj7aexSo3h
         DrcuzXcHz8jgt6CHXFdwmSTRZ8kSfKzD/Tcbho4PANgV7zLoWBvaS2y1qxbYvVlZtuVH
         txgKAQPlZh32U/zf0LMNeboijWuX9jLrdZeRCgFeTipw+a/V+2KCLaA+Yy6MHKlvVTEm
         byWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=C9V3wYJwy/DmPCuz5fqs+ao0BcX7NlRuK8P44TPxXD4=;
        b=PMsPc05uPGfNMcfJhDNs6ehUAGN3fL59QuiH2kh9vbm3XfzUNPOLSN2wBw3bbYZKiI
         RaOf/iAroU6cJ6BtTfS8PMd3QRKDcQ+o8uaqHFPeTI1s4LjUxFrj1y6tzFazwfzSe8Ra
         HybNg+FMEHdRzHQQJZVVzY2HMOqlrsgd8eglOBJhXQSObkxkYJqAYrfjkauOKk7hT7P5
         0SyY4XOJI0G53eDlKPEh69yxIwT6A8sEYD8QI1Eof4Rq5ELJlAOAwtAh+kellqmlG+js
         jctDufZuh9yGatGodG8z7xva2FdPaxPPYJXTkKHTy+IV2YwmvFhVZ8CV4YcVFTan4+wI
         JW5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WN2+Wdix;
       spf=pass (google.com: domain of 3hhe8xwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hhe8XwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C9V3wYJwy/DmPCuz5fqs+ao0BcX7NlRuK8P44TPxXD4=;
        b=Cj2ORGXEvWJGyizZldsYHe/9WkGBXNuLzH5LIXwieQd+QRVoqrQPqvkDS0bHubf2JH
         Y5J0QXZiaKi67ttFdQDgzLP9Y8vogrot9fBA5wkH3W8TPIVtHKu1fpWngu436oAWKdOT
         3kLOWk+9vSM3rmas9S6zk8lSi2KKXBFazJr1cBiDfZl4WTdTFWMI5QCFHCA4gBfnLvY4
         TYriAbk663C9i/ZZ8ru1HO8C9Vl5F1NqJ7bf5wDx678uu7Fm3L1pJgMQhVvYZShyWK+d
         tEHqIfuIaTGwCH+us1S9DlhscW35bs8hvGp0KExSIPHEYui6jVHTIWw7G1GzFXf2nwK/
         YnhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9V3wYJwy/DmPCuz5fqs+ao0BcX7NlRuK8P44TPxXD4=;
        b=bfI7m9vlBBN/N6CsHPhECqatHEMh4fBJsnmEk6ZQYBULWqYSQFCtCE0PPqR7R5XQHI
         shN3gLXWk6cobfi/bwDokiJFHE+2yx7LtFZHpLjA3zf9rnimBmQHb+r7jzDS6TyzBSw1
         A3PO8FdhBv/gYCjWymm41rFWKMDIMNDDmEl9igaBAFz5R91EutUt1r9RxQx9qu7sQF3m
         6KdoU9cu6mcjbsYTuYBwobd17waTvePUMA5ztG34vfZWH7I8Y8xts5nw4A3KPk04AH8D
         vMZPPHF0UsVOtX7ZdTEK6D3bs5i8aRZ9fdfyte9rRCwi5cMP6zb3YS/5FRR2RtOZWBki
         O/Ew==
X-Gm-Message-State: AOAM530cV11tWJXomo0UZuw9/UBMdNaRSq7QgJPOGsO2oKK5W9pmTSPx
	pcxlVU9EQOa2gghotC16qBw=
X-Google-Smtp-Source: ABdhPJxvbtHBwmpRET0CRMJqPjNvb+j0gfwZAy8lwSlxtciAZRiBYDtXPCNHXyOnryOn8hbv4bEAMQ==
X-Received: by 2002:a5d:4e47:: with SMTP id r7mr1481676wrt.342.1606162208185;
        Mon, 23 Nov 2020 12:10:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls8966178wrn.3.gmail; Mon, 23 Nov
 2020 12:10:07 -0800 (PST)
X-Received: by 2002:a5d:45d0:: with SMTP id b16mr790072wrs.350.1606162207361;
        Mon, 23 Nov 2020 12:10:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162207; cv=none;
        d=google.com; s=arc-20160816;
        b=CzBPegVeOErfEIq03TbevwLWxLqgZC2MpaNz4ugkud6gvCV8g1e/7I1ObPiN4hDZY4
         PAzpxksacZrjQU7wHTELatv7o+XdE07SFR65mPfymCRkedY4dQPLFvopasLe87c2eNh0
         NT8GyHnyu0qkauWB7SGkRLubxarQ1J6glePInYHsIcSCV5BAYzXxWZB8X1Tdq1PQMrZV
         RzjvNTTwlofeLVz0zLwGIvfLJ+3t+JV+ao1DdoOdQTWOOFdr7BnKgJsn9lcLXsYsHH9U
         jeW4LqaZzNWZ9mnHksvQj1JdXfDzoJlf8IKK+SQ0Y9QAaLyrp0J5zvr8U/jrB8PRaSx4
         LDoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hF9TK0RyS1YTrryY1Q/xCWNy21LxBIwj2x5LKL9MrUU=;
        b=eWzNTJjjdK39zpN0M5Um2nado9jARKn1WtObU15SBCC9LLez4pveCQ9QPLQhheQHbx
         BfcJN4+3XScpsMKAiCqOFaUgpQs4erk35aY45wA5mk8rsoDjsXwypnbpJEX6AQnt+tM3
         PKbzCwlUBA6ddbpU5yMp8zeh9QzrpVtXePN+1OW3dBIZsGllRD0PT7Axf+lbLihYOK1j
         s89Q1PO+Tc3tCu8rKcgwo0KLYCcnXzUAPP0GwtsPXIgnAA57HnGNrByupp0M+kvSQ77T
         rRHltcXO6cL+HOZB8s3OGkrEFGTUpftPAssn+Nbr1FjtRGBkbpEbevEeNcUGHgpcN9t9
         p+Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WN2+Wdix;
       spf=pass (google.com: domain of 3hhe8xwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hhe8XwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 3si219762wra.5.2020.11.23.12.10.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:10:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hhe8xwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id x16so6248794wrn.9
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:10:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:791a:: with SMTP id
 l26mr202416wme.1.1606162206684; Mon, 23 Nov 2020 12:10:06 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:06 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <b51a165426e906e7ec8a68d806ef3f8cd92581a6.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 42/42] kselftest/arm64: Check GCR_EL1 after context switch
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
 header.i=@google.com header.s=20161025 header.b=WN2+Wdix;       spf=pass
 (google.com: domain of 3hhe8xwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hhe8XwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b51a165426e906e7ec8a68d806ef3f8cd92581a6.1606161801.git.andreyknvl%40google.com.
