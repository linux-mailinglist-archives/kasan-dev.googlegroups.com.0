Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZNAVT6QKGQEEKNHH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 994912AE2EB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:53 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id c8sf1161269wrh.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046373; cv=pass;
        d=google.com; s=arc-20160816;
        b=H9zE9MiakAYLRgkHH20QsxZjo6zFoyq/eY2SSnYd+X9/ccrqiefMT5AvwiVmS9kK0z
         P0azIZvD9zDX6VM/wyDx03P79EG+hL3G6dMfENmB+EZ8LCekVP3N1eINbfvKb1M+JTvX
         kC6CUe0+YgrsmBuSc06YLu7ipE46Gcck1ezcGCJbWklpAgqd88+AdnqQWGNINBmPasqg
         IDryPm/QEDnhY/JPSQkBV64qUzivoqUh6bo//ShRJEwHZIwHdZu7fJ9672ICa98ffcj1
         5b431w8XpF7Krfp7joLkl+coxds7D9yfGSV7wrqLYZ91sj1qZeI2jrBEbFGQLaz5zTZm
         e9MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3AW4lx1omaNhODXVpwjA6HTXBM8I9VRzOT0S4Y6JsMA=;
        b=d/5wdYJUUbcUjPGiM+IwSE7eRMnt2GlxDwCVRZSwlweETs/weUc2H76XkbU3WeUoOC
         DUm7w/znvgrVwdl9rHFhovQjAwJyL1VU97Td8fAJ2aR3AHVKqvPWFKdCEYkt6i98l5Ko
         5PjyDkMiSh6YghvY1brs3TiY8zlMienD97P+zqHA/iH6x83W7sN4Jk9SsKGi3DvztgB9
         R0dUECZDC/7zw6ovp+tWrAX/T38BaQbi9msljG/w+YAX5FJuvPRMtGza5FVJJyNKpAE9
         pzJRMfSHywXpg9wsGNHgIyzZOzdrc59JivzDRR6G4exw0zPaXs0+GQ/L8/5ol4WfVEvn
         HAzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sn0Rmbep;
       spf=pass (google.com: domain of 3zbcrxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZBCrXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3AW4lx1omaNhODXVpwjA6HTXBM8I9VRzOT0S4Y6JsMA=;
        b=YDm+YJLz9dtxf3gzjePWO6y7MsOzaja8RfYRy0moeO4sFay2/Vnva3Exw3nymo5qjd
         +lz5gEHKpbrTzAgfAoDjrAy3Y9wTgdQcGVyYAANzWj1jGLXNxQy/CqK8oL7q+r1dIWCM
         eEzEEeBCYJ+tQIVFgnC8pJh926p2NHAM9OgXDzeN4D2PKkxQzxcTXZV+iFoqEnT9vpZ3
         Hh7AeLtn1X0mc7L4hMGloVTR77hHiBC4pr1tYqfp0opI0sYdAkm2YhXX6T1MTiNl8D2E
         pMM4uhU/b57KRHvh6aAQ/Zbcec3uSeLOa2BbWznqxUWbhmQxThPC+fzkHUhJnT0CQaNM
         5Nrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3AW4lx1omaNhODXVpwjA6HTXBM8I9VRzOT0S4Y6JsMA=;
        b=PfxuI7cuVxDlwcALyriOGdgOzZIuxWveuyXij8OXxT1pjTvDkIV4AhhZvQ3JJkV8Ua
         IC6KheL3lX8Ru0tnay0TW+c+eQn6UT33xPB1Fem+hB4mQu3XMflRgt/arU7/RpVGYX7/
         n6oWRxRi2dXae5cCMuTjLUk6FB9084eoNyH9LMrKRnYM4U2XnflaHA/RV7MyvXnVzlz9
         r3rkHbDTqQj9OFnw4rYjP4wq8K8rR2JvpsfCxH+lS/qDZP4aiP/6QRMtqz+9WHatQNU1
         /s+pWNynBWObPKaFKcNuy9JWelAXSTW0cmacfEaOtFibh0ZGyJdwEN2Denbk+uJAP4jN
         hxow==
X-Gm-Message-State: AOAM530owc30mGxsiwHG3jTOxSM9LvhV0GYNMZrQFicKOerG1WD3Dgi3
	/1UyU3IJDKjuWIgilWyVQe4=
X-Google-Smtp-Source: ABdhPJx5R7WgNVIc/QXlO9PTUKXhTWj2E2DiL9xnHwdcSP4NsMlCIV6sGJHaICTWdTohn2ypDhi4oQ==
X-Received: by 2002:adf:80eb:: with SMTP id 98mr26993944wrl.101.1605046373407;
        Tue, 10 Nov 2020 14:12:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a544:: with SMTP id j4ls463359wrb.3.gmail; Tue, 10 Nov
 2020 14:12:52 -0800 (PST)
X-Received: by 2002:adf:f6c2:: with SMTP id y2mr16285441wrp.41.1605046372640;
        Tue, 10 Nov 2020 14:12:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046372; cv=none;
        d=google.com; s=arc-20160816;
        b=MBwHFQFEkLFQmJXvOMsiDAN5elufHtnU7dIKJYHFRViSX5eOXcmwC2EP8zdMlL8MbN
         MbjTf4xunxUIviVFx6UeE4BxkqonTPAZscioGynt2bD1KEKL4C9QSPQUUD1Sfr04zUUp
         hHF15uMeZ9TMZ4/mYbaPlqDVB9kyHjQeR1/8WmDIwKsXpl5ucwd9DGL/9YTaaNM69/Jp
         B1jsJzY7F0grr3DhqW7+zVVKoXug28X/3rdWhjXPiV4Fy4SN9QZbfxTkNb636gpnkJV9
         6HZGUynhM+XzvSQLh7d4EdZmBYiKqKWHct1/ovBqFPS7G27oz1kIwLfmrX4CTlqHP/3B
         OFxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gElbIAirXSeZEu+ZxUvh6N5W/Nh8clkwQRgJHSlXRug=;
        b=YGfu8SKtKVdPLPD2dJTI/zuQHIY5I2lH/aLM5otBpW7XaVnl38ig72rhEvM1KAhqwS
         Qz2idI39S6WEX3DtKg/BmcAEsBcObYIVZUl6ZxoOt9PHRd59NfORoT0TBtHxS3UB5bew
         gvNN+vrenMx3FDhQlz3guC91I9Ys7qG8EMCjyAvEnNsebQkQVZn+ItVN4eFOghhmKXS7
         nTZXP2mBznMm8DBterBto2nyv/EBqHy06YWcsG6DQJaxrApgMLwtmURet8HoKsTaX8c7
         xM9L2isoI0lyOKQpqbhXcNk1HH+5G793mTd08u4czAF627QDD0QLRh3XtZ8Bfey8Ow+N
         wJzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sn0Rmbep;
       spf=pass (google.com: domain of 3zbcrxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZBCrXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c20si135305wmd.2.2020.11.10.14.12.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zbcrxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a130so1671484wmf.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c1d2:: with SMTP id
 a18mr251913wmj.41.1605046372211; Tue, 10 Nov 2020 14:12:52 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:41 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context switch
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sn0Rmbep;       spf=pass
 (google.com: domain of 3zbcrxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZBCrXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl%40google.com.
