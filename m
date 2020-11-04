Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU7ORT6QKGQEC7X3KMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D19B2A7154
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:53 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id z12sf218722pfa.22
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532052; cv=pass;
        d=google.com; s=arc-20160816;
        b=lg278BRyZaspkFtVGPNpZImjbfjF6CJm/mq+49BAikT5zdQte5xfukhdae6X0VMaI5
         xX2Wk8us6LxLbYNDvha45IKekebpZYp3D8PFubdDAYuqdEusaO5FsPs0ueER9RaOgs7J
         /hO0cvENW/72SWbAoF5PzlcX1h0XZBXSbtU2ojMBVEP0YeOE33Y23Xkw6yCAwXWTD3tP
         ihr4WLn06l8APvfNGNeMhtb8WhZ3CHUAIJjPdVxFY6HheJpY3EGCndxLRG8ad3qOda/v
         pZEip5DTAwsyz9b1HUCOhk4Nti5pEc+sDhvNi8/KpaIyXF3/rgHkzr2vgy97b2PjYC+x
         qPVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=g/7PXTkBb4JgdicL+dmW3idJGWwfF5tkIhpoiTWdnyY=;
        b=HGeGjRLJk7piDtKbpgEtAEKjf+aW8jaRXcN1jsU7Qd+/1nS6YwEc1gmpVxN1vj8zb9
         OmFz13zKsThdqnysPSYdK3XmJTTZ6emUjYFFrssZkEomVGvapI5EwMwQKyQNnx7bK6O1
         xgsgxiV28yHBNSc6MYC2YlcQZa10pgJeoY/RJWg6oiwmpmOKrG24ySndG7ARxPA04t6f
         1SOqtMoDVrmow7iWBTH5JxNjnCS+6kmHZTDSxFGNuLlqMpuMzl+4BA6h9rUPK1OBudcE
         uNkmQGss0GS6oj5pTPCcaqoVPMPAt5RA38TaOaf+cZd5TKe87nyhAy+0qFrfG5i7Lnf9
         XdoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=coUp8usP;
       spf=pass (google.com: domain of 3ujejxwokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3UjejXwoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g/7PXTkBb4JgdicL+dmW3idJGWwfF5tkIhpoiTWdnyY=;
        b=YIhhHvZKCCou4MoBZ6CfzYK8yzJsbMoag0aHHWB7WwnTzen4e1iYeyjHowssgyPkEl
         tU8Yy0SZLalvdlilWRYgN2T06zvr0UcSm0WFwUoIGhMUCqcxLOTjIpgj3vIJvJQEBzvO
         wbX3BtXbOjR76eNHPwYSOlr0b24aiDgEqAwj9xIBu5QAL7EDK7bAgnwFdA0beMZpxUe6
         z2Z9iLRAxByYNUDRcIDAu7oMZgOGWKPuH2zdlpWETi3/owIOpw95XcmzWstPZhfjufpU
         vBJg389yqYY1cLp/lEq8t91394CopP/ja5wL2neI3zYGqymNDTPQZQA9598mbGO6cch6
         PnfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g/7PXTkBb4JgdicL+dmW3idJGWwfF5tkIhpoiTWdnyY=;
        b=NEg9Cb0lYzEOkt+IUoy7nNrIrCSit+L14ALxi99Z6R/zE6drsVinKe7ONydaWo3jJF
         TF8xODIj5u355armtLw4wl0QSxfVyGlT4gy/ZtYFZO0IZSbKIrGni5gs6GCWKpdo8lKp
         4Hnt0Zz6GUaRvGf/BF1+rpzDVL9AAoTAu9deWxUb2hmE9olAqTwmHrVIo7FqvB1x6eIl
         LqwHZ76srYfwl9yTi2cv8lw8J18M3ZWlHLtAher6xfthNMOovRDP9AgPntjbZ0vJ8BNs
         LZoZnwpyaiOKKKQSOx4Z01pTZ4CoIGuKbvuASWpcICQ3pAQ7zhxYqRU9+twMKzJPXi43
         waIw==
X-Gm-Message-State: AOAM533EpIwCs8mrE4bgWq2VvKCnO99Df5DQPZknLwI2eSRK9maJWt6s
	Flk1yiNPUXoDyo+QCBxN4eQ=
X-Google-Smtp-Source: ABdhPJzjXlQK77L8L2XWmE9Lyx3vP3aOb112vphT0XKVLpKXYrqSKWtLkFER4L6ZdxgIJlEkDmY7oA==
X-Received: by 2002:a17:902:c412:b029:d6:2939:1b75 with SMTP id k18-20020a170902c412b02900d629391b75mr295153plk.80.1604532051921;
        Wed, 04 Nov 2020 15:20:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d03:: with SMTP id s3ls1945137pji.1.gmail; Wed, 04
 Nov 2020 15:20:51 -0800 (PST)
X-Received: by 2002:a17:902:d698:b029:d6:b974:13c5 with SMTP id v24-20020a170902d698b02900d6b97413c5mr377555ply.13.1604532051382;
        Wed, 04 Nov 2020 15:20:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532051; cv=none;
        d=google.com; s=arc-20160816;
        b=Vqh1t91fTvfHF5+tY1Ff8YiJfkqROyBT8uOyfLt7zQWKSXeW6atxn+BGch8ltbs288
         lR7yW26LFtDbfM6Hq1j89x2H8a7/9gH9Ve7wF76C+JUexMivljnTInKpeg64lGQBKzcC
         /P7HNSZM25HoH6HXt8dDPFMp7PPRWzS1cfBo0q9fnFiRAaQhgV61tRXXjs5pTLCweQWM
         LzrrAqyp5v0AdIIObZp+F2bX1pmc3pySyaTh88pV783r238qdN/Vc64CKjJU3xQrI8nw
         JTbKahuVPX07e5yqUs3HDrbg5eZpaHSgwioKvgIqm8PBM2RkpfpiiiLr99PNWbAYbetQ
         7I3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DyRPETqC+6C7nrnJCiEiYsvRb/HkPFaD35372QKa3Vk=;
        b=ih/VSqvq/n4rCYhlZvVF1O8OLt+4O0UsIPFYMZWh3DUA6CBiQFbT+boNMLzueUoXwD
         aob3MBIpKbICr+bVZGoMUQ7YiqL0fcsgEkPqmmUaG7NyGMSb47XYcWtfhFScu/Rf9LJN
         8aKDP3BW/2oi4cJJ9zvFnBhsjxNYSKBpDBwSNRbs3rjYpQnwQ54cca6nXpphuflha4AU
         63VkVtbT56bsIDWVYeFMj9iFd700vl8SjCjICpYHk/3J77ebbDIupa/UGk5q71TAu0yg
         awwT3Mnz2GhfGJhROzczwcR4ZcLVzn2uZxeX5K0m6Q4Zdvti1HV6I2udNk6FZsxrEijn
         yABg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=coUp8usP;
       spf=pass (google.com: domain of 3ujejxwokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3UjejXwoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k24si221480pjq.2.2020.11.04.15.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ujejxwokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id e23so9481118qkm.20
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9bda:: with SMTP id
 g26mr294283qvf.14.1604532050508; Wed, 04 Nov 2020 15:20:50 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:58 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <e31d3b892ec0e206f5940c3d67a6fdb1e0416d38.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 43/43] kselftest/arm64: Check GCR_EL1 after context switch
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
 header.i=@google.com header.s=20161025 header.b=coUp8usP;       spf=pass
 (google.com: domain of 3ujejxwokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3UjejXwoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e31d3b892ec0e206f5940c3d67a6fdb1e0416d38.1604531793.git.andreyknvl%40google.com.
