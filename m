Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMVP5T6AKGQEUL3ZNCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E55929F517
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:47 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id j5sf1649049ooq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999666; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCEmyLwq8i8LKLTUZreJL03SifRFUxz1SDrvJ8sywCz834B1TuH1oeADxZWlpZ+OIF
         VpMODtnDb4Z5cAA+ZoO9rBURZYvbtv/kp7/RgNOkkZKCSUDIK+IdZmfbE27dvUUd5fXQ
         WkfnDdgotp0WAMZ5Hcn01+lqoJKx7UsGyKmcD53s7eYLAT8pZ5qwlWQWVAO2fWlYeIEz
         i8Xx7LhwUjB1oPNn2Ex+RtGULbWH1OlocXeQKvJRQ8cL5EI/X+wIlC8dgAf9cwS7rPyO
         Tz9Llb7RBQtzPQ1GUeMPhOa0tTJPBYF5wwglOfZEoy8EEKsjI4gf6eA/FBw0++a8rTLL
         15Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=cxIZW+xIMClryWHkuVcDKGYRSn9ZQMg3hZfH5+Sr+As=;
        b=y6H72+/yM4+TUruIxxBIjeGubrgXm7lSUaUbpee+OjxKcWRZvWyw9IPlAZ0acTlg86
         4NSZpsutbqSfMSJRpgD3yDsiJTvQ9hUYkrTSnvz7Ehz/dgVLJgOIg57SMpvW6XIcCXvr
         BQZ6DBFzo9Oczfpst39fiOYiN1J0/9xyYJWdJ3e0DZtfqXw4gA+HI6SxX7yR0tobtEab
         Q1WOqaypZYNxorI1fF6ul7Jeu8koV/kzhLNbHvLiA4pgaZakhT0z/vbgGVQCva4NJ9+g
         USR4Zc1x9Okl2roxyx+7v/PXsHreL7g06OWv1oCBuVbi9sEq347Q0aEGbLWt8K1aqtfO
         mYLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r4eQGe9j;
       spf=pass (google.com: domain of 3srebxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRebXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cxIZW+xIMClryWHkuVcDKGYRSn9ZQMg3hZfH5+Sr+As=;
        b=RhpUR8l+mEwSVgij6qU0jFFt/zaZbcMCU7Ki05A93+4jDNZar9CbxqkZVOuMjKan+u
         xke405D/30clRh8FoTWyoiSkCVuOViWouwZYahcemGTythXcOJmjh6sDIpfe5bbeWHMn
         vaBI+hQEXfm4xMbfAqe0UPQA4/p13a53DoV7BAleI0eI9Jgs09aeuF7DtAEnVYBV3WQD
         1mDfq3sX6ucGq7dP9GqXoO0ERwD4Gh6awxqMIVP6xXcdptJc4PBt8fyW+1OBFzDtUplW
         RnRtcBA6syJuYxVMz+CaijsCuTiLr9ZwIJiIAeGoc0wIyO8gM9PJlv9/72nlsiujeChJ
         sZcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cxIZW+xIMClryWHkuVcDKGYRSn9ZQMg3hZfH5+Sr+As=;
        b=fOvvfWdn1qG9SjJ+3uVDkjd8dDwNLnpR0p0eq8CQ60VScwNwuGyHX2I6ic8O/sr1I2
         qy3lTQwwinLtSXPL2iDFgNwXpjip0n0Slt2TceooG/Dx7YGIAMn+dzcTWeKf2fHeOzEj
         K5ZaZGV+HbMSCpRZIPfzfenGtwx9xkdImmI5Sdh6IhCxFYuGwMxiCUjrz6HWeqtHeI9r
         tuc6u4wvBaJ2Jyar37QW8Y1SAbl7r2MUbfKeHd4snHwWJ7zJuwD0TyBkeI/MJh3W8Ubo
         vkxkjyHZVbZ9qYdb9ZIn+2PJI5u9bZ0+wv9pbcC8/AmVTXzDrYBwNGb3XNk2GQEiMUcR
         O67w==
X-Gm-Message-State: AOAM5320sN7JKI4fjIX+xQAn1EBrLv9cDCq2fFd5AiECbE0Nb1KxE/M+
	lp8iWr1FCMH1QNMy/iHqujw=
X-Google-Smtp-Source: ABdhPJyuCwTRfbY/cTOIi4TDghDnFS4B5jNI4iFu3/P3hyUwV3JzkcQcq3zvdWt3sPYoJCCWZMNMXg==
X-Received: by 2002:a4a:e04a:: with SMTP id v10mr4451068oos.24.1603999666106;
        Thu, 29 Oct 2020 12:27:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls950487oie.2.gmail; Thu, 29 Oct
 2020 12:27:45 -0700 (PDT)
X-Received: by 2002:aca:1106:: with SMTP id 6mr894163oir.104.1603999665717;
        Thu, 29 Oct 2020 12:27:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999665; cv=none;
        d=google.com; s=arc-20160816;
        b=KDQ/hpcwNzT9huRKzzX6Si1pnbBei9Yz8upRz/qUGLbr8LaxyIeolZdWDD6LhRUNY7
         Ti977q3F3M+gEuY6DikNrOWMBVi/p0APyQejR9WmEmMF/6oKuYFeD3Fm3x0GMj8PDjWb
         dbQC3BCELwkzjT++KoZDORuk8133Bzd6aB6c8sCJYygi05HQEfHMt0WpRB/HZetytN76
         ulT9Ym96V3oOVSKkxRhMVlaAxOMGyg0/9cXdNtPoTLJTRXLa6wJ1xQb3LPTrYYbPP9tq
         xyJbk7gWyIXVWa3CkwaWKXwWQZqzzOO2LD9+OhvuDi4/giOWRrTvx5t1GvWnjupLnnfq
         U2JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DyRPETqC+6C7nrnJCiEiYsvRb/HkPFaD35372QKa3Vk=;
        b=iqnMBBEFXLkEP9r/urGvm0EinroVBaHIzTnxebTXaLjkXUlPSsAnN1tisz7dlK7VZ7
         ZQkhp6ra/5ZPjoLK5n4MJi8wh89Fixpji13ceRwbDiqaEGYk+xqA2GnXZ4+V1GTWxGNi
         iB27y7W2IU5TfcWx5h7kUBc+NGc7gqer6/djFCleNFXIZu4YqzGJWsLgdh1fWoo0lc6H
         tXevV9YBIS8vfbWdkfVYhJkh7TCV93ZXDIhEqEB9Kd3lFxV+gwrDwHziSv89zcyetCav
         vK6uxZk6jPdXjBHzqF3XsVXebFjAT6SOCXKOgc0H18wKVkRn2l1xLoSpYpMQ287wJ/wf
         3G4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r4eQGe9j;
       spf=pass (google.com: domain of 3srebxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRebXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r6si526786oth.4.2020.10.29.12.27.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3srebxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id e8so2495427qtp.18
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4f46:: with SMTP id
 eu6mr5891999qvb.9.1603999665355; Thu, 29 Oct 2020 12:27:45 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:26:01 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <a8cdc9741ef6b793f760cf267036b999c8326bbe.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 40/40] kselftest/arm64: Check GCR_EL1 after context switch
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
 header.i=@google.com header.s=20161025 header.b=r4eQGe9j;       spf=pass
 (google.com: domain of 3srebxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRebXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a8cdc9741ef6b793f760cf267036b999c8326bbe.1603999489.git.andreyknvl%40google.com.
