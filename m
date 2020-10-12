Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJEBSP6AKGQEMKANVBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC9B28C31A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:29 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 140sf18841254ybf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535588; cv=pass;
        d=google.com; s=arc-20160816;
        b=opcu166zhzKUs7chb9tlpRuO1BvTRkjYTIQf9wYhx8vsVD5nDiUlo3iWMQt9Qj6KdI
         TrpEl8ujDbMqxDi89i3JdMRwnOYUTZA3mHWRBEdQQ2cpd7pShxIfMDHCwTBnyORgib4R
         pwKGc+VUdOfoHTtEINrKozPeNR0rGvVfyWF1Ry77R3CRmTsE16I+nXHUr9ywbsZyvBip
         s1OHOkFBQgPweaS9G8G37XYlspXgtJmWpwa/3lVnrobFN9O1diRCogpjsTKYvo0VtZt5
         ynXNCtydHcXOWBlIRuNN8veAC60469wp6bnVFQv4TatNO+H5ongnf55wKuNNj43ktcbU
         g5Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=z+Y8xN+OsV/jsPeqOsJKzjZvJUoaNL0/4BeNt3VOaS4=;
        b=SgAcbAQBUQIYRJnE6B2MaoMB8d5cz8qZN4xPYhUZRgLzKKW8w75PmuHYVPsPIUUCQN
         f3tshUyhW+uFfs1lKnJvrFaEYIDCQiZCptkwF8F7feAGmSssv1U/hyvKtHcKmuCwXfLk
         rEjuMWwXsL1kXI3QGi64ZfUmVayfKBNM/ZaEY06utt4/T8cHTrEOz9WAqLoVrwMazTu+
         Qq7xgc7Xj1heK0hBt2VQKaDWv6/AanwKYoC7DSBuTTpC1coxA8untQ0Y+CXKHdnNBwdr
         71bRPAr3XMESuG0wjwZrXFXW8KJ7GD+cc9p9AZLJRIstlOLC+3x/cic08I0pm9ucSATu
         Ftdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6g1+CAC;
       spf=pass (google.com: domain of 3o8cexwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3o8CEXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z+Y8xN+OsV/jsPeqOsJKzjZvJUoaNL0/4BeNt3VOaS4=;
        b=QTWdBM7rYWVNFw/CmjORqLbMnxGL7e5BzAd6pn5pvCMAcd9ZWd1hcUQZVYn/azr0aN
         HFAHCG7Olhyn91rKpxyOxc+0YZ25x0HlE/bedeCdwhUdWl6U9zk/gIsah9h73omTtwJZ
         RqLYxHevSSuLWgiatFs+6LeIc7yaAm2qi9Ig+Llsy/EXrzx8wJ901pLyH8RmQFai39It
         zeLADg/Vtut0aAhxbjsGoOztN1nB2ht2Z08rtdAbTGK8gcyR2dBWZK5phg7QYnm+vlLD
         6/VgbXWMbBdm1mjQTvD46fzPywlWzQCIvq+kzwHobEbapMEdaqocgln/BRvu8vyCOokW
         8kdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z+Y8xN+OsV/jsPeqOsJKzjZvJUoaNL0/4BeNt3VOaS4=;
        b=IwbPerNHEgI9R7gnSSqgYGuy04wysFaTMeGvyDGZvrpd+GEHngD2cRmwpzy8b2VgF0
         68pw/1kjExOT3gI7GDTlWdcoWhQYxGZYicSKN7gNR5wC1NA6ApJWQ6ZTXkEr2sgyQkZ5
         zmUc3Z//Ba/oJuBNC13W9ywTu2UgJi+xb8S1zO4EiGir1/Qoa36+GOb5caBVKCXctlmT
         XoHW+xhpaKq62VDTELlTgYGSqbc8jlz5okeUV2wU2gY+W9NMyL7b++nJ4ScA3/W/gTsh
         nPejkzdBqvCPn5Ul5OpVjqAbOXGB/Qtv8ECgLgrdTaDMEcXQUqjD3XVGPtHSG3tiJMdc
         r67w==
X-Gm-Message-State: AOAM5306MXNOTDpFg5cnvlJzganuFVvzUlvw2jc8rIknUOBbB/94fS6l
	U1A9hvcLvpB2K/ECciaOEX4=
X-Google-Smtp-Source: ABdhPJwJt6Lv4m5Xo+0atmenFiIjk9u2/sYaOUy6SMpvdYTvLq1ecun8KfrlRfsZwo+AuVuwS71TrA==
X-Received: by 2002:a25:d145:: with SMTP id i66mr30635790ybg.517.1602535588619;
        Mon, 12 Oct 2020 13:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e0ca:: with SMTP id x193ls1238366ybg.10.gmail; Mon, 12
 Oct 2020 13:46:28 -0700 (PDT)
X-Received: by 2002:a25:c512:: with SMTP id v18mr37832201ybe.20.1602535588182;
        Mon, 12 Oct 2020 13:46:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535588; cv=none;
        d=google.com; s=arc-20160816;
        b=VCnLp14DEjG3yfHLz4IHTkN56406OxQLsYJSTvBGdQbnKFOwl3I0F1wqOZoqTWIoux
         oW1hMEDlA1gX7VhB8uox8XFyzD5/A2c6yv1IWdAzrxW42HqS9ZTcBYm4dTo31ka5TLqn
         diO5ExWlGbb+XmgC6VRlrH4qr38j8+3aGNMl1jua52kGs66xlZgvYa7A1JmJbTbqX95U
         J+RaFUFpTnW+A8TEjxyGoUGkNtxUL8noUFPOnGJAovsW5WkzLfcQpDQvlezMDNQJpgoi
         31FPY8FMQmjAA46xdjLizzEU6B4EEgrHHUN8B0FuizCFZauN52nyngvSFBmSIkKjgN4U
         SqRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6Ay9hGKrFkLJW+yE04W+wyXAAqv03tBt/hE876sMQgg=;
        b=yLhPgR9y1p5AiA6/QZqshsn/5YsXqGNeFbQHdV0zHQy3bVRbTfjzIz31iX2Mp9/CUV
         5v8ONGCtnw5p7cyTRZlqtwbcpJ6g4zz2uhYbFbBhLwmsEkrWBmsfrdG44SXCMH66rb5Y
         tFY/tXW8PaZkDPhsCYHhE72aw6DzFOnt5CoR3MEpO/rKdQIkT0W9Pg1xaY9kmxEosG6f
         MHA+KheYr7SAzjVp7zJhCC0p05O5/IxB8VBmD07atA/UpOo2Uo773mkLVKnxlbFL/qI6
         L2rggCjK8tNmSqXm4tjBL/WBZ7uTNAeVIthN/OIXeedjEKjMQI7ZVqk3ABFM6CuFIb4f
         MN7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6g1+CAC;
       spf=pass (google.com: domain of 3o8cexwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3o8CEXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id s7si1469705ybk.3.2020.10.12.13.46.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o8cexwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id u16so13489502qkm.22
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:28 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:184c:: with SMTP id
 d12mr27760919qvy.11.1602535587784; Mon, 12 Oct 2020 13:46:27 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:46 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <6313d5b812ac46c4a0b45144e8ca2383cd560edd.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 40/40] kselftest/arm64: Check GCR_EL1 after context switch
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
 header.i=@google.com header.s=20161025 header.b=m6g1+CAC;       spf=pass
 (google.com: domain of 3o8cexwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3o8CEXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6313d5b812ac46c4a0b45144e8ca2383cd560edd.1602535397.git.andreyknvl%40google.com.
