Return-Path: <kasan-dev+bncBC33FCGW2EDRBN6LSOAQMGQEQH2I7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D69D5318616
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 09:07:19 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id l23sf4236666edt.23
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 00:07:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613030839; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZfAetpiFRhBV7IDBF8tJ/Twe8zQr9ANiSldLkODFZpp5dxM22WDb7RiI2jcYs6QtE0
         O3wuy+vQbDxQPC2yUnEUP+4/DEQMd95RWd7SDjPgHp3jqpjCncwgl+0uqqB8GqkSBFzD
         LxKPldKQ9vt/IZkg/1/4qMYd5giMMsbBOopTuoKWfkmrPuBg/waRPiS6k+vtFwUzr8Pi
         a+vepwwUcCI57hNlZebpIjdRHfK0jov9/aBLKMWPoSf6pbSUl9n2NGJOY9x/TQEMn0Ln
         nFieKw2L5KTrp+kKBQepEAaEcEGnavlAJg2Yd5jLvjw4dNCowXAYxy4EzQBqOHT0RqJ8
         aN9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WmzA+t4MDXdqAhaVF+fDIbFF3YTTNHBnAeA/eIzeOCo=;
        b=PNiuMY8l2Ywbs9145ZQSccI7N66DZ6P4In9Rcql89fzRSZv+lf7fMD3xrPRwyEvC8i
         7YqpJMvuxXu+zdl1b5yyv5rmRAAZqbu8z9PxIY7KNIYucLZD7upeb6A9m5j8nCnsaps1
         51XsJeBUlusDfOpUUorkRTuedpRxK3ElktR+Xn/687LRYd6GhkedlqCMZY2Re/GKXY0d
         Hd5oguF2lIPFbSH9kBXlN3NEewSlsPiOBkZsKAoGKv/pY+RstfAaLcqHW+UtetI/e6O2
         Sh71lmt78HX1zdcoXggxH0c/vXhx0j7OYGcky3sw/H7dxvVJlgfHDgfDakD0JLF6wv3L
         2o9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 82.98.82.6 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WmzA+t4MDXdqAhaVF+fDIbFF3YTTNHBnAeA/eIzeOCo=;
        b=grEcy35fBEd/yFXaoAL2cdAOWh+O5dEJjyAsub3fIE6prtnYaR+LKaJvj6mVvnhBVt
         UmKuW+9JUMeUyCxBR+f6NFy1dGwChYGvXtn4wwXAhT2jSKLR7HLaFvam9/7RLzoX3M0W
         1K7RNFGuuB4FpOcaR3quWhU71jeX7dzdC16eSQ+CJXGMPG1PilA/FcdYHVKYYgzaYFvh
         oiY24RcZchOOEMKKJhi/apOHfBHDDrzwD6TL9uRtNoSWg+6jAoJ3mJvkHaQSNa746Qyl
         i+wncl1n/r/LA6IIJHfVB/d3xRxuoaOE78ohC3gbTDZdbc68l0biXKXZDmHGzcHVSRSC
         yvlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WmzA+t4MDXdqAhaVF+fDIbFF3YTTNHBnAeA/eIzeOCo=;
        b=FGB72/F3OpI6wdDPtSiQGTWxPjWTCtimuDrQsMJg3vXkkicJrZONUU+kNhCdmSlJgu
         fELSdv2zDu83orACdOwXBCNNpZKrtrm6b9OuQ/aL4+9HLaAfYX+aUsG3jqy9GspEhoi2
         DCIxtzWGt4spKDv4abMPbcp6ibrfTZ3CYRt/7tUJxh9aTuXaj6TXxhmq3jT3T6vkMhxP
         d9JZ2ycQTNeWxGyraN8dq6uSSoEkuuQqHpjd9S1wNe1wHCmOh0s4gXCKepATX1zaVs1N
         eSAyLM+XiYjarOMq+fLtAH9INfUaktz2mHlc0tqHck4hiA3+T7webJV6VEOVrCFX5Cgq
         JJsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Uz9t4d0s72eP6juQCqZ6o/Nf7+o/ki0JCv1lfakJVzHRsm4Dr
	TSdmED37xpCaT+CJg+vOeOY=
X-Google-Smtp-Source: ABdhPJzyVw9E92AoVZKWpfXy7x8gkDCa9gIV2Hl9seQMJHF4nPTV1wBGaTObjHcCfIzPkFSPNdXSjQ==
X-Received: by 2002:a05:6402:46:: with SMTP id f6mr7058458edu.163.1613030839626;
        Thu, 11 Feb 2021 00:07:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:edce:: with SMTP id sb14ls2427985ejb.0.gmail; Thu,
 11 Feb 2021 00:07:18 -0800 (PST)
X-Received: by 2002:a17:906:2e06:: with SMTP id n6mr6905748eji.329.1613030838832;
        Thu, 11 Feb 2021 00:07:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613030838; cv=none;
        d=google.com; s=arc-20160816;
        b=pTcm0gC80nFpJGjF8OB4E1QDCIVWTygWhlbkdTAhmzmlcV2tX9k/lHsE4mVH7lIunM
         JN9yId9J7CLgLj/9fV0y4Lx8NXpiw/nCXbARHtVKqx3mF7GNTMiWVTu/+nNLU+j/WZR4
         a7EOwwmzU1S974Ir59wSuPAP8/dalbGpRwyVvqbYvj0funlvdaxYvy7WnTNhqV33teje
         tEOwHuWe23S8quHfXx6K+/5xOQi7/kcgd9aaNwWUGiI3GGnrpTLhFRVd2ibLEgHrcwcl
         QRaye8eHPwSqs94elSRtY9Jf2fpnKK4b3mw4KbbJR7P5X4qzfQtkd2OXqssYxMPsTTcY
         Xpyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=pkQ8My1/wFU7V8sqTmYdC58UC3UrEXE/N4/wDcP6TMc=;
        b=A0ZvJLNMLHSjWQ2TSe2YaG9xgPzBSI5FbqebkmRkOIJoPdEvrPl2GrQeWonY7di0+l
         r2L85MWUkkFLl1UtQfGdlgytqSZ4SQS8S3cCUH9mlV/fg4zpNmSNFH+/1BYKyxLXgOzO
         JtB+pj8jUsnYcWQgm87GgauI8f9ESl8vPBHpynFX0FNiRs3HpLIOXlXMb9G9vn9rh6D4
         NrBl8zKtOLvE6eh89iZvgQQ8Sqm4rjWLrGLia66frR/QoApFqHuuShd7I2Nyl+uMnXIG
         EdB1dgd8kZMMWNNdm0WJYmLUtSzo9hZXiCVJoP2AicNxpZFx7lY5pz5bzRQDli2qxFxi
         9Zgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 82.98.82.6 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from outgoing.selfhost.de (mordac.selfhost.de. [82.98.82.6])
        by gmr-mx.google.com with ESMTPS id c14si244612edr.4.2021.02.11.00.07.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Feb 2021 00:07:18 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 82.98.82.6 as permitted sender) client-ip=82.98.82.6;
Received: (qmail 10065 invoked from network); 11 Feb 2021 08:07:18 -0000
Received: from unknown (HELO dakara) (postmaster@wngmbjws.mail.selfhost.de@79.217.113.212)
  by mailout.selfhost.de with ESMTPA; 11 Feb 2021 08:07:18 -0000
Received: from atlantis.default.lan (orilla.lochmann.lan [192.168.111.113])
	by dakara (Postfix) with ESMTP id 046CB1DDEF;
	Thu, 11 Feb 2021 09:07:16 +0100 (CET)
From: Alexander Lochmann <info@alexander-lochmann.de>
To: 
Cc: Alexander Lochmann <info@alexander-lochmann.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Wei Yongjun <weiyongjun1@huawei.com>,
	Maciej Grochowski <maciej.grochowski@pm.me>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] KCOV: Introduced tracing unique covered PCs
Date: Thu, 11 Feb 2021 09:07:09 +0100
Message-Id: <20210211080716.80982-1-info@alexander-lochmann.de>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning info@alexander-lochmann.de does not
 designate 82.98.82.6 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Content-Type: text/plain; charset="UTF-8"
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

Introduced new tracing mode KCOV_MODE_UNIQUE.
It simply stores the executed PCs.
The execution order is discarded.
Each bit in the shared buffer represents every fourth
byte of the text segment.
Since a call instruction on every supported
architecture is at least four bytes, it is safe
to just store every fourth byte of the text segment.
In contrast to KCOV_MODE_TRACE_PC, the shared buffer
cannot overflow. Thus, all executed PCs are recorded.

Signed-off-by: Alexander Lochmann <info@alexander-lochmann.de>
---
 Documentation/dev-tools/kcov.rst | 80 ++++++++++++++++++++++++++++++++
 include/linux/kcov.h             |  4 +-
 include/uapi/linux/kcov.h        | 10 ++++
 kernel/kcov.c                    | 67 ++++++++++++++++++++------
 4 files changed, 147 insertions(+), 14 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 8548b0b04e43..4712a730a06a 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -127,6 +127,86 @@ That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
 mmaps coverage buffer and then forks child processes in a loop. Child processes
 only need to enable coverage (disable happens automatically on thread end).
 
+If someone is interested in a set of executed PCs, and does not care about
+execution order, he or she can advise KCOV to do so:
+
+.. code-block:: c
+
+    #include <stdio.h>
+    #include <stddef.h>
+    #include <stdint.h>
+    #include <stdlib.h>
+    #include <sys/types.h>
+    #include <sys/stat.h>
+    #include <sys/ioctl.h>
+    #include <sys/mman.h>
+    #include <unistd.h>
+    #include <fcntl.h>
+
+    #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
+    #define KCOV_INIT_UNIQUE                _IOR('c', 2, unsigned long)
+    #define KCOV_ENABLE			_IO('c', 100)
+    #define KCOV_DISABLE			_IO('c', 101)
+
+    #define BITS_PER_LONG 64
+    #define KCOV_TRACE_PC  0
+    #define KCOV_TRACE_CMP 1
+    #define KCOV_UNIQUE_PC 2
+    /*
+     * Determine start of text segment via 'nm vmlinux | grep _stext | cut -d " " -f1',
+     * and fill in.
+     */
+    #define STEXT_START 0xffffffff81000000
+
+
+
+    int main(int argc, char **argv)
+    {
+	int fd;
+	unsigned long *cover, n, i;
+
+	/* A single fd descriptor allows coverage collection on a single
+	 * thread.
+	 */
+	fd = open("/sys/kernel/debug/kcov", O_RDWR);
+	if (fd == -1)
+		perror("open"), exit(1);
+	/* Setup trace mode and trace size. */
+	if ((n = ioctl(fd, KCOV_INIT_UNIQUE, 0)) < 0)
+		perror("ioctl"), exit(1);
+	/* Mmap buffer shared between kernel- and user-space. */
+	cover = (unsigned long*)mmap(NULL, n,
+				     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
+	if ((void*)cover == MAP_FAILED)
+		perror("mmap"), exit(1);
+	/* Enable coverage collection on the current thread. */
+	if (ioctl(fd, KCOV_ENABLE, KCOV_UNIQUE_PC))
+		perror("ioctl"), exit(1);
+	/* That's the target syscal call. */
+	read(-1, NULL, 0);
+	/* Disable coverage collection for the current thread. After this call
+	 * coverage can be enabled for a different thread.
+	 */
+	if (ioctl(fd, KCOV_DISABLE, 0))
+		perror("ioctl"), exit(1);
+        /* Convert byte size into element size */
+        n /= sizeof(unsigned long);
+        /* Print executed PCs in sorted order */
+        for (i = 0; i < n; i++) {
+            for (int j = 0; j < BITS_PER_LONG; j++) {
+                if (cover[i] & (1L << j)) {
+                    printf("0x%jx\n", (uintmax_t)(STEXT_START + (i * BITS_PER_LONG + j) * 4));
+                }
+            }
+        }
+	/* Free resources. */
+	if (munmap(cover, n * sizeof(unsigned long)))
+		perror("munmap"), exit(1);
+	if (close(fd))
+		perror("close"), exit(1);
+	return 0;
+    }
+
 Comparison operands collection
 ------------------------------
 
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index a10e84707d82..aa0c8bcf8299 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -19,7 +19,9 @@ enum kcov_mode {
 	 */
 	KCOV_MODE_TRACE_PC = 2,
 	/* Collecting comparison operands mode. */
-	KCOV_MODE_TRACE_CMP = 3,
+	KCOV_MODE_TRACE_CMP = 4,
+	/* Collecting unique covered PCs. Execution order is not saved. */
+	KCOV_MODE_UNIQUE_PC = 8,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index 1d0350e44ae3..5b99b6d1a1ac 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -19,6 +19,7 @@ struct kcov_remote_arg {
 #define KCOV_REMOTE_MAX_HANDLES		0x100
 
 #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
+#define KCOV_INIT_UNIQUE		_IOR('c', 2, unsigned long)
 #define KCOV_ENABLE			_IO('c', 100)
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
@@ -35,6 +36,15 @@ enum {
 	KCOV_TRACE_PC = 0,
 	/* Collecting comparison operands mode. */
 	KCOV_TRACE_CMP = 1,
+	/*
+	 * Unique coverage collection mode.
+	 * Unique covered PCs are collected in a per-task buffer.
+	 * De-duplicates the collected PCs. Execution order is *not* saved.
+	 * Each bit in the buffer represents every fourth byte of the text segment.
+	 * Since a call instruction is at least four bytes on every supported
+	 * architecture, storing just every fourth byte is sufficient.
+	 */
+	KCOV_UNIQUE_PC = 2,
 };
 
 /*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 6b8368be89c8..8f00ba6e672a 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -24,6 +24,7 @@
 #include <linux/refcount.h>
 #include <linux/log2.h>
 #include <asm/setup.h>
+#include <asm/sections.h>
 
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
@@ -171,7 +172,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return (mode & needed_mode) && !(mode & KCOV_IN_CTXSW);
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
 	struct task_struct *t;
 	unsigned long *area;
 	unsigned long ip = canonicalize_ip(_RET_IP_);
-	unsigned long pos;
+	unsigned long pos, idx;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
 		return;
 
 	area = t->kcov_area;
-	/* The first 64-bit word is the number of subsequent PCs. */
-	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
-		area[pos] = ip;
-		WRITE_ONCE(area[0], pos);
+	if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {
+		/* The first 64-bit word is the number of subsequent PCs. */
+		pos = READ_ONCE(area[0]) + 1;
+		if (likely(pos < t->kcov_size)) {
+			area[pos] = ip;
+			WRITE_ONCE(area[0], pos);
+		}
+	} else {
+		idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
+		pos = idx % BITS_PER_LONG;
+		idx /= BITS_PER_LONG;
+		if (likely(idx < t->kcov_size))
+			WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
 	}
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -474,6 +483,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 		goto exit;
 	}
 	if (!kcov->area) {
+		kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
 		kcov->area = area;
 		vma->vm_flags |= VM_DONTEXPAND;
 		spin_unlock_irqrestore(&kcov->lock, flags);
@@ -515,6 +525,8 @@ static int kcov_get_mode(unsigned long arg)
 {
 	if (arg == KCOV_TRACE_PC)
 		return KCOV_MODE_TRACE_PC;
+	else if (arg == KCOV_UNIQUE_PC)
+		return KCOV_MODE_UNIQUE_PC;
 	else if (arg == KCOV_TRACE_CMP)
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 		return KCOV_MODE_TRACE_CMP;
@@ -562,12 +574,13 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 {
 	struct task_struct *t;
 	unsigned long size, unused;
-	int mode, i;
+	int mode, i, text_size, ret = 0;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
 	unsigned long flags;
 
 	switch (cmd) {
+	case KCOV_INIT_UNIQUE:
 	case KCOV_INIT_TRACE:
 		/*
 		 * Enable kcov in trace mode and setup buffer size.
@@ -581,11 +594,39 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * that must not overflow.
 		 */
 		size = arg;
-		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
-			return -EINVAL;
-		kcov->size = size;
+		if (cmd == KCOV_INIT_UNIQUE) {
+			if (size != 0)
+				return -EINVAL;
+			text_size = (canonicalize_ip((unsigned long)&_etext) - canonicalize_ip((unsigned long)&_stext));
+			/**
+			 * A call instr is at least four bytes on every supported architecture.
+			 * Hence, just every fourth instruction can potentially be a call.
+			 */
+			text_size /= 4;
+			/*
+			 * Round up size of text segment to multiple of BITS_PER_LONG.
+			 * Otherwise, we cannot track
+			 * the last (text_size % BITS_PER_LONG) addresses.
+			 */
+			text_size = roundup(text_size, BITS_PER_LONG);
+			/* Get the amount of bytes needed */
+			text_size = text_size / 8;
+			/* mmap() requires size to be a multiple of PAGE_SIZE */
+			text_size = roundup(text_size, PAGE_SIZE);
+			/* Get the cover size (= amount of longs stored) */
+			ret = text_size;
+			kcov->size = text_size / sizeof(unsigned long);
+			kcov_debug("text size = 0x%lx, roundup = 0x%x, kcov->size = 0x%x\n",
+					((unsigned long)&_etext) - ((unsigned long)&_stext),
+					text_size,
+					kcov->size);
+		} else {
+			if (size < 2 || size > INT_MAX / sizeof(unsigned long))
+				return -EINVAL;
+			kcov->size = size;
+		}
 		kcov->mode = KCOV_MODE_INIT;
-		return 0;
+		return ret;
 	case KCOV_ENABLE:
 		/*
 		 * Enable coverage for the current task.
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211080716.80982-1-info%40alexander-lochmann.de.
