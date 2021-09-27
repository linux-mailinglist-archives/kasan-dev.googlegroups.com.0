Return-Path: <kasan-dev+bncBC33FCGW2EDRBCUBZCFAMGQEFAVQIUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BB20419CDF
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 19:34:03 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id m2-20020a05600c3b0200b0030cd1310631sf212251wms.7
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 10:34:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632764042; cv=pass;
        d=google.com; s=arc-20160816;
        b=VX2Ie8dxdfp1BueM7wSl/t36mUeLIpdE0N9pafxJV/lpvzlgIBUHYtSU4JuDwlDgP/
         MDMLjsJiQ08fuwyaF8swtm9oN9Q4e+rXnYjBbhyFSFPgpvCxnUOt3G1hnlcUgfEDxYn1
         UY3n1UoXP7vK9xh3wjwqhvYvVFJV2bh0t9TkNfpU1FsZnsYM3A0i903z4uitmAv6uWCD
         bo7gE0IBrbUiKtqkSs1Dav5Z5hn6zscUU533ox54+eOCsfsNI3s86qQl0MIxkU/mUgkI
         ++ThyAAD0yKybX/qrR40194K20BQOTQWeEozVGbQaYTojV0aSDsxZRIDPsfZpPtiDVPk
         7O7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=o1xlKTEpEYZv3OJhSm9Mp7dq6Q9pTza9Ifvpb4H3jSc=;
        b=WDqcFlVveZHvUyBbCZ3OElZBkH8c9AkwPf2ztq0OoClqcRVoF+5Yf4WN+IM0DPrDk2
         9jhALHa366RB/00GPHe2kRj/6rJ+X34+X3RONqJp7bxJvrQ9gSYu665bXQZti+US88wF
         0h9rcVI9CHVG4GdDbzAdOd8nczjX7YFeOOCnxc5EIkOa6bTcWygFadZ7l505bgPMJAcK
         2CyMoWFyabJKP6DGaMN0pus/EoWx1q1vXRLQotw4b/orUJKVQJknWcdRligKbsuEEEC6
         LEw2EHcNNKA5LGdbGVs+/drmbRTWuBSieEEpm4ME31wNoMTuDzMFd/sT/HHiG6nh2r43
         Fg4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 129.217.128.51 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o1xlKTEpEYZv3OJhSm9Mp7dq6Q9pTza9Ifvpb4H3jSc=;
        b=tfngN+/wDupZcumvJD3K/b4fPX9uZwNE73eTjNJ8zvAv07zHIDmK0OBpa4h9c63s+c
         eAScM6oNRi/b9VUp7m9DE2OCNh1uOYXeVh2JmotI8L7Q18Gi3AVMwICt1CjCh6yQqiYC
         8Ry7maGTKx8GyA+1qdrqhSddbbGwYClvp9ucXuSn8Qz6fMlEkBzs+PZPTNPHivS4UxEu
         2wuVz4+Uom56FkpHfvv/cU/+4u7+f5Rca0a0ybvh3YieHrg5iMlWAEat7ks4N6QIFW1h
         ad3++egtUtmvZNXgJRkc6kBDZpauTM6640wT+BjlZuOJd9uyI+wPhA41qMI11wvCde0c
         nbOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o1xlKTEpEYZv3OJhSm9Mp7dq6Q9pTza9Ifvpb4H3jSc=;
        b=u2UavLFrq2KxN774wpEyLWPcK/A5phdguQL5dDQNCgSXLTUIDdheUurm4EzHL7Qtck
         UzFSj1kQKbamz5xCzbeOUxbVsTwlqVKW9QVqCxpN3v7+nuX6ZJ/cmr2iv2mcGLhGcoy/
         MPLBfHFzNPQw5INIwNyzzchm2CAV2KI9WzjGqseX0e8qgW4Xu5x7wb2ZtyAvtx6bKc+w
         +2RF8t1NPoYX10XC9E5VMR8qDj96E5p3tF3GeM8DAaD4HH302CwPg4xC8UyPFureq9rV
         Hu4SPRwM5cH7qmuJ1MF0SNbiuikJeNthM2uSIGFCLMTmbEqdtCZAWbBpN2F5yStiU99M
         UuEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MejJAbtHB5GkNkhWUMlzIIUDo7Mc004KS3xkxyevoWjuDvAPN
	zOmmtIucup5kb8bVJLnsvwg=
X-Google-Smtp-Source: ABdhPJw+JCHrUf8kag4OPjCdEGTj5e3Ny4xcCgznfxBowKstfhweertzGPvGjZ8zMxM0g8rqb+st+g==
X-Received: by 2002:a5d:4579:: with SMTP id a25mr1317653wrc.222.1632764042774;
        Mon, 27 Sep 2021 10:34:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4646:: with SMTP id n6ls43686wmo.3.canary-gmail;
 Mon, 27 Sep 2021 10:34:01 -0700 (PDT)
X-Received: by 2002:a1c:770d:: with SMTP id t13mr258426wmi.77.1632764041738;
        Mon, 27 Sep 2021 10:34:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632764041; cv=none;
        d=google.com; s=arc-20160816;
        b=Uh7t/2PCH/sU8+18nKlvKYvhmiZSwC1aFdAmKfm6zYs+yrhHHCgKvmzHd92sHjwUYo
         Cz75wjFUcapWgNWFwqsbFm8pAsheN21vN0XLrEWYSGYDJS0VTjdTY3gR6e57mWaGX6FP
         gxu6m+glGyVFxs3WANFdZFcJwOaiXqh4QXqXWguPc6gmHKQCxffXABb6jTbF4PF1ubGv
         C2Jc+o1p3xJTODQcnInZ3WrBfXKBsl0Qq+ERihSKXO1IEYBudSes5kRJqSTvmOGQT+bu
         lnUBvp4uLN/DF3rY+AZxlOqzngEu4Xx4QhLlFeUQYnb3f6xkb7RCgMCihFWUI02YCqQY
         ipGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=7McVu6ptjJwU8k/SMLWpwRHDgis9Oiznx+ToO8hkSs4=;
        b=BBj95MU2+uTT2OSgBast1VOoK0MK5bhsbn+WO7TLeKR0RYoCvVVZ5kdLC4ZEfqdihU
         zldWr4dM3jcjYwFx7r/9MRysMprm+W8x9GUqNb1morUIyVGlhp1L9aWmZd0UXtUh03Rw
         AMLNdS3L/WmMN4B3C2S/LUALtvJpaFUcfH27ft3uCF4UKzp5aS33l9ohovBK/u1kRie+
         o1ijQUGN+0iq/UkZ6udCFsoEOxWtQVZiVAk/1RdHItPWlup9R7l8S96mJX4gIV67wgIp
         DgXaNBJlZPYHbrC780aAoH2Z9JIe2adNWi5soN1lDi7Ml2EQOIEthn75mscOL6xAFBGC
         fd9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 129.217.128.51 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from unimail.uni-dortmund.de (mx1.hrz.uni-dortmund.de. [129.217.128.51])
        by gmr-mx.google.com with ESMTPS id o205si9358wme.0.2021.09.27.10.34.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Sep 2021 10:34:01 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning info@alexander-lochmann.de does not designate 129.217.128.51 as permitted sender) client-ip=129.217.128.51;
Received: from atlantis.vm.lan (p4fd97967.dip0.t-ipconnect.de [79.217.121.103])
	(authenticated bits=0)
	by unimail.uni-dortmund.de (8.17.1/8.17.1) with ESMTPSA id 18RHXnCw019905
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Mon, 27 Sep 2021 19:33:54 +0200 (CEST)
From: Alexander Lochmann <info@alexander-lochmann.de>
To: 
Cc: Alexander Lochmann <info@alexander-lochmann.de>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Andrew Klychkov <andrew.a.klychkov@gmail.com>,
        Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>,
        Johannes Berg <johannes@sipsolutions.net>,
        Ingo Molnar <mingo@kernel.org>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        "Peter Zijlstra (Intel)" <peterz@infradead.org>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Jakub Kicinski <kuba@kernel.org>, Aleksandr Nogikh <nogikh@google.com>,
        kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org
Subject: [PATCHv2] Introduced new tracing mode KCOV_MODE_UNIQUE.
Date: Mon, 27 Sep 2021 19:33:40 +0200
Message-Id: <20210927173348.265501-1-info@alexander-lochmann.de>
X-Mailer: git-send-email 2.33.0
MIME-Version: 1.0
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning info@alexander-lochmann.de does not
 designate 129.217.128.51 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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

The existing trace mode stores PCs in execution order. This could lead
to a buffer overflow if sufficient amonut of kernel code is executed.
Thus, a user might not see all executed PCs. KCOV_MODE_UNIQUE favors
completeness over execution order. While ignoring the execution order,
it marks a PC as exectued by setting a bit representing that PC. Each
bit in the shared buffer represents every fourth byte of the text
segment.  Since a call instruction on every supported architecture is
at least four bytes, it is safe to just store every fourth byte of the
text segment.

Prior to above changes, a comparison of the current kcov mode with
KCOV_IN_CTXSW set would evaluate to false, and tracing does not take
place. Since the kcov mode is now a bit mask, simply setting
KCOV_IN_CTXSW isn't sufficient anymore for the comparison to turn
false. With KCOV_IN_CTXSW being the MSB, the following comparison will
be less than zero:

	((int)(*mode & (KCOV_IN_CTXSW | needed_mode))) > 0

This restores the previous semantics: When KCOV_IN_CTXSW is set,
tracing does not take place.

We have used this mode so far to perform coverage analysis on the Linux
Test Project: http://dx.doi.org/10.18420/fgbs2020h-01. Since LTP's
testsuites are considerably large, we experienced buffer overflows with
KCOVE_MODE_TRACE_PC.

Signed-off-by: Alexander Lochmann <info@alexander-lochmann.de>
---
 Documentation/dev-tools/kcov.rst | 79 +++++++++++++++++++++++++++
 include/linux/kcov.h             | 12 +++--
 include/uapi/linux/kcov.h        | 10 ++++
 kernel/kcov.c                    | 93 +++++++++++++++++++++++++-------
 4 files changed, 171 insertions(+), 23 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d2c4c27e1702..9b0df2f8474c 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -127,6 +127,85 @@ That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
 mmaps coverage buffer and then forks child processes in a loop. Child processes
 only need to enable coverage (disable happens automatically on thread end).
 
+If someone is interested in a set of executed PCs, and does not care about
+execution order, he or she can use KCOV_INIT_UNIQUE to do so:
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
index 55dc338f6bcd..e2c0f7cc16a1 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -13,17 +13,21 @@ enum kcov_mode {
 	/* Coverage collection is not enabled yet. */
 	KCOV_MODE_DISABLED = 0,
 	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
-	KCOV_MODE_INIT = 1,
+	KCOV_MODE_INIT_TRACE = 1,
+	/* KCOV was initialized, but recording of unique PCs hasn't been chosen yet. */
+	KCOV_MODE_INIT_UNIQUE = 2,
 	/*
 	 * Tracing coverage collection mode.
 	 * Covered PCs are collected in a per-task buffer.
 	 */
-	KCOV_MODE_TRACE_PC = 2,
+	KCOV_MODE_TRACE_PC = 4,
 	/* Collecting comparison operands mode. */
-	KCOV_MODE_TRACE_CMP = 3,
+	KCOV_MODE_TRACE_CMP = 8,
+	/* Collecting unique covered PCs. Execution order is not saved. */
+	KCOV_MODE_UNIQUE_PC = 16,
 };
 
-#define KCOV_IN_CTXSW	(1 << 30)
+#define KCOV_IN_CTXSW	(1 << 31)
 
 void kcov_task_init(struct task_struct *t);
 void kcov_task_exit(struct task_struct *t);
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
index 80bfe71bbe13..578f07f28428 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -24,6 +24,7 @@
 #include <linux/refcount.h>
 #include <linux/log2.h>
 #include <asm/setup.h>
+#include <asm/sections.h>
 
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
@@ -151,10 +152,10 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
 	list_add(&area->list, &kcov_remote_areas);
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
+static __always_inline notrace bool check_kcov_mode(enum kcov_mode needed_mode,
+						    struct task_struct *t,
+						    unsigned int *mode)
 {
-	unsigned int mode;
-
 	/*
 	 * We are interested in code coverage as a function of a syscall inputs,
 	 * so we ignore code executed in interrupts, unless we are in a remote
@@ -162,7 +163,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 */
 	if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
 		return false;
-	mode = READ_ONCE(t->kcov_mode);
+	*mode = READ_ONCE(t->kcov_mode);
 	/*
 	 * There is some code that runs in interrupts but for which
 	 * in_interrupt() returns false (e.g. preempt_schedule_irq()).
@@ -171,7 +172,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return ((int)(*mode & (KCOV_IN_CTXSW | needed_mode))) > 0;
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -191,18 +192,27 @@ void notrace __sanitizer_cov_trace_pc(void)
 	struct task_struct *t;
 	unsigned long *area;
 	unsigned long ip = canonicalize_ip(_RET_IP_);
-	unsigned long pos;
+	unsigned long pos, idx;
+	unsigned int mode;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t, &mode))
 		return;
 
 	area = t->kcov_area;
-	/* The first 64-bit word is the number of subsequent PCs. */
-	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
-		area[pos] = ip;
-		WRITE_ONCE(area[0], pos);
+	if (likely(mode == KCOV_MODE_TRACE_PC)) {
+		/* The first 64-bit word is the number of subsequent PCs. */
+		pos = READ_ONCE(area[0]) + 1;
+		if (likely(pos < t->kcov_size)) {
+			area[pos] = ip;
+			WRITE_ONCE(area[0], pos);
+		}
+	} else {
+		pos = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
+		idx = pos % BITS_PER_LONG;
+		pos /= BITS_PER_LONG;
+		if (likely(pos < t->kcov_size))
+			WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L << idx);
 	}
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -213,9 +223,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	struct task_struct *t;
 	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
+	unsigned int mode;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t, &mode))
 		return;
 
 	ip = canonicalize_ip(ip);
@@ -362,7 +373,7 @@ void kcov_task_init(struct task_struct *t)
 static void kcov_reset(struct kcov *kcov)
 {
 	kcov->t = NULL;
-	kcov->mode = KCOV_MODE_INIT;
+	kcov->mode = KCOV_MODE_INIT_TRACE;
 	kcov->remote = false;
 	kcov->remote_size = 0;
 	kcov->sequence++;
@@ -468,12 +479,13 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
-	if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
+	if (kcov->mode & ~(KCOV_MODE_INIT_TRACE | KCOV_MODE_INIT_UNIQUE) || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
 	}
 	if (!kcov->area) {
+		kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
 		kcov->area = area;
 		vma->vm_flags |= VM_DONTEXPAND;
 		spin_unlock_irqrestore(&kcov->lock, flags);
@@ -515,6 +527,8 @@ static int kcov_get_mode(unsigned long arg)
 {
 	if (arg == KCOV_TRACE_PC)
 		return KCOV_MODE_TRACE_PC;
+	else if (arg == KCOV_UNIQUE_PC)
+		return KCOV_MODE_UNIQUE_PC;
 	else if (arg == KCOV_TRACE_CMP)
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 		return KCOV_MODE_TRACE_CMP;
@@ -562,12 +576,48 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 {
 	struct task_struct *t;
 	unsigned long size, unused;
-	int mode, i;
+	int mode, i, text_size;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
 	unsigned long flags;
 
 	switch (cmd) {
+	case KCOV_INIT_UNIQUE:
+		/*
+		 * Enable kcov in trace mode and setup buffer size.
+		 * Must happen before anything else.
+		 */
+		if (kcov->mode != KCOV_MODE_DISABLED)
+			return -EBUSY;
+		size = arg;
+		if (size != 0)
+			return -EINVAL;
+		text_size = (canonicalize_ip((unsigned long)&_etext)
+			     - canonicalize_ip((unsigned long)&_stext));
+		/**
+		 * A call instr is at least four bytes on every supported architecture.
+		 * Hence, just every fourth instruction can potentially be a call.
+		 */
+		text_size = roundup(text_size, 4);
+		text_size /= 4;
+		/*
+		 * Round up size of text segment to multiple of BITS_PER_LONG.
+		 * Otherwise, we cannot track
+		 * the last (text_size % BITS_PER_LONG) addresses.
+		 */
+		text_size = roundup(text_size, BITS_PER_LONG);
+		/* Get the amount of bytes needed */
+		text_size = text_size / 8;
+		/* mmap() requires size to be a multiple of PAGE_SIZE */
+		text_size = roundup(text_size, PAGE_SIZE);
+		/* Get the cover size (= amount of bytes stored) */
+		kcov->size = text_size / sizeof(unsigned long);
+		kcov_debug("text size = 0x%lx, roundup = 0x%x, kcov->size = 0x%x\n",
+				((unsigned long)&_etext) - ((unsigned long)&_stext),
+				text_size,
+				kcov->size);
+		kcov->mode = KCOV_MODE_INIT_UNIQUE;
+		return text_size;
 	case KCOV_INIT_TRACE:
 		/*
 		 * Enable kcov in trace mode and setup buffer size.
@@ -584,7 +634,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
 			return -EINVAL;
 		kcov->size = size;
-		kcov->mode = KCOV_MODE_INIT;
+		kcov->mode = KCOV_MODE_INIT_TRACE;
 		return 0;
 	case KCOV_ENABLE:
 		/*
@@ -594,7 +644,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * at task exit or voluntary by KCOV_DISABLE. After that it can
 		 * be enabled for another task.
 		 */
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (!kcov->area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -602,6 +652,11 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		mode = kcov_get_mode(arg);
 		if (mode < 0)
 			return mode;
+		if (kcov->mode == KCOV_MODE_INIT_TRACE && mode == KCOV_MODE_UNIQUE_PC)
+			return -EINVAL;
+		if (kcov->mode == KCOV_MODE_INIT_UNIQUE &&
+		    (mode & (KCOV_MODE_TRACE_PC | KCOV_MODE_TRACE_CMP)))
+			return -EINVAL;
 		kcov_fault_in_area(kcov);
 		kcov->mode = mode;
 		kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
@@ -622,7 +677,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov_put(kcov);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT_TRACE || !kcov->area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210927173348.265501-1-info%40alexander-lochmann.de.
