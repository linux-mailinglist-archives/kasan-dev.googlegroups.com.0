Return-Path: <kasan-dev+bncBAABBQ547GPQMGQEQAY73EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B4F96A6018
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 21:04:20 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id j6-20020a05600c1c0600b003eaf882cb85sf4650821wms.9
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 12:04:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677614660; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5jJoxBPorVgA1QftvqCnDzVEDGuVPKukmFn6kNr0IilGOu/BDIsEKRNpbxEnE4WKU
         OEfFCZpsIhh40KsiEP4J/ibXLDCxJy/kRgz8VT9pb/u/vH9aY0ilWZBart3BDBVR+iPF
         CNxxs4Kj6gm8R7fKU8Ijt/QxWomAZWEc+eS4zhqHdW369+5Q8znf6Q+otR6CmAQQ3sW8
         L2dfgNfLSgpJUJ0NwT6KpUkrzArYVnFoJGnvNl1kRNQpaQLrYL9L9XmcIBraXYLWDrIU
         Awcqv+He/7iWzPUSQEUFZTE0jL7PKS7L7CP72LJEi1uwM50/GNsbfyKwrIAQT+WKZXFR
         f4Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SOQNTzqvw6H4rtT5yX45zK4/fIH/UPolnlVRyk+gnko=;
        b=j7gf5mzFU26Kyy53MvKGQVA+8NZE9uscHYRY8pHymhWaSZ498/Pszru90XXFWhBS9P
         JNtNPEgV0oB7Myw3cVs51DHsLbKAHLt/Bx7yJiI5RtcMkQ7PsWPpsyKKtcIkWLd2niSd
         i/N83G7A/pNXHkTffQ6IvnFmBhDBRQcBRDCwbe/io6/RjMEDmPf9Jj6H/4EwI+cNIt3I
         J7BlGH3sSKCJh6pGJ6J7xuU0njle5CW6sWkJwTLMLDSbEkV+Rug9Bl/zRIBgTpB+QYgx
         ngZt5+UzhY+I26LiRDR5Udtq4O6jKQrsxqDC3TrbzNH1v7lrBs9E7CHsbZFxJ+9SzZW+
         mLPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T1ce0sj2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.47 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SOQNTzqvw6H4rtT5yX45zK4/fIH/UPolnlVRyk+gnko=;
        b=W+uxG0PUOCJP2b0prK+LLtOs3Cx09FPUBCc8ZW/flyL3bg1ip6x9SCiqzDDaVK84IV
         Y6NFHmYHcZ2tj4Yqjn8ZcHTCQfEVjX+ItZ51msjEe5jnmFDsMDGHV8TzJMBTkrqu8U9f
         IBbNT3nK5+3PCSZXMYpDUhEgEfZ/F6cYAMdqX3Hig+KhdAQnMJXVtZVjGPIEU/e750j4
         bXYr24q52lq41LhuqVsoSWQ6pBwZnV2EsXMbZDQzJ/1hXFE+Bo0NTXkcSdBW5O2N6c6R
         uRn8ya0NUyf2+A/kfFugmXgTO6Jpz8nF4f3oSqmKRT8ThqC5EdW9dBt32kJA4iSgaqTA
         SrXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SOQNTzqvw6H4rtT5yX45zK4/fIH/UPolnlVRyk+gnko=;
        b=ScZZ2Z/W8OWuBdpY+PMx4zT7NcU+ZOfokaqvG5ODbaDbPp9lJMZMV5UqbaiEaUuqPq
         wuBNc4ha6pnqJzJBxLZzWFMxr6dFx3mkoZApiD2gzp2zQtbWNeHPYZgi1lq3uZOyn5Db
         SLDTbfkLhkYwzCpbP38E5cB+vb5RgE9COl8Y6ElroUBYcfIvgVHHFfmtc2//Rf77Oy1G
         yKolvS5UQXiTGNWAvrxFlWpIXKXzIbiIC6ILuWWuXjowiv/KhR++mZuurem4zg+fOqMM
         CUBHdVc1n6h4241eq/yN1Z2v3ViX5S7GrSMHNzeBV6Ewod4LQmScmk1pX1Mc8cZIlh/D
         Tj4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUMuqFydDXGKHZzMtyRMYLYUnr+Xa+ZtsGSyVQWordKW25eBeii
	xYzmxG+D2x7ogNmVcXWib/U=
X-Google-Smtp-Source: AK7set9DqcQYXJDAQqFqVtLb+oRhQ0EMdwDxFVbr8UKHKeNQjS+L549bQ1ArvrqKt11DW9Hex2rqiQ==
X-Received: by 2002:a05:600c:5406:b0:3df:fc69:e977 with SMTP id he6-20020a05600c540600b003dffc69e977mr1132344wmb.5.1677614659780;
        Tue, 28 Feb 2023 12:04:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:a18:b0:2c5:55ca:3a3b with SMTP id
 co24-20020a0560000a1800b002c555ca3a3bls501701wrb.1.-pod-prod-gmail; Tue, 28
 Feb 2023 12:04:18 -0800 (PST)
X-Received: by 2002:adf:f847:0:b0:2c7:cbea:1140 with SMTP id d7-20020adff847000000b002c7cbea1140mr3120357wrq.71.1677614658641;
        Tue, 28 Feb 2023 12:04:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677614658; cv=none;
        d=google.com; s=arc-20160816;
        b=zW07SyYBZCDw2+tk48VTYwRRE/PZTXoEJHXAoFdBbx97ctwETZyfRKnPgHuxL61qvP
         Vuvm5gGlRgIanlHRsY76M1SZf9z/5EYQ5E51cRJDadXmdhycTp1bgAatBdZzfitfLtFS
         hf4cpa+sXdDDyds71GbcHkdjdPspSSPPNxyQKWOX6CitEK+St+sjJU7fC2B1Dms9uLoC
         rSH2ldPrywAU94ygDGzJfJ5FA3w/6QpIIYri1Qo7a20XYVhYLjGWLQ/UerIU8/uzf6zP
         HMN8YswCmhGz0c0NwQG9v7P9YuYYHBIeXHU9/7hvC1pvMLaNfrhRxBfoP289hglPf7r9
         V3rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/Npz3xNf7ea+esGDqQvq3tXEiMJ8ODyuW/FAIFACyJA=;
        b=BCdtSAN/kgDaHs4sSD58hqjUHvYggVnw7JQiv0c2Pfusz6oI3eNEKmlpkwdumnXlxM
         f3y8TUjXnMECejCOypF+r6Ah00Qkv2fQ7q4PS4W9c5yLPGEFdYfsyNxJB3jj7Lonp1bX
         b5R2EFlCZb5aH+Y6g8TkE8Mj1ZGvcoh7toJUXqYUxJ7eRyLQ+Ci7UhvepvIyVIO5150g
         IPf+rVpJvJ2ReiYqNpsIGKDTeWf41GNoIpolLAqq+7A3r+2UwoylNvlF9Ae0SBAgul0C
         y1kJuZJo+CMxwGg5kDnGq8bI/bmEMvy1qD4QTEc7dYPNxjCJq3HJ5M27ok3XI6LNjIxa
         sn+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T1ce0sj2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.47 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-47.mta1.migadu.com (out-47.mta1.migadu.com. [95.215.58.47])
        by gmr-mx.google.com with ESMTPS id bt24-20020a056000081800b002c59bef13d2si502470wrb.8.2023.02.28.12.04.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Feb 2023 12:04:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.47 as permitted sender) client-ip=95.215.58.47;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2] kcov: improve documentation
Date: Tue, 28 Feb 2023 21:04:15 +0100
Message-Id: <583f41c49eef15210fa813e8229730d11427efa7.1677614637.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=T1ce0sj2;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.47 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Improve KCOV documentation:

- Use KCOV instead of kcov, as the former is more widely-used.

- Mention Clang in compiler requirements.

- Use ``annotations`` for inline code.

- Rework remote coverage collection documentation for better clarity.

- Various smaller changes.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add GCC version requirement for comparison operands collection.
---
 Documentation/dev-tools/kcov.rst | 169 +++++++++++++++++++------------
 1 file changed, 102 insertions(+), 67 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d83c9ab49427..4527acfa023d 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -1,42 +1,50 @@
-kcov: code coverage for fuzzing
+KCOV: code coverage for fuzzing
 ===============================
 
-kcov exposes kernel code coverage information in a form suitable for coverage-
-guided fuzzing (randomized testing). Coverage data of a running kernel is
-exported via the "kcov" debugfs file. Coverage collection is enabled on a task
-basis, and thus it can capture precise coverage of a single system call.
+KCOV collects and exposes kernel code coverage information in a form suitable
+for coverage-guided fuzzing. Coverage data of a running kernel is exported via
+the ``kcov`` debugfs file. Coverage collection is enabled on a task basis, and
+thus KCOV can capture precise coverage of a single system call.
 
-Note that kcov does not aim to collect as much coverage as possible. It aims
-to collect more or less stable coverage that is function of syscall inputs.
-To achieve this goal it does not collect coverage in soft/hard interrupts
-and instrumentation of some inherently non-deterministic parts of kernel is
-disabled (e.g. scheduler, locking).
+Note that KCOV does not aim to collect as much coverage as possible. It aims
+to collect more or less stable coverage that is a function of syscall inputs.
+To achieve this goal, it does not collect coverage in soft/hard interrupts
+(unless remove coverage collection is enabled, see below) and from some
+inherently non-deterministic parts of the kernel (e.g. scheduler, locking).
 
-kcov is also able to collect comparison operands from the instrumented code
-(this feature currently requires that the kernel is compiled with clang).
+Besides collecting code coverage, KCOV can also collect comparison operands.
+See the "Comparison operands collection" section for details.
+
+Besides collecting coverage data from syscall handlers, KCOV can also collect
+coverage for annotated parts of the kernel executing in background kernel
+tasks or soft interrupts. See the "Remote coverage collection" section for
+details.
 
 Prerequisites
 -------------
 
-Configure the kernel with::
+KCOV relies on compiler instrumentation and requires GCC 6.1.0 or later
+or any Clang version supported by the kernel.
 
-        CONFIG_KCOV=y
+Collecting comparison operands is supported with GCC 8+ or with Clang.
 
-CONFIG_KCOV requires gcc 6.1.0 or later.
+To enable KCOV, configure the kernel with::
 
-If the comparison operands need to be collected, set::
+        CONFIG_KCOV=y
+
+To enable comparison operands collection, set::
 
 	CONFIG_KCOV_ENABLE_COMPARISONS=y
 
-Profiling data will only become accessible once debugfs has been mounted::
+Coverage data only becomes accessible once debugfs has been mounted::
 
         mount -t debugfs none /sys/kernel/debug
 
 Coverage collection
 -------------------
 
-The following program demonstrates coverage collection from within a test
-program using kcov:
+The following program demonstrates how to use KCOV to collect coverage for a
+single syscall from within a test program:
 
 .. code-block:: c
 
@@ -84,7 +92,7 @@ program using kcov:
 		perror("ioctl"), exit(1);
 	/* Reset coverage from the tail of the ioctl() call. */
 	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
-	/* That's the target syscal call. */
+	/* Call the target syscall call. */
 	read(-1, NULL, 0);
 	/* Read number of PCs collected. */
 	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
@@ -103,7 +111,7 @@ program using kcov:
 	return 0;
     }
 
-After piping through addr2line output of the program looks as follows::
+After piping through ``addr2line`` the output of the program looks as follows::
 
     SyS_read
     fs/read_write.c:562
@@ -121,12 +129,13 @@ After piping through addr2line output of the program looks as follows::
     fs/read_write.c:562
 
 If a program needs to collect coverage from several threads (independently),
-it needs to open /sys/kernel/debug/kcov in each thread separately.
+it needs to open ``/sys/kernel/debug/kcov`` in each thread separately.
 
 The interface is fine-grained to allow efficient forking of test processes.
-That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
-mmaps coverage buffer and then forks child processes in a loop. Child processes
-only need to enable coverage (disable happens automatically on thread end).
+That is, a parent process opens ``/sys/kernel/debug/kcov``, enables trace mode,
+mmaps coverage buffer, and then forks child processes in a loop. The child
+processes only need to enable coverage (it gets disabled automatically when
+a thread exits).
 
 Comparison operands collection
 ------------------------------
@@ -205,52 +214,78 @@ Comparison operands collection is similar to coverage collection:
 	return 0;
     }
 
-Note that the kcov modes (coverage collection or comparison operands) are
-mutually exclusive.
+Note that the KCOV modes (collection of code coverage or comparison operands)
+are mutually exclusive.
 
 Remote coverage collection
 --------------------------
 
-With KCOV_ENABLE coverage is collected only for syscalls that are issued
-from the current process. With KCOV_REMOTE_ENABLE it's possible to collect
-coverage for arbitrary parts of the kernel code, provided that those parts
-are annotated with kcov_remote_start()/kcov_remote_stop().
-
-This allows to collect coverage from two types of kernel background
-threads: the global ones, that are spawned during kernel boot in a limited
-number of instances (e.g. one USB hub_event() worker thread is spawned per
-USB HCD); and the local ones, that are spawned when a user interacts with
-some kernel interface (e.g. vhost workers); as well as from soft
-interrupts.
-
-To enable collecting coverage from a global background thread or from a
-softirq, a unique global handle must be assigned and passed to the
-corresponding kcov_remote_start() call. Then a userspace process can pass
-a list of such handles to the KCOV_REMOTE_ENABLE ioctl in the handles
-array field of the kcov_remote_arg struct. This will attach the used kcov
-device to the code sections, that are referenced by those handles.
-
-Since there might be many local background threads spawned from different
-userspace processes, we can't use a single global handle per annotation.
-Instead, the userspace process passes a non-zero handle through the
-common_handle field of the kcov_remote_arg struct. This common handle gets
-saved to the kcov_handle field in the current task_struct and needs to be
-passed to the newly spawned threads via custom annotations. Those threads
-should in turn be annotated with kcov_remote_start()/kcov_remote_stop().
-
-Internally kcov stores handles as u64 integers. The top byte of a handle
-is used to denote the id of a subsystem that this handle belongs to, and
-the lower 4 bytes are used to denote the id of a thread instance within
-that subsystem. A reserved value 0 is used as a subsystem id for common
-handles as they don't belong to a particular subsystem. The bytes 4-7 are
-currently reserved and must be zero. In the future the number of bytes
-used for the subsystem or handle ids might be increased.
-
-When a particular userspace process collects coverage via a common
-handle, kcov will collect coverage for each code section that is annotated
-to use the common handle obtained as kcov_handle from the current
-task_struct. However non common handles allow to collect coverage
-selectively from different subsystems.
+Besides collecting coverage data from handlers of syscalls issued from a
+userspace process, KCOV can also collect coverage for parts of the kernel
+executing in other contexts - so-called "remote" coverage.
+
+Using KCOV to collect remote coverage requires:
+
+1. Modifying kernel code to annotate the code section from where coverage
+   should be collected with ``kcov_remote_start`` and ``kcov_remote_stop``.
+
+2. Using `KCOV_REMOTE_ENABLE`` instead of ``KCOV_ENABLE`` in the userspace
+   process that collects coverage.
+
+Both ``kcov_remote_start`` and ``kcov_remote_stop`` annotations and the
+``KCOV_REMOTE_ENABLE`` ioctl accept handles that identify particular coverage
+collection sections. The way a handle is used depends on the context where the
+matching code section executes.
+
+KCOV supports collecting remote coverage from the following contexts:
+
+1. Global kernel background tasks. These are the tasks that are spawned during
+   kernel boot in a limited number of instances (e.g. one USB ``hub_event``
+   worker is spawned per one USB HCD).
+
+2. Local kernel background tasks. These are spawned when a userspace process
+   interacts with some kernel interface and are usually killed when the process
+   exits (e.g. vhost workers).
+
+3. Soft interrupts.
+
+For #1 and #3, a unique global handle must be chosen and passed to the
+corresponding ``kcov_remote_start`` call. Then a userspace process must pass
+this handle to ``KCOV_REMOTE_ENABLE`` in the ``handles`` array field of the
+``kcov_remote_arg`` struct. This will attach the used KCOV device to the code
+section referenced by this handle. Multiple global handles identifying
+different code sections can be passed at once.
+
+For #2, the userspace process instead must pass a non-zero handle through the
+``common_handle`` field of the ``kcov_remote_arg`` struct. This common handle
+gets saved to the ``kcov_handle`` field in the current ``task_struct`` and
+needs to be passed to the newly spawned local tasks via custom kernel code
+modifications. Those tasks should in turn use the passed handle in their
+``kcov_remote_start`` and ``kcov_remote_stop`` annotations.
+
+KCOV follows a predefined format for both global and common handles. Each
+handle is a ``u64`` integer. Currently, only the one top and the lower 4 bytes
+are used. Bytes 4-7 are reserved and must be zero.
+
+For global handles, the top byte of the handle denotes the id of a subsystem
+this handle belongs to. For example, KCOV uses ``1`` as the USB subsystem id.
+The lower 4 bytes of a global handle denote the id of a task instance within
+that subsystem. For example, each ``hub_event`` worker uses the USB bus number
+as the task instance id.
+
+For common handles, a reserved value ``0`` is used as a subsystem id, as such
+handles don't belong to a particular subsystem. The lower 4 bytes of a common
+handle identify a collective instance of all local tasks spawned by the
+userspace process that passed a common handle to ``KCOV_REMOTE_ENABLE``.
+
+In practice, any value can be used for common handle instance id if coverage
+is only collected from a single userspace process on the system. However, if
+common handles are used by multiple processes, unique instance ids must be
+used for each process. One option is to use the process id as the common
+handle instance id.
+
+The following program demonstrates using KCOV to collect coverage from both
+local tasks spawned by the process and the global task that handles USB bus #1:
 
 .. code-block:: c
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/583f41c49eef15210fa813e8229730d11427efa7.1677614637.git.andreyknvl%40google.com.
