Return-Path: <kasan-dev+bncBAABBF6L6OPQMGQEMSTVK2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38C106A47B4
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 18:17:12 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id l20-20020a05600c1d1400b003e10d3e1c23sf5634282wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 09:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677518231; cv=pass;
        d=google.com; s=arc-20160816;
        b=lEcqCFV/z5cZJIanDtrSNlTC1+1eWle6JJLqaY3uq+HhARIMph0WYg+OcEyLFRtTmO
         iGEoTuibxghsHrApv4I1s2/fPiZxMxQB71slHMGm97GXnh68iRvDKEwAEp3BRd1dW1aI
         DMJd/DsTwG3JCfi7a/bp0wJRAOHFn6cG78sfjomVvH+8FGIMQKNHtjnmhN84IOHlolv5
         EZ0vHkejMZCXC3DqEiEH+/2t9iPlRBtyjC3jWpHgQuFJWHGkiYLYVRtz4UwuS4SihQzS
         7LvmyCcZAL2t2tKvE8d7eO33eDI6B854HDykW1Pbz1liJpPtAYwIjGH1/1vFioQ2e0XF
         g7XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5/ZpfNdMGUbCOf/rWuQYEyMH4arXS2q4WgE+QtqEdiM=;
        b=F4TK+LLKw9O9QonUvVpjB321EIwQz8fD8jkGA3FtbS73SWbqQQlRzKCD6nnqiEeTMb
         032vGHtaO/cCkVe2uroc3m0gk7z6/5WroRGzGM3DG+Prw5y1ByVNqtsp7e1y+6C6rN1K
         8eRAGLp7gG072apEPvhV30Tfugwny0JvNfY1/wwoxxslcAcRB9+S/x7wIYAOA7K17jFO
         PoSsohZmgmNNOh9mldwRFpgMyRUiCixnfoE8ULRQoX5mlrKXjH2Z+QRVMk6/PHSfMUKC
         31qWI4A0gfzXVBAsmnpkxpdzCYRztw8Hn5cuyUUStWtW0lXVRjjCQoY7pZVr43IrH009
         R4Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZL6S5E+r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.43 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5/ZpfNdMGUbCOf/rWuQYEyMH4arXS2q4WgE+QtqEdiM=;
        b=r6mLTT5pjZSX4J2lB6ltyXJtUrcmISPCD1oNgHsfmEPq2uKssujGosu3SuFdVJIcXh
         HP05AtQoaJHhIECe+cHpcMbwEqVt4lBhyJzLulmKgzTBTNr/6o7VFAHxMZZ5Nf/qtg0D
         djWVGy8PrQElDhnY28yJvsxFqUgtVhC9lv0290mWdwavIYL0cXD/lSum3/hfTNQYF6Un
         Om2b8I/Hqpat5T+1M8DPObD0OliqPNbLEx1DUAEyvGjJp4Vec15MrI0BToQxRzzx7/cB
         nCt6+CqvQs6uNtpUuSl1FWxbwud3U52N6dENmMTqTt12d4vEhUcUxaXXYC8YMvNam2Cy
         cGww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5/ZpfNdMGUbCOf/rWuQYEyMH4arXS2q4WgE+QtqEdiM=;
        b=4XZkhSe4keklta80r/W534zZAit2njZMyzEmwH5U11X4bGdqH1B5ivoF67C5HB66Qk
         GYCWmGnlXAGXeFYwbw4wgVsfnFovmY6aH+8cc8lWkPzNSnsVuZng+iR227m5gDTHli2C
         SoW12d/7VETZ+A/DWdntvqt8n5PgwCtCzvEF0ySwX5Syzxqh/P5DxVySNfLtT3M6+NBP
         RoAv+iLkGpyiwf8Hv3oAPc9gX6sPCBUVUAGOGpO1oAJ4bqtThYXvJtMy8vWFFxMURHAm
         R/w584zg8dJexGiiTnlffphxMQGCOn/woYUz9g7nTJh5+Heccuy+qmLgRhlCzYdS46QZ
         LPsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXUqKxfQORVmQ69JMCXv/dlPLrv+nNsGERRtnMUio01miUvoJx/
	PfskNfKqwAA8hYkNHI0xa/E=
X-Google-Smtp-Source: AK7set+XwagAI/JfJukZC8FE2NRbuDGqbYrcvCzdPpBwMC5LODxI4VtOxJqekclvfUpDfVJygtLirg==
X-Received: by 2002:a5d:6a45:0:b0:2c7:11a8:e810 with SMTP id t5-20020a5d6a45000000b002c711a8e810mr1961177wrw.14.1677518231534;
        Mon, 27 Feb 2023 09:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5110:b0:3e2:1c34:a7c8 with SMTP id
 o16-20020a05600c511000b003e21c34a7c8ls7753267wms.1.-pod-canary-gmail; Mon, 27
 Feb 2023 09:17:10 -0800 (PST)
X-Received: by 2002:a05:600c:3089:b0:3eb:29fe:7343 with SMTP id g9-20020a05600c308900b003eb29fe7343mr8271332wmn.33.1677518230410;
        Mon, 27 Feb 2023 09:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677518230; cv=none;
        d=google.com; s=arc-20160816;
        b=XPrAZ5k6bPH+aou4SmQF28fhc+v57f4PojE1DfkD3EeLa7jObEF0m3RnNrxLB6U+yF
         mIZfZ1xvm7tH2Ys0LNw0L+0AoLs045fjiSDr6rTNMIu+3p9wxJGUb4fhHADj/9ONn5OA
         Svzq48TCD0vVTYDNYPlfuk3lTi1f4iVoRHfNTlRzlfCyLcceZCoz2NiFgCmd86/dobDl
         YtXDfjlRePl2WsWJ0x3B6j/bkQuqM2jZ2Lrb0bsAlA4Yj4Np1pVDJnWDv2xQS368tWWm
         mbJOTcto98B3LRF7IAkHiwzb1BzgYB/8LT1puFO4X6wLZS2ozFFnvK4SBnCNXD8TTi2B
         hILw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=i9zSXzAdjq87uOVavd3XUT89sHIO+bwDfGwXckE+rVI=;
        b=y6Oa2pG6sUOGojmursNljcazhcHdaoil35YXBbS2ilYC3CgCwBA1R/1lFAdrNDnyD3
         jKA1wqYXg6jyv8fMH3hQrlT/xx601lFVSNw9L/pVWt7bwKb3OOM/OBPUrfXQwUs6bYno
         v8aa4jPGyCz8jRUH3h8SD6FCXfiaXx1PZ873bpCR9dVV7IycZIZq04L9tCXIS0kNa793
         PT0hvl8lP2uAlL9qgRTLs7rTqpVVtnkt8dPXLgpd6kC9BO2tLFCjx6qDBYxsJnafkBdD
         kYSb61wsu6N1CI8qNBxg1+L6WMjqoYQBedcz9xzf5ikj/kpLKdZqdj+rC0Luz0aLvgQt
         4O6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZL6S5E+r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.43 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-43.mta1.migadu.com (out-43.mta1.migadu.com. [95.215.58.43])
        by gmr-mx.google.com with ESMTPS id bi5-20020a05600c3d8500b003dd1c15e7ffsi338109wmb.2.2023.02.27.09.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Feb 2023 09:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.43 as permitted sender) client-ip=95.215.58.43;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kcov: improve documentation
Date: Mon, 27 Feb 2023 18:17:03 +0100
Message-Id: <0b5efd70e31bba7912cf9a6c951f0e76a8df27df.1677517724.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZL6S5E+r;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.43 as
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kcov.rst | 169 +++++++++++++++++++------------
 1 file changed, 102 insertions(+), 67 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d83c9ab49427..a113a03a475f 100644
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
+Collecting comparison operands is only supported with Clang.
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b5efd70e31bba7912cf9a6c951f0e76a8df27df.1677517724.git.andreyknvl%40google.com.
