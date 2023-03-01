Return-Path: <kasan-dev+bncBAABB3PB7WPQMGQEIXAQUIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 303BA6A6FDB
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 16:36:15 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id j30-20020a056512029e00b004db385ddddfsf3935369lfp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 07:36:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677684974; cv=pass;
        d=google.com; s=arc-20160816;
        b=cGWezXCZFsqMW3OFbkFiASnnuI9LZcFWjFkiA98ZQwj8+qmER001FYhxFndGrOqjaF
         JqImCW1bCtldcnPYD5Yvl+uV/6iov3s5jdHD4C0DrY4d+rnfzJ0j5Kh7RhOvt0IHWcYL
         HAyms+ZQ7eY27nYPIvxSmKOzpEEFXwwK9OnfSPgUnaCtfogNqJTn+kORMKKW5rgVOee8
         5UwpMQ+ihqtgbXsWOQegRMojVsH89ehAkUOqlU6fpPVyNYKSPVXeIAOy1VhR2lrySX1O
         cP/tSU9GjTy2yvKlPsMZ6oAfDHrMoi7emw1c4Q1WIvFsj4q3MWgV0ogMcE+enuG+4JDJ
         Joaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Rp8yKt0xSj76aYBYbZu1wRXmITS5NnOOolsAR25AMT8=;
        b=uNrwPAI8wIudiMT5zyRCaRNfwabFc/dNZqXhRHKkECeEsaGS/kx4/E8cs7lf+J+VB9
         JeH1/4MCq91Ekm34Kd4oVw0aZ7P03P6oShBUX8Fxl0mSA3xxlDIQrO1vY/Gg8eJ01cdo
         avS39g2CDN4kTbj5yZfOP/hk1DJPZExotnNMTq/cpf1hyxo2pOmdOMOFuPpIXUvogMtP
         jOPRcEAfcTGCekwNiMRbPVIdPY5FgHbr06wPVCSuEJGDc69gqUWP8vDYcavnECDKBaPz
         +4CzAqgcpBt2VbHu9hzbLy01AIRCUX/qSPfp+7JZGmGrx1tVpAmn4xRaaDXl5FFqqQaB
         up8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="rhUgbe/z";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.28 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Rp8yKt0xSj76aYBYbZu1wRXmITS5NnOOolsAR25AMT8=;
        b=ASwV0YOon/qtt+7vZtqNpV0J0uK3ZvzsDS20GVJMLhB5vHNcm91MkF+n0pWWCWMXjr
         I8krJB0Dk+wET1fkHZ3H5IArXtsO3fTsQpU8dcJ9P+nIBzqCJP8Oa+BBqLVATfwq3LwU
         sQ6wDDzOROhmseFgqUkvVVyxAFXEr99mGgRqEoGtMz6P+huqCLXP6OVPwox82hIgs1/c
         p+PtpZvKm/eHOfY8KDnMaNrjS+DBqabhh4gtXbilnqNsRbDynzxBWgM5qS2LDxUAlHzl
         OqkXmhkAx+tmEFJWFyEKacGwkkBzVqPlcZ66ktSdrfL6uyzRQctAkJCmrC9BLXm+qGA1
         3wlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Rp8yKt0xSj76aYBYbZu1wRXmITS5NnOOolsAR25AMT8=;
        b=lasdL6corTw011uClQEk9UHD7w4BX/PpITOwFaCAtR7XxoHCDloDFx3BF8SuNz9+zO
         1M4zFZCbB7lK1lH77L4WwS6c9OdQchHRcnVD5E2sY9d3Otd5ZOxKpcshZqhdizGwClhb
         OTeftoiLWCPJ4rTEz3WvetRd4Xdl8D6Zjys6sb+mhJfZcSIqFCD+Zt2eD/YgpgDKdCTt
         DuenRdQz0otWtQZ10E+HYh4mGoi5hFdC1XYPaZql6kofABSpWbv6Q6x6q/pXmAvWY++l
         RuHnhEbCkQwo8jiFaaGlgPIlrFnlZPKdwZi8urq8B4A48tPxOKvrvlToZ5K0VtOzu0kK
         mI/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXBnJOVRzSbil/+0h+XoTO2kIZhDdvaH07hL3IXdgGKngghvOSD
	xaEoYvcaoxxQ4Th9PIpttuo=
X-Google-Smtp-Source: AK7set8WxDXcb8N8BuEacrTm4IaQn+jXVJI9h8pYoslvKC7p+n/u2iKHdk2j3MA7RDI5NtxHqiLWXQ==
X-Received: by 2002:a2e:8e2e:0:b0:295:d632:ba22 with SMTP id r14-20020a2e8e2e000000b00295d632ba22mr796530ljk.8.1677684974234;
        Wed, 01 Mar 2023 07:36:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211b:b0:295:a2a6:79c with SMTP id
 a27-20020a05651c211b00b00295a2a6079cls2726250ljq.11.-pod-prod-gmail; Wed, 01
 Mar 2023 07:36:13 -0800 (PST)
X-Received: by 2002:a2e:c49:0:b0:295:a542:8b47 with SMTP id o9-20020a2e0c49000000b00295a5428b47mr2047763ljd.8.1677684972908;
        Wed, 01 Mar 2023 07:36:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677684972; cv=none;
        d=google.com; s=arc-20160816;
        b=uv1laEH75lA520hQAGbHO9vzcvTMImyeEfss7Zzz9bZayKsz1YAwtN6zsGKRQFL0KT
         rGv6SEkLQIEIekZTvaKGp2lC2Yw7XWMdC4n16OT7hGM64D5saKpzN2nNehgO85sBJsXL
         mEPVZoVm34Auqw2LAOeNkshZ9sq5tX7bQ+RrlrkMnU2KenGS+gNN58XPMjjVRRCLp2bn
         n1KqY9LxgZEAVGtr3KZoI1XTm0nlKXKZukiQYhGxfMiF6yOlq4eMgzD3rSCG7YCk5b+6
         sWwR9Bame3bn3Pt0Dnn1JSfI50T76Zmjn0sjcK6uaet0sa9lVHhWWiLvCr8nj2QxoRMF
         egOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=B997K50RBKGWXSrBUG5MoDdxxD/GnEcdYW4O1Qk10so=;
        b=EenMU4AJwT5IGSZ+Hj3KDFOVO9wtxoAQmVLuJe01r5PcPoyYeTdiNqEIX0aUb54PCG
         c+fe4p05TJYnJTzl82Ddddmg96mS00xzjyI04JhZGq0C9d8WFz6L6446WT8Ad6rFWm6m
         RwTNIimYktQQ6aC0k93pXuj3rqFGGZ1F5BUVnYs4zdeYwLa2B7XNpnrv/5v1dIst499y
         +JFGzJOBjgvc90QrzcGYKiDVD2KAInyEo/NKnTj6+rTu7gwZysSFoieSZFHY7Qiqb8Un
         JWKK73ij7rybwcv7gTOZ4k5Pzc2yapuuah2qh/35GbjVepUITSGEfKgB4A3h1jcXg+1E
         vEfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="rhUgbe/z";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.28 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-28.mta0.migadu.com (out-28.mta0.migadu.com. [91.218.175.28])
        by gmr-mx.google.com with ESMTPS id q12-20020a2e874c000000b002934e1689b9si515961ljj.0.2023.03.01.07.36.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Mar 2023 07:36:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.28 as permitted sender) client-ip=91.218.175.28;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3] kcov: improve documentation
Date: Wed,  1 Mar 2023 16:36:09 +0100
Message-Id: <72be5c215c275f35891229b90622ed859f196a46.1677684837.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="rhUgbe/z";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.28 as
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
Reviewed-by: Bagas Sanjaya <bagasdotme@gmail.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Fix ``annotation`` for KCOV_REMOTE_ENABLE.

Changes v1->v2:
- Add GCC version requirement for comparison operands collection.
---
 Documentation/dev-tools/kcov.rst | 169 +++++++++++++++++++------------
 1 file changed, 102 insertions(+), 67 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d83c9ab49427..6611434e2dd2 100644
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
+2. Using ``KCOV_REMOTE_ENABLE`` instead of ``KCOV_ENABLE`` in the userspace
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72be5c215c275f35891229b90622ed859f196a46.1677684837.git.andreyknvl%40google.com.
