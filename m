Return-Path: <kasan-dev+bncBCT4XGV33UIBBO75ZWZQMGQEW6IUMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 43F1790FA98
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:37 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-24c501a9406sf358550fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845116; cv=pass;
        d=google.com; s=arc-20160816;
        b=W38Vg61EUel7vJ+guoc5F1Dt/4wUGkMd1HqN53Ljssh8iDNqc7Qqm8au70q1deGl/s
         1ldYGVFI3pKYZMoRKpKrP7tW6erGLGc+8xynwvA0EYm6eXBCSTa0xuaDiD/dFp6waw/O
         ESsrl4bP8+3oJJr+/nfyihkpaOrS7el9PwLIbc5I4+suhxeQUk6sUwtRIGe+lwsbd27+
         wFy9BtKgw4aUpEyRBNAQ/3U5xD8uEt9IhDpQbpGLZQ6yg5EhIVHWvq6dw7a8AG7AfaLu
         LqQNDp+JdmzCsP1fq8eF+FoTx425nH3djUOlH7tnk7F8LlWB1YrPmpJR/0g2XZRA4CJA
         JtgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=vSHiiAWJNanwXk33OceDnidygKEnhT3t7wT13lpwRtQ=;
        fh=1lQGguQWxKQKWvuY3HVLiClHrYRULTZTC73AqJuLX4Y=;
        b=0wZOeBz3rakNImE7mZxZ6lusL/eyVjf7ItIlHNjiXmez/FrPbJn+0Tm9d0dgWLO7BK
         9rfySA9YVJrofF5t2/qS9cOVe4DPIDCO2gjtdL/dwX3pKgRNBUmLZPhMpcP89Ddt1t7a
         bRiMNBeqSuKdPdHQIAPF3PZO8Inqc0/oAlHTevPVDz6/iHBZkY+73r0P3uMfgP7p6T8q
         vKoCfVMkS0R0xquJPmNOxlmF4p9vk/cmJyoulDixT1ubld9jbCHal4gdlj8//tduTBY+
         7pwhamJwLq8TIQhxPz16oIflsx1JH6L9ggG4LxWYVtC2Bl76QM4AL6x5307H2CZVxeFB
         Ttvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=tQruxVZ1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845116; x=1719449916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vSHiiAWJNanwXk33OceDnidygKEnhT3t7wT13lpwRtQ=;
        b=Hyv0clBivJWmt/EjUx8zpI4FcMp/AIJpZrV/jgptl7muIKeh3dvcYHafePM6Hl0XU0
         jOXK2HNvBl/C1X7LPFl7pWyIEEf4xkVSMXvAq6jl07Q6juXEiyN3EnQoFQK4fp/zdROk
         c0SHXOUW78X89nQUBvtau4hi1NKOdrXhtPt1d9t+kUvgnXX/xzq7XgCh2U0SYUEIWfYg
         fVqB8Lsh+KqQGSanawAeg0+8lMf3NYxM+Y4jj66pA6eZtZ5EpDBQjEuARj7dkPyPWYTA
         q996ioSXCX9v69zbVvaxIlWTBbBpjtd+N08m8yFjIgp7o5ZSdRtteIppVwAo37SU967E
         zIRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845116; x=1719449916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vSHiiAWJNanwXk33OceDnidygKEnhT3t7wT13lpwRtQ=;
        b=NdTLHB8yOKnEcxVhl9tCu5si//7Eva6lWJGmLQXCIResT2UUjKpbNXmhJhaQRFw16s
         U3urH6yFqkRiaGiVJbe4JmtxN2N1VR9quGSeDeL4r7ml0kp/gFoyAB40S0EqEJuc27h3
         xCZKiL4CHoZ+XfhFvJffNgD09okwr+M3TNiBgGQiocyj5Du4Moj8o4YyX/UjawuZyf8a
         8WxPjOcVEtcEHzM+0790Tvs+4QdiqG4UQ4/Fi3SrzNcRNV1RRMlyx+/bmBXxjyIE6Jgo
         4B8VKO5QGjSMYiGcD2OHYA2sCrKXuhdD2OJ/g7l6mdxLaU+6NDoKYV6tzLVgyqCJDvaZ
         bAFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1/Cv2JJX16GE+96kkBsqLJ3WtzaRKrNKlGuQX6ZShQaBfSueiCVIyGgeT3uyUin2s52sIevhQTDG9I2DfdUMu9E4oVqoM9g==
X-Gm-Message-State: AOJu0YxR5PohiZAd/po0RTHF1dsXwJZLpjWYlqrhbljq1RUsQEHYK4Au
	re5qGeRCVdk4SvqvS81YJ/XrPevXI9iO4RE78QZ177aVhm3o377O
X-Google-Smtp-Source: AGHT+IEU3pPdf1dqsovBPfs+OvezlNHGW2t7MFJGAME6iO0I24wxHppMPP29hRpJG6OSVfngrBLpgA==
X-Received: by 2002:a05:6871:820:b0:254:a1c0:eed3 with SMTP id 586e51a60fabf-25c94d6812bmr4507451fac.51.1718845116015;
        Wed, 19 Jun 2024 17:58:36 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8008:b0:706:4559:9351 with SMTP id
 d2e1a72fcca58-7064559996fls32800b3a.1.-pod-prod-04-us; Wed, 19 Jun 2024
 17:58:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/F4qehBehxVKQ9+06ECmtdx8hNBRJi2lz0SATAP1Sm31iYlVf2rdx95wtjFFPn5tXxpiEcf80vlorASpAstiz6XCwfTfGEYhVhw==
X-Received: by 2002:a17:902:eccb:b0:1f4:5c81:ba97 with SMTP id d9443c01a7336-1f9aa3b5063mr39987085ad.9.1718845114784;
        Wed, 19 Jun 2024 17:58:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845114; cv=none;
        d=google.com; s=arc-20160816;
        b=To7CKFlX8u+K2K++VTKavpjEFhhf2go5EeH6neT40Z5S0CHtqtxghWFoc/1Lp5rvla
         3QmfxS7dZwTMeaWH04tyUEaSzj7csAGPahYmCLXIZyi3hyIp+O0fo7VeveD3Q2UfuxNt
         /+C3wWBcLf0z+hHnyF0Y/eoXdOpBiXjWakWTpb3xqWEfcpKEd3LQHqlN5iuTAqL0xxo3
         P9jZwUPHSEBuSTGWqey+WNfPsdbs1i9xnxTvYf3tv+pixaNI5TW1X0tQZsvJeUCi3Zdz
         66RYpoAokwVN+SKAIPWwQPHXWCBG8tgp+3zm0LPXCXC6S5FmGwkbmI4x0QZYq3p/l5jb
         1S0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=uwiGrvKLdsZqRc+rq2PxbY1fuWMBGrHEtU/VBmAK+lc=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=EL3JdSGMmK7rtrBDCQP2mAgDtUjbUyV9e0KSX9RneOpfcExptVYLZOEiZLXKctVjUm
         AjQLrOJ368K+IVa/dxiBLfhDZcznnzmw9a9GkfwevakGzgl6/taemafLJZeyXgsxNmyg
         DfPokNDCvG1SN2juDfQspR6guIu9rReiOLpKheKovfHKrnvT/I6DwduJMRJlWWt/WlZ+
         xH0mYf8MPJW0712V4yDoNR302sMXfykkbqO4cqnU1BhZwerEky87X/F08lWk6yBQUgYB
         XJDUTtra/6W3qFLJy/zGD7XJef1/uyMw7pO3R6FVCcgvGIwBTvtur8oGVzjEaL6FVYF0
         xpHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=tQruxVZ1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855e2c38esi5549135ad.2.2024.06.19.17.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B6EE1CE22D5;
	Thu, 20 Jun 2024 00:58:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0509BC2BBFC;
	Thu, 20 Jun 2024 00:58:31 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:31 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-export-panic_on_kmsan.patch added to mm-unstable branch
Message-Id: <20240620005832.0509BC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=tQruxVZ1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: kmsan: export panic_on_kmsan
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-export-panic_on_kmsan.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-export-panic_on_kmsan.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: export panic_on_kmsan
Date: Wed, 19 Jun 2024 17:43:45 +0200

When building the kmsan test as a module, modpost fails with the following
error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for modules.

Link: https://lkml.kernel.org/r/20240619154530.163232-11-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/report.c |    1 +
 1 file changed, 1 insertion(+)

--- a/mm/kmsan/report.c~kmsan-export-panic_on_kmsan
+++ a/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
_

Patches currently in -mm which might be from iii@linux.ibm.com are

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005832.0509BC2BBFC%40smtp.kernel.org.
