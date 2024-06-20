Return-Path: <kasan-dev+bncBCT4XGV33UIBBV75ZWZQMGQERR5ZHFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A732290FAA5
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:04 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2c7c3069f37sf446810a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845143; cv=pass;
        d=google.com; s=arc-20160816;
        b=M1Joe9i1sUA89aIYcmgLIKb9wksPbALT/Eeuv+fOgA5TqQqIYQsjVFq/mjyLYCH5IS
         iID5Be0smSBgrOLv92XMbUKBBvhl0pAuBV8+md3O1yOPpAWUgc+ZNML+nNqFTWZME/pV
         4HlCiPqItgvaCrl/u6liZKIsJ67AiTc0MpxJkj6k+Kd4yd9kNt21bcFkSK5ax8dQ8sNs
         qz1W/ozxjiw0fbheqnLVGl/KDmrRjzfH1i5NlsgeV9jh/SQa5QW7NLReGuvicQwhS4pa
         Z153em77SNO0B7JyzwTrQoyWadyXoJpROdDCkuXBLcNiMl/Z/4/BKMMQxs5T+aChY8Ov
         InVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=a6A3keGmn1l7Jhk1EXTsSa+/4BIg9Fk76GRdIkRUyUM=;
        fh=VIcqhyOcaJj5AprzmBYFPl+Zc5QfhluiUil2AZaEr3A=;
        b=SHdr+WR02HM4njS6XluZV7zMdjb5OfZRqvwqKNVeTU9HFwFWbHaw8zAfzIZqyeyEYF
         VKjXfxsfnh7uH7BTlSAbTibXjZFNqE8unjzAn1dfKLDuWzSt+fSbkkXqdGZhoCsZHwSr
         zV3D8z0G+abrKY8G7KTfrTqK3igSIEYJs1I4gL6zsOLFoaXZA7IAAujJPtOXQn37nH1O
         Qh0gvPxgo7C1OkvqVJhJaKUWHxJs1BV/Z3ekwwTKauHxs/1c9/hu0Zc+vW6XMaDEXLaW
         fPhzgouH2zSJVShKZ8AmGgBW18sl3DiMZlc/KAia//Z3dBcApSisUcS/AxoNrvZKJAyq
         S6Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Khwv+sh2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845143; x=1719449943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a6A3keGmn1l7Jhk1EXTsSa+/4BIg9Fk76GRdIkRUyUM=;
        b=hQTUC0WUdFBvN1bUYE5g3XJbPEqoQWyA5dwTyXHKRPGJDtFPya5dFeIJDVCAjCejxf
         LZZIQKlRZr5pSvDEvivzUJb7FC4E0Sp0nGJO+Z+uAvHZRagS7Xchmdilwpt9s0vim6Cj
         diS9AJJtau7VK3Pjj44p4mFjyovhTjVbwtlTkbcOSNrT/rmB+3208LE8ofZF63RUkYYR
         IV4OTEciedKHaqIOP1I3+MhHTJQpYTJxd+fK0FHF0CrlRxlwsyhR7kI82PlecPaMwwvu
         vQljxvw8XUz8gj71KH4eYmEgeUH7ocUwaXs4wck9zAzLL6Eng5mE8iBCh/AQhR22hEuW
         wWUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845143; x=1719449943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a6A3keGmn1l7Jhk1EXTsSa+/4BIg9Fk76GRdIkRUyUM=;
        b=a3g5+kn0RKD7ulB/S+kcsZXR3/p78th3AWtQCP2sy1153UK/xeH2MrJDiXeBkhtOeF
         29UVLZ3y4DY7kObr3PdYmzoXlFUdaGRCW/iqxx6jdIZpskRjLl9oppNzBBfFIej85zCt
         aWG9K+uLO7uubT2KQc+CRtGdnTx6ku8KutqSr/oeWeQOevvZGmyCfcEgXACx3TTOQ/Ub
         itXC621lj21TtJm0hwetJeoD/OGTDGaRVjwoAxu8W7T4DUieNHgtLoKp5DDP5OixBks1
         IvakEztYRIuC4vl/FRd+Uc6ZdPoBMlRlsWu9kfk+jbBNl8Cib3fDwN+2d5E+pjB6Qdh7
         l5Ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvmlZWB6uZIh+b+ybGZC9arUXzKOvnL7PGw7VD1RM/2Mc4v/FLCt6FVbkFPGrljSddTJJrsd4ekL881zmXLfs5wc4pHwO1yA==
X-Gm-Message-State: AOJu0YxTRilBZj4Zz2FYftCjAhg8PE4dbjQOY3TWZSXzGT+8JCCMLaf0
	ulcrkzfw5En8+emdc5v8ibxZxoYyjkGjwUscfnMxVsEK7KUVNEPN
X-Google-Smtp-Source: AGHT+IE14UEealJrPW4B872duXnjOERvKMX3F2eeBz3K91NV3RNgc7bzfCRL/XoH8ojfsbRQHT9ZkA==
X-Received: by 2002:a17:90b:4009:b0:2c7:840a:9ace with SMTP id 98e67ed59e1d1-2c7b5dae23fmr3604546a91.45.1718845143234;
        Wed, 19 Jun 2024 17:59:03 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d246:b0:2c2:f25d:8d68 with SMTP id
 98e67ed59e1d1-2c7dfec0f16ls198986a91.1.-pod-prod-09-us; Wed, 19 Jun 2024
 17:59:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCJ33kcEihGfYsZipOhYt9rcOPZsawhAORqin887dxmu02kewDR9SuErtPpd3SONkO40ZxUj2beFmWuJ4Nd3q0UeV6Ra1RIQ+Znw==
X-Received: by 2002:a17:90a:f690:b0:2c2:d935:b5f5 with SMTP id 98e67ed59e1d1-2c7b5dae413mr3589949a91.47.1718845141947;
        Wed, 19 Jun 2024 17:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845141; cv=none;
        d=google.com; s=arc-20160816;
        b=eVQhjFNh1vqIrgPgvKNviYEUm2PGLlzhSFMh6r5D6jm47o+hlqj2xp2BcIjM3s+Tb0
         06PHRc7aXw0wHk5QZDNzSyVvg3HahDEVKKsvz6rVQSSXE5MoW1KZgUyvZCvfZDXv6Y5x
         BNcKs86A8J+VGxoHB/ZGdIMu7PqMHrK6GYelGt1HgDq5uoTPUCnDv8azlJMNyEfMo0Ok
         wghu2SJZYxWpOSGCIzCxHBG8D2U0iGJEFAWgqzBmyrgd0yFvR4jsLpHEuUW9DHm2qctP
         E4iGcb9S9AB91eCttTDEUIY5Y5O0MtALNGYXzbgBGoJAqSNpZ2qV3hTi6qLmwWB9yHnO
         PVzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=so+1Vw0E7466yCP6xMftIW3twkbRSoPX4AAr2mTGvqg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=okW9pPysv1wqER7jOO0Gii7pxf3F2pLATmvM5KPivVc/p1MTyt3V5jgFJdjsgKoRNg
         3ND2iOdf6LWWt9W052zNMpY+GqPFDT2NI70beOzVPZauxg6v6HFzHcQRYanSx0p9y/03
         WgfzM56om72597F62CFchNyLl5LM4qCTeDJXAJcB6mBZqhIJtTB/FtySGk2ZEe5LuJiK
         kGF/sPMIImDXirEHqYEW65HjHqoETNjTA3uixQlPLtbA3ZVAxx6zJuHhlcaX8E86X3Lv
         cYb6Apr+N7cV5+0Gm/CQ9s4YxMMHEZx5fz8g30PCg1sDvBsu/EsuQlmcH1cBtpN/Vgth
         VPDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Khwv+sh2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c70aa24360si447544a91.0.2024.06.19.17.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 41FF361E29;
	Thu, 20 Jun 2024 00:59:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DBF09C2BBFC;
	Thu, 20 Jun 2024 00:59:00 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:00 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-boot-add-the-kmsan-runtime-stub.patch added to mm-unstable branch
Message-Id: <20240620005900.DBF09C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Khwv+sh2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: s390/boot: add the KMSAN runtime stub
has been added to the -mm mm-unstable branch.  Its filename is
     s390-boot-add-the-kmsan-runtime-stub.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-boot-add-the-kmsan-runtime-stub.patch

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
Subject: s390/boot: add the KMSAN runtime stub
Date: Wed, 19 Jun 2024 17:43:58 +0200

It should be possible to have inline functions in the s390 header files,
which call kmsan_unpoison_memory().  The problem is that these header
files might be included by the decompressor, which does not contain KMSAN
runtime, causing linker errors.

Not compiling these calls if __SANITIZE_MEMORY__ is not defined - either
by changing kmsan-checks.h or at the call sites - may cause unintended
side effects, since calling these functions from an uninstrumented code
that is linked into the kernel is valid use case.

One might want to explicitly distinguish between the kernel and the
decompressor.  Checking for a decompressor-specific #define is quite
heavy-handed, and will have to be done at all call sites.

A more generic approach is to provide a dummy kmsan_unpoison_memory()
definition.  This produces some runtime overhead, but only when building
with CONFIG_KMSAN.  The benefit is that it does not disturb the existing
KMSAN build logic and call sites don't need to be changed.

Link: https://lkml.kernel.org/r/20240619154530.163232-24-iii@linux.ibm.com
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

 arch/s390/boot/Makefile |    1 +
 arch/s390/boot/kmsan.c  |    6 ++++++
 2 files changed, 7 insertions(+)

--- /dev/null
+++ a/arch/s390/boot/kmsan.c
@@ -0,0 +1,6 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kmsan-checks.h>
+
+void kmsan_unpoison_memory(const void *address, size_t size)
+{
+}
--- a/arch/s390/boot/Makefile~s390-boot-add-the-kmsan-runtime-stub
+++ a/arch/s390/boot/Makefile
@@ -44,6 +44,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_V
 obj-$(CONFIG_RANDOMIZE_BASE)	+= kaslr.o
 obj-y	+= $(if $(CONFIG_KERNEL_UNCOMPRESSED),,decompressor.o) info.o
 obj-$(CONFIG_KERNEL_ZSTD) += clz_ctz.o
+obj-$(CONFIG_KMSAN) += kmsan.o
 obj-all := $(obj-y) piggy.o syms.o
 
 targets	:= bzImage section_cmp.boot.data section_cmp.boot.preserved.data $(obj-y)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005900.DBF09C2BBFC%40smtp.kernel.org.
