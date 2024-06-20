Return-Path: <kasan-dev+bncBCT4XGV33UIBBVX5ZWZQMGQEKOCOVCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B7B090FAA4
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:04 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1f9bb14b0bbsf1582755ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845143; cv=pass;
        d=google.com; s=arc-20160816;
        b=GaGovENpZgW69qmkY9/YbRPOAl7QEs9kkCkiOKbRdcuKwTzkRufiPQtDJoLYeLNTHq
         nJgUbee3Ly6ymNy9jUjML99IkHlVVWQax915dKZD4bTe0e88lgo3k9SDQwIJLPub6Dwb
         ANL22Wjg1Yo0PTEOUP+EwIBiaEJXq9D4pcAFGlzh/kGt+BoJL3XKYnNX436Bor9m5hWh
         ZHKE7wf8/s2PxeHn2+GXOevo+3LSQqZR7pQsHcHTLeatJBAmO7oCtJ8gM0tn7o1++i0c
         oIcBVjSfSZom0q6ITehCKjEgQsrH5AZbPPVFWwN0BnM50V7MRoW5+2oAPCLwdhYG0nex
         yZEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=SVwFn4CjzJ0YvsWW8e9kCEBfqSl71++Fx0cEZYgZ2os=;
        fh=3QTeiQ/vDek4afNLYuMj10dUwxMWpfcoTe+dAjWYxoI=;
        b=WnbalJAE4Zd+WC8iR4twa0F3CDmPTNP0WdpuBfuu1WzgTzscZglgsghhI4SUyc/MNj
         PVDc5wP3NulMKlnMPyb7S4FW/ImykeFAOkWxM1uIM0h9V8gzLd7BwfIFtc2JMGUrr4Xc
         qSL8TAlWroea2tLLMpkWAz3o8GXydcpSOpMbnijkai99qAOBneou/k2D5EenlZtkKQIs
         OG/4NWHKM8gMnbGvtBhjruH3SpSSIxZAhGl4YjmtdVZXbXU5RoM09dHwfcySHI9KgkpY
         IUllkTNGgsQNcjNTKKb03WanqaLWlPvveilM72gj9naQJasWe4VojdUDa+DVURzIlhWc
         dUTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PhGN6wik;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845143; x=1719449943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SVwFn4CjzJ0YvsWW8e9kCEBfqSl71++Fx0cEZYgZ2os=;
        b=ivSRNaimHWXo8cFFfbY5R8+cfcL6NxGGv1Z/r+fEyFnD1v1rQt+a4iDpqHqxS0Uv1u
         4WVtQkYzsnESD1KULbNMIkVfgd2PULLyP5Aqm5HlEgTjdvfqxp9Yl7gAqRS3e4qRI0qi
         9XgJouGz7CQb1u8O6TzUU4/Zn79twThsmYzKYtcN1ZDUgMPuJuiyqL68yyhYGAmB2BWw
         A6GIzGej5hwWuRYrWS9A+QonlSFmK+wg8tPA+W7UV4jnqjy0+GWJYmknz6p7BV6hClQh
         V/hDZk42UcGoNkvKIHa/6s30+uss7QceUjcj4pqZ7dYjfPTC/zmCpatSiiyzffaiSdj1
         cz5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845143; x=1719449943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SVwFn4CjzJ0YvsWW8e9kCEBfqSl71++Fx0cEZYgZ2os=;
        b=NvqNtfP4c/Jr2x3YD33QQqsEcXoJyBY7ahWEhTePSKMQG7GTqecByx0EjvHkaVZdjY
         IaooCpzZxKPOtyGDzvPO7+OClNwEYcoxgkH8YNIoEVyCcv4K39c0HiBrzhkZAB+nDvRT
         nW+FFvK3X4gQDfSIF462TOwm8FbvaeYxvWcYiZRcudJxfcU5Gvz8FsFGMgE7rhNbxiLC
         Nuw2bw1d9gRNB8hCGnpCQAAUIw2ip4cory6EzRlPErxjGQhxkg8yoEJNWnzoywL/1ehG
         5klPIXiJEuXU0OqXLT+4CkckBXGapwiDmFT5gJEEh544/RKvTYFhwJAhlQRx+5XoeLAn
         F7tA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+xSN7N1j4Rw+VOZgCNzO2emexXCtB3Kc8Wa1jeNYm5wCUeV2j/d8xM5UtSB0ihZ6z0tiNhBdqZJQ1mzdPPN8N/U9t2Wr7OQ==
X-Gm-Message-State: AOJu0YzP8MjpUkvSlxjppEUt4decTpe9YT6GSjxaFff+TNmEVW/rVW9B
	xPOxQ/pzzjhB0mBBYXCqTz/ArdwdC9rzy3+4DdvE79HbhOMloVbV
X-Google-Smtp-Source: AGHT+IFo0vfQNz3sXX3OTE5wyX+G/BBrV29DAnW5sWWAvjV/pSCwQ6vxNGFrGKkgsFBVMN8ZcNH8fg==
X-Received: by 2002:a17:902:aa4a:b0:1f6:6754:eefb with SMTP id d9443c01a7336-1f9ae0c7a0amr3434255ad.21.1718845142660;
        Wed, 19 Jun 2024 17:59:02 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4086:b0:705:b94c:2e01 with SMTP id
 d2e1a72fcca58-70640f49b31ls225378b3a.1.-pod-prod-00-us; Wed, 19 Jun 2024
 17:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+QRLI42orrHD0nSSgaBWwRbzRWHRoSOqVZfA79t/Fla+iCT8D/k5d33qqqF3ItP14Y2uxDiVMjZnUOXiOlYdz3bgrGgcnjh47Nw==
X-Received: by 2002:a05:6a20:2589:b0:1bc:b15f:19f5 with SMTP id adf61e73a8af0-1bcba15b38fmr7148350637.7.1718845141389;
        Wed, 19 Jun 2024 17:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845141; cv=none;
        d=google.com; s=arc-20160816;
        b=MsL/wjHMaNhHaE2bAI6L4poM3N+LII13MVLwLLpOkU71M2XcXQ1ExWPASgcXiVkGfu
         LwTuLRSZvgHVbLqVPGKZ5ZQMxd6/Va32TRadxpqAbZ3I/xu2oZx2JVkoLHLv8fdnJ403
         2/3xLUJ8NVhLR0e2uxDPWL14OvwxC3ZHSOn6CfyHdg+w7Z3tpYzTjOPNGdHUW3791Mjc
         gkA5GqJ68O1gEjWVgqa6BQGe7jb1WqKKzOI2IOCm7QngJINwrKvei4gxTa700Zy/PLYz
         mExQJa4ZI0PLcPYOSFDg3RZ+NlSXsAfjw/bexbNmsDmeD+kvkQouQqEhwoQjMMJDPl7C
         xyBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ium8zpAxEqFS8bFp3dt/YKyYX6Z5JbiIS27+E9q2S9k=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=ibqTz6f3PRVhZe+HMmkwAEXH8l5IVgVcBL5ldDYnu3UvA1wZ6flhWS0Piaugnj5lRK
         UdO0fk6OUTCUG5GphnGMj9GsjHz6tEKHdobb6pRbFqDuAaNGAl7mWIVN9qAI7YWQjkUt
         6R691E5l15lewoOt6m57ug5eOni/CML1/LZiMuKSj9qJHYvKuI2BFEueEiAFQn1CwHQ5
         4nxWxBnc3ejfF/dGGIrfygO58+8o9Orxi9OjPGSkgt5Bio1Ifn78wgsHkXd4PUUsF1Re
         x1MAdDCVc9hPsPU1HejZScc0Blwmca/U38LpjEVLHUXMk22LE8nfULYGx9kVpTTI++3F
         5zVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PhGN6wik;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705eedbcd30si425900b3a.4.2024.06.19.17.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 50BAFCE22D1;
	Thu, 20 Jun 2024 00:58:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 92442C2BBFC;
	Thu, 20 Jun 2024 00:58:58 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:58 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-use-a-larger-stack-for-kmsan.patch added to mm-unstable branch
Message-Id: <20240620005858.92442C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=PhGN6wik;
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
     Subject: s390: use a larger stack for KMSAN
has been added to the -mm mm-unstable branch.  Its filename is
     s390-use-a-larger-stack-for-kmsan.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-use-a-larger-stack-for-kmsan.patch

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
Subject: s390: use a larger stack for KMSAN
Date: Wed, 19 Jun 2024 17:43:57 +0200

Adjust the stack size for the KMSAN-enabled kernel like it was done for
the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double the
stack size").  Both tools have similar requirements.

Link: https://lkml.kernel.org/r/20240619154530.163232-23-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/Makefile                  |    2 +-
 arch/s390/include/asm/thread_info.h |    2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

--- a/arch/s390/include/asm/thread_info.h~s390-use-a-larger-stack-for-kmsan
+++ a/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
--- a/arch/s390/Makefile~s390-use-a-larger-stack-for-kmsan
+++ a/arch/s390/Makefile
@@ -36,7 +36,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CON
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005858.92442C2BBFC%40smtp.kernel.org.
