Return-Path: <kasan-dev+bncBCT4XGV33UIBBSX5ZWZQMGQETQ3RFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E732F90FA9E
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:51 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3761e678b99sf365655ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845131; cv=pass;
        d=google.com; s=arc-20160816;
        b=aWnSORAz3thIyV3Kne+mVSI5JBdaj74s6hIdMLGkvywPFQ6kkMf5yWM+eJsEbkgiti
         0xZcNS950OrGgadjNsOhk8BsWZ34niXnvYl83uBkQOBLu21xgfonmJuhjOUymIRFYQyo
         3dkVonIES9JwSV32Ovo8B9lmK6JVVorqOMc/3HN6WF1GSnwCTcKpjLnSC+Rh8BLw21JR
         gkfLUXFh0+PVt/sFsQO50WKqkMYgU0JzUrYSG5jkqsSvvbepJPCa1rd7CdCJ50gAono9
         4rLan6gY1zJadm5FD0UbtqHWtzoT4CHMKrhWZexjcOGfg9iTbgDUYsEIx3WuW8fA4cRU
         qIow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=NKs6EkWJdl/qk6SfKtyh+rzI28W35f/5algSBeGUyTs=;
        fh=M16Phel4lI2WQwMFlhUi8GB93lV5fxDsGpRObE+rxgA=;
        b=uo2AHtieMTWGLtvyMD99n49vR+1sQEqcToWThKcZN119AtxOQdUThhi+xeQhIZ4fD+
         06PsMUitjRNjcMM+Q+uQQtl0VuKwAceQ8b/eWthdO2cJDTYW0UgYJTmydPhTZC4YRlO3
         uRz4R18T6nOXt2GKNxjfjSs/9EdSKXTapKioN01/JO69K1jG2l7YaKERBzRCvqIB4LZ3
         WR2krw+t11bsbk2Dm3YJVm1pi9TZEP1LLv6YOm9qyISYEULnb/AyCtGwz0vntXSRCbxu
         WsdrecHdIeibm2PAyZxqSD4lakTJACy7ws9gXIib1LHRlvI00t45r3mtrSU74cECNIHI
         B7sQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MD6PmYuO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845131; x=1719449931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NKs6EkWJdl/qk6SfKtyh+rzI28W35f/5algSBeGUyTs=;
        b=NgndkazQrX/KTbD1v9XYUTKFXoFIC/sjV5DndV8m6blGqZK8+sX+iaO4EaeYWlBKHE
         00VuRigSvtGzohOoWgNkBn2P97dpVPOt8nazlMjLbpKUmL3adcpBvIl90GlqtkwnqDMU
         wMyJS7MxP4wCLprqObgqbtTHd26eXveXU6zk/UFxFn9JhJ/tzGK1WqwaGupFWGJG3xux
         xHLOEbe3HzZfVIbNiUy+NdNXB7q8Ssb6YiGodOKAnFUxv4Oaui819cHwQ6NQcbCiaoOC
         fIU355vrPoiS7KpOwmXdX8dWuDVHaQTonqc2nEVe+2K8jrzlMrK4NQ+u+ZAAXbpuZ2w0
         IbrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845131; x=1719449931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NKs6EkWJdl/qk6SfKtyh+rzI28W35f/5algSBeGUyTs=;
        b=PMVDAhYrSBDdwHxILWwm2zcReQ9Dk8OI3C0ffV6a0H6UeLn4OsZDuFTdDb5801j9W5
         bkcjscE+M4vj61FrHzvG6uFKlGf0DTQBRilM4I2/Y9a9m2wkxPYMZQg38uc8h2swTUVu
         ZlogN5dbonKKJMk3ca8OifS3qYhIyGk5pFwKPbrGwnp+yS7Nk0zn327RLwq0PQGfw9C8
         n9s05IiXb/oLoopy7eFLZ8xd1n4GF5ZH5+XrqkslhTbD1sCDiyXe9GHUsQbokWpnvwKn
         kFsRQIkCjBDTe4GUuIiT5ngA6l+5tJSeCXXR1cvPDjW7iaucKCI27SAmzL034A1rffsn
         HJ6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKEel/v8xnyz8I/FH3a/mrr37KTvXQh/y9e5izuHh6lzAzPkV0AbMj75q66RJtSOQWI8GfX2jOM9wUpgWc6u87SlryyznrfQ==
X-Gm-Message-State: AOJu0YwbFDwjoSXQSyOCG5g/q5CIw5JxHi+1cMhWhUoiz4x7c8n/CFM7
	lwKII1tWARnlDn/F1nEy4sD2jP+E2lVNyjE6CUGq5PAVvSTQ0k+D
X-Google-Smtp-Source: AGHT+IGQYDdiDVU2A/0K6tFZrn8sfkMzcj9/5aoY8mtbMKLTp7KhWjjk1Z8eZv0y35/mD/I8ea7vTg==
X-Received: by 2002:a92:d90b:0:b0:375:f1f7:c53 with SMTP id e9e14a558f8ab-3761f762c7emr3497125ab.7.1718845130641;
        Wed, 19 Jun 2024 17:58:50 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:280d:b0:258:3c95:19a5 with SMTP id
 586e51a60fabf-25cb5f324c2ls475347fac.2.-pod-prod-06-us; Wed, 19 Jun 2024
 17:58:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEFazF20ByNLLO9QvyNVpIS5jcCxiNdwzInq1hWKgyrPhCISHA/HxOJkUMWCXxor5M6K7I42Cq582Vk9v5iqkRtZOy/wsnbbaePA==
X-Received: by 2002:a05:6808:3089:b0:3d2:16dc:f8ba with SMTP id 5614622812f47-3d51ba1b4f9mr4591572b6e.32.1718845129779;
        Wed, 19 Jun 2024 17:58:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845129; cv=none;
        d=google.com; s=arc-20160816;
        b=YR0cU3YbP7TZYRXvx52AKURRxEN3v2rEx0+Dzt4aZdw8MlJOp5Ge07wdflXkp6QQYA
         lzoFytmgSdKsMkheKPUWD5qzlry62VkcTTjKjJfFHuD7Yf3FHBhwPYvmFksOZIOuYAgg
         u35iNK+6zsN82h+ZT+bnzkmlT1ZOrG9Z4DkFRH0Tjaj29P3cSwQ6fPVbCuJIbNQWystT
         ZF5T4BwTtpdoVjl+BipsCwacvSdbuhvra7f204wb+gHLdi8bOhMNmEoJLb8C/08uUo+E
         1wGQNStzUnVcHEDPvER6xWhehlxH0+pZxR2gtQLYsi1v/gXrENcThJzssCOWKm9/MgQO
         NxSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=DnYZce+YDMNVe7MZ+cHQV+GtuaaxsDsBpXfWapbY1DE=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=RgN/KGPx+/3r7XG1JYMJNF0UxkOYqUaaMhM5MhF1FiTO2ijjpirqbFFAGE+u20boc0
         p2nmC+Dyws0IKL+0xiNdsKGJ8b1JtXEcqdazzBo/K74BUfwj5D+s5DUejljy5m5s0647
         9RzCamyKtlTje0nWBYf3gTeT7mHB28ghda9dY2GlnI46pyTBI4t644wAekvFscufsyFz
         j1b73oil0zYFMrxA7Cjakp6a0Om578jxJpFeAcNI4geiCUFSMOkWastRqjGRKEAo5vcT
         8UPRic8DDjtN3yp+MAm3qXkrfPhVR4KwuhVQPvUyMF0KCR3gEvT5Wexap+apihc7llR0
         VRlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MD6PmYuO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798b52e0254si58322385a.6.2024.06.19.17.58.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 108D1CE22C8;
	Thu, 20 Jun 2024 00:58:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53CF4C2BBFC;
	Thu, 20 Jun 2024 00:58:46 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:45 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + mm-slub-let-kmsan-access-metadata.patch added to mm-unstable branch
Message-Id: <20240620005846.53CF4C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=MD6PmYuO;
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
     Subject: mm: slub: let KMSAN access metadata
has been added to the -mm mm-unstable branch.  Its filename is
     mm-slub-let-kmsan-access-metadata.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/mm-slub-let-kmsan-access-metadata.patch

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
Subject: mm: slub: let KMSAN access metadata
Date: Wed, 19 Jun 2024 17:43:51 +0200

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes KMSAN
to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable() and
metadata_access_disable() functions to KMSAN.

Link: https://lkml.kernel.org/r/20240619154530.163232-17-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
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
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/slub.c |    2 ++
 1 file changed, 2 insertions(+)

--- a/mm/slub.c~mm-slub-let-kmsan-access-metadata
+++ a/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005846.53CF4C2BBFC%40smtp.kernel.org.
