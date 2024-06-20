Return-Path: <kasan-dev+bncBCT4XGV33UIBB4H5ZWZQMGQEAKXLCNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BCD590FAB1
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:30 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f9a3831aa9sf3489765ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845169; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hg2493RAscX8Rh9Hw8DsHHTf8MjzTCTzNbHJoXVzHiL3rLdU9lircwi/McPy8hiFEU
         ki2Kf9g41z5tAqD3Iy1/c3buWyhRIzE3NMxXdr4/E7qAzmWIRDp03KNwhWATnnzQzWSV
         XSBPeK183CKjoEreCFDHU2Oo5Oa3xNpF4u5B/hvRFwfXuXfPC5dtekVlQnYA2PMLRw5Z
         dRsrGNlj8GHsC1jxI1F/a5N4mo6QaaW5V/dplr8yjcjaKiLhyYGnruOZJnY4ZgMJSpIp
         3F+dCF6SH3sVwOsoXoJN4wZFpCqS4NUV7GWs6dIowLK2/8RllRtbwDNBstrH2HdNGycT
         b7tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=trXT+Xs1KNWvCafZkz1ajpHz1hWGNKcoL7S3qB22aZ8=;
        fh=E5Ae24c7UrrDViT4+j2w0f0AcsZaa9xivaFGvv3Wxp4=;
        b=dHSesirACKpm82RJn8u5gQt90Q86hhhwknngnrFHN6CZP1VpzVF4fQ1H1DnG5D6Ezp
         +tSbAhR3jf3JT5OZg3g9PCQwNtVJybVvpkoVYTpTQKsSYIBqjwPqs6DP+BWoUKaHhvXC
         Jhq9A/85PJFRItgPUm2ZxVUQF5AUwx/a61D98rZi0Uv7fzPdisBAstSGeJAGgZOoi/H6
         3BMLay59TLrSfJ9KIahdlkWKs6x9nqtNV2WlpzxKUvvNB3ns628jojMc3afMJRJtx6df
         nm7XaChSLEr6czdTLrxWmR1pm9C6nhY+nz87xfvXIULH7nq5k+2euz+G3HCDIGxpX4Rb
         F8Mg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FKedlEoM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845169; x=1719449969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=trXT+Xs1KNWvCafZkz1ajpHz1hWGNKcoL7S3qB22aZ8=;
        b=vP/qWmbyedBJ+E6hhFHg2VQfSLFPD+1vprnTSbW3YwShRXPfkM0EuvEWYMmZxLhW12
         FM1tEWxOxtRqaq6QWg3ZLDwMaE4DDxl9/uArokY3FjwkcxbdkwXJc9XgIATHTze+Y0ky
         XrDMwnDVLeXsg/GvjzE89V6+aotXY10iCmViktPOM/SfRj727ifgpHQRn58l+KJE4oHi
         bFq/t1OeV9nJYLh4TRdHYyvLu9+GHbQ3rgH0YKbVCqM5euzR4rj215P4R2Zn6KiCGS9R
         hedQrCjxJuoE6SiV8FWQGPCCLPMV4ckC/dBhNKdCVF9Ke+Lhzbh3N6VYTqmr3gIlxMaD
         zb4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845169; x=1719449969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=trXT+Xs1KNWvCafZkz1ajpHz1hWGNKcoL7S3qB22aZ8=;
        b=Dnd4Gpq9tmFyIfll98llJSz3QtyWh+0MqiRXZrW/eq1fgYqeQOBIWYjmQ5sm1VNjLH
         kz5kokLXBOIxsqmg91IQczV41/ZdHo8Ph2hfxcz6K6EY+6OXYGQAG6ZeGv3JUnYXq6mA
         GCVDVuMFUrRTUhdAqrZXE1QKumPaFF9nVN1F9Na8v0eR5lnIwicAzgED1cBRzc7CDjYS
         vM69QUZhmEWlnLzznSSjntB5ZEY42VrhZ7e61qKbHYdf4V4UKfpx1obbt0HSRz1lAfgx
         TLvJ+XTffgVZ3RnpusuvgAqvFPoSMJ5Ay2j63trce7eItNO1rS2x2Qe2dp1Gk892jjVR
         nnmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiRvOzfKWBr7/CgCScvSFO8ke9+V1NI2CEgp4QJwm/lXwNJe4aIbX7yT0AK4cfE1Vq6fGn65vno2YDgXj9XiXbu+Zp6Bsm1g==
X-Gm-Message-State: AOJu0YzSaPPD5mdVd1M1s/ZoxlbkFr4s3STTBSy5CDQ5HZPhiQP5vhwT
	HKFaO7nIbfAMj9MSBj2wbRdOw1ndiV+STcb/ILbfFMFFcrF+UEt7
X-Google-Smtp-Source: AGHT+IFbQRboJJSNWEaqqXjliW2FokRxZOwzyanVizcEPgPDAlMerjHnaFApmyUJ9iaD0NtGEGXXQg==
X-Received: by 2002:a17:902:db0e:b0:1f9:a602:5e41 with SMTP id d9443c01a7336-1f9aa396eaemr39707065ad.1.1718845168745;
        Wed, 19 Jun 2024 17:59:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:2780:7276 with SMTP id
 d9443c01a7336-1f9c50e6721ls2508625ad.1.-pod-prod-02-us; Wed, 19 Jun 2024
 17:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjsCW2FnLHPHSDW5uvLfv9XiWNDmlCK0YI9OFfY9cU92oCoiZgUmOmfKMtzxKrzUvGG8n0WDBG9snwzmkdDLg/oPz2s8eo9FlCSQ==
X-Received: by 2002:a17:90a:cf02:b0:2c7:b045:254a with SMTP id 98e67ed59e1d1-2c7b5daeac7mr3544305a91.46.1718845167502;
        Wed, 19 Jun 2024 17:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845167; cv=none;
        d=google.com; s=arc-20160816;
        b=A78WT/Fh+y8Q6wXQmaBzSX819ox498/T1fru4VJmesyC3JKKgJqO+BDVqtq/WoTPlr
         +QxKq6PAdjoEu89TCmf+ifWip+RDeK2pZU3nPDJftAACIjraVDfqD9AAyBY7nku5RX/4
         3/2RekZde2ZySL8kba1haIY8E2lNjmBYdMaEEQrSOzYQDR+QGE3K46oci65lha+4domk
         L0AppMB5YvUvdiy4LxKaYTEOZKTjmo5xjKhWO9wRUVkA8oczWNteyYe341vJss4fN5QA
         8vhMWMhnAdoxUaqb6aF/r7k5UQBzCJfHvDwX3bRseqCm8hFKp8rqgWNy5tPoGj541lxw
         j1bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=AGyzFTzs40IPM/r4NA25dgxup94jJwSXk/mqnFoSuDc=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=ZU8QxyRo+0QeBdqAhwDoc99ZoPvxHjjb28rAPmT2FKqhb3JbrKK1GXnyr/4RA4EQQa
         OBWa7thKhdmdnpNPi3b7MFaYLK3yCmnj6lxRU03GlxbOhwBbsQ8iIP6nXTjdqaK31nhs
         F8XwCFEInSeqCnIENYBX7RfZ3fKYLCYuKqiAOFjKzwRQQxDOnui+AqHc9H0O4A9S5NPU
         OrpDcjs1WQp2z1n+zdgCnlRMuqjsaz2nJ/CyMINDHRu+8Mr5bbJf57mkhFto3A2/bXYi
         kdFDVAaAkhtxPJbanPSDTi/nYLStUytbAW7bzZpzaJiVhl2wZ/ZZ4O+eMNe/879acRkU
         qCgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FKedlEoM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e4e0ddecsi25039a91.1.2024.06.19.17.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 73770CE22D5;
	Thu, 20 Jun 2024 00:59:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B7036C2BBFC;
	Thu, 20 Jun 2024 00:59:24 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:24 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-uaccess-add-the-missing-linux-instrumentedh-include.patch added to mm-unstable branch
Message-Id: <20240620005924.B7036C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=FKedlEoM;
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
     Subject: s390/uaccess: add the missing linux/instrumented.h #include
has been added to the -mm mm-unstable branch.  Its filename is
     s390-uaccess-add-the-missing-linux-instrumentedh-include.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-uaccess-add-the-missing-linux-instrumentedh-include.patch

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
Subject: s390/uaccess: add the missing linux/instrumented.h #include
Date: Wed, 19 Jun 2024 17:44:09 +0200

uaccess.h uses instrument_get_user() and instrument_put_user(), which are
defined in linux/instrumented.h.  Currently we get this header from
somewhere else by accident; prefer to be explicit about it and include it
directly.

Link: https://lkml.kernel.org/r/20240619154530.163232-35-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/include/asm/uaccess.h |    1 +
 1 file changed, 1 insertion(+)

--- a/arch/s390/include/asm/uaccess.h~s390-uaccess-add-the-missing-linux-instrumentedh-include
+++ a/arch/s390/include/asm/uaccess.h
@@ -18,6 +18,7 @@
 #include <asm/extable.h>
 #include <asm/facility.h>
 #include <asm-generic/access_ok.h>
+#include <linux/instrumented.h>
 
 void debug_user_asce(int exit);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005924.B7036C2BBFC%40smtp.kernel.org.
