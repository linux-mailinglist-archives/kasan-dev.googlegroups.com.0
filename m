Return-Path: <kasan-dev+bncBCT4XGV33UIBBXP5ZWZQMGQEVTAN66A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8EB290FAA8
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:10 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-627f43bec13sf6327877b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845149; cv=pass;
        d=google.com; s=arc-20160816;
        b=0F/116lCYnC+sd/JiQzuhC/PYCdGLMJLSFp2YepK9h0QgegqLmrP9F8lMp2wYpdEm6
         g2qXXI8OWaLy7l4bB0z9omZAgT9df99j1WVeZS4QHdcoR2cfgJzn1VxahTJrynGc9eFP
         nLNjAav4S6c8JcDNRdnqi2VuIzup9X/Yp3paTw5t1ghFfbe526KeLB5eH8v/so8WwXI6
         3txr+YCVdWc1m7zvbyP1xprHyDNWx8bvSErIQ4engOEUq9NZVLJjuHTZO3qI4+vhcRuJ
         ZbPn1dv+LQLpmY6zjgotW2/KkxvYAuPvfW8HCDPHU41NeIgFSczWSV8po4Wun9AyU1OE
         hIvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=O0+S2fPQT8RRWkjZYw0bgNfvr4H7mktYb0+pQGCt9QA=;
        fh=fLAY5geNp/QhC5OxHznwi1KRb5SwrknJoBURvIUV2DU=;
        b=F+YlnjgrWlcG13EolZ6cDb+v0W0pp3dZcTXa/L4TyYs3pEyFtmSQI6IdPrZTKh54Yv
         kbOePNZTS5RQA2d+lyU08qZBUKJ7gIPUAL/Cchqz/OHJkujed66DmFv7peHKHmvLC4B5
         VLDXIMfvN0TW+20BfyWag6DJZjbvt72bZssNZLdQgZvT3+AocUIKIiJeq3z653eLUE9T
         3XzZFbIPfVyneTyBdE9egL0u6rmB8+oRWDsh8lUI0TTOKOXQwjWPrKVHeIC2fyD5PFOm
         c+7AsxiPQ8QyD0+5NXl+n0zEk8P9cCqIjDuhMigfPk6wxSyb+hAMKygSmL3deA0nkJeN
         AKag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JfEz4XRm;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845149; x=1719449949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=O0+S2fPQT8RRWkjZYw0bgNfvr4H7mktYb0+pQGCt9QA=;
        b=J2O02OndwLhqfWPK4sDijJKdbENNfpsqlb7EDhGW48U3+zrOpjX21l5f2UkKNLq/7B
         Ovo0AanHE9w/seXXstiwwG7tkWrsQCH0UBXjwni+iHL4FCVW7rQ1f8RPVqV5gLL4qAaM
         rZeG19rHL0N/d/ve54XQtvQF4vY0o5c45y35Jm9xeTc3FcWz6FGc5SqOQ6H9Vxg417op
         CT6Gs9/x5X2DDTXbRgLXxwb5+MdaZlmpn5JXdQqqKpQNbkQBO0/lqVkZJCDHjIkvmObp
         r70GwFG23HVntGGoUwQmfOLAOtdlYhPUhZ5tWKPjE12hoDvq9Bf9aRVoFR2umKjiiUvV
         6zdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845149; x=1719449949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=O0+S2fPQT8RRWkjZYw0bgNfvr4H7mktYb0+pQGCt9QA=;
        b=iaArCslnUUJH/CqxemvKc4TC53/3ULkecpef0izSh2yHYZvo1IkyASr5FGA94A+Y/l
         oTJ/rAQgf3x385/BsJE/TOAEjtpkp6X8fl+Dmyax1CWsXNvAJPfJRGT6aKhCltiWqFke
         dnhzQkKgA/M6x1ZmBjsAvdv9niqrUt7KmNmITqvGmDx4yawxxMa9ZnlukyY6SnB/yNw4
         NdegHVjK1ZcKHHufVZrWwnLGxhJ5M12WGtOoGcLVGxsE6qz80TYgT5EEXbS+3nl0R0h7
         YF7JMM8xifv56Mo2LSYxXTuqpYsB9FBjkU4MThw0/u0vlYVGJ9jpR7ldhonaWUFTBLJR
         JwNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2madX7Oq2YqROnwhAUmUpkUYKgkz6Hv7N3IvYRnve9Fw7CQ+YO4ne32CyU5Q5Wjjn/fBLXr9E1El2Tt0dWvmxH2SG/LrFtQ==
X-Gm-Message-State: AOJu0Yzl3MQSeBou6pw2mH0kWOxMi4mW/BZFaVzdIfvXsUj3+QSuBGnO
	AiwRNV3Vxc//4gBb9i3ztLskIC4V+1eGDDYxpkDuNSuciItrx1ZU
X-Google-Smtp-Source: AGHT+IGj+2XnlZPEWzEivDm+MtDkChoKVMYITjdPbAPq7aJDcHytZSvd9aqi18ZgWci4kT5IPJDc/g==
X-Received: by 2002:a25:9342:0:b0:e02:9b7d:57a with SMTP id 3f1490d57ef6-e02be205872mr4331921276.46.1718845149481;
        Wed, 19 Jun 2024 17:59:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1887:b0:e02:b40e:8e90 with SMTP id
 3f1490d57ef6-e02d116cec9ls605310276.2.-pod-prod-09-us; Wed, 19 Jun 2024
 17:59:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7cJ/+a0vfaltGfBGd3f+P5LaKNr1nZLhsOd2FAn/Qkc83LIb14IqJbGMngdeHiYcaMCD0L9S8b0gT0FPVMn82jb1lLcunOoPBAw==
X-Received: by 2002:a05:690c:80f:b0:61b:1f0e:10 with SMTP id 00721157ae682-63a8d82c04cmr46627437b3.4.1718845148725;
        Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845148; cv=none;
        d=google.com; s=arc-20160816;
        b=QO1E7496xDEtU7i2TvN5QUMVqELr+1eRzmqGVCx7PJGZ37JHeVMb72Jp2w1RiE/+mA
         GMQ97tLnHVjWWptghdLR+JXBhCePLKncNG256RrICz1457AEqOHpMT23mMnTTirsM8Ad
         NLNy34cak/2Py0xjz9AJJUMDc6qDxnDIWxDixJY6OcDUm+LLMbc9I5qEs4TfGczZPjvb
         tOrQR9t7HeSUQeuVPuTzI8+3R4ELORV+iTaDQsCdir0mZPRDzcLlIZjf5cDOSbfPq101
         DXTD8I551/ajCqxJBYld0x0hr9I4wA8CEvwuWndYi+2p9W3csS1DZulrjrbW/OLnuAIa
         lgvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ibOyK/SmfEsY1hY6a/VyH3aJ20sx25oVbFBPRMRubuA=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=WOsiu++tGHu+d0BtVaJBkelhW+pK3uZfcjmjd2Ea7tE94bFJAnV+tGQa4P7Et1GLvs
         ECjv1V09H9KO1wuWgAzJdz/K9gYhb0R+7gm0+aIwdMSgs4UYzCubQ6VVxmGK603enbEs
         rqW+lvYd8E+7S02x12ggZ2oiNAegDNIERuksA/Zj0SOUxAEb5z9oAAl2TWiD/nxFdVg5
         QPP6fVRg1XhrVflj84q+ka+MyKhosO/McUWkI8nU+xi1KYmDF32o/Rhe/cMb+WkfHKYv
         yQlTH4jZX3bsyxe1r1ZSRHV9PLAmMcQM/mDOcrtX5S5tS606AHgSeSbNuXnLMh1TWJP9
         sneQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JfEz4XRm;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63bc513add9si759107b3.3.2024.06.19.17.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 5F6D7CE22D7;
	Thu, 20 Jun 2024 00:59:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A29C0C2BBFC;
	Thu, 20 Jun 2024 00:59:05 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:05 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-cpacf-unpoison-the-results-of-cpacf_trng.patch added to mm-unstable branch
Message-Id: <20240620005905.A29C0C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=JfEz4XRm;
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
     Subject: s390/cpacf: unpoison the results of cpacf_trng()
has been added to the -mm mm-unstable branch.  Its filename is
     s390-cpacf-unpoison-the-results-of-cpacf_trng.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-cpacf-unpoison-the-results-of-cpacf_trng.patch

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
Subject: s390/cpacf: unpoison the results of cpacf_trng()
Date: Wed, 19 Jun 2024 17:44:00 +0200

Prevent KMSAN from complaining about buffers filled by cpacf_trng() being
uninitialized.

Link: https://lkml.kernel.org/r/20240619154530.163232-26-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
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

 arch/s390/include/asm/cpacf.h |    3 +++
 1 file changed, 3 insertions(+)

--- a/arch/s390/include/asm/cpacf.h~s390-cpacf-unpoison-the-results-of-cpacf_trng
+++ a/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -542,6 +543,8 @@ static inline void cpacf_trng(u8 *ucbuf,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005905.A29C0C2BBFC%40smtp.kernel.org.
