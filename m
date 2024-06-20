Return-Path: <kasan-dev+bncBCT4XGV33UIBBT75ZWZQMGQE245XI5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8863690FAA1
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:57 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-259f021a915sf435057fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845136; cv=pass;
        d=google.com; s=arc-20160816;
        b=esxJTTEn7waCNFVeLM3OujvZkwEPOLRipRpaMrvvyZh+hxyLWfz9yd34cODRoxQTUs
         nDNJizL6o0nO/Hstug/pvpP1l6DzjehwR07c5HKzF6AlJnVCk5+qxy45dENdJTAsSXB1
         UqRmFLbSpmIcyMlRS3jGabwnKglw5xs880Lic2rtb8BU8RtmlPL6/+iSB4AXo4r0xrIQ
         Mc6Dx+J8F+GXJlSZcHr8cit7RtWEHuGWa5zntWttsi8+P7onAO4HWrrrgsgvVCu35Kd/
         /Tkc/CzgzCZ285FntfIVl3Cl3xCaB2gRC16hbFm2DrmBqR76uYhmRpjR/8LUn/yJbTMr
         EXCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=rdG69jZkHB/lNDrhzNX0wvx2bGUDAhqsJhQPpTH/GWU=;
        fh=aSbgPT+9yPHvyHXhmdCY+VfKwYjVs9YxjBWP5hPV9uo=;
        b=Z5B29OEyeK21tR1YQiAISZxSExzd+UgV1lgGYASgHS0gmpoBe87fBC1UhSbGSIpNle
         BsPHRtFWCEKdFMtV0ni8fRESD9Zc2yAkfJcUW2ts7Nkj52TLvuNprsui63xVrXQSG5/S
         E7pu1VWCsH4tCgAfIwPOd2SV9cMCruKxGjmen6rBeGqgkFpo2erkYMwmr5I3Wu3JeLhp
         Bc9HO1KkPSOjal7tSl9sWgWDpY7adJ1FImJ5lhEXDchZgqzarSXvvpih/U7ArKRFAvPW
         s5LnGjKfqKm3Z7woHyHYeD9I8vKVVlG9+58lbIl6rwAJXRTdrEkujaILVFhZ1S7Xy/Rg
         7Llg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PMHrSKxk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845136; x=1719449936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rdG69jZkHB/lNDrhzNX0wvx2bGUDAhqsJhQPpTH/GWU=;
        b=JSSbtCdjfoEL55/UAUfxHYE3iA9fhaqwCSXFk7cWovBEa5hpRMz8xZ1bzb7InPFvXg
         rAbnnA81FsXXVj3oqlNA3FygidncasdVvHPnO2WsMy8G7svod3AX4LnaiOtcGueeqnre
         GF0SIcF0epNpKpyNQR3Of+cb/Ghi9LGA+cvX9cDDCUu/6WGjrg41Md+MdKqbpN9BDSJA
         wTbXWewvUsXTqGZJajLLfmEUIoOMet4jot9NOUTaKk5we295OgBM4TaEgzCSQcM4dex3
         xG/Aq/Pq0UHecu5ddePY45mVajwhbOCDqLk8V2ud1lljwudY6pPPoNt3mJgS68Ln29CV
         3iiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845136; x=1719449936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rdG69jZkHB/lNDrhzNX0wvx2bGUDAhqsJhQPpTH/GWU=;
        b=Uj/mV94DCnWELLJEiyv7igtv89ZNfyUxoKgLB/NGS1s+IqkKAH+FNc+Q45b3WtOWqi
         zCA9lzOrbbkf+3byaxgz2bgZF7q+tjPUup1kHU7+36mdnj8iw2mGKmolGnQdsCcIDyky
         Dg3pPC7yA8xwSUl+HvVMtOFB7IdlMoyESlwcVF/G1P5cYCP3jQtLlZ2HpGdmJKb+i4gI
         1VlW7F3Kcw3hXvLCwhukbJAQlLskLQ/MpQEo8hCts2ZwKpq8L6IyqdVY2M8xmkxOCsWt
         hly8ck0d1SN0Z9J2NtZDqY8c6dWIpsT5FNsYjvIPuLRtkfLyxTtGhv1C7XEs6a9HK7k5
         hKrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVII4BZFsIs1V8VCsPYeCjTCDFPX/qz5T+GuwSdi47+IZ4WFEfdLNQ3luSr47XpVVrVlNvNbz6dm5xbi+xj5hfpHiq56R46sQ==
X-Gm-Message-State: AOJu0Yx1SXS0QJcEsfDSCBNyNyuXPJ6sRXES8o6cRO5nAv8GZsrRR8s9
	X222eeSL1PMKEcarmH93f5NRrFNaP2NCeVLAB4InZGNLb8/1hJL/
X-Google-Smtp-Source: AGHT+IH9gdYK6XlnCXuG76S1b3CvcYB2mMKSyEQxQNtuAiqTo7+75F2ep+mvwplyQFz7E4a3WOiZmA==
X-Received: by 2002:a05:6870:356:b0:259:a580:7a9a with SMTP id 586e51a60fabf-25c9499838dmr4518134fac.20.1718845136122;
        Wed, 19 Jun 2024 17:58:56 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:280d:b0:258:3c95:19a5 with SMTP id
 586e51a60fabf-25cb5f324c2ls475385fac.2.-pod-prod-06-us; Wed, 19 Jun 2024
 17:58:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmRAHSug8UawZFff2ULslpMCAokf6ZmXybz0ySpGSCbzczsmXppj3zyL3+T2ehpQK6W898qIcSxvBar56gUxVDDVbHAtGkCtCV2g==
X-Received: by 2002:a05:6870:5247:b0:254:956f:ff9a with SMTP id 586e51a60fabf-25c94a1f1b3mr4673112fac.32.1718845135189;
        Wed, 19 Jun 2024 17:58:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845135; cv=none;
        d=google.com; s=arc-20160816;
        b=NfZnNka/vxthvKTdElWkeuBEXQKumPB12UXM8gmfw3ZoNCoBp281dkFHL6kS1hF9NT
         YPUTqlH0+6y1QxknE6uVAtVBuV4mM7YA85nhC5LM9K/hKfWLmFzzNzt0H0VpLL98hdZV
         dr+OFScZ6YEqOjeL5zdbcaz6DygmFluiiuT7m0P52wvKwYczTBlCAgnzsNj6DMp+NPi6
         ZuVWgQqBj6i56yEp1LTIGi3J/8BK6wcoWYJVKIV3Z/B8JHaeVKRV2fX/O18bmQ8PEb4Y
         ozEGIH5RIRgAp6FS+riDf6FfKwqx3T+gojQqEo4zKMAJCeoT44di6TjYOVNxAb2omnIA
         72Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=rSg3edSfB+tJqgo7J5oWlUgS87ZLHKIw3Z+CVYTszwM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=b7oG0AXW0ZAbjx2sOcBKC0hUODxkEqjIvjeBm2q4bBputMoydiIm5yl/TbCdy7xnIO
         YLxOWLPDLu4uQyR+zM5tzVXJE9WcAu4K4QYOHVnGtJ5Rp3mlYyFQULdmh7HR66EQsU54
         plkSRd9aZaeI1M1x0YVd2GSGIiYglDtg+vxktP6H7cCKKW1M9yAYmG7P8B15YQ/d2ee/
         dz/pWF8XEjYspiyU/RRclIPc4m23HHelMB640xtQ5XgfuAXBah7HRFK53gnyYTdgxFC3
         v4XJKT/+lt223KpUc4zt6Q8m7SbjTdDiKXNQJljVG05HtvFvP6llDQUqFngGj/s96VyV
         b0Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PMHrSKxk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705e3b26323si509303b3a.3.2024.06.19.17.58.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 24559CE22C8;
	Thu, 20 Jun 2024 00:58:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 665FFC2BBFC;
	Thu, 20 Jun 2024 00:58:52 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:51 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + lib-zlib-unpoison-dfltcc-output-buffers.patch added to mm-unstable branch
Message-Id: <20240620005852.665FFC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=PMHrSKxk;
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
     Subject: lib/zlib: unpoison DFLTCC output buffers
has been added to the -mm mm-unstable branch.  Its filename is
     lib-zlib-unpoison-dfltcc-output-buffers.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/lib-zlib-unpoison-dfltcc-output-buffers.patch

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
Subject: lib/zlib: unpoison DFLTCC output buffers
Date: Wed, 19 Jun 2024 17:43:54 +0200

The constraints of the DFLTCC inline assembly are not precise: they do not
communicate the size of the output buffers to the compiler, so it cannot
automatically instrument it.

Add the manual kmsan_unpoison_memory() calls for the output buffers.  The
logic is the same as in [1].

[1] https://github.com/zlib-ng/zlib-ng/commit/1f5ddcc009ac3511e99fc88736a9e1a6381168c5

Link: https://lkml.kernel.org/r/20240619154530.163232-20-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 lib/zlib_dfltcc/dfltcc.h      |    1 +
 lib/zlib_dfltcc/dfltcc_util.h |   28 ++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+)

--- a/lib/zlib_dfltcc/dfltcc.h~lib-zlib-unpoison-dfltcc-output-buffers
+++ a/lib/zlib_dfltcc/dfltcc.h
@@ -80,6 +80,7 @@ struct dfltcc_param_v0 {
     uint8_t csb[1152];
 };
 
+static_assert(offsetof(struct dfltcc_param_v0, csb) == 384);
 static_assert(sizeof(struct dfltcc_param_v0) == 1536);
 
 #define CVT_CRC32 0
--- a/lib/zlib_dfltcc/dfltcc_util.h~lib-zlib-unpoison-dfltcc-output-buffers
+++ a/lib/zlib_dfltcc/dfltcc_util.h
@@ -2,6 +2,8 @@
 #ifndef DFLTCC_UTIL_H
 #define DFLTCC_UTIL_H
 
+#include "dfltcc.h"
+#include <linux/kmsan-checks.h>
 #include <linux/zutil.h>
 
 /*
@@ -20,6 +22,7 @@ typedef enum {
 #define DFLTCC_CMPR 2
 #define DFLTCC_XPND 4
 #define HBT_CIRCULAR (1 << 7)
+#define DFLTCC_FN_MASK ((1 << 7) - 1)
 #define HB_BITS 15
 #define HB_SIZE (1 << HB_BITS)
 
@@ -34,6 +37,7 @@ static inline dfltcc_cc dfltcc(
 )
 {
     Byte *t2 = op1 ? *op1 : NULL;
+    unsigned char *orig_t2 = t2;
     size_t t3 = len1 ? *len1 : 0;
     const Byte *t4 = op2 ? *op2 : NULL;
     size_t t5 = len2 ? *len2 : 0;
@@ -59,6 +63,30 @@ static inline dfltcc_cc dfltcc(
                      : "cc", "memory");
     t2 = r2; t3 = r3; t4 = r4; t5 = r5;
 
+    /*
+     * Unpoison the parameter block and the output buffer.
+     * This is a no-op in non-KMSAN builds.
+     */
+    switch (fn & DFLTCC_FN_MASK) {
+    case DFLTCC_QAF:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_qaf_param));
+        break;
+    case DFLTCC_GDHT:
+        kmsan_unpoison_memory(param, offsetof(struct dfltcc_param_v0, csb));
+        break;
+    case DFLTCC_CMPR:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(
+                orig_t2,
+                t2 - orig_t2 +
+                    (((struct dfltcc_param_v0 *)param)->sbb == 0 ? 0 : 1));
+        break;
+    case DFLTCC_XPND:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(orig_t2, t2 - orig_t2);
+        break;
+    }
+
     if (op1)
         *op1 = t2;
     if (len1)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005852.665FFC2BBFC%40smtp.kernel.org.
