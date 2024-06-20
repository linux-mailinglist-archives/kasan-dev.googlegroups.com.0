Return-Path: <kasan-dev+bncBCT4XGV33UIBBW75ZWZQMGQEJ234Z3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A22E90FAA6
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:09 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6b50433ada9sf1235036d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845148; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ek8vnhBEIXBKZf6CS9D/TPqOiq+RR1BtbYdyd/HPg8bctTGcn9qBox/OuLq7LhbEkv
         RU0IBVW31bMXvBWmJhT+2iJ5ntx9lWbULyOzxPVgGg7aiyvs829vTWX9caLuUcpBUH6j
         9vOAnmlWL99KOxtoKL0Vd07LtuBLMJb6uuvtKX6PVRY7kGfzmaNYVyJXBH5Wdb7Mk8sb
         Fruh0fZiGhbawhISEVeCDcVglemr8uQC5re8e/AinI5IbfqrSai/0ab/q4Ow+g7mIrc0
         PbCmLGxBZxfwmSL9dcseXr5F4oHIoNIpnEgmryEZXIQstfs+aCmUGNwJ0asCa43V7m+Q
         jKWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=gZamO+ZKQslTqslIIhxFpSL80LYcQ5cgpOTrf6+t9Mc=;
        fh=B+9Mx+F8W7gV7Mbb4VJC9NrSSF7hnZjnaQ0l8HpRhGA=;
        b=eAYGfpyo+83SJayhHaMU3BfAS0T+5ny4EPxhNddV3vbIex9xjApZUKA+nQBXOK1GDA
         +EF0qVNm7Jv5Cq/w9D4COvrN3JMdqS953sji7sH29H93enMDZLPb0vBD1pqL8416e4B6
         L7NvJx4Q/7UvbMjHhV/XB1LIKoH3aosU3kRa021ZkRgsvL7rjZpVPZm9F4CBOagSSZ5p
         Fgn0SUe6yPr9iIlH4hpOZ/o65KBBwdON4eKMgoJ7lM7pcYTIWVspTOzFhV0ibrC4MNaJ
         dSZbdGjLQgM31XRvQBnlkXwTp8gn7VfiYCvbb57LWQIOjuWfUWzMU+c0vZyboVgNTQy5
         0tag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cbSeLQp2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845148; x=1719449948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gZamO+ZKQslTqslIIhxFpSL80LYcQ5cgpOTrf6+t9Mc=;
        b=unmayQhkrT16NutOwr2EVrQ892FKhfunijh2YpcHYW+f+WO44qcYpConifvdC8kM/u
         T3/PV4gm49gUNB5tUqyRvuOYp8+IzOCWe8nKuy6/NLHvK8ZTRe46aPdw57E6UtmNELxs
         OL7lOxluBmMRi4Ahcyb3MhhecSw0F+sW3jUrVVK1pM1SY5Mls2kTqcZw/RHBJOJXhTMB
         4KkKUt9FaioZduwKR40YhWrjlvXjVWgVcV3WSbj/g3CgwQwsv098LQIp1DcxQ2EATBhP
         Gy55uo/tbRI/RsrKt55PCKG9Nt0eBrXq1Cmt/IFcUzMhD3AJbni3A7PDzsMfSc13EDbu
         FfLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845148; x=1719449948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gZamO+ZKQslTqslIIhxFpSL80LYcQ5cgpOTrf6+t9Mc=;
        b=blNfc4bYWEV/OTWRbuj5MaCRK3nyreZekRO34Q6bH5XzBWXbkfMs41FBflxUN5EVVA
         GUW0id4FK7+61g8robMwg1UF3YrIi/pC6uutdbOYpgKYIkv8EcojVwyzAKrV2FCcCxHX
         Z50jqWlijkQpgjzsThaQorZzs/nPzrxSVhM9tcN325OcE+SW4A/gH/PaErMSRNu9AaTK
         DltiteqpLizZKE1xWvkaOSMcqQc0di5QM66SA9vEf9A5hcjQ0h7r2y/4fsbdUMdLw32k
         55XHKe8p8/jZ+ISRPiodexCtsGt5lCBwqC3MQ91ZE+u/kPv+irCP/Ll4eR9Jyc3E1BJ7
         przA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVclyFXK49QSDKiLvFiY+lh/fAWkmBdqVwIUf7LruOnT5mMUaiMAZx59Nu5yJXrHNrjdJv5NmeUDMcJ5SSGXBfWTk9ppyQG0w==
X-Gm-Message-State: AOJu0Yz/VJ5OLlgertSxXM8JjtMAIxRkUbiklncEpmejGwjkrJ3ZYHV0
	14eJ64GhGXPqrCSj+62x5UUvLUnpYB3Hh71SoYVc8GrrkOYsG5Ac
X-Google-Smtp-Source: AGHT+IFs+6oxPOTNcfKBnE+Z9jafPevBOXYWDt2Kbl6LwPdO73mj6RoOnYDyPvaQp4opxk/X5vmVbA==
X-Received: by 2002:ad4:5ecc:0:b0:6aa:3158:e8c9 with SMTP id 6a1803df08f44-6b501d24869mr42905366d6.0.1718845147939;
        Wed, 19 Jun 2024 17:59:07 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3288:b0:6b5:f4e:9d67 with SMTP id
 6a1803df08f44-6b50ff09521ls3133456d6.0.-pod-prod-05-us; Wed, 19 Jun 2024
 17:59:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr9vBpzG1KP0GO/Nabf9p8OLp6ptBPnV9QOo7d4ZiTEOGSb1hWkZ/o3xS1ZR5YwAmuygKtEOjm05lxbnCoJcRi4D0VQziB8E4R8Q==
X-Received: by 2002:ad4:5809:0:b0:6b5:11b:790f with SMTP id 6a1803df08f44-6b501df8092mr42896696d6.8.1718845147106;
        Wed, 19 Jun 2024 17:59:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845147; cv=none;
        d=google.com; s=arc-20160816;
        b=m752Fk+HcM4/an8ge546yGLfoTPQUg9d5DmL0xrivXikpcymSNogNExJwkcxBxncxC
         94BLdCYPXt0mA/xRM8/WJ5dCG9JmTgXTwBSjb5f31IJENO8/ijlBbvfGtKSZdOj6ZCLj
         fDXEdc2HmCabyPHvtW9JimvdDaN2g75dVGtfqiBOgFIccG2Tv9l4OtabOm21lsPklmFA
         O6ThUqbk+NkAumNUDT3yg+GjNtT6dLldbI+DDuU8No8/V5IErMCAJkVsL4FtFRhHPfGg
         Jz35OMh3zoHzAV5qKCC4S0mJajb784RSF1ay97z3wrgTcImUee0cGFGBOzUFPC89P/IT
         S6lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=KMcMshn15WcSeAXkqT/fHpmMrj0UY6hGYvmb5egE3wI=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=yt42B29v0YxuznhbFjDjJi/WifpIerH2LCY/B3Ndh1bzjY7eitZYoWOwoQO5MtcTMz
         kdVsey3emCpV6zghFy3kWgHr0CyWvIMumfhObxet8P5/RfQ59+OWnI76WGPO3MWhMVXN
         bLOMlurjssIwuvLoOQvqNMajSxvSMaUy9o/MzU/6hBqdvnMWqPXN0lOq5SDnS0oKTKJm
         yhgocyUqPdVu+wAh2K+U04valUwtuVJYyLGl2FA9+ylWQD94HVDfXy5AAAcUVwTuvD2Z
         QsheqDoBpYyfdxsa4JV1efZZIOl2+ud03f3+RDhWA+5NRiBjROrMBiEcOfWhYyGUPr7R
         aNSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cbSeLQp2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b4f43a5d9fsi1983676d6.0.2024.06.19.17.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 68028CE22C8;
	Thu, 20 Jun 2024 00:59:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A886FC2BBFC;
	Thu, 20 Jun 2024 00:59:03 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:03 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-checksum-add-a-kmsan-check.patch added to mm-unstable branch
Message-Id: <20240620005903.A886FC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cbSeLQp2;
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
     Subject: s390/checksum: add a KMSAN check
has been added to the -mm mm-unstable branch.  Its filename is
     s390-checksum-add-a-kmsan-check.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-checksum-add-a-kmsan-check.patch

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
Subject: s390/checksum: add a KMSAN check
Date: Wed, 19 Jun 2024 17:43:59 +0200

Add a KMSAN check to the CKSM inline assembly, similar to how it was done
for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Link: https://lkml.kernel.org/r/20240619154530.163232-25-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/include/asm/checksum.h |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/include/asm/checksum.h~s390-checksum-add-a-kmsan-check
+++ a/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/instrumented.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 static inline __wsum cksm(const void *buff, int len, __wsum sum)
@@ -23,6 +24,7 @@ static inline __wsum cksm(const void *bu
 	};
 
 	instrument_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile("\n"
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005903.A886FC2BBFC%40smtp.kernel.org.
