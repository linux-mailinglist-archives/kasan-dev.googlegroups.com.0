Return-Path: <kasan-dev+bncBCT4XGV33UIBBXP5ZWZQMGQEVTAN66A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6155A90FAA7
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:10 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-44051e6249asf3092981cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845149; cv=pass;
        d=google.com; s=arc-20160816;
        b=FKmYaSVbaJB1LSv2X/EToK8zsqybRSv1PxRnBLdAR50YYfVjrMLN2kbZr/5U0ev+Pn
         CdTTmRO3rR9AYXyzUf8hyyeeJajghi2XPMIiyObMCc5hNsh0EpzYeNgxYPph3hWTUO8c
         JNLhOrXeEqkTDfwa9V9B6aZcyahSFxbBlTQcwJsawgMdjj7pEzXxrAm67+IAnGpRwRvZ
         TJechIvlvno6gJ1r64K8KXFtaRX2HIcaZhMfd2+cJQWJCxnWURhxGhLTk5or4y0znPp9
         yabFJuPdVxYvSzSVgAZ+8D/cZQmM25OF1W/duR3HsYSIanVppkqIhMCVq1YccPdyPG/B
         V/OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=4bA1YB2jSTkMXVp3oGd7+N534i4xtSQkQH+xYsclOsE=;
        fh=l9/d+c1ajUAK/pdiESiWL4HWFAWGDDSvXXnKgXAnK6o=;
        b=xgZNeQmK1EWadYijuoOBojsDyk9+wwSWDu14B8dycp4e9wbfi42SS6SfT5xZ9kv0gT
         gaYi1YtS3xlDjHYPXubieuO5YH3Tj2Q2hg4eHgvq6cQ6t9yLB1rowm+ZZbuCq+apY0jE
         QqGX+DILsQsZyIzHAKYaL4aqCchCQOa+OifTPSWBvM82ce6CYuMSsKjz44zmy4W5Ezix
         3F1ju6QTvquXlDQ46kElGjcXLDra5yOAk+ktqld/My6fWzj+IoElkdb6clm5lvMrelXt
         aG3tDI0YZ0HrqtPJud3Qzjh7dAN74fRPN9I9sqa1HD1wkxOdRFrphRk6TUluE+h1h8qy
         NK0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2E44P0Nl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845149; x=1719449949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4bA1YB2jSTkMXVp3oGd7+N534i4xtSQkQH+xYsclOsE=;
        b=cWl44jVagKvUZDfU1liQheEJNV7rgTnzqoFCsNb3NISaWqV+r39yE40P46fHgW84md
         vbTZenizpEHYGR2j46Fm4ZI/7JGtA0QzSB+YvLkv8U4I4tys6mZAPtztdv0Q6HGGWJCZ
         kYn2joDD7+SjlDNrJtmkhl73Ap7o84tHYlINUlV1iUum+3CSHskOTWmSpX8bIc6B8Mru
         xoupk4sVpZ92WF5fHWGdHqKqBUSW1UxPHRKbVoDzEJP842q0iHAhbTYrbhWYFR65MSah
         MmROCzt+b2Gdfev5PJZvOTR04qAb1EoIqfziDhl41x8kddkzh63qSkeIp3+7aPZTMnuH
         MtQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845149; x=1719449949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4bA1YB2jSTkMXVp3oGd7+N534i4xtSQkQH+xYsclOsE=;
        b=dBTul+pvYRNPjbHbDxn7ce2wSErq5QnsEZBDNi3vbpL0qAq+FtaIArQG4kgNAHczqS
         /w1eHzvIIeLUnt/EE/QluGAkCVTc+tHD59kPqXcoYX/+FLOElFtDZMXSgDSYF9WhztIA
         bXaM9XkO+YpXnHFFqHsSIc6XPqUzka7a24Vp+Q9UdCBy8oZerwz3dO+tnEj1pTTG2Tax
         /TBn6mBo86DtkzC6TwVI0o9xEQMxGsghLlNSA3Qu91UaJKCydON3fe/IgH9YwfOWscnE
         Hrh5vnh8iNuWNpMPrXCpoMwKUPVzAzI+qILam4KKuYsu8WRgCes4ehvEUxvWCaHShHwM
         YDxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsyN5ZgWKOdLCzsPAXvCKpW7NNgt0TBAKXQHWRJs7wiTWmJk+gv6yY10cKi5leXxs7s1LiJkqGZbPNHzYnszxTHMT+/LGN9A==
X-Gm-Message-State: AOJu0YyWhl9UBdFZkdcAcGUxE1yZuHCMfisqj6iHzhEDKaLC5/lid4xC
	pwKEshkVXxy/JXQpPPZW2VjJFE4jTePQIXMDJh93XGHcMThR5umm
X-Google-Smtp-Source: AGHT+IEhNfI4hF4OXYY9cUV1zx3K35kj4QofT0k88mi098uNNEadOkEPeLfu0E0Q44CjdXeJm+VQIQ==
X-Received: by 2002:a05:622a:1ba3:b0:43f:ed30:bdd3 with SMTP id d75a77b69052e-444a7a841f7mr47290631cf.59.1718845149270;
        Wed, 19 Jun 2024 17:59:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5815:0:b0:43f:f68f:3e61 with SMTP id d75a77b69052e-444b4c18bcbls3363241cf.1.-pod-prod-06-us;
 Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuqtEQDn2AXiAJCVA5Y9U/HQEUXHE+BgtOoLZEVIy8TP5h4Bw/ynDDxT7qgsNQJ0Luk0SAUZhZVz9EG61CxMWGqJggDEy5pE9JwA==
X-Received: by 2002:a05:620a:4403:b0:79b:bb97:4820 with SMTP id af79cd13be357-79bbb974dbamr271277685a.22.1718845148491;
        Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845148; cv=none;
        d=google.com; s=arc-20160816;
        b=tESl0in5tAlOBIOMtGAgb45looO2bJBHRH7sqno7d6sWF9ijNOKvi17NdpWR5Jb8KR
         +1G285MIOZLhUYJgDiEnyAA8uLB1oRIiz2eNbCWPdmTJRiFPsTOdjB3M93mEhQlpkbif
         aN5rJ68BHGX3D2+7hf9Gj62EGe84qcRRqX+HdygHWAKg+ZF64XV1Afk51oJgq1xN+2Sw
         C7JxEHnCbGdDL9wzQNCOOiCG6WBvLrouPNTosrJ076RorNlbTJCy0OdirwE3jwuFGYg/
         pVnuppYuE/AxWaiAd5/bnm//7VPOp915d0s43QWzz4pobZzxXSpu0pgYc9F716mXNaVQ
         4tEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=S+7bUdfN4HcUdFbra+/JkvK+SR57vWX1poBXMuOfo6o=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=A2tEpIXHz2W83PxWa5ly+Z6jbQpCieslJ5EgsUd7CSiCaVNGqk3DHHtc7AFkMXany9
         8tpfApUjCl67FNmOecSYU33Eo5SZHYu4xBYC07ml1ssCUqglWg7Xha6sBOw4sMQpYXAn
         KwZXlLTFcDYZKXhRtda0oGr8Oju3L3cqAOKrF9Q0ELT5Mn4MJD9y1U58tcVObp7BeYPp
         r5/6ghdZoIOMKloMTsiG79dzJSJX5/lTahKB8vAk61xA2vzLFlp8Xpzfzz2WaSiAMZI3
         ZmPp2RuBSncF6TDCigBnPaBKgPEcYpT1SNsPJmkHZqkK2pdk0ZLQKDeudsQR6E6qMkUH
         QjhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2E44P0Nl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798ac0ada77si68504385a.7.2024.06.19.17.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 06BC362023;
	Thu, 20 Jun 2024 00:59:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 99D6CC2BBFC;
	Thu, 20 Jun 2024 00:59:07 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:07 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-cpumf-unpoison-stcctm-output-buffer.patch added to mm-unstable branch
Message-Id: <20240620005907.99D6CC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2E44P0Nl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: s390/cpumf: unpoison STCCTM output buffer
has been added to the -mm mm-unstable branch.  Its filename is
     s390-cpumf-unpoison-stcctm-output-buffer.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-cpumf-unpoison-stcctm-output-buffer.patch

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
Subject: s390/cpumf: unpoison STCCTM output buffer
Date: Wed, 19 Jun 2024 17:44:01 +0200

stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
understand that it fills multiple doublewords pointed to by dest, not just
one.  This results in false positives.

Unpoison the whole dest manually with kmsan_unpoison_memory().

Link: https://lkml.kernel.org/r/20240619154530.163232-27-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/include/asm/cpu_mf.h |    6 ++++++
 1 file changed, 6 insertions(+)

--- a/arch/s390/include/asm/cpu_mf.h~s390-cpumf-unpoison-stcctm-output-buffer
+++ a/arch/s390/include/asm/cpu_mf.h
@@ -10,6 +10,7 @@
 #define _ASM_S390_CPU_MF_H
 
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/asm-extable.h>
 #include <asm/facility.h>
 
@@ -239,6 +240,11 @@ static __always_inline int stcctm(enum s
 		: "=d" (cc)
 		: "Q" (*dest), "d" (range), "i" (set)
 		: "cc", "memory");
+	/*
+	 * If cc == 2, less than RANGE counters are stored, but it's not easy
+	 * to tell how many. Always unpoison the whole range for simplicity.
+	 */
+	kmsan_unpoison_memory(dest, range * sizeof(u64));
 	return cc;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005907.99D6CC2BBFC%40smtp.kernel.org.
