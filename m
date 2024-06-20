Return-Path: <kasan-dev+bncBCT4XGV33UIBBSH5ZWZQMGQELB5X5PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF33090FA9D
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:49 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3737b6fc28fsf12711245ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845128; cv=pass;
        d=google.com; s=arc-20160816;
        b=x3q5ByUawG85AoxSfCANBNoFMgxwl4xNPLODUUWA/NOVQlwW3jUZmPJ6HbVpt9BP5I
         i80VyZEwVRhiNW4guyYgPydGPuzgJtF+xMBxaTUh5AU/rvSjGEM+u+u6jYYdhWe8FBk4
         v0Yr0cE3iEzEHcu1SrBQu+i3zayGYvustAaj/dWmTFzRIQDqtp/BM/kPRoHS62yAWtri
         U75Q+5QHj8VfFCpP1dF+VyFTUfNvXgyr0l278hM9Yg2BCJiSF5IAvZLaoOd4y7l8Z0UZ
         Gq24lMsTiyMlSm1SLih7+Ox1jiZoGiiKUqM6cfX+R8vwXR6S/mRw+Qh4Oj24PWDgZXd7
         xRsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=miwYfEyzr4R6utDKTB8xJXy6zLrMd/gTxj7uWLIDMU4=;
        fh=MYOSV0Mtphorw1H2hCStcXPO44H08ixcDXjEWaKmvmQ=;
        b=ghadvBMT31RgmI4yLIVj9UBblac81H4JZH81HM9BOxSfBbY+7Dtf5hczcZGUbFT4VW
         aoeSpybdOPKDpVUKSBnbfRY/amH7ZwRUo0q2IPYf8sYIKOmwh9dbzy3dYnoqCKaHDElZ
         lmtMhfYeo3DamRfjISTYu6wZovKCy0saqdjfqtpJVIJO+psVvKw8maRsq0+Vhgen7T16
         bAg5/9YB/q3oZyh0Mk9LppU6GNtB2NS2Luvf7KiKcwg74eQhDrgEWUlITDvEajlLgAMb
         eRVQa+ECEVZJZUfRWP6PlH5K+B2h5YHbKYrM9HLhUo9poeW+Z71ySUg8eF7UWgSPZcla
         JpuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="b/W2jgy/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845128; x=1719449928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=miwYfEyzr4R6utDKTB8xJXy6zLrMd/gTxj7uWLIDMU4=;
        b=JqSioXLlPifcRcZEdB2MuN75x6vH+u//Nktb5W2GVf6Z/mVuNDhgnbMUd+f+VNgM0/
         BwcQK0u/GNHUYWQ7BJjn7o/B2ljLrdlX6XzGGhzNAPCzLgcXPiCmmDdGhEDDIUEfFQSX
         wUeEI5ilG8fuyD+46X/feJxo9QtGXwCrzjy0bjthy+p0oIAInpA4Hc1LUWDlvij2w3nL
         K65cu/hRTYYPWUlsVA+my3T90ZcWKCToBYqbkwUOVr8Zqvrwb/RicUhnnrJAR3PBqUdq
         4GvyTDBBV4opAu5c6o/AgkC1WtwRHAth/2AAfe/TBaiHHvw2fw31HU/688O/T/Fk5qgt
         1iJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845128; x=1719449928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=miwYfEyzr4R6utDKTB8xJXy6zLrMd/gTxj7uWLIDMU4=;
        b=huggkbkHTILoanzBwxtoPKmBtiIYInEnQv/BWj/pav5kKF85AHTsxz6PrXgChJUriL
         ZYEfEmlmc0f+Qd0kqTmz93fxensWHE6+lOYQMnuUbIaY4S+C2ybfLvcw8BOazLlqTvNf
         6XBgEnE2xIfkqSMVY5eFjgRchJ9hGOlGumssLNgr0HSzlEYI74tnedFS6LEZ6otQHav1
         xxFM7Ay0k9A37kZxpNJ7aFw5QUNbPNL1YxHIN3F4R2yd2xTa1yiskI2GCrG6op7aGh5U
         PiTK2EyJsI/lxTLLvmES90ljvzVgMOKUopAihYXHUWkrGKxycWVrGDLuS6RdjD3cr3xG
         w9gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMi1baK48dGy0/H/3/3/rHrIgl0i5PT3XSX0kHzjpGtSyIbZI6S1VO7W2vTQQ7JhePUByguysJGa61j7sQsMDBkZOMtBXO3A==
X-Gm-Message-State: AOJu0YyYuCtuhrT3x82upfe1nQceQEZtfHMDiZF/f0TH3LNsU4XeDMLc
	FGJtm0Ngi7xaw0Oe/fRzZ0TztaATrGN/MQTjqbwWtooAXagXl8z2
X-Google-Smtp-Source: AGHT+IEVVeCUeJ18s2toAYgFVJBFwXt6r6Q3vztXn+IQqVQKmKd34/JldxGCfEI8ZTqrf1/zVVumKQ==
X-Received: by 2002:a92:c265:0:b0:375:b21f:9ac1 with SMTP id e9e14a558f8ab-3761d11c162mr23831485ab.12.1718845128682;
        Wed, 19 Jun 2024 17:58:48 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ef:b0:375:93f4:7453 with SMTP id
 e9e14a558f8ab-37626ae011dls1786225ab.2.-pod-prod-00-us; Wed, 19 Jun 2024
 17:58:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/RV0Tv8sgEIsEPoQibv5CB3wu1utCF3KdJ1evSvaTE/Ruz1ZfjgDn/EratxLxR0BC9h4KVIATQbjx54iRA6nd8Cro40fJCNw+Eg==
X-Received: by 2002:a05:6e02:1d88:b0:375:e471:a184 with SMTP id e9e14a558f8ab-37609544054mr54549135ab.10.1718845127557;
        Wed, 19 Jun 2024 17:58:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845127; cv=none;
        d=google.com; s=arc-20160816;
        b=P+cm/iBdf4Q4vPcEUPD9xGcM8GHvHHOKhIt5ervHwPGDa8hX3V4UwCh4H8TbHMdW4+
         AdvALnMX/KJTBZXtgCch0iEOXaJSit0xKOKafwS30SlXJS1g9rm1oV2frFt9+/myhR6l
         K5T55Und6mdLWaBqm+EeVt+BFOjSE28e+B6BCtfX3QzR99dn3lKUP/g15CP0CtI+9pi3
         Ri6WvP9SzadmZ7MItj8+/bpwJJMJLrZhomi7eyO8bqEAhLD53wji2HVQQrgDJuTqs3Y8
         bEWb+AC2eeoMajEB063HVUH5xgjRzvanvsAFaFLi+qiIwembJ40eUDFkceE89zDGL7Ba
         6BxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=DCV/B9lhDjHSHHXcm9Tupl3t2HXyNgrq1s+vKzjSbfg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=x/H/5c8Dib51+W0TsbJndjrgf6X4B4oOpGXKPGWlbF1zs2WTEPpJ5wLV/Y1Da+FKGT
         Utp30xA38WGEUlh0hQsw3oWPwzvwWiJqi2EWojorbiuLV0lm4gc42USPi5houi6ZK/j1
         05cpP+11Mt2KFQ5dDXUllsP85QvoFQpQgRV6a6nmAjQPd12gkvoasclPrxDCxMHpunnV
         gfGM2MiyqrQhwchydZWfhZqObRtnwxDkUzNR8uW+frK6P49CI0P/K/OCIXo6P+2mO0Ve
         y74Iybu9ZW0tE9uML/kjqIOd7xuB4mdLPSalNLOittkcxt4dnFWvr4MFQ1HTAWZxVXn+
         js1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="b/W2jgy/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b956a71805si775639173.7.2024.06.19.17.58.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 20BA7CE22D5;
	Thu, 20 Jun 2024 00:58:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 63957C2BBFC;
	Thu, 20 Jun 2024 00:58:44 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:43 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-do-not-round-up-pg_data_t-size.patch added to mm-unstable branch
Message-Id: <20240620005844.63957C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="b/W2jgy/";
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
     Subject: kmsan: do not round up pg_data_t size
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-do-not-round-up-pg_data_t-size.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-do-not-round-up-pg_data_t-size.patch

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
Subject: kmsan: do not round up pg_data_t size
Date: Wed, 19 Jun 2024 17:43:50 +0200

x86's alloc_node_data() rounds up node data size to PAGE_SIZE.  It's not
explained why it's needed, but it's most likely for performance reasons,
since the padding bytes are not used anywhere.  Some other architectures
do it as well, e.g., mips rounds it up to the cache line size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures.  This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Link: https://lkml.kernel.org/r/20240619154530.163232-16-iii@linux.ibm.com
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

 mm/kmsan/init.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/mm/kmsan/init.c~kmsan-do-not-round-up-pg_data_t-size
+++ a/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_s
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005844.63957C2BBFC%40smtp.kernel.org.
