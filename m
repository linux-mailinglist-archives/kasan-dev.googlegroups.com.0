Return-Path: <kasan-dev+bncBCT4XGV33UIBBRP5ZWZQMGQEHKHOD3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C50F690FA9C
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:47 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6fa0e724c95sf321979a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845126; cv=pass;
        d=google.com; s=arc-20160816;
        b=kcOe/gUaPgXits8Q/PKSXAemCz+kPp2iZjRRz1F2ECgJIZQivV6hnWz7rzxuuEAf5w
         qU7Gme9x5tKnSVVwLNjO1Eo17ov9OydHAcSg2UCQXE1+DQ7szBYUsOoJy3mRwF3oeljc
         9Z3D0Myb9Uw6tJqOZhcEl9ehNEu+v02xUiknqTxVhVxopCVcAgll5n5iB6hnxlLOEvSa
         QIRCrtKCaoNW+Uu0KYmGtjFMWVcv6QMB7Oh7Hc5jgilTpvo1utgH+U6J1BOwxjGRJ3ic
         F9VhYuoc0Sl6V511FrUmpMIdXnvNP7rwx+kH0CcZ/nodvosPPkVoAhygZ7pvd/jdI271
         DkkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=ikAfqEPfvzjMeceP3BklRSrHfmfpFQEKFGyP+Rnk61c=;
        fh=EIHJ06RWOAZK4qCjevgZs2P3T+m9kYIB5TpmRszY3lg=;
        b=y1nzCL4ZCzNKB8Kac77oZ6IlzGZFVayK7KkyyW0FEBHIFd7x2ppCUy71K3nCEjL1UD
         Cqfcs9PUKrx/uC85kzNyMaE00a+2jLTxC6FRfLV+vznoMktBx2THlaz1Vbn251Pi1DZg
         Jehvq1au0RsePs4mujpgjUTUXw78ZdwoE73d258m0ejTD8B+qRu8+7Di6VE+RZcMB0F3
         p88Z2jbkuPuDRrB9z67g73+VNiunkRv0cbg04ylOLs1LQ1c5c7OicNutvXGcAKkV+STp
         YcOnTM/BJkZHaFhnTul7tk9POTx6uoHLOwYhFuPa18yAj7hIR95z1ejixObqPs/VC+Wj
         daYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NddwpV91;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845126; x=1719449926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ikAfqEPfvzjMeceP3BklRSrHfmfpFQEKFGyP+Rnk61c=;
        b=vBQWtA0sgtJifmZNe60JD6T03s3Zw43em8pNGksV+9csPAjB9Ji/o76JQV5CI6RIFD
         q4Uc3XS3xFksqy1op3WMNsPYjBJlKiYfySeEe+lPF/0rl6DuY6uwyC93kxJHWC/ips5O
         +fgHbD40EBY3XOhdg1g77ffkNLYJXDExPnteFdMP9SohVPGgy0ihQ3lMXlHoFE/DLDbn
         AI76koPlHFnEaIr4/IJM4EuEunD9jiO/AKXvTcpjwOrDttRMXZWhbuc3q02TrWI4ES2k
         JmyDFij1oIoIGR6KWRhz0OMskvVze5+GywAJV08F2lnRWndhxdLBnIWVbyPe405K0F9R
         cEmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845126; x=1719449926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ikAfqEPfvzjMeceP3BklRSrHfmfpFQEKFGyP+Rnk61c=;
        b=HnxEiDZsQxDdlpLbONMycZTjQe3yYmaWWULk+OmASrAK2Ua7fQVxfSTnrS5jWH62N8
         uw7HV6Uc9wzVnrelaZZFZbI/9d+3FGWFHsxfB4675ygJKMaIO+a4q51DHsvN3XbWAKko
         JfLvt/t0oem8ZrK2kGuZN0yXq5fTFqf4vEeP8k13Ifc59vuXwfXz7Tpau/xTSA2mdXoS
         002MpQtrvx0jCUj1y6+7o/2al73KSuPXmwvD18wRmmqO7SROV6AnQeecenIjnc9AANWL
         YfsGxKILZwhJzc9CHvtZClJtKazQLNsnrmjKehttbzL9Y5sDmiI1OQA/87gc9cUM7KrX
         Vb6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEWWQGY3OnHECLUTNlQywF/VWJyzWK0M9AwFgFhI/GvE2JGqbFCH1anKP9a6t2sKZEEVG18pcot6yOKf78wn4uIGjIscDcsg==
X-Gm-Message-State: AOJu0YzkY1DJgq6zVHAVPutrilVX8NItRWV56W6/Xc6MVW9wYqeYYrAr
	s/w+9hBU1InflSDPJfNGJpRhir1ST9ayATjeEhk2kzsTWrxfLiVh
X-Google-Smtp-Source: AGHT+IFxz41p6c8BTbcK180jPvXLfdmn9goXcZEaHjeoGm3kXRzobVqDV9vOxzxpQMXNCkL9SstoRg==
X-Received: by 2002:a05:6870:808c:b0:254:b5d7:f469 with SMTP id 586e51a60fabf-25c94a25528mr4461780fac.31.1718845126040;
        Wed, 19 Jun 2024 17:58:46 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d252:b0:24f:c233:20c1 with SMTP id
 586e51a60fabf-25cb5ef43c4ls377006fac.1.-pod-prod-01-us; Wed, 19 Jun 2024
 17:58:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUs1bwoc/Hat5uUvaN2tADVSfxHCJR5L4zT6JFWTK7v9fFHxJvDZmJaeUWBkqHHOnKElfZOFd+Hd789RNqZAdF2qQk1HOEn+rmE+Q==
X-Received: by 2002:a05:6870:658f:b0:24f:dd11:4486 with SMTP id 586e51a60fabf-25c94d07816mr4913894fac.36.1718845125223;
        Wed, 19 Jun 2024 17:58:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845125; cv=none;
        d=google.com; s=arc-20160816;
        b=HcuUOcYqAjoB+B5ymhz4zl0X4HlkP2iT7z1d3Vur8I8p7VpzDBSHtEVi2oyRWDZHUh
         aMHd6Jhl1r+wD4RCibMSQWS7YG321I8VaGArawzia7OcehNOtf7aXSZ9p/bnnpw/3PAG
         I+ZL6GO+75kkXII51P8SCkGGBhYneY+u8NpY7QcP++kPc2VgKK5E1ShjLcGmws7CG2jt
         TpJoGCURz+T/WU4RumVImitmiZfo/JdHUcCMUHjuFCl/xOPrgVKXoFxujBRYMOj4RjP2
         Vf5y2LXNwS3n/v2R7OrHncuwDnlOEJyLjxKTWMc11Oe7uFQswQk1K2R024CtluFfrEwU
         pOIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=kJ4pz6hex+Usr1sSj8AJKNXZrJ1zg2FrfZCWobNNnBw=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=UKG0Zk1T9ME0mmOweNrDow/Aye6QlC1HG+kpcHgw+jqA5kywN3ZEeA3/jWwtHxo6qR
         +8fd/8F62KxR9l5/LXNnI4UzsGjyNcoz/Ba/18dJz7iIxY9EP/hxk52fuu7lypLDNUTy
         GLVxs4FI5ldr1glKXhDfGJ9K/O7fIeQu9vd6Ji/bO+FEummrVNpRtIz5gTpB0qSqlQWh
         8YeM8Oa4InH0x8NtTbn/Lo03bsn/zBV2bUME5aPdtw98/0eQzYw64Z9sr9jJfjydXpu2
         rAWq3I1OEXsHIO7o8srGOOBYhMK+Qmfs2Hmu8i0wVQWv0HPrvTT55NqnOnZLDst7OSBW
         4p/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NddwpV91;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705e3b26323si509298b3a.3.2024.06.19.17.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 248BFCE22CC;
	Thu, 20 Jun 2024 00:58:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67F3EC2BBFC;
	Thu, 20 Jun 2024 00:58:42 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:41 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-use-align_down-in-kmsan_get_metadata.patch added to mm-unstable branch
Message-Id: <20240620005842.67F3EC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=NddwpV91;
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
     Subject: kmsan: use ALIGN_DOWN() in kmsan_get_metadata()
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-use-align_down-in-kmsan_get_metadata.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-use-align_down-in-kmsan_get_metadata.patch

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
Subject: kmsan: use ALIGN_DOWN() in kmsan_get_metadata()
Date: Wed, 19 Jun 2024 17:43:49 +0200

Improve the readability by replacing the custom aligning logic with
ALIGN_DOWN().  Unlike other places where a similar sequence is used, there
is no size parameter that needs to be adjusted, so the standard macro
fits.

Link: https://lkml.kernel.org/r/20240619154530.163232-15-iii@linux.ibm.com
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

 mm/kmsan/shadow.c |    8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

--- a/mm/kmsan/shadow.c~kmsan-use-align_down-in-kmsan_get_metadata
+++ a/mm/kmsan/shadow.c
@@ -123,14 +123,12 @@ return_dummy:
  */
 void *kmsan_get_metadata(void *address, bool is_origin)
 {
-	u64 addr = (u64)address, pad, off;
+	u64 addr = (u64)address, off;
 	struct page *page;
 	void *ret;
 
-	if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
-		pad = addr % KMSAN_ORIGIN_SIZE;
-		addr -= pad;
-	}
+	if (is_origin)
+		addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);
 	address = (void *)addr;
 	if (kmsan_internal_is_vmalloc_addr(address) ||
 	    kmsan_internal_is_module_addr(address))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005842.67F3EC2BBFC%40smtp.kernel.org.
