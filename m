Return-Path: <kasan-dev+bncBCT4XGV33UIBBMP5ZWZQMGQERVPXSUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id A05D490FA94
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:27 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7042d4c7a21sf457091b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845106; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpqVZaGgtVC3D9s1KChpT1pOQY4DdMtnhnR7u3UjDqu9tYb1FjCU8R6H/ZYk/Cn176
         QCLDy319pLCTKGXZ3mARVx0qcfQNLFS5XFWS3iRkE9SGqpaZdsN0G27Ms/R0spfVs7mw
         3qjeGbN6jSCSlPORZ8UY1O1VmXmIMjFmJbo0sZD9vAJwoV4iwhr1iJF+XapwPJ5p0PI+
         OL3msH8XMmXJxmcnNZkcrF5W7LkROP/jeMqj/Hwy5F9fxrHH4+T0oy1hEYQRevWtFQb4
         nMop08SgPrAqo/qyxA+s87MAYsKso3jgXg/jqhhKXXINJzWk33D1HD4BIsgBEq45mRwD
         HREA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=HnzFzuU4U1c5u+p2tUUC7VC0PHB0S65Bv1iQE0FNpWM=;
        fh=34Qu777xtGrOcHPu/zfjGvxJ6uD9/TLtBKmrR4XBo4I=;
        b=AROQYLHmvq/0BQegPUoZS63BHA1NjQAS3mtwxZT2RAUK6ULZIKk6NnVmT79NFFjjn0
         ZoLu5yvXSmkfYde5DqKZkSZZ+dwvFnEuU7YP9DLVt9yz5KkXSIVhxyJRGP+VnaJaNH5R
         qzKRK5sQi/aAj9ytSUDmUKO5DgTqEvwhRm+JPMsMXCrpjmPngFd0A5uE1+gUEntJ+oo1
         1lPchgwTELpSEx9fOs2yuLoaZBYVh6qbjwZPH2yDdyDAbeS8jE6HoQ7V1jFp7PHlt25r
         wiuk/jA2AdsNAnwVRJvjpBkjMVytnuTGTRsL1SYgU8L24DT0/l8hiDU0gKh/kiFVG/O8
         7mVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dE5QxPWH;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845106; x=1719449906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HnzFzuU4U1c5u+p2tUUC7VC0PHB0S65Bv1iQE0FNpWM=;
        b=vuZH1nVX7FYnGxWoqt9l1a8TqwXaPXyscyd08fpLMJV4gtboJBVtX6ij9WaMXNnO7J
         meWRwAfFin4PSIJRtgPDh4HdrQ/1lg0Vak9bBDt13M3qT7YyaWSN44yzuHDVcP1Hb61F
         AMTyA1PhIeur3PLvk7wU+f0Ox5JG1jpopXLi2wGzJo72YqrvzPBejuDKuMBo8nXoQGHi
         dZGu3SJFdulYHKiv6RyG05kjTW9V2ktsYGERIe2YJ54wwapnZxBH915MTQ7PDJ/M/CSm
         ts7M/uuJM6UtqpfKTokMiqlvByTbZQNSBb6V3riArjnc+RUwwm9Q0BL/m+cSxxcGrrGa
         at4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845106; x=1719449906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HnzFzuU4U1c5u+p2tUUC7VC0PHB0S65Bv1iQE0FNpWM=;
        b=dnnBP5IoI8Ab1W+ebccENzYlYN7kT9WY48jHFBRVtnfAlEnIPRhLOaVY/a1zwlzgtG
         yJxm7DOKwY/edmffT+LDH29Y8DhERqG3/M8LqaFgnfWz/Ve+Lf4pS27ppeevNtiILGPl
         1yawAXJ8tiKIq5NZeQWRKsoT4JIQiD3DvFkG8cN/HBZ45fAaL/tfuwlYNBoOBt6IUXCj
         F58x0FaUgdPts45wJ65EbquVoXb48Sp5I5n6CM6bnqMZW+JtqQk1TUD8GLSSzBDv1+iV
         HhQi081I96bIpmj0aQ4nPMoPUwh2twD66eoOYSPlrFZJ/QR/iZwA4puCczkiafAAe21l
         j5xQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiXi2L76rxIPRvwCuJ0SqglcK0yzl4ddArHgUTzrj+NVTnub2RQDsvP7Fsb2Hm/0dtIxeeCA74pVrmF/EHkt6COG5gN/gfuA==
X-Gm-Message-State: AOJu0YyNp1s/QQf8YGzmBv/I/BIws7ma49AQwa1Hgdq1bicLqMo6OL/+
	fcJNjZganT6gkl2gqsvXdRfSUUVCZm/nZOlC+1VPDXvnNIV96qfA
X-Google-Smtp-Source: AGHT+IHb5OPnaLm90Jx+vJyebM2cG14dG/1GaOFPS/9Qd7DY9/nqtkgA6CGUuIeudYRTXJIUBMixiA==
X-Received: by 2002:a05:6a00:cc1:b0:706:2bd4:a68a with SMTP id d2e1a72fcca58-7062bd4a764mr4117915b3a.10.1718845106115;
        Wed, 19 Jun 2024 17:58:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e902:0:b0:706:4227:a6db with SMTP id d2e1a72fcca58-7064227a7dbls127990b3a.2.-pod-prod-04-us;
 Wed, 19 Jun 2024 17:58:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXW4l8qX7BXZwqNmihNapX14bsiq80LNXm+EhyDarwno61E5X7Jn2eLkh/TygIlUQLku/DUY06VxYzJC66MtIODJrwwOHtgoApVMA==
X-Received: by 2002:a05:6a20:914f:b0:1b8:2211:b7d9 with SMTP id adf61e73a8af0-1bcbb5a9c96mr4815933637.28.1718845104582;
        Wed, 19 Jun 2024 17:58:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845104; cv=none;
        d=google.com; s=arc-20160816;
        b=ZPUYYTIDsjpAHk/2DF3nE+j+DVW+hZDCaLftJ2AEkryqKKjKNvZzwPv6krqSLqY6Ee
         z4YAggV0SdUAQxw44BohaoHW1NESyrKqxBQm9I4l9YAc4sm5y2bBIk+v75+g4ZYG1ivU
         i9i8Bq/jyr1wq5hUb1q4o8XrRPnf71I8MdfvAFiM8AU9kL8Drusm/LlrLS2uM3W/aJeR
         pfIhhOsE7HL06VyIyUYsUWtByr7zaY77+d7MRvtqVgfgQgxWvFxX9qcWHW/RIbl0kxZa
         Fp4yBAb94DH1XZ4YNFvnYO0P36Bu0kVtcRebQXFpTRTWzXlPJhqVUa5Vj2zXgszbzq7f
         MyrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=UVSYQwqPOKwq/yxs3GMJWaA+AuiMtMPFmQpYIlObb00=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=sBN+8Ve88X0XdRxZH6RIIaT02BsxieFRZgrsbB3Kz6JIpXjBHHVCrkl1py4u8knfQn
         KvhhZHaKGSoRZFLT7p4LuI2Rd/6NmDdekgw1fWAdjzPhVCuVH5zdgKxQqgg7/BduCmBm
         BpwyorXmmhnFgGOyF46nWmYc0CSeM8NC2b+N6juxD8G8fRh3+uu0wHMYabUt3pKAmJXg
         ZKIwwFQ+uAodZ8irBfHi8epdIb/fGV8a0muBnZh8RdD/dhe98QYC5unlf9etL5R1yHLC
         I2pVgVyF8it5+I8BC0fDHx3DOM7Y/dRO0PVAHeuDszcGFjAldLTwCUnybRfh97n0G9RF
         0Enw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dE5QxPWH;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9a6286599si1476415ad.5.2024.06.19.17.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E92EB6205B;
	Thu, 20 Jun 2024 00:58:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8CB90C2BBFC;
	Thu, 20 Jun 2024 00:58:23 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:23 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch added to mm-unstable branch
Message-Id: <20240620005823.8CB90C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=dE5QxPWH;
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
     Subject: kmsan: fix kmsan_copy_to_user() on arches with overlapping address spaces
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch

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
Subject: kmsan: fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Wed, 19 Jun 2024 17:43:41 +0200

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap.  Assume that we are handling user memory access in this
case.

Link: https://lkml.kernel.org/r/20240619154530.163232-7-iii@linux.ibm.com
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

 mm/kmsan/hooks.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

--- a/mm/kmsan/hooks.c~kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces
+++ a/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005823.8CB90C2BBFC%40smtp.kernel.org.
