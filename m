Return-Path: <kasan-dev+bncBCT4XGV33UIBB2P5ZWZQMGQE7IYK5WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EFC6D90FAAC
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:22 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-25cacd5a16asf515828fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845162; cv=pass;
        d=google.com; s=arc-20160816;
        b=r/3KyzxHHwW5qhcCgtK1zFow4eRTfhEzln46oAb7Fi9e6lFYsufX0KusH0XoptbqjN
         4T/Is5B1VJ1FYXxgcq/qF+29ZExJsTE4O40LBrM53sUdIOdsxY5Z9P+dZgH+GkKF0E3n
         uzMkI7HnVBMj4qlVu46Guv0nBK+milQKCNmtLLpV/YJYqboqsUQ9BfJS7mugSE16NaE5
         p6QI/B28Xgb7F9wbSt/RKdmEeTlkElJuv4/2GwUUU6VglXq1AKv9RKAT5ALWKS2fEjUz
         98GKetRxz81ZOOpxdlLkBsZmnJ+8qCDHYSoUqppD3hEzO/ECf20yHlHsxv4UIppBqSty
         Qo3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=ZFqu1ekviYqjWuv/PrOwHXz3S+qsWgxcMNERPlJEgSk=;
        fh=q6wb/n0n6AixrQArEqCx2GBLkadPvCwvyftZ89+N15I=;
        b=PKv2okhjbBheEFKy2dv8GpSMx3ANcW/IYpUrYKNr5KhWqe6ZLUJxoPgti/c6fJS+ze
         aOAxOm84kpHahoVsogiPckltRA3IdSd5I8I8VnpPut+gZqudyZpeq6A0SR7YDRYOkVKv
         j8SXEgz1tteeovgzNd9yzzQPCFgXziPS3gBDAfMXdrFZl/njObgO4VySZnBS5jBCTlmc
         7w8KNvOWJN1L1qCYlucFSsKZAe6kEgFCkRR9mkiTT/TWQmRrkzcGCPBPOqL1QS6tIqk+
         7RsuD3nWKgJ5LjDYI/rUXiWgN8Xp27L47RfqJzHLa9zxROB9lxAoWF3kEbnMoBDKkBiQ
         Dajg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="R2FpjN/h";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845162; x=1719449962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZFqu1ekviYqjWuv/PrOwHXz3S+qsWgxcMNERPlJEgSk=;
        b=r/SdZigdCTIiZ4QMXM+m3zgxezzFu0lpoIJplX5kKmE07lzqAtC6NPZWuhpLQEfwpb
         l6EfXoH9o9rCgN6Z/XU7IdMyc0r96O9EJOj9zP2koVI3By7FQsJl5vEjRjcXinBB9ucs
         1Jir1kGYsCSR+wxvMWPGuz73QgCurRSdcJm29z3OvBdYDkSOG4u3BrcwANN5l41X+aEc
         Zm2jocKzjuEGZeEMGkAPwusUlZuACTfswZgiTgopGk2b/6X3+KKndOmvycf6MfDmpvUU
         jp8kkwJewMSu4kLQz6bYydwOrZV91IaRklWHMk3NKLAoE9OfkeI9xKHjTibPlcBvsBxA
         GqoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845162; x=1719449962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZFqu1ekviYqjWuv/PrOwHXz3S+qsWgxcMNERPlJEgSk=;
        b=MUS39KLpYo3ix+ZGGq0nhI0YyX6izatsV7feyfVQRlmTO/Kc3jUkFo499b3T6SRm/P
         qf5A77Pglf/34VIOS+xLc6x6vZ0EnW1oGZv2jajGAaHyvpEIyODmdMG8Mnoo5J3yq/Fu
         NGOAKnTRSixTY6hgiOuXsku/QR9zVl5cawgiDhX2iaaCdpwdxEHw9ZYdb9ThtStSZ8Dx
         mvvA8uaqd6MaAe+4oD/rhDh18KnP//DggwxkyPYS+Veys64f/KCiSsGrtyd6Bqp6cxP6
         Fc8FqwuWpUI0QW0C2QVIndxcBbgFOpPzHoS2BxhI/2pNyNiN5uRaBppRRnRd05W80Xtn
         Zuew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVATYVyOSULYQNSiS5PfPvbWflfRQrXmxgzywLUUZZEmfjjZO9lNyK5D54kqT6IXhgpj6yM//vcrA/W8F1Mkk32boGUS4v25A==
X-Gm-Message-State: AOJu0Yy6xeCANlDZyaprrsH7SfSfMUKME2yZgV3fiOCXiQp/Kr3m/nga
	+tgDQQahnFMytPIzK0v7WViEH/GZUHElU3onkusjhodYtUSz1Tpj
X-Google-Smtp-Source: AGHT+IG4+4bFFUbarSd1kWGnRNGh79Ex4NNJukGws+LsAXmZyh95rkkJu8asSYqlnegt28kyvp/ELg==
X-Received: by 2002:a05:6871:3213:b0:254:a217:f8b5 with SMTP id 586e51a60fabf-25c94d02f4amr3442800fac.39.1718845161745;
        Wed, 19 Jun 2024 17:59:21 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4086:b0:705:b591:29f0 with SMTP id
 d2e1a72fcca58-70640f5789als241786b3a.1.-pod-prod-06-us; Wed, 19 Jun 2024
 17:59:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXu/KeR4/lE1gS/p1MLSj/M64YEgBqgQxYDKtElhGjxu9E/W49y2xlF0TvnGFkZgqkFnt6xvVjiY19tT6W5RgHhufWo6EwiNn0phQ==
X-Received: by 2002:a05:6a20:47dd:b0:1b6:f34c:95b3 with SMTP id adf61e73a8af0-1bcbb60fca3mr3516720637.59.1718845158507;
        Wed, 19 Jun 2024 17:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845158; cv=none;
        d=google.com; s=arc-20160816;
        b=V3HZUWrMTwYRdnfrIQYDl4xY3vxmAKo0JWoG5sZWqzBNQFc/u/MWhr6aGAB+8TrcH6
         QKc1sBqU7Q1jmDTlm+l2B7D4nK5DBCwQ8nA6G/W9JDVtdY13UhyB5Su7zD157h8Iefcf
         D5i4GLrRTeXk63wmuRZ/aol7pAD5Lsk5XwVcSAt+fUbXWBBFm4rhhYyQ2GXqfgSt9BpK
         Vr8hvzTrNdTrFE/GO9xjmo6A5iVjnsp/VHi/17Lb3eX4M7j/xTog/DJUXurcW/EqVO7Z
         ouioeYYg0ZVAdKR6LmpEiBvjt4TKh03W3AnfLO8msVV/opOhY6AYjJhWD3dMLXbXXZwj
         08kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=qf27Ri4054aMkVzGjWSa6I5LHUq3Q8I1uflVDXzNq68=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=WJ+rEtmfVgxdwPp5Zo0DbC8bXq2wH3xWQEgOE5yirYJ6e0iBAUV/bcFU+fN1QKGmSv
         7RZHBNJj+3wd6+yKQM2fvhA3BAa1QSObRZ1DDIFR7ovhTiwAo27h8WUZyfx4yKik96Ka
         pnpN77udWDST3YcOl77Yn0zTnxm5CXUmb4uoPALFFnQCDTjuxxyt88OaH7vqnxpHsp6I
         TZ9eZZfix9fGFZeVdrU6fZdGhCRb24bXHlDCaG9oy7WGFKHadSKXapx7okCTz3Vuw2/F
         qSCP0Zftpism1FybHcRr3Pw5IJDWtNvNoBdy9/PwUKOTt55COe/DQAIb9pAtPzCdLvlz
         h9rQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="R2FpjN/h";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e704c18bsi20780a91.3.2024.06.19.17.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 9731BCE22D1;
	Thu, 20 Jun 2024 00:59:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DA440C2BBFC;
	Thu, 20 Jun 2024 00:59:15 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:15 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch added to mm-unstable branch
Message-Id: <20240620005915.DA440C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="R2FpjN/h";
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
     Subject: s390/mm: define KMSAN metadata for vmalloc and modules
has been added to the -mm mm-unstable branch.  Its filename is
     s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch

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
Subject: s390/mm: define KMSAN metadata for vmalloc and modules
Date: Wed, 19 Jun 2024 17:44:05 +0200

The pages for the KMSAN metadata associated with most kernel mappings are
taken from memblock by the common code.  However, vmalloc and module
metadata needs to be defined by the architectures.

Be a little bit more careful than x86: allocate exactly MODULES_LEN for
the module shadow and origins, and then take 2/3 of vmalloc for the
vmalloc shadow and origins.  This ensures that users passing small
vmalloc= values on the command line do not cause module metadata
collisions.

Link: https://lkml.kernel.org/r/20240619154530.163232-31-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/boot/startup.c        |    7 +++++++
 arch/s390/include/asm/pgtable.h |    8 ++++++++
 2 files changed, 15 insertions(+)

--- a/arch/s390/boot/startup.c~s390-mm-define-kmsan-metadata-for-vmalloc-and-modules
+++ a/arch/s390/boot/startup.c
@@ -301,11 +301,18 @@ static unsigned long setup_kernel_memory
 	MODULES_END = round_down(kernel_start, _SEGMENT_SIZE);
 	MODULES_VADDR = MODULES_END - MODULES_LEN;
 	VMALLOC_END = MODULES_VADDR;
+	if (IS_ENABLED(CONFIG_KMSAN))
+		VMALLOC_END -= MODULES_LEN * 2;
 
 	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
 	vsize = (VMALLOC_END - FIXMAP_SIZE) / 2;
 	vsize = round_down(vsize, _SEGMENT_SIZE);
 	vmalloc_size = min(vmalloc_size, vsize);
+	if (IS_ENABLED(CONFIG_KMSAN)) {
+		/* take 2/3 of vmalloc area for KMSAN shadow and origins */
+		vmalloc_size = round_down(vmalloc_size / 3, _SEGMENT_SIZE);
+		VMALLOC_END -= vmalloc_size * 2;
+	}
 	VMALLOC_START = VMALLOC_END - vmalloc_size;
 
 	__memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE, PAGE_SIZE);
--- a/arch/s390/include/asm/pgtable.h~s390-mm-define-kmsan-metadata-for-vmalloc-and-modules
+++ a/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,14 @@ static inline int is_module_addr(void *a
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_ORIGIN_START (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_ORIGIN_START (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#endif
+
 #ifdef CONFIG_RANDOMIZE_BASE
 #define KASLR_LEN	(1UL << 31)
 #else
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005915.DA440C2BBFC%40smtp.kernel.org.
