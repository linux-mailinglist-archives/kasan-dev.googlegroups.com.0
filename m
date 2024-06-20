Return-Path: <kasan-dev+bncBCT4XGV33UIBBLH5ZWZQMGQEEOMAAIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id F198890FA91
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:21 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1ed969a5e4asf1176175ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845100; cv=pass;
        d=google.com; s=arc-20160816;
        b=SCIOHYNmw3WR91Sy/fNysfM/1jTURQPaRxBpF+v3JklVmud7j/2Wt//yrzbLez01Tu
         geFzdslehKt011d2gN3hA4aVPTQYiP4ic64s5ToC+riiDzpDbf8OjTVtrSDIPbSuyVaQ
         3epQq0oRGEtg1HcAFfqmCcuva0oKGLl7+EBNdJwKQMs6ecB19Y5Z0MDbWsaDDTOzRjj4
         0fE5LpIpU+dMctL63EMmtYezOeyyUMXNeegX6+WTj55WotyIsqciIFgBK4d3L6wBaSUl
         ivstSYgZ9L3QtTA4ix3oVYqotaML+hw4PwA7PwKSRjTqbHK7Bfutj4vLqencJi6RQ2Ss
         MdSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=CGR6/bdUnhpybHDuiQsaRLHh464rpEPtfuYEHnmaS2M=;
        fh=q8qj8lwJjMSoiLM97km+u8v/QHEGyRp5S0Ii9J/tfKg=;
        b=B4GWXN0N9Z4P3RaHUQbYNFiPGPtrTGyUhMErRg/ic+c62q7bSOKsX+I5UV+NvPQnl2
         +DeAAF7LEBsLiGD9Smm4ZkDuoERlrifRmHlh9C/wVtJOM8zzPNjs0AaTug+74gzXjWC3
         l8NdWf8lrD3Ch/tPASj7MaH+102mXepcHmUip9llbvaLJDe0K+uFNyQFYb6fEeqAhJ1p
         12GOP0vHw4LkTvEn3XZx3Euu+EQvjGbCmICGUczVBZzegU8+5wEMA+LSkCcM6vq2p5uc
         VdLonQEm4Wo1+uh5XX6JzP3aDtZrDZVTj7Cm3KVrJLPTvhVhpUX6vND7Vit7YrvTpbMO
         t66w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=E1fdHsjY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845100; x=1719449900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CGR6/bdUnhpybHDuiQsaRLHh464rpEPtfuYEHnmaS2M=;
        b=J7CjSyqKUh6I0WRxkqstDQBefWaLGlwKX8y9Y/YT0JGlshBquHV73M+efpzDBi4+KR
         YXS9RknJrFAN6RQ7v/o1/FyyyVeIZq+JgFZSJ3nWOtyUFc7CC/fBTjN4T5JO7Jk9XSZ5
         7KmKihXovyBHQR8igLU+vkNmqveJsaBocTaeP0GATlXUg/ShJkkBcgbzRla7Srz3J77o
         zrvuYKzZw24pJ1sdDnj+H5nPxemw1JXJQxdBRijHq9VYI//mYi8VI0VS1XcSG5VQt2IS
         wEjbFjmmCcx+6twrCL4Rz05AsV4kOeJz4vA/OW4G4Y1vjvw5Dq9N04tkC8rGkeJgHhWP
         /wNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845100; x=1719449900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CGR6/bdUnhpybHDuiQsaRLHh464rpEPtfuYEHnmaS2M=;
        b=T9vxkHuq38SgP6YcBZSAXDQlXuu6mEspvkZDD2a4jHGLNG93sqUCV9hzOblCFPnxTH
         JC6qkpKdYCC5Ol4ntGHc6s/1fF3FibIf0r8gtCZtTme7d7fBeSyVmvBQ3aWVuvdDQORO
         42N5Y0jiExLpj8Y23ZQN7/1Zg7eyCnMEn2NNanipEKP3WE5+HxJZyApqzQ4E/HGMvfhn
         9p2tIbvz3+I416ObfN1q88t5hIj11xq45iT+6I+3/mZAAhbOKShYGvggPzujNPmSlZgu
         3lHz5O/Oy18i77kz2lnz3oP3TbkdTKREvp50EFpi76Ze1/cZ7eFqk7k89tWTuGFunaSy
         lXSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwKRayFY/No1NCi8rMpvtLLXJRyyUPHFbju5sgOx1dUemzIAsluwHql4ieQ++tA6tLU0ToT6JmKr+Rq80INtJ0GC/onP3IHA==
X-Gm-Message-State: AOJu0YyzJqMPjUD2UHjDGnGYof1xJDELUrYbaC4REeTfeE4+3WgcITj1
	RZQg+jGr2mF43DwCM2KZ0qEY2EHt8EDFDW1rsugnSRkF76bL/cno
X-Google-Smtp-Source: AGHT+IE7wrHx/13sISbtQ8l1gsxSPkd5yAmKsmzCZvnh2aLIkbFOeVxHLwgBZKkeROotY0P8sa6/LQ==
X-Received: by 2002:a17:902:be06:b0:1f2:fefc:e8e7 with SMTP id d9443c01a7336-1f9abad39demr4466215ad.2.1718845100464;
        Wed, 19 Jun 2024 17:58:20 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8d:b0:2c7:dd7d:5edd with SMTP id
 98e67ed59e1d1-2c7dff07fbfls220312a91.2.-pod-prod-05-us; Wed, 19 Jun 2024
 17:58:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkBffpw7NDO9erc7ACn3xkUYp/NsNO06uX64V/q0mCU5Wn8ijk6rGRA4mfdW68nYnRRO/RQv1YPZriBfwc4YAVvMb/GiJwg5Ny5w==
X-Received: by 2002:a17:90a:b38b:b0:2c3:3d22:b304 with SMTP id 98e67ed59e1d1-2c7b58fc912mr3712553a91.3.1718845098912;
        Wed, 19 Jun 2024 17:58:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845098; cv=none;
        d=google.com; s=arc-20160816;
        b=xnyaf5weGfe8iFhrhT2WIgltTlQbbytT2m/lcc45yCl8XRZzXn914An11ftqV15XzG
         nuJUSUJOZgYsLY9XTSG2+pUN+nzLwfdOH4X51YpJwIbZwonnmC5p7G31cmweCqbNbxuX
         LvmFDOaR1xuGPrL/0sY2pPZXtC1HWz2UkO2j2gjMTYa6pVKk+3YUwLWpQSiluj/RvtOc
         1m6/8c0HOiFBs7QHdfJnvolcN3T4h/sF+sLaWzlSTv2qZAd71irVokaQYWyuUsAjJ2ZC
         a77wt8RhRU6iFpcAsL8be9zWAaJ4UQRQ9HANpZKL3GlcvT5hGDWc0wUMbFKM6yRiIoZ6
         FWfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=IbDBwlhYG3z2IM+0/Y3FK/8m+CADlINz5fIHNaTSiQc=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=JcRcryCv7a52vGpKysvM0lXe/oGX+rKOJzX6hNJjBccAKm6ifwhwAQt/8fgr+Aih5u
         eV2Gu6ntewFt0xpvAs5yWauNi1D35EEWqRdIVzApj+KsrNWAhgthp0NRM9Tn9T70PmQC
         a1YxOPC2amDIyR93FoVZq3pWklkhWFk90wSDfWA/WlsowZB5itscO3gEyj+HhjtppC9G
         4+Fy+8bhkWF2PJkA4GpwCQB2cWhvlDv+oQIdEvLAJPbxh6BphE66RLLrO/CmKCPrpsea
         Of4C3I8ZxcyIhBrtG9vsO7AgrVVvras9bsseeXDXPThG0fBTxFqsz3dvbdBNSjUn3C0E
         dLUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=E1fdHsjY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738b2270fsi422638a91.1.2024.06.19.17.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 70C9FCE22D5;
	Thu, 20 Jun 2024 00:58:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B06EEC2BBFC;
	Thu, 20 Jun 2024 00:58:15 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:15 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch added to mm-unstable branch
Message-Id: <20240620005815.B06EEC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=E1fdHsjY;
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
     Subject: kmsan: make the tests compatible with kmsan.panic=1
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch

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
Subject: kmsan: make the tests compatible with kmsan.panic=1
Date: Wed, 19 Jun 2024 17:43:37 +0200

It's useful to have both tests and kmsan.panic=1 during development, but
right now the warnings, that the tests cause, lead to kernel panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Link: https://lkml.kernel.org/r/20240619154530.163232-3-iii@linux.ibm.com
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

 mm/kmsan/kmsan_test.c |    5 +++++
 1 file changed, 5 insertions(+)

--- a/mm/kmsan/kmsan_test.c~kmsan-make-the-tests-compatible-with-kmsanpanic=1
+++ a/mm/kmsan/kmsan_test.c
@@ -686,9 +686,13 @@ static void test_exit(struct kunit *test
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -696,6 +700,7 @@ static void kmsan_suite_exit(struct kuni
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005815.B06EEC2BBFC%40smtp.kernel.org.
