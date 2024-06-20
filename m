Return-Path: <kasan-dev+bncBCT4XGV33UIBBYP5ZWZQMGQE62RSKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 200A390FAAA
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:15 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c7c3069f38sf441528a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845154; cv=pass;
        d=google.com; s=arc-20160816;
        b=PiCVLk9hJftNiPUTiReAR/VpWk6pMcSQYMnL1Xpj45Y1gv77D7S7qSS2Y4JE+3vQE8
         gLptQFVu/zd8238fkylob2I7sY2V0z1mfH8UuZpUDh9mcYHV5y3wedt2trY4NwBcwCGy
         frp5QU1dmYte8u+PP9t+bOpAcXyLDBvZcDRbTASTK1Bj0qIeSj1ZHhg9yVXOp3JDd48o
         yJE9+is3XONFgttuMSq/EIg1t3+LDUSwweTYuFVp3aHNLqoja9nTX+OjQ4X3xmgwF3ed
         gNPaK+uhop6YROFluIqpdwPh/dn7ePvE8RBkO8d2y5Tn0V9vngApmcCbuo8em1CfEzUb
         StwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=Z5OBKta5JWesIw9TmRMml4U6xueIyPBcfSR1s6PGgWA=;
        fh=7L3tOP5yw0gevSy/m49hhtQGtWGfJwxudprzM5JHbAA=;
        b=HBokKGuhsK1mrIiw4ch3YvLwReyGFVq1GN7dxacpQsd7FZp7GAKq7RVadmTeuEfNSr
         OOEj432g9SmSQOAze1XqSry8Zbjrl48qpRbxYF/T4ELv7Iu7PWnGTdpfXeGnYsExB+iA
         69vB/1cGPZ/6lzVHvgAyalyw3vpyYwEuHoqjA7T8n/2Ns5bQMUbUue4O6oaNDvpW8UJV
         Wn8Vh8MDz8Uj2W5D885ygrGFGmndWfUVasDKdgj9bRFeLC/al0Z7t0R2Pmpj5d2tVwZ7
         +KJtKwpCss8hNZck5U7+FDtVxAhbWqz8H570vcxK9yrSuZjq7ctevceIRCu9rZYf6rV/
         p+QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=teNJfzeb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845154; x=1719449954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Z5OBKta5JWesIw9TmRMml4U6xueIyPBcfSR1s6PGgWA=;
        b=MtmxPcDWthkTL2sgrQ0uVkGkUbApWKVyvx411GpcC0W9gU0kZryZdH6iACZ3cqRWJV
         bTuXeuctvRueAZuKx5/OBlJ8obDG46ZFbepQCv6cbWIGSFFeeA+D9TpoAZ2Wy2MMqWUh
         YvnbYPzkbtacUQT3+2CsVbkpSrDKqIoFPVWiq+2s8qOdl1OvZbq1huvLvF3D4YPtacX2
         8UbRBSymgAled3BRBejJvD3QHVaeNxIOC7jTfkPpPyB3wsUbeV93irocQ1pCfM7/E8MM
         k7xL01kHVUY2sBmEGIb9hw01p9fw0D0tTckD1lHtfoDfzkMH8RPbEJ8DEtQxThaZ20mG
         lxMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845154; x=1719449954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Z5OBKta5JWesIw9TmRMml4U6xueIyPBcfSR1s6PGgWA=;
        b=GAALC33fJXsb/VJ4EU0X4ad0x8vFULG311FQmfXHV+0Iq+8SF3eLHwdwQFLRxQvRF6
         6HbdGixdpBBfs8yS/eq85sXhJAaUpN93zcMr/r64/Y7DtWD8QGm2wBfyjvDX3RaoxlZX
         9qg3LRvufpJaukeJQVpQ6kSIu9cW6ExSB4bArBqzFmFlHxcV2p/7aiZRRfayd6d57AYv
         pfVWqDii825BiPmT8TSdwqKIQj/kz4WTf1h6ueNXIe7X2huJDoUx0MxDHoy6a9DCduYX
         iboUODoXEe0NL8qUYwLc0FOWALiX6/Xd8uDYolhz6ALO1DQsN9YRdoj+BE30/CatMsbo
         GtsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuvAYrWrDWsRgfqFsLM+0/0hTNflVYML0EtnHoc8kUzX5ErXjIDfHatGF1cTQDSbEyWQvV3C2cKBngzyt/m55yglmKNEEAhQ==
X-Gm-Message-State: AOJu0Yxknco5YSxhIjdefH/JHPYAUoYdZEK64HVRIs8N7MzS1EMK7Ed5
	GSe7LBg3sgmcedLPc0XhUrpROob2TKq/90DPY3LAJjpLwMAv8zaa
X-Google-Smtp-Source: AGHT+IHKE+e+tXEOGDFetJ/L04tJXWKq7KygMGu0OpeqayqaugSjVbQVOddJPlKOybCPrF/wC8muKQ==
X-Received: by 2002:a17:90a:ea18:b0:2c7:af59:dc11 with SMTP id 98e67ed59e1d1-2c7b5dc9ff8mr3828293a91.48.1718845153725;
        Wed, 19 Jun 2024 17:59:13 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8d:b0:2c7:dd7d:5edd with SMTP id
 98e67ed59e1d1-2c7dff07fbfls220622a91.2.-pod-prod-05-us; Wed, 19 Jun 2024
 17:59:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3WlGBDi8L4XdMNp99hTAAkDZd0+T2Av/PrmK6TzCbv4IyFOzP4ZXENFAPK1//4O0xO7Fhc/tG4GdmwMv8CIqdLexmbGyd1MhsDg==
X-Received: by 2002:a17:90a:6047:b0:2c2:d813:bffa with SMTP id 98e67ed59e1d1-2c7b5dc805cmr3781429a91.43.1718845152524;
        Wed, 19 Jun 2024 17:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845152; cv=none;
        d=google.com; s=arc-20160816;
        b=wUV84QEfSKfOufMws29+MJUnq3cOqeaMGwe0jQoCTOgegVnpr8fQofYNiaK07A8m9h
         XCqOEHXiBf+pNyirWzlWRei3HudFplA/D59BDqA5N6aC9lk3OF2CPMuIfayAC40O7IQx
         kemnCrcnizyiw2a/LhQYguYjNOe0vZfD7y789lU2TIO28uslZ3Bz+nmumZ9+tadRyQT3
         E3FJtnlc6C0WPEbWWRn1LjeRugICo4acXTDy761XA1nSrUz4bOcaiYiyT2Oht9caYnfP
         pXVWJlSVz1rKF6ucCkGpyJvGxiii7SQyCkfT+IrdFgi2hOFopwBEe/kHgSPdEJqoYFLI
         wSPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=Eml6JFMn845/mxrnSP9Zi3XhFRahuYCINNYcQscR72Y=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=V2Fjoa8w+z3YOs+uL2y+AyZJL6MFUG3xsx9q5yEMJ5o1uWcggrlGznFdUjHHbCTvBG
         xRMt7Foj0gq0LZJ/mh5zTTd8z4m8DNP+0dz4z5JF8M8s6BkQISP6R4PEhJqukgMUpeFT
         QNY++OVjjYJlyA3tbcj9l3GYovYNitSTb12Llh+Q3oh95QBUsIuOWeTTuhcHDE5+Hdqt
         nKN1W1w4V1b5E5aTQblQr5cQ6Dd9IKYAzuk5vA1zN9W3m6Ml8/Yg39LYZ2efpC+KYzYM
         ywnIga/nfoaoY3fhRmvPnonhw1pPn+DbQf+O7SMD4pAdEGfRMmlCiCqAVGjBN8cU8Gcu
         rEpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=teNJfzeb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738c1998asi340737a91.1.2024.06.19.17.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D843E62064;
	Thu, 20 Jun 2024 00:59:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7F150C2BBFC;
	Thu, 20 Jun 2024 00:59:11 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:11 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch added to mm-unstable branch
Message-Id: <20240620005911.7F150C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=teNJfzeb;
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
     Subject: s390/ftrace: unpoison ftrace_regs in kprobe_ftrace_handler()
has been added to the -mm mm-unstable branch.  Its filename is
     s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch

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
Subject: s390/ftrace: unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Wed, 19 Jun 2024 17:44:03 +0200

s390 uses assembly code to initialize ftrace_regs and call
kprobe_ftrace_handler().  Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on kprobe_ftrace_handler() entry.  This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the assembly code and always unpoisoning ftrace_regs in
kprobe_ftrace_handler().

Link: https://lkml.kernel.org/r/20240619154530.163232-29-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/kernel/ftrace.c |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/kernel/ftrace.c~s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler
+++ a/arch/s390/kernel/ftrace.c
@@ -12,6 +12,7 @@
 #include <linux/ftrace.h>
 #include <linux/kernel.h>
 #include <linux/types.h>
+#include <linux/kmsan-checks.h>
 #include <linux/kprobes.h>
 #include <linux/execmem.h>
 #include <trace/syscall.h>
@@ -303,6 +304,7 @@ void kprobe_ftrace_handler(unsigned long
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005911.7F150C2BBFC%40smtp.kernel.org.
