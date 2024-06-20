Return-Path: <kasan-dev+bncBCT4XGV33UIBB5H5ZWZQMGQEBLEQHOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 22BBE90FAB3
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:34 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-dff204c75b8sf77212276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845173; cv=pass;
        d=google.com; s=arc-20160816;
        b=CBZfjuSIkPAY8sSgJ7eaFEFqCNTykzR6ss1Plpr/TVLuDGuN9+9Zfgd+S0/rcnPX4J
         htHKOwGL33RlZUY4oWr/+5lKHIZjmQxBwjxFevnBi9QRMDIFSnAHCAgEVOjosIsfB0ji
         2Ckvy7xQ2k0rsghxlOAjCdRwLRvXmRgDI275gNdbglwrUAmEH5VIqVMlwPvDkS1uVV3V
         wA3uRxBlH8nx8m2DlSATLKZZfduPuBArBxdktIRY31OX4PLrbNkAdDJ3QDT+L+wdNv6m
         e5uZoM15iJsbekk7juzba7xnFNzlofIpV4PeqbLC7HnUQUkpHuw0usf56CsHZgk/abhD
         40mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=YFRRw4PlWaBNv7GPGHVp15norQSwjCchuxIyAv2TI/8=;
        fh=ZACLHpivyLvdopnnYrAHcZIskMdhk86lCdmAZPH0kOA=;
        b=VUGVX3BaXN1CVeacBm4OYp5H1JQdc2bEbXyfodE21At0/BfGmJvfQrCfQNRy+P7628
         sNAIRRckXR4bMbCh/tuJXNoWlUgH3VGnUS9fQOxuJh/SQUMwD5EYdxk7PY5YvRl1G+IL
         oi6XFuZQgQNH2znkHBC1+5cfhz/IDWlR8ELSKjBO0aU2GQUC1iOGbY8NRL2KFDECWo9i
         NbVorzOFdynRL/Jj4B5cWQyOjlKtzWaySqMizNlU3hRyzRvO7JpoH+xe/6Vobg62LDXY
         1w3j7Qtlq1zpS+vL3EBEr7WSdjkcI6DjwONEV1GCNpeNz3/fWK4LoGfPktjBiUmXXBAd
         ajJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=mU+46IVV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845173; x=1719449973; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YFRRw4PlWaBNv7GPGHVp15norQSwjCchuxIyAv2TI/8=;
        b=EAzID0sDSWJ00Rn4NOU4GUtOFQGiF10sVIKkgV27z2MxuMzqGBBDQHAFPWMgRXABYC
         yjIXbSbDmq5lCZ4LM0ZRBLYDYSHTb9OqC4rxgVPVh8Hn8UjZf7IazzudQMS5JT3Q7w02
         xjAI4By4tws4GRo0NCTBb3+5gi37zfq+VSGSrZPHrUs64RCld4tE+fMjR5YM1GPGIWHx
         szonJT7Nzjkt8RzaJpdptO6ZQts0pI7Yj+y4IVAKaj8T9vAx/DQnpG2xO14TOLayrl1z
         LuIjFZK3iU3HIW6lw48FBWROpxEiYz4Swgh9polif6cbyU4RBUTbnCBh5pEB7UF52jai
         IAhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845173; x=1719449973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YFRRw4PlWaBNv7GPGHVp15norQSwjCchuxIyAv2TI/8=;
        b=KrnpY/zIlEYIKMEw8Tjwr85yYgcJGTnqSxKiQTnd6g/4wJfBpvx+Pt4XMMRwbBMTsK
         YtQkPQj3dM+TUY5icVigoWOA1zEke4Kz/iQ3fshMWiN0/cldwP2f+uNy5dS8LwnfoH3B
         bM1Vtod6Ukmq6UZR9RHEUzUSkny0/7oX/jKcljP0cskBJ7bQ2z1rAdRiWBtmazshIPi2
         x/1uRbWrff5FebRsXXOZ0CMzQTUasx/ExT0zPoade4ug8T3eF3776pq2OSTgfSh3GA/i
         uGxR4foelkHKvuarlEciW3QAuQzA6eA2paeggaZ10Daw5QEe8Pcpv5pwOLcTtonl1Iru
         maFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsDNX8Vuz0gYlTZ146NtpnH5rmoUijomJAipVJ4TF/6x7urHjIYU7/x8K80Dv8SGPS9PYdO0nS8XFsSLbFkhJBvUosFo9oRA==
X-Gm-Message-State: AOJu0YwdmxStfRH3UJZLCFJyu9xbxnd/TYEmqusOA8I8w8bh2FjRL4gn
	hxOX1VX3xAET/O2AZfWf4SquV4UybiNdODkEztQPu1mvrQ0hK/Ma
X-Google-Smtp-Source: AGHT+IEpwdA706BiqcCCgTzKkjZmeceEWGmEqLpefJV55UjGHzI6DN7sU2n4NFIDSh+ZvwEiM4Ap+g==
X-Received: by 2002:a25:d690:0:b0:dff:2d17:2fd1 with SMTP id 3f1490d57ef6-e02be28ead4mr3760590276.5.1718845172975;
        Wed, 19 Jun 2024 17:59:32 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1005:b0:dfe:54e6:8233 with SMTP id
 3f1490d57ef6-e02d0ac0822ls577292276.0.-pod-prod-08-us; Wed, 19 Jun 2024
 17:59:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUdSZjkqLiYGk3uuoaSvMvjK6vxoX9ADDlU/wyVp2ntRIEBN2mZhY3RtdE5RTjbMk9lMt+jQnEJ8vCQ8GhHdgr0m3SA8rBgoTsaA==
X-Received: by 2002:a25:ce87:0:b0:dff:bfc:1643 with SMTP id 3f1490d57ef6-e02be20b648mr4555278276.49.1718845171832;
        Wed, 19 Jun 2024 17:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845171; cv=none;
        d=google.com; s=arc-20160816;
        b=Zl1pheAC2tYcT6BzjlIsXA083MFzE/ISY97plhw0bIKPX1MY9L3QTy8B1czebnsDhg
         MxmnfbZHVUGkfNY465/RUNtjv5zrjSCk4HuW2w/vwSw7gswk1r+lYqdvINfUVtGSTevO
         Hn9RUjQcAyDYgKaVKdzUzUnQIax0WWCCeQGpzlllq77+n5j3YL1zq9qCJhgPg0cxyKYI
         UkoYZfiFENl603OMI3utA8cHqOYDHoQ6pS7uGDWLQWcx7/t8w7ILP1cgrfUPbmvmoM4h
         90Kp157VOERjQJjLBjGZUxXXMSWh9nD+VbzZ+L6z+zZ6U6/Y2qz0r5QzvCmlEI3Qjaq6
         EWgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=BszEpxtq9I0j/tBMCHvnY/ZruX82AUgigqWDVXIlvOw=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=RhlMQKEhCKuQiEwJjbE4Now+gviS08zxeL7ve4IO096gXIzNyilDD/l3xkjULIXshJ
         ZWYu3ZBTnKN+gfPhtWmOB7YtwgJTu6hF35ywh166fkk0P5npaVctY887ynmXJI/4pJPW
         fblLu7C1qXQUcQF25i2/LilCvAPu1/+xhM23K7GEsskDuO2b9VZDCFXPqMRi8TX+9aBm
         ObDNfr70FfklX5YyPjxLbFficPQ30WXiuaj/bGdG4WL+cd8Uswbcj4hcASsxbgKKGdys
         ydK3UgkCGgOrL8nYu1S3wdQxTtchmI0oVqKjruzULZ8cUmPBf4mg5BwlyDB2CJd2H2Wh
         AL3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=mU+46IVV;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e02b85c0a9esi299561276.3.2024.06.19.17.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8151461E29;
	Thu, 20 Jun 2024 00:59:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 27D9EC2BBFC;
	Thu, 20 Jun 2024 00:59:31 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:30 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-enable-on-s390.patch added to mm-unstable branch
Message-Id: <20240620005931.27D9EC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=mU+46IVV;
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
     Subject: kmsan: enable on s390
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-enable-on-s390.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-enable-on-s390.patch

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
Subject: kmsan: enable on s390
Date: Wed, 19 Jun 2024 17:44:12 +0200

Now that everything else is in place, enable KMSAN in Kconfig.

Link: https://lkml.kernel.org/r/20240619154530.163232-38-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/Kconfig |    1 +
 1 file changed, 1 insertion(+)

--- a/arch/s390/Kconfig~kmsan-enable-on-s390
+++ a/arch/s390/Kconfig
@@ -158,6 +158,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005931.27D9EC2BBFC%40smtp.kernel.org.
