Return-Path: <kasan-dev+bncBCT4XGV33UIBBUX5ZWZQMGQELUCZ6PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 16C8590FAA2
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:00 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f851ea7a09sf4400445ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845138; cv=pass;
        d=google.com; s=arc-20160816;
        b=OjmM2kfHL2CG1MD0etbH4rdRaK86jM+upzXoTL0RHQnhToDBxTYEdd1Ha4hkojeRG/
         90NFcWTS+Uc2NnG5juuL9dWrpMVSb8QLgyEVtGLL+IGosfTIpmRw7ryw/U9+4q1R3HxE
         qKtDiYiKsE1EdQulFaXPX8nXIXHEveJYGMj/+qxzIsWriL8h+1LrmEvq48Lwz9zme7rx
         DBEHEma45oINrml3XvVexL5embBgU23vc/7r1BM0KQed609k+0+RbmkT/t1dDnUc4AdU
         sCjETG7vAJiDpXdNnVIVJVM71XbYpSMbVRUJ6MH6DTJ/O+xld4S6LEGN2bqWkr8+AZKo
         FrxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=9AvPWOx9iQ8caPS2zZlGYl4/P1+3MYt5xMbqT7lyWAE=;
        fh=DS1QTf8dLSwvHJy1cqN7SQN/Fina34q5lVHIb+lJRQY=;
        b=sM4rbJWacaElVDoJVrsfxMuF82v5ueSgE+gafN3VrwucxPvNCp1MgYSUmNNvbPVrDd
         +hcej7Y8ZVn/sUaQtSyAoATDrnzKwQoCM7ZXdNL4G5EdJ7I9GLWUCJIS9ADah/1Na9t1
         A4+nWP2B0+Fy2htgqYWgDedQjvzlBoZzMZJSzE4JnMwGlIvPdBoyQZBczE1GetMaoCPQ
         ESxAXkblUz1bBtc18okCyZkzZzBNh/dxGdFaXdZ44+WO9ETU95Hehc9Imsv5C7V1d0jc
         01iTxtgHkeMRSHwzKgA0QpVuyz4BP+5lY95o9rEhakLta9Nu45vbtFXpPStGUauKyqul
         sz1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qRaQxXYa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845138; x=1719449938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9AvPWOx9iQ8caPS2zZlGYl4/P1+3MYt5xMbqT7lyWAE=;
        b=m7SLHxy+4mj/DKtuiF21rH51d8mVTGVWylkH+5izX7IaG4X0vO5Hx8HtVAzP6NVQeg
         F+YZUOnsZkj2Y54MZn/N2bD4LN4XXBxas3NYf/QJcWVk7khJ4fD6WPmmfv/qM/SO50MO
         Yrq9W9csyBarSQtsX8CN37OmLdPGxZxjgyR/VGRmHr0nd5bOaMFyhEG+PisTRCATxyin
         aDd65KUsAdgnAUokCpxvunJdaDAqPgdCFaLgoegGjNCXUtYh3i/khD2NFU3NCx5t96bh
         Hvg7dro+5AslVbBMr8SRT9Fur0PN411VwSxUqhAFsDopuvqRyNLBV2Q/FlcYU3u8xdfQ
         pKCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845138; x=1719449938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9AvPWOx9iQ8caPS2zZlGYl4/P1+3MYt5xMbqT7lyWAE=;
        b=b1XT6K+cMqt5rlKQKL2qjs4iPAItg4UbuaCMRN+5aU1S2u21TlwIur382RaNP++k/Q
         l4pzeFgx0j14Ryz8vH6xaGUORLRwGgw1ZCEOVcQZCFMSDcjd8Hk/HYITY8jVLjdDMkrB
         /4tvuAdGsntdqFfCC/UnF8jJ0VOb8k+x/3gM+nRYpvj6mF7CEZ2rGL3exiVFWASAsTyh
         BMQRM0OZvXtvmu3TgnbWoXEYYsuNGpWmjULeHn2+BWioIwnb1dWckJha/IlW1Gunx5+H
         sjz1lILx4NenFKFNWd+kDOMYK1XbWDncLJ8pr3Y22fTCysrp8VViK1rxQzoyQijpc5FM
         MmdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiZtpLrFfK7oqEXuEuNt9rIzuzBynxk/lDeMoeZRNc7RNbK9viWjmLa422mILfXEX7yL1e0n20fczgSmER8qYnU5Vj7Yxk5Q==
X-Gm-Message-State: AOJu0YwqQaJUWVhPMzHyFZMkz1ne0A4o8EAfxoZxxYj6lcWA/NXl2NDs
	i0m7QQsCytrR4wZb0nVaD1VJpQ4XX0Kr0eors3pYdEG3zOzh7xfD
X-Google-Smtp-Source: AGHT+IG//bua1Fg1eCbW0Y6fL1dF3oSW/AQgMCJF+L/hr70CmUmo9uyjObR4Q++DmgkWIGx4GGREqg==
X-Received: by 2002:a17:902:b7ca:b0:1f4:7db0:afbd with SMTP id d9443c01a7336-1f9abcf46d4mr4407005ad.28.1718845138593;
        Wed, 19 Jun 2024 17:58:58 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4393:b0:2c3:10d9:f2bf with SMTP id
 98e67ed59e1d1-2c7dfedaea7ls264600a91.1.-pod-prod-06-us; Wed, 19 Jun 2024
 17:58:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpbT706Wgpq4snkgCgoo4KTW2cY5JAa1NmTA9mUo/PkrNzGsRosoJxgcrPwFFyBQRC3yfZpy4qoXIYmJhvu1eWoxBrFe3udsDWwg==
X-Received: by 2002:a17:902:d482:b0:1f7:1ac9:1251 with SMTP id d9443c01a7336-1f9aa3edfbamr51133735ad.31.1718845137362;
        Wed, 19 Jun 2024 17:58:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845137; cv=none;
        d=google.com; s=arc-20160816;
        b=EkhwB5HgvcYavW9lork/JMUsiq9DYux+n7K8Vp6kO55Esxply625Vs1sk+gAP/Cthl
         ZQ6iOWCk9csrDFae5FXTXRYhW2gVsnQMw4eentmJhPAmiWCzRCH6S/7dbqL01GiJBmaA
         IuQoiuYBWTUuwaZcN5jCXEkPCpkH5nxruG56uVKtYr+KTFNeDyWQx7z2IrS1cakU1aQu
         X8EIvH4yl6mWrU6vNuMhdvPzzC76s642Ps0Y7lbRwlAzNatnPoSJCtjNjDMMZQw8g4FZ
         ZKbq4dy6HQYq3HtQW0tZUjkbGeprKuuf2C58WO0qMYxIIXtOHprKgB0OEMDGYUq1Dixh
         svdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=OjpKV9gBvbdfbGbxQBpHv/3ReBGAZpx/F8O+AGswo8U=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=kundA1ZuOZ4RdnEEkAuh7CM1oHBC5eB6ULKIfKuE3VUMfZMYvXIJwDTvc+PS93FScA
         jTHdURfNCz2dopwKDGcHFEx/GMTdzkqGDsd7u5E8lh2Q5x11+M7HUasQpMmKDtlzMHAW
         gzhpEfuVOpZIfstldJ65KbhhUeV9lnblHDdg1Xz+VTRZvAKvLeyVY4rMwqZ3i2sjxf1Z
         hP3zOecsua4vrNJeAusM2z6/1cLcxB2jXpiFcjiCzV7OqqKLDR+B4JQzF2MI9ThkWDV/
         q0p6JUiAREjchUOh/Poeyq8mE34UdrUAXjWgwtPlqxHHVkneJlOOQB4Y5dAbcLuKrGVW
         a5jA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qRaQxXYa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9a4a52891si1663225ad.10.2024.06.19.17.58.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 7CB4BCE22D5;
	Thu, 20 Jun 2024 00:58:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BF516C2BBFC;
	Thu, 20 Jun 2024 00:58:54 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:54 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-accept-ranges-starting-with-0-on-s390.patch added to mm-unstable branch
Message-Id: <20240620005854.BF516C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=qRaQxXYa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: kmsan: accept ranges starting with 0 on s390
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-accept-ranges-starting-with-0-on-s390.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-accept-ranges-starting-with-0-on-s390.patch

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
Subject: kmsan: accept ranges starting with 0 on s390
Date: Wed, 19 Jun 2024 17:43:55 +0200

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390.  There doesn't seem to be a Kconfig
option to describe this situation, so explicitly check for s390.

Link: https://lkml.kernel.org/r/20240619154530.163232-21-iii@linux.ibm.com
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

 mm/kmsan/init.c |    5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

--- a/mm/kmsan/init.c~kmsan-accept-ranges-starting-with-0-on-s390
+++ a/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_s
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005854.BF516C2BBFC%40smtp.kernel.org.
