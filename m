Return-Path: <kasan-dev+bncBCT4XGV33UIBBLP5ZWZQMGQE7YWXM3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 98FBF90FA92
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:23 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-25cb4261a5csf329733fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845102; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8MmHDvxiYTSyHLIdFwcUSYjoyunfVn7Ds83ECmgu0/1i+Vs1NRkQgEBNKTTowWTGF
         HsyyfvNlU2op9HXa4GRzFRZso5yhZmjA3iAk5XntMQDSppMYTH3IQDuH7BSfs8IUTVHd
         XvRGQvAO7KOBN63fFLvunInxAGyQSyuslTL4oOrEzdDBC8obpAX7JI8Mg+g8vf7ctu5M
         Z7BWTOHjwLEjS2hB9GM1fBpqNw182tBdVmo50xyv58+JpAv72GQxAFqCWfK3/EEEk1xy
         fBma6C/nS2HD6GcmiSZSf2nPF2/hC/ycytNIKGEnKtJ7DcH23x/ja2F5vTUzTel+u112
         xmQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=aXaCjv91d7QghcAfR6S4j8CvFKoGWZhpi4hwEYiF6A4=;
        fh=pbwmTeFya1qDqKgUDGt71PWfItMdlNZX3z/rB9aSW7U=;
        b=iuDrshzQYrSDRkwsXOBJDRSxB1HAvFy3VZflMApu1tia4o4vH3MFEDjvDV3+TvuUdr
         lmZUuO9vEuX2ea7tsVn5/RoBc9Q7j7MnTv55DKHcAGtyGh4JYpKao728U6qgQMou1j6p
         DIOHa9S+tNfjjjUYlABewzAvzssq4As2Gqod5uceyYQWcIH3zhgib0bxshXtpd2yNBzm
         JtFigKn7XZaL/3kT15jTcJ5qTNSkptL7v6qrvOocwUnfmzE+B1e4JQrUBJczOy4TfpQ6
         ZqhDluIWmUoKC0NzujYAJaEWuiHfg/pTPrpSSHZ9UkfrUSmTepwjHuDn890JyssSi5PK
         oezA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="QL/1UEPn";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845102; x=1719449902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aXaCjv91d7QghcAfR6S4j8CvFKoGWZhpi4hwEYiF6A4=;
        b=jpZHjwmWhYpyMyoSpZcLdRcgYoZG3jVE1HgYqbwIHfqA4KQAcsnU1T/qh/yeQgQLqL
         A3YPJBI7uPrJc/Y+m84n+xyLTi+z2vbM+SCz2XqFlNzEVC1xEo7kdb25Gh24jx7u9GV+
         lUyfDLy3jUh90wHMrygKfZkLiVUmbgVVK8p4wbhY9bX5C0W3WRHYioT5YLrquxVgB/jr
         0ezDNoSgmBbmA7bltUoJhNMRE/sdfVZZcC21yAL1olfQlfuEI2pfM4/W78k1DkTPA7xg
         Y7gVXkzXZzWwFN19UbmlCgdzV+tNlULY7ahZb7z8cI40rxF2lItJy4Jz1ZCH3V37I+nc
         zFdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845102; x=1719449902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aXaCjv91d7QghcAfR6S4j8CvFKoGWZhpi4hwEYiF6A4=;
        b=aS5Xp7YDdkMBTDgHvIkG9GQeb/IriV1tApo5c2PHUKmfiQE2bAVpPZVi/UTXRh9f/O
         7pW5aQSlCe8h4PQYjnPOTPyZPoa0pZrXl2RXuDJ6PJuQ8lFhKtpKRyHr95P25NihfVzR
         FK+ka73cknBTzGJOw0khdptgL9zpUt4QDnEzA/VmFtd6CcRNVGx8mtVpfoNyNfRAKIES
         Nz3xohamDOV/7g6knKdW8wXIeE9puBFDEFPM3gxb5rgYU5fUQ5EBBc6HvEjPK05Jpw7P
         d8Lyy0a7Sw51gX0msOvo8nZUZt0EqK8CirrCCmbQ7WfKoNTE8D6O/AlRAWuRMPdpTp/H
         1ukQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3c/ey9F61vCpQUuGMfwbhmolcYJlv4ZYwviJWgg5JTtdNduN8A6cwK6A7c8moxMnJvLQfAA3D/zf1dmV0JwTew1/ZvfirLQ==
X-Gm-Message-State: AOJu0YzEf6Ie1EziylZ5f7S17lzIlXqsfAHHW6cNMh/6hS4y+cuph/Wa
	X7t4a8zem08JnnjtAFll/NRNhcdSkPw65EfGrif2zKGiuUSdbJqK
X-Google-Smtp-Source: AGHT+IHkfLPknv5cqv90e5dMuGddrehHyPZVxcPLMnYW7QSkipQz24Y38BOIxkySwA0Z0lu5WRWhWA==
X-Received: by 2002:a05:6871:10c:b0:259:8cb3:db2e with SMTP id 586e51a60fabf-25c94d06ef5mr4554383fac.39.1718845102033;
        Wed, 19 Jun 2024 17:58:22 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8008:b0:706:4559:9351 with SMTP id
 d2e1a72fcca58-7064559996fls32674b3a.1.-pod-prod-04-us; Wed, 19 Jun 2024
 17:58:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3m0Xgx+SHre1N+U1ELj6qxWyM/DPMSNwdfN79XfyCqggBcL1sA4bGbgesUojM9EwcOOPc7PKxMgHuCCS/nGjMyJN3SG1y/Mg9vw==
X-Received: by 2002:a05:6a20:338a:b0:1b5:781a:61b0 with SMTP id adf61e73a8af0-1bcbb6cb355mr3959084637.61.1718845100660;
        Wed, 19 Jun 2024 17:58:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845100; cv=none;
        d=google.com; s=arc-20160816;
        b=ikQSa5TKTIOkw5JY5vo/yrZSs6DdTqqOUPA2eIjcrAYnfvsJF0V+300RfKcc9buFTH
         3wZBCoIkqBbdcpoNxEE8+RX1X40uaWUx59RiG9AblIQ3SOShCZki/Ncw5KlWJOpQEFsG
         ywC8qWDRI0XTEvtTmU7xIhtmmn4RRk9f3D8wvlywj3FdjoTPjNSWirgm+PnUQp1j0Dqn
         FcPpyuBc65MbHhD8yf88EkC1JKtt4I9Toa+Ym7C//n5srcfEDdnPgLX26aTi7meru+C+
         n0ShDHL7OlSdYqtvCtwwHXMn4TVeEEzfMFZOWd/bn3wn+tlxy36gt0zW9fhVCUuuGHWi
         IqEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=EBWkkAe/yn1xvaCymPvuhZDqoWN8hLjmSn4hdoUf+zg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=hHhFjmvR/aqBYxUPwLX/qF+cVnyvGO6YNuF9g6bXQZpDaAHDG8GUp6h90tGAEH7F0z
         ZlKunjclByMCOrbIO01IWXI+w75DMaJCYNtlkEhV2mqfdX3M8VxgHIx6vYtddgwztQSl
         r+ojv1XcfJ2FOrmLHJvABS+vYf7Nk1KpfgoorUAnqoZ6BE1IOfk+lGW+voUBW3J2Ip1p
         1NjHABMR0ljLjOeve8HcsL4eXhGTahMiOhMb94hHsHOIMGsFa5ew0LRQLrXBMdrL+zZO
         n5iupa20UMmN0wpK2yT+1GXwsB+JM2TUvuBxbV1JBeNST5R+NKKBbh3jnFir3g5BOO5a
         wXJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="QL/1UEPn";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855d19cb6si5500535ad.0.2024.06.19.17.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id F37286205B;
	Thu, 20 Jun 2024 00:58:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98DA3C2BBFC;
	Thu, 20 Jun 2024 00:58:19 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:19 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-increase-the-maximum-store-size-to-4096.patch added to mm-unstable branch
Message-Id: <20240620005819.98DA3C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="QL/1UEPn";
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
     Subject: kmsan: increase the maximum store size to 4096
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-increase-the-maximum-store-size-to-4096.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-increase-the-maximum-store-size-to-4096.patch

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
Subject: kmsan: increase the maximum store size to 4096
Date: Wed, 19 Jun 2024 17:43:39 +0200

The inline assembly block in s390's chsc() stores that much.

Link: https://lkml.kernel.org/r/20240619154530.163232-5-iii@linux.ibm.com
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

 mm/kmsan/instrumentation.c |    7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

--- a/mm/kmsan/instrumentation.c~kmsan-increase-the-maximum-store-size-to-4096
+++ a/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *a
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005819.98DA3C2BBFC%40smtp.kernel.org.
