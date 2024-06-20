Return-Path: <kasan-dev+bncBCT4XGV33UIBBYP5ZWZQMGQE62RSKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94D6090FAA9
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:14 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-43fb02db8basf3258011cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845153; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIyRBjBgrXxHz7Fpp1nTrhN/cDhguk7NLemH5oI7L6lNjE8RiaeqoCVsU8snffs1Jk
         HXd/FJsx1JD0EpX8Qh5B93ImDLVQdyn4os8Hz+9ExZmeUMvcaojezzhfUkycDjnxmUT4
         WFFDIYHqtWxQ+Kq7sJ2TfiZZEs2OetDeFg/f8kLsXH3cL3d87qSaSQTcKvH/hYiP/Dl5
         ihQ2vWK0m4BE2SCcuGjEwjSNtOFMzZVWQwFuV6ICs0prGimVF565JXF0mGY+JyaARbwn
         Ruu8NdAMhp+5ZMUHbwUIT1baqxc+UJfoo4M9GDpdP/mRyuSCrHdKCj5cGkqq2WFj7BBC
         FaZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=bwbS3gKfcvzh2gLY5bttgHym9DNNNyYmKjjiGGr9y8c=;
        fh=Sc5QtSup1Mw5c2SI9U/lvfhQe/86f361u2/c0faA9Cs=;
        b=zyFrFI+SFS0sRxnJ5p/7HFhQ0uWT3EEEDzenfVFtggBKzQ/oqE6K3O6mC1bHIFWnpl
         oB7OTxUnBONX1IIz+sf20Q5e6sX0CvuIq7DJisYueL8IgwC3TRIr+UlKSZE6PFwYr0Je
         FgKnrZ1Qt8KPoPN/7Fg1znJXNMzzUsUHp4/Z2pZHg3rcn43aNnjwdZ+ymy0ZgPHkuyfo
         yt2b7gm2HXAJcLAuy8Sfr7Twq8BEolE1DZYfCArV1IkxakKXcWiYuflUhv2KHGnawFji
         GefZounckPot6lGlIrw4Bj+D+nyhWnIDxGrMjQeRBGCMBfb3ai6lVTTWEcg+nf0JC9X1
         LHwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Waa6SUXs;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845153; x=1719449953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bwbS3gKfcvzh2gLY5bttgHym9DNNNyYmKjjiGGr9y8c=;
        b=TdMac3ut3jXQTw9wsGbT4SuTz3wtAlRaUjpO5p6TB/aEb1ZRYHQRgV3gn6ADXSL53I
         VwfVcN6hRRBKJuFcAIOXnafwmUT5cM8O3DnOZ74eHDqtaej0gXtbxwrkQ6wlTvMYRgk2
         aqWWZggFR/+0c/l5iQHCC73FPgg/g1j9yizt4IjsseQQ/VKH0jE9gLyToUyddee2Du6K
         PzrO/JX69sLqMW+FrF4KylDi5NUAsh+5tf81SZCBprAAVfP/ZJRuwnvIolwUGF1yQOsS
         QLSYykcm/fTCpZDtXRyaDdvLqw2W0PwvNtoqw8PmGFdNfkvB5OIb8upCEM88T1ZAZqqt
         1YFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845153; x=1719449953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bwbS3gKfcvzh2gLY5bttgHym9DNNNyYmKjjiGGr9y8c=;
        b=r8VXk1bMXm02ZPgvXUKcglxnm7D3XaKvELz2jf6GlptiC8Nou8EfWZztcLkRdjnhbk
         Xjt9fGf1jRXl8cI7C1v0y1Fg7hnPKpUp/sgMUIt9KXQ07ihgr92I7XdY8fxgAxRTkshS
         Z7ZEoPPWfk6PAeKG4ltx+/LbiaDF0ouD7xo0XDbj56XVJAStoj3TOOikkO63zP+pjy9u
         zN64rfwJeaLHVo7FTGYmN6IMc0DsCUIXUHP2cFCl65pa4EXePhFMtG4W14XOttwuLLRg
         /V2j7WrGAZoUSY4hjmtstYCGJRyqF37RZFMi3Z6PPLfkYrBUvWL2BMF9IBJpI06B6/3d
         lT/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrJ1Kki283qLreu19cPxjtoG0grBqlWQZ6elk1kfrSNvyAVu6BaHt8AEpF7hGXO95G93A2s6oj4ocTGKfL5ioYNIMWx5vekw==
X-Gm-Message-State: AOJu0YzoxnDyVip4laXkZ7iEdX1YQVUrVGRJoYaY43VyoJPs8rxHViZ8
	fCGlfEmc9eCfXtbqkw/E0xxeQ7vUnmvIP20TraRORFHZL+eyjuG/
X-Google-Smtp-Source: AGHT+IHjMpKAfEptMSb0laMfOJ9PLE0LP5PvAqGUx9+xtXVH1aY9svSjkoM4KTSCT+4Vb13bg70uBQ==
X-Received: by 2002:ac8:5e4e:0:b0:440:d294:3b48 with SMTP id d75a77b69052e-444a7a481d6mr49893841cf.47.1718845153532;
        Wed, 19 Jun 2024 17:59:13 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d16:0:b0:440:4eb7:2925 with SMTP id d75a77b69052e-444b4c3031als2824231cf.1.-pod-prod-01-us;
 Wed, 19 Jun 2024 17:59:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXuOPLLV26lZz0yOM2Ta5p6kdYGLhVntdkTdMhvSSgv4ObS1cC+LE+CHhWN3m2cqllqgmWegp4v6IlUwXc3kt1eH00g2PGyPgsEg==
X-Received: by 2002:a05:620a:4046:b0:79b:c0bb:1f1b with SMTP id af79cd13be357-79bc0bb2200mr195853685a.37.1718845152762;
        Wed, 19 Jun 2024 17:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845152; cv=none;
        d=google.com; s=arc-20160816;
        b=r2gNPodHESGbDW2VnPDeLFnm2YpZ9XSPrbOsnkljiHvFZYXF9sgM8+txwCuaBYtb7P
         5JhEq9FtAToHp+ReHWrYCy32nDUCDRVthmZ0LkZSHzOo3UVrXNn9ButnKKETyoqX4Qxc
         o1h5YfWpcARWt0GsugdQaOcBBAMppJ67ypzoPaFSCGwl7DsC2F4b3hsMnlp8m1TuAZbY
         59TePgrr/VcMSQTTVivKxLCkInAj9usU3rCQfkO6SPDBaHKHNux4mVvypeXEE0p1jCwv
         WbJrmR5h+lTJE7y4mCiBK7SBTS3Z1hoW1YgS/en7JulQlymfJysWEL4WmfuIH043aiN+
         4fkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ZGChcYAnXz1oNFseqsfWFlRMPn+jL/GkSp2mCMOUuXw=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=ZTEymZAWqsGcB659vffr9kCF1bn0dRAtDWe3mzErx/J9gvqi2BNJMa0CdsbUqsHqQj
         8Cf1QfUEAEIsMSYTyUjF6SjTr2FlVhP8EEyA7LhoN9flmIZyzfz92Cb/4omNNnScwxfW
         vp//Gb9LCogG1fw39ArkvKNXHHnmMirL4RxYZmKHAuIBP00iCO2wjTOuGQZti1iMNyQD
         cvv5AQbApWo/peKOkUDqiwZ04uCGQJc5yD3ukl4l6GeZYkxlZOmTu/yD1+N+lB/Uoz8k
         +qSlizYNkAPMPXGHs/9AXpUQiH5SU81SX3Z1xw2eProZJ8TiVjyGQ/VXmYO5wc25lsq6
         ZL6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Waa6SUXs;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798ac0ada77si68505185a.7.2024.06.19.17.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 4CE0FCE22D5;
	Thu, 20 Jun 2024 00:59:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8DA00C2BBFC;
	Thu, 20 Jun 2024 00:59:09 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:09 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-diag-unpoison-diag224-output-buffer.patch added to mm-unstable branch
Message-Id: <20240620005909.8DA00C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Waa6SUXs;
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
     Subject: s390/diag: unpoison diag224() output buffer
has been added to the -mm mm-unstable branch.  Its filename is
     s390-diag-unpoison-diag224-output-buffer.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-diag-unpoison-diag224-output-buffer.patch

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
Subject: s390/diag: unpoison diag224() output buffer
Date: Wed, 19 Jun 2024 17:44:02 +0200

Diagnose 224 stores 4k bytes, which currently cannot be deduced from the
inline assembly constraints.  This leads to KMSAN false positives.

Fix the constraints by using a 4k-sized struct instead of a raw pointer. 
While at it, prettify them too.

Link: https://lkml.kernel.org/r/20240619154530.163232-28-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
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

 arch/s390/kernel/diag.c |   10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

--- a/arch/s390/kernel/diag.c~s390-diag-unpoison-diag224-output-buffer
+++ a/arch/s390/kernel/diag.c
@@ -278,12 +278,14 @@ int diag224(void *ptr)
 	int rc = -EOPNOTSUPP;
 
 	diag_stat_inc(DIAG_STAT_X224);
-	asm volatile(
-		"	diag	%1,%2,0x224\n"
-		"0:	lhi	%0,0x0\n"
+	asm volatile("\n"
+		"	diag	%[type],%[addr],0x224\n"
+		"0:	lhi	%[rc],0\n"
 		"1:\n"
 		EX_TABLE(0b,1b)
-		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+		: [rc] "+d" (rc)
+		, "=m" (*(struct { char buf[PAGE_SIZE]; } *)ptr)
+		: [type] "d" (0), [addr] "d" (addr));
 	return rc;
 }
 EXPORT_SYMBOL(diag224);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005909.8DA00C2BBFC%40smtp.kernel.org.
