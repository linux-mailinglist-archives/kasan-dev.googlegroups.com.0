Return-Path: <kasan-dev+bncBCT4XGV33UIBBWPD7WZQMGQEONXYB6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C02F91CA8E
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:51 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-44648cb4f5asf101061cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628250; cv=pass;
        d=google.com; s=arc-20160816;
        b=GGzJp66dNH+yUqP+VCJbC2pim1isyUPe3GhosgeyLhFanNsqyYotD2m6W+4ud3XIuH
         bEWPPmLUOjwpEz0mF1wtEDrFurSQipD6ocB2JRJWmqBQ3ETJDjB/yyysQ/k/mnmmCkeG
         g5W/77yWqxku7xYiCu/bS5yNziA/k5azzTUEkXidml6B8JQ2O+v9AuTIrAmxiyITkgpm
         AVM/qHMbFBnuROpKvacD5MJJ0v3Re9V4k6og36YjMja4pE2bwxt9r7sSB2dEvAJPYNF0
         8A6vcU0WCxj4f69/nckPcMlGxluEKY8Mr4ycw2gxgz68QbpWA72SlbeaAekxecDO/LRN
         XrdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=6IOSqkRkriauLmF7zMtxSQAdfooyPdXRBdM7T7diPfY=;
        fh=GfxNM7guvS+khGQzr4tY7hE8KeftyNVlHSEUbay0MWk=;
        b=NKoAyO79ak3Q+rFP7LPmrGp+kt9HO1WA+zmj48ELHj7BfjElfrhXLKXl+P8+c04FbJ
         iOjx9BKUlNMhllqlzQNfO4nv5soMI8pJJy3MAlyZTqi0gjAdA3TyTWPQLo9we5S8avtz
         QzcPWM6yKTLt5m7bP6YJVT6gFJgU/y117RBt3Faot796cG6BuztSY/6R3EdLKA3pjq7F
         K7U8w139cx6uVPvC2dHASfMbyzPDvXXkcEFrbp5Ltiklr8JZJL0Zgm7wEXsHF3Fxl+ho
         C8l9MoC/tolyELNDkMhyc6yth43zgMrPsOj+doLoOCuziT6dMuDbt8MoJROUdZbTi9oc
         ZH2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=tz1ypAWR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628250; x=1720233050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6IOSqkRkriauLmF7zMtxSQAdfooyPdXRBdM7T7diPfY=;
        b=neGAHb03cf5tHHXyQjxjpOOUIfOW6N6xXXS2ZsKBmly/uQG+x5CCh+Gwfj/YXL77Hn
         aIostH7xorTggd89ASpLr/U9tMucZiR0FDJkiyDvE0xwmLFS5cxQeU6ujNUg3ya993s/
         boi8CXWFzfBnlEiedINegJE1h8GgTRe85SvedgD4btNzaav891FT223UfYrKQgeg7JLw
         3zjUx5eWY7x93QMNo3g5iaAfaoafOLb7CHeMzYpr8hxoZmmo0MoB6tEJqk23nx/CcoDb
         gANpwYgEw8WQy6lH7HzxoLhZRwYxXEbTGmeKFbv+pLqjlWus14oyDfQcXI5n8VE8MjNR
         2png==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628250; x=1720233050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6IOSqkRkriauLmF7zMtxSQAdfooyPdXRBdM7T7diPfY=;
        b=WLKYJfGfz8S9ivjM2eXPZMC2nWs29d9WWyV4EcmxZFtwsvZsNgHPHnv+kFNaTWSvmt
         +Wa3+7NHiDbk+dbC8FESussHQmNx4V+gKV1GK5+2pLor3M6MJg7rUY+aoMqfK6hE3kDM
         cn/AGYTA24Fr+6YmJ6tW/B55zhVt1oWgKbiFxu5b1R7748KqCqeAVAdEFnQlbpsBMMpm
         0t/YihfpZ39MMcVQmKh7DtDsCqRcrkqlbsA/d6VG//qQT8B3OnyLPsdL0wk44ruOqsVP
         HbceF3ag+niE8ojQLVplAfJxt9bEHVF9K9qfcnwijIUNUICSP0trDBbbX6/gyxNQOW3e
         stlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhjgGE2aq83BzHVTo0JJLfoZKu/o0zRLIaAekXZJTerQL6iyz4yjUJUYPe6ecXKaLmPafyzG4EbXHmeGf048nnmyvkLKm1Gg==
X-Gm-Message-State: AOJu0Yyem6qwQ9OJAB903HiRygx3Ugz0V/092THKScZo/lvejZJVmiR8
	I6lt2N/RB/Ovm1JvUiEM+6YLWRbMd33o23G1f03yRxeWswOlPSJx
X-Google-Smtp-Source: AGHT+IEOAwcmgs2XO+5BjkxCRySv2XTzj07pcXOFUvjcG8HSV2EOARpZEVDk6Zwyl1iILVjFD4uTUQ==
X-Received: by 2002:ac8:4914:0:b0:443:99d8:746 with SMTP id d75a77b69052e-4465cefaa1cmr1377331cf.0.1719628249968;
        Fri, 28 Jun 2024 19:30:49 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5096:b0:6b2:a43b:dc38 with SMTP id
 6a1803df08f44-6b59fa97107ls23523996d6.0.-pod-prod-00-us; Fri, 28 Jun 2024
 19:30:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzzNxxhCQhmaLwCfvYxzjnjc4Wsccex5vwjd56IgGbjATZ42t4UjWu1qh5GhkTKB0ZW2TqktINvDoCsSDRQMW3HSOvjHifXuulXw==
X-Received: by 2002:a05:620a:4103:b0:79d:561c:bbac with SMTP id af79cd13be357-79d6bacdd3bmr597910185a.32.1719628249210;
        Fri, 28 Jun 2024 19:30:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628249; cv=none;
        d=google.com; s=arc-20160816;
        b=BQ/drx07qymnGKkUsuh54uSjKc9eTUSKV2pZEXymJOlDlAmGIEMHscXYgGcHDBRtTi
         42v0zQcP6zkwwxMs/ZMyppfmQY6Yo5nj+AYaURHmyAteAFY1V0jVVzjwpSWrWubQEb6s
         DfEagdYsCQw9u3O/gjNCf88CHDXWTPBGwWVR6Svyg9V8sRNB8u0Ct/2AKprTigSnepiC
         WACiqcBiOVpdDluB+yirSCQvPNeg+IWX9iZEHI4goMSYfvqmI+UFlsB6KhWWr12PHdDU
         VivWwIVsFGu6AnCXCfzWtxmm5fsMUyX1c2ntzJTZGwGb/5KDcEx3spZv0quioajSldml
         ZIjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=I8/EtahmivaJK2Rf3HCsheVTnaLDLuxGlfLy8S6+Ijg=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=iJpFNn2yvIE3RjDjDnRA5ThlSHErC76xg9ILtS5ZuyudBviW52wHKGXWwE96zpVNT2
         4Lmo8Hd4mCcJ4nuVk6q24epj573byeO2uD9xwwMlZhHMnbqdAlnHfR8mFvg+LEP8JJDt
         mfGKPHF9nWidawIl4YSzd4ZZ2YYSASXIWKvWY1eHbn+6aUEfZk1U7EyAu5hD1qYF4eS0
         sp8uy8x4MUHdT4u6PeX2KPdmzSo/7c06ZZCM17HMi1mE4AH3mEIw4/0lisbZERB8tuUP
         1pTyHFh0dPK7IQ0i6Wavnk71zDicdIbx5+/2axwlq0Nck2MciG6mGf4noNkhVZVZ2oSf
         Fvfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=tz1ypAWR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79d6927064dsi10712785a.2.2024.06.28.19.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 92352CE434C;
	Sat, 29 Jun 2024 02:30:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BDA7CC116B1;
	Sat, 29 Jun 2024 02:30:45 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:45 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-expose-kmsan_get_metadata.patch removed from -mm tree
Message-Id: <20240629023045.BDA7CC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=tz1ypAWR;
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


The quilt patch titled
     Subject: kmsan: expose kmsan_get_metadata()
has been removed from the -mm tree.  Its filename was
     kmsan-expose-kmsan_get_metadata.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: expose kmsan_get_metadata()
Date: Fri, 21 Jun 2024 13:34:53 +0200

Each s390 CPU has lowcore pages associated with it.  Each CPU sees its own
lowcore at virtual address 0 through a hardware mechanism called
prefixing.  Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to resolve
metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the arch
code.

Link: https://lkml.kernel.org/r/20240621113706.315500-10-iii@linux.ibm.com
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

 include/linux/kmsan.h      |    9 +++++++++
 mm/kmsan/instrumentation.c |    1 +
 mm/kmsan/kmsan.h           |    1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

--- a/include/linux/kmsan.h~kmsan-expose-kmsan_get_metadata
+++ a/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
--- a/mm/kmsan/instrumentation.c~kmsan-expose-kmsan_get_metadata
+++ a/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
--- a/mm/kmsan/kmsan.h~kmsan-expose-kmsan_get_metadata
+++ a/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023045.BDA7CC116B1%40smtp.kernel.org.
