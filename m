Return-Path: <kasan-dev+bncBCT4XGV33UIBBW7D7WZQMGQEQRHAKBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9910491CA8F
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:52 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3761e678b99sf93285ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628251; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2Jffv6Ra/Ahb38GpsUutx4loeV+VLyEZ7IcSWwwOuYG53gnJbLnQxXy3zhLDKmWr+
         q6tis9+VFFvqyXmyDuursDex1EgxnDpbYQs5qkTGau14o1kPKFFXWJk+qqHIwMiOVxNE
         ayPNSEKEPFDS3TECHec5M0Uf6J8Tei/LiNKy7TQ4llnIE6RNR8K/WTKUmZGYRmSV7/M+
         F2fFQ8hK3XTF6KN8Tl2IQMACSh+tFoihdQMH41n5jx/GL9huJeEeL95cy4E59qW1w3P9
         WVMI9eFRt/36QPfSG+C6EKPg1z5erkZBr6zcheOm81/J/dF2ogCK4s1V/j15hp3l73qJ
         4CPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=XffnFJof0w7KgUgBlhm4opWIPDFje6xVJcQ6hR6qm4c=;
        fh=SQI4Hkgn452LNIPYSL2E/LNMQForWsz1/3SWwXde228=;
        b=UlVCYugzCCxhIXGV8Cph1WjP4FPaKsEJ6o0IfewFrHQLrsWMDBPRErJ4cNmR6kuR3l
         IuydSiGQDgXPr+DHoSbhUfg/yPLdnYpcOITVBr3vxqEN5c50vQHjXsQkjj+V8k3Vh0Ci
         IF9YTP0tR//ysWHKNIDaeTafjJmAWKXusqaB4NbeECLqyN1BFlNYYPYSUkYFG2zuqci0
         mV/sM5dDkQK44+zDPrb19kPAo0zjoJ6ssI57FgVDMisYeeGfJW0iSi3q1NJX+DK7HoLv
         d9fyiAnW3/wPZW6rNzQS4CG3fAIcWvdYp9n4YxVu4Uh7NzbpNlh0WwC2vct7h97HIaXY
         Cojw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Bi0l3oY3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628251; x=1720233051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XffnFJof0w7KgUgBlhm4opWIPDFje6xVJcQ6hR6qm4c=;
        b=DZlutK2x5yR68d3wlx+/Ikv5czebe/qi4Tup7I7IsNT4e7KLDJwdOXhxmw2feeW1LP
         LbJ4JHuTgYGhHOakg74GE4D3zNRq5hgJNFYlPY8IaXRdFH7bErKWjv4XMak3NF48UWop
         aF1tlVTB3P5S1bvM13LAX9fnk9Mx+ebAQbiCR6+kbW5BNrDPeXY+Bhmt6HxW1rnFtZr6
         T4h9wc0KcNxAqBWVNU2JVpFwm8iCQXMSsasNOnVSS79FYBCH4SSbm+9v1Wt18f1rHYGJ
         yyPtOncpiu8N/PB5YWPbXQcWQvA6ywKMeHNCC11/b9M2A2vLF0NpInt36mK8Bphgs1v2
         VwXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628251; x=1720233051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XffnFJof0w7KgUgBlhm4opWIPDFje6xVJcQ6hR6qm4c=;
        b=oQYp74bmbTMmIN6bSu8pVPpMcOwCtRVu5FaRMRzXhbMEyW7IrES0JdGdkzXEzS3Ru3
         AQ8zt904mgqJ1hTVPlNYC4wfeyNTB32JhOq0fqAeRgewnbzWlECawU4f5apOl+KsOjW1
         l4qWidiDJRnUtB1PQc5+7Tum964OTBlkGa11uDXx/XeSSFCcHP3OLVk/oBdTxbc2/BVs
         AeIurGo0Lbi1F8f3xuwui8/81Ng9tpJzM3KktzBBgoQwwTwCgT7bzbH0CJitmXQvDIg6
         sLMz3Tb56PLKJB1qxtFJUvTryynEw1UapVYUU/C9LsCmXEh0HbtL80n20ak8IE6InbIe
         Xk3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2PH5vrE6doi1ryYfSjJkGpbESQ9bITXHtHezAMaedIIIvG0Aj1KJkpAynzX/3nZeqruL5ud2NzgHeTeMHQVxTc++u1/aQyg==
X-Gm-Message-State: AOJu0Yzj68fIsKgdkjorvWoHT1QVWDI7RwluZDTg0YWEPFt4PtbQv5li
	an3pI1PQyZGY5m3o1ElV9Q7+C22XTXtVMW1xyOiMJlicUmJ3XR7O
X-Google-Smtp-Source: AGHT+IEBNCVASo/nL5YdKDke0GqTJr9CQHXAieQUEofCPhJR48yjcz/mFu4QEzECks43MpDfnjldKg==
X-Received: by 2002:a05:6e02:1a2f:b0:376:3968:f6c9 with SMTP id e9e14a558f8ab-37c3eface27mr1306245ab.20.1719628251378;
        Fri, 28 Jun 2024 19:30:51 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ad8c:0:b0:5c4:ee1:8321 with SMTP id 006d021491bc7-5c42006fefels896876eaf.1.-pod-prod-09-us;
 Fri, 28 Jun 2024 19:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLd2vbOX/blNNJpHvEpYEHCz9FHCo7faBjJ4HECyf1DK9FUkowWEHfJM3gHwtC4ZFowGdWPfY4cZ9F91sz/o9zctgcTDwv+99jNQ==
X-Received: by 2002:a9d:6347:0:b0:701:fd07:4d7f with SMTP id 46e09a7af769-701fd074e84mr2959996a34.25.1719628250555;
        Fri, 28 Jun 2024 19:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628250; cv=none;
        d=google.com; s=arc-20160816;
        b=lsJmOfzOwf8GaYnvsEPC8NmOC9yXXyhM4wAkVqlalGhDWOcrC/hmKiwhQg0rq3eE4t
         3rzkYjdJsYRKOhPSnRsNZhgx3I90otci6Lz2ptodlJxl/bMYwFyah/y+Iz5pFy7E/dFC
         p1Uzq3zfTXpji2XmMc+h5ZGmOSk3hJfVys6hEuDo9lr5ntg201aZUZefMRmiF9SXQ9hZ
         dEGIofDBik2OTM2Cqf3rZitcz2lqIQDiihygxvHV5jq9g/3/+GUoh2MfJ3MDKglgMJ+b
         Xb/TqxZZBs2H6bJezqNEMMXQzOEwRYhMzkyESmUdM+q/fBsIVfGjcefwfuZ4h944g0Um
         Hgrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=968YoBZ2oVBgxjbm2VA8b2QMcQCwyg5k5oWZDme8+xM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=hd6/7XRXWgTpXtPDL4ddj6r6A6RBScBt0t6C7hB+DEuVPtYjpFMgGxqI7aTl4Ojn3L
         F/Zu7vbnDBae3MtuKdBkbIYOc733RfOJoTwHbWBDbiKhbPPOF66tkWtFHUvY9SliWslS
         quaC2P0KnF0y2duGUwMcDIOT+VAUY7gFUPcS2Wdz1IAdgW1j1a8Qv7d5xPiou+uBY6yB
         tIqYJ3ek7x0ECuZo0kSgMxFgDmNAsyJJ4yRAeWaneJUYjBKi1zfjt8alNhPrNuIy0op7
         2Ze+ex0X+cmKH+lI3/5JxWTj/qE2Kasz/zdWIIKy8Vkt2RtnJZ2voIZvp/tAeLbRP99G
         8gig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Bi0l3oY3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7b7ac45si123251a34.4.2024.06.28.19.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 57319622C0;
	Sat, 29 Jun 2024 02:30:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F049BC116B1;
	Sat, 29 Jun 2024 02:30:49 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:49 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-introduce-memset_no_sanitize_memory.patch removed from -mm tree
Message-Id: <20240629023049.F049BC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Bi0l3oY3;
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


The quilt patch titled
     Subject: kmsan: introduce memset_no_sanitize_memory()
has been removed from the -mm tree.  Its filename was
     kmsan-introduce-memset_no_sanitize_memory.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: introduce memset_no_sanitize_memory()
Date: Fri, 21 Jun 2024 13:34:56 +0200

Add a wrapper for memset() that prevents unpoisoning.  This is useful for
filling memory allocator redzones.

Link: https://lkml.kernel.org/r/20240621113706.315500-13-iii@linux.ibm.com
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

 include/linux/kmsan.h |   18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

--- a/include/linux/kmsan.h~kmsan-introduce-memset_no_sanitize_memory
+++ a/include/linux/kmsan.h
@@ -255,6 +255,19 @@ void kmsan_enable_current(void);
  */
 void kmsan_disable_current(void);
 
+/**
+ * memset_no_sanitize_memory(): Fill memory without KMSAN instrumentation.
+ * @s: address of kernel memory to fill.
+ * @c: constant byte to fill the memory with.
+ * @n: number of bytes to fill.
+ *
+ * This is like memset(), but without KMSAN instrumentation.
+ */
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return __memset(s, c, n);
+}
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -362,6 +375,11 @@ static inline void kmsan_disable_current
 {
 }
 
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023049.F049BC116B1%40smtp.kernel.org.
