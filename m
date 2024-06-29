Return-Path: <kasan-dev+bncBCT4XGV33UIBB4HD7WZQMGQEJ3ARETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A41F991CA9E
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:13 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1faa9455c8dsf386275ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628272; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUcetnA8flCee9fnWpoUVUf4+ljrYg55VuPb985FWIsFNqHO20SrBXE/TBqPlCSCUr
         YC8brTgpc4HHgtMH+cCU9FVmqY/B5UsvtLsbQOOAJNNqgo+alCR1rqol7LyJVLl8hkMk
         00qqPtEbh0ZskdNDrKScOks7GbYoeiN6gJoGGlrojBH010FQ/van4HL3wcSGPAMlRJwC
         kZqYBevIpYHk1TOYcFArB55C1e9fbB4KCQnzkjdwYtWso14dgShgAem/rVtiWWlfM1UI
         R5V33M1DhR0yrgpWYnavszmlgZYABXTuWwr+z6vKEzG5qqvBEdOc6HL4ajKUnlv8EflK
         koPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=xPyEnkuEiWFf5jC4VsmAi4cjBbBwCZRhaIHFOD5tZPw=;
        fh=hDzUIH05YEaLDRMYSlXC1BsPp8M2C9hpkgh9hbEjO70=;
        b=ro/oaK+91LuEHEjWPgGy7WERVI4DtTsiHFCiibPdBs9s2q0Wk75s+xJNfLEMO+DpuP
         MXzyt8w3zIyGR+xLAz4kTcqcmV9PZpOyc9yGNbzEO9eE9DIEqFj0a2rJ8KEY5awLdzSj
         fV69YP5bzmzwjVP3PjPEeMj5Cx1EdLS6ayQ3vEtWVMArp0jYqlM1ga+yL7gLelOftL61
         +uRT86POOpItN86sOL2H1AUAPLLhj4JMDdIKddTslh9Sm1nejrQ38/T6MHJZWqHtnGl6
         rf10Bm4dkwH5pKxErkS3E9qTE6beLNfYEpxClPAeLvL9q4hzZ9HGXrBmrHBalf1PZmUT
         q1Gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Gb1UylUv;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628272; x=1720233072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xPyEnkuEiWFf5jC4VsmAi4cjBbBwCZRhaIHFOD5tZPw=;
        b=Ryr1Nk3UHK5BkVpb6hNJXa/B2hZnEZe3TDYOqXSbunggQRJBY7IRa5nP7ztWr48oum
         3WSKg4dgsoK1buue+DF2bX8LO34N4AECxhQrGinCvjAT1OrqW2NhuQCfaL0J5w/I172f
         S0HVng+y2pCKVTMkATLHwes6XSFl6RXOhqpAOLT4T7JHUq7y7sD8lvRthIWbmMblyxCh
         ZmHkg72eMp9Fv79TZvq9OIe82TvwGR6midE9JYWu9RXewQCXGygEiF7WLSXnOfan0pCL
         Z4d9J08iUe01Uce3Lc0HU87oOQgZ/wLx7YRjl4wYQuoRd3Z0WvoWzJdlBwHoyRUUyDhg
         T45g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628272; x=1720233072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xPyEnkuEiWFf5jC4VsmAi4cjBbBwCZRhaIHFOD5tZPw=;
        b=U2as7ppVD7+PoMvkMHV+bkDamv1nT8yYZzHwbOXzZLxLZ/leNsCFr7B3HOt0Ngup5Z
         6c/GWRgeRfi+kTe47adYVJMGnqVZlRXTkI2asA/meVGucdC0nSwEYWyxj2c9eE6h1aL/
         wdgreotadWGX/E+xgNoXJMJ86uuOD5bL9CzapwFd3zORqgwiqiiDhfDiEAh28zUyzMKl
         gD9I+mqnyQynl7lpSNS6U8ycF1vELprKV7MhaQWehNUNKNAwFI+Hwr3Do+eJi9hV98z6
         CG8lr9BKy1TAQN8VKBy/0uS5kwFLsjoNvuqR8dmUxpvY6E/Lzad859n2kvAYfPgZ6PJT
         SjSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWxNpjSNHJCWv9qvWDc4cRBV1NbSBdoCRuZ6SbCWyfoeqZ31omO2DM4Um/z2gstirHbZ/XF6TzHmTbhAI1GHvgEd7BsOF9Tw==
X-Gm-Message-State: AOJu0Yw1ggUy6Uo5i7aglE/mTEne6wOgvAqmtou4FGvXRAK59V1AUkBR
	vJI0zxqhrPSldsGA4R/vGCnzLv4rjAv7VzNZuFDZ+nviydnlGxGe
X-Google-Smtp-Source: AGHT+IFz2k8H1jAkqDiZSZ65zYnJVw4k5vhPjx5Kf1XhRTboc46ZLMDrPxX74EOy5OFrLq7U7Y51KQ==
X-Received: by 2002:a17:902:7845:b0:1f6:3891:7950 with SMTP id d9443c01a7336-1fad8e7d2c1mr708245ad.1.1719628272242;
        Fri, 28 Jun 2024 19:31:12 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:928b:b0:706:8a63:402d with SMTP id
 d2e1a72fcca58-708301f0bf2ls757507b3a.0.-pod-prod-08-us; Fri, 28 Jun 2024
 19:31:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJh85r8REJFoej6858rBEM23yz1DH3gDE7J1i7+fI1Y2M565LJUbVzq4zsjJrpWxtbTl7tnH3BGdLGXXMFpbwSNq/08+Fxw1KcLw==
X-Received: by 2002:aa7:888f:0:b0:706:381e:318c with SMTP id d2e1a72fcca58-70aaad2a819mr29806b3a.7.1719628270912;
        Fri, 28 Jun 2024 19:31:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628270; cv=none;
        d=google.com; s=arc-20160816;
        b=DTfIlU79aPrqFzlKLG5+m95nGHocxRVyGQeWEWF7pnGl3gm355a0+5wEcZzl/UuCGT
         2Hi4WnUe9Z4PN10jvECPO6LjwEbeLS1Erj4K3riZswbFsNlHQyodKdlDaReb/YO0GJtP
         QixMOzgNNgBz0SW8mipOdTaqgGqFPG53vdi/a/oLBB3bXmamlOfzZhdZW79/AXm/pCFp
         5tzFK0tpJe/UHWsYMLKJiaxXje99Zwk/vrXMtHKZvxZ11wolq//kXW037URDqzsNmRiM
         vi2YZgnde6rXxTxECdUCrbwKkZPui/Km+qQV2r7JonRFMXFnaKPBHMkvjK6qFxzsjbKq
         r9kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=/43Av0yxpxRWOIUJHf2xlaUcbnxKpdtj8zeUYBRSVCk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=JnCeB+QJRb8hVuQooRokoezgi686b7432Gp5uNceeZ5b2v4Wy3GJUl0S191Y2rhkaI
         AR+754hNBouPQK4k04/XTHcKGTrWtqb9TDNe/c3WKnnHoj+dTC52qf51HznErErEGXG8
         fZ4k+tXcAITbSHQPKXmknZoITstH30/CtW7+iLM1WNOq57Y8YM92R2pArPZJCmWBMzj0
         O6a9lri2xIF/5JssIayVN9f1WtCY4e/Rg7cQHIf16w4QZYI3+8adVg8I1MzHA/x5OuQW
         KL4p34gVfXBufWKVRvSmcFZNLt2MOn+FvVaTQ1FHdmV5Kq7SALwlcI/HCjjLJcV/6f/N
         b/kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Gb1UylUv;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-708011fe313si128728b3a.1.2024.06.28.19.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 04002CE3CDA;
	Sat, 29 Jun 2024 02:31:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30BEAC116B1;
	Sat, 29 Jun 2024 02:31:08 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:07 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-checksum-add-a-kmsan-check.patch removed from -mm tree
Message-Id: <20240629023108.30BEAC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Gb1UylUv;
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


The quilt patch titled
     Subject: s390/checksum: add a KMSAN check
has been removed from the -mm tree.  Its filename was
     s390-checksum-add-a-kmsan-check.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/checksum: add a KMSAN check
Date: Fri, 21 Jun 2024 13:35:09 +0200

Add a KMSAN check to the CKSM inline assembly, similar to how it was done
for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Link: https://lkml.kernel.org/r/20240621113706.315500-26-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/include/asm/checksum.h |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/include/asm/checksum.h~s390-checksum-add-a-kmsan-check
+++ a/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/instrumented.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 static inline __wsum cksm(const void *buff, int len, __wsum sum)
@@ -23,6 +24,7 @@ static inline __wsum cksm(const void *bu
 	};
 
 	instrument_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile("\n"
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023108.30BEAC116B1%40smtp.kernel.org.
