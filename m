Return-Path: <kasan-dev+bncBCT4XGV33UIBBV7D7WZQMGQE6RNPCOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8003A91CA8D
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:48 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e02bb41247dsf2030269276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628247; cv=pass;
        d=google.com; s=arc-20160816;
        b=onlBwqoQCQOTmlpEyD5nY2Unja7GegfSuj6ZjOtdmLYPMHDWHVr4Zd+K4vXinB2ahp
         lGuyUfklFGPXtnQFDYJ0h5tmdQqK1sB9VnxKuSZlVIkQE0dxTzTpNuFm2OWMtKKMfcR7
         BROKCosZaOcgrM/PILWZCiPiXTMI/YKjKoGJqT3yc3akH5y/8ketH80kndacFJj3nlM/
         b5Qf0nllcj/KWT5jikyruZXueJwHCq9dlHWBJ31cl9amHskU5DkapVx9odsx6Zpl9n1O
         NUeHV5D+d7gZyGxjvOUZILWwW2SEwcsvloThwwfvh3t89Q6SuSzmW0+xmr+ZOlZUxvLX
         We5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=mTZ0yzxvRGDEzsPUp5xpRk3nzIPfwMNg79VYMiKFvIc=;
        fh=yLlW03VsplYLgb7AzXNJUnYUksWPjHvHOtWaq1v1R8c=;
        b=S3cKO76nuN5zhRgpt3od/MA2rSPMU/utfMtS5fB9SCwkoUTWJcCLrQZUTOXKjve7kk
         O0LKrHweuy2kakYlpNAqDe3oO9OPBZvbpWuk1aLa7uylmTetpuXO66R8tU0gBj3Hz/3b
         qDkJoWR3mJFbNNDYpkFIKhK0qJBIonazxISzr3T5yErCUvO7p91h4vk7H0D78dNxWKvp
         Rno/YuPe68rB2Su+NWABWaTSheCcSAyPXRtryivmCiBHdj5ErDFPBdqvv8eiHPUGQuhj
         dwD4y3Zywz6xuY4kRByEKUJ01FlQen9iwP+Ep04s9DSiIDlpylthfKM6Ucj462WKj2AG
         qbOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JP4tuVgk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628247; x=1720233047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mTZ0yzxvRGDEzsPUp5xpRk3nzIPfwMNg79VYMiKFvIc=;
        b=pG8VeCldU8s13h0LTOCF6JwhGwj8JRQ0mxMWX1+q1/Oky82xCEcaYKDg+e6jLgAOtn
         LBoopDVSn879Gu60NhQI+CpGPLXa9RiUBa/GJ4yuQAGDvi2A3izVA4oQ1FdX2EJInEy+
         m57vtnKX/ghXM+A/1zAeIQMOFVLEgiPdrQW6L1o2aQmtmModkiA90Yj9rbKtGiSoLlT/
         uVcQkcx+/uCh20uRV1xnEqo3kc6Xn39vfiuvYs8wm5rsUN2gPjIFLlvX35kaVATuba14
         JCoZet/BvIEly6u9LlbrULCxOBgPVCQb0GlLOwxhDnezHRZowfQbUfVTZ+HjjzBmBP1H
         3qAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628247; x=1720233047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mTZ0yzxvRGDEzsPUp5xpRk3nzIPfwMNg79VYMiKFvIc=;
        b=JEvPIn8id6fOBYsoUalyK7P3r9PngBnRks4f+fZvfTeO7KLIA30Hr6gfjDn5e2exdd
         ksM6LbrB1chAU99ShvWQ6dZF1em+ooH8I4k6LodHnjCnq0gLlqJMaYNbihcv59K/hWz3
         bxdgxC8tbHFAt1FH5tmaXNTYosycaTh6kfqaQtBdriYenRelIOePIkAOWg6UQLrPeICy
         pmWLn2IpL8bmPBVBjcYDsPcSqv9CJseNyunJsPk/jrBiTtH7aRFwnUwGLj17/O4Ii3AG
         qg678bZizK3UZxnZs4j67nhjH5UnbbSP5NuY5BQ29wMBZU8GsrQ/pXnDG8wN1cs1hkXB
         DLzA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDNYYiA+/Z42An/asmfWYyhzAvgE6k6nDZNFcotYB2EkPsLfU8538I+KPHhdce5/mAMJxu1+IGuGs2wpvZHNil3NJYChB5yg==
X-Gm-Message-State: AOJu0YxR9BJUEDNY1QwXbEXelM03wdwzxuS1GAhCkZHcBgZ6Gm+Vn1wc
	/UAUlu9qcplQxGV9FCKj+W/2eF9XZxIjKFcN1Vs0NiPQZlgFGsDF
X-Google-Smtp-Source: AGHT+IHVzRcf5uHO9tFa52lYITw+tcnBpDuwct+gMP7ELs++b8e4eIOVwKd+KcPVap4Iin9pFQB68A==
X-Received: by 2002:a25:d0c7:0:b0:e03:5949:cb51 with SMTP id 3f1490d57ef6-e035949cc70mr4277640276.50.1719628247371;
        Fri, 28 Jun 2024 19:30:47 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1005:b0:e03:3d23:393f with SMTP id
 3f1490d57ef6-e03562690f9ls2037150276.1.-pod-prod-03-us; Fri, 28 Jun 2024
 19:30:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPDCB60OD1P+SyxUya3QzjgAVSwFn7NupJ3Kp8KRl3YpFVZ6bPdyGYM1HVbhHkcZI39SUbYsvA8YTpwZj5b9/tKNJmbNJk/K8OxA==
X-Received: by 2002:a81:9e4e:0:b0:62c:eb81:29ec with SMTP id 00721157ae682-64c7350de1fmr40417b3.33.1719628245041;
        Fri, 28 Jun 2024 19:30:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628245; cv=none;
        d=google.com; s=arc-20160816;
        b=H5jkJuuKlZ7x8HMmjvxG3JBXnYBhRcfPpvMlzSk0fufvAl/KKI/jBFEwfy7PqVqgSR
         CmegHvjq5HmacTid4SYsSIO1PciKg3wUE8drahb3iKFvltn0KlWHUPkYI2ISKVAetxP7
         ZgYcSpkjbP1ysj43/kBj5uTaUWcV/3xUKIwpLpIdeSzFqc/sqBOVKn6QqUUo144cxbpS
         5xJUhO6/7egFjkfttVSWFm9kING3dcWrc2smRw6lUJxHUFlh8BOPEEvUt6a3zdY4ILXi
         ToJAVXMUK+OxkndS54fwurWeTcnzHTUIJNuPOAx+GfK1rcluSYYQJEyrQjArE/Z79z22
         mMxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=+6XIV74QmiwQFGnUW8XgL5jXUPhW0NmXdLVADT6+ZO0=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=mZupFkFzv8CnxilDMPY8wlV2RsjQ6HhGW9QqFIIZBw2D2La4a9ZfiEqFDmsHu2m/be
         jmfggCjNayO5u4nBZ9hoRfZCvNxJjolQinZJAa4POYn7aOf8YEauXYRCxZXGWmECSIYT
         9Dod7sa++1xZBwQutONhuaXqw5qJ/UNBc2/aheNo0eRV6EMD8yR3jXfuTqPdZOv2zfYe
         C3yUSeUztzAD503D09ZeQzBAzUKBkAoXRM9jPpdgh21Bd99jxkJvCGzjdeic3mqNY+uu
         zmRKfECIPTSU8neVcBKnkzsmk85X4p9X61uxelm8RzwEH3rsH8XlACjJZJakhkk2fMIQ
         RTZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JP4tuVgk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-64a9c02c8b5si1324817b3.4.2024.06.28.19.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B639E622C6;
	Sat, 29 Jun 2024 02:30:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5CFA0C116B1;
	Sat, 29 Jun 2024 02:30:44 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:43 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-remove-an-x86-specific-include-from-kmsanh.patch removed from -mm tree
Message-Id: <20240629023044.5CFA0C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=JP4tuVgk;
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


The quilt patch titled
     Subject: kmsan: remove an x86-specific #include from kmsan.h
has been removed from the -mm tree.  Its filename was
     kmsan-remove-an-x86-specific-include-from-kmsanh.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: remove an x86-specific #include from kmsan.h
Date: Fri, 21 Jun 2024 13:34:52 +0200

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of consistency
with other KMSAN code.

Link: https://lkml.kernel.org/r/20240621113706.315500-9-iii@linux.ibm.com
Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
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

 mm/kmsan/kmsan.h |    8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

--- a/mm/kmsan/kmsan.h~kmsan-remove-an-x86-specific-include-from-kmsanh
+++ a/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023044.5CFA0C116B1%40smtp.kernel.org.
