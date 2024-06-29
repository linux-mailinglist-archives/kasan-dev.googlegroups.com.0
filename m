Return-Path: <kasan-dev+bncBCT4XGV33UIBBYPD7WZQMGQEPUP74IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C26D291CA95
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:58 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-375c390cedesf15392175ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628257; cv=pass;
        d=google.com; s=arc-20160816;
        b=giIjfDQ2d26IMgapROXbwWxPy6inOi+44dakwcZ8R4/zRvTbAvrX7hilHDPbQBwEve
         Arj3dneBR4NZfdEVIRXyBR+MqAsv2X3NIa2Q0YmoMwcNJl04yN5muXGJX+vh7nS3tXQg
         KJu2y9XU5h/hSngA3ldbl5iPXCY+nfXS8TmwFXBKROiuZYese/vFsrPdcqUnWxAy5DrN
         6WCzXO7AvdZgg8LcfT0g6unats9WsbocrEWvBwzvDlIvEoDEHik0tAC0/hgWc6TopFTy
         jpNRcRaxy0u3OIjxatTDLvL1hHPFDtKEXHXpLCt0+w+/4DskjBqyVJBqE1ZiVxZ/P2I6
         FJgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=4HDuCCm6rjCqxKneYpcWqfCsJ0PxmImzx/5yRZlbqb0=;
        fh=TbbNjGSEzCuhQPC4GyKImh0i13WPs+OdN0e2tGEpJqM=;
        b=x81gnmQgY0wo98MxZxcS7GNG6LImbR9nJD54Wg4x/fiACR1wjGkkkpbz7T2P9Y/o3f
         wKV8ckMekDZrLrnUOkObucaUNKOsBmQQZXdfdQr5KE6YWvwwO0oK976bAT2LnsV5ulx9
         /61CyNIY2QB8exQo+EUs4XlDxOUM6PwT+vpBSPwzrxCttnqVsEr7LiT5LT38/JYkW9zh
         TJpfsrDJf0pq1aJ80P5pz55MAxN2B1Lul8coEGbvmCL27WIor0VkrAIU9SYtS39VtpGa
         zF2lpbNWixVTU4/ACvtt5UYmnefT/02WF3J8N0Lok8uKcz/bo63kK1GjKloAvQ1LByvt
         R+xw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AUbnPYHt;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628257; x=1720233057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4HDuCCm6rjCqxKneYpcWqfCsJ0PxmImzx/5yRZlbqb0=;
        b=ShO8jBxGEVC+n2LZ3Oa/vM9GdI/Cu0srLMmxUnkVOJ6BzLe2l6X7EVZlEn9KubYSoy
         bxyOBvMJTLqa07IlwMa9krEUoSh3/0Roama61pg5vLEfzjYbhMNqE4F9vVDNDGvvDu7Z
         yzdmRC4nFUbENeAVqoW2cpqppUCyEposzYU16o8ptPkS5kv0Msf0A37ZqWaze8RLfvv1
         Lu2WZ1VPDOSYb27ILNZhqWmWBiS1I9eSCEwN0UjQ25vV52kRijY3iT81Bv6ejVOd/mxU
         T1NS41Q2nZGm2Px33/OqKDLo/3+mqf1sJRxmjXY3LEXDXRmFLBB4DOxnpq5uRloeiN9o
         j5GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628257; x=1720233057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4HDuCCm6rjCqxKneYpcWqfCsJ0PxmImzx/5yRZlbqb0=;
        b=fLf6z+xWqM1/qslUWWKx5SKjQJCYt01amC2A3rkRYWBZ8ndBu4TBv5Hva3cZvr+58W
         nP4nETAbyZkLZF+0gm9J6hJZjJHYl2nTtX7P0sD/uUA4+fOATLZAB7/K3N0vBMzVaIt2
         EXOIErr/aEVbUsyMLG/XSaYCQdxbQU0lqKKf3LZNOti1Qemx41GqvGZt8fgRyHuKzyXb
         b6tQeeTZab5U7frbPoGbcTEMYsoJOVTH+qmJ/i8SJM0b1CHUvVVKoY9Tr4gweBRf5oRt
         WaZuMVMemwM2NUKypno2mkocBQG8/ibSrI43qMF3ojAXOsbNUi2D8QngItBl5O4w9kzs
         2vQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2WBdZqQjUB0M8YX/RSZaV/LjciNJSK/vCJ0IiGQt2LAGV0FUUZMVbqYFS6Vej7wCyX67B8S9KdKpMQ0W1PoEku9t0oSqlig==
X-Gm-Message-State: AOJu0Yy0IcNoQyuVeg0mi5Fl7uxiQzIPedFCwKJmLYWYvZJM0Sv/ceAu
	FuC9vSbeDQKpiAuMoYwZDyOr7YEcfDEQowMjxyL+tFjH1DfkgPC9
X-Google-Smtp-Source: AGHT+IHPNTriFS6PP90cQJi5sI/6cuRbYPhO/+GfcSw9rjLFO5Lq7RDh9M6014y9jTstIev35b6wVA==
X-Received: by 2002:a05:6e02:138f:b0:376:2a10:ac82 with SMTP id e9e14a558f8ab-3763f693917mr251469405ab.23.1719628257424;
        Fri, 28 Jun 2024 19:30:57 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1806:b0:375:a281:a669 with SMTP id
 e9e14a558f8ab-37af09cbe5als12532915ab.2.-pod-prod-05-us; Fri, 28 Jun 2024
 19:30:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWM8KYksvhYsPhMnBbQrXRTvalJn54iV2Eb9PI5sVlClcB2hlefwFGxAbpVqog6EpqW27+locR0pftWpTJkLNKO9dyqfnl8lHTa6Q==
X-Received: by 2002:a05:6e02:1caf:b0:375:c4a3:8e2 with SMTP id e9e14a558f8ab-3763f6c2727mr233472235ab.29.1719628256465;
        Fri, 28 Jun 2024 19:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628256; cv=none;
        d=google.com; s=arc-20160816;
        b=nP7amGEu68qQ625KYYSkbg5akv7aOc2YWzi47WuNmW7+FbHjf6slNDRxmMcj+4cAhE
         wH9k2RwIPj0gurXFKS69xRj3hjwm9sdiCq/PwGmwVJ7t2YxTG1Tyk1qWe66Abwrhu9ya
         9h97yT4A+kdvG7RHkN+LerSawik1ZGuXb4OsG4kfx0aR2vyCnpi+DQ7FkmFBT0mGf4oN
         EjXNEVh4c43PQPpFnMft/gXKwcND+kweYpRpOWi7V9zXulW0VW6CD74IWmSpdhD2FY0c
         j5WT1BcRFWlRLXNNUVhmfj3PqXyz3746iAH6acvhXQyoH0gzUVCM0xhJ3ZLosl10/6RL
         q+dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=x/6qIXo0oFWvL2P/bbJCGPV3jpCkPDeiMlK40zCIceM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=GLwbLVEnwc2/+bw1e1aQ+fhFdkVq+t1a1eibsBUj8hzvX8c8uz4Vl0wKQ3rq2qYcZk
         l4/+pze9d8QpQ+Gfy44X+EPy5HLWhEHfTNLP+PNod7fqpl9yhbZri9xuZ6eidJUrBA9f
         2NS2WYptUTTBBoeGLXsTgPlJT7iXCvF1C5DXAlW9pPLSfy/SHLxCdG1UEo5WAlHqB1JT
         1qtRdV+DQzOspipBk22WYnUDWzl8a0vjJsNx7AoF4kz2gJGpTnk1a7lJ2JcjYC0wcKTe
         qcYZPNF6DgBbsnquvG7AMWgv7+87qb/TNQa3JHmHXEGTdO5pZpV7rT8tlCrptR1O+wwU
         waCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AUbnPYHt;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-37ad298148dsi1381895ab.2.2024.06.28.19.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 014B8622A1;
	Sat, 29 Jun 2024 02:30:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9DE98C116B1;
	Sat, 29 Jun 2024 02:30:55 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:55 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-expose-kmsan_warn_on.patch removed from -mm tree
Message-Id: <20240629023055.9DE98C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=AUbnPYHt;
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
     Subject: kmsan: expose KMSAN_WARN_ON()
has been removed from the -mm tree.  Its filename was
     kmsan-expose-kmsan_warn_on.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: expose KMSAN_WARN_ON()
Date: Fri, 21 Jun 2024 13:35:00 +0200

KMSAN_WARN_ON() is required for implementing s390-specific KMSAN
functions, but right now it's available only to the KMSAN internal
functions.  Expose it to subsystems through <linux/kmsan.h>.

Link: https://lkml.kernel.org/r/20240621113706.315500-17-iii@linux.ibm.com
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

 include/linux/kmsan.h |   25 +++++++++++++++++++++++++
 mm/kmsan/kmsan.h      |   24 +-----------------------
 2 files changed, 26 insertions(+), 23 deletions(-)

--- a/include/linux/kmsan.h~kmsan-expose-kmsan_warn_on
+++ a/include/linux/kmsan.h
@@ -268,6 +268,29 @@ static inline void *memset_no_sanitize_m
 	return __memset(s, c, n);
 }
 
+extern bool kmsan_enabled;
+extern int panic_on_kmsan;
+
+/*
+ * KMSAN performs a lot of consistency checks that are currently enabled by
+ * default. BUG_ON is normally discouraged in the kernel, unless used for
+ * debugging, but KMSAN itself is a debugging tool, so it makes little sense to
+ * recover if something goes wrong.
+ */
+#define KMSAN_WARN_ON(cond)                                           \
+	({                                                            \
+		const bool __cond = WARN_ON(cond);                    \
+		if (unlikely(__cond)) {                               \
+			WRITE_ONCE(kmsan_enabled, false);             \
+			if (panic_on_kmsan) {                         \
+				/* Can't call panic() here because */ \
+				/* of uaccess checks. */              \
+				BUG();                                \
+			}                                             \
+		}                                                     \
+		__cond;                                               \
+	})
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -380,6 +403,8 @@ static inline void *memset_no_sanitize_m
 	return memset(s, c, n);
 }
 
+#define KMSAN_WARN_ON WARN_ON
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
--- a/mm/kmsan/kmsan.h~kmsan-expose-kmsan_warn_on
+++ a/mm/kmsan/kmsan.h
@@ -11,6 +11,7 @@
 #define __MM_KMSAN_KMSAN_H
 
 #include <linux/irqflags.h>
+#include <linux/kmsan.h>
 #include <linux/mm.h>
 #include <linux/nmi.h>
 #include <linux/pgtable.h>
@@ -34,29 +35,6 @@
 #define KMSAN_META_SHADOW (false)
 #define KMSAN_META_ORIGIN (true)
 
-extern bool kmsan_enabled;
-extern int panic_on_kmsan;
-
-/*
- * KMSAN performs a lot of consistency checks that are currently enabled by
- * default. BUG_ON is normally discouraged in the kernel, unless used for
- * debugging, but KMSAN itself is a debugging tool, so it makes little sense to
- * recover if something goes wrong.
- */
-#define KMSAN_WARN_ON(cond)                                           \
-	({                                                            \
-		const bool __cond = WARN_ON(cond);                    \
-		if (unlikely(__cond)) {                               \
-			WRITE_ONCE(kmsan_enabled, false);             \
-			if (panic_on_kmsan) {                         \
-				/* Can't call panic() here because */ \
-				/* of uaccess checks. */              \
-				BUG();                                \
-			}                                             \
-		}                                                     \
-		__cond;                                               \
-	})
-
 /*
  * A pair of metadata pointers to be returned by the instrumentation functions.
  */
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023055.9DE98C116B1%40smtp.kernel.org.
