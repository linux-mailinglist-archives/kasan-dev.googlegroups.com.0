Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI5A2LUAKGQENEP4WSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A77F57F80
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:09 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id 64sf244228uam.22
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628708; cv=pass;
        d=google.com; s=arc-20160816;
        b=wNnJj78lkcSvARCzF9W48wdkuXI6/+Uf5kHHp57LQvJUzOSqAih0YwNQwEyUcAWH31
         hTZJGpzP7APhnq5CIpW5ZcgGBHifqBSM9At6izBgpUUAGMQn99XzYTyFgGk+2HzxwIPB
         X3VEKeB0FwpPI+GjkRu8G0ZlZfNtEFOERvzh+CeopY0q8mnWsCGBwN/R8ovooFh5RqQn
         iHpCEXVBf71ehllPWM9Sqf9lIp3djTHymVs+LqGIevZDmA6nAur6uiUxqN1af1dlOnV6
         MQ4ysHNfNRXGzv7EInUKLqEPuwn8TeBazS+6Kx7hpmfSZbmIm13WQjrl0E0ywIYpLFAA
         grjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=JYEcOfoBw7/8eCnT0BvTuger08JiR9du0AHCYb3ZiWw=;
        b=dvGLbCy0pf56V6I7WF46PqRWDvMjBbQBjZtbii7+27kbgUesZc9ZO+wYZO+Ofnc+2+
         w9CHGyHPW2Gwe2a4IS8sjJd9cBZqEi0iEFKl90eB5zKlmoDqYLa3yQTApDFnb+zu9pFp
         6VUreMkRhU9A3iT7Ezg+RoFofubhjjqlOG34UNa2u16vUakBRSvquPPbyyZVs4voRS5F
         G4T/Pwz0Sz3QLQBNBGDyzCLWm2L4PPyVo2BOoC83WF12b8FsCCTY/Fam2dP/2mTnE36O
         3W0/Y9C5knXAt2ur/riBIrT3bvekGtc1BtBhdzzTsoLSCXQzGa4ZiBQKjoEoDjBrRV/H
         jGdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dTAP9e+5;
       spf=pass (google.com: domain of 3i5auxqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=3I5AUXQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JYEcOfoBw7/8eCnT0BvTuger08JiR9du0AHCYb3ZiWw=;
        b=XB9Z5UisDrpn/BTkrkQSPuZwOYF/bNtWVHtKELC0dksRnIis/t+7rrCPKr5rmKDe+H
         KUGCl4kwrLCvJ8pw9Ov0aEY6QZ2p2RiIthatRvZoFLQfEnv8HbylHN+b/aWCkDyPuKAD
         zbS2XIAxjWtmfg6S49l1EZxusyYGTomwkAShvklOUfTqFRPc+yCdFpuyH7vx9csPNZnx
         8KE5mRGHYt92AgpuwtgtnENsMkEML4PUs7eFoXrsi9RSJtH4gfnxDg8ctZAvjwv8C7Wk
         FE3oemtm+kirfUJCN4X8yzKaXJPq4UBY/W3Wb69BUzK/5431YX+lLzYJOU/nvyGFN2NK
         Iu7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JYEcOfoBw7/8eCnT0BvTuger08JiR9du0AHCYb3ZiWw=;
        b=kY/K4nsdloAMShiwPqONRgGSJu/mbDP1W0YwZXCsy6IRHk+tXAuqz6BvJtFA10rWOL
         RPEAQixncnYhK3zV4HcPwvLKBKZEnPvU27Q1L0Og6l812tdOk6zOz/N4aFvB4Ze+kNl0
         9hv+Pa/gs3t3KocruBosPCAgbVfjgihWfetd3oQ9GFEX1UwsCesca84XLIqhWUWbuVS3
         j7+mSzgDlbzazaer3kgzOVyxIeKObKvTbjZgghDJwPv3Zycjhdru+/0tJUXDGrucerBe
         3xB9v8MyEfeUD/LrIt9dgwUN+4yhf5J5oN5FpHwSftaFkxbd3fEvjJUEdD5R0EPVcDu9
         6teA==
X-Gm-Message-State: APjAAAVc84om6mHy1vIJ9FTHDDunfh9SaJ3oPQuLZZVCMiwcpkxfUl2k
	jmGal6+3xdnc/8IX9zzlAOU=
X-Google-Smtp-Source: APXvYqy2U8H4j0ia4ZFla5oN7R2Tz+uu0EwkteKpCdppR2h4TtrZ96nyxNPEgrV9QCiOBzqTP6xcAg==
X-Received: by 2002:a67:e886:: with SMTP id x6mr2095669vsn.216.1561628707821;
        Thu, 27 Jun 2019 02:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8002:: with SMTP id b2ls489676vsd.13.gmail; Thu, 27 Jun
 2019 02:45:07 -0700 (PDT)
X-Received: by 2002:a67:1143:: with SMTP id 64mr2078324vsr.133.1561628707533;
        Thu, 27 Jun 2019 02:45:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628707; cv=none;
        d=google.com; s=arc-20160816;
        b=Xo3Wh4sEnBGqyUL2zMAz5VpMxOowa0bGVhjBpl1NrW+FsBSSUwSoi8dNCgaE4Kl/Lo
         T8z9kOZlKgl8SCi//guUWOsHyUWQdEMNhikxBJjBhU8eB8ePIhwLjvu5WaVirajas1jJ
         nEypltiwV9pNlfNz93MRDTVzlYs8VJO+K/7kf5IrWrEYEFwoqJiEQ2LFNPSoZwPfsBRR
         MeqMf0VmivGIaCuD12zPLLeCbdmTBsVLo5SD+MgSDyoqYN6pNbQH+fURT2BF3UxVBg2g
         /D0K5AKmX2wj2tAktO7XLk971kRuKd2Kx7APyalqLrZaDAOorV52FV7T7R+v9Kfi6ybv
         xUdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=M/VKnz1BZ+rvrIeSdLI9RxXAlLGL/xX/aFhsrhXW1SI=;
        b=B82dsaSDWwjlQ7cUasp7mBvDOL2GvDvgz8E8BPt75Xjp42iRNVT+aGrT772Oy6Z5jT
         Z6UN/NPKzSKar3DVfLXtP2jzLB0yCU2KVyIC/DfAgSXE4pCN/pUK6f2/LhhvX/bqG3H1
         fthJBTnDBH4LeU0dyllL+r8wCp4uC/F1UAjoGgXHAD5h9BLXSZbmoZNFaA34gOj9tNDb
         yC4hTtVCmh4gIq/s+9SGJQMZOs8NLpeEB1JWLcmiFVEp5mvDYYlHMvPx0CMgLpESBwtj
         sOEjZXma9tJ0C5wczI40HfZFdk38f5dWSGypK3z8y1zRH1KsTjQFO3OE2gs1LYGp94N6
         ObnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dTAP9e+5;
       spf=pass (google.com: domain of 3i5auxqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=3I5AUXQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc49.google.com (mail-yw1-xc49.google.com. [2607:f8b0:4864:20::c49])
        by gmr-mx.google.com with ESMTPS id 63si114603vkn.0.2019.06.27.02.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i5auxqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) client-ip=2607:f8b0:4864:20::c49;
Received: by mail-yw1-xc49.google.com with SMTP id i136so2318868ywe.23
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:07 -0700 (PDT)
X-Received: by 2002:a25:c4c4:: with SMTP id u187mr1928035ybf.185.1561628707099;
 Thu, 27 Jun 2019 02:45:07 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:41 +0200
In-Reply-To: <20190627094445.216365-1-elver@google.com>
Message-Id: <20190627094445.216365-2-elver@google.com>
Mime-Version: 1.0
References: <20190627094445.216365-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 1/5] mm/kasan: Introduce __kasan_check_{read,write}
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dTAP9e+5;       spf=pass
 (google.com: domain of 3i5auxqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=3I5AUXQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This introduces __kasan_check_{read,write}. __kasan_check functions may
be used from anywhere, even compilation units that disable
instrumentation selectively.

This change eliminates the need for the __KASAN_INTERNAL definition.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
v3:
* Fix Formatting and split introduction of __kasan_check_* and returning
  bool into 2 patches.
---
 include/linux/kasan-checks.h | 31 ++++++++++++++++++++++++++++---
 mm/kasan/common.c            | 10 ++++------
 2 files changed, 32 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index a61dc075e2ce..19a0175d2452 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -2,9 +2,34 @@
 #ifndef _LINUX_KASAN_CHECKS_H
 #define _LINUX_KASAN_CHECKS_H
 
-#if defined(__SANITIZE_ADDRESS__) || defined(__KASAN_INTERNAL)
-void kasan_check_read(const volatile void *p, unsigned int size);
-void kasan_check_write(const volatile void *p, unsigned int size);
+/*
+ * __kasan_check_*: Always available when KASAN is enabled. This may be used
+ * even in compilation units that selectively disable KASAN, but must use KASAN
+ * to validate access to an address.   Never use these in header files!
+ */
+#ifdef CONFIG_KASAN
+void __kasan_check_read(const volatile void *p, unsigned int size);
+void __kasan_check_write(const volatile void *p, unsigned int size);
+#else
+static inline void __kasan_check_read(const volatile void *p, unsigned int size)
+{ }
+static inline void __kasan_check_write(const volatile void *p, unsigned int size)
+{ }
+#endif
+
+/*
+ * kasan_check_*: Only available when the particular compilation unit has KASAN
+ * instrumentation enabled. May be used in header files.
+ */
+#ifdef __SANITIZE_ADDRESS__
+static inline void kasan_check_read(const volatile void *p, unsigned int size)
+{
+	__kasan_check_read(p, size);
+}
+static inline void kasan_check_write(const volatile void *p, unsigned int size)
+{
+	__kasan_check_read(p, size);
+}
 #else
 static inline void kasan_check_read(const volatile void *p, unsigned int size)
 { }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 242fdc01aaa9..6bada42cc152 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -14,8 +14,6 @@
  *
  */
 
-#define __KASAN_INTERNAL
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
@@ -89,17 +87,17 @@ void kasan_disable_current(void)
 	current->kasan_depth--;
 }
 
-void kasan_check_read(const volatile void *p, unsigned int size)
+void __kasan_check_read(const volatile void *p, unsigned int size)
 {
 	check_memory_region((unsigned long)p, size, false, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_read);
+EXPORT_SYMBOL(__kasan_check_read);
 
-void kasan_check_write(const volatile void *p, unsigned int size)
+void __kasan_check_write(const volatile void *p, unsigned int size)
 {
 	check_memory_region((unsigned long)p, size, true, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_write);
+EXPORT_SYMBOL(__kasan_check_write);
 
 #undef memset
 void *memset(void *addr, int c, size_t len)
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
