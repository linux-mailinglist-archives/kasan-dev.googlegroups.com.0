Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEG35OMAMGQEMXQDIZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2FA5B3051
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 09:38:57 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id j14-20020a2e800e000000b0026aaa13fc92sf204761ljg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 00:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662709136; cv=pass;
        d=google.com; s=arc-20160816;
        b=QLgDQsWcwDHttzA3XYxAUPGKqK16tt+FekRTMJvgCyrHPgkg7NauEoaOiDGYMiHTjr
         bIQLXLWw8rdEAoYHC4R23/wKKlAKNCaGKMMsHTc255Mz7AOU3rGte5lA3jlZhdx3xVSo
         PN3HfkpIWEWwPzp+KSoGQ8JBDMzLgzxsBNv4jGZGxMdEnxFOH99sDj8AmnyV/1eyabpZ
         wBjZ9KzOcuemhis+p0dNXq4S2c7ry3E1dbn5S1pEgbxJ+j8CABY7TrB67YJPBqLmN+fo
         DrJLJKKjsHFrYHoi9wFLYXnm/bSfMJG91yTzJS5Vmo608oc6i4HlZqKgdl8XHtlo9NNX
         koKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MzBLnuaLd26SrOcwBceugRZVT17CDYaUHqFcQ2kRGYc=;
        b=LvkFEBKvUeX58w0ySEnww91NXHhKeEzw2X2zg1cdyzHw+pLk99WzgFhnDe5dkiwHx2
         +u8sLWXFHnPE2aYX9sfaIh3zSVM2I2IF5aYmlzwM7JR9L7I7bNSJYw10ZC7g42mFc5gV
         cx04JF9z0LiQePEG6bSGbeJ3EINFeDdFo6GVT6pdzJ3uwgkufNxyClUCg7OMb3Euo8My
         aAuQcGdvhPo5ZyaM0GudZMyt3jykCEj2rKhbQ/nXUakO56uUqrVWHiMshu3fveXiHa5W
         Q81OmIRHsC10DatkuZqXDA7dSq0JDMN7q3Oi/3RVAz7p+Cv4LFZEotICLIxmq9q9/suy
         s6gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nx4UO6FG;
       spf=pass (google.com: domain of 3ju0aywukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ju0aYwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=MzBLnuaLd26SrOcwBceugRZVT17CDYaUHqFcQ2kRGYc=;
        b=PvsFn8jY6MMe9Swvc2SEozNPJv7p8dtsXYAQpj/GrYjCGDHY4ZhgKaB1SFY3eIqeFQ
         9yeeL2+O9wxJeb35WTWocoUYtndzO6is3zc9DRX6UixcVzZ0kgGvR5gxAGu90mFZmzY5
         /hIwQMCFod+QhY38wp6v0j/56IZGUUFhxdtAwJZT3Gd3+aWTTUT9UVsjtP7+RE88WlQX
         fB+IjkKV6C+zyqpRNYecL6TiOIdFO66MIO3I8G7xPxPmNmkUvDS8skGjNVuCVES6dyq6
         cg8tNpEucInDn61tiH6Id7/yovaxEc8sSyRK1rSF5PN7ALd3udhEu/yIUUPMESIBl9DL
         dn6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=MzBLnuaLd26SrOcwBceugRZVT17CDYaUHqFcQ2kRGYc=;
        b=QjqC8C2qz+ismDFrgeodX1tn5cPUbHnCJEwo65Ly9OHauIPss3tviLiLz+wEKGddbn
         ia55osnRrwoLs4PBG5UBLS+iACNKbNyJ+zQ/Zxd5vXzTtM6NFxvkhUA5Sky/DW/oZt8p
         Dg5pksQPmwbkGnSxxEn9X9TrPknbGlEHBao0tTb0dzmYkm1SZjxbNKFA900LHcNlJQXX
         adFGB1GzrYbHMeaU+tSWJBPNrBTzjT5XLOCiayGSqnh+JKP2lFA7WU/SkfSp6nuvtvfY
         NzEKqsLhzt8xVCgBqo5HeinVO5KAQFClalKrrAklVHA5XVhiR8JQc6xRq5rTjxb4WOhV
         4jcg==
X-Gm-Message-State: ACgBeo24mV2VFPe7QKjCWcnA13bnIvGOfbaXWzN9+HwRm5fjgU3iMBqu
	+/ETBNbj9Dszj7xjAas2hh8=
X-Google-Smtp-Source: AA6agR7x/r0axcB354MsbwTYAH60LI29KjuGiscYdpL00yoYCr299JtWOFuoQSAIG0iKMeJfcby4XQ==
X-Received: by 2002:a05:6512:b0a:b0:492:dacb:33da with SMTP id w10-20020a0565120b0a00b00492dacb33damr3731919lfu.668.1662709136207;
        Fri, 09 Sep 2022 00:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3602:b0:497:a8d8:d9ad with SMTP id
 f2-20020a056512360200b00497a8d8d9adls2720950lfs.0.-pod-prod-gmail; Fri, 09
 Sep 2022 00:38:54 -0700 (PDT)
X-Received: by 2002:a05:6512:1393:b0:48d:6f0:64c7 with SMTP id p19-20020a056512139300b0048d06f064c7mr3783849lfa.20.1662709134783;
        Fri, 09 Sep 2022 00:38:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662709134; cv=none;
        d=google.com; s=arc-20160816;
        b=qpfPeiUnvCvrqFOdwrmDP6uNlvKvehsnGHAhDPB07JlweFsU16T+I0hQ95hd2Zd33Y
         H2CzldBUeYC7qS84/yqOtjIfflvup++hoI/PFMPYrbYTCFet4Xznx6avNZUOZtOwchGk
         Y0yKmpGqNhrMH3Fqik+YEbpWkb/zG5NQKRySS2QHRiIHmTduivhxnPLZi7cud5nVTLJK
         UscOzmmCd4cAMeV+t/XK0Ayk9u3I76rcs3vmh8Sm5PBOgHwgr/vMuzc5h1ybKx54XEkA
         Ju+InAGUEzofKY4qcD3V06+omTtVOUAyshwviLZ1Jbb1eukidi/2Z9Qhe/Xs0Cze5BU3
         AIeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=CwJgI/zqEG/WNCJEuUp+CMHdoz4DAXmnbuoZdi14Bqk=;
        b=RXBgs8BQudUFgY0MtTt7IVtEl8wW3WcvwHqDD8WRLe3nk0VUhFty/aSFCUrlSFBa27
         0YlIRRekMmP4Ogmb4rD6DaD47HPgMTT2XR9lLY1qjP9YL26UsiqzBUxG83kE/7/CUanI
         HpQkhAoyYCBl0CyCu/jM4xrb9WDa14/2Dv1YRQgU3bOvw4qbN9lg4z1Y6+IdoHtnknm7
         ZK1FqezlMOeNwUou49ZXALyrdlpAnNcSsCLYN7S3RflggNo9P/yoXNFBD3EiC5kZhJcU
         7UoszG+eE/3V9bPDbdkDsvWn6VhC/k34IV2OU+iHrJF9VPIfDVnG4o8O6Ce9YdT/eU90
         zF7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nx4UO6FG;
       spf=pass (google.com: domain of 3ju0aywukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ju0aYwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id h7-20020a05651c124700b00261e5b01fe0si37241ljh.6.2022.09.09.00.38.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 00:38:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ju0aywukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f14-20020a0564021e8e00b00448da245f25so638728edf.18
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 00:38:54 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1d1e:ddcd:2020:36c2])
 (user=elver job=sendgmr) by 2002:a17:907:3f26:b0:770:8852:9bed with SMTP id
 hq38-20020a1709073f2600b0077088529bedmr7603132ejc.658.1662709134191; Fri, 09
 Sep 2022 00:38:54 -0700 (PDT)
Date: Fri,  9 Sep 2022 09:38:39 +0200
In-Reply-To: <20220909073840.45349-1-elver@google.com>
Mime-Version: 1.0
References: <20220909073840.45349-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220909073840.45349-2-elver@google.com>
Subject: [PATCH v2 2/3] kcsan: Instrument memcpy/memset/memmove with newer Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nx4UO6FG;       spf=pass
 (google.com: domain of 3ju0aywukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ju0aYwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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

With Clang version 16+, -fsanitize=thread will turn
memcpy/memset/memmove calls in instrumented functions into
__tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.

Add these functions to the core KCSAN runtime, so that we (a) catch data
races with mem* functions, and (b) won't run into linker errors with
such newer compilers.

Cc: stable@vger.kernel.org # v5.10+
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Fix for architectures which do not provide their own
  memcpy/memset/memmove and instead use the generic versions in
  lib/string. In this case we'll just alias the __tsan_ variants.
---
 kernel/kcsan/core.c | 39 +++++++++++++++++++++++++++++++++++++++
 1 file changed, 39 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index fe12dfe254ec..4015f2a3e7f6 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -18,6 +18,7 @@
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/sched.h>
+#include <linux/string.h>
 #include <linux/uaccess.h>
 
 #include "encoding.h"
@@ -1308,3 +1309,41 @@ noinline void __tsan_atomic_signal_fence(int memorder)
 	}
 }
 EXPORT_SYMBOL(__tsan_atomic_signal_fence);
+
+#ifdef __HAVE_ARCH_MEMSET
+void *__tsan_memset(void *s, int c, size_t count);
+noinline void *__tsan_memset(void *s, int c, size_t count)
+{
+	check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);
+	return __memset(s, c, count);
+}
+#else
+void *__tsan_memset(void *s, int c, size_t count) __alias(memset);
+#endif
+EXPORT_SYMBOL(__tsan_memset);
+
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__tsan_memmove(void *dst, const void *src, size_t len);
+noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
+{
+	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, len, 0, _RET_IP_);
+	return __memmove(dst, src, len);
+}
+#else
+void *__tsan_memmove(void *dst, const void *src, size_t len) __alias(memmove);
+#endif
+EXPORT_SYMBOL(__tsan_memmove);
+
+#ifdef __HAVE_ARCH_MEMCPY
+void *__tsan_memcpy(void *dst, const void *src, size_t len);
+noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
+{
+	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, len, 0, _RET_IP_);
+	return __memcpy(dst, src, len);
+}
+#else
+void *__tsan_memcpy(void *dst, const void *src, size_t len) __alias(memcpy);
+#endif
+EXPORT_SYMBOL(__tsan_memcpy);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220909073840.45349-2-elver%40google.com.
