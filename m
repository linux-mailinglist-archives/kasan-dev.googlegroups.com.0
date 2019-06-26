Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MBZ3UAKGQEAE4HOZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CF02C56BD8
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:27:58 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id y5sf2759418ioj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:27:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559277; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fej2XNGWIYrx3CASErSsi8DkHtw4Aq7R8vQXcKnA/wI1EEzJBY9Ow+pH4rG4RlCmnT
         02ZkgPElNksLx0EdyhrE+R3cuzbQ2IiRhAHiSwA4Iy2EWGP2UKxByk6U6nqqTOPUEWvc
         I2pByntQrsFAGg1GXc4S0NEgFOI7StBwnHNheKHFJVWyxXBdDae6n/3rCOMz0lY8OyGN
         QSw2xSdPIXV5g7N3N2kR348SgoH7kkPRb94BQajuakTZ9voao67dQGmy8ae7iVkVDY97
         yjBl4VL6oWRvQD2L77GPx80mMBKmu0Rm35SQpAdRfgk6MBdflSuFQND1FuGnAKMgec6n
         Z9DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9FbQa/0msFxbnlrJXbO5Upkp/JbaRIw0acEr0gz3rJo=;
        b=Pv0AAq9aBHgWWwEM5HtWF3/e1mL7+9skXuEZMOiqJ8X093RhzkSNoZb88mgREsIKf+
         i6AXabMLubGL60LrfYK/miHZAwwU/R/yRdyqm7cvl+4bhyyEwssbfzt3G7R59QEGWAxn
         tChMM80/4kEtyk9AWzTmo82s815JdJO/BALgA0r8MbxuNUBhIXXJ2N3UwcWZ3BhFoWuY
         xPvtpnS+Mxf7zevWlO9UuR2aLrfMA6nN+MXk3xxWipjXBpIOavM/zkDlxo6owCOX5d4F
         az30AhT87oNIkf7/5lf9Eh8SxpZKAuKmSm2L7L4BTvFH78DtTXx7YAWBHpbita96eN8H
         t/jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r6nw3M8i;
       spf=pass (google.com: domain of 37iatxqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=37IATXQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9FbQa/0msFxbnlrJXbO5Upkp/JbaRIw0acEr0gz3rJo=;
        b=Zoo6WLGbNHA6ddW9UuAl+ChOzQB7unuLzGT6tfw3sTvzQnSSiq32AFJtiOetbJqffN
         /D05oJPCoEtVR2SUUi7/RNj0l+P4OmPLjFfrvvRtVv9vL/LdeOwISqEiAv8IM+lllKug
         HCi4di1kCBQ35UVlnkOw6pZqvmo/JKtkDGJ8QInuDGVrC9PYI043d8dIXrtNXeG2bQUH
         sYyqsZYEwK952mwOp5+u/DwHuTriB0MMfSKYBksb9Dp7APQx9vpd9F7ZTHnHJYV7KD9p
         3xVlTggZ2+nYxFZ6lKm5lEMZqhlPIz+EVzRal0COSOFZxmXIn1Kc5tZvheQ5l+MSzWjH
         OmbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9FbQa/0msFxbnlrJXbO5Upkp/JbaRIw0acEr0gz3rJo=;
        b=p+oJfY+xPAXMLYhrzvBCXNi7uV2eigMzN5paxUlFdqeSP8FMy5BMbcgR+UKYakLS2A
         +kfG9cTfOinAl8S0KxdsZmRuDEhTgeDK4Ervjq5IHHvnBf6jZiCQpSsnyCmxmgLYQsyZ
         eni3djRjBGrT74VJ0E++pMn40xQhS6GLd+VVtPVmECwO1VG762XOrmCt9ZYG8f9s6LRX
         nEL8eX7u6q7fIuAGdXS8yI2u1TyCsT6+knToVawXN6QprNVLuosk3rcW6COaZAL8ai09
         8TXxsWTzzosFLHikgrYvejxoy3eux+Vj1i3ld3Nt9C3K7xMWf4/A+8bkMYfI4pva3vlc
         c2sQ==
X-Gm-Message-State: APjAAAU+za3QBaqB0VtBWKbR6YBSeJ9tTRcmCbjEvjSKYIb8eB8kn3R6
	K0eOSRPndiIoQaQhkyAAPoo=
X-Google-Smtp-Source: APXvYqwQXmZLjfAUilwo/RFj0SnhVVu91ia+O/NLXsrZEHIAm5Sxy00RqxhECgVDG3u33hdGtlyHOw==
X-Received: by 2002:a02:7420:: with SMTP id o32mr5222870jac.117.1561559277273;
        Wed, 26 Jun 2019 07:27:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:a517:: with SMTP id 23ls565356iog.3.gmail; Wed, 26 Jun
 2019 07:27:56 -0700 (PDT)
X-Received: by 2002:a5d:8451:: with SMTP id w17mr5672439ior.226.1561559276963;
        Wed, 26 Jun 2019 07:27:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559276; cv=none;
        d=google.com; s=arc-20160816;
        b=HsBJgYMS23hbWgUgTxY4+azEePkxo0759yRk67kRxHPaE1wyHvl9Kafl6NDrZ888xC
         PKMempwdOVz+4ZOvimLJf9DQMvFMlJBw7IckQEBfiNdKfkzyTrzHFLTivdd4Ma1zl2RL
         IZlJ08QQFgZx5VuoB9DIEmXnUGUTJlBtZiLYI7Ldrm6zG3V2QQBY3L2wI925gC99ndnw
         fTCEiI6TKhsaB2EQ/uvcp+MYZ182+aHw3VTfEDW6wl6FBnL8v0545sK5rVlttJZWNKaM
         EsAsmsqFKrQKrpp4XGxv5ohwxzfv6VP7oaLoLUZ6vcuBZKqoBiObj0IiMc4+B16Sdpfb
         fQkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=M/VKnz1BZ+rvrIeSdLI9RxXAlLGL/xX/aFhsrhXW1SI=;
        b=Gh459f7vRCohanbjq9/I26wbFa6c2khb7nJ12yEjDf3i4Hw4dk60WLoCJXeF+6h45L
         ZIzLP1js6+oKIMS3nz+8qAMPFVCQr062Y3+vMS4zWMiSAtkZm6KJ/iiGt4FnvYv3ahz6
         JJa4jHPsRnuEBuZpxYE1QBCGGYD6yFrZKXNpB3IXNR8xWYKlSRSnKbOB2Mq/Qw5Y7bQx
         XfMOGgX21hOLW9fjNWiGcEgTlk1245E/7l58JYQfLbHHmrLGbYLbDe86TFWf4wlxN2RM
         JwA1sUUK7Cay6vjKmzv9H8S7bcC0IBXFiYLaH7o37GdT9s4LNWXN6TzOoie2+PDKeG1h
         f/zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r6nw3M8i;
       spf=pass (google.com: domain of 37iatxqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=37IATXQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe49.google.com (mail-vs1-xe49.google.com. [2607:f8b0:4864:20::e49])
        by gmr-mx.google.com with ESMTPS id m3si469604ioc.4.2019.06.26.07.27.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:27:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37iatxqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) client-ip=2607:f8b0:4864:20::e49;
Received: by mail-vs1-xe49.google.com with SMTP id b188so523206vsc.21
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:27:56 -0700 (PDT)
X-Received: by 2002:ab0:70c8:: with SMTP id r8mr2695528ual.89.1561559276181;
 Wed, 26 Jun 2019 07:27:56 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:10 +0200
In-Reply-To: <20190626142014.141844-1-elver@google.com>
Message-Id: <20190626142014.141844-2-elver@google.com>
Mime-Version: 1.0
References: <20190626142014.141844-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 1/5] mm/kasan: Introduce __kasan_check_{read,write}
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
 header.i=@google.com header.s=20161025 header.b=r6nw3M8i;       spf=pass
 (google.com: domain of 37iatxqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=37IATXQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
