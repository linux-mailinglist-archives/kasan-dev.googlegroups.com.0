Return-Path: <kasan-dev+bncBDAOJ6534YNBBZ4Q4TBQMGQEABVHFSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C44B08F38
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:27:53 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b48369fadsf9110441fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:27:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762472; cv=pass;
        d=google.com; s=arc-20240605;
        b=MAmgwZcf8tTvP05ndR8dOePAv6yIruhIg33ZvmrjjQi6iQaGMeQ2zOV6ZaxNj8Q/40
         H52qpyxpOZcTRdELvWp16q6WHBpBW2bO1Ztsx7v5Sv3lvyoYHdCzmrnD3GiPREtt7uKj
         ak1MaK4l5e0UxzAYds8BpM4i6khZujK0/4c9H9uiWjgMQCK/Ryd2XlOYa81ZWaGN8vU9
         NNIcxMJS1nT4Nrbtl3E45C95T4eCdQjy4sYSPlY3/SVTsBkCDI2uGW8tmoGlPWnsG/44
         ayN7Ctt9MYOO7x3cS684+6qH6L1yqv9bMEDup0xFYKKpf5dHeGrYqYZb3qwd+02ft0fW
         65vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=WyTkya7jcgazOv5n3klUPF8x0tz010HCkIZaICylc+g=;
        fh=K4wRAPxTBCNybQ3sf12FvTJdLHcDINhK2c8Sd0lsewc=;
        b=F++4DLZ0q28VsagOq/eVnfMPjPF50jpxzS3GAMRyKxeJU1AKZRzPX7GTz2xoUInIQb
         nsgt/qlvBv2Nd3JddpxVJWAM8n1GiahSUnJUfZvR8jY1ZwFlqWqPgyXJHhkZsVF5vJZE
         YgwbHpuzC42xJTyg3FMGzUp0dfDu0KKdFous52kEGSnKCz6ahIjkwLDdMFS5rMaZOQVW
         xv6c/hjeBXWLpESBw0dySefFZZSVKbqIvW1zV/QeJvkynpcizjpYWbTutWPIu+m7wyMs
         EQh3qXteN+UnmaVBI8uLWzBJEWsbMxltX8fb/JPIrojI32ANBhnDlfd5xJKbA2yktFI/
         zslQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m55Qp1f8;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762472; x=1753367272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WyTkya7jcgazOv5n3klUPF8x0tz010HCkIZaICylc+g=;
        b=kirjGI7wx3cBfVRlRXWO5MLJdMQM4hv0IkmnUZqlpuEDgA3034bNNbmCj7lLQvdVFq
         Ge61LMGkKiCnQJG8hQCu24VXQargkA7W/lQs2cpNXTON2bHzST7Pqf5/CoiihOsPwYp6
         d3SMqfudwEiO5hkDK4sa19xbhC4Hh7huRl/IJfdz3Ntqg3PwnHouNC8seQoKbqRGg/k8
         4mWTMb54PJqxPe9EcSe3WSQMQFo3TvdOy4JNoi8dFw5mAoIvv2+CgZ/CsYPJ1mE3B9Jb
         wjFqmiewhkTVP/hQmtiPQnulp3rogVff03jZtQBnJXkgRkZsNGKtRi7Uw84geGYxrxYD
         xqXA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762472; x=1753367272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=WyTkya7jcgazOv5n3klUPF8x0tz010HCkIZaICylc+g=;
        b=BmATXKa7XjppSL9kc5T2pRb0Bk95r90FR4gI8gRKai+9HPuDf5vJ0ItmVGZBNUPiVH
         UedvwoHl3OslIbVsEeCK7ifk5eC667Qp9leZmMpkuQCQZwe6IpBoSbl7pXtlc7XssPBN
         y2QyNAw6XPmiIiyDFV0lQjiQxOAUJ4y5EJRb9iy0eiHzE5xhzmyYEnl4qxtmqddI2t0O
         TKlMT1LSVxK2sMFLSi0NVnnu6IPoVnCAoCIw25miaU6Wz6aLkuUyTfreiwKoNeF3hSv7
         xtuEePA7tba8gZD9L/vXipWX0XE1mvYRxM3kauksY3vE4UxYbMWK2yJS9tZ7AyBVEc90
         8aIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762472; x=1753367272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WyTkya7jcgazOv5n3klUPF8x0tz010HCkIZaICylc+g=;
        b=WLkwKqufJmrS10TRbwQap08rADvNQnmorOpXEQQWsSuw4ekz7RvwwtFDI09UQLHXBi
         /Q9U78KUGwr02dKzUwxuvIcule0tH8mInk+t3CQscffUhPx75EmIP7eIfJAb1SgY+o4I
         vUsK4aQy6zYBTwSVcZmYe104Lni4PVKdhN1ssOhmb6jMiUp7kCqJQgHVIqySAlvhWyUi
         8xAPfBvT97/9YCsaa5QGrxrLD+dFC/klecQ9+BNzYafoWOQSSRGEQ1ljlrsc3FBJtmgM
         4/G2tvusJ9QEouZmiuO/BPWW4sJH13delUCkyB7ShTJPitbj2M733lr7CTjhT8uXCpnr
         njQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVa3wEd/pcROQMUedyUGE2OMhzdy5k8wu41KQDmltK1CjKBELthUDdBAjVwpE/RrTcGTcdyXw==@lfdr.de
X-Gm-Message-State: AOJu0YwJtkR0JqrTG8CxwlyyHdjIDK9ZoBC4i5OfWcuyHryvINvatapf
	+PbXC4oRV/Zc5wAraR+pW0NmlcnQXE4cJW3IL/JAUABN+piuzU1mUSJu
X-Google-Smtp-Source: AGHT+IGCRmt6dx1UdaHpFi4UXvrszlpKEbBMOUHpVnosSp2uV6SOMxCQPB4olhA1d/toY8ws4+JuYw==
X-Received: by 2002:a05:651c:2128:b0:32e:aaa0:e68c with SMTP id 38308e7fff4ca-33098bdf6d7mr9416901fa.19.1752762472247;
        Thu, 17 Jul 2025 07:27:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfqWvruvNmDfE23DKTPXi5zFQWZ7SxFABjtEiu6PqGiqQ==
Received: by 2002:a2e:a23a:0:b0:330:4b06:2cc2 with SMTP id 38308e7fff4ca-3308dc5d78cls2679481fa.0.-pod-prod-00-eu-canary;
 Thu, 17 Jul 2025 07:27:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQu7xkFyX98kjf+KVAaCRgAeL8G1UkTrlBOxCFsQxD92LyhEqHNAQhZH4Cgeydpp0oDzkkMFDuiIU=@googlegroups.com
X-Received: by 2002:a05:6512:1188:b0:553:510d:f471 with SMTP id 2adb3069b0e04-55a2fe75858mr5947e87.24.1752762468384;
        Thu, 17 Jul 2025 07:27:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762468; cv=none;
        d=google.com; s=arc-20240605;
        b=gsgf0fdUnT5CzTcr0aFheowD7N0iCGqPT4MMblNLh4d9ApWfG/FX4sqjGwDf1hYj7j
         1hD9qdcSmv4Sm7KxNaJg8rAO/S1f5qu7VoAdwWefV4r8pSO4ccUOkoGlPCLyPpws0Lvv
         kxl6oBFHBgXBg+bgmqfEtBr4p+EKDUNZjvh2mfFIjBob0u/gQ2qg8qhoY/TpLEpaPG+f
         LJLvIo/jaZlma8jp5+2eOt7L/5voP13lFUFxpLOL9sW1ZYPnlwt2bzNgctnE1Ont0Hoo
         YRwJ2R+Rf93StO+X6J+OrPFFPhQbocsh92/KLBYAwgRSeDIcrO+lThjnZcouLrxQ+WQE
         z9MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CtzrgmhXOlDN0Ac+5J9qvgdYRUcauOXxnB1y58JGUsg=;
        fh=G3m8Udfsh53O+n+/hGPvzR+6M8vIuDENEukHb9Sl0NE=;
        b=SOo9cA8hscuhtb7c3R2NkI7UItSRb8IMysCrkAfmy0ZXDseMcjdBlrwR/G4zyJQ6MB
         XoyBRvyzrXoomMKcJEnojEar5xTuS6L+GoCmzT5gz8ewP9Sz92P6BanCVnJQVK2Ru05q
         DvEliSblFD82dU324f+dNtKd0EKwIMZwJ2yHMMtWRvuShQQ/Osi9Z/pgiKPCQxTiCVqi
         XcesWZhDDaF8o9DPOgTzRGm+DlXR6f0G84YuJCa3bRJqXxdcLMYAU3OdXcLoxCH5WTjL
         2cyVJlE/YLMPlNTIGnQz84zWTyuFGPQXACLu9UzaBScS8kBxRailhoTpojgg9j+f546B
         3NVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m55Qp1f8;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa29f22e5si4837711fa.3.2025.07.17.07.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-55516abe02cso1058701e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVUioydxQRtUDakVi3tfGx/qxFyIsjhU53zpggRe8wZ7Pvj5WdtG0eoqD0B2fWy371SRgfFnfhFSpU=@googlegroups.com
X-Gm-Gg: ASbGncv3vakWSiArntM9e3VuoLumpC+P2GFjbDyz7prCkVegWDXH5CQ2OUbR8r+ya5h
	HSrNPMdIJ0FHmnDX68Kzin8SXTXoMNhCd/utVGgvQ3fNBaH4lCild15JIGtvwxeIRU0nIvyejJZ
	QYH/xYKp+Pv+dtEULboTGzEXFF4Uz8GojIB7WLY+Sahxkat0Y/uRuFIYjIFMnM1EnXAYKi4pTrG
	grY0zLAvfX4FLKcDBxASYacikbwcHxW58/rgSMA5r+5dFRGwcoU2VmXY+tR16r/Z95cdloc4W0D
	2D2X4tYfxR4dM0z6liqmEDX3i5+EO4R1MWBQD7mL/AbuhYt7DhJOj0zmjGntVgkxgquqgTyPLKE
	vLWUX1LetonaYFfeGuZQhBwbyjxiVcfzWqnuNEGygpGUdSS7zOknkpdXTPq6dogea6ax5
X-Received: by 2002:a05:6512:1254:b0:553:2c01:ff4a with SMTP id 2adb3069b0e04-55a2fdd97dbmr24308e87.3.1752762467575;
        Thu, 17 Jul 2025 07:27:47 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:46 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 02/12] kasan: unify static kasan_flag_enabled across modes
Date: Thu, 17 Jul 2025 19:27:22 +0500
Message-Id: <20250717142732.292822-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m55Qp1f8;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Historically, the runtime static key kasan_flag_enabled existed only for
CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
architecture-specific kasan_arch_is_ready() implementations or evaluated
KASAN checks unconditionally, leading to code duplication.

This patch implements two-level approach:

1. kasan_enabled() - controls if KASAN is enabled at all (compile-time)
2. kasan_shadow_initialized() - tracks shadow memory
   initialization (runtime)

For architectures that select ARCH_DEFER_KASAN: kasan_shadow_initialized()
uses a static key that gets enabled when shadow memory is ready.

For architectures that don't: kasan_shadow_initialized() returns
IS_ENABLED(CONFIG_KASAN) since shadow is ready from the start.

This provides:
- Consistent interface across all KASAN modes
- Runtime control only where actually needed
- Compile-time constants for optimal performance where possible
- Clear separation between "KASAN configured" vs "shadow ready"

Also adds kasan_init_generic() function that enables the shadow flag and
handles initialization for Generic mode, and updates SW_TAGS and HW_TAGS
to use the unified kasan_shadow_enable() function.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Only architectures that need deferred KASAN get runtime overhead
- Added kasan_shadow_initialized() for shadow memory readiness tracking
- kasan_enabled() now provides compile-time check for KASAN configuration
---
 include/linux/kasan-enabled.h | 34 ++++++++++++++++++++++++++--------
 include/linux/kasan.h         |  6 ++++++
 mm/kasan/common.c             |  9 +++++++++
 mm/kasan/generic.c            | 11 +++++++++++
 mm/kasan/hw_tags.c            |  9 +--------
 mm/kasan/sw_tags.c            |  2 ++
 6 files changed, 55 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0..fa99dc58f95 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,32 +4,50 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+/* Controls whether KASAN is enabled at all (compile-time check). */
+static __always_inline bool kasan_enabled(void)
+{
+	return IS_ENABLED(CONFIG_KASAN);
+}
 
+#ifdef CONFIG_ARCH_DEFER_KASAN
+/*
+ * Global runtime flag for architectures that need deferred KASAN.
+ * Switched to 'true' by the appropriate kasan_init_*()
+ * once KASAN is fully initialized.
+ */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-static __always_inline bool kasan_enabled(void)
+static __always_inline bool kasan_shadow_initialized(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
+static inline void kasan_enable(void)
+{
+	static_branch_enable(&kasan_flag_enabled);
+}
+#else
+/* For architectures that can enable KASAN early, use compile-time check. */
+static __always_inline bool kasan_shadow_initialized(void)
 {
 	return kasan_enabled();
 }
 
-#else /* CONFIG_KASAN_HW_TAGS */
+/* No-op for architectures that don't need deferred KASAN. */
+static inline void kasan_enable(void) {}
+#endif /* CONFIG_ARCH_DEFER_KASAN */
 
-static inline bool kasan_enabled(void)
+#ifdef CONFIG_KASAN_HW_TAGS
+static inline bool kasan_hw_tags_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return kasan_enabled();
 }
-
+#else
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* LINUX_KASAN_ENABLED_H */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2..51a8293d1af 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -543,6 +543,12 @@ void kasan_report_async(void);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_GENERIC
+void __init kasan_init_generic(void);
+#else
+static inline void kasan_init_generic(void) { }
+#endif
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c7..c3a6446404d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,15 @@
 #include "kasan.h"
 #include "../slab.h"
 
+#ifdef CONFIG_ARCH_DEFER_KASAN
+/*
+ * Definition of the unified static key declared in kasan-enabled.h.
+ * This provides consistent runtime enable/disable across KASAN modes.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+#endif
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e..03b6d322ff6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -36,6 +36,17 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/*
+ * Initialize Generic KASAN and enable runtime checks.
+ * This should be called from arch kasan_init() once shadow memory is ready.
+ */
+void __init kasan_init_generic(void)
+{
+	kasan_enable();
+
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
+}
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b5..c8289a3feab 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
+	kasan_enable();
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a3..275bcbbf612 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -45,6 +45,8 @@ void __init kasan_init_sw_tags(void)
 
 	kasan_init_tags();
 
+	kasan_enable();
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
 		str_on_off(kasan_stack_collection_enabled()));
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-3-snovitoll%40gmail.com.
