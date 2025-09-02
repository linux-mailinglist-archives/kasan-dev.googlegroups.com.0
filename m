Return-Path: <kasan-dev+bncBD4NDKWHQYDRB7XI3XCQMGQEB5LAJPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 79758B41054
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 00:49:36 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b345aff439sf36343221cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 15:49:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756853375; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jo0gbf4nCUSOhWMm3eVqRKui1WIWKS26GpJwZoiNbftrh3AYvzuh9qPJC8D7rHnypm
         hVD+cXS8UPSeuAndhihCcSLL9F4Mk6DUiWZWf/5H/LkL5eJMnRQ/x0qHEb3eEuzBnA9z
         +jGXYBTSMBwmgonVbbr2dOBD+cHmZGy87m6fJ6+T5nHbnjdDcB+HrdUg5/wZPbQR64Er
         Lt4XObVIM7499QgipyxJdhkDpg1g3ojshhZri9Zmn//6TCtWlWN8+DG67XL/a7sdsp3J
         liC1ZGh+e1ZccUAio+59IpbO89d3zY0jJLPjJINTSB6NvFmxH0JlD8PVCFvYnAyoH9ea
         7I+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=oy8D1aC4Cl8MaUmVI6tT6OsB4BTg1Gmu9MHB000wuuw=;
        fh=9LPd+jHS5SjA3QLB//MPRgNZ4wEaHdMNsu96xDhUkBQ=;
        b=ePPBAr+tKIql61KSfr4hdWz7n3FJqt9bJrbREkyykJITjKrzsj4c5StKfuvqrz4xRf
         F1Tg2m9b/tVSuJxBdEv2WP0jcGAxWyl+cxu5C7/i5zQFLW3644uO9K6GYRK1QvOif0Nv
         pg1zo6kjGXe3hxPWPIa+wm42eA9QRWXWReZJ7cMf8Zr2upcq1Bdk2cla76/ga8hOGvKB
         RI6BpcVhY2HG4Wk2IGZzQVhiBbufSKvaLvV8Ao0SEwluHD4tWgaC5eBg2YzkY4mtcOaY
         kyk3CyA9OhWwb2aI0wB73kw/CwHEQ7a9Bio+Rimy+CtUnWSz7caCQtn4TXRXSx+UAuUh
         4cWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pwn8N6+J;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756853375; x=1757458175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oy8D1aC4Cl8MaUmVI6tT6OsB4BTg1Gmu9MHB000wuuw=;
        b=vEHZvkZhOquqrVMkX0QAuSiKxfAlXKkqC3M3EV9CJs9s6NpqCn0cyJuMXXHjAnb+iE
         ZdXIbaaHhLRmh66VRu353WhcbkOJquBwc1fXf6MSxdP0wy33xzCfe3ldvGawJ/xu+bWX
         X07YOGxd3oHv6yzsnjUtfXThkLXA+XfIHR5BWcTP8dUvntEgqo9SPGB01bxTAiLnc8Sg
         NN3NZNMz2qVL5Ezfu5Re6y2iNBriz/NDpIwfEyNy4FhNhYApQ++hGfVcX3r5fc9WtExL
         /gLfD0y7V+LQe7yIi1c+cAO9elMIh50JFuajQnb2+y4ARtHiKt0pn6IXBWF7CEk8lqQl
         g1KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756853375; x=1757458175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=oy8D1aC4Cl8MaUmVI6tT6OsB4BTg1Gmu9MHB000wuuw=;
        b=J98v3ZPRhLDoxZsoptWJjt1Dpq1hhaY3kFRWp41/1saGyK6ojMTlXZ2tOTV7/H/TCN
         pxSAy5n4LYmptY7oe+wwtDrMohb6WOc/p+TacuTAGOa28lwzRtCpKeiZIF6khr3u9vYS
         rzCScqQCgGOmFLNIq95hQ1dau0HZkCJXaP5AvoUEH9Bb0N5c5H7qEs7bK3sWScva+hhw
         wN+NKqgzmEUqgpCx0yZoygMd7acAMyTwlmg5yt2hRVleHRFe19CL4imqvtpdJgwGe481
         5PfgnwcEhra7fOQHacFRu+uIGTbaxcgAjcMPjpLB+PvHCptvwLEZKduQ9z1GYZ/qzlox
         2uhg==
X-Forwarded-Encrypted: i=2; AJvYcCXEiWucMrg9liWW2iiBrffU/K/47ZDMqfL/VImmhWg7YrvWbKQOtzZv67Xll+7B5CAbPrlmCw==@lfdr.de
X-Gm-Message-State: AOJu0Yz75OHua0Wg3IdlvP2fdgdN3U9oJpZJJDFe1RHVj2YSDlO6QkCL
	jjEkiYr96hFZ5O0iOUIhVTSovlWr7IvJQhPegaJEx2mY/4PwoQGulp4Q
X-Google-Smtp-Source: AGHT+IEgEoY9bsCOUK/Zz34lD3VOEbktQ5KZo7QB5Jg7MygNvco0+zgMJsyBtb6Uv9jBAT8fg1bnMw==
X-Received: by 2002:a05:622a:4c0e:b0:4b2:fc6d:22e with SMTP id d75a77b69052e-4b31dd80fdamr189613121cf.83.1756853374971;
        Tue, 02 Sep 2025 15:49:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZenozeKO006Enkw3MjO4Jk88AEUzR/H0o48vlDy98s6aw==
Received: by 2002:ac8:5895:0:b0:4ab:825d:60e7 with SMTP id d75a77b69052e-4b2fe86dc86ls96610411cf.2.-pod-prod-01-us;
 Tue, 02 Sep 2025 15:49:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXrkTzZwUjijLwM/l+KsE+p2F5aBRva+GwWTPC7J4iHWSqAdP0xD++KI6Sc/Px+PD3m+dFLwi0aD2c=@googlegroups.com
X-Received: by 2002:a05:620a:2a09:b0:7fd:93b9:ea97 with SMTP id af79cd13be357-7ff27b1f81amr1451002985a.29.1756853374033;
        Tue, 02 Sep 2025 15:49:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756853374; cv=none;
        d=google.com; s=arc-20240605;
        b=RVVindUS9enoEC8A1tGe6pi5o4wbpbD7QiIIknJ2TkN/7GSyXMAGOYyKutUmofQsZU
         UZDIzqi/aA5Yx8rAD9+xfn2b4kbX4cReYCStWP9A0hagnMAc3ONhSTR1Oh+LM6yNu4Oh
         FRBlkhVBeR5LpTyfvNYBkE5kztDz7tP5EtBKZ+Hs08WYPKTNnv8EP1LUWyWyw8UuLFf0
         V8BSvLbLqmBUv1TYREwqylo4IR/EfqEZ8f8NO1nsLSFB1LIHkEnpsLM1hgtvjmcfXMs7
         QqG89O5UIRHRlzbmZ3J2PuiOwYnGDn32RWa1E7c9/1bcznE4jS9lo+BmPaz9AsVWZ6I/
         oTcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=xxBOKnZfbB/fgbtqULf72L5k+1DzQjTBpHwMZ3WMlgg=;
        fh=7n+QxQsLm9aENWlXxuPOQaIDpq91a/JCuCEl1+awi2o=;
        b=ZVJ+eLLiNm14UJZQjhdzwoxUVGAEZoif2Wbm5kiQ9FLi1CLmnik9Cq2HwzJoVGJ9Uw
         ViT4AVhL3KRWiHUTTahN+0fYzvfGMQYM+q6vXHo//shJcHupS5iRchfBqlTzIfduBKTH
         sUNQySTyE5/yff05ES5mE3G1g71xacSdZXtoudJm4wadtMI6ySBxjO1Opvw6JCRILCRq
         kwQ6GNi65THGvC2Uxjh2ogvmpjAm4hh3qsDyNwHIh0Pc7uj2DguR4AsJLi3qc8frY2sl
         OR4qSIyi17GSB0eSiVnX0NI4FumrULslAm2hWlPXzNHGVwxqhdw4c6Lv7sFKdP9AN9cy
         X0MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pwn8N6+J;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa0b14b1csi1275685a.0.2025.09.02.15.49.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 15:49:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5A17A6021E;
	Tue,  2 Sep 2025 22:49:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2B2C9C4CEF4;
	Tue,  2 Sep 2025 22:49:29 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 02 Sep 2025 15:49:26 -0700
Subject: [PATCH] compiler-clang.h: Define __SANITIZE_*__ macros only when
 undefined
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250902-clang-update-sanitize-defines-v1-1-cf3702ca3d92@kernel.org>
X-B4-Tracking: v=1; b=H4sIAHV0t2gC/x2MQQqDQAwAvyI5G4ihQvUr0sOyGzVQVtlYkYp/N
 3icGZgTTIqKQV+dUGRX0yU7NHUFcQ55EtTkDEzcUkeM8esWf2sKm6CFrJv+BZOMmsXw/WqJKHK
 XOII/1uLheP7D57puP/hve28AAAA=
X-Change-ID: 20250902-clang-update-sanitize-defines-845000c29d2c
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Marco Elver <elver@google.com>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
 linux-kernel@vger.kernel.org, stable@vger.kernel.org, 
 Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=3508; i=nathan@kernel.org;
 h=from:subject:message-id; bh=0DZTl8k2AipkYnKDzUpqimWr/FzOIW31cDY1tZK3nQ0=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBnbSyor3R42frFJDXvwra3kuth7/wXGS63uOl61Uz76h
 9WoecWJjlIWBjEuBlkxRZbqx6rHDQ3nnGW8cWoSzBxWJpAhDFycAjARxUBGhlvLUv4LtvVvm/qk
 9NDrsis/VrZp3r+a6bzd4YpTnH/Ei8OMDC+ZjzifF9ZyT+jzmHjrUcDKdF0+YYMP+z8ZPt8WdVL
 jHjcA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pwn8N6+J;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Clang 22 recently added support for defining __SANITIZE__ macros similar
to GCC [1], which causes warnings (or errors with CONFIG_WERROR=y or
W=e) with the existing defines that the kernel creates to emulate this
behavior with existing clang versions.

  In file included from <built-in>:3:
  In file included from include/linux/compiler_types.h:171:
  include/linux/compiler-clang.h:37:9: error: '__SANITIZE_THREAD__' macro redefined [-Werror,-Wmacro-redefined]
     37 | #define __SANITIZE_THREAD__
        |         ^
  <built-in>:352:9: note: previous definition is here
    352 | #define __SANITIZE_THREAD__ 1
        |         ^

Refactor compiler-clang.h to only define the sanitizer macros when they
are undefined and adjust the rest of the code to use these macros for
checking if the sanitizers are enabled, clearing up the warnings and
allowing the kernel to easily drop these defines when the minimum
supported version of LLVM for building the kernel becomes 22.0.0 or
newer.

Cc: stable@vger.kernel.org
Link: https://github.com/llvm/llvm-project/commit/568c23bbd3303518c5056d7f03444dae4fdc8a9c [1]
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
Andrew, would it be possible to take this via mm-hotfixes?
---
 include/linux/compiler-clang.h | 29 ++++++++++++++++++++++++-----
 1 file changed, 24 insertions(+), 5 deletions(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index fa4ffe037bc7..8720a0705900 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -18,23 +18,42 @@
 #define KASAN_ABI_VERSION 5
 
 /*
+ * Clang 22 added preprocessor macros to match GCC, in hopes of eventually
+ * dropping __has_feature support for sanitizers:
+ * https://github.com/llvm/llvm-project/commit/568c23bbd3303518c5056d7f03444dae4fdc8a9c
+ * Create these macros for older versions of clang so that it is easy to clean
+ * up once the minimum supported version of LLVM for building the kernel always
+ * creates these macros.
+ *
  * Note: Checking __has_feature(*_sanitizer) is only true if the feature is
  * enabled. Therefore it is not required to additionally check defined(CONFIG_*)
  * to avoid adding redundant attributes in other configurations.
  */
+#if __has_feature(address_sanitizer) && !defined(__SANITIZE_ADDRESS__)
+#define __SANITIZE_ADDRESS__
+#endif
+#if __has_feature(hwaddress_sanitizer) && !defined(__SANITIZE_HWADDRESS__)
+#define __SANITIZE_HWADDRESS__
+#endif
+#if __has_feature(thread_sanitizer) && !defined(__SANITIZE_THREAD__)
+#define __SANITIZE_THREAD__
+#endif
 
-#if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
-/* Emulate GCC's __SANITIZE_ADDRESS__ flag */
+/*
+ * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the kernel.
+ */
+#ifdef __SANITIZE_HWADDRESS__
 #define __SANITIZE_ADDRESS__
+#endif
+
+#ifdef __SANITIZE_ADDRESS__
 #define __no_sanitize_address \
 		__attribute__((no_sanitize("address", "hwaddress")))
 #else
 #define __no_sanitize_address
 #endif
 
-#if __has_feature(thread_sanitizer)
-/* emulate gcc's __SANITIZE_THREAD__ flag */
-#define __SANITIZE_THREAD__
+#ifdef __SANITIZE_THREAD__
 #define __no_sanitize_thread \
 		__attribute__((no_sanitize("thread")))
 #else

---
base-commit: b320789d6883cc00ac78ce83bccbfe7ed58afcf0
change-id: 20250902-clang-update-sanitize-defines-845000c29d2c

Best regards,
--  
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250902-clang-update-sanitize-defines-v1-1-cf3702ca3d92%40kernel.org.
