Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEO5L4AKGQEACII6SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id C89A622BE6B
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:33 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id x4sf16841iov.8
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574032; cv=pass;
        d=google.com; s=arc-20160816;
        b=xDLODjGkPpFb6ahswT7K7YgBVEfoAtYRzY3S6Nlr5SiaF3CeUHiiODN9C8GFDp04Yo
         u0UOj2ambKV2M17+Wub4ZilAkEDayYVtjx3qzNn/Hf8Tqqcw2MG4+HcS5mK99jHjpXyI
         TONyoO848k68vA5AyyQg9UUuEUA23t80h6JFHtgDrnhixHgCnVKZG2hO7jgJaWiqYs2S
         rzyoGHnXLnlqAUs/bFi0ROdUbK/VHd9NMslZDatVgRh2Z19IlQvuIRJgBty6NRwyc4Ia
         5JdeQU6ZS8J6t/LGiWXn8jeRdsHsJG65ldjEKS9a4zSdBAPMTjXNIXmfPZY0DEWbzHN4
         tjig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YW1PmlnweW64Oko374LC9WUxS9HKMnLoMuG0YStPEjY=;
        b=GhICIT5dqFZuPcf2YT6EDbydrOfCGa1MVYz4vJUZ5yjeW9X/4Q9FNsCcip/NAm+kjX
         LnFsyfxWXk1MAAmoD3hdU4qBEzLod3WTcBXwcwm3RmoMZkmeuC0LO2cCKtmiJwu3QmYu
         QNcAk2IdvGD1ZcTO2ZS2nUYd5DXrT8NYv1neSk6rBdhOZNUKa1ycg2LMua5rVMLlMD1t
         w4QMklYCIfwD5aV0TMPinKeFhd54R6KplAZdY/41/AvevaftilRXJ4LbOux4DVKbyBg+
         WD71xnzI5QyVNxSTGeN5vmHrMAjXX0JunKkFOjEUK/jxID1EXQy3cr9j6yaWPdghekvc
         MUUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XgaUDS6l;
       spf=pass (google.com: domain of 3d4caxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D4caXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YW1PmlnweW64Oko374LC9WUxS9HKMnLoMuG0YStPEjY=;
        b=q6SVi0T/UC7MEQ5jfB8yxC4LDD4gY8LeFauKDvOoDcUsjyKM/iPcBczuq5EfoiNOPD
         pE2c8qDXTwvASQUlZ6MkHWuEoARLs799fmdrrIKKBx8ivAGYIp+NCAj57mmeK40x2lDa
         OZ6A9zoKVlJabVuv9ZHxVSLXXXz5zLLTIvaMOFEVrjKouL6joTSep4mQ4Nn4n2OcVyPq
         A/Iqgx6xWNxQGw7AYoP/JJX39aajoD9vOM//Tq6TvMMXcuUJjqYb3iIXL0N8KSdsg8/T
         PpLktEboQueARB6JDmc3f5HaSwRIL0zr0N0cRcRDAvMqMeEudgT4luhWzAp4OvGjQY9u
         d77A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YW1PmlnweW64Oko374LC9WUxS9HKMnLoMuG0YStPEjY=;
        b=LEsWrv6xzCuqPOetVc7S86Qt+ekFtljfFgWY51gKiAgepxiMbU5dQ0mehKH3fjCOKz
         lNI/gx5JbfSjCO+5Vkq/rchh6m1KH6liEGldjIE4zSzkNE5W62BwkUPKqgkpXvwKdefG
         mYV73LQEM3ql9yWKAiISyMgOS+JaOPITF2pW7a61uSS3Alms31+xIDHm2qLAkEx2sA6s
         KHvAbJAlqU4JnTrQrVjk8Vafl09C+Sn074O8Q+5WZHEDvYR0Xot41LfBWiUoFDZeaq3q
         bk1ps3K2LP8sUWWRh6Zeo6c8FketMqT6onrq1GvzszCkX49HtJvkZ9A5gqvBJxw/s5df
         qM2w==
X-Gm-Message-State: AOAM533WOA5YCgEDOPLPjD9dkEpY9HhuzNrpjkBs8MHEcGiZ1hAHGkeU
	RC5PMRl2khFWGaKH0q1WOgw=
X-Google-Smtp-Source: ABdhPJwvUMy5BsR9bQTcAZY8jM83VGtU8epsVwXyhxmjy4+T1/a+xZbMChFNGpYxf5iBVNPYwM3raw==
X-Received: by 2002:a05:6e02:dd1:: with SMTP id l17mr8636793ilj.136.1595574032452;
        Fri, 24 Jul 2020 00:00:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:22cb:: with SMTP id j11ls4791jat.8.gmail; Fri, 24
 Jul 2020 00:00:32 -0700 (PDT)
X-Received: by 2002:a05:6638:13ce:: with SMTP id i14mr9012786jaj.62.1595574032112;
        Fri, 24 Jul 2020 00:00:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574032; cv=none;
        d=google.com; s=arc-20160816;
        b=S2J5hF6G3V7oCXHZ0UW0/tCa0eteJN8q+0ynXtyCvq3tMtsA3Sv/joIDRr/Px4hfpg
         P1EStv46J2QQXQLeI+pk/4fy+oayo/kc7fOnUqIQ1GfMsJE5yrAZ+XauKuinWvxIUQMD
         HFpALq11SYDr7iyUg4CqkS1C8+q2ZleQ/CudBKrn15kQ1L16icupvxJLRgoqGhShzAlm
         FfOGZiVuYOpeVM2RpvkTTj3n5Bj9iMhsB9Y8wPOIlXCh4BV4e6kpk8RFeQhbLwbjpRMC
         YnTAlN4rDgoqiCqEE9qqPfoyB4peF4Awjk/ELXxzw0nZz+jUCFd/TNFFBZZsWA6bGfL0
         JwKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=5cayCuPk2wPjGrqLjRjs0da5Omg5sZGp1EbJR3QFOWA=;
        b=FJxCpblEypoZsZ2n9sTtD7zrspLGv8vL3LE65PO7Rb4FCCD2KvZrvnfNYO1RtN/8ai
         Gn9q2APIddQSdLyYAI904zCHQumSiBRUndV0W9fmyhDRu23EANk+OTf2C1fc7e25uAP9
         DH2Te22iyZrLgtKVuV8WwVG2ILQG3yu9uTScXf/xYzTCDmZLvgsj7hzxE+KFv4DHIpvI
         ZgSDtFvYCFK9Y9yv67AmpAsVz8ndZHGJrDpR/ztjspiFS/vwxEjPt3N0POz5DICyuDff
         Pb0ZQcJmG5DUYPmaDrFh+vpmaKU5nhKueKmwsAdAL5zEJltpq4WWvR0DcUqOLqwWSNi7
         n1kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XgaUDS6l;
       spf=pass (google.com: domain of 3d4caxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D4caXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id a15si235051ilq.4.2020.07.24.00.00.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d4caxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id i203so9324570yba.9
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:32 -0700 (PDT)
X-Received: by 2002:a25:b68d:: with SMTP id s13mr13979168ybj.330.1595574031586;
 Fri, 24 Jul 2020 00:00:31 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:04 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-5-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 4/8] kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XgaUDS6l;       spf=pass
 (google.com: domain of 3d4caxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3D4caXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks for the builtin atomics
instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add {} for readability.

Added to this series, as it would otherwise cause patch conflicts.
---
 kernel/kcsan/core.c | 30 ++++++++++++++++++++++--------
 1 file changed, 22 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4633baebf84e..e43a55643e00 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -892,14 +892,19 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
+		}                                                                                  \
 		return __atomic_load_n(ptr, memorder);                                             \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
+		}                                                                                  \
 		__atomic_store_n(ptr, v, memorder);                                                \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
@@ -908,8 +913,11 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
@@ -937,8 +945,11 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
@@ -949,8 +960,11 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
 		return exp;                                                                        \
 	}                                                                                          \
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-5-elver%40google.com.
