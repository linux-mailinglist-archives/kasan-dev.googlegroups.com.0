Return-Path: <kasan-dev+bncBDP53XW3ZQCBBIE227CQMGQEIRL2LNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C06B3EC77
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:13 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45b869d3572sf6337275e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744993; cv=pass;
        d=google.com; s=arc-20240605;
        b=GSDnNS0ZLNtROob2+FqjXggTyMt+3U7HW3l19qFXzNEJBKCDsQJi9ZOY4Fy/nyFtCM
         Ew4wJWeF7YO1rHVNWmd9o8pRSxqTM7aoSLtilX/5LGZ4AGtJ2fsaVPzMqO8KdCB7lNgB
         +M7d3lmlqwgOd0ZaTkkJRo6DayNHhIBnDZxy/0i51RlmSB2SH0kWtTITjbPQFS39Bcxl
         J+Bnw4eSM3l66JDCLz+rfPuGGO8/Udr5/MBpK2a8s+Faa3MunQ37hAZyW12aIfYcpw3I
         N5nTDiHTUZ7IiGW5Ad14t7dXDyqQma4CRg4CRrwCRZ1WTkx4OrupEYAdFNHtFtP008VQ
         Zhsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ACsPn392qe5zgyBxTaeUA+a0rt+svDLa2so27f4rQiE=;
        fh=VrQQ7KydptYJY5RUplRBX+PCHYtE3/Iab0TVg+2DKHU=;
        b=XN00BYdMd4G9E70MKsJKJgWauoYL0o0gFJE8MNROnt8JDd+JWmp+vuv7gA2/EefcEt
         mAH+Qx0K/vvwSFYrhED6QSVok18SY6BffdymiaY6wf2XJb7EooEoyBSiU2UwxQf8ye31
         MyzMy9lQGrply4n7/94Zl5xgKKLudXooL/XDDaFFEFrdlQ5U0Mw9QA1607uHBUzMUdsw
         X/HYuNh8YpQTe2VY7vwgg03L7P3vnClJ1SoIu0GaaOkzZVCeRU+yZOrRAYNN5ICErCZ1
         r0xkbSuFUeP2yX8ZZYTxoqfjwE43dcE52V0ZL0KWB7L+4Uf8J+Ft9WuV/CuUjfL9SBVE
         MGEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C8WwFxp1;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744993; x=1757349793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ACsPn392qe5zgyBxTaeUA+a0rt+svDLa2so27f4rQiE=;
        b=HOa6L8mTRSPrCzBoEUphyiiX7ZKWsY+FIJLKXAwwIffIV2nweCks4Q3uNm8gm/pqAL
         XubfR6OdJeuLZ2GF6oQy/lweGauEEcTuZIlTMYWLaPZ5sLDM3GbFvSsetY9RA/0aaqx5
         b96+1YK6PHNwRp/pczmPvnWPBb5guGApOJiwzTMj8QOtjekAd+OtcLC4YlARMpiwDTwQ
         VCoQWq4ftjZCOZpSioRfhSw4jWbIaLovUWQ2Vm7vhhk9rJf3isie1y/gvnFimx20l8kn
         faAvWEUV7jBGqhFtd73aV9xQ0HViIwD3deaf/WbZOihd4bYyVhss2mtOWuwK8HrMVY2+
         9klg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744993; x=1757349793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ACsPn392qe5zgyBxTaeUA+a0rt+svDLa2so27f4rQiE=;
        b=lrfGZicTluz/4kjSIpx5s9jy35FdBcxceIVrsN/HPoJziGEjKAFIEmFSvd8dxYUKof
         k1U66YVXXiwRSIayq4c4guvN3EcE04Lahk0y6XoeHkVr1mAb1t/vNilHdfCeyNdjtiPr
         99Mbb7gXYkyC7edUU00Js82eFRjBWAQIDy/oERllfsk/FstdZYTbje/5ydTd4mjdM+9N
         +PyGfBsoBtOyhzarbrPCfE1T9kCv3fpJddzGQN/SfPFu37TlVEO7pQXzmvH2AqEPrnu3
         5qDaiQrohMZWP16ikGawStOcpRzHT+XQWHIJEsrQXJPMXty4OyyJrgTqvzsVuxmcQzL4
         0c1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744993; x=1757349793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ACsPn392qe5zgyBxTaeUA+a0rt+svDLa2so27f4rQiE=;
        b=LYjSVFy8H/YiMZQmNqnDs0z4k4Qb2FK3L7IM5Q7zP0dL0ad6VplQqRsgjW/mVlKfJ/
         7mB6PpZhFoIYaUoJt+4MxCKaWpGMnVp5FFlnbxuvO+LQ0g1MNW+iMkV5OrDomCs/D3Ef
         rw0Rvo5rBxPP0axV+qh8VRT1kSCu6CeX7h6/IFVlnNb1ICeGRVFs00BsNz1qUg044p6V
         kSf+ZUyO+rwkCYj627BQnY+6osjpXxu0MC0q6D9Dw3pejN3e0WMdL3qPGKlXbRKEx2o/
         XbKW8c8/emBCZl86B+dDxDRfrH5u4e79bkBF0CF4EW6VUHWsN8OrDNHPPeSn6+W6rrh8
         iRHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtKUJmwqSHzf0K0JCKuPUaTOZAxFT5k+Rv4CrYf3RuGjv2lADO2sM88ugvqeLssncGW3m1dg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5qDPQ8kz2tO16nM6kv+XEE3JLvLahPl0puegQQ7NHH6eDj0PF
	1r1Il0BN9gTSlkAJXfdgLp+tj27JFYt/TrGYXZzeRnvQLouQJgXB2+5k
X-Google-Smtp-Source: AGHT+IFwKFoKb+/AKAsmpojppFoQlwpopR3BsB1JhdPMu80+OjjCdTTnM1XBcDnb/FiJID8FpD73ww==
X-Received: by 2002:a05:6000:1ace:b0:3ce:e5fc:6215 with SMTP id ffacd0b85a97d-3d1dd337b6cmr6521859f8f.26.1756744992948;
        Mon, 01 Sep 2025 09:43:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfX66WzVpvcSqoTjcxLBfhJOXsy94k0mw0qTiOeVg5PZQ==
Received: by 2002:a05:600c:1993:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-45b78cba21els25839715e9.2.-pod-prod-05-eu; Mon, 01 Sep 2025
 09:43:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2Tj44B3NRe/rBaeQz5c+HutdjSy7vq5HRh9qnvbx+N2qpPWAuqVcR2AaNGC7R1dYYmsexoRDJJ4Q=@googlegroups.com
X-Received: by 2002:a05:600c:1553:b0:45b:7608:3ca1 with SMTP id 5b1f17b1804b1-45b8c90299fmr36516145e9.23.1756744989942;
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744989; cv=none;
        d=google.com; s=arc-20240605;
        b=VV8drETdrFoZjG0w+XoMzJeyHst8HO0kkLAlUqLjUCXUNG/x3WfLWvhsMZ466kCVZT
         BySb8fFY8hxywJXY2/80CkvBaV9E7NyPiBT2naLavamZ1rM/baXH4u08wo13OCai1sAC
         1ikIZdWUl1j+V4RVURCgJgGIHPXUXti4VKgHC54Xzp56MPRt03F9WVqo7eQLys5Ju3qz
         bUGPlxFhSXpA1GewVORWEHLAmjtJFNnYLK1HJRWPvmiJ7dNWN0Bw0M97UZbla4mGEliU
         UsDa51bDYe5jmKqCOL6u+eyMF2FmuABhxS1nhwe60TE0qC/5KsrNEbt4Mozxks+i1u5M
         vsSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YtywjNgEiCtG5qk+Og9zZlkfm9Zwe/MrSwR0wbY7quk=;
        fh=2xmUil7AInRGSXCOZuPcqfEyej0NS0+LEEMz/rCdzRc=;
        b=PHDQEBguaiIkeTucyEiYvPihhj1ZnNqbqYnSr/OQaSpK8yznwZ//aOsq8WnT+64AoQ
         pCFgvqP+/SMum3JrjrrQHdZBbPPQo9l3cFdVmS/a8kd4hPlQN/URCPAMwzi0cGPQnXpo
         GRNQg+3dKKLolDlkuoCdfaBPKCG3CAMD/rR6LVy4G2eON5xb5E7ybPh5ApYRQsDhA0Yy
         urBc5BVG1cg4wgIdTRPRlySUCtx9XqOTi5hOvzXInmGmuRB7nBIg/9Eakf9HaI1sDeeS
         fhnnJVpSBZSsQXhOBJyR/jNopvoyyJp/K/H+y05qUmLVpcw1fSYRGk3SYBCRwvwQ9YWm
         +3wQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C8WwFxp1;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b8b916d49si1082135e9.0.2025.09.01.09.43.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3d0dd9c9381so3105245f8f.1;
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFhHufK5AhXoFfJ+FZOd34T7osiBCnAM25uGH5idtmJHYGv1mbSFj6eWXUhbzl4JYtrhZd3uz4CVSC@googlegroups.com, AJvYcCVs/UI8to3dY1GL7kv4wMbTegsp404gXDNU7CVikTJ9UtHR+a7p7I+qJIXNAN731Anl8g3WrXl3CCY=@googlegroups.com
X-Gm-Gg: ASbGnct5fz6LewjVHRxt3uKA2ZzAcf/UC1nX3IZj9MD7/0hZjc+IIL6T6TT6DZVBwJc
	semRpqDjq3J2jGElaPtL2W2TdB0YTRj6K1H7KM+G2CLOiXGTDH30Pj4As8NoNp/QeOMEqmHwufR
	pqvEtUV7yrQd0TGAd7E24X5udnKD8SEEOp6NXFfJi4oUMj77hlVfmNn3/IjwgnRe9em+JQLLYLB
	k1JyoxpreTRXUWS/RzHhASNc13sr0KOKSelQOjfASSY2AC/TqQJT4jfdvY+EJDf06IZ6B3Ie5j4
	9uYGNmqmZiBKX/Yrbfc94bP1qP7Um4kHH/XxrwTBWIeJsN4ldxOgqEgIB36U9+pdiOpxKtElmYf
	GXA0eK8swQ7kNzOH93DNJ5pNA3kUsCtwN+Xn2Q1qSuKBlU28sDVSu7BiobAR0s4XNa81fvJfnGL
	n3iJQLz1kxEjRFry3NiHK+oKE1gG6g
X-Received: by 2002:a5d:5f50:0:b0:3ce:8632:9fed with SMTP id ffacd0b85a97d-3d1def6a9ecmr7320649f8f.45.1756744989103;
        Mon, 01 Sep 2025 09:43:09 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:08 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	brendan.higgins@linux.dev,
	davidgow@google.com,
	dvyukov@google.com,
	jannh@google.com,
	elver@google.com,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	dhowells@redhat.com,
	lukas@wunner.de,
	ignat@cloudflare.com,
	herbert@gondor.apana.org.au,
	davem@davemloft.net,
	linux-crypto@vger.kernel.org
Subject: [PATCH v2 RFC 1/7] mm/kasan: implement kasan_poison_range
Date: Mon,  1 Sep 2025 16:42:06 +0000
Message-ID: <20250901164212.460229-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=C8WwFxp1;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Introduce a new helper function, kasan_poison_range(), to encapsulate
the logic for poisoning an arbitrary memory range of a given size, and
expose it publically in <include/linux/kasan.h>.

This is a preparatory change for the upcoming KFuzzTest patches, which
requires the ability to poison the inter-region padding in its input
buffers.

No functional change to any other subsystem is intended by this commit.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/shadow.c     | 31 +++++++++++++++++++++++++++++++
 2 files changed, 47 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..09baeb6c9f4d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -102,6 +102,21 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
+
+/**
+ * kasan_poison_range - poison the memory range [start, start + size)
+ *
+ * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, defined
+ * in <mm/kasan/kasan.h>.
+ *
+ * - If @start is unaligned, the initial partial granule at the beginning
+ *	of the range is only poisoned if CONFIG_KASAN_GENERIC is enabled.
+ * - The poisoning of the range only extends up to the last full granule before
+ *	the end of the range. Any remaining bytes in a final partial granule are
+ *	ignored.
+ */
+void kasan_poison_range(const void *start, size_t size);
+
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -402,6 +417,7 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
+static inline void kasan_poison_range(const void *start, size_t size) {}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..a1b6bfb35f07 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -147,6 +147,37 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 }
 EXPORT_SYMBOL_GPL(kasan_poison);
 
+void kasan_poison_range(const void *start, size_t size)
+{
+	void *end = (char *)start + size;
+	uintptr_t start_addr = (uintptr_t)start;
+	uintptr_t head_granule_start;
+	uintptr_t poison_body_start;
+	uintptr_t poison_body_end;
+	size_t head_prefix_size;
+	uintptr_t end_addr;
+
+	end_addr = ALIGN_DOWN((uintptr_t)end, KASAN_GRANULE_SIZE);
+	if (start_addr >= end_addr)
+		return;
+
+	head_granule_start = ALIGN_DOWN(start_addr, KASAN_GRANULE_SIZE);
+	head_prefix_size = start_addr - head_granule_start;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
+		kasan_poison_last_granule((void *)head_granule_start,
+					  head_prefix_size);
+
+	poison_body_start = ALIGN(start_addr, KASAN_GRANULE_SIZE);
+	poison_body_end = ALIGN_DOWN(end_addr, KASAN_GRANULE_SIZE);
+
+	if (poison_body_start < poison_body_end)
+		kasan_poison((void *)poison_body_start,
+			     poison_body_end - poison_body_start,
+			     KASAN_SLAB_REDZONE, false);
+}
+EXPORT_SYMBOL(kasan_poison_range);
+
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
-- 
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-2-ethan.w.s.graham%40gmail.com.
