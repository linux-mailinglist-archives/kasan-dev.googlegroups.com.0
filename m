Return-Path: <kasan-dev+bncBDP53XW3ZQCBBY6OUTDAMGQEUIC3SVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D73EB5917B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:25 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-336c3108badsf35280511fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013285; cv=pass;
        d=google.com; s=arc-20240605;
        b=ieSKG6tc5DZw0ey3ZoMoEOlJiiY5ziWymBun6G8Bp9x4CBSQc4ocqmjPTYNjql7VfU
         KnnAqF8rQsspBOrWZV5OOGaRt5Yps8umGevevaEWBWzdPiYUfTtptVy+Myzdy6vxRnQd
         9xIls7rJSFmd5fO0JD6JJ2uweJrktnnQHB+/7QlIfZ4ulHbbVoyFF2Qblp2Fij7aTck9
         /9Oa3aHhdQ2T+ULy0yo/7n2JC/g0mq32FfFSXDUfv9LYWQlqAKmT44YtZvSzEXAl7e+n
         zaPL7abKBJ7t5ESjI6cHDsz//dPbDnQ+JqYZfZHRUnyVXtOi0OA4XTrIJjB7DA33u8ud
         BPxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=L+/XlTFIoE+o0I9OCIRLlgUl7nupjmCvdI7rspvugTI=;
        fh=id3ktNlPGnx8WFudTdRG0mg5qSEsyBJj+McvMTSbVKU=;
        b=RA1YnI5mqoVhIIUK9ocep499L92cO4aot2o9XSWa4+4TzvQJ1OC5RBe3fg3GBKGzE0
         x2KdhHHbYTL5rf56E2Il2vcBDleKrn3uJGbsN/TSwL4zt6pVwLHunSVgcC6nHWPbTyFY
         gHh7xcCIHdbNvLTKW2GBUUPfYiVwJZaa8ZbXGQfUbs/HbCB8atiQ11LDkMCJLc1GV0IC
         yPzeZr2FB+EksqI8ym2sV58bNudz3psA7mosU8SwV5EeR8n7cvz+G7e27UCeZX0RzgwQ
         dM32VWFybBbwA5Uho4p/ayOMsW5TkHgcEh/s4BokOMmwLYip98FUJUWFvokUbeH5/kYE
         6Edw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l3rLLju3;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013285; x=1758618085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L+/XlTFIoE+o0I9OCIRLlgUl7nupjmCvdI7rspvugTI=;
        b=QX3GuFb7oJfasIvcEt34hfJqyZH84+Ildn70ty2tu6fC2x8fcFJ2czjqMDXiKOq1xo
         CqObVKpZnqM9RWlLl/w3l9Jm3112einZXXzYW560moOIalUwEpolMzZEaaUdU039v1jZ
         lI8r14o5T+ieumKoObqD680F7QSmV7mPY8X1xPchmtHmcfSh+PH5S3x3aZ5muKNHQdOK
         a0z+8ypPBFXYI4aGXWj/c186gVG8ahOrgD1d71R6G7WAi7m6jnw52+YLnOTXAazWVL/s
         +Ksu21TKLRdn3T8hm3c9M2691jYfrF9pS5SYSgRhav4+js+imHAIvpBNO8IsSyuwKmHu
         ckMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013285; x=1758618085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=L+/XlTFIoE+o0I9OCIRLlgUl7nupjmCvdI7rspvugTI=;
        b=Atzfq9VpxJPAiNeH/PHp3UG22D38Ruok5YKpfXMjCpRINAaSHpsU9iq/ynKwXn49Av
         nK93olw37sA1Nw1J9W1JajbeyKP+h88p6/h9M50CIAWWemxChx9WTFuHj6AT8xz6wQD+
         QOMET90A+Y0DU5pMXH+uLwhV6nTzAIdD9huVVib3bivRLj6f4v/Px36iEvnEyMkOcbF8
         ZFEIO30RVoSTNF9NlzZdZp5Sotrj5G76Vq3HPqJ5UFLsOXAsjAKfRX1eUZfMy0EGwDA5
         Pa+CW9NjW+5JzNZaJjzj3fm2d5hY3yiCBz1nKWMSiidF+tkKOtv/25kj0lq+fY6TBp+q
         1ILQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013285; x=1758618085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L+/XlTFIoE+o0I9OCIRLlgUl7nupjmCvdI7rspvugTI=;
        b=q0VWmzlIY3Q/Is9BY0A/0ZTmr9fKGnia5rSTnqdMsTzlPGWOyvNO28HtfrlPCkJZD1
         VR1Yqie2AjP12kWIcoQO6lyYHzSym0AonKZPixDsFJg8aXRpg2ZAKIGHM68IXyBTf0ap
         nSeW166qinRqz2DAr11LtsslZDAnueGMc9TH6/Bav/43591h+VT3oE21dcuIkrGmPnOf
         pIGHP+r7TI4iiFxzrJnl9uWylSKnxGIeqVMuwUvWZ+iurO2W0rwXpwOTYcFTyLsO5YPa
         vJJhMfadmWBAnjHzKvIyGfYCCfi6NVrFsa3TU1dGWBP43UifmacQQEpeWeJwfaQ87MZ1
         9gKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsJM06InR93yNu2bmB9pRo9z2VuyC3tJIl313xDF+2TjvJYip+//V0Ld7s+xkURZ/3bx6ZWg==@lfdr.de
X-Gm-Message-State: AOJu0YyPYUg67YKVT17/mE4TTCzluzs/Iz3qHF+7C8EGabMmyneHZ9oE
	HPf9gCuhVofswd0PpypZ/bG6quz7NA+cd0811lGrmCu8r7nYCLYG6AmT
X-Google-Smtp-Source: AGHT+IH4x3t1xHUZjFIGRezgxlQGrVNxTKy3l9JhAbgxA82Tgf29VzjIlRn4E/J112v0UxJdsCaEWA==
X-Received: by 2002:a2e:a00e:0:10b0:336:e0b3:2358 with SMTP id 38308e7fff4ca-3513f194d28mr35188781fa.31.1758013284188;
        Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6TE7eJpTCVaKBTZf37d2qVLQzj5CzmCCDqehlHV+rMtQ==
Received: by 2002:a05:651c:f0a:b0:335:7e09:e3da with SMTP id
 38308e7fff4ca-34eb1fc10f5ls21342321fa.2.-pod-prod-04-eu; Tue, 16 Sep 2025
 02:01:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJMnkroAcfoerXfGfuDYvuji1pXt5YQGkvA3riGQ6+26uaau1c75YQAWIFDZEVd/+h+LumCjqpTIE=@googlegroups.com
X-Received: by 2002:a05:651c:2225:b0:352:bb2:552d with SMTP id 38308e7fff4ca-3520bb2639fmr50068121fa.10.1758013280412;
        Tue, 16 Sep 2025 02:01:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013280; cv=none;
        d=google.com; s=arc-20240605;
        b=kIlfQiqYgcuUp9VH6kR6jUzXeXuIpuCn4ZUQRgZLnE4kg7UCeGxiKGH8t65Cp9ZvYc
         mzBX32a0PxKV4If3gijpWmE0jbxbv04kaXTzRZWj+MgvlS/MmMdjrFwFU02otvQlHc5d
         23LxOCyW1KkUQD4d7+xQgW75aiYelrXARA34YSfAZS+4TelXSGfXd2JRi2HkgvYbqJSj
         BzCHJ18T9d4WJq9NxYxZMxrDTqCraWTS5nNPNurz8xdpk0KAsT2Y7P5wdFaiTa4NgkG6
         Dbvda+3jmuZitzSnubCKYg0Jif/6OYwbidLq8HGsH5L3PVgiipYLHb8Cb2XXkDmzYwlT
         FAxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2yrCmffzlGuEExOPu+2JuPwFc40pU2sHK0rUuIT3g74=;
        fh=5EHqIZwRR9MUJFdfRAGDIxmTqGasQutbOvSochsQ5BM=;
        b=B9t4apPQOxx9pudQrb9zAv0DzNvRotRaEq0MlUqg0AQr+fEP6Sc8/dmJ3n7GTJKow7
         aw0TMdUzQXTU8xh65BKJanCR7jGGlGWSagvkQ6yOotDdZh5p+71mZplE4HlCBwwQhqcd
         B4TkOYi6w+LF+/91bAiezdJA1jDF3X2Vq595WbBuhRlmV8X4a7w1s4G2I47m8sDXoJFI
         PBqwjcgVxfXnyeCyIFjdbljdFrqNU6JD0lY589I/9K1N6M1d1IElykWfkv8gSlyTeq1/
         h2U1dlqAnHLSncxPqNYNaDy/XG4E7tSYDeYbl/gBKFMlnSO5JNS5Bbh/YqL+F4DoCF5Z
         xvjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l3rLLju3;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3512a98ca2bsi1938771fa.5.2025.09.16.02.01.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-45f2a69d876so14549195e9.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZTd4Iit0UXQG5XQaEnYLlUSbsx0b9ENlioX5l0pdPVkJQ4bRvV4ZMmSZ8W6zN3qsZzIzGJp/q5L8=@googlegroups.com
X-Gm-Gg: ASbGncvMSaFpsOUgKt6raHYRBG9iikRbjyJxrolkvZ9b5LTwRSufhgBAmIh69OAi9GU
	ckdBxvEh8bgllOOg1KCJWJH+fzmhbIzW25hrM4FWKb42eGsB87RrZzIgUwmy+PGjbBXCnEdVvI6
	qpwP6aM3/l8pUU6yzz0O96lKJkxQq0yht2FtgtSaiH2r/wKeQdsRiNJDYI9/Oz26ZgcDZcvjjkH
	9CblGpHAsO6Q5wHQp2tarx1wizNVvliReWR5sLjsZP36uVDmNJV5SG9jG2iobJ4+FC4qgSTkmms
	RkeJ6ajtgGFTXSZXiM5k99KvW/9GUwO/yLY8vPsyRAqnzt/6FLkflhKxSCbXwolqcOVydKExyMj
	iOeaNMC0KVHgjENw9rcoVy5IbExQJzt0VrrUdAEwt8Sh5TyTLExMzSYWNERpxXvMWscV7Eli8n6
	ZcxW+GoY17xJDB3vUFqCR8S0U=
X-Received: by 2002:a05:6000:250e:b0:3ec:d789:b35e with SMTP id ffacd0b85a97d-3ecd789b5b1mr817634f8f.8.1758013279529;
        Tue, 16 Sep 2025 02:01:19 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:18 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v1 01/10] mm/kasan: implement kasan_poison_range
Date: Tue, 16 Sep 2025 09:01:00 +0000
Message-ID: <20250916090109.91132-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=l3rLLju3;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

---
v3:
- Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
  kasan_poison_range(), and return -EINVAL when this isn't respected.
---

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 include/linux/kasan.h | 11 +++++++++++
 mm/kasan/shadow.c     | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 45 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..cd6cdf732378 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -102,6 +102,16 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
+
+/**
+ * kasan_poison_range - poison the memory range [@addr, @addr + @size)
+ *
+ * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, defined
+ * in <mm/kasan/kasan.h>: if @start is unaligned, the initial partial granule
+ * at the beginning of the range is only poisoned if CONFIG_KASAN_GENERIC=y.
+ */
+int kasan_poison_range(const void *addr, size_t size);
+
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -402,6 +412,7 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
+static inline int kasan_poison_range(const void *start, size_t size) { return 0; }
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..7faed02264f2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -147,6 +147,40 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 }
 EXPORT_SYMBOL_GPL(kasan_poison);
 
+int kasan_poison_range(const void *addr, size_t size)
+{
+	uintptr_t start_addr = (uintptr_t)addr;
+	uintptr_t head_granule_start;
+	uintptr_t poison_body_start;
+	uintptr_t poison_body_end;
+	size_t head_prefix_size;
+	uintptr_t end_addr;
+
+	if ((start_addr + size) % KASAN_GRANULE_SIZE)
+		return -EINVAL;
+
+	end_addr = ALIGN_DOWN(start_addr + size, KASAN_GRANULE_SIZE);
+	if (start_addr >= end_addr)
+		return -EINVAL;
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
+	return 0;
+}
+EXPORT_SYMBOL(kasan_poison_range);
+
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-2-ethan.w.s.graham%40gmail.com.
