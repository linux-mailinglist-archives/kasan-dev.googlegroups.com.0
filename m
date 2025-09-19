Return-Path: <kasan-dev+bncBDP53XW3ZQCBB666WXDAMGQEBZK3ZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E68DB8A1E2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:05 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-3642513cb90sf4829391fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293884; cv=pass;
        d=google.com; s=arc-20240605;
        b=AAIY1oVAAUzBM4NikIEGcqt9jtRPlCZVCgbyqOe4k3/uiEgLvEHkV0rZo9zo/R6MKc
         0WiJcG3+wFkqBsob9fWiNqKvgzvRa8xdQrIvAxuglp30bK/8e0bR8/DvOVkE7XqNZjtI
         fO752H38hKT8pzvz7QdxHTnNQaGNdmrsWzHLnSS2DNIqIva79IDVhy70G41KMBHpA3O9
         PkKLdrXF6gUXzyN/c5PZ6NnK/2+mfia1oXmysKbyWsrguq5VcEl45BR38QfA3nTznAwD
         aPvheobNDviHJY5zX2S5izYHlfPsbrXpfydlAMA1ovq/gHRGl4d15QsT+wntpNbmm/Sz
         N46w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=pX66nrCJp8b0NNcJLZsaj0zrhMPVTCba5vmg04/mf9U=;
        fh=TdsNPqizJ+U1n5IyTCsI/WNl49biowwa1XVYdrXTBPY=;
        b=Lan/lyvwEoGPaV0snZxAUfGWfRyXmbSLc5eHtDDfHRoiR0jLbXq+CsXcNfUqByS9Wo
         ybBzjiw6kTXAPy+QJ0+wMIOqLUz/hDzYHsZdZ6LDyQ4zLTiJT9+xCrqflxDpGa4V7dHw
         63bwzf54iFVDe7kjp3d7Cfi89Q9sglZJgSjcvjaUfB5GqXQqTcWVerGHoY8rGGsfZjY+
         LBk38g5FAHlZ+OMBRbhpD9qEgX/69D67CPPGTO+tvEs4/oETGEPgT/C0ld903JSP1RA+
         2sVYqwXXl/6U0mvRqSIug7mvXOPCBbo39sgo0dcolFR9a07MZ3eNn5wmeuCu+UEs2hsV
         r1ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jBPkIBO4;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293884; x=1758898684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pX66nrCJp8b0NNcJLZsaj0zrhMPVTCba5vmg04/mf9U=;
        b=oD7IDkEZlJH0jq5TwYx6gNftaKmnBw4ozDwsduNN7A9sgPhNeePNddt6T6pOEkebC3
         YPOtOxjRksr+IU0ly1jvBDBOxMRnxg5spJoH8c6bW6y9//sxSE3fZ8/BPcym0Kxlf+ow
         nbhlO1Qmyb3NsMNN0q1tzvt/5lLPNlkadHl6l2aD2ujkooaiqPK7ChpjiVSVHOJsVvPp
         GjfJ8HJsbskgEiEgaDgEiS0YbGKWe1xwrLaTmBPrQ+jMRzGKtcCCqg3mO8drEl/vlz4s
         OGCUu+rtOPKvqdKWe5Zv8/bVKcAxpQNs5DAeDt6R6t9rDJOywQQGOzwFEsXLcqiqjVh/
         YA2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293884; x=1758898684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=pX66nrCJp8b0NNcJLZsaj0zrhMPVTCba5vmg04/mf9U=;
        b=RvSU/8yGVrvt3io+wO0sVM3jwIj2kiMoLybPxxCusrRQFF4qHRF7fRTZqAuEIod9mN
         GCfFlRxLLyEGtHrIVd1SFjzb8mmJWwttQVE9VTk2VDv43veJ73Im46gx2xQvny1l/w4/
         En24nVsmqz5XW4Uf7ogWt9BbCvvppcTeGtcWYbNQ/r1hPJoCR5w2e4uIXo4q8o10Og3X
         NzwHZvjAcpUwsgCVnhKhwwMdPtAJ8qy2FNxmVBs8k1+Ejs2LnG2QviT/H3MR4X418qvp
         b4DKh0B0JGxs/FRr/4QNlbZygBS0fY8QgL3+hQew8nIs3Tzou+m0X9sB6BWsV9Nn7RH+
         438g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293884; x=1758898684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pX66nrCJp8b0NNcJLZsaj0zrhMPVTCba5vmg04/mf9U=;
        b=rnlf43S+ltxLjAzxXqRTajSIfceqV8gXMp6tR0X2wXY53ibWR7Iy0k9KqS/MHldlIU
         3R35rUeSKEfc1h4w+t8tgHsz4HmNtIPN33Sn5Uj7oIVkigwhv24VQm3i9likrWzwZj6l
         TjeZdSx5xVrJFbonouBbgIDU8Fc3b3VdfboQ1cP6oSm+9F4eYOUFOwKUxhE+YbYE2tLM
         gy32gonQXN2YGT09utHOkBiEVZppasTbz9ghxrpePx8kfVREj810lJU7TbPikpFm3emg
         llLENUhVh6Xt7rmyj75kZcpBEIpZ83x3pt0e7FGPnl7UhZYsbEq7nyD2BF8sZMaf8gVE
         svyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXt2q6/x+K4JEwF6hEl/ZhOEkoppxtxc1nM1242X1NBV1z/7Ehma2UC94gadNnwaU9CXv0SAw==@lfdr.de
X-Gm-Message-State: AOJu0YxkNRMGFP44jta8HSKpo/Qav56HDvHHSZ4ayScB4b51kYau4q8j
	dZyO5Sw3IoXnUCxier+3zJwi0lspaWIh6654t432CUijOEusWQRj7WGE
X-Google-Smtp-Source: AGHT+IFnMtXcY5FikUO0UoQgJ+9UGrN0JOV3gAyTxzrRv+Zx13pMQnbyueCuPCrOP3Khpeyo/BjepA==
X-Received: by 2002:a2e:beab:0:b0:358:d359:5729 with SMTP id 38308e7fff4ca-3641ba811c0mr10576901fa.29.1758293883948;
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5NNkMnkhdL1d2LBdpw4r5UJmArK21xulEsd7w+/ICRAg==
Received: by 2002:a2e:b815:0:b0:342:2914:6884 with SMTP id 38308e7fff4ca-361c8ae3e35ls3786121fa.2.-pod-prod-06-eu;
 Fri, 19 Sep 2025 07:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSd0rV4jXKHx0YMI2jCGDGER8bH24HxzJrUAD2y5kmgn/V+AszfLxCy745CzqVeKhGyUPtHk5B4x0=@googlegroups.com
X-Received: by 2002:a05:651c:1501:b0:336:bcfc:a422 with SMTP id 38308e7fff4ca-3641afb75a9mr12486041fa.26.1758293880449;
        Fri, 19 Sep 2025 07:58:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293880; cv=none;
        d=google.com; s=arc-20240605;
        b=bMXM10/prwXIXQZqM3KxuSu6Cqw2reqt3z45RwxkgU19qpgvXf6Gkb4JWXCN1rhlw9
         RMroIipsQwK368CL5+Gmm6RtX84PeLmk0w/5PwyqSy1P58ciA8ZuTPit93eFfQY0n2FC
         TyTdO1GpoUuy7UR2It2Mi+gfQZpGto8WNNbqjBAWsWa/X8BFZU3zOwMG61Lg+n3lDAV5
         DQ+bvVzIO3IwfymoI2/UVYxRypUTzrn7HpMBcpSO5E56J0vsM87rjudNK/kOkcwrrYYO
         tu6cLKTMjOi5PNzl5+hQAvqmznVAUN5+2SghQ90pm4N1uLqPElbjl848GhCK6h9APFnR
         +Cfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Iux7tJA7Iu45JzwDlqqn3NczB+xQmLnfn/+UUn4bsic=;
        fh=FgD4QomgQZ8ODC1nAKJlE7r1TEw/959xexXRAJLHZcI=;
        b=U1Obo+bJkYscYXsCDo+FAnQq1exAOoEfQCbRJEdBDYKy9gzqkZK9bTw7xkbAxWrZUM
         h+oIw4EGhw3/tAEmjmuldGTiPTKxb96DRH6BLSVKJmHoQtIHCpQ0Ec4sm1vO0Hxm1JKS
         T4lsSwsubhATc8dv3XPcu+uErPzRGsdXMQ6CdsMAaYAGVifILeQ+cLh6Yo5JgBFMVHx7
         GQnC/5lAdb/ppZzN6MB7HNdOfwxL59460gK/3sqZPurd8lV4ROvMdp068CzGvEpXDGsl
         pTuwddQT0BjxiU2YRN3xqpouX5uxdxrF/X3cIRvQHkMmrXwLLj+vPZGhvbOI9fBqPJWw
         R0RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jBPkIBO4;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a7cfde68si965321fa.8.2025.09.19.07.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-45f2c5ef00fso17835905e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLa2wqC5Wak9J6fNm7pabGLjyhg7uRbIEQMUp+UibVpnPcvf88fE8KIgT9LWgivHW11DHd6zPAJPI=@googlegroups.com
X-Gm-Gg: ASbGncsCifFG//PfQAbUx7enWuoUoKgQDtWQgfwjdeIs4v4fwd1N6PG9z8wP+Eh/zw2
	aovzot2vLN6myuS7f66wPjKNVYkzsq0f38ZWXq7ya1cJWFySQtjIdrq5M3XKXYY+CkW75885Lzj
	SnOgdpmRLNbOs5TC/YATHShcLjDNbpPuwmWAaw4/ZQn/zshsEfFOtMMsZPrzy/Q5P4IsF/XNS8w
	AkX9xx+6IISq2UlMjiYmj+NS3GvGtEgqzkobE/Ip/vwVJuOq2VZCc7OkonDwi7ve7Pa4xcz1tZP
	0777wSfzaaAXKSjxLmHuaVFQcYFn+0L68dPUu3WySknMu6e/4wU1EgMY2DcZ1cSeZW6/PXcJaWF
	c6Pt/gioh1X9A+gx5bmzcdhvhHmoIvPoWPdcNI2EzEATdvspoyudC9p8XEPSABeuaGOE8Z+R8zM
	AadkdxkeWWGwzcroU=
X-Received: by 2002:a05:600c:b8d:b0:45d:e326:96fb with SMTP id 5b1f17b1804b1-467ef72d771mr33033965e9.30.1758293879733;
        Fri, 19 Sep 2025 07:57:59 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.57.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:57:59 -0700 (PDT)
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
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 01/10] mm/kasan: implement kasan_poison_range
Date: Fri, 19 Sep 2025 14:57:41 +0000
Message-ID: <20250919145750.3448393-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jBPkIBO4;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>

---
PR v1:
- Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
  kasan_poison_range(), and return -EINVAL when this isn't respected.
---
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
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-2-ethan.w.s.graham%40gmail.com.
