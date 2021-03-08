Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3MRTGBAMGQEUAX4L6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8074F3312A0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 16:55:25 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id k8sf5207163edn.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 07:55:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615218925; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rbj2oeG5M4GA+DRfzcp/BHNaLW5yRLKDtF2IIdARylgMN/L+c6ZiMbd/3kXDA8XP8V
         VNqg3Ce4Y/h0Cp/G48g3m0e2sd9GF2ML3xdqNVWsYtyg53+fWpI/aS2jxqifzvsvANZP
         V/OLdozZVm3f0+OxuLsGLlGo7MmMbcZBBfUjVxjSfqCWmgd+Kzj1wM29/HHwtNDBJJu/
         +z+/M0lYErVPbJOBUnRbVoytFCLA7LM9hJHDeKHMtXAVKuqvVxh4doQjlbnb3TQKI3qk
         DnoKvr/n8u85IPlbyUa190rG4cvr+Rs3BpGg5puIuLT/pJD2tIYfB81kPibhq6d77QYD
         QJ6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dHfXTFF4pSFfX6AQiIpC0HScwBq5GsyOfv2ORnaRk3k=;
        b=Q/r87Arh+mJdTDdDe1PDjHuoHgG7G5LvVGMF/j9zSUoxd5YLptNghwqghPdd6fyOLJ
         FP2ZZr6euSguveRyZEOZSVOm2vgzIj9waHpgEI7oXmnMWs0oaHG1XP/QDRrAdTl70fh8
         qse65I0TUyiVhUbv2yeh5NWIuw4MYuhX9FkLB1KmF4JRjdNEw8cSbEWUVSpb70ZcpEtA
         DIagf78lFeX4ejAOi8JmTkBesU/C4WB9RwaLyXGljns1Lzn1ASj0PBA/44rp9n00N9kh
         9KFpTIrXATRSRXgGhYH7JUuvjuhPY8k/mork1UbyzdqEjdEOmt7OzAoIPiF2usz43ay6
         6Osg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pB4bszXs;
       spf=pass (google.com: domain of 37ehgyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37EhGYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dHfXTFF4pSFfX6AQiIpC0HScwBq5GsyOfv2ORnaRk3k=;
        b=N+3sKzj0QtL2FpLJTp2zNtm3L5r5hIAOhwJTpS2Z6zs2xU4RQ5YB1LGIHHJ0DG4yO/
         EPHYHxetUlh+oDCIQyjt26qVJUhGpQrcVMsx7Wxz11i+onve5KdYS9G6qFE2BErV1YyY
         96Ud0wls/UXCYmMFa0PUK6rp3TzL3kKIxPXkv44bMsHgCP8BBej2hZ6scR5nnqWoILaJ
         qvd+vIiysKQ1efMzKAI37bXLKs83XeaF7tbNPCQFeSLzT31Btjb1G0Tpb/jSUk/szVRU
         jb6bDM8rpenMQNauovGeVfCRIvfjiKzpH5y6+VCHiKSZYoq3HB4lChTRCsdRu4qXWK/X
         YXrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dHfXTFF4pSFfX6AQiIpC0HScwBq5GsyOfv2ORnaRk3k=;
        b=CBiTmn8/fpNA4ZIWiTehsLZ1VrJ15R01mY5y9ecJy+hbBYD3zcu14X01q9hc2Empci
         4mu7YeIpgFDhmb0QQStCEx3qxQYRIOosR9EDriE35/N4Ip9PEiv++Vi8Q2v/ohS9ms62
         KZukZuWLBOC7WOVioa8qQ+QcrwYIyl61lZqtYvX/RZMzhk+YjPG2gsefihnEKLiu11w2
         YltUzRaYTKseTaUTBS6GQrs486ObR4Hss0ZwT4OzPIHTtURA79Fv1TBFuOTMTuv5lwRL
         XFOlTmYhFTXQgG4EjvP3OXPfMG4vgYnaXb+d7UJp19vd/SMWKZn+RuH4g2ClbJMuVHSC
         y+9A==
X-Gm-Message-State: AOAM532WcGXvZM1tGBl0B4KYnpv88KpggOcVJmKoCZJAVb8siyh8b7f+
	DeaORrYzCdD21dRX3PbSORU=
X-Google-Smtp-Source: ABdhPJwKTCkmKvxo+W3KhWnsncC3nhwtxmlpeQT4EhgYWy3PoROAwkv0XaPUBf1HADm6Ixp75G+wSQ==
X-Received: by 2002:a17:906:c09:: with SMTP id s9mr15614740ejf.539.1615218925250;
        Mon, 08 Mar 2021 07:55:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d788:: with SMTP id s8ls7595748edq.1.gmail; Mon, 08 Mar
 2021 07:55:24 -0800 (PST)
X-Received: by 2002:aa7:d3d8:: with SMTP id o24mr22714826edr.165.1615218924406;
        Mon, 08 Mar 2021 07:55:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615218924; cv=none;
        d=google.com; s=arc-20160816;
        b=pJV/+OqFuVWlZ3qgSiLqcRFgMOJTC5KWzYWF+LlWf69hIqcqoFPmOXqJUiYuVx4kVx
         ZxajymZgK/xccXC1jlHsNAR+VGHSXvvskLPkivigqj6Ck3qR/F3TXPVJa06EaxVy75i2
         Dhmz9L6KcMROExDEJA/nB7cJTrUh3lKsmduBnUMnY9EEunqqumOZY/dTPxNHXHftuG4X
         tePCCxEsyMfBe9ubZJUCDXEqKkFgrCdJAE9mXDpLbtwN9MqMH66vTEkn/oNRxLhS+EjM
         MvEDvG1IHusiY+1NC8/xp/exE6k95DmAE0WwLpKYtXu3VwnsufPwcg5+oZsenF/dQ+5k
         R3BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/BAO9ttHzCncRHdq2i5eu5LhUmwsdIn4HIy1rtrNRFc=;
        b=UNSVs608E93a46Q4UtK1AK+nOAZNSXZeMWM6RsV+6PrpqxI032zmZxQ7HLZ3hYdn6d
         /1B6vFh+vbj3E4kuIWS99vuLYDY33ksvtsWrirDHnVF6IdEUtTe/J+znjA5/sEfC7LWp
         gIJQ6tmg2Ys5q6BI2xGk/kp6u5KVAnPSIDlsJdHPdG1yUuoV+vBTwcMZTQj0eJbO+sUL
         2v5CElwA2Y9sC0lKPHz5KdkxIh7NRgtqSuUv50iReTzOpM8AAxocSDE39d5P3wbefngd
         a6ie1h88ZeqP6v1UAijGXE6Gn7xkiXt/yux0XlJTMlGXypod5oNkeZ0XIvAhmpBmJxyy
         ccaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pB4bszXs;
       spf=pass (google.com: domain of 37ehgyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37EhGYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z4si373870ejn.1.2021.03.08.07.55.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 07:55:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 37ehgyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id i14so5124830wmq.7
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 07:55:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:35c1:: with SMTP id
 r1mr22344025wmq.60.1615218924080; Mon, 08 Mar 2021 07:55:24 -0800 (PST)
Date: Mon,  8 Mar 2021 16:55:14 +0100
In-Reply-To: <cover.1615218180.git.andreyknvl@google.com>
Message-Id: <755161094eac5b0fc15273d609c78a459d4d07b9.1615218180.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615218180.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2 1/5] arm64: kasan: allow to init memory when setting tags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pB4bszXs;       spf=pass
 (google.com: domain of 37ehgyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37EhGYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change adds an argument to mte_set_mem_tag_range() that allows
to enable memory initialization when settinh the allocation tags.
The implementation uses stzg instruction instead of stg when this
argument indicates to initialize memory.

Combining setting allocation tags with memory initialization will
improve HW_TAGS KASAN performance when init_on_alloc/free is enabled.

This change doesn't integrate memory initialization with KASAN,
this is done is subsequent patches in this series.

Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h    |  4 ++--
 arch/arm64/include/asm/mte-kasan.h | 20 ++++++++++++++------
 mm/kasan/kasan.h                   |  9 +++++----
 3 files changed, 21 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index c759faf7a1ff..f1ba48b4347d 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -248,8 +248,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
-#define arch_set_mem_tag_range(addr, size, tag)	\
-			mte_set_mem_tag_range((addr), (size), (tag))
+#define arch_set_mem_tag_range(addr, size, tag, init)	\
+			mte_set_mem_tag_range((addr), (size), (tag), (init))
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 /*
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 7ab500e2ad17..35fe549f7ea4 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -53,7 +53,8 @@ static inline u8 mte_get_random_tag(void)
  * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
  * size must be non-zero and MTE_GRANULE_SIZE aligned.
  */
-static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+static inline void mte_set_mem_tag_range(void *addr, size_t size,
+						u8 tag, bool init)
 {
 	u64 curr, end;
 
@@ -68,10 +69,16 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 		 * 'asm volatile' is required to prevent the compiler to move
 		 * the statement outside of the loop.
 		 */
-		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
-			     :
-			     : "r" (curr)
-			     : "memory");
+		if (init)
+			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
+				     :
+				     : "r" (curr)
+				     : "memory");
+		else
+			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
+				     :
+				     : "r" (curr)
+				     : "memory");
 
 		curr += MTE_GRANULE_SIZE;
 	} while (curr != end);
@@ -100,7 +107,8 @@ static inline u8 mte_get_random_tag(void)
 	return 0xFF;
 }
 
-static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+static inline void mte_set_mem_tag_range(void *addr, size_t size,
+						u8 tag, bool init)
 {
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8c55634d6edd..7fbb32234414 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -291,7 +291,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_get_mem_tag(addr)	(0xFF)
 #endif
 #ifndef arch_set_mem_tag_range
-#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#define arch_set_mem_tag_range(addr, size, tag, init) ((void *)(addr))
 #endif
 
 #define hw_enable_tagging()			arch_enable_tagging()
@@ -299,7 +299,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
-#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+#define hw_set_mem_tag_range(addr, size, tag, init) \
+			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -343,7 +344,7 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
 	if (WARN_ON(size & KASAN_GRANULE_MASK))
 		return;
 
-	hw_set_mem_tag_range((void *)addr, size, value);
+	hw_set_mem_tag_range((void *)addr, size, value, false);
 }
 
 static inline void kasan_unpoison(const void *addr, size_t size)
@@ -360,7 +361,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
 		return;
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
-	hw_set_mem_tag_range((void *)addr, size, tag);
+	hw_set_mem_tag_range((void *)addr, size, tag, false);
 }
 
 static inline bool kasan_byte_accessible(const void *addr)
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/755161094eac5b0fc15273d609c78a459d4d07b9.1615218180.git.andreyknvl%40google.com.
