Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHXOTWBAMGQE5OONTGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 32F773326FE
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:47 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id i26sf5659707ljn.13
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296286; cv=pass;
        d=google.com; s=arc-20160816;
        b=rgRHq0C+nEUr2RA32SklWoxeQPnzyWu+7rScjZcY6BxzXzo0Ac3L/UurqbfguMkxt6
         gPUm/p0YToa6phVjr63T6WaLkAIS7Xdh2p1tlXKqTuzF68lUevpcYcuAOejx0Dvxba0C
         cdjba2xcEwxrg63CQKW6GDUbw1eHQLTnzHM0HLk4rlPJeVPX41bCRpLMzkqTJpidtDb7
         R5zyYVyKR2gBdbjNWLUgLS04jxNcfFD92ylyVFnJI/j/boSap1KH88KDhqRp1sy+vvMk
         aYE07yOBCsdjEKDmWCsG65e1b9v6QwTSHu81HqkWl2DLKt3jWjOxQfhLS6Rtr9E4cMb4
         zLkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CZQBJ3R2aj6PoHXxz5O518LkdbcWvNm6Foi8Q4qKz8s=;
        b=YHUfAe2h7yK5pZIWCLIPGx5R6aEWwyLtcyFGkrF4r0JRyALl0Vp04NvwHTb/HKRst5
         p8Z5vtNOsPQYii7fjJrnzo42oWeF3ui3Y5pqJh/g0AjVRb6qfblqg2q08QZNqMv2WsU+
         zutHKF8nsjQaB7M5ERl0efGTQJ8YgbZp5SHKzD37YVKGNsrFmEksB5dxgNQFbCnAbtlR
         J7NI5NWF20BV6Ur54DlgCZTw9UpvOg/BGBtn09PZisWYcxPqdiFufgDREorHjCZpgcmF
         bVPzkxGcY0rah+MvvjvjgyJNWwDIKvy/GkEGJ9tgFUVuqWPWZKfYsGzqYd4mZZ0jHxZK
         qBVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l34afbqA;
       spf=pass (google.com: domain of 3hxdhyaokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HXdHYAoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CZQBJ3R2aj6PoHXxz5O518LkdbcWvNm6Foi8Q4qKz8s=;
        b=lE7sonCGU1KVANvcOgrwszizkvzGdj/OhO3dWuNUbJWM+6ectqOQbA0lv/vUnUKMDj
         NZprV1mX0D4SHBiBC5nvf8NInDaIqIyEpw1RpazxXEsMfYYhHu3iQqt+D59mWppY3Yf+
         +DX5JzFlQaBNVshgyjbw+oMhMczq4MTnU6oIymWycozUJqNYb09JxtTCDa6Ir9L1remy
         bs2+WCkyGKrUC7KAfsRc4UE1sazE7amjeuX/59YZXiBjb1j03IdqrjIq4MdVvDgPfclU
         hZjiMYT58JKn+5GnatGVJRsj+TFyeUox6/HOs2fdGc10ta5wwK4FcrZmbcZ4fMv5ZGL1
         f0tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CZQBJ3R2aj6PoHXxz5O518LkdbcWvNm6Foi8Q4qKz8s=;
        b=RBPC2Cd0FnzLnT/un7VNZZDK+CssoVRMik9aPh4+VNPTno1zn0LItaxK/ezQgcyLgN
         nw1vVPrOO/7I2JvUtjsgZakRxjj93/nRGojp/FyC6zaTymtbrIMvpsu+hB3bcPpEOUaZ
         rQ5dUc5OqXSMew9cLPWM8sq/be4t/T6RCXhnhjtgu6Wzlv5Fog9VOHsW5iepc4Ya38aB
         cjDDyT6cHDh4jGx3TiIYFV2HCBwcgWA5DDmQ0nUdkBa1RtakqGhhVhTGmUAWAdUH1Oao
         lfwDbtcvoeEE1fLJDlmODZhZ7TcU28nxfyH3aNrTqqbswBFRuzZSHC+ES1haVw8Hc5yq
         BNnQ==
X-Gm-Message-State: AOAM533j2RuYxEgQeejW1cK/EyNvoSrr/78YUh5HlBE35NDzw4tVarau
	Hrf8kgvNESw19qR/1Qz/jyQ=
X-Google-Smtp-Source: ABdhPJxdf7qEkqDrPHmAWMMc16SinD9QbDbxdOFCTBlPqHaHs4j86egzIl3Pe9A7VyPJ8ygs/L12nQ==
X-Received: by 2002:a05:6512:3226:: with SMTP id f6mr17019772lfe.171.1615296286649;
        Tue, 09 Mar 2021 05:24:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ac46:: with SMTP id r6ls3816212lfc.2.gmail; Tue, 09 Mar
 2021 05:24:45 -0800 (PST)
X-Received: by 2002:ac2:5e9d:: with SMTP id b29mr17326476lfq.31.1615296285658;
        Tue, 09 Mar 2021 05:24:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296285; cv=none;
        d=google.com; s=arc-20160816;
        b=hO/gy9t4Onv/6OGXxoq0OgOJHAn/6Y/wGpWbNyQze5S+an+XmoEH9l21B82C+7f/vL
         CPXSEIhpz86/wIFwyhx16FkUFaQhJU9uxgPcw2joTXPhZkGWbSelCO9jVqU3rM17vF+j
         cqdmucAdUGZVdXO+PnxfnRbEazjotg65MoZrSfAj7JpQ3AsEnn0qG8sYdsGfN0hnBEYj
         rUsQKWuBqvSiiSLDftr5Lxb1HOBBhbkztiHbaSYrAbEYxwei+8E7FMZ6UEEYPFy1QJJp
         fUPfvLcqczlvaNAX+/Bm7KGmxeQqm+oozpQl4ueEQs/msDRrRreFSfkBVikZzrTI2cGf
         GDTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=l+UpHCxZ2NwdA6Wfc2QV4OtHQWAx+WJePRBQJIJEiJo=;
        b=Y4o7WGO7tTZufa7oLD2MEcHy3YfXafD2L/2HFuAWGuIX4LMu8fJWN1ZAVcedubf7KD
         zr0XOOr815kKORXLuLPl8g6OZS/lyhYu2wFYumzu/km+xNWIFkCciaj2TJxPHV8DrGS8
         auqpU6Bv/xNYm1QFrwGYiS6wVymuymaDwawUNm/kRKY3MO8un33bw5ZxeH1FSt6IR1Yo
         6p8JrVMOCkz5/5QaRNsvP3BJIdLMPegPL5np3dw6glEwbsDE3D2FLw1G2C9nUGV2BgL/
         6/U18PPAtrav0YGOQ9rmnO6Mce7JvuqeVDJrxFwbdMkk7DyiNAc0WdGa76zNdvrvInkb
         5lDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l34afbqA;
       spf=pass (google.com: domain of 3hxdhyaokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HXdHYAoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d19si575265ljo.1.2021.03.09.05.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hxdhyaokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c9so431959wme.5
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6810:: with SMTP id
 w16mr28447553wru.333.1615296285067; Tue, 09 Mar 2021 05:24:45 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:35 +0100
In-Reply-To: <cover.1615296150.git.andreyknvl@google.com>
Message-Id: <d04ae90cc36be3fe246ea8025e5085495681c3d7.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615296150.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 1/5] arm64: kasan: allow to init memory when setting tags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l34afbqA;       spf=pass
 (google.com: domain of 3hxdhyaokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HXdHYAoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/memory.h    |  4 +--
 arch/arm64/include/asm/mte-kasan.h | 39 +++++++++++++++++++-----------
 mm/kasan/kasan.h                   |  9 ++++---
 3 files changed, 32 insertions(+), 20 deletions(-)

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
index 7ab500e2ad17..570af3e99296 100644
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
 
@@ -63,18 +64,27 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	curr = (u64)__tag_set(addr, tag);
 	end = curr + size;
 
-	do {
-		/*
-		 * 'asm volatile' is required to prevent the compiler to move
-		 * the statement outside of the loop.
-		 */
-		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
-			     :
-			     : "r" (curr)
-			     : "memory");
-
-		curr += MTE_GRANULE_SIZE;
-	} while (curr != end);
+	/*
+	 * 'asm volatile' is required to prevent the compiler to move
+	 * the statement outside of the loop.
+	 */
+	if (init) {
+		do {
+			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
+				     :
+				     : "r" (curr)
+				     : "memory");
+			curr += MTE_GRANULE_SIZE;
+		} while (curr != end);
+	} else {
+		do {
+			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
+				     :
+				     : "r" (curr)
+				     : "memory");
+			curr += MTE_GRANULE_SIZE;
+		} while (curr != end);
+	}
 }
 
 void mte_enable_kernel(void);
@@ -100,7 +110,8 @@ static inline u8 mte_get_random_tag(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d04ae90cc36be3fe246ea8025e5085495681c3d7.1615296150.git.andreyknvl%40google.com.
