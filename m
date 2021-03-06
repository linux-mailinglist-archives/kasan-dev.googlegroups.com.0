Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQUTROBAMGQE2I2DTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 88F8732F725
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:02 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id x9sf1760206wro.9
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989762; cv=pass;
        d=google.com; s=arc-20160816;
        b=HrgHuRF13pBGptK6tatPU8fCPzMSXHxe1xmLprNZRNDqviOmko1ApKvwnlH4DYDNxI
         bmzMulYwrcERDTJTmea4zs35gqqcBWI1xAeq90mx15vVincOMB9cloPwHKjp56cRHMOu
         XoE1Rlea139MaX15Yne2HknfkQ/5i55vn71yG86U72aOwpVHoTaf19pdYLdT6aE9jt7p
         6i7oFkMQdUWxaBTnuPH4dYDdZwYi5FhdQf8/bSDGmYzfTHn4SIW3R1NKsWKER26nj7UC
         xZbzz2Uv0AE4ZkpY+7CJxTgaO0im78rWj+lzo4KIyFvdr20OZ4VCLThmPCVIvn0OgMQI
         9aCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=AUWm46jeUbXYdTBbG3CKv7I99G08uuhZi+HwRvx5lXE=;
        b=ak/GhA06pPpzXVqM6AJvKiRWOYksTeNgtRxZuG5zSoqAEm0+D0fdwaT+FiB76y6EUZ
         vOKeFhFltutmvIyks0P5sLIyOYxIY3xNYPaqAGtEvfBZdUk60mRmUwD9VaDJAut/OH+3
         J2whlGq/rEwAgGeR4Ma95Bo45A9dVOqTruheSAw4LJEaENhNie6DH+FNPEXIBZkG/yzj
         pfW3IQfgEAVDQheaLMZV4dJpEUanZnGy+K6GuntJGsZaKQEC1GHWZwyEulTHUXPoNiFd
         AVTLcLIwdH9clJuRPGRO48g35PQI2z4NAnx60c2WuaURcvwjfb0UwtvE9SMY4NW2h07e
         WWqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WPOHPdaR;
       spf=pass (google.com: domain of 3wclcyaokcwggtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wclCYAoKCWgGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AUWm46jeUbXYdTBbG3CKv7I99G08uuhZi+HwRvx5lXE=;
        b=mTrq8KMD4Wp6E05+tVbQk12pAhseCmPUJc8iedp48KmVLUUgVNow7HiZ3BmLy4EIqh
         3tA2ZjIj/JJ1aFnYrfTTveb/LW/1rs8EnaoKeohi77eyz2fcTFUPjwPJ9xFqhoWk28MB
         /f8skHGQclQCi8pR9Jb+s8cEnM0rHReJv6mcVsLNzqC+N0xzLxKgcYg8sc1fxcXsDv8C
         myuqiXUpZtNE9YjCuScp/e22iK2H4jDBscYMNE5n+vo0I4DdKT44e+0QQ5z6oZEmc3bE
         RcvIW2DjTEqxRwbgL6x5A/K7UGHC+Odn7WMf7MxEzwDED2mMa+cKh0vOvnaYEb7aIYYf
         AI/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AUWm46jeUbXYdTBbG3CKv7I99G08uuhZi+HwRvx5lXE=;
        b=Htyfopdq2pUKViNmmabXR51N3iQgp34FW1sr/yySCzNG9MCgYduz2fdIM0U9VBkesA
         EjL0C6TaJpkLvMomerMwZB03SkgfSVbPXFYHYhbksnkEN3rqHmBG5sUZA6g4/J3WvBT5
         0KYs4h57xdmlslUgI/3Ivcq39ZhB8iKP5VTLGyUek22xg7gyfaJ6moJsaOAV135Zixim
         vPF8eQzArIJm/sePgpsecrPKEbLcHp6eU6+XY1pECpHM7M8EBNkrKP1lmYFggsbLH1tb
         g0tVROUY7kGPUu6PTinnHyCgryBWJlIVcUxl1sQLExAiT/nYJiQFbXr97g9i5/IWTlp3
         Im8Q==
X-Gm-Message-State: AOAM530xlYro3KaDboRvHl71zAbITuAukWfyyOu4Zmpb69wBKieeDV59
	Jylroe6sD4KyE1D1l/TJCVk=
X-Google-Smtp-Source: ABdhPJxc1+dqMc7/+Lu2w4EnpSh+QVL4/QVLseEg+j9Xyv0eJK6ry/8jGMXqZfRW34DZIrqtHJ8wdw==
X-Received: by 2002:a5d:4fca:: with SMTP id h10mr12324281wrw.70.1614989762384;
        Fri, 05 Mar 2021 16:16:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1981:: with SMTP id 123ls5490605wmz.3.gmail; Fri, 05 Mar
 2021 16:16:01 -0800 (PST)
X-Received: by 2002:a7b:c010:: with SMTP id c16mr11488679wmb.46.1614989761568;
        Fri, 05 Mar 2021 16:16:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989761; cv=none;
        d=google.com; s=arc-20160816;
        b=0YpPbQo2Iv5O4g1kPPDXSADx8C67kKKyt3TiJe1eVNb9vsI+NtvV0Jg3nmQdjqQva1
         NdZI8lTmodJ2o94up2lmlk25EsqxAGJq+CL9NKA6DCTaGhYoEuKBGvo/jPrfUysW/tVl
         yYhhD9IxPPwAsPr0nA+3fxG5RVGNhqRqfKzbtNLBknDVJaLPcK6FA//9S6Ne22EG6VCB
         fPrKezyLGrooebWLjyQCqAqdNYOn4ALFm/WxHQUkFdZr/HhOi6UqrO1oLggQeeKee6U6
         FrQ9l8swnNRreEAZXKwlmq8RVZXkmMTbh4W0cLCsId4e8/zoVbYmr0e7InhQDtsHeI0i
         FfTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0Q6hAqH6fyVVw5hCkpEOYFgiWfgnj6qL15/X+pD6J2A=;
        b=b6ST59GfNlwwEklBP7py9+NpQus2UW3l4mBxLh93TMBKWsu2HA6t3hvZVvvMHVBV/M
         qAY7XjgZsKcnJSRHyDys2JwVeCnYBCnffixrl9j6ip4xh0NjS3+fRGcPtZVYIr+Q6XfQ
         Vg09Hsytd3vDXy8MXxM+L0rbJA1WnMpbcexgFzEAOLRRVAoKOGDbaAbF9kLqgo/r35tU
         pLRkN9REE/xNiJEsubK9Vd6XgaouKralavaTknht6gspEzk7td8+LY1nRoOGQknvtuQ+
         caUp7dyFZhuUfYkOvQOgl8r2HZGo+jOU6vOFyGkJxpfHtnZ3fzItUWQFVyBQHwvuG47Y
         Olhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WPOHPdaR;
       spf=pass (google.com: domain of 3wclcyaokcwggtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wclCYAoKCWgGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id t124si570733wmb.3.2021.03.05.16.16.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wclcyaokcwggtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id w10so3982369wmk.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:16:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2109:: with SMTP id
 u9mr11025313wml.44.1614989761143; Fri, 05 Mar 2021 16:16:01 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:50 +0100
In-Reply-To: <cover.1614989433.git.andreyknvl@google.com>
Message-Id: <e43afadb507f25dfb1abfcb958470a3393bfdbf9.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 1/5] arm64: kasan: allow to init memory when setting tags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WPOHPdaR;       spf=pass
 (google.com: domain of 3wclcyaokcwggtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wclCYAoKCWgGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e43afadb507f25dfb1abfcb958470a3393bfdbf9.1614989433.git.andreyknvl%40google.com.
