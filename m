Return-Path: <kasan-dev+bncBAABBQEKXCHAMGQEPFU7ZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DF5C481FA1
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:12 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id d13-20020adf9b8d000000b001a2aa837f8dsf6532610wrc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891712; cv=pass;
        d=google.com; s=arc-20160816;
        b=IunM5WRA8MNd++IWpyKgpfgGyXZ5F+W+h/C1fELzzNbmlW4ybdJpBOoJVkBYSnNcwZ
         YoeLb3sqUR1Ck9qSEW0cUpEnCy0lzZD/OacH1aRSD6L/6Y2W1RrdxPvITggEi1Vfg+jO
         9GTvgPw7/ViMLLDRiapLSAAlFzfRYhuudhUUrWEOJARLemQ/zUIvzmqxhcwnn91+EMSp
         sc/d7A8iNJv77AZeMP9e5EEhty2fhe/6qlpYdNHPTzSWMRxacQVQU4O5keeWQavqYIXA
         xmxLZrr0g3XMrYF+X9DLmPEIz9fQnc9NtfL3EYk+HkoZixQotVGaJJx+JTsDBG4K92SH
         HbUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vK0ejOE8bsiNFNI2cQ366y0wVlj6ByxsQtwYbRMG50Y=;
        b=DBEh+EqlHxJc7JvSQTdIvaHOVu/Lqmq5AWWqpjAWnPFzd+u5Re5rT+ht1NXslerdhR
         zvMA3SNMUfyYqdqinr4pXSBgKcoMEithnvSPfxDttR+7RmrD1nyCuTTMn+1wtaU5MWCb
         sSR1MVa+rZE3UH61zpY6nyl6iAYO5Cbc+4C/hWdzA3+OrTqFbSO+QnyWfONn30ofsxvL
         VJlKY3XQOIbs0+nyn8aBz8CryjVj2iRXpgiRY3G0Vcd0E4I6mVWrQ1bKxfS/vHdhqHxw
         nms7IrDBgJYkQ/2ymsQbdsn+26myeJ6djqbaTwlOG6eEN2rytXL0Bs9vFhvKejTifxbg
         OfFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hTVLkp46;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vK0ejOE8bsiNFNI2cQ366y0wVlj6ByxsQtwYbRMG50Y=;
        b=Ve63UsHyi6dLFdy1CU2VcUNnDJiG8E4ngud2TBHvZQql3RoJf+N8DwHYxTAnj9tyjj
         Osq1VcscOo9Vkz2HPY3R1xlYKD+SMDvYAAAi/c2mr8+6B3JII3z7I18Lzasw5L2HU2sa
         yLdTB2gGfju8cKRs62zvgXi57XSGFFzZrKLpbq76SOm7i+29ezQwcRpjtkT8wK8g+gV2
         gKC30WRWE0aKpUHfW8V2ObdiyjKW5pU0LG9DbqOy8GBwsmDC41ZTCr7UxS2aRhBG80K7
         T8SaG5/ASJs9pdBb5aZ7WCclSndt1YvoAk52XPAPIYpDkjuCh4GEotftb3aaNtG1Ig49
         2klg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vK0ejOE8bsiNFNI2cQ366y0wVlj6ByxsQtwYbRMG50Y=;
        b=01XAiu/NZpJdFs7AauJTlcVi4jXdnmxmB7xuOEfchUrTJvmoqzel10P7MhcPoxvqsL
         Mw4tpExMMpycemIATv3pzkwK/OJQCR1bH6OryaWoRvE3ojohvf3OVs/yjV8MEzrcH54A
         QHXZidAc8BLqQGE9B3N3z/mYY4oq586V7DEkotCurENmcHk7G9l1+dsl3LwOPashYQJx
         GFmLi4ODkfakZotOBzqHib/XzGQhgCXGFvmLefeT6wqnZM9Ft/MWaFXuNose685dV/MV
         E5RnONsv9CJM2oyPyEnHUYXW7hFqMkVG73QRLBaP/W+HLdtCZq8y3iG0Y/iBAj0htyfx
         bHaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530L1IxluEpJTb1zGvLSglahfQ/GmZ9WPxryTpIMm5MkeSPhtUD4
	F8OD1vT/w7eqRlBCyTXzC0w=
X-Google-Smtp-Source: ABdhPJybQexfYlahV8lDHCew/0IL2mYoDbBewUUdc1uIRi63kQW0E0Q1nIul6wgZ8goV4ARp/laQlA==
X-Received: by 2002:a5d:46d0:: with SMTP id g16mr27576633wrs.624.1640891712243;
        Thu, 30 Dec 2021 11:15:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls302767wrb.2.gmail; Thu, 30 Dec
 2021 11:15:11 -0800 (PST)
X-Received: by 2002:a5d:5384:: with SMTP id d4mr26625682wrv.121.1640891711689;
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891711; cv=none;
        d=google.com; s=arc-20160816;
        b=VH9E1s9T7oD4kiMSmeXUcKsOIYaEfJstdZyxfbEKS9lBKrsZBWZ/vT6/PxUeiIuFa8
         9vpYw20Hx99SyuYJnJXC0lUutjEO01tHeETQmAmTTWiqHIXzVrjSKu3Zt/B2XjN9didm
         YDqkRH604p+FPYFyNPR7j+vUxFmAQYFeuJddALQDyAQWP2F0YXaTFj0/0MqZfe3gLbx/
         LrC7EulWo9Lb/HAXDR7j1+oNvET0MwSH3C7J3WMFS3itMXpMa3LGw97J5lF3HkpsVVZG
         MiX9ZeKfUQNZNo70HzM6DmM0ioausgprekZ7dpi6aN7NlINxNGBUx2QaYgFdqEgPTdyv
         0VQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zMk+i6psUWRrJkriJ76ixSA3XRodREnil0b2HWyShlc=;
        b=ya8KSfyPiq7dQt7qRK7c5IhqLKPA7wjzctNDU1cXZZnzenaAHLeRAU4MuDt+f0o0ul
         DGEGBsv2EPtkdTruqMYr65hUqPkveKZ02OFHoI/fVWICMilr0bCoNOUKsdrUAJHuGs7i
         SloohpAtirJ7eXbXBN/DkLvTptKTJpBcTAvx55Kzt0pI/D/Qb7awG7KELajwJ6m6fYIz
         fNT+DeC3LIZI/OP9yjpCVRGlNCMsmwdDW8KiO023dD2STTBGVKrxAgNWkncnqXXlog6z
         5pfiTQkXlivNn3NS0dFgP8OTIwJjGUnjdJ1/KKneB+sQj17fGGXy4nuZjy6wNlHi0xDT
         PAzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hTVLkp46;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id m12si946602wrp.3.2021.12.30.11.15.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 23/39] kasan, arm64: reset pointer tags of vmapped stacks
Date: Thu, 30 Dec 2021 20:14:48 +0100
Message-Id: <c2d4db71b1c8019845719fb40b95dc749aeff25a.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hTVLkp46;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation in
arch_alloc_vmap_stack().

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the SP register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP register needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Add this patch.
---
 arch/arm64/include/asm/vmap_stack.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/vmap_stack.h
index 894e031b28d2..20873099c035 100644
--- a/arch/arm64/include/asm/vmap_stack.h
+++ b/arch/arm64/include/asm/vmap_stack.h
@@ -17,10 +17,13 @@
  */
 static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
 {
+	void *p;
+
 	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
 
-	return __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
+	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
 			__builtin_return_address(0));
+	return kasan_reset_tag(p);
 }
 
 #endif /* __ASM_VMAP_STACK_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c2d4db71b1c8019845719fb40b95dc749aeff25a.1640891329.git.andreyknvl%40google.com.
