Return-Path: <kasan-dev+bncBAABBNH2QOHAMGQEJQBY4FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C9BBB47B58F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:01:24 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id b75-20020a1c804e000000b0034569bde713sf218133wmd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:01:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037684; cv=pass;
        d=google.com; s=arc-20160816;
        b=z+OWYCW3kst7ZtrDdb0zVa/HQ8PbMcYLHM6LxXH24rnmNtqCfrPg7SOX83kDUBA5Xz
         lqb2H+W0LySH6H2WDtf98hKB296cdUKgfCyzr99LDmYEf/F4wyxIeCmIV0umZSwFzFqK
         vAoarRwUZ4+cEkDM4qbJVgVVS+tlZnfWtxf0Aw+vDfY3z2KFCzjfOk2bvCJP0tpa90tR
         +jsgHA4c01l7dUGu7Hz58+tOYxomzrKXK1ro4HZvh0sDxjTwwTMPE3iDJtVtvfKJRhPs
         /SRk1A5UGNbw2XnB7o/ohjr/MiQ5YFQLLlMdF4cYjza+Ty4XQon2tnTXOpBlwhu1v62n
         a/Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+xqrRxf8hM0fZz9RoahlCnleg8SCP/uamLfYqznKGPE=;
        b=QK99RxWfFkjr/da+R3lx/8JGw+moNwFyYRYPd3s96PUYF4+IPq6SAW0hx77MVBTBK5
         eUPaeb/sC7He3LzP5Ous63cmp8Vd8WsadVXGDSckELPu5DEbiSibK2P2g0cR0NeYxQH8
         F/fdn8wthRB1T5nIJxnEtddeBMaqYgDgv4Y0MbGyJecccCHLch4u0YVgvBPRwPh4Dzxc
         eORt1DU4poyfwxzWDxM3aPEahf1gr25T0NLN8/PavEf4X6oUxDuKTtdVIGTJt9yxydLj
         F7eNAqYx4ZNBgn5KS10ApN3IS5Ij7kDkKvjNOflRksoUg9jot+NxI83mMj/HOSax/IQE
         rPNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z6vsEqQq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+xqrRxf8hM0fZz9RoahlCnleg8SCP/uamLfYqznKGPE=;
        b=LsUnDkuPoI4Qq4XSqBMDWi/UkaHs6buIrhUE7sAVLN1aHOLwD0VaYTZorE6GCpEnhJ
         LrF78G+5DTMZQ3Wxi9Ti/kxkVXDIZTyGaxrBFEq7Daq7G2M2wdhC+MXGFqUhDo8lecrV
         Z4WQZcU3xL/Qfs3/Jv/eRc80HEocqz28nVJ0fFCcQeWo+2cQvwb625htl3d1xGH3QBLw
         1P/mWy06F3msrHOP0bh82ZOuShn4rpIGcM0wmsStUU1ButKDEoZXA/m0wzQOUOkaH6RN
         ceAkBv3mU9uus1weFGYpOfxO00QbEzpahOY6fHo9SQk2PEFUuk9YP1LRdgVATI72y023
         crjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+xqrRxf8hM0fZz9RoahlCnleg8SCP/uamLfYqznKGPE=;
        b=aPK3zT0uPO1PutwHJs1FCKyOsqpXaVGliwxK0lNuvCg2eFq5gl5XuHV+bUuFfwd7r+
         vKSKubT1KHIrT+z2Lp3Skic1fnjXt9STwckV9v5Q1MLPJ+OAVJm87MU1dEbvYa8hk7wD
         /id5Jpp8FC0eFjSxGM7Kn16jLCVUGGvYge2TTHzJ5Ax3dsg9VW5PqQCEbLhmxZbbQxw3
         Q4+kWwjtany9MQfLj4CRb31r2iwG6ecSi/XMxlLPqoL8iyxGFm6SDRCPnXrDu8rNW7pL
         PYN8X5WrOrZoos0W7vXmK1W6yuReQYUw1yf/l2IXQMZr3k+c8GRFmT17O49ogEPAzjJx
         WHhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SR1G8D4B3e6yhkpH+5IiXqZOCXzf67Q4+DGacQa/ATIAN3wP8
	4Bb8zah5c+chvTIRZYHMwv0=
X-Google-Smtp-Source: ABdhPJznmbx7WlGSQnKKorhenivWwefttHOo1+vaABh3HRDhZBy+u7RFwOVAkL6ayEZCX+C9juHXNQ==
X-Received: by 2002:adf:f3c5:: with SMTP id g5mr84768wrp.683.1640037684630;
        Mon, 20 Dec 2021 14:01:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:210c:: with SMTP id u12ls237851wml.2.canary-gmail;
 Mon, 20 Dec 2021 14:01:23 -0800 (PST)
X-Received: by 2002:a7b:c2a1:: with SMTP id c1mr58371wmk.112.1640037683884;
        Mon, 20 Dec 2021 14:01:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037683; cv=none;
        d=google.com; s=arc-20160816;
        b=YncS3R+SGjagAdlCM9u6r0/hV6Ehi8xfQ/5L/cYX2WBluALJkqlAZqYC92XKUG1e9j
         2KWX9/Riq3022Rbdk2XP63tbHvCd6Y9nCz3Tdnbo/1yDFGl/rbLRfyWFpzC20G48pjxX
         3oNiZ7cCM84+E5pwBT0v4JZj1HXI/Asvc1nGAIXmdYebOk0XOwp+FcIn7iVe98hffnmz
         ofs28qIEsV6gY55wEc9rMB2/dGwpQQ6s0hgtLNrugVKUEqX1AotvpGCaokK73GSs7Fjd
         9VN8b9Mx/K/cGQPrDSWNu2TJgaMdSTqWIQFKMSGkDrIEFAusV56sB4FDUwBJQObXGZzR
         CG6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zMk+i6psUWRrJkriJ76ixSA3XRodREnil0b2HWyShlc=;
        b=pC1nWdS/Rjh1vc3/tTjCT1+HkkdJFjy5l/mI1f8og763UeUd3K3VuNsys1PUmocDjY
         kQ+YYoZFThXGfuvTUrDNMkt5LDP1PH4Xfdy2XeYEy7kfuUuEGYv/BSBaFaiByYYIPFni
         5GAEHTmnxUkJ4UyRKj16veQCBVzqK1ataFqyJPSk+ZjyIOrHhWgm10gTNIGh0hrwvudi
         8daCV0xc9AIySa1ZACt/x2CiVpv5CigHhYd56eXsj/I0obeFj/yN58VFGGDA0qe5NBQZ
         wfqwbjh2s9wKfBXooQeuCUyBvM5Ln7LoW/coaxlPQhn2x51eA6UyigqryWjQ9q3R8gc3
         Ha2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z6vsEqQq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id ay11si53880wmb.0.2021.12.20.14.01.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:01:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 23/39] kasan, arm64: reset pointer tags of vmapped stacks
Date: Mon, 20 Dec 2021 23:01:02 +0100
Message-Id: <a3630b186fb5effdbe7c5c87c3b82d2d7bb9ecfb.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z6vsEqQq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3630b186fb5effdbe7c5c87c3b82d2d7bb9ecfb.1640036051.git.andreyknvl%40google.com.
