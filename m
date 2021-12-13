Return-Path: <kasan-dev+bncBAABBIEC36GQMGQEKC6T3RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C844736E6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:41 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id f15-20020a056512228f00b004037c0ab223sf8069016lfu.16
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432481; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTnE6i+sq+QyyzLUeLMjMTcOp5TsrQi7lgxThzB71lL6/xaU/jHS8yZFkXtjOPfaaX
         ij0Ik7Tnlb6XFaH20bS9PeQTOZX2P4g+3mHJ0KhE54ZpK6sY6i/PvJo0kuPujkKo9cC2
         Azw9nw5itkMgo2+KZBvJP3lMTa7isxwAKYxvzaDhJ2GTWWay1eS8/uCyNMIDERdrvfE/
         dWJKX604a9srZKUu3dPJA5H6yJ+mutXQEbq8ZERX22jwJxxaL/QZIx9/lMVdcXlvJT9+
         GdOB7no46v7rfAwl4Rqayndv+/oRa7tdCET+XBEU8UaLlzeWAA4MH+a2VpB2LrXipwky
         cEhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IbZMsGi+/xUZuy26eoS/cugXTTG5+kHsUYIUepfQiVA=;
        b=q4JWLNWvoBwlOpmEoGWszrIjbnkf8dtVkJwDDBYdOVKqxQ+ij939PxtjvM1zXxpgcT
         T48Knz0/dV+xa5h+kj9tYG03lzBPHBRYthMoOSlcdOpy/bJ0tqPF7CGnjHEpGaqZgveL
         XoHT0oHFxFRTQOECN9hCktVGOIYxFtQPd0Fa77d2d1oUQlShKkbAgysfvrwJ9waTwZep
         iHspk1ja9SultCmBvvnF8aq6xOeIvuHIY72JnoEWCxliDIPQM1qFJy9CRYsBBSzjsg7w
         BI5xhPK3OItq3YFmvuCcVtHv8ZMSZb9pO2rE/wFnSNG+Jzhcrr/2OeIAmKu2aMNPA95U
         KUUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=etceA798;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbZMsGi+/xUZuy26eoS/cugXTTG5+kHsUYIUepfQiVA=;
        b=TppvIUzlrfmzwFuAgSFSMtvyP7EQeqXFic9wmXRit8Z+C7N4kAPx5hzjY5jEgyey1g
         QrakGPLENWOv2YSGzDJcetWUaMQ7Ok7qUL2NG3NQc4x+MvPW/pJr3xz/1W0ZeWn8/c27
         TnZlecBOMzcb9/kX7zpQ1rugh1rxFOVMesOFEc+BxpcC/2U+D2bqFIIpBiSUNO8a0qH4
         DOuvUcI8cIvFpAMDEEugRJPKSKBbXuO7Zj99PBAJJvFTZaM0wVcOg+6BSwygLYzyCJev
         +qezaYicZbOB7JpdsdMdCLF1Octpoi8DNcwlKh6aabmHcQsguTfRl23/8jMckLR5Nmlw
         5lcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbZMsGi+/xUZuy26eoS/cugXTTG5+kHsUYIUepfQiVA=;
        b=33zr8CUG4T2RFte4gpc9UP1VzirjeJOzyll4iNGuRlq/g1x/nFN6ODDY1L2IkRtUqd
         dEBMSk2Dv8pTDm+lnvX4DhKswOmR8e4gtjyfxvoa1GB5Lpjg7wdJ8jUSwMO/MH3SbJVc
         gnN9PQotnHyK6AL2TV/5tfpxzb5HXzFc0Q+fS4bnLKX4uu0z9wQF4LpRwQPOtt6OOr8H
         5/ObZkFX7lfTCx3AdUw/ZKDoVemolAemGyv0JdjU3YSkm7JiUaE76V9uTq20970GZhEp
         Y35OEM7GIX/pADlJUz8Fvft4L2K9SIANQIxiQFGKOv7NynT/divhplisBlR0puTi6qhV
         Oqmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EKcpNMeVPMGl7dg6MaYYSmXdOz4iNsbNwvwInRK5U3/RjGFb2
	+C3CjMYsgDqHIcrUfvx9vzs=
X-Google-Smtp-Source: ABdhPJwo0hp6an7CCfFYuQJSU4yKxDP8qMH5xZIDOlK34rwZRnV50HDo54lfRQRiBiBcSRCdNA5xAA==
X-Received: by 2002:a2e:f1a:: with SMTP id 26mr1114166ljp.480.1639432481137;
        Mon, 13 Dec 2021 13:54:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1553160lfv.1.gmail; Mon,
 13 Dec 2021 13:54:40 -0800 (PST)
X-Received: by 2002:a05:6512:3402:: with SMTP id i2mr903930lfr.447.1639432480240;
        Mon, 13 Dec 2021 13:54:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432480; cv=none;
        d=google.com; s=arc-20160816;
        b=T5z8jgKR7UDIEEr/0hyfsd2i+WUKUrAi685W8eM7URFYNFDnvdplsAjdjlugFsZX59
         7KyeHcw2rhMtocHfufGH4BpmOt7F86qCnRKbCFVipdIUt1jUWUlRth//qtWN9wcOB8Ve
         nnfuGOgfQlPrBO/cR3vCICIcihGLyZ1YXAki8fqhcAh8xTs1OwuxnY7klUjsP9in+afo
         lvzkvGCiNFUUNaUUskaBKz7C9/XLcWevaEfjMI62vqlkTtMaUJMETf618US4URFZSnLS
         55MEBFkfITKeUHJImPRpHiX3X+XQWyIxTMHfxtrislurrx1HibveAI3Z7NbrkDzsu+Cm
         /pZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yrzW1sRI0uWg5UfgxRnOwTnc7XfDGQwyJkjr78hdM+k=;
        b=C6RgDHB+Mkh45do6Hd2Ijju7d/gNQ4KaJkYkBqQ94b0x7ha7LKTjlUqzk6T6xOyVti
         zxUuHAWVKBXkjWaXSZ00QxOayq6WnQTrziHszA/2uOVSEaZE4bI4+qLSz+y6cTmfaSnU
         ViLXW42Nsu8IyXy9bEssIS+N5BLkw44Cbdg1PS+eshOQFPmFCQsdB2zFS5eSV32wKqhl
         ApyJko4N3wJ4Pecv2cmm2nsqv9RHxIfgfXzhHbPnIWDa+Nrtn9z6WYDl+sLki94DVRIx
         eTg2j/f7nOM2rVnesATFAS8jYYwqvyLXYWPXcM5tDkfmJ13Z75B8XpGAJfae5ttsiZsT
         ZRFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=etceA798;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id i12si729654lfr.7.2021.12.13.13.54.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 23/38] kasan, arm64: reset pointer tags of vmapped stacks
Date: Mon, 13 Dec 2021 22:54:19 +0100
Message-Id: <bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=etceA798;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl%40google.com.
