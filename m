Return-Path: <kasan-dev+bncBAABBMVX52VAMGQEOJM2AIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D1D27F1B58
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:32 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-507d0e4eedasf4291318e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502451; cv=pass;
        d=google.com; s=arc-20160816;
        b=UDco0sbyUbdZqt6QK82RVCc5voVgTFXrUI6b/xJT7jQ61lLhsi1/XgSrpQypN9pFZf
         LM/OM/L/5cIntr28kI5RkuEklahSyZdlLx3zyEITF3ybyICeIjYHWxpY1cfM6Tm7kQtd
         l/HcvBwChzqiqT7rZYmdddlW8RW5Q3stUt7PwU6Da+85m9wAknRv7xr4Re11y3E88NE3
         W86RHlUef1QIzxSH4vSqcI1WRaVVvqSFo7i0Jask0zS/Qkx4wqQuxQGaPhouNayGl5A2
         p2OckmRPFVcrls6ieqDzMewNHjbS4JjJPtw1iIKY2MAI7q6BKU+FJ5BV8HeY6USGgP1i
         WJ9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nfTGwt5NDNmf3wIhXdINVOr13PleTN6na9prMGfnfwA=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=LMQJJK2eJuayHc5Z2MuheJaJwDUxN8/YmmfZ5PQriTyCVBEGkj8x/uhoQw4TPOOqYc
         ySH+/gpvKZaoac3Z6ORTgOk5qkjKbm30f6YGTnFq/IiFC52MDjV8Yj1hm1keQysVSagr
         K8ZBE49qrosKDmnk0or0O06NFGWUpJpazLLohFxKnC2twm+toSQsx7PGcOifLXYB0I7v
         Bb1HkCVDtiuAZbTbH29dG3tEJAqzlREvKGD84P+3EePspFYVmJrFKQUhyeq4mjHunGUd
         +FH4cnvpZefWv4MUJpyXI+/SQyEGTa67reisAyGKq8DjKfJOGnnEtj0Gs8f7ex6IZADn
         yC/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sig9IVvl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502451; x=1701107251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nfTGwt5NDNmf3wIhXdINVOr13PleTN6na9prMGfnfwA=;
        b=QRdTsYILIHibolseEs2+HFk2v2m7CsIF+6tzPiehi8/aqxpNVPDWKXMp2jcbWK4tiu
         nX94gJCn453/1p8nmqTHYEiuESZAPlD9I9Xs8Y/0mFlh81UaG0PaC052Fk389neurpXL
         yokZI+ghlJXNDCRVgsl2+ROmM4oiiEfYXnucD6fzQ8WQM0ZSA4smKXwwuEm8KnhKkQaR
         rk2gOYYy7JWuoCBXrRlu4tFeFQDslkH4iiJz1Fud/ARwmK8KGwNvRYJWCLlGkSVj+F7s
         EBwSpHi2fLLritIT1y0fM3OE/C8090eFnj3ta12ri4FkXfITBRkSlvpL/nWW2v9rlNDH
         lJ7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502451; x=1701107251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nfTGwt5NDNmf3wIhXdINVOr13PleTN6na9prMGfnfwA=;
        b=KCv4aea8vJCjrqk+vUx+XwSjtAAd6yc4rQDUVT0qDW8Th1wDrqu60xTXmkSMp5eQE8
         GLRB6uSxnhGBe9ElPwqT6F/cyHUTLsPpnWDvgSr1PCi0eWQtMBmLZ0U4B5o2CIOGVI0X
         K0jxFlB4gULRhiaaKeE0k/mswY4iVEReHz51IBCbBsMIGIihEn2+rSWiVT4941jUJ8QY
         CC32UlSiszmK5kJkUL0Cii6iTgNNI0hKN0QPdsvUFx61v4sqbPWimq60SxUNhVxhQMlP
         jxN9asSBZlF5JoZs7tnTmiEU7g9RiUbtNd8qbd46MLxyr2h26Z4fr9fYuhZFR4/Cze0p
         fnNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYG8WUtZq7Y86+jrIgueQXiSQd4uMQf165+SQT0n9bc8kyezW3
	UKQl1oiLAogFuWzOi/WLBlY=
X-Google-Smtp-Source: AGHT+IFTfAKxO3nLTWRRrUijTUCEX1ZdIPQNCCCNUZGrVAdnaz73lKBOAY9Uvz5pzLEPYLVjkifCUA==
X-Received: by 2002:ac2:5982:0:b0:50a:7575:1339 with SMTP id w2-20020ac25982000000b0050a75751339mr6325247lfn.18.1700502451193;
        Mon, 20 Nov 2023 09:47:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b10:b0:50a:68f4:6371 with SMTP id
 w16-20020a0565120b1000b0050a68f46371ls107067lfu.2.-pod-prod-04-eu; Mon, 20
 Nov 2023 09:47:29 -0800 (PST)
X-Received: by 2002:a05:6512:3e08:b0:50a:a6b4:de49 with SMTP id i8-20020a0565123e0800b0050aa6b4de49mr7600897lfv.61.1700502449498;
        Mon, 20 Nov 2023 09:47:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502449; cv=none;
        d=google.com; s=arc-20160816;
        b=JF90hwy0haw1JMXYQG/fMQ9unGl3Urr+pp85KcjqbQVWiB6fxlNUpJdKyUeTWRDeCA
         m6PrT5iuuUbEusa2u8inN7y5e+XFognLpIpHlBcHxBYzCZCgZXr282cO36GPS+PRUm/8
         Xnd3g/9XdmZdw1ExufMxz5bwh/Yt9+asgsSMBMgmuaRQwQZcGr2+jl6IMQPR9AdA4Tuv
         h8C170rFL05wvWoi+F2I9rQrcFZsE9utH7GcFIgJqKp3EDbcL4ATs9/uoo9wihI1RJHh
         M2c/JppC07OCjDKv47V1yLEl9zyexEiJIeXoRvazT+a0vyQC+2wlGLA3w1ozgvFuH17z
         oF5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lmg5zTuKt1w9oWZyNpXv7HY69NJCp78Dr+tP0crczmk=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=EQc1VaY1myHKGrHFJ+qbeMxSf38nt5LYJuOaaGIWqrgCYyKmKr+Jxl2+ZDA4c/Vlv+
         MIzllpDR7Ho1oiwOiJdPCLht8q7v+2AHrulsz/h59Pi+8BKBH5V9nbZdTonVQBV8jzxR
         Yfk+mNG96R8TDFFTrNyxlaBT+L7dpL07aETBtDM3ryRwkzxwNHm0v4MKzVAQYPSK4OE+
         zDSs7PALrw7TZNExtERYvjExNLFlAWvEIYFZ5vaSKCVOhPqkiibggUakCTS2Cix28Yhv
         SuaMDAuNEhVwlr6ADb469WuhOdKiPc6N6cATh9GX62vViqP3hVN74QG65TmJgtxcfFPO
         NrfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sig9IVvl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [95.215.58.189])
        by gmr-mx.google.com with ESMTPS id h21-20020a0564020e9500b0053e90546ff6si329297eda.1.2023.11.20.09.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) client-ip=95.215.58.189;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 04/22] lib/stackdepot: drop valid bit from handles
Date: Mon, 20 Nov 2023 18:47:02 +0100
Message-Id: <34969bba2ca6e012c6ad071767197dee64dc5723.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sig9IVvl;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as
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

Stack depot doesn't use the valid bit in handles in any way, so drop it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3e71c8f61c7d..46a422d31c1f 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -32,13 +32,12 @@
 
 #define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
 
-#define DEPOT_VALID_BITS 1
 #define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
 #define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
 #define DEPOT_STACK_ALIGN 4
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
-#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
-			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
+			       STACK_DEPOT_EXTRA_BITS)
 #define DEPOT_POOLS_CAP 8192
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
@@ -50,7 +49,6 @@ union handle_parts {
 	struct {
 		u32 pool_index	: DEPOT_POOL_INDEX_BITS;
 		u32 offset	: DEPOT_OFFSET_BITS;
-		u32 valid	: DEPOT_VALID_BITS;
 		u32 extra	: STACK_DEPOT_EXTRA_BITS;
 	};
 };
@@ -309,7 +307,6 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->size = size;
 	stack->handle.pool_index = pool_index;
 	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
-	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34969bba2ca6e012c6ad071767197dee64dc5723.1700502145.git.andreyknvl%40google.com.
