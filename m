Return-Path: <kasan-dev+bncBAABBC64Q6UAMGQEZAXO7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 0733379F005
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:53 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-31c5c762f97sf623f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625292; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDCwlfQOjJjpRSULz1ylcuEPutsysseFMG3I6lu1PQWPK8Y0yvAhBRsMg3Ki6t4LFo
         S0DtIUvMkhkKyK1zlxHvGM2NCCimA6LZjqKch497wR7XGIy+QpYg6jFZsQFrCcoxSSIP
         jq37Rhz78UDXF4y1oGGnl89AJrf2ee8SXFEB/FVLgWXGfkncfUxLy/AUGaS7LcjNGBda
         btPjQupT75GG/eAzJBYIfSIzgVpOAFG144cL6b2J9ULjSoRAtnlxTaz5Ha/9tQO/NS08
         cxm8tT13iWHcuHatIa37qnmWc2j8Vqako/nUR3FqU/xCwXEUXNGj7UjXo0kFwguHSq8j
         y4EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3qPiW9dXX51GTs32yENcgAzoYb2rkEOcrahZksvGHM4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=w2kkXPb1zQerBkbx0Vh/E0YRS4efIeSrAjyp+h8fRysYXGGlprhuLI2allGaIsEEpg
         upNWp6Mv7TbK96dH/rKP1QJKdoPywKlokxaWBu6tt8SKlD9Rifrikim+pZvnfil8QjnO
         hSfUiRIEbuDc/HswdTmplDvDoErgOAvhlt4xXqmk/Fj89TOYioya4nXeRHtLf0sv7PZJ
         YUdHIh8QktZfMaPMwjNOiC0GFdVgnpgzHM2gXokBsc+wqD9hVBsCkQCIeBvp2lfRvpBX
         N/d54mHMK7i+wqrUmfyZJpAH7RCrLrf/9FS4z6TeOA3NjBlDpwU7FN6h62gA2O38GzTX
         cfoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XFAMKTE8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625292; x=1695230092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3qPiW9dXX51GTs32yENcgAzoYb2rkEOcrahZksvGHM4=;
        b=GDOi2STTSXERD52W73kzlawyZLGH93xFw8MzI0IsGBUCj5sakOUMVl9wVfU3egWslm
         fEEHBKT/X/MCRRU9ivTPSn7yro/YPr9lWKQQmKLzxayx6XD+6lggmDLmz/MNeuauK8qg
         27dJ0YDdjv90VjMH4tyrmlTM4jU+4swCzUGZ4MW5A0tzG6yDGeKEhhbxCaIL4OA4bOou
         I3ebuFQGvmKhem1P+nQRQA1Uo4Gzv6UcXcguVJD81KItvHOEwq9HIpVRQ150xGW502ZX
         dyda1nvgnBDHEDvn0Ix2WME6fhIAdPwceMmO/4BZ/EAu0Vtd+T/TFvgViyE8jmZFfm0E
         pk7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625292; x=1695230092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3qPiW9dXX51GTs32yENcgAzoYb2rkEOcrahZksvGHM4=;
        b=ieFXTPsh7iAyGLPA/u+X5suyuuBmKfo5R8WS60AN+Q765fPasCqY8v/dGa8Orlkdb4
         jzlkt2Ks9ovb8FmP2m36PKDw01iQjPTc4vnFOT+ujATBxwkjDQymi9V0CY2pSYKOyMuI
         vghb8RB+ueCtZlSzBzZanbIk3KF+Q27zMNZcInr7V75wiFqJbH+QbZUt107etOhdDSHF
         pa0OomlSXH/pNUUpRR+UcgkhAvBvfuuIMZnXEJXUitfqDx0DzKJdNIGW2WKiX/pVzpKm
         1cOQu0FLc0YGAUey37MU2vBJW+XFfcxeIZ/RM93/EddFoG9fv9+DWOPtmdKKJCbGewgQ
         1GXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzsEO8HkBTb1q4eGJkcAEmoxSmPVD2GJCGxl8CjushJaiNo0lw+
	sc06oMmjzp9D1N3ZIAOkTbc=
X-Google-Smtp-Source: AGHT+IF+BZUeQvSVD0RkUHxJazTZfB/ozUWEkp8tVsajU9Kd3ksTcHaBKdh4NnDXVoQfaFIZt4tUEw==
X-Received: by 2002:a5d:6a4c:0:b0:319:7c7d:8d1 with SMTP id t12-20020a5d6a4c000000b003197c7d08d1mr2715687wrw.44.1694625291724;
        Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa47:0:b0:312:831e:ec96 with SMTP id y7-20020adffa47000000b00312831eec96ls1485526wrr.2.-pod-prod-09-eu;
 Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
X-Received: by 2002:adf:fe8b:0:b0:31f:a0ab:26b5 with SMTP id l11-20020adffe8b000000b0031fa0ab26b5mr2866004wrr.8.1694625290397;
        Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625290; cv=none;
        d=google.com; s=arc-20160816;
        b=Zy32CW65VPcjMoKcHWEgu/daQlyp3ZK+zQIXT738h8dZW7DhP7E4uQNKpJyChiY+P7
         OHBEikG4iZrtLnX9//c5OQZ7YGsW14I/2WnwgNBweg6NOHEk8eHdvyPfu/C7J5ljbEma
         8FnFYT0KfVUsxepsQVBxcHDORdPA6sEbFZ60OIzOcF0YOpJoK6vYoUPnpAWrUROqz4AN
         8gqV4iWKc2Gb2q0ec7PZR7udiaLLR1HlSwwJwcpLsAwnMTm8mNaLctwmprASWm2DLQaz
         x/3bZyOX9d+o/s5UbEY0NeEHE9Y/wCeRYbtbyNBtsgc99hgfsKxlJRybLumQ4YUYipb/
         W/hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eQriSK20/8KwwHOVdQKhz9C/zLOim8sff0QLVit0F7g=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Q+kwTSP+aP+oAoml75RNr2fkyEnCCLqLK1H502ZOOwKIAOyBXdzRnrNkuhix452v2E
         7NsL7A4sOfA79f28Vx1HTzc6Z2EPCauYPQMVfvB60ES2UQNLegpvQddAKhlocK7BLhji
         8RrqvNdr+EGOxbwRleDadqlQkzSZhQf1FzVoKAwMf4Po6b659GR7TudNJMPR7E3wI22a
         4/Qaa5WZul6f/P3po4dM+DkQbdSiMUvp4Mq39hbn9fQjK2Hfm9jG5ieqRuo53hF4cgBN
         x+1sTqK23QiQQr2BnisVIVhkJ5CzFuz25j98Rc4bzEdwAqeTYAe2CVOCskqSnozPqE6g
         gjqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XFAMKTE8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-217.mta0.migadu.com (out-217.mta0.migadu.com. [2001:41d0:1004:224b::d9])
        by gmr-mx.google.com with ESMTPS id az4-20020adfe184000000b0031596f8eeebsi967183wrb.7.2023.09.13.10.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d9 as permitted sender) client-ip=2001:41d0:1004:224b::d9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 03/19] lib/stackdepot: drop valid bit from handles
Date: Wed, 13 Sep 2023 19:14:28 +0200
Message-Id: <5cbb8235fe6418f970fd0012450defdce598abcf.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XFAMKTE8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::d9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Stack depot doesn't use the valid bit in handles in any way, so drop it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0772125efe8a..482eac40791e 100644
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
@@ -303,7 +301,6 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5cbb8235fe6418f970fd0012450defdce598abcf.1694625260.git.andreyknvl%40google.com.
