Return-Path: <kasan-dev+bncBAABBUOTXOHQMGQELBHRGHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC52E498792
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:58 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id r18-20020ac252b2000000b00436a7ee54cdsf3343649lfm.15
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047378; cv=pass;
        d=google.com; s=arc-20160816;
        b=pmxp76zGCq61Z9/E0lMrldZGq4h3plMMHhkDJlzbV+ua+QmLvdRd9FLCu4dekcTU1g
         lKD+htA9/p/UIA56OQAairRWB6R0zcnYnihhKZeW0AQrKHHpJy1SEdtMsD+z80UAz7jX
         DpB2xhid0SsZfCSh5H8EFtxz6r4gmDqoOio5FthP4nCoS4VkwXgsie3r6n3Gkx3bOjcD
         GImGja/ZlWhJmUtPqZqd9/eEl0IkT98vkElWH42EzPB9fU/wPKPTFeiOmTZY3GhTAIbc
         ALe7iRGUAY9uHyzIoh963+vNkE8XmbpeQnOXKKVE+vMfjdLIopynQwr9+r8Ijqb1xqFC
         hdRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yMW7oY/fH4uGotyVo2uedbeG19sOQiFe+aULWYSGSFU=;
        b=dJuPgJP/2AymnDhmd8EvlvuoTTNAoFpbo7tjyKEtvLyAEzNPXmFxbwhXEjAOnY4VDO
         716cRDZSJ/Nt9+XW5zxxMhUW3//d10+r8eXv0CVvuUGyV1GVWMLOTzvLNlMqt91D3Xem
         Dp4yRwNvjoNz9c+o9LzSdNczYbAqAOk/anldI8ZcnI9Fdtdk7hdrwJ0CiqR2nemiA5Ug
         UjT+Rxh+IU/xGAino4bUqVXwrSQN1h1U0/Tt82qy/raxTwH3hg6OMUpgWLkOooAYPIBm
         FLO0ZHd9N6jIM4K1ZeNwbaC2Eq8DoSLFbuX/+R7eM4UtPDD+tFjdLwiD+CriXdX46LEx
         HuAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T0BhkxS8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yMW7oY/fH4uGotyVo2uedbeG19sOQiFe+aULWYSGSFU=;
        b=PTLvGWUiy3llX/nzqRVbCeV17i7/BC07uH3rekheXuFfp/s9iLZ5Kq7oDOrFb8TO1W
         Jw5MJaLpJFEHIsb1hxuLMb0k5MB2Xmb3qkd0HrhACzjeJjk8wENfwxwyPuztTpklnZn1
         kdmsTzCilCu8uKpqTejWDnVtxl1FLj7mG670Mz7UrOyxu6b+vd2zPsngZ0kHAYh/GJRT
         KrBYyHi22fHCWYzvRC0fhxzUoOQgxXQJySMTeAXrKHVxmJ9me4j/S6AJGyY9UYBUvd/G
         LLAN9//rC7fRKHef2NIHKq92p78gMU3+RH0raov6I6E1vBU8YyQmF9voM4BbKypr1KXs
         bi8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yMW7oY/fH4uGotyVo2uedbeG19sOQiFe+aULWYSGSFU=;
        b=aMJbTevSqDmIlV1A0piCH/e9u9bB9i9/5imiUhSaiFe3LE76h4qAaVBQF30w3z9XJP
         +EEl1CzZlvg8SvKRY92ufWsbhB3lCdqcmWJUcejUQdp82UDtg6kQ33TLT+AiWWIROBlW
         4JkAIqscI1FHvVP4TgUCNlM9IYq1cIn4ykAtkMB3TmPoFNtpnJWZmrxx8hEtiPEOjH6X
         xTafTqV4EsnP8j2i/YCXltsyRwInMHayU1yqWHX+zV1NfBjDNXKF0P9KKDRYkVdTUDKV
         xZ70oOFh/HmwVAKPLJXYp758+Cs1UvTvH1MTpm1pvSabdjEym/XrUIl13TuULwSr/wFK
         HzEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wOxKQL4SBMe3KBh2udgYkKay0/oS59oZyg9RCBUvLaKQg6FL8
	rk+oAovdPMtw9XDP/Qvz8O0=
X-Google-Smtp-Source: ABdhPJyDu0nvcqANrdgYGsOMppU8WexKTkdxbVDYupbZIQenBJleBVKzOP0WSJb4jCVHP32CID53Cg==
X-Received: by 2002:a05:6512:3a82:: with SMTP id q2mr7507525lfu.638.1643047378169;
        Mon, 24 Jan 2022 10:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0b:: with SMTP id k11ls2480422ljq.2.gmail; Mon, 24
 Jan 2022 10:02:57 -0800 (PST)
X-Received: by 2002:a2e:9ec7:: with SMTP id h7mr12012021ljk.394.1643047377286;
        Mon, 24 Jan 2022 10:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047377; cv=none;
        d=google.com; s=arc-20160816;
        b=LH4dc01Ye8SklmeZ0j73kNhuCnawrJrK9a12VxOf8UEx/QU7OtJh3S1GGEpduEz8UM
         1j/fhTLBcyCJYRuMLPycZaYX3/7mDEgFRjfr9JenZPr/cpeJTVSCH5yS5d2q+szxCwjN
         f6ACuyTk9ASAMeyplRXotEmNDDy3A7YYIlbQzVrV2lvhoe4vfXaYwDk5+11g997eZV81
         uoTd/A/rIybpHEKKydjtvNy0XAplPw9UxNQN/vcVakW3NtDHXa9rTWHUkuZ2+5wNyyln
         1FtigtTzu9u3y/7r8PkBvBNmQlnzRQfRe1SQQMhlGvaiwQaWOokw4eDPWi5pshfHLs4x
         Vk0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PiyMHSnkvYvDw2LQdkJa/J+//+u8Wif2b5Y6jyI/vHU=;
        b=vBQtBjjyvEmGkF1gMGl6yobzEgSE6Sw2uwyhePIz0PXGCE7ZxcXGO6cW62mAc/G3j/
         Rdz6/r6ZfKLrASKUt3ylUOTA72NB1anBw+4UGj+yg93okbIqg71UeFqDfZR68XPVQAKa
         +wy0Zzo2u9vwkNG04B4a1k0pCKBnfmj7vsJCaivSoNng4YYZmVPWa5g7YLxARkIkBTCJ
         NQ+uHwHtBY7iS2wyXFv2zZBOdaZUpZsi3ZcdROOjLGg6/+FRXM5zHhs39wZNyhxye+Xp
         69lg5ZWav3p2N4WH+if1E4cFc3f8MqbVQz3FqZ2MG7YR7Eix3lMkeTPBtx36fhkzWVze
         Nnjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T0BhkxS8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id p21si388819ljo.6.2022.01.24.10.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH v6 04/39] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Mon, 24 Jan 2022 19:02:12 +0100
Message-Id: <ae4f9bcf071577258e786bcec4798c145d718c46.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=T0BhkxS8;       spf=pass
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

Simplify the code around calling kasan_poison_pages() in
free_pages_prepare().

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v1->v2:
- Don't reorder kasan_poison_pages() and free_pages_prepare().
---
 mm/page_alloc.c | 18 +++++-------------
 1 file changed, 5 insertions(+), 13 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e5f95c6ab0ac..60bc838a4d85 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1302,6 +1302,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 {
 	int bad = 0;
 	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
+	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1374,19 +1375,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (kasan_has_integrated_init()) {
-		bool init = want_init_on_free();
-
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	} else {
-		bool init = want_init_on_free();
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	}
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
+	if (!skip_kasan_poison)
+		kasan_poison_pages(page, order, init);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae4f9bcf071577258e786bcec4798c145d718c46.1643047180.git.andreyknvl%40google.com.
