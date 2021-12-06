Return-Path: <kasan-dev+bncBAABBR4IXKGQMGQEQG4LFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 70EDD46AAAB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:40 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id u20-20020a056512129400b0040373ffc60bsf4341155lfs.15
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827080; cv=pass;
        d=google.com; s=arc-20160816;
        b=oEcqCK8I0p9RuQAsA01asoYqr8SRltuQldB8hkFAWdfTlhj3JuVXFQFLlRmdguNj3A
         MS699lcFZCWRwg8/GMCx93hMYxcOL0tIVFg/czLl9iKE7aq0yWZ/LHy/XsO3zo+DBvC1
         Qgb3EkN1HwyqVczjrC6rs2V2Ol+gONw7yJgZtWxCJ9nkRoIpYKAJVTu499tUXtum/8kR
         UJUyVU3k3eyXBla0gLu38cQkAboAh/4sNjaXqiA5igGJjnnpjtXmzwq/1jKSx0A37A6I
         JuFTr5pF/WW6Y4SBYBvxlUnRs44dArtMzTPKFU6/7FrYnxW4ktxqb8yCRsn+KlOSW5LU
         HpQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XIcn/CjL3xBlWxdyd98fSk/MxEGPpuqfJ07/aoGNlm4=;
        b=SZWg1rmeP9vgnXZLSpZBxzbcCEdmUvTtnyjwLiuzHi5dAQ/dzMtumlVdnXAqjVj1UZ
         LEcC+2LwLSAVUOq+jHGdJ64IBezUylW9LL1ZZosBhD66H5y/5/TLSZTba+yiZtre9xwO
         49TPKmwrmwbNWeMTovqrWdEAB/aAU4VQcsAW66ZyZDLb+3RzjfSPkyyqqMYNiW5fwsIQ
         U2n8uyDsveQjJG9vSuotY9+c9tfFBgg1GJKb4T+e9U2ovmyXaDL9PGDSkNsw4+uWCrhh
         DtpfVH0acquFy2AowV7lA4wIrEpjbjYpzMoTyFTUyBHEYz9HDkkSQs4GXVDx8PbYAr2i
         1oQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qXzJ+ayG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XIcn/CjL3xBlWxdyd98fSk/MxEGPpuqfJ07/aoGNlm4=;
        b=Ske5Bs7J3ObXQcuaEHWTcEWVdIGIXNLPH6Ly9QC8NSllEOQ+DG1V3Pj771+GCKe7sQ
         LmbkI2LYxkHIRxdVQ2Uwx4AE4Y2s8fEYVl+W8aoK2O84+QsJEhapWW6TAe/OVvgSxCSH
         QbnUT3NjeOPzUDZpB8udNCfKJ7usrG3sNYZh2q27x5ml33lGqKDaPnDHwSCGQY/m9jHl
         BvO1/kyckjLfzygz55ab7JnoM6JnQ4OwRi0f4omLdQXss24clrgC/z/oKNAZemwMUa6X
         WcWBvGFAJBN/AOcd437dQ5Vc+jyl6c+w2/S2Ga+YMN+WTpCYxFqCWLnkhZa4i5s3egHB
         bp1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XIcn/CjL3xBlWxdyd98fSk/MxEGPpuqfJ07/aoGNlm4=;
        b=Jv5dAd7PrnHJy1iXm0yeo2vCA19eHc1KT5MWV1BuW7M5VcvThzrIrvboVk3wWo5HRg
         C/LE1SByNAQLcja4VeAiAb6vCJsL7u133ZvrVqLsEEQv2pgZzUZE3nOUK6a/pDI1KuQb
         bG/JrTwZQbA7lDLHWFBq3ddxEnh4uqFlasyl+Q3o85Smldb/zYY0AlJg8oSqgxYbj3q8
         dIDvp7AygVc9qjRpJ8z4217gxo2oPrDtjyK7+unnk/JVcXYmevJfcFGVF9X+w39wtDsS
         9PIpUPE9EmnOMD3vvDJvpUMBoQw76mi1QBqH+EaPS3I4XnjCBPEm/d9H6ONfMQfer95N
         5vRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kQRhnpKeLJCWDC3uNJsAHhFTeaushwIisqqPLtUnNG+DnoiFt
	KZBwqxTBpIusbhmxtbT7vqM=
X-Google-Smtp-Source: ABdhPJwQihcYv3sddIr68VK4cwEwrcnkX6EzuFISqTx/Ewqn8AXNsVqEjoJW+2iYIYHfDqRGnJJDTQ==
X-Received: by 2002:a2e:83c4:: with SMTP id s4mr36538724ljh.445.1638827080020;
        Mon, 06 Dec 2021 13:44:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls2821709ljr.0.gmail; Mon, 06
 Dec 2021 13:44:39 -0800 (PST)
X-Received: by 2002:a2e:b6d1:: with SMTP id m17mr38439409ljo.273.1638827079046;
        Mon, 06 Dec 2021 13:44:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827079; cv=none;
        d=google.com; s=arc-20160816;
        b=D42U7loF+H5drLlfAa2rKKv/hR2tsT8yIiyaFw4AQwzyu2qLViNrcd9Zc6kiVGbTG8
         1sdXGcW/cRxATzF6iy903hCsBWbDig1ww+IJdVPgsIT6hJT9wWX4qkCZMnPyvPWHQfuc
         mMDpv51i7hC9Jn5X1oEWXK1fucvp3akEz1dxiW3Iua//cgrHDJ1ch5gu85Oz0lrQR+5Q
         BNgl61tyfTgcMCiXMYjuP9MzzFDe8OnjpQ8n/HyHobMeh8JXLz9pzHma1QDyFEdM362S
         wgeM3755YMIiXYqIbkmU2Twz/NrlJTPu2cuMtouZxr1+LCmFHpPj+2aYYo+89D9B5oao
         L/hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TniNgsonCV7N4x8CfBP962yTwJ3ZQbzv223ievd0EoQ=;
        b=i4xa7g5dG4gTajFC5cTiHhuwCO6E0UhsOuaxFzwk4d+RxRf7oGuIQSOvdKG6LbeMjj
         0fmGXps7bfDP0wsExRq38skrEK0dPcoS+gY9pF4AIvFh+Do/1P5hqDBCALHKHn8c8PAk
         BPSp4QNf39ghJpKLAol2MdTD+iPd3tPoODtJMHeQBzfgc8NTx+d0uMwUUrb2tLmyYnwC
         9cc3SJog0U8uOGMHe1QbvvbzSJ9Z4Xle11fOZ6vCxgxSd+O9pcGHFrYZpTgJyMwNiF03
         eEirC31bUFUmg4obtVZnxBPQjxg7UcQkBHAwXzOCCVp9xwPDld0YgeI0GzNf9m3Uybmz
         ZDCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qXzJ+ayG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id c12si706720ljf.4.2021.12.06.13.44.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 08/34] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Mon,  6 Dec 2021 22:43:45 +0100
Message-Id: <cca947c05c4881cf5b7548614909f1625f47be61.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qXzJ+ayG;       spf=pass
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

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cca947c05c4881cf5b7548614909f1625f47be61.1638825394.git.andreyknvl%40google.com.
