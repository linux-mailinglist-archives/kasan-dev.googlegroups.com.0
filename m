Return-Path: <kasan-dev+bncBAABBMHZQOHAMGQEEHFPWGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FD3B47B574
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:12 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id z199-20020a1c7ed0000000b003456affcffasf236582wmc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037552; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRDIb8z2vPKuuEQ0RBJa62LzM7RVH54ePPfWzNgTkmP165x+wz/UZEnFQs9D8lFZ1z
         qxP+lKDwHPxc8gU1OggibQOqUUI+TLFMkM1+lMMUWZf69yv09395lR1hJmOzj2kIDI+U
         Or2WJvrey+u8BXysrcQ5Ubaash0Q/gpP3QqMW+7YMpfgDb5XmXv9ZuzFswPmAlDarJzm
         cz6XG7xtKl3jBjK+Egapnho9wCXdAS8889lTTL/+lrn4cpGGRQxd9iHDxdmTjptYvDNB
         fvRSkRQoxwPbD6pKp9fNg5kwlZfmug3aN8iuVRl98w84C9D+UXnA7NuO7XWVtS9TTQLJ
         MaTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bs+Jh4shENb8SOcFLbIxjERgZbU/xiPJ6NEW2mOtWCA=;
        b=CXrrsmPC3HJpy8EolnkXHW//BTLLk6+NRR/Acwf+vJ0MKyuZ251J3Kx3uowDJj4pgX
         APesFBv0pYdrj1ihpQ3ygIhH/lqT3GVx/QWHexNMA7T5Q0jJAY4pwE3Gby3J81f8NjPT
         MGCRQXMS/JODPHO+Y4P/goVNNZX/NANECxlQj9vzodzLvxinvZxQdnu05iPZg4kLfc+e
         JPT9PeZ90B9sdYIFuEWc3rJeaDEvumbfDo4eL87HV9wRulPfgrGggsXd/OTAKVb6rQh6
         Eb4w3uKWWJSWy0F1IJURTZPUNimw2hLeIHRvRIw5oKSZur6hYxKKnCtFBYCC35MmtKMa
         lQCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F97bEeeJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bs+Jh4shENb8SOcFLbIxjERgZbU/xiPJ6NEW2mOtWCA=;
        b=Z4+jZl+0e8wvuuHOqpR+lm3NFu3ukQQJ5mDuRRBxa2+cnkGL+Eoqn7D0Qwood93sck
         onJDe168SVJgp8OlkpLOpKxnt1kZ/A7W0ejRLi54/KRTrHp+KKsUIDTrDuVitICA8Coz
         BoTTLf58nH5y6VDmqmRsB20HA1+zQim+OWAlii7qYCUy1X/GzfQ2L3p2LE46LGpW3Fsj
         rYWYsJk28T0rsmmKT5ljAazdpLdScUIFSqrMVwicPr/fGSfq9jXe2zGZs/jKUqEWZAF7
         7xsXuuXacQ7s8xXWtSALSXHEd0dbnzJtPdhQ/YSu+2dGjsI2FdkMw+P5vdo0V7lg4uq8
         AxQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bs+Jh4shENb8SOcFLbIxjERgZbU/xiPJ6NEW2mOtWCA=;
        b=1yOnS54ubwSQ7njrGjOLy78OrK1TvL+HpfKqRj01D8/eKS69rdLxdgW/N5+tp2E33T
         OvmCeucUQqJ2fM1TcpTPMrMycB50FgD2YMzpSYC2z0X0OPFEFJH/CTX/0e5ESvZeUnjz
         Wpy+VwE9D1fOozoyFscrGqy06u2Tb0zpbuzg4oBgpmRDOVv7gTJpmRr3ZZhvLk8Iitah
         e5uYZbR0nTcbbVFLRT8sy+JCKGMx8q/2Xt+16mILEhf6VH4c0CQj1aUVbBHMzaknhccz
         hie8pAyyPVDrNT1fzsiLGftjVMF30rHeDTUBAgcm+NJQCDJQ9kVozvSexkrYm+RZe/V4
         5tpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533thIENcte677TdcFM84FCWyL/0uHfuZ+oizZ5cFjLEXMbCucJO
	p7Y+NC9EztHenRXzAwIgLNE=
X-Google-Smtp-Source: ABdhPJz9GReP5s+IThcW+RXt1Ks7Kw2fXr8T7Wkh1/dbWbOJpQPbFYCMNU8T5XetXFLM5KFqYPJwDQ==
X-Received: by 2002:a1c:1d0d:: with SMTP id d13mr57956wmd.78.1640037552202;
        Mon, 20 Dec 2021 13:59:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6377611wrh.3.gmail; Mon, 20 Dec
 2021 13:59:11 -0800 (PST)
X-Received: by 2002:a5d:6d8b:: with SMTP id l11mr86743wrs.335.1640037551543;
        Mon, 20 Dec 2021 13:59:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037551; cv=none;
        d=google.com; s=arc-20160816;
        b=wJ+W4VL2KqWNHTY5bNCXuZv5HdssaHHWA8lNTtIM5iay6OAZMVVkOUAzgQBYv5K5Q0
         2tRKbaxedXXmKVPdrsZBKXV9NVz4ohadtKvbBZp9XVP/CKGkUHt0TGk5V6UmFtBu7dYl
         0ooIOrp0h0q5MxunbToz/bpzHHB3hXEXYBPVitaooo9HQDydSB3m+LmeShPH0tuuc4e4
         GBWtijiydLX3Dvx1V75j/o2P+1cm+5BJ6UBpAFXfwyb7JLg8L9zHRFv80fhWRWJBTRjF
         skcCCzrJF2pJitpnRwGBQ8QgM8s0fsS0C+uV/TmrJOmKCMU1HIrRUGfuZrSv226oNaGG
         QDCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lLRehdStIsdn/AnAQZ01/ErmphlQVweFQPGIsWoJgns=;
        b=hrdkM1gKxtmMc493BKYC5l0a6qg8jpcWUDS9tfLkJIWuW9kzXhkP+fseqrZQ1j8yjj
         /xNqr2K8Kc8c0LnkaFE6nrDm4gxAmz/MuLt/c4DooEs3ZjguLvIYAf+GnubwTJ97vj1k
         af/xdcM2OSDDeAqEOubeBAoTvY+AyXC8QOTQLO9Gbq4SdtTzGgipp3Y3nTTFfLZIZIP7
         glOeeLIE219g5dCYbRmJP+z1MzpoG8Ti/7hBdLRdbG1m2T6B0XM8Qa2iJYEvLZaefP0f
         fFkpm5+8FuxcIMz4vYh7/T6GNUgIk/7mYV49c7KlnixUZBLR8qzRdSS1SaD7gCJu5jAG
         mTPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F97bEeeJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id g9si966800wrm.3.2021.12.20.13.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v4 06/39] kasan: drop skip_kasan_poison variable in free_pages_prepare
Date: Mon, 20 Dec 2021 22:58:21 +0100
Message-Id: <91c2d00aabbfda5dea828301d3a508a2abdbf686.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F97bEeeJ;       spf=pass
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

skip_kasan_poison is only used in a single place.
Call should_skip_kasan_poison() directly for simplicity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/page_alloc.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 114d6b010331..73280222e0e8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1300,7 +1300,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
-	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1374,7 +1373,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!skip_kasan_poison) {
+	if (!should_skip_kasan_poison(page, fpi_flags)) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91c2d00aabbfda5dea828301d3a508a2abdbf686.1640036051.git.andreyknvl%40google.com.
