Return-Path: <kasan-dev+bncBAABBJ4B36GQMGQE5KGENZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E6A684736CF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:39 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203sf7048077wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432359; cv=pass;
        d=google.com; s=arc-20160816;
        b=t5zLfEZEzOGlXEwTinBh12kr+x9tCE8gWyJll1o1Bcjw+ofNvC5voNeRtD1FY+y0DJ
         oa6KIp/UvQTUnMUl8VkV2NDLu2mmCTXq9HzYBZiX2GL8x8ClA4HIJel4k7xBgkXvaFfK
         NjSYqeA7zLGz0NL9apT0NmQywdNFpF9mdKtiin+/yPU09UbQfmvRDyAnZNl5YBSM1XT6
         RCg2fZ9WwjTXIqCaaZlfN8W7gDD7aV7S1KRCeLjId4e+qRg9oV0F8bjaeJWuxcapwuK6
         Iy8iLh+BI04dg6MXcEfH6wngu5yXqMMR6m/x5kl8Xir1OlXhfKDYmCVEVQ+jJ7pK5+pz
         W4pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5jWRlJ25+Lk6uheI59sHTX27icffE9GaYkr6N9C0cKA=;
        b=AhKnUJ6ZS6UPl8Fv0I1ubNzMKH2oIQXBkQFK5EYv18U1jQuv04uS8QBSQ/Zhwzo2hj
         zw0cvQYIy/oZiF1vvvGYUNQ3Ms08GuDiM/23P+sBlSo7tlvtIYQj6wFhmt86/dZudGSc
         Eqh7c14t2ALn5pJaSFZ1jzoMzfctD46Q4A+EJLXThIzpOv869HLyrmzYCaU/SS5u9jA/
         m3ZL+C4Ie7PBlQTw7LrXzDvWYYz8y0nFod3C6SZiaYzAm7UDCGDncAvwek2GWoy8A5JV
         6wor3FcvweJc5IVXQmzdp2cGUVSkoT7sf5zPHJ1D1Ge2vBMHL+IOmuApiA+srXI02hEq
         njIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G5CM0Ggy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jWRlJ25+Lk6uheI59sHTX27icffE9GaYkr6N9C0cKA=;
        b=DqhsvPa0Ko9E9OnZfThtkT6xA0+7K7+IvE7fEqAZr4KqldlMYgUN8DvN6t/AeHkOa1
         oNtPVoP/a6e11MQqpkRNl0WBVHfIGF9aSBgKn44pY83dnHEAGnSHqREo4bvHqAGzbXjr
         aQlxD2eQtqCFsqmECwtWWZMW+t6pv4DcbHRvUlpRA/5xFl+rv4Riq6BVDXfEPkNh096F
         r5zizJzK5FIY8fIReCfRoUOzQrDrQaU/F62rahn59LFsfEhg1zwE8WHbCyQ9D3S3FiSb
         bAW25HpL2sjUId47DvaLjedgSG5UTp6qG38hfZpt/v7q6kAU2jwabsYEBn4A0eycqF0/
         8FiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jWRlJ25+Lk6uheI59sHTX27icffE9GaYkr6N9C0cKA=;
        b=dZDqP2BrWoT1dh8MxP5xFvtSEuVd2i+444jY1Kqwz8NhwTtXRcy0J86PXS+Y2ys4iN
         Gw2IuvMw/ZgzhhWVgWYJNevfGzz0Fd0Ieqrjhn9wZUqne9wthkgSnWB1KaWn7g+n340y
         5+SORfJ+Y0dRrHO3/ieKyk8w7rd8et1/1/ubWRNNl3LnPvHd2dNPB042AHekUAaeNgHl
         FmlLL02USeR5yF/XXnGjVPokTExxI6gqU3x9A1J0o/CRb+wTo/C/TuPSm9/b7tDWw+gE
         UdmtWCFrN/OLL928rWqkMgsCqz0zHCivTw6/wBhvH9cBsHoCOrR69HwR0qDVwbiJxXm7
         BEQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SEhrGHptyFEnCsNU5T5VKR3/t3KNTPaRd3K8yDOgM0ak6S3Yb
	l9e8m2vJQ7muX8ajhhsspLA=
X-Google-Smtp-Source: ABdhPJzdQHpyS6iZVPaq1B6P6Cq9My8UFRVyX+e2GwDmgzZ4MXGGDGMmOfeYmVW0HhR6zv0BcHMWHw==
X-Received: by 2002:adf:82f7:: with SMTP id 110mr1249381wrc.111.1639432359595;
        Mon, 13 Dec 2021 13:52:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2110:: with SMTP id u16ls93999wml.0.gmail; Mon, 13
 Dec 2021 13:52:38 -0800 (PST)
X-Received: by 2002:a7b:c8d5:: with SMTP id f21mr41102532wml.146.1639432358750;
        Mon, 13 Dec 2021 13:52:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432358; cv=none;
        d=google.com; s=arc-20160816;
        b=gKv4h64GhvQcyUMFpuGFNrBjoTvlVsMRWp2xCzu2svXaVJLOVvW/SIvf8yE7wKII+2
         9OGYIxTVM5qbnulChc3EKgMbxfDMhlsMpnrw1h7+OfzGx15akiINxQY2dckCm3PwpVnn
         Xmfq9At0b3Yo2NrsxI8V/gh3qASw01bM8yaylpfIFjnRbAqWic0eaIq6sCnfV3LY1v0b
         iB3Jhuwoz/IGMa5TnfMoDGBTo5S8hDzoOa2o7XW1GKltLyRkG2+CN7LSEuK/tYycsQm6
         cy2JzZ2DOlO5MNPYSzNZ9ajVO5OQOyulQv4dqPXPUw47Id13p2nxU/Cp6E5ZpWCH8gb8
         EyNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rCn5z8YiS6P3XwP2jmdoUMnLM4ulEzQucJZxHZmfuTU=;
        b=ITt49XffYMjF8lI8+WMa6Na9+1eiw5Q0rx+EepBMY/3zDshg34k8+QS0U0MUpnSFxM
         Jt2f5vCQgsHw/brxB4h+r6xALWmLDjxcvgPh4tQRiRONZHkD+AcKJ3WjR1Gp/inHnWga
         /A9HK2xf9lo2wk7AXSW0a9ek26XIJxwWjKFKwNByEPdGoznHSz32ED8trKD2lgpY4+Z5
         3uOws+bFdsWj6+icKLV0cQsAZoOWIRLXsfRK2cqWISWhlRy2wxOHnW0cZV0Tw5Ey60r2
         LxzcFwSjC6aJrIjM7OagGIXmQQJpfO7Ov3H6MJ+jVC1sX9CfR4T4H2bEXmpPGlD4UacK
         AgcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G5CM0Ggy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id s138si33354wme.1.2021.12.13.13.52.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:38 -0800 (PST)
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
Subject: [PATCH mm v3 09/38] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Mon, 13 Dec 2021 22:51:28 +0100
Message-Id: <fa64826c55c90d29f8ce2f71b588591fb9cfc23e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=G5CM0Ggy;       spf=pass
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

Separate code for zeroing memory from the code clearing tags in
post_alloc_hook().

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 73280222e0e8..9ecdf2124ac1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2419,19 +2419,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		kasan_alloc_pages(page, order, gfp_flags);
 	} else {
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
 
 		kasan_unpoison_pages(page, order, init);
 
-		if (init) {
-			if (gfp_flags & __GFP_ZEROTAGS) {
-				int i;
+		if (init_tags) {
+			int i;
 
-				for (i = 0; i < 1 << order; i++)
-					tag_clear_highpage(page + i);
-			} else {
-				kernel_init_free_pages(page, 1 << order);
-			}
+			for (i = 0; i < 1 << order; i++)
+				tag_clear_highpage(page + i);
+
+			init = false;
 		}
+
+		if (init)
+			kernel_init_free_pages(page, 1 << order);
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fa64826c55c90d29f8ce2f71b588591fb9cfc23e.1639432170.git.andreyknvl%40google.com.
