Return-Path: <kasan-dev+bncBAABBO4IXKGQMGQEMO2IB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F1F3846AAA6
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:27 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf2337278wrh.20
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827067; cv=pass;
        d=google.com; s=arc-20160816;
        b=lVEvhVXHLbKGO70K/5K+8PaEwsbh/p4dCo1rPWBOXh/Hvvitq4dQM6g75cc6oFYLGd
         h8GM1JQDGEqT0ZZrBsbrRaI2xHA6hkAViEKTEaG2epI63vKxvGFjY98UKe7n0I6VJfUI
         C9urnmyBKJ6JYBDzujFglejC+JAiysmaJzOaadYpP4Uc5kDYqAqqWXlapUBtlNCOZiXI
         96EkO7iZ+swcezwmxHY7I0XK9GyQlqEC+7bFV+Lz2xhXqu/mAkmtk0bNL2mOzCDm+Qwa
         lB9bYpqrbKIOg+hYxGCUHaCmbqgQFYfrmv5LFWXFNkzpt07cQXvx+81r4voYIr9bSJVP
         G2Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JEdVq44hDHC7MM6wQmc5BK9qfZDw8X4NAToHAna5Mrw=;
        b=TGZku9Wnal6Ti1E4xafkt2sduO7egAaKaBlnJfZO6aRiKqX1hZFbKGbGoikIkDFNq8
         3mlBvAXxsC+/CN0EDn6qO82GaAgQt4JxRTiBhgxeRR8pTsDOWJwVXz+6NUuiqwIABE9Z
         i8Dsj9dS6jd7+xR4SMt9GGfLYMVe+YFh6NnMdAcmZ4q05zMVTS+t78MIfQghEUYP/cu5
         sMmZjH/kOqsx7Gkb8Ca5bke73bOXbDDEjuPz3oK1pm/9+03043VWbXvLcz+pCb3iB5M9
         1Qo15l/aJXU5H3gzoRH/IOz312BkBOhQYUV/5dGkVSQ0bXJkhetfT+g/rek2CUNqukyD
         97Fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ib6i3xZY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JEdVq44hDHC7MM6wQmc5BK9qfZDw8X4NAToHAna5Mrw=;
        b=Su6BtmwdWlxopXMMEJxqV6PwAjKqPEA1U2LZ9uWvs2yhgbvWnM6UHnCNKgQEVBXGzK
         sNGDHkYCaK1aF72rBW0mJ9oNdG6jcd4yrZQqKkkiEFvgeaD2PKLxxd0lQruUQDQlYlpL
         nJ9uwvQBbgvUJS61wYJKUuU+vR2l2sfdaR3HyzvseIvdMFRxPWf8CLISgv5+iAexSu4Y
         TZjr4ZjIr0A/+060M6zd4VLPP9UUNBfo3DoeAJD5nKhmNkjQJ8qT+eAtaEojgqgEXJ0O
         yBOKvA4TF2fwowJdveC00RDDsQOg9DLd9xbKySmXn+6nbakVzyfZexMM2/9E9Gr8h+qG
         c1Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JEdVq44hDHC7MM6wQmc5BK9qfZDw8X4NAToHAna5Mrw=;
        b=Ioc1rPbXlqUvuFOtLitGvmDibsOnPv0ojIGvjCPvvlet08mzIlgdRVKY91MM/srk2P
         7LcbWdTxhW932L7NZYJUq+WKc3ZJ0w/5E64FFfqbYYS3xKjvoVMrpbCGM9yoPQj+TX3v
         IX63/2u2nOZNT4FrSNr2SXDEb2NFQ8s9PgqxVdssWAKuxOsSxIvATyZtvaIZcTAtbgQM
         nLy3TxVaWqMNDF13zUX0kUa+xol5QWJp2bTITUVBA/PAdFwb/wBW9HUhMuX8DPXzlRxP
         yCgBHKYPKRWeWRtBwutuMs9MJ+QuZXfXAoo+hYp/rDsH2DNjcdVeBebQGp9zx+A44bye
         MfDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530k+wzwHNyIzv99o29f2GqYZawHtcbbPEw33UunrYa01ZObSi/Z
	wUl1Gpso7jLFXYr+NJWZ+V8=
X-Google-Smtp-Source: ABdhPJz/YjSkT6h0Mmp3EPOhGIQb7B+Y/1gQGGMrpPG9MoRFvzege43TqwIlKQZQJshL5vxs+lVFjw==
X-Received: by 2002:adf:f44c:: with SMTP id f12mr45051939wrp.620.1638827067786;
        Mon, 06 Dec 2021 13:44:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls225832wmr.1.canary-gmail;
 Mon, 06 Dec 2021 13:44:27 -0800 (PST)
X-Received: by 2002:a1c:4d0b:: with SMTP id o11mr1542557wmh.68.1638827067053;
        Mon, 06 Dec 2021 13:44:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827067; cv=none;
        d=google.com; s=arc-20160816;
        b=ZdbeYplOFAcpZPBwxJcyH0EHVqvaatSTfqnPcDNgvSTnMABLzT4vKq89AcqrJLJbRm
         Zolv8XtfbgWu9k1SHyGg/iE5vwiuEYNUuvlNnk+i9+kM0GPnzGtsoL5J+VdCVYN6bkMG
         RhVYHlImAJqksydjmqZ+EKXroQDX7Xk/uftId0uWLFeF3vF5mY4EWjwGY2x8Ea2yuUDt
         Snpp+kjzvNknZIr31HViV7VmrHz6hYBudC+ZzWPTzet2fCAUaNAWjcPvCrbclNm8jmA5
         QoFxPeFX8eLMhn0XC0YXTxA3YGPtKOCOyI1OD+KNKpUChRy3pTBr7qrbZw3CeWy6Y9nM
         WWOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6WD5Ks+OgrOC+xp6cA4qnOUMHkVFyvh2xcK78VT3o/c=;
        b=GToRKWIwTGgYUIgE100ZenwpO1WZ3C7d34rSkbF5ahf563r9Zq7LQtcDSm1b1uG2wD
         UxadvAKNH/JlgE26EPJbT55kq5iToW7OEkqH7G2ugTRPP2C+buLBGWXmILtyd5bw0v0s
         zWUinHWv3jpR7yU2N2rl5p+M8waHfu4ljL7AGFt3wqH/P8bfUmj7YpLvUXX4f2SizHlS
         VqFKXonlkj456xLqhMKxqZuD6DkHy98tloLKJk0mEIvDo2VmW5mZ9PrgFQQLJI1wjXZI
         knCeaV+TktFGeQV30EWhQiFXE0y/7elkMamugxPxQsCJyj9hIY0/kh6y6btaFvfr5Nd9
         fz1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ib6i3xZY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id o29si118222wms.1.2021.12.06.13.44.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:27 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH v2 06/34] kasan: drop skip_kasan_poison variable in free_pages_prepare
Date: Mon,  6 Dec 2021 22:43:43 +0100
Message-Id: <82bf83ec678d19cf086bb62d92f5fe113de6e8b7.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ib6i3xZY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 2ada09a58e4b..f70bfa63a374 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1288,7 +1288,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
-	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1360,7 +1359,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82bf83ec678d19cf086bb62d92f5fe113de6e8b7.1638825394.git.andreyknvl%40google.com.
