Return-Path: <kasan-dev+bncBAABBXFUTKGQMGQE23W3AAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 443A3464062
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:45 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 24-20020ac25f58000000b0041799ebf529sf8496242lfz.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308444; cv=pass;
        d=google.com; s=arc-20160816;
        b=NrBh0ixiE1D138P1a6fMbzsVZqwSQyBMmZAH5TGLTiC7aumL/G11r+SkxDL8rkoX7+
         LCfC5NEKG5x5oZvaiWj+0QnjAaUaK0aXWne36YYfbQVl6ejKJuWK+V2CxosjblI2IEGA
         TfTvjq1pce3kodJ1lXOzCqUggWV1IfH0QXx4vlTQZIKfDJtN9ESLwlTF8XIOWTBa9nLO
         MYgCKXxiNhcWWxz0oug+QSBy0D+Y0kMz3bZyghxqnW7Cy/TvF1WEbdR4vzTlj0NG4xy+
         4ol1DYomDSTuIxQV7HiLp51Y6ppA7yvyCe3BRDI9hnQbn5xOaBA1jrElrLo5SEr25tsb
         Gibg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=J0CaPc2Fsq19UvdFU7jyUDzL8mfgLCXdn5+OxyGGxSs=;
        b=VDcmyiLrc9hu6xwIbx5vk3ON/yqgK2fV5/GIk5eRvmJNEYFkP4zAtQUiM8nlqVy3CS
         dnbswjz8ajd3TuVTCd8ZXLWMb8+qnwqxekwcHanH5C1jq4UlKwYlbPdUf+ZQ20Oz6oFM
         +P95L9DlyDbIohl+haPLBcMMYFUdjVYOiWIPWd7xx+vgawm/BiS3VXG7N8kmr/izsqn8
         XgOpDpmt8FNDk4MDQGy+cIxTE2RelYIv0wY2isWwgBnJPu9TNsq/RMfVCRAz57mAk5iz
         x4RAGneD3HIwiSD7cRC9cwPOETwFTPZiKrkN1YUEs89Aug1Ksg/qVbR1N+O4ZHyNlMp5
         l2+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J0CaPc2Fsq19UvdFU7jyUDzL8mfgLCXdn5+OxyGGxSs=;
        b=fAE71oHNibTR/pLyvmExT46Gh7roDoVmALvjNLp1Z9YPJo7nZ0FVquI32UpgxKnCxh
         5SgeRKO5lOOxhYl2VOpJkl5cinE2iz4nXa34bAYAe50HoSh9tiPQXkNXsxBpCHJC0Fl8
         /hq7cGbV53sXfM2zXdxg8mZrt1QyrgaE7pK7uZtHOZk1zEpCQywag+UvcYeMko1SgN23
         IqowNUgLZWjerqmRFTrIHRDOq+xpiBOcLoerI0SrcrRYHGWTKvR2CJJh9RdZZibkR5aw
         o1J+hQEFBezdvD5soRa7kINIQgXBd4GnFquxbM3sM7uq+yRZ4C2B2saLJj6/rd8fteY6
         pRPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J0CaPc2Fsq19UvdFU7jyUDzL8mfgLCXdn5+OxyGGxSs=;
        b=3tLLWitAlmo/EJbUxYQHcMW29ogoFhhJ9vKN7FMsUNwhOlwAsQhRTkWwxG5T0e5Upj
         +sx1QRM+myl8xr4iQRx+gbvgh+w8ky/jjWmGYB+weMxOyP0hjTkOh2v45C4nnQ1QJ52h
         j3u4PyHmZV3qZTwdF269Of+EjUFImAcuajTTVqmJ9aR8ffuqJNymtrAzsDyCs7UqBoLe
         F+z5KDtztlynCTYwU4QCldHxhrqIdkFMGI2aUTXWz+ncb/fzCEiMpXucnW/5uxVkrqMR
         Fvx8H6lSZHitY2w4wFzZiuigHXM8SKUyK/MoLXbb7FyVVNMPHC6VROxlsUKgyIyxu5GV
         QPRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531oenUyUbyQGSI5kqC9MGucVvOY1ZSl3QIGM+RdKDRNub54tSMp
	b9Ilc4xFi+1qaXUw0jVs6yk=
X-Google-Smtp-Source: ABdhPJz/x2BU6QF+tDteeALMD6cTKlvaikq4Vz9ZW0Uf5xnFX8TfustUY45wwxMWGii2h8yO+HgeKQ==
X-Received: by 2002:a19:c350:: with SMTP id t77mr1782455lff.152.1638308444804;
        Tue, 30 Nov 2021 13:40:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls63306lfu.0.gmail; Tue, 30
 Nov 2021 13:40:44 -0800 (PST)
X-Received: by 2002:ac2:4c4d:: with SMTP id o13mr1736151lfk.196.1638308444003;
        Tue, 30 Nov 2021 13:40:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308444; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4pcEPHYuaEIXo6CZM0ybhoy7szm+4UoAycVja1+WTrhe3Nw5rfZe/lmMTUzQCymBq
         VvqFwHJDSnHGCU9nPuPK179868USaBn5EMMRTFpplL1Z89op1yYCBL59zpqQ5qFS5r/0
         K1aAkdnanCckUmh/kZJJCdC6pSv8o16Om9tSFwJgxl/te1LIlFAZUBtZDsxpyblg5u9l
         nnez7r9Fn5TDBeh2tj3Faf7TD7H1/Xn5EKHUSKImnXT4qP+mr3ibsE41WoqZdyuyh/kV
         Hd3ITVrJq6hkBc389gO/YkdYB3zuC5mBvCOfJMyKERADtr5cazj/0b1aTpwn/UCYjme/
         fpqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=zsDRsCvLOp665k6gUzTOg5pLx73ksI8+J74DDwtZ2M0=;
        b=qrzVh9aglK1wgdb0vs7rrhK9f38caUBakyglVCh43ZaSuYpVBjtN9LWOR3zyEXlsso
         srVBWnaK+cjnGBLTY5YcD3OfjRRVM+/1r1mjZNCoApmD9LfumaPWfhcHlXoYavk7Lqah
         xqo23LP1PNtZQFjKMdgba36JU/YF5cvx5znvJI0lH8SXmUtC08TLOK1f7SypiDCgGzE7
         w/Jpb70z8uTQVPi0IQuhFAYaPGuQfjFrANNIaLftZbZ9pYXGJb+Q7YQqGu8Ow7B5Rkhi
         af4CsuNbhLpjhB2RwFi9tNCHQyBPssHlHfktZALIVxWvYBZmqWuAVrWjE7o7/EHDUc/w
         HKXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e15si1987540ljg.0.2021.11.30.13.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 04/31] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Tue, 30 Nov 2021 22:39:10 +0100
Message-Id: <b28f30ed5d662439fd2354b7a05e4d58a2889e5f.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

Reording kasan_poison_pages() and kernel_init_free_pages() is OK,
since kernel_init_free_pages() can handle poisoned memory.

This patch does no functional changes besides reordering the calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 18 +++++-------------
 1 file changed, 5 insertions(+), 13 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3f3ea41f8c64..0673db27dd12 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1289,6 +1289,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 {
 	int bad = 0;
 	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
+	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1359,19 +1360,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
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
+	if (!skip_kasan_poison)
+		kasan_poison_pages(page, order, init);
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b28f30ed5d662439fd2354b7a05e4d58a2889e5f.1638308023.git.andreyknvl%40google.com.
