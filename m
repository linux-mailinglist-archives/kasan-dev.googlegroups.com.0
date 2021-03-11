Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMPGVCBAMGQETM3XHNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id CBAF9337692
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 16:11:46 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id k4sf15742608qtd.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 07:11:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615475505; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfClI9XyWlmVB0tsiDdR4wD2NhEd2X9g/hD0fNbYecYfPzOG+Rwjpv/b9gY3iIObmH
         fntOdiiANWjALUS45JmHJZVBl7L1qBcAuTxWJpCeFD/FpWeWyx/y1kgfafkHguJ9HwTu
         2hC9ecJGfaO48BsDR1+BnQe5K+mmPpdlmpJKX03JWjexu9D9lWo2lEbOrSHzquHGyrd5
         RUT1/mnt0C7IQGV+RI7kDsucmzFGovWPgCly40qsQOZLi0cY+yhun/CfDdw9SOKzxLfY
         73b+/jfai180xZiEepZZmzc+nwXuvIwDPNFk6c3Q0S2UAPM0A6NSyouMscC+uy4sAtcX
         KcRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=izeuZkxwmxYSY66tEq1Las8xddCWNHdIga8zU6komWo=;
        b=sibynyxJ/xZxHUnlCbH1FxaKWT3ukTUgBz7hpxcD9ZYEN0vzqdrJFou03a2U9I/0yl
         lUcw9zHgV7RKFiDrXhyQ9/TA0pjX+hGGqeYYy36jOOtBT88YbuExLLLdWUyx9moTASwj
         w1iPowmtfLGOLyINs8Dr8UvfUIhdLF2a/3NA5rE32tYdy6HfAtYk9sZFudjTeIuqsjgd
         bTVyIr8sUqMZnFAx0oeAN1vtziuZF8bPbZyuUptrSKhYxI0vHy8e5DiXheFJC9q9kvo4
         7dC1d5KTcfN+zw4oHWgLlM17nXxTTFHtHDMbzz/UxQYVSOZb3RRZTGbXxwyQAyGtZJTQ
         lwSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RHJUA4xf;
       spf=pass (google.com: domain of 3mdnkyaokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MDNKYAoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=izeuZkxwmxYSY66tEq1Las8xddCWNHdIga8zU6komWo=;
        b=cVBogLQDDThXGzb8f040XmxFIyiwBZGVcPlaPglCY8O7WrySjFVSG7frhT4I7e/ac7
         mWyqZy7htCj8Qr0+7YF5QlmcCJu2Aee0vApqvGoNQOgNXMUuq6qPrj7y7xpNYGyQFus6
         QI+pC7Fm2Vobu5AURg1XvpZJ+m+C5+49jnr+Bigj65/XsROG2WNzAxnlDQTQqg9bhPZx
         DeHZGL02TEzQRc8wAmnePdA5rQlwu60/1mLrGuUcX3jyrVIqnra+1agrqSYCSidfoEsA
         Dq07CyCW3WXDUDts+5NZLdOGmVPGK2gUARkY5j+HVqP3C98f2bMswVg5Pui3x1wrrm0h
         QnWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=izeuZkxwmxYSY66tEq1Las8xddCWNHdIga8zU6komWo=;
        b=iH62blV99mYPPG8KeUw0LEbCpCwE6EhvC4SO7mYAzrE2ILEdiT6TqEW72kBnzSQMr4
         Gov//CKm6iIoqn6keZDSqn6ssx/5DNfKh7efBkAY2UCGp70YcQ42PUmhNkGozbrRvSJQ
         Dk8WRz2dEVlyD4uaV2cJxx4b1FTBt3XMyNUZQ/0VkAbaRIICV6wXqIlCmQeh0hqkyKze
         fpdnRpPw6ZcWEdYviwRY3mUZCFQd2jJ1pYP874N+htjkQgoE2t8I0EyTdAdAWy4ITE7S
         50LRR4gDYOHCEjjdukB2Ys1+fPvcWWIdaOsMqg40JGC3cIwpXzGTFmgMj73V25VVl0RV
         lTxA==
X-Gm-Message-State: AOAM532T0q3+ePcs6Z/ySal2KJuZ0vsruz7gyUb9amLnw/a/2KW9Iv2h
	1BNNqfUNTuRKmh/cgVQli0I=
X-Google-Smtp-Source: ABdhPJwyaHlHh/xyG433UsN2H1dLrpM0NeAHDBVfo/Xj6wVHuiM1a/bWsmMcS4sQH1BrIiOffPONcw==
X-Received: by 2002:a05:620a:b01:: with SMTP id t1mr7732095qkg.422.1615475505684;
        Thu, 11 Mar 2021 07:11:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5803:: with SMTP id g3ls2282564qtg.9.gmail; Thu, 11 Mar
 2021 07:11:45 -0800 (PST)
X-Received: by 2002:ac8:4e95:: with SMTP id 21mr7673289qtp.177.1615475505144;
        Thu, 11 Mar 2021 07:11:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615475505; cv=none;
        d=google.com; s=arc-20160816;
        b=HK7V9v9FwNLl+KLjhDtY0oV2yz6MHYYVbzGE8Z1IpAjsfYfWaLH4FNpqMoEEeEgEOP
         riDZ4cDI8o1o7w6Y5lBzHGoIHD8IAOQq/10PQqPDs3mimhIlWwhPB38ass3nclZqqIpQ
         ysJRuo3jYQB+1azgEwu2xqGbml/Ym/io6odmzS0DGxEnrJOXdb40uMK8nl9Yh8IFYtyj
         +WGiAQAxlgepIhngP+ChF1o/nMAWqoZ4ZGt6FTJt3xJNI/3bfAdf9Jlu1ory5rZkXFlq
         bnVAqPC+LSopAkIp3OzuDn0dc1iwJ0vAQhR0VDJbp3zHwEyjllhNjX2I1cB0P7vKkFFa
         Y8ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=AApTWOpa7ui0/YyXhD3tUhfEI1bu0UZzTT8+Disz7/w=;
        b=vtrUOS6Xjrj80fzyx5BvvVRhpGTmncelBXuaWXh81p9+Gn89qrLKHu6LQZMxUPUGRk
         fjPLpMEThAZ2byNxu8hbe8GqmUCmHjoNszeD7ULseV3m+8fzxeFSLahDTrhW+pS9Dc+v
         PTHbo196YMicYfAaR31Z7FLw1phJJk34+1Ydl2qiZKyhLUe4Fr6rpllIV0Pl9AKWkTYk
         0HXXOIVGtd0cOD/5+XNUsYOwh51u+aYNgRfm9xSVVKgvR/shavtJtzguTT47/fcvARp5
         byy/9MalH7R98P6gh1roU4LbkP8tUtG/7oPuQRRbEUgBfjN0TrJPLGPhGXzIZJjgwa7r
         9Jfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RHJUA4xf;
       spf=pass (google.com: domain of 3mdnkyaokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MDNKYAoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id j10si167494qko.3.2021.03.11.07.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 07:11:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mdnkyaokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id c1so15748299qke.8
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 07:11:45 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ea4b:: with SMTP id
 u11mr7819047qvp.43.1615475504801; Thu, 11 Mar 2021 07:11:44 -0800 (PST)
Date: Thu, 11 Mar 2021 16:11:41 +0100
Message-Id: <1a41abb11c51b264511d9e71c303bb16d5cb367b.1615475452.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH] kasan: fix per-page tags for non-page_alloc pages
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RHJUA4xf;       spf=pass
 (google.com: domain of 3mdnkyaokcccn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MDNKYAoKCccn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

To allow performing tag checks on page_alloc addresses obtained via
page_address(), tag-based KASAN modes store tags for page_alloc
allocations in page->flags.

Currently, the default tag value stored in page->flags is 0x00.
Therefore, page_address() returns a 0x00ffff... address for pages
that were not allocated via page_alloc.

This might cause problems. A particular case we encountered is a conflict
with KFENCE. If a KFENCE-allocated slab object is being freed via
kfree(page_address(page) + offset), the address passed to kfree() will
get tagged with 0x00 (as slab pages keep the default per-page tags).
This leads to is_kfence_address() check failing, and a KFENCE object
ending up in normal slab freelist, which causes memory corruptions.

This patch changes the way KASAN stores tag in page-flags: they are now
stored xor'ed with 0xff. This way, KASAN doesn't need to initialize
per-page flags for every created page, which might be slow.

With this change, page_address() returns natively-tagged (with 0xff)
pointers for pages that didn't have tags set explicitly.

This patch fixes the encountered conflict with KFENCE and prevents more
similar issues that can occur in the future.

Fixes: 2813b9c02962 ("kasan, mm, arm64: tag non slab memory allocated via pagealloc")
Cc: stable@vger.kernel.org
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/mm.h | 18 +++++++++++++++---
 1 file changed, 15 insertions(+), 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 77e64e3eac80..c45c28f094a7 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1440,16 +1440,28 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
+/*
+ * KASAN per-page tags are stored xor'ed with 0xff. This allows to avoid
+ * setting tags for all pages to native kernel tag value 0xff, as the default
+ * value 0x00 maps to 0xff.
+ */
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	if (kasan_enabled())
-		return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-	return 0xff;
+	u8 tag = 0xff;
+
+	if (kasan_enabled()) {
+		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+		tag ^= 0xff;
+	}
+
+	return tag;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag)
 {
 	if (kasan_enabled()) {
+		tag ^= 0xff;
 		page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
 		page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
 	}
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a41abb11c51b264511d9e71c303bb16d5cb367b.1615475452.git.andreyknvl%40google.com.
