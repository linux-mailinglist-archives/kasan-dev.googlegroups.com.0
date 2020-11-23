Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYVQ6D6QKGQEFTHPXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F2AE2C1578
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:31 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id z9sf3911642ljh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162530; cv=pass;
        d=google.com; s=arc-20160816;
        b=PYKmkh04dspMEeED3LMwkF/Yrg7zG94xZ4+nMNyiUo6e+wFkeHIbL/JcU9wC/r+6C9
         iWVDHeOKsAhhy7omccVP6v601/UPpChTDgxRsTraV968LaIPPrzmwfzZ3lukAQupm5kE
         SkbVM9xpCTk5uABrfl1px/lca28SIKC0D4JXDKMpu+pSvQgkQeP7z0ajArBdgAMziyUa
         aIeggcJawNlCbtr9p5pkpM6u0xk/Kd3mUF//HjAq7buudtA6Ajg8dhYH7N81jOjtYqTN
         xdSbe+mjASCmME29/JkbWh8qB1SvBELKvckLGZJmARdjYKrmgKRYCyLH4F9yx+R7Rq2z
         GzBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=WB2MWSwBU65sMjpH+lWB+Fs5jVJJhtO9/u/MLtlGSeU=;
        b=SbbMYD6AYrxxXwaFp8PsTliCky2pyA56fSRXuNUa5TwoZcKuflXiq36aQAYBky7znx
         0EqiEqwNIkD9M+k+orkew9HN7sL2rTc/Yx7tuFnDLbm700vz9WfttAxsvw07hpurweD6
         8bOnw9+S9cG9cRboaw9VnGX5M5dgIoFUREa5LbS7XY5K+zVxPA/SoHjFtCTJEX3t5u8l
         AQlA5W8vD/5iF9gEX0CtUQ+L4q+l2aDDJ7Ff+839AQPlwNW+xcsAxTK1dHmAz5NGHnlx
         zJWco90S88EQz5ueTh+pXr11D1l+BPNx3KDRMUQQC6T3mYhAKCo26ySa3osQAL5gUEOA
         ceIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHo5ItmT;
       spf=pass (google.com: domain of 3yri8xwokcyykxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YRi8XwoKCYYkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WB2MWSwBU65sMjpH+lWB+Fs5jVJJhtO9/u/MLtlGSeU=;
        b=kB9T7n5/4vuk/XzO+ygmxVllL9b+YhtY4jgMnkWkjriZ2EshQqyrNO2Ff+ga+uYYHm
         HXGKXvGnHgkj2ii9PWF2lW4Uelf2PGPrAWBXJMV4vJ5nkfK0OGskfxe3idll/yKybzki
         Jt1eJZlHyOXIzeOT2E5O+hKXFjWcSpbK86nxHqRPmsSvrDdHvZifSoLXot6LeruTFwya
         44QuJ5wE0XYbM7/7M5eASWcYbaoZt8tPL8jp6lQFu8k9U36tDZCkmxTego9OqKFNcbtB
         9xUo07chgx8/hWs9s64tqzq9JdF7j34lNGVOw5OvBf6Yb3OqFCgpURzIOV3qHzJbEmcA
         XCWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WB2MWSwBU65sMjpH+lWB+Fs5jVJJhtO9/u/MLtlGSeU=;
        b=i2Kgktk7aJKCYsm7HdC1MAa+7d5o5SUExe21eQzpOuLMGa4pFZuHtFPMJnMLXmyn1h
         fMWeVjIT4p2DuqNbxsT3bbm6UN5whLTTMrfqvdTg3sIxmGbdiKRMc8CvRxhgdZvwHGA4
         ITxBe9Q+HHWyFVQHZB0KlaezBbMwvRmiXFTjuRX3VzAHs6gzBBRhTH1bVWSyp7OZyVJa
         w+0orQ6noxAjqKiWU8NDEoCPlw1brDug4ezJYbonp+ZLbUQLVrQbYWqih9j+Mqbh4RTD
         98XIgDChKRR64gI00jW5+elqbzlxafcrLhkGbWa3gYbih/DQWV5z1bX+VqPfQTQamH7+
         +mgg==
X-Gm-Message-State: AOAM530TLLJ6e0iOYXaotl02ZY5KB45TtF6jBZelxyttjrsZHqrJJ04I
	QWkDLKiNG7qpzXFLGq8xZAo=
X-Google-Smtp-Source: ABdhPJzoVl66X8xKyiQm9COww5tF7zu90jWArGOnPJO+9Inu/a7R5fSh1b6gbWelu96TviMrIaqo8g==
X-Received: by 2002:a19:bce:: with SMTP id 197mr377593lfl.468.1606162530750;
        Mon, 23 Nov 2020 12:15:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:: with SMTP id v13ls2568617lfo.2.gmail; Mon, 23 Nov
 2020 12:15:29 -0800 (PST)
X-Received: by 2002:ac2:4204:: with SMTP id y4mr410632lfh.224.1606162529888;
        Mon, 23 Nov 2020 12:15:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162529; cv=none;
        d=google.com; s=arc-20160816;
        b=fIiu7MXOmN32xT1VznEDWXEldPG/juY3VIW1P0FZNgU6ZlvKlhl/hnoGXpQWk9TWxv
         Nr6+K6CpnT7/vvM2JavnFVYhxNoq6QPlvEKzqQij1qE/1l4GCq74Et/xFrpt1XDnMS+S
         HntZC5E8sW/o1rIJwoltCuAIe/lp+l3Jk6gXXShwiBGEaAqGfyO1pf5peJea42FEEofm
         DqaBnNWHkUtc/UkyJ2RTrzkKr+9UEpD30RQBZ1T9D7/pDlAEFCDmIw/IG657p3kbHkP8
         AYBPlqqH6HF/7PqVQM57Yk5sr3D4Zef+Wk6Sld8Q18Dh4GW0vvqwttYcW5LJS/kfULQt
         ra9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=wBmPP01T6X6nVOaGKZckDZFO93MqGK09sbRfPDSt1eI=;
        b=C7g182FZfeJW307fnIP9dOf/4PFJ9nvGgKDbf0jWbDjosHbgJLeakZPgTGbb8O80Wu
         sGOAt69rSzMuwrDtfEHl8Mx3OXblMLwQbRsOkwLcFUf38BwiStc1PIc8JfK+2/87DQzt
         JbzhDGbiqOBSdjAkZZHh2IZRei5URLwdGQVboI94D9tXax2C2DHWhFhrUKEiBUEwuXv5
         MuZtNOjJ3i6zZ41qnIfJgQzqe50VMTnQortRIs7dcajarnxNLjdsqapXBUhDdVl2Eqd0
         DrpbEcpJjq9Oite3qSXJSE7t9uDFmoJIaBDYYQVwMzTSDY96XHyefPP7Dy4Y6yHkXuIg
         aF5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHo5ItmT;
       spf=pass (google.com: domain of 3yri8xwokcyykxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YRi8XwoKCYYkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f5si29519ljc.0.2020.11.23.12.15.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yri8xwokcyykxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q11so1499657wrw.14
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:810c:: with SMTP id
 c12mr609306wmd.96.1606162529119; Mon, 23 Nov 2020 12:15:29 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:45 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <121eeab245f98555862b289d2ba9269c868fbbcf.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 15/19] kasan: simplify assign_tag and set_tag calls
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vHo5ItmT;       spf=pass
 (google.com: domain of 3yri8xwokcyykxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YRi8XwoKCYYkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
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

set_tag() already ignores the tag for the generic mode, so just call it
as is. Add a check for the generic mode to assign_tag(), and simplify its
call in ____kasan_kmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
---
 mm/kasan/common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1a88e4005181..821678a58ac6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -234,6 +234,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 static u8 assign_tag(struct kmem_cache *cache, const void *object,
 			bool init, bool keep_tag)
 {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return 0xff;
+
 	/*
 	 * 1. When an object is kmalloc()'ed, two hooks are called:
 	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
@@ -276,8 +279,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		object = set_tag(object, assign_tag(cache, object, true, false));
+	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
+	object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -364,7 +367,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag = 0xff;
+	u8 tag;
 
 	if (gfpflags_allow_blocking(flags))
 		quarantine_reduce();
@@ -379,9 +382,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	unpoison_range(set_tag(object, tag), size);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/121eeab245f98555862b289d2ba9269c868fbbcf.1606162397.git.andreyknvl%40google.com.
