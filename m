Return-Path: <kasan-dev+bncBAABBLXN26LAMGQEGTQLX7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id AA30C578ECD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:26 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v123-20020a1cac81000000b003a02a3f0beesf9431978wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189486; cv=pass;
        d=google.com; s=arc-20160816;
        b=rq++Qvn7Xi8nnGsRPVziz18Mb/51P58f6SXW3NC3A+Ln01mKWQxY1TNN29yYN4amUw
         W3gI8KU/2WIdS2kQQhV+YM5EuQl6ev23yd2giAXDBSaVK36O7XSms9Y6hiaG/2a0KV2X
         sZsqphdztyAKgYxcfvAayv0Ptn47f9WvTJ2j5L7Kz1RQ1ml+M55KBKWzGa/I9ZYZdPnY
         bb+e+QwBq3skkMmMt+QewLaFs17v7jEyXpdzaMGYGrxs62ZGE9XNOioirzCCCkcgu62I
         R97AdvFCn5/l+ARDAUhNSlttT9u2m9k3GvmxDm445r2epuqqzyUldojNZeULgAYyjki9
         ausQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wJJsWvJhIjXlTWJxy+XqjfHxqha8+JgcJwaOukiV3NM=;
        b=znmW2adcOGItucI6cfRz/jr98a+gyr2n4e4QQ7HxwviJ/Gj+m8sg9SGCEaXLjcKPrK
         o7CvcN6DjzQVhWPSd1KOARyqnIZFYXu8mP8gE7rH1ZcGZqbKYbUyEMXprgdCsRvM+6MW
         +311P8WFqm3B2kbpsLoVOWPaby9Y2HVwDKeSLADY1ClCOg/TWtOWwnxctY9MCB4JQJgl
         1tmP5ILidopN/B4a/h+Q+IcIvmgv3ao6IboARa5QDFCXMREtGj0LaBp0he1eSeiFXWe6
         QiYXtrszyu8yOdAKTSjVV3NB2p2aOZ9SBdphIAxd2v+3Af7S9b+hsWGMCE057i/9WvJ2
         TxkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Id+3GRXV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJJsWvJhIjXlTWJxy+XqjfHxqha8+JgcJwaOukiV3NM=;
        b=kpXUbsEk0InBbCY7+lf8F2T50RTfb79XBL7+9HSn4EdZVCfsGiGDZLWJ2AQlOAAdXO
         GqdwdO+V9tX5KSSYDUgVAPvYG0ZM6AA6MHHc909zKKbI1lugselkGePl4ixi6YRZVw1R
         aqn2A4i29dgRsx1j+H3hxdaLeWAD1vqMFwKyWFuuReITwWpkjKIkTSnYG9TAku5NtOdS
         TARatGEBU4M4Bqbq/Gc4qBEfJBZoQACRnEw5XmWfPYHooMrUnKc3Dv0LY+ujDJVeH6wE
         RnzuoIHi4R6Y6DkH3HcGyywMYURupPW4NUG8WVHpfjFbPQ11MzhS8oClpHgO79nWCQRD
         OQiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJJsWvJhIjXlTWJxy+XqjfHxqha8+JgcJwaOukiV3NM=;
        b=JwhqJitGet8dCpbjr4mIoBDAIq1dBA1PDfTE0DlhLsbC9shmZLbXVC3FcIhDssowRU
         0RQRZv5d9QPvH8cHPvSnUtJLolksjbTabTHkdIN08bQLTk+vtxAc5tbyvqvhUYpOttfA
         qFoyjh5dqwbdrB9VRArSIDMqgl9e1mk4XtK5ybqAbbavYeCtH2FtUg3PvBXh//rOeaHz
         mJqlhqKCYlDz7dViNXWgu/raQBhJ0GVD67szmL95w0ZcuLfJzy7qgxLhQYXm0x9iNVGs
         TQUc6kO9KWMt9PKbaVvpJIC+VvxTnSjXTkQU+bU2VzFSp7LzvLSjCMzt4Xhvtn4gR1KL
         mgpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+jmDbcJ6/vvCYLoAHhuolMgn4C+8rkgPFG8R/Cp/FoERKaaF/3
	xtoVrtb3mwDwwiCzXysZOUQ=
X-Google-Smtp-Source: AGRyM1vu1sLQ8ueLV74YHPgg2ZGiYVhHErpkjpnozOtrXjx2SK9uzG0mnDGU/GVjen38sqPchr69Zw==
X-Received: by 2002:a05:6000:2cb:b0:21d:7760:778c with SMTP id o11-20020a05600002cb00b0021d7760778cmr25456393wry.329.1658189486423;
        Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:284a:b0:3a3:7eb:364e with SMTP id
 r10-20020a05600c284a00b003a307eb364els41006wmb.0.-pod-prod-gmail; Mon, 18 Jul
 2022 17:11:25 -0700 (PDT)
X-Received: by 2002:a1c:7209:0:b0:3a3:1f31:ef3a with SMTP id n9-20020a1c7209000000b003a31f31ef3amr4074646wmc.87.1658189485734;
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189485; cv=none;
        d=google.com; s=arc-20160816;
        b=FH/pkhRggrtcmZ2L4vvgrnLye16f9YqCZn2Wkb31YKykj8QjraF/5DzWCM8iMqMTds
         RT+j+y6fs14e338w0lZYQLa1WBVaMpmSLnFKyu2yjglwx0HycKuTpvAU58smZoyzhxEN
         xgx/Pe3CAK67bWEjbKDFtOgv3PpOfsjmaQv39xzUHzH7gYj6Flc5yZv/GgdvjRfGI/c3
         vy2vWmHvVLxa85sQMNK/Npys4dWnbQmNkrV+3k2PnGEE1w2Q6BgwROBEM6K8qkWMl590
         K8qx/E26oSqq/P8OLlkE5pp1+1+RulP/x1luIzeYraDDmzkZM00fTqwcMMDBY8JbOWz1
         CrjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OY6e59NvKBhkMf/4HyAqWSEo1eLRPIhpqy/QZPuprxE=;
        b=JVISTkkszwuUM+0Iq2xLhsbb9FEeSxfAPpqn85PRTHakAP5HCxTcO4AnjbcwjYJ7IB
         bMfbzLcibrafU86nkT5n9Jnv1dk7K3ltuCKecstqIPsvEsutHcr7L4+1Vpvjdci/wFJB
         h3YKMbIVzL6ghvQagXCPmFv34GuNpQtw/Y5qJVTEcbR6FO6vzn48eY34Em1U5BnqaPS6
         SmtIkzjCPtR2BcCg0jGtiw0iSUmGtcPaDFVNB+IDI9ZYTk4mED/C3VOkP54JV+74WTWf
         4nLRzBpR7R9kPizmVnJzP4UsfPU2kLyQJ2Sz5FbKPonCYEl6I+KcXa5T1n13TRcNVQhc
         SNqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Id+3GRXV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id u10-20020a7bcb0a000000b003a2ca59af2dsi326069wmj.1.2022.07.18.17.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 09/33] kasan: clear metadata functions for tag-based modes
Date: Tue, 19 Jul 2022 02:09:49 +0200
Message-Id: <1c89671b9041628b86be7907a5edd340ab13222f.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Id+3GRXV;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Remove implementations of the metadata-related functions for the tag-based
modes.

The following patches in the series will provide alternative
implementations.

As of this patch, the tag-based modes no longer collect alloc and free
stack traces. This functionality will be restored later in the series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/tags.c | 33 ++-------------------------------
 1 file changed, 2 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 2e200969a4b8..f11c89505c77 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -19,54 +19,25 @@
 
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return;
-
-	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
 						void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->alloc_track;
+	return NULL;
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 						void *object, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->free_track;
+	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c89671b9041628b86be7907a5edd340ab13222f.1658189199.git.andreyknvl%40google.com.
