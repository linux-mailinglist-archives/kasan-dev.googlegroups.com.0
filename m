Return-Path: <kasan-dev+bncBAABB3HVRKIAMGQE72NM76Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id F23EB4AE159
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 19:48:12 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id x24-20020a056512079800b00440a45c6249sf807589lfr.23
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 10:48:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644346092; cv=pass;
        d=google.com; s=arc-20160816;
        b=gYOVU1A0nbDbw9Lp8Js4aa3PYPdZJK1u9V0b3B5e8Vg2Eb/Ve9WqkWTYw5wUbicBBy
         QVhH1+N5MydB77jgpDxaw+moddtgndkD5stZ7TPwpPr4rpI6vkuqzg5t/2M0ynb7ChBa
         MP209jEkKOV16WSij3A0YXdSlC/LNPbJfPhBQObAnewPBXZ7sXhQ84VY/xyzzrd86cA5
         mqORphRdwYLExVZjWU+WcV4cCH9+NPTQUa2vbsx7O+8RJyFfOgRqul2DYVUf1A40SjYS
         JzmGA1SjIZpxAEMrFzZ2tF4LXCU/sJYku6LhTzZtMcgwhsl9WfZ9aPwZXIAJbfL0UNcE
         FcvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WO0F7HhkWfYUzvghm5h31AB0kTENAvNsE4woAEa4XFY=;
        b=FbLz494RB+QDgxMrJOhZw+cDZkYBOx9/NkW+dNAh23ri0u1WsiF9bIlQ8iM8dw2Fez
         LbYoFqT9i2ypqjqKzWyCaxeSl69N31cHngkkuLf4CMwf61S5v6d3zbKc3jJ4JXUri/tz
         R6wSZSRkkuOBX2Tw9GuuSeKg8/FrQQymMbWP2gt9KKXhcc7XmZgnLzrYklNLzNJJ0TzA
         Zfkj8X6eN5+HwcYc+MsZsIUoMck/awNasxAn5waMdjGQ+9C+fMZg2NGi9ZaIBvbZ1vUG
         eio63HCkSSoF7eHSoN53IuLpnLOsvmuFog1h7y1bYDUeU03Jr9Z5ikbpSpIkc1BVpYp8
         f1XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YwjFDHDp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WO0F7HhkWfYUzvghm5h31AB0kTENAvNsE4woAEa4XFY=;
        b=qTLGyh0VRsE7YM6bZ12xdPenH8AXUL63DUxt5fRbNVjtoG5egNnMJ9/e1Ob15CFWbi
         dqeeR4f+uB2s8KmzWB68ElFfrecTz/LiNgjwZ7GFqEJUsOG9ijIkoBDuVBp87e7UnnFf
         40O3nzX5QDAmBWlfgDktXule4BIBepkPhSt4dtj+W7D3IJ7iIYDie2WDKow/XSDTJ1A1
         R/TevtvddniZaan/GLA83un+7S8iDYi5/7br50m1G5rpIcj/LjjRB0DXnmPTn1onzqQM
         i8Di6KnktUFxn+bviYEj1LFcDp9H5NkfWRePjRskh1D+97azLyFeSVZ5Vhp5d3Jh3Afm
         BUCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WO0F7HhkWfYUzvghm5h31AB0kTENAvNsE4woAEa4XFY=;
        b=XeNCs+IjreSqSbrzMW4Uix15RAJTgvZtcDjosPlHVqXGbUiP1EIad5fvQQKOJArF7r
         ArQlrTNP9DENYUewouR45RmA7AeWQHbujEsi03aDtxY3Fg1sRfWL9xah+4ZPeAMWuPN7
         qaQM+997N+WdRbrenXGvowTUthtTbKxgPo5Z7BYMCAQn5CoV8XiaUrw58pzn1z9/2m+W
         DvEz8ZEMKzDATjWMUzNoIXJVQ1VTxDbwoGv1eWXSuKpk/wCB+Wk30V29muvjdDW8BntJ
         LTq4QIyWnetqzZGLz6qQ81UfzaSHkx68EbvB9aDcD6YTCOKCgXEmjj0lHx8tdeT5Cy4b
         RsJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531m7+xLRFie1ddr2cKrxdZI6T2rnWOSJn/VRAamQuz22yAI/rMs
	tdSOPowaehvyR/fkrdnijhk=
X-Google-Smtp-Source: ABdhPJzBOfexQ6hxj/J730W/tFKpoJ0M76sEBaCalfMc5XzCQ4HY8roNqk9qnCDqjdYt+H5L8fF0Mw==
X-Received: by 2002:a05:6512:11f2:: with SMTP id p18mr3595134lfs.665.1644346092417;
        Tue, 08 Feb 2022 10:48:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8d2:: with SMTP id s18ls1507347ljp.6.gmail; Tue, 08 Feb
 2022 10:48:11 -0800 (PST)
X-Received: by 2002:a2e:9941:: with SMTP id r1mr3729628ljj.348.1644346091552;
        Tue, 08 Feb 2022 10:48:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644346091; cv=none;
        d=google.com; s=arc-20160816;
        b=OsS5IDQdKDu7QGDewD9JCk+OIyAijUxn3VUODHZeUBPNipP0MxotdjxPQuIRma14GB
         ehz9WD6wwX0OvUSR7jfvMG0rW73TMUPCBtpvLs8M2JM1NX23/xu/BqURF5ScHOj0MyhV
         WZTqZjzFYqITQjzevBelhXL8IgPSxW1Sdvhp2GTBDaVKAB1dsCb5Lv3BpmCm6nRDmkSY
         7MfFXwaz0EANeRiwmaOxpN47fWlbkG2opVSwFCFKay9kb9dVG3NrC+FHSbj2kF4OKWYh
         77w/abiyzPjzdcO24GvFRx51xFKd0cqfpricb4G6JbblQhaPtTWvWfiO48gXSzsatjP1
         fOxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gcjgT1JGS5YXvEC8btLC0N+cld9EBSbr9pVNw5PdFDA=;
        b=HdqeeWSQbYcJISz3xN6L8uM+TAmTvw2TcxH1X0EVPsIkFBVfqaT1lJswWfflEaaKak
         VvlCEYvRPoDc/9MJVRPX0W1Qkyh9lTQBzAM7v88F9BFXabBFcwg4DtdglVtQA5RKYVNL
         WfA4uskLLp7pp89CsPwxTgYh82YT3rqi+VuQnFYV4PyNL75uhs4rEmlos8PZjSUyAHdO
         2XG0LPmZ7Tf7Z3XcBNfFVnU2d1vHMhAg+gcrLhZB6JRf/ISi5BQ41F0cWhEPyaBkikFq
         o6nHyfeXg9jEniSnxYrx+hieMLc6G8B6o7+ob7th/oN6hq6urSv6iR6VXmoDa8e1GxC7
         kUnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YwjFDHDp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id l5si658211lfk.11.2022.02.08.10.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 08 Feb 2022 10:48:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2] kasan: test: prevent cache merging in kmem_cache_double_destroy
Date: Tue,  8 Feb 2022 19:48:08 +0100
Message-Id: <b597bd434c49591d8af00ee3993a42c609dc9a59.1644346040.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=YwjFDHDp;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

With HW_TAGS KASAN and kasan.stacktrace=off, the cache created in the
kmem_cache_double_destroy() test might get merged with an existing one.
Thus, the first kmem_cache_destroy() call won't actually destroy it
but will only decrease the refcount. This causes the test to fail.

Provide an empty constructor for the created cache to prevent the cache
from getting merged.

Fixes: f98f966cd750 ("kasan: test: add test case for double-kmem_cache_destroy()")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..3b413f8c8a71 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -869,11 +869,14 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void empty_cache_ctor(void *object) { }
+
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
 
-	cache = kmem_cache_create("test_cache", 200, 0, 0, NULL);
+	/* Provide a constructor to prevent cache merging. */
+	cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
 	kmem_cache_destroy(cache);
 	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b597bd434c49591d8af00ee3993a42c609dc9a59.1644346040.git.andreyknvl%40google.com.
