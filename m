Return-Path: <kasan-dev+bncBAABBAXM2SEAMGQECMKPGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 13B713EA6E0
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:55 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id v25-20020a2e2f190000b029019bb571862dsf2065626ljv.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780034; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAGQd+PvJJGp/HxpoccHqiWj12g+XgOWlvPvVqCKcMnUiRKrGEchwZAIZ+feoBg6Lg
         nx6uaiBAYUCDj0nCnpmh0dkgFwSkpLvudqT03W57pcry2dSAFwlne+Vo60ryrMCSYPgy
         k9sy5ggWxGLj6q6ESvLsuzgLlaDxbGdv7fBCq1ZVWwK0stOGBmMZZCQqo/lTN9Z95up1
         wgZiI3d7Krv5k/Kf13BStyad22Qmn3UWUauSHRTW6i0X32fo0MPUMfeUmoSOSfU9E8a7
         e+G9rujuLNAGeGweYNfPjU357jDLKPwRYFkGXzpY0L4cdFoJBjMVId+QGFfEDQdkTkli
         S5VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UbIeVCiaN/eyQy0grd4O/1gbwYGwNsX2pQLpgjPase8=;
        b=uzyGZgSPbxSVB7i68CCeVvgKsp3OUO7PBIUbPCtaH4kO+lCThhs3EONlsyp+gbFuiP
         +MHslNyxS4udbW0iJTiN2pc7eXbjHGjEJpWgCuPpXa+UhZtlcHTWmKcME/YYKfaByyfx
         X2NuW2k7xJKUjsngWHzdqN60MzhEOlNES6nr6wi4g0FbtQ6R/oN/+Rdun97H31kV9qW7
         abKx7bvinzBzaqoD/Brzbdthr2R52u8PoatnsdEM3mg3GLY63hU3u+GwX8xbzRaL39wv
         cAI+7ibUlBwiQckmqv9bdSVycn0P8DRHCAk5KThlWE20CygmlV+TadGSrZmC/MXctA/A
         D3PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=omGleRtp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbIeVCiaN/eyQy0grd4O/1gbwYGwNsX2pQLpgjPase8=;
        b=U9mTpiK+4RX9WP73UKh3TygINEoHTqfWF7Al4RrHWaUGoa/PNt5mDAowGIp2Ur+b1O
         AKnbxa/9FTXa82pzMH90T+0+fR1A2nT6uMY0obAXNAP/uDoKg3GXN9qej8yXEO6k4Ukp
         BBdJoxf2JV8armFkvzeZcVz4zHTsbU83FlWmZu5ZJ807098QUhQL91T+Auqm05xGSfbW
         VdTK03S+ypXVQkSReN9IRVPGiQhtF1RHN7kmBDg/WyFwnsQTZG0+utW0X/ADUNDILsfB
         agKf43yiSlL6IpOjVqnO7hoTkYOt+nUHG5ak2AGoJ/NKDzt6Pr3nbdsGEzxmjhsUb93d
         0Y4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbIeVCiaN/eyQy0grd4O/1gbwYGwNsX2pQLpgjPase8=;
        b=FTNHYfMkpvLzSMcKyCwT1aQ4c1stnBTE7aC1/5PMa+plDSWb+60X0rtlmd5WG7OQDd
         wJlLzOsADUrGd+6IjGsRXv0nhMYjv8LiESVpOwVy98/s1c3zjTrOO4wOhurp8RB5g79K
         ut2w6+1GXwxMC5G1gE+8TY0/Cq4WkeLwULaBG6R6bcJeNJUhZTVMlcrNBeGFKPQONzGO
         vXAFlhdVvJPb5ZS6LhgbriAEY3gV9aVv5LrZBlsjMqBWCaHdXzXPEqhZHKu1ZLK1jqdu
         Cix50O1KmNZEjR6LjVHw+9oIDVc/XBe7xOmDLBF/Pj14/1G1tFaHXbEjgMWYtNMu9UhK
         YNCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53151JkENiPo/LcABMadipQiVZejeulwmiV07Q86oD6wiVGoI6KF
	wG9AVYnVyCmsb5tLGFK+vPo=
X-Google-Smtp-Source: ABdhPJzuEZu1AvciZxzPaRSq+yynZ78XKvWzolnVbXzbtpu2Q8vxRsZ6iJ+QQxnO/aAK0EGP2ACNvg==
X-Received: by 2002:a05:6512:3889:: with SMTP id n9mr2744702lft.589.1628780034675;
        Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9019:: with SMTP id h25ls1041253ljg.8.gmail; Thu, 12 Aug
 2021 07:53:53 -0700 (PDT)
X-Received: by 2002:a05:651c:626:: with SMTP id k38mr3126616lje.304.1628780033814;
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780033; cv=none;
        d=google.com; s=arc-20160816;
        b=S7/5tsDaief+scgwblVyNSJgtM2Mf0LjdbuUzwLu8MGtr3jeh7XiV+qZQXMIgQZq5n
         WRTY3XgfKGV34C3qtgIyjzrP6Edir8ZHW/PpE+jeLfbmTqkP/DCHTe1mJdWveHqbz9qT
         G1KUC3vKcca5SqUC+bi/iERMfeq4JBJQT3iJrul1kyNrSv8Utv70CiR+k6CxG4FjZ4Cc
         vJWnO5xikogD+CLIfkX06MSJM97yzRIQlaBqe+Y3isj8KAKfR7uqxRa139zRKGNN8W/5
         oUQkY+82otE84Jshrq6VPXQ6n/QPjqNwlXhqBYFfETFLUwDHvw4hAKaxkLn/eDgmQEIk
         HKEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3Rw7L29Rl9lI7li/pGD4SgpCx3KCWINRLEY+hWljSMg=;
        b=xL1vVWbVrheSeBkooXjsG+NkNYvpOUQWm4YKq+OjDcR+IIjWRigyG75PoJn64B3QzP
         lrzWrZA1vi03ziyLljU0nBIwJOoz8FDE840Ci39hVzkkjCcLf3cAJUyNkA9zeMoHVLbF
         on2KAIIXRocOBz5bcFfnYpErzvj9OxGR1WY3bEGe1d5zI+PzzylAy18nn77MVaaj8v/2
         guAxkNDGg8DLQIGCd7SbiCByamrlA64jDkBUwtiYKRooWsH898lrbz9UNwD77zQHRWSc
         B8utZMtLsypTyenaHMOvscYNpBk20oPMZJMh0Gn4Wpf0etaNbQ9hBbe0SVcP8an9BvYf
         tT0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=omGleRtp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id a21si115998lfk.12.2021.08.12.07.53.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 4/8] kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
Date: Thu, 12 Aug 2021 16:53:31 +0200
Message-Id: <088733a06ac21eba29aa85b6f769d2abd74f9638.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=omGleRtp;       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

The HW_TAGS mode doesn't check memmove for negative size. As a result,
the kmalloc_memmove_invalid_size test corrupts memory, which can result
in a crash.

Disable this test with HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index db73bc9e3fa2..1f533a7346d9 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -501,11 +501,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	size_t size = 64;
 	volatile size_t invalid_size = -2;
 
+	/*
+	 * Hardware tag-based mode doesn't check memmove for negative size.
+	 * As a result, this test introduces a side-effect memory corruption,
+	 * which can result in a crash.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
-
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/088733a06ac21eba29aa85b6f769d2abd74f9638.1628779805.git.andreyknvl%40gmail.com.
