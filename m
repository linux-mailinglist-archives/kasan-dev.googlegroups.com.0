Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR672L7QKGQE5K4BHDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 094F02EB28B
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:25 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id l37sf431880ota.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871304; cv=pass;
        d=google.com; s=arc-20160816;
        b=SWKBGHAt3H4BmJg//F6wlQdQ/zirymlowuvkd9sp87ov66c5x5GRLPCRJ7xIJzsFQK
         5/6bPd0WQNZqY1hjBaDfVLxWnpWgUq2YomqQuxzDxjUXYBKgJ5XJUW9p+zeVezIPycfa
         +tHzrrMQMp4KRkQ7a6M2KWZdHUErNaFWU64sk6Jbc8OsXSnOj3voBbrefhoAVjubOlVF
         8W9td+4FrgxKZMzw6viE6TQL+SB9IGXshkmu9VxeSz2/Umr0bSK537N/ZDxKeS9vlRUH
         0iK7enF3OOfc/ykq64sPe7U05pdNVSMYLS8KW16sXCOv0c0lD95y4dU+StpaLvX8AbWv
         4bZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=we/aDBBRuj0IIFbhhBFjTU7TIOudHhN6PvRi25CBuq0=;
        b=js8MR2D7AoaysJCQO1engZ9wAj0AlWxauQtu555AyFg7dCgQ0JqLXdZ6YRCnt6waKl
         jNOpRfum79eWbTlsk/I4ZmoLP22gZv5ySK5V/YedpJsaxPTY+0a4AzxkcUGzYuroXr2M
         Qy3wHfXB/NIqovotTdZnoypOFkZJdnRWtVus3txHiJ2qbg7dn4w4+ZFbJS+H2W1RpXoB
         767JLxBfyrgiISew9cNfoPcCFovpDiBQrrThNp/qNi1IfuvB5OVc2+xNBFMScilNsdYx
         ViHS7iXNMfO78vQ0T0UJ7RpH00cknNbFrjAA2DAPoJaCuHXyv5P0m33skoiKC7p7h8QT
         xkEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fb3Q6nCT;
       spf=pass (google.com: domain of 3x6_0xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3x6_0XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=we/aDBBRuj0IIFbhhBFjTU7TIOudHhN6PvRi25CBuq0=;
        b=RfrvZgLejzrsEWmntWtjo6mQEqAWNUv2j1sydyCoLrp/ujVCBQsw7gGVEu8kdnCQ4c
         QjYr8jD1c5MdteFXWiPE1p1PZ6QWaHMBWHBPNY9Pr2UDQemWXuveyLflbQzKNWS5CyW5
         +TFzO+b6bjP+bBPWjbeLisVH+U7o70eW5zFdOn/KQR4dKwhrBCrDIP4F7GX/A5EZqefB
         X0wHfCYXvRCwFo1vT3pNbJPfAqVSKTLLCZ9/eM/HwWCfMnW40phOgc8bB4bLCfE4ZgRc
         T8i3KFT0yhLJRcDYO+9RIMBeYQC51VjLRE0F/c4x7AyLjTLW4h6hcsy9gABBFpHpXbQc
         BLFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=we/aDBBRuj0IIFbhhBFjTU7TIOudHhN6PvRi25CBuq0=;
        b=QSNmfUZZGrcwTqatNhyNp5AwWWN0PpYE35pdt9Bc/Fqt36KTCqMq15Z6kiNJmnHKdV
         tV/Zh7svgQ3ZsdenU0F0My5P55PvZBALtRNtzIHE1F7yvfYmakCMJ3XMXTl5GlmKI3MD
         9KBxCI5YLRA/dSQHAhFM2Epp50sVAk3zeZUiNU2SPl0Dvf2y7ZotDncm6MMcYc7n/3j+
         9ujQVwyXj9cxODP2XY3XSV5pLdt2gLguWajvAMI5GUyJj7n1kYttGUmWsRxT1F/OxVbj
         j5pTPrZu8YcqY0ZuFikD83DWa0UnamIyRdScgOVhZjkPZ02L3h//4z2LwtKmK4MIoVCC
         jwbA==
X-Gm-Message-State: AOAM530NTje/DhxnLVi0ikYyO30PTd5MBF4b07Y6ugKlmVy+H2Ekn4e0
	TXM3FG4Nl1ielz+v2y7g22g=
X-Google-Smtp-Source: ABdhPJyls66ww+CBIEzCc3zdPqgQC7OQeXbhuTPCzKZ2c967+hVt4mNG1s/CYTVBsQp2tGoLgC+DFw==
X-Received: by 2002:a9d:6b99:: with SMTP id b25mr588080otq.49.1609871304031;
        Tue, 05 Jan 2021 10:28:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:140e:: with SMTP id v14ls130792otp.4.gmail; Tue, 05
 Jan 2021 10:28:23 -0800 (PST)
X-Received: by 2002:a9d:7f81:: with SMTP id t1mr602902otp.166.1609871303703;
        Tue, 05 Jan 2021 10:28:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871303; cv=none;
        d=google.com; s=arc-20160816;
        b=gLWQ0E1zovkVLcp+RC4hGJ7/77lx/bBqa1G3n/NOz6bNn5n2Lz1/5htq/AcgLy37X5
         1dAxPUe/pKmHK+DwDdN3lIy8CtKtRCV9xOPFSBxlU0bgXDuXIfGnC26CFOAhvpZgxnBw
         wmmGBVFrFpAb8eXhXvM+ioI8M0kqhPhDH4kQum+B/SoC0njxwYcQbIiyTrbIgKEtGyuM
         pn0gohd1u4NZJgMgOEJegOOUp/CP69BvIjCRIcm75YPctd12CVEVcfXaDYk1UjesGNnk
         ujRcE1tXFwHuacm0lrqSEdr02HStYXqIBxG3SJ7K+EjWO2tDuvA3Eyb2ANyip/L1ahEE
         /D8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KRXpzoAkHqv6MlP+Q/fGJx09RWdmlAlIVzxtUVuwpVM=;
        b=DgGM0S5tSAyNEVLsnwY0/Z/6KI3h4/7mnC6cjcYxBRwrJjuPg4JOlPW0qEjOJ1rnrL
         ZBi/OxYM6JzfeDMvoE10LYRrmVHfcF4Juwoj17Ed9WHB1HYGA65bsNmpHEYidOjjnptt
         395dMwl5kLPNocTYnwxILDNay2a9QRoidCcpCfmjry3fKz+od1Qm/Ek/V0rOUG0gyC5W
         H5BIA3WA6P8+B50EH3ec9kIjf06xHtAWPhiWSKt7fHzOzb7OhraxzWqoRH1/LB9CpCH7
         naCtDHwCGZplFIX0FDJe7uYdXv4zdeP6Pyy17M91obdPkM3wQBPXRqpZM2mrxFT+m7wn
         Nj7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fb3Q6nCT;
       spf=pass (google.com: domain of 3x6_0xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3x6_0XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id w68si13645oia.4.2021.01.05.10.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3x6_0xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id q3so489041qkq.21
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b38b:: with SMTP id
 t11mr470993qve.58.1609871303254; Tue, 05 Jan 2021 10:28:23 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:52 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 08/11] kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fb3Q6nCT;       spf=pass
 (google.com: domain of 3x6_0xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3x6_0XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

In the kmalloc_uaf2() test, the pointers to the two allocated memory
blocks might be the same, and the test will fail. With the software
tag-based mode, the probability of the that happening is 1/254, so it's
hard to observe the failure. For the hardware tag-based mode though,
the probablity is 1/14, which is quite noticable.

Allow up to 4 attempts at generating different tags for the tag-based
modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
---
 lib/test_kasan.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b5077a47b95a..b67da7f6e17f 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -375,7 +375,9 @@ static void kmalloc_uaf2(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size = 43;
+	int counter = 0;
 
+again:
 	ptr1 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -384,6 +386,13 @@ static void kmalloc_uaf2(struct kunit *test)
 	ptr2 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/*
+	 * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
+	 * Allow up to 4 attempts at generating different tags.
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 4)
+		goto again;
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl%40google.com.
