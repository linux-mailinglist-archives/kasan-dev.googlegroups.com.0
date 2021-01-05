Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSW72L7QKGQEXQYD7QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33D7F2EB28C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:28 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id 193sf141599pfz.9
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871307; cv=pass;
        d=google.com; s=arc-20160816;
        b=1FRoZWRTzlYFQNrnKi8mw8dcnCfSnFgXig1EEHB7SJpoaHe0CdAmx5J5vmS7uWxvPz
         DTRML3XQ37fLniWf/EU3Lbi5nEwLvzo2hbr9Ug+TAVxcAoWjZBwmjvV1C7iz4v/mC/3y
         TfSbFbwR+B3X70FZowv5B5oRbFirlS9wFA2NH7BBI/AzKl/wEo0RJg8iElSwDOzmGSTk
         C0B32pqg3u4js4uPo0saHl/RUQ7yQbmR5puvq/aszvPqvMi1Juz4qzhnZlxJGWRApuuM
         z6BFuM3EXszoXj/VkL5104PmeNbQjh5pg2sUkqRjYf7FV+WZZhTLOR/yiyQLJ5lpA7dN
         LOMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=V4pG9O+rvnvmbpgeF+hCUJ3uyQgZaK2IkYZPyE8xFTM=;
        b=aQ1lq2ME3eGAjeDiMeoaW0icaCz/HRJ45pjGTMkE8Pj+3HG2No2/hEsnoP0HkB81Zf
         bAhPEoSErnbNxb4eLB1lpKMqIO4mSZq5qhIPCZiyYE6Cb1aKOShtD8lvPsFMVcOof/kA
         etOpPTdZxJVem4QuCwpkf5yeR54r9OjEqBKv5WgA7U83hwz+bTP++ff55a3LRviiEiY5
         WiK2Zji0ErO235yxKJz99qKRmpQfJMgjvCFAn2LRogpmt1dwCGGL1aAmkbUrw8A7kBaJ
         +9V1dN0d9A3f/7yIhCkSqRkWV9tLfQVaIgJaTPR+tbIxxLr/xOfC/L7lLR8XOD7X5X0u
         2Elg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KhhzCW5E;
       spf=pass (google.com: domain of 3ya_0xwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ya_0XwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=V4pG9O+rvnvmbpgeF+hCUJ3uyQgZaK2IkYZPyE8xFTM=;
        b=LYmQ74yXBuXvyt67P/zDjhlFPC9NiPsCHhQaPfzskHRi5/TPdURHUv8tQ+rPyLnIjh
         65CJ9goBwzOHVqBEd4i9wYZ+kNbTMPfUrQigLIAqEB+GZYHcxebJzHqOXwiiP5F6OitH
         RS4ukef3QV04BWwptlyNfSQ4Gk8rugLv/FteQNnqxyZyUdm+FcsXfxHp2eTdR+CF1b/w
         ezPOjaiQMSBf4JAVwrLHeNHaUzfLPub/VytLINwyncojpiBQdpD6HlOUEmz05qBFoLNu
         xA20eWpU9FCnDtjZKBsvSxK9vwkwR/0nF9BSCKU/vXweK4MVDMEO56pVq7cfvQsY9cxS
         PB3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V4pG9O+rvnvmbpgeF+hCUJ3uyQgZaK2IkYZPyE8xFTM=;
        b=JFzP+WzzVi+nlXVFzaWnUIM3rDmPAwmoZ4ib33aacrTGL+YdK6bKDMiovulQGuYO0S
         qbBZPrxBR9pcVnoM5ZVuz23RI2FMhwAm5kp7voysZarRJ/kvMpRNEUkQgzF1hbgAIcs9
         /nxEpNpOFkt3UBqEJX2BW8AWR1mv5MdVTPq3CWRAPjzX6mHfMwBSqqHEqcdUHiLuC+dA
         RDzlpm7to7J6t0x7Ftz9DEchqL6ZB+oSilby2d0A0CVZfuFMTGQTM3McceJWU44MlyN/
         cswdQqefdut++OsWK6UomX2Gm92MSn6DvVhaQ2XfxegsnXJwjVS1vR0rxQJxcwSrW7wu
         M/Ag==
X-Gm-Message-State: AOAM533J8ZO9LPTQcrC0lAIZK9Xmynpd4bikPENQifjC9eCDu13M0tyq
	NDs7igtz7F4UkRws9JhtNzQ=
X-Google-Smtp-Source: ABdhPJz+cxJYQvtUUWO/3REUNGBuXOQIDx1HUnAoyigxpxSsn0OnuRzpckobnV9N4z+ZUk6WUcL3mg==
X-Received: by 2002:a62:1d43:0:b029:1ab:7f7a:4ab8 with SMTP id d64-20020a621d430000b02901ab7f7a4ab8mr646948pfd.43.1609871306934;
        Tue, 05 Jan 2021 10:28:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc47:: with SMTP id t7ls128761pjv.2.gmail; Tue, 05
 Jan 2021 10:28:26 -0800 (PST)
X-Received: by 2002:a17:90b:1945:: with SMTP id nk5mr524654pjb.30.1609871306443;
        Tue, 05 Jan 2021 10:28:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871306; cv=none;
        d=google.com; s=arc-20160816;
        b=vfAtC4U6Ge24iJ2SXTepHE/gK2+dHFse9xHxJJAeBuMdOcTkhOYoDmtMXjAOf9LUpi
         FHrh8IQPI6/8uZJO+WXSeETZIjfNn5SwN/B6l1MWNeeLzc2IUPftp6xTmsChjoUbxyfS
         5DA/gLFm9ggaGaWEOwq7aV8/C90fcAGeXa8yzfMEuYChoBEHwGw7cgMXreDCbVyhhe3u
         WErU1JgCLEUFrcqKMpMsafqhqt+eckEWN+YYw2vZ3E1femDKd93ExcVAjlc1P9/bYKJC
         e8cJoTrZVavFDS4mU+tW+4yrqjxwLPyQ0YOSdt8uh5Kxq/Z6awh3ynPwkEFUIiRFfotO
         MJdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iBAofrYhtWdvm45KaDvHp4GorxFru4go+vxs4/2NiTo=;
        b=OVRKf3F58E50MhvZSwEIti+B1yYiNgu3x6jSWvSQGOau0wL8Hz9qvl9EqnQHXaOGaC
         SaCZQ0JibhYYpej1yiEO4DI6Bu/IZpYJ/X4dzfC3KJboj5SbFWQaCQ/ZM16QuSup4K+I
         BjQ2GrHngCeSdTWbt4QJc7E+iWmwbpUfcGOzvAJchxP4cD2a42bJ0POelyvjPpAtqyKa
         EbAgloSlI4gdPYOqI42o6ZdjeZmFVUBIPFfW4w8OuAqrsUm1bIWAhkfgT4gzoPQUlC4u
         Bx6ONW8Wve1C009ooBJ1fBC8qQLI/Mc3yA+90GXxhuC866zQkxiEpoBD1WmYCuvBR/lJ
         4PKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KhhzCW5E;
       spf=pass (google.com: domain of 3ya_0xwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ya_0XwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h11si351623pjv.3.2021.01.05.10.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ya_0xwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 188so522823qkh.7
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e90a:: with SMTP id
 a10mr863092qvo.38.1609871305814; Tue, 05 Jan 2021 10:28:25 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:53 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 09/11] kasan: fix memory corruption in kasan_bitops_tags test
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
 header.i=@google.com header.s=20161025 header.b=KhhzCW5E;       spf=pass
 (google.com: domain of 3ya_0xwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ya_0XwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

Since the hardware tag-based KASAN mode might not have a redzone that
comes after an allocated object (when kasan.mode=prod is enabled), the
kasan_bitops_tags() test ends up corrupting the next object in memory.

Change the test so it always accesses the redzone that lies within the
allocated object's boundaries.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
---
 lib/test_kasan.c | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b67da7f6e17f..3ea52da52714 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -771,17 +771,17 @@ static void kasan_bitops_tags(struct kunit *test)
 
 	/* This test is specifically crafted for the tag-based mode. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
+		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
 		return;
 	}
 
-	/* Allocation size will be rounded to up granule size, which is 16. */
-	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
+	/* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
+	bits = kzalloc(48, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
-	/* Do the accesses past the 16 allocated bytes. */
-	kasan_bitops_modify(test, BITS_PER_LONG, &bits[1]);
-	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, &bits[1]);
+	/* Do the accesses past the 48 allocated bytes, but within the redone. */
+	kasan_bitops_modify(test, BITS_PER_LONG, (void *)bits + 48);
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, (void *)bits + 48);
 
 	kfree(bits);
 }
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl%40google.com.
