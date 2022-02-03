Return-Path: <kasan-dev+bncBC5JXFXXVEGRB3PX6CHQMGQEXI55SEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A2A7C4A8DAE
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Feb 2022 21:32:45 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id j1-20020aa7c341000000b0040417b84efesf2059098edr.21
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Feb 2022 12:32:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643920365; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gr7HM3atJPC69fjOS4svHOKYhbs3tLA3SyK35BidcM1Ezc4FkPpYiL1gF7MYn+sM+8
         ajJtz4IlGhaNRleYG6QKe6F+xb01TavCQxBMb2kCSgNYOqTxWI6qw20+2maQgRzNklUp
         O1MrnhTyWUjQnN4fPcFhDSe2IV/L1XBYYXVl+BVNQOLEQJYdsH9wIs3U2ifrlmVKf1yD
         7+RZfnrqmGxManDeJjlkSsMiGY3oqzmDPYSJ8uZQaPDvMPhZrlF/e9fI76CC+miX7YiU
         moSmpR7LKPRynduHkbLDCrlGVy1rMBbibu+r5QFptVjDiJvgE7VlbFWyqrtr7q+SxId6
         dGvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PM+nioRYP7X/FUO9xGmQbQJTSiwc2Z229Knr2GSf/CA=;
        b=ijqZqSN6OYBGiZottkacxedMHsI5+mqsXnr+93hvWBcmhIKVwWzD6PJbEWwoKHoXzq
         1fy89xNx9MlV8RhBp7S5TNpTY7Dm9xXaBym+B6n4smVSApgIFcdaUgqt887n4p7FgvKl
         i4r2xvPhFBWKftGPPIVgi9Qv1MNEg898h+0G6YfRoVk2VCrBYOQM/pOkf3CK6RswRSjr
         FRg59YHxI2t7ZZ8k4UcKVorBrhnOi1CttfIQrQN8ox3W8XrT5YBUtbN5Z2EnpAES3Eou
         tRx5rNRfhpe/XSKWbzQbQOTWgThuwknAIL5nG/l3Rq0Y9GbGdCrx2oBGRrFdEXG1hB1X
         Ih2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="H/gn1eWK";
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PM+nioRYP7X/FUO9xGmQbQJTSiwc2Z229Knr2GSf/CA=;
        b=RPZk7utovp0wUlP7RMJjP5f6867q/4ngvkkBxR1r69Wutq43u3i1XClyHnwFtu/FF+
         T9hWcHdcuEqG0CqH/85NjGhApB1zZvEK2XlIc6PghDmZtc59HGW/L8HoTNI04mVCmMYm
         Sz6YKStuXMPIWcPmH/fuM9Q1UczSSBXkFDyEKIfVzKl9RSBukj4ZSrkh5BgPcU3Au/jd
         oMuNR40GyhjYi/ipXDN9WhAqY4hhAKtdK/sLLTcVienFFPvs/obdOvoqqiSEKoPbgDmF
         OF+VY8a72gq2ifiRJYHmsSznUA3xQoviFslyDMY7ZgvE1be2UVohlOpzW4zDw8l+xly2
         CzKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PM+nioRYP7X/FUO9xGmQbQJTSiwc2Z229Knr2GSf/CA=;
        b=WzK5/WcUJm/3tEE2Pvs9Bd0fyp5/OVQRgto2p2neoDDiZhCjCnMvHM741M90jWTZLT
         fqFxpcLutXo8nPlw4yCCYrfnRnq6SHCR0Rf+wDp7Z1x3NvmyaPM4e1eQaXBAMFKkSYpl
         zhMRFuHN4IA24JXjqinUy7Y/yMGzg+ud1vYhBqEunAeDLmcV2FvYl6IBBuoqJ5krFn5R
         Ygwq0nTn1HZDZT+2yE6nwo10KjwlECova0M54CDzlc1ZaZhEp76Dd4YYBGzZ1ceUYlPJ
         mZMGtoKi/b3kSz5iVqYkN2tNn/HiaCrL1CeUR5Q8GaAZbt6QnkYmB5n4rmxti/g6CB4W
         PXTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533e+v/F0INgTtwecr9o1k6OhUAPn6DTCELvnEW9oPjTeXqkT81b
	LkNWOTTBz/6UZy5IKvEKiTI=
X-Google-Smtp-Source: ABdhPJzBaJmTMXGaC05osWpiTu695v3As0CpM9EG57wV/DM5GfQAt6/HnKm7S5wrXY28yRPksizQ3A==
X-Received: by 2002:a17:907:3f0d:: with SMTP id hq13mr31041264ejc.358.1643920365218;
        Thu, 03 Feb 2022 12:32:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1612:: with SMTP id hb18ls11525815ejc.7.gmail; Thu,
 03 Feb 2022 12:32:44 -0800 (PST)
X-Received: by 2002:a17:906:9755:: with SMTP id o21mr24192998ejy.26.1643920364166;
        Thu, 03 Feb 2022 12:32:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643920364; cv=none;
        d=google.com; s=arc-20160816;
        b=M5BET/csAy3oKQcsSk1mVLaXlBRLJEcPwwHuTBcPrV2wWplmhVJF7s4lPPBWHrA8Pm
         4Q/pSimwTmaDmQNsx8Z1bE0EpYCTO6Kw5IDB/2B7uvXRAM0A9yJKCM8lFDAfp/l//iVG
         8x9d1d7RSPgZTWORcJJ9cnZFaZH3Ufbc/4HBhZDWNz6v7ndRvZkRgtTeDNEFfYA7KTU6
         3Gf7JiE++0OGrjXGzMjCb3N7wT4iqOjsxu8HGbEGHXe9nFdIK+N76VghJMyLb8fNE8zR
         bGYIOHeQSPMYFVH8UAOalKqIKtzLUOEiFdW6YmfqjFFaqTQZcQE8JC+Fx1K/FJZvK4+5
         a67w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Kx7Vm4dHTZXc1kZ1ru0nknkAUTiIGeCkS+oQUnfZKxQ=;
        b=LPY9tL0OaOUyPF9tfJ1soi9gKWSKFDxyr/qGJr9sV/h5loPyc7i5pV+juMVS0E4gE8
         mx+rWOCHOqTs2c1SO3tNEPSmmPm9Etjh9gcTtXxLXRd5Xa5b0itFg9NsrZsAHrbpL8gJ
         1dxJ2NimkhUE9VTk2Jyrakul47G/Gr5iS8fjaIHeRr+wbIRL+zRao7KWVLFRfE67MaxC
         6dU4T9SeL1MNnD2CnYKlgy8PMbPQiwMjdE3MyHSYCa5EVycEpzJqqN0QRssBqiqOCUFi
         JZ2grtSwJp3ohuXCWuLq+PYoMmKauigMdC5tWT5lTmc6ik65WcOwGIggdTwWxSThF5h6
         GgcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="H/gn1eWK";
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v18si1255986edy.0.2022.02.03.12.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Feb 2022 12:32:44 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id EA8E8B835A1;
	Thu,  3 Feb 2022 20:32:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 54A92C340E8;
	Thu,  3 Feb 2022 20:32:41 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Nico Pache <npache@redhat.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Brendan Higgins <brendanhiggins@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.16 52/52] kasan: test: fix compatibility with FORTIFY_SOURCE
Date: Thu,  3 Feb 2022 15:29:46 -0500
Message-Id: <20220203202947.2304-52-sashal@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220203202947.2304-1-sashal@kernel.org>
References: <20220203202947.2304-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="H/gn1eWK";       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

[ Upstream commit 09c6304e38e440b93a9ebf3f3cf75cd6cb529f91 ]

With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
dynamic checks using __builtin_object_size(ptr), which when failed will
panic the kernel.

Because the KASAN test deliberately performs out-of-bounds operations,
the kernel panics with FORTIFY_SOURCE, for example:

 | kernel BUG at lib/string_helpers.c:910!
 | invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
 | CPU: 1 PID: 137 Comm: kunit_try_catch Tainted: G    B             5.16.0-rc3+ #3
 | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
 | RIP: 0010:fortify_panic+0x19/0x1b
 | ...
 | Call Trace:
 |  kmalloc_oob_in_memset.cold+0x16/0x16
 |  ...

Fix it by also hiding `ptr` from the optimizer, which will ensure that
__builtin_object_size() does not return a valid size, preventing
fortified string functions from panicking.

Link: https://lkml.kernel.org/r/20220124160744.1244685-1-elver@google.com
Signed-off-by: Marco Elver <elver@google.com>
Reported-by: Nico Pache <npache@redhat.com>
Reviewed-by: Nico Pache <npache@redhat.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 0643573f86862..2ef2948261bf8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -492,6 +492,7 @@ static void kmalloc_oob_in_memset(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
@@ -515,6 +516,7 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
@@ -531,6 +533,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
@@ -869,6 +872,7 @@ static void kasan_memchr(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_ptr_result = memchr(ptr, '1', size + 1));
@@ -895,6 +899,7 @@ static void kasan_memcmp(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_int_result = memcmp(ptr, arr, size+1));
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220203202947.2304-52-sashal%40kernel.org.
