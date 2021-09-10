Return-Path: <kasan-dev+bncBC5JXFXXVEGRBRWI5KEQMGQEPXHCJPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 162C44060B3
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:16 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id e17-20020ab03111000000b002b313609437sf71445ual.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233095; cv=pass;
        d=google.com; s=arc-20160816;
        b=uvEp5JuVkEmUvIdOtuWHpj/OEZ1TEkka4+9ig52EDX0Q5qZEJ0DnJCyXX2eqRZt2uG
         PlEm9PKAsA3FEykPVXktc5fXMb3HtwJcgDQa6414gyY/MSxYRiTESBE95dXplp7kwR+B
         g+nBWX7rETklCsj0UCiLxrkZt+Qj+nBjSbTDK+JNInB2zq3YSxd1IKcPLmQyJpR5oO1Q
         GeNDOER27t8H+6RkoFITwuTWrzm/3/upXFbVtZ/FhpcxGojqsvMjKOVN01Oz1D3SeZpc
         0fV0ONhx5pLnqPl6nkI5GYMtQl4K30iR3+uY60+bKfj7EK4aVPvOZ0PeiiqppfG0l0XV
         CYUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HB8t+PvUrq6nHEV1wy7fjRAKtmZz2RvYVG+c1skNEMo=;
        b=zwbknhAZ4fYzfjKOR6eEjhHLJDGvHGPdYQXTjIaGfVJ5+qTyKKxcmETYRP3wtr1PeO
         45JIs0RhPuoaBCawGrs3C+58/bTgtNBJPznbvjO7fEDATY1SsoXiY3TqoE1urJZf01sR
         M1iIvFLvtuym/FKR5azI+hc9gMLb77VxE48tO+Fn5Z3R4Nh7/BBm+A3GwmVTn283iQKn
         UydI9xKHw9NHElq+Tzmo8vFlUeQXpnv4tPEcZOtD9x7o2YNmmTYYvJuAOpCEXvnOyxKC
         V4TKF2ZYIRJlI0K+7CZ/kaJeFiP1Iji29sOR7kbWc9hDO+UGjJqcKEJ06vkiSAgnzrNK
         UVsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J3qnWjPs;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HB8t+PvUrq6nHEV1wy7fjRAKtmZz2RvYVG+c1skNEMo=;
        b=dG+qc/0jKgyPkOmtdhp/3/5AtcnTTUWHFuptRRgM9++TCG7lwZLtEL9EpPG/4WKyRw
         G4upiY2XL2zqfkY5BjDZk21nL7VkYS7i9vzeHG+QAi5NYtPofvhuJRBD9nhHmB7HPPLi
         AFH0fjuFoeylqyEUXVNM+xtMuJLt2OORtDFhWHvxf3uhOoUDPQj2LcWbp2dxaFKeg5Gh
         pFVl0X73BgXtrEwLTs7fiFuOpwXHt14ta2eKAKEI8IGbwEvr5dBvRPFrlMXfvyEqIHH0
         MuaEfZVm8XhiDW9IY1s04i+SLf6dnVj4SVHe+nS1QkjC6ZB1hfz7oo9IzGAbPmYSRDk9
         eLTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HB8t+PvUrq6nHEV1wy7fjRAKtmZz2RvYVG+c1skNEMo=;
        b=pn/ykBRPFiuKIYnuO56IVRU18Lyr9FIoLdg676VBelhe6JtEK0TH2wxhC/AeY/hK1k
         YW2Pc6PY8H7w9nWhZ1OiZPPV2nbOoe4hbEg1uDsRKKiBSaH386tLeexJvIPX/Tr6JPAE
         TT67ThAWyMlp6tfxcosTUpu9tgbOOs+bBK6HBz7GseTfWuyiOecDmlAf2nm2/s8/U9iv
         is1ZTId/MXWx4gpcqXfheLKSBNm9/no3LNsIXNmCBHRILG8LMpNHgU0fmSt5fYFPFoge
         mNuRyNLTOTbiE1pyJNBRx4w26oc45bmZeIuHtYiHB7iCNz6Ny87V8pchiDEOfuzS5Prz
         VXMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316iGqXdkJLW48VN07MjTm1g2Tw/0gRxPVTcmOib249M3ZRJ9iL
	umQSKkjEubnkxxIUFCjEV/M=
X-Google-Smtp-Source: ABdhPJzScm8CRCEgSRPZFZjVA0bWuXiWwDjbvM+cGO9RKWSQK5cwwMvppf/8Ybfre3Ikl/oVYWka6Q==
X-Received: by 2002:a67:d31a:: with SMTP id a26mr1459034vsj.14.1631233095040;
        Thu, 09 Sep 2021 17:18:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edd7:: with SMTP id e23ls709176vsp.5.gmail; Thu, 09 Sep
 2021 17:18:14 -0700 (PDT)
X-Received: by 2002:a67:d098:: with SMTP id s24mr4373070vsi.23.1631233094462;
        Thu, 09 Sep 2021 17:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233094; cv=none;
        d=google.com; s=arc-20160816;
        b=p4uYzjqV7P+E+182pJEpor5x+H9vIXB+JnTjD270fDPOZTgWbxN1eloPzdKukr4LRX
         ms8XW5jaeFbZ5dG1DXtUd4B3dPGCxfnOVXRVRwux2Iwpz+9QrSBqAoQQl7ToAwIZpoD3
         J6BjPD3b0D+W7chzuGN6TqSGO7t/7NNj2m2E3aupHOHpcqOuMOfg3UxHizdeBp0nABdl
         2hEypgMtIXQyrzsHLJRiFGKETY/kBujLYh2+qJ8wAempNO7f1waAkqx9jTOrojy82zq0
         BJJn0LzKCOWp66qnQpUsYZ0mRcjI/Vr1np31xxb9yzHNM1AQ358T1uERSOPjTZk3VHmj
         b7uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZT+BV8RZFLyQUSd0m+PtZArjTsLDkRHGJTLaiEpO5Kk=;
        b=a2/T+g0rg1BS/CISe0yg6tlG76O3DeL6GjgCnKzGpZgzyQgLUyDjVtQmjAWx3+W1ir
         +TzQM80bz9wLEjEIDVoQcD5467xfwNEWdlI+Pm2hbhKh37r2FzRwLhWLKEOwUwqxkGtX
         AVXVRWtVAsbUyvQTIvhVQ5eYLgjf9+byPcPi90P6SKrQTm/AbuypWHuKfQQAqI7SyHS+
         JIvi3u/cb8H7m6hEBn/Eu90fvOWvH7rZMgO351FK63B1FQp29NIIH4E+ljPoitDKquFe
         OXZsTXW9kiWgUhQ1lB4sWctnppz0ty0bRCZzgmyPtC/6iu5xFSoQe+efQpGc5RAyiqOy
         N8bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J3qnWjPs;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y185si218496vky.0.2021.09.09.17.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 82719610A3;
	Fri, 10 Sep 2021 00:18:12 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.14 96/99] kasan: test: only do kmalloc_uaf_memset for generic mode
Date: Thu,  9 Sep 2021 20:15:55 -0400
Message-Id: <20210910001558.173296-96-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J3qnWjPs;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

[ Upstream commit 25b12a58e848459ae2dbf2e7d318ef168bd1c5e2 ]

kmalloc_uaf_memset() writes to freed memory, which is only safe with the
GENERIC mode (as it uses quarantine).  For other modes, this test corrupts
kernel memory, which might result in a crash.

Only enable kmalloc_uaf_memset() for the GENERIC mode.

Link: https://lkml.kernel.org/r/2e1c87b607b1292556cde3cab2764f108542b60c.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c149675300bd..65adde0757a3 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -518,6 +518,12 @@ static void kmalloc_uaf_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 33;
 
+	/*
+	 * Only generic KASAN uses quarantine, which is required to avoid a
+	 * kernel memory corruption this test causes.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-96-sashal%40kernel.org.
