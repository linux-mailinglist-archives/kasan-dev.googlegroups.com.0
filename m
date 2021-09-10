Return-Path: <kasan-dev+bncBC5JXFXXVEGRBS6I5KEQMGQEZ3XB3ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id C59A84060B6
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:20 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id 23-20020a05620a071700b00426392c0e6esf377120qkc.4
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233100; cv=pass;
        d=google.com; s=arc-20160816;
        b=V3jQMUSo6OnZnooXMIMlhEeQAA+E2An3Qh+Fw+LJbNv3ZM21sRqnJARfEgzkNPjdxl
         w3JZvqIN1A6S5pkD2qDWAbk4Io2UipbNg7v3IJ/pVFpIOEw6JB7OGYNdI/ZLhs8u84k5
         1By2+KBocXX9589BTTDpmLuTXbFwalXh0T/TBTiqTnVlOD3vJExAA2x2K9vZawDAxft0
         crXFvNGxDy228EWecr7E+4Xtkb7Vx0CYhMatE2sDrWuW7/tobLriiWXqZZXeA3DyvHTM
         707DVpYbfyDKZcG1JCeDV2bHJbLrtcyaRv/AvyjU/CTVWnyfi5VtF/hBd2+LAd+RO5+y
         w85Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5v9EijOK5Il7YJHZTiTqXn3gVXEDU+JNw2yzNs2g+Eg=;
        b=Io8iOimYEP8YVQ9VB3ixOwiQJNKqI/93lBE33+Xsu728KYs8gionDflFYPdxsPX+KA
         PZy0mmBEXS3h2jzLGrReK5oVksqd15q8SKoKAUjsUlPl4F512Y4O1Y/usldwYxUQQ6lu
         82JtSpE02C6fVXQb7bljhCwkUxb9IRThlWTnXmrIL9xVisuVztU7h2GKecxgOfUYwSli
         XdvJfmrAnaXeusBNgnLb7mtbYwRXkPl1MhIDOZ7f+i3ESrKsFGR4ohVeO8V7fg86bjwW
         mSlveWD/pe6NJgAeTDFNpsxU13d7zDM9Z3wdPqIwxlqx8WdPp+yYHOwVje+Tv7osiX02
         7lzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SMICO8jK;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5v9EijOK5Il7YJHZTiTqXn3gVXEDU+JNw2yzNs2g+Eg=;
        b=Cc6EKsLoyDFrMpfNqkuPy8krP4Uuq3XZEJHOeVWIXWWEWMnGSIs8De2Pk0StPO7fkv
         3Klftw8yqTgLN9GrLE2B6hlUi/qA0iiWt83407maNyIt6xMWMQvgdeDpYs97GvKJaSUP
         g46iPl5Vb2XfCswuMdJlyIC+Aj0s9nMKGPmgAdqbfeMKUnLdRZWMFil+GTe1yKJhaYvQ
         Yxc8FzGE3dhOlmNan/u8Vn5flUCVoLsLsMCMyCijoyyzE5T040L2wHodxS4NIoMY0R9m
         fvb++1JQdM2QMBjgVE7BShYiYgup/JiNkve8okEy4k8RCcJNxCcX7i1SYQb3vZUoMG2k
         mO/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5v9EijOK5Il7YJHZTiTqXn3gVXEDU+JNw2yzNs2g+Eg=;
        b=7cu5totGnVlWec5ITCi6xnJlXvH3/cIHpYWpGfTHkRmvOZhJgiUlbHwzT1eNx6VIhj
         kQrAc7ZrgIVMfMbQaAc5GIRGrZJCsPWJ/7pYUoUkJYPktig1CqzAWvz5rylYt/iRg00a
         MQwuk4OguqE1gE6kFELOrN+yMiR9yL4QKXB7kel1Ti9+iCpaj+eZ1qA59FAtppq/ARiO
         A+Bko/tKN3sGHmXC4LFOuRDdtkcZ4s3HttJHcIVpq39AYDqM3vLHJ3VRpBBDZ3VoAcSQ
         YtTpVPvllWTn1K1ju0YyS3AEyVzNFC8RTpxT7m35GUDHa8ovvie3i2Q4O7n8aJ/yHW83
         AfXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530v8cRrz9phYO4pJ5cqa1T3RoiDqswYzkxcw7hXgl6/4OqmaLKj
	rW+uBqACv2kOumhr4g7aDrg=
X-Google-Smtp-Source: ABdhPJzL5Kg2oCcST+hmFdqr+23yv7Ko42ysSdMVM7/g1sUcJM9FnkDfX8Y3RombwlsCLBRwWvprTA==
X-Received: by 2002:a05:622a:1898:: with SMTP id v24mr5612167qtc.226.1631233099955;
        Thu, 09 Sep 2021 17:18:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4590:: with SMTP id l16ls2101735qtn.3.gmail; Thu, 09 Sep
 2021 17:18:19 -0700 (PDT)
X-Received: by 2002:aed:204b:: with SMTP id 69mr5534812qta.24.1631233099519;
        Thu, 09 Sep 2021 17:18:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233099; cv=none;
        d=google.com; s=arc-20160816;
        b=R0E+kb9++rA4tyvAtHjtbTn/zcp5q1h5otlrioCooL/LXNwYIsBIrhBVx8ZYrLbkkq
         B9k+ayuslkDvIy4dYsOMnnXWIOLKiA0YhvG4c3joiXQS2WfQhM4S1J/2LODB2czwdBvZ
         GrRDpmrG/tAlZZhv80WzbqkUYosdXgHEeQHpAmgUmVfyTWr8+gSiu7L4nJec3BtapQS7
         cC7ADorYnhbOj1R0jdy0o2BWZrOAx5WvHg4T7iyuhKNkzHJNHzSyQddcolJgtitDXDRB
         BjFpoDmBXinBhokvtA1G2b9B6F3XQ/EDtEEghNxRWvLa1mo1vX42uhLdA1AUc03OpRg4
         /Jeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ic/+d9i0EjGDmemIdZbS5lFh8WKXBIBb/879FCd3d7o=;
        b=ZEpGyzr9zxTbqzcY7TrwOh7tkMFWlxzmdtwZ7bfouZxk6KiPOdnTlPLANpe/zGTPOQ
         qzKrwXQayq4dhUv660UWjhLfMaHZHd2eoScDjoqkerDgqZvf1o1NdOLGrvEvnrLJJZvE
         vVf8CL1T2Fv4bDYkbysBMXdLrmAXyWKLmP0vzHZQXvvFRTZybyWifE4h7osmKU2+/TgX
         TBd9K5TyoG42fSLHTmuiJFNNkT97gZ5f19e1rp3lcP6YxfOBjJsqhnxDBUrDbH5pa3rk
         h4EImCWt5OvJUWDsmFuaFkgQg6fb6HFUx8kbqRKX87c5iFzBNI84eXyzxbZaYGL152EC
         tCzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SMICO8jK;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g18si370507qto.2.2021.09.09.17.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 68F7E610A3;
	Fri, 10 Sep 2021 00:18:17 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.14 99/99] kasan: test: avoid corrupting memory in kasan_rcu_uaf
Date: Thu,  9 Sep 2021 20:15:58 -0400
Message-Id: <20210910001558.173296-99-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SMICO8jK;       spf=pass
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

[ Upstream commit f16de0bcdb55bf18e2533ca625f3e4b4952f254c ]

kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
only safe with the GENERIC mode (as it uses quarantine).  For other modes,
this test corrupts kernel memory, which might result in a crash.

Turn the write into a read.

Link: https://lkml.kernel.org/r/b6f2c3bf712d2457c783fa59498225b66a634f62.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan_module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index fa73b9df0be4..7ebf433edef3 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -71,7 +71,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
 						struct kasan_rcu_info, rcu);
 
 	kfree(fp);
-	fp->i = 1;
+	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
 static noinline void __init kasan_rcu_uaf(void)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-99-sashal%40kernel.org.
