Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYFAVT6QKGQEH5MGFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B77D2AE2E9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:49 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id h24sf78695lfm.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046369; cv=pass;
        d=google.com; s=arc-20160816;
        b=dvNIOoS6osFE48v7kudezjAeg6SW1LA45VDN+zZQX7JiQUvNJnRTK3M7OWOc4Onoza
         3Gp0xKj8z07P9qohZXDY620rjF8YJhBgPQUZOClxedvwJAUMNIUC8Fiqislifnw9z7AM
         iS9YiMNoxFybGsvKZyS1u2nOhI/uqFjrNLFebaouw4X96240HfeoKSHjqFSd+4vEzdLf
         4mT4NY9ktEsNJhgagHkqPPsH07NSxleRfqaD8hjA9anxUEhE49iCaMd09R46dL8JT7Hv
         oQUamSsze3+7q9t5WOghVdttIdI4e1C6EB8KOvZFeowBO/BsrHWkSRw77EUTXwCiMTt5
         KybQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+CeNxGA/eSClLjfNV8MuH6nfO5DGFDQ8+u8Eu/4rQk4=;
        b=pbOvOAHWRUN71QEDnooKe5RJVSIP0ROh8CKKDJtJ6/y4uCl2PvtnA9KfE+G6zNi0P9
         eBz++cfWG4e44k5MXCtjaPRQ8Y8xFL7CNmaDs3wCnkkDmKB41Thgm8BHUZqihiUaKX2v
         LWs1ZXWe00fi0lRPAOQAap+r4Fr/G5GrDB+E7LVhwqg37QTLgRGOYY8bIsCDLBpZ7tKC
         6pF+MhNNSAMh6VR297ExpULy+4rnPsZ3tFvYgFZNOk4rQk8TB2AG0Yuo3s3MuntntPZR
         X5utnvS+KABogEyrMjclohbLh+paHu7j/6sIKMMeG/yW567V71xAWNtwdgn6HzQddLgj
         4uwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RxPazZ62;
       spf=pass (google.com: domain of 3xxcrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XxCrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+CeNxGA/eSClLjfNV8MuH6nfO5DGFDQ8+u8Eu/4rQk4=;
        b=Uoad6R1Z9fJs+CfoHyUSkdgxQRD6MC6silXOjlR4CE8BM3wSizpZ+ATo1VjG7UpZWX
         iZp7L4Z3wcucmjDhcdoJ+9exW/N5JSsGbCEu9OJ1wnDPl6+ywCAaJTbdj8ttUl6sHU+9
         pnu9SN+A3UMSqT+Tfsd/1WBUMNxJEDLRCHqIVGZwSYsG84QdPnneTgEw6oFUVGuYOBnm
         lbXFjRwIuKXj6lD+oYTKnksNtCuOiQTrNUsFqTcJaThDm+qdJsnH80tzIVtX6DbHWtGL
         3Hvq3k2VZEimpXbqNAUlpyY12X3l4dAfcAllI5JLUggFN3PDxkIyF6ZQUtCosLmTCx/+
         HUrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CeNxGA/eSClLjfNV8MuH6nfO5DGFDQ8+u8Eu/4rQk4=;
        b=tI+XhLv2NfYwGpEhnc6ZuDtFStsj8bp7tr9pdPbhuhqSwg9njZR6TXraESvmwFKM1e
         QOw4+ujJ64DNHLzWsFnyJ0nwIge2OZde8AkBvgJxO/g9Zwl2BBsjdOdVjVdDtsPKXtGu
         Fl2JEL6tbalt0pk+ix8HX6QSo/bfj40Evyh56q23RLp1efg19rLQlRJbjC40bCLHh7bu
         lYReppgwWPcwqARXmpc+tXEGFfM0tCjznYhsRUmzwqN+OreroQ7NZJ7KQUpwZCBPBvDi
         ubZGP1F68g6CJtPFDDVitDBz+LgxXG9wAioXzFROxI7jJS1y8hLBCch+QrD7euekuh/X
         ByBw==
X-Gm-Message-State: AOAM530E70n7Q0Jn/HTW2lFWOYz3LXxhgTlLT/1nAv3y+6uqXkrJ3ccj
	o+IYI45PqBqRzt/iUGGu/ng=
X-Google-Smtp-Source: ABdhPJwEiJ0oJGpKIvWPk+C/hzCRQlEfWsrDmXshTT5MudQ6jgtu347DD0/+U6Z/JvmovTkQksJwrA==
X-Received: by 2002:a05:6512:405:: with SMTP id u5mr9184086lfk.286.1605046368997;
        Tue, 10 Nov 2020 14:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls1289598lfa.2.gmail; Tue, 10 Nov
 2020 14:12:48 -0800 (PST)
X-Received: by 2002:a05:6512:68b:: with SMTP id t11mr1849919lfe.77.1605046367999;
        Tue, 10 Nov 2020 14:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046367; cv=none;
        d=google.com; s=arc-20160816;
        b=cAbs59DvJWA+4OHyqccS3nLxGmAxbYFAe3+Z6Rp+LeEPI0yEHNBq/tkxodntslQSig
         vrJOE7/HZYBEU6QpLt0o5Xaj+RXBiU9nCIXiJYjhXYPuHdUyb55r7zPZ2saJg1Rl5GST
         RC80lVKJH3ithVBCS5HmAXEI4hHfUhpl8Xk2Jvo8WnNDiX4Zljld9PVPNLhQeQUY4v06
         V6mRdIx4ltB8TRVtWzZwXOk60KwYlVUOBIKl7JlCyle4sTYHyzMFYryXMGyVdKfe2M0l
         ER5kXbGPVWkX1uo1OYytJn/W230Gbpafq9Y217q79m8u5qbjDywIQN9rXer6+iDtRKs7
         qaZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=3bLCl/qn5nElnEm7yzZVsuSSkTputMy9yS6WNazIy+Q=;
        b=KVh1yOgon9i69LhMm51lyG6+LErLHpCELhHCZxi++OlL3C1SGHvxYoEi9jXI5bLT59
         YNxoz6IHM+CUJ+tjEBmFLINBs26lfToP1H+sdbbFFfeALygEjrMKMJjva53t4bu96nzd
         0kpaNOQA5hNqxfY6vp8a3WsKHXwfDtwjs2tCcXmo8KKq8vw9KRL12RgDtdSvypVK7HZn
         fP9Mq06r0M1RJYleW5ZeBLoumBYX+XAmkmcSV/n5ZwChX3+7rbl0iCcy+QNzYHzpzArU
         +O5WszUv+5hh6EwbjJ/QRgbnb+cPL07LG6/6XIRV3iDsRWABY0YRTVE9Ek14OoSSXmg4
         MQkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RxPazZ62;
       spf=pass (google.com: domain of 3xxcrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XxCrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id o185si3397lfa.12.2020.11.10.14.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xxcrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r15so1105888wrn.15
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf1a:: with SMTP id
 l26mr289880wmg.18.1605046367415; Tue, 10 Nov 2020 14:12:47 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:39 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <3d24722ca600b65a186a55ae47777a00a7c9407c.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 42/44] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RxPazZ62;       spf=pass
 (google.com: domain of 3xxcrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XxCrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 456741645f01..c35e73efd407 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d24722ca600b65a186a55ae47777a00a7c9407c.1605046192.git.andreyknvl%40google.com.
