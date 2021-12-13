Return-Path: <kasan-dev+bncBAABBZMC36GQMGQEOK26VXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5764947370B
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:50 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf10284864wmj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432550; cv=pass;
        d=google.com; s=arc-20160816;
        b=yVG0M11KZDI9FGxmHk9qRHUCt+rM3OcUCcZWzd6KUdaoFZWYijP7f5HHwxQpcmJ2+5
         KCteZPCEBkxj9R273AUA+IKXbutO2B2Z9uhm+DkWMuj1PEGhyUd67u7ZsG2sm4TBJaUs
         chobGqFECYrtgsgu67PLX+PaDQIAgsVmoay2uObuxSzDbNiNnzblWPzLqGnwfViBfUna
         Sa3tE7zdz2szvLvqSYTxVdeyiPo93vwhJdNcX/K7JvJOJAAdRrTRzoJRcRbRgw8ZGxrb
         M0MGE7WsClfSzCm7kYAILb7HehNCtsXUNVxr+uYKAMSBFGl0dFcFRIfR9HezVr2hUvL0
         uXDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PvC2vgb2SJ/NIy1RpkfNh0svQGZB4trgY4ryrq97JdE=;
        b=KBZ8STfaQ7JxaugrXsVmqWgMxat22lrLxppzSjR6OgH/roFzjW9EWucsDCh18Mgcwf
         ElozFLjLq5d2s+hPPLLPp7iwwFkdBpNBQRxFzB2BwGtmmqED9CaWrgRKiS9dqeVHLpsy
         +3qRBCIqe9nuQEtl3fSzCKzvLOxW1c6ggnv4EQr70RCm0xJ185C0nVxs116sni2IQKxE
         CNoDdrVqPuysHvhpii7xm1H131fdBJQqzVz3w7sT2/Oaiqh4gB2N4IrCGC/m7ea9ueg2
         Q6/IbdToERjv/cMqJcvBNWgtk9n5FgLjXVtIXvsk8dpnXt7OsjV5uNKVWhC6EwR9I33N
         fmkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="KjO/G7hN";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PvC2vgb2SJ/NIy1RpkfNh0svQGZB4trgY4ryrq97JdE=;
        b=aW4Ppc8dx58Od4y2Gcrk7ZiVJh/YbJe9Dt9pUdLHOrFWf2VRCvLVgxthtqs/OwKmhw
         BWb6XrTnIvMQxaRMmctPOAd5NQhMoPyC+JPgSM3LQyohFWkli5ZGybldXRoIlAaXBMcn
         SGN7DSqPST8YEcwfdbg/yO+G9O2XxF0Ab5NQlea04w3nldw4UQh+LGjx5cJDyU4qv2kP
         lydE+gV5yORUEvAi87XgY5rVvAbBGDjBqPsMwaRjdlF4FnXNk4e1l7tg8vWTo7AZhWGx
         NCnDeXpMvD7RTl8dZ9yMlC3BGP33rcBhHZQY6SsMwphm8W/YH0wo7sM3JkIYu42TjEBr
         +qfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PvC2vgb2SJ/NIy1RpkfNh0svQGZB4trgY4ryrq97JdE=;
        b=5jwOaDklH5D71Ph+WUTNpkuiLCSYGWkm1bF+IIkDlaA1LXMUxfujPwgAjZUcqwO+Jg
         ua6yf5k+MGLAzxw55NNg3GYbdoWLk4TeqDmWVn1oIGwuS1AmGkH3m6yWctk9SeNTZACn
         m1iscbIXXDOn68x0Zw7jLWq5JOqQOpmg9019XZifGTeMWay/oLAnVNjfVU4i1QOrzDNa
         I0GcQCKC930TvRs1lahQyUU44y8D0prg4RetIL3cvXyaHLSpGWuDcdYkDzm1duADDtxP
         7TlZa8f1adtr5iIzwNyIWXdj9nhvz5VWo872fEZTTiTwQycRQzkL+tzHvSgHmN2VteLU
         KcnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KHw0h9biBo9NYQapsAySUVEW6dTKWV3Uy1JnacajzLfNPFeE5
	i8Ckow93DWZY8/tjIH5r6B8=
X-Google-Smtp-Source: ABdhPJwcXyPJvMpW+mvjp9v036YPO8HZyM/9Kisfllvp8AchLAYgpG8CqXG0takSf4QHt0NsM4IueQ==
X-Received: by 2002:a05:600c:3b8f:: with SMTP id n15mr41558526wms.180.1639432550016;
        Mon, 13 Dec 2021 13:55:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls504360wrr.0.gmail; Mon, 13 Dec
 2021 13:55:49 -0800 (PST)
X-Received: by 2002:adf:fb09:: with SMTP id c9mr1229893wrr.223.1639432549397;
        Mon, 13 Dec 2021 13:55:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432549; cv=none;
        d=google.com; s=arc-20160816;
        b=lwOq7HCr49U7m8PuaZfpwHE0J0RC05MB2ZAAjF6iTW0TEu8Hfbg3PMYjrr6HN/VWag
         HozT6fmlmiHI1iOM9lxjT6rDNMIWckMdmDh9riOy/VbtVgjt6A1n2nqTWEOki+WfAX0K
         9hJYUTur3u3U2GVxPPEAhWvEI9uNzSWr18jnX7bqusI5QEqf8xKYPSQwBK6mHJFOJQlU
         wMp8HaJxuFo/nP+M8IuNHXaKaOVg6oY/PxeVSTt+0faBKeO/VTWs5Y0MKf3PG1HwXw0N
         nhM7muleWmXVUOV1UzmHY9yFx3Hlq2+3Mj3zMHDrhFhnpy7JXa7SleQ5nzEl13uOBiq2
         bohQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iZXIY+Rf2d0lHK12UJvskCxlA4nRW5M9PkBwAVYILek=;
        b=V0tkWjwBZJFyXzd19AeJgDbsPjLwP8br1tKFNqZaV8Xqhbh2q8cxr7E9dhLvxf9Roc
         4Grgr+5xAQCdIN4qqm/K3GjSRp6v6TkW30y9lIp0mJZDB5n2/5AS6gB+3YRLBdWJ+RKD
         x9+l5Ye+u+fKZL6U+EEiHjHQM6bdPmbzLL6SyO5pbvI+VW5EWkTXYbevFQk8oitTkjTj
         8Hh4XjexWwqhErAFpd0wsvFOYC47E3ZMhNtMmG7sMt2/UtIsJUKIeUSseUe5VFt6YW0a
         TTLqq53Tce7ZGP9xcX0JUQLXR3/GwNjm//GQ9fbJ6Kv3Jecdzpw64HVdwme7zYbcn69A
         GV+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="KjO/G7hN";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id p11si23631wms.3.2021.12.13.13.55.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 36/38] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Date: Mon, 13 Dec 2021 22:55:38 +0100
Message-Id: <2a3e235be2015882c6e90e6810f4974a31e7ad42.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="KjO/G7hN";       spf=pass
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

Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
select KASAN_VMALLOC if KANSAN_GENERIC is enabled").

The same change is needed for SW_TAGS KASAN.

HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
they already work together as is. Still, selecting KASAN_VMALLOC still
makes sense to make vmalloc() always protected. In case any bugs in
KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
flag can be used to disable vmalloc() checking.

Select KASAN_VMALLOC for all KASAN modes for arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Split out this patch.
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e30b72208efc..29bda8b65b0b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -203,7 +203,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2a3e235be2015882c6e90e6810f4974a31e7ad42.1639432170.git.andreyknvl%40google.com.
