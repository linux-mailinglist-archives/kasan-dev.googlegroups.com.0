Return-Path: <kasan-dev+bncBAABBMFVSKWAMGQEGNXEEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D4CD81BF5E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:09 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2cc70265abesf3126931fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189168; cv=pass;
        d=google.com; s=arc-20160816;
        b=MEfxY6yRBIk7BZ7fHZte0DBbrXQxTmA3l1nzHXsTh5Y+01JRUtGr6+0fT9ZvlZVCKF
         QC6OQ/JqTxcBlU/W+lgSkCSIyF8fogS36+XVfFwOAkpAnxEKLnlkBK4EmCzbpkF0L7fu
         Wt2087siacas0zXDTkSoYoDYRYQvQnhze/EZb8kgZF1q5WZ8sBJpUejrKIQdbfkO03z0
         RBViv1sB0lzoe2TO1ihd0VRRR7wN00ekFb0eP5Q9lmix0xlUwYVA6giaxyPVQi8RCxnO
         ZkCsDneM9pLSg64KTgYYENk8c45MbbsTwIiToObGW0biNdYDmLwDFeAoaVHUkth743zR
         W5fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=i+NlgosxUDfftfhKpVIGyOItmwltZDu96ADuuMfhwag=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=Q9oQv9HxaKS2lZYwB4AC+PaWb5cqj9013KQXK4Cu1rZzhkr/EIeFLy2q/Kh7cqnYVd
         XMT1xSB2CMICzq4PtoJ+r4JlV5LQkRz62cRYLvapMlPPInn/tk4nbm2ngZLXOR3T9+Lc
         73LJgEJ7yXDSbraLdLkA76J2pJVlCRHY+n7vlb99VfoNLDX7lLQ+VECZwVG05b516i3B
         En5Tg1JbM5UgnflILq9xHGxio35tOklRRsTZbroVlEEtpIpUbkhDxub3bETsqsQssCmM
         tElRB6kOXurgNUZ65Oj1GLmoi/dmcP6n3Q1OaGh0rCNxYrVVSaNEduRXp8xKcOe0ABfi
         WqKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eN0oFbJi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189168; x=1703793968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i+NlgosxUDfftfhKpVIGyOItmwltZDu96ADuuMfhwag=;
        b=KBnWZ0+LEuj8n4CqMWvIqpX4MDcbvMUAezBZczCaaR6lgkBy5kwbLlVcbGXEwn05Ua
         5KgHDuKFcO0E95J1Lgpr9K6HoHvv5kdmEYkpP9Rn1X7WFZGcTgCn/u3HIO1paE+9OXip
         efIJP2//drtWXIwQRDOteD+Tpxkt3Hhcx5JnlqvPJ2hh92U0yJn8MkdgBU8LVdg5T8MH
         LY7e+8Y4rgKUWQVTetFUxS7Nep9hQC/g2ixz0QNPWhIPmnRvQNJ2Nx8NKtrkOm/njNF7
         X5cdG+2btXLVOMpFTGPuX11sDOS9IJqfk+bTDAkfPyRL/wsrj/Bd79TS3hTq8tuZriOn
         A5/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189168; x=1703793968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i+NlgosxUDfftfhKpVIGyOItmwltZDu96ADuuMfhwag=;
        b=vNVpZwHocJ28pYC1WKksIwQGjBqVXhIhwb++DH7bNTN3/J+XaD778wU5uLitZEV3J1
         CVRd9GQrH614Bw+Au5Q9lDwdX2w6wJ7CvRtVygi2IhUQ/0kWtUjqSkkxF6+hVr87f+Gv
         hsQEUQfrDKwHPutnE6IUiMeOjTEGFdh5zX9hwj0XnaG9pq2dEyl5Kr38Y350W5m2QsZX
         +7sZXPqYsiCWO2KrEjr5/RCI28j87ydRmw/DTs5gBFl1Jxdk/9sViwBe2KRdlSkhnNIN
         LunrNZB/ZR2R7BeZ0fD4bU2H711vs0pwZEqjVB/KFbdO1PPALTrrbO9oUaUhze0JsnYW
         U19g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJZhYc4SwdHSmqOsfG7wN23ZzguaFZnMua6ha8UsXGVtL3CKDM
	Lf2FWtfiUyhN1pNBQYIqVoA=
X-Google-Smtp-Source: AGHT+IHNIYfzphSEConcQuNMkkPyYd3dQ1hzGf19sroybKkJrH7LsU7Jzyvum4MXGZrORTBRnBRHEg==
X-Received: by 2002:ac2:4c23:0:b0:50e:4a7b:f506 with SMTP id u3-20020ac24c23000000b0050e4a7bf506mr197327lfq.4.1703189168367;
        Thu, 21 Dec 2023 12:06:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:b0:40c:461f:bd7f with SMTP id
 i4-20020a05600c354400b0040c461fbd7fls773881wmq.2.-pod-prod-01-eu; Thu, 21 Dec
 2023 12:06:07 -0800 (PST)
X-Received: by 2002:a05:600c:1548:b0:40b:5e4a:408a with SMTP id f8-20020a05600c154800b0040b5e4a408amr137078wmg.170.1703189166751;
        Thu, 21 Dec 2023 12:06:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189166; cv=none;
        d=google.com; s=arc-20160816;
        b=OW6JZCYqVEYh8jklRTv9+reLYWrSPPxz4uhRs+kGsICGJu036bJF3QzXIj3BY0xKmK
         E0H6/uW3UbXBxwGDxMqcUJUgbN2wK6BCJM3Xcf4C/6OmIifMV0H0aiimeJB9rbfJ+87q
         E7lzlrCv6lbADfCKY0wa4EkBkB+rNWKojEeLvJtZ0qDNwiPa42A0Ol8CtfV4e0WrPxiG
         9QBuZ0HWRiv3gFXGQhtKSBmzXzuo4ckMMJywv9ORyOJTVDwWswv7FlJEGBPQBCZiRk/5
         kXvz8BGSIAv/FBXGBroClMaWQEyl+Xo4kDpS2u450LeftEe9TExAdy5FywEhWAIfpICI
         +xhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a/6/sI3HKZf6Tm/zhA/G4IhIpYOeRmpfsNisTtqnMzE=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=FKbeM+REwynWXjcJ3txI2v2TeTC5nUrfAH64TCFJVdikk7TKaeCk1CK4YNHWRgeWRn
         PIMw4Ebw2R/IwPNQWVwbp9keKpFVdg+/tXnK1WlFj/vWoi5ydiRfcGdNo7dFB+FXvnl4
         6puJm8rXcO9SUreAf4GZRuDR5QdacuieYm9OUY3c1Nbt8/4DsLlG2VmiyOQTzHLoYtu3
         hStKiuZ6fw2oiy/BfzFlXdVzKAXNiKOIPGFR6kXcqH8Y97DaabHHuG5CdkXRwNoDe5wA
         K4stIYngDwyPSfV5IbRLG6S0BKnwxRdh/NUTVJ4FDUtBSHCUMB5AwN6dKHFg3HeyYD/q
         nalQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eN0oFbJi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id ba2-20020a0560001c0200b003365d6b3e14si144298wrb.1.2023.12.21.12.06.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 09/11] kasan: export kasan_poison as GPL
Date: Thu, 21 Dec 2023 21:04:51 +0100
Message-Id: <171d0b8b2e807d04cca74f973830f9b169e06fb8.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eN0oFbJi;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

KASAN uses EXPORT_SYMBOL_GPL for symbols whose exporting is only required
for KASAN tests when they are built as a module.

kasan_poison is one on those symbols, so export it as GPL.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/shadow.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 30625303d01a..9ef84f31833f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -145,7 +145,7 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
-EXPORT_SYMBOL(kasan_poison);
+EXPORT_SYMBOL_GPL(kasan_poison);
 
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171d0b8b2e807d04cca74f973830f9b169e06fb8.1703188911.git.andreyknvl%40google.com.
