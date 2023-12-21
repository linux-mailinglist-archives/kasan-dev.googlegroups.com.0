Return-Path: <kasan-dev+bncBAABB4FUSKWAMGQEJKKMUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2678881BF54
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:05 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2cc77fdf765sf8473701fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189104; cv=pass;
        d=google.com; s=arc-20160816;
        b=zXtTzwytObE654iHPw7RIllomlCwl/RPlPi3MXjdiqzBxmLf99rWYybVHMv5lYspeJ
         B6d1NI231Tz+H8HYU/wX1668NSJbz9axfOATM7qQdyNqTkzuNilWi+6jRL/JJC8WA9MZ
         E2N1tXjiX9Ta+O5qC1SCw282J4O4M5WKGwTWmbqQiQxL/B3boIp1QdIYRk+sXdMrVkm4
         PprJfVyOpY84YqIfVPIIDBgl2kcV1W2e7bbmTlzsRnZch/z41IKoVhMNrHkdDncdSKX4
         OMjPfPrfxQtcVKcgsaF33TRgSCbIWw4bDQPSbpEP8M06gfsOC4iVpYON1h6n3ZBQOAol
         dfyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AOWz+E4KI7SnMyfJlBVxEj3sp4QzFAYoTYp2ovGRd54=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=d2Aed84hw0fpP+vDYT/my0N2iV3kbo7hndN6VfCeBWtoHew3seOoN1RpWl+KuCmVnK
         qsQdo0JbXbfDa/+fXlt01icunZhuBDYcKICqccLxHTWd01UCLpMa4DGZVTVP3VKBNMnv
         c32zTuyrSnAmbgspH7PX/ImoPkOUDaiAuLYF1UPchut9wZeafzWMjNgPqF6qSKErMGBm
         z0uYPjxETOoexCcGlG/5bJPS+jZdSJlGgSDHHbSVhtNU9xPRuVTuYsf/0wq5kvvZkZMj
         L2fFdVRuCh45GpprxKRNpKKuSYd7epS2iOZ3DHtYxjYGbuKfSmstCO9E9dmhH4MFJ4S3
         4I1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=D1d+7ZX8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189104; x=1703793904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AOWz+E4KI7SnMyfJlBVxEj3sp4QzFAYoTYp2ovGRd54=;
        b=LUIyOZCqnJPkErT6JTzqM1r0m25JEtk9pG/s3RFkA+PvFfxRwPtmMk285UL3QbLLQ1
         3N+X2fQatw1VBrLZoIMDAmCIw47WjR8XIl+UJXT1Cc4Phoay5fSPwmK9Ft1ZH7Yx0XvS
         JI2tPFlUNGmhp3BSPJDZ9pHa8Tngv8lWaMSRbRaHDnxjOIVlvqEArHwddkf/DU0jGjff
         C7rr6iLxzqKlXJ/Z9lILYGWoG5HEVDgs6gkDWleApxJSN7I6elEkZe3tfhArOSsLJqru
         Kve20BOwnRcFKKfbvVozCuh9LlCmwAFJjmsz5r+mtCXJ/VIRj9NbyCXlEJt1KI3C35cz
         yycA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189104; x=1703793904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AOWz+E4KI7SnMyfJlBVxEj3sp4QzFAYoTYp2ovGRd54=;
        b=a5SL1GbaTmt5xVhI0dC2hX5cj4Zssdhnl1ig3ArhXUBSWPhHym0XUhRtuYlHojbpQ1
         Vi+GZPAyluBI1ZaBxT0VSrjQNLRBJ+fCoGfHj/xUI5qsp2T7dzNIz4iNok5cypMxbpxb
         UYPD1ghjHlfD/tUUEF1FK9hSVrMmag7mQymQpJDSUo9fu7FfW6Wz9VXo0mj/I77ruI/9
         URXZ6g9YTQ5iVw2DQc4bEteRSK4lh21c2YtI9KNZ4r9+erZ/05cpQ8qILpRZUXHECf9x
         MdKgv3cj2Ex9h6Oh3/gyHnQpK+ubtRN6lGYEfnjkegVsZod3nCXI00/yU1O2qkUWsWzp
         oUew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzE/KgzuPOcGITuVZUPLklRyOnYQ/uOP7uKajpamKt3J4IO0Xi3
	LWVYi+H8J8UQvRDvS+OwaHc=
X-Google-Smtp-Source: AGHT+IFLyNLVUf8L7oM9Ht5bHgnpn1GuoCxDqtaJEzisO0t2wc/evizNqq7IWFcNTd/m0dMMDWX/UA==
X-Received: by 2002:a2e:854d:0:b0:2cc:a2e4:a43d with SMTP id u13-20020a2e854d000000b002cca2e4a43dmr52816ljj.38.1703189104390;
        Thu, 21 Dec 2023 12:05:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a496:0:b0:2cc:7e5a:90e6 with SMTP id h22-20020a2ea496000000b002cc7e5a90e6ls56378lji.1.-pod-prod-06-eu;
 Thu, 21 Dec 2023 12:05:03 -0800 (PST)
X-Received: by 2002:a2e:3a03:0:b0:2cc:9435:a5f8 with SMTP id h3-20020a2e3a03000000b002cc9435a5f8mr71570lja.6.1703189102618;
        Thu, 21 Dec 2023 12:05:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189102; cv=none;
        d=google.com; s=arc-20160816;
        b=Ri/LuyWtBV1htZS9UQ5Cbm4VSReBUTsKCGDBtHB14p3c6Jj+6FInyWxTf2hAUG5ZuW
         7Ca1GWi0sQn2DbYV9OHx8JCYXU3UbMLXeZoYSVaCJ3BYuWUaE0cpNzDSQSE6IopVqj0o
         3QM8L3TXCxX6iqi4l3fZc49xSAXuh0Fks6oG3+Kd8sx0Zak4IkOHRPiYGTQSrDd/cp+q
         VrjEl5nUO1GF9NJNf3TIOKVzQyUIt6DyBQAr+e4VO2F0aiTAZ+Ybz+9MfEG+tzDANwaT
         XKCdGe02EQ0zVzAb9q2SD2XGY/vuY7F5OYB5DfgfHXpVAAJGRN+wOqigz+ZHMJpgvyMo
         ksrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yJpT5npX9+Mi4/2vKIXBMX5Zb3QcQCwOWJP1qz8pE0M=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=qZUJA9ZSlX1gu/4OMrvDgpqj6dYUlgRBIOgjGL95YpQEFTxzbtmqBXWeDPYQ/tsTop
         dG2X1aVcS36ZSu5rZDV5FMf0Lz0HiOG/ZYk/GB1sG/GjCfaSpZLOV6UADyrX5yRifBW0
         GWqF59LCxK4Oq2f6jsi/FZJVgF1Srop8iK0rwy4iMHIcUb5h1wbq1Abp/SteNK1gP8Bn
         hz2jvCyyVmxsEVdJ15ovr99oHDvFWA2TH/FcurdE0+YiZURZ5RAFZrvrgoMDzqzk55wy
         Oj8q+qjwDI6a7EPRfZ1QT4IyfGYn2iCzlyE0Xu5VZ9D/Bqvn8YERg/C7i1R0c63OdGCb
         XvvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=D1d+7ZX8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta1.migadu.com (out-176.mta1.migadu.com. [95.215.58.176])
        by gmr-mx.google.com with ESMTPS id z12-20020a2e884c000000b002cc5d3ea655si110264ljj.8.2023.12.21.12.05.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:05:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) client-ip=95.215.58.176;
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
Subject: [PATCH mm 05/11] kasan: update kasan_poison documentation comment
Date: Thu, 21 Dec 2023 21:04:47 +0100
Message-Id: <992a302542059fc40d86ea560eac413ecb31b6a1.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=D1d+7ZX8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as
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

The comment for kasan_poison says that the size argument gets aligned by
the function to KASAN_GRANULE_SIZE, which is wrong: the argument must be
already aligned when it is passed to the function.

Remove the invalid part of the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 38af25b9c89c..1c34511090d7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -513,8 +513,6 @@ static inline bool kasan_byte_accessible(const void *addr)
  * @size - range size, must be aligned to KASAN_GRANULE_SIZE
  * @value - value that's written to metadata for the range
  * @init - whether to initialize the memory range (only for hardware tag-based)
- *
- * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
  */
 void kasan_poison(const void *addr, size_t size, u8 value, bool init);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/992a302542059fc40d86ea560eac413ecb31b6a1.1703188911.git.andreyknvl%40google.com.
