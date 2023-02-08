Return-Path: <kasan-dev+bncBCXO5E6EQQFBB4VAR6PQMGQEYKB64SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id CCD6868F367
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:40:19 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1500bc69a97sf9834006fac.7
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:40:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874418; cv=pass;
        d=google.com; s=arc-20160816;
        b=gulT0YM+90HJuyHlFc7uBC/jTnUId037eOGKSOb60ShAa5Qq1w4s5kptef9dovVanx
         HytpIJAJbhDek/EODKSsTWrR6jsXvGD25ZgXryV96yd9A6QcRGAuSyVGQad1aToAdRVg
         BQ5qIL36If+p67LVAP2CZTWs+euJhO5e3UrrvK9h5jBCz/X8z9rMwoOlULN8oNJHefnP
         cGwT8+hIpbFm0aCXPZES3/7KwFuS3Rl4bHWs3X/f397eRrtB1+/PTXZkW5hfmKaTKM9y
         NenLLTTBH/kY/CSdMQ+nISqGXc5AQZYbCLE3jYrcodCAN082Kvuxfyv18GRdqPXihmcq
         P+iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Dq3P0nTe1T6lE9QksCgQEfWvAOWGB/nP139iMZHw+mY=;
        b=0u2X2+IzJyl4j8q5BvoDkipAyS9SJ19VTOyL/rjtp4+7BV/LyDkYuVPINDJBhVMva8
         bKr9dsk2jUeb+J/gIVLIg2gNvyQ4NJ0Tzcpm8klkoltzFFGwZzQIxoj1xYkxMnDvzAM0
         Qm+F1OgQUejLfcAm0otB1Lz71ui1P8ZvkmNfOhE/CabWP1PLoKjtn6TNOe5emmOIF+mS
         pJHeY0pTB7fw7omCEBv2T6KEi87ZfIwVcqkIX5prGd+GoMefsU0FBtg/zEXBeDrSAuxC
         OdIF4av+li8aYK1yCtFWEHf5C71Zu9YYDPP+NBr0cy/Uo+41AHcC89Msdk7jIFqWgY1D
         hsvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WbTBU4bb;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Dq3P0nTe1T6lE9QksCgQEfWvAOWGB/nP139iMZHw+mY=;
        b=RYwLj7pSsuiF6PnM4Rs6q2FPYpO/DRJ+wMvpoJxICMDP8CTiCb8MBVWeLit8aANH+k
         8nSrtgd4bO92a44kjHCAKwk+ZxzSRrb2Q1r8XO62h52QMxPWzhsv30sseWOs8GxMF9+A
         ytOC6+ycKhrx++RUJB9Od2xdCl8/YJ7kOXVJrgg+XmWeLjY0jtqc7+3Mgt3LolWf0zbp
         Tosx59JpEt3a9uyBsx2KR1PTVqMqfwUsM1hCdJWsjeefJyYd4mkE55BcMVODpc+jNtnG
         qDQLfUkKJobzTIjpo7q/DrJrT+1oV7HgsDnMYEjVA7TqF7ZycSE8nqWs81fOay3yON9Y
         W/WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Dq3P0nTe1T6lE9QksCgQEfWvAOWGB/nP139iMZHw+mY=;
        b=FwCnmV8uJNgB7F+XAd3mC63kEH2zb2MgIdI7TyHyFKr2sAll3XQjJUetYCu0QmqrmX
         zyJgV0EE7k+sNKM9R8xWgEjMYQzU138n/YwoCX1q5h3XefdlyXfxVPgMYWx4nd6hBtBn
         mXmwa/Mox3PuHvF/MuGXL6GaDXLD/dJXe5LEcv/qr4luX+FELE0bvEWk114PqIasNzhw
         vaAKwKzDcoFvL6AV2yaNEql9WTWuFZ3pnolc/qSUoYBfWlGc1dPLmTMUQBNcCO/Hs6DQ
         AKXRyaUHaE9vukG3EmrkSYd+dztHRu7qDI3PZxpE2XYh7MaGXvyPrEdqg75rIWNuToXw
         DkXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXS95R4JxB3yG/m7oCjbBkLTZIvrd4DJqhOQ1BDGdBYYMUzKlL7
	9GpVSnGSphBfzIrD3U5nSEegkA==
X-Google-Smtp-Source: AK7set9ECaW9039lPr+zoCe9hmpJQheDTGWbByeDj3dLvNdCvJLz8lucpi+P/0IIEK2xG6l21HtbGA==
X-Received: by 2002:a05:6870:d183:b0:16a:24a7:28a7 with SMTP id a3-20020a056870d18300b0016a24a728a7mr378671oac.288.1675874418313;
        Wed, 08 Feb 2023 08:40:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:62da:0:b0:68b:e258:1c5c with SMTP id z26-20020a9d62da000000b0068be2581c5cls2109351otk.6.-pod-prod-gmail;
 Wed, 08 Feb 2023 08:40:17 -0800 (PST)
X-Received: by 2002:a9d:60c:0:b0:68b:ba93:6c11 with SMTP id 12-20020a9d060c000000b0068bba936c11mr4086088otn.23.1675874417870;
        Wed, 08 Feb 2023 08:40:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874417; cv=none;
        d=google.com; s=arc-20160816;
        b=oZ131KV0Qx+jqF8YoiY2Z8nntU8lJ7CB6Y4bG6HL09Oat4fWukOJRhEZw2oQMVBvXE
         Ugz4Y90wrSCcbC1bRRA3G6B+nzaQhe+2SqLboRboBf5q7sgy63G9R66U0Wlz8w6wtOuS
         d7sKZMQPwIud8JahVMYY5SSQVFrWWAKFkaQnvoBnXc7YPZj2hC5LA8VJisnX4u1G5UzW
         0KS0c3yMD8NzJ4Iv1HG2aZUBRCEidemdGzq4b1qnzHQGKACfWPmSCwwYo/o/QMoD2+Ng
         QKE7L0o1S1HrEc0mKtdodWciocNTXV7g2lyPm7MKDx/IwmZotjHrQphU+pAH/wYITT15
         CDjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/9gCt/DXMCz5FsPggffU4ASpM56svrE/8oAUHWynS+o=;
        b=LnMAPVnxFJFk3EmIZiUq6S3kJ9fEwupckzUXiPv5ovpTGHvP+u0ZYbjdCN85ZJs4ls
         mHtF7CfBmhaqRm8SaLcjC7E7DATtcqlv0W+jKE1uZUVdT0o16QJq2McYyBYVxlyGnlqF
         SJlQt5n5AiJA+pdRQoLK7TRyPs2K94NctAXxnz3eAIhBIi1G90t+uP7W1h8SlQecLQfq
         yp8Zi9+r4n/f7l84VmYGFKG6nzieNiSqoJWrkWi8CgCzZObVNen8gqz7vJfYdCdOmW2q
         C9qv6qDKT12t1dsk1pIfsHBinn5JC/smcbN8GBTWCrmPsb1zK56+0WBVl1WNdmEwkK/6
         i18A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WbTBU4bb;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e2-20020a4ad242000000b004f52827c8b8si1213422oos.2.2023.02.08.08.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 08:40:17 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9CE7561718;
	Wed,  8 Feb 2023 16:40:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1CEC1C433D2;
	Wed,  8 Feb 2023 16:40:13 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/4] kasan: mark addr_has_metadata __always_inline
Date: Wed,  8 Feb 2023 17:39:55 +0100
Message-Id: <20230208164011.2287122-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WbTBU4bb;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

When the compiler decides not to inline this function, objdump
complains about incorrect UACCESS state:

mm/kasan/generic.o: warning: objtool: __asan_load2+0x11: call to addr_has_metadata() with UACCESS enabled

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/kasan.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3231314e071f..9377b0789edc 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -297,7 +297,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_metadata(const void *addr)
+static __always_inline bool addr_has_metadata(const void *addr)
 {
 	return (kasan_reset_tag(addr) >=
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
@@ -316,7 +316,7 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-static inline bool addr_has_metadata(const void *addr)
+static __always_inline bool addr_has_metadata(const void *addr)
 {
 	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208164011.2287122-1-arnd%40kernel.org.
