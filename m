Return-Path: <kasan-dev+bncBAABBI5372IAMGQEX5UKDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 898254CAA89
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:38:59 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id a5-20020adfdd05000000b001f023fe32ffsf830833wrm.18
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:38:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239139; cv=pass;
        d=google.com; s=arc-20160816;
        b=BgImbt3mwwryqtlhVLRy323iS4nw6HSmAhcplApjoXgH1K6AGXoM2jY3yCKeMfItsZ
         O6X6fAfNQgaJn7dDUrcxq+7v2zjX7lwPdVdv5oPwdytNdviZtXSxb/JnqGT4zoWcFjyJ
         Gjcm4XpugOIZFqo2FycsisXoMlJwykhIb0EsWzz5NqgIwVBWf/PMjWYsxK1wAZ5IM8j2
         Qt2wcyawdqA0dby2BxznBpMAtcBHNxZWg5qGaRxQUTv6yQXL/dq4qsSJHXLajT6pLyk+
         fr+M4etmJ5IMDumQ8x7sfiXEUFt619vAdIzQ27ySTmjI5GVjKMPklpah/q6Ws2vwPFRp
         SicQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wVQBWLXLm05dfqElGS0Z6n8ELiQY1QOYCsN3g9u/jMA=;
        b=h6LhoS74JsUK+AaDVXe06M4QtUKBJEeJDl+a9/EVYMVHxOUMME3v5tnmA6bHUwrwO2
         nKMIattF3OxSOrwcuGzJYZaRTsba9gtNADDusmJhcG/aPwyZUNhSObv/sx4BXAo8ipCU
         sg6xTWKETJlENuzS8nqszp0CmGgJ7nFIIdWCoX5ixbvADHC878TTSrYI/iI51VZK7K4u
         1/OxTYLx9CYtDslf5BPAv2/3Sv3A3VQzH3obZaBJ+yKOq1JjVSrUjrfWtmdvhcPced/f
         vsaHeQ2FhgXRl/rRzb52qoh9SpGHbeNj2v5Hs6bIhvQVX7S3NU/S13yEG2usFmrAcMY+
         HpJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lH9wtAh7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wVQBWLXLm05dfqElGS0Z6n8ELiQY1QOYCsN3g9u/jMA=;
        b=PYHmoT618nlsuerBhvNJ8HJGPIWw4jQiagXaivzLuKhDcGfzpd5prHCTcJFCODNCIF
         w6XaRmk7+A9vS6Tj4bnYSid0xvzmFOgoKip4u0SHY1DPBF7CknhuFLiljUOsBPdmYQoc
         nLpHhzcxPlnZyt07phYLJJL5Xh6ExTXXh+d9rl5ojwqVORuU49pbygoEoU8bjTeTXlRR
         4qpg0+6HavWsF7+RyYDaTJGJAO97ZJ31QscATY4+G1zxhDsrL9acirjU0Hob43VeMVbr
         77bL6wiW/yfLRoxVgTwRBAGPdTfvGZsToGf+JFUeWdQjceUjxJOrZ/LGrqKkjh8T17PZ
         9jGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wVQBWLXLm05dfqElGS0Z6n8ELiQY1QOYCsN3g9u/jMA=;
        b=AhIUUk8gf7cAST1WisDbUrt0B+oWWKmTh1EhVD9z99rdeywFwiFb3bfP+yLUIfnmB8
         1zGbqlwbZZ0srBl4eDLJqMXKfHsopmIagBbctnmwpTZwMha3tDENPXk0Ikb/eC+oxWlD
         nFx57qZo4dSPKiial0/s3lfZZd/mFoJjgf0ek5dgg0NDG4O4orZL4stRF9c2VPWsI+DH
         VS9dEW6QmL+aCgKXTFkULMo34llpOSaMGuKl7mE8/FK1wbn0Q30uLxUlEBmH6sXpXY7b
         0pxlVhRTUnZrJ7gHte73AR/klILkI2vNH2Bgq8jyBqiw5q/ZCR5/ryQrwz/cB8aJMLwq
         /Ogw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tBkgszhsPoZVXoR4vP0g8Pr1VpD9z/Q8PdU37qzx3WQb3PhFC
	9sgwxR/O+OtL2culrbxjOqA=
X-Google-Smtp-Source: ABdhPJyKB1+gtIz2xIIPMP12IsykY8dtehjsop4JRCEaBu4e/I/Kuk/Ue0sRqQOXtDN0nAHmvAWDPw==
X-Received: by 2002:a5d:4091:0:b0:1ef:6670:3fa5 with SMTP id o17-20020a5d4091000000b001ef66703fa5mr20009281wrp.632.1646239139305;
        Wed, 02 Mar 2022 08:38:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls703509wrc.1.gmail;
 Wed, 02 Mar 2022 08:38:58 -0800 (PST)
X-Received: by 2002:a5d:4089:0:b0:1f0:4819:61ba with SMTP id o9-20020a5d4089000000b001f0481961bamr1279436wrp.307.1646239138698;
        Wed, 02 Mar 2022 08:38:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239138; cv=none;
        d=google.com; s=arc-20160816;
        b=Shko1+LxJRyXuNDhoqnq5ydaFwVM1MFT1tF7kxgg7ELM2grRVUKEHoqGEc7vxHV6IM
         mp3QbpOmvhqSf/QPL6aPvaCRPS1boXa7xqBCm+Pm8vEfIzW+AG662rHFf7fiic5ElC4Z
         vlJV3/fCDYSkVL4wW+FXtry24WVsGJMoVX0oSrlIgfG8NX/6BG5m8QBUM80H0vay6BdS
         jnSqWvIiyT1DRqvJF1EUhMr7F7x6OxZ8Z7A7Ze6jeBuF1pxJqiWRLiXH/xJJgTEeJ14B
         086E3yuZOpyBFUeMVk2EzYNnw4KRAVLs+3+oN45rLtg5/OgU1JTS2R90JqV0UKll2uc/
         UR9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=M062mhOVYVf9bJIp01ZOeX3qpFJNVUV/wAEZA8I272E=;
        b=QxiPBuzgRm35hCM9laTV6iOtXl1P7FWuu9FuNOph4poK0I0YutBE1d1uTlBEPagUBX
         v1Az28Vox+sKBzrBgAUQMOUmzVm5cJQEniGLcGqYq/5aqo/bouonJIdrzl+nLoGmSGv1
         bWrOvBIj1aphbsYKQNWCJEgfCEldz5uUbpVWr5YpFlRNwm4bOICPzPIcMKg1AnOwrU2F
         31MJck4+25izuG6ck3UrMoAdhJ+BDKViEOOiVkXjV8CWyY/FawE7CWAkcFSQpEw9SY0h
         9IrLsnRHvyw1iTX6tDLUxyKhn0AC+Y30+2H0B+YgG1ybfK+JTSq7P7MMHv/9QuhsZkMr
         Dd/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lH9wtAh7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id p42-20020a05600c1daa00b00384472596bfsi123218wms.2.2022.03.02.08.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:38:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 14/22] kasan: merge __kasan_report into kasan_report
Date: Wed,  2 Mar 2022 17:36:34 +0100
Message-Id: <c8a125497ef82f7042b3795918dffb81a85a878e.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lH9wtAh7;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Merge __kasan_report() into kasan_report(). The code is simple enough
to be readable without the __kasan_report() helper.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 36 +++++++++++++++---------------------
 1 file changed, 15 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 41c7966451e3..56d5ba235542 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -435,37 +435,31 @@ static void print_report(struct kasan_access_info *info)
 	}
 }
 
-static void __kasan_report(void *addr, size_t size, bool is_write,
-				unsigned long ip)
-{
-	struct kasan_access_info info;
-	unsigned long flags;
-
-	start_report(&flags, true);
-
-	info.access_addr = addr;
-	info.first_bad_addr = kasan_find_first_bad_addr(addr, size);
-	info.access_size = size;
-	info.is_write = is_write;
-	info.ip = ip;
-
-	print_report(&info);
-
-	end_report(&flags, addr);
-}
-
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
-	unsigned long ua_flags = user_access_save();
 	bool ret = true;
+	void *ptr = (void *)addr;
+	unsigned long ua_flags = user_access_save();
+	unsigned long irq_flags;
+	struct kasan_access_info info;
 
 	if (unlikely(!report_enabled())) {
 		ret = false;
 		goto out;
 	}
 
-	__kasan_report((void *)addr, size, is_write, ip);
+	start_report(&irq_flags, true);
+
+	info.access_addr = ptr;
+	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
+	info.access_size = size;
+	info.is_write = is_write;
+	info.ip = ip;
+
+	print_report(&info);
+
+	end_report(&irq_flags, ptr);
 
 out:
 	user_access_restore(ua_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8a125497ef82f7042b3795918dffb81a85a878e.1646237226.git.andreyknvl%40google.com.
