Return-Path: <kasan-dev+bncBAABB6MB36GQMGQECSDUCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9D94736E3
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:02 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id w11-20020a05651234cb00b0041f93ca5812sf6060719lfr.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432442; cv=pass;
        d=google.com; s=arc-20160816;
        b=CUgqDFwm4F9lV9r9HaeTWs/rqxVf4GbOgTiAGfSna2iC7udHwC/vk2ttuBTOv6yzY4
         6qG0IPHd0j6ot+FrUaXojZMklezwGkVsNEfl5aa808aD0wksIRsZi1YBrkh+Rsfx7ZXV
         uztbbYb2v7IvS0CH20us085hUyLMlmhxVV+8zZGanhK+XZSQoFvhUO0JtHqyzCik6c1j
         0X+qYhJjOaiX4fwC0ufrvScTw7XgN1wNMC2lvDS3hXzbXJjiQUWD93zj4bKO1OzN9quP
         2irmqG57VAdtccBDXtilEEqVwWdNpi2WhmKxWVEGH3bosK1bPAwXaKwgfQkNBuWG0VYu
         5ftw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ks02A31QuJ44hDEnZxYgDXAbE6eKtFfWNm7sQLy7i+o=;
        b=NoTqVJZDJ1T9M/N/LoHW2diMESgn2lUJluam/gNT1iXEHdWLsRdT/yRbGjBn5Cw0X2
         CLkFm4PrOO8+d2AgfM2kv9jLZFzGxzyF1h0/Kc/PCBmoyxykmBSnT/rW5RntNEzkVSBw
         8ydMl/pv2/0I+7Q911rtqotuTF0O/OtiPGSkZi/K8VgzSvf0crh5eCoPrUI2xPxRGJPk
         jMALdfETWqr9eVQztJ2nLZYGbQHPxBW6+Q12KRjkniugKGgZzkmJP3RaGivYL9FRKteL
         r1qdL7xmX2CzrU2RMAhdLZep4zBhnB4AjtODZy8ur38bcKvQQuJsXm2UO5OTmvNE2qLO
         dJGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hfcejgai;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ks02A31QuJ44hDEnZxYgDXAbE6eKtFfWNm7sQLy7i+o=;
        b=D7myyNcjgs38zTsaEMhUDQoKUHWSMrHQW9BByrNzMfBgOFknahKfwjkDoQeNDc5Lyj
         sVgG7A+zh0vvK7ZddJueabv26khIT6T0J77An2SRgTbQt5r25ME6VhH8awU+l6WWXlld
         eLGTnHd8xz6gRB9UmjF76Z44jhERW57Ss+zJ/ikBzA6oN+ZUvKrB3MpqFanse5Om7SCP
         qgCT+HhCRqNlvw5L+Ksw3yf+6Mc7Y0HmJ41UVht15BcmX3tPdAROxU4TuIYZ4eprXhS6
         Dhe34rJSAzI4DqwYY8/Fe/8p/bzLNXDwmhWsaLcj4wkzBF0TW+RM4Z9REBqDP5kx2DlB
         x1VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ks02A31QuJ44hDEnZxYgDXAbE6eKtFfWNm7sQLy7i+o=;
        b=hwnfDTK7s1JbnmUxERwcvSA39Rs/f/vKzvKyvOX4Z4s/y64VbiD0sSR5M7eDx2UMQG
         xw36m6yka2ibaALiJvIirOhaDYjmH88WANcObIoRPMnrnj/5IoHEyvq+GLLXY31hle7v
         txfEpQPBI7YH8ZhK+RbCv8zRP6NBGHfeVrKow2l/sQms/3RCuVGFJH50K9ZF0ldHeQCk
         dWCEDLWZhPRnJqfIe4/F9jblnD6TXlEBZQZVyy1fWCP9aeVEZLN4+c8H3X7a/X9rtOPL
         BodsB2FhcytWZnmvwEDSEySre8gmDRkJCCWuzz3kTwV3D4GEqNogSKPLY484fpmdP5Fi
         jpzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/lngF7bqj8SZcc/iArpwVMu4X4w4YP6jAumwzX9HlNcVTLYyi
	H6FQcR8gafcJH2tMWZy2Fmk=
X-Google-Smtp-Source: ABdhPJzIYO8BjZ4hgdpzlR+NpG7aiLl6PIzBU94wA+Vfnbo1zvKNJcLSoufBMVCB6qToG8kPwwfzmw==
X-Received: by 2002:a2e:a4b6:: with SMTP id g22mr1032022ljm.447.1639432442156;
        Mon, 13 Dec 2021 13:54:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls2715364lji.1.gmail; Mon, 13 Dec
 2021 13:54:01 -0800 (PST)
X-Received: by 2002:a2e:9b07:: with SMTP id u7mr1173115lji.200.1639432441322;
        Mon, 13 Dec 2021 13:54:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432441; cv=none;
        d=google.com; s=arc-20160816;
        b=Q8IkzY0EpOHKc5RsJqaViDAVHU6JOxG2aCsEEWXLcBEE1zfPI6hVhQg7mK6iJOk+ev
         xDfthlXq4cZLUa+LTtwskv0ZZZrBEHgeOuXjO9xJTVvl10+decJg16c8FdVbyy2FIkSi
         GIymWuF/JbqA12QE8XjMNT0yaF9RaruRGC294Icwzq2AHoXqZGX5A0dIVHLGUAmqY4Gg
         7HemUJyTQX6mu9b2iER3WCI/HZypLYgxFSEWZXThB6/EoLyfFDXFqdYt09Uk59pYU5SX
         tHTfr1NRUSUgJwO+1LZSUMcw4cSWeopDwV3Hq2s8yChFpTlARGVOCbptZUrbeARaa0nI
         /0dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ei8kdZ5sQSvooSj5JSSxP/TjdwvJrbBJ/NUBpnrkl04=;
        b=Wi6dz0e2JRnTuUjG8v9ZSPzJ1aUXazuUBoxaXDNnNsrM0Zh8QU6KoRnbX4/yjtKgXi
         9CeggGb8qVHj6S3CeqnldOH4gHHW0baHJumMHIISH9CdhEhK5RXMYFmOFQF0ZWG6vRm6
         3YO12v2mfaVbze1q4y1ih8WO29eSzCVmfVUDLp2AUzW7plylFLw3FiWFCmDdo/rksSr8
         3lGhm6ms4QhaXXhycMx2MVl5R7FpwZ13S9WJFfC88GW7RIcHaXjXPeZphkLDxZncyJWr
         UFuulwaLtJuIBqVj1kUkRHDWPYM1+d/MwVmTfK/I4ui+VJrhXmfnW520tc8a4Mzmuo8T
         AJPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hfcejgai;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id g21si810668lfv.11.2021.12.13.13.54.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 20/38] kasan: add wrappers for vmalloc hooks
Date: Mon, 13 Dec 2021 22:53:10 +0100
Message-Id: <7d99d96f1aa2bda4858dd573387fd93bcac1320d.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hfcejgai;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 46a63374c86f..da320069e7cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,8 +424,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index bf7ab62fbfb9..39d0b32ebf70 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7d99d96f1aa2bda4858dd573387fd93bcac1320d.1639432170.git.andreyknvl%40google.com.
