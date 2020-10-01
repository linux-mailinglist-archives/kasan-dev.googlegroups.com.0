Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHWE3H5QKGQEBCOJ3IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CC1E280B03
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:27 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 13sf46175wmf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593887; cv=pass;
        d=google.com; s=arc-20160816;
        b=1LbreH41MSjgkAPpVzVdeIHrCCcpW+f8cUAVzR60Qxa5QtGeJig9nP0Zj0XKBoDBij
         4aR2hdIB+U16niLx6UGHeRwLr0cOwc4TNbbO1h+zib6S1J5sNGTZ+0+i9UgA0E5IQq+/
         x8mgsS0guDVqpwvZkgnoswiT+ZZyuIwAmpNhNoVODAFV1Y7LzyZZ6NBivwKJ41a39hh9
         ami4cwwvuRvhvAVIpDTIgkTEyhzQtdGnZQT1nIj/jMCkazYHloTkul/OSh4quf2gEmLp
         er2jYDhC8Vd08TH9xvmZ6xaf8AttqggoBqK0kBHjp26BVvUp7gIhVwqqk6Iu8SK+RYDm
         +rfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1lgtIwWXCdFczeyviQtS1onBVCgB0R4u8a63q39eFpw=;
        b=rpPuhV0RnecyZP8kM1TRBUNiIKiWM9TPzYf64sCJh2y9ln+S+0IuBnl+0atMvh2Jr7
         OPs9oHvGicAi6G9TdE6Q0NMThmp5lYfC/kPxwkfRUlxWGroAbprjqszsJwbr0nK0tlU+
         WDJsmYaDErjSc3zq4InAsFHCGTTeb7uFSTITGVE5WCt6nBHttcf1A77BIDUVpgHWNbPM
         Q3W+M2oDLfDlii+pMgHTt+UHa7h+lYK/lR9VXAbHhjFDqqCBAd+qNr23R+IrY57YEw6i
         Wk/lYhiBv85mwG4rigH5GKwJzo4mN+SaFwjKCxiS+PtaDYPRPHwIfOZvAWdJ6L/arYAA
         wvIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kEegrqMj;
       spf=pass (google.com: domain of 3hwj2xwokcbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HWJ2XwoKCbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1lgtIwWXCdFczeyviQtS1onBVCgB0R4u8a63q39eFpw=;
        b=H0x72TlT/Q1z6R4fKsn/NJhXBsFCxUgcrx5rbnwjONojP5jjDx+IHb2XX14ISku4+I
         RptWJ1jkHWInBwIF1urfoeijfgJ4xoLUwSV6+9qw0d2aOmfvP4YsJLDlcRTmW9EyeroS
         IV5m715+1h/TzrDLnvHkDtynpEJaUUrcWo+1xsw+ISf9P7CtaOB6D8JR3t1X803DCAI9
         4vk5dVZi4Smw2dd7Bk3kyRjwXXpDTFjqy6GhK4gytafypFgZq/huMHMUl6tgFRVoM0M9
         wFi8QvW3nni6kCd3CLJDPPEVpquqq2TtTbXm0QMldgKQrRTVQ0yeEYBWKzniKjDp0sfz
         vDEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1lgtIwWXCdFczeyviQtS1onBVCgB0R4u8a63q39eFpw=;
        b=VK4Xiem/JOoxdpLdhVJRiXWBfHfPmexsRPFBgdmln8SCHKIN4e0tB0xo1asXx16NBP
         XwB3c1Toaf44CpGQs3vsrJ8C4Ki/oWdw6dLoh2eLKRQYFdq24a3baZP73qLN7VBsXILI
         ZDTnIPUmE6nryTSANxQcg4gE+Mnkd4PVuGoA6vsD5tNWVIc/CONuzGwBc6AB28H3MBQq
         lL2keRPfBtFrHmkm+wiu+zwLplM/BqJRUFVZQKUxKZirUScc2nErjfjn11dRvpimOqgH
         LT9GXRC7ni1tYY4drdV59pahzRSQkS2qN1UoqfIqtkqqvCATj6MLIJQTxabLO38xfEiy
         LZDA==
X-Gm-Message-State: AOAM5337EoEB7RBy3Wn5N0pdsUQ9hvnPA3UaPBcyLai5i1wOeGLhAuLP
	4AkhknQXWgJXhAGlj+iyLDU=
X-Google-Smtp-Source: ABdhPJyoKwNmkadaTUuL+7G7C/f2ocmFHgiRD8o1rLPks4s+MKAQANMnlFp2EUBwgn9hbIrudsi/IQ==
X-Received: by 2002:adf:f903:: with SMTP id b3mr11821491wrr.142.1601593887123;
        Thu, 01 Oct 2020 16:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls2803351wrq.0.gmail; Thu, 01 Oct
 2020 16:11:26 -0700 (PDT)
X-Received: by 2002:a5d:540e:: with SMTP id g14mr11832454wrv.148.1601593886231;
        Thu, 01 Oct 2020 16:11:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593886; cv=none;
        d=google.com; s=arc-20160816;
        b=HeM4bAJU1iSahaHN18pylLC5zaIVpjHxS/MLp26MJyf1B0wG5twa7ZGcIWybfTGdHv
         REk1w2YXbLo8gk73Q0jBwJ5E+yooLFC2I03sTt+JRS6ip6bE0U64Sr0pIaJS2yMJYNMN
         dIsfJ3KmyD+NocCJ2dKZZlGbWjjglfr5V8OX5y9gS4VgKu8TrqKI6su8dmfveO6GPwSf
         nXzz82uM3pLXnqntlsTryzNg/7KE/W9WuNIim/csqBWTr6guhu8RfQPTq2WCnfxfVl2P
         wevc4EIOkRPb8PvqaqutLajb1NB7kKcUA9Q3q69A6C792ipQGAxNZbyD6qV2FqEScs1K
         5mtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Cbv+CjmfjBTD0ICXD0e117ENri0Oo47gp+rha6sXLiY=;
        b=TXvbVcAXg8qHrRQoxpLi6Hl7zkThd/qs3Db3zXGFvsFDQo5sHI9YQIG9UJ5GIGEZif
         ZuwYMKgrhMmXIDhkwUuOsBf4Z9ZeKiFLjYRXFJXkDcgIdKDgSQ4SdqYZU/B/HO0ShgSK
         zuSZ7gl91VZMm082Nys0NZHSs6ZOm6JKMbg+/gNhVxC2r2Pz2xrZ9uUmvvQ3SmHm6TzD
         T+cPCi/j3xl5nidMmM3rWx6DYZeth6jCO6sfSk2HO25WbltPla0KW7EIaZTE64YjM6Ka
         nGLapPDuTttPEckSAaRp+cMKPqhwuN7suxwatQy46/bifDj3JQj7Ot6ULRHUjMr88X96
         dt2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kEegrqMj;
       spf=pass (google.com: domain of 3hwj2xwokcbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HWJ2XwoKCbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w2si151714wrr.5.2020.10.01.16.11.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hwj2xwokcbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y3so113310wrl.21
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:26 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c14f:: with SMTP id
 z15mr1323wmi.1.1601593885526; Thu, 01 Oct 2020 16:11:25 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:18 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <0786198b08625bef6402ba298930bb26f4a567ee.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 17/39] kasan: rename print_shadow_for_address to print_memory_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kEegrqMj;       spf=pass
 (google.com: domain of 3hwj2xwokcbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HWJ2XwoKCbwcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 145b966f8f4d..9e4d539d62f4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -250,7 +250,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -311,7 +311,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -347,7 +347,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0786198b08625bef6402ba298930bb26f4a567ee.1601593784.git.andreyknvl%40google.com.
