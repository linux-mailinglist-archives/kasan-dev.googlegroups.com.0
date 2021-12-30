Return-Path: <kasan-dev+bncBAABBPMLXCHAMGQE5XZQXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8B1481FC3
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:17:17 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf6566831wrc.17
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891837; cv=pass;
        d=google.com; s=arc-20160816;
        b=JNmN0E0/POlfLyi/rYQMCrcxJ0oEin4h1zcHSG6jlx/XU9HNE9+cy/51QQPgn/pqa0
         nnBd2Yk3QlMLO01UFAQ+oL1J7WEN6MWIpPJqpqkdt+XxbP3Dgxe29trx1zfedrD3HNGr
         C8QUmMQ41VriTAdlrZJOdIMRjzUOlf1RC7k6R/mcudbrMIq7aqXwzAmRu5wANO6UrEKq
         8LbafnOatMxLSffFEgTVcR31lwwcbdd34nxOezPHfHhEj2RsGaSwpSI/8hSI2X9Q1bpD
         tHoCdfJMNhl3rGp2wo/N7PbkTGKf0PE3MwyclcmC3AJNduDK4OGtdYptor5t88T1DvZK
         fjhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EUF42zSvx8IQYSAG3Rpwip9z7NrO0jcCgEES/eJ0nnU=;
        b=uAlNe49MnIjhX7HfIpx3+vXb8n3mF5ACsXAjAh9negpSApp+G34tZeojexJgQUKynG
         O41FwI9XtdbWVMiTr0OQ8L2cYJAvJhIusrQzOSjEMQx+xVzopg+YcdPPOv7p6IDzVX0z
         g8BkEOya8bD8Glj27DJ+8jE0FK3ngGM75gpScjXuCAM3x2ZBLzOYBMODUAH6xroyIrUX
         V/NJV17aHj0B9xY3CJukNGVwyZVII40m6qoqsBMRXtQmWV3i9wU/mnqK5c+UXXHXk/nv
         OVuL4wPAkWjWYGpJb+jkhpETbmSq1RcxKmokv/0wsCeeljdodNRws6iudK57P1rCzKRF
         ZSEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HKWSHEkq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUF42zSvx8IQYSAG3Rpwip9z7NrO0jcCgEES/eJ0nnU=;
        b=e1CEXbv95N+KkglaksDNw2yDWLlCjyAYa0lQylEqMPmmb4C1tAdkzEiMkFeu/kIL/X
         Ifa8lXSLmO/RGXO7CrWbTnDPMqcsUNPKLVIsoLRRmQrNK9yk3CNJk5Iz3lMbcbaEkHj5
         2y7B1o4Taf5MueISfbIvG1939s8luufU3MwFrg4Q2lBTixR0qY80+NDMYgs5hbgcaBP9
         mtNwssRn7CiIOqYYvCuacRyPdEXceW8HDknE4Fngm1dLVMnkljeW2Z+dfHjpYkKBwVBP
         DyG4FbxZQ6VI0MM2LEIsDfxP2a3Kska1iMoW9cxih0X6TSIB9IjQLayJC28q9YR3nkNo
         MOyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUF42zSvx8IQYSAG3Rpwip9z7NrO0jcCgEES/eJ0nnU=;
        b=riepKt6TVhR7QuCgiG+yuIygew/H2sHTXkPkS8BmmHb3uwvPonnTrQqTrxf7w4tgRT
         hMydhwiKfbHM1T/9fq0eqad/DA+WUY2RhQ3xf8gM/zM7x1WOo0FwckXopqS+lCzXH4E0
         oSNoJjramwDEcurDlA83r0NJ+CRsgaXnfgapyKvC/a7Ow0S61HMum3U0BR/iKrDEp5S4
         OqHdeQmXi7IBkGOqEWD0aOKYptVShXAsfmIxW/g/QO/6QiowwCdqrrl+6N/C2lmuYn30
         7hY2qW/I+W7BZZqZHPsK4QzAaUb3UhZAIXvNYJdS2xVcj5CMoLmat/USZ+jLStOfu+fo
         w8Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336MvMDfMqn2vU0xncWdTOyIk8tEoZSJemyfm45kqUkExEfaMF4
	Z6zg5BtRcmu30j89z9h52yA=
X-Google-Smtp-Source: ABdhPJzXQmWtX62ZZUohOjWHZ2NkvFjgTzBJh7CYgE2AmRTuhVblPixsFUDajQJcIK3Z3+iNxlcNlA==
X-Received: by 2002:a05:600c:5009:: with SMTP id n9mr27366446wmr.162.1640891837497;
        Thu, 30 Dec 2021 11:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls308523wra.0.gmail; Thu, 30 Dec
 2021 11:17:16 -0800 (PST)
X-Received: by 2002:a5d:50c2:: with SMTP id f2mr26230312wrt.459.1640891836775;
        Thu, 30 Dec 2021 11:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891836; cv=none;
        d=google.com; s=arc-20160816;
        b=Jhq82gHPSpZ+JqwgFZw+OxJ2t5fRGa5KfloAGkjxfXByQyXo6brba77RdhOC0a6Kv+
         ZOnvC0DrAFXtHQxFJKKfXJ3+1a7pncrH6nXKkT1VYyRViswE04c//2FmI2N348BESN1w
         UbwmGEdpXl8JMr378rr4RnRjaipvcAsGe8iOlJHSvUKgUiTW+y6J0g00u0pXelfOHAfX
         FhMjdfTBCgXvgi/aMjNmKX+l5IPcL4b4q5DDNe/h9rQ8y54miNuGhVrbgsOT7fQoi5lX
         oFfTvd/UiLfoijT2J0Mf1ON1WWbko3pZCl1B2tTYDqQOvfMdMSvhuQ5pyJ5wSg9S87Bb
         Jy3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XC1+Aytkcqzf1ileaTyJqJ/4yyuLy4mtp9hx3Zvq9co=;
        b=Omb2gxc8T/meILb26ISgnfed+s5ia2TCXIfOsuBNs56jNO1ovPTwhG/bg570EpNIY4
         m0bWCud/bAx391EQ+G17CejGdJfmdHNpzFTaXr7y4WxwP32To3D0ujiQSXLjnaf50AoO
         hGhvfgf1+3fzxkeIQQWNt8bGXADwkGZp7kxFWDJiExRFRk9Pet/O1/lQJUfDcCmlxwIi
         paUjb3bl0HHC5PC0uSxY3xUC++dQETLUBujQkjCxOUWogdSxfAJv0GdPmAn68dUKPPG8
         SLplv7t4vNFZxVovenOoPN7sdt0F1DOijeYbbC3mYolO20dZUvh1zwVsYJy3rWgHF7gS
         +nxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HKWSHEkq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id e5si141755wrj.8.2021.12.30.11.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 36/39] kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
Date: Thu, 30 Dec 2021 20:17:11 +0100
Message-Id: <f863f9d1e78c1ca3924db0d8a36a19b8e06f57e6.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HKWSHEkq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Allow enabling CONFIG_KASAN_VMALLOC with SW_TAGS and HW_TAGS KASAN
modes.

Also adjust CONFIG_KASAN_VMALLOC description:

- Mention HW_TAGS support.
- Remove unneeded internal details: they have no place in Kconfig
  description and are already explained in the documentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 879757b6dd14..1f3e620188a2 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -178,17 +178,17 @@ config KASAN_TAGS_IDENTIFY
 	  memory consumption.
 
 config KASAN_VMALLOC
-	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
+	bool "Check accesses to vmalloc allocations"
+	depends on HAVE_ARCH_KASAN_VMALLOC
 	help
-	  By default, the shadow region for vmalloc space is the read-only
-	  zero page. This means that KASAN cannot detect errors involving
-	  vmalloc space.
-
-	  Enabling this option will hook in to vmap/vmalloc and back those
-	  mappings with real shadow memory allocated on demand. This allows
-	  for KASAN to detect more sorts of errors (and to support vmapped
-	  stacks), but at the cost of higher memory usage.
+	  This mode makes KASAN check accesses to vmalloc allocations for
+	  validity.
+
+	  With software KASAN modes, checking is done for all types of vmalloc
+	  allocations. Enabling this option leads to higher memory usage.
+
+	  With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
+	  There is no additional memory usage.
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f863f9d1e78c1ca3924db0d8a36a19b8e06f57e6.1640891329.git.andreyknvl%40google.com.
