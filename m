Return-Path: <kasan-dev+bncBAABBZEC36GQMGQEWHU7APA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B9947370A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:48 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m2-20020a056512014200b0041042b64791sf8076465lfo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432548; cv=pass;
        d=google.com; s=arc-20160816;
        b=r6s7zWJCw4G/9mKZXVUhTURyzWpWGW9v7qFD89z2zKYeI971/a44D5FovczWRPQHdg
         2kzIN7gfAopPbc0hVETYGeDqBh3gZ8LjLVZfru4nDxeCEsO4NCDYv7McnaDt3Am+QO55
         ZtFUeo9k06eKVgr7h2WLFs8culf5Tm8ZiFPRGx3nxT7Rp+Mr661aMjThXzvZe/6pliK/
         jQzh90RAc9L0/JGz30YM97luX2dzM7XDYd9nZDvcGKx5RlJXlrre6mnj3VWeZ6XnoJGJ
         +M3fozuqBiSlZ1YEZehA/QA/8w65e8jUbj03yeGYGKwX+tvQZo3evnTnxxVQ3sMiSuTn
         lcoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Fmn2SmielTyn8f2Not8eTjvjjlxq7VsvuVAQ/FnRYZo=;
        b=bUsNFoTTo+QUdpAAOZ1NTd5XeuuBP1mfsonNBPj+xarfwva40LFQZgJ2trarzIUVXO
         bZhkMjiwTdm805nGczlosZ5zdSXyrBHUUfx5gitNzwQn5nsoFOaA82GxjQMdV1sUAPuw
         fpuUA8kfaqMicTYrwfRuzUCLUBpe1Xx/o6jLZk65B004jSSElRw5m0QNFdsKdO8QbIZy
         nNPQ6X9OBgMN3Et4BUP1tNDYaojx91DrwSFBKzYqfPSBbSc8GRxjU7RGf6/dUIze0WeK
         oxaYQ528R1qhq5x7aUwLmQX847eLlykm7GHkN0YmskqIxOeZNFJib57/++hlvEX87zya
         tBRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=obiHIW5B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fmn2SmielTyn8f2Not8eTjvjjlxq7VsvuVAQ/FnRYZo=;
        b=Bml7nEdbeR0UgmAeJnlDH0AxpWNFKfBZysFRNT75fA6+BzFfh5yYRhwr3EONerTyQs
         /TbrE21P2lwoODTUB2ljEgMdVNE1vG8/I+ICkq4OnYPdiZITAOKLNwBdvPS1u2SD1Q/D
         ubffHkLtsMryUaujgfC+z699Nq7j8XH79QhedbLUmf7IBWUILiV/CbwS3jh0MiK1qVnv
         2g2p0rOpRmbxkBdrGr3V1C85du3KI/52kgBheV2rliySIVLGdgJsu+hqEHiQHs2WmSse
         7Np3dcL+f5wAd0cW0zVOXtskUUQkGiRvCNBT3TkwNW8tbTks3aPkw0JyS++jHePlrCvX
         263A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fmn2SmielTyn8f2Not8eTjvjjlxq7VsvuVAQ/FnRYZo=;
        b=p2E8Q92uMhi6Ir9QvrdF6Us5DNpI+ldvSQcPNlzR41bDYEp2vnEyWv0AHDcsSp+/5U
         OPS0Ng/sc20m+1S0Vld3TCi62xYd+3xSMI1oP7i6uoiTGu0xVEElE/F8LO5AfMYoljaz
         IxtouR6wk6gb8BP1y3eFWkiF16f3v/IIr/E/Bf4UrBCa1Cm4O6mDMJ/eUEGA+vJFMtaY
         8GpmA8b66SI6ag6QANlbB/JuOguNFO4RN9KgvKDzZIyjmInc45ZwlAsjirRzNqCg8Lwa
         bxEN5LDs7YD7O1sHbbnSI/h6zJ8DtkQt1zdrbxDj+6ze5dUvk1v+SBaFN4TYea1npTEl
         0eJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UTqFEzfkorQ+xudRiH3nzMNzDRBeVcsTvDMoqvWCPwyn8bEh4
	pCgTtQHkRBj0sg1N/Z8KBqE=
X-Google-Smtp-Source: ABdhPJyUXpV5Hx2iyPGbBXXM6z4FO/C0JHKfcjO+1HAaSbBHZmUD3hMjeBkUJ5Gl8OZ+aoIibieRXQ==
X-Received: by 2002:ac2:44c3:: with SMTP id d3mr956518lfm.610.1639432548311;
        Mon, 13 Dec 2021 13:55:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1554477lfv.1.gmail; Mon,
 13 Dec 2021 13:55:47 -0800 (PST)
X-Received: by 2002:a19:6752:: with SMTP id e18mr914637lfj.195.1639432547620;
        Mon, 13 Dec 2021 13:55:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432547; cv=none;
        d=google.com; s=arc-20160816;
        b=j1V/TPK3UVL9n/Qv6r/5+DVc3UqvoRea5rPj0DU467ZiuXUFwnXyZwiwBrQyAIgvwB
         NkznrRpcq6zQoa3o9p081uFRC5HqbJmcXxWEsJ0ZVWMI128t2Lz4uWJgmW2h3gtiBAnh
         cYjHA22VNU3tILY1PlCAkRVd4jxXE4qtEr9Bp9b5F3ZIQfiYwm667ZFURhAyUuuCFjPh
         A47AU25TuBhmYdYOnK0uXz7auc0PjIqmv4MvszRsX99niBSTExjlCLn3xCFmivvxEqrb
         TH8+6DLYx0fPiUyHL0+sOU0r8tSDPUViTQWuvOZScvIEtaS0dIcUAW9OKSmZTeB69ewq
         I4GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XC1+Aytkcqzf1ileaTyJqJ/4yyuLy4mtp9hx3Zvq9co=;
        b=Dd6QpBdCknIjO40grCeRftuKjyAmMp0R8ltHG0+0TkeQWOZ56458hoA34KGUWuWZdp
         EckNHO7rfs94Gr3SQKcGaHa8sMlTT94gADpfF40WcdKm1SoeqLFplBWuzLi+K9web14Q
         lH1TiG9uWUyZNS/XTRFBDWMLyMhJ2C6QSnEgw/j891Uv76C0QabByaYHoXBa7bBzTSUa
         orTqCnDRQuatBwWqeq/hDkeKONkq1quwnYk+w/lyBGThlm7sbW0gSsRssYlLPF2hllIN
         OrxiUvUXWwshkBpGHjZdAyTtWiviqlm0J1/LlW01wqzKBonsFkVWTU408e1twdzZvZZB
         0Jyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=obiHIW5B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id j13si593743lfu.5.2021.12.13.13.55.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:47 -0800 (PST)
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
Subject: [PATCH mm v3 35/38] kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
Date: Mon, 13 Dec 2021 22:55:37 +0100
Message-Id: <90635a81c52723268a9c9ebc683243dd88e4a4eb.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=obiHIW5B;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/90635a81c52723268a9c9ebc683243dd88e4a4eb.1639432170.git.andreyknvl%40google.com.
