Return-Path: <kasan-dev+bncBAABBIGWXOHQMGQE2AKMPHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A64F94987DF
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:08:32 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id en7-20020a056402528700b00404aba0a6ffsf12397006edb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:08:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047712; cv=pass;
        d=google.com; s=arc-20160816;
        b=P+nBjI8BXisyCIkdLdijPcm7xGZ0CpycYEhiAHUkbtoTdOxePFmfEkTkxudM43i+sB
         NBcmYBBrbmDe6CKCICWZ6hM4+AP8a6+a9diw+EfWJwH+x9zsaAf3GgDQnj0NdxvzFYMe
         UA+ALviA9bsgEsTSSCiZWC0/OU5Bn3M7r4CMM5sZN8cS9zpgrvpy47u0mL0q1lk6dPZT
         u9PAN/unwSEp+rXeZb8fFhq93qsrjhjDADZG/2sJgUzno/wH0QzVxFYFZuWS3d/77qX5
         22iF+Ml7oZPylstEUzC7jznRydPNaLK0P7xNy9oA1oHsIYC4fPM1IMPT0Uqx137R/0L4
         aycg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JZABY2gehBC8ake5rhEwZmHlMZypCjlG/epWkTCQlEM=;
        b=Mjq++ll4EY/kqmW02QCH1QQ2p+dXBYd1kUyMBO8ug1EVdPfj6JhSaNEd5Dmnxmc3MT
         qL7RN2EoBQtkAjPz0Ov+L4ieOvD0/W6EgILDfQBvuKJ6Chwpb9lxl5hMzuQWzuIbWIqW
         jvYraVA3VHohIDg+7BidbL6cVIrUSWpfQz4rBjT+aoGvK/JhOin4p7TPTnYLjsReNTR0
         576zIapO8z8fgP2Hf9KtyZQg4FcZJzCIzWW5qrW0aK8U5BD0QB6B/6egsCAjDXofn7GJ
         Pt1PA0fu6BdqzIQ5F3kWIwZHYyeMyCGfXpD9cvX2zDMMa8lW/xXZjeCGyTzzAc8V/lNK
         yMeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=liPt02iR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JZABY2gehBC8ake5rhEwZmHlMZypCjlG/epWkTCQlEM=;
        b=ad6JlLhsobo8l2dlEmeo6pA7N2KYtWaS+vIReGRm+PQskZTlcg65QdXPG77xneCpUI
         vY92tcqB4LOiE1RM7u04Kje0lPuDrcppZcJ+pOQQHz+OHmlBMDiytJKfNzgX7SXnrXMp
         pW/BxDRsDTZ52/jniVkQ0ixOdLX5FXu5JgfukV10Wi9k8AIJoNFLq37cE9Hb8oFn5pYf
         A/DAl1EAl//oOEL51vW9UsVCnSoNQarM1D2iTq69aQWQokIbTlYg9MmZveqZIp0DUV03
         JVkbd7LtIg5+MAFOBskSWPOwcsO55++ccx/9/9Gy8WzRZTYpc/1iBmm4lAGaT87N3o4c
         8AaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JZABY2gehBC8ake5rhEwZmHlMZypCjlG/epWkTCQlEM=;
        b=yu4NW3gxQy/sXz5xHqS3f1rWrthCV16oTiOI5dkAkdsdo2L9stZnQFaNW5Qi2N3OIW
         x59/lR0fV9v9ALaSnnRF5oTFByRGSfnTRnCe9AgMg2BHEnhSeDSKf309QxounC1wpD7N
         +KUqWL6Y3LcrLnJaeKry8UKLVnk9/yjV4PkrMqANHThjERFgwpLB0rpHmGwv05Pxa4lX
         jlIfYsvOIFKK6ehvVsr4eFXlt82+jUQuh83pukcjqnAbbweOcwBQl16m2yw3ERuBEymr
         Krt3dN541dCR+/36jhEY8iIdEX13jK0MSjfAi6JH4Pc8Pn08eQ6k3b3vejTF2qi3410G
         uFNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U0+awYxxZ+mbvL4Qm7pXkS06tq5inPOgbSE6VHk6DR2s6Sd3j
	De+L9UGYOJVU+qN6ugSCC+I=
X-Google-Smtp-Source: ABdhPJzFvO9MCRhUg3GO/7z3Z40jZsrmGxuvbsTJgARHcsGi8l7yqlJWw+ce76ipA46lbr92AHnl1g==
X-Received: by 2002:aa7:c6d8:: with SMTP id b24mr17193610eds.72.1643047712382;
        Mon, 24 Jan 2022 10:08:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:204c:: with SMTP id bc12ls5759481edb.2.gmail; Mon,
 24 Jan 2022 10:08:31 -0800 (PST)
X-Received: by 2002:a05:6402:34cb:: with SMTP id w11mr16705603edc.158.1643047711586;
        Mon, 24 Jan 2022 10:08:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047711; cv=none;
        d=google.com; s=arc-20160816;
        b=Pi9Oj4bk4eCY+0kTA9Q5fd4I5DxCsgG88/PFPidiLcfDl+TgDXvHJZEnGQboPiAmkQ
         vbAoewLKadxxakU0SnZuTUt3jtxIFKmtpf9K3yVpb2438NSR+LkK0GWECPSdKnLwnxkk
         dE9nszXXG9ahULMKpoEO+jKUd+bvxEeqX9Z1KfpKeqh2CISgTPJng/eNXLDu49AvIeAU
         ibHYclO0Q07Jjxm80m21pcY+/CBjhY/JYBSCav1K2vCOV534Dpu4m3xM+14TX5a0aQcU
         +J15jkx3qycao77eBlb5a9M95GNOh1qpR5uNrjuq8tD/OajwtGHaSCYA3rOGeCC6tO2V
         XCpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XC1+Aytkcqzf1ileaTyJqJ/4yyuLy4mtp9hx3Zvq9co=;
        b=YBUh1Rp+ZildP5JRRe3eJKA/rPFeE4k+7GVqkyJ/gDXQo2cke+d2+VRvK+91GXH+5h
         LNzmTHkNzUZeUmthECovc+mk1pqblWnA7ntEBS7pxRtH9sx+NN4L8igq/8YXnPNvL86x
         LUqznasKvk0VayN5GfmowLocAGCmTTqgao2rqna2ae07eRcyKK4NNGZcSyUMq+Rslff6
         eBG3PlI0A0bHQMb9lk/vB8jPWxGnGKszgolxT8DJHOrS3XqrhE+Wn+VEhjZQV/af/es1
         RPEm6n4SKw3fi546bk6u3mNFnCiEgyKvNIzvQjnZEeXF2GSppndxALzmG9ld6GxabSyf
         XVTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=liPt02iR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id f18si551385edf.3.2022.01.24.10.08.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:08:31 -0800 (PST)
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
Subject: [PATCH v6 36/39] kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
Date: Mon, 24 Jan 2022 19:05:10 +0100
Message-Id: <bfa0fdedfe25f65e5caa4e410f074ddbac7a0b59.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=liPt02iR;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfa0fdedfe25f65e5caa4e410f074ddbac7a0b59.1643047180.git.andreyknvl%40google.com.
