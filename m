Return-Path: <kasan-dev+bncBAABBOWBTKGQMGQEL7JBE5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4273464100
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:54 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id s18-20020ac25c52000000b004016bab6a12sf8575654lfp.21
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310074; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtE3p6IyvD2ketLa/3Qa62x2Lsa0gsQW6gSba8Ygsh95K6T/ARrfooLKaxwxzsVPI5
         cRbsn9ZKksiE4tG75acK1kwvdhaReVhOhBrxc3mL+ciYt/UCmZxpyWKxDCkvcut4nwnZ
         YSDx1dX/PWmsNuUz7o4gKMaAA7OoXAe9ML60DxncvcaYyv3+fuiNg+jjWj3CjJAa+Nng
         0QvrpZ8+WHCAE/89/6icabPI0yAU/cO63DgLJfI/ua6OztIveBlNb0I7nWFhmYLZzRcV
         yZadEiGZ6q/0lnf+Wi2muc/Q4GvLvXlble0FITRkaQaWtN85sxmERYX+ul2c0ulpD/xW
         z0ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qK3W/0atEgjIJJNPwSQ6afH6oCN5MUgpwE+U5SOirCw=;
        b=SOlr6krG2bnjUAYDtYjFIiDKs76HHgmS+SLhcU6Q4GmVql+gVpQF9NzqcW8sua82Zx
         IgJayHtmJnWcGFGX9CU+tcBig/Dg6BPJIQU+FTH+4lEhAAk8rGXMPTGmbZmtCFWSPp5z
         DQliFtkJJnQIAKgCgbI7qXv7iQO0N8Sh4/lQ4zv8yBo1SXQeH9B/ukE/tOdzLfmUHWp7
         VI8olvsALAktijsDy9uqQQj0vZoM+YKMwG8xc1MaYskT/UhGvD6kDzpqSqlOszHxbbSy
         +lNTbX6X6snuavKos3f8cJj5ezFQIKcHEinagm8xCcnvuIFu4wO8t7p11SBXN633+FAJ
         v0yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s1AnY5h2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qK3W/0atEgjIJJNPwSQ6afH6oCN5MUgpwE+U5SOirCw=;
        b=AypEvc+uvVBMVo+VT3PgO4zKV3HnOIBdUPGsrLx+gffLonJptnP5QLvKyC9wqTNqtm
         8vh4yc8MGB/iPUT9EDnNCCaGLotQxth/1Z1cfR7yWJXi5x9RZ7kD4Ws7fEL9KtITWx4d
         jz26tFlCDtQ8AeX7jU2D3zElxG0Xyp/RLTzlPoXOyhb3Uh728k8FpXBstJ4K2j9UmAnl
         z4CiE7JxhLlU2MpGJxVhMIPzRAREjgR7KHaiFRIJD22zvzlnvAiQQG8oQMxBHOr4pJqc
         TnUq7WW4lZ0fdN4jq5kNv+1ErhIZSbtxQrnZ6iHqW0KjRAWgRcWR/+qlH7f3rdu76zcp
         6aFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qK3W/0atEgjIJJNPwSQ6afH6oCN5MUgpwE+U5SOirCw=;
        b=AJgX49jDjlzhvNNoxd1jOr17E3r8emJEhrAp0V0eSA9c8grbo1jb7S07AP9YDSqFmq
         EEDY054/EF5Gio8sQ/QYESj65WLKHWAjboKCKfNDYZ7XAeznb4xOePs9oCryGO6DQplz
         in7GQghZ3+37lXtL3et70CqPUGkQHa2aSCa+Z/CD3vN0CHJy27gLNZsI/U8g6qvqV7I7
         57dDL+GD4lgS6W6RThWW6v+h4a4Poitg6ZHGj2JxxmeFPt0Zedfz7+mqKHLiGkCRIvjR
         wyhRAYWyAtze3/BR/8eWO5Rwg4EoVdJhXCXmLed+EoPV2YRFd3qsgCC8vtVI4RShU+mQ
         ezmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ESCxvOci87aRMZ7xBIp6jXzyLTbHNUusbXdn98r60UV+deR3t
	fxakkuyKYewYs8h0I1XN8fM=
X-Google-Smtp-Source: ABdhPJzgMEpFzPpxMfJhLZU/Puds9RRzzhuQpY1dB1MOsedIg/APHAIL/yvz40L1CdCuYsjZRJz0SA==
X-Received: by 2002:ac2:5615:: with SMTP id v21mr1995186lfd.112.1638310074358;
        Tue, 30 Nov 2021 14:07:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls90109lfv.3.gmail; Tue, 30
 Nov 2021 14:07:53 -0800 (PST)
X-Received: by 2002:a05:6512:33bc:: with SMTP id i28mr1924009lfg.33.1638310073724;
        Tue, 30 Nov 2021 14:07:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310073; cv=none;
        d=google.com; s=arc-20160816;
        b=zM9l8hdX/kdUO/MU9OUsk/CN3iWqLj4U8xxnTuWaUVBiEMwQqiMNX6UBsUsTcOZi2P
         lLkskb+mwGspG1n8KkyX6awAfO+IGqJxWCvVHTtyNoPwAwd8TZfiImeaL7H1BWRXrNqC
         l84CUTYcy3J+fDSxqrJgz9+QbGmyz4vr84NPVLkGuXtrqeKS/lyvDRMWpaJ7mgrcekZJ
         iZAgOHyX00BO8SLPUVk4XCU5PtqdR+NZScilNYao3Yrb+L//9Ikm2oqRCAx4qhOejZ93
         nFavit7JvKsA7wJWyPFf2Y7QHtTjxigfJC630gLPqxm+wse1NxKjITtHOVEUjEmeP57J
         Vg9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IXyg2OmXCwGvEgzJdDkzZ/hs5ydqycKFWdffFjeLykY=;
        b=cA9JRnfY4+JS6Lb1/Pp1ruygv3WmXh5+S9VYLXd4kQEl+hT7qSyihiLoaZJ6RggJGp
         mbl4kexy15kuIXhK5QUqcM8eHCwExbUNcuWOQ7sK972AxGPx6aqq5PC13KlDk8nxAdC5
         3al6CBJbU+NM1264O6E+B58IKnzQo5USDuz2ro0JaKtQtiW1J7rbgWJghGFgEqd/p1us
         BVGz8v/0sAQRYYDQ/yywJrUGxZqPfQKfMXMZzuwIsr1+XPvHS4jGDL1mhRcAFhwLdz1H
         lv2drRDH2MNZheEXEWz4x+eIqj5K0b79vqiQs+JtxyCsfHtsbZmA1j9ytJuxX8n8oHrI
         82pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s1AnY5h2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id h12si1660504lfv.4.2021.11.30.14.07.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 23/31] kasan, arm64: allow KASAN_VMALLOC with SW_TAGS
Date: Tue, 30 Nov 2021 23:07:51 +0100
Message-Id: <f90dfb0c02598aab3ad1b5b6ea4a4104b14e099d.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=s1AnY5h2;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

vmalloc support for SW_TAGS KASAN is now complete.

Allow enabling CONFIG_KASAN_VMALLOC.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/Kconfig | 1 +
 lib/Kconfig.kasan  | 2 +-
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index c4207cf9bb17..c05d7a06276f 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -206,6 +206,7 @@ config ARM64
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
 	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN_SW_TAGS
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cdc842d090db..3f144a87f8a3 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -179,7 +179,7 @@ config KASAN_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
+	depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f90dfb0c02598aab3ad1b5b6ea4a4104b14e099d.1638308023.git.andreyknvl%40google.com.
