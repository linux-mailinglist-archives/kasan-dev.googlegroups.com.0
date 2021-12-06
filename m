Return-Path: <kasan-dev+bncBAABBQUIXKGQMGQEFOF2D7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 55D4946AAA7
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:35 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id t9-20020a056512068900b00417ba105469sf4374354lfe.4
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827075; cv=pass;
        d=google.com; s=arc-20160816;
        b=FRbZzBOGj7g2XfTkByznOct0aFabM/CwmwYZYX9DMmuWFCE/z9AshEgc6afA9TkQIY
         xG9kdASneTy7wKSCQSuLFbOTs5YcbTxe3vvt7tR+R/1xOJQNNGR+Pu48p9ENxtwYH4xa
         EEAia0wDs0MYzjX+tVRHGrbbSXzbvZhC5WZWAmokeIfG12hu/m//8wGIlyJcvgJmCeRx
         s9oAbUOARjWUQK+EMFERijfVXyIrdH/Xp/Mhw1b3IBDf1oMi6Y+zmD6VSudO/PmlvQQm
         eP3xsHWCi1gVKsTr2baZ1sw1SYx+muo2FBvx3gDObGaVwPKOPNk+KUfbkqbEwRF+nTYR
         Ln0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bo9g1D2VpB9ZMgOaHoBtnnL9DOX3U3IV6e00ykohpwA=;
        b=JUEL0FtKowTgLmIIYG80nbz5SGwy2OTfCl7B6Z93jmFfRKHre4VNIuC7ioZUQNZyS0
         AqGJr7cm2oiH/chg9dTncMXCii1s8aPQhk8ygTSjCu2myf77sEmjPahUtcmxF51jEw7X
         aBqdD3GjkueqdRrbBITO8kKRD8uku7u95Et/p4YY8HLaL7eR1y+BP2Fm3NwL8U2il4gq
         2404Yvz0RBK9k7u19ZFVuAQ3wF4cyEUMpLbRgnlLPolFUyOqzv5lKjK/idpKLdG/384L
         Nd/qocYoFVGTLI/Wi7Lf4T/qeVRc7YjjjCTH6j9nl9y+RSVtcu/aDnNMtCtjYd8PUhKl
         kx1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TD3DS7kX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bo9g1D2VpB9ZMgOaHoBtnnL9DOX3U3IV6e00ykohpwA=;
        b=Qx0Zwp62BY4Ly1QRmnDjDZbLn/kcjaoVo1Ip5H6lv0Sw8PIqnHyn3w0GtkFh3uNYP7
         molY1YIHQGFI0mq/OrYoO32rr/qbSmyyUACv2ZpZrOjm/2oj2GK9iz7ZXKjHDyPLfN90
         igleE78/Uz7VCxH2eHKrPp6KutX0MMv8euYBof241XCjYdg6IHfaInIIQMu9YVCp47VL
         kh/nJ3YWkt7t4qzMb/qQ0p6TwDalNkaCe/icOyhX3CqQIt8UCyUlSCkpZiQkdBaNL94+
         tTjQl9CAQZn9jlvO+MFoc9TLYpASbjQeqw74sWc4ruOkoiYQlpyA9MNcKRwUZbpytrUk
         lRSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bo9g1D2VpB9ZMgOaHoBtnnL9DOX3U3IV6e00ykohpwA=;
        b=LDhhhMwol80/fzFXSQ7GiqT6NQz8KC5ss1lTGSxseRx0ZfycdI3Q7Ng8Mi5L0nXkS1
         FrDt7SVcSO//8azprGSW64xZyec7j/61HGa39eBw37uKX+67i9If+ZzFZzY50c/81vl9
         j+cPAkjWvvZeQG73XFIvRqmBr1NaNGcEsH5fFkqZ8rUYhiRHuROx5nuf39YjcQGg0vVc
         /8PM+27f/FjZsUK1Yrim4Ky+VSUy9JqUtc1qyH9oOrwfHs1Lgwr0nc9N3ovlzv3r/tm6
         n1kixk9Kmen+1vDDzvRq/I+9NogulTeW8jwZdvYz4hapPq3ER1i1BdPiomG5RMI8bqC7
         UnBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532njqYpXgr3m4LLcpD1jZFCUKT7NK3Pd9DmRTEc44rMlLLjDCbx
	oKUPgNeGlMYOdhAdocGBfhA=
X-Google-Smtp-Source: ABdhPJytA+zraZLwTzZiYw52l45MPsDqjNUHoM0APG03BrwjMWpJqvbYXfebc660Iw929kmx7e1BRA==
X-Received: by 2002:ac2:442c:: with SMTP id w12mr37831537lfl.554.1638827074932;
        Mon, 06 Dec 2021 13:44:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1924649lfv.1.gmail; Mon,
 06 Dec 2021 13:44:34 -0800 (PST)
X-Received: by 2002:a05:6512:1151:: with SMTP id m17mr38124777lfg.414.1638827074077;
        Mon, 06 Dec 2021 13:44:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827074; cv=none;
        d=google.com; s=arc-20160816;
        b=bIlC+7s6uH1er2VKSSfZ+a0U//+GX5DwBCorvrsE/bZVa+4wvqxDaoI2etVrnvugsN
         YdOOqbnKRnkXUesMlxZbvH64dAl37mb2maAFeySK4ygWqCymwvrSOtgH5zBGc2suDx/f
         SqXuTUWyxRHf+4a/mwGtWPv6ze+8BRmzc7sfwGncZ8G2yrmwLPSgMD/G5Yim11NPxJLG
         aG7DhRnDT0JoIOtam8COdWc1WFf4IHjHdhj12ZxMLQ7b9WwNzDqdcD9thrm3bnEwUysF
         iB8yYQAsgBCe7dObCUO6QgUfY78Ah/eyWd6NZg2Vst68S+2L9mgJBUsByZk7sX1bI8sj
         6qvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2VlRNVgjD8s3LiQBttrzG+uL14gJGV2zDjLV32J+vek=;
        b=MEzdJeB53CZXjY2a01XQZZECgkSWqVYx/CQLMIVQ+28maLNbJsqespUJSgRxXj6ruH
         Gd4X0HQ0QoIX0jD+IMiASzfcmOQCFvxP9av4oULlXS7M71MxbfVayD7TeKg2PsK/Pvk/
         v9FSmi+UhwcQAlpnid+4I/YXqcPxWMePZMElKxinlW102KrfOvlBi6M6n64PWfbx8MQQ
         Edjr3F7lZBgJsQk/bJSAMbuDbhv3aYy4gHOyKkIjCIHj93P05IhKT2MmRARSXu+T9wj4
         CZlRPu8l/L6IFL3upR5KlOFM5OEhLFIBxxLakAID4j1e5AV5dUCadDYi93vrQOdQ1zTi
         GZug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TD3DS7kX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id h12si810406lfv.4.2021.12.06.13.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 07/34] mm: clarify __GFP_ZEROTAGS comment
Date: Mon,  6 Dec 2021 22:43:44 +0100
Message-Id: <a2b2528f6d96fbc6a0c68f16e7212f80f3ef1505.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TD3DS7kX;       spf=pass
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

__GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
allocation, it's possible to set memory tags at the same time with little
performance impact.

Clarify this intention of __GFP_ZEROTAGS in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index b976c4177299..dddd7597689f 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -232,8 +232,8 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2b2528f6d96fbc6a0c68f16e7212f80f3ef1505.1638825394.git.andreyknvl%40google.com.
