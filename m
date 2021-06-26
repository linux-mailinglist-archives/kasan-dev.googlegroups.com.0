Return-Path: <kasan-dev+bncBDY7XDHKR4OBBZHZ3ODAMGQEBGZIHQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C2C53B4DE4
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 12:09:42 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id ev11-20020a17090aeacbb0290170558d2cbfsf832837pjb.7
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 03:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624702180; cv=pass;
        d=google.com; s=arc-20160816;
        b=kozRYFTq7pLCv0nuPYsGp6ss0EEof0eEZTvz776DTB4yLkG3+cFaU+xTpxb4GRiJBX
         IndTUgG2/kBVxw5m93bbf1BaZvo2SKjCrQIkXQnT5xMRJ9FG9g8wuUyyR4RIMJnQPzRp
         d/SfJx9aS1YBWvZcasa25ceKfF7wKj0k1M75LgJWrQ+nuSz3rQ+NxD/5Xg/hA6NF1soz
         XdZjINlFll8RxJYlSaplwFgxyief3gMCAlUuPTsByXHbpz39MxxpvzuO1zuigUM7d0H8
         uOYy+c7XaFT93f3e4GQFEBxDIeNTz4xkvhHC0dD99f1SP0CM3anF+Nj/oG7oqljg+FO5
         Wv9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p+QdQucHwVqrFxgmsORa4AFH+5V6WF4dEwA1yq622VI=;
        b=LsSEjhery1hK9/99iP8xvzyMmhOq9xOOhntbbXJlQ93zhgsWJpjXn9KcRCyH5+McT3
         QS8bmF2Lx0g8cM9/hd4y7aLrsneEjAq8nGyLKfvR+QqfOYva33EgUK4egQqdFJxG3TFF
         Th2coJ2EDSFApowf6M9uc/pEES7G9IqlqF6XEw54DNX4Y5OIV4zJybtALyIgMJD733E8
         ha7YfX1nHM0yLTfoLSx+UHSOHC9B1pPrJ0nEiLhcOCVNlpeGGQZ24o2aJT8Wamcl3yIn
         p7fBAHFK4CWbM4J+pyAczDFCY6IRliUvu+l2gxCqj6IZfuQSAxFZ8GeJ0uEgi5Y8hMoV
         Xv3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p+QdQucHwVqrFxgmsORa4AFH+5V6WF4dEwA1yq622VI=;
        b=U9qgvct2tK1F756MEDvwZ2Y5+pvBbIpy5zkcfKiAz51fsJqLixUSukUJWQ5OulzBEK
         JzwOFqBZFge0ddEJtNWsVKQq9Q5IBqGYRT2rTnvaDSc2XztLuu62rmRPXmpCP0NPSZWG
         v8W8khBgI14Y/6fvVZvb/iXSllyy2m5fZTJyXNv+dz0BUTV2YrWgrVfA/Y3OVLj7i1xi
         j3h9X26oMRmhwYJs6E62nQ2FCCEBdGfCy1qQmV9zr4ryUnb3HAXcSr96jrF5v7npWnMD
         VPItltnKhZZLkj3PDA2coStbvuchwxFYdvywVc/ehRFUv1AJEaRC1wHvXA9aUQhH7Ti5
         riyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p+QdQucHwVqrFxgmsORa4AFH+5V6WF4dEwA1yq622VI=;
        b=oqkCct1D+pvakJFlH3S64x2qWJ3gJGb7USkSWZDJ7O6OraHhWu4rb231m4iCJHIEkj
         FaqT0HjhffXtIx1PMKhUPoJ1pxv7R9TOdsqWm/hWnzJkyVaYBFTeeqhglVxaM8zFKtd5
         +CT7fzVVZEjPIPUGxLtHIvtPhzldCa2+WDu3W9f+Q/HT6CHCzSUho78xieQJN2v79SV3
         C0eW9mtfisrUx/XBedYbi6XBW4sw/PSJ8nJiNberoxGzeO8Tc6k6qhDZKDG92/XWlYoB
         yHGI/++sCSdVzj7ap1h/NyDn1TKGbU2vbmncw/aYG+Oi0b12jxEOxklY0e809VhTc1iN
         tqDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GXGYV2mzRDEtZRVzI6aKkCVypTfns2XqIsxaH5V+OzC+M2mw2
	Y3hsdzxqqxlACe+EWKjIZOU=
X-Google-Smtp-Source: ABdhPJwkCG1Uhp2NIWYHaZkdLS+yFw72sHscODxazLH4wIKIFe/r/VrzXO1IV9B3Mj/FGUsLN9vMLg==
X-Received: by 2002:a17:90b:4d8b:: with SMTP id oj11mr19805022pjb.146.1624702180645;
        Sat, 26 Jun 2021 03:09:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1943:: with SMTP id 3ls5799214pgz.8.gmail; Sat, 26 Jun
 2021 03:09:40 -0700 (PDT)
X-Received: by 2002:a63:755:: with SMTP id 82mr13612723pgh.209.1624702180020;
        Sat, 26 Jun 2021 03:09:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624702180; cv=none;
        d=google.com; s=arc-20160816;
        b=H8Rt0ajONnJwKhqcLEwATzPdaCm0pcbUt38GXeo7sXd3NdhS9csOKOQyGchiupJ2/H
         BWvfa6wXfD4OhfaAESdSrkRQdP3scPeFwPaQZp/s5gbect7w0DLVrUi7E9Sr7ADf5yiJ
         0S313B9cv2ttxHEr/L4rlh9y74/Na3fmIB/6Xg2/dTXJzqkv/mvBo3IYi2MxJUyGOed1
         k+R/Er4U3drhuJGqzqJqUU1m00UwgwVpuwqF0YNKGIP4csu7rLS8C4jzt3D7+367FsAN
         JNEQkDvhkpBFhiEWohsBEIs+aKtTeK5Zc6K3VYpnq1wePra1MvWAACl8KV2Hx3+fPXNr
         S+wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=jHJuQpSWKW8gtfeqOlelyRBRwae2YLD4g3dAcKtMdsE=;
        b=pIG37sZKefHQBugnquLUltlJggInfQLybO0fGroM9q81/rnQsjioIcsstWVwxDj8j1
         Tx1SdbSCp0cCSnPtjpWce5aSoWrJXwlaiKWgfWevMGxtPf6gXV7J7ZMJ7wAqn0ce8dE5
         ULFOn6vEN3kjW2e8lVb21jnaYR/WBu3XkAQWn4dV6KKAi5sMEpMe6tA7rYajErze48WO
         IS7DKlLKzNDCw1i+LdMlFfOBBXvMM0VG2TzTHZ9LLM/koMskr+ZZWwv+pkR/ZAHpJLup
         KCf44k0kCcXdHoC2vATM67DwDmnNhfqZNvdD2naXZSESdTGfV4hAHhwsok5GyGF/nUhy
         goxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id b18si592888pfl.1.2021.06.26.03.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jun 2021 03:09:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 18061d37e5004212a9df52c84f059005-20210626
X-UUID: 18061d37e5004212a9df52c84f059005-20210626
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2029163543; Sat, 26 Jun 2021 18:09:36 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 26 Jun 2021 18:09:35 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 26 Jun 2021 18:09:35 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v4 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
Date: Sat, 26 Jun 2021 18:09:29 +0800
Message-ID: <20210626100931.22794-2-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

This patch renames CONFIG_KASAN_SW_TAGS_IDENTIFY to
CONFIG_KASAN_TAGS_IDENTIFY in order to be compatible
with hardware tag-based mode.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/Kconfig.kasan         | 2 +-
 mm/kasan/kasan.h          | 4 ++--
 mm/kasan/report_sw_tags.c | 2 +-
 mm/kasan/sw_tags.c        | 4 ++--
 4 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index c3b228828a80..fdb4a08dba83 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -167,7 +167,7 @@ config KASAN_STACK
 	  instrumentation is also disabled as it adds inline-style
 	  instrumentation that is run unconditionally.
 
-config KASAN_SW_TAGS_IDENTIFY
+config KASAN_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
 	depends on KASAN_SW_TAGS
 	help
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7b45b17a8106..952df2db7fdd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
@@ -170,7 +170,7 @@ struct kasan_alloc_meta {
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
 #endif
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
 #endif
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 3d20d3451d9e..821a14a19a92 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -31,7 +31,7 @@
 
 const char *kasan_get_bug_type(struct kasan_access_info *info)
 {
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
 	struct page *page;
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 9362938abbfa..dd05e6c801fa 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -177,7 +177,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	if (!alloc_meta)
 		return;
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
 	alloc_meta->free_pointer_tag[idx] = tag;
 	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
@@ -196,7 +196,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	if (!alloc_meta)
 		return NULL;
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
 		if (alloc_meta->free_pointer_tag[i] == tag)
 			break;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-2-Kuan-Ying.Lee%40mediatek.com.
