Return-Path: <kasan-dev+bncBDY7XDHKR4OBBCWMX6FQMGQE5G5KQYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C256443484A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 11:48:59 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id c65-20020a251c44000000b005ba81fe4944sf29709775ybc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 02:48:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634723338; cv=pass;
        d=google.com; s=arc-20160816;
        b=Opjy2kWiGuzM0WYJSar7lQtW7m52aPtSiOTI1zrNvCxQmVE7rOxDNr5f54Bm+gxyHx
         k6WbtvoSBLvhBY15oH5Fh2j57BFQ2u1vvpB3Z3hwmwKmIRuwusJZ8T5KT4Yn62HyTH7C
         9V3OeDjdZvEhoch0vfTI/GXPLD3c6d1RS4f2PiAmz5SLsJ2HcN0rcBOATb6wxSWPUobF
         F6C67VgNUOzlcapZ14YSl938LZAR4ELjptiG9FEIdFt+swHTPEA24/OQtd6VA2DIPVpY
         8InW1OGmbyR/O51QvG+hNcn5X/L7KWkl58l0gMfJbOZLnYF1eehKoTdO3h2K9GBtAakj
         Xy7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7e5AdWNQsZ8txvrftzv8/ZF7JorH/x7iC5HDKKLYfpY=;
        b=q5g6jxNSIaiYGquALNfeA4QILDp3OsoAK9a4YfinPeBysESM9AAncaBSPbOTRJcTkJ
         h7mvGj6BdkDtfJFkM1zaTz0+0RDI/i2/O6Okwe2FSh/37gMLpx73tbuLJAYCwXZhvO9e
         fx6ljJpRS56kzcdQd1j22TNvx+23ib8D/A9UwHFNBi+GLLzUzUMmWRhZIOeZo+/3RxUd
         ZeTUAhWhGyRLJqtXMWjk5KvHQLBlirdr25TTVxVTpxzylAyYLjO1eJQnHbkzqZuMMSDh
         6qCA5iuW/+uhZzRf/ygtSxvjhnql4JhU3SNaYrc31RF74j8Kp03wlzzYJSu2i3RxTiwm
         oYrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7e5AdWNQsZ8txvrftzv8/ZF7JorH/x7iC5HDKKLYfpY=;
        b=t70Dpdb13OXn0PXukBcZAp9dDyrXukFekEwkjs2ymxMG65WKhyp5Vj1HLRBsWOC5u8
         wMHf9JIEAE4Ys6+oF1A5+MkOJSbI+/BivHvACIwnazEHNHX5b7LVFemONB0WzBL7Jgk2
         FjqxJuDxaFYllqpVR27o5H+SdIMJnldKO76UVXqXv3l9QFujP2RSwEyw2XdunKvP4S13
         PUyxPuVqZ5fEhw8gY6LtogL04vKkvSEunEtSDQAcxgzD4lESydxpMK+2PaMiEsiB8yOr
         YxQDZPuzQG+WBXK1qFbHYK5dNkF/TCsw8dEJHnHGwSmC5+g85cpX0Q5iixdYVti14oi0
         1N0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7e5AdWNQsZ8txvrftzv8/ZF7JorH/x7iC5HDKKLYfpY=;
        b=K8ORfGZwOxWU3xk7K8VXEbQ7Et53OKvtPfpacWlODI4umLhFmULMHhLIRtV/GnWXgu
         EW+IvbqpAPU5+AjI1b/nAcosBznDJb3klbJpFFCc9g0tAg88P+AdlE8W3zNQZkmdtBif
         /+f2NKv+t6+G7I1STIvCzYb9f8MxXVA0TOb1F+2A3BCywcGo75DRC3WDS76nd+/JFpFu
         10wo8wbCIJCFivoDnJIfuKDEg+bXsfO1OfD0exlif0K7w31RqZnTJSu2QRIPQhKFKCBV
         00ewHyDiUbGyZUEWM0JcBcyQMitc72nISYyocMqKH3RLUAfCWhs3YTL/kl0OS9NIRokf
         6eag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328kRfUeSTQjK3KvgP/twjKsCEmZP3e82kylFfEUrhBJQQXpFlb
	hpdpEWU3AeFehpkXp0nhHZ0=
X-Google-Smtp-Source: ABdhPJw3NJD8degGnOI2rb1PzbfxLBCG+rk8DUaBvfGsOfs6kQItwtMz9KCAvnyZel2BYVEQl+nFPA==
X-Received: by 2002:a25:9241:: with SMTP id e1mr41479928ybo.38.1634723338616;
        Wed, 20 Oct 2021 02:48:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9788:: with SMTP id i8ls1200350ybo.4.gmail; Wed, 20 Oct
 2021 02:48:58 -0700 (PDT)
X-Received: by 2002:a25:bbc2:: with SMTP id c2mr10132975ybk.42.1634723338174;
        Wed, 20 Oct 2021 02:48:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634723338; cv=none;
        d=google.com; s=arc-20160816;
        b=tb0heLBGRBR9EdOEDFQ0iMU+rHA8S9vtqG7b1xIoxCvILoVdpOAm+EQ7+8QQcalpE/
         QG4nljeOn6XcMw+G/IUA/N4TLhlzbDQ+NGo1LKCjPB1RjaPP+06iNq04toS849VAs+XQ
         mVW7zm5eV/+ukgbMsWLglM+XfPKTXfrhWxZcnLvnm+Fbk4NoMkJXmgZ2TlLZ5JfX4+PL
         jvmh4FyYWFNxcPE8V0QedKrwWLbXltpFjonYDYVpWxn3LHd6InFxnPJsrhktw17GvgEg
         FC0iM+QEsjYGJgxXeZ0KTp3A87f0iimi9QGgSrgtNSduEEU0yICSfJPw5+zzMF9JATyZ
         nrHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=jTLv3LKQrUqvNnJ57kOgsX9tqUVTnd7eZay6F0YEiF0=;
        b=l12aBFhcngaob27O+r64DHLfJILlYk1m7/LUB00XA8DndQ3kXC5G0eaown8118kwXV
         b0EQFpFZkRbYfpEOG6VpTAbAaN0RrO0bu2j2gt5lV3jfrCEZjArU+T7tmiUL0cmFlsIh
         bjMVkjuO31naeapHC8onBye2NmPglAF2zizJhlunjpxEgWf76tbM/5vw8FicafzuFpVc
         SUCtTS5klDuQv3y4Cr38xBEfNVS+mtxId5TLg9NcsbBXahVw0OTxlN1nnSkr/Xlbh7KP
         8HNGVweGgh4jJe5UJVW8XcrI1116THyFN+Z6qCT0FVF9HEpuSeOCC9KGa54DkBUcPlUc
         qzEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id k1si160054ybp.1.2021.10.20.02.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Oct 2021 02:48:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 52b919d9a5ba49d6a32525d28890f2c0-20211020
X-UUID: 52b919d9a5ba49d6a32525d28890f2c0-20211020
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1720517181; Wed, 20 Oct 2021 17:48:54 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Wed, 20 Oct 2021 17:48:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 Oct 2021 17:48:52 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
	<will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, Marco Elver <elver@google.com>
CC: <chinwen.chang@mediatek.com>, <yee.lee@mediatek.com>,
	<nicholas.tang@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3] kasan: add kasan mode messages when kasan init
Date: Wed, 20 Oct 2021 17:48:50 +0800
Message-ID: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

There are multiple kasan modes. It makes sense that we add some messages
to know which kasan mode is when booting up. see [1].

Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
v3:
 - Rebase to linux-next
 - Move kasan_mode_info() into hw_tags.c
v2:
 - Rebase to linux-next
 - HW-tag based mode need to consider asymm mode
 - Thanks Marco's suggestion

 arch/arm64/mm/kasan_init.c |  2 +-
 mm/kasan/hw_tags.c         | 14 +++++++++++++-
 mm/kasan/sw_tags.c         |  2 +-
 3 files changed, 15 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 5b996ca4d996..6f5a6fe8edd7 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -309,7 +309,7 @@ void __init kasan_init(void)
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
 	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index dc892119e88f..7355cb534e4f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -106,6 +106,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
+static inline const char *kasan_mode_info(void)
+{
+	if (kasan_mode == KASAN_MODE_ASYNC)
+		return "async";
+	else if (kasan_mode == KASAN_MODE_ASYMM)
+		return "asymm";
+	else
+		return "sync";
+}
+
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
@@ -177,7 +187,9 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+		kasan_mode_info(),
+		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index bd3f540feb47..77f13f391b57 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
 }
 
 /*
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211020094850.4113-1-Kuan-Ying.Lee%40mediatek.com.
