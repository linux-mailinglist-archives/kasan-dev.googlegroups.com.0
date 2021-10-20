Return-Path: <kasan-dev+bncBDY7XDHKR4OBB3PGX2FQMGQE3KVELJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2094344FD
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 08:13:02 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id n6-20020ab01e46000000b002ca7b8a916csf1314330uak.5
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 23:13:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634710381; cv=pass;
        d=google.com; s=arc-20160816;
        b=XnW0kVZPnQlhqrrWCTZuAP93fOy3WalcTbDK2pTzkvUiy5cbvSyFM8rKLzFJB7tMFD
         IBUzYNGTEdtomBAjn2ub7RCL8awTb9GEGfQCjg/46MRMzGAp4tuFOugxT/8KB+6GEQQC
         LnrNwydL/FfLFGTEeiosbAN46geubPX+Q7igjAUdXCe8ejX36d8zv2gj6xUSHiyidjHy
         JO3MGT4dNQYFN06narrXCqjF4U/nALvcllwziPPlgFFNEmZp1kaF3wy5D52eiMZzMMu4
         Iu40tuO2txpxUm2TaK/oXmaZvoZBs9Arf3uR1A8DeMAex+H9ck6Hr7FRRw6dfUS7V3B/
         CZyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=eDFXsxrCDqAYMie/OWFEwYgebmv34wX5SgbPgqadJsg=;
        b=iDx258K1uSQUne3PiIT+MPJEWPQSdT2y0kU9ZSLnVYzi/z1jvYPpayouZd7mXv5fYj
         Q8hspzzkfLOgSxZeOgY9WoinnNv6e7jnzbWh9k4Lty7pExUZNW+VIDi3iqXNFXoRT2KG
         c/wwoK2FP8UrWBIdO3B20zi6jzg1BuWVLjpcf0phgQecGaKTzFrR4mJtC7ZePfb3lvE9
         SEZZADQ/3NJK3VpB7R3xQHxXnOmWwI4IU4+KgecU0l8QRZ0mQAdxlpYC7AdnjPwAkYqE
         ewA9Oaf3PdDZdgdKAHGTsV6/AfAeR/qPzSDgasdETg1hWO1EddgGgDwP/TQPLsfU1lhF
         U3Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eDFXsxrCDqAYMie/OWFEwYgebmv34wX5SgbPgqadJsg=;
        b=bn4iwRvMiEiL5r+nXARtqF0ux0D6NhXDL+WzQckMSpQ3+dKMez1DBzGwxE9rp1eQ2p
         /tJ2scDG/CpXxpIVnVOkxtrJu5oN9jG0NDBg4gUPpooSGTaqmhBEtgdPiOtoi9kLz3XQ
         Zqyf0kNLA2xkKdJRmDjwhqG/Ns+2ufxH8pf8raKniVFcFUr3Spk2RklebOlraimmGrdG
         B2I/PWyUXHte8Z5/iWUqaI+yhNAK0SzhuDLLabYsREQQ0ofhHc4eF2rk3eLobmdk29kp
         X2fBZuEZTIEroYW/sJJ0I4GCJnfZZWX/H1Lc0+QNX/vh50QXZES3trYc3RmQy8iL+PzE
         zYWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eDFXsxrCDqAYMie/OWFEwYgebmv34wX5SgbPgqadJsg=;
        b=M1fDQPrT6sJxu0Ifwf7suLnoqpeLeWLIycGrzq1Yt4r9wJ/LGTPnUPRgJI4yLqsKoh
         ZyCTogNJF6gO4vq0zfi33KIDf7C/Rh7+LwyziOjfKKIFJERr4tWeP3TVDikSI6Q5QGS0
         Q3InnwlmC7XAj9kkE9dpmCRBMymqjRon7VyPkPEJJSkW5BWROFw3zC4l7+jdY0Y2ulZd
         SZI40Lbo8Phon+/ibjhU00N+3O+qWmMqUvGm7lkY5XxwSZGWW67BtS1pylDPGckgsB1q
         FRX9iwP/fcJU8TwwSO6WeNg4FO3pEPfT6/7OySw4ZpbH5+cLQLjuOAqPRDhznAFlSj9s
         ovZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ICN/P1+fSNRAeRHNVpbcFKctsXsNiENtJjg6/1zsIRBsmYglx
	oCYz2KlkFYYFmy1R/BuYdhA=
X-Google-Smtp-Source: ABdhPJwWUqcGGeBXb8fAlX95chY8CZFICNP6KtUVZA7i3fS8WanqzfP9cWagpDGc38xVOh7WBvEphQ==
X-Received: by 2002:a05:6122:511:: with SMTP id x17mr6951777vko.14.1634710381533;
        Tue, 19 Oct 2021 23:13:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:bc09:: with SMTP id t9ls392511vsn.8.gmail; Tue, 19 Oct
 2021 23:13:01 -0700 (PDT)
X-Received: by 2002:a67:ca1c:: with SMTP id z28mr40292469vsk.11.1634710381004;
        Tue, 19 Oct 2021 23:13:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634710381; cv=none;
        d=google.com; s=arc-20160816;
        b=Y83mFZyT1Xu9MIxJ/kThhFpFGte78MISFoKlK5Vw+4eEpwlWqk+C6ZnvUwGqzl12ih
         N//mZw5jlRJc9fdInJs8KXT7GRcNtC8ku8g/+nDB/o6OzQQReFU6KtBVgsgX9Iu5s9Mc
         uSkltAZOnmcWhpv667+YYULermv7t+ImiuM3gDorBWtnBlbnHeM+AYZxcQ+ZWd/R7Z6V
         +WDLNXyL//HJFO4VOQudeP0p/eC6kwxko/lphVIUmc5gu1OemOCBsIcw6tHSrv/u9ECi
         NIjom35F5iOc+R6kVwVMQWpYXeaCK0OS6n6twFYeLqCc8raBUI65EdCfzQSU3xdElG5Q
         QcgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=dq94LENGeOH5kscGjO4AeiggaLkHNIev5GtO7EAkipM=;
        b=s76knpcdCddPvwGIdQ7dYxF0cjuG/7M93ecEOzplk97W9cRU12Y7YZyyCYD3/8NLf5
         icDplf2AjfOQ9zDyhXeA6e4hxiCTYRNlL3mkUZ980bwO/4tJIlYfBMrjJ+qj3dAvFhSQ
         Obm+n/a8N7qPqzj/LHCLPjWWW+g1b0ZEwJZA2eifEE42NZV7LBgCYVgJIlYpTDqE4dcq
         stCm3sIGHldgFNNxphjPbbwR1UI1YOkePdPMO4esJzSLQrUMq2nxbDN0C4E0LmsoCjhm
         +Wl5F/pJTuPJT3xHlGj01v63r2mt83LT1xkwPI+/pB+pOUmINE8m1VJC5hPrbk1gYcC3
         Bjzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id y8si94311vsy.0.2021.10.19.23.12.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Oct 2021 23:13:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 154ad8d91b31496bb95a5cc342c30621-20211020
X-UUID: 154ad8d91b31496bb95a5cc342c30621-20211020
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 493942100; Wed, 20 Oct 2021 14:12:55 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Wed, 20 Oct 2021 14:12:54 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 Oct 2021 14:12:54 +0800
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
Subject: [PATCH v2] kasan: add kasan mode messages when kasan init
Date: Wed, 20 Oct 2021 14:12:48 +0800
Message-ID: <20211020061248.13270-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
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

There are multiple kasan modes. It makes sense that we add some messages
to know which kasan mode is when booting up. see [1].

Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
change since v2:
 - Rebase to linux-next
 - HW-tags based mode need to consider asymm mode
 - Thanks for Marco's suggestion

 arch/arm64/mm/kasan_init.c |  2 +-
 mm/kasan/hw_tags.c         |  4 +++-
 mm/kasan/kasan.h           | 10 ++++++++++
 mm/kasan/sw_tags.c         |  2 +-
 4 files changed, 15 insertions(+), 3 deletions(-)

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
index dc892119e88f..1d5c89c7cdfe 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -177,7 +177,9 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+		kasan_mode_info(),
+		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index aebd8df86a1f..387ed7b6de37 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -36,6 +36,16 @@ static inline bool kasan_sync_fault_possible(void)
 {
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
+
+static inline const char *kasan_mode_info(void)
+{
+	if (kasan_mode == KASAN_MODE_ASYNC)
+		return "async";
+	else if (kasan_mode == KASAN_MODE_ASYMM)
+		return "asymm";
+	else
+		return "sync";
+}
 #else
 
 static inline bool kasan_stack_collection_enabled(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211020061248.13270-1-Kuan-Ying.Lee%40mediatek.com.
