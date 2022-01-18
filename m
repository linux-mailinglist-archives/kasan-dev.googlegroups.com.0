Return-Path: <kasan-dev+bncBCN7B3VUS4CRBLUYTKHQMGQEYZDLTVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id BCB28492308
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 10:45:19 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id y15-20020a17090a600f00b001b3501d9e7esf1284477pji.8
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 01:45:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642499118; cv=pass;
        d=google.com; s=arc-20160816;
        b=z32Zk9Nz9ph6ZQ1I3f59t0TQshOc0ivtruLRQEDVxhIN7D7KqX3AKcIGktxLLjT0Ut
         kjHLSl8t/GCtQ9qe+EuYko6X3krxr1ExAkm9qoIYexIXd8w69RQEfMLVCdCpy1Hodwji
         ICjItF6ZAkNTZPWFhHRuUx6uWRv1qPzPuxwCAnKtT7neca20G1sQ6IcAcM79mgr9BE2w
         jNZaDzSwUi3+RMpPUttKnN47HJDd6oYN4fd6z+3/CMz9ilooiu/CqfoR6b/TJw9sbiGd
         1YzQNdqeWfQSx6uSKvPL8fWm7hX6D5Lg/g6e33UaYIMxpM5Z66M6PPQ7OYuFXhePUVqa
         MHtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IVUlmB3MrsLR5w/4l5+FjDWqAhbskOpjXcrAQed1+MM=;
        b=va025P5zdmN9SjjpjqDuLLhH9zv24Kq32nqy5d18oYCda9PYBJUmpYIuBGWEQXEevM
         TV8o5lN3vVyQAr90R55+fSY21l8zolxpaTefVKSIoxbQ9xL8W9OVpIv3DJSVBwrvyBaB
         b8YihG1u2LEelf7U7sHyRyT22pqqsZ9bnRJesAist6pbZhi5WVMKjrnB5yx8gJUPDW+N
         sYht2UT+mXV7FJp+4MnNSDw9WveT/70fbH+NuIk27SYC4whjvbEZKuWuBaRtoFEsGP2c
         M6qmuaKSNEBznnZ94fkN6i0L+Ckc4MT++kig0dUtrVcxQYya+UJErFFnrWjUL22W/b97
         SoHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVUlmB3MrsLR5w/4l5+FjDWqAhbskOpjXcrAQed1+MM=;
        b=t58SbNbK+4I16VsUN8KAnUEL6nb2kFCK0StPeiVTn1NjLTWdQ2dp+kdvpfssNiv6vr
         2CYHuudMarMwFZYtHlPrCv5kQgvctbcIiMxBGwMp0kGJ4A/qXKk6MzQBGrpaHWMbYu7a
         lFCMg4X5Xzk/E2weQ7iwy2TonWR1/J685O9ZSe/a8wxHfBP08Rqzr7U/WSs1LdTBuIKr
         Trfu/XsrP6LgyEEXFQrAxrleS8HHCfiFAKTQYow+i5qcYd/6weo1ZKpi9z4EhxXXkvWR
         ksRJRSHsXEP7mxd7ocq3O1QOoYAMmAzEqxyMra6ttLtGXPgehfeqJw0OPmuQGwPtFQGo
         aNcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVUlmB3MrsLR5w/4l5+FjDWqAhbskOpjXcrAQed1+MM=;
        b=y3uX/uPLQWVrN0UaX/0XXlHTLtNf9n75B4gEtKVfvhI2+EbUpI/81WrPonDW99UIsZ
         HK0gj+1ZJgdsBpfYebA5nDF2qEyR3/4t09/JuD3MNqmmRSDveT2jieql2MW0tGk2QPE+
         8j49H8XhFTSYN8chCmrMwi3nj7OGMlvbeZxNFYCR3z6Ll6WWLR/X05ZW32Nt9XAhm/6J
         ZLmJ3KCeE4H3NvSWPNDYIWZIDNLiG2uRUWmMsvnoPdLY7EyPlqMFpAT/DqqCFa1KA0vH
         oCcX2NhUIWVSyT9BhicVg7JXhMy+Nb3MUwrDxccrNQqMIAnIT4Uy1MCXxroOdAc1LRS5
         Ld/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335nKVOSvGdWoS78tZ9jlwgV4D2rlF0BhE+O9wqmGpBZ8uqBtm4
	06yhy2FrScsrfvXivhev9aA=
X-Google-Smtp-Source: ABdhPJwGmCGR9rHQYHuxVk4ibcPW232S+oyec8h40ZhpAx7YBN1zjWhqggpapMIuMhU2s+hwSgC/Gw==
X-Received: by 2002:a63:7f59:: with SMTP id p25mr22575617pgn.612.1642499118263;
        Tue, 18 Jan 2022 01:45:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96ea:: with SMTP id i10ls7219859pfq.6.gmail; Tue, 18 Jan
 2022 01:45:17 -0800 (PST)
X-Received: by 2002:a05:6a00:228a:b0:4c1:e696:6784 with SMTP id f10-20020a056a00228a00b004c1e6966784mr24373959pfe.74.1642499117612;
        Tue, 18 Jan 2022 01:45:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642499117; cv=none;
        d=google.com; s=arc-20160816;
        b=oYtHM5B4Jf/zoie+FxSF7qlNs2bsOWRjCBCO6MM8NackgdRUcC9QnAVr43Iwuedn5n
         +eaoNUQZmwBUYrDV7dv+wFdibm0KQ8bJFN5WHq+mi60pbKZ21V3qbv8a6+OFz4yq4yC8
         g6KhVdQlDFfmrpknKHle/0fYJbx4y6QTDouFxYqJJGi/BTS7yOiF5yj7t/Mp1Tv4+QFg
         1gkg8nyETFX74qVXyoMkJquh/pE+6gKC6uR7KNbEZD1C1cqFkSQb5gHaKhBXEDFdpm1D
         4mPKeO+MKn8CQ5/bSI76KgSEIW5LHjnyZeYbi7SrS46WUKsNfyU2QBt+PhDCr1BjeApW
         t8NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=0tiQ8Vi1GrAZRBi38/2OPaxs6N6MbYAd1YFti6Djj4Q=;
        b=WKkV4txs8MnAPdSbMTeIjm0TvPK7kPG0liJQ5J96mP95vQauLxWmmTK5ziKm9HM5aK
         tvvd+RFlFwD0qzPP28t960MAwkGBz4k95kPy1GveXf3gZB6heYJE5wOOYrE0mbikET85
         0nepfW6QM6IOADXpFXTFJjSprNKqVc8Q2O2Au0kVdg9J+F7hWCjg7Hp1S1OoYLG00HxZ
         aMuk+iDkkXWgZu/e/dEimXTJOQV/pIaX+lxWL97k5FDSFAJBG7E4IE6m2WHiNv9ROCnD
         IMtG2IKNVteXYPI3FoN1mtXTIkmpW45bi707k0rB/TyJTTVfppCoHHXwUnJ+53wxOBVF
         sp9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id a22si726240plm.6.2022.01.18.01.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jan 2022 01:45:17 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 3ac0b93d468c4530814d3e7583a6dd19-20220118
X-UUID: 3ac0b93d468c4530814d3e7583a6dd19-20220118
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1560820504; Tue, 18 Jan 2022 17:45:12 +0800
Received: from mtkexhb01.mediatek.inc (172.21.101.102) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 18 Jan 2022 17:45:11 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb01.mediatek.inc
 (172.21.101.102) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Tue, 18 Jan
 2022 17:45:10 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 18 Jan 2022 17:45:10 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>
CC: Russell King <linux@armlinux.org.uk>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Linus Walleij <linus.walleij@linaro.org>, <rmk+kernel@armlinux.org.uk>,
	"Geert Uytterhoeven" <geert+renesas@glider.be>, Ard Biesheuvel
	<ardb@kernel.org>, Mark Rutland <mark.rutland@arm.com>, Anshuman Khandual
	<anshuman.khandual@arm.com>, Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<yj.chiang@mediatek.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Tue, 18 Jan 2022 17:44:49 +0800
Message-ID: <20220118094450.7730-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220118094450.7730-1-lecopzer.chen@mediatek.com>
References: <20220118094450.7730-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

Simply make shadow of vmalloc area mapped on demand.

This can fix ARM_MODULE_PLTS with KASAN and provide first step
to support CONFIG_VMAP_STACK in ARM.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index fabe39169b12..f97f2c416be0 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -72,6 +72,7 @@ config ARM
 	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..29caee9c79ce 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -236,7 +236,11 @@ void __init kasan_init(void)
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
 				    kasan_mem_to_shadow((void *)-1UL) + 1);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220118094450.7730-2-lecopzer.chen%40mediatek.com.
