Return-Path: <kasan-dev+bncBCN7B3VUS4CRBFVMYGIQMGQEAFQV3RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 07ABF4D96FC
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Mar 2022 10:02:16 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id n66-20020a254045000000b0062883b59ddbsf16221479yba.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Mar 2022 02:02:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647334934; cv=pass;
        d=google.com; s=arc-20160816;
        b=xNs0Vj4HOTMVE5pWrr5+0jMquGYgiOsaZ1DpYNJkqz+h792AFeFe3ueJ6FUwbGxSPM
         V+6IIGmfLfGVX3Xak2azKvniK6rl5ZK7v9knz/Zszb5PXxdZLtp3k6VRULPZnIPj54Xx
         OwfOktHNSf9CrbKaS1eqhgz9i6SVjubW+XL3B9aWjk5rh+pI71eUi00202aWFfIYtcAM
         h2K0VTroVy1m1W0TvcahYnCDr4loUAewdJt/Gn3SPMNEpeoXVR7tw85INoF86w2hZHvk
         KHBtaDFHSrOPVYv3wxXXwAj8mcAUnJ5kLEa0FXR7FAGL4VVyDvnVKqPtlSo0qSqlXTGt
         4vDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GeecDFQuDyyhCPxc0H4FdjUZQiAM6gR6SoN888kIv1s=;
        b=ITaMaKIdhrvTU7/mBZZntnjAoV+VBxKhxZfmCk++jyUM+7h4vVFYWNTS2jWEEnonx2
         7pCcy2KjDzMA4PCmSHGtTswAw1Q4ZMf+CLCvNsN2Huk6eF4iIYWmJ2jCX+WcSMkaMi+u
         70Vuba2wxS4HN8fJUXlyG0xeiOiNa+iB8iVfjLDSnnr7zXcYOBjlEuZ0Zx6mnZ0d13nQ
         86sNPfIAg2wwFg5tdNojoaUr4rrubF5Y67stKfS5E9o/4gl/9TJgDUe+Yx/Y3K2tpYt4
         WLSYeusEpu2+sXCj09XNZboQk6ITWv4O8cMsSmWRdbXKE6+bbDVwmUD7rH7B0TsaxtXV
         PmQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GeecDFQuDyyhCPxc0H4FdjUZQiAM6gR6SoN888kIv1s=;
        b=XU7nVTudtifkfqfb+oDUFmL06aQAW64Vt7PGKb+QYRP2KUKh50Cp2sWgjchubzMq08
         ga5vjmkrzrGiP7IL66GDYnso+PtG0SKpfG2jok6ELWcbFRly9hqdoI3ydfSCh3ffTqcY
         mXVCgm0XgT6FwveYhRtuoWZuQCzv26HcH+jLpZXraCmgjYgb1TowmjyIoY/bf8HqNtv1
         5KFfqDOOWoOeAv/sQAyb4cUY62Ks/wk2y+x7cp4JnaGIA11l6HsdoQr9iugJ5CyOctvs
         Ix+IwwPpuuZE0FM9VPcTg5tf1yhZy1SBqTr2Y/nF5TNCcPr+mSC0DrVfmMXaLo7cdg8+
         OjpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GeecDFQuDyyhCPxc0H4FdjUZQiAM6gR6SoN888kIv1s=;
        b=Xg5tizMOfE4gezSCC6CvOnvh4/v+WN/kiy9H/lXnkgLlDszc1bRg9OhWVKAbpV0UOJ
         nm+Kg7M2bwEiLg7cwDkb3bXTKEOR5OITQhQT04f42LANlKgAUXVA2z0ldDEqo+mvumRV
         jO2At8fyz4X6oa4OuL4QvJdIhmkYsPiTXjJrc4fny/WAbykomC9tim42jYPGFlYv8kii
         VErvude8+x2ymDYS9kVISmzMerY0X9KeZ+BO8UR5/3ueVt3RLM/sOlMF/0su5ddJlPRb
         CwEOXyg+XiegvOYfcXtMWeJz3U5ivztzmcGzcb/y7ENLHdflOR52RKUFn/4NKpJc9Mkg
         oXAg==
X-Gm-Message-State: AOAM530Sgup29cBR/VbXrg9wbp5AMZAAc3CWPIKPOx00ANhkaoxayo4A
	BAyC829IMSjcvCOOc5gsrtM=
X-Google-Smtp-Source: ABdhPJxBClaoAm9/hn9723pjNpspqObGLsg/Ab4tdB68bUzLjO44+jItMK2+3I9WT2StX6XnJj6pgw==
X-Received: by 2002:a81:af21:0:b0:2d6:f5c2:44f4 with SMTP id n33-20020a81af21000000b002d6f5c244f4mr22789255ywh.353.1647334934363;
        Tue, 15 Mar 2022 02:02:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:110c:b0:629:2656:4307 with SMTP id
 o12-20020a056902110c00b0062926564307ls7095814ybu.4.gmail; Tue, 15 Mar 2022
 02:02:13 -0700 (PDT)
X-Received: by 2002:a5b:c7:0:b0:633:7f15:9729 with SMTP id d7-20020a5b00c7000000b006337f159729mr75002ybp.98.1647334933903;
        Tue, 15 Mar 2022 02:02:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647334933; cv=none;
        d=google.com; s=arc-20160816;
        b=tIsRePU0E3drsksVlbzakCl1DqyYio5mIsp/mCcP2YB9S8evMQ2UENqYDe1xOsWP/o
         NpPSxpa1DA3F6L1vHbLM/sD4yZ22z6paRHb99LHKBWZUw06BHLXqvKKZOQahP8Ge60qm
         9X6+63x49snOux5HXJs9GbIZG6ZmFJRGXQRVnf+cF1FYb75aok4YrrGjHmsKvphdw0NT
         EW58/uOOWQDCmxnq+yK2FwDZMzPdqgbox3J9naDNRyX9H3106fP0uYYA+vCzJ3/ZdJYG
         GWPTFiGvVn1qRMxxbt1Huo27HGKeMwzHz4lg8iPbZawjvQWOSyWVRCwCInPi0gWL59uo
         utHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=SCz55rx5ChBdS+x/O2bwXlHBwxIbSKW/q9fOiscTHpU=;
        b=jZnyx3441fGL5/1he/RICpaPnvFtj0ZbPVjoTaUlSxjPzITGqtzN243OomTE3JBM1s
         0lhH8HbyUMl5aS30NtI1TSgR9eklq228FxyuQyXbjkYgucl8p9zgjfFSJei38ooC2S6A
         QUK7VMkNg7u/qtybXwtXpoWgymCp16fkwxuzNHptx6M2rrHaRPNG3huVre4LcnI9DJjv
         oeAiRf1X7fIAwqNvNo+AlMjau+58y21gmwO7IUd4OQmrhFhaVX95OKo6OlX9dsfdsCS6
         hOZq1MwWMpk2XRzzFqPjx2bewnb7vK4zS6gWytDXhE0cO3mM8q9pvFC3rpr5BHiAvCoI
         bI/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id be16-20020a05690c009000b002e58bb7f75dsi40718ywb.2.2022.03.15.02.02.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Mar 2022 02:02:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: a990be5c12d74a1c96fc4f13e96d0be7-20220315
X-UUID: a990be5c12d74a1c96fc4f13e96d0be7-20220315
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 556387979; Tue, 15 Mar 2022 17:02:06 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Tue, 15 Mar 2022 17:02:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 15 Mar 2022 17:02:04 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>, <linux@armlinux.org.uk>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linus.walleij@linaro.org>,
	<linux-arm-kernel@lists.infradead.org>, <lukas.bulwahn@gmail.com>,
	<mark.rutland@arm.com>, <masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v4 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Tue, 15 Mar 2022 17:01:56 +0800
Message-ID: <20220315090157.27001-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220315090157.27001-1-lecopzer.chen@mediatek.com>
References: <20220315090157.27001-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and support CONFIG_VMAP_STACK with KASan.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 4c97cb40eebb..78250e246cc6 100644
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
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220315090157.27001-2-lecopzer.chen%40mediatek.com.
