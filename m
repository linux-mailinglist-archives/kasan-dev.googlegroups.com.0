Return-Path: <kasan-dev+bncBC447XVYUEMRBQF34CBQMGQE6TBHJZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 09D6F3607EF
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 13:04:34 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id q24-20020a0565122118b02901ae16b0713asf2450841lfr.16
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 04:04:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618484673; cv=pass;
        d=google.com; s=arc-20160816;
        b=a4xKFohijm/GtZ4m8d1agNZ+95paQIUUDXbDLVMyUSfNUbtu5M0KZKDS7BOYY8Suh8
         Ae6pYwBvltTsQABC0ua01+tuKYpLTEhpoCZ0UzO4DgwZ1TxLgXN8RbtUfTLBgbB7hZsD
         6C/+pniEur1lhaeKLjll6T+XrFUmAeNTpfukFLmgf3EjBgqSviBtbzo2CrH7YfZsRti/
         cg1zciLganZuYq61jQAo3lSTfhfXWOIiYPPFFV0OIvyafSvVTJ8496a2tZAjh/W54oWs
         UEw31ncau+4bddJzvtxDoSHKmldXHz8fZJqq1wiGeh+WYj/xsS4FteDS9q/0wrhi5gz6
         YGsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YwQ0OXtO03TD2LA5qaEk5VP0Tku5uaGCOAUCvjUzvRA=;
        b=klezacFvdHm5ysOZnf6pRKO8xtzwkkUrKPazo8I/qXEinYr8ejR5kOXKtwTVV4v7d0
         Fq/X2IEcObkkiRyk6X+GFMxtak0AV2OZUN6LUqeXdhgHYn66JIyn/uvEFXF+THQchO6b
         jCw3ClJuPPe2faw+qb4hh1X+DgY/d+E1N/zUfjsYAOh58G3AXHYLRQ1BspF4gwhP+1k+
         EYDpU2khhBhro1dqI0frQ3aGtzw6L13Tx3wRBVdScHj94mNgiHfnRaYCubLhmSno2YQZ
         e5Zdfunnd+Iy5SiiKTAO+b4A6vN0KRM0kzSdiuhzVgjLgYsDnzsfB1+DB770qUFWSWrk
         VHfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YwQ0OXtO03TD2LA5qaEk5VP0Tku5uaGCOAUCvjUzvRA=;
        b=kBNlHDq+cXClVDATYfFHocfgImltA9R/wz1z1CTAFKP2qobL6CfV/WLDZMcVB/1Ttl
         VKgfovUaD8VLhpOa74eqqtioxjGTxDNOJ6rKMY7gxoEiEm9lVMPTNAuXXLoGjDx4xiD0
         4embzMct8amCDCtzL2zdIjTu8bxnt3LiQ7EP0vdnJjV20zCYWZU0BBeRhLmy8WgOGFbc
         HAF8h/w9AlV07H4eqX2lAxNZllq4kJVSxgfzZ/d69RE2UQYUD4L1xjXBdUdKqXCw6zGP
         cRUOI9ONASD0wLGXR+F42SHZ8Zu5efKFRHkrlQPS87uDzB/bBDLLR5iOO19E+lqtUXbe
         Yk2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YwQ0OXtO03TD2LA5qaEk5VP0Tku5uaGCOAUCvjUzvRA=;
        b=tJrOyhy1LnbPje3EiulxbNK1bVXjQBF2k4LVMII6LLCj6Itct4kLPBVpBE7u7mXL6s
         0/IoJkr5BEJE5TjoGE0zkAmH3CmJTx/oJhyJzFnMFeD2s3O/OLKpSAeXWV9OF6dYPirK
         ElgXq6XTPCVaLGwuiixW+lTdNJ+mIOqrNr4Vw1gaR4FNu+b9x3I702fejQ0Sor5KY9pi
         PCGmAFl419y4dUWWvut2TeLKNC2OaLz/ZWmiP3D7CZhacdYkAo/7a/7rzY4NAyeV+uzV
         pouZnl0hXFirjkRgeaoq92Ev78Cyct7UjXawd/ui45WwZ9WXG1xQRkbBVzeykBY6b6z5
         I7Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533pK6CAH7m1lbg0iA4L/1bj/jYpkU/5Xde+aPOMSo7uO1qnOWw7
	2y0/mgE6J1+vWfiMfDxb944=
X-Google-Smtp-Source: ABdhPJyv/tMpB9qfl5YraUnohCJIctFoGdRkpurAAcWypKNDjpNUkibhDX/YUoj1MgOc1eRc9+pz9g==
X-Received: by 2002:ac2:4a6e:: with SMTP id q14mr2092918lfp.271.1618484673436;
        Thu, 15 Apr 2021 04:04:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5c07:: with SMTP id q7ls1043786ljb.11.gmail; Thu, 15 Apr
 2021 04:04:32 -0700 (PDT)
X-Received: by 2002:a2e:8e28:: with SMTP id r8mr1504607ljk.156.1618484672186;
        Thu, 15 Apr 2021 04:04:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618484672; cv=none;
        d=google.com; s=arc-20160816;
        b=NBU3KX/1lzEh5xsJSn7Ma6gIhSRTWk4y5f0aQX2U8kQCMzzRr2hlbWDnT0U2bEfkzO
         pOwLxwGXcnO1ud1bIWlT1Sxvaj2R9QJGTEC3jgli2O3S6T83dK76FW5sMXB3dgbTsiXR
         ak3da6Y2XgtCY8TCSkTVYCTdAopq/PpXuBfFq/mFjvb1CmXW3VegQvaSsL98ZWx3c3HE
         4QfG6H9d/Hc4fw0KzWv3p2u2nle3Zd096iSU7oM6mqmAOmwH5RS6VLM8SpKOlUqvdtqi
         ART683PxjyAGpVmOU/WGIo6TE7Wf7XBSNuWkG/yJynwqkYBrvSYpnVbO9RtZZp27gwJK
         1vzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=IbDa10lNiAVDnQpyZxMsU0GsYU3d2rd0C7iMTYwbPRA=;
        b=p2NDD4ukh3YjpPIxSzznzYkEzD1Mszoho4lU/TFnu5uyjaGxF/85DVtZUZqdxrqgEi
         UBhdEc73VUu74h1LC5fjtJVVggall0mUjL0HBxWypaF0GFzdmqAZlaEfN98wXQqEb+CK
         x4ovInj4iOV6gBiPsJ8US5iR6rH4cybCquZpE+oTQopmbQ2OEKz/mxQ70sluZP4ZkRQW
         +xu2N0S1c/77N09bthuzhLk11A+B83Cr1g2xsMW1JkbGznVOnsztNG7s75qjoDBlmkSn
         oS8XLZumyGLMJJdTB03HJh/C7foD1JgemR8ie7+uAAgg3rGrcsqsf2fz1p8ZZZH0yoqP
         FeCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id a10si112942lfs.11.2021.04.15.04.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 15 Apr 2021 04:04:32 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id E665324000C;
	Thu, 15 Apr 2021 11:04:27 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH] riscv: Protect kernel linear mapping only if CONFIG_STRICT_KERNEL_RWX is set
Date: Thu, 15 Apr 2021 07:04:26 -0400
Message-Id: <20210415110426.2238-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different permissions
to the kernel data and text sections, so make sure it is defined before
trying to protect the kernel linear mapping.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/kernel/setup.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index 626003bb5fca..ab394d173cd4 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
 
 	sbi_init();
 
-	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
+	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
 		protect_kernel_text_data();
-
-#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
-	protect_kernel_linear_mapping_text_rodata();
+#ifdef CONFIG_64BIT
+		protect_kernel_linear_mapping_text_rodata();
 #endif
+	}
 
 #ifdef CONFIG_SWIOTLB
 	swiotlb_init(1);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210415110426.2238-1-alex%40ghiti.fr.
