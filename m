Return-Path: <kasan-dev+bncBAABBDOM7OBAMGQEE7KEUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF2DB34B54F
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 09:00:14 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id r63sf2470069vkg.6
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 01:00:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616832013; cv=pass;
        d=google.com; s=arc-20160816;
        b=oI2vTD/vjvgJzE603qXTSCgSbcINDcyo2z7LLoAtN9bCrWcv/NdosUsXsZJyRQNGEZ
         qJ+Zlgq9EJigMk1hzbnE6cIs8jN6C7Meo6E8nchxnd2MHxa1AwTZ6xLOxn/NOYai5MAS
         oxaSVHn19ABUytzFQoe6eUFyLitlJSkX2n2ADk8s/BE9sZIBNARymOJhu5servOhvcIG
         hVx5uvGIPLyIrTH706E3oiVCMXFO27kyRXXKG3YF8cEniVWxIIPh18J+NOKHOweu9H/E
         /Ih17tx/AUWEPZUhoj+l8lOrb2BXyAUBhlIA+T/eTh+6x0Q35X7FXeSpZMrQ5gl6zbak
         PnVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=z5B9k9TromgRrVG/YShydWOYptu5KDHbtxqAK9OI0Hs=;
        b=w2CD0puqhNewlc8BfDHMH0GUM8B2XlZWbwtLJtAMsqevbNpeXyLJSrI2KfRpESy2HW
         g1rRkoupHX4ge6gyXVG6PyNI5gvJ4rm0ilwHudsS+rYcO/kSJwjyQRI4kD8fabm/0Sov
         5xr4g4/NcZk8Heop2ECpvr8vvVhrhB9I30Xq74Ud2C0ZxKLmmX1Ao5kpdE87yw83O3tW
         YkEOVURT1UiacV+dkir/QngyWEmDB1JgT1FsDvmOT7yz9mwQWb1E3xpmlOQ5Rywj1q2R
         lBLr5wxVwrwDdaankJ2xc6u+ecQNSlwDzgaoxWQLFN0ibnovuUR+BixT/SIE1laRo7uq
         CsNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z5B9k9TromgRrVG/YShydWOYptu5KDHbtxqAK9OI0Hs=;
        b=U0e19uQWm1qoXwu+Knyf5GKOZ1Yv2wctitVY0U61GlTivn4sbzKg2lisFwqzDtXniN
         QWEbm01Z+vaTFIIVt7W2tiQtVf0n6Mpk0dXu0mlEg+wHKBm9fjFlO+iEPAF9YZznRJ9F
         h4oyDmECN9zR1KoZa2iSjO80C4or1HYlHi0cEMSm7utCTAh1x73Ivc2u2wWcq91/aiaq
         rplG3VF8NxMkQFf29+tjCRdAIcTYUis+30lLqOc9Bov1DN7RYx2vTOhYiZzN+bQdaeKm
         wLA3s/S26+PBkN3Cp4CkbViieZggZHGLbp3zIwz0NvdNQNieplob6giSwdvkvVN/yUe2
         YF2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z5B9k9TromgRrVG/YShydWOYptu5KDHbtxqAK9OI0Hs=;
        b=FTdgHWZl2mA4gWCny5XiR8glITIO9ZzErOssMRAVqVnF7Td9UymXFLQ4HnejlJGvG1
         YotEfI7ZmOVtPqy2IVGkFi/h4PKxpsXyMbSCoRsihOuCenaSrFfQzG2ShtI7ND0AbJjt
         RHgh5jGWf6Pq8Cc3j0YvU57gQKHVhIPhL+TovrxZJP5XUq2TjS/88g6Kwava0pMv+uAE
         Q2XydI1ezFJpbX6ZJdrBnxyTQXyG/ieEfsdmcZ/dvbq1h8kLzoQndY02tsOFVmdcfkvL
         Tt4aianNTKrhwHvser7VDPPfyLDwjO1GoNXqYdBLYf48jhdV6MjW7cQTYU8fVSjgAqNZ
         mUIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lBo7uRKYgV2o5A0Rtb7tjMNUn4uTSDvLx5tQq1dzQST8X+V+8
	dKXS+DJkaPxnvSBeIz79Ipk=
X-Google-Smtp-Source: ABdhPJxCLmm/j+ALKaUh9UMxSz5T0ykazNmtj+xmHPkIijA1Z/Um/liANSTywl0pXO2QJBc1RmVU4g==
X-Received: by 2002:ab0:2eab:: with SMTP id y11mr3363241uay.127.1616832013705;
        Sat, 27 Mar 2021 01:00:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e88d:: with SMTP id x13ls1450832vsn.11.gmail; Sat, 27
 Mar 2021 01:00:13 -0700 (PDT)
X-Received: by 2002:a67:be15:: with SMTP id x21mr10706073vsq.5.1616832013028;
        Sat, 27 Mar 2021 01:00:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616832013; cv=none;
        d=google.com; s=arc-20160816;
        b=zwDeHJPAkmCvyJYS6etXt4CuE5rn2JBGSRoJe4/97iTTZncfm6whksf3IWiX7N/VZC
         tJ96e+1ycOxU7pFFj+2Lv/lxLgYxlFRjt/MpC5Q1Gnzo3TI37wckhn1DnaIyvRRJBXOo
         pR6UNJTzkBs7QViycZUw+Z0RfW+uMNjOXyepOy+iciM0bqNvCiddL660SEKBskVA/vFv
         YuQBkT55fqFNgxQJuSvPAWm9Ks6YThbuiCdwBKb/bxiiFGV594w/EArUpNIGYTi0Ihy/
         OLwJHf10PjzKe6xmtNSpWPlwM3FvpBy0sP1MsamKr2RZW+cTucRcOzh3i8nZ5o9kYKuF
         G8Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=62PS92v6BR3TXAJyLjK5ee/inahdl5Z0+yZN06/B2Qo=;
        b=Wl+wXB58fO/1ucsl2kU0D6m+HjhwExwak2OL1s9sWVUg7uM3rIsltNq2bT28bS4tBO
         +xqoFsgW0/KEubGwUWBqq+LbW2n9bWPY2yeSOymFwVQKtA+ZF+JD1MywXROwFO1d5h9e
         /1Ui5o8sWQexTEJkREu+qJeSbjK7nuybmwjwIS1NxRO0gy2iXbyl4Vo+9LBxbtQH0Q4o
         65vTAId8LB69MoKIvwZk8TvhIcKay+jTiN0cxrKGB6ZtmPH8dSbOArJkvL7AI24nuVl7
         UoX22ONH90B2ITW+unXbLzwFwxwK0SztIprFo9S4/evGoxhzTogxjTYhOQw4FtL8v82n
         iXgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id u21si652109vkn.2.2021.03.27.01.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 27 Mar 2021 01:00:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from DGGEMS412-HUB.china.huawei.com (unknown [172.30.72.59])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4F6rmB6CZVzPqjx;
	Sat, 27 Mar 2021 15:57:30 +0800 (CST)
Received: from huawei.com (10.175.113.32) by DGGEMS412-HUB.china.huawei.com
 (10.3.19.212) with Microsoft SMTP Server id 14.3.498.0; Sat, 27 Mar 2021
 15:59:58 +0800
From: Shixin Liu <liushixin2@huawei.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Russell King
	<linux@armlinux.org.uk>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, Shixin Liu <liushixin2@huawei.com>
Subject: [PATCH] arm: 9016/2: Make symbol 'tmp_pmd_table' static
Date: Sat, 27 Mar 2021 16:30:18 +0800
Message-ID: <20210327083018.1922539-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Symbol 'tmp_pmd_table' is not used outside of kasan_init.c and only used
when CONFIG_ARM_LPAE enabled. So marks it static and add it into CONFIG_ARM_LPAE.

Signed-off-by: Shixin Liu <liushixin2@huawei.com>
---
 arch/arm/mm/kasan_init.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 9c348042a724..3a06d3b51f97 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -27,7 +27,9 @@
 
 static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
-pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
+#ifdef CONFIG_ARM_LPAE
+static pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
+#endif
 
 static __init void *kasan_alloc_block(size_t size)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210327083018.1922539-1-liushixin2%40huawei.com.
