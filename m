Return-Path: <kasan-dev+bncBDIK5VOGT4GRB5FCQSQQMGQEYCIJCUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 606ED6C9A54
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 05:45:58 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id w11-20020a0568080d4b00b00386d5b8445dsf1304544oik.1
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Mar 2023 20:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679888756; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZHdKM/XCi7dC2njfWnvsJJbuAkjZwlseLEtZuu7uXhUHWF9q6GRFW4W+wBWFbiAKfD
         3sU0b0rpNVQfEsy9ikmVTLjtwLbgqK/b6CVhdQs78vRZ9q17GipNfBS7yKXR9+JAuFI4
         9j2deirTPQO15Cwpxpg+VurA25F7xg1mulIIGtNxVzvt1SLJbmYcNLkO9iQ7dULDYCja
         YcFISJ4lr/A0ZYwUDFfdRzuYqz4Z9qFMpSGiV4hlPc1UR2uv9GPU9Yi9c5R2iTl04ESr
         LOfSLUhLZQ0Y7u6VHVYhaW4OHd61yRz2g0Rlg6wPdWKV87HmLm/LIYhOxETVfzx550G8
         pIdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=2lnCX13pZAADeEDCEq7elCyNaXL6/K9KB8koLNqnuR8=;
        b=rg2eNbpMXGTRzxGuhgouz/KW8OD/ZsZXVxSikE7WFNxLvzvNjCs0c5AcwxRbgW5nTf
         johMA6nZzyiMpkb8SPw1Up1hgNugVVp9Ny+d5kseNzt9foC/3ObDs4lm1CoObAyH5vr4
         GKNXIDdNvJ/eZkwAwdszKBNCZQWi2J2b2A7kWVkCow6Uk5iRZrdT1VHdN3QotpUhmN4j
         aX9iV0Uu3UCB04XOmD2t7gBCtPnNVDkVNh3Z00OsmV6PbqvVt7+Q//+mxkzTkyRlc11j
         lse+an0dxMMDHOXpIbr8hD5mLJGoBwCPY63kv6C//+gjD7///JaW8fA9l7y2D/2A0G0P
         RGyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679888756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2lnCX13pZAADeEDCEq7elCyNaXL6/K9KB8koLNqnuR8=;
        b=Vkt3q4U5o28G4b83JvNFGSCJIOkpi1FYW/xoMbIvmkAXOK1j9DXVk+EdyC98esEJUh
         V2CKnYsXAVCgColmHkfMwpovdUPgWxihzscMIKDUSc/dhceCMQxZ8TZb4+G1NJPc7pRq
         VYLC+aCD2X1wCGZCwbQWHpWv7Ells7631ROzwzGtOlWg0aER4fWLTalYl1FsBH0mguN2
         uGG9psCRBeHhbo/nGAdo5HjwQ2wr4fRNOkg+NNU5vqyOD26ODtFjPltGZQuH4we9OQr3
         Wf0VCn1w8UDs7AnCtf64+pl1PdJW/Lh0s8ye+wgjpWnNDm5ItO8A/wNK+9tciIl81JkV
         8Ovw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679888756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2lnCX13pZAADeEDCEq7elCyNaXL6/K9KB8koLNqnuR8=;
        b=DsTxRk7P/dAkvAj/n17BYiI+CtxrOQ4Uw+5lkz19ZhloZ4Mq03IXsN7sAa8LvEqShz
         rvr3mHUwvg582zAEAN41hFTBbuZBlyeSwiLqgVfnK9uW2EGlhabqfJhbDVAvfKY2kPfc
         fjFTSJS2C8Q5yA0n/KUjzoBwjS2nQVIQ4mmgbSpKmj5FR4wvBFxfz3CixWl2wzHxYeQV
         4+cvgpc6BJjrpGovHZAus3qv4QB3zsCbptTO1uX19nMmyuszFvMKCjo9CWdkSSresN6g
         bGA1AwXf9v06wxJH5eXUGjE9VnHq/3DUHZ3qcXv3Xi1z6Ma6KZ7f4ffktwN5ZA6uXrcV
         2WkA==
X-Gm-Message-State: AAQBX9f+r73mr+7OUorCLz0lm7XuMqe1X55c7JjPLOjpQ5xXfLD3S2dy
	tnYtsRdSAIRZ20wyPLxWNuQ=
X-Google-Smtp-Source: AKy350Y1glhjPHIPwfFrF97UCi6jQgsgEQXR3rwlqHxO5SQQzZTtR4Pa6yJqeZUzckui9dkiuzcG/Q==
X-Received: by 2002:a05:6871:8a93:b0:17e:8a64:3dab with SMTP id tm19-20020a0568718a9300b0017e8a643dabmr3401053oab.0.1679888756518;
        Sun, 26 Mar 2023 20:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:96a3:b0:177:90a9:cbc3 with SMTP id
 o35-20020a05687096a300b0017790a9cbc3ls2313634oaq.2.-pod-prod-gmail; Sun, 26
 Mar 2023 20:45:56 -0700 (PDT)
X-Received: by 2002:a05:6871:5cc:b0:17a:a825:6be9 with SMTP id v12-20020a05687105cc00b0017aa8256be9mr6294220oan.43.1679888756114;
        Sun, 26 Mar 2023 20:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679888756; cv=none;
        d=google.com; s=arc-20160816;
        b=S4nU/acx/E7mInssHcl3l6fd2lYlfNgxxdj9W+vg0HexMyFDuCcZ7h/gGFTeaKzqHp
         /VKbJkq+ikCortf8CTfltpNXHPQdWGRqG5+d4GltLO8OYMEhBBzDbepIrTfxgZ1Ts1va
         UwZGRMHSNo5XcGJLaMLI57qRCmumAbPvh65WebKgcX57fffr0VY6vyftJ9xmO5vqUZhh
         CjSW4YFzY7bJwqe0Lokdmnm42HK9kgdXqP/Wt2SoRtw2W8sfF/PI3hfTabjcSLE5rSAW
         L/yKYpKEAZGj/4tuUKuTWCaxeukM5M7reDbnWgKQLOak9HzUah8Q2B0IcZ3bfRKpgRmx
         5sXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=hHtIkdZcgKJHiusW3p25nmgnoJpfPHJgOBjS5cAzEEc=;
        b=L1DqJL4bUmPtMeTuDQx1wEGmo1Rb/RbyBxpj9xCQpKZbI9m4BWiQipGJzzkO6ZzsJ0
         izOLieRFc5bayTw8dfxEQ8F28Apyqjuj5P0YMXYPcHeeSY9vD00nEEvJvCuKcFGyLbtT
         Xt8oxD/GJnb6QLCB0AgWthwpEX94o2Jj2dONyHWQzL7q3vZYmZQOXqKP+lBeLmaIJYZ+
         4N8xTJZkcprARnrYv9hmFrM4+LZlWW/Jvpfe2mxlqZpbHp5Dr0VoGprN8qIPUrIUroqe
         SkFbs/VlAwmc48NmHdTLwfR3RnzlfySF8MproTgE1senimJ2tYQu9GnNetgdEhff0ysZ
         mjag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id gr25-20020a056870aa9900b001762cd3225csi2503971oab.3.2023.03.26.20.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Mar 2023 20:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500006.china.huawei.com (unknown [172.30.72.55])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4PlJby6q14zL66b;
	Mon, 27 Mar 2023 11:45:02 +0800 (CST)
Received: from thunder-town.china.huawei.com (10.174.178.55) by
 dggpemm500006.china.huawei.com (7.185.36.236) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Mon, 27 Mar 2023 11:45:29 +0800
From: "'Zhen Lei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Zhen Lei <thunder.leizhen@huawei.com>
Subject: [PATCH] kmsan: fix a stale comment in kmsan_save_stack_with_flags()
Date: Mon, 27 Mar 2023 11:41:49 +0800
Message-ID: <20230327034149.942-1-thunder.leizhen@huawei.com>
X-Mailer: git-send-email 2.37.3.windows.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.178.55]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500006.china.huawei.com (7.185.36.236)
X-CFilter-Loop: Reflected
X-Original-Sender: thunder.leizhen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.189
 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Zhen Lei <thunder.leizhen@huawei.com>
Reply-To: Zhen Lei <thunder.leizhen@huawei.com>
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

After commit 446ec83805dd ("mm/page_alloc: use might_alloc()") and
commit 84172f4bb752 ("mm/page_alloc: combine __alloc_pages and
__alloc_pages_nodemask"), the comment is no longer accurate.
Flag '__GFP_DIRECT_RECLAIM' is clear enough on its own, so remove the
comment rather than update it.

Signed-off-by: Zhen Lei <thunder.leizhen@huawei.com>
---
 mm/kmsan/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index f710257d68670ee..7d1e4aa30bae622 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -73,7 +73,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 
 	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
 
-	/* Don't sleep (see might_sleep_if() in __alloc_pages_nodemask()). */
+	/* Don't sleep. */
 	flags &= ~__GFP_DIRECT_RECLAIM;
 
 	handle = __stack_depot_save(entries, nr_entries, flags, true);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230327034149.942-1-thunder.leizhen%40huawei.com.
