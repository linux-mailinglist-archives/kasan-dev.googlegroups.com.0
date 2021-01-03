Return-Path: <kasan-dev+bncBCCJX7VWUANBBGONYX7QKGQE3T6VMVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AFA62E8B30
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 07:39:23 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id y2sf7517657pfr.12
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Jan 2021 22:39:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609655961; cv=pass;
        d=google.com; s=arc-20160816;
        b=W0M+SGZF1P1+r5G9TfjdTFKNpH7Jrqhf7xmohAvlWG3uSe5Wuf4VeuEkJ3FxsT7j8+
         yqUG6lNKcnc7xOIwzav2KWBwrVU/5vWDOTJeN6wUMbHva/4jclVKF6vKTOUOrJ1xJvmv
         KqHRDKri1HVOOfUaUxciyJ+yDtWT5uu4CpTaYv07IOoiP6BSp59YWRxvDTM0HDLBXDau
         YKV0unCkCljzPQszaeNjOSIfeJQpEAYsyQxue9Ew1hS2+Y2/GReqhQtt63RGljQuTr3J
         FkteRA+l8xD/DpqYtC7sMjQDC3jYRc9y/QfnGB89zVkCReqUW+0ptAGbA2DTmvURuO2Y
         B0Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=E3vxH+MspSznLdoQ/Dx5zoGyGJ2JdMwu9sfCuoT36xo=;
        b=mH2mmnAy78N7viRVgIGrCet8zRvGk7jQV/pJwYuBf6lhThTGKHOwm66FLY9/XFxHy2
         VwDNHFju7/C5KBosJUKuyM0i9S3NBSddu+pBZ26ClzMHcMrIMcLpNI4XwKBr692e4C0i
         JcwfN1bM+N7ao0U6CN8nPsdTwbO40K6wBshn3j4Lqvd9s50/C7rILpp9SaLZb0gve94l
         xMwQZfaq51T8Xf3eOKpgv/5j0QSe1iuSxh5F0PWA2tmhnVfESgUJL3vYVujjHZ6i8ZaI
         RJGSUD49hvzrAwbdyGBvBb1q2Fd+qwLj0fBNdMfzzlwy6NGRGnODVl5iu9WIuhvh4si0
         Ixaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=aJfunVgt;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E3vxH+MspSznLdoQ/Dx5zoGyGJ2JdMwu9sfCuoT36xo=;
        b=hYBVDVaZGbfrDmnld/Jh/6/WqHrbsue5zqECS/bVO6NL8pCKzzRM1cSuzkQKRgAp+p
         sSYIHuFx30wq62q/MnmBsPWrx+COcu4Z2/XmIQ8ywwBUQw5SqDy81jHPkme9YOCoaR7E
         /AqiylR3yrZxxyRSpGL19meM0/rkBZYUpThAlDSSX0P/DDsxoSMsAvW3FRtBUPsvftsz
         HBKhGMV6LpWAHsuVJOKPAzMJemaZeIQTtwLb+XDmiBlK6w97bJ4AA/MuPkmd+PzEhiaP
         bRUhXiiCd3m9SZWlKoiqj0FUPSru0+RhX2OaFevbP5gK/4zrz1WLC9olSiiyt0laxr2M
         sSHA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E3vxH+MspSznLdoQ/Dx5zoGyGJ2JdMwu9sfCuoT36xo=;
        b=N/TWqTwzhcC8TCq/00f4v7dKbENMibI0tfnte3yUxdebu5HaAiZKz4w5rfDNXmnDV7
         imgKNpTr+uyXs7eDaq3iwNW9LrU5tF4rTvaIkRmTkanqbHqy3g4I0TDEC5ldVpcvk/Np
         r+erZRi09AsXRTftdptJzbA69i4FQ/SwcXRvLMQ9e+WmDtELUxJGPWgjLtPi58q2yoNF
         weZP9rU3YuDRnzb47njLA4FcoGIMCU1ITQpw93dcwxiwPmAuvbXnvReS8cHZLpHK+ekq
         4HlPBVCDK4PGsBelZwqwzG7vl9/5m8XDDvnwwCyCcMxtBVmzabdE2eQJcDd/fl4JIpie
         Jy8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E3vxH+MspSznLdoQ/Dx5zoGyGJ2JdMwu9sfCuoT36xo=;
        b=hnMUTxTSyOxhKpcAOQYUB5dVbP2VAybnQjNFFUltuUbbFiMINeOdkp5bqupfHkDe3e
         8vvu8tTyAkQwhQjjYXm03AUZGRP4ZzeDot/bAs2Qqblec8Ex9u0+6qXdiUUKfbyCA9gj
         vmJRFVg9VoLMgVNN82WjgUnzTKnGxpR2UIPeXXTyACgpl0xpY9SGlYiZXeEcDhXD+42k
         YTBfaMl4yVKOoEqRjg29V6xR1CK4Qg+cG1wZdNCQ7xh3d9WhFVqqZuvYy1A6e5esO0GV
         QxwbR6Id3aQDI6Nf0VoJQW+FcpUZFimInjQg8KSLVH68/qCGCgAG5wLMFUEjR9i4MfcN
         28Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cH4rJhwqhahQrMRHE+CzI7EcDBsiB3XdqOA/KGVivjPMeoIBC
	6MmrcjKrixEBxe6rZAu/b6s=
X-Google-Smtp-Source: ABdhPJz76k0tXG8tW7tfFDPlXvES3hZb16yaecnflLqODXhJSJufaLwpuk6bG50U/bgVLsZPk457/w==
X-Received: by 2002:a65:6a09:: with SMTP id m9mr38118510pgu.51.1609655961452;
        Sat, 02 Jan 2021 22:39:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9286:: with SMTP id j6ls27058777pfa.7.gmail; Sat, 02 Jan
 2021 22:39:21 -0800 (PST)
X-Received: by 2002:aa7:8517:0:b029:19d:d70f:86ec with SMTP id v23-20020aa785170000b029019dd70f86ecmr61430269pfn.19.1609655960917;
        Sat, 02 Jan 2021 22:39:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609655960; cv=none;
        d=google.com; s=arc-20160816;
        b=sEFgQjtn1MTvAQiLPDVhBIrj+vWaE4x4RZ+WgOxoQrr7v2rGwPYA6Q5geD8dH9iSvU
         iS1sOFfDMpk11Z/qUWyGrdxChIauHWGDlO7xonghE8xS/sbTxSbiWkATnEa4OQuJcEID
         IPH+hbdLE9QholnQq/3Dh5jWNKNeuLya1JIerc/GvtotQX8gubNGXLWPySLfsj+M9FAg
         Tj1Kia5HK7MUvugieDrdhTTMnRYq5QFpLoGsgKdt/8zkTa6q79p1Ecd+AbAPb91MRwlS
         Zc3I/DGbMVyLHW/+LMxdilxkgwAhqG444xzvFjGmi6GfNiCDqSVKS3fT4ahRD9Es+NhM
         cATQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8Y92qT875d3aESyjMGQPzSpXc2nldV50acl7AIHo37A=;
        b=tyBE45bwhhzEPNctEtiLtRKv0Af/0Z4XUdeDjSh98FxVeLe/3CrXdTCT6VGNbLYHAe
         HSbXGikeBOz+t43AcfuCOyk+guJg4ujC+dWXo1o5422RuExTQS65Hyah7pBImR5SSc2n
         8mFFZAjhMBXDw9xUTi35bMAr6Ixm7vpKgukzUHHYMB5mo2S3QVeHVUVYf8Zs2tIzxpJG
         VA2wCQ4ol9EDgAY8wu5ItssMRKvV7LZxYpsUpfmOlJB1yN1dnFUES9tXjTjwLJCsFAEo
         lfCuJUoRwsWTuBYQuChDYO/EFNVND5N8VTtf45FldPtYvcaSLmKeJNBkDrIpL0qDoOvC
         FEug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=aJfunVgt;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id b18si3317217pls.1.2021.01.02.22.39.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Jan 2021 22:39:20 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id b8so12773613plx.0
        for <kasan-dev@googlegroups.com>; Sat, 02 Jan 2021 22:39:20 -0800 (PST)
X-Received: by 2002:a17:902:7086:b029:dc:8d:feab with SMTP id z6-20020a1709027086b02900dc008dfeabmr67602599plk.22.1609655960535;
        Sat, 02 Jan 2021 22:39:20 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id 73sm45465993pga.26.2021.01.02.22.39.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 02 Jan 2021 22:39:19 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH] kasan: fix incorrect arguments passing in kasan_add_zero_shadow
Date: Sun,  3 Jan 2021 14:38:47 +0800
Message-Id: <20210103063847.5963-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=aJfunVgt;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::632
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

kasan_remove_zero_shadow() shall use original virtual address, start
and size, instead of shadow address.

Fixes: 0207df4fa1a86 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 mm/kasan/init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index bc0ad208b3a7..67051cfae41c 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -481,7 +481,6 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
 	if (ret)
-		kasan_remove_zero_shadow(shadow_start,
-					size >> KASAN_SHADOW_SCALE_SHIFT);
+		kasan_remove_zero_shadow(start, size);
 	return ret;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103063847.5963-1-lecopzer%40gmail.com.
