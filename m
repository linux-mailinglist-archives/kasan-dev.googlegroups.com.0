Return-Path: <kasan-dev+bncBCN7B3VUS4CRBFFK7GAAMGQEGKUYAEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CC4BF311C34
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:37 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id k63sf5037486oob.20
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600596; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpKIBcHGY5PBcFG9NK1vtEe9Df8VdI6ZwjiO31edhsIVMPdGtOoHz7QFWid2ajcqJX
         aQqSjPgS627G/KEQdMkQCgq7rPfQMbl8ZVVEmnmfslz7t3i0sl7ienKmA/tGwWuygcKk
         RkSktU/ZRJDWXbNIS2FPXZwpnDVovNK9L12np+ootnNJTn6PrIcjq1jID/7zPBwM+YRn
         Vyfqfro+eckwf46bWg7Qj0JLtzM9DiiAcqav31AWanTofXafR3UiYEtPiNpdSCcTRnvw
         q5o8TIKg/U5on/MbN4XyVwVWEYvNe/UqY8MguPwEzP7cQ9glBjqJ+Azr3r1LvY7KMtH4
         7yVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CTK/Y+84E0Rz7OwKDO5NbjYl9TKNtAOVRLDXaW7wD5A=;
        b=Hl1btTqDw2aW02/YqLym45M2jPPTOZ3WatZBjxuCQu2jerkv/7mGFHC2LqQ4shsuPl
         hU9I15CAbf0ygkOyH7viM2aKGplzXcmfPN8as2VCdeH/sLcMDaVtoUdZXd9Sip4RZT9W
         G0eTX60ETQfgWXeT/kck7UDlnt5wjcCRi/MYLdZY1cXsGTHQLK85mR+Fl8U7vDGWbr96
         48jxRcXALNGc+EK4kQsdNWFPmW1wRr3UpzwGPo54eCGmSdpPxYah9zxTr05lF45GT6EI
         ZCwYs1phcrANwqM7wT8uu3EDtEHO3EmSQlLsaStrvfiRhrmmyNl4uxCk+a4bw2IlX0hl
         7wdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CTK/Y+84E0Rz7OwKDO5NbjYl9TKNtAOVRLDXaW7wD5A=;
        b=hpapGjxezIdT7WjEPjtQwu84xyEAjDXFE1Q2F7ZdoGYT4zdB1IjazpKwc7Lu8Gdfm/
         /Yzt99kQ4AJqOYGBC9ThiAF9fSs8mbpv7sSYDG4DbhGox4VdJiFxu9t1ZdTqLkxlpNfs
         VVXAzO+J6+DganXLUTPGCPmbqHOx5chVzUlbTTpia4OV8rQvoRliiblLHMLFczSREShA
         jum+GMuRSWHsIZRq8VgGqjf5MylAZxVifp45ieAwjd2qyq9PXGxhhc2UyiFSTnzuRhJv
         Ex7cZBMHj2ySxeAwc213rEeVOo7Q4dKxeMPPIsGm/YqbICkHuN+R6LNvuwREvbV3rqDO
         4aCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CTK/Y+84E0Rz7OwKDO5NbjYl9TKNtAOVRLDXaW7wD5A=;
        b=EmxZ73a53hWb4A3F9UNqPihExXzZfVMvpOqygNsWG0tsVJeD2VcAb+E/RETY14jdJE
         Xyc1LsbI/40JDmiTwEc8t1cjzexFsm5JeWV+drRPNUE4JMOBHkE/IpsIWCtY9V6NcJ5R
         7RtEd8pjoxSuEwW99hP0UQ5P2g4R8KWYxcMAd/c61s3MXkSNV8GXelU2XrNZqB414wi0
         bxT52sAA+5hY5tCQlBQn4+O07kVryjmDGL2Zh3354EpGCMNwfcVGT/EJsJYJ2pFzFWbY
         3S4cq2GNKzTwBNGn+sJr0AyddouRjyIu9i5dKcmLdW0MiVL47XuAhcBqQwzY9LZf7Gp/
         U4YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DZ5RhzezOANlRB1ERQZC/b2M+0f94YZy/gf0aP1m+vKYK7nDr
	WNKz5iG6aQONnvuuXzEZcE8=
X-Google-Smtp-Source: ABdhPJzVEc31KFLOcr9dAE6GQ9M+ZFtejZUqIT3p88j7Hm6NwnoXUBn3zXxJJBu7F9Jbl9eTt06KbA==
X-Received: by 2002:aca:b683:: with SMTP id g125mr5332275oif.47.1612600596369;
        Sat, 06 Feb 2021 00:36:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7290:: with SMTP id t16ls2854922otj.11.gmail; Sat, 06
 Feb 2021 00:36:35 -0800 (PST)
X-Received: by 2002:a9d:75d1:: with SMTP id c17mr6228209otl.78.1612600595902;
        Sat, 06 Feb 2021 00:36:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600595; cv=none;
        d=google.com; s=arc-20160816;
        b=KgvIJ0kQ8wGvX6ipKNBiWBIPB814Fsi+cILu2vaDPZjsC1hnyULrPUTibBacD/6KBh
         tPtc059MAC52MxBmkreOYo5jBYEe2bpaqjJjh/6URLLozQjwnF6LFXlLh0chh3ejGkua
         s9/kra/2OSJ0HZdphCLzGhjIwlJTiSoYnVmgA9sZOvOQmG4BLWdR4UowZhthXJMrhELw
         6pn88vJSIQuvBsvVWVwUQZqdETS5B6W/fsQuph360zwuiGw+hwnDnXzaiCBT43y7h4ad
         M7CnrbQdHbzCj3uIKFRBqcoW4U25DVupjAhUaBzcSHqwTKDoPmaFxJraJ/JphFGa6iZT
         399Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=grZq009Xmt+QDKWl/o4L24H+4kI+JK07VQuxP4SBXsc=;
        b=YEcXKedmKbhfrZJQFDXRqGzAK+uxZqaME8pQyD+X80bR/zq+WPApPQuLf35HUXphWw
         OTZrdMVtSxl3IC4SPoyYFuUj9LyRZOTISKTxhz8VSCSqfwAwDe+fwvgFiXX2J9bU2UOy
         jGIe4YL8ttBplCv1u30o6IqJzxvcn0aVamt+ZvHNUUOEcpo9BeftD17Wb1Avc3qGhIO/
         HcfrLOAnE2gFvcTF7AzKhBi/13i/Slffri3c7XKBKMXmMqUH3bFwl8u92lk6CUvPunGi
         TPdN4QvPwqvvZDQy8leOZSdZs13j0B3MzisdCkyntXKCb5/g9nibndD09Wlq7aoVmAlt
         HTLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id e184si984191oif.0.2021.02.06.00.36.33
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:33 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d0371bc42d6a433280f0882081989412-20210206
X-UUID: d0371bc42d6a433280f0882081989412-20210206
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 123114299; Sat, 06 Feb 2021 16:36:29 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:06 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:07 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<will@kernel.org>
CC: <dan.j.williams@intel.com>, <aryabinin@virtuozzo.com>,
	<glider@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-mediatek@lists.infradead.org>, <yj.chiang@mediatek.com>,
	<catalin.marinas@arm.com>, <ardb@kernel.org>, <andreyknvl@google.com>,
	<broonie@kernel.org>, <linux@roeck-us.net>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <robin.murphy@arm.com>,
	<vincenzo.frascino@arm.com>, <gustavoars@kernel.org>, <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v3 3/5] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
Date: Sat, 6 Feb 2021 16:35:50 +0800
Message-ID: <20210206083552.24394-4-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
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

Now we can backed shadow memory in vmalloc area,
thus make KASAN_VMALLOC selectable.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index f39568b28ec1..a8f5a9171a85 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -136,6 +136,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-4-lecopzer.chen%40mediatek.com.
