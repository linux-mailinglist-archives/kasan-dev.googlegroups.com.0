Return-Path: <kasan-dev+bncBCCJX7VWUANBBZEM437QKGQEZCGMWKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D672E2EFEF3
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:33:09 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id o8sf18435803ybq.22
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:33:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610188389; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfIikH80ng+EWkUIoWdU3Gl+s8JrYZTs+Dg+ywdunxx+Rdjq2mHwp1AoLAH0Ego/BH
         lv1JG1DXOBnh7V7bqcbuCKDHV3fYTQlYCyRGZaZEKUXcprGoQalZ7nIRTQiyyIIB/W6r
         iVO23kHgJ152Yv6U3oX8sTrgleJa9cD9iD3M6wz9ehJgbSkrESxDIWXEjx9LJiN1Le7L
         2H2R6MKVLkWaUXss30lihP970ChW47M0iV8BYmWe0RxcpAs7DHW1yTTIvmmT1hteX9Ao
         cYCMF/1DyrSm1ul6/d55Vaci/4rNgB3bgyakO764tAvxY+x/1n7f1hYVUNaboXAS7xts
         LwEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=yZA58qI+hSTP29iasw9AzkxheR6Gey4YilZvvfIyXco=;
        b=EgJBG45BZLRVr5j2T48ilHmgsZsgz1YSfFel/vyaklVDQb6wrs1V0Z7krgnmjaj5Da
         pKoFT5eEP0XJKUFafUKBW8vAHBSujjmOqp5cm+NCzn0Es8F1NsMLUxUmJw1wbZKTaSFX
         Ravk55gxzAzEuzbojQBaYho6t2Ca6PkLM4EV5/nFHT3u+qKLfgZlaiPjnO8LT8rvm8Dh
         n0guWvKab7m0MwQN7T+LwH73M9rf5Thcvxcqz+0IW6ESlVa+p+Ptn/z0V945KfCmQZ5u
         7CZ+tMkshb1n9USAQzi5ZSZPmQwPBliJNmIoCOh5fkY7qjHnfeIHSAIv3tAwH6FUfhtA
         /eBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Kor0HaVe;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yZA58qI+hSTP29iasw9AzkxheR6Gey4YilZvvfIyXco=;
        b=FupxqvlUe5EuQq4L8qzXwzxVOmO1KEpiwzDbF+AakROgJpW+/cgKgSVGu83afSXc5d
         yWxwB9NaMVU5NP7Eb6de5Hnjt9tPafWPsVRc9DY0tHiRdt4PW8yKzSXZmP3dwkod3lsT
         az256Hx4N+iEaw7pfCB6P6tGwdKHCDfeLdSq8bEPD32gbmIRfGuUdivqU4FKbsI4eJy6
         FmzMM9yxLUNfxOJvcECsRwJSV725WYQCyuiS5I/+rRQ0gj6THZMcMEc2UE8CLTh1MUbp
         NtIxeJzCx/7wxkybSFRuCnDz3n2f/JbrT5kung9qMTbyBLZf+nF1JbDFlZXA2C55mTyi
         7NIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yZA58qI+hSTP29iasw9AzkxheR6Gey4YilZvvfIyXco=;
        b=l25lvX/IAofXriHgifxLXeTr2yING3ZwOWDgQ5cRl3IgjcicUxi7I8x71/KIm8a4ZC
         rtmoagEi122uFQtSvvqaEfIbr/dpn7rtyWTaY8+TGnzDyVgFpYe5ZYFdTv+0YlY2CQ4O
         RqbyTHUofI6uN40sHX0Ec9Z4kiJjdsBEO1ANsLHjlmQ4bUFMjesxVkvbI96d8rP7jNVn
         rYul4L1ZXq01yiCYoFlyoX+u+0hH+xoI4oAG7Qqt+WexmP+sY7CoWv9a04WZ0AM4rJSz
         UUfr/lPPS1mvd1sWwaEv0Q1AXW3upQ1sJv//MZHe/AXs8o+p3XR6tnJAW/3DA5/iBpAa
         DpIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yZA58qI+hSTP29iasw9AzkxheR6Gey4YilZvvfIyXco=;
        b=TI1oqU09s1GngTwrzrxY0ORFa/q77XB0ySeEXHsmFCM6EvV354sgffKXDbE1/xASX4
         /rtxASRFEW7nNmge9pKmea5Kq2B0BFeihZgY27S7U4pH1AENsWqkUomlmiXUiWNruQd1
         K6LZuMAoVVMe+Tggp2ZAfWXjoknsc6639ZaOMXRFXA5TG/tcFtZqYHi9QO27LDP2Hkc8
         yvRSPJhDaKCy3KZwWeUfqjeXgq6P4CuGN2B1LPZUux1QRC+mbU2HicDzUoAwB1VmHyWt
         GPJ65b2r0MpcwyEtLgzHKcPXsyBZ1M4ze/6icaFOiZ0VupUhWpmBaKKYc0M5VY4nyUyx
         EPCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339calMdHyG5BE3AD/MBe6LqfwxkRvPjmVu1iguGFig8x6l8iFn
	+omstAytARNRMZnktSJtV2g=
X-Google-Smtp-Source: ABdhPJzbhDVywBZ3iqkFiVyzcH+dc5OZPveuHluJHr/uTbEelC6sztPagbIPY/i6YOXcazUF+Vpceg==
X-Received: by 2002:a25:6a88:: with SMTP id f130mr11655640ybc.5.1610188388924;
        Sat, 09 Jan 2021 02:33:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:6af:: with SMTP id j15ls7024089ybt.3.gmail; Sat, 09
 Jan 2021 02:33:08 -0800 (PST)
X-Received: by 2002:a25:8708:: with SMTP id a8mr11890506ybl.92.1610188388413;
        Sat, 09 Jan 2021 02:33:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610188388; cv=none;
        d=google.com; s=arc-20160816;
        b=Chf8mBi8ah3ZHuT7a9qOT1ziOnMFnl2PVE7WOqIglLjagqVFQV+PVkwK/EQz7Y5H04
         51SgN4wzVJKd+uTyw2oVsECsd3jmrXwIXDm7BkcoJIx7CyohBo+PCJQj/gGoTdv+RFqu
         ORm0Lc3JFqN7bnUq17HosxVORZIJqz+XbVo+2BX919xxrO/iuENgY0wroAOlif8Cib3D
         evvvlchpDMNnyaeQfQYHV+3KGxwYDEe0WwGZirLg10u/gwGKgFU4DpY0TTBgCIUFKdAL
         6SUy9GqIJe5vyuauCMADfn31j94dHqEFvSoRpLgwmuBs33atYjTk7j8YgBJWqZpgmFsE
         QCDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=REJcHYfVpby7r9Plat861Deb3UCTNl3jWnkLKDVNOTw=;
        b=MW2bHiYmOsupkpGpgEO/uel2L2rt4Mqon7OpDrXe9nLYh4H/KKB3fcWijyVHiWpiH1
         GASgaiIwPKRvP2GK5uE6pTkUWC+C1r7iV+sYBPiJBmW5yTWC1IGJtoBRY3x86VvoU1Yl
         Z2+C3kHOSxZOggtxi6E0MVm31rEU0PJkOWNx+yH9ej/pyu46dUGPmvCKnt1gZU11WB5J
         DVw5ktF03aknveU84bcWqBPmv4H3gOJEcUdxi96IxUevMVPd7weSP4EiGihAuz1ezimM
         8mgQoBrne36v7F/i00uYdxPMtSc+o7Nrb28Q25QdESK8kV4YJXFsjF6tOGHeNw2OlSK9
         Bf4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Kor0HaVe;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id s187si1507549ybc.2.2021.01.09.02.33.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 02:33:08 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id j1so7029907pld.3
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 02:33:08 -0800 (PST)
X-Received: by 2002:a17:90b:512:: with SMTP id r18mr7980605pjz.166.1610188387613;
        Sat, 09 Jan 2021 02:33:07 -0800 (PST)
Received: from localhost.localdomain (61-230-13-78.dynamic-ip.hinet.net. [61.230.13.78])
        by smtp.gmail.com with ESMTPSA id w200sm11691572pfc.14.2021.01.09.02.33.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Jan 2021 02:33:07 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	ardb@kernel.org,
	andreyknvl@google.com,
	broonie@kernel.org,
	linux@roeck-us.net,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	robin.murphy@arm.com,
	vincenzo.frascino@arm.com,
	gustavoars@kernel.org,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat,  9 Jan 2021 18:32:48 +0800
Message-Id: <20210109103252.812517-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Kor0HaVe;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::633
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

Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Acroding to how x86 ported it [1], they early allocated p4d and pgd,
but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
by not to populate the vmalloc area except for kimg address.

Test environment:
    4G and 8G Qemu virt, 
    39-bit VA + 4k PAGE_SIZE with 3-level page table,
    test by lib/test_kasan.ko and lib/test_kasan_module.ko

It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL
and randomize module region inside vmalloc area.


[1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>


v2 -> v1
	1. kasan_init.c tweak indent
	2. change Kconfig depends only on HAVE_ARCH_KASAN
	3. support randomized module region.

v1:
https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/

Lecopzer Chen (4):
  arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
  arm64: kasan: abstract _text and _end to KERNEL_START/END
  arm64: Kconfig: support CONFIG_KASAN_VMALLOC
  arm64: kaslr: support randomized module area with KASAN_VMALLOC

 arch/arm64/Kconfig         |  1 +
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 arch/arm64/mm/kasan_init.c | 29 +++++++++++++++++++++--------
 4 files changed, 41 insertions(+), 23 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109103252.812517-1-lecopzer%40gmail.com.
