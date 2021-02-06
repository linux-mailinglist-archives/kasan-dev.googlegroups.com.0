Return-Path: <kasan-dev+bncBCN7B3VUS4CRB7NJ7GAAMGQEYKUIMNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39565311C2F
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:14 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id 70sf7888581qkh.4
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600573; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+V6zB4nUrl2RLCB1mcSgh8Yoo8zA2hWDCc7/L4dGAB2XCEFkEvHeI/lKzEwO+AJHa
         FKSrj5qRbIbqyuUwjZjnKUV3v9cBL4ECJArLR85t6iXxauBLfc90Pc/ZrVChbRv/jCms
         ZE43Yyu7utJRQhfjHZrWimHioyBeqlMOvJG/TXKgnOmOKBziZjM8rFm4Dcn7yCshv0F0
         QETsUxNryJxHH+WANNxufqkZdkl4wELrj1ObQovSLIps3Jn3lmIM30EqUhJgtCGRHLDW
         BOLdt/Nj0HVeuCRSsdwAQKPYIXd/60dW14goKdFbMip/zoeBR9QVXBkKBOaNI3S8ZzX1
         LPtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IcIh8JJJAeM4NmlRqTUI7sD3oveZzp+KQW7qW+v3GEI=;
        b=sVr4HosLowQRYjI8eLB2BACsXkyKazyTQSgPRR3WCNCPzA31qjhQgz6pLOUV5Q9qBb
         v4mN/uzccxgT6NuPsb7L7ZBifJ4AKRvkfU3mNaVCK5Ds8VmApU9Od8IJ+g3JCZwZOZI7
         +nMPLhsDPq9QKxfRkWpuoJyPeDorG2hj0MlxvZWm4ZkzeotCBXEIWkfEb4v2L1f/cBJc
         Tfusbz/YVwU6wlbJ0yKzS3rSBg4alybDkha61akdO9ReEBOM8VAXcKYqDy2/ERg7iQ0L
         Ce47RwpVYWKrALirRi2c0ezGBZciCOULOH/KX5vac/hK32hHckioAC/GRbbs25C1D5uI
         PCzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IcIh8JJJAeM4NmlRqTUI7sD3oveZzp+KQW7qW+v3GEI=;
        b=g4WkgpGNaiI8kV5SeFEcnn++bfwynouarogmJvmIHFmAs7iezIEpW+HZh7OwP7Tdks
         X2OlnTTYMbp64HhD6di4DGIrD7LsAFsNMffGWEjpF0cWCPb4w6AfQ0Inr2vhDyWtJGY8
         hoofKfXrGkOc5NOZr7Wmd/WLny63yC5LZBahFHK5yelzuJQT7GtDvW9RMHmx6wr15ElS
         5UutO/IQaEvc1d/TJKuIkMgLSmAXeNS4L+n+n2zMtpkUI1UPF8NQK/2rmC6NKnMP8q/t
         qHvDMyhVFz350296zK9wZV4UHil+ygotAIv85aRDIelpe0TnSZ55DzfwLDXgRfmeLUz4
         Yunw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IcIh8JJJAeM4NmlRqTUI7sD3oveZzp+KQW7qW+v3GEI=;
        b=Sa6hdb74sJ3q1aCF0gaDig0NJdSCobEAtgPAZhcIvqyP48srfE0LhUYb5pLQPVccwx
         fE23Xhbo5/wbwRX+LR0sA53p+wgDqZZ3UzvJwAotfByJNaL0A3liRejCU1eeRxldo0kE
         mxWLdkcOY4d3YRlnDgIclw0tBgqRGi68gPDT+qgqnhbaMSyYC+B581Q6+KTCGspOdZlW
         rre1pYOOAZexRcCwAeAbd8mIt2MZo0RgUmDxnxqNQBTstx8p0ppKElQOwJio8m6CLpao
         nV+R2mWydKQXtPZ02Z3JyAobl1P39/UZ2f/wzZ39XAdbb6WGJm7+Yf1RqMIYT4iwW95N
         YQdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336zmCzDW7LOcuxJe2QHHFTnS3x5KSGC6W24VPHgsgKDPyPtE+o
	y9rMMkIf29qZjnZBb9gVZiY=
X-Google-Smtp-Source: ABdhPJwcJtxMg6JXbCsHa3k/9iumUl3BzXQ8odb7oEX9Q9/GWq9B0gXv9O4gycTOVLFKOVp11LH7VQ==
X-Received: by 2002:ac8:6bcf:: with SMTP id b15mr7697023qtt.34.1612600573348;
        Sat, 06 Feb 2021 00:36:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3267:: with SMTP id y94ls4418363qtd.8.gmail; Sat, 06 Feb
 2021 00:36:13 -0800 (PST)
X-Received: by 2002:a05:622a:453:: with SMTP id o19mr7805156qtx.344.1612600573004;
        Sat, 06 Feb 2021 00:36:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600573; cv=none;
        d=google.com; s=arc-20160816;
        b=yuMZLDeDLqxBvTTjWi09uKKsxLz8CHqCmWsbe1YwVu63LACeUsuiz+URyrgpmkJccZ
         qofh2Jx65h+M5NPRjl38aIfpGU12AFa1Qr9+u3/BzN/cLgInjsuvY1G6fUKyJu7xOirh
         zGpnVt8vYKQwHx8FMqGnbLBQbhGzm2e1SpyFkDCVlDosOht9W4GkbAu4DjhrFXboYnxX
         Pg96WJ7PZjrqap4261KwS6bzFq8BfcGcDnskJVwfddqL52PQv9cd/0/y8cWUT+BdNyqT
         tS/lVpjqoMomy38n8HKo/7Urla9eT4t0dJCewN1x1Pc3SNRZcjfogp6yKT7BY/vDgbGt
         +6KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Omliwx8S7i8gi8khYq/l2eHtcV7ThvPPp5mR+Z3U2NM=;
        b=VQ5VPzSGgUkdOZtoArliHrefzzvuZ2AdKjakdMFJnP+Zw69DdgvRGXcO82oBKv84Nx
         qe9xX/IC7OArD2c2t7Luezk25wJh5hjztlZ8oePqFtjUFdbRcKO5VZgBvVw1+NL0qced
         nyOaX6UTTZE1s8mhDApa9YztkHXIzsMkqEmpfm72RGV/+z/ySOO/tRnh2baCUIAnMAqz
         lEKmfqoStMx/Zl3iiNc/F+mJ8/XnbxvU8Kwpr0PYTfxwx07zel/0jAOOvvYTrIj8pVG9
         a5lGr3H3HruluB5d2yGFlXMR/kS+/6mU0fV2Kbyo5Mk0/N5B5bR6Ku9q6Me1dAUWG841
         DhTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id u4si554225qtd.3.2021.02.06.00.36.10
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:11 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 53bfa8a91c8d442fb25bd5cdc930985c-20210206
X-UUID: 53bfa8a91c8d442fb25bd5cdc930985c-20210206
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1992209691; Sat, 06 Feb 2021 16:36:06 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:04 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:04 +0800
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
Subject: [PATCH v3 0/5] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat, 6 Feb 2021 16:35:47 +0800
Message-ID: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 48ED01F9EB92388DB50C25F6565B6744F8836A662E8B2C774BE4F94EFBD8AA522000:8
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


Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Acroding to how x86 ported it [1], they early allocated p4d and pgd,
but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
by not to populate the vmalloc area except for kimg address.

  -----------  vmalloc_shadow_start
 |           |
 |           | 
 |           | <= non-mapping
 |           |
 |           |
 |-----------|
 |///////////|<- kimage shadow with page table mapping.
 |-----------|
 |           |
 |           | <= non-mapping
 |           |
 ------------- vmalloc_shadow_end
 |00000000000|
 |00000000000| <= Zero shadow
 |00000000000|
 ------------- KASAN_SHADOW_END


Test environment:
    4G and 8G Qemu virt, 
    39-bit VA + 4k PAGE_SIZE with 3-level page table,
    test by lib/test_kasan.ko and lib/test_kasan_module.ko

It works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL
and randomize module region inside vmalloc area.

Also work with VMAP_STACK, thanks Ard for testing it.


[1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")


Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Ard Biesheuvel <ardb@kernel.org>

---
Thanks Will Deacon, Ard Biesheuvel and Andrey Konovalov
for reviewing and suggestion.

v3 -> v2
rebase on 5.11-rc6
	1. remove always true condition in kasan_init() and remove unsed
	   vmalloc_shadow_start.
	2. select KASAN_VMALLOC if KANSAN_GENERIC is enabled
	   for VMAP_STACK.
	3. tweak commit message

v2 -> v1
	1. kasan_init.c tweak indent
	2. change Kconfig depends only on HAVE_ARCH_KASAN
	3. support randomized module region.


v2:
https://lkml.org/lkml/2021/1/9/49
v1:
https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/
---
Lecopzer Chen (5):
  arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
  arm64: kasan: abstract _text and _end to KERNEL_START/END
  arm64: Kconfig: support CONFIG_KASAN_VMALLOC
  arm64: kaslr: support randomized module area with KASAN_VMALLOC
  arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled

 arch/arm64/Kconfig         |  2 ++
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 arch/arm64/mm/kasan_init.c | 24 ++++++++++++++++--------
 4 files changed, 37 insertions(+), 23 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-1-lecopzer.chen%40mediatek.com.
