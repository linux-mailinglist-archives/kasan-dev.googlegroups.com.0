Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMXR3CDQMGQEFDM5I3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 628E33CF22B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jul 2021 04:45:07 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id j3-20020a4a94430000b029025c2496941asf13813992ooi.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 19:45:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626749106; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJUBr0NefyyjrdOPVGSMYwR1h7GByCs6WAaMwjK/Bo38YfYIxnsPRxktlpJbETXsBL
         yiT3bGN+u21zOaTpnB3Q/VQkYq03AVBeXg7paPKIj58pbng6IpV0TW0T2spn/r93rWvh
         zEwonswNi90VfICLWcDrXYb3r39ycBl+uua1IS2nVDv2LZxRNSJys4hEy0ZMc/2OWONp
         jiHjswiwJGRcS0+wnUI5fMTE3XR4WkkG2nOxxhBUi7l1uA5iO1odLYzrb51nSnYo6AlS
         k2mCF7DKsKfWzL1iC6F/M5mFXPA9Vz5DUkXcd6lftaXQTK+mFoXUZWlDgACD49C5Klq7
         jGqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=A4RIZg9v6+J81fMi7ghWgEk3BrO9VzhERVdHI7J4cHY=;
        b=T+4ImxcVTNSu+1Cu8y+IRAOuTVQ4siUILUDztnHfkJxkNWiXkTpxkyQ65srBA4x4fC
         1zZrCorMfnIAdVRhwAb0olGEintm3gqpJoJ/FQwIbUTgtKrf8zUomMf3DxHBQK4RueKv
         RJ7Y6pPxel6aTfphSh4/Zug2mmsGBcCCfYdMiLOHDTyiZz0VXvNjRCt/oc23G0QV3m4/
         kzLHYS7cZlPkmlNz9Hcdz6xHo9SAYKibiMhTOKeOxtTYYI3Szfj051m29As+3bs91xKe
         7LnCUKeLte2snqQCPOvTBvlSv/X/JIN6/Ei7lH9fGLVoJO31lPsi5r+wI6ZmOltzGkEp
         xIGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A4RIZg9v6+J81fMi7ghWgEk3BrO9VzhERVdHI7J4cHY=;
        b=JWwXKg+KMB56qJ2q2AMthw0UOfS30lYZGLsFKODydqbC8iVQ9Iq7jIRZgSfeELmlzA
         3RniONh8G8sBwqULAtkglXCd83QuWHh3r5/h7Q2HrWlCtkroPeaKLjd9LpdAifBNLhjc
         x1W73MY4z9BuklOyFmMQQYa7gDhIDI2D6K2BgVSUd1dP/BEmmOFNDl6zoPuBOQjcFvkV
         JX8EobVHRloEUYvwfkdKLSVJKStDSztCVwBWpn/DDLt9QEa74ocTh+h2vwLX9Gxdautl
         DIO2NT/qbKgr9ImJKxjLF+flD3pRSBbkyFPCYbCCtww6RH0Vy5BYWuOai3N4727NZOWT
         ZOpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A4RIZg9v6+J81fMi7ghWgEk3BrO9VzhERVdHI7J4cHY=;
        b=j/Y6LspvfPXY3hLQJYNhwkUjOa3Pc0zc+kU2APcndUdyWrU4NaaWGp+ykvk/TZ2Cp6
         OoNdb9+bQ+/7KVlLETJrctVDJm+FoRqnXJZyDPjCBlKNtINjoxoNMd3C1HHe/HWdCMp/
         YChYjWzdU9T/uoU6sCJAoLnze9To9otAP4gOmmc9tzlUxqcBuDr0AZVy9x8p4b85aEr3
         hkzB3u4TAvjXPhdUkc+9+J/xvZd477lGjhm40L6RU1qOba0pBHil2lim7+R5tx+RkD9m
         3wHcqJ4C7ER1Jd2zjMmB26b6RGM2MlfJU4eMzPGAAo23nyMrfd8A17gyckWkksvXDaCj
         fwNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331mLrANMo/R1swKVXTYv3aYAC0yY2zwRMXAQlXRu6bVDZrYXMD
	o64JtZUoEES78G02b6CnVDI=
X-Google-Smtp-Source: ABdhPJw7d6WOTQN+rkSgPMk8hyyE4QQC05BioSrE4hryfCylgZRO6FyYtapnPVLX7Gs2iMJDs8TQEA==
X-Received: by 2002:a9d:4916:: with SMTP id e22mr21207307otf.112.1626749106145;
        Mon, 19 Jul 2021 19:45:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4101:: with SMTP id w1ls1524603ott.11.gmail; Mon,
 19 Jul 2021 19:45:05 -0700 (PDT)
X-Received: by 2002:a05:6830:12ca:: with SMTP id a10mr16258457otq.361.1626749105820;
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626749105; cv=none;
        d=google.com; s=arc-20160816;
        b=0PBHDR5zSDC+pFNsLDgTdP2CYWLm+RMZhGJmm7MU+fQeSp4TA2T0AAWVwrUsp4AP96
         lmA4GaPCjaaQ+loie0DvSS25qyVYREOQCeczPLD3XoxbuLjW4IxWv4mjL0NGsWPVJ69E
         Lj28SkACXp17arYhVyjowODez1Pk8OX2+683FyGqrkDrP0XPlB/peJ0/PsYCqybgCGLt
         KZp9SJBsxS44GcHNEFgq6QcQ3wmRSTSzCK6H5Q+E2wudPAHwxKNRMdohwpR63O1HcqdD
         0FCf3TTN6WepvBuyJHT2xOn0WXrGtWevyQ6IgVcu2eVJx6Jdrb6TVI+gXmR2sAcNOwRJ
         XD5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=y2RWqIsHGNnVzcX1mW8g6FTSvbiYNcs+/i7HplyYl04=;
        b=M8Kh81r2f/5qJmLC5Dd5WgEISNCv/+WW1exyMV5fC6QSiJpuSmIZzbrU4TserT8MFr
         0p5llyCAZ0cbrhlvpMeFWUBwGRJXnWFdORt3TTxXhb/PdX7lvwRJ2/I9loqs0Sq8GCeH
         VwcPkjEkkowtIHxqo0QuctZ7abh+JMkQYOIqcwNNMqucWUIYMNVcFkRu09eQ+zm3wSTu
         pKhNUvQ+Ws7OeEVanEFUYIx2xFthql/TngE/Rz78sZXBvz5lo5NFJJEcjsbebgsKMHgg
         +3UejceWbJCjLdcznDhUJLLCD7WHth9NNPtw+dD1/gAK/sbO8EntWoCadT4utqM6xK3P
         2ZQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id b9si2869972ooq.1.2021.07.19.19.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GTNHp4wvqz7wx5;
	Tue, 20 Jul 2021 10:40:54 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:31 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:30 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH v2 0/3] arm64: support page mapping percpu first chunk allocator
Date: Tue, 20 Jul 2021 10:51:02 +0800
Message-ID: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Percpu embedded first chunk allocator is the firstly option, but it
could fails on ARM64, eg,
  "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
  "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
  "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"

then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
even the system could not boot successfully.

Let's implement page mapping percpu first chunk allocator as a fallback
to the embedding allocator to increase the robustness of the system.

Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLOC enabled.

Tested on ARM64 qemu with cmdline "percpu_alloc=page" based on v5.14-rc2.

V2:
- fix build error when CONFIG_KASAN disabled, found by lkp@intel.com
- drop wrong __weak comment from kasan_populate_early_vm_area_shadow(),
  found by Marco Elver <elver@google.com>

Kefeng Wang (3):
  vmalloc: Choose a better start address in vm_area_register_early()
  arm64: Support page mapping percpu first chunk allocator
  kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC

 arch/arm64/Kconfig         |  4 ++
 arch/arm64/mm/kasan_init.c | 17 ++++++++
 drivers/base/arch_numa.c   | 82 +++++++++++++++++++++++++++++++++-----
 include/linux/kasan.h      |  6 +++
 mm/kasan/init.c            |  5 +++
 mm/vmalloc.c               |  9 +++--
 6 files changed, 110 insertions(+), 13 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210720025105.103680-1-wangkefeng.wang%40huawei.com.
