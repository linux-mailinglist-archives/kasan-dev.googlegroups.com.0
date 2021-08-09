Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTHMYOEAMGQECCUZOCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80FD43E42C7
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 11:33:07 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id na18-20020a17090b4c12b0290178153d1c65sf17459025pjb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 02:33:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628501580; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJiC0npG+AIlQBwt9Dz5MhnfX9/4xcdeb5c9THZ7P70XNExF+tQnNdWnYvmlp1VIHM
         hVXm4tMpUbFERbJXS0N20Pv8CJH8VwjbIeOYhSaDb+/AcP9oS7JuojIxciRYVzYYJ/L8
         iGJWw2RNgT4lNZdCG8EUkt/aDEXpnejYIrMb3rKaYl3dsM9ZIU0HGx0uPaU6LubvPSN9
         IpaTuo7gItl3pVprkmnh6JQoC/EDbQO3AVjm/ko0QNhYH9w0nJo4U5MLqFIvFyOlN/ys
         Ml8WqK9uc4L000Kq/YtyAT9zKeM/0/2ZeHaDMUv+dixR2futrekcuSgKPFqXqZNj8eEp
         Jucw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=0J9Y2ONnrB/dIewTIds/nemfgO0OLUZ9kAFoDAY4Toc=;
        b=gTS73k1A2Lr9ACmh9qQNKraHd3mAghtBkrXjLL6P11a+njJwwintjBxXnIpcuObC61
         5ygrZLIPsOkHstxEEbMEzP5atNh+wqvGlGrvFk3lIyUiFHi36/RN9WIovkLhO/z4sog3
         4BepqjJf3Gg16w5b2Z8HcIbQQ1Zzw5kYOFxQXiSi3Ad0MUeS8L7w54oUeNkWAgHupc6m
         6sEmQBeEuzu60YdPcNVMHRmHgPcHzm7fWY0EXLZWjNVNU3o90SJoaHGk46AGkTwds54P
         /lCtNWcpT4R89fp8LXvekG2e0XmQlrbk2GWxPUTLLAclSkXlQKrOzSew9wsx9AMyTAFd
         7zKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0J9Y2ONnrB/dIewTIds/nemfgO0OLUZ9kAFoDAY4Toc=;
        b=figzyJDQp06iaNgx3OjH0J3LlPnJxFJWT4/h/T/k7qAQDS/ONEfuIwIw1toXyMW2M5
         vmZXbvstjtrCnjDvdmvj9XWW7R4RT1TpEHFY2LPvMMPPZIQS9SocZA5+kQ+RPEerHI6U
         9KfRKm7wwC983cldXYqeQe57MRAKw33ZWEv2eRIvRlDsadlJs7YyloMIDdReWu8a0TkW
         IR+SWhqlSm/cmHvAr8VWpHCkDe1XlhLhSdNjqXdWyLGvLEudWYN1D4kerOEGRjzFjuw7
         XmtDgNOJsmdAKDAQEve8pKqKe7R4a3tEcIttw4lWOOaFchmWtBvnMBAKfLOIet+j58hG
         c01g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0J9Y2ONnrB/dIewTIds/nemfgO0OLUZ9kAFoDAY4Toc=;
        b=VyzhRSsYkj9k4l0sGljXEiVXG6GMWnYzsAqAIC/TRvwIEi1CLS3tcQlEKmRvziKt9S
         DtNG/rJEyGvDOi6DcdK2M0ovNskkYe3CDhpbla+9E+DBBGA07OgFMbwnfKfzb2rQI+XX
         qRQegJpMWE87cVzb8L9Lifl387+5cvIswTlJoR23w78Tk3myVK7WDvSI6XoTkMU5guye
         smsDGHdp9xvwQRC0d6ig3hh/LnUv0fgv/yW8hyD/CLxOsfy6X4Zpag71BPg8iYxFdBqr
         hcl5Ldh5PsD2Hw3prQ00dtnYXgNtOxoGXqMcwRueq6+sQlIWiRAK54QB/UrWDsl75CFT
         IGrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UDvVyutRJ8yGw7nT3atGvkrxqe3F99L3WwYDPLXSo57c6eVPo
	71nCliM1t297OI92UUG6Avg=
X-Google-Smtp-Source: ABdhPJxMNRtuyAOeofRsqaBgCbTlShGS2kTX0xuEeGjORP7E1WXdPniUQ3Jl1IpL5qyYOj/Is99wKg==
X-Received: by 2002:a05:6a00:2411:b029:3b6:2acf:6d16 with SMTP id z17-20020a056a002411b02903b62acf6d16mr17315312pfh.44.1628501580640;
        Mon, 09 Aug 2021 02:33:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls7314330pls.3.gmail; Mon, 09
 Aug 2021 02:33:00 -0700 (PDT)
X-Received: by 2002:a17:90a:7065:: with SMTP id f92mr35082626pjk.16.1628501579961;
        Mon, 09 Aug 2021 02:32:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628501579; cv=none;
        d=google.com; s=arc-20160816;
        b=n848veRnr1x4M5Xb7kjB988lM7NUKZNUz2YBjKJsAyZIzwBIHAhLKUrWqdJwL+9qOE
         Rum0vTDm0+gUWwrJz+qE99ENodUNQf4x7/okA24XKJzU+C4qjUYZZ/d8wEvyEM9KjpRV
         XRrobumRodaQ+54rFIKQLqstGJw3XxrNg1qp/0EBkTTD+wpGFuEsvrPcuGhoC6LEYx5P
         pXWyN/1Ujei8j68TjttvtI9bV21i/9ngO+TWLoHytfry0o64b2I5jp50kTUGyxm/Q1Xb
         mwK1hMjcDtDAFLFFTmfCpQLeP/zpkkVYPVxiL2Nhd3d7du1KIAN0450TjlSzuRe+cA0l
         0yXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=mhMTxL9RMMvkCre9krPksGSKXbeX4uWhd4UB4zhrPzg=;
        b=HhA6WBYrYLHHLv34pz668i9mEQisAclSeCahR1PnkSAhxXEULPxfImAFrkmlaIQOxb
         u7zRc+q7hODMwJabnKYs4IiekbR3iIBnZDSAtYQ2gcK0knmnvfGYR2uuzWOHmP5aCnAw
         P2bVZoEGcnDcC71OmSzmhiS6y1PTW5CckxxOzy81W88Ikmul7p84uqeaxCy9lfo7nsy2
         sCePZI67TdWYWZOXzVOqD5t1V9THuMMkfRbdwGbPkON+PPwrpW4m1E2lEH7dFRrLa+Cp
         xZK0VETkTehD1OQLIZCh3/58Z8+BF0gx3IUjaPOEHWmK81k/lyQtFEQ91TlIEMaLLV6b
         Lu/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id g12si475003pfc.4.2021.08.09.02.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 02:32:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GjrPD6J8QzcmLV;
	Mon,  9 Aug 2021 17:28:48 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:26 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:25 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v3 0/3] arm64: support page mapping percpu first chunk allocator
Date: Mon, 9 Aug 2021 17:37:47 +0800
Message-ID: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
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

Tested on ARM64 qemu with cmdline "percpu_alloc=page" based on v5.14-rc5.

v3:
- search for a range that fits instead of always picking the end from
  vmalloc area suggested by Catalin.
- use NUMA_NO_NODE to avoid "virt_to_phys used for non-linear address:"
  issue in arm64 kasan_populate_early_vm_area_shadow().
- add Acked-by: Marco Elver <elver@google.com> to patch v3

V2:
- fix build error when CONFIG_KASAN disabled, found by lkp@intel.com
- drop wrong __weak comment from kasan_populate_early_vm_area_shadow(),
  found by Marco Elver <elver@google.com>

Kefeng Wang (3):
  vmalloc: Choose a better start address in vm_area_register_early()
  arm64: Support page mapping percpu first chunk allocator
  kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC

 arch/arm64/Kconfig         |  4 ++
 arch/arm64/mm/kasan_init.c | 16 ++++++++
 drivers/base/arch_numa.c   | 82 +++++++++++++++++++++++++++++++++-----
 include/linux/kasan.h      |  6 +++
 mm/kasan/init.c            |  5 +++
 mm/vmalloc.c               | 17 +++++---
 6 files changed, 115 insertions(+), 15 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809093750.131091-1-wangkefeng.wang%40huawei.com.
