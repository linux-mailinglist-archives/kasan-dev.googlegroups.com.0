Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBG35OEQMGQER4G3OJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 23CD24066C3
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 07:30:45 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id p12-20020ad4496c000000b0037a535cb8b2sf4639049qvy.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 22:30:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631251844; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y/vQIsfQZ9hpY8vWtuUr7UpA/afRR5t35j8KvYg+m0E1l4bMJO3Kf1wWUB0GYZ0f7F
         F7/V9JV5aaMA5wDCzgqWrROOSZ0bLinikqJMdHx8OLV+Rz2bo0hflJs67iXvEIfqkm4N
         cQVDIUT2U/urv83Lrpqc+qEQZ5kxMYK3Hb0iNCRzAC+YL4nDguz4RUTGI90U/eUzDYxL
         nO3l7HEol+9ynNwZ/12qywb2WEVcphoKMz8g/0rIJhdWNObIScfUgtLojeDs3Hwcvgqg
         OV01EeSWG+LlO6tbpNiW2MYB0KiJXhjUQlk/JCCvtHBoKwQmidk/P77IoPsUPtsgwMJs
         UHPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2mUO6kiDOcKoAYrqB2j1ZWLrI6xPhSLj+bwRDVS887w=;
        b=aRSnmi1bBD5qpNrs+v7TqKIwT9XSBW8nG+EOfVcZxmFmVwLkP1hBvX6pF+UejByjMO
         AtPewnxRhbSMCBnoA/FxQpF1PmI6/OVcQrEAUgbzYniZt+5tpxflgOAa+tSBVr92t9ZC
         R5bxav4KDVTRo59w1ujcyT3xfgmbnQA1Bs3UONZ0yHNMsm/58mUmTHEfeccOWO3cULQ0
         o6t7vY2I2g0pu+qr8fpiyXjB5Ts22aYuIQrDpRd6qPTJqbCJOSOqdFEtl6++38T5QAc2
         2DSZT/rBJe9LQqYx3v5NUk0I0ZRPsoX65/+2ASTDxqZY4lsQqDMFgI4Z5penbYGpv/+E
         bJtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2mUO6kiDOcKoAYrqB2j1ZWLrI6xPhSLj+bwRDVS887w=;
        b=PqI97ADN3d0B05thziGU8LzIY+5yN0kagHGyu+4bXO8K/ri+fQPGzqfWxGBIxbNvLg
         2X3jZ2zIK5aLrhtdf8KSn5CQnDq8t2z2ZxjdGnFVzniY5LlttykMcZSqRK4WU/WsZOvh
         xvt9h+9Z9dfwjXBRmRP3fEsdnE00SY7Z6xKItRBGLa1mwZaYioV8vj9h7HBa1Mok3haC
         oWfAF7zkG5U7dhKLlQTznzl5yyw+VqcnjFVxdyZ2E/srP18f4xKStAljmQBsblztgiBc
         6d8LwQkSXdYgGNaP1lyNb+iJdy/aGRh4TbHjL5NCCI5VsVMA15zR+cgnDLELUW/+y95P
         TOIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2mUO6kiDOcKoAYrqB2j1ZWLrI6xPhSLj+bwRDVS887w=;
        b=o+Rp7RwDsFVxMN66LS6B+yD9aWnR7jLmJ7LHpeD/O1yN9k9q4TEuGDkZGPrKapftEz
         VvhlxtLcwA9E/nGvstDR0griVEpMy9lBrsIjsPDcDRGs0fNMgbzI2VNPLg1FbSM4oU7L
         RzD5KBC7o9ORhHY9qm3ZwXbFIWBYFkBLLI9SJkBOXDf9IFLYLQP0olv1r2GmBBl40mtk
         YyFs/Yh21jl2zcObvlpjhusV/iSSFWmdLU4PamNUKCzmzMVLzKA49bbZYffa4cHqaOJF
         EeRfzZ4pco+tdtowWxjt3Wyrt1DWIbjJgO5sP7tAD7p3rCveOWEgGEcmIajTmpOenrBr
         qT4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vskVxKhm7CxNuv2SqGKZvYWxTWcKppe3Z4cnRz62c8WjuOSPN
	GFjDoyuwPAXcUzsxgjZzfjI=
X-Google-Smtp-Source: ABdhPJys3fU/obUUTm+zuNE88fJp5Mmmh2tXKt5qqJESz/frU7nKRIhppLHYiFT3TmL82efr4oHG+g==
X-Received: by 2002:ac8:6697:: with SMTP id d23mr6449102qtp.34.1631251844160;
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:c5:: with SMTP id d5ls2435193qtg.1.gmail; Thu, 09 Sep
 2021 22:30:43 -0700 (PDT)
X-Received: by 2002:ac8:70d7:: with SMTP id g23mr6566308qtp.150.1631251843737;
        Thu, 09 Sep 2021 22:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631251843; cv=none;
        d=google.com; s=arc-20160816;
        b=r6tEWgLOtmr5KB9ZIQKrrUGBXYHklm4geDHuHxqgu1rkVU6b3y+PtG7Ix7n+dVt7cu
         TQ99hFwRUoT5hD+Wrbi0hMaauCmMQwOFF2OIZY3GasSVM4RJh4uL/Z9VUyeYr6Yn+Hwg
         CQBgMr4QhX7LuCStiDr8ingkQhwP+IMW1cU0ex+fyJ67ol7v4OVrwOMON6IJL+tkdir0
         cq8V3p71XcV8SUsQYMH/lwvM9bXaMHkCTlxE5nkpNjXjLKCaojmj9D5B96PbLG/FWGiw
         AjhSEbdfLwjiVsCDNyKRlroN68AcTdayhnddve1mOjy7OYDf08B2s1uuduFawdKqSg7a
         ZuiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=eorY1uoRFV5vxRqjPvZWnjoF9wWBUGt3zM/S+6yFoCI=;
        b=0CWj9+0QSal5HOM6zN1TY1DdwsSQgnjz3tp+iJUTmzxOePXPE5wWH4Sk643XOB6DR+
         sF96qXdHioh4sXXfxJS22YMovU+a5lp/4RMyCWSRBk8KdumGLVbV3hNXgZTcrXy6mqAE
         K68Y4hXcTII+U78ygtY4pG+GRrBBi4vQcru3IqB78eS75N28Pa47cmtrWHx68aIqSvC3
         tOgXiZoNql3w8cnWXXuXYCKj7j7qxPKi7jAWniUrP0rWJRcUf1Y6FGk4rR6/eUV2YRRW
         DynWRWGN2rc5NJwhbpFnQqiRnQVs1yqZyZouDt/H+WN2luKCmDMaM7W9HElUBHDusAwa
         Q9fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id u18si324880qkp.6.2021.09.09.22.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 22:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4H5PZV6MDcz8stp;
	Fri, 10 Sep 2021 13:29:38 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:10 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:09 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v4 0/3] arm64: support page mapping percpu first chunk allocator
Date: Fri, 10 Sep 2021 13:33:51 +0800
Message-ID: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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

Tested on ARM64 qemu with cmdline "percpu_alloc=page" based on v5.14.

V4:
- add ACK/RB
- address comments about patch1 from Catalin
- add Greg and Andrew into list suggested by Catalin

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
 mm/vmalloc.c               | 19 ++++++---
 6 files changed, 116 insertions(+), 16 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910053354.26721-1-wangkefeng.wang%40huawei.com.
