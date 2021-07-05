Return-Path: <kasan-dev+bncBCRKFI7J2AJRB4WPRODQMGQEGMMT47A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B9333BBBF3
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:07:32 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id c24-20020a1709028498b0290128cdfbb2f1sf6257213plo.14
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483251; cv=pass;
        d=google.com; s=arc-20160816;
        b=yCqq3HB/0pCf9/HkAk5i/y/YeySm/VUWsoxmVCushceIDtvdZ0P7yOs6pc2+jefyQZ
         YPqWCj/yjblSVYNBweEtFNG/gr9sHl5qxLqzjhHq+wkUBOs2Rwc+Lt3epVkctVTeDc5l
         llGRZLlAIiAPgT7VllDuWdnPXgo+iGE3NWxudvpbdtbUiJ1/XF2L+vdQQThluB8ipbN6
         IdYbRclrLloTWiDgB0Hb8gBAoc++/gEx8uydEEI3ZKOqBX/wb+QVQFW+W8iOj3c7K65l
         NApLbDAVk/lEY0UmBF+10eEjbPMFGzXy8injD8UjzkcQld2pJl6S0HMCKeh5uQZ5zpKV
         f+gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=st4CNpJGrsvKmIIKmvdnX1SpsVW9VoJB3e8N7+27gdQ=;
        b=k5726FwEjVstRcBdSjNi567jniI8yYvmCePd2gsG7JAILKGUM1+jRG4nPds7q+jYJn
         gjok9nqA+r9Nb44te2HnR8lx5hlogvm7HbZMxV5atkYFbYQERfAxfZF22zE6V7NAoAu+
         26ysccVnBdRsuJEP+LO6wgK+QuZ6piH9nAVmgSEAfkjvcGgFSXVph7/fJkGn3YZr5Rji
         2holaOoDYvuTzAmoxA83q9biym1ZTeYwdBCin0jh50UpMAhzSsY5eX2aV5Ey79zqFB2/
         /PvfUCqeBHfClIpgR+z0JKBuz2pazOJuVh+dzaZSVGr0wzUPVeU6lZzSsTRjpBpNsx2O
         dw9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=st4CNpJGrsvKmIIKmvdnX1SpsVW9VoJB3e8N7+27gdQ=;
        b=D1M1p6Td9EvcM0d57LsmEHtEkT9kaomje1evge0baBA6hukriP9W1JfaK7i40aJ50Q
         B4+LWvBk5p1EXyRyDyJdcbFS+sHOAKO67SiF76jZafpIajf6HMXEDRDPtzJlvrKSQKZz
         4N86QM4dRkPh7AWQtD4PlPyJiCK24NAoXX/g4W8hdAe+YSC0sN8PPyN8URZ4UPbGzqOV
         /R5aABtQbXxbtaKG9C8wLkK/Lqx9TbDH3GntgpT9z+CbFksfAa5D+qPYfE+FqfmcHFoE
         G44LSOqw5VASTtIOjxlpT39nDEVrDa6AwtExTv6ddhwOiSU5MsIkFtwEwWme1OlO/hIS
         yJ5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=st4CNpJGrsvKmIIKmvdnX1SpsVW9VoJB3e8N7+27gdQ=;
        b=JupoKk7uL1iXMmIrH7Gl2xi52ridqJEKJyhRFOMUXtYY819TaSWnhIOpANX35uoQSQ
         FgF/RXtqGIEhB9gWQ3YmDIj03026GiXc+jfED9+0y6larhMfnTqul37XqjVYwG8SRzXV
         xvVNDLYMMBlbSkq+u00ABmiuEKBEIVA5VsoktZtGLlO6avm6iXhjCbAqLWhGiywVE7YM
         cVPQD91vsNtXXl0Yfap9/swSrXAuQ+fK4E6cZDhmGSb0RLkcs48B4V+SForQ2F2efYro
         yPVvEO8kpcIdGemiG0bBi6OC0efr/C6i5D1tyEUZcS5jvN7qmP6Q1zPPCeVHZvXipCDE
         owCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xrq41RM+8MPrrX8d+AqR5y1Ypm0MIv9jKA2JJRui/4FEEKnbi
	+OfoePvSFpgbB2NtsYmzw3k=
X-Google-Smtp-Source: ABdhPJzJHXWRXfzdOmIHxkh7WA8Fc+nocwNrNiiAV6DVLU2vNbs+TF/40Lu7lpSjRgBUZThi0QLmPA==
X-Received: by 2002:a65:63ce:: with SMTP id n14mr15041651pgv.273.1625483250840;
        Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8410:: with SMTP id j16ls13151377pjn.2.canary-gmail;
 Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
X-Received: by 2002:a17:90b:3756:: with SMTP id ne22mr15247944pjb.197.1625483250387;
        Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483250; cv=none;
        d=google.com; s=arc-20160816;
        b=K9Yk2Cj8D8TU+iGufU9R0Lg40ucptG5oWS0QA2v4s65b+7uEuwO49QSECHpf43sCa0
         oIq5maKi4B7U2lzK/G1o5POOb1qzv9/q+TR+NJqKc0rEz3fR0x0IwexZYM9iUWUUmuvX
         OHwrT5035imbyYqbRAP5rHbIqVdZ5rUy6SDJzlerNt4CGQyr6rjgTokrRG/fN2gAyUsS
         rdu+vBbG0HsGSmnUxiAWmbBSwFONH3KzHnIDDQYjbrzc4Bc1vZXX8MPOIdK6mJatJ+tI
         VUtmE6msniinaJAbDSNrhWoBKCNRgeo+S1pXq3VviIiPYF2eWnER4XzTvndZiz9a2oU/
         9KjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=h9jfEEYCdIPf1zLDYpmi8ybqavv+3ORuVka1ZxIASak=;
        b=YnxJki/sOoTBbcRbO525bewnn7Yx44C4MKcSYIp6Xsz1qBFwKT0BFsalGX+crqhWuK
         Hqt7IyQ9uh6Wg/J3IO5pjIuynaZLTtB6ax5m71h4j2ctw37ejtAA6W4UITCu6dp0i1jb
         KXtIwuUtPimYTA6tVt8QnrBO4q1Gnt6FCJuqyuB75xLeESljljX9dN9Pao7DNxPvSwcu
         6z0AWyuao5A2kTykZPKpRAWvDyK0hRd9kRj7LlS04DL+Qjiit3JFIde/11lrSu2J0dwY
         5VuF2OTlWaIhbKcPClahx8B6Y/5LCDxvGL5wQo+Yi0unjzguFKTh04HkolvQ9xTKsHE4
         7lBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id g7si63080pju.0.2021.07.05.04.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4GJN8F16nMz75YK;
	Mon,  5 Jul 2021 19:03:09 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:28 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:27 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH -next 0/3] arm64: support page mapping percpu first chunk allocator
Date: Mon, 5 Jul 2021 19:14:50 +0800
Message-ID: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
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
the system can't boot successfully.

Let's implement page mapping percpu first chunk allocator as a fallback
to the embedding allocator to increase the robustness of the system.

Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLOC enabled.

Tested on ARM64 qemu with cmdline "percpu_alloc=page" based on next-20210630.

Kefeng Wang (3):
  vmalloc: Choose a better start address in vm_area_register_early()
  arm64: Support page mapping percpu first chunk allocator
  kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC

 arch/arm64/Kconfig         |  4 ++
 arch/arm64/mm/kasan_init.c | 18 +++++++++
 drivers/base/arch_numa.c   | 82 +++++++++++++++++++++++++++++++++-----
 include/linux/kasan.h      |  2 +
 mm/kasan/init.c            |  5 +++
 mm/vmalloc.c               |  9 +++--
 6 files changed, 107 insertions(+), 13 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705111453.164230-1-wangkefeng.wang%40huawei.com.
