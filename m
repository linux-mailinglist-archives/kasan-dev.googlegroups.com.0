Return-Path: <kasan-dev+bncBAABBQOQW7UQKGQEGXFUG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D984D6AB63
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 17:07:47 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id m1sf9924653vkl.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 08:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563289666; cv=pass;
        d=google.com; s=arc-20160816;
        b=S1wzgsyGaQsaW/SoD/V1qie26/PrdQtYVQUxJZjwpd+IuYzcV+Y78CY8HWMnYigMwf
         1uaT9Z3f9JBsOhQiLUbf7gJYPyWZFNneJXuMkUzRL4VZgZCDoCStgSISoM4BQci5Eom6
         irVmIWuXsTXqSIP5fWzauFSgRSW4A/1bDVjK1Ewku5mWruN1skLREhiQJN9KYcpv+JtF
         aFsyUyTc1118zXgCyG73roloZ/85EFGYnWyrU1ue+jhGJDpoOsfipyq2wABnJ3pXkDe2
         dRw4YcouTFzneyXJ9H5CyJ2WlKkr0PKuveHUJ81SI/JFZvzn+C1lG5V32QjjTp88VKat
         wJfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :user-agent:date:message-id:cc:to:subject:from:sender:dkim-signature;
        bh=2chQJc4zRjxnTbj5u8TliDuOtdB6VBNPn8RVF/D/XRA=;
        b=dfbgOBqbY4OC8YGqFdZpMf6ms8DEASzBCA6LocBzh0jEFY5iai4uIxZwRum5/Xqycn
         VgtNQkvluPubN8Ky7RM5lJTmMXggZ0n13JL6Hu6m+mMnXFpQsrT/55deyRVLtC34CAGP
         iuzV1qNVOq/MuJeFDp6lOsi88RoU+fKm0g6gIfXJBca01Y/1n6Rp27KVSp1GrTGwGLdF
         92WpcKLCaQEP1dRPJIG851vDop8vgvxZhLdQpy2ehrMWY8gFzF0sTSfeKgV+4C+ILT90
         27OJAew1CgWc1CvYcIvbh01uM0048aq3kqejs1/5Vtnn4ffgA5sdPAicW/Vt65pe/zde
         1WKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:message-id:date:user-agent:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2chQJc4zRjxnTbj5u8TliDuOtdB6VBNPn8RVF/D/XRA=;
        b=qwXlKOfnp6svm7m55lVgjweVs5QKLnEMT2YxnIIxaEnlELFQwZSUEXF/XhvuaPRlOq
         b0y83i74GsiihxraAqNHLRgjjjZDh6YRWtQx+nWQ3Gv+H+xbjyZoBPKg6V5ZP4Sz014g
         8TYRNSh/UpicZ8bVjxvV75IRTOw2AFdxj2qmheOo1a6Idr/J/dA6LCCDoEeV/M4UgHew
         B6D4Cwk/AOEVOFder7yRs5Tj8HyZz6UDu1r0iUEM+CiXk09oSXexIw9fwVpDLk3/d2cu
         YkgzmckZyds2WhkxXTyvbh+B7yrzVrMnPRZ8GfKMCeOGmYM4BrC0a2AK/OPeJ5j/cC4G
         jQJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:message-id:date
         :user-agent:mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2chQJc4zRjxnTbj5u8TliDuOtdB6VBNPn8RVF/D/XRA=;
        b=QI3gdHx6fYVken0pe+QbhLc3BiLqywieFWLs3o58SmPuEr1WAQcQh/8LmRAkU9we5D
         M2rlrsiAe6hZERpWo10kJYm2978BQQdj+wcwJZM0w4B46jMryygC4au8IrNaRjFL9AN9
         v4Dz1VbuL3TyWuBLFYMZHvy/PpPCR8vMWM8LHgeh48zaGWq8R70lc0Lt85Vuu3Y3cB0D
         DvL8QwSrBPO8Aw0gvuXEckDrGCQBr5ocKOTd+nwvb6rrTIhC1zBG7lFYVdCxoCHZkBN9
         tYAvUhZKW5YXaITdg6L+M+5NMKt3qjjtDG2D1ZA0NISG++x052Y/11v+ZSUIRVUDbRvv
         ub1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOHZ/EfjG0A6AlFTfvbz4V+vN+5dewaOyPe78LceyOVdOomPq6
	wfAiReKrUwRGs8SgCdyz0Yc=
X-Google-Smtp-Source: APXvYqw9t2+j51fvP4QgrECRCNCxcO2CaQr1tdbXGFR9783srRPM6Nj6VbyrdIdF2ddS6U/AFLlrEg==
X-Received: by 2002:a1f:2b07:: with SMTP id r7mr12635639vkr.65.1563289666753;
        Tue, 16 Jul 2019 08:07:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6787:: with SMTP id v7ls1475758uar.0.gmail; Tue, 16 Jul
 2019 08:07:45 -0700 (PDT)
X-Received: by 2002:ab0:3007:: with SMTP id f7mr1223028ual.12.1563289665428;
        Tue, 16 Jul 2019 08:07:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563289665; cv=none;
        d=google.com; s=arc-20160816;
        b=hO0PFvVsQSze+slCpMu24BzC4BYHnUyP+Tyms9N2zsejGw/g4vjagDxuMPdCnI0MhS
         8lvn+7/j95UZHH7Yrv7hdjQL5jyVQcH7Z0CQjoiG68G+0wq4YgrcEBOI7Emw4NI7MIQi
         rZraFSASjxKWK721mXvZnfOH8Cx8q/uZDFyq9bdJOKzcxdTj+RgRrjTksY7oSeKOjykf
         AnnZzP7FVRMxPmS7BLni+/HaKklPeHYdCTDhlO7RSs8o4R+Y3M/yqFm6HGs7LXtl8NJv
         msV483qT4kyRou+Ti3ySahxNubINlceM5hZaf8WfLZE3RTTqDtMpKVnz8tUiHkrAQoLc
         9CGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version:user-agent
         :date:message-id:cc:to:subject:from;
        bh=kS5XzNE/JOhNSaAgE/Xu4OzRmof5zZE1h0WMis96O20=;
        b=K9NsS2B8/eqYIL0lxMi2Hb2FaiL9nXxLC1pN88pXpDvKUFX4W58JqgOJnjmqnsXFhx
         pITfVGBiMGuLgooB8lHJ4CtYLaiTrJYkX2zhgz0vwos9AAvJwHowRlWH7Kttlf1ey5lB
         zeuy6l96v9cCtiv9br3SttOQSnKZU7b7euJEn0xNejycT29Si2QrQaUqFkpKDizezbja
         A+7ANxwSXBhBadqorX/vpAo3c0nXOr2NfROG1UG8pk8OZuuFdisJL1lLauscv4f5RmvZ
         Wg3U5fi+vcXGiYHFkfQ6y5YRPJGoAGjHzo2RzuE/mSgFtCg2wRrDuruQi+UNvzMCsP5b
         46qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
Received: from huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id b5si894087vsd.2.2019.07.16.08.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jul 2019 08:07:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from DGGEMS404-HUB.china.huawei.com (unknown [172.30.72.60])
	by Forcepoint Email with ESMTP id 6FD8436EF5574397A8B3;
	Tue, 16 Jul 2019 23:07:42 +0800 (CST)
Received: from [127.0.0.1] (10.184.12.158) by DGGEMS404-HUB.china.huawei.com
 (10.3.19.204) with Microsoft SMTP Server id 14.3.439.0; Tue, 16 Jul 2019
 23:07:32 +0800
From: Zenghui Yu <yuzenghui@huawei.com>
Subject: BUG: KASAN: slab-out-of-bounds in kvm_pmu_get_canonical_pmc+0x48/0x78
To: <kvmarm@lists.cs.columbia.edu>
CC: Marc Zyngier <marc.zyngier@arm.com>, <andrew.murray@arm.com>,
	<kasan-dev@googlegroups.com>, <kvm@vger.kernel.org>
Message-ID: <644e3455-ea6d-697a-e452-b58961341381@huawei.com>
Date: Tue, 16 Jul 2019 23:05:14 +0800
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101
 Thunderbird/64.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.184.12.158]
X-CFilter-Loop: Reflected
X-Original-Sender: yuzenghui@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuzenghui@huawei.com designates 45.249.212.32 as
 permitted sender) smtp.mailfrom=yuzenghui@huawei.com
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

Hi folks,

Running the latest kernel with KASAN enabled, we will hit the following
KASAN BUG during guest's boot process.

I'm in commit 9637d517347e80ee2fe1c5d8ce45ba1b88d8b5cd.

Any problems in the chained PMU code? Or just a false positive?

---8<---

[  654.706268] 
==================================================================
[  654.706280] BUG: KASAN: slab-out-of-bounds in 
kvm_pmu_get_canonical_pmc+0x48/0x78
[  654.706286] Read of size 8 at addr ffff801d6c8fea38 by task 
qemu-kvm/23268

[  654.706296] CPU: 2 PID: 23268 Comm: qemu-kvm Not tainted 5.2.0+ #178
[  654.706301] Hardware name: Huawei TaiShan 2280 /BC11SPCD, BIOS 1.58 
10/24/2018
[  654.706305] Call trace:
[  654.706311]  dump_backtrace+0x0/0x238
[  654.706317]  show_stack+0x24/0x30
[  654.706325]  dump_stack+0xe0/0x134
[  654.706332]  print_address_description+0x80/0x408
[  654.706338]  __kasan_report+0x164/0x1a0
[  654.706343]  kasan_report+0xc/0x18
[  654.706348]  __asan_load8+0x88/0xb0
[  654.706353]  kvm_pmu_get_canonical_pmc+0x48/0x78
[  654.706358]  kvm_pmu_stop_counter+0x28/0x118
[  654.706363]  kvm_pmu_vcpu_reset+0x60/0xa8
[  654.706369]  kvm_reset_vcpu+0x30/0x4d8
[  654.706376]  kvm_arch_vcpu_ioctl+0xa04/0xc18
[  654.706381]  kvm_vcpu_ioctl+0x17c/0xde8
[  654.706387]  do_vfs_ioctl+0x150/0xaf8
[  654.706392]  ksys_ioctl+0x84/0xb8
[  654.706397]  __arm64_sys_ioctl+0x4c/0x60
[  654.706403]  el0_svc_common.constprop.0+0xb4/0x208
[  654.706409]  el0_svc_handler+0x3c/0xa8
[  654.706414]  el0_svc+0x8/0xc

[  654.706422] Allocated by task 23268:
[  654.706429]  __kasan_kmalloc.isra.0+0xd0/0x180
[  654.706435]  kasan_slab_alloc+0x14/0x20
[  654.706440]  kmem_cache_alloc+0x17c/0x4a8
[  654.706445]  kvm_arch_vcpu_create+0xa0/0x130
[  654.706451]  kvm_vm_ioctl+0x844/0x1218
[  654.706456]  do_vfs_ioctl+0x150/0xaf8
[  654.706461]  ksys_ioctl+0x84/0xb8
[  654.706466]  __arm64_sys_ioctl+0x4c/0x60
[  654.706472]  el0_svc_common.constprop.0+0xb4/0x208
[  654.706478]  el0_svc_handler+0x3c/0xa8
[  654.706482]  el0_svc+0x8/0xc

[  654.706490] Freed by task 0:
[  654.706493] (stack is not available)

[  654.706501] The buggy address belongs to the object at ffff801d6c8fc010
  which belongs to the cache kvm_vcpu of size 10784
[  654.706507] The buggy address is located 8 bytes to the right of
  10784-byte region [ffff801d6c8fc010, ffff801d6c8fea30)
[  654.706510] The buggy address belongs to the page:
[  654.706516] page:ffff7e0075b23f00 refcount:1 mapcount:0 
mapping:ffff801db257e480 index:0x0 compound_mapcount: 0
[  654.706524] flags: 0xffffe0000010200(slab|head)
[  654.706532] raw: 0ffffe0000010200 ffff801db2586ee0 ffff801db2586ee0 
ffff801db257e480
[  654.706538] raw: 0000000000000000 0000000000010001 00000001ffffffff 
0000000000000000
[  654.706542] page dumped because: kasan: bad access detected

[  654.706549] Memory state around the buggy address:
[  654.706554]  ffff801d6c8fe900: 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00
[  654.706560]  ffff801d6c8fe980: 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00
[  654.706565] >ffff801d6c8fea00: 00 00 00 00 00 00 fc fc fc fc fc fc fc 
fc fc fc
[  654.706568]                                         ^
[  654.706573]  ffff801d6c8fea80: fc fc fc fc fc fc fc fc fc fc fc fc fc 
fc fc fc
[  654.706578]  ffff801d6c8feb00: fc fc fc fc fc fc fc fc fc fc fc fc fc 
fc fc fc
[  654.706582] 
==================================================================


Thanks,
zenghui

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/644e3455-ea6d-697a-e452-b58961341381%40huawei.com.
For more options, visit https://groups.google.com/d/optout.
