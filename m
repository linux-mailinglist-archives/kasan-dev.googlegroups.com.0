Return-Path: <kasan-dev+bncBAABBB5ZXDUQKGQE5KO4RQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF0CA6AF26
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 20:50:48 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id g2sf10969321wrq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 11:50:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563303048; cv=pass;
        d=google.com; s=arc-20160816;
        b=reYdFIqdpaxft+vOhWCHsOdzlc/wJhLzYabU2kCzXa6F9cQds/FfDiFiVdrJkUN31i
         ab4+BhJddwPihwdzM8U5GrUnsUROh/256cynlB1Fa26jyyh0Xwxy4UUwnccHjmNxAo9Q
         hda7dOKZix5AfnBDEReWi9X0rlwOvR7zuuTN3+PEfmJPLDF4Q5X44n1i5K/L91xuPgqh
         DtNrGs2rI8PfjjlXE5hzG3G+BHBTUSA07b0AFWUQT83bFwzJy6bwUvYyLD6nd9HFU0Fi
         IN6LPZLUUR9hGc2I2qYMxy0Y55nburx1QaJ1rjCe/dseIEFmZdooWLVb6ytRtHg5FMTC
         nj+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Q6KuQYAGFGeNbbcHQbv2jhT1/D1HIAHEcngIxkxAdZA=;
        b=FcQqcyLyMyBBBq5lDZOpHydWAAsqhHuh2lssDwynoLC5rjJadnpxIgaaTdNfyHRaz1
         eeiupHjGLDNItEvHopGC3KgHscfeIBSRU4kOAVhopFhq80mXtpk6fg7LA6orqd4xZvqc
         KAvQ7YBY9lt+C6Hoe6KOAFsEBWxv9YyCHmctSigcTO6lkJxdMAl5WOkFF+/EnOhcQMWV
         E27CAh9o3o8bZMg4tRJfoCsEcQrg1o8gO13dLxvOFK8TDUox07apiOh/3VlBdZVmkipK
         0FTjVfsG5EtIRiJCn9vlMdGS7JCtjHPshqqJTzOHm6KYHxQFBTYPRrjFQkSmn7ESMobw
         Grug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andrew.murray@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=andrew.murray@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q6KuQYAGFGeNbbcHQbv2jhT1/D1HIAHEcngIxkxAdZA=;
        b=YPDnCm6vQBMsqFTtX1VnKAHKDBZuz/AAtBQXyYCNrlLC7TrDuKc9Q0ZtgihF3rOfU+
         7D3YsF8sRziUCqCbfAPCVe02brvopmSzY1EUhoNuom14McbpfnsKa49e05NUx/Q+xq7U
         sIMiETbcgDtk/1XQGA6SU60Ag0ykcm1HEg2YY47DtcMF24DDoQDqsJ5tptguhmtHwcYz
         XTF3+Mr/pqojHtvja30/xA9SNVuOr8u2HtYxDE6alwCRuxSYNOPbN1jtVfKnEtQp6+n4
         D5ZnI66us7p6khMwnl86lAsk5rSEkmptQKrpL9pysoonXJJsbvQPu8iEmT/xSTXqb7pw
         VgUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q6KuQYAGFGeNbbcHQbv2jhT1/D1HIAHEcngIxkxAdZA=;
        b=PAu3ZS80hw6KOPL6QmZLGR+R7e6Wi54rub6Ths9PfQw5Hb4//tnttT8pVOXjIcH0mU
         qRsTtJH85E2bNhqyadmjq0G/A41p5z8KBEGqsgHfuSpCMnGrKlcUqpaSLZr6U83LvR8H
         fNC6HZoa445NEXuU32doWUHtO7xzrHlYMjl7qjD0jA27mNMS55eVTvp5OyTNRTCB+pRq
         xcT2E00V8L2HQnwb5EZLeSrdxewdJRk5WWqZ6luPmd4SDYkBgx6GPdKgIHRCP1ADMd9a
         EOii9tGeWKos5DZzgviGSsKly5TlxqOGnkwXLnFMjHHnTNbJ1JdlH3f57bZx3OYqw1pw
         t91w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUJJeY5tJ9b27raawDtVHIPYylLypridPKWCfdr5Lg+iNOStQ2v
	UxbF341TWZn5gUwz9qIhzlY=
X-Google-Smtp-Source: APXvYqyCy+fsw/8dHef25GyysTirMDj9sJQNOh2jFMtD5n4HKfd7fZpSjJ7SJIIMqnwi3oJcolizOg==
X-Received: by 2002:a05:600c:20ca:: with SMTP id y10mr1734873wmm.72.1563303047696;
        Tue, 16 Jul 2019 11:50:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a745:: with SMTP id e5ls6982743wrd.5.gmail; Tue, 16 Jul
 2019 11:50:47 -0700 (PDT)
X-Received: by 2002:a5d:4602:: with SMTP id t2mr24430093wrq.340.1563303047334;
        Tue, 16 Jul 2019 11:50:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563303047; cv=none;
        d=google.com; s=arc-20160816;
        b=dPe8lw1VSHm/dgbVLWH1y1tLDCT9p38GGhXpsHGgwTPG7sCTmvn5DhOSi/eH2iFkrP
         ndCS4VCyVp6W+dzZgT9JpFv2KRnQj1OycbuAQFrPWWHRPky6S8jbbqcdRZtEobveNDZg
         EnvB7z7m83uIulHoF0mcmsUiq2tfgIN0G6tgL109VP0sbymbkF8agB7d8Y0Fb6lx398H
         Y4rBGfN57rbdtrkGzNted/dIW9CpeYyAI8pUaqA+igvaMoG555YHb6zPADg3WNRYq+vk
         L3c+S9JMYkiBOM1aIWDgTK0EFoySVtbxtVkBCTSFbTSZf1FeMhb4vXxXDU136ZEhqzzm
         wQmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=zG0MKhsNI5yKkIcCNQHsYn7i8thkAjImh1tShMAL/Dc=;
        b=uQAnT1DHX1vaA+OvjOOAiiG5lvgq40la0jmeZT5EpuHPI/qSI0RU4PjM/OBbEG6gkx
         w5kq2rvdo3coP4IOuGLaL5/k7tOk0y8+vK/PR4QTnVBXAHMCmATa7GXXtW3tKVle2sti
         Qk155j3SwKySAOM1nDUT8GNe3k1x3sXggBRzS2aXffQZCsJHCHUas6EmW1cyyR/pjynd
         1uXLQKs+5R5ffxyhTMtzmiDu49MWYr2taByFm015YD+LtKR5gSr4ZHXaJYQJI+pinq6Z
         1/nUM0PAXLqVmgdcKvUsYM5mOOXphsdBpTzeKfyyG5YpLc7e+qmSEbVU+yXtyuuZF2Y+
         EGkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andrew.murray@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=andrew.murray@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u16si898240wrr.0.2019.07.16.11.50.47
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Jul 2019 11:50:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrew.murray@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4FEEF2B;
	Tue, 16 Jul 2019 11:50:46 -0700 (PDT)
Received: from localhost (unknown [10.37.6.20])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BB7E83F59C;
	Tue, 16 Jul 2019 11:50:45 -0700 (PDT)
Date: Tue, 16 Jul 2019 19:50:44 +0100
From: Andrew Murray <andrew.murray@arm.com>
To: Zenghui Yu <yuzenghui@huawei.com>
Cc: kvmarm@lists.cs.columbia.edu, Marc Zyngier <marc.zyngier@arm.com>,
	kasan-dev@googlegroups.com, kvm@vger.kernel.org,
	"Wanghaibin (D)" <wanghaibin.wang@huawei.com>
Subject: Re: BUG: KASAN: slab-out-of-bounds in
 kvm_pmu_get_canonical_pmc+0x48/0x78
Message-ID: <20190716185043.GV7227@e119886-lin.cambridge.arm.com>
References: <644e3455-ea6d-697a-e452-b58961341381@huawei.com>
 <f9d5d18a-7631-f3e2-d73a-21d8eee183f1@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <f9d5d18a-7631-f3e2-d73a-21d8eee183f1@huawei.com>
User-Agent: Mutt/1.10.1+81 (426a6c1) (2018-08-26)
X-Original-Sender: andrew.murray@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of andrew.murray@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=andrew.murray@arm.com
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

On Tue, Jul 16, 2019 at 11:14:37PM +0800, Zenghui Yu wrote:
>=20
> On 2019/7/16 23:05, Zenghui Yu wrote:
> > Hi folks,
> >=20
> > Running the latest kernel with KASAN enabled, we will hit the following
> > KASAN BUG during guest's boot process.
> >=20
> > I'm in commit 9637d517347e80ee2fe1c5d8ce45ba1b88d8b5cd.
> >=20
> > Any problems in the chained PMU code? Or just a false positive?
> >=20
> > ---8<---
> >=20
> > [=C2=A0 654.706268]
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [=C2=A0 654.706280] BUG: KASAN: slab-out-of-bounds in
> > kvm_pmu_get_canonical_pmc+0x48/0x78
> > [=C2=A0 654.706286] Read of size 8 at addr ffff801d6c8fea38 by task
> > qemu-kvm/23268
> >=20
> > [=C2=A0 654.706296] CPU: 2 PID: 23268 Comm: qemu-kvm Not tainted 5.2.0+=
 #178
> > [=C2=A0 654.706301] Hardware name: Huawei TaiShan 2280 /BC11SPCD, BIOS =
1.58
> > 10/24/2018
> > [=C2=A0 654.706305] Call trace:
> > [=C2=A0 654.706311]=C2=A0 dump_backtrace+0x0/0x238
> > [=C2=A0 654.706317]=C2=A0 show_stack+0x24/0x30
> > [=C2=A0 654.706325]=C2=A0 dump_stack+0xe0/0x134
> > [=C2=A0 654.706332]=C2=A0 print_address_description+0x80/0x408
> > [=C2=A0 654.706338]=C2=A0 __kasan_report+0x164/0x1a0
> > [=C2=A0 654.706343]=C2=A0 kasan_report+0xc/0x18
> > [=C2=A0 654.706348]=C2=A0 __asan_load8+0x88/0xb0
> > [=C2=A0 654.706353]=C2=A0 kvm_pmu_get_canonical_pmc+0x48/0x78
>=20
> I noticed that we will use "pmc->idx" and the "chained" bitmap to
> determine if the pmc is chained, in kvm_pmu_pmc_is_chained().
>=20
> Should we initialize the idx and the bitmap appropriately before
> doing kvm_pmu_stop_counter()?  Like:

Hi Zenghui,

Thanks for spotting this and investigating - I'll make sure to use KASAN
in the future when testing...

>=20
>=20
> diff --git a/virt/kvm/arm/pmu.c b/virt/kvm/arm/pmu.c
> index 3dd8238..cf3119a 100644
> --- a/virt/kvm/arm/pmu.c
> +++ b/virt/kvm/arm/pmu.c
> @@ -224,12 +224,12 @@ void kvm_pmu_vcpu_reset(struct kvm_vcpu *vcpu)
>  	int i;
>  	struct kvm_pmu *pmu =3D &vcpu->arch.pmu;
>=20
> +	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
> +
>  	for (i =3D 0; i < ARMV8_PMU_MAX_COUNTERS; i++) {
> -		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
>  		pmu->pmc[i].idx =3D i;
> +		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
>  	}
> -
> -	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
>  }

We have to be a little careful here, as the vcpu may be reset after use.
Upon resetting we must ensure that any existing perf_events are released -
this is why kvm_pmu_stop_counter is called before bitmap_zero (as
kvm_pmu_stop_counter relies on kvm_pmu_pmc_is_chained).

(For example, by clearing the bitmap before stopping the counters, we will
attempt to release the perf event for both pmc's in a chained pair. Whereas
we should only release the canonical pmc. It's actually OK right now as we
set the non-canonical pmc perf_event will be NULL - but who knows that this
will hold true in the future. The code makes the assumption that the
non-canonical perf event isn't touched on a chained pair).

The KASAN bug gets fixed by moving the assignment of idx before=20
kvm_pmu_stop_counter. Therefore I'd suggest you drop the bitmap_zero hunks.

Can you send a patch with just the idx assignment hunk please?

Thanks,

Andrew Murray

>=20
>  /**
>=20
>=20
> Thanks,
> zenghui
>=20
> > [=C2=A0 654.706358]=C2=A0 kvm_pmu_stop_counter+0x28/0x118
> > [=C2=A0 654.706363]=C2=A0 kvm_pmu_vcpu_reset+0x60/0xa8
> > [=C2=A0 654.706369]=C2=A0 kvm_reset_vcpu+0x30/0x4d8
> > [=C2=A0 654.706376]=C2=A0 kvm_arch_vcpu_ioctl+0xa04/0xc18
> > [=C2=A0 654.706381]=C2=A0 kvm_vcpu_ioctl+0x17c/0xde8
> > [=C2=A0 654.706387]=C2=A0 do_vfs_ioctl+0x150/0xaf8
> > [=C2=A0 654.706392]=C2=A0 ksys_ioctl+0x84/0xb8
> > [=C2=A0 654.706397]=C2=A0 __arm64_sys_ioctl+0x4c/0x60
> > [=C2=A0 654.706403]=C2=A0 el0_svc_common.constprop.0+0xb4/0x208
> > [=C2=A0 654.706409]=C2=A0 el0_svc_handler+0x3c/0xa8
> > [=C2=A0 654.706414]=C2=A0 el0_svc+0x8/0xc
> >=20
> > [=C2=A0 654.706422] Allocated by task 23268:
> > [=C2=A0 654.706429]=C2=A0 __kasan_kmalloc.isra.0+0xd0/0x180
> > [=C2=A0 654.706435]=C2=A0 kasan_slab_alloc+0x14/0x20
> > [=C2=A0 654.706440]=C2=A0 kmem_cache_alloc+0x17c/0x4a8
> > [=C2=A0 654.706445]=C2=A0 kvm_arch_vcpu_create+0xa0/0x130
> > [=C2=A0 654.706451]=C2=A0 kvm_vm_ioctl+0x844/0x1218
> > [=C2=A0 654.706456]=C2=A0 do_vfs_ioctl+0x150/0xaf8
> > [=C2=A0 654.706461]=C2=A0 ksys_ioctl+0x84/0xb8
> > [=C2=A0 654.706466]=C2=A0 __arm64_sys_ioctl+0x4c/0x60
> > [=C2=A0 654.706472]=C2=A0 el0_svc_common.constprop.0+0xb4/0x208
> > [=C2=A0 654.706478]=C2=A0 el0_svc_handler+0x3c/0xa8
> > [=C2=A0 654.706482]=C2=A0 el0_svc+0x8/0xc
> >=20
> > [=C2=A0 654.706490] Freed by task 0:
> > [=C2=A0 654.706493] (stack is not available)
> >=20
> > [=C2=A0 654.706501] The buggy address belongs to the object at ffff801d=
6c8fc010
> >  =C2=A0which belongs to the cache kvm_vcpu of size 10784
> > [=C2=A0 654.706507] The buggy address is located 8 bytes to the right o=
f
> >  =C2=A010784-byte region [ffff801d6c8fc010, ffff801d6c8fea30)
> > [=C2=A0 654.706510] The buggy address belongs to the page:
> > [=C2=A0 654.706516] page:ffff7e0075b23f00 refcount:1 mapcount:0
> > mapping:ffff801db257e480 index:0x0 compound_mapcount: 0
> > [=C2=A0 654.706524] flags: 0xffffe0000010200(slab|head)
> > [=C2=A0 654.706532] raw: 0ffffe0000010200 ffff801db2586ee0 ffff801db258=
6ee0
> > ffff801db257e480
> > [=C2=A0 654.706538] raw: 0000000000000000 0000000000010001 00000001ffff=
ffff
> > 0000000000000000
> > [=C2=A0 654.706542] page dumped because: kasan: bad access detected
> >=20
> > [=C2=A0 654.706549] Memory state around the buggy address:
> > [=C2=A0 654.706554]=C2=A0 ffff801d6c8fe900: 00 00 00 00 00 00 00 00 00 =
00 00 00 00
> > 00 00 00
> > [=C2=A0 654.706560]=C2=A0 ffff801d6c8fe980: 00 00 00 00 00 00 00 00 00 =
00 00 00 00
> > 00 00 00
> > [=C2=A0 654.706565] >ffff801d6c8fea00: 00 00 00 00 00 00 fc fc fc fc fc=
 fc fc
> > fc fc fc
> > [=C2=A0 654.706568]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
> > [=C2=A0 654.706573]=C2=A0 ffff801d6c8fea80: fc fc fc fc fc fc fc fc fc =
fc fc fc fc
> > fc fc fc
> > [=C2=A0 654.706578]=C2=A0 ffff801d6c8feb00: fc fc fc fc fc fc fc fc fc =
fc fc fc fc
> > fc fc fc
> > [=C2=A0 654.706582]
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20190716185043.GV7227%40e119886-lin.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
