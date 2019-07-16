Return-Path: <kasan-dev+bncBAABBNGVW7UQKGQEAGGPUJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E8B536AB7F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 17:18:12 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e14sf4680219ljj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2019 08:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563290292; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsSgCEDJ3BZtkJ8uhRACT7RnPMtK+ikGu+iTpUte/fi0jw59loW12TbDgJGCyRcEZu
         uDMk2OY+iuzheHFw2Mpg+QsBg0rup+BvNjuaVKro7aGJa5IEshgqFKgC+0imcfjrpb9b
         rcRb07iMsW3r5IoimVNTu17LmB3vKmstELYrtJEv8VNIWJPbfD3TvHPOsIqcOwTy0VdE
         /C4uMZ3WvrhC54zPlR05hHbWJF0aq0/GWKHIkNerTXsmtbTOnHU8JFpa+hrwHf2qt/At
         e8j8Ktrj0VMjpdZr8xKtaK1PEM/jZVX1UA8DuOFXJmVupRy8mxa+Ap/EHXyvakgzNVPW
         i5gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=GV9RuvUsKBdaVqZRciawNLkRfjAZR/xYy5jZwKw+/wY=;
        b=T7rLSoOerahmxeEk9SQHf1K245jf4+mnfClzcdnMZIxSvYG09xfPFlD0S6aBcjU6uw
         r2JVVRAByvQQzTWWVN2zrCwEjyYdBa3nCEAIMMlIOXn+2/b3iXSDpP58uyNeZ1yUMgqS
         ExKP4Vw6q+fCcNuytcP6s7HdHo9SLYu5+Q0GcaFFPVwAuwCGqHsT965FBE4jH0IRm1RY
         9kAbXwNP+MihVjXQQ3W6R58JFa1GS0smoZP9oRlJVtePZLJa84N1sCqEUu0uMUZe/IKs
         SDWTZANO+Igm6FuIxDUSI3pj4loD6aCkMc5OJunC1yvlm6BA9Buwn3vmmQSfZ+Yh/G+A
         wU0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GV9RuvUsKBdaVqZRciawNLkRfjAZR/xYy5jZwKw+/wY=;
        b=Lqc8tMlvT1KCZx/9UBvXOdalr4Y+P7p32vSecq1LbdQCSOr5tOT9ImXj8K5uM7jOpx
         j5d5BzFjAbb9mtWbz25S1ZnUBIIcoehw4bes0rdU/iSY702MOX6plolxHPXdyYq2624Z
         EbdyxGeHgpo3g4BJvWM60FA1bEW1QiLyrUz2sxBi0lUUCa1BLISCAcCXg/kfVdRp5y1H
         xJ+5XJG2Zba2FoIytFXS37WvJnF4c0t4RSM7QTapsqXyJuBVCkAloS0rE0cwCIUgS6Ns
         xBsEukbNMXyJ6q5ys+x0Mbed4SzBipHMeePOK2eWB/PYXPlciZOjRkWuVsR/gT5DN45t
         RrUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GV9RuvUsKBdaVqZRciawNLkRfjAZR/xYy5jZwKw+/wY=;
        b=qvMr/HjZLbknceFrGlENpJvcBJ7co9+/rIMcKz8J87O+hQFnMPKf/S20chNotry2bt
         pldoetoJfodizt7CPcrGuQE6AqoGSApmr4mKsrTfXpvJDNg5kIIP8tyPbmssP8C5F2nP
         EHaREMlbzyAK4uV9KXRt7d1klCw7sifoWngTQp3ZIFxYSOrPVXfXYidHa592cxinm4Dm
         m6cs1vGkibJOTwounwUSMJdDJUCvgjxwxd95H1cu2fVgYC+rvxJpF8xBADeiR7N4QgdP
         l8tqn/qEYduMyf5BqoRfbxnxiQT5mpXq5Qo5+ZX9phLg6vvIkc+TqoU30ED/ynmz5kRj
         r3EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUszjsP+72PNpUddXfC6xpIGonA6Y8BlVB/7mp4CvMGa56JChoW
	IDdWJHh2jpaAhw/isH4Fv2Q=
X-Google-Smtp-Source: APXvYqwlrGaEJLGTIZBvlO4LGyVej5BGbpdRZ3JqDs/m2Al+sYhuu9E9OeyxG8VECIUN+y4Em5Drvg==
X-Received: by 2002:ac2:46d5:: with SMTP id p21mr14637169lfo.133.1563290292498;
        Tue, 16 Jul 2019 08:18:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4a67:: with SMTP id q7ls1675874lfp.2.gmail; Tue, 16 Jul
 2019 08:18:12 -0700 (PDT)
X-Received: by 2002:ac2:4466:: with SMTP id y6mr15116960lfl.0.1563290292199;
        Tue, 16 Jul 2019 08:18:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563290292; cv=none;
        d=google.com; s=arc-20160816;
        b=XOIzXumh877bFDRTXEHp7cTyquWUOrqruztN6zoDbGcFyOI19kqLpLgseQMINzuwRd
         0aMVPAGHGnIyOBSUAl9YkaBF/wrbThRMhmztZX3YU++FiRZVeBMaQMBWTH89Z7pKaAeV
         TG9ioXkMKBwrODBG61Mvg1KUFbdrMocpD11Z2prDJMrcdiqCvYeEFyCX4CC/AAAfMJn7
         NlvM5O/zkJ/pL9dUPob+MkhyMRnwOdcnfMrzmmYAKZVRamI/b3kmXkyfQZ/ks2h/OUpJ
         6ewpfscxq6Z5XodZxb2Hv436quK4PjMgd0/XodeX9iApSkmzpbTYxHPz05JynomYC8wP
         Rp7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=FbxgogPcLO1kJdQkdpKAvgcT35dVu+L43c00mCXnrig=;
        b=a1rxudI4q/1rzzmqaz0idLExsi/5EfnQaXiPRoTiz/a9uYJVa30s9AhTUGFZFSr3s3
         xHA8d7+Z80RI2OjhGuoQxpOMbeCNtrgoTiqefOm7m6nK5CGp38uO0gEkeyskxiCEPecx
         uSq6YqN9zLvBBISAPi64ODT5ePTNnsKjZpZB55RZwUR79/rnTJLKsaXnNYJdGZ2QsHcu
         c1FIPr/qRnc+r7fvsdBhOb1bDyfqlSY9MY2C3UkX8afJZfNLHD5fWfoAiTah1nx9KsVS
         upM8ucKiq0EHb+XgCkvjrUr+hAlBNMkwE3TaiUdHiJy7qx/zze5ogWWxD0niwotOk9co
         CXUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
Received: from huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id s14si1291923ljg.4.2019.07.16.08.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jul 2019 08:18:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from DGGEMS404-HUB.china.huawei.com (unknown [172.30.72.59])
	by Forcepoint Email with ESMTP id 500C491AD3FBB4DAFBEF;
	Tue, 16 Jul 2019 23:18:06 +0800 (CST)
Received: from [127.0.0.1] (10.184.12.158) by DGGEMS404-HUB.china.huawei.com
 (10.3.19.204) with Microsoft SMTP Server id 14.3.439.0; Tue, 16 Jul 2019
 23:17:59 +0800
Subject: Re: BUG: KASAN: slab-out-of-bounds in
 kvm_pmu_get_canonical_pmc+0x48/0x78
From: Zenghui Yu <yuzenghui@huawei.com>
To: <kvmarm@lists.cs.columbia.edu>
CC: Marc Zyngier <marc.zyngier@arm.com>, <andrew.murray@arm.com>,
	<kasan-dev@googlegroups.com>, <kvm@vger.kernel.org>, "Wanghaibin (D)"
	<wanghaibin.wang@huawei.com>
References: <644e3455-ea6d-697a-e452-b58961341381@huawei.com>
Message-ID: <f9d5d18a-7631-f3e2-d73a-21d8eee183f1@huawei.com>
Date: Tue, 16 Jul 2019 23:14:37 +0800
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101
 Thunderbird/64.0
MIME-Version: 1.0
In-Reply-To: <644e3455-ea6d-697a-e452-b58961341381@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.184.12.158]
X-CFilter-Loop: Reflected
X-Original-Sender: yuzenghui@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuzenghui@huawei.com designates 45.249.212.191 as
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


On 2019/7/16 23:05, Zenghui Yu wrote:
> Hi folks,
>=20
> Running the latest kernel with KASAN enabled, we will hit the following
> KASAN BUG during guest's boot process.
>=20
> I'm in commit 9637d517347e80ee2fe1c5d8ce45ba1b88d8b5cd.
>=20
> Any problems in the chained PMU code? Or just a false positive?
>=20
> ---8<---
>=20
> [=C2=A0 654.706268]=20
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [=C2=A0 654.706280] BUG: KASAN: slab-out-of-bounds in=20
> kvm_pmu_get_canonical_pmc+0x48/0x78
> [=C2=A0 654.706286] Read of size 8 at addr ffff801d6c8fea38 by task=20
> qemu-kvm/23268
>=20
> [=C2=A0 654.706296] CPU: 2 PID: 23268 Comm: qemu-kvm Not tainted 5.2.0+ #=
178
> [=C2=A0 654.706301] Hardware name: Huawei TaiShan 2280 /BC11SPCD, BIOS 1.=
58=20
> 10/24/2018
> [=C2=A0 654.706305] Call trace:
> [=C2=A0 654.706311]=C2=A0 dump_backtrace+0x0/0x238
> [=C2=A0 654.706317]=C2=A0 show_stack+0x24/0x30
> [=C2=A0 654.706325]=C2=A0 dump_stack+0xe0/0x134
> [=C2=A0 654.706332]=C2=A0 print_address_description+0x80/0x408
> [=C2=A0 654.706338]=C2=A0 __kasan_report+0x164/0x1a0
> [=C2=A0 654.706343]=C2=A0 kasan_report+0xc/0x18
> [=C2=A0 654.706348]=C2=A0 __asan_load8+0x88/0xb0
> [=C2=A0 654.706353]=C2=A0 kvm_pmu_get_canonical_pmc+0x48/0x78

I noticed that we will use "pmc->idx" and the "chained" bitmap to
determine if the pmc is chained, in kvm_pmu_pmc_is_chained().

Should we initialize the idx and the bitmap appropriately before
doing kvm_pmu_stop_counter()?  Like:


diff --git a/virt/kvm/arm/pmu.c b/virt/kvm/arm/pmu.c
index 3dd8238..cf3119a 100644
--- a/virt/kvm/arm/pmu.c
+++ b/virt/kvm/arm/pmu.c
@@ -224,12 +224,12 @@ void kvm_pmu_vcpu_reset(struct kvm_vcpu *vcpu)
  	int i;
  	struct kvm_pmu *pmu =3D &vcpu->arch.pmu;

+	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
+
  	for (i =3D 0; i < ARMV8_PMU_MAX_COUNTERS; i++) {
-		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
  		pmu->pmc[i].idx =3D i;
+		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
  	}
-
-	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
  }

  /**


Thanks,
zenghui

> [=C2=A0 654.706358]=C2=A0 kvm_pmu_stop_counter+0x28/0x118
> [=C2=A0 654.706363]=C2=A0 kvm_pmu_vcpu_reset+0x60/0xa8
> [=C2=A0 654.706369]=C2=A0 kvm_reset_vcpu+0x30/0x4d8
> [=C2=A0 654.706376]=C2=A0 kvm_arch_vcpu_ioctl+0xa04/0xc18
> [=C2=A0 654.706381]=C2=A0 kvm_vcpu_ioctl+0x17c/0xde8
> [=C2=A0 654.706387]=C2=A0 do_vfs_ioctl+0x150/0xaf8
> [=C2=A0 654.706392]=C2=A0 ksys_ioctl+0x84/0xb8
> [=C2=A0 654.706397]=C2=A0 __arm64_sys_ioctl+0x4c/0x60
> [=C2=A0 654.706403]=C2=A0 el0_svc_common.constprop.0+0xb4/0x208
> [=C2=A0 654.706409]=C2=A0 el0_svc_handler+0x3c/0xa8
> [=C2=A0 654.706414]=C2=A0 el0_svc+0x8/0xc
>=20
> [=C2=A0 654.706422] Allocated by task 23268:
> [=C2=A0 654.706429]=C2=A0 __kasan_kmalloc.isra.0+0xd0/0x180
> [=C2=A0 654.706435]=C2=A0 kasan_slab_alloc+0x14/0x20
> [=C2=A0 654.706440]=C2=A0 kmem_cache_alloc+0x17c/0x4a8
> [=C2=A0 654.706445]=C2=A0 kvm_arch_vcpu_create+0xa0/0x130
> [=C2=A0 654.706451]=C2=A0 kvm_vm_ioctl+0x844/0x1218
> [=C2=A0 654.706456]=C2=A0 do_vfs_ioctl+0x150/0xaf8
> [=C2=A0 654.706461]=C2=A0 ksys_ioctl+0x84/0xb8
> [=C2=A0 654.706466]=C2=A0 __arm64_sys_ioctl+0x4c/0x60
> [=C2=A0 654.706472]=C2=A0 el0_svc_common.constprop.0+0xb4/0x208
> [=C2=A0 654.706478]=C2=A0 el0_svc_handler+0x3c/0xa8
> [=C2=A0 654.706482]=C2=A0 el0_svc+0x8/0xc
>=20
> [=C2=A0 654.706490] Freed by task 0:
> [=C2=A0 654.706493] (stack is not available)
>=20
> [=C2=A0 654.706501] The buggy address belongs to the object at ffff801d6c=
8fc010
>  =C2=A0which belongs to the cache kvm_vcpu of size 10784
> [=C2=A0 654.706507] The buggy address is located 8 bytes to the right of
>  =C2=A010784-byte region [ffff801d6c8fc010, ffff801d6c8fea30)
> [=C2=A0 654.706510] The buggy address belongs to the page:
> [=C2=A0 654.706516] page:ffff7e0075b23f00 refcount:1 mapcount:0=20
> mapping:ffff801db257e480 index:0x0 compound_mapcount: 0
> [=C2=A0 654.706524] flags: 0xffffe0000010200(slab|head)
> [=C2=A0 654.706532] raw: 0ffffe0000010200 ffff801db2586ee0 ffff801db2586e=
e0=20
> ffff801db257e480
> [=C2=A0 654.706538] raw: 0000000000000000 0000000000010001 00000001ffffff=
ff=20
> 0000000000000000
> [=C2=A0 654.706542] page dumped because: kasan: bad access detected
>=20
> [=C2=A0 654.706549] Memory state around the buggy address:
> [=C2=A0 654.706554]=C2=A0 ffff801d6c8fe900: 00 00 00 00 00 00 00 00 00 00=
 00 00 00=20
> 00 00 00
> [=C2=A0 654.706560]=C2=A0 ffff801d6c8fe980: 00 00 00 00 00 00 00 00 00 00=
 00 00 00=20
> 00 00 00
> [=C2=A0 654.706565] >ffff801d6c8fea00: 00 00 00 00 00 00 fc fc fc fc fc f=
c fc=20
> fc fc fc
> [=C2=A0 654.706568]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
> [=C2=A0 654.706573]=C2=A0 ffff801d6c8fea80: fc fc fc fc fc fc fc fc fc fc=
 fc fc fc=20
> fc fc fc
> [=C2=A0 654.706578]=C2=A0 ffff801d6c8feb00: fc fc fc fc fc fc fc fc fc fc=
 fc fc fc=20
> fc fc fc
> [=C2=A0 654.706582]=20
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f9d5d18a-7631-f3e2-d73a-21d8eee183f1%40huawei.com.
For more options, visit https://groups.google.com/d/optout.
