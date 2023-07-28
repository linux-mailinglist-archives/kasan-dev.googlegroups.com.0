Return-Path: <kasan-dev+bncBAABBSNTRWTAMGQECES4UOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C55937663D5
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 08:01:46 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-348c2705818sf393265ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 23:01:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690524105; cv=pass;
        d=google.com; s=arc-20160816;
        b=n9a6NlpIA8nKutpH/7IdZalbFmUYwnHjBwOUL0Xp3ehqP7OP3lNIbT0yYQ8wivvazA
         wIbwCWm/l14ci8/6CrC7SbWg7y8NbNpVzd3EoC5P05zXPFIecMSK6Ao1dNefZicaVFxY
         PeqWP0frHKuqdkpN9XtPluE+E03x0KHKLeDtH0LDymReP3mdFdL/hwr4zBMJLbsgavPY
         F8rp1hbvh5jytiXIvrFMcSvvX8z3e/3W2IurE8oT5fX8SgqKynQuoignmZBQcdrL5MHU
         rBTr3tiSbVT33dXh2rO5N/w9vO0aoUGc54SNZwBU/FeagkaxK4idVzAHuXtnadbwJQzg
         pUpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=eyaWu4hAwiEOhO1m9tUy9yR56KkswUBtRmI/nPir/0s=;
        fh=1dGRKi1xriwBGVfVkR2ESMRml7x/plugtzIacBSpAHc=;
        b=cnJl94VRpwKnwtuY1GLN+NNcYmsi3MRBTlKxGhgAuJF8K4R2tOERKpPt0xjqvr2/+N
         9BTxRdFQ1wzIANBZyg+oHC/2EUGF0f6t7MMjQIJsl01EBQSnBktCdCHfUMfA1W8W3635
         JanTsqATf2JjvCr+UujqyLbXisOTzRA4GRZBTQKzal2axK1ta9rhnv/Z675zu5w9ZtP8
         04z6T42+zA3kut8uJe27rGJKf4J8MY1EsoSahRsbzrvWbVxKOeo0Kv+v17ipun4tnnxq
         4H0hczbYleJPrrju7J/MOMQpY7zdSPIxFN7KtcPS63uFZfcAxXhVbFbiCGr5F1SBv7hz
         f9jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690524105; x=1691128905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eyaWu4hAwiEOhO1m9tUy9yR56KkswUBtRmI/nPir/0s=;
        b=AnksfdfegEGZTQfIixRYJiwNIcW9spy8Iy31Hlfb/kRWxtfSbJgRkZyiEdPRpE4mVw
         FdsN06mPYMDCzEhYaXTHjmJhSj0RzGwV70hi4Ol5+6vkzO3Vt9Ce7KOO0UYls9OU45kG
         FX2u3i9Alq6rwxfWHpLtXNviZSMzVo8kpSj4QONhsJS+VnuGYWUKPjTB5JHCgU5VsRB3
         ZGENHmlHB5PG4BKIkVvSHUXS5Qx/9bNa03Vt9Sx0mQ4SW6OWTPtEkvCf+fCRhJayCeGJ
         BI7TuRic6ujh6JfWsjMeM78OyIM+DuCzK20r+PGAmr54utEbjE/P4sGA+cO+nK2SSUSL
         0CuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690524105; x=1691128905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eyaWu4hAwiEOhO1m9tUy9yR56KkswUBtRmI/nPir/0s=;
        b=IulG9ZUnxosvj4X6DnU5wnGsDgtIG/QdOVTyF5hnljaTlhcaW5h1+9PdylYv402n1/
         etGUfWt2I+uOzi2HWWSMpNPYiraN8XlFX7xlCSQLJLNdKF3gdVU7bI33nO7eBPhJvku4
         kGzoEti28xL6DwtojGPUvMqpc/mATNlquQpRH9Vyo5hsp+hqWJBl9GcQGmDou0M9TPCy
         /Dalgdpv8DJyGkWaqPQdYeG0MWF4fuigalqYVU1n4VqMSRjJiAkK0M2HHBWfGLpFcZ4V
         SHW9s17w8TCakB2uMeiwYW6r9C4Kb84x83/Cb8NiPmb89XfWr9xqGJX2f8Rys6KTATZl
         GuSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYFPNCIdMyOavfxYM7CeDbwMxEH6WBJ2JT5dTQ41ChISqrFbV6k
	gbvW43PaGL+QF3MXbkmr58A=
X-Google-Smtp-Source: APBJJlEzJj5whdZWQWAc3wpzuWRDAfJkHkgRLqA/As3Un0hGj6elG6P8sGUeZ1O+wPisHiDLGUiOYw==
X-Received: by 2002:a92:c26a:0:b0:348:d4f4:4d49 with SMTP id h10-20020a92c26a000000b00348d4f44d49mr127917ild.3.1690524105402;
        Thu, 27 Jul 2023 23:01:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6129:b0:1ba:2267:82c9 with SMTP id
 s41-20020a056870612900b001ba226782c9ls2062491oae.1.-pod-prod-04-us; Thu, 27
 Jul 2023 23:01:44 -0700 (PDT)
X-Received: by 2002:a05:6870:14c1:b0:1b0:3075:2f9d with SMTP id l1-20020a05687014c100b001b030752f9dmr2201410oab.34.1690524104713;
        Thu, 27 Jul 2023 23:01:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690524104; cv=none;
        d=google.com; s=arc-20160816;
        b=L4oj4z5nPinAe+XjpoLgHfnVlJ0iMebhD4DQt2jNJd0+U3D26/j7pLLv37AGk4s+OH
         Puc0HqKjn1BEudqBFZ0Nt5UnOLvgBAotvakRfCiIKelRTlVs5+76YyrnxL8aSuws7XlR
         /87dYBfehz7j41nP5foPDmjSS7cCAc4yip5QmiUoXoMyHm5LLFqUwNSCTHDUvFX0A3hn
         jqe12aqWcl9EzTofO1BqsbZcXqneHvIwc/PVe1uNiZ6glPoMW4Ph3M2DeQSc6uYbw7KQ
         btokfO2nXCavJEiamywv1JtTHyF9YHVuc3SWiVRdcUFmw2+QZeB6/qaabBWUODvp7gB2
         pccA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=OD+aQJvPtw/BRqBGXBN6HjyY2HMr4e4whf2g7OZOeI0=;
        fh=1dGRKi1xriwBGVfVkR2ESMRml7x/plugtzIacBSpAHc=;
        b=IAFQkj/xdo0FTbb+VbjuyD32eKJQcLHLHC0HYHr5SkY5BPShNaQW7Ye2EcPUHPtfnW
         5rEvyVGtfeXU64n+8WEQubhzuuFMVZYcHbnQbWrri+A/JQb1kQtkhiedc95QFKE4etvO
         7L28cm4ou9wRlqxAXLhy3TYa88VnStq3Tg6GpDcvmCs5sfAI023TbwqLMPLz8d0hdRMq
         BqftXVROk+foIubLpM6BrBiOOX2LQaU/kNjTQ4nc80OYZPpoSI8rIiXOzpdOkqqxD+I7
         vKobUP+lwcP9r+NhB4pzCKaWZUR023m9x6T1uTAUShdS1H+ROtyHpn/DlBtkaYo/Newx
         GgNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id l10-20020a056830334a00b006bc823723b5si62014ott.3.2023.07.27.23.01.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jul 2023 23:01:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 396d4dbed1354d1eab9d06acfbe96f85-20230728
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:475f62b3-5a79-4e92-8548-a55a316fe131,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-9,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:6
X-CID-INFO: VERSION:1.1.28,REQID:475f62b3-5a79-4e92-8548-a55a316fe131,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-9,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:6
X-CID-META: VersionHash:176cd25,CLOUDID:18c58c42-d291-4e62-b539-43d7d78362ba,B
	ulkID:230728112732139381RX,BulkQuantity:2,Recheck:0,SF:24|17|19|43|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,OSI
	:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: 396d4dbed1354d1eab9d06acfbe96f85-20230728
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 189198503; Fri, 28 Jul 2023 14:01:35 +0800
From: Enze Li <lienze@kylinos.cn>
To: Jackie Liu <liu.yun@linux.dev>
Cc: chenhuacai@kernel.org,  kernel@xen0n.name,  loongarch@lists.linux.dev,
  glider@google.com,  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 4/4 v2] LoongArch: Add KFENCE support
In-Reply-To: <fa3dcc1b-03b2-567c-b143-8e3a100af9f6@linux.dev> (Jackie Liu's
	message of "Tue, 25 Jul 2023 22:34:50 +0800")
References: <20230725061451.1231480-1-lienze@kylinos.cn>
	<20230725061451.1231480-5-lienze@kylinos.cn>
	<fa3dcc1b-03b2-567c-b143-8e3a100af9f6@linux.dev>
Date: Fri, 28 Jul 2023 14:01:25 +0800
Message-ID: <87sf98a822.fsf@kylinos.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

On Tue, Jul 25 2023 at 10:34:50 PM +0800, Jackie Liu wrote:

> =E5=9C=A8 2023/7/25 14:14, Enze Li =E5=86=99=E9=81=93:
>> The LoongArch architecture is quite different from other architectures.
>> When the allocating of KFENCE itself is done, it is mapped to the direct
>> mapping configuration window [1] by default on LoongArch.  It means that
>> it is not possible to use the page table mapped mode which required by
>> the KFENCE system and therefore it should be remapped to the appropriate
>> region.
>>
>> This patch adds architecture specific implementation details for KFENCE.
>> In particular, this implements the required interface in <asm/kfence.h>.
>>
>> Tested this patch by running the testcases and all passed.
>>
>> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN=
.html#virtual-address-space-and-address-translation-mode
>>
>> Signed-off-by: Enze Li <lienze@kylinos.cn>
>> ---
>>   arch/loongarch/Kconfig               |  1 +
>>   arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
>>   arch/loongarch/include/asm/pgtable.h | 14 ++++++-
>>   arch/loongarch/mm/fault.c            | 22 ++++++----
>>   4 files changed, 90 insertions(+), 9 deletions(-)
>>   create mode 100644 arch/loongarch/include/asm/kfence.h
>>
>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
>> index 70635ea3d1e4..5b63b16be49e 100644
>> --- a/arch/loongarch/Kconfig
>> +++ b/arch/loongarch/Kconfig
>> @@ -91,6 +91,7 @@ config LOONGARCH
>>   	select HAVE_ARCH_AUDITSYSCALL
>>   	select HAVE_ARCH_JUMP_LABEL
>>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>> +	select HAVE_ARCH_KFENCE
>>   	select HAVE_ARCH_MMAP_RND_BITS if MMU
>>   	select HAVE_ARCH_SECCOMP_FILTER
>>   	select HAVE_ARCH_TRACEHOOK
>> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/includ=
e/asm/kfence.h
>> new file mode 100644
>> index 000000000000..fb39076fe4d7
>> --- /dev/null
>> +++ b/arch/loongarch/include/asm/kfence.h
>> @@ -0,0 +1,62 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +/*
>> + * KFENCE support for LoongArch.
>> + *
>> + * Author: Enze Li <lienze@kylinos.cn>
>> + * Copyright (C) 2022-2023 KylinSoft Corporation.
>> + */
>> +
>> +#ifndef _ASM_LOONGARCH_KFENCE_H
>> +#define _ASM_LOONGARCH_KFENCE_H
>> +
>> +#include <linux/kfence.h>
>> +#include <asm/pgtable.h>
>> +#include <asm/tlb.h>
>> +
>> +static inline bool arch_kfence_init_pool(void)
>> +{
>> +	char *kfence_pool =3D __kfence_pool;
>> +	struct vm_struct *area;
>> +	int err;
>> +
>> +	area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
>> +				    KFENCE_AREA_START, KFENCE_AREA_END,
>> +				    __builtin_return_address(0));
>> +	if (!area)
>> +		return false;
>> +
>> +	__kfence_pool =3D (char *)area->addr;
>
> I think there should be something wrong here.
>
>> +	err =3D ioremap_page_range((unsigned long)__kfence_pool,
>> +				 (unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
>> +				 virt_to_phys((void *)kfence_pool),
>> +				 PAGE_KERNEL);
>> +	if (err) {
>> +		free_vm_area(area);
>
> If err > 0, return area->addr here, It's not correct.

Hi Jackie,

Good catch!  I'll fix this issue in v3.

Cheers!
Enze

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87sf98a822.fsf%40kylinos.cn.
