Return-Path: <kasan-dev+bncBAABBAFQ6OSQMGQEPSIDSAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E345A75E049
	for <lists+kasan-dev@lfdr.de>; Sun, 23 Jul 2023 09:34:26 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-666edb72db2sf1934326b3a.0
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jul 2023 00:34:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690097665; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaUX5BzWASgYn7Sw5lhPwuZrw5G3QDX04j6WqOIMrp4anvh8pkgK8FkzEV+KM3zrhe
         EAq+Her902z50Gxnxi7q6C7kcy+BB+ioCxRSTp4+gWHPlIz45XGtoyUiZJHIaF35isll
         BKYtCpdhUbCPwX0SKBcuEiUV2NHkCFSI2srE3ZeiW0phOOS/f93L1I16RMo/aTSDXTK9
         cMQQSkb/3BMLjrcHovW/1gYM9wC4VprCIIVW5YeTi39U4vsACl+IIRF3YxwkiHQ2+rSW
         ZmSeZ2S5j3LHa/Im0lq/h3mGjDCuycR3yyQubHXwTlpgfm9R7av8PS42e1n9rPUXLJWg
         tnhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=rHtCNNwP9J4E5nV06fpJlJaI6ESuoKhW/qMyNLD+D1c=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=H7TYsW4kAmjIKx2V91k/kxeBzS+PKMbykFzhYYL/CejREeAtZpvPpO5alKgUW61iQ6
         ZWqaehTCg833qsT200N6ZB0k0oxZS5YvukygJTpLb473R82Dom3AHX91/C04dUPfxtwc
         xHEbup3otIXDVqqUHZTIPgptuQ9QUn6eMkaMtna1/th2ioHb2zaoDzkR9rbb1FjrWtuM
         iQXPpmJWN0byw3fsoMRvsmzel21nT9a4uGscU1SF0pMLlvBZiNMfs57QIscx0Zw9E1yr
         dF/NXs/Z33lJjtn6ZSpEGBfqaa6fqlbGQIaOXJbNLcKzSkiWYjFvfbAkv8WOmTkcRyOb
         Il2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690097665; x=1690702465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rHtCNNwP9J4E5nV06fpJlJaI6ESuoKhW/qMyNLD+D1c=;
        b=Kpm/aX9BVlYc4zBryPWhFhlcV0lIrIFe+CQ5CQdNz47PdDTfFiMR1OqmB9aJ6R0b+N
         kkBZiGBs7oGmtW0IoHnJ02o9YFO69Ldg7GFPq3a1PhPaLqjgJASnocatcW0pj15p8pld
         /oCxYSf4NTdTT/rayiK33g/I140NtYmpBw6PPjVbCClW0F9Hjv7TIRadpApYof9yrzZP
         LBHVqUWwrjtrJEyZ1X2AgSH/hQJgWBw9+bV/7P61xXbF0VMyOj/WPZ5VNxVzTUqVlvTO
         I2wUlQEbDVZNk6oQQZvK7hIPPP6mxgdqsQEgciaWyz+2jaUZcFmDYZWXolSFzZhv9LEs
         wXoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690097665; x=1690702465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rHtCNNwP9J4E5nV06fpJlJaI6ESuoKhW/qMyNLD+D1c=;
        b=GkNF7oAnHFToe0AF2Lk+PIRYDy3NZIaOXw6rSZrM1+pKw29a9aM5FLAvdsGCDRTbwb
         KXjaNUlKv3YxH04Zj1hy/yNXIq2v20fBgzIML7z1tAHZKWyK21kOFK7K5yIquwe9rDfl
         5XvQXtLtBhb2/NHEdj8v4PEyLJaFyp12tIxXk5OAxPuTfnVPV+J4tL77PzoQdqX3GvnI
         CzydBfw5Ec27vfwsBbiD+Zs/DuzjB14nDZyzjNGCCYlUcUBVDY91xh0bWHhdZEN142hg
         y8mHq81/cKz6fbGTgvz+510dpP1jhkUriFV2TkpQYQnZF107v6V/dw/5WkL/t6rTpU3O
         liaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYdT0eGKMI0DvxGOombMA1JOfMiRKeb4JImFqAEfECpdbjNnlTP
	lqvKI1kpWhKj7bax6/1tn/U=
X-Google-Smtp-Source: APBJJlHgD24jgInII/MuXnSxIupF0iCskWTEhvFW3uSVty/UDnU9kdQvsqG1DsWYalWKrCLxt+ibSg==
X-Received: by 2002:a05:6a00:1350:b0:65b:351a:e70a with SMTP id k16-20020a056a00135000b0065b351ae70amr6782616pfu.29.1690097665113;
        Sun, 23 Jul 2023 00:34:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:18ca:0:b0:666:e97f:cb0f with SMTP id 193-20020a6218ca000000b00666e97fcb0fls2130784pfy.0.-pod-prod-05-us;
 Sun, 23 Jul 2023 00:34:24 -0700 (PDT)
X-Received: by 2002:a05:6a20:7486:b0:132:d029:e2d7 with SMTP id p6-20020a056a20748600b00132d029e2d7mr7736018pzd.55.1690097664425;
        Sun, 23 Jul 2023 00:34:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690097664; cv=none;
        d=google.com; s=arc-20160816;
        b=0k+IevfXcdwoVxu5w62XuhpOLpqaWSPuPmjl9YQCZARcvaty5tro/BFUsF3Xi9bYRw
         iukwEScK8G5nB8Qykb6EzYSLH6xUS/qlDMZWz3mkWexN7P89aY4b+FL3qLX0jaherDQB
         EoPULbIv4gM755jr9oC5giKmUcp0vAi4yFkIjKEXmM9ppZ8HNCLgg59ihe9hbkIW2JAQ
         3llBNVwJc5G5EXC/NopLnSU0dK/6Kgxq3yfzfgzu0Q2gmYBdLuX+CgbnXnbZzORPvg4M
         Z71ue/Wx1IFWtjhi5XMfPrSSk2ncqSmMCSBUeqy4aq6DEm7JVMGwC+LFxaoPpWFEMhgK
         CHkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=NTrjRsqDU0JPO/TksSAZQ2975dh9ntf+HqOxhoFiv8c=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=EVt8vXWTmqRqLEA+s8G2FLWy/b0CdxUd+eSsXvr1gYVcwVHwiyjLy6K0rHsxGlxYCH
         A+SvuebciVSAre93T9gIywxBtNz4IurR9o8nm+oqVPDbSAleYy4fIM15czRYfyJBdtH0
         3/ZTFnBH0T5nW6XdOgC4rxR50hDTskW/18L5LWX+IQfO8WBurVhFjK6wgYfwhaxCWixI
         Qd2Wii233tkHgcJ3E+ZAX/h8inxkDvXiHlR4jz3EcLr7JCVelX5++hi2xhs8g30ConST
         LD6g0TeR5FPBhA6Vvp4qxAtsaFXjg/jQbqnebUx77YIgIdLa1RRVS3ug5rDQrmAfjv7L
         9NUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id g36-20020a632024000000b0054fd799a6e2si498524pgg.2.2023.07.23.00.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jul 2023 00:34:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 03ea0833cfc34e699fa3ba5a09395578-20230723
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:d0d69a12-911b-4bc0-b4f9-f8d6f42fbb37,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:d0d69a12-911b-4bc0-b4f9-f8d6f42fbb37,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:c15ef98e-7caa-48c2-8dbb-206f0389473c,B
	ulkID:230721111347J28IJWE1,BulkQuantity:2,Recheck:0,SF:24|17|19|44|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,OSI
	:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,TF_CID_SPAM_ULS,
	TF_CID_SPAM_SNR
X-UUID: 03ea0833cfc34e699fa3ba5a09395578-20230723
X-User: lienze@kylinos.cn
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1903500873; Sun, 23 Jul 2023 15:34:15 +0800
From: Enze Li <lienze@kylinos.cn>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: kernel@xen0n.name,  loongarch@lists.linux.dev,  glider@google.com,
  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 4/4] LoongArch: Add KFENCE support
In-Reply-To: <CAAhV-H6FoC1v9f9Vkq9rzk=0j88RczLgiYTiBUBNDwx3B=3tYA@mail.gmail.com>
	(Huacai Chen's message of "Fri, 21 Jul 2023 11:19:10 +0800")
References: <20230719082732.2189747-1-lienze@kylinos.cn>
	<20230719082732.2189747-5-lienze@kylinos.cn>
	<CAAhV-H71sv+VeLfNzuiqitYcuB4rHnho=dRYQftwo1__3bLZSQ@mail.gmail.com>
	<87lefaez31.fsf@kylinos.cn>
	<CAAhV-H6FoC1v9f9Vkq9rzk=0j88RczLgiYTiBUBNDwx3B=3tYA@mail.gmail.com>
Date: Sun, 23 Jul 2023 15:34:08 +0800
Message-ID: <87h6pvaxov.fsf@kylinos.cn>
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

On Fri, Jul 21 2023 at 11:19:10 AM +0800, Huacai Chen wrote:

> Hi, Enze,
>
> On Fri, Jul 21, 2023 at 11:14=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrot=
e:
>>
>> On Wed, Jul 19 2023 at 11:27:50 PM +0800, Huacai Chen wrote:
>>
>> > Hi, Enze,
>> >
>> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wr=
ote:
>> >>
>> >> The LoongArch architecture is quite different from other architecture=
s.
>> >> When the allocating of KFENCE itself is done, it is mapped to the dir=
ect
>> >> mapping configuration window [1] by default on LoongArch.  It means t=
hat
>> >> it is not possible to use the page table mapped mode which required b=
y
>> >> the KFENCE system and therefore it should be remapped to the appropri=
ate
>> >> region.
>> >>
>> >> This patch adds architecture specific implementation details for KFEN=
CE.
>> >> In particular, this implements the required interface in <asm/kfence.=
h>.
>> >>
>> >> Tested this patch by using the testcases and all passed.
>> >>
>> >> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1=
-EN.html#virtual-address-space-and-address-translation-mode
>> >>
>> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
>> >> ---
>> >>  arch/loongarch/Kconfig               |  1 +
>> >>  arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++=
++
>> >>  arch/loongarch/include/asm/pgtable.h |  6 +++
>> >>  arch/loongarch/mm/fault.c            | 22 ++++++----
>> >>  4 files changed, 83 insertions(+), 8 deletions(-)
>> >>  create mode 100644 arch/loongarch/include/asm/kfence.h
>> >>
>> >> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
>> >> index 5411e3a4eb88..db27729003d3 100644
>> >> --- a/arch/loongarch/Kconfig
>> >> +++ b/arch/loongarch/Kconfig
>> >> @@ -93,6 +93,7 @@ config LOONGARCH
>> >>         select HAVE_ARCH_JUMP_LABEL
>> >>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>> >>         select HAVE_ARCH_KASAN
>> >> +       select HAVE_ARCH_KFENCE if 64BIT
>> > "if 64BIT" can be dropped here.
>> >
>>
>> Fixed.
>>
>> >>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>> >>         select HAVE_ARCH_SECCOMP_FILTER
>> >>         select HAVE_ARCH_TRACEHOOK
>> >> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/inc=
lude/asm/kfence.h
>> >> new file mode 100644
>> >> index 000000000000..2a85acc2bc70
>> >> --- /dev/null
>> >> +++ b/arch/loongarch/include/asm/kfence.h
>> >> @@ -0,0 +1,62 @@
>> >> +/* SPDX-License-Identifier: GPL-2.0 */
>> >> +/*
>> >> + * KFENCE support for LoongArch.
>> >> + *
>> >> + * Author: Enze Li <lienze@kylinos.cn>
>> >> + * Copyright (C) 2022-2023 KylinSoft Corporation.
>> >> + */
>> >> +
>> >> +#ifndef _ASM_LOONGARCH_KFENCE_H
>> >> +#define _ASM_LOONGARCH_KFENCE_H
>> >> +
>> >> +#include <linux/kfence.h>
>> >> +#include <asm/pgtable.h>
>> >> +#include <asm/tlb.h>
>> >> +
>> >> +static inline char *arch_kfence_init_pool(void)
>> >> +{
>> >> +       char *__kfence_pool_orig =3D __kfence_pool;
>> > I prefer kfence_pool than __kfence_pool_orig here.
>> >
>>
>> Fixed.
>>
>> >> +       struct vm_struct *area;
>> >> +       int err;
>> >> +
>> >> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
>> >> +                                   KFENCE_AREA_START, KFENCE_AREA_EN=
D,
>> >> +                                   __builtin_return_address(0));
>> >> +       if (!area)
>> >> +               return NULL;
>> >> +
>> >> +       __kfence_pool =3D (char *)area->addr;
>> >> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
>> >> +                                (unsigned long)__kfence_pool + KFENC=
E_POOL_SIZE,
>> >> +                                virt_to_phys((void *)__kfence_pool_o=
rig),
>> >> +                                PAGE_KERNEL);
>> >> +       if (err) {
>> >> +               free_vm_area(area);
>> >> +               return NULL;
>> >> +       }
>> >> +
>> >> +       return __kfence_pool;
>> >> +}
>> >> +
>> >> +/* Protect the given page and flush TLB. */
>> >> +static inline bool kfence_protect_page(unsigned long addr, bool prot=
ect)
>> >> +{
>> >> +       pte_t *pte =3D virt_to_kpte(addr);
>> >> +
>> >> +       if (WARN_ON(!pte) || pte_none(*pte))
>> >> +               return false;
>> >> +
>> >> +       if (protect)
>> >> +               set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _P=
AGE_PRESENT)));
>> >> +       else
>> >> +               set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PA=
GE_PRESENT)));
>> >> +
>> >> +       /* Flush this CPU's TLB. */
>> >> +       preempt_disable();
>> >> +       local_flush_tlb_one(addr);
>> >> +       preempt_enable();
>> >> +
>> >> +       return true;
>> >> +}
>> >> +
>> >> +#endif /* _ASM_LOONGARCH_KFENCE_H */
>> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/in=
clude/asm/pgtable.h
>> >> index 0fc074b8bd48..5a9c81298fe3 100644
>> >> --- a/arch/loongarch/include/asm/pgtable.h
>> >> +++ b/arch/loongarch/include/asm/pgtable.h
>> >> @@ -85,7 +85,13 @@ extern unsigned long zero_page_mask;
>> >>  #define MODULES_VADDR  (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
>> >>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>> >>
>> >> +#ifdef CONFIG_KFENCE
>> >> +#define KFENCE_AREA_START      MODULES_END
>> >> +#define KFENCE_AREA_END                (KFENCE_AREA_START + SZ_512M)
>> > Why you choose 512M here?
>> >
>>
>> One day I noticed that 512M can hold 16K (default 255) KFENCE objects,
>> which should be more than enough and I think this should be appropriate.
>>
>> As far as I see, KFENCE system does not have the upper limit of this
>> value(CONFIG_KFENCE_NUM_OBJECTS), which could theoretically be any
>> number.  There's another way, how about setting this value to be
>> determined by the configuration, like this,
>>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>  +#define KFENCE_AREA_END \
>>  + (KFENCE_AREA_START + (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> How does other archs configure the size?
>

They all use the same one with a macro named KFENCE_POOL_SIZE defined
like this during kernel startup,

#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)

For now, we do not need to consider the KASAN region, and get enough
address space after vmemmap, this will not be a problem.

>>
>> >> +#define VMALLOC_START          KFENCE_AREA_END
>> >> +#else
>> >>  #define VMALLOC_START  MODULES_END
>> >> +#endif
>> > I don't like to put KFENCE_AREA between module and vmalloc range (it
>> > may cause some problems), can we put it after vmemmap?
>>
>> I found that there is not enough space after vmemmap and that these
>> spaces are affected by KASAN. As follows,
>>
>> Without KASAN
>> ###### module 0xffff800002008000~0xffff800012008000
>> ###### malloc 0xffff800032008000~0xfffffefffe000000
>> ###### vmemmap 0xffffff0000000000~0xffffffffffffffff
>>
>> With KASAN
>> ###### module 0xffff800002008000~0xffff800012008000
>> ###### malloc 0xffff800032008000~0xffffbefffe000000
>> ###### vmemmap 0xffffbf0000000000~0xffffbfffffffffff
>>
>> What about put it before MODULES_START?
> I temporarily drop KASAN in linux-next for you. You can update a new
> patch version without KASAN (still, put KFENCE after vmemmap), and
> then we can improve further.
>
> Huacai

Thank you so much. :)

The v2 of the patchset is on the way.

Best Regards,
Enze

>>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -82,7 +82,14 @@ extern unsigned long zero_page_mask;
>>   * Avoid the first couple of pages so NULL pointer dereferences will
>>   * still reliably trap.
>>   */
>> +#ifdef CONFIG_KFENCE
>> +#define KFENCE_AREA_START      (vm_map_base + PCI_IOSIZE + (2 * PAGE_SI=
ZE))
>> +#define KFENCE_AREA_END        \
>> +       (KFENCE_AREA_START + (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_=
SIZE)
>> +#define MODULES_VADDR  KFENCE_AREA_END
>> +#else
>>  #define MODULES_VADDR  (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
>> +#endif
>>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
>>
>> Best Regards,
>> Enze
>>
>> >>
>> >>  #ifndef CONFIG_KASAN
>> >>  #define VMALLOC_END    \
>> >> diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
>> >> index da5b6d518cdb..c0319128b221 100644
>> >> --- a/arch/loongarch/mm/fault.c
>> >> +++ b/arch/loongarch/mm/fault.c
>> >> @@ -23,6 +23,7 @@
>> >>  #include <linux/kprobes.h>
>> >>  #include <linux/perf_event.h>
>> >>  #include <linux/uaccess.h>
>> >> +#include <linux/kfence.h>
>> >>
>> >>  #include <asm/branch.h>
>> >>  #include <asm/mmu_context.h>
>> >> @@ -30,7 +31,8 @@
>> >>
>> >>  int show_unhandled_signals =3D 1;
>> >>
>> >> -static void __kprobes no_context(struct pt_regs *regs, unsigned long=
 address)
>> >> +static void __kprobes no_context(struct pt_regs *regs, unsigned long=
 address,
>> >> +                                unsigned long write)
>> >>  {
>> >>         const int field =3D sizeof(unsigned long) * 2;
>> >>
>> >> @@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *re=
gs, unsigned long address)
>> >>         if (fixup_exception(regs))
>> >>                 return;
>> >>
>> >> +       if (kfence_handle_page_fault(address, write, regs))
>> >> +               return;
>> >> +
>> >>         /*
>> >>          * Oops. The kernel tried to access some bad page. We'll have=
 to
>> >>          * terminate things with extreme prejudice.
>> >> @@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *=
regs, unsigned long address)
>> >>         die("Oops", regs);
>> >>  }
>> >>
>> >> -static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigne=
d long address)
>> >> +static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigne=
d long address,
>> >> +                                      unsigned long write)
>> >>  {
>> >>         /*
>> >>          * We ran out of memory, call the OOM killer, and return the =
userspace
>> >>          * (which will retry the fault, or kill us if we got oom-kill=
ed).
>> >>          */
>> >>         if (!user_mode(regs)) {
>> >> -               no_context(regs, address);
>> >> +               no_context(regs, address, write);
>> >>                 return;
>> >>         }
>> >>         pagefault_out_of_memory();
>> >> @@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *reg=
s,
>> >>  {
>> >>         /* Kernel mode? Handle exceptions or die */
>> >>         if (!user_mode(regs)) {
>> >> -               no_context(regs, address);
>> >> +               no_context(regs, address, write);
>> >>                 return;
>> >>         }
>> >>
>> >> @@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *re=
gs,
>> >>
>> >>         /* Kernel mode? Handle exceptions or die */
>> >>         if (!user_mode(regs)) {
>> >> -               no_context(regs, address);
>> >> +               no_context(regs, address, write);
>> >>                 return;
>> >>         }
>> >>
>> >> @@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_r=
egs *regs,
>> >>          */
>> >>         if (address & __UA_LIMIT) {
>> >>                 if (!user_mode(regs))
>> >> -                       no_context(regs, address);
>> >> +                       no_context(regs, address, write);
>> >>                 else
>> >>                         do_sigsegv(regs, write, address, si_code);
>> >>                 return;
>> >> @@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_r=
egs *regs,
>> >>
>> >>         if (fault_signal_pending(fault, regs)) {
>> >>                 if (!user_mode(regs))
>> >> -                       no_context(regs, address);
>> >> +                       no_context(regs, address, write);
>> >>                 return;
>> >>         }
>> >>
>> >> @@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_r=
egs *regs,
>> >>         if (unlikely(fault & VM_FAULT_ERROR)) {
>> >>                 mmap_read_unlock(mm);
>> >>                 if (fault & VM_FAULT_OOM) {
>> >> -                       do_out_of_memory(regs, address);
>> >> +                       do_out_of_memory(regs, address, write);
>> >>                         return;
>> >>                 } else if (fault & VM_FAULT_SIGSEGV) {
>> >>                         do_sigsegv(regs, write, address, si_code);
>> >> --
>> >> 2.34.1
>> >>
>> >>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87h6pvaxov.fsf%40kylinos.cn.
