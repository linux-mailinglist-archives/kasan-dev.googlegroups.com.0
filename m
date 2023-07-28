Return-Path: <kasan-dev+bncBAABBKXLRSTAMGQE4JTXJUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 424A8766263
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 05:27:41 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-686e7b27f55sf1298071b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 20:27:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690514859; cv=pass;
        d=google.com; s=arc-20160816;
        b=FLuh3ZvL+Njy6nj6LRieVgA78Fdr4EhNyk3du70s2pYe5/HJq7rEt28q3P7TtfCbDW
         y4Pkv0x8y/o4ch0E7hFiVOax3+IFjJ/ww0z6JibT81VPMCdyX8KhdahWprmlE3phshVg
         HYkOlAS5gm4VOUUgzOw2pVbt/BsHIbM9gc2c5/wS20gKuTyZPFVIhRFEgU6XGrtntu/A
         vP1P4CkXG62IJJJFL9zoNrDEeXyXXFsbKXAKhRj/3cKzg1jss7a6k9w+uhmVipzF0JOp
         fGPcxFs/9SYwL6yb22PTkvlr1ni1TLVn3slmdGdJAIxWSAmax6IkpXHR8gsFkr8Fz+93
         ezCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=KHeGX+1ynGRT/Kkc0b5+vaLN6ovm8Hxq5S0C+UCXAAA=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=ZzClhHBH95yqKfKa291UtvA/JBM9R64+s53XOz4FSSwd72z7mHZz4ApcS+g4WXnea0
         K3iPB3uBXvVs11O6STygtgoK6dxa67eA8awwgvXgQzuR6734skxaXEddKR2yYVpcAlUq
         f7jh3QpX053GKQjNFfazWtHAyafJt5yVuV/NadY1TJif7HxVaC0LKnUbjXfHUQKcvbkJ
         ZfpckAGK0MAZQLrPe37IU3mBanhpIJTjMYmANW3Lwr6thW3NCSS5PdzF8QlmFIQYw26d
         CQPiwHn/qdnJ/R1haGZyF69CS89awCmX9kZ9lAZ5bAcgBhQtkWo49Au5c7I0JQWQ91Eo
         uXlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690514859; x=1691119659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KHeGX+1ynGRT/Kkc0b5+vaLN6ovm8Hxq5S0C+UCXAAA=;
        b=iQdlCn//ETtDABW2hH/1+K+sfX9xDRjCaFxydjT2L8H0jHQxnT+b0GprfozSrhXivM
         1QJrupUxO0tg1tjIx51w2D1RaAZfA3OwzqP265fvQxDtAWHUdzcdOmMBpsx/pT+MSi/N
         IeDt2nkgdmN3bzP8TT23Xih2GuAriafGZhKtA0Q0NTXYkNktC21S5moA9EVfCHQL/cHg
         N2BmDiNj7jFcUEdh7E6rdffYAXVYj07neXrgxVLkpm81i5s8sJUp1TNc1U+rgngmJQHR
         ZCXUfXhOpWI4FK5isX/U/o+NcTFzn3ZAjQhDvtgD+4FocfzZiMWYAQHSJklT6ihGcfQT
         +A0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690514859; x=1691119659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KHeGX+1ynGRT/Kkc0b5+vaLN6ovm8Hxq5S0C+UCXAAA=;
        b=VjpBJ+47kAQp79EsiP8FcF/ZrZBRi03iP7i85qYssxNiTws84LWXNA0sBXQSDKlg5t
         wru/VHJyEzubDElGcWCxhTwC69uDjMMD0uRcyxah8+Y4CQcEwmhEgB8apvvts0A5JRqq
         ZRiEk9P1nx29mfcBOBfI97c+gh1QzStNO6Alo2wQGMhgutN92OuWMZpswMXQHzUZQssR
         QgIT1wJ5MxJMFOulTCVfVaLgP0xaU0peoJP+QwgieKyLYowHdTY6/ilY9w/svDnNwFQx
         wWINWkUIp7LHIV0sGjWhNupBOkzD5oIvfcmH3zoitAvECN8eOfodwXCYD1verIwNztYd
         /qdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbBrimNsj+E2NT06kYXu8A32lz4wOS6R2JU+HlmNqLQvaBvGMJp
	Y2htOmMH1WnNqXcZvtDnwQs=
X-Google-Smtp-Source: APBJJlHw95Sdz4gLwVlKqOLvJxicmcKJGhrw47tnWbraAVnfnEGBSrKyhmhA6vHoKGNP5bRCUQlP0A==
X-Received: by 2002:a05:6a00:1ad3:b0:687:1184:5420 with SMTP id f19-20020a056a001ad300b0068711845420mr355139pfv.0.1690514859175;
        Thu, 27 Jul 2023 20:27:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:17d6:0:b0:686:c079:96d9 with SMTP id 205-20020a6217d6000000b00686c07996d9ls90370pfx.0.-pod-prod-05-us;
 Thu, 27 Jul 2023 20:27:38 -0700 (PDT)
X-Received: by 2002:a05:6a21:780a:b0:13b:a129:a6cd with SMTP id be10-20020a056a21780a00b0013ba129a6cdmr580177pzc.58.1690514858122;
        Thu, 27 Jul 2023 20:27:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690514858; cv=none;
        d=google.com; s=arc-20160816;
        b=JAZWF/9YTd4Y2NFDFjs7k+29BJ1EhIqtC7XrRxCvQxit0mOTelGwuesVLfrf3rW0J5
         MORrej11qQSydbdOz6tcdRSu/LQXF3cCqNUY3chBVocUDINkCUK/X5M+LGWa+ZNpys75
         EdGCZNDXX6pS6oE5gHDrvJ7WrrveE3zyhvwkZr1WOwIgQeHlo3QJy9hJtDI2bNOtS8AZ
         S/vVAYrPM+NOfv6IonlyHz/tu7KpzQs7nymTWBEv8oaVzQLXkDvCxP+tvhEMBujrwGUC
         UvS4NxNszaunMmBojmqb6ZTGt4N4BH1oQhKojj8pFTIsR830eTEPVYXOCUXWLX2o3jSq
         OrBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=2EkPlUzVeDxJfjMOFlVM36muPF5g/OQmTTkDz7xtco8=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=gNcTaS4L7uxTPSAjge6IGOTY1WcN3PGrcqzYXiCfrENwOH2BqKjv1T5UTVSF8QYxTE
         QZjISQxtlB5YwriJvYBc7ABCpBMs3hbOfRnvg2oSbSgZ2NF00KnTQKxkOCwOoPSBXM5D
         sEyyFvxjHCpwjtmnEf86dbVQJFOJQw+e7po+De0odnXLMr2Cn96iJkeK11bYxByFSxr8
         hvq34yPcm4Tb5s+xLuNNpzMQIACXHh/AeKkPOyuJjJ1r1mDOwsoADZyddY+EyLQM4xBy
         q6vgy+QVsWha/FTUr9iD7GsLhpkCf5371QhZOzbgwf6XY7s4ZtJUfs3oo4GmipwtDNde
         KJXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id f20-20020a056a0022d400b00686db56bd12si221828pfj.3.2023.07.27.20.27.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jul 2023 20:27:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 19dc9f5dff3d431c92d5a1cc6d843c4c-20230728
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:ccc37edf-59fd-4d48-9685-43112f1925cc,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:ccc37edf-59fd-4d48-9685-43112f1925cc,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:d1798b42-d291-4e62-b539-43d7d78362ba,B
	ulkID:230728112732139381RX,BulkQuantity:0,Recheck:0,SF:24|17|19|44|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OS
	I:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,TF_CID_SPAM_ULS,
	TF_CID_SPAM_SNR
X-UUID: 19dc9f5dff3d431c92d5a1cc6d843c4c-20230728
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1069411927; Fri, 28 Jul 2023 11:27:30 +0800
From: Enze Li <lienze@kylinos.cn>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: kernel@xen0n.name,  loongarch@lists.linux.dev,  glider@google.com,
  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 4/4 v2] LoongArch: Add KFENCE support
In-Reply-To: <CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy+t+6gKONytwKQA@mail.gmail.com>
	(Huacai Chen's message of "Thu, 27 Jul 2023 09:26:04 +0800")
References: <20230725061451.1231480-1-lienze@kylinos.cn>
	<20230725061451.1231480-5-lienze@kylinos.cn>
	<CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy+t+6gKONytwKQA@mail.gmail.com>
Date: Fri, 28 Jul 2023 11:27:20 +0800
Message-ID: <87wmykaf6v.fsf@kylinos.cn>
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

On Thu, Jul 27 2023 at 09:26:04 AM +0800, Huacai Chen wrote:

> On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote=
:
>>
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
>>  arch/loongarch/Kconfig               |  1 +
>>  arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
>>  arch/loongarch/include/asm/pgtable.h | 14 ++++++-
>>  arch/loongarch/mm/fault.c            | 22 ++++++----
>>  4 files changed, 90 insertions(+), 9 deletions(-)
>>  create mode 100644 arch/loongarch/include/asm/kfence.h
>>
>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
>> index 70635ea3d1e4..5b63b16be49e 100644
>> --- a/arch/loongarch/Kconfig
>> +++ b/arch/loongarch/Kconfig
>> @@ -91,6 +91,7 @@ config LOONGARCH
>>         select HAVE_ARCH_AUDITSYSCALL
>>         select HAVE_ARCH_JUMP_LABEL
>>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>> +       select HAVE_ARCH_KFENCE
>>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>>         select HAVE_ARCH_SECCOMP_FILTER
>>         select HAVE_ARCH_TRACEHOOK
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
>> +       char *kfence_pool =3D __kfence_pool;
>> +       struct vm_struct *area;
>> +       int err;
>> +
>> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
>> +                                   KFENCE_AREA_START, KFENCE_AREA_END,
>> +                                   __builtin_return_address(0));
>> +       if (!area)
>> +               return false;
>> +
>> +       __kfence_pool =3D (char *)area->addr;
>> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
>> +                                (unsigned long)__kfence_pool + KFENCE_P=
OOL_SIZE,
>> +                                virt_to_phys((void *)kfence_pool),
>> +                                PAGE_KERNEL);
>> +       if (err) {
>> +               free_vm_area(area);
>> +               return false;
>> +       }
>> +
>> +       return true;
>> +}
>> +
>> +/* Protect the given page and flush TLB. */
>> +static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +{
>> +       pte_t *pte =3D virt_to_kpte(addr);
>> +
>> +       if (WARN_ON(!pte) || pte_none(*pte))
>> +               return false;
>> +
>> +       if (protect)
>> +               set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _PAGE=
_PRESENT)));
>> +       else
>> +               set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PAGE_=
PRESENT)));
>> +
>> +       /* Flush this CPU's TLB. */
>> +       preempt_disable();
>> +       local_flush_tlb_one(addr);
>> +       preempt_enable();
>> +
>> +       return true;
>> +}
>> +
>> +#endif /* _ASM_LOONGARCH_KFENCE_H */
>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inclu=
de/asm/pgtable.h
>> index 98a0c98de9d1..2702a6ba7122 100644
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -77,6 +77,13 @@ extern unsigned long zero_page_mask;
>>         (virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr=
)) & zero_page_mask))))
>>  #define __HAVE_COLOR_ZERO_PAGE
>>
>> +#ifdef CONFIG_KFENCE
>> +#define KFENCE_AREA_SIZE \
>> +       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)

Hi Huacai,

> Another question: Why define KFENCE_AREA_SIZE while there is already
> KFENCE_POOL_SIZE?

The KFENCE_POOL_SIZE macro is defined in linux/kfence.h.  When I trying
to include this header file, I see the following error,

----------------------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s
In file included from ./arch/loongarch/include/asm/pgtable.h:64,
                 from ./include/linux/pgtable.h:6,
                 from ./include/linux/mm.h:29,
                 from arch/loongarch/kernel/asm-offsets.c:9:
./include/linux/kfence.h:93:35: warning: =E2=80=98struct kmem_cache=E2=80=
=99 declared inside parameter list will not be visible outside of this defi=
nition or declaration
   93 | void kfence_shutdown_cache(struct kmem_cache *s);
      |                                   ^~~~~~~~~~
./include/linux/kfence.h:99:29: warning: =E2=80=98struct kmem_cache=E2=80=
=99 declared inside parameter list will not be visible outside of this defi=
nition or declaration
   99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags=
);
      |                             ^~~~~~~~~~
./include/linux/kfence.h:117:50: warning: =E2=80=98struct kmem_cache=E2=80=
=99 declared inside parameter list will not be visible outside of this defi=
nition or declaration
  117 | static __always_inline void *kfence_alloc(struct kmem_cache *s, siz=
e_t size, gfp_t flags)
      |                                                  ^~~~~~~~~~
./include/linux/kfence.h: In function =E2=80=98kfence_alloc=E2=80=99:
./include/linux/kfence.h:128:31: error: passing argument 1 of =E2=80=98__kf=
ence_alloc=E2=80=99 from incompatible pointer type [-Werror=3Dincompatible-=
pointer-types]
  128 |         return __kfence_alloc(s, size, flags);
      |                               ^
      |                               |
      |                               struct kmem_cache *
--------------------------------------------------------------------

The root cause of this issue is that linux/kfence.h should be expanded
after linux/mm.h, not before.  That said, we can not put any
"high-level" header files in the "low-level" ones.

> And why is KFENCE_AREA_SIZE a little larger than
> KFENCE_POOL_SIZE? If we can reuse KFENCE_POOL_SIZE,
> KFENCE_AREA_START/KFENCE_AREA_END can be renamed to
> KFENCE_POOL_START/KFENCE_POOL_END.

+#define KFENCE_AREA_SIZE \
+       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
                                              ^^^^^
                                             =20
Here I've added two extra pages, that's due to working with
__get_vm_area_caller() to request the space correctly.

1. arch_kfence_init_pool
     __get_vm_area_caller
       __get_vm_area_node
         =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
           if (!(flags & VM_NO_GUARD))
                   size +=3D PAGE_SIZE;
         =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

If we do not set VM_NO_GUARD, we would get one more page as "GUARD".
Setting VM_NO_GUARD is dangerous behavior and I suggest we keep this
page.

2. arch_kfence_init_pool
     __get_vm_area_caller
       __get_vm_area_node                        !!!This is my comment--
           =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D                     =
|
           if (flags & VM_IOREMAP)                                     |
                   align =3D 1ul << clamp_t(int, ...                     |
           *** We got "align=3D=3D0x200000" here.  Based on the default  <-=
-
               KFENCE objects of 255, we got the maximum align here. ***
           =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

           alloc_vmap_area
             __alloc_vmap_area
               =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
               nva_start_addr =3D ALIGN(vstart, align);
               *** When running here, the starting address will be
                   moved forward one byte due to alignment
                   requirements.  If we do not give enough space, we'll
                   fail on the next line. ***
              =20
               if (nva_start_addr + size > vend)
                       return vend;
               =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
              =20
Theoretically, this alignment requires at most 2MB of space.  However,
considering that the starting address is fixed (the starting position is
determined by VMEMMAP_END), I think that adding another page will be
enough.

Best Regards,
Enze

>> +#else
>> +#define KFENCE_AREA_SIZE       0
>> +#endif
>> +
>>  /*
>>   * TLB refill handlers may also map the vmalloc area into xkvrange.
>>   * Avoid the first couple of pages so NULL pointer dereferences will
>> @@ -88,11 +95,16 @@ extern unsigned long zero_page_mask;
>>  #define VMALLOC_START  MODULES_END
>>  #define VMALLOC_END    \
>>         (vm_map_base +  \
>> -        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE *=
 PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
>> +        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE *=
 PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE - KFENCE_AREA_SI=
ZE)
>>
>>  #define vmemmap                ((struct page *)((VMALLOC_END + PMD_SIZE=
) & PMD_MASK))
>>  #define VMEMMAP_END    ((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
>>
>> +#ifdef CONFIG_KFENCE
>> +#define KFENCE_AREA_START      VMEMMAP_END
>> +#define KFENCE_AREA_END                (KFENCE_AREA_START + KFENCE_AREA=
_SIZE)
>> +#endif
>> +
>>  #define pte_ERROR(e) \
>>         pr_err("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e=
))
>>  #ifndef __PAGETABLE_PMD_FOLDED
>> diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
>> index da5b6d518cdb..c0319128b221 100644
>> --- a/arch/loongarch/mm/fault.c
>> +++ b/arch/loongarch/mm/fault.c
>> @@ -23,6 +23,7 @@
>>  #include <linux/kprobes.h>
>>  #include <linux/perf_event.h>
>>  #include <linux/uaccess.h>
>> +#include <linux/kfence.h>
>>
>>  #include <asm/branch.h>
>>  #include <asm/mmu_context.h>
>> @@ -30,7 +31,8 @@
>>
>>  int show_unhandled_signals =3D 1;
>>
>> -static void __kprobes no_context(struct pt_regs *regs, unsigned long ad=
dress)
>> +static void __kprobes no_context(struct pt_regs *regs, unsigned long ad=
dress,
>> +                                unsigned long write)
>>  {
>>         const int field =3D sizeof(unsigned long) * 2;
>>
>> @@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *regs,=
 unsigned long address)
>>         if (fixup_exception(regs))
>>                 return;
>>
>> +       if (kfence_handle_page_fault(address, write, regs))
>> +               return;
>> +
>>         /*
>>          * Oops. The kernel tried to access some bad page. We'll have to
>>          * terminate things with extreme prejudice.
>> @@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *reg=
s, unsigned long address)
>>         die("Oops", regs);
>>  }
>>
>> -static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned l=
ong address)
>> +static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned l=
ong address,
>> +                                      unsigned long write)
>>  {
>>         /*
>>          * We ran out of memory, call the OOM killer, and return the use=
rspace
>>          * (which will retry the fault, or kill us if we got oom-killed)=
.
>>          */
>>         if (!user_mode(regs)) {
>> -               no_context(regs, address);
>> +               no_context(regs, address, write);
>>                 return;
>>         }
>>         pagefault_out_of_memory();
>> @@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *regs,
>>  {
>>         /* Kernel mode? Handle exceptions or die */
>>         if (!user_mode(regs)) {
>> -               no_context(regs, address);
>> +               no_context(regs, address, write);
>>                 return;
>>         }
>>
>> @@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *regs,
>>
>>         /* Kernel mode? Handle exceptions or die */
>>         if (!user_mode(regs)) {
>> -               no_context(regs, address);
>> +               no_context(regs, address, write);
>>                 return;
>>         }
>>
>> @@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_regs=
 *regs,
>>          */
>>         if (address & __UA_LIMIT) {
>>                 if (!user_mode(regs))
>> -                       no_context(regs, address);
>> +                       no_context(regs, address, write);
>>                 else
>>                         do_sigsegv(regs, write, address, si_code);
>>                 return;
>> @@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_regs=
 *regs,
>>
>>         if (fault_signal_pending(fault, regs)) {
>>                 if (!user_mode(regs))
>> -                       no_context(regs, address);
>> +                       no_context(regs, address, write);
>>                 return;
>>         }
>>
>> @@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_regs=
 *regs,
>>         if (unlikely(fault & VM_FAULT_ERROR)) {
>>                 mmap_read_unlock(mm);
>>                 if (fault & VM_FAULT_OOM) {
>> -                       do_out_of_memory(regs, address);
>> +                       do_out_of_memory(regs, address, write);
>>                         return;
>>                 } else if (fault & VM_FAULT_SIGSEGV) {
>>                         do_sigsegv(regs, write, address, si_code);
>> --
>> 2.34.1
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87wmykaf6v.fsf%40kylinos.cn.
