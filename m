Return-Path: <kasan-dev+bncBAABBI66XK6QMGQE7WCGEFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EAA3FA35505
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 03:49:09 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-220d1c24b25sf35593955ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 18:49:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739501348; cv=pass;
        d=google.com; s=arc-20240605;
        b=RelZPUUk8UzYvhtosBjHZfNNb3hNuLi9TBQUvA4LctpfoGeflx2dbV5cXhE4IDgKXY
         E+MwlL7N3d/SFDUE6bIfRoXO5GV+oSyPb1V5Ueqd7MMLdhirKwr3VS7j8uFyGb9VU616
         LgIh4vReLxowB7ZNT0AMpr+KNkiVVFWgzPGKWOHZ5KnPfO+8qdCRN07f/NWvYe5MCxxX
         UgboFaxujyA1fwFCujx421II+gKV+j2gCqn1NNYaCu5tyYaeyI8lkPc2wuLUa0jAnZxn
         C1xRCTbDu2qNJoGdWwA3L49YGNy/tp4v4vqG18/PHhnYZ9KMn3Vf0pnCN0poTNpfZb19
         klpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=7F6pvtr4xTBNZP/9kQFfqAnZGnT1BkPI3SHxgs5sf5g=;
        fh=w7ceXuAKRXAVpExACyJwEVWvkugFKC/Swr8B0SPVQC0=;
        b=MSkhfV09GkHu4SG4DTisXVhuQrX4tDskSy5RwaVNgwPXaUEF1qn0UYCu+2JPscOQhU
         2YXU7x9Nh5rfQfF5XVgtnOKRR5T/XU2ddCZYnwXYsrpnv1cIHOWDovwqeFKKfouD0uTq
         4G+SuRmSnJQTY5yF8Qm5vZQYm6/qNBTY39KV5nYi/Ws16W2daYq0Qq26B4jpqzhWZZE/
         bOGHLFcolos4KNtFWyIxr9Qhle+u3wEkje43aico+ADUyy2UTI8XQZUcAB8mQSZ+W4Sw
         6wvRMIbkpoOwnP1S5VCgqT8isDToNml4yrCHm4j+ZkxsmTn7LqsjY334HksGgfx7x/hq
         Oxkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739501348; x=1740106148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7F6pvtr4xTBNZP/9kQFfqAnZGnT1BkPI3SHxgs5sf5g=;
        b=gB8dgj13j7HBnnWZXegRNomQ0tKwUqA4HJm/HLDafScKEfffMhDiN6tD4+Y5URkmEc
         zahMr9En7k12seVlylq1FtfUg5Knc4PmsjGwNOSmfomFrFfDRgFpUSls7n/TJ2pcmi3u
         Tfh+/y7m3YrbtjqjCUA6deGVVm2rby2sPA5h34a9TdXHzhuTIUDlaECWqsGyRbILLnDA
         bI4Y5OiQzqEJDDdbC697FBPTrPmNQJkhbxMgC//giwG/w3qiKt+RvWUxVI2tTeDmzaSu
         t+7R8wnuwm4TB4teH0GYZMnjH9c1N+8ji2WDF4GdfW3f27lPKaxNvfQKkdYp6eR78RD9
         GbqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739501348; x=1740106148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7F6pvtr4xTBNZP/9kQFfqAnZGnT1BkPI3SHxgs5sf5g=;
        b=RdMs7NAuC5rWfjmy5zys5ozADNIOf3e120EczPhCkhSxf0r77K26xw3LYlA7xqsMtq
         pliXp5i0aUo4kft4+HQK38X9J/6g55hcyMXPOtpuCmWXbPyY2FE/98IwZPms2qC8sjnY
         5HVjhixGQGk410RUgXa1x/Yz33PT6gO7sIB/gy3CqKAWSmI+InGIpsCl4oOG93iuho6q
         QsDKUhfYTnqy1Y5f159jqw5As3urIT5wg3hk4pCmcGxo12dD2xwsDiNWiVYEugQs56kn
         uRJflYV8CZIK5cC1VLBxdXAq9KCbMtBN9LfEOptZTw8xR0KNikQSK0TzXAWYmEE8AbBu
         Yw9g==
X-Forwarded-Encrypted: i=2; AJvYcCW5femOhw/VQd/LYHR1Aj+dtjngwZCTP1rUx2J+ZrGVA8qJC+zoHPofXCdJoelh4+vYsYP9Xw==@lfdr.de
X-Gm-Message-State: AOJu0YyQDsUO+Gt2TadUC7zjMRr7ctfYE3tQvSwSP8WOf0qHJuWRB8O8
	YslbbxjuwwQ0878hJhVqYlI+RwbibfnDIMYlosjvOtVRldXJkBnf
X-Google-Smtp-Source: AGHT+IGcW2qwQElu74Y9U5Wm31OsntSIcXte2JwNhQFHUfHbFZbru5tYUdL3CcKC/CmCZvOXqT5ZPQ==
X-Received: by 2002:a05:6a21:99a5:b0:1e1:a716:3172 with SMTP id adf61e73a8af0-1ee6b2fb49cmr9772726637.12.1739501348041;
        Thu, 13 Feb 2025 18:49:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEzH4KWwZphkDAD2R3eXBKXnuq0wtPX9bw2nn+gQ8GKiw==
Received: by 2002:a05:6a00:6304:b0:730:9340:6635 with SMTP id
 d2e1a72fcca58-7323bddbad8ls1510582b3a.0.-pod-prod-05-us; Thu, 13 Feb 2025
 18:49:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVxFLF+vJsWkTjT3kEDhGwVjU7S4IpyQXixIM9H1UQxGCIWNnG7LrfaYhCyAroazhguGNYDDv+b3Fk=@googlegroups.com
X-Received: by 2002:a05:6a21:3289:b0:1e0:d0c8:7100 with SMTP id adf61e73a8af0-1ee6b2e1d5emr10829119637.7.1739501346941;
        Thu, 13 Feb 2025 18:49:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739501346; cv=none;
        d=google.com; s=arc-20240605;
        b=WYduFqbu5Sz4Mq3UtLPoPSTKyuB8c649mXGHXa9y3LMxvWMCWTG2u0C1KSRG6RB/cb
         x4N0oEdZ9dasvXPyRqLFFx7+qSnOqLMAdkQffHszRlLb9n2yVslGNnvkYUdbY48OX/E1
         jhQjL9xfr9gTdUuh2beuY6VcfXi4MUkyzMfEwwR6jc+h3bckakd3hL6/eKJw5nF/whv0
         fMxfc/rFPyExOt4RF4eEySOvWyI05o4DJS5eq7WBaSLQ7skMklRNE33xXjp0qJBNv0mS
         Pmvbtx3TPqzExr+86OmYn7v6lLVHay/D8PnuJFDZriiWmhJvYlOqPTkyl+rBd5NENtxq
         VYDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=Qdv27WOOjvDepPMV24X/lprplWgreW0f92yGmOb5lxY=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=DU3JDGxDB1rNlBoGbfIdl9qkYF+ge0qDTZ2sd0nI6sQunE/71+1hFMyWIlnYQ9AiUc
         73FeP1m5WvaMaZie7VHJfya0G/Lk1WiJLfY7+ZnPAddIWE/9cnwFxSZHFa/sF/ZljK0/
         6kWCH1WL9i9ueu245Giu52iHONeCwzSpc8GprG7OSqqlZVuO5tkKIrsHwdIDIPgRvIwN
         WJheF6S+VHaPLVIEL2Q4s4eeofeISWRN9ahyYWPLNMdSpB2c1OMWUXvmp1QN8Sz1+X1n
         YWztEbOO6JRBWL5vIKI0KtvEE6B+BOBk47lsMzTlA6AL5XyTIVyK9wcA1YyELSpkdHAc
         pHKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73242766706si128331b3a.5.2025.02.13.18.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Feb 2025 18:49:06 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.163.17])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4YvGcX1dFHz2FdPV;
	Fri, 14 Feb 2025 10:45:16 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 362F01A0188;
	Fri, 14 Feb 2025 10:49:04 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Fri, 14 Feb 2025 10:49:01 +0800
Message-ID: <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com>
Date: Fri, 14 Feb 2025 10:49:01 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, James Morse <james.morse@arm.com>, Robin Murphy
	<robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Aneesh
 Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com> <Z6zWSXzKctkpyH7-@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z6zWSXzKctkpyH7-@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
> On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
>> Currently, many scenarios that can tolerate memory errors when copying p=
age
>> have been supported in the kernel[1~5], all of which are implemented by
>> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
>>
>> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
>> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
>> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>>
>> Add new helper copy_mc_page() which provide a page copy implementation w=
ith
>> hardware memory error safe. The code logic of copy_mc_page() is the same=
 as
>> copy_page(), the main difference is that the ldp insn of copy_mc_page()
>> contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefore, the
>> main logic is extracted to copy_page_template.S. In addition, the fixup =
of
>> MOPS insn is not considered at present.
>=20
> Could we not add the exception table entry permanently but ignore the
> exception table entry if it's not on the do_sea() path? That would save
> some code duplication.

I'm sorry, I didn't catch your point, that the do_sea() and non do_sea()
paths use different exception tables? My understanding is that the
exception table entry problem is fine. After all, the search is
performed only after a fault trigger. Code duplication can be solved by
extracting repeated logic to a public file.

>=20
>> diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page=
.S
>> new file mode 100644
>> index 000000000000..51564828c30c
>> --- /dev/null
>> +++ b/arch/arm64/lib/copy_mc_page.S
>> @@ -0,0 +1,37 @@
>> +/* SPDX-License-Identifier: GPL-2.0-only */
>> +
>> +#include <linux/linkage.h>
>> +#include <linux/const.h>
>> +#include <asm/assembler.h>
>> +#include <asm/page.h>
>> +#include <asm/cpufeature.h>
>> +#include <asm/alternative.h>
>> +#include <asm/asm-extable.h>
>> +#include <asm/asm-uaccess.h>
>> +
>> +/*
>> + * Copy a page from src to dest (both are page aligned) with memory err=
or safe
>> + *
>> + * Parameters:
>> + *	x0 - dest
>> + *	x1 - src
>> + * Returns:
>> + * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
>> + *	     while copying.
>> + */
>> +	.macro ldp1 reg1, reg2, ptr, val
>> +	KERNEL_MEM_ERR(9998f, ldp \reg1, \reg2, [\ptr, \val])
>> +	.endm
>> +
>> +SYM_FUNC_START(__pi_copy_mc_page)
>> +#include "copy_page_template.S"
>> +
>> +	mov x0, #0
>> +	ret
>> +
>> +9998:	mov x0, #-EFAULT
>> +	ret
>> +
>> +SYM_FUNC_END(__pi_copy_mc_page)
>> +SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
>> +EXPORT_SYMBOL(copy_mc_page)
> [...]
>> diff --git a/arch/arm64/lib/copy_page_template.S b/arch/arm64/lib/copy_p=
age_template.S
>> new file mode 100644
>> index 000000000000..f96c7988c93d
>> --- /dev/null
>> +++ b/arch/arm64/lib/copy_page_template.S
>> @@ -0,0 +1,70 @@
>> +/* SPDX-License-Identifier: GPL-2.0-only */
>> +/*
>> + * Copyright (C) 2012 ARM Ltd.
>> + */
>> +
>> +/*
>> + * Copy a page from src to dest (both are page aligned)
>> + *
>> + * Parameters:
>> + *	x0 - dest
>> + *	x1 - src
>> + */
>> +
>> +#ifdef CONFIG_AS_HAS_MOPS
>> +	.arch_extension mops
>> +alternative_if_not ARM64_HAS_MOPS
>> +	b	.Lno_mops
>> +alternative_else_nop_endif
>> +
>> +	mov	x2, #PAGE_SIZE
>> +	cpypwn	[x0]!, [x1]!, x2!
>> +	cpymwn	[x0]!, [x1]!, x2!
>> +	cpyewn	[x0]!, [x1]!, x2!
>> +	ret
>> +.Lno_mops:
>> +#endif
> [...]
>=20
> So if we have FEAT_MOPS, the machine check won't work?
>=20
> Kristina is going to post MOPS support for the uaccess routines soon.
> You can see how they are wired up and do something similar here.
>=20
> But I'd prefer if we had the same code, only the exception table entry
> treated differently. Similarly for the MTE tag copying.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
9955002-c3b1-459d-9b42-8d07475c3fd3%40huawei.com.
