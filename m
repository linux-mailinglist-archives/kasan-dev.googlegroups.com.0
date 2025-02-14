Return-Path: <kasan-dev+bncBAABBWWAXK6QMGQEQJO2ZJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB0BA353DE
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 02:46:04 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6e664e086f1sf7086306d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 17:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739497563; cv=pass;
        d=google.com; s=arc-20240605;
        b=VsVZsTBveQ3ZAWhllXRiZKad3VY2n2GwLL6Z93slW0t7IByewuzWxe4rrQmkIO8krz
         /ikVrD2xuOG0gDqx0pSPTJ8UkcKDgdUTrzIvWSqwSYBOC73ECIa9baxjdjkEP7Ywqkc7
         QU8Cy9XS7EbxdXUbCDeHBZ1u2FoO5iqoR/SF8BNXwnGVvEmz5kwf5QvkAQGXWgZohROZ
         L4vo9O53WevlJBx2Ls+0/8QmVOknKqmpKtWU+lNJgQFa+7QsG182juqO/pMkYmu3408H
         7d7ptOasZR3DeLQcrvy2kXsxFFOa5fEr4mg5WTULcvBVl1RHeMg+w4k2PrX5rSak6/H8
         lK9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=bm8h3n+bEswr8styf+nZOHtlVnHSqaG5DGS63w85o5U=;
        fh=CuKw/wcKT44lx4qDyGjPULWlKGLFLeyAbiiY2Ilfd78=;
        b=dxhI9vq4KfCRhysF7PadB/32AlzJLun+gPrLkubI9FdcO2VvwkyanXBVZcRA9b+4ru
         HP1NEKLVLmDbShcIuH3UJFJi1Hf0o/vnBPazkmHQm4ySTiOftMvmNyABd8xwXJscsrh2
         DbdtzEoOBrqjd0/4KDR6I21R1OBhnxf1bKVETeixkASU3q7J5CXXUY9PK4XDrovn3TH6
         MykOkzxKv+jHIoRBk0ZCZjIfU59Si5tMJDoo2Fco1i8WCEAdLdyCg/1aaV7Snv1haNvy
         4dPcn4Cncv1NWBiWqIUTbDM2h5+kH63xk1lmUiQiDKdutOJ2cEe+cV2F3cab2+sUgctX
         MHGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739497563; x=1740102363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bm8h3n+bEswr8styf+nZOHtlVnHSqaG5DGS63w85o5U=;
        b=Bwu/okEEEWQCsIL+uuH0zGTYKmw2Yx1/9dB8/Fucii/X18I025fDqvYsRkd3xoEaq3
         fQk/xHrUBCpCeJSmaUE1GGfF+dynStfLT5u02V2hRbZRS0586CUCWUZ7ENafuMc2K8Gn
         wKvHQPpAnj5yMim0iKL5/zUEfkEDpDERHzRz/qM6/WaLhuJ7Q4v/HIz7+v4Kmrtw6qZH
         Rfv9HcVs52SJOoIzZRU07P0oWDs39aMVXk7NPYKZAxMvMXx/rlxE1t7VwP+DbwDcqEpB
         F4kfgac7mNJ6imjqCm2ZQQRJhhg/Vk9dQsHYM8bYnD81C9g4oh5S+QA8IROFhciKESt9
         X+/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739497563; x=1740102363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bm8h3n+bEswr8styf+nZOHtlVnHSqaG5DGS63w85o5U=;
        b=JK8JRXMrD+Kzq1Hjz39og6ARf3NPKQU2bu16sXfvH+Sgv57jyDzuz+aJ9Oms/e0L4+
         sKy62oZ9zpQb0ZiSvTl3ocx8FxDFmenug8BgiKhP7pef5P4lvg18fupsvjSbnApDvsTj
         Vc71BIfA27UYBd3TR1FNDshOYWiTwp9ZxBA9i+YFlGxxoqopoVIyiyjLeZ/crvoWUHHL
         rXswWIo94YrTCppoYK1ycg7Lp+3nMfb7WVauyuEQ7Jom9oGmbOQsDqjKdrF8IiJRrblz
         z6hZtLchW73Y3qY6pI6QkL3EILuc+hiDEfF+5Tu3F1673ojj2QfzBa9BrDd39X6w0t8I
         Yfmg==
X-Forwarded-Encrypted: i=2; AJvYcCXZRSIQ+fYLIMSJeICvyM2FpWqf+M9NhkNLEckTsUHRxMBgXoUjDEhjC9ydhCrtNJskpRsghQ==@lfdr.de
X-Gm-Message-State: AOJu0YzZLcUll9PTZ/a2ElJBvBr7ajQe8nl5fUi813m111rqK9tcylzK
	PjOTz/EV0AqWRX3yQ7yGRVhfeOuBq2IBq30r8IxMCMN8Z+wCLDmF
X-Google-Smtp-Source: AGHT+IE14ZEut0T40YiUGTzNz3DX5/p6XgbElL/vJCzO3PduJQVx+IFI3vDrm51EYd79ShSzLJlYBw==
X-Received: by 2002:ad4:5d68:0:b0:6e6:5fe5:a596 with SMTP id 6a1803df08f44-6e65ff4e8ebmr57457266d6.19.1739497563082;
        Thu, 13 Feb 2025 17:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG4Vt313pajoyMv7xu+NlTtt+lMXfCYjnu9NgZYi+ONLw==
Received: by 2002:a05:6214:5ec8:b0:6e1:8e40:5ef6 with SMTP id
 6a1803df08f44-6e65c1dee96ls10564616d6.0.-pod-prod-03-us; Thu, 13 Feb 2025
 17:46:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW72KxJnXI4GNofhm1pUDh3Ix+SueXZ2WNpU/FbwKwhGNbpXrhgVhqNKvEgKy0ba7UTMK5tsYJ+D7g=@googlegroups.com
X-Received: by 2002:a05:6122:3109:b0:50d:a31c:678c with SMTP id 71dfb90a1353d-52067bf1a31mr9513148e0c.2.1739497562317;
        Thu, 13 Feb 2025 17:46:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739497562; cv=none;
        d=google.com; s=arc-20240605;
        b=V1vZZtwsM85I5f94SNAZe1JbmXFZHyP5sA6fkqUm9N+06lUXL4WaWjFvp0A39AcenG
         zlkiLh4kNhAfdPsi/Fo0uO7+wZO2gnxxKd9UAJ1RJpFZadJ07LCi+Jn47DgCnGf3RGyf
         PPlyq4KnGihCtg4gfl0gN88Bm++k1kCPK+RI8kXjUEWTLQDde7yMVDcOhmtiEv+a6U3j
         oMTIZsppVuxs1qz+eakw3/34QOM3b2cgpbI5sgIGtaA/ZAnbL+QCZ1fg39Is31zP9lBw
         QUrr462dpAIkozrjnK1IJ59xViM3Ea+0KGxNMz59er7X1ZEYXV9AS100GpboJl8vwWat
         LNNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=/xou2uZRbnImxMqVFANwRB9AlkIaAnGUiupsZKCr/kI=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=M46FE3j8OHkJI5wJP2Tdoo79UVSQDOGNKC0bNaFWVi8hxGzdDdtBTQ8dVO9v2LG74h
         qnlTvSlQuEt9UYlb3cFYet5idVngdvvFUuc9TYVDOqUKbm2ncxX9LKZzV8IMjn6iagFC
         BkCfNiheFl5UDLkaVlSuxKhAkx877okX7/gZTwJhfxC32mMuq5ameRDk9Up6kF9jUAaO
         266d9mK//AQ6PJZEKRHN+BjgIQLbv/fJa14cNqSl9tuA3uL0lARseE81l1Hty+tehVTi
         EEmSkD/6VMiDSnqOdmk6UpUcuWSlF/f8I8d+29kDUOOEVkZ6S7Fnav9pBziQjA3M3zVI
         fONQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5207aa45a6dsi129764e0c.1.2025.02.13.17.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Feb 2025 17:46:02 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.162.254])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4YvFBx5FCVz1W5g8;
	Fri, 14 Feb 2025 09:41:29 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id CA0DB18032E;
	Fri, 14 Feb 2025 09:45:58 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Fri, 14 Feb 2025 09:45:56 +0800
Message-ID: <6aecab97-5ba8-38dd-1df7-87e5f557017e@huawei.com>
Date: Fri, 14 Feb 2025 09:45:55 +0800
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
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as
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

The location of the added exception table entry is likely to appear on
the a path, which should not be avoided. What we can do is merge
duplicate code as much as possible, and extract common code into common
files, as we did in this patch.


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

Does MOPS also support features similar to memory error safe? I'll see
how he handles it.

>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
aecab97-5ba8-38dd-1df7-87e5f557017e%40huawei.com.
