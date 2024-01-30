Return-Path: <kasan-dev+bncBAABBJMA4SWQMGQEZFBCRIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A9AF1842687
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 14:56:54 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68c5eeeaea7sf15196396d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 05:56:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706623013; cv=pass;
        d=google.com; s=arc-20160816;
        b=RHMRMZG++lJee1DkeV1Xa9uuJtU3P4ThYBmTzJ5B3keoyP63lh8Wl0ps70x6+8sUGQ
         Vkwm7LCoLsNArw1NeedWuwKz8X4c504F4zOxRuRct2omWvQkt16DyKtdHEWHNh+xwwND
         RazaJNWlFtIt+Z781OF1z/7SnLvnleWWlfcHwNnmAYZG0ay5/5fc6TjvG2J8F1eQVnw5
         zvfhO6K6r9+3EavapoSzDu5ZWsyxGeIjNyk6y3S08i+lYNWhBgJhkhmGk9ll5BSVjh9b
         LXHt6GHdz2wpcg3lsuC2DB1J/hU5vErLX5puNhQ/w9d4pGV63Atq2ea7/WiTn5gWzHKi
         tj3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=4cc7nxvrM637WwQgCGDfFTjnNlV+CNJOZ5w1XD710WU=;
        fh=SkinFZrIw21zxxmMKXLbCyNGssrUrO6CI2WFv9cWQ00=;
        b=vQCD97ojjgxlMsAq024PFs/tQ0ewkAZlOYOiHS9CIQWc/Y+tSmiiAy2npMhR7T25mF
         M9vYY8Diw1DMthGCrg/JTD9XDRiOcrDogCS7feNDTOX6ryOl+UNrB+7o6lwe70W35wtb
         mpcx0lYjVvqpayPL2pNY0W+k9KHM4Z9gqMGRSUoPmOfCRiSeaSN63MyLWUpUHmKGPqvY
         z9AxCFYBDxh1MTZo6LrJ2J7MWKgCDs7mdrHBNICCl0eWf8219e8eLTjzuGn3RzBV6IlD
         2NzXaS9wSMpt+KxXdZnIEyWl2Kff83HHBe76DDAAKs51jX9ZZuVjOiUd10oMGAx0OK8r
         /fwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706623013; x=1707227813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4cc7nxvrM637WwQgCGDfFTjnNlV+CNJOZ5w1XD710WU=;
        b=Sha1CGQwD40zevSRj0fWsYV2jM8h7jK+Mf3ikASbxho0cJts2+aOg7pTphEwQCB/1S
         0srHX5u/IQm2UuKqCpfNEkB1WnH/OKy8Eo3R7U6l4NKzpAGMSpJV+EBtobyZUxcsawQu
         Za/raDiLmyL2g6Ks/saYj+fjJvoYl9PF3ILPDCJGqNs7WA3QyJ1OZDSAZ2PmbpAt+MYQ
         Od8dpIHnECcjFEpZN+TAGAuzT9dw2kVyb9z0euA/mRbKWGmmizwo2wekCqdoiK33Go89
         XvL+h9iYtkL+p8xOFFiePFjQnV6y9PKUvb/LphTAvpDFvF/eGDccDMYZVrINGJeQDh51
         FaIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706623013; x=1707227813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4cc7nxvrM637WwQgCGDfFTjnNlV+CNJOZ5w1XD710WU=;
        b=J4EAXrX4gO+Y6QLS9qP8FshEpaf1UQKOITupeFMLx3WTPD7ATysbUZ1sxiC6RCl4m0
         uXCvS6mrR3Sml6wAG/L+pQCoFO1jaMe9NqPYjTC6A5egyI91Vkg35d4K9DzKHKnG8aS4
         NgEHdpltA7gm+LMfkspPBGZDtGKRrdQzK8xfveHr3BWpG1jsnlvGk/NKjq5VYKr07T76
         I5N0EAIvVim3H4Pjb9jOhPZTEnNC0J2nm/u/O/OD3AVhaINwLTMs3g/5y6+Aar2FTqGK
         x2dRaA+qovqs33nJ0Ww2SdExMXWmMnGEuOe/e6lMwkv8RplWPzjrqDCKAO/dBtiP4grs
         XWKg==
X-Gm-Message-State: AOJu0Yyybslo9yjhX14FDYw6q57GZXBmiq4dMQdVYcaHca/2VOMKpont
	4fv3S20iE/nMOj79Q1Zboy489wKd6BshvLnuF99J47zY+TlPWCTV
X-Google-Smtp-Source: AGHT+IEY/NehKXXDWAyE498jAwTtZcLktCAOw/VRDpucq/32X55RyL0khrsyH3EvEP0nU0tTGJHS2Q==
X-Received: by 2002:a05:6214:aca:b0:686:ace9:bd36 with SMTP id g10-20020a0562140aca00b00686ace9bd36mr8675231qvi.124.1706623013305;
        Tue, 30 Jan 2024 05:56:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2486:b0:68c:45f7:b89e with SMTP id
 gi6-20020a056214248600b0068c45f7b89els390628qvb.2.-pod-prod-08-us; Tue, 30
 Jan 2024 05:56:52 -0800 (PST)
X-Received: by 2002:a67:ee06:0:b0:46b:115c:30ee with SMTP id f6-20020a67ee06000000b0046b115c30eemr2932431vsp.2.1706623012662;
        Tue, 30 Jan 2024 05:56:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706623012; cv=none;
        d=google.com; s=arc-20160816;
        b=cqSqGIza0cgiF2M6mR2aMCT3Rvna7aJ3lgkUmSzmWDi3H13XTJWNQc9m5Qhn0yavW5
         yCr9El1J/JonjxGt+LGJUPFKKyzVVZvCc/ExDtP7WxiOTZBrr2xv/AyswRqw3h8jN+zh
         Tc13QY0upGVpftaSo9Pnfak9b23jB8SgsO8P4mAS4zQ4Z/H4lHfr+/7R/d0Ch4mTjQFe
         FYCCSL3o8LizRLRnzJWQZsU/pMFc/nZUX6wK5DjbaBagWtrARRgiJzv2CyHLSxpvTlYC
         r9hRpkNWlFiQrjqZysrEDL8IErWpZifI1prtmzyfVCeC9WFAG3dyGIt76AgnjDModHu0
         hHYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=2qmGtunv406cGM/BA/Bx2N841HhYOMXYVlROr2g9kVU=;
        fh=SkinFZrIw21zxxmMKXLbCyNGssrUrO6CI2WFv9cWQ00=;
        b=rrIiR+oC47PxWmXFatJ4/Qca4uNL+xHUdCkM0Q/oycQI30Q4f3gsmvEu58edduJhA7
         BqmIFP2aKnjWlSkOkF/2wXusEgfvoUoYuCHlPHuyFn+KB7WlfmSVZ558kt7pL732GE/O
         PEEgKP5sl1wTUIMASg9w5uge0VJsD7h2r4VN9w/JLXoweuavnPouiHtMq0kqQRuUUiRt
         E72ofkzdx6NGHA9bnha1nBMiwOQ2DhXBZuFOfc+133Cc9CB8I0SJ2k+IVRYUc3Tij7DB
         8uAoBTB1JN40FHp7adyg/s8aD9/uYJhCWih7/YmuC4z/6Hc+YwDt7cEZ8L8KT7tOqGON
         inFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCW2994UIXL/iQ3eR8jX0X0ioEIENjrI1ryGIfAPHVvtiim0k77DiohZcFHTtWk5YgWT68SO93igY0XPQj5ATZM3PeXvpy/60bn8wQ==
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id cw36-20020a056130222400b007d5a1d1a465si715242uab.0.2024.01.30.05.56.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 05:56:52 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4TPRXm5dNzz1vsnb;
	Tue, 30 Jan 2024 21:56:24 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 77B311A016C;
	Tue, 30 Jan 2024 21:56:49 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 21:56:47 +0800
Message-ID: <a9080311-b7a9-bb2c-13a4-650ecc8d459e@huawei.com>
Date: Tue, 30 Jan 2024 21:56:46 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v10 6/6] arm64: introduce copy_mc_to_kernel()
 implementation
To: Mark Rutland <mark.rutland@arm.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	James Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
 Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Aneesh Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>, <linuxppc-dev@lists.ozlabs.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-7-tongtiangen@huawei.com>
 <ZbjNbA1Onnjd6kyp@FVFF77S0Q05N>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZbjNbA1Onnjd6kyp@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as
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



=E5=9C=A8 2024/1/30 18:20, Mark Rutland =E5=86=99=E9=81=93:
> On Mon, Jan 29, 2024 at 09:46:52PM +0800, Tong Tiangen wrote:
>> The copy_mc_to_kernel() helper is memory copy implementation that handle=
s
>> source exceptions. It can be used in memory copy scenarios that tolerate
>> hardware memory errors(e.g: pmem_read/dax_copy_to_iter).
>>
>> Currnently, only x86 and ppc suuport this helper, after arm64 support
>> machine check safe framework, we introduce copy_mc_to_kernel()
>> implementation.
>>
>> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
>> ---
>>   arch/arm64/include/asm/string.h  |   5 +
>>   arch/arm64/include/asm/uaccess.h |  21 +++
>>   arch/arm64/lib/Makefile          |   2 +-
>>   arch/arm64/lib/memcpy_mc.S       | 257 +++++++++++++++++++++++++++++++
>>   mm/kasan/shadow.c                |  12 ++
>>   5 files changed, 296 insertions(+), 1 deletion(-)
>>   create mode 100644 arch/arm64/lib/memcpy_mc.S
>=20
> Looking at the diffstat and code, this duplicates arch/arm64/lib/memcpy.S=
 with
> a few annotations. Duplicating that code is not maintainable, and so we c=
annot
> take this as-is.
>=20
> If you want a version that can handle faults that *must* be written such =
that
> the code is shared with the regular memcpy. That could be done by using m=
acros
> to instantiate two copies (one with fault handling, the other without).
>=20
> It would also be very helpful to see *any* indication that this has been
> tested, which is sorely lacking in the series as-is.
>=20
> Mark.

OK, so that's what I'm really want to solve right now, a lot of
  duplicate code, and I'm going to think about how to deal with that.

Thank you very much for your good advice:)
Tong.

>=20
>> diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/st=
ring.h
>> index 3a3264ff47b9..995b63c26e99 100644
>> --- a/arch/arm64/include/asm/string.h
>> +++ b/arch/arm64/include/asm/string.h
>> @@ -35,6 +35,10 @@ extern void *memchr(const void *, int, __kernel_size_=
t);
>>   extern void *memcpy(void *, const void *, __kernel_size_t);
>>   extern void *__memcpy(void *, const void *, __kernel_size_t);
>>  =20
>> +#define __HAVE_ARCH_MEMCPY_MC
>> +extern int memcpy_mcs(void *, const void *, __kernel_size_t);
>> +extern int __memcpy_mcs(void *, const void *, __kernel_size_t);
>> +
>>   #define __HAVE_ARCH_MEMMOVE
>>   extern void *memmove(void *, const void *, __kernel_size_t);
>>   extern void *__memmove(void *, const void *, __kernel_size_t);
>> @@ -57,6 +61,7 @@ void memcpy_flushcache(void *dst, const void *src, siz=
e_t cnt);
>>    */
>>  =20
>>   #define memcpy(dst, src, len) __memcpy(dst, src, len)
>> +#define memcpy_mcs(dst, src, len) __memcpy_mcs(dst, src, len)
>>   #define memmove(dst, src, len) __memmove(dst, src, len)
>>   #define memset(s, c, n) __memset(s, c, n)
>>  =20
>> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/u=
access.h
>> index 14be5000c5a0..61e28ef2112a 100644
>> --- a/arch/arm64/include/asm/uaccess.h
>> +++ b/arch/arm64/include/asm/uaccess.h
>> @@ -425,4 +425,25 @@ static inline size_t probe_subpage_writeable(const =
char __user *uaddr,
>>  =20
>>   #endif /* CONFIG_ARCH_HAS_SUBPAGE_FAULTS */
>>  =20
>> +#ifdef CONFIG_ARCH_HAS_COPY_MC
>> +/**
>> + * copy_mc_to_kernel - memory copy that handles source exceptions
>> + *
>> + * @dst:	destination address
>> + * @src:	source address
>> + * @len:	number of bytes to copy
>> + *
>> + * Return 0 for success, or #size if there was an exception.
>> + */
>> +static inline unsigned long __must_check
>> +copy_mc_to_kernel(void *to, const void *from, unsigned long size)
>> +{
>> +	int ret;
>> +
>> +	ret =3D memcpy_mcs(to, from, size);
>> +	return (ret =3D=3D -EFAULT) ? size : 0;
>> +}
>> +#define copy_mc_to_kernel copy_mc_to_kernel
>> +#endif
>> +
>>   #endif /* __ASM_UACCESS_H */
>> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
>> index a2fd865b816d..899d6ae9698c 100644
>> --- a/arch/arm64/lib/Makefile
>> +++ b/arch/arm64/lib/Makefile
>> @@ -3,7 +3,7 @@ lib-y		:=3D clear_user.o delay.o copy_from_user.o		\
>>   		   copy_to_user.o copy_page.o				\
>>   		   clear_page.o csum.o insn.o memchr.o memcpy.o		\
>>   		   memset.o memcmp.o strcmp.o strncmp.o strlen.o	\
>> -		   strnlen.o strchr.o strrchr.o tishift.o
>> +		   strnlen.o strchr.o strrchr.o tishift.o memcpy_mc.o
>>  =20
>>   ifeq ($(CONFIG_KERNEL_MODE_NEON), y)
>>   obj-$(CONFIG_XOR_BLOCKS)	+=3D xor-neon.o
>> diff --git a/arch/arm64/lib/memcpy_mc.S b/arch/arm64/lib/memcpy_mc.S
>> new file mode 100644
>> index 000000000000..7076b500d154
>> --- /dev/null
>> +++ b/arch/arm64/lib/memcpy_mc.S
>> @@ -0,0 +1,257 @@
>> +/* SPDX-License-Identifier: GPL-2.0-only */
>> +/*
>> + * Copyright (c) 2012-2021, Arm Limited.
>> + *
>> + * Adapted from the original at:
>> + * https://github.com/ARM-software/optimized-routines/blob/afd6244a1f8d=
9229/string/aarch64/memcpy.S
>> + */
>> +
>> +#include <linux/linkage.h>
>> +#include <asm/assembler.h>
>> +
>> +/* Assumptions:
>> + *
>> + * ARMv8-a, AArch64, unaligned accesses.
>> + *
>> + */
>> +
>> +#define L(label) .L ## label
>> +
>> +#define dstin	x0
>> +#define src	x1
>> +#define count	x2
>> +#define dst	x3
>> +#define srcend	x4
>> +#define dstend	x5
>> +#define A_l	x6
>> +#define A_lw	w6
>> +#define A_h	x7
>> +#define B_l	x8
>> +#define B_lw	w8
>> +#define B_h	x9
>> +#define C_l	x10
>> +#define C_lw	w10
>> +#define C_h	x11
>> +#define D_l	x12
>> +#define D_h	x13
>> +#define E_l	x14
>> +#define E_h	x15
>> +#define F_l	x16
>> +#define F_h	x17
>> +#define G_l	count
>> +#define G_h	dst
>> +#define H_l	src
>> +#define H_h	srcend
>> +#define tmp1	x14
>> +
>> +/* This implementation handles overlaps and supports both memcpy and me=
mmove
>> +   from a single entry point.  It uses unaligned accesses and branchles=
s
>> +   sequences to keep the code small, simple and improve performance.
>> +
>> +   Copies are split into 3 main cases: small copies of up to 32 bytes, =
medium
>> +   copies of up to 128 bytes, and large copies.  The overhead of the ov=
erlap
>> +   check is negligible since it is only required for large copies.
>> +
>> +   Large copies use a software pipelined loop processing 64 bytes per i=
teration.
>> +   The destination pointer is 16-byte aligned to minimize unaligned acc=
esses.
>> +   The loop tail is handled by always copying 64 bytes from the end.
>> +*/
>> +
>> +SYM_FUNC_START(__pi_memcpy_mcs)
>> +	add	srcend, src, count
>> +	add	dstend, dstin, count
>> +	cmp	count, 128
>> +	b.hi	L(copy_long)
>> +	cmp	count, 32
>> +	b.hi	L(copy32_128)
>> +
>> +	/* Small copies: 0..32 bytes.  */
>> +	cmp	count, 16
>> +	b.lo	L(copy16)
>> +	CPY_MC(9998f, ldp	A_l, A_h, [src])
>> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
>> +	mov x0, #0
>> +	ret
>> +
>> +	/* Copy 8-15 bytes.  */
>> +L(copy16):
>> +	tbz	count, 3, L(copy8)
>> +	CPY_MC(9998f, ldr	A_l, [src])
>> +	CPY_MC(9998f, ldr	A_h, [srcend, -8])
>> +	CPY_MC(9998f, str	A_l, [dstin])
>> +	CPY_MC(9998f, str	A_h, [dstend, -8])
>> +	mov x0, #0
>> +	ret
>> +
>> +	.p2align 3
>> +	/* Copy 4-7 bytes.  */
>> +L(copy8):
>> +	tbz	count, 2, L(copy4)
>> +	CPY_MC(9998f, ldr	A_lw, [src])
>> +	CPY_MC(9998f, ldr	B_lw, [srcend, -4])
>> +	CPY_MC(9998f, str	A_lw, [dstin])
>> +	CPY_MC(9998f, str	B_lw, [dstend, -4])
>> +	mov x0, #0
>> +	ret
>> +
>> +	/* Copy 0..3 bytes using a branchless sequence.  */
>> +L(copy4):
>> +	cbz	count, L(copy0)
>> +	lsr	tmp1, count, 1
>> +	CPY_MC(9998f, ldrb	A_lw, [src])
>> +	CPY_MC(9998f, ldrb	C_lw, [srcend, -1])
>> +	CPY_MC(9998f, ldrb	B_lw, [src, tmp1])
>> +	CPY_MC(9998f, strb	A_lw, [dstin])
>> +	CPY_MC(9998f, strb	B_lw, [dstin, tmp1])
>> +	CPY_MC(9998f, strb	C_lw, [dstend, -1])
>> +L(copy0):
>> +	mov x0, #0
>> +	ret
>> +
>> +	.p2align 4
>> +	/* Medium copies: 33..128 bytes.  */
>> +L(copy32_128):
>> +	CPY_MC(9998f, ldp	A_l, A_h, [src])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -32])
>> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
>> +	cmp	count, 64
>> +	b.hi	L(copy128)
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
>> +	mov x0, #0
>> +	ret
>> +
>> +	.p2align 4
>> +	/* Copy 65..128 bytes.  */
>> +L(copy128):
>> +	CPY_MC(9998f, ldp	E_l, E_h, [src, 32])
>> +	CPY_MC(9998f, ldp	F_l, F_h, [src, 48])
>> +	cmp	count, 96
>> +	b.ls	L(copy96)
>> +	CPY_MC(9998f, ldp	G_l, G_h, [srcend, -64])
>> +	CPY_MC(9998f, ldp	H_l, H_h, [srcend, -48])
>> +	CPY_MC(9998f, stp	G_l, G_h, [dstend, -64])
>> +	CPY_MC(9998f, stp	H_l, H_h, [dstend, -48])
>> +L(copy96):
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
>> +	CPY_MC(9998f, stp	E_l, E_h, [dstin, 32])
>> +	CPY_MC(9998f, stp	F_l, F_h, [dstin, 48])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
>> +	mov x0, #0
>> +	ret
>> +
>> +	.p2align 4
>> +	/* Copy more than 128 bytes.  */
>> +L(copy_long):
>> +	/* Use backwards copy if there is an overlap.  */
>> +	sub	tmp1, dstin, src
>> +	cbz	tmp1, L(copy0)
>> +	cmp	tmp1, count
>> +	b.lo	L(copy_long_backwards)
>> +
>> +	/* Copy 16 bytes and then align dst to 16-byte alignment.  */
>> +
>> +	CPY_MC(9998f, ldp	D_l, D_h, [src])
>> +	and	tmp1, dstin, 15
>> +	bic	dst, dstin, 15
>> +	sub	src, src, tmp1
>> +	add	count, count, tmp1	/* Count is now 16 too large.  */
>> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstin])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
>> +	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
>> +	subs	count, count, 128 + 16	/* Test and readjust count.  */
>> +	b.ls	L(copy64_from_end)
>> +
>> +L(loop64):
>> +	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
>> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dst, 64]!)
>> +	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
>> +	subs	count, count, 64
>> +	b.hi	L(loop64)
>> +
>> +	/* Write the last iteration and copy 64 bytes from the end.  */
>> +L(copy64_from_end):
>> +	CPY_MC(9998f, ldp	E_l, E_h, [srcend, -64])
>> +	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
>> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -48])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -16])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dst, 64])
>> +	CPY_MC(9998f, stp	E_l, E_h, [dstend, -64])
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -48])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -16])
>> +	mov x0, #0
>> +	ret
>> +
>> +	.p2align 4
>> +
>> +	/* Large backwards copy for overlapping copies.
>> +	   Copy 16 bytes and then align dst to 16-byte alignment.  */
>> +L(copy_long_backwards):
>> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
>> +	and	tmp1, dstend, 15
>> +	sub	srcend, srcend, tmp1
>> +	sub	count, count, tmp1
>> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
>> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
>> +	sub	dstend, dstend, tmp1
>> +	subs	count, count, 128
>> +	b.ls	L(copy64_from_start)
>> +
>> +L(loop64_backwards):
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
>> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64]!)
>> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
>> +	subs	count, count, 64
>> +	b.hi	L(loop64_backwards)
>> +
>> +	/* Write the last iteration and copy 64 bytes from the start.  */
>> +L(copy64_from_start):
>> +	CPY_MC(9998f, ldp	G_l, G_h, [src, 48])
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
>> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 32])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
>> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
>> +	CPY_MC(9998f, ldp	C_l, C_h, [src])
>> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64])
>> +	CPY_MC(9998f, stp	G_l, G_h, [dstin, 48])
>> +	CPY_MC(9998f, stp	A_l, A_h, [dstin, 32])
>> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
>> +	CPY_MC(9998f, stp	C_l, C_h, [dstin])
>> +	mov x0, #0
>> +	ret
>> +
>> +9998:	mov x0, #-EFAULT
>> +	ret
>> +SYM_FUNC_END(__pi_memcpy_mcs)
>> +
>> +SYM_FUNC_ALIAS(__memcpy_mcs, __pi_memcpy_mcs)
>> +EXPORT_SYMBOL(__memcpy_mcs)
>> +SYM_FUNC_ALIAS_WEAK(memcpy_mcs, __memcpy_mcs)
>> +EXPORT_SYMBOL(memcpy_mcs)
>> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
>> index 9ef84f31833f..e6519fd329b2 100644
>> --- a/mm/kasan/shadow.c
>> +++ b/mm/kasan/shadow.c
>> @@ -79,6 +79,18 @@ void *memcpy(void *dest, const void *src, size_t len)
>>   }
>>   #endif
>>  =20
>> +#ifdef __HAVE_ARCH_MEMCPY_MC
>> +#undef memcpy_mcs
>> +int memcpy_mcs(void *dest, const void *src, size_t len)
>> +{
>> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
>> +		return (unsigned long)len;
>> +
>> +	return __memcpy_mcs(dest, src, len);
>> +}
>> +#endif
>> +
>>   void *__asan_memset(void *addr, int c, ssize_t len)
>>   {
>>   	if (!kasan_check_range(addr, len, true, _RET_IP_))
>> --=20
>> 2.25.1
>>
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a9080311-b7a9-bb2c-13a4-650ecc8d459e%40huawei.com.
