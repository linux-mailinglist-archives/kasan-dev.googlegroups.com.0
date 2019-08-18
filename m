Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBLEK4PVAKGQEPY74SYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DF1EF91450
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Aug 2019 05:25:34 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id m19sf52560pgv.7
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 20:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566098733; cv=pass;
        d=google.com; s=arc-20160816;
        b=ipdul7ZwlGFGHR7ZfO3mXxlYFCJhqhSq/sClS3cc5YYRSeRuhuNFIP+lqj2JlQBJQp
         PEzeRWhmaxu/DmnuvL8WnrXOcbM1CV9lebzpBLuG0QJUTwN3gwUnt7+Z8GyU+hUUB2Ys
         /ReuOHQfV0XydnMj3Is/BlrEG1JL9JanIi4rV99SQgOhHpsb9zWHmYvgbV1qMC3OKucL
         O9/Zxh9mfPCU1o6VBK5zhCE0lN2IvCacN3FJK9+XMeRqP+wwISX9QH9vt+N8omob/0v4
         XmUfPDFLYSEQHt94dWWtFAD225/XNDUniVJW4fvCURZzd2FABDTQfNiwliVFCjgcw7WD
         RunA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=SmMsdDujg1DWFV1ohiSDg7jaZMBnN8pgp6Fy2DTMe4k=;
        b=aeKU0vAVQQC1tarrb7IuOM7A0spEsj5/sM0v56qMW1fNnVbB7md/HAvGum/8AQkuOd
         qJdgBoNhT1aLJjLCbsnX+AmT9Q7UfnfNH1e9oB7HgBB6FUGf2PUv2Be03PKazT6h/JRV
         N5mhOKpxi+abFYxGAjIa0usVh6Ld/0ptL4ATNOQCfdfzexXECpuNLAT4yKDZJHn92mKB
         URijjK1kJjPOUprjyPONsclbrMKgrumQ9j0TzLZWNqlAJZrwYU1Eee+HeoOg0daiVxnr
         1LBFvJBWYskdd60cEg/eJhmpvihl4jf1lQf2uJqQ3SgPiFMjB7lQ7gD98n0pLPN2dz5T
         eXpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=dY9He6fm;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SmMsdDujg1DWFV1ohiSDg7jaZMBnN8pgp6Fy2DTMe4k=;
        b=IlwjGSpO6z09OW2a8Ga7Ug13fumgufjR41Y5fMDjzLcsJV6NV9Hx4Rjwaso+6u1xiP
         1vn7i20Mi6d7Hd9wZLxTw8E+F+7fWmdvW3hOqcSYpzYorEtJ6rnMxj2eQaiXuErXmERj
         KqMdhL4tm4XCu1B2WKGkXn9ziccYn/3cnThuY/c9Xy7bnBeYo9Ik50IwYVHGTtHNAZRt
         SCMKQ33lZ+aX/i1DLVq5JVBvSvPefXuPbDNdCbfhJLkIMFW0O0r+VqcAsCLCbunW+RhS
         f8+wWhNXI9JhsB4lnoCklOkuTXrydD7G7Y3ZltJiptf44r93xSKZB0tR8L5Uw7UYolcp
         qFEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SmMsdDujg1DWFV1ohiSDg7jaZMBnN8pgp6Fy2DTMe4k=;
        b=Fx5x2LdhV9Ba7Dd7ZHBJUQEsuKEhfTjlmMM/v7epSOCeukrH7PiAX+67uGKcWe5XUj
         Z4cVtoiflSsTmiI5niuSjnCti4+lqmlAb8IoIFyU7HP6arzGTQ4o/D5zt/7mSZi/0jtT
         0e1R73Q2R1fqMDv6UCwuIywzIWxDNhgPH7UN5Ei8B6q/Stvw8a9b0gIxJ1zXd8GTqX6p
         Y7BNZ1TrBMeuHkZugNBndHsDU6Eq79cA+yzHTx399wSI7UigyqLcJMuDFCnzn2SxpIrH
         V2PlC5pTVnfXRJfIWo2WiFDTbH3uvkX4+mkzDnjOiTTMi2x8rsBHYKdKZ47qHobd9bYD
         fTRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUrC78NSzZGpJUl6cHqbNYOFbXvWmlOBlzED5AWAEgclPp3FetW
	mw072PMGeZrLDQLsn2zRQno=
X-Google-Smtp-Source: APXvYqw/ZwkuSMFVa4nbUTA29Yi6GcQFBXr914tEn+BAqpSZiqEfRpVDFZBs2FdI3QQZV+eoWs4IWg==
X-Received: by 2002:a62:4e05:: with SMTP id c5mr18059175pfb.66.1566098733001;
        Sat, 17 Aug 2019 20:25:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:614e:: with SMTP id o14ls2637055pgv.7.gmail; Sat, 17 Aug
 2019 20:25:32 -0700 (PDT)
X-Received: by 2002:a63:841:: with SMTP id 62mr13080485pgi.1.1566098732538;
        Sat, 17 Aug 2019 20:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566098732; cv=none;
        d=google.com; s=arc-20160816;
        b=PcGeWdJXgeOWC4Wb1EAU4SXrehg9b/JZDpLlyRacJAG2erjhJuUMSXfjYNLFiVX7ou
         hDU+b+WuAglbI8qoueJFwXv+ugDw5yNK9TNYNmD1AQy1KdU1qVAniyfs4KTCFnVJwDNo
         Pf82AZtNRug3lTvRn9todtdryRzG+gvx32Z+H2+ukOGc06Ugb4eGEr99GZmEDT/usAmK
         oj3i/Qm9baQ3RIDabTMj9MV/r0+Z6xhO+Ti2I4H61jnUK98SQpsxnUd7LCoQ+zGPmgDW
         IK9/4OpuUhDAmKsSLZWdT9AqwyO1CbXkjRsRpxNF6EfyC7H6jDC7lg/2tkhcGF9qI54P
         9nZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=r3b3h8odkiIqkmQj2ElqAUg66aCs14UyDf1MJRMWwp8=;
        b=sb4BfuntY5wlC+5+QL+lNMyNXshveXW+kcAA8zBhnGFsrJ1zGkZVlE4mLqGgJX2FB4
         ZPEWi9r5wTBok19kOSdKlMUUFg96tIUidcXnXouhP+mizsOKey9z/Rz64O1Y04qfA/9x
         mrOKMe2DXI3bt2g0S15nRmCeKoUDH/rw5fWh47gfEgu9Zi7S21GDTtTGu6ILSVODVx0S
         Li+cpzyZPRZCO/WaZtwyiQdntV7hzvO/K1OtgPin17OyENIaCAdgkNxRz8pmloF/iRbq
         e/YQRMAkMJtGebvSRaw+AdsOFySRlOcwoxzpuPxnOpkNNbMWPXOBdsH6Y3qN/RZ3+CNA
         62EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=dY9He6fm;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id a79si445039pfa.5.2019.08.17.20.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Aug 2019 20:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id 44so10507207qtg.11
        for <kasan-dev@googlegroups.com>; Sat, 17 Aug 2019 20:25:32 -0700 (PDT)
X-Received: by 2002:ac8:289b:: with SMTP id i27mr15581485qti.67.1566098731470;
        Sat, 17 Aug 2019 20:25:31 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id f20sm7094444qtf.68.2019.08.17.20.25.29
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 17 Aug 2019 20:25:30 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
Date: Sat, 17 Aug 2019 23:25:28 -0400
Cc: Linux MM <linux-mm@kvack.org>,
 linux-nvdimm <linux-nvdimm@lists.01.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev@googlegroups.com,
 Baoquan He <bhe@redhat.com>,
 Dave Jiang <dave.jiang@intel.com>,
 Thomas Gleixner <tglx@linutronix.de>
Content-Transfer-Encoding: quoted-printable
Message-Id: <0AC959D7-5BCB-4A81-BBDC-990E9826EB45@lca.pw>
References: <1565991345.8572.28.camel@lca.pw>
 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
 <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
 <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
 <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
To: Dan Williams <dan.j.williams@intel.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=dY9He6fm;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Aug 17, 2019, at 12:59 PM, Dan Williams <dan.j.williams@intel.com> wro=
te:
>=20
> On Sat, Aug 17, 2019 at 4:13 AM Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Aug 16, 2019, at 11:57 PM, Dan Williams <dan.j.williams@intel.com> w=
rote:
>>>=20
>>> On Fri, Aug 16, 2019 at 8:34 PM Qian Cai <cai@lca.pw> wrote:
>>>>=20
>>>>=20
>>>>=20
>>>>> On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel.com> =
wrote:
>>>>>=20
>>>>> On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
>>>>>>=20
>>>>>> Every so often recently, booting Intel CPU server on linux-next trig=
gers this
>>>>>> warning. Trying to figure out if  the commit 7cc7867fb061
>>>>>> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit =
here.
>>>>>>=20
>>>>>> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
>>>>>> devm_memremap_pages+0x894/0xc70:
>>>>>> devm_memremap_pages at mm/memremap.c:307
>>>>>=20
>>>>> Previously the forced section alignment in devm_memremap_pages() woul=
d
>>>>> cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
>>>>> (12K on x86) constraint.
>>>>>=20
>>>>> Can you provide a dump of /proc/iomem? I'm curious what resource is
>>>>> triggering such a small alignment granularity.
>>>>=20
>>>> This is with memmap=3D4G!4G ,
>>>>=20
>>>> # cat /proc/iomem
>>> [..]
>>>> 100000000-155dfffff : Persistent Memory (legacy)
>>>> 100000000-155dfffff : namespace0.0
>>>> 155e00000-15982bfff : System RAM
>>>> 155e00000-156a00fa0 : Kernel code
>>>> 156a00fa1-15765d67f : Kernel data
>>>> 157837000-1597fffff : Kernel bss
>>>> 15982c000-1ffffffff : Persistent Memory (legacy)
>>>> 200000000-87fffffff : System RAM
>>>=20
>>> Ok, looks like 4G is bad choice to land the pmem emulation on this
>>> system because it collides with where the kernel is deployed and gets
>>> broken into tiny pieces that violate kasan's. This is a known problem
>>> with memmap=3D. You need to pick an memory range that does not collide
>>> with anything else. See:
>>>=20
>>>   https://nvdimm.wiki.kernel.org/how_to_choose_the_correct_memmap_kerne=
l_parameter_for_pmem_on_your_system
>>>=20
>>> ...for more info.
>>=20
>> Well, it seems I did exactly follow the information in that link,
>>=20
>> [    0.000000] BIOS-provided physical RAM map:
>> [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x0000000000093fff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x0000000000094000-0x000000000009ffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000000e0000-0x00000000000fffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000005a7a0fff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x000000005a7a1000-0x000000005b5e0fff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x000000005b5e1000-0x00000000790fefff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x00000000790ff000-0x00000000791fefff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000791ff000-0x000000007b5fefff] AC=
PI NVS
>> [    0.000000] BIOS-e820: [mem 0x000000007b5ff000-0x000000007b7fefff] AC=
PI data
>> [    0.000000] BIOS-e820: [mem 0x000000007b7ff000-0x000000007b7fffff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x000000007b800000-0x000000008fffffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000ff800000-0x00000000ffffffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000087fffffff] us=
able
>>=20
>> Where 4G is good. Then,
>>=20
>> [    0.000000] user-defined physical RAM map:
>> [    0.000000] user: [mem 0x0000000000000000-0x0000000000093fff] usable
>> [    0.000000] user: [mem 0x0000000000094000-0x000000000009ffff] reserve=
d
>> [    0.000000] user: [mem 0x00000000000e0000-0x00000000000fffff] reserve=
d
>> [    0.000000] user: [mem 0x0000000000100000-0x000000005a7a0fff] usable
>> [    0.000000] user: [mem 0x000000005a7a1000-0x000000005b5e0fff] reserve=
d
>> [    0.000000] user: [mem 0x000000005b5e1000-0x00000000790fefff] usable
>> [    0.000000] user: [mem 0x00000000790ff000-0x00000000791fefff] reserve=
d
>> [    0.000000] user: [mem 0x00000000791ff000-0x000000007b5fefff] ACPI NV=
S
>> [    0.000000] user: [mem 0x000000007b5ff000-0x000000007b7fefff] ACPI da=
ta
>> [    0.000000] user: [mem 0x000000007b7ff000-0x000000007b7fffff] usable
>> [    0.000000] user: [mem 0x000000007b800000-0x000000008fffffff] reserve=
d
>> [    0.000000] user: [mem 0x00000000ff800000-0x00000000ffffffff] reserve=
d
>> [    0.000000] user: [mem 0x0000000100000000-0x00000001ffffffff] persist=
ent (type 12)
>> [    0.000000] user: [mem 0x0000000200000000-0x000000087fffffff] usable
>>=20
>> The doc did mention that =E2=80=9CThere seems to be an issue with CONFIG=
_KSAN at the moment however.=E2=80=9D
>> without more detail though.
>=20
> Does disabling CONFIG_RANDOMIZE_BASE help? Maybe that workaround has
> regressed. Effectively we need to find what is causing the kernel to
> sometimes be placed in the middle of a custom reserved memmap=3D range.

Yes, disabling KASLR works good so far. Assuming the workaround, i.e., f284=
42497b5c
(=E2=80=9Cx86/boot: Fix KASLR and memmap=3D collision=E2=80=9D) is correct.

The only other commit that might regress it from my research so far is,

d52e7d5a952c ("x86/KASLR: Parse all 'memmap=3D' boot option entries=E2=80=
=9D)


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0AC959D7-5BCB-4A81-BBDC-990E9826EB45%40lca.pw.
