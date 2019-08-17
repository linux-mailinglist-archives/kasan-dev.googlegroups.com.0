Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBLWC37VAKGQEJRRTGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AAC359102E
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 13:12:47 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id m13sf6172297ioj.23
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 04:12:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566040366; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZNSeHccInffIxEL18Xs7rwm7NojLf79zsANcblcLWyUKC24tQ9HQQXctVwoFTgNGy2
         pUbEFTO0wag2tjZRXg6x4qTgYBX1HzTjRRvymbzY80dnauTyuqEdjt3LYGDqT7DLezis
         FNQIxT0NUZn7HErxm55KEMUtW8Ck5TDyGA22fzn7I9VM4Y8htZdhfmJQDgOBMtaijZh/
         rJW2uahZ9iYKAq98uAC6teoKE6poA753QHxyKzMo8DtkZY+W53Boz1b7hZ2xK4GRCnWj
         Ya4NwfdgBoUfp/bZTRvVELkVLzAp4HAUEk31ZrtTab1d/Tc8hrYcMmyLb+09xkZEuk9F
         iy2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=cmwpH/5Vyf9573+YLSv/mg+Jt3tD1pgjWLNWUEDNu7w=;
        b=azfjJ0L7sbgB/q1D8RtykRG8KCenoduz6OfL5cTG9DcGl7p6OO7z7QSkZr0E00qhkK
         jkgkLEaCmOmUzULl1YYjbrhyJRHK3XcvN9kF9eOVPJHVCEjSmws9zziwxADmJqNuqEy5
         CQeVXyYToD9jTpB4XN/LwQ1kEyfoxlGx78T06jxi72Wuxt6mkyy2PQqrI5FVoRLVie+F
         Ygn+309INOo+nRs63q1ako402E61KT+CmyZ1bS0D9sqgpZeVc3SfoESEbf8HzJSfJYHR
         5kuzdi5CfeaI/MZ9twKjg0eUzEJaLw4aS5QyxPxKZivovNTSTfHq+qcz2zIYx28DHbMe
         XTIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qSx2IaXw;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cmwpH/5Vyf9573+YLSv/mg+Jt3tD1pgjWLNWUEDNu7w=;
        b=sUj/QF5Kae2XBaCpA4J55obC2U493/8BgHvg+krIMKVd2oaTaxOpnwl+7W20o5Lm++
         kfZ/Lgfic5Rp2U+sjtR/vxQAtMZv/jmiiFGP3+2LhPc3hxX70/LJ1AW1YfO+EXkBnsvK
         la6TAYGQ7cD1WzIkkMGsHVrsR2ucc3F4WCXTRuXir0dlxc1u3G+nOixv3Fkh8srJg7th
         /W2Vhyc2hkO9gIRMj/hOabKtpWjuLEjcgu5duGZzT2qAR4oNSB3ruKs9KrCAIYNO3tTf
         7ibDDyNdB8Ioq+hXztA5PG1wcoFBU7lKl1/HcVJpnXFMUhyGUax3p5n++X93eFw97ZKZ
         ErDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cmwpH/5Vyf9573+YLSv/mg+Jt3tD1pgjWLNWUEDNu7w=;
        b=XqDUD2od1K4qoWlaGqwTvl1yvy+lx2WxIySIkRzvsx7W470GSSUNo2jHxb51dVoHxF
         hOkjfxgtAV33VWRelFSRi8JAz4u9T5eJFLceEfO5MVoew/R4QpwXNkegOQMBgkk7ZSWQ
         ntvjY9NJnz6exGHQcSOM1JzMz6DIyEMytTtBusLxWNNgwXDNXzLBnXlDAaAPyIiu7jmu
         WCuumhhGXD9zPKCR6XJREsvV+LGkTvByzbyl3kYO+dkyFSASgrNpMnlelCLCCHiKsmXI
         AUiNkMKmv0mq1X+Jy/EAclDWKSXeR5rDXlOM6pYyKuqpeeq/vzU2wPydAJ5sAmQbf6Zs
         pZRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVEzIGMHyVK1nT5UJybvbAAaCzYO9Camzs2G8ijvItxeKlTDMCi
	BEAolb/dfnHqAcMaau4S7rQ=
X-Google-Smtp-Source: APXvYqz7RUuaisTanRMjzgH86t0X11uwBZRVHdSOHNPYZTV7uPymnnf+UwSGHVRmfli9cVjuhe7j7Q==
X-Received: by 2002:a02:9f19:: with SMTP id z25mr16008585jal.107.1566040366573;
        Sat, 17 Aug 2019 04:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8d17:: with SMTP id p23ls2883108ioj.14.gmail; Sat, 17
 Aug 2019 04:12:46 -0700 (PDT)
X-Received: by 2002:a05:6602:c7:: with SMTP id z7mr16394513ioe.130.1566040366155;
        Sat, 17 Aug 2019 04:12:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566040366; cv=none;
        d=google.com; s=arc-20160816;
        b=sGfN0ReH+CLmS0X5gKRqytv+RPQU4hTt053J6F8JogSlB+TnjO4nUmmPnE21e+X01P
         ZswMmrPQfYSE9To3P2KCWzXOSNNJcoz0xJBHLCxAthgL4uWqGC0aKRdfhTVjRsOBvB0J
         BBP9ZdurZwxUB3KwMH9dS2M+YTyMBu9SVKrNb7Tio+P/a6pSaV63EA6rP1IiAKLyxCCG
         DL8l6t5mVGa4GAaU+J7vAkR/BM/JlZU0HnIVtWZfnUVVi1UFEHRQOjmnrFiLV1IxjA4D
         GYbhv2fOXaRJCg8xuzasoNJ2woIIbdBvrnCdkosEQBEDHE+xVOdWWOyq1jE3cXj81rFH
         2euA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=hnyyRW//9ToVhTEfhUiVXZ2Yyj1FvnMmcd3JbCX3+aQ=;
        b=MrCwaBuDpA2N3W4olD2fPg1MqkDkLe6U/PuLqQ7LVWEJzi7nxkh+9ECeOwZ4zPNHQR
         aM/MsxZr1m0JozIF25Way+5tb59IkBPpmdfAXI6yC0WGdjurTkk/b7L2bbQ+9MxJA06k
         M2G/66HzHCYMVVEsI2GOmcGwXo5vgOfcEhyEDmZ9mLUDZleqbA5rFggNecrxNnmx0cv4
         Mixp5+/I6OT1PQxyv2sAGxWy0MzfWKUkOuwhy8LTe8gbaLDidlhR2L9Yy33knzBFSAiG
         Xey+mQ6+GNpiaK44UtFsBVjn43lr87ZCloQo84Sgd6xsurQGs7zTmH62j648GdQK9zpK
         81GQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qSx2IaXw;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id m190si377714iof.3.2019.08.17.04.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Aug 2019 04:12:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id s145so6873479qke.7
        for <kasan-dev@googlegroups.com>; Sat, 17 Aug 2019 04:12:46 -0700 (PDT)
X-Received: by 2002:a37:8607:: with SMTP id i7mr3251078qkd.455.1566040365423;
        Sat, 17 Aug 2019 04:12:45 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id s3sm1906595qkc.57.2019.08.17.04.12.44
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 17 Aug 2019 04:12:44 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
Date: Sat, 17 Aug 2019 07:12:43 -0400
Cc: Linux MM <linux-mm@kvack.org>,
 linux-nvdimm <linux-nvdimm@lists.01.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev@googlegroups.com
Content-Transfer-Encoding: quoted-printable
Message-Id: <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
References: <1565991345.8572.28.camel@lca.pw>
 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
 <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
To: Dan Williams <dan.j.williams@intel.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=qSx2IaXw;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
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



> On Aug 16, 2019, at 11:57 PM, Dan Williams <dan.j.williams@intel.com> wro=
te:
>=20
> On Fri, Aug 16, 2019 at 8:34 PM Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel.com> wr=
ote:
>>>=20
>>> On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
>>>>=20
>>>> Every so often recently, booting Intel CPU server on linux-next trigge=
rs this
>>>> warning. Trying to figure out if  the commit 7cc7867fb061
>>>> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit he=
re.
>>>>=20
>>>> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
>>>> devm_memremap_pages+0x894/0xc70:
>>>> devm_memremap_pages at mm/memremap.c:307
>>>=20
>>> Previously the forced section alignment in devm_memremap_pages() would
>>> cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
>>> (12K on x86) constraint.
>>>=20
>>> Can you provide a dump of /proc/iomem? I'm curious what resource is
>>> triggering such a small alignment granularity.
>>=20
>> This is with memmap=3D4G!4G ,
>>=20
>> # cat /proc/iomem
> [..]
>> 100000000-155dfffff : Persistent Memory (legacy)
>>  100000000-155dfffff : namespace0.0
>> 155e00000-15982bfff : System RAM
>>  155e00000-156a00fa0 : Kernel code
>>  156a00fa1-15765d67f : Kernel data
>>  157837000-1597fffff : Kernel bss
>> 15982c000-1ffffffff : Persistent Memory (legacy)
>> 200000000-87fffffff : System RAM
>=20
> Ok, looks like 4G is bad choice to land the pmem emulation on this
> system because it collides with where the kernel is deployed and gets
> broken into tiny pieces that violate kasan's. This is a known problem
> with memmap=3D. You need to pick an memory range that does not collide
> with anything else. See:
>=20
>    https://nvdimm.wiki.kernel.org/how_to_choose_the_correct_memmap_kernel=
_parameter_for_pmem_on_your_system
>=20
> ...for more info.

Well, it seems I did exactly follow the information in that link,

[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x0000000000093fff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x0000000000094000-0x000000000009ffff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x00000000000e0000-0x00000000000fffff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000005a7a0fff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x000000005a7a1000-0x000000005b5e0fff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x000000005b5e1000-0x00000000790fefff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x00000000790ff000-0x00000000791fefff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x00000000791ff000-0x000000007b5fefff] ACPI =
NVS
[    0.000000] BIOS-e820: [mem 0x000000007b5ff000-0x000000007b7fefff] ACPI =
data
[    0.000000] BIOS-e820: [mem 0x000000007b7ff000-0x000000007b7fffff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x000000007b800000-0x000000008fffffff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x00000000ff800000-0x00000000ffffffff] reser=
ved
[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000087fffffff] usabl=
e

Where 4G is good. Then,

[    0.000000] user-defined physical RAM map:
[    0.000000] user: [mem 0x0000000000000000-0x0000000000093fff] usable
[    0.000000] user: [mem 0x0000000000094000-0x000000000009ffff] reserved
[    0.000000] user: [mem 0x00000000000e0000-0x00000000000fffff] reserved
[    0.000000] user: [mem 0x0000000000100000-0x000000005a7a0fff] usable
[    0.000000] user: [mem 0x000000005a7a1000-0x000000005b5e0fff] reserved
[    0.000000] user: [mem 0x000000005b5e1000-0x00000000790fefff] usable
[    0.000000] user: [mem 0x00000000790ff000-0x00000000791fefff] reserved
[    0.000000] user: [mem 0x00000000791ff000-0x000000007b5fefff] ACPI NVS
[    0.000000] user: [mem 0x000000007b5ff000-0x000000007b7fefff] ACPI data
[    0.000000] user: [mem 0x000000007b7ff000-0x000000007b7fffff] usable
[    0.000000] user: [mem 0x000000007b800000-0x000000008fffffff] reserved
[    0.000000] user: [mem 0x00000000ff800000-0x00000000ffffffff] reserved
[    0.000000] user: [mem 0x0000000100000000-0x00000001ffffffff] persistent=
 (type 12)
[    0.000000] user: [mem 0x0000000200000000-0x000000087fffffff] usable

The doc did mention that =E2=80=9CThere seems to be an issue with CONFIG_KS=
AN at the moment however.=E2=80=9D
without more detail though.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/E7A04694-504D-4FB3-9864-03C2CBA3898E%40lca.pw.
