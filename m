Return-Path: <kasan-dev+bncBC447XVYUEMRBGVT5SBQMGQEDOIY7DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B81D36315E
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 19:23:38 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id k1-20020adfd2210000b02901040d1dbcaesf6283741wrh.17
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 10:23:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618680218; cv=pass;
        d=google.com; s=arc-20160816;
        b=m9bk78MsNFPXM8+Q2JQ3GjTQz1rq3ALgv9EPOOmaQN13vbc9wXbdaCK/tdp8UxyHLk
         sr0ioFSHCcdGt8EYs1BEXICyeSl1rEdHuykEqOsy4AjrSTRY27vFnguPw59zqDNoqmRm
         dHXfeegbuk+9uBovvDI1CqVXOS3JEo28ZpSrgHrvO9FCJeQcUWo0E502XoBKnTa99fDB
         /nZbMlkUTu10O457GXoLs7Sz4GaiUhZGn332z2v9IqvgzXBwHT/fqWs1nhZivnI5/zwC
         ZO0PYKwoS64GjOCPOGKHSMUh37+6j2YjzSS8Fj9rbJYAJxNEy7wAqokk+sxeLzwHWkAp
         Ph/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=BMBgVPhqC8Dp0PJMNLRVIIa9ijZd2zcSPIejuq5xsR0=;
        b=g5lLAdprg/As9o1HGTVDyHqoglhoV+XZbbDsyng6XA+RRC5RxA0GG6ZfHw4R0vmvl1
         SB2Qfhdg6SK0xsuTy34JWteiGKu1qdo4XLH2SiDIQuODicRD4PSnXX5DAy9JiNGC1qum
         S9vBsykwwxEPe3gI1APLaGZUi1hUDMVSk/til8S1kt3u7E4fbRQURTQGruGv7pzpLELF
         pxneyZ4UhCXMXFv3ChzefPVXmLtcr2IKUGUy5HvmQXrtalYCEAJrfNQwx1sBq01AnAcg
         XIKGipzse7dDfHBf/+jEYJdjT6bthtQrNK/PteBGS0CLvQwLIw3sFCmtVrqbCStQHDdP
         NJcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BMBgVPhqC8Dp0PJMNLRVIIa9ijZd2zcSPIejuq5xsR0=;
        b=ApWJ4UUloEPKgtYwLWRM0woaR5hlBSxdga1kQADvXh/epCs5bcctcZv/C2YfPcbpXb
         woXY/ixv8M2fMbLrTcrXo2rSPg4NdE11E05ix+MUCqyz/lNt/7B777w2/yR0FBCtgp2q
         n26t3vdIRi59wLTN21tB89EzOvES3Adc9+RPaYvHf5R3HrK2p7ef+KFVJXdSVgE3tImu
         9us8hBfQRO7mumrjCCLGx8hGOFzsdINrsP80+qOPQqE5R9+LMsScIIJPoa+oY4836vYb
         0iK+TGVK2dLLLHPjlns8tiC8HmY61H+U8R/1zS9suXI9UU1wH55kPJW3culLzko5BTPu
         963Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BMBgVPhqC8Dp0PJMNLRVIIa9ijZd2zcSPIejuq5xsR0=;
        b=UOEUocZiYdk4KiwP/tcHhTfkoCYJ/K3WgTjGG3lYTEw8mIWBhUsQLR5GYt6tVJgCHG
         jQrT6Y49XJyYn2VP/r3aoRqECPkaAHu8lu3j5lsCx9Ax9ROV2yTE9OaWuEqPGTT8aZOF
         noIw4G89LAUEA6kHWMhvLm7daDFFEzQyDOZ2zOZVrfrnvmkfquqypoB6dz7i02G+HPNo
         40T7ZECDH0PK28WCx1D4sq4Q7UPyK0FKaMSuC7sONRCGCZBmMrCKHxjbqY2O4tJRXp/F
         2NmzOYi3hOB+gcgpkJ8MZmJ3cuvL1/i+7NfDQFsQc8ls0qjEWcYxlrROx2AuiTScsh8b
         MdCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JJqLkAZA9CuSGEzigqwQCyx7fHW8dc/M2cqBHDvrQ+gZNj3pk
	eShUpRw9Syvlgv8NANAbvW0=
X-Google-Smtp-Source: ABdhPJzC4+0ycoQhaJoU9gEqWBTWiDo2Tzcc+MQW9ZULh8qfyPQhbHRHMc6L4Mi6ctPQVyTiTwtS7Q==
X-Received: by 2002:a1c:1d14:: with SMTP id d20mr13875189wmd.49.1618680218420;
        Sat, 17 Apr 2021 10:23:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb47:: with SMTP id c7ls2306054wrs.0.gmail; Sat, 17 Apr
 2021 10:23:37 -0700 (PDT)
X-Received: by 2002:a05:6000:1848:: with SMTP id c8mr5294529wri.210.1618680217646;
        Sat, 17 Apr 2021 10:23:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618680217; cv=none;
        d=google.com; s=arc-20160816;
        b=nqMTFIYgEnd/iR7Lwm8v93k2uzTOdlSgF1CJNGcKPfjJeKINdUYQfjQLl9DS6qRSst
         rJjXRmTdVB0JDSct6HxtFnVPbWgT9FTHgKgcLfSy63HrjHDXbfWobWUxCft5/iy05zuN
         mGgETT15SaiqMW/mtSTjXH3BX5bqR5Sal4U7TGnueAzc4mPvD3ZyAZgPiRso2lEztA6b
         pV3xxI0GnFoPlpP32pbUNOIqjLPCOTwrU9AiqvbgoI5dMSlKpYpOwckBPBrLP0Kufk6k
         N8gCP2AAYW09udMqDRG+JNJ5He4SMrZ1WXe/jasXe0TxCCFmigcyHn33fpjQ77nThzYt
         GWWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=S0cSJjkUH/S8SZSJwUfAt3HMwfoA8lXcrgWomg/s0p8=;
        b=pneJYS+b2VV5Dr2w3WObrLCNx7GRZvWZ0wYMiHZ1sGBkU779UH7Sur9F0AtpPcpvcs
         2zh5zG2k1f0cU9umqwp+2d5/iiqvKc35FoM/wCJbvvASoUGE9V4OS+aDwix8IWvih6Bk
         eS6Zv50q5b3H3QC1jSQ7+rERrqgUv39GUt7LqoJrJI3hcKCvZRmIDl0Pxu/WYo7EDQHh
         SRzsn9kb0MP6xYz2TEBD4HRMvVrCJZzCkQvz4BjFPi67NldF5GswPPsxn5n4g93XpIh5
         /upqvCV6K9v5nqHeDyGQ58SvYTlbrsKa+XCxoCw6ucO14i/tyCh31ZB7N8CQ9CeNxNew
         8hXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id 5si202118wrj.4.2021.04.17.10.23.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 17 Apr 2021 10:23:37 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id C6153E0003;
	Sat, 17 Apr 2021 17:23:33 +0000 (UTC)
Subject: Re: [PATCH v4 1/3] riscv: Move kernel mapping outside of linear
 mapping
To: Guenter Roeck <linux@roeck-us.net>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Arnd Bergmann <arnd@arndb.de>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <20210409061500.14673-1-alex@ghiti.fr>
 <20210409061500.14673-2-alex@ghiti.fr> <20210416185139.GA42339@roeck-us.net>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <8c23ed42-d8c7-70be-71d8-0eb74ace8e67@ghiti.fr>
Date: Sat, 17 Apr 2021 13:23:33 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <20210416185139.GA42339@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Guenter,

Le 4/16/21 =C3=A0 2:51 PM, Guenter Roeck a =C3=A9crit=C2=A0:
> On Fri, Apr 09, 2021 at 02:14:58AM -0400, Alexandre Ghiti wrote:
>> This is a preparatory patch for relocatable kernel and sv48 support.
>>
>> The kernel used to be linked at PAGE_OFFSET address therefore we could u=
se
>> the linear mapping for the kernel mapping. But the relocated kernel base
>> address will be different from PAGE_OFFSET and since in the linear mappi=
ng,
>> two different virtual addresses cannot point to the same physical addres=
s,
>> the kernel mapping needs to lie outside the linear mapping so that we do=
n't
>> have to copy it at the same physical offset.
>>
>> The kernel mapping is moved to the last 2GB of the address space, BPF
>> is now always after the kernel and modules use the 2GB memory range righ=
t
>> before the kernel, so BPF and modules regions do not overlap. KASLR
>> implementation will simply have to move the kernel in the last 2GB range
>> and just take care of leaving enough space for BPF.
>>
>> In addition, by moving the kernel to the end of the address space, both
>> sv39 and sv48 kernels will be exactly the same without needing to be
>> relocated at runtime.
>>
>> Suggested-by: Arnd Bergmann <arnd@arndb.de>
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>=20
> In next-20210416, when booting a riscv32 image in qemu, this patch result=
s in:
>=20
> [    0.000000] Linux version 5.12.0-rc7-next-20210416 (groeck@desktop) (r=
iscv32-linux-gcc (GCC) 10.3.0, GNU ld (GNU Binutils) 2.36.1) #1 SMP Fri Apr=
 16 10:38:09 PDT 2021
> [    0.000000] OF: fdt: Ignoring memory block 0x80000000 - 0xa0000000
> [    0.000000] Machine model: riscv-virtio,qemu
> [    0.000000] earlycon: uart8250 at MMIO 0x10000000 (options '115200')
> [    0.000000] printk: bootconsole [uart8250] enabled
> [    0.000000] efi: UEFI not found.
> [    0.000000] Kernel panic - not syncing: init_resources: Failed to allo=
cate 160 bytes
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.12.0-rc7-next-20=
210416 #1
> [    0.000000] Hardware name: riscv-virtio,qemu (DT)
> [    0.000000] Call Trace:
> [    0.000000] [<80005292>] walk_stackframe+0x0/0xce
> [    0.000000] [<809f4db8>] dump_backtrace+0x38/0x46
> [    0.000000] [<809f4dd4>] show_stack+0xe/0x16
> [    0.000000] [<809ff1d0>] dump_stack+0x92/0xc6
> [    0.000000] [<809f4fee>] panic+0x10a/0x2d8
> [    0.000000] [<80c02b24>] setup_arch+0x2a0/0x4ea
> [    0.000000] [<80c006b0>] start_kernel+0x90/0x628
> [    0.000000] ---[ end Kernel panic - not syncing: init_resources: Faile=
d to allocate 160 bytes ]---
>=20
> Reverting it fixes the problem. I understand that the version in -next is
> different to this version of the patch, but I also tried v4 and it still
> crashes with the same error message.
>=20

I completely neglected 32b kernel in this series, I fixed that here:

Thank you for testing and reporting,

Alex

> Guenter
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8c23ed42-d8c7-70be-71d8-0eb74ace8e67%40ghiti.fr.
