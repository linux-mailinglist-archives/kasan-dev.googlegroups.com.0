Return-Path: <kasan-dev+bncBDLKPY4HVQKBBFGLYLCAMGQE6QAASYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 38268B1A132
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:20:38 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3326ee4c8c0sf3948161fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754310037; cv=pass;
        d=google.com; s=arc-20240605;
        b=cy+pEA3jF0C79CdoRoaQH5BD9FEOx8gAPZjPbSJ7fZ1zZ0/lvJOvObRNGqnN/3cjwA
         dKeohchkKfb+FR0Su6Ie5h/ZONO94K0NgLQ47ybQd5+WvpfY5mQ85t4kPmQfZXPymm3B
         aoQWkEhntTwB7MsDFCPSeyFp/ul7foc37ccLSKf3KL+lV65Y4ginWorqAR68/jCCAUHm
         yfTagVha/BwDbLk37Lb4YV2vsWWBPy56p5Iv2eVYn1JTs+Xq4BiYpmVS/h6UlTgWPuLP
         6fmbZS7rcwKVtg2jdjlJgl557vUW/uDxmMxf1/wGO1gtkaeXLp74YzHNw6aylPC/6wsl
         VK8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=PRbjjvU3OB8T/Vq0qP0U9IDnGlcR9EpQXP253HcEueE=;
        fh=ARr3rk1UcNA5AOKy/PDZdo7zJdy5F1XqlxniJpVYiJ0=;
        b=PZT/JW2e15ERNADojn54EG0uuk8InX+WlNEoBwdidfB8ZjUvVeMWtBV5nyHu7ao/Ei
         hiHlJHRp+WuOYuFGGqJE8TsZIKS9e3UuNWepinRaFWjVoyQpSBC16qwv3ej5KYq0qglS
         eg4Tpwaydca/L5Yv4gHKAsckMMllZ3NAF27e/pWVWwTFzcHk0Mhj1RlAX5bBmjH1M+oI
         qrdybdzW9oewXAJebCqc8+NkJj87eJloZU0EAik3njCKFzCy+WWDr5qjXWIHeOSSMWpr
         cIbXC62RXgjVBdAthknhBBmZIpsNZg3yUs3PtXw6E2JRtmnVvH/3a6UM0XbJgdMOjiFg
         bW0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754310037; x=1754914837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PRbjjvU3OB8T/Vq0qP0U9IDnGlcR9EpQXP253HcEueE=;
        b=knibZbzNbmIDtdRW+aF4pe7mVXajnGSRwikTGfgFwtDLTbNrI9Xbju7DSg49GGMYQD
         dwNAz+gAfCPQn5FViIkychFiBHeRhVpA6nHJfcOHbWPKtXxd3Y6yBcq3xewS2v7FfD2S
         Lk2NgMni0iYKuPkKCqVwiqI05RXdx4IufHP/sRawAu1cfleoaE7KnxMnmWdN+97xJBGh
         zcot/lardfUnuTJFQ5Z+mOdRIqqQR785CDzE6nuWF1mQfIKvZvDYj+wEKE/pn36kQDH0
         ZZYKKCf9xeFYTRPQaNkU+TBrEWtxHgU9IaFR7gkkN7SANOy++C1UGrZM6TH8PZVqLOCb
         Vpsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754310037; x=1754914837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PRbjjvU3OB8T/Vq0qP0U9IDnGlcR9EpQXP253HcEueE=;
        b=OrClfwqMUP5u/snL/QrHmoa9QGg8d8luk+lFHxYoYUqySksTTPNT5q3NIsWdFXDawz
         UUYy5AC45aSjuqLzbXTEiXgajNbTElIkVsjx8R+JlBBub450FFudkJqlJnC57YJNsTyZ
         WDU0uhLzuUKA8zUiKp1NJkGgla5wohqRJz3zITos1xnQqExbNUigiI9sgVGyizZfcZJD
         t+pcL0+UYTPBN7A4SnpdU+MmRVf6Qc0bZePlqm3koB5Ria/qDB9xN76er1W32+a6WGnQ
         sNq7inHg1SzrucT56O4/HvmqhvHO5Sy4aHhVhTYZng+KslFuDuWuHqVQxN2js6XYvtJW
         lv0w==
X-Forwarded-Encrypted: i=2; AJvYcCVOH9dXbQAWhgFy30VX9Xu2lVxSmtv6Hsd1Fq3HBuFZGeiRyXVgESTVA7NqOWhaZBlnfIEdBg==@lfdr.de
X-Gm-Message-State: AOJu0YxADU0TSa+f1NsWy6piqw/Ih+MHcLCSTtSIQVO8PhjNUjpl0oX2
	gh25xkts0NzUDykvp4ko5K0iJYWXmnYANNkAjwuRD46m5aUpEx0vsavL
X-Google-Smtp-Source: AGHT+IG0G7aO+91bM+1+G/uZtjrwaJUuO2g1QGsVHnd+l6qARwpixpBJeahout0AotWsYLPDmt+KFg==
X-Received: by 2002:a05:651c:198a:b0:32b:34c5:225d with SMTP id 38308e7fff4ca-3325669528fmr22200691fa.1.1754310036662;
        Mon, 04 Aug 2025 05:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdX9iJD6FoDB3bzVTx63M3549658mRN3xvXGnx9QWQ1YA==
Received: by 2002:a2e:602:0:b0:331:e5a8:6292 with SMTP id 38308e7fff4ca-332381f7a4bls8845601fa.0.-pod-prod-04-eu;
 Mon, 04 Aug 2025 05:20:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXDLZZGXmmQbej9Kluu6Ll5vDnAcHwKj+CgIjVxTN/87+6S2en85prL7fnO9rKhzLZwLVqbq4PKAs=@googlegroups.com
X-Received: by 2002:a2e:9c51:0:b0:332:5195:5632 with SMTP id 38308e7fff4ca-33256779cafmr17695651fa.21.1754310033724;
        Mon, 04 Aug 2025 05:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754310033; cv=none;
        d=google.com; s=arc-20240605;
        b=d23W00fku2UU61Yizmlv7cN8+ahzye5FAh6H5EIdreM9dY0mwXNHNMCKYjZjeEAmdI
         ARvaIP2PcPt0fD95bgKO5rTkVzR0/SEfvcWVtm/AOY49vDHO2GohQzEZOz0mwmwnIsNd
         HuMXgz+bdR/p1M2DGGS6AXplRJDNZKci5d/UU64Cuhmp5k8uwr9VxW1MMIqHgNqEw3KN
         +879srqUc3Tq/pBjj4Ocye3C1v6eDwnlFcJU55Yo9a2cwEMccbp+erZA/IPyBtGLM7Ed
         OzOeEFpdXxUQP/fN/8iXcqly79X0LKv0l37JYBNWdW9QfuAhphl86ZJo4F1+KhP9UJNJ
         gdUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=EEXPPFH4l8VuLr/3UDtR2Lyz5HeTqsVq+1KVy/ssu0I=;
        fh=/lsZ2DGxVCE3UB0j0vIX6AcKg/J33XcXyGaL6aumIUo=;
        b=HcXnak6mF5GFDW1529WLsjaXiEnzca3wLs6hWGF99h9CoYNeB8taAe3hQzhrZ95gQv
         UhvFPfK0FuVjY+qhlQFHuQtbtfVvkYW3J5HAqFDvgPOhfn2nzoY6rn/pDkArIQN0w3ig
         zhu4HYmTI1fLTeblPNsrFQseK1wSHsxc2aL8eJmiqyQ5oQZsLn1DbKBO7+xERMvIgZ4F
         STXFrEdq7xYvEB1fuq3c4/nP/IENZ758Ayofgxo6oqPpm6TIcP5Kcc8qBQEgSZ3T3+ja
         chhdtTC0cK3r2t60Fi/T64EZqCoHxO4PKB0AJXnYDFUBshaBCvfzz0V0NLKR6Jfy4djO
         j6og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTP id 2adb3069b0e04-55b887deca0si250415e87.2.2025.08.04.05.20.33
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Aug 2025 05:20:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bwZxK1dGRz9t2s;
	Mon,  4 Aug 2025 14:04:53 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id dlBu_8hLK5co; Mon,  4 Aug 2025 14:04:53 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bwZws04Yhz9sr6;
	Mon,  4 Aug 2025 14:04:29 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E7AA88B764;
	Mon,  4 Aug 2025 14:04:28 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id CvwZaHj2jN54; Mon,  4 Aug 2025 14:04:28 +0200 (CEST)
Received: from [10.25.207.160] (unknown [10.25.207.160])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BA7898B763;
	Mon,  4 Aug 2025 14:04:28 +0200 (CEST)
Message-ID: <74b373bb-cf18-49b3-84ed-56d04e09c71e@csgroup.eu>
Date: Mon, 4 Aug 2025 14:04:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/12] kasan: unify kasan_arch_is_ready() and remove
 arch-specific implementations
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, linuxppc-dev@lists.ozlabs.org
Cc: hca@linux.ibm.com, akpm@linux-foundation.org,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <f10f3599-509d-4455-94a3-fcbeeffd8219@gmail.com>
 <CACzwLxjD0oXGGm2dkDdXjX0sxoNC2asQbjigkDWGCn48bitxSw@mail.gmail.com>
 <f7051d82-559f-420d-a766-6126ba2ed5ab@gmail.com>
 <CACzwLxjESCT_=1BG2rWiaxz1wCYbVWHAvf+v4=S5dzeHJ8c97g@mail.gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <CACzwLxjESCT_=1BG2rWiaxz1wCYbVWHAvf+v4=S5dzeHJ8c97g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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

Hi,

Le 03/08/2025 =C3=A0 21:27, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> On Wed, Jul 23, 2025 at 10:33=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gm=
ail.com> wrote:
>>
>> ...
>>
>> I don't know if it's a real problem or not. I'm just pointing out that w=
e might
>> have tricky use case here and maybe that's a problem, because nobody had=
 such use
>> case in mind. But maybe it's just fine.
>> I think we just need to boot test it, to see if this works.
>> ...
>> powerpc used static key same way before your patches, so powerpc should =
be fine.
>=20
> Hello,
>=20
> Just heads up that I am still working on v4.
> While I can verify the success on compile and booting with my changes
> on x86, arm with SW/HW_TAGS modes, I'm having issues with PowerPC, UML
> arch that selects ARCH_DEFER_KASAN.
>=20
> Adding Christophe Leroy in TO. Please advise on the powerpc panic issue.

I don't have the problem you report. Is it with your v3 series ?

I started from=20
https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git/log/?h=3D=
merge=20
(commit de12314b471bf)

Took your series with

   b4 shazam 20250717142732.292822-1-snovitoll@gmail.com

built ppc64le_defconfig

And successfully boot it under QEMU:

$ qemu-system-ppc64 -M pseries,x-vof=3Don -m 1G -nographic -vga none=20
-kernel vmlinux -initrd qemu/rootfs-el.cpio.gz -append noreboot
qemu-system-ppc64: warning: TCG doesn't support requested feature,=20
cap-cfpc=3Dworkaround
qemu-system-ppc64: warning: TCG doesn't support requested feature,=20
cap-sbbc=3Dworkaround
qemu-system-ppc64: warning: TCG doesn't support requested feature,=20
cap-ibs=3Dworkaround
qemu-system-ppc64: warning: TCG doesn't support requested feature,=20
cap-ccf-assist=3Don
[    0.000000][    T0] random: crng init done
[    0.000000][    T0] radix-mmu: Page sizes from device-tree:
[    0.000000][    T0] radix-mmu: Page size shift =3D 12 AP=3D0x0
[    0.000000][    T0] radix-mmu: Page size shift =3D 16 AP=3D0x5
[    0.000000][    T0] radix-mmu: Page size shift =3D 21 AP=3D0x1
[    0.000000][    T0] radix-mmu: Page size shift =3D 30 AP=3D0x2
[    0.000000][    T0] Activating Kernel Userspace Access Prevention
[    0.000000][    T0] Activating Kernel Userspace Execution Prevention
[    0.000000][    T0] radix-mmu: Mapped=20
0x0000000000000000-0x0000000003e00000 with 2.00 MiB pages (exec)
[    0.000000][    T0] radix-mmu: Mapped=20
0x0000000003e00000-0x0000000040000000 with 2.00 MiB pages
[    0.000000][    T0] lpar: Using radix MMU under hypervisor
[    0.000000][    T0] Linux version 6.16.0-02450-g1c11a8599f68=20
(chleroy@PO20335.IDSI0.si.c-s.fr) (powerpc64-linux-gcc (GCC) 8.5.0, GNU=20
ld (GNU Binutils) 2.36.1) #1459 SMP Mon Aug  4 12:49:11 CEST 2025
[    0.000000][    T0] KernelAddressSanitizer initialized (generic)
[    0.000000][    T0] OF: reserved mem: Reserved memory: No=20
reserved-memory node in the DT
[    0.000000][    T0] Found initrd at 0xc000000004cf0000:0xc00000000530d15=
a
[    0.000000][    T0] Hardware name: IBM pSeries (emulated by qemu)=20
POWER9 (architected) 0x4e1202 0xf000005 pSeries
[    0.000000][    T0] printk: legacy bootconsole [udbg0] enabled
[    0.000000][    T0] Partition configured for 1 cpus.
[    0.000000][    T0] CPU maps initialized for 1 thread per core
[    0.000000][    T0] numa: Partition configured for 1 NUMA nodes.
[    0.000000][    T0] ----------------------------------------------------=
-
[    0.000000][    T0] phys_mem_size     =3D 0x40000000
[    0.000000][    T0] dcache_bsize      =3D 0x80
[    0.000000][    T0] icache_bsize      =3D 0x80
[    0.000000][    T0] cpu_features      =3D 0x0001c06b8f4f9187
[    0.000000][    T0]   possible        =3D 0x003ffbfbcf5fb187
[    0.000000][    T0]   always          =3D 0x0000000380008181
[    0.000000][    T0] cpu_user_features =3D 0xdc0065c2 0xaef00000
[    0.000000][    T0] mmu_features      =3D 0x3c007641
[    0.000000][    T0] firmware_features =3D 0x00000a85455a445f
[    0.000000][    T0] vmalloc start     =3D 0xc008000000000000
[    0.000000][    T0] IO start          =3D 0xc00a000000000000
[    0.000000][    T0] vmemmap start     =3D 0xc00c000000000000
[    0.000000][    T0] ----------------------------------------------------=
-
[    0.000000][    T0] NODE_DATA(0) allocated [mem 0x3fb30800-0x3fb37fff]
[    0.000000][    T0] rfi-flush: fallback displacement flush available
[    0.000000][    T0] rfi-flush: ori type flush available
[    0.000000][    T0] rfi-flush: mttrig type flush available
[    0.000000][    T0] count-cache-flush: hardware flush enabled.
[    0.000000][    T0] link-stack-flush: software flush enabled.
[    0.000000][    T0] stf-barrier: eieio barrier available
[    0.000000][    T0] PPC64 nvram contains 65536 bytes
[    0.000000][    T0] barrier-nospec: using ORI speculation barrier
[    0.000000][    T0] Zone ranges:
[    0.000000][    T0]   Normal   [mem=20
0x0000000000000000-0x000000003fffffff]
[    0.000000][    T0]   Device   empty
[    0.000000][    T0] Movable zone start for each node
[    0.000000][    T0] Early memory node ranges
[    0.000000][    T0]   node   0: [mem=20
0x0000000000000000-0x000000003fffffff]
[    0.000000][    T0] Initmem setup node 0 [mem=20
0x0000000000000000-0x000000003fffffff]
[    0.000000][    T0] percpu: Embedded 3 pages/cpu s122904 r0 d73704=20
u196608
[    0.000000][    T0] Kernel command line: noreboot
[    0.000000][    T0] Unknown kernel command line parameters=20
"noreboot", will be passed to user space.
[    0.000000][    T0] printk: log buffer data + meta data: 262144 +=20
917504 =3D 1179648 bytes
[    0.000000][    T0] Dentry cache hash table entries: 131072 (order:=20
4, 1048576 bytes, linear)
[    0.000000][    T0] Inode-cache hash table entries: 65536 (order: 3,=20
524288 bytes, linear)
[    0.000000][    T0] Fallback order for Node 0: 0
[    0.000000][    T0] Built 1 zonelists, mobility grouping on.  Total=20
pages: 16384
[    0.000000][    T0] Policy zone: Normal
[    0.000000][    T0] mem auto-init: stack:off, heap alloc:off, heap=20
free:off
[    0.000000][    T0] stackdepot: allocating hash table via=20
alloc_large_system_hash
[    0.000000][    T0] stackdepot hash table entries: 1048576 (order: 8,=20
16777216 bytes, linear)
[    0.000000][    T0] SLUB: HWalign=3D128, Order=3D0-3, MinObjects=3D0,=20
CPUs=3D1, Nodes=3D1
[    0.000000][    T0] ftrace: allocating 47840 entries in 12 pages
[    0.000000][    T0] ftrace: allocated 12 pages with 2 groups
[    0.000000][    T0] rcu: Hierarchical RCU implementation.
[    0.000000][    T0] rcu: 	RCU event tracing is enabled.
[    0.000000][    T0] rcu: 	RCU restricting CPUs from NR_CPUS=3D2048 to=20
nr_cpu_ids=3D1.
[    0.000000][    T0] 	Rude variant of Tasks RCU enabled.
[    0.000000][    T0] 	Tracing variant of Tasks RCU enabled.
[    0.000000][    T0] rcu: RCU calculated value of scheduler-enlistment=20
delay is 100 jiffies.
[    0.000000][    T0] rcu: Adjusting geometry for rcu_fanout_leaf=3D16,=20
nr_cpu_ids=3D1
[    0.000000][    T0] RCU Tasks Rude: Setting shift to 0 and lim to 1=20
rcu_task_cb_adjust=3D1 rcu_task_cpu_ids=3D1.
[    0.000000][    T0] RCU Tasks Trace: Setting shift to 0 and lim to 1=20
rcu_task_cb_adjust=3D1 rcu_task_cpu_ids=3D1.
[    0.000000][    T0] NR_IRQS: 512, nr_irqs: 512, preallocated irqs: 16
[    0.000000][    T0] xive: Using IRQ range [0-0]
[    0.000000][    T0] xive: Interrupt handling initialized with spapr=20
backend
[    0.000000][    T0] xive: Using priority 6 for all interrupts
[    0.000000][    T0] xive: Using 64kB queues
[    0.000000][    T0] rcu: srcu_init: Setting srcu_struct sizes based=20
on contention.
[    0.000290][    T0] time_init: 56 bit decrementer (max: 7fffffffffffff)
[    0.001690][    T0] clocksource: timebase: mask: 0xffffffffffffffff=20
max_cycles: 0x761537d007, max_idle_ns: 440795202126 ns
[    0.003232][    T0] clocksource: timebase mult[1f40000] shift[24]=20
registered
[    0.040308][    T0] Console: colour dummy device 80x25
[    0.042553][    T0] printk: legacy console [hvc0] enabled
[    0.042553][    T0] printk: legacy console [hvc0] enabled
[    0.043883][    T0] printk: legacy bootconsole [udbg0] disabled
[    0.043883][    T0] printk: legacy bootconsole [udbg0] disabled
[    0.052810][    T0] pid_max: default: 32768 minimum: 301
[    0.062682][    T0] LSM: initializing=20
lsm=3Dlockdown,capability,landlock,yama,selinux,bpf,ima
[    0.075902][    T0] landlock: Up and running.
[    0.076246][    T0] Yama: becoming mindful.
[    0.077639][    T0] SELinux:  Initializing.
[    0.157184][    T0] LSM support for eBPF active
[    0.170713][    T0] Mount-cache hash table entries: 8192 (order: 0,=20
65536 bytes, linear)
[    0.171081][    T0] Mountpoint-cache hash table entries: 8192 (order:=20
0, 65536 bytes, linear)
[    0.319421][    T1] POWER9 performance monitor hardware support=20
registered
[    0.329508][    T1] rcu: Hierarchical SRCU implementation.
[    0.329940][    T1] rcu: 	Max phase no-delay instances is 400.
[    0.382714][    T1] smp: Bringing up secondary CPUs ...
[    0.385679][    T1] smp: Brought up 1 node, 1 CPU
[    0.392599][    T1] numa: Node 0 CPUs: 0
[    0.445093][   T20] node 0 deferred pages initialised in 21ms
[    0.447420][    T1] Memory: 784000K/1048576K available (25600K kernel=20
code, 9216K rwdata, 23552K rodata, 13824K init, 2373K bss, 254528K=20
reserved, 0K cma-reserved)
[    0.469596][   T20] pgdatinit0 (20) used greatest stack depth: 29936=20
bytes left
[    0.504269][    T1] devtmpfs: initialized
[    0.605561][    T1] PCI host bridge /pci@800000020000000  ranges:
[    0.607269][    T1]   IO 0x0000200000000000..0x000020000000ffff ->=20
0x0000000000000000
[    0.607837][    T1]  MEM 0x0000200080000000..0x00002000ffffffff ->=20
0x0000000080000000
[    0.608141][    T1]  MEM 0x0000210000000000..0x000021ffffffffff ->=20
0x0000210000000000
[    0.623659][    T1] clocksource: jiffies: mask: 0xffffffff=20
max_cycles: 0xffffffff, max_idle_ns: 1911260446275000 ns
[    0.625600][    T1] posixtimers hash table entries: 512 (order: -3,=20
8192 bytes, linear)
[    0.627067][    T1] futex hash table entries: 256 (32768 bytes on 1=20
NUMA nodes, total 32 KiB, linear).
[    0.692128][    T1] NET: Registered PF_NETLINK/PF_ROUTE protocol family
[    0.714282][    T1] audit: initializing netlink subsys (disabled)
[    0.722232][   T25] audit: type=3D2000 audit(1754308137.543:1):=20
state=3Dinitialized audit_enabled=3D0 res=3D1
[    0.743697][    T1] cpuidle: using governor menu
[    0.755015][    T1] WARNING: nvram corruption detected: 0-length=20
partition
[    0.755541][    T1] nvram: No room to create ibm,rtas-log partition,=20
deleting any obsolete OS partitions...
[    0.755794][    T1] nvram: Failed to find or create ibm,rtas-log=20
partition, err -28
[    0.756219][    T1] nvram: No room to create lnx,oops-log partition,=20
deleting any obsolete OS partitions...
[    0.756379][    T1] nvram: Failed to find or create lnx,oops-log=20
partition, err -28
Linux ppc64le
#1459 SMP Mon Au[    0.756539][    T1] nvram: Failed to initialize oops=20
partition!
[    0.762921][    T1] EEH: pSeries platform initialized
[    0.808097][    T1] kprobes: kprobe jump-optimization is enabled. All=20
kprobes are optimized if possible.
[    1.365147][    T1] HugeTLB: allocation took 0ms with=20
hugepage_allocation_threads=3D1
[    1.366269][    T1] HugeTLB: registered 2.00 MiB page size,=20
pre-allocated 0 pages
[    1.366456][    T1] HugeTLB: 0 KiB vmemmap can be freed for a 2.00=20
MiB page
[    1.366728][    T1] HugeTLB: registered 1.00 GiB page size,=20
pre-allocated 0 pages
[    1.366870][    T1] HugeTLB: 0 KiB vmemmap can be freed for a 1.00=20
GiB page
[    1.486251][    T1] iommu: Default domain type: Translated
[    1.486543][    T1] iommu: DMA domain TLB invalidation policy: strict=20
mode
[    1.525452][    T1] SCSI subsystem initialized
[    1.552424][    T1] usbcore: registered new interface driver usbfs
[    1.554049][    T1] usbcore: registered new interface driver hub
[    1.559907][    T1] usbcore: registered new device driver usb
[    1.562100][    T1] pps_core: LinuxPPS API ver. 1 registered
[    1.562266][    T1] pps_core: Software ver. 5.3.6 - Copyright=20
2005-2007 Rodolfo Giometti <giometti@linux.it>
[    1.566642][    T1] PTP clock support registered
[    1.577168][    T1] EDAC MC: Ver: 3.0.0
[    1.672772][    T1] PCI: Probing PCI hardware
[    1.833395][    T1] PCI host bridge to bus 0000:00
[    1.834524][    T1] pci_bus 0000:00: root bus resource [io=20
0x10000-0x1ffff] (bus address [0x0000-0xffff])
[    1.835316][    T1] pci_bus 0000:00: root bus resource [mem=20
0x200080000000-0x2000ffffffff] (bus address [0x80000000-0xffffffff])
[    1.835750][    T1] pci_bus 0000:00: root bus resource [mem=20
0x210000000000-0x21ffffffffff 64bit]
[    1.836268][    T1] pci_bus 0000:00: root bus resource [bus 00-ff]
[    1.852192][    T1] IOMMU table initialized, virtual merging enabled
[    1.864698][    T1] pci_bus 0000:00: resource 4 [io  0x10000-0x1ffff]
[    1.864967][    T1] pci_bus 0000:00: resource 5 [mem=20
0x200080000000-0x2000ffffffff]
[    1.865136][    T1] pci_bus 0000:00: resource 6 [mem=20
0x210000000000-0x21ffffffffff 64bit]
[    1.865619][    T1] EEH: No capable adapters found: recovery disabled.
[    1.895816][    T1] vgaarb: loaded
[    1.906597][    T1] clocksource: Switched to clocksource timebase
[    7.645823][    T1] NET: Registered PF_INET protocol family
[    7.650783][    T1] IP idents hash table entries: 16384 (order: 1,=20
131072 bytes, linear)
[    7.684628][    T1] tcp_listen_portaddr_hash hash table entries: 4096=20
(order: 0, 65536 bytes, linear)
[    7.686311][    T1] Table-perturb hash table entries: 65536 (order:=20
2, 262144 bytes, linear)
[    7.687827][    T1] TCP established hash table entries: 8192 (order:=20
0, 65536 bytes, linear)
[    7.690430][    T1] TCP bind hash table entries: 8192 (order: 2,=20
262144 bytes, linear)
[    7.694736][    T1] TCP: Hash tables configured (established 8192=20
bind 8192)
[    7.697887][    T1] UDP hash table entries: 1024 (order: 0, 65536=20
bytes, linear)
[    7.700717][    T1] UDP-Lite hash table entries: 1024 (order: 0,=20
65536 bytes, linear)
[    7.709437][    T1] NET: Registered PF_UNIX/PF_LOCAL protocol family
[    7.728670][    T1] RPC: Registered named UNIX socket transport module.
[    7.729411][    T1] RPC: Registered udp transport module.
[    7.729661][    T1] RPC: Registered tcp transport module.
[    7.729825][    T1] RPC: Registered tcp-with-tls transport module.
[    7.731574][    T1] RPC: Registered tcp NFSv4.1 backchannel transport=20
module.
[    7.732309][    T1] PCI: CLS 0 bytes, default 128
[    7.769612][   T12] Trying to unpack rootfs image as initramfs...
[    7.937617][    T1] Initialise system trusted keyrings
[    7.942505][    T1] Key type blacklist registered
[    7.964894][    T1] workingset: timestamp_bits=3D38 max_order=3D14=20
bucket_order=3D0
[    8.127738][    T1] NFS: Registering the id_resolver key type
[    8.129779][    T1] Key type id_resolver registered
[    8.130646][    T1] Key type id_legacy registered
[    8.150761][    T1] SGI XFS with ACLs, security attributes, no debug=20
enabled
[    8.343926][    T1] integrity: Platform Keyring initialized
[    8.348809][    T1] Key type asymmetric registered
[    8.354232][    T1] Asymmetric key parser 'x509' registered
[    8.372851][    T1] Block layer SCSI generic (bsg) driver version 0.4=20
loaded (major 247)
[    8.375844][    T1] io scheduler mq-deadline registered
[    8.377498][    T1] io scheduler kyber registered
[   11.082153][    T1] Serial: 8250/16550 driver, 4 ports, IRQ sharing=20
disabled
[   11.199822][    T1] Non-volatile memory driver v1.3
[   11.749528][    T1] brd: module loaded
[   12.062135][    T1] loop: module loaded
[   12.078153][    T1] ipr: IBM Power RAID SCSI Device Driver version:=20
2.6.4 (March 14, 2017)
[   12.118444][    T1] ibmvscsi 71000003: SRP_VERSION: 16.a
[   12.134566][    T1] ibmvscsi 71000003: Maximum ID: 64 Maximum LUN: 32=20
Maximum Channel: 3
[   12.135207][    T1] scsi host0: IBM POWER Virtual SCSI Adapter 1.5.9
[   12.188126][    C0] ibmvscsi 71000003: partner initialization complete
[   12.191555][    C0] ibmvscsi 71000003: host srp version: 16.a, host=20
partition qemu (0), OS 2, max io 2097152
[   12.192709][    C0] ibmvscsi 71000003: sent SRP login
[   12.193698][    C0] ibmvscsi 71000003: SRP_LOGIN succeeded
[   12.381686][    T1] scsi 0:0:2:0: CD-ROM            QEMU     QEMU=20
CD-ROM      2.5+ PQ: 0 ANSI: 5
[   17.470934][   T12] Freeing initrd memory: 6208K
[   18.458146][    C0] sr 0:0:2:0: Power-on or device reset occurred
[   18.468304][    T1] sr 0:0:2:0: [sr0] scsi3-mmc drive: 16x/50x cd/rw=20
xa/form2 cdda tray
[   18.469176][    T1] cdrom: Uniform CD-ROM driver Revision: 3.20
[   18.507507][    T1] sr 0:0:2:0: Attached scsi generic sg0 type 5
[   18.535454][    T1] e100: Intel(R) PRO/100 Network Driver
[   18.535682][    T1] e100: Copyright(c) 1999-2006 Intel Corporation
[   18.536741][    T1] e1000: Intel(R) PRO/1000 Network Driver
[   18.536894][    T1] e1000: Copyright (c) 1999-2006 Intel Corporation.
[   18.538093][    T1] e1000e: Intel(R) PRO/1000 Network Driver
[   18.538241][    T1] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
[   18.548528][    T1] i2c_dev: i2c /dev entries driver
[   18.551722][    T1] device-mapper: core: CONFIG_IMA_DISABLE_HTABLE is=20
disabled. Duplicate IMA measurements will not be recorded in the IMA log.
[   18.553452][    T1] device-mapper: uevent: version 1.0.3
[   18.564534][    T1] device-mapper: ioctl: 4.50.0-ioctl (2025-04-28)=20
initialised: dm-devel@lists.linux.dev
[   18.591869][    T1] usbcore: registered new interface driver usbhid
[   18.592226][    T1] usbhid: USB HID core driver
[   18.594958][    T1] ipip: IPv4 and MPLS over IPv4 tunneling driver
[   18.611797][    T1] NET: Registered PF_INET6 protocol family
[   18.651618][    T1] Segment Routing with IPv6
[   18.653186][    T1] In-situ OAM (IOAM) with IPv6
[   18.656776][    T1] sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
[   18.672737][    T1] NET: Registered PF_PACKET protocol family
[   18.676757][    T1] Key type dns_resolver registered
[   18.678951][    T1] secvar-sysfs: Failed to retrieve secvar operations
[   18.683474][    T1] Running code patching self-tests ...
[   19.045499][    T1] registered taskstats version 1
[   19.055453][    T1] Loading compiled-in X.509 certificates
[   19.106895][    T1] Loaded X.509 cert 'Build time autogenerated=20
kernel key: 9f01b0d991e9d73077cd296c67edb3efb56e2c47'
[   19.372917][    T1] Demotion targets for Node 0: null
[   19.373664][    T1] page_owner is disabled
[   19.385615][    T1] Secure boot mode disabled
[   19.387815][    T1] ima: No TPM chip found, activating TPM-bypass!
[   19.389833][    T1] Loading compiled-in module X.509 certificates
[   19.406497][    T1] Loaded X.509 cert 'Build time autogenerated=20
kernel key: 9f01b0d991e9d73077cd296c67edb3efb56e2c47'
[   19.407680][    T1] ima: Allocated hash algorithm: sha256
[   19.416714][    T1] Secure boot mode disabled
[   19.417345][    T1] Trusted boot mode disabled
[   19.417596][    T1] ima: No architecture policies found
[   19.426439][    T1] printk: legacy console [netcon0] enabled
[   19.426791][    T1] netconsole: network logging started
[   19.610553][    T1] Freeing unused kernel image (initmem) memory: 13824K
[   19.766345][    T1] Checked W+X mappings: passed, no W+X pages found
[   19.767739][    T1] rodata_test: all tests were successful
[   19.768936][    T1] Run /init as init process
[   20.432221][   T58] mount (58) used greatest stack depth: 26992 bytes=20
left
[   20.808923][   T60] mount (60) used greatest stack depth: 26416 bytes=20
left
mount: mounting devtmpfs on /dev failed: Device or resource busy
Starting syslogd: OK
Starting klogd: OK
Running sysctl: [   24.879851][   T83] find (83) used greatest stack=20
depth: 26368 bytes left
[   24.945794][   T84] xargs (84) used greatest stack depth: 26240 bytes=20
left
OK
Saving 256 bits of creditable seed for next boot
Starting network: [   26.530674][   T96] ip (96) used greatest stack=20
depth: 26048 bytes left
[   27.018425][   T97] ip (97) used greatest stack depth: 24256 bytes left
Waiting for interface eth0 to appear..... timeout!
run-parts: /etc/network/if-pre-up.d/wait_iface: exit status 1
FAIL
[   33.902403][    C0] hrtimer: interrupt took 3450588 ns
Found console hvc0

Linux version 6.16.0-02450-g1c11a8599f68=20
(chleroy@PO20335.IDSI0.si.c-s.fr) (powerpc64-linux-gcc (GCC) 8.5.0, GNU=20
ld (GNU Binutils) 2.36.1) #1459 SMP Mon Aug  4 12:49:11 CEST 2025
Network interface test failed
TPM selftest failed
File system test skipped
Boot successful.
~ #


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
4b373bb-cf18-49b3-84ed-56d04e09c71e%40csgroup.eu.
