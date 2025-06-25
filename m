Return-Path: <kasan-dev+bncBDCPL7WX3MKBBP4Y5XBAMGQEZG2O23A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DEE4AAE740C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 03:09:23 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b2c36951518sf1319456a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 18:09:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750813759; cv=pass;
        d=google.com; s=arc-20240605;
        b=jnTBgOdztRG/URla8HQTOwG9KDpUqm63SeTw6dTA/1PanXuSAnz76zhIxW4csctk2o
         jr9gFBNlxdswqFeXIhwAMbI2WSw2e2PlZcz4f2NEuzw0cNY4ergMQPYtPopBx0gix5Vy
         oOqTTnreACIGKdh0ujWahMVMEk41lrHG5ufufSpsFfdV3K8JlvY03KRq/7VmugJEDp5l
         wjAXLRVaHCZ/M62WDOaeqExHuJltUXwOxcecMWkszpPOuqgsbZDACQaFhv7lQyPkmsbY
         9OzSLAMqbVRRYDWoZzAgJ0WPQ/u9yjWjH2lJtccwxwgWMUl2fnNBUZAUYhyT5Iwhhxdq
         p8LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:references:in-reply-to:user-agent:subject
         :cc:to:from:date:dkim-signature;
        bh=ul1WdXdakBgFTfOMDjRfXvrDxNUEHWyvAfhUIpoOSgw=;
        fh=iGge47q8KBk9uxDRx6Ob4AVS0e2DyYMBcIQD0Qv9LhA=;
        b=lpVlGoLFEt35iyGL9vH+1WjRJBeyv8oxEkaPhV7JDSJAG6UVnMFmlG1X6S8lz19PX5
         Ijyihn19vo57mJPdLzLbAsJA/9yuU+Qdm7ErbDlYbGq50jj5D3mdYW/qIPjcNIN1n/9i
         TpXWLzRmURKwIXFCRjzWV0MKRRW95HJnt7jPgLt+EeZxs1gCfsO1SV3/kd2tKPPV9gpk
         0JR+0EHR4YFc7qU7iGPVRc4/DptMGtdFT0+vyot1ofZQmubgeFsPl1KfBg+C5OHANRq5
         rZzsdMtuMKZbrZYLZCxnixUgUX2z9jwIzymIQ/utuhSwKgGhVVP/FVgzyGNvI9iYyzQg
         la3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=si3Mv9bY;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750813759; x=1751418559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ul1WdXdakBgFTfOMDjRfXvrDxNUEHWyvAfhUIpoOSgw=;
        b=Ij/Ny7YMQmqbrPvLVIfadAM/NaCg+TKjKWXvCNS6hrZQq8gUVjWq5wTuKoRVFZW0NQ
         1L13ZR/2a9x2MorLjw/lGTGfkdTaIaBaPM3t172/k8/+e6NbkruJO0T4m+c7Hh+QusAU
         k4afr9ERTn22yYzv8k7/kAYYmWc1JHcLDRVtksodB5aiQIVJaR1j22MVr7djw/GavmFu
         mkgz7CumyWleF6WybezIQguct/bXru9SH6trdwEgDKfJ54ZRZr3gdsgykEfaijBc+10x
         2MVgRLYgqdRs3GvO9Cj9ZEbfUIGuuPoQkeNguoEY0c39wzhvG8JZKoeEqVgwPj3smw1i
         wIHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750813759; x=1751418559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ul1WdXdakBgFTfOMDjRfXvrDxNUEHWyvAfhUIpoOSgw=;
        b=BI19CKhrKDQz/e+9eQgTmjoYCjw7hrskxuVb7LmFzysZb/r0pZgtoHSPLsMLhN1+yo
         nj+TcMFIqqec5y/fc+IylEUAKLLlyWGeZf4lGsJCrjB6QI8/iWPiTMRRhRCZbVzSkmmw
         Eh3ilZfFZRxjkv6nrdWEpM99DwsERSDf818dg3zKHKETeZutUn2g5nHYjc4uToNyLM29
         8dZ3yEGZdfyz2gVzEejitfNoB9JGLhBhtktZg+55FLGZ8kvDdQbMB94MaQ1BjTbKqO3b
         GJy/SIwZKih/EJgDJFjIrOffC0ZRJsfAhcubOI3reh/7mI4/7Cbl1LZY9g7uKnRJNDXo
         50Gg==
X-Forwarded-Encrypted: i=2; AJvYcCXfi5QF5w7rX0Q/prRG3Y484dxpa9tSnwUfGgBNOpCiQBD69v26ZDTOSzE0sB3ltY1GpOB/qQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzkumku8iPKw0SQAxn0BDERcpV7xDIaOfiWY9a8Etn9YNKULi/Z
	NvwqF+oS/L8QeXMe96PABIDAmWZhLRxrB0vB618xZBFdmtUezsG5H8u2
X-Google-Smtp-Source: AGHT+IENBpPDqCQntZ0or56191sdfORhesRDMYtPECuuOKjyTbL03jGgAhPj8LYNxinT2BCIxp1X9g==
X-Received: by 2002:a05:6a21:1788:b0:21c:faa4:9abb with SMTP id adf61e73a8af0-2207f25deb5mr1644368637.20.1750813759348;
        Tue, 24 Jun 2025 18:09:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf51sxfrqn0ZgR4VQ5GJiRJC0uBe4XSH1lPobyFBN/fFg==
Received: by 2002:a05:6a00:14ce:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-748f9694dc0ls7252294b3a.1.-pod-prod-03-us; Tue, 24 Jun 2025
 18:09:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1SyOOgqwhR+RHPFAJL/u9qQluAOaQSC0xnKSt7xpbbEaTPGcv6JMrQaC6nFeZbyC02xlEF6m54Y8=@googlegroups.com
X-Received: by 2002:a05:6a00:10c2:b0:736:5822:74b4 with SMTP id d2e1a72fcca58-74ad45b9121mr1807983b3a.21.1750813757996;
        Tue, 24 Jun 2025 18:09:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750813757; cv=none;
        d=google.com; s=arc-20240605;
        b=X3gJCu/iu/c1gj/12aulU3zfYo5UjF4isYgDNoICrcTzLo2XukiZ7kxqCFsU+RBWGZ
         VmSEt5Lz0EnQIRnDa6RSH9M3fZWJHFyZuXxaqMX4aQ848TTgwHsO7Dtnd4aF3VMArUT9
         VRyGYmKuRAiXc+EjtX8SAiAqOpMr5o95sYIWx5JrTVj0ZXTb6im2pQozAoI3UUN2G/ax
         zRRqTPKD02V2mOv2EQqXrErIDSIQOoeenb07d03NZJyQMa7O1CaD0bOnTyK8LVsy872f
         EDw1MYHgd8ikIf3i123mIiT2rAL6D508xgZuIyN6qsq6/Yar7vxeNZOU8/CicEWvtrn3
         w3zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=HFw2kmBOCe8dAlOebCiebY1IUKv0rnJ+4n3KRhV6q3w=;
        fh=/gd/g49tjmFS3ktMB2OQkRx+Pjn/nl2wG+JvvJFBtkQ=;
        b=XjjiT6oF0v/6wxXkrJUSxGaGfWwvfOJkRb5f1pSWnO+ExMEovQNQHaRA12L2Sg+rVA
         Uix5DhRI6j/6ZWEDatmcjaKVNVZEad32anOUai2qy5+7JY3nBFFgiUdah26fvp46EGey
         mVpVwOiTo53Ufehzq6VCHSPepu/hwUkujz72fwLEGAGQpGpevb4F/Zm9OXqa45itDfdO
         4cWZ73dUGULmIXxXgD0xiXZV9spykUNTC4WjVbrKBHmY1QhO0qlEtk1G7Azry+qIJ5U0
         exF4DAeSNUjQ7z1Ln6bVO1p6N79mV/3gwbCWwy0vJuRb3Vkm4yC7kiVPSwbqqKLftBFH
         DdqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=si3Mv9bY;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-749c86d7efesi126017b3a.3.2025.06.24.18.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jun 2025 18:09:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C914360051;
	Wed, 25 Jun 2025 01:09:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6F5E3C4CEE3;
	Wed, 25 Jun 2025 01:09:16 +0000 (UTC)
Date: Tue, 24 Jun 2025 18:09:18 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Huacai Chen <chenhuacai@kernel.org>
CC: Arnd Bergmann <arnd@arndb.de>, WANG Xuerui <kernel@xen0n.name>,
 Thomas Gleixner <tglx@linutronix.de>,
 Tianyang Zhang <zhangtianyang@loongson.cn>, Bibo Mao <maobibo@loongson.cn>,
 Jiaxun Yang <jiaxun.yang@flygoat.com>, loongarch@lists.linux.dev,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Ard Biesheuvel <ardb@kernel.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>,
 Nicolas Schier <nicolas.schier@linux.dev>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 linux-kernel@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org,
 sparclinux@vger.kernel.org, llvm@lists.linux.dev
Subject: =?US-ASCII?Q?Re=3A_=5BPATCH_v2_10/14=5D_loongarch=3A_Han?=
 =?US-ASCII?Q?dle_KCOV_=5F=5Finit_vs_inline_mismatches?=
User-Agent: K-9 Mail for Android
In-Reply-To: <CAAhV-H5oHPG+etNawAmVwyDtg80iKUrAM_m3Vj57bBO0scHqvQ@mail.gmail.com>
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-10-kees@kernel.org> <CAAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ@mail.gmail.com> <CAAhV-H5oHPG+etNawAmVwyDtg80iKUrAM_m3Vj57bBO0scHqvQ@mail.gmail.com>
Message-ID: <B5A11282-CB0E-46E0-A5D7-EF4D8BFC23B4@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=si3Mv9bY;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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



On June 24, 2025 5:31:12 AM PDT, Huacai Chen <chenhuacai@kernel.org> wrote:
>Hi, Kees,
>
>On Thu, Jun 19, 2025 at 4:55=E2=80=AFPM Huacai Chen <chenhuacai@kernel.org=
> wrote:
>>
>> Hi, Kees,
>>
>> On Fri, May 23, 2025 at 12:39=E2=80=AFPM Kees Cook <kees@kernel.org> wro=
te:
>> >
>> > When KCOV is enabled all functions get instrumented, unless
>> > the __no_sanitize_coverage attribute is used. To prepare for
>> > __no_sanitize_coverage being applied to __init functions, we have to
>> > handle differences in how GCC's inline optimizations get resolved. For
>> > loongarch this exposed several places where __init annotations were
>> > missing but ended up being "accidentally correct". Fix these cases and
>> > force one function to be inline with __always_inline.
>> >
>> > Signed-off-by: Kees Cook <kees@kernel.org>
>> > ---
>> > Cc: Huacai Chen <chenhuacai@kernel.org>
>> > Cc: WANG Xuerui <kernel@xen0n.name>
>> > Cc: Thomas Gleixner <tglx@linutronix.de>
>> > Cc: Tianyang Zhang <zhangtianyang@loongson.cn>
>> > Cc: Bibo Mao <maobibo@loongson.cn>
>> > Cc: Jiaxun Yang <jiaxun.yang@flygoat.com>
>> > Cc: <loongarch@lists.linux.dev>
>> > ---
>> >  arch/loongarch/include/asm/smp.h | 2 +-
>> >  arch/loongarch/kernel/time.c     | 2 +-
>> >  arch/loongarch/mm/ioremap.c      | 4 ++--
>> >  3 files changed, 4 insertions(+), 4 deletions(-)
>> >
>> > diff --git a/arch/loongarch/include/asm/smp.h b/arch/loongarch/include=
/asm/smp.h
>> > index ad0bd234a0f1..88e19d8a11f4 100644
>> > --- a/arch/loongarch/include/asm/smp.h
>> > +++ b/arch/loongarch/include/asm/smp.h
>> > @@ -39,7 +39,7 @@ int loongson_cpu_disable(void);
>> >  void loongson_cpu_die(unsigned int cpu);
>> >  #endif
>> >
>> > -static inline void plat_smp_setup(void)
>> > +static __always_inline void plat_smp_setup(void)
>> Similar to x86 and arm, I prefer to mark it as __init rather than
>> __always_inline.
>If you have no objections, I will apply this patch with the above modifica=
tion.

That's fine by me; thank you! I didn't have a chance yet to verify that it =
actually fixes the mismatches I saw, but if it looks good to you, yes pleas=
e. :)

-Kees

>
>
>Huacai
>
>>
>> Huacai
>>
>> >  {
>> >         loongson_smp_setup();
>> >  }
>> > diff --git a/arch/loongarch/kernel/time.c b/arch/loongarch/kernel/time=
.c
>> > index bc75a3a69fc8..367906b10f81 100644
>> > --- a/arch/loongarch/kernel/time.c
>> > +++ b/arch/loongarch/kernel/time.c
>> > @@ -102,7 +102,7 @@ static int constant_timer_next_event(unsigned long=
 delta, struct clock_event_dev
>> >         return 0;
>> >  }
>> >
>> > -static unsigned long __init get_loops_per_jiffy(void)
>> > +static unsigned long get_loops_per_jiffy(void)
>> >  {
>> >         unsigned long lpj =3D (unsigned long)const_clock_freq;
>> >
>> > diff --git a/arch/loongarch/mm/ioremap.c b/arch/loongarch/mm/ioremap.c
>> > index 70ca73019811..df949a3d0f34 100644
>> > --- a/arch/loongarch/mm/ioremap.c
>> > +++ b/arch/loongarch/mm/ioremap.c
>> > @@ -16,12 +16,12 @@ void __init early_iounmap(void __iomem *addr, unsi=
gned long size)
>> >
>> >  }
>> >
>> > -void *early_memremap_ro(resource_size_t phys_addr, unsigned long size=
)
>> > +void * __init early_memremap_ro(resource_size_t phys_addr, unsigned l=
ong size)
>> >  {
>> >         return early_memremap(phys_addr, size);
>> >  }
>> >
>> > -void *early_memremap_prot(resource_size_t phys_addr, unsigned long si=
ze,
>> > +void * __init early_memremap_prot(resource_size_t phys_addr, unsigned=
 long size,
>> >                     unsigned long prot_val)
>> >  {
>> >         return early_memremap(phys_addr, size);
>> > --
>> > 2.34.1
>> >

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/B=
5A11282-CB0E-46E0-A5D7-EF4D8BFC23B4%40kernel.org.
