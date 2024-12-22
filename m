Return-Path: <kasan-dev+bncBDZ2VWGKUYCBBSWFTW5QMGQEWTT2EAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 11A729FA323
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 01:52:29 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ef9864e006sf4039548a91.2
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 16:52:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734828747; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lmr5ncLkGLlPjmYrh11kpXMjkU+IB4CxcjS1fyT8LTLzwqOvtU1JZzMMi/0xHSg3Nm
         iGDI0eAZQ9pk9zjU5IHBmwCVyeg6Ljbn8/5iQh5+syDbQ+AwdLgqCFb8/SvNP1CmVQC6
         wndzvI2UPsmwr6Lc7vzSyHvRlV3DF2RjI7upPmbPgqH9W2x2on2T62oB499Jy4cz9Jp9
         FH+K84/sSR+Sqd33yDdHbKdL8gJppt4PnPHpgFi8DGqik4vTxwMv3NUoha2nh7VSEzPV
         zGnB8ZKujmZ/KHZScvcT9aiUVeOJD/J5f7OHShdz2tCAkzkxOFZUNLxVkG01nLyIr0u0
         GbVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GORGVo4fPFC+WczaxH2fEkfg2MLvaULrsw8Anh+UDDA=;
        fh=qVKcRlacUKr6hztmFTFxz4cg4dQYMzQnt5XsvmlTsGw=;
        b=LYZ3N9ETYETUfFWuPY9ylOZSDzUWABPnAkjHX/KrkP3WXpjf0m4nqZTnPWw66VUf96
         xG+IMmkypGIC0hZEr1/66h62DPvvAsm50wbTaDdScntvgRIcDrXpstuxygXfM2riBXj9
         MvIOA2xjrc1DyF15kr9ouhH0/qX2dDZNcc63l1qLz9oUKOImQOMYSab5EstegtUfETKn
         e2vIFXAbuhAIHOy1g8kJjdYFng7Lp5fqCv0k2EK9G4kzVEfmibv+blgjEDyzmNjbWflT
         hhJw5fthAsjWaH9ViMWiWAEySC9BAqhfLHYGmv9EBWzJ776/TWol0lyHGxxVhJslNIuU
         7NhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AwFe+PNb;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734828747; x=1735433547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GORGVo4fPFC+WczaxH2fEkfg2MLvaULrsw8Anh+UDDA=;
        b=dfqEwWgfICJblzbGjNtlceAtwduDlju2CTQEBlfSNtAJa/p9kjOtZztigGale4V4j4
         Jz2YgJDVEhUzudxTmdTrWsYf7SNZxDGVwX++stFzFCtKI1Xk8lbkQpLpCRTwdpp7haKP
         R8z7PysHyURQT09Ecav3a6IE0SXKAmJ1AYFvW+wudN2hhLKAl6qxnb05aYoTuItc93lF
         5PLpWrNwZ4bbJNyiVhjBQFe1DBRQ5/18I8ST3E3+ExTOOcjAWwMGJ/JA9/jatpjtXwXD
         slLXXE+n9SgT5pnsAi/Ky5cupoedoe43iBgzAU6vSwcaVhQAIRg2+kiDPUtWy8aLfEzz
         VDcw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734828747; x=1735433547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GORGVo4fPFC+WczaxH2fEkfg2MLvaULrsw8Anh+UDDA=;
        b=Tly0tJFcZlLiNFbeA7VUMCksxXTOCl5VMGWBS8xpyogFIgkdAe125kn5PoNY0A4Pyr
         zwVFyitTqN/SpP0ZDlI5st70AdfENE7S3MULpeu6WO+bZIrW3kTymJ2LJ2fiNcZA38rp
         M8w5Hj8+KAgVlCp4zc8+1/TAgbgtB1J7lzFnJdrDTqKUaeXEwqOSatGgdFLckV5JYgxq
         nnFLp+u8RpLwIKsP33XfH2VN0Du7+yTpLkpGiUa6YqhSz05s6deEmRD2AdQoP9jJssdv
         2S/J3iNrUIB1SrySnZhp9C20SmIfQoDoL+LWsh3iq4M2ybqa8Vc6S6udKIFseOQhIGHN
         ffQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734828747; x=1735433547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GORGVo4fPFC+WczaxH2fEkfg2MLvaULrsw8Anh+UDDA=;
        b=YlqdleIjHvSY+nQAotzuK54o62miPZizseY2HI0p976d0zsqLJrL45b9CJ2g+dN2kG
         Zrwe17wW45XMoAQ/M1v1RimYUDa5R8Dghv1NmafJKXccw7U4Lr+MpnF9xragtNE5F/2Y
         0M0Iu/3ZQOJJWOlFsav3VitKt4zV68UNRKbg97L2qn62XinPP9aDaKyuHa90s25gkR+y
         bKcdiYl/fhId52JCscPn1y9C6j1hcgc7hKVKtBlRsG2QgylL4kOixC/P+ooq3gdpjVEy
         U2cxUxviLwCsBUlsO15NSQZgIv6CzopgN73btWErySQZoewwxMPAZkasanmcRkIjjqoI
         9Aiw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMh8xBy/7ejZLl8ggEv6bWqFO90s7FzXkl4C9ldf/aIKWPWaBfQCT0YAYwRZEPNMMr8GjgoA==@lfdr.de
X-Gm-Message-State: AOJu0YyfmK8vUxRgwycxNMx1Q1Js6G4qH5IGXjb7fLgkEv7JaW8Y8cxa
	Nmo2Wi3CFgtOFeNgUrSkUydHWngRiSsEI9181KX00WH4Nc/gRlE9
X-Google-Smtp-Source: AGHT+IHGdxhP08UPKJsiRP1XuidrgAzXGzF2LhxP6nVrIipnSf1vhihatSn+bzymTA0lhvoM5HMMAQ==
X-Received: by 2002:a17:90b:534b:b0:2ee:c91a:acf7 with SMTP id 98e67ed59e1d1-2f452dfccdcmr12210363a91.4.1734828746778;
        Sat, 21 Dec 2024 16:52:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1f85:b0:2ef:288a:b248 with SMTP id
 98e67ed59e1d1-2f4430e0810ls999940a91.2.-pod-prod-03-us; Sat, 21 Dec 2024
 16:52:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVkX+a0Hv6q9v8OXBYsC+u2XFsef7Gzv4YATtPzFX/hzFl2M2SabySmPF1bYW/WlrIdPnl88KOUUg=@googlegroups.com
X-Received: by 2002:a17:90b:2f07:b0:2ea:9ccb:d1f4 with SMTP id 98e67ed59e1d1-2f452d32b5fmr14639032a91.0.1734828745292;
        Sat, 21 Dec 2024 16:52:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734828745; cv=none;
        d=google.com; s=arc-20240605;
        b=ghzH02xKfcs+fA73bmGqVRNnUa4pQraAdcaTZVMEIpyc1P/AV+Sh7QJ72kNaezmKHB
         uaUy1nva1JQRsiqHBkJY6k3s7ESeS260oYQbCEfD9cax3DcmR5/e7WDY6pTx/Y8wP3JM
         wO9eflA9Rh1eWXfx9/ZyPVoSmUSxPjI3cZR7sbf8weidpKBg9wITHu5pwWRJmsth4Zvh
         YGvSLcVj39dmgXvW12B+yU/v8/41gqyGcOvcrdb+Jm6D5b9rCvtCJs+oHSDtQgZ5RGwD
         oP3SQqQxZ2nqQGqx3YpgYnNNBfd4HXaJY+idTOTMn+LyPmsmSddoS6nwXXzp6DWaAPHE
         WV5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G56dFj5BRaIttSoRxhRi+K83W3sP81bwdAaZ6QoaIrc=;
        fh=OmpnMkJrKf8AypQ7cQ9R0hetAmnztCLeX2N/k3VSjX8=;
        b=F4/2hwtWApzylFprb1W0kJwNZxt6GmKXjTKbseYGoy8GWeExcPFaAVsY71f5eSpW/o
         uJo2ljtvxyxqLFnPl3HKcbBp0nve0ZIkJk1emxwaOc5PrN8ZPsXERM1TDhdX5lwuLaWV
         rKZxBvbSelQa4eHu0N9nyMS2RHH8lM4sr4+ubnUcW/Br0uTjgignLa/bzXQ6u9GKxkG4
         kLrUj6etCt+hcTyfSeq1/qe5BEfmpdtqK2jTqm2pF7pmipQ3WWZ99jicrNhCFHi0jGfK
         LfdJLy6cpNQXYxH09DBq/MR0Ryn1XqAKObvNCRqGkHty5vKB342GszEhBsYuRp0TIBPb
         VtsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AwFe+PNb;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f2ed530d80si575260a91.1.2024.12.21.16.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Dec 2024 16:52:25 -0800 (PST)
Received-SPF: pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-e46ebe19368so2382029276.0
        for <kasan-dev@googlegroups.com>; Sat, 21 Dec 2024 16:52:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVUPyNMhZLdufwqkfcAvlCFeu8NWhnUqLt+2jfaEVlFF966oMSE5dlI/n1IEYE+flEBxLR7K1sAWvQ=@googlegroups.com
X-Gm-Gg: ASbGncsQnycKtWMIAOUzJW3HuZRCUCksScR0TVho1ln8+8nXqe3XipdgkAm1A14f/lG
	/1PXLwSecS63DeW25n5faYhL9B4Yx/NPFKOEK18M=
X-Received: by 2002:a05:690c:4e82:b0:6f0:21d6:4497 with SMTP id
 00721157ae682-6f3f80d911amr42730727b3.9.1734828744363; Sat, 21 Dec 2024
 16:52:24 -0800 (PST)
MIME-Version: 1.0
References: <20241221104304.2655909-1-guoweikang.kernel@gmail.com> <CAMuHMdXbB-ksxZ9+YRz86wazPGSM09ZFX7JZoyH--=UDndS=TQ@mail.gmail.com>
In-Reply-To: <CAMuHMdXbB-ksxZ9+YRz86wazPGSM09ZFX7JZoyH--=UDndS=TQ@mail.gmail.com>
From: Weikang Guo <guoweikang.kernel@gmail.com>
Date: Sun, 22 Dec 2024 08:52:14 +0800
Message-ID: <CAOm6qn=aN_n3jRc79wr-AGVaQXCbZoyE0yXYcZfw28-uBv+zuQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm/memblock: Add memblock_alloc_or_panic interface
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>, 
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Oreoluwa Babatunde <quic_obabatun@quicinc.com>, 
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>, 
	Hanjun Guo <guohanjun@huawei.com>, Easwar Hariharan <eahariha@linux.microsoft.com>, 
	Johannes Berg <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, 
	Dave Hansen <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, 
	KP Singh <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>, 
	Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>, 
	WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>, 
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne <shorne@gmail.com>, 
	Helge Deller <deller@gmx.de>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao <naveen@kernel.org>, 
	Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff Levand <geoff@infradead.org>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Yoshinori Sato <ysato@users.sourceforge.jp>, 
	Rich Felker <dalias@libc.org>, John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, 
	Andreas Larsson <andreas@gaisler.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-alpha@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, 
	linux-mips@vger.kernel.org, linux-openrisc@vger.kernel.org, 
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, 
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-acpi@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-omap@vger.kernel.org, linux-clk@vger.kernel.org, 
	devicetree@vger.kernel.org, linux-mm@kvack.org, linux-pm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: guoweikang.kernel@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AwFe+PNb;       spf=pass
 (google.com: domain of guoweikang.kernel@gmail.com designates
 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Geert Uytterhoeven <geert@linux-m68k.org> wrote on Saturday, 21
December 2024 at 22:10
>
> Hi Guo,
>
> On Sat, Dec 21, 2024 at 11:43=E2=80=AFAM Guo Weikang
> <guoweikang.kernel@gmail.com> wrote:
> > Before SLUB initialization, various subsystems used memblock_alloc to
> > allocate memory. In most cases, when memory allocation fails, an immedi=
ate
> > panic is required. To simplify this behavior and reduce repetitive chec=
ks,
> > introduce `memblock_alloc_or_panic`. This function ensures that memory
> > allocation failures result in a panic automatically, improving code
> > readability and consistency across subsystems that require this behavio=
r.
> >
> > Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
>
> Thanks for your patch!
>
> > --- a/include/linux/memblock.h
> > +++ b/include/linux/memblock.h
> > @@ -417,6 +417,20 @@ static __always_inline void *memblock_alloc(phys_a=
ddr_t size, phys_addr_t align)
> >                                       MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_N=
O_NODE);
> >  }
> >
> > +static __always_inline void *__memblock_alloc_or_panic(phys_addr_t siz=
e,
> > +                                                      phys_addr_t alig=
n,
> > +                                                      const char *func=
)
> > +{
> > +       void *addr =3D memblock_alloc(size, align);
> > +
> > +       if (unlikely(!addr))
> > +               panic("%s: Failed to allocate %llu bytes\n", func, size=
);
> > +       return addr;
> > +}
>
> Please make this out-of-line, and move it to mm/memblock.c, so we have
> just a single copy in the final binary.
>
Got it, I'll make the change
> > +
> > +#define memblock_alloc_or_panic(size, align)    \
> > +        __memblock_alloc_or_panic(size, align, __func__)
> > +
> >  static inline void *memblock_alloc_raw(phys_addr_t size,
> >                                                phys_addr_t align)
> >  {
> > diff --git a/init/main.c b/init/main.c
>
> Gr{oetje,eeting}s,
>
>                         Geert
>
> --
> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m6=
8k.org
>
> In personal conversations with technical people, I call myself a hacker. =
But
> when I'm talking to journalists I just say "programmer" or something like=
 that.
>                                 -- Linus Torvalds

Best regards
             Guo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AOm6qn%3DaN_n3jRc79wr-AGVaQXCbZoyE0yXYcZfw28-uBv%2BzuQ%40mail.gmail.com.
