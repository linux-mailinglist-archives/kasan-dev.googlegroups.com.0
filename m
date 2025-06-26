Return-Path: <kasan-dev+bncBDAOJ6534YNBBS5B6XBAMGQERJVAQBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 98A96AE9F6C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:53:19 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553ab0afaa4sf554741e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:53:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945996; cv=pass;
        d=google.com; s=arc-20240605;
        b=egDzb8e+kIDGGUH7iXVd1HGu04CKkZopDppE/dNQyewGlPTCZiTOfLfygehsueQeSz
         guq4/9GqF13fOhRHEJN63swJkqunAau/4x+wTI7fS8cSTHqKbYYZoPxcZXNM9RtgWXF1
         Je3Z8qhukExw4FTbKhwOw1ajSvqyBFXoHkBDX10hQ8XcmhnRZGnSDWrky5z+6DYO/nIv
         H0b9XKM4o4ThXglFqHvqcCIJjKQUEAV6X3mgt0eyrvKX3NZ8DnEJhIydDVSssb8rJfcj
         PUCPBRw7VlnFpvPjKSZf95pzmyVQj8fYAd9YXnuB/i35+IcwdywIQXBjoYDBImWInE8Y
         VnYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=5YAHutT4ePwos7SGd89WO7WQovvxHxOM8YWaXJlHriw=;
        fh=oPQwfdqUKr/hWk1w19WDyY/gmvqTLqgPXuQPhvk7ZDc=;
        b=A0xeOm9ztggX4YZonW0ywVfuCoigVsCCLVfvIG4qIGRkP70gsklf5IREFi70ApokEX
         lgIpJwgGa3WkT2Qhj8Qkh4wuujI3/88XdmPc4h6nTnXM9kd4qIf1tfCrKFuAIWjh25pS
         R1iUKczRd+pRGosu5yiXukIwD4A0J9ni4uEVyR7DzCLACpfym3jUMvBDB65SaqMJ1fId
         rkH4UN7SCHQUUjHfqTh6Tj+7fqmezPVMLGYxRP5lvHDprKfmfB2Y4IYB3N0mF4hrnspn
         qtUS0tEqcgPDrkVssjKz02dwERD2TQqrSXgJ0oMMTxnWE7C3Hu9I8SwTyulf9ySwG4uE
         tDHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=brvWxeWW;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945996; x=1751550796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5YAHutT4ePwos7SGd89WO7WQovvxHxOM8YWaXJlHriw=;
        b=moOBaHBpBeF7dftqgRhI7zLo7NeB4WDea2LPjqlzZK30FjadfdKseOOAF3NUWSeOAI
         bghJHm6Ov3xn8pp76GHkek4mJnbXuiZjLgZcebxrnw6OAxH8/NJS1T0XZCLlebqWVLhu
         XM6/rqcpbwBqhh3hOucUPDPvb1mnaw+qajZrM51+Hqj0SMaSOPUguCaXYIeBXmEACCDm
         UpmLs2nZip8GUF1pe3DvZJ0zh+/F7QRZmAylVYjivk4z62rgoECKAo1DI2Ah2DqLbKjF
         Wpbw2GLtNJVrRbU10kYmg3oMricG5N00T6E0VLuoIFbH5c3eo6PLkWhOCqDvAFJMjnoD
         b7tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750945996; x=1751550796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5YAHutT4ePwos7SGd89WO7WQovvxHxOM8YWaXJlHriw=;
        b=LP3fTqOyWPtHTpKybeWYQHRsGFUBbXuQgPem+eiJE9srST8y0srUzxtWpRGK7fon+Z
         pcxj0lBIXQOnrq0WSrFZ7o8Pr79y172g3NUxn0j7uA4HRGq6wAJbk2gcnOGx+b0KcfuH
         xUieGflB/u0cuI/nRhGn0Rc2DOOble4KUvkkultR5yUhWPBWFsz3lSZZ6YPU+SQ777vm
         ScPRik8jQ9dYaIF8/sEUtVFXnN+YhvVSsuBqTkmWwkz+quD86UURyYyrByB4nm1Lgt4U
         Y3oR0ML5yszHhbZFqBeANmcg4wPgD0usU+Ko1P/2NnqKVUlNQTzkJM+v32p4CdEsVfBz
         mbRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945996; x=1751550796;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5YAHutT4ePwos7SGd89WO7WQovvxHxOM8YWaXJlHriw=;
        b=v3POjLIr4wWiSOgIRkxCr0JTucXu4iwfR7AQi/Ygf6vx25eSed/4i1XeTJ8M22hQ4j
         +CEb7J7kpt+R/yNOlxITkuTwqeum9tmZzdoARCim16J4U7UnhC5GnSKNkqHI34YX65bb
         5SLCgB80wNol49E87uuqA6R1l9fiF2EwXi9n7xJHnZ06aFBguU9PiGnzAHHog4kKQU3y
         GpAv8jXTIdUHWkCXyx2S0pG1p4Loq88IRE67PXGXO5LfxvzOJi8hg2PAG2bZHzAPgQtg
         2KuzEWJX8GuAmFyFzOCON2GpuwtFwu1sxObBljrxIzi/hBGiiee2nxzDDTnPmb6IcrQo
         oyvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVz4ktksTxjIaiQdXym/VApGiI4Im5BsyQQDwJoyXjK7XUaiSSlK9K8nNpeQPDq0hV2JU7Bsg==@lfdr.de
X-Gm-Message-State: AOJu0YwgewVNGR/xKJ+cqsQyaTaUN1eTs2njQBcuYdD0/Tr9AONpELBY
	EipBhNBn+nuiB30bIV2yJqw5ZxKBkSWOwlAhTRjkS2XvWQiF43mw6TzM
X-Google-Smtp-Source: AGHT+IG0AI5ivRLcQIlftifh3YALPnTduI2Y7YxXSrhe1Hd05nHGoRsZ6Ekf2Bso85W6FHNPmjqtIA==
X-Received: by 2002:a05:6512:b86:b0:553:2fec:b139 with SMTP id 2adb3069b0e04-554fdce7632mr2315637e87.24.1750945996023;
        Thu, 26 Jun 2025 06:53:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcmgMVs4sGjwOXXp7FcNx4OhK/ioHJwPN0cCY/gv7A75g==
Received: by 2002:a05:6512:6088:b0:553:67a9:4aa1 with SMTP id
 2adb3069b0e04-55502e0649els345114e87.1.-pod-prod-09-eu; Thu, 26 Jun 2025
 06:53:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXltXDeXnEsIkAgsLf7AoMETI2HKcZH1xbQLG0w3lTDWrhIV5Vc/c6e4zywQP23WrGxBzeGGnmm6M=@googlegroups.com
X-Received: by 2002:a05:6512:3a8c:b0:553:d12f:9cb3 with SMTP id 2adb3069b0e04-554fdcd7112mr2258931e87.15.1750945992686;
        Thu, 26 Jun 2025 06:53:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945992; cv=none;
        d=google.com; s=arc-20240605;
        b=iom1vQ/jk5IAx0kDPDx/rd7RCiDHuqAP01JodOt8/JGq2wY/AE6VhupfNlx3X+hfH7
         0AngkqXKsf2l+NEZfDEs8OQQK6ejl5ewIZqr/LLXBIVasFHGxrbv21SLQliHkZxZWyUP
         wDxDxFVwZy/GY+ZKu9t8Q6DpSm3sSpzb4REyUayDw3w7lCGVclusSAxiy/LbJOxO9gIW
         a8cJ2oybLztBT6QuGqQyhK/cXn1UVNjOg2tBn8iR6ZmFffcCB7fW9LePHx1QuhDLqoKj
         bgTL6dUnRTowfQ2FOlI3HOtJOd9+nyMnzM2YRoyFNuMFoNLuV8FtS5rcvlesoRBtM33B
         +HCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zlpUNKK3G9db+EdwcDWwBbzYx+1GRPZcFPyn0Q/NIe0=;
        fh=C2efY3fLMo3+fe1oF0PvZx7Rslm7N+nTyKRHwXHDdtQ=;
        b=i9bwhke4qLb6ukRigYUq9giKFwvpCr+LBDCZf6Ds+5q2bM9fLyzZw6U/jFOd7QWmUP
         FMe7JIzSdIu1epJ0O27rTX7oWzQbQx43xyuNwTJw1Kd6e9xS49J6RH+3meXQsk5IbkiX
         21GPnSiFrGk8wR6BxL4oz8KoLhjAZL15KGg0kjY0WkQMT42bbcmL45wzzNi8Dggp6F+v
         +QkQ4+Dv4RzbtluQkHPTduz20H1Iy7xiUPXRyqxkCKmcJnetEDSKr6XytntsoFNp4lco
         m8iZtQa+PKNjYXW/rfy/07u+aSHsuNN0F9A0HOzt5MVWOk4HqXjbi/AAq4TJkYLcT86Q
         KVpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=brvWxeWW;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b2b97d2si1160e87.10.2025.06.26.06.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:53:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-32b7113ed6bso10383771fa.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:53:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX+mf4qiK3b1aX9nF8AbaJJiyaUn54CYTrFgEWjdRH47hpdCQcCG2xTpelyxGu8AOU2oabG8ehfaB0=@googlegroups.com
X-Gm-Gg: ASbGncv3dtgjnaPDNuRSzqLLns7e1HzyCdLfSuhrvVj+FW7elk6VkYdWVArM8hKxlAE
	W0IwK3AI+FuMFMtDZj0LJ5ka0+46zChpkkYVSBNXN5sPyb5x/ASf8a/ERX0snE0OA1a2sfgFAKj
	MkId/WMGF1tHsP70/2JcmjI8LhtlJ/kP0or3grj2scxg==
X-Received: by 2002:a05:651c:f0b:b0:32b:7284:88 with SMTP id
 38308e7fff4ca-32cc6497155mr12421921fa.7.1750945991880; Thu, 26 Jun 2025
 06:53:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250625095224.118679-1-snovitoll@gmail.com> <20250625095224.118679-6-snovitoll@gmail.com>
 <20250626132943.GJ1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250626132943.GJ1613200@noisy.programming.kicks-ass.net>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Thu, 26 Jun 2025 18:52:53 +0500
X-Gm-Features: Ac12FXynXHan9NKB65s06xjAcLer_ajNs_gE1LBlTEt_pC6nGG6YTexJKgab6gM
Message-ID: <CACzwLxj3WLTK+A7YLcYvg5ZwvQdvoBuZL3bmEF+ELinFZgU=Pg@mail.gmail.com>
Subject: Re: [PATCH 5/9] kasan/loongarch: call kasan_init_generic in kasan_init
To: Peter Zijlstra <peterz@infradead.org>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	christophe.leroy@csgroup.eu, hca@linux.ibm.com, gor@linux.ibm.com, 
	agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	dave.hansen@linux.intel.com, luto@kernel.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, hpa@zytor.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, akpm@linux-foundation.org, 
	guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org, 
	tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com, 
	kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=brvWxeWW;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Jun 26, 2025 at 6:29=E2=80=AFPM Peter Zijlstra <peterz@infradead.or=
g> wrote:
>
> On Wed, Jun 25, 2025 at 02:52:20PM +0500, Sabyrzhan Tasbolatov wrote:
> > Call kasan_init_generic() which enables the static flag
> > to mark generic KASAN initialized, otherwise it's an inline stub.
> >
> > Replace `kasan_arch_is_ready` with `kasan_enabled`.
> > Delete the flag `kasan_early_stage` in favor of the global static key
> > enabled via kasan_enabled().
> >
> > printk banner is printed earlier right where `kasan_early_stage`
> > was flipped, just to keep the same flow.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> >  arch/loongarch/include/asm/kasan.h | 7 -------
> >  arch/loongarch/mm/kasan_init.c     | 7 ++-----
> >  2 files changed, 2 insertions(+), 12 deletions(-)
> >
> > diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/includ=
e/asm/kasan.h
> > index 7f52bd31b9d..b0b74871257 100644
> > --- a/arch/loongarch/include/asm/kasan.h
> > +++ b/arch/loongarch/include/asm/kasan.h
> > @@ -66,7 +66,6 @@
> >  #define XKPRANGE_WC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKPRANGE_WC=
_KASAN_OFFSET)
> >  #define XKVRANGE_VC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKVRANGE_VC=
_KASAN_OFFSET)
> >
> > -extern bool kasan_early_stage;
> >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >
> >  #define kasan_mem_to_shadow kasan_mem_to_shadow
> > @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
> >  #define kasan_shadow_to_mem kasan_shadow_to_mem
> >  const void *kasan_shadow_to_mem(const void *shadow_addr);
> >
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -     return !kasan_early_stage;
> > -}
> > -
> >  #define addr_has_metadata addr_has_metadata
> >  static __always_inline bool addr_has_metadata(const void *addr)
> >  {
> > diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_i=
nit.c
> > index d2681272d8f..cf8315f9119 100644
> > --- a/arch/loongarch/mm/kasan_init.c
> > +++ b/arch/loongarch/mm/kasan_init.c
> > @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata _=
_aligned(PAGE_SIZE);
> >  #define __pte_none(early, pte) (early ? pte_none(pte) : \
> >  ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_sha=
dow_page)))
> >
> > -bool kasan_early_stage =3D true;
> > -
> >  void *kasan_mem_to_shadow(const void *addr)
> >  {
> > -     if (!kasan_arch_is_ready()) {
> > +     if (!kasan_enabled()) {
> >               return (void *)(kasan_early_shadow_page);
> >       } else {
> >               unsigned long maddr =3D (unsigned long)addr;
> > @@ -298,7 +296,7 @@ void __init kasan_init(void)
> >       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_S=
TART),
> >                                       kasan_mem_to_shadow((void *)KFENC=
E_AREA_END));
> >
> > -     kasan_early_stage =3D false;
> > +     kasan_init_generic();
> >
> >       /* Populate the linear mapping */
> >       for_each_mem_range(i, &pa_start, &pa_end) {
> > @@ -329,5 +327,4 @@ void __init kasan_init(void)
> >
> >       /* At this point kasan is fully initialized. Enable error message=
s */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized.\n");
> >  }
>
> This one is weird because its the only arch that does things after
> marking early_state false.
>
> Is that really correct, or should kasan_init_generic() be last, like all
> the other architectures?

It really differs from other arch kasan_init(). I can't verify that
kasan_init_generic()
can be placed at the end of kasan_init() because right after
switching the KASAN flag, there's kasan_enabled() check in
kasan_mem_to_shadow().

In arch/loongarch/mm/kasan_init.c:

void *kasan_mem_to_shadow(const void *addr)
{
        if (!kasan_enabled()) {
                return (void *)(kasan_early_shadow_page);
        } else {
...
}

void __init kasan_init(void)
{
...
        kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_STA=
RT),
        kasan_mem_to_shadow((void *)KFENCE_AREA_END));

        kasan_init_generic();

        /* Populate the linear mapping */
        for_each_mem_range(i, &pa_start, &pa_end) {
....
        kasan_map_populate((unsigned long)kasan_mem_to_shadow(start),
}

>
> Also, please move init_task.kasan_depth =3D 0 into the generic thing.
> ARM64 might have fooled you with the wrapper function, but they all do
> this right before that pr_info you're taking out.

Please check "[PATCH 1/9] kasan: unify static kasan_flag_enabled across mod=
es",
where I've replied to Christophe:
https://lore.kernel.org/all/CACzwLxj3KWdy-mBu-te1OFf2FZ8eTp5CieYswF5NVY4qPW=
D93Q@mail.gmail.com/

I can try to put `init_task.kasan_depth =3D 0;` in kasan_init_generic(),
but in ARM64 kasan_init() we'll still need to have this line for
HW_TAGS, SW_TAGS mode.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxj3WLTK%2BA7YLcYvg5ZwvQdvoBuZL3bmEF%2BELinFZgU%3DPg%40mail.gmail.com.
