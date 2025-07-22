Return-Path: <kasan-dev+bncBDAOJ6534YNBBLNN77BQMGQE3I7VRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F357B0E360
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 20:21:35 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45600d19a2asf49334635e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 11:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753208494; cv=pass;
        d=google.com; s=arc-20240605;
        b=ly+QZvnQo3GLfDuGAeGjGOJRVhaa2Di1UxDvfsN+UJxMuPMJTeSHHcg7PwVJTR8gyp
         UkHRX+usvKbmwV9P/YwEd405ALBivL2JAqp/PngPEpbtBDdLiv+q4xoRG0saKMMtCF8C
         neKBFXtU+ueKNqcdcihfviJenxgd3KMc7H8g0hRlCl9Q4cNYJj8mUvriqu5LmrT6khpL
         T6Q2A45lGBPcVualDX/tQbSQV7Y+LqgjG9jR1QNGs2paU6upeJ+NNvWk5IEcRvZgn8u+
         +E/fm0Tk0nhmJm6BvWMuszdZkPfLnLRYyXGQqCSJDtWk9vZRhhB+I0Ql4tlzZHGAih0I
         05cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=X3UYXc2fc2emVNokfjBvPg8UA/Y7aowLyCb69PR2LMg=;
        fh=jUm/x3Of0ZUP/JxgutCAGb7ZloWMDRx902IOQnbLgeA=;
        b=SLbVgjOVcF0/UOe7ch4NWEhgOaLLR3gvakyHwyG1wqdSLq//61w7vdFDvWZ6kV1wLd
         pgx40+VCzTO8lYnSHWmTP9Koj8048sLCEaFwC6ijzj3Ot8GavPq77N3Bt2AH8s3ju843
         pFxcL89qcjGueMq7inCo6V/ym7Y0sOAbEZCwquuzdclfF4YzHTuMKxY8SHIIn2dX71Jc
         lP7QJdaan/4U/IQRtJgP966UGpefXOsFonPxCUpo3chroawE/pRhJX+QNJnwgZF33usW
         OwXMM1rS8QEKrb9cj0x9A8mw/vPpfoqV6SN/AyJYm3xSWMZhnThGLJ6HLCIcoOP2rFNS
         H58w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WL3nrrub;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753208494; x=1753813294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X3UYXc2fc2emVNokfjBvPg8UA/Y7aowLyCb69PR2LMg=;
        b=o0QoTQ5PqLph1kM9lhIIz4IuXKe2ITuS2OuiRHvb+0ztlJYodnC2RHsCg9uGwWuZ5k
         K7Wetzy7zxWASkzf9VwMyGKJxqRESPo43lto+6gmgpi8hV9wRcjbJPKiwruAtzkIIqVi
         17oc2asm0dHSoji7f8WSUFaLvS72Krf4sVkMwOXIUYxjiRjQywqIUlzwNE0i6+Fh+pP+
         r1P3+SJW5s3qO8Ob0ASyOdEove6faquYYLPL/Ucd6BtGquwnrjiKwNn6R8lkTNgTC5hn
         yGPyZDtg3WOakCe75asOXiyrDTloP0JFXe7lkkex1y7s9UjZ7TnLz6Zq2EBjGoL5hgML
         cC0g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753208494; x=1753813294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=X3UYXc2fc2emVNokfjBvPg8UA/Y7aowLyCb69PR2LMg=;
        b=AJRKPrYUHvaA1z5up+Jdm0V458FayeZ0cZQApdRF8zvGZxvKDhNKksoxWu7X8Gf/9w
         PdMov8DSJG4f3Td3fMNa8+209Qzen0ioXDp65FXJyfaXnUX9I5LVr+8T4HpRZx0iw8su
         NYBHynPjUz4xUNcZy6LZek8E7Xaeiq7Kx3AF8Rav1GDXIIfgb9nZX9Q3QqkWaGd5LuXX
         1JRqvv/AmAvkBEiyno7KqcfOcT5sQ+XoKj8i3ocBA2wAF3BrQNq91SKAbnX+bGqqK37G
         7h0l2QBpd5NLrYl6OTJjVFxIQpUw1cHn6QF8/VF2TJRctVV8rs1F8yUgA2uKy/WUsBeH
         mtcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753208494; x=1753813294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X3UYXc2fc2emVNokfjBvPg8UA/Y7aowLyCb69PR2LMg=;
        b=SQuJMdMfwIv149XScN8upNcY1Jh32Cc5uTi9LfPtOQgADu6CFeqj82xpKg/LmSiWJ+
         rUrEACsZbENxEtbKvz7YRIrp7lnFyZW96XSLw9/2ODyFa63k9OyTI36bTLQdawvv2RH7
         sKEyVXuEpBLPi9ZMnZ3kOultK2070aK/qPFlVe1wNtUpjWSF/hHUQJsmz1MYxRfxc6e3
         o86EGDMKJkd4RifOBhoELO89R1JEP39Zvm2I+IcrxVbGa7/gBgerBCLvTN4kcyat24ti
         XGhZX5ZcdgaHL/ooivi7Ok878DKgmOsUmWz48p1mbqn6pM8o1I6CQ3cUdxmTecm6fBDX
         8KaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbT45tgSUzvdIcR0rT7YxUFb3iyMC0KK84gApcwJcPA+Tazoni8sKw45oG99Bnh0BITNDIBw==@lfdr.de
X-Gm-Message-State: AOJu0YxXxtBjs3rSMrAduYrSZhtIJsrrj9Cq4O3ZqvQMMkS+vpYpmDva
	3nDkgmtg6oGdWTWnrd47D3zmoB3V3R6ULCJEJ92s2SrnlFxBS3xUoK9e
X-Google-Smtp-Source: AGHT+IHybagz0Le/t9eqprBMDYoXgAuINyCBNHcBz8x5QELirvE5jEP2fQndo1ucFS8Z8liEi1DL4A==
X-Received: by 2002:a05:600c:1c10:b0:456:1f09:6846 with SMTP id 5b1f17b1804b1-4562e3771e4mr200886395e9.25.1753208494291;
        Tue, 22 Jul 2025 11:21:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd0ELj2+O4X/gDlonyAyBvRmrOo1M0+FtotjTaxUi/Lmw==
Received: by 2002:a05:600c:8b2b:b0:456:133f:8c4a with SMTP id
 5b1f17b1804b1-456340bf3c8ls29367825e9.0.-pod-prod-07-eu; Tue, 22 Jul 2025
 11:21:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpDqCh+Dbsx5IfN9KH+42owUtLpot1PCTQ4ffeFQ0WZp1uuFB2XG+w4ByvsS/WseUenFoKzFJ3L4o=@googlegroups.com
X-Received: by 2002:a05:600c:3f09:b0:456:1dd2:4e3a with SMTP id 5b1f17b1804b1-4562e32e292mr233767005e9.3.1753208491640;
        Tue, 22 Jul 2025 11:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753208491; cv=none;
        d=google.com; s=arc-20240605;
        b=VVtyQ9PI+mBYb7nLD08VKjcMOP3G6WqI/rdlx36A/0YYHAe2nlXJh2UJUuk+sFc71Z
         77oANyQDVg/UkSHidlcZVb9OXG0UGnkUhB8Qchm7+DLObomje4tlBB6HDVCPo85s4JD4
         gPjutCVef4Uso/FUJkRP4J1IXpo4UhfmTXCgbG2cPi6ttfp1AdoWvmj08JXQt97IRxca
         Ir8yLGBWFFPVasVCqwKNHickHYFz49ptJXk9A4kIQ6Cbr9GVwqC+DTfL2wKSz0fLttv5
         5B9sMS7LcOy6Kevs+NoP2/qsVIz5SkBF9r+jQUJi5mXDTQBbxdesOxwPUm2yQB76FrhL
         w5ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=s1bfHAcPl/XMz8xDguK3teTl09r5v0kLVciBst2DtbI=;
        fh=VoS9HFHslTBIRNTRrUxKulx8zkNg12sAx0aVVzvxDiQ=;
        b=WBOS5+PbMrTSShZ9ibUETBz/r3+b1UszQdwF5awIBsBMqbC1ujU5y2Bl0kp94Q+Tu3
         QR3eyqx4r0agO8LgXbCOtnX9qzLqeLUHEcnHugXj+ShCFrjwSShwq2Bpzgq07UBrzLsN
         +BN3XtT4SIP9rD3NjIVg5dLOXhZGIJRHTrFakq101a2KqB9Zypn8F28xPIEpkJTC3XGH
         6dBk+7tzloxkYtj63jzOnYdi/2LQr3YdRj1iPLo+k6h0k3S5jYv6VMzWWPuuMbRyWUVe
         1h8dMjeOGo1yttUaVhL7AZc09nFTtbKSez61IZOb4myl1BeP+qmfUvtEwUTCrfyJHNV9
         3mOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WL3nrrub;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b61ca468b1si280515f8f.5.2025.07.22.11.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jul 2025 11:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-55a2604ebc1so5096785e87.0
        for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 11:21:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuQB4txcGeO53MDikh5NmFt7QccZzhVlP/bCMn5+Kls0GZX7vsULKQGNGlKVs0vrclztpOjGrAGts=@googlegroups.com
X-Gm-Gg: ASbGncuLIub6J3tmLcSNYC/NLHCNBWthKEJeiZrxQH7u5FeYWJIYyT6WQovAkjdQXjf
	Pow6nFmabK/m957d/yEepWQtj5rWjqUdes/RUIrCWUlqnRWjwrIcvoM3h+AI9Y91NcN+qlRCeTn
	teHfwFGtDkpV0Yvr/YthGSowFskaVkQRi8MhjO5i2T6Pqv53hTgb67+/Ktn5X6CVITBoI7rguVL
	O6kgos=
X-Received: by 2002:a05:6512:4021:b0:553:2190:fef8 with SMTP id
 2adb3069b0e04-55a513998a5mr31899e87.7.1753208490745; Tue, 22 Jul 2025
 11:21:30 -0700 (PDT)
MIME-Version: 1.0
References: <20250717142732.292822-1-snovitoll@gmail.com> <f10f3599-509d-4455-94a3-fcbeeffd8219@gmail.com>
In-Reply-To: <f10f3599-509d-4455-94a3-fcbeeffd8219@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 22 Jul 2025 23:21:13 +0500
X-Gm-Features: Ac12FXzOVMCIvnTEhZltt3TS4XKarYeDIkGkWcMAqG0GgJ62pPTw9Xni6fYiOgs
Message-ID: <CACzwLxjD0oXGGm2dkDdXjX0sxoNC2asQbjigkDWGCn48bitxSw@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] kasan: unify kasan_arch_is_ready() and remove
 arch-specific implementations
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WL3nrrub;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12b
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

On Tue, Jul 22, 2025 at 3:59=E2=80=AFAM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
>
>
> On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
>
> > =3D=3D=3D Testing with patches
> >
> > Testing in v3:
> >
> > - Compiled every affected arch with no errors:
> >
> > $ make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-st=
rip \
> >       OBJCOPY=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-read=
elf \
> >       HOSTCC=3Dclang HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld=
 \
> >       ARCH=3D$ARCH
> >
> > $ clang --version
> > ClangBuiltLinux clang version 19.1.4
> > Target: x86_64-unknown-linux-gnu
> > Thread model: posix
> >
> > - make ARCH=3Dum produces the warning during compiling:
> >       MODPOST Module.symvers
> >       WARNING: modpost: vmlinux: section mismatch in reference: \
> >               kasan_init+0x43 (section: .ltext) -> \
> >               kasan_init_generic (section: .init.text)
> >
> > AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
> > is placed in own section ".kasan_init", which calls kasan_init_generic(=
)
> > which is marked with "__init".
> >
> > - Booting via qemu-system- and running KUnit tests:
> >
> > * arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results=
.
> > * x86_64 (GENERIC): no regression, no errors
> >
>
> It would be interesting to see whether ARCH_DEFER_KASAN=3Dy arches work.
> These series add static key into __asan_load*()/_store*() which are calle=
d
> from everywhere, including the code patching static branches during the s=
witch.
>
> I have suspicion that the code patching static branches during static key=
 switch
> might not be prepared to the fact the current CPU might try to execute th=
is static
> branch in the middle of switch.

AFAIU, you're referring to this function in mm/kasan/generic.c:

static __always_inline bool check_region_inline(const void *addr,

      size_t size, bool write,

      unsigned long ret_ip)
{
        if (!kasan_shadow_initialized())
                return true;
...
}

and particularly, to architectures that selects ARCH_DEFER_KASAN=3Dy, which=
 are
loongarch, powerpc, um. So when these arch try to enable the static key:

1. static_branch_enable(&kasan_flag_enabled) called
2. Kernel patches code - changes jump instructions
3. Code patching involves memory writes
4. Memory writes can trigger any KASAN wrapper function
5. Wrapper calls kasan_shadow_initialized()
6. kasan_shadow_initialized() calls static_branch_likely(&kasan_flag_enable=
d)
7. This reads the static key being patched --- this is the potential issue?

The current runtime check is following in tis v3 patch series:

#ifdef CONFIG_ARCH_DEFER_KASAN
...
static __always_inline bool kasan_shadow_initialized(void)
{
        return static_branch_likely(&kasan_flag_enabled);
}
...
#endif

I wonder, if I should add some protection only for KASAN_GENERIC,
where check_region_inline() is called (or for all KASAN modes?):

#ifdef CONFIG_ARCH_DEFER_KASAN
...
static __always_inline bool kasan_shadow_initialized(void)
{
        /* Avoid recursion (?) during static key patching */
        if (static_key_count(&kasan_flag_enabled.key) < 0)
                return false;
        return static_branch_likely(&kasan_flag_enabled);
}
...
#endif

Please suggest where the issue is and if I understood the problem.
I might try to run QEMU on powerpc with KUnits to see if I see any logs.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxjD0oXGGm2dkDdXjX0sxoNC2asQbjigkDWGCn48bitxSw%40mail.gmail.com.
