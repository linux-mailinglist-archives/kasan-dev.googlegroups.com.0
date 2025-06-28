Return-Path: <kasan-dev+bncBDAOJ6534YNBBUW277BAMGQEESPAW2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D1BAEC75F
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 15:25:43 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-553bb00ae24sf2026861e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 06:25:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751117140; cv=pass;
        d=google.com; s=arc-20240605;
        b=MWTE9WcdMqK+zV1P7pImS4Lm9ecwXlRvjO3sTM8zYrSH2/6sLZC6dUeNjr+CoN57zN
         ltHC7bUcH5uOhCHnKWXlQA0kIg1FEsA8WmrvEefO5yWyO6H0CrIXNEjBwkmTSpnCzJGj
         yathbQtiLvFxhFAo7rEYSPyxMZKJs7r/9ukn0Xu7+Splh6fro1xFLlgz9JSmhOusrlpn
         hDdvegiuB0P+qs65J/FsjAYOxLL+B2kBXBSs3dmNB2t1ggP8nDcxiuBux3U4H5cpgHTd
         PcAxH79ZBPnwisJl+hvRdV5ngwbMeE2VaeyE3EInMBfuKQAhbxdmmhIav7Ut0+vY3kr8
         CoeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vIDiH66+4cRqqpLXaOAAC4cnbLiVUX4xAfMKlafeMb4=;
        fh=4pU4B97e3V4qCDOWUB4ObNk5i1P324joRlsnkH2QUE0=;
        b=jYOF8b5vQasogU3X+HXsxiufzxw1MRVqb+qH0IVUKI9py20DF7QhBvfks0G2tS9hKI
         AePnDJVDyvGLFaKTqUYe0gG9rwkYCw68IMqTPlhJJT0rWBQZJE7E6u0IbL7KyYkmF+HR
         kRtPg6NX4bKXt3AEmmyRIhfa8RrgLZEM5UzC40+GLqIU+ZYkUZYoGYLC32fvrlCIOhyw
         NpkiRcbtDMeN5kce/i9r6n+iDgpTK8ehSS2BPu9gVGv/uK5XEIpWqQyqPLWCBxJLZLwz
         YtiS0FXen1mku1WvNwKSqqftf3bBvI3XW+qTkGnI5V5S5j1saIuydUNFguVIuXX4yvUO
         vbDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gZ9Ae8FI;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751117140; x=1751721940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vIDiH66+4cRqqpLXaOAAC4cnbLiVUX4xAfMKlafeMb4=;
        b=EEC51GsRTAk4N2y+OrzRHdiTsOOVakqoamYi45dixUPc9Vh29cbdLzuZsGGsmdqNN7
         AJZOhhbJMVFsapeBfSRwbD0/6Ueq93S0KsEIDBS7e4TqQV99r8szYPddPDoC+DVPXOtR
         4GKnXZfwdNIWH5/WUyFKGYzcfFEmV7F2mg66cM9N9XCiSjXfXZU8uE3jdYx4gKa4S/k+
         jGcOzPNobbXJNmllO+f8Bki8AC3RhCuS8ck43GaRdyfNfmUl+8J37mg9nXnJ7ar3FeKM
         lp45adVAcJixFy5SHugCODPyppMacnxmzm5H6HA0Bja/UCaD5cR/J8z9NgjKWeGvl1fr
         pPiA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751117140; x=1751721940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vIDiH66+4cRqqpLXaOAAC4cnbLiVUX4xAfMKlafeMb4=;
        b=NTksC8IZEX5eVSsXir/0/fRfAgsZkEHfWe1WTNK3hbay5qQNQqQfCCaDsfsxVp8qa0
         pZrTe4M0+umuUGF/7BWiVyN3ObOUvnN/Wm8SlTxcdRvDg6LtCKWOILAdAg3+JNLFZUki
         iP5wodVE/IIb/mxIt3GGxCE6r8NSrMh8nJ34VheYBlevWQclN6ohQNm29C/j9cAOWBvg
         +Y6rYlh0NqNlOFnny2G/VwLiUuJjRHw/hN3l9wQWYxqLlbgQUO3SxZZWtm2Z2NTlxUsQ
         60cN6S4Srwu8UszZdyrZk+6S+W16hr5wOUy0w/wxThBzEXkKWNQH9F71mejrr0s2JkQ/
         6h/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751117140; x=1751721940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vIDiH66+4cRqqpLXaOAAC4cnbLiVUX4xAfMKlafeMb4=;
        b=emR/1svXYOT0Must1ZFmfAANxv64PLi+mtqnUhw/dX7fJW3CHWxTov9Oe9+8FbKMBg
         yrKjlZezLbDit2DMAWrubhtvAWUEnqi/gMxhyPoyH1RMbtRDn3R5L01EF01v8Up5iLuN
         m3ZyIa+UMK9KDJ+DIA7hjMkVYozjYky+54xE11kWyA6zBuuXJHoP207l3rZame6YOCZw
         oXsIdZOgG4muClpJk6g+nVQIZCHLzwTY0FMJm9Z4BxS926TGHoBeoJBjM1eRpZGX00DX
         1PjgFtRFNPyscbxfYuWnBZQXY7z/bg2PC+6opLGg3z3kx/sre9kSF2H2FTW9I3vmGO0w
         gfNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfin7e5bp2opYdwF2Eo7wksNAAXzs7H4wyYDkJ0sLcqBUEdJRZgs0bw6yUk/BovYmUqkWMzQ==@lfdr.de
X-Gm-Message-State: AOJu0YwWdOpaCluk2eG53bjq7OFm6eNevf+4HBHdm1HZelxFXTGC/hd3
	zau979nCwIeeaNaVXqs9/y+7hsJhyFncPM0E232YHmFPrnc2bNpS2WK1
X-Google-Smtp-Source: AGHT+IFkaFX1KhZzptsozBCC6b+1JwyW9oNUboDR9CaeToDODx8IPK8k44ZhsSW5aFg/EmhfVIyEaQ==
X-Received: by 2002:a05:6512:2214:b0:553:2bb2:7890 with SMTP id 2adb3069b0e04-5550b838da2mr2248305e87.25.1751117139622;
        Sat, 28 Jun 2025 06:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeXtjNsaRtzemc4HM2HTVhWn29j/Q9zJzqbW4qSAsibeg==
Received: by 2002:a05:6512:114c:b0:553:ca9e:dc63 with SMTP id
 2adb3069b0e04-55502c9613bls984475e87.0.-pod-prod-03-eu; Sat, 28 Jun 2025
 06:25:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUivuIB0k7uQWn0Qnr8g6VGV1O+hZPiOc3CQ5u83iaujifQ1zS32nS7rf+xEt79bbMpOfhJcX4A3p4=@googlegroups.com
X-Received: by 2002:a05:6512:ea5:b0:553:a469:3fed with SMTP id 2adb3069b0e04-5550b7e7b6fmr2244811e87.11.1751117135884;
        Sat, 28 Jun 2025 06:25:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751117135; cv=none;
        d=google.com; s=arc-20240605;
        b=I64JR5VnMHul70tnoT6cmZ3G3AzsOsOkLruJAPCoUlfKpzIxvUGlRM2F20Lee2ddPm
         EKpu58oMa1tqz7/RjGyxeQcaGLT/P05LxBsHZ8tOVpF+hqhuChbHJcVT6pM6e5SzVcjy
         OZFNzbOcm8PRIaO7JlrWAR6Gm61uZfuAItkLiwMoqLRZKxBAAtdyipgJsK/7Y5r3zDrJ
         NGBlS/S4+muC54NBC1NmGSMAd2lKW6AWebli+nOhmPfuJC5x0apf+F2UhHoHai4cW6qv
         ybi1p41IpzGdBSjyQOMcWhpl+OsiKyhcKFz1QoOLU1A3tscUM20U+35Fxh/5b5t4wScJ
         Xx/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=L9hXJHuBvyYPVmVbLpoMFR4H07JOmA06RF+Wl4Z/7RE=;
        fh=xgXINoQ33ad+SU6p5f+FBSE1kBeHwq/sleJpJ1JjJLQ=;
        b=Uwd3Q8eGPEV+LpgcKPhY2M2maYV9LcrcGGOMjTG/LDSEVT3oe2Chcc+OUjZokGMICZ
         K5xpJVlZ1aKpKG2i2HU2nuqVotsup8rifA8Fj0ustiQbwdLyBnfu320+AN+IyhtXjyya
         8lkyBwABnCGeko9qr/gPq85zmEyDbQHeZohZvo1hKUAhwax/75a+zmeCblNvq7Bd/AFV
         wugKX8r+2RUkGpCf2PFKfhnUbclTpqInBkgQvgtaG14VzVus7QarD5VhrwKQakYNYW8W
         llk6zRjVdpvpF9fpZgKOF+ggfzLfugby/kOhBqfQbvJC8CfUyHmlbrC31kjQwXEQweDX
         nHHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gZ9Ae8FI;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b2b97d2si315634e87.10.2025.06.28.06.25.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 28 Jun 2025 06:25:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-555163cd09aso268435e87.3
        for <kasan-dev@googlegroups.com>; Sat, 28 Jun 2025 06:25:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWHcs2UIw/VykUVMJ0p1jrYQlWd3yMLKQWWV/evbuek1iWi4MiVdg5AR6oUGOpIDlyW1v6NtOAfvJ0=@googlegroups.com
X-Gm-Gg: ASbGncsm8WdoC0PlS+P8CIZfaM5PmAWz5Mwzx5tjsJlzZkJ5atlFRuxv2pExjaFZDQn
	dJhFLk6ImM+7JC0J8odUZT+4dufol0xuHH1Yxzu9TOrs0z16Maq46YuNBHqdNkthUmnd0ZXjYGe
	A9xAFrFhOv1fHkBNZdm/tvC30ukCgVZN31Gir3WJgbuXvMdOg=
X-Received: by 2002:a05:6512:401e:b0:553:d1b0:1f1f with SMTP id
 2adb3069b0e04-5550b817bf9mr2031982e87.21.1751117135042; Sat, 28 Jun 2025
 06:25:35 -0700 (PDT)
MIME-Version: 1.0
References: <20250626153147.145312-1-snovitoll@gmail.com> <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
In-Reply-To: <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Sat, 28 Jun 2025 18:25:17 +0500
X-Gm-Features: Ac12FXz_1yZEfUGAygYOxkSS_g1GpWf3Y2t1PdPyYRlgb0h3dTvUyL8mVDVK8Qk
Message-ID: <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with kasan_enabled
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, linux@armlinux.org.uk, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, palmer@dabbelt.com, 
	aou@eecs.berkeley.edu, alex@ghiti.fr, hca@linux.ibm.com, gor@linux.ibm.com, 
	agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org, 
	hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, nathan@kernel.org, nick.desaulniers+lkml@gmail.com, 
	morbo@google.com, justinstitt@google.com, arnd@arndb.de, rppt@kernel.org, 
	geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com, 
	tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gZ9Ae8FI;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12f
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

On Sat, Jun 28, 2025 at 3:57=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Thu, Jun 26, 2025 at 5:32=E2=80=AFPM Sabyrzhan Tasbolatov
> <snovitoll@gmail.com> wrote:
> >
> > This patch series unifies the kasan_arch_is_ready() and kasan_enabled()
> > interfaces by extending the existing kasan_enabled() infrastructure to
> > work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).
> >
> > Currently, kasan_enabled() only works for HW_TAGS mode using a static k=
ey,
> > while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-time
> > constant) or rely on architecture-specific kasan_arch_is_ready()
> > implementations with custom static keys and global variables.
> >
> > This leads to:
> > - Code duplication across architectures
> > - Inconsistent runtime behavior between KASAN modes
> > - Architecture-specific readiness tracking
> >
> > After this series:
> > - All KASAN modes use the same kasan_flag_enabled static key
> > - Consistent runtime enable/disable behavior across modes
> > - Simplified architecture code with unified kasan_init_generic() calls
> > - Elimination of arch specific kasan_arch_is_ready() implementations
> > - Unified vmalloc integration using kasan_enabled() checks
> >
> > This addresses the bugzilla issue [1] about making
> > kasan_flag_enabled and kasan_enabled() work for Generic mode,
> > and extends it to provide true unification across all modes.
> >
> > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>
> Hi Sabyrzhan,
>
> Thank you for working on this!
>
> One aspect that is missing from the patches is moving the
> kasan_arch_is_ready() calls into the include/linux/kasan.h (this is
> not explicitly mentioned in the issue, but this is what the "adding
> __wrappers" part is about).
>
> Another thing that needs careful consideration is whether it's
> possible to combine kasan_arch_is_ready() and kasan_enabled() into the
> same check logically at all. There's one issue mentioned in [1]:

Hello,
I've removed kasan_arch_is_ready() at all in this series:
[PATCH v2 11/11] kasan: replace kasan_arch_is_ready with kasan_enabled

Is it not what's expected by unification?

>
> > In kasan_cache_create() we unconditionally allocate a metadata buffer,
> > but the kasan_init_slab_obj() call to initialise it is guarded by
> > kasan_enabled(). But later parts of the code only check the presence of
> > the buffer before using it, so bad things happen if kasan_enabled()
> > later turns on (I was getting some error about invalid lock state).
>
> And there might be other callbacks that should be executed even before
> kasan_init_...() completes. But then for the HW_TAGS mode, if
> kasan_enabled() is off, then we don't want to execute any callbacks.
>
> So maybe we do actually need a separate static key for
> kasan_arch_is_ready(). But even if so, it still makes sense to move
> kasan_arch_is_ready() into the __wrappers for the affected callbacks.
>
> Thanks!
>
> [1] https://lore.kernel.org/linux-mm/CA+fCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0=
EA8RAtyr-KgkHdg@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x%2ByjSA%40mail.gmail.com.
