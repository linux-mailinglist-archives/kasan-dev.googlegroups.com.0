Return-Path: <kasan-dev+bncBDW2JDUY5AORBXVSTPDQMGQEZIUBX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EF4BBC6B29
	for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 23:36:32 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-36a632165c9sf7073651fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 14:36:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759959392; cv=pass;
        d=google.com; s=arc-20240605;
        b=CV1RXGPn+wYpO2LJFSbcxdiWhxhUVoGvqXI9CFwq2yy0u7pxAqcafvltun7t9itm78
         kMeVsFDgc8dES2nhfQMoKFhc+jhfTYZevPTvCgtKUIT12igbAH5G/RJcHCHu0SWhyMac
         MghVnfFCyrRhZPPMD/N9Y/WkK/dKgdvqAv3gBMlvm9HJTW5XJ2voIVF46fwG+Vwubh9M
         sfStOGu0O/OBjS090dLFskMo8KEJ3CBkaQDD3Xwklyryq8aFsg81I5aEYOfJ/XcDweOf
         dlcXSmTjjPlOQjAqP328c7emhedfVBnWedPi9X30qEFg1P/QS/yfwdEZ34GGb+B3gyQP
         LtUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=C/NraLvmLGH1SIqafu1ifbN21yMZqQKaO1lOLTsvhlo=;
        fh=5ZFa6ndMTGtqDwjLtX+6+l9LslXD6CWqivVe5N4EcMo=;
        b=i0Vftvn05Inpp4jn0sZjq2a3uSNqEthzJ2tLnR9MPboZ/5nVWa1fSXZzWhIKTIEYFq
         OeVy4yl0kt98LBliAn0iJAeUZLegkwDps8pm3sQn9jmElea3p7S2BahEOb+N2pLAFylz
         6xLnr8ahp2n+rixeIZLtGKALyESaK1VEjWfginQafcRM4BOhA+mOlx79NQqhvK3ieY0o
         eOdm4D2xo9mbOj5FYG0XKD0Nf0Izxpo3vJJ5CU2G5Gpg5HgenXSlWozHPOt0PfiIYovV
         Gg7dzXr96dINvR2NLT+w7wAp79Y0XpjRP6t0CjmstKWJcLm8ve52yImjzVx4A8oYjZsk
         7F3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WPEvHQrJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759959392; x=1760564192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C/NraLvmLGH1SIqafu1ifbN21yMZqQKaO1lOLTsvhlo=;
        b=ldtKvZxf1/zlUcTcbau+rwrxsj07x/ZBe9uc+BY2WRQ4yW6qNg+skWzgcimOzfF2K9
         mbe3rZ5Hg01OqYmBhKjV8eqs3jniOk7mjgMmvhKxGm+NqJ1sKJKguodGUL9gUvOYR7iI
         MWe4DlD1qlXMYQ7kFWeK6f9STJdiFtIqT5kA4AO3v7zIsTBWDW/o4PZycMkt2UR5cHic
         zMwQGmUSt7WOzLsM6IUpPu7gm8v+B/r0iTR6hqk+B8pPRXQ59/QfIja55L6/jmfxcSRF
         8AMgfIDT6L6seS5aJ00bu4atO45pVEFLm/O3NpF3jfqLlN3yxXtj5wYLdex4BZD3em2V
         5OLg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759959392; x=1760564192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C/NraLvmLGH1SIqafu1ifbN21yMZqQKaO1lOLTsvhlo=;
        b=kKkQxKvMF6BnRl5+/TqBpxOXUpRDh90QJlvcdFlBkl1UH5SW8bq34D9vtjH62uPMcm
         y1fekE6kWbIN56Nsc8jCRqkKaGD+pD7/L3fI9KF4yAHG4loRj90/QQ8NlSe1tXVFegiC
         Tz5+FGES7Blu1dRkpOx7mrvKFz29QKg5NufCPzFIL1BKJ+Pjws5uPO6Mf+jMLkTjGkJD
         f81eGfTScJfwCZRB1XOSQIpdjIBX4ZbC+Gvp0QWqk2iBUzBHJ+J5ADr4IUHLMCi5Aj/L
         6jHmxaeGZSqSRouVddZwIuYj3e95qfcpPSlytSBwGG/sNHLLOldat27cszTM5wIpROiM
         ifHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759959392; x=1760564192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C/NraLvmLGH1SIqafu1ifbN21yMZqQKaO1lOLTsvhlo=;
        b=RUtLY+hKypRaEs82aMWanmk5rhvabaR1XNb6npdcu4qYhCBfEOqwclELLrxOQW6D98
         dgGoTU7my9i48n1kMOHXWpyX5dJ9dJaHZy4rfz8W3F8pC90A3KWtI/QKwZgGkp1/9Ett
         uJpiO07tjvZvHTCZY+Qtuu76FUCyK1pnKROIXfoWt9QTlA2mcXpM8/kBevmcXXOxfDER
         grdratyjDak67nfCKXJIQ0F5Oi44en2brknJapDsL5eaySeMTOUx2d2ODBTsKFW7R+Sb
         pi+N0cz3A7gdIfmezKeIszmUeOZGft42ekPruaTlO2XNhjBUJOKM6CkZBpEDFfanIFFr
         KgNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbR/cFYmm7lBOXdLZ1VJBY5a4g3j3ACmxYUrDqUHSV2KnUJTRF94pQuTK3aWuFlFpLBHdJsw==@lfdr.de
X-Gm-Message-State: AOJu0YyE9c2XclNw3ZUavUO4Ra8tt1Q5jatdlcOdy/4xBiDamaJe5upj
	ynPf6xXAWHu/U8DgRBv1V3HYJmNmNJMrsyC//MVk6iWto+uF/6O/PdaH
X-Google-Smtp-Source: AGHT+IGYQ+B8oVyAk9rQ1Xs/Q+J7+H1az2m6OWwYJJj9YeNF8lp4eYZte20Zwp/2hW4tpMrwCMkzaw==
X-Received: by 2002:a2e:858d:0:b0:337:e0d9:69a0 with SMTP id 38308e7fff4ca-3760a58a767mr12884631fa.20.1759959391288;
        Wed, 08 Oct 2025 14:36:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4ae8C1jDd+py/Y/9qkD4aLMqIEob8pFzOvDOj0FFmfxQ=="
Received: by 2002:a05:651c:4384:10b0:372:94b2:759b with SMTP id
 38308e7fff4ca-3761ca17d91ls236821fa.2.-pod-prod-00-eu; Wed, 08 Oct 2025
 14:36:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUtcE3cw4RkUJtQi384uOeAhMLOzjL3iVgsksspy3Bnj7lsp26WnRdmyMazIyUNq0EuKBqrjoy4I8=@googlegroups.com
X-Received: by 2002:a05:651c:3608:b0:36c:b120:37b6 with SMTP id 38308e7fff4ca-3760a543562mr16116621fa.19.1759959388338;
        Wed, 08 Oct 2025 14:36:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759959388; cv=none;
        d=google.com; s=arc-20240605;
        b=QrU1OeFeTqkdI932aKd9S3KUE8dz4cQmMyARV1W8cB9CYFpEhEpYt8pqQS3aLEiox+
         bDMGBopNzKzccn/2l/5U9TmbE5N2LyEjGP9qm9zxdEmQioXqYhkjQj5SECkeXGtfr1Cx
         g42L3/zH0r6A5wggwp6gZyA/Bt/BwrHl/tEA8fhRmba3P+6QoLUOvBKcoNQXoEdDIHDm
         IVtb0BqtW5Kd4tZ5qeOoKghclvlsauM4u4uHfbUJdlg240eJjYEUmMqSHy1egmggeoeS
         6ZB3Picg2svPfoPzG58D91PXgF3IhZ3QfGqTLp8BRF7fgR5dzx8KLdMHnBrOloeku5dk
         3v/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FEmyrKTdVo56+b/Tyh73u1BP5jkBeN0eSir3I6ZA6yY=;
        fh=Ct4T6D21kHF3pegVxKPAjZ7y3qlu5zkasgOUCgtheGg=;
        b=BruSfJCtr7/dWVr89/ugsjbvkM7XUx0OWe+JiS9XTy9R3q25XqUWtW9Td7T6Cm4aCI
         yoPR2xjBXxNZhhHi5a75w8r2X6h85+5drN+190ewb8/7RYniM0Dx6aZdQTAx7/ePTBt5
         CJ/V/45fQ7iIBinJd0ZfOp9fZQt9WZz+WXNxnybeZK+nerz75E1qktVjGYIp8sxkXV14
         UYj0W8HsEAk+MD+5/wnPq48LFWnnKd+MfrFAVpJX6eCr7t1aSaQXprBqEwvELvfZmL1V
         zXVYARnGZ8Z1sFkT1gWahGhUDp77Y6uskiAO/pS8qiTO/om38nku0eprwrfCNqMGMu+4
         lV7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WPEvHQrJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-375f3abc3bdsi1624101fa.8.2025.10.08.14.36.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 14:36:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-3fc36b99e92so1107171f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 14:36:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOrEWyvY4mWUV9IJMidwNLEOJMXk6c0fzj4+JHStURoqe8bqwIepkYixMSGJXRTVhVS7z8Z0dmGts=@googlegroups.com
X-Gm-Gg: ASbGncvhxKgrYNI/J2YIe4uMkAC6QmruT5/7pBA5MFAJVuw2JglKvHulcT1oqMNSACH
	lE6O7f1AoZznnQZcivM/iFsmBMcOfdVH0+0eVrHgQcVHkbwLtFPkWI2/0c6a0Y0uuMhKNegDdmd
	k1bMhQ4mqFx6NNGtoSpYpaS79guloe8P449GQk8O24EsnO4oyKze0DeFQFIwXnjl8A4Bn0zAdz0
	W8fS/zNnY0ii1RKTyf7BPLjBGpaFqlM
X-Received: by 2002:a5d:64e8:0:b0:3e9:4fe4:2621 with SMTP id
 ffacd0b85a97d-42666aa6354mr3738354f8f.7.1759959387489; Wed, 08 Oct 2025
 14:36:27 -0700 (PDT)
MIME-Version: 1.0
References: <20251008210425.125021-3-ysk@kzalloc.com>
In-Reply-To: <20251008210425.125021-3-ysk@kzalloc.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 8 Oct 2025 23:36:16 +0200
X-Gm-Features: AS18NWDr7cACmDmTAFMFA6336Xs4RqGaLFCrqQxRq3mWW-FZjr-4oeDaD1dmdEM
Message-ID: <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
Subject: Re: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when
 KASAN_GENERIC is active
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	James Morse <james.morse@arm.com>, Yeoreum Yun <yeoreum.yun@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marc Zyngier <maz@kernel.org>, 
	Mark Brown <broonie@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WPEvHQrJ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Wed, Oct 8, 2025 at 11:13=E2=80=AFPM Yunseong Kim <ysk@kzalloc.com> wrot=
e:
>
> When a kernel built with CONFIG_KASAN_GENERIC=3Dy is booted on MTE-capabl=
e
> hardware, a kernel panic occurs early in the boot process. The crash
> happens when the CPU feature detection logic attempts to enable the Memor=
y
> Tagging Extension (MTE) via cpu_enable_mte().
>
> Because the kernel is instrumented by the software-only Generic KASAN,
> the code within cpu_enable_mte() itself is instrumented. This leads to
> a fatal memory access fault within KASAN's shadow memory region when
> the MTE initialization is attempted. Currently, the only workaround is
> to boot with the "arm64.nomte" kernel parameter.
>
> This bug was discovered during work on supporting the Debian debug kernel
> on the Arm v9.2 RADXA Orion O6 board:
>
>  https://salsa.debian.org/kernel-team/linux/-/merge_requests/1670
>
> Related kernel configs:
>
>  CONFIG_ARM64_AS_HAS_MTE=3Dy
>  CONFIG_ARM64_MTE=3Dy
>
>  CONFIG_KASAN_SHADOW_OFFSET=3D0xdfff800000000000
>  CONFIG_HAVE_ARCH_KASAN=3Dy
>  CONFIG_HAVE_ARCH_KASAN_SW_TAGS=3Dy
>  CONFIG_HAVE_ARCH_KASAN_HW_TAGS=3Dy
>  CONFIG_HAVE_ARCH_KASAN_VMALLOC=3Dy
>  CONFIG_CC_HAS_KASAN_GENERIC=3Dy
>  CONFIG_CC_HAS_KASAN_SW_TAGS=3Dy
>
>  CONFIG_KASAN=3Dy
>  CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=3Dy
>  CONFIG_KASAN_GENERIC=3Dy
>
> The panic log clearly shows the conflict:
>
> [    0.000000] kasan: KernelAddressSanitizer initialized (generic)
> [    0.000000] psci: probing for conduit method from ACPI.
> [    0.000000] psci: PSCIv1.1 detected in firmware.
> [    0.000000] psci: Using standard PSCI v0.2 function IDs
> [    0.000000] psci: Trusted OS migration not required
> [    0.000000] psci: SMC Calling Convention v1.2
> [    0.000000] percpu: Embedded 486 pages/cpu s1950104 r8192 d32360 u1990=
656
> [    0.000000] pcpu-alloc: s1950104 r8192 d32360 u1990656 alloc=3D486*409=
6
> [    0.000000] pcpu-alloc: [0] 00 [0] 01 [0] 02 [0] 03 [0] 04 [0] 05 [0] =
06 [0] 07
> [    0.000000] pcpu-alloc: [0] 08 [0] 09 [0] 10 [0] 11
> [    0.000000] Detected PIPT I-cache on CPU0
> [    0.000000] CPU features: detected: Address authentication (architecte=
d QARMA3 algorithm)
> [    0.000000] CPU features: detected: GICv3 CPU interface
> [    0.000000] CPU features: detected: HCRX_EL2 register
> [    0.000000] CPU features: detected: Virtualization Host Extensions
> [    0.000000] CPU features: detected: Memory Tagging Extension
> [    0.000000] CPU features: detected: Asymmetric MTE Tag Check Fault
> [    0.000000] CPU features: detected: Spectre-v4
> [    0.000000] CPU features: detected: Spectre-BHB
> [    0.000000] CPU features: detected: SSBS not fully self-synchronizing
> [    0.000000] Unable to handle kernel paging request at virtual address =
dfff800000000005
> [    0.000000] KASAN: null-ptr-deref in range [0x0000000000000028-0x00000=
0000000002f]
> [    0.000000] Mem abort info:
> [    0.000000]   ESR =3D 0x0000000096000005
> [    0.000000]   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
> [    0.000000]   SET =3D 0, FnV =3D 0
> [    0.000000]   EA =3D 0, S1PTW =3D 0
> [    0.000000]   FSC =3D 0x05: level 1 translation fault
> [    0.000000] Data abort info:
> [    0.000000]   ISV =3D 0, ISS =3D 0x00000005, ISS2 =3D 0x00000000
> [    0.000000]   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
> [    0.000000]   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0
> [    0.000000] [dfff800000000005] address between user and kernel address=
 ranges
> [    0.000000] Internal error: Oops: 0000000096000005 [#1]  SMP
> [    0.000000] Modules linked in:
> [    0.000000] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.17+unrele=
ased-debug-arm64 #1 PREEMPTLAZY  Debian 6.17-1~exp1
> [    0.000000] pstate: 800000c9 (Nzcv daIF -PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
> [    0.000000] pc : cpu_enable_mte+0x104/0x440
> [    0.000000] lr : cpu_enable_mte+0xf4/0x440
> [    0.000000] sp : ffff800084f67d80
> [    0.000000] x29: ffff800084f67d80 x28: 0000000000000043 x27: 000000000=
0000001
> [    0.000000] x26: 0000000000000001 x25: ffff800084204008 x24: ffff80008=
4203da8
> [    0.000000] x23: ffff800084204000 x22: ffff800084203000 x21: ffff80008=
65a8000
> [    0.000000] x20: fffffffffffffffe x19: fffffdffddaa6a00 x18: 000000000=
0000011
> [    0.000000] x17: 0000000000000000 x16: 0000000000000000 x15: 000000000=
0000000
> [    0.000000] x14: 0000000000000000 x13: 0000000000000001 x12: ffff70001=
0a04829
> [    0.000000] x11: 1ffff00010a04828 x10: ffff700010a04828 x9 : dfff80000=
0000000
> [    0.000000] x8 : ffff800085024143 x7 : 0000000000000001 x6 : ffff70001=
0a04828
> [    0.000000] x5 : ffff800084f9d200 x4 : 0000000000000000 x3 : ffff80008=
00794ac
> [    0.000000] x2 : 0000000000000005 x1 : dfff800000000000 x0 : 000000000=
000002e
> [    0.000000] Call trace:
> [    0.000000]  cpu_enable_mte+0x104/0x440 (P)
> [    0.000000]  enable_cpu_capabilities+0x188/0x208
> [    0.000000]  setup_boot_cpu_features+0x44/0x60
> [    0.000000]  smp_prepare_boot_cpu+0x9c/0xb8
> [    0.000000]  start_kernel+0xc8/0x528
> [    0.000000]  __primary_switched+0x8c/0xa0
> [    0.000000] Code: 9100c280 d2d00001 f2fbffe1 d343fc02 (38e16841)
> [    0.000000] ---[ end trace 0000000000000000 ]---
> [    0.000000] Kernel panic - not syncing: Attempted to kill the idle tas=
k!
> [    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the=
 idle task! ]---
>
> Signed-off-by: Yunseong Kim <ysk@kzalloc.com>
> ---
>  arch/arm64/kernel/cpufeature.c | 26 ++++++++++++++++++++++----
>  1 file changed, 22 insertions(+), 4 deletions(-)
>
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeatur=
e.c
> index 5ed401ff79e3..a0a9fa1b376d 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2340,6 +2340,24 @@ static void cpu_enable_mte(struct arm64_cpu_capabi=
lities const *cap)
>
>         kasan_init_hw_tags_cpu();
>  }
> +
> +static bool has_usable_mte(const struct arm64_cpu_capabilities *entry, i=
nt scope)
> +{
> +       if (!has_cpuid_feature(entry, scope))
> +               return false;
> +
> +       /*
> +        * MTE and Generic KASAN are mutually exclusive. Generic KASAN is=
 a
> +        * software-only mode that is incompatible with the MTE hardware.
> +        * Do not enable MTE if Generic KASAN is active.

I do not understand this. Why is Generic KASAN incompatible with MTE?
Running Generic KASAN in the kernel while having MTE enabled (and e.g.
used in userspace) seems like a valid combination.

The crash log above looks like a NULL-ptr-deref. On which line of code
does it happen?


> +        */
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) && kasan_enabled()) {
> +               pr_warn_once("MTE capability disabled due to Generic KASA=
N conflict\n");
> +               return false;
> +       }
> +
> +       return true;
> +}
>  #endif /* CONFIG_ARM64_MTE */
>
>  static void user_feature_fixup(void)
> @@ -2850,7 +2868,7 @@ static const struct arm64_cpu_capabilities arm64_fe=
atures[] =3D {
>                 .desc =3D "Memory Tagging Extension",
>                 .capability =3D ARM64_MTE,
>                 .type =3D ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
> -               .matches =3D has_cpuid_feature,
> +               .matches =3D has_usable_mte,
>                 .cpu_enable =3D cpu_enable_mte,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE2)
>         },
> @@ -2858,21 +2876,21 @@ static const struct arm64_cpu_capabilities arm64_=
features[] =3D {
>                 .desc =3D "Asymmetric MTE Tag Check Fault",
>                 .capability =3D ARM64_MTE_ASYMM,
>                 .type =3D ARM64_CPUCAP_BOOT_CPU_FEATURE,
> -               .matches =3D has_cpuid_feature,
> +               .matches =3D has_usable_mte,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE3)
>         },
>         {
>                 .desc =3D "FAR on MTE Tag Check Fault",
>                 .capability =3D ARM64_MTE_FAR,
>                 .type =3D ARM64_CPUCAP_SYSTEM_FEATURE,
> -               .matches =3D has_cpuid_feature,
> +               .matches =3D has_usable_mte,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTEFAR, IMP)
>         },
>         {
>                 .desc =3D "Store Only MTE Tag Check",
>                 .capability =3D ARM64_MTE_STORE_ONLY,
>                 .type =3D ARM64_CPUCAP_BOOT_CPU_FEATURE,
> -               .matches =3D has_cpuid_feature,
> +               .matches =3D has_usable_mte,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>         },
>  #endif /* CONFIG_ARM64_MTE */
> --
> 2.51.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg%40mail.gmail.com.
