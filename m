Return-Path: <kasan-dev+bncBDW2JDUY5AORBTVK6O2QMGQEJ6ALKBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD105951F56
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:03:27 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-52efce218fesf8399184e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:03:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651407; cv=pass;
        d=google.com; s=arc-20160816;
        b=rPqJAz98yYP2PJEvU+yRCobM/uGjQ17eCKXYtSqgYY3MtnT/svJg2IUerfz3QoK54U
         H37SNtGLnxeDyCI3MGfhNyG0NV8bqtvUF7Xpr6hfz0G5SSQLOGEAFLo5X0dfxk5havjl
         q3mBcASozXYKJ79lkHwrmk0Lc1KtMpplLfl9YUhIrthA1+Eia6CHO0XJyo9ufpXRCK5o
         XLaBbBzaR8vxejjrAAriPYpx2gWRbjNM+8JAC4+59Lw/D2+SBT6KSMBqufvIEvMCuwOL
         UUlNBXa1XT33gwLKUNr76P8RgL1l5nQU2i1p0Tyv47rndRogSC1iqE3Y6DfyvJH5I17n
         dyCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=I2C8pz/aEutHarrRqQUtgydb3w2ac5/Xe2BuNM2KHJg=;
        fh=dY/RYP7jsyLDwe4dOEiajaEiB43MYEBk2c4Mfp0qpkQ=;
        b=N1oBbVObih3TXu78jcdsxNSJCM3Mw3wJp5PKz0oCOJHQ+ztWwc8Ym4qk1Q+qkR4xC9
         RipViyGiPnZDA6uRrs6hYsZ+ACpoymwtb/Y1WxGcl7GTKgCvlrCifB1QB+sypxFutpnI
         YtYKwhyN2xFgqlANzPVDAeBcSO9rOTVzZSZNcIwtnp2UeatGXy1OPEH7y3YvWnnoNpIo
         xf2sonUNMDK/07ynUGg5LepgWDl3sfFc3ZjC/7KVGXForGFpOxKUceaqMRRKhT0iYEZB
         tu2v4cEvvabrFduNHUbZHHT0f5a0EmMieCHEvVvMKV4nKqltW+s2XP6rd3qFK5O4LC24
         HzUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZrmedXYf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651407; x=1724256207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I2C8pz/aEutHarrRqQUtgydb3w2ac5/Xe2BuNM2KHJg=;
        b=QNIeRBBdwAXg4LNe5l6Ma5CiYJTmpmXkqfMNhVqt+lGkkaZdFkOAWpI0dHp3pmSxvP
         z/n8CUjFAGh/WNjmwSIcUhoJdHWDRYPzv+1cyLqbVv4mRbp9hktBcdsBiLHHEcZoOARU
         l1BkoHcAAyNyh3vFCcbmszLkhHZwOCIgHDJlyvD19n9+mj5v7h7GL5WOMt4CMzLRdD4z
         EgxzIT83OlSRDaKi4UCG5G77z/PPCtYbFGVAR9hATZJ3Pw1qL3IaQR9IFJU9e9owAYtV
         7c+jU+6lbMyev0pU0N//oum/FzZKxX0yLHLoRNOhVyR9owWsd8E6zK9QCpYt/CkKF0wi
         S3dA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651407; x=1724256207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I2C8pz/aEutHarrRqQUtgydb3w2ac5/Xe2BuNM2KHJg=;
        b=AYuS08ysy2Xf3VDi8V5twT+i/4PxsIzByM6GDwkgjIZAwgn472t4Hfx3gfmpl92hWx
         ni5r0wlV1QNvh9mN70DCoK6RDA+ggllSkQL0bj+jgYJZecBPeMDVNBsFp4Sw+NMZ2NR+
         ywrWFrZ444udIpAtfXNwJwox+1ujROX21jS0GXVMFO3T4ZHO2hZA+cFiFvCkrqjq6vLp
         jJazrGnwJ4+M0ZS9THlm2dO49jfQMo2tfO9uCVP7kWNM464naI4wvxoQAWKtxlC/z+ZO
         88g6KGt3crkwoN5nuXgwNUzQfOu/t0jSgjXhI1jDl4p2bbBKNa3/KeWCBQi0ShhXwAcD
         lw3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651407; x=1724256207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I2C8pz/aEutHarrRqQUtgydb3w2ac5/Xe2BuNM2KHJg=;
        b=G/Q1HRZtg7meym+4pjdtSzlhcY5z7dV5IH0JqOJ/heJOhC5tXx0+EekBlNDASKDGyA
         /VjOFT7sLDqim7w+mv2pk+9URz/JRRWnku2clk0qKbUlK30jj8QnkwFmIMYRP7y4DRWM
         12MyZ1q8rU5sLlLk7cFBkPehpu7A8G48GeOLDoYLyM60OlnD3eeNJWiI4qemaIjB0wC7
         rvrGU0Z3Eg6z39qjekn4MHlP8rbw/l6GXhG82lglemKbGr8P4j2frivorGimU8M/FsDf
         hYg7HMzmSqWDn+D5mijCHlkes6lNEoVsd63ZO1766TDULJ2GGBdPrrrDQRC30/F2FZ/n
         o4DQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlXfKOrvyv1MFo2GwM+UDpNJaBR8zC0qjNFkxouhJP4coRpTtvojVePAyFCv/8AuAXHJid4CeiVt+/UNSM0SLQT5ixedjUbg==
X-Gm-Message-State: AOJu0Yx28qNtlyvCyuFdHOTidDZpV7E5NaA8lv6Q4r1EUp4bYIH9uW8E
	QiZbh8StHmuEwXMY+j7SjfA77bDfv1QZnjJXY10a/XACFXd87bB9
X-Google-Smtp-Source: AGHT+IHu4nZoTvHFrqvh0GJxa6+r2X4sUSnFE+q8hUKGJv53vhlUpZDqhuzGgNhX+/K7SDzPN2zWmA==
X-Received: by 2002:a05:6512:3b22:b0:530:d088:234a with SMTP id 2adb3069b0e04-532edbcda1bmr2370496e87.54.1723651406487;
        Wed, 14 Aug 2024 09:03:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1110:b0:52e:6e57:6ad5 with SMTP id
 2adb3069b0e04-53307d16feals29053e87.2.-pod-prod-04-eu; Wed, 14 Aug 2024
 09:03:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoz/i9yrs8UvPrSqOeAew7osDTNCuUUOm1vQJQ5WlC0VnhtqM/ZjSmaRKjttWrFLGfbYltUUgFp38Y6HrEu5aK2VmGXpaHYorkmA==
X-Received: by 2002:a05:6512:3190:b0:52c:f2e0:db23 with SMTP id 2adb3069b0e04-532edbb3817mr2408302e87.40.1723651404206;
        Wed, 14 Aug 2024 09:03:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651404; cv=none;
        d=google.com; s=arc-20160816;
        b=yUMB6UOeGV3UcEWlf02FVtf6dSR8tMjKopTC5JSfzaHsKvyQ+wBggU42X0Osnfipyz
         ET8RH2z4K2vB8Foy8VKlWt2/Rv3DSkpihB7AsNSEAYyooOmrJPLk+6G9lKLAs6lW/v5G
         ClOisaYIlmsnEnav/SX0EgeMCFtcjDGJgsmZvZZlgCaGU5Tzuft20qP4b9KP7xvTuonq
         hqPw0gWTIy1IOVwOZPAxtPac3FYC6z5xsVznp0e1qPlvzLSVRMjdE0RNCmDecQ1CiamP
         g4gCu80aXjF939dteOeDsJ4MN5gcv0v3eE9qrB7id/OZ6QF6geb85zM0o62HiArAqX8Y
         aOpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AHzTMnbxJwH6LulEheHcfUtlUWn0EPZAfPsSwomgDYU=;
        fh=Sd/0iNk6J95g1Xj3I36GOqhOgzUX26ajLiH3ZOY2oB4=;
        b=sWoHwGkNvdUpVM3ntyPHACvBvfxL73mzwlSQLyBQEjbALm2aHkJGcIGNsyb5wR/EFF
         Z5n8+MgGmaxcHirBr0/xwEnYpC+fbgiOKlSPROyfAoKuX8d4511d9HCCeAg7sZnAVKRy
         WVa+kX5JlrbKaYgHaMJnJkm4p+zACU9DLTfrjE8xXdFTUiF3Yu7oE15jzmsIkvS/WVlt
         nBeHfEvonUhG5puL/n4OWZq3kizY28+Tq3MUJ7Jy+9tm8qEk/Sxf2sODoHFLyYHvcDIF
         /Hj5e/oMgbijuFIuw3cR6LmXTBhdcnYcCAsNG2uKQcU0VGdIaA3e/MPTfuK8902/sM2s
         /HYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZrmedXYf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200effdcdsi218801e87.9.2024.08.14.09.03.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:03:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-428e1915e18so46787145e9.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:03:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXM36bYnfWFzpbYVtkin1lFA45CQGkx7qFaXF+H1DfWGHOtqjkPoSNfkXDIKB/g44Ck7uTMLP15ie4mJT4CPwVpZk9R2/tDuKlSvA==
X-Received: by 2002:a05:600c:46cd:b0:427:9dad:17df with SMTP id
 5b1f17b1804b1-429dd23bf18mr21690025e9.12.1723651403192; Wed, 14 Aug 2024
 09:03:23 -0700 (PDT)
MIME-Version: 1.0
References: <20240814085618.968833-1-samuel.holland@sifive.com>
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:03:12 +0200
Message-ID: <CA+fCnZf0H2yqHUOzQR1vJV=-NK-HVU0d372kavcNjsDd_XY5+g@mail.gmail.com>
Subject: Re: [RFC PATCH 0/7] kasan: RISC-V support for KASAN_SW_TAGS using
 pointer masking
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZrmedXYf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336
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

On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> This series implements support for software tag-based KASAN using the
> RISC-V pointer masking extension[1], which supports 7 and/or 16-bit
> tags. This implementation uses 7-bit tags, so it is compatible with
> either hardware mode. Patch 3 adds supports for KASAN_SW_TAGS with tag
> widths other than 8 bits.

This is awesome!

> Pointer masking is an optional ISA extension, and it must be enabled
> using an SBI call to firmware on each CPU. If the SBI call fails on the
> boot CPU, KASAN is globally disabled. Patch 2 adds support for boot-time
> disabling of KASAN_SW_TAGS.
>
> The SBI call is part of the upcoming SBI Firmware Features (FWFT)
> extension[2][3]. Since generic FWFT support is not yet merged to Linux,
> I open-coded the sbi_ecall() in this RFC to keep this series focused.
>
> With my RISC-V KASAN fixes series[4] applied, this implementation passes
> all but one of the KASAN KUnit tests. It fails vmalloc_percpu(), which
> also fails on arm64:

Hm, this test passes on arm64 for me. Could you share the kernel
config that you used?


>
>       ...
>       ok 65 vmalloc_oob
>       ok 66 vmap_tags
>       ok 67 vm_map_ram_tags
>       # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
>       Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
>           (u8)((u8)((u64)(c_ptr) >> 57)) =3D=3D 127 (0x7f)
>           (u8)0x7f =3D=3D 127 (0x7f)
>       # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
>       Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
>           (u8)((u8)((u64)(c_ptr) >> 57)) =3D=3D 127 (0x7f)
>           (u8)0x7f =3D=3D 127 (0x7f)
>       # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
>       Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
>           (u8)((u8)((u64)(c_ptr) >> 57)) =3D=3D 127 (0x7f)
>           (u8)0x7f =3D=3D 127 (0x7f)
>       # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
>       Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
>           (u8)((u8)((u64)(c_ptr) >> 57)) =3D=3D 127 (0x7f)
>           (u8)0x7f =3D=3D 127 (0x7f)
>       not ok 68 vmalloc_percpu
>       ok 69 match_all_not_assigned
>       ok 70 match_all_ptr_tag
>       ...
>   # kasan: pass:62 fail:1 skip:8 total:71
>   # Totals: pass:62 fail:1 skip:8 total:71
>
> I'm not sure how I'm supposed to hook in to the percpu allocator.
>
> When running with hardware or firmware that doesn't support pointer
> masking, the kernel still boots successfully:
>
>   kasan: test: Can't run KASAN tests with KASAN disabled
>       # kasan:     # failed to initialize (-1)
>   not ok 1 kasan
>
> If stack tagging is enabled but pointer masking is unsupported, an extra
> change (patch 7) is required so all pointers to stack variables are
> tagged with KASAN_TAG_KERENL and can be dereferenced. I'm not sure if
> this change should be RISC-V specific or made more generic.
>
> This series can be tested by applying patch series to LLVM[5], QEMU[6],
> and OpenSBI[7].
>
> [1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer=
-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
> [2]: https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-f=
irmware-features.adoc
> [3]: https://github.com/riscv-non-isa/riscv-sbi-doc/pull/161
> [4]: https://lore.kernel.org/linux-riscv/20240801033725.28816-1-samuel.ho=
lland@sifive.com/
> [5]: https://github.com/SiFiveHolland/llvm-project/commits/up/riscv64-ker=
nel-hwasan
> [6]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliv=
ersmonkey.space/
> [7]: https://lists.infradead.org/pipermail/opensbi/2024-August/007244.htm=
l
>
>
> Samuel Holland (7):
>   kasan: sw_tags: Use arithmetic shift for shadow computation
>   kasan: sw_tags: Check kasan_flag_enabled at runtime
>   kasan: sw_tags: Support tag widths less than 8 bits
>   riscv: Do not rely on KASAN to define the memory layout
>   riscv: Align the sv39 linear map to 16 GiB
>   riscv: Implement KASAN_SW_TAGS
>   kasan: sw_tags: Support runtime stack tagging control for RISC-V
>
>  Documentation/arch/riscv/vm-layout.rst | 10 ++---
>  Documentation/dev-tools/kasan.rst      | 14 +++---
>  arch/arm64/Kconfig                     | 10 ++---
>  arch/arm64/include/asm/kasan.h         |  6 ++-
>  arch/arm64/include/asm/memory.h        |  8 ++++
>  arch/arm64/include/asm/uaccess.h       |  1 +
>  arch/arm64/mm/kasan_init.c             |  7 ++-
>  arch/riscv/Kconfig                     |  4 +-
>  arch/riscv/include/asm/cache.h         |  4 ++
>  arch/riscv/include/asm/kasan.h         | 29 +++++++++++-
>  arch/riscv/include/asm/page.h          | 21 +++++++--
>  arch/riscv/include/asm/pgtable.h       |  6 +++
>  arch/riscv/include/asm/tlbflush.h      |  4 +-
>  arch/riscv/kernel/setup.c              |  6 +++
>  arch/riscv/kernel/smpboot.c            |  8 +++-
>  arch/riscv/lib/Makefile                |  2 +
>  arch/riscv/lib/kasan_sw_tags.S         | 61 ++++++++++++++++++++++++++
>  arch/riscv/mm/init.c                   |  2 +-
>  arch/riscv/mm/kasan_init.c             | 30 ++++++++++++-
>  arch/riscv/mm/physaddr.c               |  4 ++
>  include/linux/kasan-enabled.h          | 15 +++----
>  include/linux/kasan-tags.h             | 13 +++---
>  include/linux/kasan.h                  | 10 ++++-
>  mm/kasan/hw_tags.c                     | 10 -----
>  mm/kasan/kasan.h                       |  2 +
>  mm/kasan/sw_tags.c                     |  9 ++++
>  mm/kasan/tags.c                        | 10 +++++
>  scripts/Makefile.kasan                 |  5 +++
>  scripts/gdb/linux/mm.py                |  5 ++-
>  29 files changed, 255 insertions(+), 61 deletions(-)
>  create mode 100644 arch/riscv/lib/kasan_sw_tags.S
>
> --
> 2.45.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf0H2yqHUOzQR1vJV%3D-NK-HVU0d372kavcNjsDd_XY5%2Bg%40mail.=
gmail.com.
