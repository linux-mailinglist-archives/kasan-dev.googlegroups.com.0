Return-Path: <kasan-dev+bncBDCPL7WX3MKBB4MWQDAAMGQESYOKUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 959EAA90CA6
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 21:56:34 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6eeffdba0e2sf1392086d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 12:56:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744833393; cv=pass;
        d=google.com; s=arc-20240605;
        b=DQvRaWbMEkadz8Evy/cG58OFU04xTOkj2rCssiNMvfGQe2+HoCtd5P70eR0CKzPHUJ
         4TcXDQOzRSu9EvvQ34+Am86xhkyGfx1ETJ4KXpo9M7AGp9vWCKZnI52vsIzliBw7oRpE
         plWdVEYd1z9f1WfCJqLZIyLbOk3m8VXk1CtqqflSFbPObVXY41U4sdnQ4+/lNXh7Jcao
         P6sICo2a/t0RJ26HMzbZ4+NaW5FXH9oRtGqjbDrhBQ4An/rW3TN0FDbEBSVgGLr3s+sv
         XPOwyWgZCDMzvXZshvdq/mzjLh6xoaleVX6d3/lJhjBrqeC8KKft/FPFYtqymJwwk83i
         iT6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/W5fpgG8k5GwrlKssMhVBVFzz4HSB1y1lJqr7/nBWfQ=;
        fh=bSxD86QJ+KMDw1DqzCXjcjC8QGwVkXZGF4/KyuESGt4=;
        b=HXHWUh7NN63LsXJiHFmzo3a2t/QSnVMaVLzOK60KP9nuWiLyyj4FU8owceBddF4lSY
         4VnudPyvFmPPILy0n6fQommuEDUU6vhsEK+qJtjmYlKgDi9QWe9QYGSyrrV0TfQ2WBCR
         eP5G7tk+AUOV6vjbq1gLq/mtsO6It6bh16cYqZ9XfSdzF7hb95TE09ubZTcDWZzunQC4
         adU40+RPyaRroeRp5JKNuoIZqxB6VLiSzmCxg/cA/oABYpzsNNxOEVuorI6qHsJSNQWy
         M14llzMlqHcied8qIipErigAe9U9BCaC/C/J60IFY+LJeUjDd7oqDOkkw1L7/UGBeSUX
         npjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q28ERErF;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744833393; x=1745438193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/W5fpgG8k5GwrlKssMhVBVFzz4HSB1y1lJqr7/nBWfQ=;
        b=L/xBounIkyT36LKBtrkljuNqBkV5412Hok6NC+y8AlqcLyIu11EpG2894BNECdPhOS
         Ek0NSvdsZ+U/D/g8LYRp8ClWwqPtUVuFJlfTtstsiV8JpSacN7l7CP65G0CUbqskGkrR
         +KSWYryf/y7jL12RZUXL7vUN4YMVDyVX20mfuctKL7IOgwMfdlXUmoZ70YybXkDc645s
         pCwTQKNxQfGBaVmCLBIAxZAzqgS+5sTzvpJ/q8RqWgA4RdzzOVwm8gJclISxGEB5o0D0
         18gnb81YJGsONXxxwNZV+fxW9P8QQwuJck2DkB49shM0W69nl9bWa6BxycD+nZCtfGps
         eIHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744833393; x=1745438193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/W5fpgG8k5GwrlKssMhVBVFzz4HSB1y1lJqr7/nBWfQ=;
        b=Wk8vddJqist6lcdc+s4dhmWxMQltDbt6uvIPM5UCp2iUHIYmhPWVhPZJ7+c2B/ohUW
         FFm3ugzto6whseg00VTffpl1Bz+T/llzEBmKCAfKO6cRi3gEitVIOn4nTW0ko/N484nJ
         1p7YR7OKkoG5uPz1Eqze6wan+/TeKjlrwrRbj/lWM6GklRNr24ZNLYpYjiqRN4Ig01sb
         cGUdf4IS6CUARKeOH/75mZYUc3HCsUSWPLWuCZ/LMpZRVunLPvbOvAmEvBhlI1ijBVUA
         0MmZP23FyeBHthhlrHOipHZqM3IyBOyDyHuPgTY2trKovQj9rMbdNiGpZU6b+0zsO+vu
         UCHg==
X-Forwarded-Encrypted: i=2; AJvYcCVy6mVViCD3wDjQdWEke+ieda4mPV5mvLfKI+t9QWpv/vznTDlvJxVu7YwV8rLMoIuoEzx4pA==@lfdr.de
X-Gm-Message-State: AOJu0Yxu3xPdVYg9VlE2vDf3ya8S4mWW3SzF2kC2mv/WLlA3dd1FbF94
	FpZJfU32X53hQPhWeP/9ecqi8bXl+zO8UwCRMmzxSJme4WWlLHRF
X-Google-Smtp-Source: AGHT+IFJkDw/4H3ovU1h8+FdiF9tEUaXGMHm3A/0/C9Rb97VFi2E/kd5TtbmN/oxXhTCubfwajh6ig==
X-Received: by 2002:ad4:5aae:0:b0:6e6:6c10:76fb with SMTP id 6a1803df08f44-6f2b2f9526dmr54941866d6.25.1744833393401;
        Wed, 16 Apr 2025 12:56:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIdke1qJIYBYq0eoW4S9Bfc2OnqBvN9VJnQDI/gH34Njg==
Received: by 2002:ad4:548d:0:b0:6e8:f4cb:3021 with SMTP id 6a1803df08f44-6f2b9a9b536ls2275626d6.2.-pod-prod-09-us;
 Wed, 16 Apr 2025 12:56:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6SPxWdAyQRkStROtTfyB7CJC4LbjTnZVA72TevlsEd57gjt9Hs85AQ/jKxcyurKFEqkiuMVcpUXk=@googlegroups.com
X-Received: by 2002:a05:6214:f0a:b0:6ea:d393:962c with SMTP id 6a1803df08f44-6f2b304c47amr39565696d6.30.1744833392497;
        Wed, 16 Apr 2025 12:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744833392; cv=none;
        d=google.com; s=arc-20240605;
        b=LkS70+dkWj+CXKYjDimjWOEJZ1t0GwKyvJ2Zd5rIP/o1ZTHPrLXAsbiEAfoH3FyHzK
         cRzdnHQJXaEpP1U0SBfT86NqMcra4olTmHlfujvJhqJXqmDRREe+B9uMkME1/VwBG+US
         y/+xbr6Aqj7/FZxAZulCMXClVFB5NVp8YE45H16cOUksnbwqBQkNQiI6BUdmpEXrBh5U
         srG28kSjorUIRCmC7NTwCYfc8axbaVy3WxrsiDylHNvdy2EXx3S3HoYimv4URxilrM2R
         /Qfxyr2AemvMOksaW0ih78SVnBAQf/k8aNWWiehc5Osp9lRFycs83gh81LfVXxaDMB8a
         M0iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zOy0kKZXmd4v4LZe/WO0h2WayUdvDZh1TqXaFa62B1o=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=h6whYgTFvsn15qcuARf+SLgFYtwU7wyizUaP2AUZiFopexzNzu4HLjK1r8BS0Cz9We
         ydgtqQY3hK9ayvb6205cmpMo2Esdbb6t8UNvHYDqIgz9M7a5IZ/BOylC/2fBv8pjOYOF
         Pfw+jmcVyGewbZ4sT4BKU8cdsLKPoly/2pSpP8SImcT47iz0eaQfDfGfHnSDShhaRpx4
         jSaZxx6+fo7wMob4OxQ9ipjeXm0PfU4isOTRfOKkhYBTmOnp+OAtwbBERHwQk8GHFlJD
         E5HRgzySVDgrbgT6RgT22xJz+UNMqxdKTw0l2soiovfe7KEwmczS6jTU7MS1zUUfMj1h
         x09A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q28ERErF;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de9eb0fdsi7742726d6.8.2025.04.16.12.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Apr 2025 12:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 740F16156A;
	Wed, 16 Apr 2025 19:56:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 33C56C4CEE2;
	Wed, 16 Apr 2025 19:56:31 +0000 (UTC)
Date: Wed, 16 Apr 2025 12:56:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, maz@kernel.org, oliver.upton@linux.dev,
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com,
	x86@kernel.org, hpa@zytor.com, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH 0/4] KVM: arm64: UBSAN at EL2
Message-ID: <202504161255.7583BC11@keescook>
References: <20250416180440.231949-1-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250416180440.231949-1-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q28ERErF;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Wed, Apr 16, 2025 at 06:04:30PM +0000, Mostafa Saleh wrote:
> Many of the sanitizers the kernel supports are disabled when running
> in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> (and makes more sense) to integrate than others.
> Last year, kCFI support was added in [1]
>=20
> This patchset adds support for UBSAN in EL2.
> UBSAN can run in 2 modes:
>   1) =E2=80=9CNormal=E2=80=9D (CONFIG_UBSAN_TRAP=3Dn): In this mode the c=
ompiler will
>   do the UBSAN checks and insert some function calls in case of
>   failures, it can provide more information(ex: what is the value of
>   the out of bound) about the failures through those function arguments,
>   and those functions(implemented in lib/ubsan.c) will print a report wit=
h
>   such errors.
>=20
>   2) Trap (CONFIG_UBSAN_TRAP=3Dy): This is a minimal mode, where similarl=
y,
>   the compiler will do the checks, but instead of doing function calls,
>   it would do a =E2=80=9Cbrk #imm=E2=80=9D (for ARM64) with a unique code=
 with the failure
>   type, but without any extra information (ex: only print the out-bound l=
ine
>   but not the index)
>=20
> For nvhe/hvhe/proctected modes, #2 would be suitable, as there is no way =
to
> print reports from EL2, so similarly to kCFI(even with permissive) it wou=
ld
> cause the hypervisor to panic.
>=20
> But that means that for EL2 we need to compile the code with the same opt=
ions
> as used by =E2=80=9CCONFIG_UBSAN_TRAP=E2=80=9D independently from the ker=
nel config.
>=20
> This patch series adds a new KCONFIG for ARM64 to choose to enable UBSAN
> separately for the modes mentioned.
>=20
> The same logic decoding the kernel UBSAN is reused, so the messages from
> the hypervisor will look similar as:
> [   29.215332] kvm [190]: nVHE hyp UBSAN: array index out of bounds at: [=
<ffff8000811f2344>] __kvm_nvhe_handle___pkvm_init_vm+0xa8/0xac!
>=20
> In this patch set, the same UBSAN options(for check types) are used for b=
oth
> EL1/EL2, although a case can be made to have separate options (leading to
> totally separate CFLAGS) if we want EL2 to be compiled with stricter chec=
ks
> for something as protected mode.
> However, re-using the current flags, makes code re-use easier for
> report_ubsan_failure() and  Makefile.ubsan
>=20
> [1] https://lore.kernel.org/all/20240610063244.2828978-1-ptosi@google.com=
/
>=20
>=20
> Mostafa Saleh (4):
>   arm64: Introduce esr_is_ubsan_brk()
>   ubsan: Remove regs from report_ubsan_failure()
>   KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
>   KVM: arm64: Handle UBSAN faults
>=20
>  arch/arm64/include/asm/esr.h     | 5 +++++
>  arch/arm64/kernel/traps.c        | 4 ++--
>  arch/arm64/kvm/handle_exit.c     | 6 ++++++
>  arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
>  arch/x86/kernel/traps.c          | 2 +-
>  include/linux/ubsan.h            | 6 +++---
>  lib/Kconfig.ubsan                | 9 +++++++++
>  lib/ubsan.c                      | 8 +++++---
>  scripts/Makefile.ubsan           | 5 ++++-
>  9 files changed, 41 insertions(+), 10 deletions(-)

Nice! I assume this will go via the arm64 tree? I could carry it also,
if I get arm64 maintainer Acks...

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02504161255.7583BC11%40keescook.
