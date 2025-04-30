Return-Path: <kasan-dev+bncBCVLV266TMPBB346ZHAAMGQEDU6K5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 86BFAAA519E
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:27:29 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-30bf67adf33sf5893781fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:27:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746030449; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fw/7Mg4QdYG0AKZSg5mnUB3+Mbt08V72ZHA2BPaJEokz/+6jWa9ydhlWscFiUyDS1E
         KJgAsW7QkFJ+HSmNuhzT3ISaP3aMm6BEK9CXwWuyNACViNTwK5dBhBogdnj25ZaYXr71
         MbMrAo1Ot72k9GTfFWEZKnGitNXLxQsynsHDPqZ9SZZD2SysPRTzZgYLsD45+S4Akdta
         LwuKEIFFc/z49muCYoYLplePEL0ztERJ0zzyFcVhTu3FitUGSwmLQhoTVZ7iD/8nBIdW
         ji1K12OLDjA2an7O7LRSPGtPI7IbQQ/FP87sRmOH14slSJS3DcLF7Ytyo2GJotKMvaQW
         qgDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=seGzPBfTE35WaXg+sQHpPDR6azlMHZNpgV3eiKXS5hE=;
        fh=G4LEY3rpfMU+ZTXRhKgB3j8DSpQrWzxw5xf5o8Y9VZ0=;
        b=eFPlzeGYOOpztyReGZH8aL5OSeKlEKRVdYyQY1JBjTlNUy7yUpJtTq5i+E8IQ9cKtx
         +SFFb5ar7VerGbs6I+C2teo3abv0CrKeMIX0WPwUNCMHoN0q1/eWJz78+rkWzY+rTKco
         xEvByxpyUtt27/5XXFtgiKuKEnN9wJ2UfSJKff4gfzXTAN+9ty+bGy3i1ii/wDTwHW+6
         cks8zLrYPRxyP+zdBSgd3QKv0ymgRC5hp6cHpCHsI4HluZGvVhWyeXG4XFpQugiwFJAE
         i4DGENrIY4q3ovD18uB+ci+0xOeow5upAoGHBTvrLFEbefDHlqSbUrvBUK9fDRBcUb6Y
         QatQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xy0pdhVA;
       spf=pass (google.com: domain of 3a08saagkczomgimn494aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3a08SaAgKCZoMGIMN494AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746030449; x=1746635249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=seGzPBfTE35WaXg+sQHpPDR6azlMHZNpgV3eiKXS5hE=;
        b=Q9GP1J/R3Ptft65ajbNXYcn7j97ZElWPieXG2YgjXwSE0VL6Us2QSRw/RlEut8IcrB
         e7AdmI/Y3mXDyIxyujH/o4CQvrc0QFLA2ZC6+91yq46tvZrtLCoeGTJFw5h3VNcANp0q
         DEMguBwdl16uw5ng8y8buRfxvYlj3zhhwTdDpxzostxXqc0JoM54B+xFTKQLeqbARrxb
         k5wXK9R3rGSjCyCVy+nkxe2cjQ4yI65Dcu73VzbKaWPLnEwcZrq3VTE814fazGdgbXZD
         tyHLEjpYjTVH93VsfYxCNstAInGwui0tuSOOGThVLZGbqZCS+6Dw9w+RikteJTIv4pZt
         LHxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746030449; x=1746635249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=seGzPBfTE35WaXg+sQHpPDR6azlMHZNpgV3eiKXS5hE=;
        b=vKDc4FpymfLwe+a33i/sZlsCoyhVApgnM+BtGlWUlWlXAW9+JsCtvigB0lJbyRRrPP
         dxCtwwNfWqKLTXoEYqBu8X/jae3E76ifSd5f8G+bVPkScIwgoS1VWZC7OgKDn8+PwAcP
         bAa+4C7B60NjA6JNRdsSw4/p1eRfMwAwsCO8tEq2Z15Wzwck3HiWOiei0iQXE9wCO+5/
         frbiBvZdUtPqP+2molR2fxUE4Dc2LyuTiUMQDd19GgJmf4svHexLyd+csELLMuX+2wNO
         cq1Sp3MXOoG97FW0/ozEW0SRYqwd/iEF5Rg9WytMlwhN0qXQGHaUWlpkxM2gp+/2oa1U
         EJAA==
X-Forwarded-Encrypted: i=2; AJvYcCXiv5iczXxcLZlblbKeIKQNtCImst7wvPtMgDivMiA4+UVJykR+l6+kBZuHBjsjkEDBCVqK5Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw/g0Eiycgn86PBF0cIPY/4IAOzaPsag5xrmBAn6J48bh/O2A1W
	u+F/7tj4L2aRqJA/3O+z3nn0o/UwIJt/tjAWkhOvn2nR1ALDQQjd
X-Google-Smtp-Source: AGHT+IF4yCS3EUS6Fn/3BJC84IYyC25beeYM7zf4gj46r8m3ZVHK6byWodJKdqTeIPH3rBjOLt4D5w==
X-Received: by 2002:a05:6512:3e2a:b0:54e:8189:2ec9 with SMTP id 2adb3069b0e04-54ea69f8d9dmr21059e87.21.1746030447775;
        Wed, 30 Apr 2025 09:27:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH1xpUG0mzG+rYAv+/fb8nZr9WRUgzWOfoxMbcIpunR4A==
Received: by 2002:a19:640d:0:b0:549:950d:3478 with SMTP id 2adb3069b0e04-54ea675fb89ls8355e87.2.-pod-prod-00-eu;
 Wed, 30 Apr 2025 09:27:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVT12ouhgSrIfP7SfKTVXryeKI9gStfbx9NRW8Xwi8dGwnwqhruWPeNye7uOfhHxnIH6l5XSviRvmo=@googlegroups.com
X-Received: by 2002:a05:6512:31c7:b0:54e:784e:541 with SMTP id 2adb3069b0e04-54ea69e0e73mr41351e87.14.1746030444340;
        Wed, 30 Apr 2025 09:27:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746030444; cv=none;
        d=google.com; s=arc-20240605;
        b=Je+csYW8Swoh5cpDr3qeIYsfQZYUvqrCBHliCIShQa9/OYK0c5NQz9iP0vO8n7TGog
         rxnIutp/uWdK6SBvWHEg/GHpkkSYEzDPT/8mdsIBbyvgSRy8YtWUsa4tyA+rR/sRZJFF
         0Zcw95ocPMcRPDWAED7cOFjiVMVFra/FbcJnOtecojSAaJAdY+Mi9b4sNKBOvr5Zqmu9
         1vixAgkX5mqo1ClG4dGg9YWYva+6VVAuyo+LP/lzRz3Ff23lRU8KLHkbatEvgACDdrA1
         EjttwLBLQ+AAzUAn1LN2maxurWSnE8hUYRDBXqSiWp8t66m703PP770Rrvv0H+60hyOJ
         ZyGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=son2TtAYXWFKHIb+qv3GEJQE2heH3nn7VYU4EbNQqf8=;
        fh=MMoUOq5bVUJsTVEyahflhvYJdPmbZNMt/gQBEf5QX8w=;
        b=G10rnBP3Fdeswrc5uRuN/d2JEOi8FtcD3GZHJGHlXnfOwiXN0eWXCj2YPSGiACfWp6
         Ghn/v/y/+M83V1Pepk6bB0zAgNS7k+BjVEUojwjlIy2Wn/L4WxYyY7XvCWxraNxTHV0V
         5C9yw9gpZR8dbhS+dqSfcX4eeu4X7BkQJ2aiqrl8A1oMWwuUnLl6NBQiGyiVjP8V/GHy
         r2PNumAjo+RnwuOIsxYFLJhlYqRSCfiZM9IaXnlRUvdsdU94UXBeAz2R/WjVN6aUOeIz
         7kwrlgUshKL1VCjj3J7Ww0s067chL8FFSVZakTsn4ytXuzBP/rR3kPrDXxsJ2TV8tEbq
         7u8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xy0pdhVA;
       spf=pass (google.com: domain of 3a08saagkczomgimn494aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3a08SaAgKCZoMGIMN494AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-31e93f8326csi694131fa.1.2025.04.30.09.27.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:27:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a08saagkczomgimn494aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43f251dc364so40813425e9.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:27:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNXyvhcWTjob3S64MWKaKCkjUxqee5ie/vfsg843AdCMV7YOWZZQ4xykTVzY85NHizdChAOLXP/+I=@googlegroups.com
X-Received: from wmqb17.prod.google.com ([2002:a05:600c:4e11:b0:440:5e10:a596])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:1f0c:b0:43d:b51:46fb with SMTP id 5b1f17b1804b1-441b1f31004mr39397195e9.2.1746030443778;
 Wed, 30 Apr 2025 09:27:23 -0700 (PDT)
Date: Wed, 30 Apr 2025 16:27:07 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250430162713.1997569-1-smostafa@google.com>
Subject: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Xy0pdhVA;       spf=pass
 (google.com: domain of 3a08saagkczomgimn494aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3a08SaAgKCZoMGIMN494AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Many of the sanitizers the kernel supports are disabled when running
in EL2 with nvhe/hvhe/proctected modes, some of those are easier
(and makes more sense) to integrate than others.
Last year, kCFI support was added in [1]

This patchset adds support for UBSAN in EL2.
UBSAN can run in 2 modes:
  1) =E2=80=9CNormal=E2=80=9D (CONFIG_UBSAN_TRAP=3Dn): In this mode the com=
piler will
  do the UBSAN checks and insert some function calls in case of
  failures, it can provide more information(ex: what is the value of
  the out of bound) about the failures through those function arguments,
  and those functions(implemented in lib/ubsan.c) will print a report with
  such errors.

  2) Trap (CONFIG_UBSAN_TRAP=3Dy): This is a minimal mode, where similarly,
  the compiler will do the checks, but instead of doing function calls,
  it would do a =E2=80=9Cbrk #imm=E2=80=9D (for ARM64) with a unique code w=
ith the failure
  type, but without any extra information (ex: only print the out-bound lin=
e
  but not the index)

For nvhe/hvhe/proctected modes, #2 would be suitable, as there is no way to
print reports from EL2, so similarly to kCFI(even with permissive) it would
cause the hypervisor to panic.

But that means that for EL2 we need to compile the code with the same optio=
ns
as used by =E2=80=9CCONFIG_UBSAN_TRAP=E2=80=9D independently from the kerne=
l config.

This patch series adds a new KCONFIG for ARM64 to choose to enable UBSAN
separately for the modes mentioned.

The same logic decoding the kernel UBSAN is reused, so the messages from
the hypervisor will look similar as:
[   29.215332] kvm [190]: nVHE hyp UBSAN: array index out of bounds at: [<f=
fff8000811f2344>] __kvm_nvhe_handle___pkvm_init_vm+0xa8/0xac!

In this patch set, the same UBSAN options(for check types) are used for bot=
h
EL1/EL2, although a case can be made to have separate options (leading to
totally separate CFLAGS) if we want EL2 to be compiled with stricter checks
for something as protected mode.
However, re-using the current flags, makes code re-use easier for
report_ubsan_failure() and  Makefile.ubsan

[1] https://lore.kernel.org/all/20240610063244.2828978-1-ptosi@google.com/

Changes from v1:
- https://lore.kernel.org/all/20250416180440.231949-1-smostafa@google.com/
- Collected Kees Acked-By
- Rename CFLAGS flag to CFLAGS_UBSAN_TRAP
- Small comment fix

Mostafa Saleh (4):
  arm64: Introduce esr_is_ubsan_brk()
  ubsan: Remove regs from report_ubsan_failure()
  KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
  KVM: arm64: Handle UBSAN faults

 arch/arm64/include/asm/esr.h     | 5 +++++
 arch/arm64/kernel/traps.c        | 4 ++--
 arch/arm64/kvm/handle_exit.c     | 6 ++++++
 arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
 arch/x86/kernel/traps.c          | 2 +-
 include/linux/ubsan.h            | 6 +++---
 lib/Kconfig.ubsan                | 9 +++++++++
 lib/ubsan.c                      | 8 +++++---
 scripts/Makefile.ubsan           | 5 ++++-
 9 files changed, 41 insertions(+), 10 deletions(-)

--=20
2.49.0.967.g6a0df3ecc3-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250430162713.1997569-1-smostafa%40google.com.
