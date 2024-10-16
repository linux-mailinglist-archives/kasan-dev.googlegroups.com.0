Return-Path: <kasan-dev+bncBCMIFTP47IJBBYWDYC4AMGQEDCVVO5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 904579A13C1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:20 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-286efde9783sf205287fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110499; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ig5vb1DXG7nDab04/3YBsNr8UblIFHZCiFgXoM08+m4IJBtBiw3OmSsGXKLBNMTjFC
         DkOfj2fOeFLer1VcsskcdZau3GMtqL0Gqshg2HsdOmRopGZj9Xn6mqq0UZEPmHggRtFg
         t9Gfdj+NTul4jba22VYUj6CKRolqAf9pWEOr/kKF+RonfyvGosJLZB1JIhR7k3FzCq/d
         kRmxYRfWqdqYt1KmU7F+empkJR4buIo2gQmQOX3BJ7EhsI8b1eCbcshC3Zr5QI0K8E0f
         A3Rc+9DxMN4cMikY0e/wBuDWj8MHF3OVMfpdosZt7Rph4TLLa8HHGgOxby0IBc1cy9e4
         0Nag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=3IqFlNoFKRukrYn9raQy9ECv3om70bQBhwqe295R9Sc=;
        fh=xz589LMiGkBXTGlrVo+TXzlRrZtyiksprjgxNHCdvnY=;
        b=DINzLDmTNc9vGoLOd6CXqYr7Mv01e/NQPRXu9lS9OmwTRwGKpgRV21CFBkcplo/Dfm
         2/H4ulbiJ8loJ3D/XdCQ1afwx8yC9z+4Bb9iJ5HEzd3mtf1d8m2b1SVh3BuOSdVtuNyG
         OaM0HUA75YLd+GK1YZwgunqQjU6bHp8dbnqiGuwy6AK18TH6yU9XpVVnfvUhr7hekIUn
         6G4kiMyKj5eopye4THq7neqkZNgipfcQCvbJwxa3S7U3PWJy5przeqchfndSFz3u5pWO
         fs8KSijKVyPasGoXiVEawGC/CjuofFcrwoCopF72BSXNZFtCJHGEx0x/J2AqfQr6S2lR
         8CAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Ex4ZzTkg;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110499; x=1729715299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3IqFlNoFKRukrYn9raQy9ECv3om70bQBhwqe295R9Sc=;
        b=mlnMUg5GHEL3fuKQademiK+KUqw5iM2n3BW31iMAYrBHMb+Sbds3JcMluM4jU/NUUV
         3V0at680dnI7R8y0P5mrAndUfnEuh0zG/v1eLk5q+zgP16YPGbzCkQFs2H+nzV2RFVvc
         3YrJ7MPmQGpRw/97YE1ff34L4R9BCfUon/oXVsB4xlFlX994Y5yo3ezY1XEk91AwNVj+
         9tqbixMMh2KCwPJYOw/Nq9V3nXAKDmtz/vrzYtbiegcfr+rgicXAH4IlpjN74nGEMk06
         /qkK1Kj2pLNFdo7mzG4I+1iXwVzxXllNEBMlDEaMNJ3OBonCWwHLo7t54kmJ6RaUuBrg
         5CRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110499; x=1729715299;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3IqFlNoFKRukrYn9raQy9ECv3om70bQBhwqe295R9Sc=;
        b=gjA2C68d0vUbA5RcuNCwdE/I1Ut/+mUFfvp92j1Fe4Ta5Bkl1jnqZFWkCy7nLe9qFg
         xo59nBu4BnfXImjzQjClNn0p/3AAK+QgdfPISLs6vzZ5I/jXFcZbJHqo1eK3+oOQ6oeC
         xZhhhdVhqAw3NYxCkPIrJm9W6AltJ1CuFt+ORyB7SMbzpRuvh9LHIm5Fi5uEdWML3K9z
         m+YYOCqBhf+WfrJG+wBnNo6s1AOa0+H4NgN8fyZNyroWJtp+i+XcKIHNc9H5OyWGxn2e
         wl37EYOqmtSpQh1v7bG/EakF2EhlVs9nKCAapZzSssi+ANCmJeRIwlhmBgCIgG95ipqP
         RmJg==
X-Forwarded-Encrypted: i=2; AJvYcCXZUGeNnNFQgbBpBfQFDyHjvmQz9mWjewEWySHwF8MlFYBVLdsX2EPDkszeyCYeXZJrNV0R0A==@lfdr.de
X-Gm-Message-State: AOJu0YwvDwnljgOfeuE32so61g+dD4pZCCO5Z3AC5OUKFguKLTAoIeBB
	I7pyHjTITqAfBosprTHTqNVje5imykxy1ruQI3prQyU4/P2RctgH
X-Google-Smtp-Source: AGHT+IH+LMbQ3j5yweWORMV9ZYrBgFeTBJlga2yrjvatMK4GSGYFFTKMrgJWosD2ztmIq8+nMR1Rog==
X-Received: by 2002:a05:6870:e389:b0:251:2755:5a33 with SMTP id 586e51a60fabf-288874df623mr10078013fac.39.1729110499013;
        Wed, 16 Oct 2024 13:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d82:b0:26f:e0d3:95d4 with SMTP id
 586e51a60fabf-2890c82a4c4ls200431fac.0.-pod-prod-05-us; Wed, 16 Oct 2024
 13:28:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4sgFIdpUhJBjdsEN0cH+At4EcFjmkqFXdjAM4jayCJnwf9FUhTJEFe6h85laNdyVa/iy+MNxLBNs=@googlegroups.com
X-Received: by 2002:a05:6808:3a07:b0:3e5:da5e:6080 with SMTP id 5614622812f47-3e5da5e6616mr11464313b6e.36.1729110498197;
        Wed, 16 Oct 2024 13:28:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110498; cv=none;
        d=google.com; s=arc-20240605;
        b=IMm4SyYH+80YrszmiFp28qzFkfpe05Jk0TQEsE301Ppt8wa4VQ5k6eFzQRTJAKyF52
         haqiRhcdYSJoXeVwHIoyza0ZMaFno8Ym1ukJn6GYBsi4NSuRGi8LszaMRcYdKz/YPhsO
         OeUJl83Jhm3O3lTyLJg8CZNhEUauWZ84EN/Sk6DGrDhT5UhaLyddu9wZ82PdH0z78bXL
         5I10a0ILjOeBZmrszjuNg+X4b+WjeqqhfZhH8M/JKmVTy2EiXNnmuQ3OGQOk/wsdSklL
         K3AdT46Wg385ArjWmCYpQtRizzB/cxUSBj4r+UZ6p6834srboylwxrverR0haiOc/Do1
         oIXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hEUhwJlktvJ9XLTxaEULHD6mXOGpKAbrtbb51ie7J44=;
        fh=a5k0KOf+3wjb5H8cDUu+FuAlz5OOPCR0SWEcFKvPwvw=;
        b=k3Yzs1uYRWNlKJ+KHhBRWtg7EZ2ib6F8Rdaw7bUZFXFp/Z74z9EKePxrM7GQOmpHuK
         33FTjwykesVu3xUlvmME2pItpR9PjtGGisGzLBnX8OYB2oLWdR2Blt7oE1Z+MeKt8IfU
         HQ4FPAX7kHtSATXYQ009tC4BOYd5cT/QPcasaMhjYiQUCoMC5Ezk9Y7HgBiiykFoqnyb
         VqXFs8OvgG5OnQ/OCTEvSnTbUsni1l6Y/rYQFauLvgaMfwI52JTr5RlIsss823Gk8fbU
         YxLDJqoENp1S31jTc7XKaDfYs8iAzh0H0ay+hm5SmmtaMd2DBICCMWVodei84uiRjOTr
         wU4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Ex4ZzTkg;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e5f9e23526si46335b6e.4.2024.10.16.13.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-2e2ed2230d8so182201a91.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoyHeEDa36oWAgTw1STLE7dA+A9oibIYx0FZBetwzBH/Ki1S9ZRCVq37TP8G35P+GgVoeneE/HSDY=@googlegroups.com
X-Received: by 2002:a17:90b:4b8b:b0:2e2:9077:a3b4 with SMTP id 98e67ed59e1d1-2e3151b8a44mr21167547a91.7.1729110497313;
        Wed, 16 Oct 2024 13:28:17 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:16 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 00/10] riscv: Userspace pointer masking and tagged address ABI
Date: Wed, 16 Oct 2024 13:27:41 -0700
Message-ID: <20241016202814.4061541-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Ex4ZzTkg;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"
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

RISC-V defines three extensions for pointer masking[1]:
 - Smmpm: configured in M-mode, affects M-mode
 - Smnpm: configured in M-mode, affects the next lower mode (S or U-mode)
 - Ssnpm: configured in S-mode, affects the next lower mode (VS, VU, or U-mode)

This series adds support for configuring Smnpm or Ssnpm (depending on
which privilege mode the kernel is running in) to allow pointer masking
in userspace (VU or U-mode), extending the PR_SET_TAGGED_ADDR_CTRL API
from arm64. Unlike arm64 TBI, userspace pointer masking is not enabled
by default on RISC-V. Additionally, the tag width (referred to as PMLEN)
is variable, so userspace needs to ask the kernel for a specific tag
width, which is interpreted as a lower bound on the number of tag bits.

This series also adds support for a tagged address ABI similar to arm64
and x86. Since accesses from the kernel to user memory use the kernel's
pointer masking configuration, not the user's, the kernel must untag
user pointers in software before dereferencing them. And since the tag
width is variable, as with LAM on x86, it must be kept the same across
all threads in a process so untagged_addr_remote() can work.

[1]: https://github.com/riscv/riscv-j-extension/raw/d70011dde6c2/zjpm-spec.pdf
---
This series depends on the per-thread envcfg series in riscv/for-next.

This series can be tested in QEMU by applying a patch set[2].

KASAN_SW_TAGS using pointer masking is an independent patch series[3].

[2]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
[3]: https://lore.kernel.org/linux-riscv/20240814085618.968833-1-samuel.holland@sifive.com/

Changes in v5:
 - Update pointer masking spec version to 1.0 and state to ratified
 - Document how PR_[SG]ET_TAGGED_ADDR_CTRL are used on RISC-V
 - Document that the RISC-V tagged address ABI is the same as AArch64
 - Rename "pm" selftests directory to "abi" to be more generic
 - Fix -Wparentheses warnings
 - Fix order of operations when writing via the tagged pointer
 - Update pointer masking spec version to 1.0 in hwprobe documentation

Changes in v4:
 - Switch IS_ENABLED back to #ifdef to fix riscv32 build
 - Combine __untagged_addr() and __untagged_addr_remote()

Changes in v3:
 - Note in the commit message that the ISA extension spec is frozen
 - Rebase on riscv/for-next (ISA extension list conflicts)
 - Remove RISCV_ISA_EXT_SxPM, which was not used anywhere
 - Use shifts instead of large numbers in ENVCFG_PMM* macro definitions
 - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
   since it only controls the userspace part of pointer masking
 - Use IS_ENABLED instead of #ifdef when possible
 - Use an enum for the supported PMLEN values
 - Simplify the logic in set_tagged_addr_ctrl()
 - Use IS_ENABLED instead of #ifdef when possible
 - Implement mm_untag_mask()
 - Remove pmlen from struct thread_info (now only in mm_context_t)

Changes in v2:
 - Drop patch 4 ("riscv: Define is_compat_thread()"), as an equivalent
   patch was already applied
 - Move patch 5 ("riscv: Split per-CPU and per-thread envcfg bits") to a
   different series[3]
 - Update pointer masking specification version reference
 - Provide macros for the extension affecting the kernel and userspace
 - Use the correct name for the hstatus.HUPMM field
 - Rebase on riscv/linux.git for-next
 - Add and use the envcfg_update_bits() helper function
 - Inline flush_tagged_addr_state()
 - Implement untagged_addr_remote()
 - Restrict PMLEN changes once a process is multithreaded
 - Rename "tags" directory to "pm" to avoid .gitignore rules
 - Add .gitignore file to ignore the compiled selftest binary
 - Write to a pipe to force dereferencing the user pointer
 - Handle SIGSEGV in the child process to reduce dmesg noise
 - Export Supm via hwprobe
 - Export Smnpm and Ssnpm to KVM guests

Samuel Holland (10):
  dt-bindings: riscv: Add pointer masking ISA extensions
  riscv: Add ISA extension parsing for pointer masking
  riscv: Add CSR definitions for pointer masking
  riscv: Add support for userspace pointer masking
  riscv: Add support for the tagged address ABI
  riscv: Allow ptrace control of the tagged address ABI
  riscv: selftests: Add a pointer masking test
  riscv: hwprobe: Export the Supm ISA extension
  RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
  KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test

 Documentation/arch/riscv/hwprobe.rst          |   3 +
 Documentation/arch/riscv/uabi.rst             |  16 +
 .../devicetree/bindings/riscv/extensions.yaml |  18 +
 arch/riscv/Kconfig                            |  11 +
 arch/riscv/include/asm/csr.h                  |  16 +
 arch/riscv/include/asm/hwcap.h                |   5 +
 arch/riscv/include/asm/mmu.h                  |   7 +
 arch/riscv/include/asm/mmu_context.h          |  13 +
 arch/riscv/include/asm/processor.h            |   8 +
 arch/riscv/include/asm/switch_to.h            |  11 +
 arch/riscv/include/asm/uaccess.h              |  43 ++-
 arch/riscv/include/uapi/asm/hwprobe.h         |   1 +
 arch/riscv/include/uapi/asm/kvm.h             |   2 +
 arch/riscv/kernel/cpufeature.c                |   3 +
 arch/riscv/kernel/process.c                   | 154 ++++++++
 arch/riscv/kernel/ptrace.c                    |  42 +++
 arch/riscv/kernel/sys_hwprobe.c               |   3 +
 arch/riscv/kvm/vcpu_onereg.c                  |   4 +
 include/uapi/linux/elf.h                      |   1 +
 include/uapi/linux/prctl.h                    |   5 +-
 .../selftests/kvm/riscv/get-reg-list.c        |   8 +
 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/abi/.gitignore  |   1 +
 tools/testing/selftests/riscv/abi/Makefile    |  10 +
 .../selftests/riscv/abi/pointer_masking.c     | 332 ++++++++++++++++++
 25 files changed, 712 insertions(+), 7 deletions(-)
 create mode 100644 tools/testing/selftests/riscv/abi/.gitignore
 create mode 100644 tools/testing/selftests/riscv/abi/Makefile
 create mode 100644 tools/testing/selftests/riscv/abi/pointer_masking.c

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-1-samuel.holland%40sifive.com.
