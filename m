Return-Path: <kasan-dev+bncBCMIFTP47IJBBEPE5SZQMGQE7IKVJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 597CB9172F0
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:39 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7068613e4d2sf4397081b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349777; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPy5FiJCGjSQWtgzwUb6xqOfm8Z1C93fepkz2JglmaAMKJYjDcmYNbKCHkSFgIDT+c
         /MKFFCG/fnqv15m6H2zPx8ze2ER9nuWUNDwdEfR7vGldc24VaKEmJWFVO+LEJqU9uPU3
         HwAvEx1dl1gPw0e4hzqdEkz7EDrUP9wz0USuKRxqBw2L0DM/wyrtacPtcKQRyFs7bVN4
         bTU4hWSxh6aWxn/tL59VlT/yk47e/SjthIUP2EfaQUSqYv7NZMTXhw2Yye0sdz5HqjQM
         dg3/FcZ8ilPZT+I7F4ABTBV+zTTWZGj4/xO/fikUFVSAx8Wtdd5IHc7GnWiOS425BuVD
         6cEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=T2PLMG0rpF/ufNiXIdsZgSZz3RdHrWtH5AgxPIqTBaM=;
        fh=wVB3pQ9jm7nrj11yzCYLpv6uXcx/IGONR7Xv8HcNuYo=;
        b=oxCk/eaZ9RH6caB2jj3k94iZ9PQHJm67ec+zxoo26LkEATbwbFRd09tQLr7KJLMMrW
         Atkg1bycyKiKC5GU4Zy1azZ0j/UgOC6nbHNZu2LRTuvhSbQh+SMSG/xLLLZK/Gijkpf/
         1S4y2BL+ELMxXGGM/qT59nerGXUvyFB4GO3IxRy0Hmz4zu+XPFizvXSugut+nwxZquAt
         rtFTQ0+4MSSb7FtJueIWcKCylLJosVSzSGvJ7PeOnozLd1A8oMwqgRlycXAmbNQMEoBW
         7I9fdR2MpcdLrhScvFwPOifOgupX5oaNIK9za0jjsGdgaNfC1nLEtLUzUkR1gYTxDmn+
         oNDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=L4m2ky6f;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349777; x=1719954577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T2PLMG0rpF/ufNiXIdsZgSZz3RdHrWtH5AgxPIqTBaM=;
        b=vD619zwaA/+0DCiClainT1vYAxKGbV+iyO/ouiBlk8uwEs0DVjE0gBDcv8wDbpE7SG
         BQefY2ThIgKnMXKXio2diunp8wssDfRZS3+uteeK0oj+yVx85vATvf6ZZ9J62ML97M6F
         KcgrzysEIelCEnWgxSoLfS7yEkbKUTsdx9gXM/FCvZb0ZsEudaBxKjb7dJoYWr9hyKNs
         6JTY0AuKmSVFnm1bPNQLAjCNbCZLbpOdKn7GDZynsdApEh5OVRf0HsjH5tU20/Mk8NzU
         xGch0M3pjI2JQHsP94rphkYjpriPbcuQ1Hyen1lSn3+gO+JIKVb/BXA21dJedDEhNO/Y
         tSdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349777; x=1719954577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T2PLMG0rpF/ufNiXIdsZgSZz3RdHrWtH5AgxPIqTBaM=;
        b=BVT9A5ZXzcBlIlgUoJ3mcMybhHuQbHbiWtCF/TdDqlFAUYVeZrUHjTELoXUGwMT7Sq
         IKNkvp1zhsje/9QBQ0bA6xq6y9NOA21IOTG6AWUZ5rwvfqCOnCHMHozp3tV0y5j5/tMC
         iUyRAX14w0wUimU/vxxXZIxo/DHxzknNf8cMNiC27LCid/6t8GvbWoGC5z+bGXi92VIv
         4TNNuNErOXPtGAnSrhNkps2xDIlawUUQZygKFP86vAnC2Cig4neMSmub5xsAX35LqQlQ
         k1JrmBoMgkoiiuZITGcXGitqanw4ig/Yy6pddpUOc9IncEaLgatPx8LGCMB7yvg1oRnK
         Fckw==
X-Forwarded-Encrypted: i=2; AJvYcCXhblYLO+xaffLlOWiioClYEc0nT3dTg9PqyrdhNgtA6M/P7e6JRBPLLfx3cAZocuovfTiDyIyYbem76JhtFCbG/IlgHPso0g==
X-Gm-Message-State: AOJu0YwQAt9Oo64bmRNaDgCGI7g2gBju62BGVVhSEA6sULsqc6ccuZCY
	QMTgyoGP3nN/rbB2gGQlXOanlU3VxkX/jc8ht/BKz83fEFJ+uOi4
X-Google-Smtp-Source: AGHT+IEzV6q0LdkTieG+HFL/r9Fr/X01sh/uV+jvBcn89UdPf+qKRdX1v17rZY+reEimVF16syl/gA==
X-Received: by 2002:a05:6a20:c528:b0:1b5:581e:a065 with SMTP id adf61e73a8af0-1bcf7fba27amr9670743637.39.1719349777464;
        Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c49:b0:2c6:ea3d:6fa2 with SMTP id
 98e67ed59e1d1-2c7dfbe9814ls2408178a91.0.-pod-prod-08-us; Tue, 25 Jun 2024
 14:09:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo8gL2hAUwk+F1iBRKTQzv9N1eLzYUAQbPSePc9o3K2H9C/KLCghX55Yvy3VjnT8bXrO8A9U7n6sq5w83RVh2OzS8T35JKUQjA1g==
X-Received: by 2002:a17:90a:c256:b0:2c2:1d7a:1e10 with SMTP id 98e67ed59e1d1-2c861246b54mr7939832a91.15.1719349776269;
        Tue, 25 Jun 2024 14:09:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349776; cv=none;
        d=google.com; s=arc-20160816;
        b=bAXPXgevywwfK9XGBFiqlJnibsrPzQcwqliRAQbH6cjYGTXAI1ZOb9zEQe/bXkFw03
         /KlxuanFpqbDXXrgEcyilYskG1dL1eH7yTqXXsO1BG+3nZvzB0l7xAkayO+ogqyrAtGH
         NysPnWjnhBqGFe/E3rCTufBnZgnXkywOk2sPn6M1rorEdfzKfWiOx47KU5k0kfo07wqn
         9mtw221z6J7sa3KOY6DBspB8ECyynUG4bX4I2GSZQSdoLJecdxl+IWsu5JxB1fO3zZO3
         QBDOyS4bMpghndB63Mwq49F6ozMXO30G/CFD654LyPzJLbQHhUiPXd+MoeMPIDpi78zP
         CelQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EUBdVGV0+fMFwjwLM0qvSzcFICs4EkTcqE1zrLWEtEM=;
        fh=joGkZhvI84aeQINihq+1kbHyAPXaMe0GbKRk3/E+DQU=;
        b=cawPNOXX72aMaOxGzrzq/Ag74fBUMLD6IJxhjUHc9CePK8n3uEqVd7Xx4qJxeVVBF8
         LWvpnBtavcjdc/OX4BAtia6pam3Zp72WI50bFXcO1doZ5UIdQQR4BMimnD2mBJEoWMIh
         Q/edPzSrvctr/ew8Nuk/KXjzk9IBPVrIk4BkUWSnV/AQUtOaX6Zv7xD2rUBEjZ1FSWFC
         /GMSrqb6tSPuncKHfIiONFI/zTY7yKX4o4cbDEIv/Dz1GyXwjoq1Tjj1muwfM7KLOYwH
         vARXomtcubAw3HYhBETzxr35m/2E4z+vGtIZPYrMDpR0W7n8dcdrrXPQqwXq/wMROkmN
         vWLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=L4m2ky6f;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c8b83294f3si165377a91.1.2024.06.25.14.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1f9d9b57b90so40493545ad.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVyHMX5lzEHqJd8n/36vPc35Cu/WS/9yhmM6T5LxYvAjHV4rmNr4BMHMwhnmJbxeBPPNOzYfPW91rZv51yPsik2Ikp7bnr0CZ65ZQ==
X-Received: by 2002:a17:902:c10c:b0:1fa:a2a:221e with SMTP id d9443c01a7336-1fa23ef0d8bmr91219335ad.40.1719349775795;
        Tue, 25 Jun 2024 14:09:35 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:35 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 00/10] riscv: Userspace pointer masking and tagged address ABI
Date: Tue, 25 Jun 2024 14:09:11 -0700
Message-ID: <20240625210933.1620802-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=L4m2ky6f;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
width (which is interpreted as a lower bound on the number of tag bits).

This series also adds support for a tagged address ABI similar to arm64
and x86. Since accesses from the kernel to user memory use the kernel's
pointer masking configuration, not the user's, the kernel must untag
user pointers in software before dereferencing them. And since the tag
length is variable, as with LAM on x86, it must be the same across all
threads in a process so untagged_addr_remote() can work.

This series depends on my per-thread envcfg series[3].

This series can be tested in QEMU by applying a patch set[2].

KASAN support will be added in a separate patch series.

[1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
[2]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
[3]: https://lore.kernel.org/linux-riscv/20240613171447.3176616-1-samuel.holland@sifive.com/

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
  selftests: riscv: Add a pointer masking test
  riscv: hwprobe: Export the Supm ISA extension
  RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
  KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test

 Documentation/arch/riscv/hwprobe.rst          |   3 +
 .../devicetree/bindings/riscv/extensions.yaml |  18 +
 arch/riscv/Kconfig                            |  11 +
 arch/riscv/include/asm/csr.h                  |  16 +
 arch/riscv/include/asm/hwcap.h                |   7 +
 arch/riscv/include/asm/mmu.h                  |   7 +
 arch/riscv/include/asm/mmu_context.h          |   6 +
 arch/riscv/include/asm/processor.h            |   8 +
 arch/riscv/include/asm/switch_to.h            |  11 +
 arch/riscv/include/asm/thread_info.h          |   3 +
 arch/riscv/include/asm/uaccess.h              |  58 ++-
 arch/riscv/include/uapi/asm/hwprobe.h         |   1 +
 arch/riscv/include/uapi/asm/kvm.h             |   2 +
 arch/riscv/kernel/cpufeature.c                |   3 +
 arch/riscv/kernel/process.c                   | 164 +++++++++
 arch/riscv/kernel/ptrace.c                    |  42 +++
 arch/riscv/kernel/sys_hwprobe.c               |   3 +
 arch/riscv/kvm/vcpu_onereg.c                  |   3 +
 include/uapi/linux/elf.h                      |   1 +
 include/uapi/linux/prctl.h                    |   3 +
 .../selftests/kvm/riscv/get-reg-list.c        |   8 +
 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/pm/.gitignore   |   1 +
 tools/testing/selftests/riscv/pm/Makefile     |  10 +
 .../selftests/riscv/pm/pointer_masking.c      | 330 ++++++++++++++++++
 25 files changed, 715 insertions(+), 6 deletions(-)
 create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
 create mode 100644 tools/testing/selftests/riscv/pm/Makefile
 create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c

-- 
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-1-samuel.holland%40sifive.com.
