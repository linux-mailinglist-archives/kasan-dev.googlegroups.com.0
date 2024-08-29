Return-Path: <kasan-dev+bncBCMIFTP47IJBBA4RX63AMGQEBOBXGIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2773096372B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:01:57 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2701a253946sf150800fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:01:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893316; cv=pass;
        d=google.com; s=arc-20240605;
        b=DlcW6hF3oEJAfVMgMWTkGnvQAFI1B0Ye/Au0cTgC9rCPZgYPxV+vST9E5qn0pQRS6q
         G8t63AAMNM7kwa6lUil8n6qEIkTMbMnYtCb2fmogOAVvvAqk1jtPUnWuHSlSXGmiRmVx
         CsIHW1F7TZUHAZtsY4DEuqeOhDukY1nOawFmXFdipRr/6Wx33xO7MDgTmGSUQcJu7aLn
         CkhQDa+wPcuYWm4T1huJEEShERV7YoGVs/cbIHkaVEpuHcvUnE675Tq7HlZeCZdh1zkH
         S8St8mithHxBw8t+2MPQJaqhKTfaIqQEwWQ2NrIusiuOXp72aQcb+XI3iaFLi0Tl817/
         /kyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=x7CoAorWNwnpWevKfKlWQIHMLVgpBuaCAV+MSfmjLOg=;
        fh=8IVS8ElQ6Bl9fkWx1DrzrSvWVA2g6nej1YvWucNoGXE=;
        b=aqkqbpX5evunAth+yfTzwpZLMEr9dxVhQTE2i7pz+lgIMKJWEg64K9nCzoKYwEM0GL
         Xm8z6qr2Ehm25FRFyqrU735NBiBLhxr43GzL5ZO+FRvHgP18PUHVDX6+uWQrqF/reLDo
         nk5iiDy+mUJEgVWNWw/5lHMvPvumknYcCgApwSkPg3xoepDiF+7siunHHLEYJc3y/2tG
         PZk0GrN32LHNe/iSlhAWwu/5p8kvbvLZDwsd7F0pRvXiv7q3eo2nBpiUoQe3uiLkKje+
         0GFRlm+xDz/9m4CT92IjPPHA/KzqYi4onRZWtqA0AVFPbb9therAH4ME3Me/EOiIgas+
         xKUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=EAVkf62M;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893316; x=1725498116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x7CoAorWNwnpWevKfKlWQIHMLVgpBuaCAV+MSfmjLOg=;
        b=qaPpcdSf3gNScnJMyeYytHdU+09k141GBIX3iif2DZj1ETaoNyRC5WWawzSqMLKDG5
         sIcpN77kmd3RGPgEPAeZQGSVi7afCuFxr9YchEpBPllh+gAV+6zeVlXrMYCB4p9HK7kb
         N/5wRFxXSp0QWgz2bAAluNcaa7vW72xYnEnRf4mJnGQuCYUFfX+sc7dPSQ3FC9biZKDg
         VrVyJS2Xs+NZNgFC7N/1JivsY+6M1ckfu69UcQjgzTUbfPI4ahhNBEPm+aglgMC+/AtM
         OBcbYMv2mAtSpqBmMbd7yeHESm/xUwPwKHVx75fBEliT0N8P/Xjb0SgNVq9qwBd2QXuS
         ucoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893316; x=1725498116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=x7CoAorWNwnpWevKfKlWQIHMLVgpBuaCAV+MSfmjLOg=;
        b=VjFvHUoDm9Q9BRpYCoexcfxt1Nfh9z1l/LN5JOdjuPWLIoptaaumyYXPQlUyk4n2a8
         vyjDZBBdkAfJ50LE2niMsFck4q6W/OIy5PvAijQle9j8wwhNYSnKnTvin9k2MPVMWGaj
         ryvV39BjecLG+esRbGG1nvm2oe7bAj7ffFbVKkTctcQAkOlEzCiqBdhI136NsK91EIDD
         9ca7eqE8kirAX0YN5KKXxXmTx/5G6jTE8op7NOcTw3eq4kN1PjUjTTLPs9+cSWdIg/14
         crt2vZUNRcsztpttgvxl9H17P4v5I6zG3BPIG6IDtMQfKh0lQPxqB4F3YUl+nbffNCzD
         Q31g==
X-Forwarded-Encrypted: i=2; AJvYcCWL/8e1e/JxnbioGWm7kN4LDMm2iBCxAgKMLFjmf8Syyly4ZLhmdS9OJDFlQ4n6h/WqQ1dpPg==@lfdr.de
X-Gm-Message-State: AOJu0YyfYJmJ5eBgTEMol3tGB27lTewLIv9Vms/hwiGRSLWVkReySahA
	s45HcSb895vGj/7gdUFLWmEDlhFMtMYxMeti6QYv1RBslu8j/xDS
X-Google-Smtp-Source: AGHT+IFyrGYcmJyPIA9yjAnF7kqfETkauF9KReZZOEFEKINP6u6/pOtzuJjTCQfccWHKuFK0QcsZSw==
X-Received: by 2002:a05:6871:7828:b0:25d:8d4:68ab with SMTP id 586e51a60fabf-277902bfc25mr1679753fac.40.1724893315869;
        Wed, 28 Aug 2024 18:01:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a085:b0:25c:b2c1:8569 with SMTP id
 586e51a60fabf-2778f4fd364ls544821fac.1.-pod-prod-04-us; Wed, 28 Aug 2024
 18:01:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSsGjLY1Abv0iNxHSe6JXILDnseGl8yM5MtLItjNQljb193VH26Mz0J/ARemGx7nnqX3hnHQq1IWc=@googlegroups.com
X-Received: by 2002:a05:6870:4713:b0:270:1eca:e9fd with SMTP id 586e51a60fabf-277900774c5mr1350380fac.3.1724893314943;
        Wed, 28 Aug 2024 18:01:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893314; cv=none;
        d=google.com; s=arc-20160816;
        b=I8wRpMXTdticagE3M/IKtY3rJoi/zrzbSJaoWXrI/zplfjk854hDP5C715jId7cyzi
         iMxFN7AtbYlN/ryHr6qmkDbuwuMoNzI7/vxKVQHmUkfGLhTcltwMU5uWgEf+iN8Afp4K
         I1NoqqGSXyflTIAvE30dIiw48WdO6yAvg/3Zq4tlhX+uJxZnqvCWsW9xQgx0HccApTHa
         7vZlb96KFnRWuV6hAFBqRDRNYQ4bhfKUQMU7oO3drzWs9tNFUFF8dMmg72y7EJolcdkT
         bfwWLywm3kbxwphzE6nKe4EB7ryvovx27JUmsr2O5Qx1RVb+9RChW4mSNXNQQKE5lOe3
         Mw8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6QwsbhYPJkRIIKdEOQBCTBjh/yHwiNO4KwyjIKyWe5c=;
        fh=MTk75dVwlGfZ6SApQwyIr+WTVBdRcMlAKXgmqYQ6KsU=;
        b=wCBKnlsI7VqS8hkNPWZgWQ7VHa/chu1dh5+HSjk0iQ3l3Al0fk1eiiiD6/6kC4gm+D
         X+sYQDRQpFFo8RNlX5mnkQh08FEE9eMADZoR4zZ5U6r3gr+CV6qulE8vzOxWMNKa6mw0
         8/LqVgyFAJOnip8ez6YAGAXMqBUb/7lpA7iQpz5UUxAU1RErh/MTH3fcu6F2ckZyqo2y
         LzodkThUD4z4fM4C0t386oXKnA14GDCXbDsxoai+15PVGTgLrZx4ydFAlRqnO1DyW9OU
         ZrSY5I0qA45hQXhHmdB38oWvZjq/jhFBS97M/wrhXRtEHgpKYwV0s7/cSNIfur33iz9w
         p0dA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=EAVkf62M;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27799bbbc90si4264fac.0.2024.08.28.18.01.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:01:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7142e4dddbfso102774b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:01:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWGpIcnZk33fLzZxvmQ1FD8OPbecohBFWWrveUJ1DO7yW9snAIDfCiD6n++6vSpNZtzpwV2VDwXZ4A=@googlegroups.com
X-Received: by 2002:a05:6a00:17a8:b0:70a:fb91:66d7 with SMTP id d2e1a72fcca58-715dfca3b68mr1609341b3a.20.1724893313850;
        Wed, 28 Aug 2024 18:01:53 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.01.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:01:53 -0700 (PDT)
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
Subject: [PATCH v4 00/10] riscv: Userspace pointer masking and tagged address ABI
Date: Wed, 28 Aug 2024 18:01:22 -0700
Message-ID: <20240829010151.2813377-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=EAVkf62M;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

This series depends on my per-thread envcfg series[3].

This series can be tested in QEMU by applying a patch set[2].

KASAN support will be added in a separate patch series.

[1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
[2]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
[3]: https://lore.kernel.org/linux-riscv/20240814081126.956287-1-samuel.holland@sifive.com/

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
  selftests: riscv: Add a pointer masking test
  riscv: hwprobe: Export the Supm ISA extension
  RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
  KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test

 Documentation/arch/riscv/hwprobe.rst          |   3 +
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
 arch/riscv/kvm/vcpu_onereg.c                  |   3 +
 include/uapi/linux/elf.h                      |   1 +
 include/uapi/linux/prctl.h                    |   3 +
 .../selftests/kvm/riscv/get-reg-list.c        |   8 +
 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/pm/.gitignore   |   1 +
 tools/testing/selftests/riscv/pm/Makefile     |  10 +
 .../selftests/riscv/pm/pointer_masking.c      | 330 ++++++++++++++++++
 24 files changed, 692 insertions(+), 6 deletions(-)
 create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
 create mode 100644 tools/testing/selftests/riscv/pm/Makefile
 create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-1-samuel.holland%40sifive.com.
