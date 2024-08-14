Return-Path: <kasan-dev+bncBCMIFTP47IJBB4OO6G2QMGQEU35HP6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 667BE951646
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:42 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-45029c1e5c5sf87335721cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623281; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6vf0TTCpuriBUHwd2umPpxks7TeSVisXX3wwaem6il0d05SUuqFkLooY1ksbLwp6g
         2BOipTzhflmi8FatPYHY735VZu9E/O80EywYp3wqbQLov5jGji7UPzQoVSm9vadMZbrn
         XPDVjnkQ3D1ZkDEInDZKIyQmVzPfWM9cyMa7xNXNq3ZagpdjgFAmi8eWAHjdxt8+00q1
         Ud+lq0OGzfPgO/ae/gmnrzyPxmg91f07ocAYRlEjdIYZDYf0M28jI1DwcgJibBZMsP9F
         wPTluyxE/9+N6NlLJIR+An+y7ZYBo8553d42zDcztKgPv6mu/h1K6JrYnHITE5qXyjNb
         YCsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=TbnGgg74evcpnAxOQv2yzP/84FPuWtNjZvR/oeOGIME=;
        fh=eWCiIFdW+KgZu4niE1tn0bk5z1axLtY2fV31GooC9us=;
        b=dcCLa0KDbB4IZdm22o7641r2dS/7IOuyjZe5fW6/PV6DCmPNzTikoOzJYoyw9zwf77
         IQAYwfDO6qBhYQPlZ73ZJjSZkVUNeUaFtG7Nr5hluxkdAwdtYEF7RQWFn1viB1vpLVXm
         BevyfQQqMadI8SKqPjA5gJLOiUxYksrvAjSouzm8YKeL5rir8+0qadBNkOBa2qhfcGPe
         RxUPbhEAJBhL0Wd8WhxVLS7GKd5EyBUQ2BiBNfy37IWR+yeJwSC8TY/+cus+t1PMXcWa
         2JTa56EJcqeAEF13P3SvL5EOcd8LEWdh4eWgpvzeODWcI5B+Rs7fWs6NrLiZ9cSdc5lu
         1Ezg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=fqpKIt2A;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623281; x=1724228081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TbnGgg74evcpnAxOQv2yzP/84FPuWtNjZvR/oeOGIME=;
        b=kJ5q+QALEGVleRuHQDa7gXMNEIDxq0L2/OIv7/OwAgJsAltPw6/Zug2YCCLTmucRMF
         QEP95hDgAhnWT/pUDwA1l7evfxxQsEuVxpuGx8S/+ki8SvIpDp+4fOT94gOkZGAd8jRB
         b76PgcSWRF3JTJpA0sWpYspS1bEQe+TbQxUFaYgNxy1Lb+jgFcIim8cDY1RoMA3H8Jcx
         kn3Rx4Xx29aqIC2LknLKSraDhgY5CgH1oWkSPBvJpGVRAgEm/kw9OuF7U5kX/QwhiotF
         lVlHBZNQnDn2PtGFUqBnPvR/KfNx8LLy+3jQJXwBrIyjQLWtY3//QPbY2xn/vv1wlQTl
         RXvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623281; x=1724228081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TbnGgg74evcpnAxOQv2yzP/84FPuWtNjZvR/oeOGIME=;
        b=xJ1QVBOKXfme/v5v7sAUctnGdNiQWHcck0Jb5qfwz80kv3idzrK2o33yDTBfI2MYxw
         A8ewddLx+NISq9hAzUVJOKnTdh6mXkcluFwkQUrTQTIGh08QQL5vpLRLnrIGsiaAri4A
         8//VxtM7QHpH8DJdyBQPaFiavD1EGw7Bz/fWRFTW6geakI0SiHBQfOUMGE7gXpRInPuF
         xPHyOBsmB0W3erPb4MmidE0vyOkMaPcoPNyXk8HYas53fQNM9xOv4OJh0UGSXqv9VKWm
         a2+qH72AOIiv8Jyn6PcsNJPKRYFbPmvt7M9gvKfWXjvOdrjymn1km7pZWNPNgXdxfcJN
         va9Q==
X-Forwarded-Encrypted: i=2; AJvYcCUqFCsh7LxwkCXMeJMHuXiCaxh+ZSOEpso9iQsFcUlJRKBwvck7nRJxw+Trzg3o18A0RB9KlmtOWkmCclMKTaH+iV+SkHWDyQ==
X-Gm-Message-State: AOJu0YzSzOcbE0nn+xB54A5Bvvq82wpYQxwKvKf99+c+zsIybL4iIg1V
	Eka+MHyvsWBu1chFGtsacgO5/c3bKXM3IEhAVBkbbSdABi9xIDTu
X-Google-Smtp-Source: AGHT+IEtMuAjQ8NSDxJm1OPi0vYbqoym5amD3l5/0wQ4+lPwh36riUbcastafI2lubPEShDbblWrlg==
X-Received: by 2002:a05:622a:4c05:b0:451:ca77:c5a1 with SMTP id d75a77b69052e-4535bb21016mr18534731cf.35.1723623281168;
        Wed, 14 Aug 2024 01:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a29:b0:447:ca9a:34f2 with SMTP id
 d75a77b69052e-451d12f6dbbls35938111cf.2.-pod-prod-05-us; Wed, 14 Aug 2024
 01:14:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUu2xGtnqa+/vSkaAQDFtjsX4rrilB1L8O1R2FS6vSxKFPo2gXkJsNX+zLrw5t3COiAdKL+o39YXRtCWqAZ5AA00JY2Wbo1SO/5Bg==
X-Received: by 2002:a05:6102:4194:b0:493:b006:e1a with SMTP id ada2fe7eead31-497598e44e9mr2735397137.7.1723623280417;
        Wed, 14 Aug 2024 01:14:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623280; cv=none;
        d=google.com; s=arc-20160816;
        b=H6sFMB1EaxtsaefCPIn4LXFOF14Wqq0rnnokV6ibIRAxptD6TGa+nqqBzRTzI+6vqp
         Imh0lanb5MK+wtko0XTlVFArtn5o96XlCY4bOCT+hZ4RIwfw4WkvYZiDx82vwC8R2eoF
         lcpF8f0F+wJDK0DiAm6EHdvOsJUlzVv64/eeEV7P7lKrRaHRl81p3rX0XkfZqnKQllQx
         ZEORJ+uODRwAI8PL7DL3tVNDfMXsWe8EMLKC6/pZW9JsyOHWHjaj2Tv4mRVagWUF+Zpi
         gPeRwcuX1SxuQ/midzhyuTTFQ4OFPtQHM74EZxQc8Nn/2E0RyDzw3vK71kG0E6uYPxCp
         J9mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7X7rwinZQ3JvqiiqzaTRexejN5yFH2f9NFPeSO2fsBU=;
        fh=lrVtHal4Sxe0X58j+1WIDFz7+DqgoSWP7XR1itR36aU=;
        b=SCQdyl7MscGHiGDcEFOApqUXBgpVo+wEVNx0G0sV8eAA6F1GgtT6Rrf9S/Jm8/3+so
         xFSui1zNlAIPOiOq07XOJLAG+JNdPsGK3CGh+gwkk8yJaOzNojBWlWZx5VPfd+ZpkKc7
         zvrq2VF+hwN8+ZoCF0bxXrIuuFg9PhYF8k06mSG6bbghag0yv+8FTOD0oyoHLKy8GF9f
         WzSkIy0FOzjNW8LocIusemzIC953BV/uFuMwTEDN8TMRER6LyYUhsG4MprytsYQNiVhF
         jZXLBmurzUFdmHrWLbI9YujdQtvEaiOgBkuRZ7oK2DzSaPjuLyLatImml3X7DCHL38mk
         cL/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=fqpKIt2A;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-842eeeaac10si27931241.2.2024.08.14.01.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-70d1a74a43bso4637501b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkQ70RurVrHl8MLF6ltC1Rxq4Bx5wlMEX/EpB+2JqTQZgEzvAU7/BHV18zgdyicclTnv8TzFUgiDihXsGgYJznfrFohQ+jrUTIKA==
X-Received: by 2002:a05:6a21:31c7:b0:1c2:8af6:31c2 with SMTP id adf61e73a8af0-1c8eaf86b54mr2479321637.44.1723623279321;
        Wed, 14 Aug 2024 01:14:39 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:38 -0700 (PDT)
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
Subject: [PATCH v3 00/10] riscv: Userspace pointer masking and tagged address ABI
Date: Wed, 14 Aug 2024 01:13:27 -0700
Message-ID: <20240814081437.956855-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=fqpKIt2A;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
 arch/riscv/include/asm/uaccess.h              |  58 ++-
 arch/riscv/include/uapi/asm/hwprobe.h         |   1 +
 arch/riscv/include/uapi/asm/kvm.h             |   2 +
 arch/riscv/kernel/cpufeature.c                |   3 +
 arch/riscv/kernel/process.c                   | 153 ++++++++
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
 24 files changed, 706 insertions(+), 6 deletions(-)
 create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
 create mode 100644 tools/testing/selftests/riscv/pm/Makefile
 create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-1-samuel.holland%40sifive.com.
