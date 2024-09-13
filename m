Return-Path: <kasan-dev+bncBDHJX64K2UNBBOP7SG3QMGQEUF6C7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 29D9997878E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 20:08:59 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-206da734c53sf32973005ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 11:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726250937; cv=pass;
        d=google.com; s=arc-20240605;
        b=BjrisXZnZkGm3BzHDgGOwsP00O8Grjyb7kAT9btfL6W7h4U9PXc+xlJlZP7a5lA6/o
         voxzOiByHWGVI7Cc+M0A5wTQXB4hGS8mkua7j7Jj3G/+j8Zmdldw3nnxrsyrt25M7dFD
         NBV3uy7mJh+2chfiW7GbEte2Fak4ovjUILom6KuOdKzkSyoCznqUPTULV8dpQBIi6+IU
         x6/IAoaY7AEScIkL99Ld2VgCmUGKb6pgD390vH1sDDo9DIeboER/UlnumCJJkXrlYY2w
         4bmnyarVFppdUOYPUPbpPT+Esmj5y4DTPT0mIPfgf3es1q5hygFiPg4ngr/YZc5PAcne
         8PhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uRUUeGT9nmjYVBdYBycqiq61fSVTyBDFZoxrEpibkjM=;
        fh=L8Pl9IfXW5G/CnHW48MSyTQC3+771XPXTF6o4QuwOjc=;
        b=VZDXToq6rmKgwzzOWhTXkJ6unaT5WhsiYIUHwk+i4vtjtkTO1zZUGIFRVcilnFZXfi
         ciGc2peZlUvpNiV/zrChh0jEE+AlcvoqSmwlEeJtCPCDDG6MOKbPmK4VxlDgUe0L+daC
         so7NUlF6bQxzEMvMh/UNqpHKeXO5cpjFFlEb/+4o9u5JDthLAOEjX+OCcRVyCd9nuLUH
         w99g1TXlEofnU+jdL/H2UKxxtwOy/oDJ9lb9X7rI7J4HGbM074dxSF6yVMUzpDLmHwCC
         Ibz8quNe/PRaQM3RulAUaHWJlD/aKx8Bgzt8MBSjSN7vXyguMSLzhAHAStJQlq3DxOaQ
         3Xfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=m7bPJ9zU;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726250937; x=1726855737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uRUUeGT9nmjYVBdYBycqiq61fSVTyBDFZoxrEpibkjM=;
        b=L4x0W/n1NMgQMLJVNBjzetL/hOlq8EpOEDy5uZs8cuo5wgrYdjIQ2kAw12VI1Rx5SN
         N3y98NwE0VWmiAENpatqgp/gZjRh1zdjISbdEP7T9SLDyexbfYcQCAEY3ykQpA0X5PJk
         ryz/b80qsj9tNNbwCK/S0NrvnfhlA6DA4Al/goeIiBgXOJhx4v66v6MJdpJ85JQYN3Hm
         MKbwsqa64ytnawt0Zwd7c8SaX/rX3ZWPa1eD99Pw/ZYbLEjeghDsIUkj1tPLYlWQJXiG
         kR8frzHb2LWCUAZCTA0cgzIa76TmRtEhli/ljpaAheT+iYRwQ0ZN43v8iZBd+En45xsZ
         Ju3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726250937; x=1726855737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uRUUeGT9nmjYVBdYBycqiq61fSVTyBDFZoxrEpibkjM=;
        b=oUstDHWA1DjrjEG16LkKGnzHdQyUL+ZS0JTL+1sqNDg1xWpXjcI6pH5lObn1Qll0HL
         Z53wqxea87l4VAoIZyRuPR7M5jiptp7qwANWn+LoXf4/myWBreK+n4Fstyb0doiQ6289
         wQ58er0bRDyvsanugnZcaY60q7Yx45U+/EGGPA/aVRIzx8B4cL2gYU7tBo0LjrgmU7vN
         WSYoWeorRoiGAU99RGFz0SEKP2YRa2/KM7mdh22h1hk6cL3hs7QNLC1LC5MnpiwvtOxn
         Ia2FIxhvJMwYEz8hd/IBYfSFKToWA054p48Dues1VPBD5MpzmGBEHt+A67rdkL+hJNPf
         t62g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWi7YK6Y6iqcC7sjiR2m8GG8aK/glj/Xo3PljU1HlTCK3z4kNwWrUNWs+9zwnq6l7+EiskKw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0IijXa+92FHzFhXh7gLDywjnCUKUcdrY5Tcxpa+UWyvW18NPT
	uHBTXGSBlSJK7RocVP5S6HzwCC5M/4jjh50iskBxnzq05ZHTxASb
X-Google-Smtp-Source: AGHT+IFeQvcUmPKZrIdXcmCZlj+sWJWIr7AiqONo3h9+UXQIpEDY77HvkVMxLvwGin+g61L3wj9w5Q==
X-Received: by 2002:a17:903:24e:b0:205:5d12:3f24 with SMTP id d9443c01a7336-2076e347618mr112210205ad.20.1726250937268;
        Fri, 13 Sep 2024 11:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2287:b0:206:a24f:b08f with SMTP id
 d9443c01a7336-2076cb0f4cdls21083825ad.2.-pod-prod-03-us; Fri, 13 Sep 2024
 11:08:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMPriAD3YN+j6RrGZlwKtrhwokf369TnAngwGvfkDO76w+NkraWS9vpZxk3DGt0nVakXhqtclAiho=@googlegroups.com
X-Received: by 2002:a05:6a21:1191:b0:1ce:d08c:2c10 with SMTP id adf61e73a8af0-1cf7615c25dmr11740399637.28.1726250936071;
        Fri, 13 Sep 2024 11:08:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726250936; cv=none;
        d=google.com; s=arc-20240605;
        b=HIKGXGRaxSlX9fctD4S+vREaCU30+o2GNGe/mbP3Uvoz/9ameeoiG0yQ0czDLqbe2m
         rcsduCN3Qa/eJBez9TcKP6DZYz7ao/LPJpzTFZQ+1pmLKUfpDIuWtity2xCWNl1Vx/pN
         cH81NUz6xawoy/wV30QUfKGKZZ+4XOMY9HdUlTDJsBGyVlDajxgVOMftNs1YzmVQ//lt
         tXu1m2JNutkC/XfWNJF2t90fUKiB1xx9Y8y6M3VQMkKbcrZfKrDQey/LoVXqXuqSQ6eb
         Ewt6f3Q2CrQew0PBmoX3+Xe6rhtcbylJ3gepT1OvdzI8FkwnPHWoT5gOBruqFDmtfCdC
         5Usw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0ZnA3erGKxX6kl7LXrESncIv3ytuXvzogy+s/qD8NvE=;
        fh=IVJq3U+poOZFjnozna6pftnvAqoMTKEprgSo7LP2KCQ=;
        b=L6sailKNQegL9qLSqTX+sTdyPG9SzVZ9xEhfv7PQdHuNoev3h7MgLQjm+lXT2Qv3+f
         nWqVwdAcdIp8cDteSgEB8R/nMzL1+6EDMwFeO1JGu2aIAODLheF7/8DhTyRn/QMInGjH
         q78QE2p4XpPbXh5aALwDTwpSCW0E9dOnk9g2hVylKVW/xQIekwZfe1tuqtDaOXnUqS0J
         sa1vXFk14ftQOUflbDViWHWsieCoznlK1tp8X6XdZjUESb9LsxswS0yUKjqV2BhmVvJQ
         tgAeZKjvPRtTY9KnyD9D03i0gGT4vYTi+HRUh/vJnE8UyIN20JdZrvHvC9tVke3euPmp
         UTDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=m7bPJ9zU;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-719090e8fd3si461407b3a.3.2024.09.13.11.08.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 11:08:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2055f630934so22592285ad.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Sep 2024 11:08:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVvAsfwW4aFdxlUtsOTH3w0vpG6X9ziBcNGXcnZxgCHATJLZrFkwWtvNWTLOIfXavwhkN93HuTFcig=@googlegroups.com
X-Received: by 2002:a17:902:f550:b0:205:4e4a:72d9 with SMTP id d9443c01a7336-2076e30651fmr127545975ad.7.1726250935453;
        Fri, 13 Sep 2024 11:08:55 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2076afe9a75sm30468575ad.211.2024.09.13.11.08.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Sep 2024 11:08:54 -0700 (PDT)
Date: Fri, 13 Sep 2024 11:08:52 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 00/10] riscv: Userspace pointer masking and tagged
 address ABI
Message-ID: <ZuR/tK+9cKUXqDga@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=m7bPJ9zU;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:22PM -0700, Samuel Holland wrote:
> RISC-V defines three extensions for pointer masking[1]:
>  - Smmpm: configured in M-mode, affects M-mode
>  - Smnpm: configured in M-mode, affects the next lower mode (S or U-mode)
>  - Ssnpm: configured in S-mode, affects the next lower mode (VS, VU, or U-mode)
> 
> This series adds support for configuring Smnpm or Ssnpm (depending on
> which privilege mode the kernel is running in) to allow pointer masking
> in userspace (VU or U-mode), extending the PR_SET_TAGGED_ADDR_CTRL API
> from arm64. Unlike arm64 TBI, userspace pointer masking is not enabled
> by default on RISC-V. Additionally, the tag width (referred to as PMLEN)
> is variable, so userspace needs to ask the kernel for a specific tag
> width, which is interpreted as a lower bound on the number of tag bits.
> 
> This series also adds support for a tagged address ABI similar to arm64
> and x86. Since accesses from the kernel to user memory use the kernel's
> pointer masking configuration, not the user's, the kernel must untag
> user pointers in software before dereferencing them. And since the tag
> width is variable, as with LAM on x86, it must be kept the same across
> all threads in a process so untagged_addr_remote() can work.
> 
> This series depends on my per-thread envcfg series[3].
> 
> This series can be tested in QEMU by applying a patch set[2].
> 
> KASAN support will be added in a separate patch series.
> 
> [1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
> [2]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
> [3]: https://lore.kernel.org/linux-riscv/20240814081126.956287-1-samuel.holland@sifive.com/
> 
> Changes in v4:
>  - Switch IS_ENABLED back to #ifdef to fix riscv32 build
>  - Combine __untagged_addr() and __untagged_addr_remote()
> 
> Changes in v3:
>  - Note in the commit message that the ISA extension spec is frozen
>  - Rebase on riscv/for-next (ISA extension list conflicts)
>  - Remove RISCV_ISA_EXT_SxPM, which was not used anywhere
>  - Use shifts instead of large numbers in ENVCFG_PMM* macro definitions
>  - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
>    since it only controls the userspace part of pointer masking
>  - Use IS_ENABLED instead of #ifdef when possible
>  - Use an enum for the supported PMLEN values
>  - Simplify the logic in set_tagged_addr_ctrl()
>  - Use IS_ENABLED instead of #ifdef when possible
>  - Implement mm_untag_mask()
>  - Remove pmlen from struct thread_info (now only in mm_context_t)
> 
> Changes in v2:
>  - Drop patch 4 ("riscv: Define is_compat_thread()"), as an equivalent
>    patch was already applied
>  - Move patch 5 ("riscv: Split per-CPU and per-thread envcfg bits") to a
>    different series[3]
>  - Update pointer masking specification version reference
>  - Provide macros for the extension affecting the kernel and userspace
>  - Use the correct name for the hstatus.HUPMM field
>  - Rebase on riscv/linux.git for-next
>  - Add and use the envcfg_update_bits() helper function
>  - Inline flush_tagged_addr_state()
>  - Implement untagged_addr_remote()
>  - Restrict PMLEN changes once a process is multithreaded
>  - Rename "tags" directory to "pm" to avoid .gitignore rules
>  - Add .gitignore file to ignore the compiled selftest binary
>  - Write to a pipe to force dereferencing the user pointer
>  - Handle SIGSEGV in the child process to reduce dmesg noise
>  - Export Supm via hwprobe
>  - Export Smnpm and Ssnpm to KVM guests
> 
> Samuel Holland (10):
>   dt-bindings: riscv: Add pointer masking ISA extensions
>   riscv: Add ISA extension parsing for pointer masking
>   riscv: Add CSR definitions for pointer masking
>   riscv: Add support for userspace pointer masking
>   riscv: Add support for the tagged address ABI
>   riscv: Allow ptrace control of the tagged address ABI
>   selftests: riscv: Add a pointer masking test
>   riscv: hwprobe: Export the Supm ISA extension
>   RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
>   KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
> 
>  Documentation/arch/riscv/hwprobe.rst          |   3 +

Would you be open to writing documentation similar to what is available
for arm? https://www.kernel.org/doc/html/next/arm64/tagged-address-abi.html

- Charlie

>  .../devicetree/bindings/riscv/extensions.yaml |  18 +
>  arch/riscv/Kconfig                            |  11 +
>  arch/riscv/include/asm/csr.h                  |  16 +
>  arch/riscv/include/asm/hwcap.h                |   5 +
>  arch/riscv/include/asm/mmu.h                  |   7 +
>  arch/riscv/include/asm/mmu_context.h          |  13 +
>  arch/riscv/include/asm/processor.h            |   8 +
>  arch/riscv/include/asm/switch_to.h            |  11 +
>  arch/riscv/include/asm/uaccess.h              |  43 ++-
>  arch/riscv/include/uapi/asm/hwprobe.h         |   1 +
>  arch/riscv/include/uapi/asm/kvm.h             |   2 +
>  arch/riscv/kernel/cpufeature.c                |   3 +
>  arch/riscv/kernel/process.c                   | 154 ++++++++
>  arch/riscv/kernel/ptrace.c                    |  42 +++
>  arch/riscv/kernel/sys_hwprobe.c               |   3 +
>  arch/riscv/kvm/vcpu_onereg.c                  |   3 +
>  include/uapi/linux/elf.h                      |   1 +
>  include/uapi/linux/prctl.h                    |   3 +
>  .../selftests/kvm/riscv/get-reg-list.c        |   8 +
>  tools/testing/selftests/riscv/Makefile        |   2 +-
>  tools/testing/selftests/riscv/pm/.gitignore   |   1 +
>  tools/testing/selftests/riscv/pm/Makefile     |  10 +
>  .../selftests/riscv/pm/pointer_masking.c      | 330 ++++++++++++++++++
>  24 files changed, 692 insertions(+), 6 deletions(-)
>  create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
>  create mode 100644 tools/testing/selftests/riscv/pm/Makefile
>  create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c
> 
> -- 
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuR/tK%2B9cKUXqDga%40ghost.
