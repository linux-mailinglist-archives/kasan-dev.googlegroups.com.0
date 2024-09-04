Return-Path: <kasan-dev+bncBDFJHU6GRMBBBBNH4G3AMGQEUOV7HBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 04D7696BC61
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 14:33:12 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-7142fc79985sf6578511b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 05:33:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725453190; cv=pass;
        d=google.com; s=arc-20240605;
        b=eI7eU4ga4krMZFegxa1FDOax6m+OrtnpSfGX9hb+xTWR2ie9RW56KRMUy5ErJkY48v
         rUJGGBalwsBo9WsAxoGTQmTC28QjH8oUqPSnD2+IVgH/1NIBCw9p16cQS4v6X8vzP6zZ
         x4FawWE+p/xVECZ6UN3HVf5KdhOQp7ljC/6XOd+parLvYPtgusRZDE64l9+H6ySBVKe/
         2rUXJ9AqV5XylXcdstqZG6DD+9OcqbnEDyKVEnq99OmPwdGM0TnvDT+gxaJDyRhrJvQv
         SbJIkoHu8kFFJnkLJv3/fcOf5diNBFsvEwS76Tqm99ltwwfKA5UG7T084OxB2Pe00XjL
         wRJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=4oD7uca10xHDJqTY0XvxBa6A+4pCjBv9OWzcav4c4jQ=;
        fh=Bj6bEPmf1shFkBAAYFglHNCp0hjlE4B1K0L+5NsRKZI=;
        b=SQPM/Lpg3bthYaq+ntZVbiueGmTJlEz/eeqzUsOEM4jaG/FqNkXspsF3t+u50JNXFw
         99ZBwt4Ht8mytwNymi0l0zYGu9FRHA4AbF7m8l3TNtve/IUhAM+6rkkD5BDgmwXU0vh8
         695Miw21dMrjKJgmNoBIE0bubt9DkfVz+EJvBbPEZ2w08TsImxx6O+V3Jc/lvmHn8gV+
         +KRZuC2k1adPfsh6V1QHYaIwAM865P3iJ9QMwDJXZTnCIysZ7MNaBU+f7RSY9BCOhupx
         MOj5+sDsqQ5vh+g4FbNmdWg20QquQyuN6D9++16fWiBmW+GwNS/u31xdU/BOQ5kCj0hI
         YMpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=kB59i7Wc;
       spf=neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725453190; x=1726057990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4oD7uca10xHDJqTY0XvxBa6A+4pCjBv9OWzcav4c4jQ=;
        b=Tkif0ZwnbiZ/5Ykq4IKUKhlb4tAKhZf62Rw7DMAeJSiMkvtuZWpCruKbFYHKODmbw+
         xpxNNmLoR2AjWm5Xb//JM3n8XQ7fuYxB/S47Olvb2skjGyFoKUCp2UicHmNQEuhOxjmH
         27F8Op9tPrGoJIWnqsORFnz0dNoLiLQn84n/h5Hn2/ZsyqxVcaxwrqdMcrH0o03RN/y+
         8ijOmiBte06O/mIJd5EZd4e4907TYRLs2lzfDlMbNzQtC7qA+75b/TSI1U9cnTMBI1rB
         svQoLJCalvOLRgCcR1MmSAeqv9gTZnHUNiwFynM+3Kfgw98XbezACTwjLqabR+N1qg99
         p/bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725453190; x=1726057990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4oD7uca10xHDJqTY0XvxBa6A+4pCjBv9OWzcav4c4jQ=;
        b=vZWtzp+tqJebUEyrNTXUiM1cidYZzUZxrdMMVMzyPUIsSC+o5pQWux5/yYzM0GQS+H
         fcMB69O6aJamUAMDl8WKBnvrFl/wbI8x3OUjSsjOJJ0VHMr3be/lOEDRdp1qhWrghxAe
         +WHA5HzkYnPuexSxWqW36Si9FrtcLiE4vJaC/7hycTCSX31iVeNRHQAJ1awQWzoR3uTd
         yInSwC851oMlyY9ScPWKzm4G9dMq6jM/f7h11z4cA8HDUM45nmRFYkI6E+vWeQkS3kyv
         QYwdSHnWuKkuM7uwbedh2XEkJ8T+0YNAzCVpZzDoMavoK+cxp/VjVc0bOyJcfLFoLJjp
         9W4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUWrmmAmaji15hfrilajBJR20nC08UMiawyNGI0HQvQjDWjSVnalYvts64OX8vHQm9/l/tWdg==@lfdr.de
X-Gm-Message-State: AOJu0YzGRd0xtrTsh+hqsBYJXb+tPBJABf4ZC/dZbiNjp2LY69HiU9+4
	/GODGQbnqeFeBKuvIQOrCuvNt0IeW8T9v5dmH47ZNDVyfMfLSN9H
X-Google-Smtp-Source: AGHT+IFsVPtHBU1bz5WKQQUI80bs98eOOwtAZHLp0JYtPhenQFRWs1Z1agYsECT9WtCVdIPlse+krA==
X-Received: by 2002:a05:6a20:4389:b0:1c0:e997:7081 with SMTP id adf61e73a8af0-1cecdf2e14amr17654309637.29.1725453190023;
        Wed, 04 Sep 2024 05:33:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a24:b0:706:a89c:32b4 with SMTP id
 d2e1a72fcca58-715de43b239ls4397736b3a.0.-pod-prod-06-us; Wed, 04 Sep 2024
 05:33:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdI8Fg620nk5YtU8a6WW31L+/sg3nqtH4JwW0nmWN8hiLgzNcGCpHtwa5lxu0fDN+QlMSdDgdQ1ho=@googlegroups.com
X-Received: by 2002:a05:6a00:2ea8:b0:714:3325:d8e9 with SMTP id d2e1a72fcca58-7173b690c1cmr18145574b3a.22.1725453188664;
        Wed, 04 Sep 2024 05:33:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725453188; cv=none;
        d=google.com; s=arc-20240605;
        b=Ntj3Ghqrl+7WofpAO0tj0QMhMTMdZz5EKpgYR8eniIdjVf5i/9xJgemXyqrlwKCwDD
         8it1BuZPicWBxA0YPHcc9DkDDYmbMTztoVYPnatvCbR/nHm0pEdvKrMgx2ix3d+4KmE7
         yvStDals/Km14gINnr5L7NUPW901ezW7/5Z464cMrk/MOLXCBzqeKSIJkwKUFpVy4wiV
         NHracQGnQrnAiJQjBuR0zjKGmdmoOpyZpeYASrDJ/4ZNI3VZsOsCLBqMGf4+b7GpAVTj
         kDpdrbDfTnCCI3Tp2BiOwnK3CPlXk4vDr74n3tw1FxBdw0S0yvmcTGzdfyjUODHw9Ne3
         B3aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6ZsaBihnC5N+75Ve3rV3kB2kS1uqP0/r3+HmOHWQjaE=;
        fh=Zm7NCs/Jf5JL4sYve7h4EM4f3AXGiq7aeq0x/xj/Za4=;
        b=XgZX/qxyFbviqwqly3T0JPhni/y0fJXNsZt6nwJqj6xyVd/90pvziXanRiiWCiTys4
         OlSQOvsgLXiRe5B1/Tt9bP4RCFB+rhwxm45+k7W1oLb2vPDOhVIAkUcTqySSrUz1mxOD
         0PUmSSrH1Al5ESF3DfD+FjHri15w2Oj4VdGRJZ/32LMQxsSq4PIjCMO2g8JiZfrrZ2Bz
         AXjNXpbf3E7qMPCSHyjTeufgYU8X4hFZNUeQ/I+DydbOTYwIWupo5cwMKeV3PvUWo6IM
         AvDmy3jMcPkOSlabfGlSQjP6E5VJTPXoENRbh1RvEUWbdyT7zKYJuyXSgVRUfiYT+3es
         cJmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=kB59i7Wc;
       spf=neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7177f9c462csi29130b3a.1.2024.09.04.05.33.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 05:33:08 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id e9e14a558f8ab-39f37a5a091so21636035ab.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 05:33:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXOj3h4gegY4JDX95hO+3ic4pN4l0Y+T5A9WEIEhT2DA3iB9Wp6yJ60IWaBtYXknQNZzL1sxERxCVQ=@googlegroups.com
X-Received: by 2002:a05:6e02:2146:b0:39d:2a84:869f with SMTP id
 e9e14a558f8ab-39f49a1ff96mr164451425ab.6.1725453187950; Wed, 04 Sep 2024
 05:33:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Wed, 4 Sep 2024 18:02:57 +0530
Message-ID: <CAAhSdy04aEg35j3NTGOz5Gs_wPP3PBuR7sKbvosvQ1jFFGE5sQ@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] riscv: Userspace pointer masking and tagged
 address ABI
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601
 header.b=kB59i7Wc;       spf=neutral (google.com: 2607:f8b0:4864:20::129 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 29, 2024 at 6:31=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> RISC-V defines three extensions for pointer masking[1]:
>  - Smmpm: configured in M-mode, affects M-mode
>  - Smnpm: configured in M-mode, affects the next lower mode (S or U-mode)
>  - Ssnpm: configured in S-mode, affects the next lower mode (VS, VU, or U=
-mode)
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
> [1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer=
-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
> [2]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliv=
ersmonkey.space/
> [3]: https://lore.kernel.org/linux-riscv/20240814081126.956287-1-samuel.h=
olland@sifive.com/
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

Please CC kvm-riscv mailing list for KVM changes otherwise the
KVM RISC-V patchwork can't track patches.

>
>  Documentation/arch/riscv/hwprobe.rst          |   3 +
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

Regards,
Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy04aEg35j3NTGOz5Gs_wPP3PBuR7sKbvosvQ1jFFGE5sQ%40mail.gmail.=
com.
