Return-Path: <kasan-dev+bncBCMIFTP47IJBBNUV5CXQMGQE5ZFACSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D703F8806F9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:19 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-dcc58cddb50sf9727566276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885558; cv=pass;
        d=google.com; s=arc-20160816;
        b=R1GVWFyGvPxKNrYlB7EThILWYtuChK3w9bzNysvLDMsMFPSpHeZUJXb9X7R4b1trtN
         y4ldnBey8GSuBZ3pFRvMtEcXOL2D5sX2H6XELgKvvk1PRo6pHdL94pWhZYdo8I8Q0k2b
         fHCd5ili25ovttEvK/64vWcu2iQOYZFvuINM2nqOCA3AxP4z9mB/lTLO84JRjSDVPtQ8
         DdGPQb2nG13v8EGJMwOcEV/ZeZEArLot4pS61WBDmIyp0ttGjXTpwHZ5JLgKuRMN8Gmo
         stIzj4Q1hYAu2dWD0idJCv6GoO/pBQ4vQtKFICDUJdOwxH6+RlUM9mU9ZhmEFbU2vGf3
         iorw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=eP+epYpzUPKyqyST6rXc4nbiMclHhWJ/bO7ofEuOpHw=;
        fh=eA20SBaNR1H0VG9NYdY9e7id4TGKg3L+9jDVFwjwnVg=;
        b=ccUJ+vXR/BsOYaaTmZwvtQMmETr1n/WI8ah1E4KVXV0MvlE1gDQ+Px/ueiMBcA6fVL
         PtZ0uSE575RlU/7g0S0u88ex5kDDr7XOgRb9qnN9H05r8SbPsjwpSBXLQgfCb7q++Xw9
         8IetHeW7MY4c8I4Xk6s1GhcQiZC0Ycn38gO8lKMTlOkKE6fx7JFEUXu4DfVTLyBBrBCJ
         17rIL9SU16NU5tNVzh0LHn4GuoOTi9ZBSSHhS6ZmGnhncrs29giAIkY7a7V/nUgVcLJ4
         R6jdJAg8x75N+cQ8v1xuVzNmYUgl/cMLIKHa1+ZuoGtwFFjdytqM0jP5Lzsp67JggVKA
         Scww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=aODDGSiX;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885558; x=1711490358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eP+epYpzUPKyqyST6rXc4nbiMclHhWJ/bO7ofEuOpHw=;
        b=wvhQMShQnKsVVO0+oKek8SzpBZVJoCZB85MWl3TkAEBC9b9VmBp4t2VVHIm1NakHBw
         7v2ocNHzWfTFSNEAR8iqnrSy9aqyrnkDR0FaWmQYcFa/6tdV0g38l3dHJAPQDb5Uv4Vr
         sGEDT+lES5+y68yGUhNbyARbsBQxXJ33N9MfMNmU3pWNvcQcPg/DqfBukN7solWQcGKq
         yDQryQmZtO/I+N6Vdv90whB81GiNpPxYxl2YUAUn8i21Z3X5LEeaQvX1g4l8H+ehQOj1
         FimC9QkCsLDBI8CfEFIqK0V4rcLawjdPFlmdowUg2pa2V85G+D8c1rgx9F7rOz3axnFd
         dJhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885558; x=1711490358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eP+epYpzUPKyqyST6rXc4nbiMclHhWJ/bO7ofEuOpHw=;
        b=e16c2NbT9pwsMOhCdKq7yKA60giHaCXHHU+aiFT0deipg+BtQI4CYjy20C+46kpZR6
         RJRn5qgxxf9Q7wZa3QsEzkEXSscu1vVEJxfFD26JS04nE6kk5SGno9gqwBitV5v6sQW6
         C1HhcwL2bI0GIu9a+86f4W7K59BIeaDHq4ax5Ks/PQayAMbRRilP5ggN7B4r4bMi7uYA
         GXJIoNFlmUb04Ztf8+fjv66LN11Plndao5pVEuLXz1ySZcP+VyhLZlksIKAnVFU9R25j
         IDbswPLM/mRbN7FlWoWHSWrMifYrlx1fyzjJHnRVfgUinl/FghFfAjUUWT8U3xPrSyjI
         Il5A==
X-Forwarded-Encrypted: i=2; AJvYcCWfsH3skHT14ZzGrI623pXGWjrdhXl9yolttcR8b9LhRN2yjwgPaaMLHCuAgtKNw0iseO0i0zuo820ZYlGQKhSp7XRGdgQC6g==
X-Gm-Message-State: AOJu0Yz/M0V4Kqq4zGdIij/FBn8vEj/jJWiQERyzmCtjelD6iZvym76N
	esX6pc2/wGGbZLnYDqbqAM+YwLP+bL4jDMt1WKLc+o6kOAATiPzW
X-Google-Smtp-Source: AGHT+IHt+RBypVDPHpQcXlqmS3lTaMzmHHSjMY/1dTJPkK/ZHhJgc6hWvbFrHw9W56I31DNYWUBnQA==
X-Received: by 2002:a5b:24f:0:b0:dcf:2b44:f38d with SMTP id g15-20020a5b024f000000b00dcf2b44f38dmr218969ybp.49.1710885558393;
        Tue, 19 Mar 2024 14:59:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa4b:0:b0:dc7:4363:dc02 with SMTP id s69-20020a25aa4b000000b00dc74363dc02ls2636085ybi.1.-pod-prod-06-us;
 Tue, 19 Mar 2024 14:59:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnvaGxqS5n9dpC5snucgBCqGIE1rjfVBITPjZVgDJh+vsrpBuxHRlwIav5QtWJq8Y8ji3hLz6XXjSsRXSU6unqB+AsVIUsqeqwDg==
X-Received: by 2002:a0d:e28c:0:b0:609:9a17:e937 with SMTP id l134-20020a0de28c000000b006099a17e937mr265435ywe.48.1710885557386;
        Tue, 19 Mar 2024 14:59:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885557; cv=none;
        d=google.com; s=arc-20160816;
        b=WRDrTRQ/SE6F6ALV5YCdHXqfk5ofQGC8oLLOSFAcwtujpGfK9vzFEb1jAtiKulfmY5
         Kxn6zUQyg86uAKtq9tN/o6l3CJ/Xj1ECLnKT+70EyHC6jDPkCn5A+QbTlQn2yZff/ZSt
         ZjK36qyE3kP4u43ITp9nymQAEnrJT8v2JJtdayyinRdnBRf2W1EchkyOjCJj0w0wjpXD
         9NTxXEJTgZwDWZrjuhT5r8opILIcdMLXfDnvlkUjkNoUsnrDnd2aYBFm/UnvgfWv7ByS
         orilKJPyYSTC/tTt3urE6SvHf2fcp7KU+prQPGFrUVfcXGK3/wuf2I90zgARcQTQcJh8
         bN5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Rmlb8dkFyYxdz94/c3CDo0QI5YbaWEmRF37tY2/vORM=;
        fh=EN/UEapNsJXrW6HGPHinkBKpebvigLfgXeLmj1B+x8g=;
        b=i0+uOys8NxqYGMqj5+fAma3fTMJd6pNhLYgjsliu/OQRk0TwnOUj7GniujES2DivVV
         Xa4RGTTSjYHe/XuXXM/PtRND0o0CLqmMn2GVmVJ0oYkFsBZnnkYp4QA6Vc5I1Cr5n0P/
         WhKWRLxUKkOQYIhnJgpMRAqXnXG1TDnIKx0WgxrkW6xk0K5jBmyHMSwb7Zx228V2Mwi5
         avCI8FXYM3+9iCM+Q8vRSoryDbDc0QrgK3A+nMNb9uRBhN0KnnNeH93lxY/wHMwrRU2f
         EuXKFuaeh+DIk0PB2romKZ611hG1PMZmDSi15QbJeAErg3W8ZXUvCkmJjmaprMGG4llP
         22Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=aODDGSiX;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id t18-20020a0dea12000000b00609fe86a0a6si1433677ywe.2.2024.03.19.14.59.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6da202aa138so3271745b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCBfrSz/ZQ7QK2z37WXMBwLUVM5tn+oXaib0+8e3Jwo3BAqPrCnKMM4fDaTccCHtDSls9gQglFkpWKrLhuHFkEOM2LkPJ/DjzFUw==
X-Received: by 2002:a05:6a00:a22:b0:6e7:4abe:85a0 with SMTP id p34-20020a056a000a2200b006e74abe85a0mr457780pfh.14.1710885556934;
        Tue, 19 Mar 2024 14:59:16 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:16 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrew Jones <ajones@ventanamicro.com>
Subject: [RFC PATCH 0/9] riscv: Userspace pointer masking and tagged address ABI
Date: Tue, 19 Mar 2024 14:58:26 -0700
Message-ID: <20240319215915.832127-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=aODDGSiX;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
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
 - Ssnpm: configured in S-mode, affects the next lower mode (U-mode)

This series adds support for configuring Smnpm or Ssnpm (depending on
which mode the kernel is running in) to allow pointer masking in
userspace by extending the existing PR_SET_TAGGED_ADDR_CTRL API from
arm64. Unlike arm64 TBI, userspace pointer masking is not enabled by
default on RISC-V. Additionally, the tag width (referred to as PMLEN) is
variable, so userspace needs to ask the kernel for a specific tag width
(which is interpreted as a minimum number of tag bits).

This series also adds support for a tagged address ABI similar to arm64.
Since accesses from the kernel to user memory use the kernel's pointer
masking configuration, not the user's, the kernel must untag user
pointers in software before dereferencing them.

This series can be tested in QEMU by applying a patch set[2].

KASAN support is not included here because there is not yet any standard
way for the kernel to ask firmware to enable pointer masking in S-mode.

[1]: https://github.com/riscv/riscv-j-extension/raw/a1e68469c60/zjpm-spec.pdf
[2]: https://patchwork.kernel.org/project/qemu-devel/list/?series=822467&archive=both


Samuel Holland (9):
  dt-bindings: riscv: Add pointer masking ISA extensions
  riscv: Add ISA extension parsing for pointer masking
  riscv: Add CSR definitions for pointer masking
  riscv: Define is_compat_thread()
  riscv: Split per-CPU and per-thread envcfg bits
  riscv: Add support for userspace pointer masking
  riscv: Add support for the tagged address ABI
  riscv: Allow ptrace control of the tagged address ABI
  selftests: riscv: Add a pointer masking test

 .../devicetree/bindings/riscv/extensions.yaml |  18 +
 arch/riscv/Kconfig                            |   8 +
 arch/riscv/include/asm/compat.h               |  16 +
 arch/riscv/include/asm/cpufeature.h           |   2 +
 arch/riscv/include/asm/csr.h                  |  16 +
 arch/riscv/include/asm/hwcap.h                |   5 +
 arch/riscv/include/asm/processor.h            |  10 +
 arch/riscv/include/asm/switch_to.h            |  12 +
 arch/riscv/include/asm/uaccess.h              |  40 ++-
 arch/riscv/kernel/cpufeature.c                |   7 +-
 arch/riscv/kernel/process.c                   | 154 +++++++++
 arch/riscv/kernel/ptrace.c                    |  42 +++
 include/uapi/linux/elf.h                      |   1 +
 include/uapi/linux/prctl.h                    |   3 +
 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/tags/Makefile   |  10 +
 .../selftests/riscv/tags/pointer_masking.c    | 307 ++++++++++++++++++
 17 files changed, 646 insertions(+), 7 deletions(-)
 create mode 100644 tools/testing/selftests/riscv/tags/Makefile
 create mode 100644 tools/testing/selftests/riscv/tags/pointer_masking.c

-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-1-samuel.holland%40sifive.com.
