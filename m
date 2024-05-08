Return-Path: <kasan-dev+bncBDXY7I6V6AMRBR5A56YQMGQEJSOK6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C94918C04CB
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:19:36 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-417c5cc7c96sf313585e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:19:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715195976; cv=pass;
        d=google.com; s=arc-20160816;
        b=tBDZ1SDkHme7/3twOVx0/3stO+gdIloA1e6Xha6gKGxr4H8v+Rv6MUPNUPzB10HnZH
         mK3VSFw2HdwXuCCZo81UQHYIyvu+dBlWjPs/FTNbchPIdO8m3MnRoV/EIxLHklLW4OBS
         ry8Yvs7ZgTkwajfxG4kGOmhtg9Q4yxtcboDlhKXgqD/qAaSjWMkR3eAvburVOeqYDhCt
         gyIeZ0Xf/z4+A1c8hBF4lzj1pRyBTCZXpXzZ/7V07Qlw33pLsDzrl033BqEoK2SEZkMH
         qVnzpDjaR64e1noDb6Pb7LbJ3aE6p/I0hhmS4jDSVfUGtHUqzT7sHTCeiePE1uL4gZXl
         42uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qzXVOloZJrqp7W1pJIUJsnSmEV+OxxALvEaMbYe9YbA=;
        fh=iQkiecD0GviH0qnrTWElUtOoFjIffBSrDOPm/zqREMc=;
        b=bLdDP2/Mr5brLk8u8eiLvQ3AW5UsdhzMX0O5f9GLam2hJP5S+dhqjgxqnuo9228WVH
         9SvMEPFTjqGfpPifI3Acdk1LDJAInmyAtSNuxvKqzxyjYP3kFt+L4LU/AmUsG95uTdCQ
         T6oNQRhvn+l5JrzgC7LiINFq+aGjwQvOxU0Ybr9WN7qZ8ue4hSTDOiKw7KLEzVcAMFlP
         o+Qig2bz3RJtdLZh7b28FMOFXOJLRbfSUXW2kgW5pmOIWpY904+qrbGJJQsLQqpYtFuJ
         9ksna/8tbUIyiKABjCADtn7ZjpspAMSAsPaEGaoJhSHmeyem+6YyX4WQ765msXpQ/HQH
         mUhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=YY8Fujar;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715195976; x=1715800776; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qzXVOloZJrqp7W1pJIUJsnSmEV+OxxALvEaMbYe9YbA=;
        b=WLf88+rdrxB6K4e5ECVjDgFHXmRk2tMtgWzJKYX86Gnx7AzhVt6PmnnHJdeylRSiUn
         kC5J66uvHXmV8NKZdnUUHY968PFNzveTprvZ2lyqxaQ9Cd1eEP+q+SC8UMem3IGd8qfG
         +Md0gH9+B15uv2A1c3LUkDIWpAQzvCWbDdyttbGdmcPv7IZ7TzTH0JGENR+CWoXGErLx
         l8P2+Dq4miDD2FkWKA7HysKnzMEq+Rdqm6JtNdP0dZ8iMNRul2Uyuan2MTGZvtjhMctk
         /sLnY/6TgATzlo19fH2fe3lTi/ZGj//RJ7YbTMbSg2b6a3OEiQX5ftQlI3w/z0RGl3tP
         H0Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715195976; x=1715800776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qzXVOloZJrqp7W1pJIUJsnSmEV+OxxALvEaMbYe9YbA=;
        b=octW//NEQVXjfCHZ5aF7FpKiKxMe8AhjujSxPO0DyYd86RbxphxYjp0VwPp93lrVdh
         RatAk8OZRpEn9zc1MiuJ30Y/cBS7z97UeIJqWFwP2SJn07WUiqp00WzGEGQKAYQvUSJJ
         IxbJs5njBT3Yb83rosVe7qfyhA6yp8hf2+cZC5RurjIlvQgacFzRjIabaRxMNQrYnnx+
         hY7GuJxnaJzbVfm+yiPgvs5m0M8GYn4quUvvrh6NQUn6g67bz/AQgTKOan5qWv6unbFj
         BAEZd/29AOZBb9vwd96cNpVgNxNqxf+pWTyhrdFc8UwZ0j4RuNPxQcTEXKFOBryCTeRh
         JfiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCViTtBlCxt4qxbAsJrx8Fb+MyGDVMrb87g7BOFtH2XAHp5SBcds5+/O9KRTsg2904FqxOrtsGZuXduuZAXEV75lsMKisjGcRQ==
X-Gm-Message-State: AOJu0YwKhlsXcOI+Pry+zom4bskSUUEmBsb/4D117fvnO3H0ceWx33TT
	XkoqwqONm5yqRqVsU0R/7d9h7QpA6P5dWWnQRqajZURrTI8ycONx
X-Google-Smtp-Source: AGHT+IG439pkHaIfE1m/VBv0/cLqQcQ1bEG/0jKGMRpRs5wfFBCgitVxqAoYr/OKN2ovPcRlzUbt1g==
X-Received: by 2002:a05:600c:1394:b0:41b:e4dd:e320 with SMTP id 5b1f17b1804b1-41f723a0c63mr28491945e9.26.1715195975656;
        Wed, 08 May 2024 12:19:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fcf:b0:41c:259:11e8 with SMTP id
 5b1f17b1804b1-41fc20ecc5als448245e9.2.-pod-prod-03-eu; Wed, 08 May 2024
 12:19:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuqzEDLit24wmWHybd9MaUklLy2LvqAYbyJm4vDhpNkvdjbED5W6J0i1KFsJLPRRPM6pTTwJLTSZM1Y17psI0Sz2Puae4rNbMKnQ==
X-Received: by 2002:a05:600c:46ce:b0:41b:e609:bc97 with SMTP id 5b1f17b1804b1-41f71cc1512mr27964695e9.2.1715195973732;
        Wed, 08 May 2024 12:19:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715195973; cv=none;
        d=google.com; s=arc-20160816;
        b=DEh1D7FjgSHkEyMU5o/3KjW/Uf8XgR+HnbuH+yiyTkWhM3LVgZtC/3YQ6LhUUNUWar
         hC0aNdgxoy3L8S/52V+Yq9LWdWvsTHWB/VPHVkfYkWOrkyf1B2xkShZYOhU0wGYoi+Q/
         +WQTD73w9lWNo1CXo8oNrHI7Qt/Z2nOtuJM7R7V3TMVnEMs5uwEFB5DiJ3cmLi89lrme
         xnJdZSH8dVanHTKzCPXz5l9oCs826VgRWj92BtudyPiI08D5mHSCUHnNCdRC9dENY9Rm
         m1mv0RYZC8Px1a52dT6hVaLkxk6lU9R5Xs6RvPeEbArVfwdtY1kK02lNR+u+dUTV/5e5
         /BAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=K1uKlYjMTe4xfHBkLhM4fwrAS4H0Wd2FQ2UyNN+YPgM=;
        fh=hm8pdxjzXHXfHdXUQsjvFEeekOyrHCq+f+OIYtk54s0=;
        b=sRRkaMukJ137siYSYPuUwdmUa86hGPPCWQCx3Tuu6+4M0t1zFjpXzno3LnXIpcYKNB
         caq9HtA9Y1HUDcfPIe/DIqATr8sY1CTdmKAkB2N3laBTseP+NinUMdtlewD7Um14hlTO
         L1sNCG90bZY2IKuQjambHBPfQ6L/d6HMESJSGpIBrGAvM8EVuji1Ew6U084zbxQW4Luk
         FgNWR0XTIunCQ37RTmoXpCVHdWnhoBk1SNMJgAWnErKZHlMfRQk8EhVQL366BVYcxZWr
         ooDMaqYfyeCXVM58UgsCzSq3JDnADLw8Cur7raUro1hFgPmfpJLwNl6PBmn7fo2AuqI6
         hm5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=YY8Fujar;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id ci1-20020a5d5d81000000b0034dc752cce2si509244wrb.0.2024.05.08.12.19.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:19:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id 38308e7fff4ca-2db17e8767cso1542091fa.3
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:19:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJCVcU+MJd/Mm3T6Gp/gzmfxHNh8NQgcW8NCq4q7VFQjed2mY+QQfy6uI8tBYDe2ovQfFkSz+daN57aXx+NT2pTGxqHqdda35yCw==
X-Received: by 2002:a2e:81a:0:b0:2e0:12f1:f827 with SMTP id 38308e7fff4ca-2e4479a2ca4mr23591601fa.43.1715195973157;
        Wed, 08 May 2024 12:19:33 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-41f88110f3esm32622515e9.29.2024.05.08.12.19.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:19:32 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Ard Biesheuvel <ardb@kernel.org>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 00/12] Make riscv use THP contpte support for arm64
Date: Wed,  8 May 2024 21:19:19 +0200
Message-Id: <20240508191931.46060-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=YY8Fujar;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

This allows riscv to support napot (riscv equivalent to contpte) THPs by
moving arm64 contpte support into mm, the previous series [1] only merging
riscv and arm64 implementations of hugetlbfs contpte.

riscv contpte specification allows for different contpte sizes, although
only 64KB is supported for now. So in this patchset is implemented the
support of multiple contpte sizes, which introduces a few arch specific
helpers to determine what sizes are supported. Even though only one size
is supported on riscv, the implementation of the multi size support is to
show what it will look like when we support other sizes, and make sure
it does not regress arm64.

I tested arm64 using the cow kselftest and a kernel build with 4KB base
page size and 64KB contpte. riscv was tested with the same tests on *all*
contpte sizes that fit in the last page table level (support for PMD sizes
is not present here). Both arch were only tested on qemu.

Alexandre Ghiti (12):
  mm, arm64: Rename ARM64_CONTPTE to THP_CONTPTE
  mm, riscv, arm64: Use common ptep_get() function
  mm, riscv, arm64: Use common set_ptes() function
  mm, riscv, arm64: Use common ptep_get_lockless() function
  mm, riscv, arm64: Use common set_pte() function
  mm, riscv, arm64: Use common pte_clear() function
  mm, riscv, arm64: Use common ptep_get_and_clear() function
  mm, riscv, arm64: Use common ptep_test_and_clear_young() function
  mm, riscv, arm64: Use common ptep_clear_flush_young() function
  mm, riscv, arm64: Use common ptep_set_access_flags() function
  mm, riscv, arm64: Use common ptep_set_wrprotect()/wrprotect_ptes()
    functions
  mm, riscv, arm64: Use common
    get_and_clear_full_ptes()/clear_full_ptes() functions

 arch/arm64/Kconfig               |   9 -
 arch/arm64/include/asm/pgtable.h | 318 +++++---------
 arch/arm64/mm/Makefile           |   1 -
 arch/arm64/mm/contpte.c          | 408 ------------------
 arch/arm64/mm/hugetlbpage.c      |   6 +-
 arch/arm64/mm/mmu.c              |   2 +-
 arch/riscv/include/asm/kfence.h  |   4 +-
 arch/riscv/include/asm/pgtable.h | 206 +++++++++-
 arch/riscv/kernel/efi.c          |   4 +-
 arch/riscv/kernel/hibernate.c    |   2 +-
 arch/riscv/kvm/mmu.c             |  26 +-
 arch/riscv/mm/fault.c            |   2 +-
 arch/riscv/mm/init.c             |   4 +-
 arch/riscv/mm/kasan_init.c       |  16 +-
 arch/riscv/mm/pageattr.c         |   8 +-
 arch/riscv/mm/pgtable.c          |   6 +-
 include/linux/contpte.h          |  37 ++
 mm/Kconfig                       |   9 +
 mm/contpte.c                     | 685 ++++++++++++++++++++++++++++++-
 19 files changed, 1056 insertions(+), 697 deletions(-)
 delete mode 100644 arch/arm64/mm/contpte.c
 create mode 100644 include/linux/contpte.h

-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-1-alexghiti%40rivosinc.com.
