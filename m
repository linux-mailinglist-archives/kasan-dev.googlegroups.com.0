Return-Path: <kasan-dev+bncBDXY7I6V6AMRBBNE4OVQMGQE6AK5C4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 42A3F80F979
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 22:35:04 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ca23b6f61esf35856461fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 13:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702416903; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCDy9klo+YBcvdc7CMf+Cuq6gUA/Ohn7BO/fQlYcb87ZYTwEeHdHsIEihG7hsBmB1N
         Dz1Z8R/Wxs5J1wv3bw2u3jEKKyYj2F8gNW3iD+utleElQL9xG2SeGsHss/PwVbzFrUwP
         2YcNVGNEN5qqQ2O4W5cBRxMEAM04OidIM2tApxuadvvuiaiTrW4473bGG+U3BNp7vE9B
         jU1hIfnulNOnxpxSN8b8Ra1O+uungbeLbluGYLPBsq0BgC0kezAf3O8ig4KxCQPKIrpr
         coIv3mEe650FnjQknLqjJUwwLJBO0R15NHN8vnW6VM9MJD78YHlZAiHZjeLKCowxxWkj
         0JXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GBpLQvVOM9GvxvtjkVW3gl2QDGs663tsrwwYP8uILt4=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=HYZv+3sb7vCInP/nseAYH64vx+Ej3QdxQlVyR5utgBp8rfryLlayT3X8t/rkzw2JV/
         CHycxopzOOP6haNF8fN+jBc52WEgdSaOrw6AgwOzQwdK8m0MczXQLO6X+IfFERNLTIQj
         iwE1bOPEUW1fWEUNt19g5njO8X0vTZu+qhF9HJ66ZCcB7YLioBroPEVheiB3ujBwnyF3
         tUReyrwrc7pDTIvgVpHNXr3NCLtvrV/38so9zsSXgZMLdIEtbPhBIXsLlm/AwSkmys0d
         QcggDnPxDK/NdSDLgs1g5v0Lld3gJH1BgP8fKojcMXEgE8ha3xQQxuM6mAUY5q2s5NHt
         07ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ycQ5EXnS;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702416903; x=1703021703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GBpLQvVOM9GvxvtjkVW3gl2QDGs663tsrwwYP8uILt4=;
        b=Od1+EgiYqVK0whj2daK3swQnVaZFPRKveOhWoegpJOu3TrMw59fNkwnYJFly3PkAtJ
         bXk7TSSDjXC9AfdIyshf1B8yYD2YGI8opjMnI6+pRe4bYu9S/jZXvcqDIXJT43QWd2SG
         KFAGQWlOjhibSLNf6JyGZt/It8qanerlzTq3dlujaPHeST5ytC+/UwH4br3ry3Uign3E
         PdpoZpBbXXpMSAUxjy4XbQAP9xceDyHqIVpXbUIvEdDG1ZsQc9gjXyhjIgLIUdC1bhy9
         kGVR72KUWhnGUedPW5BFrRzc/BuPXH75Ia0WGFs9mGR3mR9K3mCFvvglxI1B9R8QJZYJ
         bXvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702416903; x=1703021703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GBpLQvVOM9GvxvtjkVW3gl2QDGs663tsrwwYP8uILt4=;
        b=xBY/4Xjv6xeL49z5wWMMcho1CXrnVHeXNwDtrb1YXEUic+09M8vTOndGFnV8fZGMST
         r7qoiTsgU67ZP7qH73PQN3OHde+bg3Ne/CALjlRnONetDRQ/SQ0q+K+8Q4p08WtyjFEd
         FKtxGdusRMOBe21B0RID9zKx+uDGDD5jctCC5SbBS/Fyrb+LkgeGLiVxxxVMwJyXrADD
         F8Wv/wS76CN2tuxaSXfUwPZ9tkEbRI4sxwY1im1qc3525OUpxpR0tTlZgvpNU2kbYauC
         uDb0lvQAmo1zzcOKwuuYSKt2eSZOth7QBVtySI1yh0LnKtqE337Q5Uw8Uqy8mnMWVYqE
         9gBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxEfsjScGJz+SYep4b59NdztW0BspHj5d/XMams38Lqu5lbFJiL
	dGNXJcYFAfrah4/Kc1itUdg=
X-Google-Smtp-Source: AGHT+IElX6lJqb7ldgpifWZ49NNhdcSyaK+cIbqD2JDj8UTGH58vuOn/F/z4b5XHL9HAkz4fRt8Aag==
X-Received: by 2002:a2e:82cf:0:b0:2ca:5d4:c172 with SMTP id n15-20020a2e82cf000000b002ca05d4c172mr3978823ljh.23.1702416902129;
        Tue, 12 Dec 2023 13:35:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2123:b0:2ca:267:bef6 with SMTP id
 a35-20020a05651c212300b002ca0267bef6ls450556ljq.0.-pod-prod-00-eu; Tue, 12
 Dec 2023 13:35:00 -0800 (PST)
X-Received: by 2002:a05:6512:4894:b0:50c:1047:5a04 with SMTP id eq20-20020a056512489400b0050c10475a04mr3578187lfb.15.1702416900151;
        Tue, 12 Dec 2023 13:35:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702416900; cv=none;
        d=google.com; s=arc-20160816;
        b=TRXVFpiCpHRMnKlCZ7759fS/JlkA/d/TIeY0/iOuywAxBpB4ic62fspmB/mBbX2F8g
         va8C1Do4Y9AnIoSArChSF2GkCx5mPSYbnSu/RAa/vFvjCbH9DHttdBvaWavHOq/gpZqf
         4RILxYR4hdXbHMDO0ckGq0zmFsQM6Y9oEgh0Y35i+I1yDJMYVpi4AccBJLi34rjcarzA
         JYP4MqZXvThzCSnlgLtQZKYKT3/MC+yB8ZRPJvm1HTOIdPYqdcuGV/qVlyumDwv/TJG4
         t/Y/ZVpL9JlWxLKpu+etEraeeykLkGk2hH/N3xrQMl0lF8jwx0AHB56h0I2bpbd45VFh
         pp8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=692HNWJOlFtonZp1MhpojM8sdqlm3KHIVwJ0Hg03uAs=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=GGRPCtELBrRCyXO1hcAwKzmQkpRprdox9qZOaYwN0eiIBU+Q76Byd8R6CJeYLJTN9Y
         dkMD49w0X/WhnZ12AIJRj40cFU2iIrvyMqbblFTcG6dHt2o4JvNYaTMCF4qVh83uE41H
         iGMWCf2soVL/aEBRN5zGfpET16ieqHic7hFL1ssLCj0ome/DGOo3eOn7hcJeN+diSnVQ
         YfD412jzDqnGvf+ofYQIePJw9Xwb24691O4qjRgV8tntJDDksxEbvD0sH5YTmugkdOrP
         6vqjb/MmjngWH5/ENXajfEKve4AdHiCE6IbA3puvB91riVKs/q4rBvs8Zh76nN84QG4W
         /8WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ycQ5EXnS;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id k9-20020ac257c9000000b0050bf698be8fsi410872lfo.6.2023.12.12.13.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 13:35:00 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-40c55872d80so5116445e9.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 13:35:00 -0800 (PST)
X-Received: by 2002:a05:600c:600b:b0:40b:5e4a:2374 with SMTP id az11-20020a05600c600b00b0040b5e4a2374mr3902004wmb.118.1702416899421;
        Tue, 12 Dec 2023 13:34:59 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id bg38-20020a05600c3ca600b0040b540ff0a5sm17655337wmb.19.2023.12.12.13.34.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 13:34:58 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 0/2] riscv: Enable percpu page first chunk allocator
Date: Tue, 12 Dec 2023 22:34:55 +0100
Message-Id: <20231212213457.132605-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=ycQ5EXnS;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

While working with pcpu variables, I noticed that riscv did not support
first chunk allocation in the vmalloc area which may be needed as a fallback
in case of a sparse NUMA configuration.

patch 1 starts by introducing a new function flush_cache_vmap_early() which
is needed since a new vmalloc mapping is established and directly accessed:
on riscv, this would likely fail in case of a reordered access or if the
uarch caches invalid entries in TLB.
Note that most architectures do not include asm-generic/cacheflush.h so to
avoid build failures, this patch implements the new function on each of
those architectures. For all architectures except riscv, this new function
is implemented as a no-op to keep the existing behaviour but it likely
needs another implementation.

patch 2 simply enables the page percpu first chunk allocator in riscv.

Changes in v2:
- Rebase on top of 6.7
- Define flush_cache_vmap_early() for all architectures that do
  not include <asm-generic/cacheflush.h> to avoid build failures

Alexandre Ghiti (2):
  mm: Introduce flush_cache_vmap_early()
  riscv: Enable pcpu page first chunk allocator

 arch/arc/include/asm/cacheflush.h      | 1 +
 arch/arm/include/asm/cacheflush.h      | 2 ++
 arch/csky/abiv1/inc/abi/cacheflush.h   | 1 +
 arch/csky/abiv2/inc/abi/cacheflush.h   | 1 +
 arch/m68k/include/asm/cacheflush_mm.h  | 1 +
 arch/mips/include/asm/cacheflush.h     | 2 ++
 arch/nios2/include/asm/cacheflush.h    | 1 +
 arch/parisc/include/asm/cacheflush.h   | 1 +
 arch/riscv/Kconfig                     | 2 ++
 arch/riscv/include/asm/cacheflush.h    | 3 ++-
 arch/riscv/include/asm/tlbflush.h      | 1 +
 arch/riscv/mm/kasan_init.c             | 8 ++++++++
 arch/riscv/mm/tlbflush.c               | 5 +++++
 arch/sh/include/asm/cacheflush.h       | 1 +
 arch/sparc/include/asm/cacheflush_32.h | 1 +
 arch/sparc/include/asm/cacheflush_64.h | 1 +
 arch/xtensa/include/asm/cacheflush.h   | 6 ++++--
 include/asm-generic/cacheflush.h       | 6 ++++++
 mm/percpu.c                            | 8 +-------
 19 files changed, 42 insertions(+), 10 deletions(-)

-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231212213457.132605-1-alexghiti%40rivosinc.com.
