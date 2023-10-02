Return-Path: <kasan-dev+bncBDXY7I6V6AMRB3V25OUAMGQE6RQP56Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FDE67B560A
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Oct 2023 17:10:40 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-32337a3929asf6669636f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 08:10:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696259440; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojZI5oYstzOOjB3khvCp234nV5K0z1FlhVX7/VndPIPGBgpkV28AMYzCFRoicWgTh3
         sN7owiusJGpZkErL5p0t4GFGr/YrhjNdZ2TQnTYtjr8HwguV3yNGvQlY0VCb7z0l2KXY
         /zFsKTSWcjL1aS2c+EER6qe/Yddbj6nlPeMMdhW38iqV4aTRp2B1ny6OAEzoNGPtu/Ir
         NNMtdneGhXP3H52fQIsiYV+hoJLXssUiJFtVCzKlZ+NLPnjXWEcySrCZqokmturflgBP
         UP7Ffo4Kjr1JeuXeAFBJRaQbTaDuOUUuAkrkTWBU3ye7Xea5ZTNZcD/uTQKj55g79Vo3
         QDrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=y2rE7eCEv+JwRKFPwS9t9PPxFBVgwA+f8A8q8a8OrK8=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=QHlST+pjw/89Ra29PsLEXJqPLKHepNGNF8REkVV8/KPVJLzzT3z0nGYRIyhqSz6YeN
         3A3xfvcKbmakQ4Mhh2EVRSXzLk/ilABorT4CVD/0iqGXIriAV8VTYgKd4KXplzy4jdyD
         AdraFT3+KtxKmEeE64iBGRsQ4zcwFHHz/Q2sSKSHLEQDH7XJQfE2MkAywd7vWJZ+VzmK
         tLuV2E/uRJaycJDhZTTTPWCag50s/ctcmFhbK5Vasj3eGgb8uvlD/RRQ+uBdMebwVmtg
         3jKgxAIs7fpm6qQTPTmkdqpUoOuN4bI0jPyQWcWCTTdqLtn83Te5JFrAIJbpaZGohBrL
         8b9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=2vpQ9ey2;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696259440; x=1696864240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y2rE7eCEv+JwRKFPwS9t9PPxFBVgwA+f8A8q8a8OrK8=;
        b=ofVNhqLnqsDsjr257rpK8pEu8+asELq7nCnEWivxp8C2tet/0jd92MrMzBE509bgRv
         YhNrGwrHE6qEwmzJ6uC6yPcEMA32+0OZucTDA6SrCLlNEdzARSDymzhBZq+tEmaL/5gP
         jHHdteKeD29YWSsYLyrYPVJ1tJfuIxz432eIEgsbyRjBj5MU9XmYSSSnu50rje+74byF
         lxsQkz54BFzWzdhvDjQSP1bHJ6YTOGAZgJAjNSpzRNQWVzHtZNWUdNYl8tB+hopNwOfN
         h5+XFHEQ7cnp0JZAJ6bllX3RFcYbxBWrSM5vfKHGN4grzChzxIbkevBX48nnL1qZkquV
         jQAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696259440; x=1696864240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y2rE7eCEv+JwRKFPwS9t9PPxFBVgwA+f8A8q8a8OrK8=;
        b=OSTGu/GYhuNfg76Tcllfjdcbm46OZL4/ub4R8hBVEZMFYmSnBToIFEZVSqcEfpJ1ol
         AX/O5eDhNueTZqrBahCnU120o9mQGAStDDcYa38PYsG0cQXya7xraTfk7tWu6mfVpiML
         9tdDhieWYjnSUfXjTYeiHlnm+89eELB4/1jNyNEkX+RwXlVF857T2X8DIGYgl11BpDAi
         2BolvDk9hiQAhE71qIo53HHnQgWscxwG26sQJlxF/kkjkw6vNBiUVUuyfUHfpYdmkrez
         pSM/UYQvnlpBccx5pk0GvwZEkIfhWx3ZQzEFWnmojaUIGPYnwerZ8ENuzPjU1UOfhyCW
         DLhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yym+0LAvDd+5D+0SWARv1Zr9mdeKqx7n04GRgww+lgmeqms107E
	F1KRtktI7nF3rANdUU61Opg=
X-Google-Smtp-Source: AGHT+IG/5O7QQCAdwXSlizgN8w/wBJcvXlU85vZbVriWj5Mn3Wn1xknsJWNfTnH1Lj/XDWoGGurwMQ==
X-Received: by 2002:a5d:604a:0:b0:31f:f1f4:ca85 with SMTP id j10-20020a5d604a000000b0031ff1f4ca85mr9427827wrt.37.1696259438322;
        Mon, 02 Oct 2023 08:10:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ce10:0:b0:31f:ea2d:5619 with SMTP id p16-20020adfce10000000b0031fea2d5619ls2522891wrn.0.-pod-prod-09-eu;
 Mon, 02 Oct 2023 08:10:36 -0700 (PDT)
X-Received: by 2002:a05:600c:2189:b0:405:36a0:108f with SMTP id e9-20020a05600c218900b0040536a0108fmr10405653wme.41.1696259436560;
        Mon, 02 Oct 2023 08:10:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696259436; cv=none;
        d=google.com; s=arc-20160816;
        b=H5Qj6QiQTCn3sy/sLQnnsJd1yeFbxIYW+rArwESwkaasuKJ8UDVcfoAWDhX7fsszj1
         eH/vDqqMBqvWrE0ZEJvjFttNOPjK/5LGFlao8KYWRY2RH2XJpH4xU/zNDMijaUI9+fJQ
         LunzEXVtmEyDsNRGP8RwkkODFkb+TRUT3I7tDKqAjgWBpddsSwWF9KBHf7OWISUCXFlz
         FhitcWSu23Hmm7+wAq+dL5v22yZpjm/QIc0tWqglQwWhF+7zIGBBL5KX/N9QgWshFio1
         jxZM9lW5ZXRQd5j/KiR1yS1vzUM15qGuyEUmTcg/RIg6xAlzRVaJVYmwR2Du6dChZo2u
         u3Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BviuOqu94hunsSO/3Ul5WhMTTjDvZpGvaCCYOAqyBa0=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=ixBQm6kV85J3vPFjrJZWX0x4QfHPB0Ks4C30+YuY6MNdefIuZ/ZSFu/1FnAavmyaVt
         YgJwC/pIYydnsAnijUw/mmWKhJ2xJ4xRWUz6xC8zU4xNjbb6tmI5gGSp/oNiOkZy/FGV
         yGWx5VCCls7J3/Ukj/mrLL2uOcSUUBiw0pxNFkrLoxPOBoAXZkLbeG7U5MVq5qFUxQq1
         spkosBd+Ve8nYRvG1P7I5+2dxoOOLZhqFnqzkCfLUj7YEaAGzwuJhet0r0EKfWKIqTBh
         ywHuQW/tPuijg9Nm9rcZGWkvvGiKNCu1OCXdyeJYjrZ3UIeIURm28QKrnDpumPlKv8+Y
         ziMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=2vpQ9ey2;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id az27-20020a05600c601b00b0040476a42269si614496wmb.2.2023.10.02.08.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Oct 2023 08:10:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3231d6504e1so12623633f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 02 Oct 2023 08:10:36 -0700 (PDT)
X-Received: by 2002:adf:ea8f:0:b0:320:1c6:628c with SMTP id s15-20020adfea8f000000b0032001c6628cmr11378844wrm.65.1696259436015;
        Mon, 02 Oct 2023 08:10:36 -0700 (PDT)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id b16-20020a5d4d90000000b0031fba0a746bsm8493981wru.9.2023.10.02.08.10.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Oct 2023 08:10:35 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 0/5] riscv: Use READ_ONCE()/WRITE_ONCE() for pte accesses
Date: Mon,  2 Oct 2023 17:10:26 +0200
Message-Id: <20231002151031.110551-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=2vpQ9ey2;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

This series is a follow-up for riscv of a recent series from Ryan [1] which
converts all direct dereferences of pte_t into a ptet_get() access.

The goal here for riscv is to use READ_ONCE()/WRITE_ONCE() for all page
table entries accesses to avoid any compiler transformation when the
hardware can concurrently modify the page tables entries (A/D bits for
example).

I went a bit further and added pud/p4d/pgd_get() helpers as such concurrent
modifications can happen too at those levels.

[1] https://lore.kernel.org/all/20230612151545.3317766-1-ryan.roberts@arm.com/

Alexandre Ghiti (5):
  riscv: Use WRITE_ONCE() when setting page table entries
  mm: Introduce pudp/p4dp/pgdp_get() functions
  riscv: mm: Only compile pgtable.c if MMU
  riscv: Suffix all page table entry pointers with 'p'
  riscv: Use accessors to page table entries instead of direct
    dereference

 arch/riscv/include/asm/kfence.h     |   6 +-
 arch/riscv/include/asm/kvm_host.h   |   2 +-
 arch/riscv/include/asm/pgalloc.h    |  86 ++++++++++----------
 arch/riscv/include/asm/pgtable-64.h |  26 +++---
 arch/riscv/include/asm/pgtable.h    |  33 ++------
 arch/riscv/kernel/efi.c             |   2 +-
 arch/riscv/kvm/mmu.c                |  44 +++++-----
 arch/riscv/mm/Makefile              |   3 +-
 arch/riscv/mm/fault.c               |  38 ++++-----
 arch/riscv/mm/hugetlbpage.c         |  80 +++++++++----------
 arch/riscv/mm/init.c                |  30 +++----
 arch/riscv/mm/kasan_init.c          | 119 ++++++++++++++--------------
 arch/riscv/mm/pageattr.c            |  74 +++++++++--------
 arch/riscv/mm/pgtable.c             |  71 +++++++++++------
 include/linux/pgtable.h             |  21 +++++
 15 files changed, 334 insertions(+), 301 deletions(-)

-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231002151031.110551-1-alexghiti%40rivosinc.com.
