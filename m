Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBCNZ4OFQMGQE7ZU5SEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id A03C243C1F0
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 06:58:50 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id b8-20020a05651c028800b00211cc108922sf122047ljo.15
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 21:58:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635310730; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOFUR7++N5hXXgwZaO7bvfZk9HdVsfbeXuDJ2xH2anGwxvdduUbHY5AyVGaaQnEoal
         iDA/elUJtbej5tcRQEM8UkXILtmnnUUz75eTulSN5KJU8KDXSMAs+ScSO9Gy1iTfCaEv
         AnBrMCnNqipj+fVoD0jpxVGkT2vf5BDos2vAyuP/0Q/McmzXfImO3Vx7C35m8RNWcLNX
         apWXE04/oMj2CatNMWbM7qnJ0T2obj/Qkl/7x68AY8ZgzbGaOs5mHc8fToxbxan4bkPx
         Xd8Afw9v9xb9nXgbBdW6Wkw2aqAG49v5hK7E/cvSe0qcpU/B9W15/nnIR/Z1Snw4KYW0
         CW3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CGDjqDSup7b+qjDKe61KqrAPzDnJFKnhszMrjN+7reU=;
        b=z80eegBulPbNBKXs+ALWzbMm2ksbN/pqpmyjQsrZauV/z7HUp/2x6s9aGLS7iBEvsN
         m2XsOCYL7lHFpquj9Z9iyypj/3YTDIEKlWiy7LMzrzxuLgMUjPzNAahNOvybCttt98hy
         shxQTBvq9JT9j9gGYVdgPHPo/lT41WJHYgt7qHQbQiX942OH0/+vUNXITBh/JZqfM4Y7
         pXT3Pd1D6RX1N2j3Kg4WZpQv7Zog0MYdFLr0AZDmy+8ZjMtjRN7qhHHCeEZklsmsPBXA
         3TdQ2rHdfbeVpEEf/MeRQtflMyhsmGuxYoO7VMhqgzjAxqgQwU7U95/5/BFlWg/ADlht
         xJUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=IMdq8wnN;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CGDjqDSup7b+qjDKe61KqrAPzDnJFKnhszMrjN+7reU=;
        b=T7GPiZrkDIvHaEIPG+akMU4GVY4uO41AZzn71RtB65rcE9y0aHCs21eFpUPCnsDCLu
         eG/QrVKT9WljuAF38WtsGCmAt72ISgLeyRc+x5nVnDGDaqJ2t6MxCVXm6TELgL88S2yE
         5GGq7JaEAbKq18/rsfVJJuj4zcZMqBe0UXe6gkUtMSJnx7e3ZJFd2PV2TCUuoIRItntz
         AUhchSpT4UncUjNt9vQB6SEigAcVbPPTPVYGtsbXDh0Wy/ldRifirb0lTY3xHX85fsZA
         2Ky+b9vQwLWnwObJb+A9EXCWZRZgiMNU/vjFKU/Qht8KxUT0gTvuuYMA9FIwzKQ7+92X
         v0ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CGDjqDSup7b+qjDKe61KqrAPzDnJFKnhszMrjN+7reU=;
        b=x9uHGwx6r7nCeyPUSNGxnOepQcw/NZHRbso2UvnJ50c5wn0FMtYpEZqwG82dTH8ZAQ
         cPpzvTKhmTlUxID9ppwpMnDFqxGfmSacDFTs6H4mcBWvEpheeZfCUfzzI2UAYqqt3dM4
         vumvO8ZD5U+U1W07Q5mrvX1jwNYXUrqwIaZ9tk6/B5+9JYMl6Bb9UjplwBbGdk61tzBm
         X6ILdXxscSvhpLR41YYYHi0hJ59zaGguLRDFU8NBG5Q//j3tvKWMYxgUXkx3Gystyo3h
         f0ixcBzZotzoNJ71X3Q1SJhpYHUwWjwodY9QUGWI/yS3XxZGLhe8T0/NnTr+JPps7d2m
         o0mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nVZt8w0wEGLB5hlcYiWCafzy/+Z6yQm8kkFBS+ZXMeSUdBQId
	74bPmSePL2RdnLRNalGNal8=
X-Google-Smtp-Source: ABdhPJzxB5P3SxN5nu1Ou2abHbYXrnCjNEDNVi+hj3Dp1/LruH+d2tORn72gIPHWT4x7GlrXqRjinQ==
X-Received: by 2002:a05:6512:2111:: with SMTP id q17mr7615195lfr.338.1635310730125;
        Tue, 26 Oct 2021 21:58:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0e:: with SMTP id b14ls156517ljf.6.gmail; Tue, 26 Oct
 2021 21:58:49 -0700 (PDT)
X-Received: by 2002:a2e:904f:: with SMTP id n15mr30692679ljg.153.1635310729120;
        Tue, 26 Oct 2021 21:58:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635310729; cv=none;
        d=google.com; s=arc-20160816;
        b=PSSTlW66mBnHpdLnxZYwefGATvn1RDm24yiwVjTrltNYttAMxx8w34k5lVdubEDkJY
         I2I3rAD/OoGUPRSqTYenvSyxlPQdr/8VJcxs71zzmusDqj5SGgRg+6E3yX0bnzmAjC96
         z3o7eP5wGupMKZHirX61Ynk26y7fXmZaTt6bG+GQ4dIq0mZK0iV9C+M1FFnWrGVbh8b6
         Rtik7RZIlLYikin09DH9nUN/FR9jfLCMGR0FbwMmv0FX+Q9qH6Huxyg5amvGQ/9smskk
         0ileLmQCQeXB/hOf2H4zKFnj9sOadmklKupPKrWyjXgB85hXVX9H607eEU8gvZGiyzBc
         4GTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OZLbG+qup29O7pa3I3sT9lWunjud959dueLBGLyt7Gg=;
        b=jzBcR9RhQu0uIfzCMveuq+Sc2H5aWpjPq+v8HMRzB7AZunLAiW6VblFdxvjfKhFrbd
         kR6mAtiZnXmI+BsWjuBEGBdZybAh4nLMSvJzpKswDgsU5mP7mn+ah3PfklS+okVJ+9gn
         NPxwou4dnN1RJT7DuGZwRHbK3I79j/GDdsrWHRXEi6OVjEdSAQweUF+RRwLFMg6dePzn
         fceAwsIex763A0MVNJfF54bJt7nB68MI7dpabrsVg9mK6LQbArpqVegvBO6zYpOf+hEC
         iR+yjk6QrmS20m0gTTIFpg8Kn5KSxy7icBS5lXetwwx9taKpWFQKFoD4oJn66b0KJnXD
         BOWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=IMdq8wnN;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id q8si40426ljg.7.2021.10.26.21.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Oct 2021 21:58:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 08A433F19A
	for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 04:58:48 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id b81-20020a1c8054000000b0032c9d428b7fso709711wmd.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 21:58:48 -0700 (PDT)
X-Received: by 2002:a1c:e911:: with SMTP id q17mr3260840wmc.174.1635310727618;
        Tue, 26 Oct 2021 21:58:47 -0700 (PDT)
X-Received: by 2002:a1c:e911:: with SMTP id q17mr3260825wmc.174.1635310727489;
        Tue, 26 Oct 2021 21:58:47 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id o1sm11775586wru.91.2021.10.26.21.58.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Oct 2021 21:58:47 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Nathan Chancellor <nathan@kernel.org>
Subject: [PATCH 1/2] riscv: Fix asan-stack clang build
Date: Wed, 27 Oct 2021 06:58:42 +0200
Message-Id: <20211027045843.1770770-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=IMdq8wnN;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
Kconfig, it prevents asan-stack from getting disabled with clang even
when CONFIG_KASAN_STACK is disabled: fix this by defining the
corresponding config.

Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/Kconfig             | 6 ++++++
 arch/riscv/include/asm/kasan.h | 3 +--
 arch/riscv/mm/kasan_init.c     | 3 +++
 3 files changed, 10 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index c1abbc876e5b..79250b1ed54e 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -162,6 +162,12 @@ config PAGE_OFFSET
 	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
 	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN_GENERIC
+	default 0xdfffffc800000000 if 64BIT
+	default 0xffffffff if 32BIT
+
 config ARCH_FLATMEM_ENABLE
 	def_bool !NUMA
 
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index a2b3d9cdbc86..b00f503ec124 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -30,8 +30,7 @@
 #define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
 #define KASAN_SHADOW_START	KERN_VIRT_START
 #define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
-#define KASAN_SHADOW_OFFSET	(KASAN_SHADOW_END - (1ULL << \
-					(64 - KASAN_SHADOW_SCALE_SHIFT)))
+#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index d7189c8714a9..8175e98b9073 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
 	uintptr_t i;
 	pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
 
+	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
 			mk_pte(virt_to_page(kasan_early_shadow_page),
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211027045843.1770770-1-alexandre.ghiti%40canonical.com.
