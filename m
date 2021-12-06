Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBXOYW6GQMGQETWL2DVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 089BE46947D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:56:30 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id w16-20020a05651c103000b00218c9d46faesf3286570ljm.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:56:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788189; cv=pass;
        d=google.com; s=arc-20160816;
        b=AjFyz6/4u4Jq7zaJJZyFC21MbO5qEpDHa6ogQ6iVmRR1BwjlmrohZ0hihByTXVzez6
         1Zx2dLxUytqCg1W9TAk4TdQd47lQj/tJTir1+DwCmsaFZG1ECOyZ9oBmad2WEWe3ItlN
         u/x0NL2B86NJESSBAsp3k0WBIVwKhUzFt3774ex6bCJ3Y0UI0aOzIjlIXcxY2qvliyC2
         vrRrLXabOKaDBvHwQ5fNoaUznRBhxPGZbE6v2JIuJ+01k++zizCuSRFvEQd0+9aCnMVq
         2dIOrmjxWPOye7WqzY4tfq/lSlF71igxWH3ms4zfARCeqsyPz4IFt0eFs0hpT4BgDvt7
         llJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=Y9q91knjcDyPMGO/D7j0ZezbWLoldaUucMHry+xLuqU=;
        b=weTfTotOGhuOydTzW6cXXpRqFsEaVVvGyU9sKTfbcQb4xEcpXNdYeXT47Py9DYxMVP
         7w14SIVPyKmhlPCnYwMn3ly+5ExHDIBbPjjmsOZ4APHsUneE605lBSntfgykNpip2asw
         2GQtlPwu6XnfuIUl/AL03r7UzAWwAqU5t1hpz0DanIjora7bE4aca+hsiaFIy/3i+v3l
         tQSlmfmK8y9s0VhpXQyULL38VySs/KbgSc8aQTJU9FYaf2T6vjADbQF+rBGWZkSkpvSs
         8w9w1Znma6X9h5zGXFpXyEceDkeccw3d9xU1P0n6YbU2eGVKW+x37YVryeJ23hjnQcLL
         wzng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=kRQvGMmQ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y9q91knjcDyPMGO/D7j0ZezbWLoldaUucMHry+xLuqU=;
        b=afIUHpzLVp5+a5Hj9y/F5djE8gY7/g1ufwgYut1B8PdhxbVqSvgWevEWabBUtZvaTS
         IQXE8cFTV4cOwF9k2xtztAMS5wX3082wMQ7u/AunNknkSeZ0fiRUUufBG5kZQnwcwOJi
         tXH4nhyvek5UIxjlrjlgvtw7Ajb5kzmRr2IX3YpsjuE45DRsUSdBEZhm9AMWA13FOLVe
         KmSMrmOQ2gi/9CA8INQEL98wnHX2o5cRg13naKAltlMKQy1xVNG4B9efaXY21T1f6rkR
         2Vl5th/Og96ZcUCkWFncsVx+O0/qzY9LKftlHMZ12X0lPOIQT9YVYbTMk5VmLFh3jMCT
         OHSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y9q91knjcDyPMGO/D7j0ZezbWLoldaUucMHry+xLuqU=;
        b=Kzlpm1ebp+8K6iuWCaLJKPPGNbtEAnidJ7WX+9D01R/IafTungt3bZNvA6St+ZDgB2
         7uPK0SGBFASFZ8/xgNuNbga3wHYUA+PRmj1Q2ZiouFupnMh8q+n6pVWVkEx9q3fC2KOh
         djofz/dAyUKXQAzz3ke9Iya3a3X3a/Da08LKgX8qrmh9TgukV5sBxEA2N0kO0+1+xgyy
         S8WNGUYr/bWx9El3wkljzxu34q/bPyM+iSPixaHEmi7oUFeUgM0UrJdEFk9r588I5Y2W
         brs/oBoJRozWh5ijquZea8U3H/DiWQa1Ky03HAiSs6AD7yPcfqQSms8wlC7FMFdCc6G3
         jhsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xYzP4GL67qU9rM5er4uyHEDikce9bKJKFMHrqKI2PWTsnIFkg
	2oQ2vUIvyxBx0tV0rECgtFU=
X-Google-Smtp-Source: ABdhPJw522hok5dLQffLvhgZEF+F02Z1ZLrUJ8LfgqHxMDHG7RE7+udRXT02SvIMkuVCDsY0EsEZcQ==
X-Received: by 2002:a19:c350:: with SMTP id t77mr34715952lff.152.1638788189642;
        Mon, 06 Dec 2021 02:56:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls704678lfu.0.gmail; Mon, 06
 Dec 2021 02:56:28 -0800 (PST)
X-Received: by 2002:a05:6512:3a8d:: with SMTP id q13mr32775382lfu.73.1638788188838;
        Mon, 06 Dec 2021 02:56:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788188; cv=none;
        d=google.com; s=arc-20160816;
        b=GQWPgum3g/1/0hW6rU1c+UwEkvBBWnNli375XjfBcWXi8d9XEMMvPP7UCk2r7OU9io
         ARtznzYgFrbBm7mt6KsUNYtzdp4Y0085bes0L+h1MTQ7oySakXVbkoFJdfsG9oBBX5pm
         ZPyPdkwRyPBIW/6AIB/ui9Ps8GW3Z+a5CUBzDKbA8bpVOTdY59lpNTU9V3mzdm8Eib55
         nsue67vkurDnqtSvKDFDYsFhmCBxwSjZxZpoMNtiA/QFV+NQXs1dUXLLM3Z+lxOVB4mY
         OnT+xybw6YT+cT+rHDubyitEV3eFRtkYImhi89tALCSWqrNwGOO2DzzyHtA/UdLoVIsP
         q46w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CS+lflLGdqIBScWk3+o9lUxh8jVqR8Nq2WKSyjwTWok=;
        b=GNcv55yECaK9ypkKGTsUVIyGw8hZvJ/9SowPmwz+88deWwU35fuNfjdFsl/bhYG5EK
         rnR4bRON13jEOlTcqalGp/AaMrVItjd8S3vrZzwBMK4PEgFwUGnTNR6gY+Cc8yiS5ezs
         yp/mJnN86V6f9L3R1VZPJi30HnOpagE8WA5musyCy4ZO3wvmfgxpNWCkZAuDsFrjpgw2
         u4uGk3QncTkw8cwP7ApfXmVvJ7/f+/uhC/Re8fmbY7R7IFQHhIIMparhFhVrI+1+dZP5
         SZJaP1Vwa9tod6pxDCqX88CIh8kgTde+bkvR7DMEgyoiMxHBz2aVQy7aSrHgA4YqyjWu
         XOJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=kRQvGMmQ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id e15si894362ljg.0.2021.12.06.02.56.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:56:28 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 12BB73F1BF
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:56:28 +0000 (UTC)
Received: by mail-wm1-f71.google.com with SMTP id r129-20020a1c4487000000b00333629ed22dso7678597wma.6
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:56:28 -0800 (PST)
X-Received: by 2002:a5d:6447:: with SMTP id d7mr41714889wrw.118.1638788187806;
        Mon, 06 Dec 2021 02:56:27 -0800 (PST)
X-Received: by 2002:a5d:6447:: with SMTP id d7mr41714859wrw.118.1638788187621;
        Mon, 06 Dec 2021 02:56:27 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id v6sm13522985wmh.8.2021.12.06.02.56.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:56:27 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v3 09/13] riscv: Explicit comment about user virtual address space size
Date: Mon,  6 Dec 2021 11:46:53 +0100
Message-Id: <20211206104657.433304-10-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=kRQvGMmQ;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Define precisely the size of the user accessible virtual space size
for sv32/39/48 mmu types and explain why the whole virtual address
space is split into 2 equal chunks between kernel and user space.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/include/asm/pgtable.h | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgta=
ble.h
index e1c74ef4ead2..fe1701329237 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -677,6 +677,15 @@ static inline pmd_t pmdp_establish(struct vm_area_stru=
ct *vma,
 /*
  * Task size is 0x4000000000 for RV64 or 0x9fc00000 for RV32.
  * Note that PGDIR_SIZE must evenly divide TASK_SIZE.
+ * Task size is:
+ * -     0x9fc00000 (~2.5GB) for RV32.
+ * -   0x4000000000 ( 256GB) for RV64 using SV39 mmu
+ * - 0x800000000000 ( 128TB) for RV64 using SV48 mmu
+ *
+ * Note that PGDIR_SIZE must evenly divide TASK_SIZE since "RISC-V
+ * Instruction Set Manual Volume II: Privileged Architecture" states that
+ * "load and store effective addresses, which are 64bits, must have bits
+ * 63=E2=80=9348 all equal to bit 47, or else a page-fault exception will =
occur."
  */
 #ifdef CONFIG_64BIT
 #define TASK_SIZE      (PGDIR_SIZE * PTRS_PER_PGD / 2)
--=20
2.32.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20211206104657.433304-10-alexandre.ghiti%40canonical.com.
