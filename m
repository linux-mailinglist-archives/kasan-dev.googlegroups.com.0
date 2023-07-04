Return-Path: <kasan-dev+bncBDXY7I6V6AMRBQU3R6SQMGQEBVCLZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 77D2C746AEA
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 09:44:04 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4f956a29f2asf4917912e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 00:44:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688456643; cv=pass;
        d=google.com; s=arc-20160816;
        b=eh70kSIrLz68hHJO47vkhzgsENDHBIsUBfuFTBmRmRODX5zqkeSUpUMWebmBWI8kTy
         lF7Vvf4KjyMIR9eW16wX1j1YjDMYX6PfE7JcRgvEIfwaZcxzLQZltd6W7Zfz4xQymRZU
         6c/VRa6E8TZV+T0BO0JDUZ2jTi04uzTc7yS+XWMnVsBYG5nLpuxPnkl5IHYLXll8juEK
         tkf5OsFu0nzeYD9zP56FlFLpyCzBDwTdq13qnYJ4p3h86Ua4BXL04NP1xurQp2njaSYR
         a1r4oNX65g5T5gFqcBYgAUmOspRQJIV5bhKIagMQCU/E/R5LZhsQiICNbQ8CikSx2uZJ
         dQnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WFPpNP9IqM1XUbZP+aj6/GtUZscqPe6fq82HfFsaqCM=;
        fh=xE5BgginaCOW92gneVIc0ugwmp/9aQLW1vVBfbkya1w=;
        b=VQxEw5aXk7XcSy3h1GXXzFT1BIKQDF0B/X6LJnbwvdN2ceRUr15xunErejWs9uFru5
         s/eWAenHVnS5QsEUysWvMnyPRZLAwkjQblee/L5L3Dd0Ib04G0GHMXyhMNI4kQK/WDzb
         cIKlWKwaeQ/tH1IXYp4YgS/ZPAH/HPpuk0pugGkj68s+AZlgxI3OuGvz+tf8GvawZwx3
         aCHvqu2b0mNVm6r4HvR+jqA8GiGsmbIUh7TEAMOPgrEvDWiSNDgX8P+UCx3K2SGS3O4T
         cttEln/4m/MNgn4LsoYVzvzeUZd9sVtbPFlFz45Dxt9mpJGUkB6UEz5DHmGAL/jyNJ+U
         8EpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=UW+p9aqo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688456643; x=1691048643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WFPpNP9IqM1XUbZP+aj6/GtUZscqPe6fq82HfFsaqCM=;
        b=CgWp3zcCWdF7UljbILStjUZ5dpGJVtPzYuxc59MvCV+Mqkx5d1d1tHIC5SzVnw+BTw
         G7LoOW1bVLDrqcFP4MwpyowvYX1KkEON7xZEmrx1qs2GUaMI1ANYko7xxeGxQCCSTU6n
         BgFR3r4nhKjA1KXeA69/iCSZJZMamka+CGop0mEyuGIo0NL7SCV3tE70hY8bpvhD/puB
         JpwlA++o6CjjLUY9z0ON5Ymu/3An+J5ohfe/3p6ichzwDl4z80K/joyKlqENQ8WdQe02
         Pwon8aQsRRUzOplxbvMf1APiUvtT0+pA5X62vN0UZF8t9mgLVlC20M5nqpgayCeXpZL/
         VhOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688456643; x=1691048643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WFPpNP9IqM1XUbZP+aj6/GtUZscqPe6fq82HfFsaqCM=;
        b=C6otxsYwaMu1KyUyEPX0zKzdzzets08/HlD7lEtXJ0LnA2go5Zq8nOvHRm7RHdArzG
         x6rGQmHv0t969AeN478k7zM1kyLkSAZsjUCQCbm4208KqsWCDBSjigBfYJnf/C/DXvFa
         pZsZjp2Lw3PyhcIofA7eUYa+NAHFmje7m1RXQSuhKUzylURElRacZ9RY3MoAj+5xqMQg
         K5q4yFcsYIXKlQs/koYUTavmgIlwGUKCizWhvANcEw23SePjc+UMnrRgRV0g8KuNKQlt
         MoTDAA5wrfQiC3D859csls39Fq73l6hXZSCs5mWteb001T8ldURbIBABEbeAifDC8/bE
         2+uQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZuGIuLIBeuDLUjHdddUvi2WzIu2CglyrwxnWXcGj3bEFj4SrCW
	AJDNBr11YlBQJYLYKjAey4M=
X-Google-Smtp-Source: APBJJlGHBxJute9C3Q7d1z2IuGzBLO8RZsHZMkuy0iIvZOr7tev9I9mlxbY/uYJlp8EJ0ti21T7n7Q==
X-Received: by 2002:ac2:5e69:0:b0:4f8:66e1:14e3 with SMTP id a9-20020ac25e69000000b004f866e114e3mr7656442lfr.17.1688456642837;
        Tue, 04 Jul 2023 00:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:645d:0:b0:4f9:5598:ec0d with SMTP id b29-20020a19645d000000b004f95598ec0dls1020825lfj.2.-pod-prod-02-eu;
 Tue, 04 Jul 2023 00:44:01 -0700 (PDT)
X-Received: by 2002:ac2:4c22:0:b0:4f9:24b6:6695 with SMTP id u2-20020ac24c22000000b004f924b66695mr7988439lfq.29.1688456641144;
        Tue, 04 Jul 2023 00:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688456641; cv=none;
        d=google.com; s=arc-20160816;
        b=LLmyOPD9oU5n+OFZEsDpXP6WDe2yqpvU3H8KHAEcakwLuCqvnXc7No912/7xnPGoTJ
         YldL9TvO2v+l+El3fJMN11GHhhzLKac/CXXMQqcXzb0TEDkbGsoi2f384QDT5G++6rNY
         U5MYdagbzopGO0dTSFNwVfLle64VxoWS0x5lAcr/DWcMP+JzNI1SnDfSGF7Qzdc+JRJm
         pi7mQyD2JQnfQ15cxy4zzcJ4hV/5Aezmm0Z3Vu+u64kL2oIH4mDPHXAT/2fTq75rw06s
         P1pB/6wUDtB4q59qKeKcMMNtRRBXdjn/Xpl9tSsSvSs+yRbZgoSL5l/DrbqcfvL0DV0E
         9nYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NaN7FLuvwVnpnxsPOCNUh4V539jNJliF9+H8DZcJ4YM=;
        fh=xE5BgginaCOW92gneVIc0ugwmp/9aQLW1vVBfbkya1w=;
        b=JM5dO8MGZQGSM2H5KCkzVRjNvhiGdhye9EMafZqb13Pxp6aKQiNy5s4xUq1BcGD/rw
         040HklnvfCi43C+KLvEjSbKlY2gyhh8S7ebzhzBH/gt562VPtAoFaG5wHTU2ZlJtzPNf
         Uo5OGF9fU+0RaZxjWBRLiaMDOWK0f8LJPcLLgMro3mc1R7rnufCb7/y6L/A9AEWlGDVM
         iV1T/V5mP79cgvoUyEQ5j+gv7qJKw5M29YdKrYgCVttYQ92FCTdCd4wRfKSyqCKuyBsJ
         5IUqxmuREiVtsKaht7JQMj+j+qPaUQuGZ55pCOwUEINlHJRnK7IN8irQhWD9Xkev4lPt
         HbEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=UW+p9aqo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id y24-20020a1c4b18000000b003f9d3636ac6si513546wma.0.2023.07.04.00.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Jul 2023 00:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-3fbc0981755so59546595e9.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Jul 2023 00:44:01 -0700 (PDT)
X-Received: by 2002:a7b:cc82:0:b0:3fb:b008:2002 with SMTP id p2-20020a7bcc82000000b003fbb0082002mr10415933wma.0.1688456640324;
        Tue, 04 Jul 2023 00:44:00 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com ([93.23.105.195])
        by smtp.gmail.com with ESMTPSA id y5-20020a05600c364500b003fbc9d178a8sm10790933wmq.4.2023.07.04.00.43.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jul 2023 00:43:59 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	=?UTF-8?q?Bj=C3=B6rn=20T=C3=B6pel?= <bjorn@rivosinc.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: kernel test robot <lkp@intel.com>
Subject: [PATCH 1/2] riscv: Mark KASAN tmp* page tables variables as static
Date: Tue,  4 Jul 2023 09:43:56 +0200
Message-Id: <20230704074357.233982-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208
 header.b=UW+p9aqo;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

tmp_pg_dir, tmp_p4d and tmp_pud are only used in kasan_init.c so they
should be declared as static.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202306282202.bODptiGE-lkp@intel.com/
Fixes: 96f9d4daf745 ("riscv: Rework kasan population functions")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/kasan_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 8fc0efcf905c..b88914741f3d 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -23,9 +23,9 @@
  */
 
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
-pgd_t tmp_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
-p4d_t tmp_p4d[PTRS_PER_P4D] __page_aligned_bss;
-pud_t tmp_pud[PTRS_PER_PUD] __page_aligned_bss;
+static pgd_t tmp_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
+static p4d_t tmp_p4d[PTRS_PER_P4D] __page_aligned_bss;
+static pud_t tmp_pud[PTRS_PER_PUD] __page_aligned_bss;
 
 static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
 {
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230704074357.233982-1-alexghiti%40rivosinc.com.
