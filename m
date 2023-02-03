Return-Path: <kasan-dev+bncBDXY7I6V6AMRBOP46KPAMGQE3EHTHOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 95A32689153
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:56:41 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id ay19-20020a05600c1e1300b003dc54daba42sf2232958wmb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:56:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675411001; cv=pass;
        d=google.com; s=arc-20160816;
        b=wWfaIsz8j8u0AL9/VYm1QYfI+Oa/Gq2EKoxHNOr5QuglY+hD/lZG1Q66+xoHnZVLrL
         c5H2M4azP5wbN957fy21/OBM8TPt21bWD2rppMqN5bhbFtPB/IWpmpo6Ibr4YDolSsJ4
         wauiY8dTXmVNXbnNXxOg7bCDyQ5e8+EKTvV2/56v6DEVi5RDBP8IE3Y2C3bO7zuPMJSD
         QO4Ws7cwQCK8WclQTV0fI1K95wEW7ojwTL4HBvg8CCSqvQJ15/9pCJhFxjpGQVUq22qC
         rzrHcJzI4MgCa3AyjdDEUIKh2VTgrGIU6zmKlXs6Aq4uiqB/yOZgOwVs2b9GfiHzoixE
         uq6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pVIwPuB8zaKrv9QOo/zWu02Kx0+esd5A1xwNhiwDEF8=;
        b=ucCGRESp27ddP1/vGc13tj2cyUZtugNsylAXWQkMWOH7kA06prP8JhJFiwKTzAPkoi
         73XSSfTEelVVMoyQFCBPyl9V9P3Gx8leIQhM2DZ1CeXqdIRcOOTlET0nQ16CKLQa1Jnw
         3HUXRAGxQCoEafnii1PQ/CLKJGLrVi2FsGjvHtID1byJe6PnMJBPUO5sbdpxcGw5d+rU
         AIV4y9zGlPMZSg9qyktzSSOK+GH6OjHlE/6H8o6zOjNMtw6KNVbafpB0QFl1SKEQcSXC
         iOpNQ3AL5d/pRDBuINtiz1h5ShOixyH5yGf3dDcm63Ui1qv4vzFOBJ6pJNbgY7+T+bM9
         T3Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=XuczLvag;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pVIwPuB8zaKrv9QOo/zWu02Kx0+esd5A1xwNhiwDEF8=;
        b=oNox9IYhqFXwoNNPzhFxy8rwrxed40Kruit+PHEcr7/hMWcEBqEqnYd5qJeSf0XdQm
         eEZGG4krvMP3LAzr9GSECsuZEiAdGjjV27a67av0Xu2wF+PA5+Ah+WCPzBADyHtFIYFH
         xzsKZS9s6vw4NZ5L/5OLh1EJd5hTBZGD5FPwQpNHoy1lY/9Lxf4WB8H0bSPybv5PxCZ3
         VIAGGIaySQLwx2bXcVGUW/lup0uWA1s0P8lZLwy6G/7njHecbQnr1buo7Y24oC9w2Dop
         kzSoX+2HnolcGM43s8u53zt0A9uzUr4dEVeyTjgfdENnthuL0IdQFfvrb6j2ia2/FhyW
         u8Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pVIwPuB8zaKrv9QOo/zWu02Kx0+esd5A1xwNhiwDEF8=;
        b=NpphewlhBKTxg48Urf2uCpaamYv59EdQG0tODERk62GIAJtWaAsuJP1Ahs9ECXvaP2
         kg1owjY4df0WiZ6VjCXhDYtgm/rQot88G6TA0MSBgUnZcCAwyozmn6XXDdqIuNhKcx+y
         ufNiN/mhjz3ETq+bKV9AA/ycS0xHTFOV7cdS4ZarFQV2f60GvFTpJ98Tr1F+dGAP/IJ6
         gii9BtQ4GGfE0iFuEQQPx8XIkmZXQcKsgW7OywQIkEPr0d1wHQVdzaWiNUUHPmMXgoFN
         a1L/cti1eoo8Uh31SRYJzquQ2PnlHiMkfSpH6GPRG6TRttZn9iw2BXR56QNbYvbYY+UQ
         jEZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWMXHiQ3aU3+5c3h8N7fRi1yxNef3QU4X9eCABUGWY6o/IDYK1m
	0noTwCcSDVN4nShPoGQKOHQ=
X-Google-Smtp-Source: AK7set+oOskn4DsfhqM5gEw1GmewPayi0gy4IHc3gI35iexd2jktd3NtL2TZiWnnc0D9K2jLDFAEmw==
X-Received: by 2002:a5d:5381:0:b0:2bf:b561:8eea with SMTP id d1-20020a5d5381000000b002bfb5618eeamr295312wrv.611.1675411001304;
        Thu, 02 Feb 2023 23:56:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35cc:b0:3cf:9be3:73dd with SMTP id
 r12-20020a05600c35cc00b003cf9be373ddls4256676wmq.3.-pod-canary-gmail; Thu, 02
 Feb 2023 23:56:40 -0800 (PST)
X-Received: by 2002:a05:600c:3491:b0:3db:fc4:d018 with SMTP id a17-20020a05600c349100b003db0fc4d018mr9502853wmq.40.1675411000054;
        Thu, 02 Feb 2023 23:56:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675411000; cv=none;
        d=google.com; s=arc-20160816;
        b=jdYkg0K1fKS2cS2DT58ttuGzSnMsIYjhO32zgaMCIKarE9FV71TUlc18j0Vpow31MC
         V+2aCCm/VcGXNfb6AOcLQ+j79vFKpKAxsA+cpjbKQGg/qpj6ThYMzNly3mCkqeCJdveI
         kkFFGtFqpt/nr+T4i/zBOPUS0PnyKfvinPfGki9cJViGkRxMQxvXugqr8jYzP7+zw7Y3
         7em3Tp4STSoQH0cgGfJLTwQH3pvbrKUkg1u7eySjttENHNm+qS/ND9l6aVsXVU2IM91m
         cqsKxfwtT3sFTk/gRfbRhZaVyWAiIEdN20uAYv2QawUXzJKvmSJiXS6iS2SytzYCYNoi
         oKKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6xmv+QSgbqVHZO5FLG2f26KzmGjk1zWdaRkSSaCJJ9A=;
        b=wKhi0hDoDuIMfGLmrUQLAm/AB9y4QC9tJ7BXSNr1y6YFHsDsG+ASPRZQwGACMgUDy6
         US4TJgRB3e59tUbse9r7SG92ClA6lL/SCDq4kRyK+0UvZHYe36JZJj2f3K9rbyZ2K1ib
         228HnfyTHkIrhEjgpaN62qOsaAbnTHz7XI0BOUJfLxTM86szJyL3iSZlbZLdbiPXynSU
         4Mo0snXaHFL7+r5lMwbmOhrCAT2hN6l8lDT94nHL6siTaUkX+Lg6S8d2+l4alEMHo1vg
         pujeoAPqlB69aHkJg3fMzADyuZALqWNGj6aveeVacJzOibc2NsHWeV9EJi7OAmVoaE4w
         YYFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=XuczLvag;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id p10-20020a05600c1d8a00b003d9c73c820asi551132wms.3.2023.02.02.23.56.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:56:40 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id bt17so828406wrb.8
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:56:40 -0800 (PST)
X-Received: by 2002:a5d:684d:0:b0:2bf:81eb:dc26 with SMTP id o13-20020a5d684d000000b002bf81ebdc26mr8135682wrw.37.1675410999759;
        Thu, 02 Feb 2023 23:56:39 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id j6-20020adfb306000000b002c3d29d83d2sm878564wrd.63.2023.02.02.23.56.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:56:39 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v4 4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
Date: Fri,  3 Feb 2023 08:52:30 +0100
Message-Id: <20230203075232.274282-5-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=XuczLvag;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The EFI stub must not use any KASAN instrumented code as the kernel
proper did not initialize the thread pointer and the mapping for the
KASAN shadow region.

Avoid using the generic strcmp function, instead use the one in
drivers/firmware/efi/libstub/string.c.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
Acked-by: Ard Biesheuvel <ardb@kernel.org>
---
 arch/riscv/kernel/image-vars.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
index 7e2962ef73f9..15616155008c 100644
--- a/arch/riscv/kernel/image-vars.h
+++ b/arch/riscv/kernel/image-vars.h
@@ -23,8 +23,6 @@
  * linked at. The routines below are all implemented in assembler in a
  * position independent manner
  */
-__efistub_strcmp		= strcmp;
-
 __efistub__start		= _start;
 __efistub__start_kernel		= _start_kernel;
 __efistub__end			= _end;
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-5-alexghiti%40rivosinc.com.
