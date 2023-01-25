Return-Path: <kasan-dev+bncBDXY7I6V6AMRBBGQYOPAMGQEM7QCGWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5095467ABA6
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:27:49 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id bi41-20020a0565120ea900b004d584f37a04sf7925927lfb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:27:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635268; cv=pass;
        d=google.com; s=arc-20160816;
        b=GjsyKHiof5kcBnslMwHoBCWPE0XljVz65EEGEYhZfT3q4aahY6PRVpuuDZ+HrZbvE3
         Gr/H2M6kfxI90UWasD0cRJKZiuAAwnDlUUOzYqgNGHT4pZxIA1sPhErtXMcxu/6OYDOl
         O8ZF1TqB1tx94hD6Ke1MTzJRg6pnwUKkUKD/ouZSELfP9L5xJ5X71cjwFiz2GrIb8i/7
         BlcCCNj86VOYihlgUl8c9Y1ZlmO/g+lHqbLxithqCoUUBf2QwUTBXt2iJ06l4evw79hP
         rKknOY3kv+fL3PbZNRR7Gou9SQvNE9RoKI9c8T6hksky0vG0YsiSZFWpcruP+hyvIlKf
         Ferg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=30669W4EOiV2BLoqhX8LKn3DJ3F9ZicX5EvFRVY6bfY=;
        b=U9GZ/n0ZSqJjdk6etzt1dSp0oe4mrwsTPFo/BUxGkjhSeN6pQxqWGKigX1GGeH25yX
         zeczeWBBnX91rZlOzaZaEWtr5QCoJooDookAyTWyEl3z8cGmC5OPuMfXFRH7xW5kk04w
         /DVtDwRG4H06SQHhVfW6x8TRJqILlC7rQXMXjv1o5XCr9SCxI4bWIU4tFiIVfoxjU33F
         KqFP30vxXKWMyN2FOqWc9OfaO4ZTL+JQLn/V1ri+UGyvPQHs/iaN5u3KS+rBCEuPhHj4
         XwHrwx5a65z9NZU0WBIq/QBDiGVZVT8BWZhdWOH9iFdON8VB5FUg424i8HrPgGFg6PeW
         GqwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=cbBspW8q;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=30669W4EOiV2BLoqhX8LKn3DJ3F9ZicX5EvFRVY6bfY=;
        b=EFalKqBawT7+7J4zsNvtKZl1wNogNImzH9RoZoQut3HRNC72a55SjY+jkblWA2+asS
         DFY9VE+OEbbSdUrxipY9ADxoTuxz4KMFBIo6ncsFS3t3phCPRE8/Puw/OQyH/DLK+uep
         v88F1Q3kL8v5yEeeF1LqcbwARIepBR6Gil0U/+UC632AnUdbiBWF4P4OwGvwtwef0hZA
         P236Pwz42lkZ1ao8X/nhs3Q5lKgJxT2h8yfoLhiO7mSJLkMBc3ecvE3AztoDFN3st26t
         nZcBSB/iwYeNbIjh991B1f7gBTWdBXR5yTdOBPA0CUXshfnScVbytpbCACpTMQTb9bf2
         gtGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=30669W4EOiV2BLoqhX8LKn3DJ3F9ZicX5EvFRVY6bfY=;
        b=YntLpuPTUeIo82Zjf5XOB8gSOKiwlhMcxTU7UAzMlYqkevRumKy5zttL8CkYINjCH4
         3LBEhaG7NeI8uESE3zZCXqtLRvv7uivHlZxkeOEXeSGdRZPFTMrUGz6r5FNFxV+4hB82
         EclHslGo/pYj7GYeUvT/vUYHuBQXTJT088E4zjYguIiJwPW9E9vBA/sEmYiAVTTumfuF
         GXyqpScatAGBbe+yadpzwmRPRmvCOrF5iTBRmu8QjdJh5fNiIsI0LdVMkU/wtvhKGMvi
         NuiSRU5RnJMiEtL7wKtD23jzpZAhbdLhoaMvUXTJg2dwAX9Y9iEdg7gnUNyuCMylWhTH
         W9PA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq+jA3Cnnt1NPcmgOfd9Wfz1z6EmeBEVVtIsR433jS8BYYkua3u
	2ZZaVqWj0NG6hnsRxSnd9W0=
X-Google-Smtp-Source: AMrXdXvqqpazTnhuclJQvJvfpWuOTfaLjHRGfjQRsPaSHTChz9F1PAg4Om1fMgegDgEi8SV3wCTFQw==
X-Received: by 2002:a05:6512:2355:b0:4d5:a160:6182 with SMTP id p21-20020a056512235500b004d5a1606182mr1261080lfu.81.1674635268592;
        Wed, 25 Jan 2023 00:27:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls8936465lfr.0.-pod-prod-gmail; Wed, 25
 Jan 2023 00:27:47 -0800 (PST)
X-Received: by 2002:ac2:599e:0:b0:4d7:22d2:9913 with SMTP id w30-20020ac2599e000000b004d722d29913mr347712lfn.16.1674635267606;
        Wed, 25 Jan 2023 00:27:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635267; cv=none;
        d=google.com; s=arc-20160816;
        b=uL4GWI1wpqkfdFJHKsZxhv/AKm5Vb7OrknXI3lQBEfCfagh8LKlm5B7bys1vnVeHHI
         zJJheiMBD34y8mTcr0xJLvbvAHi4bPLOpu/XdYKEHvbkrnlPmfKjsBT5lsmNq7Wp00Zl
         2yoe0N9jlFI9m26oZoK1wtR7GHcBgvGjSMWnfUooT+fqaTkZC9Y84U633WWRoqjA04QB
         Rgv96t4HUF2P34uppeXWntofsx/USQCHacZlDhepfqQhukghtheT2jVD+BSPs5gqvB19
         VKLpI1SppHDYOr5HlQ7bB/c2PWExaCfWcBfdhxP4KI34d00SMNCzDyJqE7Ei8stKt4Sp
         ngQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6xmv+QSgbqVHZO5FLG2f26KzmGjk1zWdaRkSSaCJJ9A=;
        b=jwf+efwh0ZWpC4ccyi+VGbuGYqu8YtgySgLPLFRBDRntNVSym+0eHCJ/i+uA1BOf8t
         yyHaN3Hu9EBL7ciOL3x1gWy0DtMNnnmrgJ3GyEOag2ELz5YOXbI7+f7/YhGEQLlpijVs
         xeVOUDGtC3uc/5fLc8EtqlYZLS/atUsmfkFr+U+OYQJWEirmrOlbds6rZgEarTuPb6nU
         55Hks36RuxDvbg5WqfPvJYTg8SDbUCLfn6l1ag7zECIMpc/P751/n2NS1FdaIjfphueQ
         VKqIAxQ/SUkJ22j+ZRoQ+fVIm/LmoVBs2BeawBVo/DBOsOijoqhgna3fxzGKnjVqe0nT
         VSSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=cbBspW8q;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id j16-20020ac253b0000000b004d57ca1c967si239781lfh.0.2023.01.25.00.27.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:27:47 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id h12so12224195wrv.10
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:27:47 -0800 (PST)
X-Received: by 2002:a05:6000:1c0e:b0:26f:6bf:348f with SMTP id ba14-20020a0560001c0e00b0026f06bf348fmr24106837wrb.6.1674635266981;
        Wed, 25 Jan 2023 00:27:46 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id g9-20020adfa489000000b002b065272da2sm3863367wrb.13.2023.01.25.00.27.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:27:46 -0800 (PST)
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
Subject: [PATCH v3 4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
Date: Wed, 25 Jan 2023 09:23:31 +0100
Message-Id: <20230125082333.1577572-5-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=cbBspW8q;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-5-alexghiti%40rivosinc.com.
