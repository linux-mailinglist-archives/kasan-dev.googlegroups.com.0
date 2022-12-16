Return-Path: <kasan-dev+bncBDXY7I6V6AMRBWFX6KOAMGQESDTPIJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C58164EEF4
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:24:57 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id y8-20020a2e9d48000000b0027f1feabc75sf650369ljj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:24:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671207896; cv=pass;
        d=google.com; s=arc-20160816;
        b=yFxzz5n65No8wnxYMpGBCwNCXWUVqysjneUKg0bqWXfn5UEgcjMhz8qrX3K5JHDhVW
         Vusyj0l2g0+cvZ5d7YZ+MrjUk9GEdAMFkK6hh6TY6yLMSii7yKq0ux3QmOYMLbPC56hy
         7ivdrMtZcEtUhPRZd36h6eQ0bsPQYx2/4o+lRswXMIGKBEx5D5iiJQCkW8uYYUsJ5xo8
         0G3B9+dsVOj9kRlnMr+bIVFcdbZ9RnSUU8SQ69ekch7vZ8qjuXWJNNbRbMlWajRk4Cbv
         rUyo8LQotiPkdbQe972dI6wIEPynx7LGB22QiEwsG2/fPVH7S+Ic9dghS2NXpuM3i1aT
         AcvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/xKu2wSf0Q+K3MdGc4pWbV3fSS07C/2gTWfLuLLAis8=;
        b=P91HWJsJ13ACfra87xr5MSS8grphvH8c3NlWMjOhk+tNb+fygyidQyhmXiWkZIyla2
         YppaO1f0WM/BifL9Tdqhb444R6N+VbiJ861wvRVUy/H0Q0IoygiEObscrz/vNSh52m8A
         xEkSUjIOSEuvDkA+/SgdahIdEHhIBJTafSO6LN1W5TrBR+bdCYFe7uvUdvBWc0XB2wgk
         WErr9pejfnYRy/asQuyjR3ZdGdyoSrair3Z3sJivwamocZjbHtTT8KOBiQYFBqbjSeOk
         EpcU2xWGGHvSToPZqRnd5Z+cvlE+xwrEwGviKdULWB4RgL/ZaxXLVhJtR4ZGlbTcwU3k
         cKtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=5zZ212Ik;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/xKu2wSf0Q+K3MdGc4pWbV3fSS07C/2gTWfLuLLAis8=;
        b=tT46o63yyVvayzHMc7+o72/imszrTd7WQiLAXjMJ42uqJqWYYzhQ4W5u4VQLLlvVf6
         1vqISvJYgVOhQ7pa+WBAc3RcS3cYG85uf70TPp3g/9YvIKW2abYfa2UlYxLTkmhPNjpp
         wIH53+pWXl8cT72Nes4VstV/hsYWejw8rM/qvzTka0EpZM7rSUYYZ3Ek0k+GJkDvmZbd
         HGq5iMAzq1TNKgHGmk0HNHjWeUBteNPRZ1JQSq0pnaNcH0AVz9fc91GvebJyiOzyBkRA
         hfKKnqkPlTtTADbqta/nOf5FuQ69xHzjWv+E5IPoS9oUEa4L4C0FAL+NrY1oBliz3v59
         0suA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/xKu2wSf0Q+K3MdGc4pWbV3fSS07C/2gTWfLuLLAis8=;
        b=Ku1Ln1s6N5OGV2mParxUQWzQhaWr4keQt8Rg9gz8S1q9N/2LRE2UmO/RwFxhr4DTa/
         ckf+H72zkAl5mS9lJfaDNUGlV1RTXqPHMUnpo9zD61POKyrkrJd5i4/QgY56kUyY/Yn1
         meCKySwOSQBa+09AOro0Mvbq83U7fRdA2gSwoGxYPtIV6n2K1eaIeNJQOp110L18L9Lz
         DeSdmt39VB5IAt0U6iB68FdsJRyavBEjzxTnbN5amTiVBO0dtqkZwy5+Ttea/ORDVrwX
         EgmnsVhe+qcUd5M7CX6zEQrzaG1PO6B02PNXSB1J83ncf/ZzVYlN7SpzfY2wx5Yd9nsz
         HHNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plkIUIRfDrQW3CUO8+KoT2juS+ZAxjQontcoRTihLj+CAO9rqIe
	8yHSASbJ9bk6803OiGhKzWM=
X-Google-Smtp-Source: AA0mqf4snYXVsfyCAhZ+6ROFJTIwFvH2C/RjzXw9DvpmiFR0Po4zDalAByDK+wphc9MOtD6aEJeRqg==
X-Received: by 2002:a2e:6a08:0:b0:27a:9e4:b7ab with SMTP id f8-20020a2e6a08000000b0027a09e4b7abmr6554527ljc.394.1671207896574;
        Fri, 16 Dec 2022 08:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:4942:0:b0:26b:ff81:b7cb with SMTP id b2-20020a2e4942000000b0026bff81b7cbls440043ljd.6.-pod-prod-gmail;
 Fri, 16 Dec 2022 08:24:55 -0800 (PST)
X-Received: by 2002:a05:651c:1721:b0:278:e5ce:f553 with SMTP id be33-20020a05651c172100b00278e5cef553mr13999728ljb.11.1671207895518;
        Fri, 16 Dec 2022 08:24:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671207895; cv=none;
        d=google.com; s=arc-20160816;
        b=xZU8/gsSi7W8k5TlJ1xebUVT6XR3PdH3F3xmOUAsECJLji3xgVUwcrps0ooW054DVZ
         kXKCjFUJF9nzkFliQ06Rn8J7P4O/r1TPehrbD09A7s38WvayYFCX5klpmjnBV0PI0c27
         z7pTzu2gHCXa3UPp/JjcaLP9pn2ylnQmTSYF3BttZ481vMtzEYefzTZoNbz1tzE7eDaQ
         INBf/CDC3c5KebzaKTtN7Ue+bsXn6/gOr24+BBzjb9y0Qhp8ZrrYgktDElI3G5cL6NeJ
         DuVxJ6Snyn3GgOljTFmsAVVp21PL0c2n7vlUVYVnwlAVDccXNlJ2AsBL+nHFPnJuQZcK
         W5zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xKAmpdKbBscT+wI0zsC3ixLztutjRoSSvZIlGNHmM4Q=;
        b=zVJUrBtK+AN9pGakhPqKiJfiTUa0mAvezQMHPP1sQsW5YAMf8ZkZpcUypGA6BPj/yO
         dT7XgyUZygvJ9nWW9OJZFDF0bog0ek71bQ4GtTDzadeV5GsDcCmExDfA4lJV0kTmb2fp
         y321mKRNAc22XjccjGScvMBpwGKl3iW3QkfnrEz/quEsCXlHGsoucRoDEfEFFcueYZFH
         nKmoyFgkU9aiYRp65MvwBy4RoP4FR4kPpJbLxHCWj9eyhQc7nXInmngsLHjVd00xLLB+
         WPitTlbF7VojRaiyo3VV0FQ83ZRdqb6/pvsoLUlO9b8GfdMvTZ3CEyAZYW8qPMFEoAoV
         V7GQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=5zZ212Ik;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id f27-20020a05651c02db00b0027976ad74c9si128150ljo.5.2022.12.16.08.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id i187-20020a1c3bc4000000b003d1e906ca23so1567171wma.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:24:55 -0800 (PST)
X-Received: by 2002:a05:600c:4f89:b0:3cf:d0be:1231 with SMTP id n9-20020a05600c4f8900b003cfd0be1231mr36102867wmq.13.1671207895040;
        Fri, 16 Dec 2022 08:24:55 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id h16-20020a05600c351000b003d23a3b783bsm3450995wmq.10.2022.12.16.08.24.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:24:54 -0800 (PST)
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
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
Date: Fri, 16 Dec 2022 17:21:38 +0100
Message-Id: <20221216162141.1701255-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=5zZ212Ik;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The early virtual address should lie in the kernel address space for
inline kasan instrumentation to succeed, otherwise kasan tries to
dereference an address that does not exist in the address space (since
kasan only maps *kernel* address space, not the userspace).

Simply use the very first address of the kernel address space for the
early fdt mapping.

It allowed an Ubuntu kernel to boot successfully with inline
instrumentation.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 58bcf395efdc..d5aa6ca732f2 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -57,7 +57,7 @@ unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
 EXPORT_SYMBOL(empty_zero_page);
 
 extern char _start[];
-#define DTB_EARLY_BASE_VA      PGDIR_SIZE
+#define DTB_EARLY_BASE_VA      (ADDRESS_SPACE_END - (PTRS_PER_PGD / 2 * PGDIR_SIZE) + 1)
 void *_dtb_early_va __initdata;
 uintptr_t _dtb_early_pa __initdata;
 
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-4-alexghiti%40rivosinc.com.
