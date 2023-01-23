Return-Path: <kasan-dev+bncBDXY7I6V6AMRBKN3XGPAMGQEFZRGRTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F286778C7
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:12:58 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id y26-20020a0565123f1a00b004b4b8aabd0csf4834569lfa.16
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:12:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468778; cv=pass;
        d=google.com; s=arc-20160816;
        b=QDEbHr6e2SApctbC6jqqzAdW8nGk+GaZ+XGvlA28h55Qn0MYytN11ZblcvujuhLIKg
         ydo4Ioa9K62CT02zAksz+sWcekWN9TiNb4ov9NmZeRdEIpmkSTeVyO4XWYMHo7n5eQUh
         S/giHxkvgw7OIsN+8Z2CKBuKE0H//SGziqW1s7Tt3+890YJODN0oSMWDuvQTy0+VbcBA
         2EGxt6MjtGNU3LV0GAJ+4aNirKH4UC8wyPS22k0oXq63NQo0m7FOF7G/WG7+6jumWzau
         fsKRZP2VVR/N+BrpiHVr/DPg724wkiiIoW1tsno5RQDhg+H9njHxwIVFuhzHPESu98GP
         nuhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F/dMbGvpauUOUv988D+lerKgAk9gqE7blD1KhPzCAzM=;
        b=PjGv1C6aSICMQY/uFobQEuk1SoZep8FHYkMogZqPCIYgYfhFkPpt5UImvstMA/QaJo
         FYClSmMxvxjIIMuAvKUWzpy5I6Rp2wWiMG5808ydv2XqSFkgLILiMuW+mYCooCeUgZs6
         IgJ+LPj4XVt8GQYnN55yoGS4QH2hov5A77oLqdyMiLxGWSP7oPT3nsD4OMuH1hX4AYjP
         DmCsWfpskim89SMgVpj4zeTk5eX9tUdOxZQsPg3d8OiAmQweP+GhCpVCwFfLzSuF/v3L
         +tyrrSove4sR1mBx1BtZdmLYw8ZEqSrW92SqRREJd4RYpH0YhD1RrMgBjAuy1FOkSUFi
         SJCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=HXc8RqVo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F/dMbGvpauUOUv988D+lerKgAk9gqE7blD1KhPzCAzM=;
        b=N9WHpDS8zWJqWzb8hoA5B01bPt8G2NKPqTyI4Nj/VKGdjGrpiUQ3arE9Og5Kov8Mif
         Kcc7AwPueXB77v4H8xDetSiN6VKssODwZSalGxi4DNgG0Xes8ZGzuxX/1psg5fQvoLRi
         nVnOFCPSp0GX92XFrF1uqaAQbPrUH3CWi1Pt9dhoirD9NNAz62msDO8aLDxmpdfkpf/s
         vHfFi6F8ZeyoMolXj1Lok2VQ/r+h/pFSxN0ncEZ7hVjapF4pjz26W+PQ0H+ooExH6KVs
         QB35A3YjaQCWKOs+5s+Lzpptlmem0d5iQ6i/Y8kHhUr1GV/y9vGASn43ccylZZw3FdMS
         Acdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F/dMbGvpauUOUv988D+lerKgAk9gqE7blD1KhPzCAzM=;
        b=yvR3kohApLpdmdzts2YmKjNvGV52uQq5+tfiV15PZM15ABTAoLvXa2ZbZMBkFuOs+G
         CUWE6vT1QuYGjx+xtETqhcgGq+8rS38+J+rjeBpzYU3S9zZy4BmPGR7vlWaKdGmdvlTj
         y87Ok6YUXhH6bDf8GfVU6ISpJIOwTSNxr27dPNcdBPpeVL4SwwDpmcgqO3txi43Cbjn/
         qC/h5Hr41Kao46ojH4Ddx9gMOinPwvCYH7RYDUoOyb/vBHVucpX+BPhhQJ2pu4trX2jh
         bxLNOnwMeWDiQfpebqLNQHidkkttCB4wm2qMwUuxg3cFVNK2BW7YHg+gDdFwY8g4yhFL
         Z1xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpcvLJrgulRP87RGIK98yhet4kZe9VjEWoulG/88ALA42jjbDe8
	i/Agp7gBqv7s5PdgXRZ0U9I=
X-Google-Smtp-Source: AMrXdXujLJfp9nO3Qm1PW/oa8y5k6HW4dheoE/2WfgFY6+OkFrO/+hhpdxu5U+jHDM/UbJcrXEdTjA==
X-Received: by 2002:a05:6512:318e:b0:4ce:7fa4:1f3 with SMTP id i14-20020a056512318e00b004ce7fa401f3mr2774088lfe.638.1674468777933;
        Mon, 23 Jan 2023 02:12:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls4100740lfr.0.-pod-prod-gmail; Mon, 23
 Jan 2023 02:12:57 -0800 (PST)
X-Received: by 2002:a05:6512:3b9b:b0:4d5:9682:6ec6 with SMTP id g27-20020a0565123b9b00b004d596826ec6mr7099245lfv.18.1674468776941;
        Mon, 23 Jan 2023 02:12:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468776; cv=none;
        d=google.com; s=arc-20160816;
        b=JUtojF4ADuHdQ9eoERazm0ifUQwv3KwDU3b8vVlccuaBJLS+qkZ8qAtp37T6gm0X0j
         EWOfkuyeYMaEwdZyCG5jQmqwVfxs/yv5/NjXB+N73jCUx9z2QNpanHZ5/LbuBoaXuEei
         /wJwJ2Jume6dqdSoJ7dwu6eDN3XCBQhU584E1092FNnO/B3Q4d8A9r26hMKRghjtElM6
         7hPFsg5HC1jKWcYYU92/05O1gxvBLc4i9EFpsbkQfLENGRXKDykADhSU3Z8U/ANbDT4N
         kDLAGtt9iWvazb3gl22cpsZNZz5s0DoNAkIzzhfkrqwe4RmcJRbfoG50MANgcdYpPH1U
         ugAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VzLCWkEIOjhYvr7p7s7uKUj96vyQiWAZD9+xORl+Fd4=;
        b=yYzEbILUh1dQtxGmsoLeMgS6hnN0DzgyTC0THCpcafYyuyj+yBJHBwwXrvOQGm8hfq
         YH7IPDECJYg3WAXTUCY28rdTHgIqaqr6WqJ836MdhkkCT2REHFfzZjD5An3zgdVTWGEF
         wqkXTvU9fXg3GB6Jn8Q1z/umYXRn0DQJkmitOlRNGUlP3KtFwitnnsDjCu/XjV0iv6NQ
         EF27pzWa6SuVFv5wDZoXDc/faK1HZuLFlXsVHGChd2z+WLDfbMQzIE6ZWZNNDcQMEksv
         KpBgo29GrpVJ0pSrwKB2fvU/1fuqcKFCkqDpr16h8KncPRZCsh/ns8105wqG9h9aWTsU
         HNaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=HXc8RqVo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id c5-20020a056512324500b004b069b33a43si2077839lfr.3.2023.01.23.02.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:12:56 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id d4-20020a05600c3ac400b003db1de2aef0so8132918wms.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:12:56 -0800 (PST)
X-Received: by 2002:a05:600c:1c83:b0:3db:27b3:a654 with SMTP id k3-20020a05600c1c8300b003db27b3a654mr14875103wms.26.1674468776649;
        Mon, 23 Jan 2023 02:12:56 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id d19-20020a05600c34d300b003a6125562e1sm10375823wmq.46.2023.01.23.02.12.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:12:56 -0800 (PST)
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
Subject: [PATCH v2 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
Date: Mon, 23 Jan 2023 11:09:48 +0100
Message-Id: <20230123100951.810807-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=HXc8RqVo;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
index 478d6763a01a..87f6a5d475a6 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-4-alexghiti%40rivosinc.com.
