Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBIP72GFAMGQEFJUM7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BCE5E41C7AD
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 17:00:51 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id n22-20020a0565120ad600b003fcc09af59fsf2612926lfu.21
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 08:00:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927651; cv=pass;
        d=google.com; s=arc-20160816;
        b=GH+CPkKS7OS2D3ytXI4KrUJJ+bjEvBGqmSZkXzTn+z4Ffc1KbWFqqaSZf429J1Kacl
         uCG7UJMo9Cte1lhRHYHrfuP99CTojaOVr2Lpsh3JtLQ6vKVnVjJQVn+7CuRfG7dJ9nC1
         YxLv1Gr1nQ3RTe8LlyQ+uCI2CKBEilEdYMNPL9e+lAYM3cfwnY183OvHvCwjhhnkmGQz
         ftcYC+5TIdR1IteJyuXb19Ep5Z36DNhSdKZkxznjQtQmm/P4WyMX9EWUYkzIkO/kZNkH
         z3rtCOy64p24u8wumCBCf5gM82Pp4Xkykkdt/fL8BwcR333IE3HQcGul3oS7itt1HMyd
         FY/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SCsw3WREMtIjVJ1mc817wHN5KIKSTK8ecXF+4hnJvnc=;
        b=ooBBlI1llsn982ffAqhcOvJ58FBdxGCMYkd2ysrnl22kzF7AHlW7D0BiQbWo5/MEa/
         1mNPyvNtzsWkHWjyBxtHEMFCvgLTZuvWCaAanCGsPu46ECvWB8jSA/9IBipl+cz1yqXB
         6w+l2b7zs4P14QuUlHN4vEknCsCfh9SpfgLFw9YF9kS7j4LX4pZfrv5wltK+ofA+RPvP
         e5p8bz8I9gWoX44ihtwml8RrAHmK/D6iIzeCb+0RFGuj5pPdAYb+VLkM3BinERVWF4pd
         Qv4Stv/9fUYxkWG6AvBD1GerucXn2Qn3Pn/yKf3irihPhOc+xjaOpzM/uJ7yrDwFtczF
         s9Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=CdndsxOn;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SCsw3WREMtIjVJ1mc817wHN5KIKSTK8ecXF+4hnJvnc=;
        b=a6SmjE/ok+rC2x1mT/l62XdQMzzcJcShT7NE5JTamBVRZ81JTg5fZro061+z457SV0
         X1RVDE1sDdPpi+RIClEFiOGF/x/z6ElzDoaAH5GvkzmpebvYII9euWwhFXURNzcGAfoN
         WnRHQJUZG+p2U4evvY1CRiLv+vmGPahRw7kWwD2KK9VcCv1E5FJwRkAxTNwWgj7It4AZ
         65VDeFzZ9MtUEYinfLxdEgPxGutEuhrjK5M0fDYk5kQNaWdn6jOvbpVnLBr3HYBNPcvL
         VTaAaNo6c+l7d2IBuKdtLFy/aeRI1mxFgHe866WWnaCBbUzE1//3b1QfJuHlBchVRqlv
         HLLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SCsw3WREMtIjVJ1mc817wHN5KIKSTK8ecXF+4hnJvnc=;
        b=vaqdhiUcwQ/nB56oylKVv0mj7KFLOvLt90eiG05w/P00FpFdCkFGOJ7dWMKVvKlgCP
         CXEcI2Rxzbn/d4FOgNj9AreJQle2NN/7jduenJ+ztfbQEYmoQTLEQ9f2e4oD0LB+KAKW
         NVKgPY21IZVYz4Wz7CrYtOE0Ej8MXU0qQRj1MBHhlhWqDHkPo9fB0nDJVkqXAnStORqO
         ahHU1D3t7yxGIKSbkUJeJp5HqwA8vkZa3DP+bGXk68LD5zeikt7q9TJ5xTDMcTYjwBXA
         nNoaqRE/GAY3bDdUeXEN0u3AXMUzRUVw53Om0xFvAQqDHMOoAIwDLQs4LAf+xxyQs+gA
         qS1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uBkGEgTVTbIHVdFG3+8FVSPRODs8e8th3xn01/yoK6c8m1WvA
	u8kAgLc4+7pAOWNtMVJgLmA=
X-Google-Smtp-Source: ABdhPJygrdgd5LXuSmsj3CUhj+2hdc7V9L6tXaR3TBrybUFK/yeZN6YJeUzgdudv39M52ytwFJt+nw==
X-Received: by 2002:a2e:a492:: with SMTP id h18mr412649lji.10.1632927649867;
        Wed, 29 Sep 2021 08:00:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3994:: with SMTP id j20ls591716lfu.3.gmail; Wed, 29
 Sep 2021 08:00:48 -0700 (PDT)
X-Received: by 2002:a19:6f4a:: with SMTP id n10mr166901lfk.290.1632927648135;
        Wed, 29 Sep 2021 08:00:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927648; cv=none;
        d=google.com; s=arc-20160816;
        b=dGUQdjApyoxP94gxUFRUcELyuMyUTRoFOwX8M1v4I43IRF2x1Q7mHazWv/OaUGqXb5
         1sHdO5Qy5IA0UcQOcRGpczvZN7mmbmRyyPlq+Ti+qS5npiJBY//r4IniT+gQ54tF732S
         toV4fCgccNMVqm7AUiQte5VHdVyE9k80aAnmooNoB2Sp64I3v/rwQNk3GMKM/P73oITm
         xMkdC2usHjNnEm4zx4p0gYI86oOxvL+W3fcEf9bJZ/ubEwQe6LLG/JbMm1Ym1f0yNqXu
         /q1Cl/67BVADEtyUBqLJHe2iCoGlSqGHKfVWOlX2ONOuaJoDltsweY7I813AyagoC2Ea
         VEqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vJN7Ck0uNCFG+Ctq/qAp6lWVQYR8Vj2mrO3VtePHdDo=;
        b=UL20IVHuwBgxYMuouHTCS+LYqsQHG/afPTFmeraI34ya4FrT57SPOKE9RRMIybyEJz
         TsQ6ivSPmMHHuhWG59kAmbCe0pA8ka68pnQulAuBIeCOoFv348o2n/7FVOlN2sZJ+RSI
         8PfIOSaOC6HzII6iliwSCqmHis/dmFwIo6WQjal2bZOrTfIhz1sQF+FlY9U3Nyc2Rhxp
         5iKQ9zDgtaJaQxZN9TC4SVxbR08QAxj+5FCsLlRs+aYc4pXlbwf2F8ubUlQlzRL13v4e
         ktm/0rO9MhHlKGBdMBIxgfQtSS8H6JPVHuvHjA4R2+tlkBoG2hzzn8i85EhW6LRFZBTr
         tSUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=CdndsxOn;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id v25si7636lfr.1.2021.09.29.08.00.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 08:00:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 46523405FB
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 15:00:47 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id l42-20020a05600c1d2a00b0030d02f09530so951042wms.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 08:00:47 -0700 (PDT)
X-Received: by 2002:adf:d4cb:: with SMTP id w11mr327565wrk.125.1632927646707;
        Wed, 29 Sep 2021 08:00:46 -0700 (PDT)
X-Received: by 2002:adf:d4cb:: with SMTP id w11mr327526wrk.125.1632927646559;
        Wed, 29 Sep 2021 08:00:46 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id e8sm142306wrr.42.2021.09.29.08.00.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 08:00:46 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
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
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 09/10] riscv: Initialize thread pointer before calling C functions
Date: Wed, 29 Sep 2021 16:51:12 +0200
Message-Id: <20210929145113.1935778-10-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=CdndsxOn;       spf=pass
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

Because of the stack canary feature that reads from the current task
structure the stack canary value, the thread pointer register "tp" must
be set before calling any C function from head.S: by chance, setup_vm
and all the functions that it calls does not seem to be part of the
functions where the canary check is done, but in the following commits,
some functions will.

Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/kernel/head.S | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
index 8f21ef339c68..892a25c6079d 100644
--- a/arch/riscv/kernel/head.S
+++ b/arch/riscv/kernel/head.S
@@ -301,6 +301,7 @@ clear_bss_done:
 	REG_S a0, (a2)
 
 	/* Initialize page tables and relocate to virtual addresses */
+	la tp, init_task
 	la sp, init_thread_union + THREAD_SIZE
 	XIP_FIXUP_OFFSET sp
 #ifdef CONFIG_BUILTIN_DTB
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-10-alexandre.ghiti%40canonical.com.
