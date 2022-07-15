Return-Path: <kasan-dev+bncBAABBZHEYWLAMGQEWQOH44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C5402576336
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 15:57:57 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id w8-20020a197b08000000b00489e72a3025sf1808789lfc.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 06:57:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657893477; cv=pass;
        d=google.com; s=arc-20160816;
        b=szHKQMEGevEjJ4JQu2efBGfVED9UJy17ld3ZmxCkbfd/FRffSCEqjE/rejTPcLmO6s
         imPtib10DGr1wv0+gKePqoDsctEApTwiwLsMLPm1bdeVZx1riB2w5vEEcykk6Zq3/ScW
         wkQw8VaEvFRuB8eOqU0vENgSlBxbDXgZ9xm1TTI358vFDATaRl0DS0PAhHBRXvakDVZo
         mXAPaEiMhmxags86HSZY3hA4FAecTYP5mIuhf+IZhAQVVAn/LRCLejhEgOIBVHhCafE+
         Ch5LobLRSKBhPJkQwFboLo6ogaQAIUuSo9Dtz0PLcV79Ck2eTXZANWk5fdoeF9XGNXQd
         SGXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Ncb7oYLzNyr5aCp1lR+q1kWxsvNPDUvybJ4SMByJEk=;
        b=Iyy432v8bFVELFyo3/pkh1RBLI29v9ztPJlDR454zkEzdmVR4K3pHxroMT3LeIH3ZL
         5gAvq5eX+I26NYWYmuJGxAcMqwz+ALMhpO5U5avhC52GoPtxSwshcMfGj/ikK7ts/A3/
         8AH+PZ1Z/CCuq/SmjxJVvTNUGSV914PFXLKal91KC/vlV7MvJgDWnkq2yPV3K3o7OAOU
         JSAv9F65Nc6kzOU+15K4merFVhY77OjeTxC75yDrOpG7z6pVEAHnqyaxcwLHziuIUl04
         HTSuOJriceEttwneifTIOShYP1H/c4eiRS/iNhmiHGNKPdXfFzDF/VM8FVYQMlCaYWvG
         xTDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YPbRBCi4;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ncb7oYLzNyr5aCp1lR+q1kWxsvNPDUvybJ4SMByJEk=;
        b=bPgK1mXcUGVmSfzymP8JEd7WZhm/e7XWpfM/lReaknCPPL+HjtFO/Ga1vq0tkE0dGv
         fLzQpEAgHk7AhawhL29vOWNoJtCdhZVnsVD22Y4o1yW0cwhhXS7ptVfkZA3u+4iH1izg
         Y9/h6roGwSGQ68UBRZercWQ1AgMzeEgGM2dgvnzeqp+85QqGd+ueQ9gwNv/lAclGI/bO
         zDCADYwKdKZKJI13PjW7W2jHbuq5FvEzNqzrBHpScTYPL4hK2AaqWnwQFKw5LbT73zFG
         Cpbr+oBdMN5xCeXqEf8FrE5Y7nkgequAbrV7UjWLKVREys+gTBD0KjuV/WFsnCdHzu6m
         mngw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ncb7oYLzNyr5aCp1lR+q1kWxsvNPDUvybJ4SMByJEk=;
        b=ynBGygA2ykJ+m0f3ZuL0qFZcYTy+x5xHtR6Vj1nX7OA6Nz6BqSDZFnaTQxfqwkMrGB
         1SYrRIzFT+20bZ1aI+DAd+l8KqxloXTJOgbMfN4dUOlfhKxbiyzcVGWSooQerqpTl3oI
         3c49n75PtqreiPWNBoFzcgvKyW1PlAaI9cLhJccyMr+ci5HDNiHGpZTyVynuXTL+xA8R
         YPHsdyhpGjVAnmFYCvsb51JMw0Q9oXxKRCvaWat0WfvZqiV+hNx45UgYajUCf2qMU/WS
         BZHBuh6DSuNHY9VbV9xYURMJAsepd6MeN58CzXnubpyzPSQ7QfeFgZOsLcDSEgldzylx
         7wLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/igGIldrooxkx/PPvNE+3k4NU20rVcoqeEJdfC/KI07l1S0UaE
	s8QaLJXmUcTUw9IVpCKEOr0=
X-Google-Smtp-Source: AGRyM1vPb95NpRGFa142lPbkq2dQfCbBNyYJjiFSAEflj/LLawBeOe2DB7Qw4gBKVIbyLtxN1/G9ug==
X-Received: by 2002:a05:6512:308c:b0:48a:22a5:f3d0 with SMTP id z12-20020a056512308c00b0048a22a5f3d0mr1858438lfd.494.1657893477118;
        Fri, 15 Jul 2022 06:57:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e14:b0:487:cd81:f0e6 with SMTP id
 i20-20020a0565123e1400b00487cd81f0e6ls1216141lfv.0.gmail; Fri, 15 Jul 2022
 06:57:56 -0700 (PDT)
X-Received: by 2002:a05:6512:3b0a:b0:489:da13:180a with SMTP id f10-20020a0565123b0a00b00489da13180amr8251922lfv.489.1657893476268;
        Fri, 15 Jul 2022 06:57:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657893476; cv=none;
        d=google.com; s=arc-20160816;
        b=dX3qFSK0MF0LLcHAaULtazBZ3Fndr7WU32J0xTeWkvp3uXTndNSTEMTC3eDWweojVF
         1kPZ7hF68fnhDpr03DLRO9uGozNi39MW8r3W29Ri6DwBt6bjXOiWt7NfNtisjP7a0IkZ
         Dk7qISA2DZgdD9g8bTq/pMCq/vF7Ze6UN2gvBDeHJ6Abs+3FXWZtiGArpyfhMf+lzeTz
         +izyR2+0+H671vqkvWiAqmI80xMVQZh7Se+i4gtLv21gpIDWOXQeChZV3pCQpEPHslOQ
         t99iOy4RgIfMBP5PBJ7W21OQMYw666AfeT/IY6JISkeQ5qCWg+sA2uHoGfuU0toZUaaa
         VZ3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eMXBf7KhZsXe8C6gWPYl/qlwrLsAnBlpMpGYf9/z1fA=;
        b=M6t+jFMGJbNSQ4zymtm03sNREt2pOLU/zubJSYNgEBCHel9BmXrUTQKbPGWusPWOwb
         YQyvkG60NmdEeZc11KwVZfYcWIJCVcibxp7UTgL4Ax3S5oaHAuh/nyjZux4SlloNwUOo
         xzZi7nYjwmCQEwuQVjmFNsPcNDY2vEQ+ZuN0dIfRxcJTpA+nfjvjVfiUwyMuLiu95wrL
         kr4otLNhsfyMg+5ZZWXUDSmCv5w/HlJY/l8Lm7yWYhav51/teeFuxrUUE/TZ8zqpPsuK
         Zr7Ws4hazU5Twja+aW+vHMNUKbVUVJTvVeIzp/fmOwyKYP4LpNSKdAG/k+49dv+CzPx6
         ewaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YPbRBCi4;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id z20-20020a05651c11d400b0025a8d717b7dsi136382ljo.5.2022.07.15.06.57.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 06:57:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id BB9B6B82C6E;
	Fri, 15 Jul 2022 13:57:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4D00EC3411E;
	Fri, 15 Jul 2022 13:57:49 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@rivosinc.com>
Subject: [PATCH v5 1/2] riscv: move sbi_init() earlier before jump_label_init()
Date: Fri, 15 Jul 2022 21:48:46 +0800
Message-Id: <20220715134847.2190-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220715134847.2190-1-jszhang@kernel.org>
References: <20220715134847.2190-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YPbRBCi4;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

We call jump_label_init() in setup_arch() is to use static key
mechanism earlier, but riscv jump label relies on the sbi functions,
If we enable static key before sbi_init(), the code path looks like:
  static_branch_enable()
    ..
      arch_jump_label_transform()
        patch_text_nosync()
          flush_icache_range()
            flush_icache_all()
              sbi_remote_fence_i() for CONFIG_RISCV_SBI case
                __sbi_rfence()

Since sbi isn't initialized, so NULL deference! Here is a typical
panic log:

[    0.000000] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[    0.000000] Oops [#1]
[    0.000000] Modules linked in:
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.18.0-rc7+ #79
[    0.000000] Hardware name: riscv-virtio,qemu (DT)
[    0.000000] epc : 0x0
[    0.000000]  ra : sbi_remote_fence_i+0x1e/0x26
[    0.000000] epc : 0000000000000000 ra : ffffffff80005826 sp : ffffffff80c03d50
[    0.000000]  gp : ffffffff80ca6178 tp : ffffffff80c0ad80 t0 : 6200000000000000
[    0.000000]  t1 : 0000000000000000 t2 : 62203a6b746e6972 s0 : ffffffff80c03d60
[    0.000000]  s1 : ffffffff80001af6 a0 : 0000000000000000 a1 : 0000000000000000
[    0.000000]  a2 : 0000000000000000 a3 : 0000000000000000 a4 : 0000000000000000
[    0.000000]  a5 : 0000000000000000 a6 : 0000000000000000 a7 : 0000000000080200
[    0.000000]  s2 : ffffffff808b3e48 s3 : ffffffff808bf698 s4 : ffffffff80cb2818
[    0.000000]  s5 : 0000000000000001 s6 : ffffffff80c9c345 s7 : ffffffff80895aa0
[    0.000000]  s8 : 0000000000000001 s9 : 000000000000007f s10: 0000000000000000
[    0.000000]  s11: 0000000000000000 t3 : ffffffff80824d08 t4 : 0000000000000022
[    0.000000]  t5 : 000000000000003d t6 : 0000000000000000
[    0.000000] status: 0000000000000100 badaddr: 0000000000000000 cause: 000000000000000c
[    0.000000] ---[ end trace 0000000000000000 ]---
[    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
[    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the idle task! ]---

Fix this issue by moving sbi_init() earlier before jump_label_init()

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Atish Patra <atishp@rivosinc.com>
---
 arch/riscv/kernel/setup.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index f0f36a4a0e9b..f5762f7b982d 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -269,6 +269,7 @@ void __init setup_arch(char **cmdline_p)
 	*cmdline_p = boot_command_line;
 
 	early_ioremap_setup();
+	sbi_init();
 	jump_label_init();
 	parse_early_param();
 
@@ -285,7 +286,6 @@ void __init setup_arch(char **cmdline_p)
 	misc_mem_init();
 
 	init_resources();
-	sbi_init();
 
 #ifdef CONFIG_KASAN
 	kasan_init();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715134847.2190-2-jszhang%40kernel.org.
