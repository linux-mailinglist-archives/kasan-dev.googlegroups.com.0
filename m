Return-Path: <kasan-dev+bncBAABBZOWTGKAMGQEWRWEKOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C23A652D9D2
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 18:08:06 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id r9-20020a92cd89000000b002d16798b3cfsf1393763ilb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 09:08:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652976485; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZW/HyGuEw1oDHCerrKHeoQMiWsVJGBM5mZBK5omAfomqPxsHCi6rqAkWw7mrN9vt8l
         czGoTfOGd39/mH7E89m3vN7Xtbc6CVaQttlie3sjXt8NDi0dlmTqhijFWVJg+5QAFwmr
         ibRi3f/lJErJpBDjidxZcniH0TatyX+oanttNlcqSz3b+EpykDD6nDmibMOCVmjLxjin
         3EsFu5b7g0MehCLqcqeyvjVMG8q5F5RwbDx1RH075azqEKp9VE7IUeozUiiO4KuD3r5D
         XgzGIh9mLSNZ6wg7yEpM0AJegl6FuCpEl+zGzKxmv0wXi4san0lb2dGL1loEfTY5eZ/1
         GGPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pfkZAWlEQvfCqvX6fzbR25gVwov1RLVSkIzbK6IhJ/s=;
        b=EcJPRlLEcctkyLb/BLHyzGqS/nXAECOX9AGCcT7QZI2J+lxRWXBftZ48rQ02DUHsvj
         QOOyUp69mtsPIcdeAzxARX9jouoOygL8Vuq+SUmQgiGh/BCgXrFvy03OQhG3DQrplCgS
         K/gqmOvRAJjegMOApihdHSJUR89N9xtcDRC5Aeb5IYHh1nzOp0FUbamuo3FI+ikzP5HM
         E5ehrmwMqefwDrn/Ts+Lj+Qx3/49gXwcRD0YvQnaO6jSKnWWxqJdJzK28xL2JiggBDY6
         Ny3IVqtlFMfgakF7JhE+k9kv9oWAId4xz0SrKZ82fBFzlc0L5CPexUSnIQ4X7q2sm1f7
         l7gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YonGe4NX;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pfkZAWlEQvfCqvX6fzbR25gVwov1RLVSkIzbK6IhJ/s=;
        b=bSsBZ/v2Y8Qaf7I2F+a9zwlxxWxalnOq5Ff0KKw+gICPTjTxqB8gk3OG3FjXYOBjW9
         5vddOve2iRhqlwG+8jrE+pE1tUBaTLgPsZ/bj5uYbDHtEo4TQk3CtIDLiB7/aDLBt52S
         YjNj2IN87xBkYlyFk1tWrCPu2tkZWKvU1bd0iOwRRutX84RCkozU73NTKIlNadyu94kA
         tTAKHIKWcZriVbiCKEopRQJ3CA+1yW8X+4enBcj4SUMmWEVMlqGkC8BQhpF0jibXgjhu
         Eu/X3RcC1WLIweuuBk57r3pk7MkjaQPokv9J2RX+MzwLOFCbzW0xEtA3f9hPqF/mv2fl
         sF7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pfkZAWlEQvfCqvX6fzbR25gVwov1RLVSkIzbK6IhJ/s=;
        b=KwGl/jM0/CNrmsgA4YIZe48XIE7COU/lhqbXgCVx7KJZoLGSthF4GwO4Ujpe6NIh9n
         U5ElVx9DIJFlRO/xiyc4pQ/Tu2ujgcaXSXfNkq/5GJ/ECPvbIwZpRYARcWkSW5saxiHK
         tzBthUUt4Sgw2fWELdt8ViTn1PGSqgs42Yg8O5TtmFM5yRsKncJm2jr5NEoXwk3X2ZFu
         rbXttUwK48C+eKT8j/ZyworKEp4tdxMHAnkuQrSLgyddPZ0dzo0z/ZP1rtUuEjMYz4MA
         CrwUjnywK6TIu+mL/ITdIN36LJOhfJ0wU4y8D5ntK8POcWlDPNWRjE6cRmcYkKBU2/Sp
         zZ2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XnhEFEoWwwMXVPYVtPH5b3UmkjIrxklWQpNAgEQzNCM7en5Ir
	zHWRKnk2FFZEcrCDIacr14A=
X-Google-Smtp-Source: ABdhPJyqnOcRrlNw7LxYZu7Ejhzp+VlHdtmDGB4KZwhoxtWmC9OqbajjoKh5/jWoN+LFmKpECPtEmw==
X-Received: by 2002:a05:6e02:1a82:b0:2d1:6d48:db99 with SMTP id k2-20020a056e021a8200b002d16d48db99mr1622737ilv.232.1652976485515;
        Thu, 19 May 2022 09:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2ccf:b0:65a:c4d1:896f with SMTP id
 j15-20020a0566022ccf00b0065ac4d1896fls349750iow.8.gmail; Thu, 19 May 2022
 09:08:05 -0700 (PDT)
X-Received: by 2002:a05:6602:2dc4:b0:648:adac:bae8 with SMTP id l4-20020a0566022dc400b00648adacbae8mr2899785iow.9.1652976485152;
        Thu, 19 May 2022 09:08:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652976485; cv=none;
        d=google.com; s=arc-20160816;
        b=zrGxDgEE3do5KPt1Pu2uHsGCeHWzu8wUuOjoK45habI1HkehMIygIo32dNGIFks3zK
         6Hp35vnfthQIjz0PqYRhT3Quxg1I3alKgQckgkhoFutu57UTKUSP/1WxPrR13wNU1cWy
         CqEYbh+eJIcDlae3HB4WQQh+b0mhPBEdCZV/Py382wYs/mNhqryLozePjq8WGXfJqBBh
         TRc9QtczEgD2sekSnm9AkoLLiOwKzw78AcKY2jUuTckUWl6JC2Rxi/HVYMCtQlnF6UpR
         CxHIjTPRXGTIQJp4nqLqYbVf98Hja1SlinHPR2TRNhRpGmouk7dkKeUiP/fTmmMbNN8D
         r1Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/vLhOSCP5QNhrXNB+0eP1Vbw79xEqu/cnNqULBdNP0g=;
        b=z6EvPFLc2GUgyYYP9d5pcYVQZ0KYFIuG8GLIYx4aPTg+/iurmwAdyKGjccfKBtOuGg
         DWZId/c6trq20rc8meBaknwCmyakoJEn6uraIdpBX+00thQE7a/5u3fkYtGWtY//aiFg
         ewX2G5uBlfghONtU4tPcEEjE5KqhoTEcB7zDU3uROl5HxUdxIT4zPgcWiN5YzuBQjjhu
         4lr3P5z3ayJOjvz/4Blyj3Y8HW9ecbVp0dZCEIpeGISW/WHoVXbfaHfLR6w5+8tavALA
         Q4NJdInkWnBdwYnkcyvZdQIQqBdgfdi0S7l5do1sPfbQjw+hQ/w/c4EZuAKXTqwtwfQj
         DgYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YonGe4NX;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l4-20020a05663814c400b0032e33893912si252jak.4.2022.05.19.09.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 09:08:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BB7F961BDC;
	Thu, 19 May 2022 16:08:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D17CFC34113;
	Thu, 19 May 2022 16:07:56 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@rivosinc.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 1/2] riscv: move sbi_init() earlier before jump_label_init()
Date: Thu, 19 May 2022 23:59:17 +0800
Message-Id: <20220519155918.3882-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220519155918.3882-1-jszhang@kernel.org>
References: <20220519155918.3882-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YonGe4NX;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
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
---
 arch/riscv/kernel/setup.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index 834eb652a7b9..d150cedeb7e0 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -268,6 +268,7 @@ void __init setup_arch(char **cmdline_p)
 	*cmdline_p = boot_command_line;
 
 	early_ioremap_setup();
+	sbi_init();
 	jump_label_init();
 	parse_early_param();
 
@@ -284,7 +285,6 @@ void __init setup_arch(char **cmdline_p)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220519155918.3882-2-jszhang%40kernel.org.
