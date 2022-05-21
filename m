Return-Path: <kasan-dev+bncBAABBIPVUOKAMGQEDVQ5XJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7204852FD6D
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 16:43:46 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id v124-20020a1cac82000000b003948b870a8dsf7749941wme.2
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 07:43:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653144226; cv=pass;
        d=google.com; s=arc-20160816;
        b=UsYR1rjdB7GV2uiRCWDACGX4pvj3idEny1uDzSWa945sRCgPpBrZW28GZblTahjL6I
         +zTBuMXLTcbv25ys0bfy7HytdWVH+KrIGDTuvGSlGDzpinVQEgOTFJsKLcjQwWhRP4YC
         xoSFUkkr3xGBoHx0sFeppUovax0UakHBvo7X8cgcBzGTHQ/ZMe4Y1n9ulljTFnprIsyJ
         jOp2boUFsMmI7VooFeQI8X/SiEm7osEQehaAl3qD2GoihzC0MZvF+fNJRCtcWYnYLF/K
         ShtXqWgKjb0QDaaHVd98w1Q2pGo/D0qYneChOpH4T7Fb2bg5Kg0N8mFKML/ywgHvFARj
         NGFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mkrc3g7tDzwxG8Z5R2SKdM9GBUsFlU2lhGcKoiD9t1Y=;
        b=bQLDkYQDm/I0Taxrt/ab7HJd94OJSe5zm+4SE+3Hjg66NfvZHw+PoDElzEFmsOzx+C
         ec+TyPeR9wWcu6cHjS+I4/YTf4y+WTDx6pLhHbfUMBbWKu4txSaMm5W2QqDu1L5vtau8
         K95JVCWowblyAW08qjJV2zDT0bbAHq4ZKriqvPkFqcJr2EpZVR9no+ExLIRNZRoINPZT
         TEqpZ4KLizS+Pf0STF6GzG210I0jIc4ZgbtRxTCu+5bu3yAyknrZJRVsWeFHcpPWbxlh
         336swMgnK+/8ox7JITV3SoGcjzKHI7JIiKBrsJqjbGAID2iMYSZWe9lP73ludwAspqNs
         q9Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MDN3oAuJ;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mkrc3g7tDzwxG8Z5R2SKdM9GBUsFlU2lhGcKoiD9t1Y=;
        b=eAHn5/l9RIOqb8uI2tRjWB8AbNeVOTeFD6ytk/fvTKQjCqFS1Psjp6Lem+1w59nQY+
         h7jiCvJrIWEaOe1ne5wWWvyOpMb7OOUA6mFOvP12aTRSLwcNo41r7wdlq0jyJoOqjqld
         wTlCP8mYe2Zs95YQXqcAaVQLjksCct0qh+b8x8I1VW2pWGGo7vI7nhHysamvyEdvwIqu
         btlKHh5nVQVFUQSvT6yQvoHXfTIDmv+7aufOgkslViHFbDZ0Pc2z10LnU/bl+QWNHVcS
         MS8NKSTxE55bgVSNUfNCVcxWunbWAomhTgZJTWDdUfzug3ktL5bfmAgVL0SQiACUXkx5
         k0VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mkrc3g7tDzwxG8Z5R2SKdM9GBUsFlU2lhGcKoiD9t1Y=;
        b=CSnplbPtvKRXQ228TTwUI2y93P6oX5LanlLfgGiJyJdQyM2kbx/FVxgTFRaRLXXJD0
         /7nbu3+33nXx/uz2kBFR3BGvmlU9YRVWS/IhQnSWlRlUPim2QiIl7s0YwkxILdTLDS3t
         frwumszTDWXDx8OI2GRhzn09F4q/BB4sZLu8tMNxlBf6aQoYxzY4DA6lWQya1fxoVU7+
         ZnlAKL5GOpERsEUx3BNIYgmAKToL8WaddJuaynSKhTHbh3KV8ls/fgjupS1vv2Uuw2zP
         Ag3UJxQFoD3eH9H7J+BnubpjhQd+PNhPni2o4S5moW/gJTMyeXx75mR0zLUis6AEZ51p
         MgnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53037Rcdu9dgzlmncm0wTpxccTmxdr3/CBfper0vVS0ABaQ1FSov
	2kFE5uWP3EyuO8TabQB/GGo=
X-Google-Smtp-Source: ABdhPJw7blvj2RcbpCAZaXPlPvexb2xhckwwLRySa7SPzbInLCFrT+2EV9VtfItEwq3BMbewtJDmYQ==
X-Received: by 2002:a05:6000:1c01:b0:20f:c6ff:43d9 with SMTP id ba1-20020a0560001c0100b0020fc6ff43d9mr2890935wrb.156.1653144226132;
        Sat, 21 May 2022 07:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f11:b0:394:7a2e:a847 with SMTP id
 bd17-20020a05600c1f1100b003947a2ea847ls3778509wmb.0.gmail; Sat, 21 May 2022
 07:43:45 -0700 (PDT)
X-Received: by 2002:a05:600c:4fce:b0:394:5f8e:8124 with SMTP id o14-20020a05600c4fce00b003945f8e8124mr13234121wmq.107.1653144225352;
        Sat, 21 May 2022 07:43:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653144225; cv=none;
        d=google.com; s=arc-20160816;
        b=HAcpTZUT21Ab9skF2JG8SEJkz0UJxsjJXqwk4IOjkP6IiOFWuXBEmvuO+d4C5XAmvN
         evbYrDdAHBAbE6+mP2Pq/KViPYR4J3MUdugRyekOuIBlh7JctGk9mEk43Vk5De/KwJHy
         QP8VNQAWP9rqdksjmD2kYvRuq3qbpuA+b4dD2gfuFRm56ZCqXEot01Shp2E/f8yLiA6O
         JQYDYbdeA2kjjUIau86Q5eqoJlcuJPyyzFsaw60P7neOySmo2QB2dDv/IC9FUg7Tawr5
         sKrRVUNftE0Q8kPHAbehyzSkB/IQdRrG8EQjOi41TLBkeC9ga4CtYiGvCQfLGbiNm8P/
         BJNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/vLhOSCP5QNhrXNB+0eP1Vbw79xEqu/cnNqULBdNP0g=;
        b=XNtB8IM2EOiILkNO7a+zt/Ak1vDlX0dBqeKY/JD9FNSS/z/yMSvKQft6QX1Nk7zlPx
         IiMs5xeWezzA1XfTLXoHqURrWyAIG7Z3bdwb5m8vdjPQ2a4GcAgFPCwGuzKoAmDg0Q0b
         OBIyC7sVL/7p8L2nOR2JS+wJZ1wijt8IhsJISHntzxTGgvHtzdwAhoK1AajsnXv7ls7Z
         aBMJVw9yf4FuTt16ZbKgwa+WWTTS/OVu8t2fMSZkCxrtIzhTT3nFJ7ZFgAWVoAAWUnwr
         dUJQZYwiomH4crVYBTmUAW2YmacHq6GENjPGPjGZb30gF8qwar8hk7sxI4HK3m8lC0RB
         8Sqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MDN3oAuJ;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b00394803e5756si325606wmb.0.2022.05.21.07.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 May 2022 07:43:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1A9DFB80687;
	Sat, 21 May 2022 14:43:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 31233C385B8;
	Sat, 21 May 2022 14:43:34 +0000 (UTC)
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
Subject: [PATCH v4 1/2] riscv: move sbi_init() earlier before jump_label_init()
Date: Sat, 21 May 2022 22:34:55 +0800
Message-Id: <20220521143456.2759-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220521143456.2759-1-jszhang@kernel.org>
References: <20220521143456.2759-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MDN3oAuJ;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220521143456.2759-2-jszhang%40kernel.org.
