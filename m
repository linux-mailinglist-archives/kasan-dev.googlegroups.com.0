Return-Path: <kasan-dev+bncBAABBRGQZKLAMGQEEXSGFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 136F2576DAC
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 14:00:05 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r188-20020a1c44c5000000b003a2fdeea756sf88588wma.2
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 05:00:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657972804; cv=pass;
        d=google.com; s=arc-20160816;
        b=F9jVwc9R6Wb9AG6/DQCXMXio7iqDbaf5kp4zTPPT/DOhLrrxF/Find1WyC1cdg7KS6
         oc4dOtr/kHRBoKW15RCGFlzUFbV1W9gIGnTKBT3UyJvGAzjJS1gzunozwvYKw/H1hPQ5
         af+v0/eJMUjs5LrRes856rZ/ZX56PnB2xnHlE3Xn9E8SwtbLDfIQoE7wrbvTYoRk7QqJ
         npuc3c/gmoquLvOHd6UWWbAcqP2udI9VrHw4U3XzetG0rEzFnZyz4npDLaBvrRqlQIuz
         H5yNDE0r8RJ3hUeek/7jLH/z3rga6RD86MlBO+2LveOXG5obF0lLe+6J793SD5VJsC78
         SqUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BGo+AvwgBAkBlLe6aUp82rYBEzR4iMwmFx4ujdUagk8=;
        b=jzQsdZWeGpSCelysuBEHS2+b/HkajRL6JOHqXaEo1LvjrORGgMz4EFWlfzqh9GUMDO
         KgxbHC2iVwMhAH3ok90lNg86cHPlIxpSuX+f5KTccddAFKjB7CnMwTi3Bh/F7jfb3ovX
         rF9hXvk2Q0o5f+sc809+xiIthzTyddUVD4260nexYrupkWBI2S/emdKnql/JhNQASJEc
         lD+IZgtAjlATbtjmCJ8vMQ252ThfP/vypPZ5f1uJ8NnztJ40QzR1c47Riqf8J+JRlSeM
         rRMtHikW5Z5hvy3mqoSR/WIlTcDbAYlBbKPufQGzlJXnr0WZ3rXuXsis53MkZB2rjpoD
         vxPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZDDi5kb7;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BGo+AvwgBAkBlLe6aUp82rYBEzR4iMwmFx4ujdUagk8=;
        b=SfE457Rhfpfvj3b6rW5SvxSFDax1bmxpfMwy0DOenQxUdw0SmFf4eu5h7xGZH8KJ2D
         GskcWiRjMB8UAQ3jf8YF68cYv4qRb+RM0xBpdKXcabeZSaAqhW/ye6m01vzZSfh0bkmL
         i0QSf7GN4MtF1toPJaWzG49jA0ohpdFcMlTANz7vC19yjsSPwe6vYKndKJ6yUXxv4qZH
         4BUEb2l2x7HnkI/3P0b54/NSm7/FOIu5pU03vAi5aHZ0UKq1Gg8bQP09jVFw1SAU9nyf
         Ji2a6BoWJMrxWi1RuPqsGPcgCcOGpvgcEPzlzt7i+hKTXUtqVb8dzmMftaCAb7TdToNZ
         DfYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BGo+AvwgBAkBlLe6aUp82rYBEzR4iMwmFx4ujdUagk8=;
        b=SpsPSteeT9iL2aivCnvosRTg+RpVGRCJ+VOh2Fto33/gVvLMNDA2mxPcoy/iFnWRKM
         qKanIz/6MNEnm0XIjo8m2gx2E6haKnnRuq0ozsTLGLiBZ8s2yEUxLSX5d6CwKRoithTs
         AsARfGB4kxCtK9WBnM/hzfoHZjZ1PjN4LPEQsgKj+3NaGJFWCrTame2LTRq9MNiBXWZS
         nNnYwwb7+XlJrNq/A9Khkfe2Jftx2UA7To6pUaHPNevpJmR0Gh5KzC3+r70bxpwirmLK
         8OV5tnhNJC4RacjvLcIB8kweKqMUWsVWS/bOn3VKzOZxkByaifvfG65VWRQ6hfJB+em1
         /E+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/xEmQPnYACNLsbnVz3uay5+kmoVfgkopTbNd4vPmWdBfmuYcm/
	oYtP/8HFS6F9qGklBf9aaCY=
X-Google-Smtp-Source: AGRyM1sqfCOVjf++LofiFlChmGJRZ+hDKWSatTZy9Nn13q17TQhHlSiRf/G8fTkJwiJszYnnGFxo5w==
X-Received: by 2002:a5d:4bc4:0:b0:21d:918c:b945 with SMTP id l4-20020a5d4bc4000000b0021d918cb945mr16029313wrt.287.1657972804588;
        Sat, 16 Jul 2022 05:00:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls7030774wms.1.gmail; Sat, 16 Jul 2022
 05:00:03 -0700 (PDT)
X-Received: by 2002:a7b:c8d1:0:b0:3a2:e502:79c0 with SMTP id f17-20020a7bc8d1000000b003a2e50279c0mr18306690wml.196.1657972803819;
        Sat, 16 Jul 2022 05:00:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657972803; cv=none;
        d=google.com; s=arc-20160816;
        b=RLpty54/JAktXvN/vTQ0eS5RV4RhXBfzw5Nep3ex8Eyu6NWRExzU4eCp1M3Nj8/sTX
         GwkSo35pyoyB2izpFN54GkMAEV6GR9df53i2ekBpkoLJHbmHD6gPgugiCH9jed1+ZLJ3
         qPP+smVzuI25BhyzRydcNyE+olJuLmBiBd/o81rhPtk154JxDBiRrTq6KoUrJk58UNuO
         R5ij8n7DiutvYWM9UHvigg7BauOgefiRPg8gX3Y7N8kMKkyc6MkCAsOkr5M0LjxxCe/b
         ucYp+q7ew6RKI3eEzpEXi039seMJ3hgFBuodK4/gSZ9fg18KR7tPGlk/Xau2P6d3jiKk
         YfQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eMXBf7KhZsXe8C6gWPYl/qlwrLsAnBlpMpGYf9/z1fA=;
        b=gMiNyMJ+tt4dqJ9DK9ViM5PC/0rv02mEaUejXjj036JOvjQRJnC+WJ+PeRgbB7NhZF
         0Edk2LLh8OHHD71xbCDyvY4PlvDF9xH+Deh9w5jUwqPkJk1GUD1SjWplf4S175dkzj2z
         lEBT55JM4ut3FzqVuiHY5kkNsgKgWeiQFqwZBJvpNjPmbx7paMgqdFCnkwL3YFzvOucK
         rgLqU/qc11+m2IZDIgZQDJPUZuUl3CThgytk8MGnQ0Kx4AXf6MG6fTk+ehcjv6LC29cZ
         KQKKMpbipJ7cohnGmIZCOArWC9IPfKqqUOfVyrFJXtT0LQ7MZA245uh6N9Sbz0eDXc8H
         iMaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZDDi5kb7;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u3-20020a056000038300b0021d9c42c7f4si171148wrf.2.2022.07.16.05.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 16 Jul 2022 05:00:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 7D623B80022;
	Sat, 16 Jul 2022 12:00:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 02EBCC34115;
	Sat, 16 Jul 2022 11:59:58 +0000 (UTC)
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
	Emil Renner Berthing <emil.renner.berthing@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@rivosinc.com>
Subject: [PATCH v6 1/2] riscv: move sbi_init() earlier before jump_label_init()
Date: Sat, 16 Jul 2022 19:50:58 +0800
Message-Id: <20220716115059.3509-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220716115059.3509-1-jszhang@kernel.org>
References: <20220716115059.3509-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZDDi5kb7;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220716115059.3509-2-jszhang%40kernel.org.
