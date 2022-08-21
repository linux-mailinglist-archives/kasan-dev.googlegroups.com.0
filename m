Return-Path: <kasan-dev+bncBAABBPH5RCMAMGQEPES5CGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C871059B45C
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 16:18:37 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id j13-20020aca170d000000b0034564366571sf18877oii.9
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 07:18:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661091516; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ql8Cz5LdbQfxmZUB3pCWfZ8ZAhgcvVZdbMVBZ7EV+0jOU1SFcy5Lv/IZMfIiLaNuKz
         jxoSTXgI6+iGqkS+UfHHQ1Mwsv2ESQCMU9WoCMtOCKPln9h10rwQkyrYvB+qyjkhi+ol
         hiZKtzARMcDNrHpJV0+LxPaDJY4cI5aWw2S4Etq+rT3O35ZIyuJwaUdiuoo+ddc3nzSW
         VXTP6nQqSrREGEqx9k0t5ZqFagGGlOpfTLf1txqajd5REp2J4vRzI981rjT+nzwqo/00
         TU2fUdoqX1Lz/oI8MsiYf7Lihf2XdrGfx+0J7X5B4vNA2mvQP0M8IOZia1kExe3BSogl
         x9Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4gUhdYaWB5Fu+khcdbEDs5xvvSzxWAOOGGUIX7hn6KY=;
        b=Ap5LlMxplaXfCGgjLG1r+7II1c+tmtEvKUDF5Adbw+SiAeu/G1nc7SEeBLV/DM8ZPa
         iy3EuOBmRvvTM4nIzgVvpxZWdA3hZ+7kcytIX6ukOQCHG+lwV7FvmGhYxdN18GA4k/R3
         OeP2qBCR+dCF+K7Muy3IjO1xqg3pAtWhwd9k8L7GroNNXv4MCfFae5WzicISXNHI1OE2
         AF+Eelp1KX3FPQHdfyqHn3aiFciytCg9cn0fmG5UExKGg2iasw+jJI02DYXSQUtEYm+G
         +L7LU0dq3/dkyV/KmfxXw2GpQ6lOgZlcieHW/yWYI12TfiKVnxiMXiFfrAoSr7seopcF
         c3rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lLoUbh4e;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=4gUhdYaWB5Fu+khcdbEDs5xvvSzxWAOOGGUIX7hn6KY=;
        b=Jkm9bM+vo7g/q1mLJ1r2CIJ4BKeXRK/4l795PqrefIO7C3ycnOYqLabnVT0TlkURgV
         CcY1kesDZaT1KvDOpkqdvny9EkrH7af6fxzPcB/Egwgty5kKqZtmo4PguO4KjpWswRNV
         864Dfa33d7OrcDL/8xYkwWBouguN9LEQ1ot4uxbMM2RIwCXRQtjTtPREkKY2xt0iJrSm
         nDPkdYZyGq6J/adaxg7FTBuC6ZuQd8iMbqqY3v2JQQI0GtrVc19JhuyvyY900nEY2z7l
         b5jMrq80R+294AmGQTEJCFSysR2ZjGAz2hVnh8f6D7J2XsRh1m107r1oUakPlqqgt4Ll
         3tvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=4gUhdYaWB5Fu+khcdbEDs5xvvSzxWAOOGGUIX7hn6KY=;
        b=1Mtu6PlAVFpWQjpMo9NgyS5obRw1e/6qOX2rPfWoF1LujTTCyv7iy0bKS5LmNaTaPo
         yKo6EXyUwTN7L0Hw9JjtrfKeT64LDAmYz/zVwb+J7Ks7KEKud9RsYhLzvoYG5hBvxDRX
         08DMZPyk8XsK1RtmIO9oIIqgMbJttJVqpFeYE46RbmpwzSzzUGSV7G0uS6UW9+JNssLF
         6ajZUnvs2q3+/9iCuL4MKkDxw6r1BWH81mLXCePB3KypO92QbDLaa017eMPEs4J31/PJ
         7MOGT2QLtCCO4QTgAXiX0iOPDJrt4PI/gmmbaIouBRqfzLlc2jsRgg2MWc4xTNXsTMvj
         sHDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2tWIgyZKe7WZrrlEHS2IzWovIfSup06pa2KmtqE9Kg1jo5l9Ir
	6MgnmqYYcTfc+tmB9iME8Lw=
X-Google-Smtp-Source: AA6agR4EI82sOoS3aMCPti/k4ERwu8SYXt46fB3QqHcA1Im3twCoK5JpJbCeZPbw61w+xi3hhAalpw==
X-Received: by 2002:a05:6870:348f:b0:10c:991:5c5d with SMTP id n15-20020a056870348f00b0010c09915c5dmr10235567oah.67.1661091516353;
        Sun, 21 Aug 2022 07:18:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6e9a:0:b0:61c:ac06:86ce with SMTP id a26-20020a9d6e9a000000b0061cac0686cels1360740otr.0.-pod-prod-gmail;
 Sun, 21 Aug 2022 07:18:36 -0700 (PDT)
X-Received: by 2002:a9d:f27:0:b0:636:edde:81e5 with SMTP id 36-20020a9d0f27000000b00636edde81e5mr6604776ott.46.1661091515980;
        Sun, 21 Aug 2022 07:18:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661091515; cv=none;
        d=google.com; s=arc-20160816;
        b=JNmVf4gwoWLjnIKPNjQXWV3NG9bAPSjZc4gUrWiyXoHaCVWYMrWNsCVCqvYoi7m2yg
         2UMN6BIGFhOp6AtWnPn5BCLNuwU7biBPr+RlNNwUNK2oR081unjbxT6otH3bblr0NlCN
         cqvqAY0l05WIC5hl/rI2kdg0pjx3lLipB1QE0DNcke0hiO6gELOMT4JZ5vvLASidH53o
         XqMNnpjAyfDP2ptkLrV4XbrEKpJZJh8FwARNjcP7LXS0sYOInAWvXjv5i2zR/BueA/SS
         5c853UrzVaOehL/kyD6yr36CVIZ1ThXtdhdf55l6M2OSEhc+RDqvYmlmOHE3BLx8hJM7
         ViAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ta9syHVO05gEWGvueJILtuiNMof0fzQ5Xx+T2ol+JG0=;
        b=VmVpW+CVRUKGLakUXtJFn/AWX1KvTTNRVjh9uNgjSivMLTMwvmPyYnYAKe2kHOtet8
         yBlZI/QBHa3qaHtCK729bE+EmzNRm/BYEKIPYjwmkV7ROjDPMerptkKY2Bg6FUN4AgBS
         xdYMNB05D7aUjQQ2DOO6K67kovG5+6NR/4QkO+EuK0yk1G0VSm3OGWD1uu+SiKWRzoh+
         eLeDs2j/U6Izdwj/2U2uinHLf0F7oCDZrwtpcbptiWwQDhHqClYfQtLss9sEQY1AWWhY
         wRFAjnAX274GIIfrvAEzqUmLZLhajVChnBaBx+GFXwXz6C79RK9vEMazcqgLlkhZVE1i
         cVyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lLoUbh4e;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u18-20020a056870f29200b0011ca4383bd6si1086640oap.4.2022.08.21.07.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Aug 2022 07:18:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A2D0060EAC;
	Sun, 21 Aug 2022 14:18:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DAC36C433D7;
	Sun, 21 Aug 2022 14:18:31 +0000 (UTC)
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
Subject: [PATCH v6 RESEND 1/2] riscv: move sbi_init() earlier before jump_label_init()
Date: Sun, 21 Aug 2022 22:09:17 +0800
Message-Id: <20220821140918.3613-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220821140918.3613-1-jszhang@kernel.org>
References: <20220821140918.3613-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lLoUbh4e;       spf=pass
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
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Atish Patra <atishp@rivosinc.com>
---
 arch/riscv/kernel/setup.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index 95ef6e2bf45c..19ead6877c16 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -270,6 +270,7 @@ void __init setup_arch(char **cmdline_p)
 	*cmdline_p = boot_command_line;
 
 	early_ioremap_setup();
+	sbi_init();
 	jump_label_init();
 	parse_early_param();
 
@@ -286,7 +287,6 @@ void __init setup_arch(char **cmdline_p)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220821140918.3613-2-jszhang%40kernel.org.
