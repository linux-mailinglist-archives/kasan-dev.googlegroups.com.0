Return-Path: <kasan-dev+bncBD4NDKWHQYDRB5X6UXDQMGQEFAVH3GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A4B4BCEA42
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 23:49:44 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-7fa235e330dsf107277946d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 14:49:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760132983; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ht0kNUKqYWuOQANLrOwhp16mrbKmtvGw4LdNib0v7FEdEt70zto29vAarC93n4C0v6
         JKFjwSdvc3AvUy7iue3Bfprf1wbfifxgVGKOwucjerHfPvoqL5NuJTc3KEpw4DJBFgPR
         3CTfqfYZSfP85exFi7/QNrvhPFiXlSKmkOwhVy15eVXLqM7V/oeEX5QrWtIiTFlYY+N8
         VQf//PzSqsOeyBaP4+CGqa7Vbr3pxECk+68hLDrZoyCQut4jFetlxkfJBqfTf+1/DjBh
         SvVo0t93uHkQ8UaHIo+7pTgb0IfkqK+9iYYIWiaYav0a9zx9+p5FjcSXTP1B5RkgMmWF
         VevA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=6B7VCp5eHawPLY02srblfCFjsLhObMEhfMnGuTjklxE=;
        fh=aj29eJjSWyBGHmYLB0b5DOXz4A0Qlx947nXLczgsWWM=;
        b=XxkUVV1KFd6umIDXVqswzMkLnkvAHM5lsyt0ewPJ4SRw5bhYoMLfLIwJNznNjpSXvR
         dsG1ZlClMOzNqPMcbJlLCCiuRz+pNVi14abA8/RxQLoxcRMiHOMzdMsGjB8qUG5Fw9NO
         ZWMEGYChJQLH2Nr4MyIn0iKCHDmfsFWZTpnyDkoSiHSYemBXIYYpNazx/omGgefLuOSY
         DgbOiHIZJdwWuX/BLsxYztlX9BDYi4dRDED3WNPV2myGNTuoGLeOqWsLiQP8JkOQ26eU
         TGp+0aT+ffpFGE9L/1iF0+PwtgTl4TnJsp8vX5KzSjjhUN+nzS/1Tz7F4q+CHaH24BZb
         zTdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hvBAVpKx;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760132983; x=1760737783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6B7VCp5eHawPLY02srblfCFjsLhObMEhfMnGuTjklxE=;
        b=Og/ps0RXZq8cOB9HeKumq6quk2OTb5sNj48jPww3+FMNvA085BvH9MO1agMVihiNre
         npy+GNsi6FiwbMTi2lpUYWwSbRSIyra4MjtBOxgvvCf3Ezw0txVk8ytuanY85eek9+HM
         YEW34cX6/HVe3pPWQmE1ALCAF/ALbSHYX2bV/8A7zI0cqWPg4QOgKHwxcVnA6vLmxmjm
         92mXloFAPeOYZMAUC+A+V5w5JWYk7CcpCVC1QqmdiGE9JOtjeD0Dc7CTfBEGwGN2Q1ef
         /05NSCSQejisfW2LmLncQ64u0fCLX/ap7ivlV2YoXdAG/nA6fAoKAQlTYCM0uDjN10LM
         Peeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760132983; x=1760737783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6B7VCp5eHawPLY02srblfCFjsLhObMEhfMnGuTjklxE=;
        b=tMLAgivVlrX8DMHMbYTT6g5YnIyyyylVLt+Und723YtQ2oNjNQ/UkHtbFwEGAYKHiV
         ELItgubnmE12qBj0XskjjmaHiPDVaSQfkCpi9e/me0W4Zc5m5Hgs8kZ0BuCJhV/xLoBD
         r3ZXzCMTxMrkv02BqnRf9GO/jY4av4xGiUDpLYFcalxBDD1s8pqMfYFJvqlOPyGAEgGA
         cnUOYhtMJyC2eRhMngjUjTs3UB99JY0in4h1I/FqlquYnNT0M3OARh02aYD3vRMNje++
         NmwljF/JfTTNXvl+hAwwwIseKYeTgZ/+gUPkk09vYH4dywnQGoIkD10/8nSTPOm9TQ6r
         1zoQ==
X-Forwarded-Encrypted: i=2; AJvYcCUvOSHJBPbQaQGQwyXSQBlU6iqCbScYJzC5zVU69ZqBV97gj8P/ORV2zmVWaoThZ2VChoSEmw==@lfdr.de
X-Gm-Message-State: AOJu0YxaG4XHhTp3SwmjUbDqpk0PMPxoi7pjqi0fzi69dqNOr+G0/RUA
	Otwlq+giz4hZipI+Cexgj99CzjVuOViFd4CN07AOvBc5rbtoOH0Tm/Rj
X-Google-Smtp-Source: AGHT+IENKkOkTm712xRZVsjtg0UPPfDOtTl035yn9IJmQdlOwNEDvjMb9LhMlw4eEtChG7rZ0gh82Q==
X-Received: by 2002:a05:6214:3014:b0:78f:48ef:d8c with SMTP id 6a1803df08f44-87b3a7e7b73mr156774616d6.22.1760132982955;
        Fri, 10 Oct 2025 14:49:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6bgE2GIxZfzvn8DoZ+DtUORbWvH2jTkXWrCojgDJFakg=="
Received: by 2002:a0c:e788:0:b0:7ca:aa1f:8e39 with SMTP id 6a1803df08f44-87aeef4ac5dls30226646d6.0.-pod-prod-00-us-canary;
 Fri, 10 Oct 2025 14:49:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjY3f3wDCLs9ubj/UvH6d71kmUyFd8A7wJzuQMRpa8DWlD7lyUeclGT7RLPcj7MDs/zS2KIAYaFlo=@googlegroups.com
X-Received: by 2002:a05:6122:1e08:b0:553:6cf3:2be0 with SMTP id 71dfb90a1353d-554a8f27c38mr8158671e0c.5.1760132981974;
        Fri, 10 Oct 2025 14:49:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760132981; cv=none;
        d=google.com; s=arc-20240605;
        b=RM9HcA31b7cCsx3B5Awo1bRK9TgopTWSr7CNfaZnKVdNz6SoQc4RlnRqwsbDJaR49w
         TFRq7P4zqb7GVn5Y8/maj+iYn30OcDY4XbamNt31M3KOlSOy/Vf32vJ98HH53Pkxwi6L
         vOn/wzjqyILa1avDrNUrqNwUu+XQEHB3D6QAT0O2bKVdTg4j+Nrswm2x7Mj9vgnLkn9N
         lM00Wk6FprU2xvN9H2IUA3ARSN0h1xXVaWu0Gq4a9ZjOm92vMi/dSor9q8+2mZxbSXBn
         gjoHCPnP5QmnrJ5dLoRSSTD11mCmSfaWbkvm2IGENEBbR2NXGhfx3uGyYq+Gj1LvqxHa
         KhaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=Qmjp4bmjcPopzRhkC0CPHz0FCIAs3GJma9YL5R5RNDI=;
        fh=W/4gL26RFSK5XclRNf0dNCKUmoqaaUR7KbPN/9Zi2+k=;
        b=lixfGCFuD6LOGH85Rr2HGhQM3kxzpPmjMjnSZYupgvl0KI6g+Ekn5bdLl39IdCKtfv
         YmCiR+JsEDiNxAQG/6MtdhEnu18R+RDgSGM6T8VKy/ePZNJjD4kI0AEaM90PFkE+N5yK
         gjbTQqLIu2D9UekGOjD65dCQN8Qhbz6z6+iB4lkMFvn0ct0nWb16NAkqDteM9aE188vF
         kmhay3hp3ly/CiyfrY0wy9gBggLg3UfYH+9lQK1rj8ngHVLuGWMS7FxW32AKsxuesXJc
         P4nPDawZEYdaWKdXtXVW86DrhZaU6NeqphcoptEZpA516/IwOPI4S0ycqkvQdNPmLDhp
         MOUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hvBAVpKx;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-554e8c847c1si31110e0c.4.2025.10.10.14.49.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Oct 2025 14:49:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4150A43DA8;
	Fri, 10 Oct 2025 21:49:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D2153C4CEF1;
	Fri, 10 Oct 2025 21:49:38 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Oct 2025 14:49:27 -0700
Subject: [PATCH] kbuild: Use '--strip-unneeded-symbol' for removing module
 device table symbols
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251010-kbuild-fix-mod-device-syms-reloc-err-v1-1-6dc88143af25@kernel.org>
X-B4-Tracking: v=1; b=H4sIAGZ/6WgC/x2NywrCQAwAf6XkbGC3Ggr+iniwm2hDHysJLUrpv
 xs8zmFmdnAxFYdrs4PJpq51CcinBsrwWF6CysHQppZyygnHftWJ8akfnCsjh1ME/Ts7mky1oJg
 hnamjTvhSmCBSb5MQ/pvb/Th+W0+vD3YAAAA=
X-Change-ID: 20251010-kbuild-fix-mod-device-syms-reloc-err-535757ed4cd5
To: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nsc@kernel.org>, 
 Alexey Gladkov <legion@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, linux-kbuild@vger.kernel.org, 
 linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 kasan-dev@googlegroups.com, Charles Mirabile <cmirabil@redhat.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=3205; i=nathan@kernel.org;
 h=from:subject:message-id; bh=WhUTgOUQwZz/mKwCSbgdhMyMfQoSYK7seDZUD2CkcCU=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBkv64vuftv+/x4bb8O50Pxtn7ZMb9qS+un6CuUbNyWeb
 BPTUHM71FHKwiDGxSArpshS/Vj1uKHhnLOMN05NgpnDygQyhIGLUwAmUjWVkWHNk3fzFJ+tye3+
 X2qU5a1y1Xth79mzTTY3xGYw1Z/4VO/B8D+XI+Sn2Isr5zme2tsuYpv9oqumYdLtY2mNoaU9V51
 2hTMBAA==
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hvBAVpKx;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

After commit 5ab23c7923a1 ("modpost: Create modalias for builtin
modules"), relocatable RISC-V kernels with CONFIG_KASAN=y start failing
when attempting to strip the module device table symbols:

  riscv64-linux-objcopy: not stripping symbol `__mod_device_table__kmod_irq_starfive_jh8100_intc__of__starfive_intc_irqchip_match_table' because it is named in a relocation
  make[4]: *** [scripts/Makefile.vmlinux:97: vmlinux] Error 1

The relocation appears to come from .LASANLOC5 in .data.rel.local:

  $ llvm-objdump --disassemble-symbols=.LASANLOC5 --disassemble-all -r drivers/irqchip/irq-starfive-jh8100-intc.o

  drivers/irqchip/irq-starfive-jh8100-intc.o:   file format elf64-littleriscv

  Disassembly of section .data.rel.local:

  0000000000000180 <.LASANLOC5>:
  ...
       1d0: 0000          unimp
                  00000000000001d0:  R_RISCV_64   __mod_device_table__kmod_irq_starfive_jh8100_intc__of__starfive_intc_irqchip_match_table
  ...

This section appears to come from GCC for including additional
information about global variables that may be protected by KASAN.

There appears to be no way to opt out of the generation of these symbols
through either a flag or attribute. Attempting to remove '.LASANLOC*'
with '--strip-symbol' results in the same error as above because these
symbols may refer to (thus have relocation between) each other.

Avoid this build breakage by switching to '--strip-unneeded-symbol' for
removing __mod_device_table__ symbols, as it will only remove the symbol
when there is no relocation pointing to it. While this may result in a
little more bloat in the symbol table in certain configurations, it is
not as bad as outright build failures.

Fixes: 5ab23c7923a1 ("modpost: Create modalias for builtin modules")
Reported-by: Charles Mirabile <cmirabil@redhat.com>
Closes: https://lore.kernel.org/20251007011637.2512413-1-cmirabil@redhat.com/
Suggested-by: Alexey Gladkov <legion@kernel.org>
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
I am Cc'ing KASAN folks in case they have any additional knowledge
around .LASANLOC symbols or how to remove/avoid them.

I plan to send this to Linus tomorrow.
---
 scripts/Makefile.vmlinux | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/scripts/Makefile.vmlinux b/scripts/Makefile.vmlinux
index c02f85c2e241..ced4379550d7 100644
--- a/scripts/Makefile.vmlinux
+++ b/scripts/Makefile.vmlinux
@@ -87,7 +87,7 @@ remove-section-$(CONFIG_ARCH_VMLINUX_NEEDS_RELOCS) += '.rel*' '!.rel*.dyn'
 # https://sourceware.org/git/?p=binutils-gdb.git;a=commit;h=c12d9fa2afe7abcbe407a00e15719e1a1350c2a7
 remove-section-$(CONFIG_ARCH_VMLINUX_NEEDS_RELOCS) += '.rel.*'
 
-remove-symbols := -w --strip-symbol='__mod_device_table__*'
+remove-symbols := -w --strip-unneeded-symbol='__mod_device_table__*'
 
 # To avoid warnings: "empty loadable segment detected at ..." from GNU objcopy,
 # it is necessary to remove the PT_LOAD flag from the segment.

---
base-commit: cfc584537150484874e10ec4e59ad2ecbae46bfe
change-id: 20251010-kbuild-fix-mod-device-syms-reloc-err-535757ed4cd5

Best regards,
--  
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251010-kbuild-fix-mod-device-syms-reloc-err-v1-1-6dc88143af25%40kernel.org.
