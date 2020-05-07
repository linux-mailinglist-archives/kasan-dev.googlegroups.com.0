Return-Path: <kasan-dev+bncBDE6RCFOWIARB54G2D2QKGQE3GJUCCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 96CFB1C8B44
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 14:47:52 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id f56sf6568034qte.18
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 05:47:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588855671; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hw2bctny+1SJ+5UZ9qGOYaB48q/xG7aqG6C/gagddoPFU49TJx5ICqGOWdy3SBXv+D
         m2Fl4QX9/LOZj5c2pGBb9bZJyOpZGDTXNWEyYnOB/pNYKbVttjCB1g8YUAwd3joZdgGK
         sgC+D0S/Lhej878hTlXHSpe7dKGd8NfcUq0qejYpdqFifYPvoDqUwfLzqa+w83vd9wCj
         xQiz8QE42UXWUB4Z5BzhxvKeSggREhfe1UT3cRHl5BBLNsIeMH3IuGMfXJaCBt2xW7FZ
         jd7CNSLACMAkcSwOy4WwlJvCjRBsAmmFYsPzmyDOj6VgU2o5jGw14smAUZ6SFdD/aweY
         5ojQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OsuIf4YwoKj7MnRCBTzgmFvHcsT5RJDt20/dgc4DE1M=;
        b=bsCtYaKHvyxKFGJ0KnQ/NmgRjo5sDUOukoophRyun7G/DY4Yq4IubUSFGhvKrfWIO+
         iMix+qKl85amOwPcENt0J6LbRqeXYl860jjk0t4HgQQ6cioJkDLbJzS2y9MA0ujbi3lK
         03qSNUEZzTavngOGlVuLk+6gfuwWN9lIKogojgKvgIiPMv3l+sX47XANQfqTP1KmWar9
         xF0GqBZmZLZ0oWXyYS/T55mountaC0C47u5JKFbA4YRNTyGhAitx9fwtGqKlyRYzsrXe
         9p92j5Dx0HQtQpRNxFSfNjvxf3UN2HIHgiesho8LmOEMT2Qv92SJrlQ7TroY3zXc/ih+
         ckjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=a22GdmKB;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OsuIf4YwoKj7MnRCBTzgmFvHcsT5RJDt20/dgc4DE1M=;
        b=ibFZj+3efd2QQLgaAH/bsWzBmZn5AMe6UFY7scTW1OAroxp6k4d05YOPll4JbP1Cii
         IEuhivWkQD4WdC0QR00nFOTZpM0VOfazzc8awMsW+REUpyupmEcOKA/xi9CuzlH2IJ0c
         adr2iFhe88zm12qRILVsN36565RsoEOCvhdfC3mEBXpRBl1UAwCv5vtH3WKTFplsiYL4
         EVm0YCQsmFENMG+jCjKLLaRn1XlJMHooflQPLtIich67fCmF6jS3rAMTJrPGqj7r1re2
         KoIyx9aWCXxCVuy1CWo6as7NwtXRcbrus078MQwQIHcFyeyyrPfNt99rUxFNEeP6jaiH
         RNSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OsuIf4YwoKj7MnRCBTzgmFvHcsT5RJDt20/dgc4DE1M=;
        b=QE7ZIC2nr+4gJHnQr6T3jE53QgqaKUH0CeQEnLN/uTpRjneM0LAe6ll9VdFLg/9Mez
         3EWjiylnIKm+eToCvRf/mpNrgpw7/Lyr9qVtdX35jTuVOQe5AqMEzOK/5wbG344fl5VE
         L5S94J7u6IkAS2Ze1JysBrAg0VuvHWXbCaWui+eKe2zXLhvYZbWFmSqoLe0S23+HtCcd
         wKfUK8D/jY7zHp+zOQ2s8+IhdgNL2vil/p8j66ON1ITfwKS/LfLLhZsBo/mwsK0MiEe9
         GwveoY3mENokOZmZRhX0rkWfr1psi5g7cQBKXSplxk6lRoHFl9scS03ltSBKt0QPDiZJ
         lQaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Puaf/Xm+vjEt7IO3y3p4ev+cJv1/2D+5uHGB3GQCW0ZsSjwFuwBe
	SnKh7qBnXaZ55GP/P7qO/nQ=
X-Google-Smtp-Source: APiQypLJSZleSeY9A/IsDV+s7TmUsHutc+V01dct8c7HX+AUELdBW/S2zgejPU47noPQlrLo27ClUQ==
X-Received: by 2002:a37:a310:: with SMTP id m16mr13022066qke.346.1588855671301;
        Thu, 07 May 2020 05:47:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1237:: with SMTP id v23ls5533013qkj.11.gmail; Thu,
 07 May 2020 05:47:51 -0700 (PDT)
X-Received: by 2002:a1c:3c42:: with SMTP id j63mr6049709wma.118.1588855670853;
        Thu, 07 May 2020 05:47:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588855670; cv=none;
        d=google.com; s=arc-20160816;
        b=wXCDvevjEHq+0mOp4PKH08RPbUZT1gUNWely/yF38Dink9mmA6c3tbDVIHWKKptmNh
         AYEHx6SklNMM0WZHDA59GZEWAGfPFA3+PCZWmKLPu3bdMqsI5JHttVCbeuFNZLFfXcdt
         xqEC6kXFTzWNnpig2lMpSSIMMBYmdjD8n5N8ykRoa/TklkOMiNmYBzjWEyx9zlZKEcJ7
         OKTxpNy5sNml0bb1QTBwiAPrKIRfrHdzWpFr+mLbuz39aocCX+EJlB4fyuGIEosx3YmD
         wFHkSnqAg6C3oj0nELWz4foYgutggLyPgynD1YLHC6ljtCy4TadWfBjPk1vm6JTDXPHM
         iKng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OFzLjGWJZUchbaZBa5lRk73Fn2jLSts6/MNQ/Gs4VTs=;
        b=tACZqz6808G4jF/udQtvHVm4bY8LxcMCyrUoeo7uJ+1oFp6JelgpwJ1l7j3Gx1n28D
         0pY6qXiovbr7F8SmF0WbSFYZAUOBvwnoB7A1qovstoQWDDbfEoS39wV6WmFhUmh1o8NZ
         5W1664Nx046NjXvqBr9DcSUcG1qq41C8b9/9VwbO2plGd78wgVMrvr46AUZyEQQyzQ8n
         HRI7R4/D8rbfVLPZ6YQWBZoaJ0oL8B3PH5mZnn3qqugKjn1IR9McoU16VSWFH5Lox7ag
         I3YpJgx7gms8pnub+tR7acalZ7O/Xmd1UVtESTFREubpLH/6ZDK4E0eb1n+sW2O4Fs1t
         skww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=a22GdmKB;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id w8si298842wrn.2.2020.05.07.05.47.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 May 2020 05:47:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id a4so4351605lfh.12
        for <kasan-dev@googlegroups.com>; Thu, 07 May 2020 05:47:50 -0700 (PDT)
X-Received: by 2002:a19:644f:: with SMTP id b15mr8825581lfj.28.1588855670390;
        Thu, 07 May 2020 05:47:50 -0700 (PDT)
Received: from localhost.localdomain (c-f3d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.243])
        by smtp.gmail.com with ESMTPSA id b4sm3730126lfo.33.2020.05.07.05.47.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 May 2020 05:47:49 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Marc Zyngier <marc.zyngier@arm.com>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 1/5 v8] ARM: Disable KASan instrumentation for some code
Date: Thu,  7 May 2020 14:45:18 +0200
Message-Id: <20200507124522.171323-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200507124522.171323-1-linus.walleij@linaro.org>
References: <20200507124522.171323-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=a22GdmKB;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Disable instrumentation for arch/arm/boot/compressed/*
since that code is executed before the kernel has even
set up its mappings and definately out of scope for
KASan.

Disable instrumentation of arch/arm/vdso/* because that code
is not linked with the kernel image, so the KASan management
code would fail to link.

Disable instrumentation of arch/arm/mm/physaddr.c. See commit
ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
for more details.

Disable kasan check in the function unwind_pop_register because
it does not matter that kasan checks failed when unwind_pop_register()
reads the stack memory of a task.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v7->v8:
- Do not sanitize arch/arm/mm/mmu.c.
  Apart from being intuitively correct, it turns out that KASan
  will insert a __asan_load4() into the set_pte_at() function
  in mmu.c and this is something that KASan calls in the early
  initialization, to set up the shadow memory. Naturally,
  __asan_load4() cannot be called before the shadow memory is
  set up so we need to exclude mmu.c from sanitization.
ChangeLog v6->v7:
- Removed the KVM instrumentaton disablement since KVM
  on ARM32 is gone.
---
 arch/arm/boot/compressed/Makefile | 1 +
 arch/arm/kernel/unwind.c          | 6 +++++-
 arch/arm/mm/Makefile              | 2 ++
 arch/arm/vdso/Makefile            | 2 ++
 4 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 9c11e7490292..abd6f3d5c2ba 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index 11a964fd66f4..739a77f39a8f 100644
--- a/arch/arm/kernel/unwind.c
+++ b/arch/arm/kernel/unwind.c
@@ -236,7 +236,11 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	/* Use READ_ONCE_NOCHECK here to avoid this memory access
+	 * from being tracked by KASAN.
+	 */
+	ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
+	(*vsp)++;
 	return URC_OK;
 }
 
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 7cb1699fbfc4..99699c32d8a5 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -7,6 +7,7 @@ obj-y				:= extable.o fault.o init.o iomap.o
 obj-y				+= dma-mapping$(MMUEXT).o
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o
@@ -16,6 +17,7 @@ endif
 obj-$(CONFIG_ARM_PTDUMP_CORE)	+= dump.o
 obj-$(CONFIG_ARM_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
 obj-$(CONFIG_MODULES)		+= proc-syms.o
+KASAN_SANITIZE_physaddr.o	:= n
 obj-$(CONFIG_DEBUG_VIRTUAL)	+= physaddr.o
 
 obj-$(CONFIG_ALIGNMENT_TRAP)	+= alignment.o
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index d3c9f03e7e79..71d18d59bd35 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -42,6 +42,8 @@ GCOV_PROFILE := n
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT := n
 
+KASAN_SANITIZE := n
+
 # Force dependency
 $(obj)/vdso.o : $(obj)/vdso.so
 
-- 
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507124522.171323-2-linus.walleij%40linaro.org.
