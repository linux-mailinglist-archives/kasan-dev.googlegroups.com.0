Return-Path: <kasan-dev+bncBDE6RCFOWIARBTNDSP6AKGQEPZ2R2JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A83CA28C466
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 23:59:41 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id y14sf158868lfl.7
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 14:59:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602539981; cv=pass;
        d=google.com; s=arc-20160816;
        b=jXhU/ZsLg7i8Pdjlmv22fKn2jnh7uoqyabG0h5DYo9DEIR1YDNWSvzOpzXySqZNJyn
         F6JuRmN0gUY9o99gDlPbI6G6l+2fsItgglEwbytdLMRaDrtmaf7GtWWFHETz60Mf8n9a
         Kc4UwJox+stnxInO3YPrQXKMjjwC9jdooIvT4JuBtSbKrMFRmdTp9rUPeh1be7CB9ddC
         f7VOkq6B7reFVhoKRnxdsAQOnXDOSj7Z8JP47PnWT6kU3+dWc9qShbCLu1rANJvYrXov
         UKT0xuLjbYlYuOKj5A1m8BcqlUBARCM++ohrhac6vfq8sSaGOZ6q+cPWIUW2Ld6FB9Dz
         Ud+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Roqelml+EggxZrOFF3ZCXNq2tcL6HaUfPiyWiQXDfSw=;
        b=T81iEFvAXzBYK1EhZwQ5lPdXRzI0qgmCbrHtkS6krFY/fVA9Dznk2FDYrcndzB7WVp
         b+WVW1pnEa7wOHdTY0D1vkfUVZEhCNRSIqlzx1h2TpLY0NQF8eHN2GlJnwGT7xUiIHIU
         sPV+SvTyv/w+w7NNI4/PkAFULGTV13cpE54w86/sZxSJ3n3GokIHsU9gSoSSJpxdpHig
         IyI+lEY7JzT42ZH3kHqGHCXO5f4H8A/moN+2lq+7pprVCIxKF+RTh/qJWeZhtgMk7KVQ
         sp0/ysqTS8sionNNn/voULMuFnGtD3Ks0sG1pAcHFW4/fZCE2SYxPAO31AyrId2JfxEZ
         2nsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Jav/Zj+s";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Roqelml+EggxZrOFF3ZCXNq2tcL6HaUfPiyWiQXDfSw=;
        b=PiF/0ph9oE7u31wzAwpDdsIlsr3VItdZsXuJCFQRiZQ4KlT5ViCNRdQA7gV+T1Eleh
         RduffXMPNF5sRlmTkkN0cbjPfHjOJqcjCq5RU172aPJ6rVe7p1XhnoRMkCuMokFJWVQu
         qgHS9reeGAuh5DwPgwfUV/0wPdIF7zhn8/yEfjR96MvWnO1veIyFOlvwhieyGEC9Hb00
         p6QtIW0+oP1hFNHX4P/KZzYaz4Wjf4UuWtB22puisYptH/fcbvQ61a6RwMS75AP4/i2Z
         fA8zD6wff4cu0AhNx5EQBnrW90AgUUbbSnpJDmrR7HZaLgOHAMHcmxq2lW7OOzRNQe3S
         qhMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Roqelml+EggxZrOFF3ZCXNq2tcL6HaUfPiyWiQXDfSw=;
        b=fRc6q10s3kZgw6J6TMZJFF74wRlU1Ue7FHByJy2vmacX0OYV0H916xHFzwfDPhRvgF
         jCDyfL/AFn73CxF/61ZzhrAKtAi7gbAJN7LITDwheBFh2AuFlGY7/weoDIO/Qyc3RaTE
         3Gdw6LJkecjME3ErkNMsqSKY420FWNkeqKXU5mot1VfPxx0k545OicbPrwDQNYTyYo18
         leffNebtg+//iliJgoHd3bCHJGU+h9HrAi/+W4KbyjlyInXOPjgL0Zdkbw7b/FsQizPt
         TPoAgzdiQCzfzHRI0mLcdC10c3r6iB+HnxCzi3qqfbxPQTKOQObnnvCkrGZvzevjGqQb
         j4KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mCj8j8aRtXz5UBz2vDALTwVk20S2RVO3nH+Axp6F5Hg7Zd6bC
	yU/vURQsK2q2qObBdY1NNgQ=
X-Google-Smtp-Source: ABdhPJxyKV/EWN01IYQT1ZCIEhrw8r5uLapZJVUlJPj/weIS7gdrgINoGGAYmnJXpwmHBDok8r6Lwg==
X-Received: by 2002:a2e:9c85:: with SMTP id x5mr7796158lji.92.1602539981231;
        Mon, 12 Oct 2020 14:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7a0e:: with SMTP id v14ls995194ljc.7.gmail; Mon, 12 Oct
 2020 14:59:40 -0700 (PDT)
X-Received: by 2002:a2e:a49c:: with SMTP id h28mr2345757lji.417.1602539980185;
        Mon, 12 Oct 2020 14:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602539980; cv=none;
        d=google.com; s=arc-20160816;
        b=eXgwBJmYgTxGxFJj1gQhKFEKGDvFS9ajimTAQ7Cb/EpoFz2W4ZjjZs+wsd4vAivzrL
         I8yf9x//ioPcjlR2vOd0x5LdrAgx6N0wETczHvtC3DxKwbL0OXgEw4kT4nn/LU6khdSE
         nFdiF9oUTa3gkP8+sUTQ/ePtTje86x/wvTpa5dA426JCWpi9+ecDktkng4M47n3zD9+4
         iGb2Uo3OLqM/JzCmGbyEzRDxRsg6ARhma0DQ4yHmQ+UkpKd9kbk97WPo6DngCJsIvLml
         0i1kNT6mg2IvvbMQBu/hVGBzTF0BCexnVXyiGuDfc2hobvPwl6FOXFZBeDscuO2W6C9P
         +45A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1qB7JR5tdYbDqJsNnt81xF5Glji0+CVS4pHlM1KqnuA=;
        b=WSKz86ytOjEvxTC1y59npbdTru77fYqNZYxabtFezA/3IFE0/iwf80hxTu/cRfRaV/
         F/kw3k764KbYnBfMM/Bu9IvZdz4u3zsU09TBRI2raYeWv3FJT2Bfu5HRsAFqZSEcyfP7
         TNz0hy1naAtpeqBxVilIZJdM3JN5JNPEN2eZGnc5YcPAXjZlco5tcDXDtA7g/9gi8W9R
         n1Y8gEqBw/ANTXB/gMQ/WstWeFMlwDYeqIjyLFf9t85SUBQzdp2I551ukBJ8v0nZWt3D
         2hCcMy22g1vg+6t3e3T+lxuIIPLT0jWWr66H2SLiNdInLmK+eVn3U9Of+7c9gBnbGSUI
         tsEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Jav/Zj+s";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id y12si511514ljc.1.2020.10.12.14.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 14:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id a4so18285415lji.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 14:59:40 -0700 (PDT)
X-Received: by 2002:a2e:6e12:: with SMTP id j18mr10007997ljc.389.1602539979930;
        Mon, 12 Oct 2020 14:59:39 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id w9sm2985887ljh.95.2020.10.12.14.59.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Oct 2020 14:59:39 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 5/5 v15] ARM: Enable KASan for ARM
Date: Mon, 12 Oct 2020 23:57:01 +0200
Message-Id: <20201012215701.123389-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201012215701.123389-1-linus.walleij@linaro.org>
References: <20201012215701.123389-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="Jav/Zj+s";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

From: Andrey Ryabinin <ryabinin@virtuozzo.com>

This patch enables the kernel address sanitizer for ARM. XIP_KERNEL
has not been tested and is therefore not allowed for now.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v14->v15:
- Resend with the other patches
ChangeLog v13->v14:
- Resend with the other patches.
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Fix the arch feature matrix for Arm to include KASan.
- Collect Ard's tags.
ChangeLog v7->v8:
- Moved the hacks to __ADDRESS_SANITIZE__ to the patch
  replacing the memory access functions.
- Moved the definition of KASAN_OFFSET out of this patch
  and to the patch that defines the virtual memory used by
  KASan.
---
 Documentation/dev-tools/kasan.rst                   | 4 ++--
 Documentation/features/debug/KASAN/arch-support.txt | 2 +-
 arch/arm/Kconfig                                    | 1 +
 3 files changed, 4 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..050dcd346144 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -18,8 +18,8 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
+and riscv architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Documentation/features/debug/KASAN/arch-support.txt
index c3fe9b266e7b..b2288dc14b72 100644
--- a/Documentation/features/debug/KASAN/arch-support.txt
+++ b/Documentation/features/debug/KASAN/arch-support.txt
@@ -8,7 +8,7 @@
     -----------------------
     |       alpha: | TODO |
     |         arc: | TODO |
-    |         arm: | TODO |
+    |         arm: |  ok  |
     |       arm64: |  ok  |
     |         c6x: | TODO |
     |        csky: | TODO |
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 0489b8d07172..873bd26f5d43 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -66,6 +66,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201012215701.123389-6-linus.walleij%40linaro.org.
