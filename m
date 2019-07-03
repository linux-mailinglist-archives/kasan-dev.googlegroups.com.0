Return-Path: <kasan-dev+bncBDEKVJM7XAHRBS5M6TUAKGQEJ4QKSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 726535EDED
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 22:55:40 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id a19sf868024ljk.18
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 13:55:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562187340; cv=pass;
        d=google.com; s=arc-20160816;
        b=kxam6Cq5U0JwS4566qPd/Vax3j+IgKPqknBBQON38pW5//3XECMgUAI7J3rqN6T7LG
         zCpSoAKg9HuaUKG3K9TtZBKoio818J5/wD3URsZWfzlj0HQ0SwC9DcIWssLEreFfRFmp
         SdXLvyJS9wiIpzXKK2ttMlSEZV2l+T7yTZPVfl4b45G99enDmHGJqee38z4xk4OTxn9S
         2f9AlslRXMILKf3ZYJu1NUoXqdIXSamfOTy2NrNlE82S+J0Dh6pJsoyhb5EZnC513wc7
         +iot3iu0gsRq+IpT44ryehZIhUeHh9AghaL4r4P/Wp9UkP07uzgij0x02/Wpg4nsCcsu
         u/xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=tCwRO/5iMBvoDzK8aNBPL+PX3qGT/tq6AI6Se0m0w9o=;
        b=XngSzTkGyzyW6Em1alGBQf7SB5WwddXQPulJiPBhNi7q4ssX93ztlUTiFDbD7oF0+v
         5jV0WWQm+syYUmJGM8rgeWNw7qSWMZfQp++5/6R4nQatKdAJGZ+wJrasEsf+zn1C1nvB
         xakP8XzyGDNtvyDIwugLAfVOmaaye5wLc0xGZt0tAEkKhb1J3DdJ3iLH6FzG6cJfilYx
         rpOMmeic/281wAwFeEyxXQEZGVqMFJampZ1XzFIreoCdhk4kEZi2p+rm+1CGwdewiP3M
         /D8ztBIS3luAIxW+nDMOSJxe2QQT7yKf6IdQXEa5KvwgF/P3dP8fLH3s+FgSR9sQi7Sb
         0I1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tCwRO/5iMBvoDzK8aNBPL+PX3qGT/tq6AI6Se0m0w9o=;
        b=huPyXf/OBk6uB6qqhkDOYMJM3zwyDlmzo0xMEGjdAcBJwZfsbkdRveDWZjO9861/bT
         ksfX106UMuqowWMCh4jQ94y2yx3zcEjnLIkvz4rNFG9Ef8p9uOB3P1w2WKiVrkJ5rTIe
         9Z0KdIt+p1fRl8D372P0EoQoySyrPEO4Bhh7I/6aK1QbDUXYCHbCpQVgkB0hlewQBjBf
         55qyVanJen9dfvlFvpFUws/h5L/pL9u5K59Tbu3V3dPX+5C1gSlxFwE4EeNfHCpmrals
         4LFtc7b9dsJahy+s3tJuazFXTCmU4zVs1P2yIpO87MDpwWI2nAPgQ+jSGJ9i8FLrqmbr
         GE/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tCwRO/5iMBvoDzK8aNBPL+PX3qGT/tq6AI6Se0m0w9o=;
        b=muMCvc5YCyUlsEeNruDFCiwlkW2dvUEHaOOKqmyj14arNBol5NB5MuW+zvqk6GT17E
         g2oM04sDff0VM7g+8V4E9FWJCM0LBSpIlpTMMTvFnYfbBcXP2t3f2wJG3sFym4z6en5G
         /+/lZq8m7A5+BbUqwv1qSCPnBORjRdsv6C5fF+CIF1gC6HBNv1xW46p2Ob1Q1Q7/sfdb
         rTVWFqdNweCE2Lg/QqFBua/MzLfxAf9FVsCN2/5DdyrG9C62ql2dUL15IOcAhV9YDLkG
         MwTto8x0bi5WEpa3jAW5VnWIJWhycU5eWblLBxa7mwy+OOGDT/JdbuK66CSun9n3ID//
         IzZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDfke7hzF0SMTMzGCxtojtEWNjQSpwtn1zv3m60DJhv45/ZSH0
	pi72f/pEOVML5TfSAmXSnA8=
X-Google-Smtp-Source: APXvYqwMMPOjc5FaLoJLUgCa2raTszBkblJYi7R9j0z5DkJ7tPr59h4IvwOUd94232LMZLqY1H1Nqw==
X-Received: by 2002:a2e:3602:: with SMTP id d2mr22898047lja.112.1562187340049;
        Wed, 03 Jul 2019 13:55:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9dc8:: with SMTP id x8ls465538ljj.2.gmail; Wed, 03 Jul
 2019 13:55:39 -0700 (PDT)
X-Received: by 2002:a2e:8ecb:: with SMTP id e11mr22403410ljl.218.1562187339525;
        Wed, 03 Jul 2019 13:55:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562187339; cv=none;
        d=google.com; s=arc-20160816;
        b=RQtbfHMzQ173BkqDv4EDPXvkJSFAZ0IGJQNtSZrZWudfhY9wlgIpYzDdlPIJiuNeM4
         3eqQGL+gQtjA4ikfHPidjMN9i1xaC1wCh1/br2XBCou6QFXzHJMli1rJz4WH28tvNhN/
         Hc0CqeDVu/fvPtsVAVmiUw8+IHGKztqzNwEVxK9SL036ptQ/RvyI+vP/dVRO2WCGLZT4
         oqsJ6u7LFbzsgVbqX7bawtL9N51HOOuYM1uS35deURFUPiVhLZCc0zX2+AAOoL9uVMak
         OQt2aEE3jp8BlKpTVqIddKxDPsBwX3DIe3YU1MgbUbINuDz1n7BLN1dwqVSTsoQ9prTY
         o8VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=+lBsDcmXIwNnGE4dmbLJ1M4DqByzAQLGIGP4+KM9A7Q=;
        b=bNX8zG76T9guWfJrSpyEuTVsxrgaMMMpBiX7vzGiP9JPpgs3vkB10R962qSECKclir
         HZr1UJM53LMMQC4slOMdryCAuJL7mNxXjiV1CBtngpb89Ag47YqrQ/1ljYYA7LDzMWwg
         A+7h85vIWIkuXgo2CkmY3dvK7lzUw6bLDxraOlpzZ9WD3ABI9DtOSBVXeMr4GMOHJ65C
         gIgZi6Ydv/3zDpCReEhF8RTZpUj/zeBq4n6YnjwFkGDNwnJxxUD+nRtg4156wVJ1znWg
         4+XTblucaToynNw8v3W2ubIHiSLXwkFDDuLiRx0jmDlFrlA9PcOBz3DSfkGcaJkku3t1
         995g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.134])
        by gmr-mx.google.com with ESMTPS id q7si214387lji.5.2019.07.03.13.55.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 13:55:39 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.134;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue010 [212.227.15.129]) with ESMTPA (Nemesis) id
 1M27Bp-1hgJRq2Gin-002TZ9; Wed, 03 Jul 2019 22:55:31 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Nicolas Pitre <nico@fluxnic.net>,
	Stefan Agner <stefan@agner.ch>,
	Nathan Chancellor <natechancellor@gmail.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	linux-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org
Subject: [PATCH 1/3] ARM: fix kasan link failures
Date: Wed,  3 Jul 2019 22:54:36 +0200
Message-Id: <20190703205527.955320-1-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:N0nhNH56c4bAPUvE+lb81hmqvGKzvYovB1gWPnLR0wVZb6l2Cus
 VlcxdC8pK77LU32vdSY3Hh7JVCF2Dn86C7mE5dWcn3mW4hOXnlPLCso1Cp9anA4gdrDrzo5
 Ut7QKtxvDcquKr7d9Bv/USwELBGTW65u6iuQdfFdQsgx+VYAxaDSI2S8DskzTjruoWUa2ES
 iWji7SQpVNS6kv9tSkXzg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:kkc3pKM7JBI=:7SfM19cEIrMeD+akm/v6F2
 a7GlFineaNLRR0bDHAg64d4H8VDDp7Z9+1z0wPu6ycgl2veXYMIYLK3ymKqKG4KsWypouYG9r
 mtCXBQ4VLnNmtTGxxFuxJdpI3h2zw4v1U8tAUn4YrVtxSPTXfdIvp75IvfpBXX/UvFQyZ1dp3
 U/VKYT/72+IpBEt1wioAoWf3LlbQGf9SBTdADJK+a4xjGSe3fKWyWBteSoLXu6ryzobEgrfT/
 H00WLhhVLscWXXo5mo/pjrrFTjO/7XZo+uTlJcuSiqSfdPcxYtMHz12+C9S/Z+2HGLOq5uVEg
 DQhJ/O0i8wws7dtN346JYXJBuU/miXvgasyL26bSAp6kAWdEvGPuQv4kdmfMsj2Rw9lg5Y0t7
 R3R01XUVVi1aq89YlWjRoLzbt5hAlFIAd9ilTc+/+QVxtDzzPpenqcaqMjFQubTYDYkRT5SOm
 2tnPirJJacaRkDbQ5bTGJ3Ul32o6ej09+cOCaH0aWrQYPlKKbkU5SGLBNU7s4LARIsVt2Hw4s
 Ii7qWkUVDiwx+d52CbaSbjqmAtNjS+r0w7ri4LGuUhZvHPf08gKYO/WCR80f/kRyUbqfwxENo
 IhhjA/hQkMP7YWhi+VCHHS49JyodFnSForBRio4snDdEmhFwCJpwTHCqNH15yPzgwWJt5lz3z
 AZS6ncqMjqWtz5QOMSnp3u12Dp15VIpniGDr/zVGGmfL/6EJFRba+9xAe2ivD9P0FL/W7RCuG
 awSwZR/Uu8glWMOfQlXU3FQt8a2h94oDitdTGg==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.134 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

Getting the redirects for memcpy/memmove/memset functions right
in the decompressor and the efi stub is a bit tricky. Originally
these were meant to prevent the kasan code from calling itself
recursively. The decompressor is built without kasan but uses
the same redirects when CONFIG_KASAN is enabled, except in a few
cases that now cause link failures:

arch/arm/boot/compressed/fdt_rw.o: In function `fdt_set_name':
fdt_rw.c:(.text+0x3d4): undefined reference to `memcpy'
arch/arm/boot/compressed/fdt_rw.o: In function `fdt_add_property_':
fdt_rw.c:(.text+0x121c): undefined reference to `memmove'
arch/arm/boot/compressed/fdt_rw.o: In function `fdt_splice_':
fdt_rw.c:(.text+0x1460): undefined reference to `memmove'
arch/arm/boot/compressed/fdt_ro.o: In function `fdt_get_path':
fdt_ro.c:(.text+0x1384): undefined reference to `memcpy'
arch/arm/boot/compressed/fdt_wip.o: In function `fdt_setprop_inplace_namelen_partial':
fdt_wip.c:(.text+0x48): undefined reference to `memcpy'
arch/arm/boot/compressed/fdt_wip.o: In function `fdt_setprop_inplace':
fdt_wip.c:(.text+0x100): undefined reference to `memcpy'
arch/arm/boot/compressed/fdt.o: In function `fdt_move':
fdt.c:(.text+0xa04): undefined reference to `memmove'
arch/arm/boot/compressed/atags_to_fdt.o: In function `atags_to_fdt':
atags_to_fdt.c:(.text+0x404): undefined reference to `memcpy'
atags_to_fdt.c:(.text+0x450): undefined reference to `memcpy'

I tried to make everything use them, but ran into other problems:

drivers/firmware/efi/libstub/lib-fdt_sw.stub.o: In function `fdt_create_with_flags':
fdt_sw.c:(.text+0x34): undefined reference to `__memset'
arch/arm/boot/compressed/decompress.o: In function `lzo1x_decompress_safe':
decompress.c:(.text+0x290): undefined reference to `__memset'

This makes all the early boot code not use the redirects, which
works because we don't sanitize that code.

Setting -D__SANITIZE_ADDRESS__ is a bit confusing here, but it
does the trick.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 arch/arm/boot/compressed/Makefile     | 1 +
 arch/arm/boot/compressed/decompress.c | 2 --
 arch/arm/boot/compressed/libfdt_env.h | 2 --
 drivers/firmware/efi/libstub/Makefile | 3 ++-
 4 files changed, 3 insertions(+), 5 deletions(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index dcc27fb24fbb..d91c2ded0e3d 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -25,6 +25,7 @@ endif
 
 GCOV_PROFILE		:= n
 KASAN_SANITIZE		:= n
+CFLAGS_KERNEL += -D__SANITIZE_ADDRESS__
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/boot/compressed/decompress.c b/arch/arm/boot/compressed/decompress.c
index 3794fae5f818..aa075d8372ea 100644
--- a/arch/arm/boot/compressed/decompress.c
+++ b/arch/arm/boot/compressed/decompress.c
@@ -47,10 +47,8 @@ extern char * strchrnul(const char *, int);
 #endif
 
 #ifdef CONFIG_KERNEL_XZ
-#ifndef CONFIG_KASAN
 #define memmove memmove
 #define memcpy memcpy
-#endif
 #include "../../../../lib/decompress_unxz.c"
 #endif
 
diff --git a/arch/arm/boot/compressed/libfdt_env.h b/arch/arm/boot/compressed/libfdt_env.h
index 8091efc21407..b36c0289a308 100644
--- a/arch/arm/boot/compressed/libfdt_env.h
+++ b/arch/arm/boot/compressed/libfdt_env.h
@@ -19,6 +19,4 @@ typedef __be64 fdt64_t;
 #define fdt64_to_cpu(x)		be64_to_cpu(x)
 #define cpu_to_fdt64(x)		cpu_to_be64(x)
 
-#undef memset
-
 #endif
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index 0460c7581220..fd1d72ea04dd 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -20,7 +20,8 @@ cflags-$(CONFIG_ARM64)		:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
 				   -fpie $(DISABLE_STACKLEAK_PLUGIN)
 cflags-$(CONFIG_ARM)		:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
 				   -fno-builtin -fpic \
-				   $(call cc-option,-mno-single-pic-base)
+				   $(call cc-option,-mno-single-pic-base) \
+				   -D__SANITIZE_ADDRESS__
 
 cflags-$(CONFIG_EFI_ARMSTUB)	+= -I$(srctree)/scripts/dtc/libfdt
 
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190703205527.955320-1-arnd%40arndb.de.
For more options, visit https://groups.google.com/d/optout.
