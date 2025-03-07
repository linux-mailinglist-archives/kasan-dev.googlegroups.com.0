Return-Path: <kasan-dev+bncBDCPL7WX3MKBBR7HVG7AMGQEE73N7HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 18E6DA55F4B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 05:19:21 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7c3c5e92d41sf265772085a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 20:19:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741321160; cv=pass;
        d=google.com; s=arc-20240605;
        b=C4TY1lT72V+TsvaAy49vWJZBZIGn2PGN4R9SAA6wPaz7wHnNsesCUxcXHqmi8l+vv8
         CHhrI2etfPwtcsMI+baNDKJ4RPkWo0P71Igo2ChWqmYkLBepJ0Owafa//XwiXbSnLAXC
         0hwDwDTNTZ5ZmhK7j5N7yUpMw+4mgBVL32MJ4vrpJsmieLECSS3gTCWXyDI+5LddGN/u
         nFFpsbIYUPpuHOUaxk8kp19rNuxluiwOM9Ko84CHvn2OxwOMoD5r3SZStQ0DEyu+QUCU
         04lyd5wcJV7R2NiBNKpoOfZRoEIXYvw8uQePWU9PypZSPhLtuFMpiEQL+ad9RVqTu4AM
         hciQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MdrVe1dnKp5M9nosLYnFPzJaUZunIoOqSdMBzUQT0f0=;
        fh=ZTTc01vaJsx+Y8CaV4zz5+vJKnPlw1PxGfbgc5EG0uU=;
        b=Z7Ri41+PPzXB+oriuLm3ZwmPWNf9crHOuXUwqVVLMQc+Ns5GCuazht9jQJ0T4Rql0x
         r/Z0l/P/TNIRmslKuXEeoz61Aq7cUIV7rJDvDvC7M3qQzYV3XaQ8Bz8lerfvGwqDPsN6
         MHWxjq8TsP58XWh0JPqr1toqCXbzGhdkz8pV/x1r0KblHu2JyCCZvLDvSU4UzkSOKIf+
         JV+6hagiMOMAQFoOU/yZGC6jCHOOuWkuvScnFtJUt4ZwEVnBJ83SbuTlVKp3+VzvzByf
         PFG+S7ZwlEWGSlZtDmaw154Wzzu6en41OsybzVscM6iYHJGf52R/piDkXKP0sBX5Bd5f
         EC6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="m7xtot/L";
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741321160; x=1741925960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MdrVe1dnKp5M9nosLYnFPzJaUZunIoOqSdMBzUQT0f0=;
        b=NlsnvYodbcMhLyziMhWst3v2buHoscyKhSFj6jY4To5008uObI0jwrrEv3W+1uQkte
         Xln3pK4QJ8eTNmgmjyerzA+76R88hTyNT4Qs8GC9AADS3sk/Fyn06vexBSG8cCSACepe
         sxoZfR2a9fFpiPSt19ee1bk/wLDCNvtkM+jppNn6t2QKLnJ1SKR+VyXnZmxrHpDL2KpV
         1ieuLG785pFOzJbFp2mvYkcFFZi9n1e8cXlhZ14vwVb3WrYjCdBc/lhbLGx/DkvUszpF
         KE2/zTty4TV28+Zz9QM0pB+ozLJmv5GiRLPCdc9G2meuMhWAD9AnbbpkZk3WfRBPIQSz
         eACA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741321160; x=1741925960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MdrVe1dnKp5M9nosLYnFPzJaUZunIoOqSdMBzUQT0f0=;
        b=IZaTktULpsoQI3jO6l/ge+/0oteFmI9RXncTEigSm6dJqAeq2ZWa60qYwWUIkSj1Kc
         8G2zIqzcw8JQ1OBxttRWsQpqLtu8JTX4EyitF+sNFP4SF2p1bDipBa371v5xtbJERdbj
         jkasR9EehWQHnH2gb+md4W4SEfditKa337chDipYcfrPWDgvP5tgBvaffaH5jzm7fqgT
         HcRp+sP+fQRNHbCb99XukjcSka/IUVrw0HR9WNVfcVVaUsoIxa3lavphtn10bPKiNKmZ
         DiwYGiLBwOt1U9eDzwNQpP5P6FWmhPifOi81lgx6P7x4KENoPIVozm7JHEMVDSszSzkK
         P1bg==
X-Forwarded-Encrypted: i=2; AJvYcCW9+/RRcXlCU/YYxs69P2uKsNE1HU+wU+mfw5FH+v1NKr+2r3setM71UW+xuRBiUyxXHsEkfg==@lfdr.de
X-Gm-Message-State: AOJu0Yy3BoIiRpJlLb76+GalesBsLVLRY8jmfB0HkkNsUYjupQqoWBsU
	rIH5F6xjpbSLq6vUHygzGmVg1Fyv3vd1FxRYFwJ7LNx8ygdo3GsV
X-Google-Smtp-Source: AGHT+IFdgf181nX0XMoU5u38n+vMIEtI05M9v1vOXpQoKwI5+Tszm2QBj3tatYgFnu3DLs6xUCkDsw==
X-Received: by 2002:a05:620a:2794:b0:7c3:c7f8:9f6c with SMTP id af79cd13be357-7c4e61b70e9mr324433985a.40.1741321159653;
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHmPXOarpycl3zlyg1JR//HdcicwRMb1nKHlNnJR7ubMA==
Received: by 2002:a05:6214:1928:b0:6e8:ebac:d407 with SMTP id
 6a1803df08f44-6e8f4eb44c1ls20812656d6.1.-pod-prod-02-us; Thu, 06 Mar 2025
 20:19:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjKXJ0sDW0tp/yE5IJd1no46nwGvq8Qq/NePuza136ORmkjH5uNlikzsykDhtIAlLcWtAHlHJEs0U=@googlegroups.com
X-Received: by 2002:a05:6214:d6d:b0:6e8:9170:9d06 with SMTP id 6a1803df08f44-6e900697909mr27397326d6.37.1741321158767;
        Thu, 06 Mar 2025 20:19:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741321158; cv=none;
        d=google.com; s=arc-20240605;
        b=lqLrGqClHs8pyw0y+jNNCEV2yfw3nazTKwTvGr51reAGvIJm2x34AhsX9wuK/g8ZuK
         XybAXze9VKOt029diiAUBQG60coezOF/2AovaZB1pnpgFFn6hFJMSMUWkgS9b6tXpFR5
         qvp7KGWzfuPw9tfbGG6UTtS3+PhlaUIAVTjVuQYU764PXNMod0d3sjAhQQ4oNND0xfWI
         og5tgXp30tr5xyVijAcbp9+lr4JCS6MOjgqEIR5HDDSSdp45WxfHE1mf15ggJuKGxIJU
         qHC525/ArVg2h/zGYA7HyUmsYSt+xArTE8JEOrfFxgXPEJAKpoi+fZods5WHanLi2s1R
         fmzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ycITNIpgJ6ywnKmmFBHEHvetTTyNNBXUyoieM/07ZSI=;
        fh=1RKVnkRzz9lFFdxP6bnipYYK2VGeZeTbRu24xXc+nq4=;
        b=TRPNR2BZH3Qd8rDEFCZxvDyfPuI0iJ69IX+GQPqDOyrPVy6lqI0ShUNH4dXR3N9DKl
         umkTHEBihJB3HwhVqr+YNLiubF19W2qj27NUIAvEUWU2HPFVyrOYp3ENySP6z1IPB1Xf
         YrjZ8k2IHNHTg92wyuHe/z/Hmt3wME/YONA79Iupn3EzSbbw84/zxC8PlZZfSrWl/uo+
         ID10CvNAC3wWzZDaDdIwhR49LCudWwswW979dPOAZaPzJgMc22Fbuzwksi7Y8hEK8r9j
         gkT7QrC2r1enzuhtCv5e5z0y+7QLexJ4Gl9RWyDKb2cjc4uZqiWxvlJABZlgouGZrFbH
         ohZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="m7xtot/L";
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e8f7123595si1232136d6.3.2025.03.06.20.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 20:19:18 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A7C30A45435;
	Fri,  7 Mar 2025 04:13:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D534FC4CED1;
	Fri,  7 Mar 2025 04:19:17 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Hao Luo <haoluo@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	Bill Wendling <morbo@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Tony Ambardar <tony.ambardar@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Jan Hendrik Farr <kernel@jfarr.cc>,
	Alexander Lobakin <aleksander.lobakin@intel.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 1/3] ubsan/overflow: Rework integer overflow sanitizer option to turn on everything
Date: Thu,  6 Mar 2025 20:19:09 -0800
Message-Id: <20250307041914.937329-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250307040948.work.791-kees@kernel.org>
References: <20250307040948.work.791-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=10875; i=kees@kernel.org; h=from:subject; bh=jF2FPa66QDBZ6tSBhJch3R++EPhCPpvxAmCZwq5WTIw=; b=owGbwMvMwCVmps19z/KJym7G02pJDOmnivc12DiqfHFzPZRQcErs48W+2m9Cyv4Tqp5zrr/fE 1J91LW/o5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCKiogx/ZaobtZWP7PLMvcjF 5HpCa1HFJI8XFWUa7Y/SHQ8f2n1uLSPDu8uvpurGVdn6TmVZl7DO2M5AM6siZc1yt77EI59ytqg zAAA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="m7xtot/L";       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

Since we're going to approach integer overflow mitigation a type at a
time, we need to enable all of the associated sanitizers, and then opt
into types one at a time.

Rename the existing "signed wrap" sanitizer to just the entire topic area:
"integer wrap". Enable the implicit integer truncation sanitizers, with
required callbacks and tests.

Notably, this requires features (currently) only available in Clang,
so we can depend on the cc-option tests to determine availability
instead of doing version tests.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Justin Stitt <justinstitt@google.com>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Hao Luo <haoluo@google.com>
Cc: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Cc: linux-hardening@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: linux-kbuild@vger.kernel.org
---
 include/linux/compiler_types.h  |  2 +-
 kernel/configs/hardening.config |  2 +-
 lib/Kconfig.ubsan               | 23 +++++++++++------------
 lib/test_ubsan.c                | 18 ++++++++++++++----
 lib/ubsan.c                     | 28 ++++++++++++++++++++++++++--
 lib/ubsan.h                     |  8 ++++++++
 scripts/Makefile.lib            |  4 ++--
 scripts/Makefile.ubsan          |  8 ++++++--
 8 files changed, 69 insertions(+), 24 deletions(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index f59393464ea7..4ad3e900bc3d 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -360,7 +360,7 @@ struct ftrace_likely_data {
 #endif
 
 /* Do not trap wrapping arithmetic within an annotated function. */
-#ifdef CONFIG_UBSAN_SIGNED_WRAP
+#ifdef CONFIG_UBSAN_INTEGER_WRAP
 # define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
 #else
 # define __signed_wrap
diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index 3fabb8f55ef6..dd7c32fb5ac1 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -46,7 +46,7 @@ CONFIG_UBSAN_BOUNDS=y
 # CONFIG_UBSAN_SHIFT is not set
 # CONFIG_UBSAN_DIV_ZERO is not set
 # CONFIG_UBSAN_UNREACHABLE is not set
-# CONFIG_UBSAN_SIGNED_WRAP is not set
+# CONFIG_UBSAN_INTEGER_WRAP is not set
 # CONFIG_UBSAN_BOOL is not set
 # CONFIG_UBSAN_ENUM is not set
 # CONFIG_UBSAN_ALIGNMENT is not set
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 1d4aa7a83b3a..63e5622010e0 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -116,21 +116,20 @@ config UBSAN_UNREACHABLE
 	  This option enables -fsanitize=unreachable which checks for control
 	  flow reaching an expected-to-be-unreachable position.
 
-config UBSAN_SIGNED_WRAP
-	bool "Perform checking for signed arithmetic wrap-around"
+config UBSAN_INTEGER_WRAP
+	bool "Perform checking for integer arithmetic wrap-around"
 	default UBSAN
 	depends on !COMPILE_TEST
-	# The no_sanitize attribute was introduced in GCC with version 8.
-	depends on !CC_IS_GCC || GCC_VERSION >= 80000
 	depends on $(cc-option,-fsanitize=signed-integer-overflow)
-	help
-	  This option enables -fsanitize=signed-integer-overflow which checks
-	  for wrap-around of any arithmetic operations with signed integers.
-	  This currently performs nearly no instrumentation due to the
-	  kernel's use of -fno-strict-overflow which converts all would-be
-	  arithmetic undefined behavior into wrap-around arithmetic. Future
-	  sanitizer versions will allow for wrap-around checking (rather than
-	  exclusively undefined behavior).
+	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
+	depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
+	depends on $(cc-option,-fsanitize=implicit-unsigned-integer-truncation)
+	help
+	  This option enables all of the sanitizers involved in integer overflow
+	  (wrap-around) mitigation: signed-integer-overflow, unsigned-integer-overflow,
+	  implicit-signed-integer-truncation, and implicit-unsigned-integer-truncation.
+	  This is currently limited only to the size_t type while testing and
+	  compiler development continues.
 
 config UBSAN_BOOL
 	bool "Perform checking for non-boolean values used as boolean"
diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 5d7b10e98610..8772e5edaa4f 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -15,7 +15,7 @@ static void test_ubsan_add_overflow(void)
 {
 	volatile int val = INT_MAX;
 
-	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	UBSAN_TEST(CONFIG_UBSAN_INTEGER_WRAP);
 	val += 2;
 }
 
@@ -24,7 +24,7 @@ static void test_ubsan_sub_overflow(void)
 	volatile int val = INT_MIN;
 	volatile int val2 = 2;
 
-	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	UBSAN_TEST(CONFIG_UBSAN_INTEGER_WRAP);
 	val -= val2;
 }
 
@@ -32,7 +32,7 @@ static void test_ubsan_mul_overflow(void)
 {
 	volatile int val = INT_MAX / 2;
 
-	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	UBSAN_TEST(CONFIG_UBSAN_INTEGER_WRAP);
 	val *= 3;
 }
 
@@ -40,7 +40,7 @@ static void test_ubsan_negate_overflow(void)
 {
 	volatile int val = INT_MIN;
 
-	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	UBSAN_TEST(CONFIG_UBSAN_INTEGER_WRAP);
 	val = -val;
 }
 
@@ -53,6 +53,15 @@ static void test_ubsan_divrem_overflow(void)
 	val /= val2;
 }
 
+static void test_ubsan_truncate_signed(void)
+{
+	volatile long val = LONG_MAX;
+	volatile int val2 = 0;
+
+	UBSAN_TEST(CONFIG_UBSAN_INTEGER_WRAP);
+	val2 = val;
+}
+
 static void test_ubsan_shift_out_of_bounds(void)
 {
 	volatile int neg = -1, wrap = 4;
@@ -127,6 +136,7 @@ static const test_ubsan_fp test_ubsan_array[] = {
 	test_ubsan_sub_overflow,
 	test_ubsan_mul_overflow,
 	test_ubsan_negate_overflow,
+	test_ubsan_truncate_signed,
 	test_ubsan_shift_out_of_bounds,
 	test_ubsan_out_of_bounds,
 	test_ubsan_load_invalid_value,
diff --git a/lib/ubsan.c b/lib/ubsan.c
index a1c983d148f1..cdc1d31c3821 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -44,7 +44,7 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
 	case ubsan_shift_out_of_bounds:
 		return "UBSAN: shift out of bounds";
 #endif
-#if defined(CONFIG_UBSAN_DIV_ZERO) || defined(CONFIG_UBSAN_SIGNED_WRAP)
+#if defined(CONFIG_UBSAN_DIV_ZERO) || defined(CONFIG_UBSAN_INTEGER_WRAP)
 	/*
 	 * SanitizerKind::IntegerDivideByZero and
 	 * SanitizerKind::SignedIntegerOverflow emit
@@ -79,7 +79,7 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
 	case ubsan_type_mismatch:
 		return "UBSAN: type mismatch";
 #endif
-#ifdef CONFIG_UBSAN_SIGNED_WRAP
+#ifdef CONFIG_UBSAN_INTEGER_WRAP
 	/*
 	 * SanitizerKind::SignedIntegerOverflow emits
 	 * SanitizerHandler::AddOverflow, SanitizerHandler::SubOverflow,
@@ -303,6 +303,30 @@ void __ubsan_handle_negate_overflow(void *_data, void *old_val)
 }
 EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
 
+void __ubsan_handle_implicit_conversion(void *_data, void *from_val, void *to_val)
+{
+	struct implicit_conversion_data *data = _data;
+	char from_val_str[VALUE_LENGTH];
+	char to_val_str[VALUE_LENGTH];
+
+	if (suppress_report(&data->location))
+		return;
+
+	val_to_string(from_val_str, sizeof(from_val_str), data->from_type, from_val);
+	val_to_string(to_val_str, sizeof(to_val_str), data->to_type, to_val);
+
+	ubsan_prologue(&data->location, "implicit-conversion");
+
+	pr_err("cannot represent %s value %s during %s %s, truncated to %s\n",
+		data->from_type->type_name,
+		from_val_str,
+		type_check_kinds[data->type_check_kind],
+		data->to_type->type_name,
+		to_val_str);
+
+	ubsan_epilogue();
+}
+EXPORT_SYMBOL(__ubsan_handle_implicit_conversion);
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
 {
diff --git a/lib/ubsan.h b/lib/ubsan.h
index 07e37d4429b4..b37e22374e77 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -62,6 +62,13 @@ struct overflow_data {
 	struct type_descriptor *type;
 };
 
+struct implicit_conversion_data {
+	struct source_location location;
+	struct type_descriptor *from_type;
+	struct type_descriptor *to_type;
+	unsigned char type_check_kind;
+};
+
 struct type_mismatch_data {
 	struct source_location location;
 	struct type_descriptor *type;
@@ -142,6 +149,7 @@ void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs)
 void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
 void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
 void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_implicit_conversion(void *_data, void *lhs, void *rhs);
 void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
 void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
 void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index cad20f0e66ee..981d14ef9db2 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -166,8 +166,8 @@ _c_flags += $(if $(patsubst n%,, \
 		$(UBSAN_SANITIZE_$(target-stem).o)$(UBSAN_SANITIZE)$(is-kernel-object)), \
 		$(CFLAGS_UBSAN))
 _c_flags += $(if $(patsubst n%,, \
-		$(UBSAN_SIGNED_WRAP_$(target-stem).o)$(UBSAN_SANITIZE_$(target-stem).o)$(UBSAN_SIGNED_WRAP)$(UBSAN_SANITIZE)$(is-kernel-object)), \
-		$(CFLAGS_UBSAN_SIGNED_WRAP))
+		$(UBSAN_INTEGER_WRAP_$(target-stem).o)$(UBSAN_SANITIZE_$(target-stem).o)$(UBSAN_INTEGER_WRAP)$(UBSAN_SANITIZE)$(is-kernel-object)), \
+		$(CFLAGS_UBSAN_INTEGER_WRAP))
 endif
 
 ifeq ($(CONFIG_KCOV),y)
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index b2d3b273b802..4fad9afed24c 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -14,5 +14,9 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
-ubsan-signed-wrap-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)     += -fsanitize=signed-integer-overflow
-export CFLAGS_UBSAN_SIGNED_WRAP := $(ubsan-signed-wrap-cflags-y)
+ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
+	-fsanitize=signed-integer-overflow			\
+	-fsanitize=unsigned-integer-overflow			\
+	-fsanitize=implicit-signed-integer-truncation		\
+	-fsanitize=implicit-unsigned-integer-truncation
+export CFLAGS_UBSAN_INTEGER_WRAP := $(ubsan-integer-wrap-cflags-y)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250307041914.937329-1-kees%40kernel.org.
