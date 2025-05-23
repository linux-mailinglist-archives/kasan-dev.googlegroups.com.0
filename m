Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHYX7AQMGQEGK2GJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA57EAC1B00
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:41 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3dc8ab0ac67sf34273125ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975180; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+p2iQYMiD15P8jmHepu/SlAMTnpifRyCkE2xfecGSVDDfw5GY8p4w9UHTFQ4GsOI0
         QPItHWCdLc4Ph4Pa6McvnrTWEuO1lkEQZQz4BbA4+ziwyjk/C6vyPGb7ppvLZbmBR1j+
         qLok9plNxTL0gCBEkcfFWWw4TFpndc/QL7iCFqG1FJPQ+8BIp/ivI73bcnSmw0gXykOR
         r2zxCBDVEa1/7Q0zxMrwtXn+4VTTghws9mNqRgbDhm8TEkSq8pyxQh6MAueAcaoh2aQ7
         1Egm1fzTnO8V/wFDbIPJImvI720y+gY/l7WVCa1T3WI4CuUgVVQ7BfCVFcPBaF8/D825
         uV+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3W9nMVx6tjWEv78ySFeU/rgz0q8oZJWTRlYTYFgfuSM=;
        fh=OpZ+24vTXn0WZcfHKsDDgROfwbZCX4NTrdV+KstKnGg=;
        b=cnScpT1gVt9uCXZh6EBOtk+3MdKhRxk1XtKl+SaU1KI2VXmAb3qmZu9C9eT0vg8X22
         2JvNJjHDD3ouezvGZi0CvZoAk83Lfw6S6jGEPsOiMd9pZ/bsNvmOarcC2/MDGoc7h53y
         bu/YsEf11JEz91Az27hUPBpl1Gp9eTeIqiZoqu17Gnue9ptGeBoyrMC4ur+OS3+vYQzH
         EvRBbcHukNB4nVnvXzlF44bQEDnrHxK/T983yLibWgHLRWK630IUTTMWBmkWbsh/ekho
         wGJ9h2VbmKWTSpz/YBN7RdKIZU3jmAlhhajUwkw6e5hOKpfSR1J4GMaG64lVmYgekq9G
         uHyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i+a8IsmW;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975180; x=1748579980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3W9nMVx6tjWEv78ySFeU/rgz0q8oZJWTRlYTYFgfuSM=;
        b=G50hQ4V7tt0DxXl+ymV8W1Y1KIv81skg8ZbmjgdPd9A+usn9dxoZOfOZXIMNqAA430
         VtPG04vIXdTfsqkWUq3JQGixbIt7CKBUfT17TWxzDXdck0WcesjZASniNDuPZ1ld6L7C
         WYnXJdWBwYXLorrV9eUpaXRM9NWhTagfVPdTRcU9N4L9TqKecgvVacN7Vh5qq3+820cL
         gttpl/WRBwaSgoDp0oG20/WBjvXiI1NzETjOmth4l6aLU8IAm7Tcm+LcnHZHFDalc7z0
         G4HG4gKEROO6/tH3g80YHsVweykYS8C2CA78Accq4SyM92odaxXMBNRoKp4p/J5ksS3o
         /MLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975180; x=1748579980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3W9nMVx6tjWEv78ySFeU/rgz0q8oZJWTRlYTYFgfuSM=;
        b=VyuHZDtVyYcHvifn75mqUBdheJ6TXzB697f5PXEsZw6mZxUX9mpPd0iGP+7x2vsAD5
         SM74gV9Jv42Aw6SicAISac54Wf0zA6auesOZGaRzqY5vVuLYxaAv+vDtpy+UgmoCMyWu
         FIge1kxCQullkPFMCt0jIhsjgk1M3mC8AV1M8rykkR1W8M8Y3JOg5MBNt1+di4/YqgSx
         AQqLqYbx7aOr1ngthdYClf7c45GCD9HaHwCEKU5ZJv87MHiflbnklwRVq7xQoGwyzRCQ
         EJyxJA1NMYEa+NCDMBawKtll9pagOxvhUUerQ96/N2KHx26ujF+aLavNvlBCRKhBY03v
         TyfQ==
X-Forwarded-Encrypted: i=2; AJvYcCWQixB6IW9R0U8QBrYvhG40/SunG/otGIQm37qN+kWbG7Kbms8+IaovvUJzGfGPPnkrkWCwMw==@lfdr.de
X-Gm-Message-State: AOJu0YysvmaEBcUVjN0drd4lK/bryTOJZN8PTX1WbogLRlZq+EqtYrOF
	qKaZrfI6jLF+wH0St4V+2e73aaAopb2FAwYtUNhKqwx7iSqyWJgZtHeT
X-Google-Smtp-Source: AGHT+IEIwifg1p88Z/IUGzlijwylquLp6abZ+0Ub+tizW2NXdUv/NSI1qLyARjF2tmeEo6XomgEENQ==
X-Received: by 2002:a05:6e02:12cf:b0:3d5:8923:faa5 with SMTP id e9e14a558f8ab-3db842c7158mr266339985ab.10.1747975180186;
        Thu, 22 May 2025 21:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEwbo1c5iSmpdzHzgST94GAVx01ycLumRb+0isQiQiBzA==
Received: by 2002:a05:6e02:17c9:b0:3dc:8f0a:a81 with SMTP id
 e9e14a558f8ab-3dc8f0a0acdls10644625ab.1.-pod-prod-02-us; Thu, 22 May 2025
 21:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAyP9gyCh3dDp2wP8W7UmK4N/BD9KwjUS29OvvaJp84HmFbocpAkLGxf80NOr2pXG6WmIasbZowDI=@googlegroups.com
X-Received: by 2002:a05:6e02:1745:b0:3db:7b4c:309b with SMTP id e9e14a558f8ab-3db8429768amr333945895ab.2.1747975179328;
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975179; cv=none;
        d=google.com; s=arc-20240605;
        b=CBtN+I0dTm5jH4AC6kK6igS1ZVqo5cEF/wLrnPMLZzTTKKDrOHyX9WzlLjfHkbItCI
         xpEYS7lXlc3PL4uyMgHBqjbiZSpOEtFJawTuK5V7LKoXqT2CnkYpiicA96/wpsZxQX+h
         8pcGihd5mzIW0zwAookVMR4Ix7vebE5p7pWkv1aqBFX1x+sECZ/PU2G1llsBZSSvHOoc
         9P3zSEgiO5CFROkRTgysUIE3ITOq3N1zNXw+PqnPzjQtDCIhhElNAOiX8bdhmzh/XBf5
         21Wz0q23WE87tE50cFTJ7z4iOMLgcFcnPQGVWspar3AOcvsC6L2w/QQNP1ekFtTJVsXj
         sMng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QBmi1nCfdaTMLi/zwjIyatWWKcM/XuFxbLBe4bFrq8k=;
        fh=xrXMT+NePT1UiVpMDmsviEJzoH5LT080PVsJSFk4SaM=;
        b=BRWKQsghw0UHE3zTXNe0Eb468thMkax9n3so29NqM6D3hdloq4IDd6SUgQNJDD11IG
         mH8mm6atuuMVHktuktAyqEsrN8MHaCCL0EBHZ5vOOL+0M2rHmOdd2eaEtEQ4PJ+0RM0Q
         6FwBxnvI9ThaBixEC+0yZMbSfuBf+QTTU+M7rK8jR7Q+EeaCLLn2ZX8yb04885XTPMWN
         Az4gLpwAKjDufhvfPUzPDA1vgBhAFM8IcjIBMQt20x54Od317pT2E6dr9PJ1ewfoWB2h
         4clvQxt/7isk3vCWXQcFrQMqUlUOEdl8bVrSOdfhjTdhrADg2pnXSo6ewKBjDiE1bkzc
         R3nA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i+a8IsmW;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4fbcc43c51fsi652926173.5.2025.05.22.21.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9138244D22;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 64BFDC4CEED;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	linux-hardening@vger.kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 02/14] stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
Date: Thu, 22 May 2025 21:39:12 -0700
Message-Id: <20250523043935.2009972-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=11486; i=kees@kernel.org; h=from:subject; bh=6jDSpkitaXxC96OxJjyaip+FfU4NrOF4Y8k/mkqIlN4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v388d99a4lGamGETdeemkuEC3/SchscmPwLXLDdIk 9wmtra6o5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCLNYYwMe5wZf7q5M+2YOsvW na0ll3XpXv/156rcSmbvuOG+/bTRSkaGrn2i2+dzxfIZ7A7e/v5EnMDNnh0sT1bekHjWxsUf1Hi SEQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i+a8IsmW;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

The Clang stack depth tracking implementation has a fixed name for
the stack depth tracking callback, "__sanitizer_cov_stack_depth", so
rename the GCC plugin function to match since the plugin has no external
dependencies on naming.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <linux-hardening@vger.kernel.org>
---
 security/Kconfig.hardening             |  4 +-
 scripts/gcc-plugins/stackleak_plugin.c | 52 +++++++++++++-------------
 include/linux/kstack_erase.h           |  2 +-
 kernel/kstack_erase.c                  |  4 +-
 tools/objtool/check.c                  |  2 +-
 5 files changed, 32 insertions(+), 32 deletions(-)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 125b35e2ef0f..f7aa2024ab25 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -129,8 +129,8 @@ config KSTACK_ERASE_TRACK_MIN_SIZE
 	help
 	  The KSTACK_ERASE option instruments the kernel code for tracking
 	  the lowest border of the kernel stack (and for some other purposes).
-	  It inserts the stackleak_track_stack() call for the functions with
-	  a stack frame size greater than or equal to this parameter.
+	  It inserts the __sanitizer_cov_stack_depth() call for the functions
+	  with a stack frame size greater than or equal to this parameter.
 	  If unsure, leave the default value 100.
 
 config KSTACK_ERASE_METRICS
diff --git a/scripts/gcc-plugins/stackleak_plugin.c b/scripts/gcc-plugins/stackleak_plugin.c
index d20c47d21ad8..e486488c867d 100644
--- a/scripts/gcc-plugins/stackleak_plugin.c
+++ b/scripts/gcc-plugins/stackleak_plugin.c
@@ -9,7 +9,7 @@
  * any of the gcc libraries
  *
  * This gcc plugin is needed for tracking the lowest border of the kernel stack.
- * It instruments the kernel code inserting stackleak_track_stack() calls:
+ * It instruments the kernel code inserting __sanitizer_cov_stack_depth() calls:
  *  - after alloca();
  *  - for the functions with a stack frame size greater than or equal
  *     to the "track-min-size" plugin parameter.
@@ -33,7 +33,7 @@ __visible int plugin_is_GPL_compatible;
 
 static int track_frame_size = -1;
 static bool build_for_x86 = false;
-static const char track_function[] = "stackleak_track_stack";
+static const char track_function[] = "__sanitizer_cov_stack_depth";
 static bool disable = false;
 static bool verbose = false;
 
@@ -58,7 +58,7 @@ static void add_stack_tracking_gcall(gimple_stmt_iterator *gsi, bool after)
 	cgraph_node_ptr node;
 	basic_block bb;
 
-	/* Insert calling stackleak_track_stack() */
+	/* Insert calling __sanitizer_cov_stack_depth() */
 	stmt = gimple_build_call(track_function_decl, 0);
 	gimple_call = as_a_gcall(stmt);
 	if (after)
@@ -120,12 +120,12 @@ static void add_stack_tracking_gasm(gimple_stmt_iterator *gsi, bool after)
 	gcc_assert(build_for_x86);
 
 	/*
-	 * Insert calling stackleak_track_stack() in asm:
-	 *   asm volatile("call stackleak_track_stack"
+	 * Insert calling __sanitizer_cov_stack_depth() in asm:
+	 *   asm volatile("call __sanitizer_cov_stack_depth"
 	 *		  :: "r" (current_stack_pointer))
 	 * Use ASM_CALL_CONSTRAINT trick from arch/x86/include/asm/asm.h.
 	 * This constraint is taken into account during gcc shrink-wrapping
-	 * optimization. It is needed to be sure that stackleak_track_stack()
+	 * optimization. It is needed to be sure that __sanitizer_cov_stack_depth()
 	 * call is inserted after the prologue of the containing function,
 	 * when the stack frame is prepared.
 	 */
@@ -137,7 +137,7 @@ static void add_stack_tracking_gasm(gimple_stmt_iterator *gsi, bool after)
 	input = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
 	input = chainon(NULL_TREE, build_tree_list(input, sp_decl));
 	vec_safe_push(inputs, input);
-	asm_call = gimple_build_asm_vec("call stackleak_track_stack",
+	asm_call = gimple_build_asm_vec("call __sanitizer_cov_stack_depth",
 					inputs, NULL, NULL, NULL);
 	gimple_asm_set_volatile(asm_call, true);
 	if (after)
@@ -151,11 +151,11 @@ static void add_stack_tracking(gimple_stmt_iterator *gsi, bool after)
 {
 	/*
 	 * The 'no_caller_saved_registers' attribute is used for
-	 * stackleak_track_stack(). If the compiler supports this attribute for
-	 * the target arch, we can add calling stackleak_track_stack() in asm.
+	 * __sanitizer_cov_stack_depth(). If the compiler supports this attribute for
+	 * the target arch, we can add calling __sanitizer_cov_stack_depth() in asm.
 	 * That improves performance: we avoid useless operations with the
 	 * caller-saved registers in the functions from which we will remove
-	 * stackleak_track_stack() call during the stackleak_cleanup pass.
+	 * __sanitizer_cov_stack_depth() call during the stackleak_cleanup pass.
 	 */
 	if (lookup_attribute_spec(get_identifier("no_caller_saved_registers")))
 		add_stack_tracking_gasm(gsi, after);
@@ -165,7 +165,7 @@ static void add_stack_tracking(gimple_stmt_iterator *gsi, bool after)
 
 /*
  * Work with the GIMPLE representation of the code. Insert the
- * stackleak_track_stack() call after alloca() and into the beginning
+ * __sanitizer_cov_stack_depth() call after alloca() and into the beginning
  * of the function if it is not instrumented.
  */
 static unsigned int stackleak_instrument_execute(void)
@@ -205,7 +205,7 @@ static unsigned int stackleak_instrument_execute(void)
 					DECL_NAME_POINTER(current_function_decl));
 			}
 
-			/* Insert stackleak_track_stack() call after alloca() */
+			/* Insert __sanitizer_cov_stack_depth() call after alloca() */
 			add_stack_tracking(&gsi, true);
 			if (bb == entry_bb)
 				prologue_instrumented = true;
@@ -241,7 +241,7 @@ static unsigned int stackleak_instrument_execute(void)
 		return 0;
 	}
 
-	/* Insert stackleak_track_stack() call at the function beginning */
+	/* Insert __sanitizer_cov_stack_depth() call at the function beginning */
 	bb = entry_bb;
 	if (!single_pred_p(bb)) {
 		/* gcc_assert(bb_loop_depth(bb) ||
@@ -270,15 +270,15 @@ static void remove_stack_tracking_gcall(void)
 	rtx_insn *insn, *next;
 
 	/*
-	 * Find stackleak_track_stack() calls. Loop through the chain of insns,
+	 * Find __sanitizer_cov_stack_depth() calls. Loop through the chain of insns,
 	 * which is an RTL representation of the code for a function.
 	 *
 	 * The example of a matching insn:
-	 *  (call_insn 8 4 10 2 (call (mem (symbol_ref ("stackleak_track_stack")
-	 *  [flags 0x41] <function_decl 0x7f7cd3302a80 stackleak_track_stack>)
-	 *  [0 stackleak_track_stack S1 A8]) (0)) 675 {*call} (expr_list
-	 *  (symbol_ref ("stackleak_track_stack") [flags 0x41] <function_decl
-	 *  0x7f7cd3302a80 stackleak_track_stack>) (expr_list (0) (nil))) (nil))
+	 *  (call_insn 8 4 10 2 (call (mem (symbol_ref ("__sanitizer_cov_stack_depth")
+	 *  [flags 0x41] <function_decl 0x7f7cd3302a80 __sanitizer_cov_stack_depth>)
+	 *  [0 __sanitizer_cov_stack_depth S1 A8]) (0)) 675 {*call} (expr_list
+	 *  (symbol_ref ("__sanitizer_cov_stack_depth") [flags 0x41] <function_decl
+	 *  0x7f7cd3302a80 __sanitizer_cov_stack_depth>) (expr_list (0) (nil))) (nil))
 	 */
 	for (insn = get_insns(); insn; insn = next) {
 		rtx body;
@@ -318,7 +318,7 @@ static void remove_stack_tracking_gcall(void)
 		if (SYMBOL_REF_DECL(body) != track_function_decl)
 			continue;
 
-		/* Delete the stackleak_track_stack() call */
+		/* Delete the __sanitizer_cov_stack_depth() call */
 		delete_insn_and_edges(insn);
 #if BUILDING_GCC_VERSION < 8000
 		if (GET_CODE(next) == NOTE &&
@@ -340,12 +340,12 @@ static bool remove_stack_tracking_gasm(void)
 	gcc_assert(build_for_x86);
 
 	/*
-	 * Find stackleak_track_stack() asm calls. Loop through the chain of
+	 * Find __sanitizer_cov_stack_depth() asm calls. Loop through the chain of
 	 * insns, which is an RTL representation of the code for a function.
 	 *
 	 * The example of a matching insn:
 	 *  (insn 11 5 12 2 (parallel [ (asm_operands/v
-	 *  ("call stackleak_track_stack") ("") 0
+	 *  ("call __sanitizer_cov_stack_depth") ("") 0
 	 *  [ (reg/v:DI 7 sp [ current_stack_pointer ]) ]
 	 *  [ (asm_input:DI ("r")) ] [])
 	 *  (clobber (reg:CC 17 flags)) ]) -1 (nil))
@@ -375,7 +375,7 @@ static bool remove_stack_tracking_gasm(void)
 			continue;
 
 		if (strcmp(ASM_OPERANDS_TEMPLATE(body),
-						"call stackleak_track_stack")) {
+						"call __sanitizer_cov_stack_depth")) {
 			continue;
 		}
 
@@ -389,7 +389,7 @@ static bool remove_stack_tracking_gasm(void)
 
 /*
  * Work with the RTL representation of the code.
- * Remove the unneeded stackleak_track_stack() calls from the functions
+ * Remove the unneeded __sanitizer_cov_stack_depth() calls from the functions
  * which don't call alloca() and don't have a large enough stack frame size.
  */
 static unsigned int stackleak_cleanup_execute(void)
@@ -474,13 +474,13 @@ static bool stackleak_gate(void)
 	return track_frame_size >= 0;
 }
 
-/* Build the function declaration for stackleak_track_stack() */
+/* Build the function declaration for __sanitizer_cov_stack_depth() */
 static void stackleak_start_unit(void *gcc_data __unused,
 				 void *user_data __unused)
 {
 	tree fntype;
 
-	/* void stackleak_track_stack(void) */
+	/* void __sanitizer_cov_stack_depth(void) */
 	fntype = build_function_type_list(void_type_node, NULL_TREE);
 	track_function_decl = build_fn_decl(track_function, fntype);
 	DECL_ASSEMBLER_NAME(track_function_decl); /* for LTO */
diff --git a/include/linux/kstack_erase.h b/include/linux/kstack_erase.h
index 4e432eefa4d0..bf3bf1905557 100644
--- a/include/linux/kstack_erase.h
+++ b/include/linux/kstack_erase.h
@@ -80,7 +80,7 @@ static inline void stackleak_task_init(struct task_struct *t)
 asmlinkage void noinstr stackleak_erase(void);
 asmlinkage void noinstr stackleak_erase_on_task_stack(void);
 asmlinkage void noinstr stackleak_erase_off_task_stack(void);
-void __no_caller_saved_registers noinstr stackleak_track_stack(void);
+void __no_caller_saved_registers noinstr __sanitizer_cov_stack_depth(void);
 
 #else /* !CONFIG_KSTACK_ERASE */
 static inline void stackleak_task_init(struct task_struct *t) { }
diff --git a/kernel/kstack_erase.c b/kernel/kstack_erase.c
index 201b846f8345..e49bb88b4f0a 100644
--- a/kernel/kstack_erase.c
+++ b/kernel/kstack_erase.c
@@ -156,7 +156,7 @@ asmlinkage void noinstr stackleak_erase_off_task_stack(void)
 	__stackleak_erase(false);
 }
 
-void __used __no_caller_saved_registers noinstr stackleak_track_stack(void)
+void __used __no_caller_saved_registers noinstr __sanitizer_cov_stack_depth(void)
 {
 	unsigned long sp = current_stack_pointer;
 
@@ -174,4 +174,4 @@ void __used __no_caller_saved_registers noinstr stackleak_track_stack(void)
 		current->lowest_stack = sp;
 	}
 }
-EXPORT_SYMBOL(stackleak_track_stack);
+EXPORT_SYMBOL(__sanitizer_cov_stack_depth);
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 31088a138bc9..dad81194a81b 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1192,7 +1192,7 @@ static const char *uaccess_safe_builtin[] = {
 	"__ubsan_handle_shift_out_of_bounds",
 	"__ubsan_handle_load_invalid_value",
 	/* KSTACK_ERASE */
-	"stackleak_track_stack",
+	"__sanitizer_cov_stack_depth",
 	/* TRACE_BRANCH_PROFILING */
 	"ftrace_likely_update",
 	/* STACKPROTECTOR */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-2-kees%40kernel.org.
