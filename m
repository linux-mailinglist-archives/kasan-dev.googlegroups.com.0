Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B6CE1B09749
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b3ba7659210sf1077415a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794724; cv=pass;
        d=google.com; s=arc-20240605;
        b=XuhzApRyvSRUAL8AKuGuTSUoGbTgZsk8xrsPB+cCHPdiqtWVrrgECt5ACrSxqpJHxK
         HiiIfZ94Y8WPAafPZ9mOPcCA+Hh/zPjM9cKz4nxzzSVUG4HyvZ92DeRhiZB0OHs+rvRW
         kU93gXeHQDpmN1e0Elqgrvewds/W7qv8ur6Qv1ByevVx7esn30wrHydvLXvBuJTYm3Fk
         lpsQdzsIXQmgHhaR3ctpLEr3pujjtw3PU1c+dnhhDgmP3OkuNKmk8dwuyP4B3w4dLjeY
         RLhJoRuYEsLx1T8a6Thh48VHWtV2rdgLDWME+x6/z0Cc+stpUV4/qUIRZXReHKDW7hKP
         EBXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bJnNZz2r9k4DIwz3JTJ06zfqjwGaShqaH358irsIhyo=;
        fh=7YtPONtcHfGdL8SFqSWLOmOkTJjj0Tj54d+zKl5LaLc=;
        b=FOaVsX3CiImi7GZUjNjlG8V4linWXYo0p9RzrUp9WgSpxJnk9Ef861uW0Jus1od5fl
         CQ7nChXIuvpdpQocWLnaxqOB9qjBhVZ1muRMHliRgBnENf9wFl4l8VP7HJcdl3JIYsac
         2o10slZHwo0aj2f2uK0FbFH09/i2teXDti5q1rf2Obj6aW8QN76/NwA/kWt9NQ8szK7+
         RiYAUO5z8AgzYeHymEngpMY4DYwmyRwle1iBlsMGyj0LI98fdksmTd1yefrOiJsQAoKA
         hmCbzd/ONnVvJQsqCJzzQHNgDUHUhb2B9OCG6Yp9trxj/4414Tkg5A7uIBspgYi4CjAV
         eI0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bnYTbDgT;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794724; x=1753399524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bJnNZz2r9k4DIwz3JTJ06zfqjwGaShqaH358irsIhyo=;
        b=q52jPBx1gXNQb/TMauJv56nTtpj6dPaL1y1eATLj38iLt2UMTIhecqWgW4leGl+ZDV
         NK/Q9fY3K1JY7zaWGNABBWnV/CUaWy2vcM3myi7c9hFUDA54jLVLRwjsbjnHe9b7agsV
         lUhfMeIO50r60+vEjqr/FBbVr2uPuhEu4O2SII8DEOnalhX3cNJ7c9XsSPbXOAEkWrDu
         hIVCqohrAkKBwBeS/vs/XwF74kueXqzzwVNYphD2ZTDoagYiEkWfpLwLO7OWTzUU7W56
         dlQ3DoEJSa52CG/K6EKn5+Qjps7oeXasHATJo4Szbr3fS4cY3aWR6A8j9OS+qfmMfhka
         vviA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794724; x=1753399524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bJnNZz2r9k4DIwz3JTJ06zfqjwGaShqaH358irsIhyo=;
        b=w0JKJ8ozn+S9AwbfRJ4EDzOrL3bmyaHLGsmKtj7YeqM/+gMMhDLEAjKjtSO7MJ79n2
         arSbuKy1ZTazAnVY0kCR9LTasMFMS2h9iAT5Nz08QWK1jg3QFXixT+Se4xtU7vhU5Zz3
         fVNisco6N6c5Eq5PPbZMT4S821Sy83f9wt8gabUBUGnyQoWWaWKui8gdFmSOMqPEgpcJ
         0q3BivO+2QJ2cwxPfKE1SANql4+uaVSoHJeWekHahzlp2pF6Je0eNnj7ZjR2DJDyRIFe
         hDYAf42mn9KJwtZv03KKKJI0QHaQcQ/GHAlNpTVAtFLA5fRM+oUi20b2hu1RoNnwslgr
         upkg==
X-Forwarded-Encrypted: i=2; AJvYcCXkmHsufxqBh5APgO1S6WcbZve8hZgPLMry2YsuljSGaXX+yQOI+ib4MRcB1nSBp6Do6mEa+A==@lfdr.de
X-Gm-Message-State: AOJu0Yy36Hb7nDjLXVwUfYd8Nef43EgoNve6QJEI2V5ou2zzDS3tmEnt
	NGcUHuUDoahxKy8IeiQIWobom36NVgEvTjiTvTSDFda7PyG4mZdBV+yP
X-Google-Smtp-Source: AGHT+IHmay+9gcgsdJ9FgGLgYZ9nLQmxJJaeibEQcTEQRq/ovKcwsl6+/vn8l3xWf7lvW2Eefny6ng==
X-Received: by 2002:a17:902:da8a:b0:23c:8f21:ac59 with SMTP id d9443c01a7336-23e2572b0c0mr129782415ad.29.1752794723660;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdq8i9fOFJkjI4zNJzydo5EglOHQMOH1nf9HXORrTkDZA==
Received: by 2002:a17:902:d192:b0:234:aa6d:511a with SMTP id
 d9443c01a7336-23e2eb4e818ls8213905ad.0.-pod-prod-07-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoTmgUhrL8w8tjXw2K7GK3vRu9ZZfm+o2yssaNJDYPUDl0UF8WxTcakK72PQMvf30/ZYzyYRMg8Lc=@googlegroups.com
X-Received: by 2002:a17:903:228d:b0:23c:8f4c:6658 with SMTP id d9443c01a7336-23e2572a0dcmr115474385ad.25.1752794722257;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=U3aXgGp6k1sfRa25FCS2FzGCU59V5hVr+oLLBvDWD+0tlSI5hwy7RheeOiMxwJDS6q
         iJTF4+w2fKOHMAGZJ+7Tp5nFRpalpelc8gioXH6gKHxd9mnRrZu4Fm0YjypVqSaq3pWV
         CNZ7WnQHVnei0BUpHDtW8PItQDAVbr1BaMQlj4zZO0YAB1r2PIUQPUNStPJ696FiQaS9
         B9T+7AmkDNBPBNgVUeHblLQjPFQHfH4p7lpfKzD7NDjOBIEQojfEPP9uDgei0ctdhoOC
         MX763YzeIu2L0z5V50/RjkFXd5A7arkUkL8jBl2r9j+3oOczos/L9WdnaJJwYNz6NUXx
         47pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l5/DiOMP5IDBoe3PFgRykYkj5ZQc4B51RptLIWYVtXY=;
        fh=KzLSqhbsvMm7EyGrZAWcPBIOvNs671j43Q6sSUIMKFs=;
        b=Hcy36vTaLPEZv6bGuv7ivc2cJaC+V/uEb8QvCoADipuezQxV75hX1MFmZvQlNo9lD5
         uvL6jHcjwLvxUBBUpbCl+IWGrlUdTooqdh1hSO6xkcpOyhdX/uJMJvNd9obX5oLAkXJ0
         PWqaUhgF7r74jtI4KWoW5ctuZfRW7484+UB2pVpa6Cfvw6vsgb3HN2FwMdRq6IB8aOGb
         W+UtxXFFXX1ueN9nrag+G4l/38eefZ0xi7i9yeVcTyedQEixbZ9P+DL7C4JsC+hVjZms
         fFOYR4pN2Rzg/WVGZOiIIOk1bhyeVr0aBtcoygnDbJY9a+zZ6Bxxx84/SOUsaGMt9OUg
         v/jA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bnYTbDgT;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c9f1d9743si228434a91.1.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 103AF613F9;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D078C4CEF0;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	linux-hardening@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
Subject: [PATCH v3 02/13] stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
Date: Thu, 17 Jul 2025 16:25:07 -0700
Message-Id: <20250717232519.2984886-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=11486; i=kees@kernel.org; h=from:subject; bh=QO3sphraMQU4pplXqgpqBgGUJOqKb6MMyrCLVjfJgf4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbVFRYqs7HtQl3OrNeT1jq9hG1gfr7PnFD3xh7FzY7 aM18yV7RykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwERmnGX4XxQUq2kysTBh9Yqi gx0XD2ffidwp9TBF0XG2aNZOt/kfPRkZbqSGvrbV7LugE1awdMeemZ8P/z4lWN73Wnp36mS7u+4 v+QE=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bnYTbDgT;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
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
index 1b3e6968a82d..01144ab8e906 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1193,7 +1193,7 @@ static const char *uaccess_safe_builtin[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-2-kees%40kernel.org.
