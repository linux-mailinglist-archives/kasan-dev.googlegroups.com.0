Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5GG53AAMGQETX6KVZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A87BAAE88A
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:22 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e77d3eeed04sf215724276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641781; cv=pass;
        d=google.com; s=arc-20240605;
        b=CYXUlBv7dtJC4aI8M9ry7vwjwFyTEQBiQjV9jSZU06xNtVPSNcPF3faPILZDp3Snm/
         h7kqmU3IdRsqO7LwDCz8Mpe/eXiWCmdGJqWywM6UjCD4w5jtHMVea0PCYtCNPjn5b90R
         itXdvQQuZsYri1Ty1nUTqhM1EIlA3DERdRYSM2PtpwfI2s4YDlmWgv/CLtejRPwh9xzs
         U/9tKO7lxZqiTh6CCypSK1UL3LSt+h5+7iz/fI/EodcNELgqPkzJOe/7me9KTs9F9+Hx
         a0QAUcVGUOACr4K7dOghkNmPdMtihr2o0a3sCArOftfXiQnOJufri7gKLj9O7oXMu2nQ
         edtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T/XHRw3S/Xj8DPBoF8LgjbL453f27U5Cu3v4RZI9WXY=;
        fh=ALaxNHw1zz4VoMzOVUCm82avgGugw8TlXE+lPYXIL1g=;
        b=Fwr4j4t2ZhL2M1BXclO4/20xW9glIIo5TB+8n+VBx5Vrg5DLMZWoUkHqa61KWuWfrl
         fw3y3/m1rRV4ZXiIJwAPjUP5lqi3Z1XK8xQS+TuJPD5xj9gB7TH2o079gxAWzelfkAWI
         Q/XX4AO/WzB3EMxiH6PhSM7fkdqLuHJaU6x3mJRkrT/PdPcZ/B90Yd2CPM9vYops+oJZ
         rJb8HmrDOJUcbMvHxb9frxbkghNackOJMV/qzmP+VKYTiPJt9iQvkptGlk5le6g5ajtj
         mYMaIwyFDK+s2LajIhseL7KM+4ybaaNbujecuJQfNSDx4HbVd2sRlb7QolbU7by56aDG
         Fc9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u1u0pSpD;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641781; x=1747246581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T/XHRw3S/Xj8DPBoF8LgjbL453f27U5Cu3v4RZI9WXY=;
        b=vufvlgEImvNyQe1YPQaA2cDdPDrYojHZVGLOi3N/yt39t54TWxLyI442GIe/OILthU
         CiEOBp9QZtUXZ0URr7vfbrSAtsFBdt1wY+cYjP3S/CGBIc2C+Bch4xsdHPXMjrMlRKnD
         dz+yhuTsdEghMYFzpQvM8/pGigv2DXjjH3VOAdPZMNCwDQgKXJ1h0gbAFbINtO52gdRv
         xMDdWkY3+Gl0+KDY95oTICgFTA7a8RMKr9dWgJkbL9r4CORot5BbhYTDAFIYlla/zbRS
         QeYnTuwCbFt1e5zotMxgLQdzhLHD1j7LAl2XLpwTS5eV7jKgTdRTjU9mFmswt/3LqOYt
         r5LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641781; x=1747246581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T/XHRw3S/Xj8DPBoF8LgjbL453f27U5Cu3v4RZI9WXY=;
        b=TcTdxKNG5plX6ZvBUwjM3i9IYToZrEKLBKdIBQuS9kU3X924fq5cG44it5bkRkcP5s
         iY06G5B+ewsQioZFii1nkrRy54NcMAnpIzYuZ9teDWmiAtAMBhFpYL5lYSUvuxqlqdqm
         Ooswi2fv6pcx9bVjf16TDGqgR/Ikqp6mOgb2oywyJ2FcaaCR+0/c9+heq+U0MqHDG1Ew
         E++cOMjXPOPIWyo39bC4pPRHViF11+WZoAYIk4wxlFJeQS1bjNytOkhMaGHNl6lou8VQ
         8AbHh4ptzM0rg3ebnw962GGYDHS/IwzHf7T4qRsev3iSRdiKiq08kzzSyk6Wc/HYLrRt
         +p2w==
X-Forwarded-Encrypted: i=2; AJvYcCUTy1f1x8EycLKS9OqDgXvtPy8P0pzgz6nEEVC7E8yjb/pLLUv+VOxdjcZZQKUPkPF35y53ew==@lfdr.de
X-Gm-Message-State: AOJu0YxG8fvgoDovQl9BqfidG0jAJGc1DLqprOg1EqQGXjQgDTbwQGs5
	bXhAlM/cTGgBiBO50qq+0JvtassdQu6t0pSUirDducKsZnqQntxK
X-Google-Smtp-Source: AGHT+IGud0eQYUmWG9jmweqvPEdAWZf75F6i1JvyIHOE+MbLI6ntSiKHoUiY3SxE3mUNJ8NjzxqQbA==
X-Received: by 2002:a05:6902:1ac5:b0:e75:607f:5fd2 with SMTP id 3f1490d57ef6-e7881d10714mr5683712276.48.1746641780761;
        Wed, 07 May 2025 11:16:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGfVNpNOFsnPtuI/FHPFeH/1foQnOZhYcIFyELiD7G2yw==
Received: by 2002:a25:aa43:0:b0:e78:eb25:6599 with SMTP id 3f1490d57ef6-e78edffeaffls210993276.2.-pod-prod-06-us;
 Wed, 07 May 2025 11:16:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZkZYvLvZIZG/5Zgl3fInyBya1KK1Q2duvBhLGRYJvfXpbu4fA8vGKctzekwJr2JHkjcN9L9OW6gk=@googlegroups.com
X-Received: by 2002:a05:690c:700c:b0:6f7:5a46:fe5f with SMTP id 00721157ae682-70a1d9d892fmr64508327b3.1.1746641779195;
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641779; cv=none;
        d=google.com; s=arc-20240605;
        b=S+/7ctr91SWI+j6U3QdHSDYAQ3aQ9PyJ1CkUO4OEsCVuoHZKnjaBBFPeMUZRwvO955
         yhtT8qfYUO8w3Bo3nhoAUsqiWXuDgG8IcGzQGEGMA88L+ZHye00suntupFmEBRKGnk0Q
         kJkNfI4TTB25cJKUhVvySNcqIJUZ71Cm2vRR2Jj3BNQX+gVTSJsM9mPmsjf7x0Vgirqt
         dV1HooQ0JKVl5CoYRYTUvo6kCIu83CiRafLB2p7VUcUGMzt4tsGBgsJlrUJ13keKXgCV
         sWhJ+wuNnqyKdAGQtb+BbOSaHWJ1nfW85lkMkwvUS8eAERuxkl+cPkdRVuorvRoIto+h
         uwqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KeY8ZMbkuUDWGojF26YaLZF1k4AtGAsjBLRl0RdS4Bk=;
        fh=xrXMT+NePT1UiVpMDmsviEJzoH5LT080PVsJSFk4SaM=;
        b=QMHuKVoxyS8iWHN5rL7Xj0EP1dWDib5Cwamv2qtcDSbNH53FzKc2PezouvNCt3NT6g
         QkFKmLbN5RAFwaqBI7eadT1ZU8sfHVj8TZ9fLGn2ugvdwqCyKeE2yimoy5h91cIAFZs+
         k9AOCPDVclPk05wXK/TVxmk0jCljtNdUdkcHQefPIPgb+r/O+H89X+qKxj4IuksGCZxX
         W80vX22z/pNs1Nh5Yl4wQjmPuYM8rNfWc3Rn4cvmwRvfQsjJw+CoaVbxd1xTKe5aw0f/
         IeO2h6oiiGhYaoVtYWOc76z6yWkDPfxVQnHPbqKnpCdtQI5ZlDUHysVnEsX2WCNBjGga
         DhDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u1u0pSpD;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7091b623b02si1914237b3.2.2025.05.07.11.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id B550AA4DC19;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3C685C4CEE9;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
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
Subject: [PATCH 4/8] stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
Date: Wed,  7 May 2025 11:16:10 -0700
Message-Id: <20250507181615.1947159-4-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=11429; i=kees@kernel.org; h=from:subject; bh=6Q9uh62q6SkNNJk0VXiSTm2HMDshuMHoXOhVSBim3Js=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi3MENts7tXm5z7rDvWBm5prEstc7xQ49040UXbNwl 2Pm5mvBHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABP52szIcHHStinFM79Mm9M/ O+x3cEx83y/m5hy3xIfPryo1blgofZeR4UxS5zpfB9dppxRKuC1yXzQsFys7vj1mYbnhujfpDUf 2cQIA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u1u0pSpD;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

The Clang stack depth tracking implementation has a fixed name for the
stack depth tracking callback, "__sanitizer_cov_stack_depth", so rename
the GCC plugin function to match since it has no external dependencies.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <linux-hardening@vger.kernel.org>
---
 security/Kconfig.hardening             |  4 +-
 scripts/gcc-plugins/stackleak_plugin.c | 52 +++++++++++++-------------
 include/linux/stackleak.h              |  2 +-
 kernel/stackleak.c                     |  4 +-
 tools/objtool/check.c                  |  2 +-
 5 files changed, 32 insertions(+), 32 deletions(-)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 2d5852676991..2be6aed71c92 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -205,8 +205,8 @@ config STACKLEAK_TRACK_MIN_SIZE
 	help
 	  The STACKLEAK options instruments the kernel code for tracking
 	  the lowest border of the kernel stack (and for some other purposes).
-	  It inserts the stackleak_track_stack() call for the functions with
-	  a stack frame size greater than or equal to this parameter.
+	  It inserts the __sanitizer_cov_stack_depth() call for the functions
+	  with a stack frame size greater than or equal to this parameter.
 	  If unsure, leave the default value 100.
 
 config STACKLEAK_METRICS
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
diff --git a/include/linux/stackleak.h b/include/linux/stackleak.h
index 71e8242fd8f2..a669574a3562 100644
--- a/include/linux/stackleak.h
+++ b/include/linux/stackleak.h
@@ -80,7 +80,7 @@ static inline void stackleak_task_init(struct task_struct *t)
 asmlinkage void noinstr stackleak_erase(void);
 asmlinkage void noinstr stackleak_erase_on_task_stack(void);
 asmlinkage void noinstr stackleak_erase_off_task_stack(void);
-void __no_caller_saved_registers noinstr stackleak_track_stack(void);
+void __no_caller_saved_registers noinstr __sanitizer_cov_stack_depth(void);
 
 #else /* !CONFIG_STACKLEAK */
 static inline void stackleak_task_init(struct task_struct *t) { }
diff --git a/kernel/stackleak.c b/kernel/stackleak.c
index bb65321761b4..5158468968e2 100644
--- a/kernel/stackleak.c
+++ b/kernel/stackleak.c
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
index 3a411064fa34..05d0095c1384 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1191,7 +1191,7 @@ static const char *uaccess_safe_builtin[] = {
 	"__ubsan_handle_shift_out_of_bounds",
 	"__ubsan_handle_load_invalid_value",
 	/* STACKLEAK */
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-4-kees%40kernel.org.
