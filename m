Return-Path: <kasan-dev+bncBDCPL7WX3MKBBRFU3K7QMGQEMCULMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 43840A82BB7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 18:03:18 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff5296726fsf10427494a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 09:03:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744214596; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q3GinaBBg9A5u7MgXQ7I+LF7gb4N/6hDzFJ0bMSXpIiJzA7wpLFINGSA6ioMCbwwA1
         en5PUD7dKD2vQciEa3BKCLKCNrULIobvJInbfTg5dold5QX4yl5i4Hy6tr40Pc1p++EX
         HIhYfUtRjt+8sFGOl6RWc3GWb5ds+d9Sc4aU9w6/NLdyUTOxrVHJTrQ0xZ2Z621PJ5fk
         fwUnEOLnfr8ffVIvxWJqTBVGMCW6hd7nkKS8yYb7PPY26ryFnn1zRl7dFWfCqsCu8HzY
         yGjdwH+ceSdDWr0hWLVdpgnh1Zisq5QnHHYfYBAS7maqMkOitXVLl6BKfYSR+lIyTxPv
         Jp3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=WIb2PGPlCqmD+7Qtzdv3OKAnd0eWwhm5P6P33iWSU/c=;
        fh=1Dcw5gAdBdvYfPLEnwDbS3UcZcUPXyBZAHHe7XGglNo=;
        b=YeFOVkAeF7N34+Jy61nXv1vFxpfhlptYdXVQgehAWJDqyMu8vQIKa+vIYj579T8YRj
         7O+9GOmGU0NtbPk29CJAjAUbM447gT90hmQ/NiQkfltdexAR8iLkidzPHrYc9ikyv+Ls
         rYkX9IPe+MAt+5yk94KlvzGjoG0cXxA/fpTRrD8xlf3ccLfrIkUDlA4MhlNYV1T46QJv
         dxzB6CB/Izovz2QyzP/Qqvi2SzfA0NonrbbHajFFrf308JVoD7q+SzXiP2uQRNS3OmAc
         11HGMe8rIgTAXJ30vh9wuzlzkBrrxSDV5EKBHq0+wO8xpn4dkXOWi9Ei3jqrLTNF3bEq
         l/dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SBkFCHrY;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744214596; x=1744819396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WIb2PGPlCqmD+7Qtzdv3OKAnd0eWwhm5P6P33iWSU/c=;
        b=j80ZV/SXz/PkS6AC+0BI3m4FuGRUmCls9zz1vGKpQQjraqYTBy8LTlNj8vnKIV6Rhz
         OgxuwAwXCccrrYt9MhvraA/AaxMajqoiVkBwlVUEw0O1JfJrcuBcQ4DYy3ExqP4rGxBa
         0EY8wKZE0EiacsQWMIPUee5nKU3qaV5nlcOkRbgrd0imw2YhiPbyy2Gv1anlXzIw8wwa
         q6BqLQZFw1DS0nlnHjX04yzxaIEWgK2RT6hyBbi4bbbqhF9UvC3Efqh+Gu8PAFpzEiaW
         DcJoDIMbfcxYoQRKaz9r0qDlNCeKSV+YLJsn2K3eCEq2Or9AOOKAabBJAVl8hTKHnl0H
         PVbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744214596; x=1744819396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WIb2PGPlCqmD+7Qtzdv3OKAnd0eWwhm5P6P33iWSU/c=;
        b=IF1LMv3H5l7d+EUH4YJAVOuJEoLliZW0hsYmoVyFJDfx2uE++8+3rIdRBLikg2wHFX
         ed0xv66hgdCG0l4QzLFgFg6kFtNKOdDcvK20VU3oN9KcWw1U/KjzhN818KQVknQjqeJP
         x6aTVmv4h1nQ057tKkqV4T7HQk7EqMEu4Zk+XS146qSfgjB53HrvY2HEz9zMXRhnqLWh
         KF09VqKWkLq2tpFJ0rg7vHm1qBGJztLEdsDT6Ur7P3p07I6dI3TRv8RmysUQySN4yHol
         o8rpxruoX+fMjy9l8wn7kJ6CBfyVP8F3ydB9/YtffWEfdz/hFFOlonL7JE7AusHTFcHN
         hQiw==
X-Forwarded-Encrypted: i=2; AJvYcCU8xoVanyVvlcuDQCdB7jU7+a1VmzuKrjTy8UtsEmeZmw/fxFQTeCiFvabwZK4xZY5rM4QdzA==@lfdr.de
X-Gm-Message-State: AOJu0YzCH3WeUBArerWuxFZZTSq3MaVqyjr2aLnBgdpd+9kf6spMcPRo
	d/aPfmPdcG6tJVRMsnXaUM7ldSuM7TZw5LWKweQylexFGN3B3MGu
X-Google-Smtp-Source: AGHT+IHcFLmypv9NZber+y0ZeQEcn3HONpaGSXTgRj4uiURaNBb6tBLdfg1Y8kTerBzobYQvAupLDA==
X-Received: by 2002:a17:90b:520d:b0:2fe:8c22:48b0 with SMTP id 98e67ed59e1d1-306dbbc269cmr5165500a91.15.1744214596388;
        Wed, 09 Apr 2025 09:03:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJufrvY5XnAuQ0mc2QO/SaBKfckUqz0tRIWChEXjXya0A==
Received: by 2002:a17:90a:5803:b0:301:aec9:2622 with SMTP id
 98e67ed59e1d1-306ebf93702ls32878a91.0.-pod-prod-03-us; Wed, 09 Apr 2025
 09:03:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6Qap0KcqPgsdeK+k/j2VfwgfruNZ6s7xaUHBQ4ynhGLdoij4n9pW617ldkTYBm4Isx+0iEPLScqQ=@googlegroups.com
X-Received: by 2002:a17:90b:1f8f:b0:305:2d28:c8fd with SMTP id 98e67ed59e1d1-306dbc2bf43mr5467542a91.24.1744214592501;
        Wed, 09 Apr 2025 09:03:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744214592; cv=none;
        d=google.com; s=arc-20240605;
        b=RY+yC+X5z14/YYETjglwuldW8GgHnV7OcxNZo1XCLfjyP8ou9GafeF2HwNHQDd/nhx
         GyIF/VAWZKMB2mZxnahzcTixDX0s7fHpMqfHYhOM7JDYFemhdq4Pk6eBJPmlWZbBGsYR
         o053F3Us8etTOCrAHdmSEk7eVHicvHbuNljvSRasgMLnQyIKHxFSRdalUTBdC5Dl7BQS
         +iRVZ+1rn9n6TcZUmQtXJkX4ZS2yGaHKplAuffGm+4TsQHl26ZZQHfMDoqSiSIT/Lxvk
         JBKZ6UEG5gh12lLR5Kx6us6kcXS5Y1IV27xO3G7JRrtsCq4esXm6qi8C6wAVoC1mQIqz
         Rr6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BPIM0fH+W3ImUVDAA+F06iDQbRHV+hDzR2WNKIU0A14=;
        fh=nBVmUOPuOOxjS3ByfVb3QhWjskXlUhKtNmdOcukEc0g=;
        b=S9Bjxr8kbE0ALVY/DW3qAfFG1v27Ek6o5TuNfjy2PVdJg2iIFGHjsooxkoLsvGuin0
         o3NlSSaa9h4wBotALsa/98Ls7XQgnqtRBeEJFkoENVwoLc4ICadU+HxVZ1PVpv/cGClV
         HFYBkVNAx5iLit72vCekAdTxkrYzW/QNvgT5Z3P4YR4ln6xA5qbi8DG5s6rrjnNUOQ4v
         Exm2ApG4Km+LAy7JxOXg1vIXRyj2/mVGjzP2qm+4kxTwn5TCrDFcYwqhIWDxT9fAeKPN
         cQofg9zo6x5UR4qCuwIJOuiamu1sPAmma9Sk4aVnYfQ61VCO9nTzhh2PK1zYBZtLRVHh
         fzzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SBkFCHrY;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22ac7b67ca5si567045ad.1.2025.04.09.09.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 09:03:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E1D27A42F31;
	Wed,  9 Apr 2025 15:57:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2CC1DC4CEE2;
	Wed,  9 Apr 2025 16:03:11 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] gcc-plugins: Remove SANCOV plugin
Date: Wed,  9 Apr 2025 09:02:56 -0700
Message-Id: <20250409160251.work.914-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=7959; i=kees@kernel.org; h=from:subject:message-id; bh=+ziiKcpq40KHLTKB5D7JfzLNH/xmK8EsYce/6ImmTAs=; b=owGbwMvMwCVmps19z/KJym7G02pJDOnfZumvVRVfeZjhfoe+9f43M7rkwuYeDHz90VFA4ngUW 028ddeWjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIlEWDIy/G35sXOHPA+PhRJ/ 0NcgDUkO9zfbRGfx/rd97qGkucVChuGf8rXX3R1L9I8yX4otqVqqM9k9Tm12ifAx2zdO4h8DQu7 wAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SBkFCHrY;       spf=pass
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

There are very few users of this plugin[1], and since it's features
are available in GCC 6 and later (and Clang), users can update their
compilers if they need support on newer kernels.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Link: https://lore.kernel.org/all/08393aa3-05a3-4e3f-8004-f374a3ec4b7e@app.fastmail.com/ [1]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-kbuild@vger.kernel.org
Cc: linux-hardening@vger.kernel.org
Cc: kasan-dev@googlegroups.com
---
 lib/Kconfig.debug                   |   4 +-
 scripts/Makefile.gcc-plugins        |   2 -
 scripts/Makefile.kcov               |   1 -
 scripts/gcc-plugins/Kconfig         |  10 ---
 scripts/gcc-plugins/sancov_plugin.c | 134 ----------------------------
 5 files changed, 1 insertion(+), 150 deletions(-)
 delete mode 100644 scripts/gcc-plugins/sancov_plugin.c

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 1af972a92d06..e7347419ffc5 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2135,15 +2135,13 @@ config ARCH_HAS_KCOV
 config CC_HAS_SANCOV_TRACE_PC
 	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
 
-
 config KCOV
 	bool "Code coverage for fuzzing"
 	depends on ARCH_HAS_KCOV
-	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
+	depends on CC_HAS_SANCOV_TRACE_PC
 	depends on !ARCH_WANTS_NO_INSTR || HAVE_NOINSTR_HACK || \
 		   GCC_VERSION >= 120000 || CC_IS_CLANG
 	select DEBUG_FS
-	select GCC_PLUGIN_SANCOV if !CC_HAS_SANCOV_TRACE_PC
 	select OBJTOOL if HAVE_NOINSTR_HACK
 	help
 	  KCOV exposes kernel code coverage information in a form suitable
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index e4deaf5fa571..6da109d563a5 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -52,8 +52,6 @@ KBUILD_CFLAGS += $(GCC_PLUGINS_CFLAGS)
 
 # Some plugins are enabled outside of this Makefile, but they still need to
 # be included in GCC_PLUGIN so they can get built.
-gcc-plugin-external-$(CONFIG_GCC_PLUGIN_SANCOV)			\
-	+= sancov_plugin.so
 gcc-plugin-external-$(CONFIG_GCC_PLUGIN_RANDSTRUCT)		\
 	+= randomize_layout_plugin.so
 
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b..67de7942b3e7 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,6 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0-only
 kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
-kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
 export CFLAGS_KCOV := $(kcov-flags-y)
diff --git a/scripts/gcc-plugins/Kconfig b/scripts/gcc-plugins/Kconfig
index e383cda05367..ba868d1eef3d 100644
--- a/scripts/gcc-plugins/Kconfig
+++ b/scripts/gcc-plugins/Kconfig
@@ -19,16 +19,6 @@ menuconfig GCC_PLUGINS
 
 if GCC_PLUGINS
 
-config GCC_PLUGIN_SANCOV
-	bool
-	# Plugin can be removed once the kernel only supports GCC 6+
-	depends on !CC_HAS_SANCOV_TRACE_PC
-	help
-	  This plugin inserts a __sanitizer_cov_trace_pc() call at the start of
-	  basic blocks. It supports all gcc versions with plugin support (from
-	  gcc-4.5 on). It is based on the commit "Add fuzzing coverage support"
-	  by Dmitry Vyukov <dvyukov@google.com>.
-
 config GCC_PLUGIN_LATENT_ENTROPY
 	bool "Generate some entropy during boot and runtime"
 	help
diff --git a/scripts/gcc-plugins/sancov_plugin.c b/scripts/gcc-plugins/sancov_plugin.c
deleted file mode 100644
index b76cb9c42cec..000000000000
--- a/scripts/gcc-plugins/sancov_plugin.c
+++ /dev/null
@@ -1,134 +0,0 @@
-/*
- * Copyright 2011-2016 by Emese Revfy <re.emese@gmail.com>
- * Licensed under the GPL v2, or (at your option) v3
- *
- * Homepage:
- * https://github.com/ephox-gcc-plugins/sancov
- *
- * This plugin inserts a __sanitizer_cov_trace_pc() call at the start of basic blocks.
- * It supports all gcc versions with plugin support (from gcc-4.5 on).
- * It is based on the commit "Add fuzzing coverage support" by Dmitry Vyukov <dvyukov@google.com>.
- *
- * You can read about it more here:
- *  https://gcc.gnu.org/viewcvs/gcc?limit_changes=0&view=revision&revision=231296
- *  https://lwn.net/Articles/674854/
- *  https://github.com/google/syzkaller
- *  https://lwn.net/Articles/677764/
- *
- * Usage:
- * make run
- */
-
-#include "gcc-common.h"
-
-__visible int plugin_is_GPL_compatible;
-
-tree sancov_fndecl;
-
-static struct plugin_info sancov_plugin_info = {
-	.version	= PLUGIN_VERSION,
-	.help		= "sancov plugin\n",
-};
-
-static unsigned int sancov_execute(void)
-{
-	basic_block bb;
-
-	/* Remove this line when this plugin and kcov will be in the kernel.
-	if (!strcmp(DECL_NAME_POINTER(current_function_decl), DECL_NAME_POINTER(sancov_fndecl)))
-		return 0;
-	*/
-
-	FOR_EACH_BB_FN(bb, cfun) {
-		const_gimple stmt;
-		gcall *gcall;
-		gimple_stmt_iterator gsi = gsi_after_labels(bb);
-
-		if (gsi_end_p(gsi))
-			continue;
-
-		stmt = gsi_stmt(gsi);
-		gcall = as_a_gcall(gimple_build_call(sancov_fndecl, 0));
-		gimple_set_location(gcall, gimple_location(stmt));
-		gsi_insert_before(&gsi, gcall, GSI_SAME_STMT);
-	}
-	return 0;
-}
-
-#define PASS_NAME sancov
-
-#define NO_GATE
-#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_stmts | TODO_update_ssa_no_phi | TODO_verify_flow
-
-#include "gcc-generate-gimple-pass.h"
-
-static void sancov_start_unit(void __unused *gcc_data, void __unused *user_data)
-{
-	tree leaf_attr, nothrow_attr;
-	tree BT_FN_VOID = build_function_type_list(void_type_node, NULL_TREE);
-
-	sancov_fndecl = build_fn_decl("__sanitizer_cov_trace_pc", BT_FN_VOID);
-
-	DECL_ASSEMBLER_NAME(sancov_fndecl);
-	TREE_PUBLIC(sancov_fndecl) = 1;
-	DECL_EXTERNAL(sancov_fndecl) = 1;
-	DECL_ARTIFICIAL(sancov_fndecl) = 1;
-	DECL_PRESERVE_P(sancov_fndecl) = 1;
-	DECL_UNINLINABLE(sancov_fndecl) = 1;
-	TREE_USED(sancov_fndecl) = 1;
-
-	nothrow_attr = tree_cons(get_identifier("nothrow"), NULL, NULL);
-	decl_attributes(&sancov_fndecl, nothrow_attr, 0);
-	gcc_assert(TREE_NOTHROW(sancov_fndecl));
-	leaf_attr = tree_cons(get_identifier("leaf"), NULL, NULL);
-	decl_attributes(&sancov_fndecl, leaf_attr, 0);
-}
-
-__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
-{
-	int i;
-	const char * const plugin_name = plugin_info->base_name;
-	const int argc = plugin_info->argc;
-	const struct plugin_argument * const argv = plugin_info->argv;
-	bool enable = true;
-
-	static const struct ggc_root_tab gt_ggc_r_gt_sancov[] = {
-		{
-			.base = &sancov_fndecl,
-			.nelt = 1,
-			.stride = sizeof(sancov_fndecl),
-			.cb = &gt_ggc_mx_tree_node,
-			.pchw = &gt_pch_nx_tree_node
-		},
-		LAST_GGC_ROOT_TAB
-	};
-
-	/* BBs can be split afterwards?? */
-	PASS_INFO(sancov, "asan", 0, PASS_POS_INSERT_BEFORE);
-
-	if (!plugin_default_version_check(version, &gcc_version)) {
-		error(G_("incompatible gcc/plugin versions"));
-		return 1;
-	}
-
-	for (i = 0; i < argc; ++i) {
-		if (!strcmp(argv[i].key, "no-sancov")) {
-			enable = false;
-			continue;
-		}
-		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
-	}
-
-	register_callback(plugin_name, PLUGIN_INFO, NULL, &sancov_plugin_info);
-
-	if (!enable)
-		return 0;
-
-#if BUILDING_GCC_VERSION < 6000
-	register_callback(plugin_name, PLUGIN_START_UNIT, &sancov_start_unit, NULL);
-	register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_sancov);
-	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &sancov_pass_info);
-#endif
-
-	return 0;
-}
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250409160251.work.914-kees%40kernel.org.
