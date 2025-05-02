Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5N2TAAMGQE5NBDFLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id B8F3AAA79C4
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 21:01:36 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-47693206d3bsf60148321cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 12:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746212495; cv=pass;
        d=google.com; s=arc-20240605;
        b=VFEhb8Csz1RfGRuJTSbPOJllaAyZ7fAiw1ka3kE1RoV8QYMxkvfU/x3yBuPywTHF3T
         jXSmBPM8ltXqY894zxGe+A5L4VFibgqDJxCHDoGYvw/OQWtQYkt6iC2+8iWEOKqLtA1E
         sWhKoucmDWDnfHrKRq/6yTXSQHQ8p3Gh/cK8OUHS6rDHrnFan+pgNNXRMV9lkygpvaDn
         ldV24Eg8FC38O3HFdTK+RWzfYUtS3RlAapAycNSrSX+4iXx2K3Q7pfGDulxkJJ3ANwry
         HBWbQPXitNBCtM1XFX/goEjgkaiec0evnEMnRgh0e1V5uR5EvmJXQK5X/d5GKdrIZNUo
         NUaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qpY92BlbT07ru2/CBXTVKHeY8qCFqD5GIC5DLhGx/ls=;
        fh=RJyTqlYKVt4D/uCu17eBvDLcsIySkQ7m8RS2vS5SNJ8=;
        b=TyAkuqjoeWkDBRsOKo3bkhnhZxNTrwZmVt7Zuh1ijtoccoh03mVdq3TUXjBcovS5gY
         5TUb2AywIOKRizYRxmDmZzwmwXi+LXaj3xjnv7R7qTlgKR6fJF+/hE4f/lo7zAn1m7vY
         Sw7ROQTMUH7gGV/5usUvqG66xBeGQZ/wGPRuZKZirbMo3srGJJy9rWfcoGbE7NDACVM+
         ED6kKjAjUYhE2HGeSSdMrKJmTfZ8gf7S4nEnEHvh684A53vi6fI9+UM25SPuo1csB9VP
         btenW5SIpCLlB9kA4qLs/VTt9f/2/QenDvrVXsQD2H2GhV5eIlUg51HsEAXCuMzGQfIF
         rSnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qpAiqDc3;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746212495; x=1746817295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qpY92BlbT07ru2/CBXTVKHeY8qCFqD5GIC5DLhGx/ls=;
        b=l4M6csA17qvEE/khoKD6Th0q5u6zpanexzTVjNSQCxV/zhpQiaRDRuSRuAL+ZB3fRA
         1q64ez6GV2njsR4+1t1Lfr1ssWE+5yaYkfOsb5lU6SyXvdRQmt1NLOAHgMb38BDbCA1W
         tvKEPGTJzIRcErHq7mq13M9+oZCM8U9tZ0RLHKTBTqHa28UIMdXm4k0ujDy+4WuLdv0l
         tT8Bam4hWyvG184FhVs1m7j9UAvVq1/D1BNVvWfc3GfZCmYnjh33mNTa493bpCxc0lnu
         Ibj2txPic6vxJ20xJJm3Xm2fg+Yl3h3cnamDFjpQ9YSUeFiTrVeGur5eOFT9JrAgHo1V
         sk3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746212495; x=1746817295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qpY92BlbT07ru2/CBXTVKHeY8qCFqD5GIC5DLhGx/ls=;
        b=Q7tif+apiXJ5Jxla7TE7MhZDqI3g9p+UUTRZnbTRk+FIVglRGiL/mjHIbLFFL+mpVE
         +Y8fL+ZWfmrcJUhtnXszEIF8IXRiB1y0/APDm6CCwPLd8o6PrQ7QWIZpvsMhXbkJx5Zb
         0aJWMp50n6sHhyiq2e8QYjzW+XMq62uE5hMSR+XlfW5RaqIiqqlzLk3JK06c8B1Xy82J
         fn8DHeGbqBQVx5TVDn43PapYw7l2roQgHHpcUvB/jx4AkgjV5Cl2wlSOnaswqxlUdUV2
         5nNdyppY67U4YdxEbrbjs6aLBq2sKvkArcJlcaDAq8HjHsmK6AwctL+E1/J6mKUdD5Nl
         CnpQ==
X-Forwarded-Encrypted: i=2; AJvYcCUQ35TJ51O+TnEk8GefWPparzpSyMux43wWgFUE9fQITr6axRmd3Szn/PQwBWLhZYsubwNonw==@lfdr.de
X-Gm-Message-State: AOJu0YxZPU4P2ZNZvRPfkujF2CU0ocpnJCtOdVnISRp4sVO/0lCIQoVJ
	yisVgYjJyzVBeQKWprDLjI16FHKr2Zk/5g43uUaKZGcbSI+/TsqQ
X-Google-Smtp-Source: AGHT+IHmr0/cQeeKnf0FAOvGzC3IzSepIEq2gyrsIN4a7JMzpihAc6idksbGenBBL0hvyB+qAVi2RA==
X-Received: by 2002:a05:622a:1f0b:b0:47a:e616:cab2 with SMTP id d75a77b69052e-48c314507ffmr60932611cf.15.1746212495546;
        Fri, 02 May 2025 12:01:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHwZkd3DMcE4B5ECD2OacovcxL2W+iptilP/VKDLWorjg==
Received: by 2002:a05:622a:4787:b0:47e:c50e:95f6 with SMTP id
 d75a77b69052e-48ad89a123fls30575961cf.1.-pod-prod-06-us; Fri, 02 May 2025
 12:01:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7ZfQocCJExx9yhjP4NeR5ynC+ZPAWG7QEJ+jYZbTWFtufvJUyAohZOPJmywLHJg4seX99H5ikGdM=@googlegroups.com
X-Received: by 2002:ac8:6f0b:0:b0:476:a6bc:a94d with SMTP id d75a77b69052e-48c31452caamr62880461cf.19.1746212493889;
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746212493; cv=none;
        d=google.com; s=arc-20240605;
        b=Ib/4a9zabJCNRQSiSfz2vB1DzWaoRHFut4nbYpGIDSI8YZxOYrFFxuwKXWNnbZg2hG
         N7DpCcJ3QEJqugSEGDo/cHWLN34QXt2AoLtxm7Gg67FB95Lpq3gjOU+aCEO2Gj+s7DMc
         8wHaV3N521ZTZK3Cjg7V+E8I9JyqWbBQFGEaEOFLzG0SWbHGL1v7l57nTk//xFj4VGrl
         gN4YOb/D/g0DDa1FDmbdIaXKquYFpgtM6KCGWHP4zIttNZh8GU1HjTpA+UNYYv7LtGo5
         ncSDIVkYEb6cOTPZoyMA/Zwn+yB+StS6FOqEltLvCjRHX9fiMFhNveXljTVOugG06xda
         CpsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0EDjcIqIyveZhqI1sOovxaboQkvKntt48sOQGMe7Ybw=;
        fh=ZbmHbp73JUM0UFM9HFZXF54WG/+vvJSZ251UBkwHoB8=;
        b=Sbn4/hCgtTSl1kYfC2EMI50J/uHt2rcZqBcRMwtco4W3jHL1O10yBzVoakxPaPZv0z
         8r57HO06D3sZYwvUUqF8T0Sn3MV64Ugeb0jspfPWnrEQdfxy304abhVgBRj/ittXa3lP
         XFVDhr+u/Xlaz+L3KdvgS3jkAtYKL3R8Yhk0croVaAJMKIX9+WDC5Ik2TN1K1FTXoYb6
         TgEHUVuRck8+sAOi07Fl7BOvDiTblMijVyylrPK2UPiRgPEMGueh25WMCiMUWb9bTGGs
         DGmt7XI/OfT9L5HIU0F+vgaElTDZ7mdmw1SyWx9Rxt5GO/oR84owmB+lunCXPus0r82Y
         8hBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qpAiqDc3;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-48b960cd884si196161cf.1.2025.05.02.12.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id A71556844D;
	Fri,  2 May 2025 19:01:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D2C9C4CEEF;
	Fri,  2 May 2025 19:01:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
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
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH RFC 2/4] stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
Date: Fri,  2 May 2025 12:01:25 -0700
Message-Id: <20250502190129.246328-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502185834.work.560-kees@kernel.org>
References: <20250502185834.work.560-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=11391; i=kees@kernel.org; h=from:subject; bh=7I88xKKl+S/SbyjDaiSTE40W0kyqkp1EQfua5U78PZ8=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmiYm3LV8zvdj55z/bzfna/NTLWi0wylt38Istd8Ccjx WujAoNIRykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwESKGxgZWl8H6zjqMR5u7rnb /EicLWWtTtqCp97Nm2tT7NnPfpsXwcjwv71pxusd83ilnU+cCroW4lY/3dfWScUoxH/xd3dX9Tv 8AA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qpAiqDc3;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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
the GCC plugin function to match.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <linux-hardening@vger.kernel.org>
---
 include/linux/stackleak.h              |  2 +-
 kernel/stackleak.c                     |  4 +-
 scripts/gcc-plugins/stackleak_plugin.c | 52 +++++++++++++-------------
 security/Kconfig.hardening             |  4 +-
 tools/objtool/check.c                  |  2 +-
 5 files changed, 32 insertions(+), 32 deletions(-)

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
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 8aa5c1d4794d..edcc489a6805 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502190129.246328-2-kees%40kernel.org.
