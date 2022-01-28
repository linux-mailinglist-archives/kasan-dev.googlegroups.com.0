Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VOZ6HQMGQEHZMDC6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3123D49F89C
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:45:55 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id o4-20020a170906768400b006a981625756sf2809785ejm.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:45:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370355; cv=pass;
        d=google.com; s=arc-20160816;
        b=JDpLqnFFiPAFPws0bmYLcOGh5v+sMrvli5D4whJlplqRu+jiaGV6+Adq4rOr0Xv75D
         2H3tpUXVFglehgvzYnBlTKaXxNt2fb8Ty1jk3mwfPDzwn8xH6GJ1IrKulIkWQTfEqHyt
         GpT43YZ7GdJDr+5V4WD+8jdpbr+w4LCEj5TEHnWnXFGrJ918oN2RvMuvrG3k1qn62Awk
         IRcy9nlYkbh1B5vRc+0RvGApauGcmCA+ObgK9P2fw3k6glXvOdKzEovfXuqM2mpI4sHX
         Ms+R/SaDPOTyd8kaWAeIGTow4ipLR5Qj+2pI33R6hNiTSifE1OgQobCv+uOjmJoPCgpd
         SWWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=BZ4TMSjmldf35+qQwcq6xOLkcS6/IxoADs+76XTVdpA=;
        b=VW6WWsU26vD5VccakU4o/+FwTfzeExxY9WDJWEAKFvgdQZMCrm5h2VWti8//0Kh/tw
         g4x2HjfMBuR7PfYNlgL6Hch2nXoYL/qW1CyoHGUjPLkUb/kHnDPR40NKSRIijmQNx7qM
         GAkwa+hG+EHIEtIuULbMARKoGQsaCeLuNkakFAbhi5jeTjDrRofRle5iiWZXzL4+7/A5
         fZ0Abz/iiis2koqlFvz0PTNrj2NwRgiSL4yd0mm26q9NQAOEsYtFBkRD+xVl3XWdAQ2f
         6Oywm4gOHnR+N7CcbS9WjaYb7xZtaA27fDXWghXinlO/meesiKA+DHtG7GxZlyo+/xyX
         FZGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fEJYvnHu;
       spf=pass (google.com: domain of 3cdfzyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cdfzYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZ4TMSjmldf35+qQwcq6xOLkcS6/IxoADs+76XTVdpA=;
        b=FF5m3fJPe62FW2cmYF82YCP1J30TbiAApvNMHqD+NCNrv12U2cQaSC+2RQnKe8cSIb
         VApCeMclgmK5q0EosEzrdy7tgQi7br/32pnVox9HTPF38/MtjCqlfYWYK3/nyiPW+vt0
         cLShL2rq04xCGCpa0JTB2pg7h60nFTC5LxlwG1q+NLtKNaHfJgO7lpJrAVAlCuayH5Bf
         92dB3qb4wkTBuXNgY8RIeuJs4jXL02fT1m1ofaNiiXUrCZjD4BtrtV/JWNwWbnq5wEEk
         6i7K60SuKGDIBFE/w6jAbKEJsRPunmR+prAzvbsHf3EXb3KnHyVM5tb5a3GTaM/k+AKt
         nYsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZ4TMSjmldf35+qQwcq6xOLkcS6/IxoADs+76XTVdpA=;
        b=WenYC/l6qHw+NgTPRrkssu4Q2FkfUp5sA2A13wQYCvoF9o0354uPjEH9c/Zhuw9ODj
         30CAjD4mjhs/nmLc8t6qm53zLfLDuIqyEE91i2Dlf4lTYCEZb377S+FLXj5L42oLJBN2
         cK2MDbIi9LBCbQOup/nW3zOgnwp2TXOUvaNysrc6PMfgnoAzIYyVtuxI3GSD1K/AtNFz
         LMl5zNomXgWzeerQoPl6oakWUXoMyyg+rd1p1aTf9g/u1+nm2kjigPT3GoTL/R3P+2uf
         ThnjsUqzK5gPyaS3UB5Kgvyw0fNV5NTukqyjvo3b/GdoSWCx3WGNrLhPaPIoeNA4OUIX
         4lGQ==
X-Gm-Message-State: AOAM533fw8M+NFbj8WJpMwjoYPfABVauMe8PWqGiVEHbTcg7/Y8wtQC0
	W5fPOEpF2CxfALkBdRotxZ0=
X-Google-Smtp-Source: ABdhPJwjF8COaW+u9Gu9bedGz9CtsCJK8xxvFNqfpoHGAwgOKRQJyqkfVCyFbt9hYZrEmPxz3bt2QQ==
X-Received: by 2002:a50:d70e:: with SMTP id t14mr7755707edi.19.1643370354761;
        Fri, 28 Jan 2022 03:45:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2742:: with SMTP id z2ls7236820edd.2.gmail; Fri, 28
 Jan 2022 03:45:53 -0800 (PST)
X-Received: by 2002:a05:6402:448c:: with SMTP id er12mr7798751edb.137.1643370353644;
        Fri, 28 Jan 2022 03:45:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370353; cv=none;
        d=google.com; s=arc-20160816;
        b=ZZ3jOHZTjzA5Y/3Jr8BzXYRxcmEBg1HrniqdW+6xnJ+07fzlKqB/z/mHuThg+Acu4X
         rJHUYs80NIHgtinTiQBxk45lfZg1sQ/PElTo2V/XHuw9KgfTzdC5CzBc20WrPGupxAPc
         XyjNdJUwQaeQ4u6Eo5x/X6ULhxfus+2T5EjJUaGdyyM16pcM8FQlb8qxa6f4KtfCijYW
         2vGmkpKefAPp767Y59pp5H3yhzOogo1yiP+d/4PmtHrdioYYCQhQp67He4H/kogiSaom
         wS45gyw3oz1iUv3QZvzM+bBdhlHQ06qWT5wiWOOaxCoZ+B7DsOEB76+gqUD66F6OaT5w
         er5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=wFWaeqF62cKOElQQL7pp3r58nzR0TbsroVad70HicBs=;
        b=SnBHQMvwO/2OltiphEw2kZPWDRObvM5buWMnUEVlCs4/b4pswwQJAOqJdIW4f5F18f
         OWK5qcd2gXI4OXZtZ1a7x0qWjkubXmSNCXcEB2081GJgc6LwIGq/kmJTXHPyxcq/OK3d
         PkQG3iv0ZxUAy7ETNUdOW+AslfEiMWy6NIUegUZud7IyufQlSxpqgi8xa60jc1cS9Fg8
         Q5esxcU7lqR1D1Kr1TCpvl2tzUVnYcEdxBcDBjvGyWmzNgIOqlEmiwox/avZ8JCtCZlL
         I0ylREZg/NeWw05usiyRRZFiSyqQ2gt+Msx2l3dp6nB08r8HsCYjgUFebzNkxpbNUZRO
         +ijw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fEJYvnHu;
       spf=pass (google.com: domain of 3cdfzyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cdfzYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id s15si218184eji.1.2022.01.28.03.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 03:45:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cdfzyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id f188-20020a1c1fc5000000b0034d79edde84so1381968wmf.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 03:45:53 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f088:5245:7f91:d730])
 (user=elver job=sendgmr) by 2002:a05:600c:4e0d:: with SMTP id
 b13mr7191313wmq.188.1643370353320; Fri, 28 Jan 2022 03:45:53 -0800 (PST)
Date: Fri, 28 Jan 2022 12:44:46 +0100
In-Reply-To: <20220128114446.740575-1-elver@google.com>
Message-Id: <20220128114446.740575-2-elver@google.com>
Mime-Version: 1.0
References: <20220128114446.740575-1-elver@google.com>
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
Subject: [PATCH 2/2] stack: Constrain stack offset randomization with Clang builds
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fEJYvnHu;       spf=pass
 (google.com: domain of 3cdfzyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cdfzYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

All supported versions of Clang perform auto-init of __builtin_alloca()
when stack auto-init is on (CONFIG_INIT_STACK_ALL_{ZERO,PATTERN}).

add_random_kstack_offset() uses __builtin_alloca() to add a stack
offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
enabled, add_random_kstack_offset() will auto-init that unused portion
of the stack used to add an offset.

There are several problems with this:

	1. These offsets can be as large as 1023 bytes. Performing
	   memset() on them isn't exactly cheap, and this is done on
	   every syscall entry.

	2. Architectures adding add_random_kstack_offset() to syscall
	   entry implemented in C require them to be 'noinstr' (e.g. see
	   x86 and s390). The potential problem here is that a call to
	   memset may occur, which is not noinstr.

A x86_64 defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:

 | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section

Clang 14 (unreleased) will introduce a way to skip alloca initialization
via __builtin_alloca_uninitialized() (https://reviews.llvm.org/D115440).

Constrain RANDOMIZE_KSTACK_OFFSET to only be enabled if no stack
auto-init is enabled, the compiler is GCC, or Clang is version 14+. Use
__builtin_alloca_uninitialized() if the compiler provides it, as is done
by Clang 14.

Link: https://lkml.kernel.org/r/YbHTKUjEejZCLyhX@elver.google.com
Fixes: 39218ff4c625 ("stack: Optionally randomize kernel stack offset each syscall")
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/Kconfig                     |  1 +
 include/linux/randomize_kstack.h | 14 ++++++++++++--
 2 files changed, 13 insertions(+), 2 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 2cde48d9b77c..c5b50bfe31c1 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -1163,6 +1163,7 @@ config RANDOMIZE_KSTACK_OFFSET
 	bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
 	default y
 	depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
+	depends on INIT_STACK_NONE || !CC_IS_CLANG || CLANG_VERSION >= 140000
 	help
 	  The kernel stack offset can be randomized (after pt_regs) by
 	  roughly 5 bits of entropy, frustrating memory corruption
diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
index 91f1b990a3c3..5c711d73ed10 100644
--- a/include/linux/randomize_kstack.h
+++ b/include/linux/randomize_kstack.h
@@ -17,8 +17,18 @@ DECLARE_PER_CPU(u32, kstack_offset);
  * alignment. Also, since this use is being explicitly masked to a max of
  * 10 bits, stack-clash style attacks are unlikely. For more details see
  * "VLAs" in Documentation/process/deprecated.rst
+ *
+ * The normal alloca() can be initialized with INIT_STACK_ALL. Initializing the
+ * unused area on each syscall entry is expensive, and generating an implicit
+ * call to memset() may also be problematic (such as in noinstr functions).
+ * Therefore, if the compiler provides it, use the "uninitialized" variant.
  */
-void *__builtin_alloca(size_t size);
+#if __has_builtin(__builtin_alloca_uninitialized)
+#define __kstack_alloca __builtin_alloca_uninitialized
+#else
+#define __kstack_alloca __builtin_alloca
+#endif
+
 /*
  * Use, at most, 10 bits of entropy. We explicitly cap this to keep the
  * "VLA" from being unbounded (see above). 10 bits leaves enough room for
@@ -37,7 +47,7 @@ void *__builtin_alloca(size_t size);
 	if (static_branch_maybe(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,	\
 				&randomize_kstack_offset)) {		\
 		u32 offset = raw_cpu_read(kstack_offset);		\
-		u8 *ptr = __builtin_alloca(KSTACK_OFFSET_MAX(offset));	\
+		u8 *ptr = __kstack_alloca(KSTACK_OFFSET_MAX(offset));	\
 		/* Keep allocation even after "ptr" loses scope. */	\
 		asm volatile("" :: "r"(ptr) : "memory");		\
 	}								\
-- 
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220128114446.740575-2-elver%40google.com.
