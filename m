Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYON32HQMGQELVCUJKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 214164A3F0A
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 10:07:46 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id w7-20020adfbac7000000b001d6f75e4faesf4574975wrg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 01:07:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643620066; cv=pass;
        d=google.com; s=arc-20160816;
        b=Djy24HftxpZQ9YZ0BecjU9Nv99QhRRoCj2obNg6FD8GofcGMYu8HTHXZzDHllyrUi1
         9qRJhxwuIpc6gdna95neBoQpakaJF5BXJxtPSStFD2T1nJTflCwtnE5UMFgVpj+A2wLs
         6kmnl49DEJ1f79EcQz7sN0MqjEVtiz1MXEYFGv3dKWG9nNrQB0Tr7JoAv/Hi9CzwM5yL
         PsQbrR8TsLjJJEmS/yIswQPjp9NPmI5zbzK+esT/94E0237ykLHo8QKGA1TPdN2o0rc5
         REpcGSvYk8zqhoBHqgiSloYVCX3YIlduj48xfwdkD3QS+2HCU2YnaLQc69T20tAEVBPI
         Kd1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=KusZ8ajwgMPUSONk16FhEUs8HKTq6q9t670euRKH2BU=;
        b=NEpFIxDWlnPd2WfvWPLFpQzrcyfLqArzbUmEOCTLrREpK4XBt3YAFbGFwC+9SBPcq9
         GKIQlD+yi8k5qdR8E2/5LLzDeu9vpX5DxCzwJPvg7VyLXpcKVGk2PkNKF++jz7bN7yJL
         5oez+hM5xUxNKHUaC0VXDwKCgfnpn69TcAt6xv/6K7ir79MJJ5lr4jfjx7j3BXBJxUlf
         w38tITz2ESEM6ajvOg7hfbQHYvCbl8vaxBtn529uKi1qe3RZFq9QDfCYbWMtUFhB7sx+
         onXkt6Ie8QxSg4YJe5Q+vAn4lrxgzHaeqLKppDdwFTmXuH7HiRMpKJuqTjhOzxHegvCc
         K7NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sSmlJYoz;
       spf=pass (google.com: domain of 34kb3yqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Kb3YQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KusZ8ajwgMPUSONk16FhEUs8HKTq6q9t670euRKH2BU=;
        b=TGloVh0gI7pe4k3gWbhwe4KwVtAazBumRwxt09/4JvFthxerQqiPV1YEZEHatUN+Pr
         mB2SmtfFXWx6zVfdWvIuLPb+HJ5brEjZm0Dzg2/WAuM+Sf+Z3VpnlXnbM9sdlD+IuK+3
         znK7UVy+M2QTJq/HaFJeN/OkO/SZRxvnR637GdTvW+iqexjRV1jJaPCB/XColFEXq41p
         7Sh99fe8jC87yDN6Gwmp98bp86CjI+I3uCBx8xNNtG93J+3OsQka4JyS5t0I9l5w6By/
         EDkXJ+OmCGMaDU8/lzwY8/ImBgfngyaXckgVqsUm3K0kl+I7JcmlvVfIrcNy2E+lV5y/
         XruA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KusZ8ajwgMPUSONk16FhEUs8HKTq6q9t670euRKH2BU=;
        b=hMdaEgDkcoz1mbLcEIhJ9v0JcjikgtL+NvKaAOqz36iQSp0tJWCFi85jqWcA3R+UoY
         VYWZoF5dCnD1+59DPgRZdlzm1bfxCIE+4Lp9TMWBK//faOq8f+mT90NKh4shO10FZQSH
         9P7T0sRBGSERinslbrebShNyljEzs54+cGusB4RAf0lqWa6L6VnW/55rppHN3ooA+hIU
         Y9dz+h93JoWRdDf1iK8lLiFrtC/r3sTLnkO8puLZd+29s8dTVxQKvdKZ7WVyrR1HWJyw
         lvwL+cHO6m0u+kIeRHO/9nANTkUlD1EYqi6wNR8snA/1SyTS6LdXg0fkEV1bQC48w2Km
         8DOA==
X-Gm-Message-State: AOAM531hC1H4aBR7eVKGY8EDud6S/nIBVpXJNa1L758SdezA3/8pvhlV
	19Ruv6o2q6lni8a6F79e0ao=
X-Google-Smtp-Source: ABdhPJwH39DhuUzSEzxsq/IpQkO+tIAXcfQ7Ykuuz9xvl2Le+YbHlIsUrgxIhC3R2dq9vM4C5M2KVA==
X-Received: by 2002:a05:6000:1707:: with SMTP id n7mr16456101wrc.662.1643620065843;
        Mon, 31 Jan 2022 01:07:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2787:: with SMTP id n129ls7615959wmn.2.gmail; Mon, 31
 Jan 2022 01:07:45 -0800 (PST)
X-Received: by 2002:adf:aade:: with SMTP id i30mr16504701wrc.629.1643620064960;
        Mon, 31 Jan 2022 01:07:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643620064; cv=none;
        d=google.com; s=arc-20160816;
        b=pwYP3Bjv4lJ8SIyIStyOKegcp5LfLZMJwjrrqNrNfTUBFWqISnoENGVJB8c9uWwwqz
         CBbHLtKUQnQNHenFxrrcB4Wsy3yEmP82PLw9I3gTAzBIAisHt52d7VmEGQ34BiQmjkqW
         v5Xlgsy/SEaBXaj6cPR9Rc6d0ICvC7hxqEwbu5yrz9bTA7rtDSh3ZS9WmbNv0zsC77iE
         AzcHCR/4thvVOkXMCUh4LQFdTDovOCi0rL0wyDXEVQ9BtEGpjNVB5/XD/b7rEP4AiZxa
         FPn0uWZgMZR+ngsdJXLcT9NpBySWS7gpeaxVJ36zPnEAuqJdRIxs6u7BX8bQhfQ07zY2
         nANg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Bko2bBOFt8SFav6I5TjYOIulrzQuEbXeq+2gLbCWAVI=;
        b=O2fkW01PK6lMGdt0XVxS+UZ4XPuWowNjt6GtPGof5lv0Hq9TMstgKMevx87dG4XFPW
         gotFENXGQQL/sadrK2j+a5/I1pdCH3L8GPWyHtMCFp8f/t3cERVihJsWlcjw6nj+8qbC
         3nECGMm8PcdNRNFnNMAb0vG6fWgfSTfZyg9AR28nc/1WSrwxTv2z/YI6nJC7VdbQai/4
         hXT1rBIiGJ1HtDlNRSSaIr1BHtSGumMbg2t/0V9Ha8y0N7cmN1408IP4ZvqSuGy42bud
         KarwjJXb+DZaLYXhORQygREGp6DlW1QPyxc3vEv3yG6NOuYYBxGxQD2JSnFSdlB5At6l
         1kog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sSmlJYoz;
       spf=pass (google.com: domain of 34kb3yqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Kb3YQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id x2si429969wmk.2.2022.01.31.01.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 01:07:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 34kb3yqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id n7-20020a1c7207000000b0034ec3d8ce0aso5560982wmc.8
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 01:07:44 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9caa:cc34:599f:ecd4])
 (user=elver job=sendgmr) by 2002:a05:600c:2741:: with SMTP id
 1mr17797025wmw.50.1643620064562; Mon, 31 Jan 2022 01:07:44 -0800 (PST)
Date: Mon, 31 Jan 2022 10:05:21 +0100
In-Reply-To: <20220131090521.1947110-1-elver@google.com>
Message-Id: <20220131090521.1947110-2-elver@google.com>
Mime-Version: 1.0
References: <20220131090521.1947110-1-elver@google.com>
X-Mailer: git-send-email 2.35.0.rc2.247.g8bbb082509-goog
Subject: [PATCH v2 2/2] stack: Constrain and fix stack offset randomization
 with Clang builds
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Elena Reshetova <elena.reshetova@intel.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sSmlJYoz;       spf=pass
 (google.com: domain of 34kb3yqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Kb3YQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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
Reviewed-by: Nathan Chancellor <nathan@kernel.org>
---
v2:
* Update comment to point out which compilers initialize allocas.
---
 arch/Kconfig                     |  1 +
 include/linux/randomize_kstack.h | 16 ++++++++++++++--
 2 files changed, 15 insertions(+), 2 deletions(-)

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
index 91f1b990a3c3..1468caf001c0 100644
--- a/include/linux/randomize_kstack.h
+++ b/include/linux/randomize_kstack.h
@@ -17,8 +17,20 @@ DECLARE_PER_CPU(u32, kstack_offset);
  * alignment. Also, since this use is being explicitly masked to a max of
  * 10 bits, stack-clash style attacks are unlikely. For more details see
  * "VLAs" in Documentation/process/deprecated.rst
+ *
+ * The normal __builtin_alloca() is initialized with INIT_STACK_ALL (currently
+ * only with Clang and not GCC). Initializing the unused area on each syscall
+ * entry is expensive, and generating an implicit call to memset() may also be
+ * problematic (such as in noinstr functions). Therefore, if the compiler
+ * supports it (which it should if it initializes allocas), always use the
+ * "uninitialized" variant of the builtin.
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
@@ -37,7 +49,7 @@ void *__builtin_alloca(size_t size);
 	if (static_branch_maybe(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,	\
 				&randomize_kstack_offset)) {		\
 		u32 offset = raw_cpu_read(kstack_offset);		\
-		u8 *ptr = __builtin_alloca(KSTACK_OFFSET_MAX(offset));	\
+		u8 *ptr = __kstack_alloca(KSTACK_OFFSET_MAX(offset));	\
 		/* Keep allocation even after "ptr" loses scope. */	\
 		asm volatile("" :: "r"(ptr) : "memory");		\
 	}								\
-- 
2.35.0.rc2.247.g8bbb082509-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220131090521.1947110-2-elver%40google.com.
