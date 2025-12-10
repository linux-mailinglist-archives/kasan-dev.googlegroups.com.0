Return-Path: <kasan-dev+bncBAABBJO443EQMGQE2UB2QLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D1BCB3A18
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:30:14 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-64174630bf9sf91342a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:30:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387814; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fep5QiO0DCOtVaxhkO7B8a84S6SOLXr7rN5RdseOctWyKH7k1rr8BuUJjqKUWnTfqo
         ZJ9HN9P6+k7/HZ1XeojuwmU2E80cj3835yVaFUH/LQJV7iOqcM79RG68VwGOz4jIZcuw
         QkZdkg7uUgOBGrGIIMF4zgW+YoiRpxvwGDvJ4rNSWj/ElhpiAEe4hJGK0TKKl18BdBTD
         rj+IFU+c6Hy15P2CNPvcJTbGK1KIr45yJqvDsu1E7PdxGwp8tZOlpGY+D9pHNzGkte3+
         vP+60z9JaQKdgBboAtrAY1lmQYlsOpyOBJKBnxfsmB3uJDCoFi0vSY42BwhREsMM3PZy
         dNNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=/brJOSSBbbpP3LDUxRIK+5IYStuBDynuEK9a8oxyPTo=;
        fh=jh6+B81526EBk6L/nmYVSdfcjYOV0zLtFrhkUxfZOCw=;
        b=Pa4ZG7FJbGaJ+gaafgI8EQV+hWkfCWdCqV3ync16PI7YEhllj907X9L8QlI0QgSf/U
         LrduClkRgVybG9ioOO4wCjuo7r2VTZEec2lYHpD7Cg9Kkhn4M1Hc8YN/L8+LzbszItwB
         rYchvng5mlS1m3/EvD7+TBD8Wh88jCZifcxYQTQ+ES1fX3ya4LwMgpbNc76lcsdcwWXQ
         SnCPO0UrcAkauKkYP/JELUGMZMb1JcRznMqF+Tw39MPuH8wdjzjfGiBBdmsH4TmsFAfH
         kBbPr3nB6sThBRbbFof5jtkgSqhAwtLGibYATAxZPc68pOkCTrKC1vT5bFX5fxXCb4dl
         AdeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bff9AUQ6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387814; x=1765992614; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=/brJOSSBbbpP3LDUxRIK+5IYStuBDynuEK9a8oxyPTo=;
        b=ZRwmbAUifaY7/MsU1/121lXGyM806gBn8pyxfU3tcMAcxAiZE3jiTaExPJ/NlykhoY
         ZlNMWDsjofscy/STw9jRevko4Dn+jLxtu2Orc3I5kb7b0rhzPqPUBixgSJoyOfygUZxW
         oL6g4MgrXUs34OsG4X9yLTxz8ThBJxe7K8SXlfBnk15savB7udNrRr1A+VE0+OuDNWC9
         lK/cFUsq3U4GoLMlBlUCkQKUItX4CTjNgc6rQQaQ3RrEifcnVTlBQRH5nJjF5vXViFwK
         K6L2hl+nZSgQ1jdVyvA6kiNyUB8g9dUJgKL5lbCENZqmsCCdEEXAKL/e2ZtgSb9DRvzq
         A+Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387814; x=1765992614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/brJOSSBbbpP3LDUxRIK+5IYStuBDynuEK9a8oxyPTo=;
        b=aC1zYUfDVt/CFdrqSHJ0q7bJp+5cq33MG0cSI+SMMNRUil6X9UaJF+fGyBnVAlJOyK
         1+iW6dPfjRN7gl2wdSitN049IRaYsU8FWn7VVCPo9fcVmefNXJIzBXgnrsi+jn4V9xcd
         C4FoWzn9ZDEWLuS7npVGS2eBJO90XVFPjHYVMbPY/pdvxhjtVQmh8zSOyUU9cRUTtXMv
         /CzSSrixX8UHIHu23AsD1toGKgYj7xK2rOf8UAUDPiIOD7Zu41YBovzuXLMyXxIi9Uk3
         WrDAns65enCjIyYPbOXtCeHz8ZmLeZnUbYKVCBoTtbEN9wpTDKR1JfFQR8o1Ep/1tmgZ
         85EA==
X-Forwarded-Encrypted: i=2; AJvYcCX7jilacjk80/vN8KgZMZttWieKx1cXjRhPOwEZ7Ba0LyKw3uIEAIC97xtDvDE4qQMpFpjezA==@lfdr.de
X-Gm-Message-State: AOJu0YzVBc9zScavPGCVwCAiP0D++RVy4iDIDhjrf0ndp1JgJLcgvI1Z
	DTC+lEHq4nqOY0+AeVsR46fWtKWAGF5bPRdeO62Hj0yKEZtwfCJnvQk7
X-Google-Smtp-Source: AGHT+IFf9mdPCz5zvvmrFcbjx36gSqvjIJrCVgP2k39SVhHDDsKKCOrg+9ohc6wIQBwoU/cJfe2SDg==
X-Received: by 2002:a05:6402:3487:b0:640:f974:7629 with SMTP id 4fb4d7f45d1cf-6496cb5cae9mr3151159a12.15.1765387813874;
        Wed, 10 Dec 2025 09:30:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbqa8vFogYTOCsePkUNkvPmIuu/0A4PaE6yMDREMBc5hA=="
Received: by 2002:aa7:d5c1:0:b0:649:784c:cac1 with SMTP id 4fb4d7f45d1cf-649784ccb9bls845369a12.2.-pod-prod-09-eu;
 Wed, 10 Dec 2025 09:30:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLUhL0NEjWXB1UmAbfvubQL6eCcoqVB+8UQaBmXq7KerKQVdPMiIjM9kaDG89drVvYxZo9x61Czkc=@googlegroups.com
X-Received: by 2002:a05:6402:1cc1:b0:649:6a2e:9bc7 with SMTP id 4fb4d7f45d1cf-6496cb53039mr3042009a12.13.1765387811769;
        Wed, 10 Dec 2025 09:30:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387811; cv=none;
        d=google.com; s=arc-20240605;
        b=du3Mb1VhE6kNtymlO9sKfYhQn/yM3C6ETLOrYu3OBEQIRlW79SOlulkYP8/cyP82mp
         kl9BwcvlDiX8X/re1qcbIT9H/LkzBBaWtbls/+54aDH+LRS36n6w2JIqrdrOCh9tA8je
         hzbQtBF09/brFbfqS4rNTxfwh4nQGZZ/FoRMw7Ifru9IBYEX00OpqDGKB7NoDidcA3Bo
         rHOOj0TfVdENbK7l2YuSu0ijib+sgnZjKjLspcVvrBDmzoMxTLX+LBCql22Oks91zjaD
         jecj6AUV0NS9fvutzKyTu0isic8JK0fZx5Jdap3LZFDMBW2OgZvtvqgLHz+qAzMDgpQa
         5Cpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=lY9fE4khm8TKePDz5X4aC5hOywz6v3YeXyq28VGtz8g=;
        fh=oKYIkYo4ILSbTSXy6E+VFCgZLN6WGwkYTTWWqUb7Dew=;
        b=Soz39zdcK2kxHwSm4uxPjmIzFhGbSbA2WjA2xdHMphPNJgMMpD6MfNXsZT2P4lnCAS
         pg0souKcD3hFeNvOCp8QggeuF/LxZxh+3HhPhzz5jqXkraPSDTBRbpafNIGTOImqb1jl
         YvLCmIgD+UK4BesajjMuWvBHMgypXuEnrtlnS0mZdxLhEB+4zDMhyovABFyag/4S7C2c
         Yi5vX0UzvJNAvRLKd3PrjzYx0Lwr6SMx2uSG/26+pZOUyHzLCYF1qUcfKnoswgKr5DeV
         kX4tz4a6hI4j86kDLWcDNEUgeqk/UJ4Z/8pZJ42mrJcFL3Tz+3MqupzabWd2FU/UvCgD
         8XzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bff9AUQ6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64982042339si2213a12.2.2025.12.10.09.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:30:11 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Wed, 10 Dec 2025 17:30:05 +0000
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev
Subject: [PATCH v7 12/15] x86/kasan: Handle UD1 for inline KASAN reports
Message-ID: <13fa5da13adf927abbb7dd85d19fbaa8e4fadc84.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 7032ee222089e9740a5e84130b4a9493439885f2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=bff9AUQ6;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Inline KASAN on x86 should do tag mismatch reports by passing the
metadata through the UD1 instruction and the faulty address through RDI,
a scheme that's already used by UBSan and is easy to extend.

The current LLVM way of passing KASAN software tag mode metadata is done
using the INT3 instruction. However that should be changed because it
doesn't align to how the kernel already handles UD1 for similar use
cases. Since inline software tag-based KASAN doesn't work on x86 due to
missing compiler support it can be fixed and the INT3 can be changed to
UD1 at the same time.

Add a kasan component to the #UD decoding and handling functions.

Make part of that hook - which decides whether to die or recover from a
tag mismatch - arch independent to avoid duplicating a long comment on
both x86 and arm64 architectures.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v7:
- Redo the #UD handling that's based on Peter Zijlstra WARN() patches.
- Rename kasan_inline.c -> kasan_sw_tags.c (Alexander)

Changelog v6:
- Change the whole patch from using INT3 to UD1.

Changelog v5:
- Add die to argument list of kasan_inline_recover() in
  arch/arm64/kernel/traps.c.

Changelog v4:
- Make kasan_handler() a stub in a header file. Remove #ifdef from
  traps.c.
- Consolidate the "recover" comment into one place.
- Make small changes to the patch message.

 MAINTAINERS                  |  2 +-
 arch/x86/include/asm/bug.h   |  1 +
 arch/x86/include/asm/kasan.h | 20 ++++++++++++++++++++
 arch/x86/kernel/traps.c      | 13 ++++++++++++-
 arch/x86/mm/Makefile         |  2 ++
 arch/x86/mm/kasan_sw_tags.c  | 19 +++++++++++++++++++
 include/linux/kasan.h        | 23 +++++++++++++++++++++++
 7 files changed, 78 insertions(+), 2 deletions(-)
 create mode 100644 arch/x86/mm/kasan_sw_tags.c

diff --git a/MAINTAINERS b/MAINTAINERS
index a591598cc4b5..ff1c036ae39f 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13421,7 +13421,7 @@ S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
 F:	arch/*/include/asm/*kasan*.h
-F:	arch/*/mm/kasan_init*
+F:	arch/*/mm/kasan_*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
index 83b0fb38732d..eb733ac14598 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -32,6 +32,7 @@
 #define BUG_UD1			0xfffd
 #define BUG_UD1_UBSAN		0xfffc
 #define BUG_UD1_WARN		0xfffb
+#define BUG_UD1_KASAN		0xfffa
 #define BUG_UDB			0xffd6
 #define BUG_LOCK		0xfff0
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index eab12527ed7f..6e083d45770d 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,6 +6,24 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+/*
+ * LLVM ABI for reporting tag mismatches in inline KASAN mode.
+ * On x86 the UD1 instruction is used to carry metadata in the ECX register
+ * to the KASAN report. ECX is used to differentiate KASAN from UBSan when
+ * decoding the UD1 instruction.
+ *
+ * SIZE refers to how many bytes the faulty memory access
+ * requested.
+ * WRITE bit, when set, indicates the access was a write, otherwise
+ * it was a read.
+ * RECOVER bit, when set, should allow the kernel to carry on after
+ * a tag mismatch. Otherwise die() is called.
+ */
+#define KASAN_ECX_RECOVER	0x20
+#define KASAN_ECX_WRITE		0x10
+#define KASAN_ECX_SIZE_MASK	0x0f
+#define KASAN_ECX_SIZE(ecx)	(1 << ((ecx) & KASAN_ECX_SIZE_MASK))
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
 /*
@@ -34,10 +52,12 @@
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+void kasan_inline_handler(struct pt_regs *regs, unsigned int metadata, u64 addr);
 #else
 #define __tag_shifted(tag)		0UL
 #define __tag_reset(addr)		(addr)
 #define __tag_get(addr)			0
+static inline void kasan_inline_handler(struct pt_regs *regs, unsigned int metadata, u64 addr) { }
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_64BIT
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index cb324cc1fd99..e55e5441fc83 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -102,6 +102,7 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
  * FineIBT:      f0 75 f9                lock jne . - 6
  * UBSan{0}:     67 0f b9 00             ud1    (%eax),%eax
  * UBSan{10}:    67 0f b9 40 10          ud1    0x10(%eax),%eax
+ * KASAN:        48 0f b9 41 XX          ud1    0xXX(%rcx),%reg
  * static_call:  0f b9 cc                ud1    %esp,%ecx
  * __WARN_trap:  67 48 0f b9 3a          ud1    (%edx),%reg
  *
@@ -190,6 +191,10 @@ __always_inline int decode_bug(unsigned long addr, s32 *imm, int *len)
 		addr += 1;
 		if (rm == 0)		/* (%eax) */
 			type = BUG_UD1_UBSAN;
+		if (rm == 1) {		/* (%ecx) */
+			type = BUG_UD1_KASAN;
+			*imm += reg << 8;
+		}
 		break;
 
 	case 2: *imm = *(s32 *)addr;
@@ -399,7 +404,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
 
 static noinstr bool handle_bug(struct pt_regs *regs)
 {
-	unsigned long addr = regs->ip;
+	unsigned long kasan_addr, addr = regs->ip;
 	bool handled = false;
 	int ud_type, ud_len;
 	s32 ud_imm;
@@ -454,6 +459,12 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 		}
 		break;
 
+	case BUG_UD1_KASAN:
+		kasan_addr = (u64)pt_regs_val(regs, ud_imm >> 8);
+		kasan_inline_handler(regs, ud_imm, kasan_addr);
+		handled = true;
+		break;
+
 	default:
 		break;
 	}
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 5b9908f13dcf..b562963a866e 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -36,7 +36,9 @@ obj-$(CONFIG_PTDUMP)		+= dump_pagetables.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o
 
 KASAN_SANITIZE_kasan_init_$(BITS).o := n
+KASAN_SANITIZE_kasan_sw_tags.o := n
 obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o
+obj-$(CONFIG_KASAN_SW_TAGS)	+= kasan_sw_tags.o
 
 KMSAN_SANITIZE_kmsan_shadow.o	:= n
 obj-$(CONFIG_KMSAN)		+= kmsan_shadow.o
diff --git a/arch/x86/mm/kasan_sw_tags.c b/arch/x86/mm/kasan_sw_tags.c
new file mode 100644
index 000000000000..93b63be584fd
--- /dev/null
+++ b/arch/x86/mm/kasan_sw_tags.c
@@ -0,0 +1,19 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kasan.h>
+#include <linux/kdebug.h>
+
+void kasan_inline_handler(struct pt_regs *regs, unsigned int metadata, u64 addr)
+{
+	u64 pc = regs->ip;
+	bool recover = metadata & KASAN_ECX_RECOVER;
+	bool write = metadata & KASAN_ECX_WRITE;
+	size_t size = KASAN_ECX_SIZE(metadata);
+
+	if (user_mode(regs))
+		return;
+
+	if (!kasan_report((void *)addr, size, write, pc))
+		return;
+
+	kasan_die_unless_recover(recover, "Oops - KASAN", regs, metadata, die);
+}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5cb21b90a2ec..03e263fb9fa1 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -669,4 +669,27 @@ void kasan_non_canonical_hook(unsigned long addr);
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+/*
+ * The instrumentation allows to control whether we can proceed after
+ * a crash was detected. This is done by passing the -recover flag to
+ * the compiler. Disabling recovery allows to generate more compact
+ * code.
+ *
+ * Unfortunately disabling recovery doesn't work for the kernel right
+ * now. KASAN reporting is disabled in some contexts (for example when
+ * the allocator accesses slab object metadata; this is controlled by
+ * current->kasan_depth). All these accesses are detected by the tool,
+ * even though the reports for them are not printed.
+ *
+ * This is something that might be fixed at some point in the future.
+ */
+static inline void kasan_die_unless_recover(bool recover, char *msg, struct pt_regs *regs,
+	unsigned long err, void die_fn(const char *str, struct pt_regs *regs, long err))
+{
+	if (!recover)
+		die_fn(msg, regs, err);
+}
+#endif
+
 #endif /* LINUX_KASAN_H */
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/13fa5da13adf927abbb7dd85d19fbaa8e4fadc84.1765386422.git.m.wieczorretman%40pm.me.
