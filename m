Return-Path: <kasan-dev+bncBAABBSW6STFQMGQEF7Z4RHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AE41BD145B7
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:28:44 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-81f3fe5ca8esf1354595b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:28:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238923; cv=pass;
        d=google.com; s=arc-20240605;
        b=jt3jRze2GS/TUK6JhgQQw+O6tvwincgNMjw0jP8YU6vyh+TzbT2Z6gzE6ptIplAVg6
         8QjVjKkfW6RVU8jbmjHnsFjG9iEH0X7jMjYlBxMztAiekvCMwuf7wmZs8qb/npPLnROk
         1uEU1yqkzIXOHRzHZh9Q1ZkQIFwykF+KBtQHTGohnqqLWvs6bVjngs0j7XLLUDRCnr90
         9Dp5cGoxoYxlKLjhfqIEBaPg83SN4pp1QvrfW9+pHCHuLbaoPdQ+JIybbxrvFBZfMO8i
         sU6MwGGTzHGtZk07U/V5Tmt+7zzA3dbHw0cxeA0+PHzTpffj4s0zBmhPZYbva0ZsL9x2
         3f6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=BtIRZFLnz4sH8Ddg/W3Mh8mIITuQ4DcPHyvNbRyYtXY=;
        fh=rjmjnQ+MNaHGMYcyt0NPHkO6amQ+gLFA9RNHyObhE9E=;
        b=AcDwK/ynOKTjuOCpVmmBabP88FlTNaJ9yGMQ+FE9I4sqlqiu65EwDLAHX5Fz/V2HV0
         +7avTHUKwW2Ae0pH/8iTNOgXXZ10ht8Tk8SCS7c4VfFNC4SjFMdxr29JMaFpwinPhrxO
         tLhrO/Iw7xlfXMCEtwG9CUSzYol/U3RCZ6io4LHLqsOgrWZk5pZV7CfGp+UrvE8FOR+Y
         uX3zzA4iGCVnRH0XLgfy8W1XOFlz4l7FOgQgPo6qPw1avPiIdu2g4f/W8MkP6J2VTNnH
         87VqvhQEP32/vgifVxCmiZrrOaCQl1IcyqdmWs4wP9z6dx8hKNWMuUJGyWN5Ew140fyO
         CEow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=YVS1R785;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238923; x=1768843723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=BtIRZFLnz4sH8Ddg/W3Mh8mIITuQ4DcPHyvNbRyYtXY=;
        b=f0tGrE4IxclgXw+bfMixT92rilrGnEw9UDrR/QgvaDqmqwF2gYhWF4zed8shVNjzDi
         WWPQ5qQ4njiFCEVThcYqnbDXh6V2I6WLg3VTuGsMew7wTqi1m7Nqe71f/ZC4FKdK866N
         nyi6n+4c0I6yY6xzCY6iWNhnDMPjjIJVjltwIxYZUhwfFCdw9nMdPtaKC9cyctLbYXZQ
         yeOMZCxxjvysi3yv2mXv2FEWa8lF4I7mha9VlDL9UPL7vykSvendxmjjKiVclEe8agJ8
         YvMEOfqVA3PCXche/7nsynF5JnsKo6aGQZMWIlYuFzcy+3TgZVVN3Mffn/G5Il4s4Isj
         IEFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238923; x=1768843723;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BtIRZFLnz4sH8Ddg/W3Mh8mIITuQ4DcPHyvNbRyYtXY=;
        b=rycv/OlIQ13sgRM41I3DRPTl9utPadm03ZWJZjhnNsdgsd88s1BI2ZBM4GBEj97RBt
         I3q1YO4Eg5atuyg0f/kGRNqDK96Ttd20wZbMCFXeIH9TlQbLsccxy1HGaIpWgMCv0xvb
         2lgXVtOmSnmnXvlnichz7ZJW5c45X3H3LOsNuidUcl5pNU6Wc/bLqcWj/5UAzsjeUxS3
         Fxw2LeAis18cdadzIwnn54PdnlSiy+NnG0CS/TqGmEU290w8sj39SN/VjDtWNZL0xdS8
         2D3PvF8+ovNg+Wd1bRjeNJ5sqhtw6yIlOLQzIgWVOUhNMXP7f8fyCbpevu1dmJimfKK1
         g8BA==
X-Forwarded-Encrypted: i=2; AJvYcCUr3+6qej0FiS11x+GDHh8xreNmWBTMrJQpqPcx9VXER5ZzbNQmdalrFH7eNVNNS46tqmC3cg==@lfdr.de
X-Gm-Message-State: AOJu0YyIiZXY4F+zlRu8y4IQcRTL9H89q0LEkj/nHt3s20k6pddEQoMr
	MbccCmENOmWkpcYlNEXxon5N24utssnoiB7HVosBfoLsIcB+JxcO/4CL
X-Google-Smtp-Source: AGHT+IGdbli7tUZwk/Y8aXsgVM6gcjyw5CHQ+eD7e2ahfAAO0/wMhyqNl4vSMA614FO6YIbDXakyvQ==
X-Received: by 2002:a05:6a00:2c85:b0:7e8:4398:b352 with SMTP id d2e1a72fcca58-81b7f7e28abmr14363747b3a.37.1768238922783;
        Mon, 12 Jan 2026 09:28:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FfW7ZTc54IMAdADKXG23IJq2I3lq1nPCMWITmUWizUjg=="
Received: by 2002:a05:6a00:244f:b0:81e:4338:cee7 with SMTP id
 d2e1a72fcca58-81e4338d00fls2951771b3a.1.-pod-prod-02-us; Mon, 12 Jan 2026
 09:28:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEJ3HaAEhjjkWSyVimF4YZ0rh+wfipXy7H7AlvWbMVW6gZoUVUDM/l4XXOEu8VI2/7HfV2i144Lk4=@googlegroups.com
X-Received: by 2002:a05:6a20:a105:b0:334:a681:389c with SMTP id adf61e73a8af0-3898f8f3b19mr16400475637.15.1768238920629;
        Mon, 12 Jan 2026 09:28:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238920; cv=none;
        d=google.com; s=arc-20240605;
        b=hRmSIebn39rOspzodko8jEvNKSvQaAGtjE0TfIIbbkFhIcFtvkTDXdRSJGJX3zIbTe
         yk6WM+I39H+OdxTZZjEPlj2JSlGtGdYcKk3P4/vL8I7zdWgbUD2UII0r4/PBO+3DwhVW
         vdsuQlDX2SPGKdYEIwzvYvhdOygFCB/PonYLt2vp9HTIO/N+63l7zEzsYrllHC2FYP40
         OamYHM61Ex9BRNeskM/4cW1LLvsLI1zaMbRWVsA48lYL8iSkpzxD9fE1mzWUwgztsG7e
         hBvfSmlflKjM6FQnsloER0P+SLHJF2nZfoj4ELc2JgYZCLFpAKi8rjhPTJpfqUQEN7hI
         h0HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=smEYUjE4TiZwGsUIUGvN4uRam6KETrr7zjszlbfCqLA=;
        fh=U0OOTr31LAvjJ8HIdSeHP6HnrUH+XWUEkxuVYLDBF9c=;
        b=TDUJxtXfrt4TKO1rto5qE7MCOHGWHV768dCEhGaAnuZZ896/lkCkzxjwkVwu0coDuY
         fmQnoFb3cAPl/89RWVYfCAjzh7D0tVUZsWNpxaw22YRFP7wnTA6UnIa+d/uGl7lcpkS6
         XQKxGh6X7mmVH3ifahlN7lBOQKaRxsrKREH5xLSeaoZk/M2m+dDVgfEi9fMhzCjzlfTO
         ENq2h7S7/TCzNl3TcuF3H/k4KY3UevVVh5av713RN+Jey2my0LSCeeuCUeWOyGXvaEC+
         RDbuw6tA3zw+2dk0nVAzhSvVlsoyMw276qFUFtuPZxZH6P5JBUJWNErrhrQAWbUsyn7a
         NB5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=YVS1R785;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c4d8ce6c390si556275a12.2.2026.01.12.09.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:28:40 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Mon, 12 Jan 2026 17:28:35 +0000
To: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Subject: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan available
Message-ID: <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 7114c3fdb473fc3c6e894749edc0df69710932f4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=YVS1R785;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
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

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

The value for sw_tags KASAN_SHADOW_OFFSET was calculated by rearranging
the formulas for KASAN_SHADOW_START and KASAN_SHADOW_END from
arch/x86/include/asm/kasan.h - the only prerequisites being
KASAN_SHADOW_SCALE_SHIFT of 4, and KASAN_SHADOW_END equal to the
one from KASAN generic mode.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v7:
- Add a paragraph to the patch message explaining how the various
  addresses and the KASAN_SHADOW_OFFSET were calculated.

Changelog v6:
- Don't enable KASAN if LAM is not supported.
- Move kasan_init_tags() to kasan_init_64.c to not clutter the setup.c
  file.
- Move the #ifdef for the KASAN scale shift here.
- Move the gdb code to patch "Use arithmetic shift for shadow
  computation".
- Return "depends on KASAN" line to Kconfig.
- Add the defer kasan config option so KASAN can be disabled on hardware
  that doesn't have LAM.

Changelog v4:
- Add x86 specific kasan_mem_to_shadow().
- Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
  KASAN_SHADOW_START/END.
- Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
- Disable inline and stack support when software tags are enabled on
  x86.

Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
 arch/x86/Kconfig                     | 4 ++++
 arch/x86/boot/compressed/misc.h      | 1 +
 arch/x86/include/asm/kasan.h         | 5 +++++
 arch/x86/mm/kasan_init_64.c          | 6 ++++++
 lib/Kconfig.kasan                    | 3 ++-
 6 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index a6cf05d51bd8..ccbdbb4cda36 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 80527299f859..21c71d9e0698 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -67,6 +67,7 @@ config X86
 	select ARCH_CLOCKSOURCE_INIT
 	select ARCH_CONFIGURES_CPU_MITIGATIONS
 	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
+	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
 	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIGRATION
 	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
 	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
@@ -196,6 +197,8 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
+	select ARCH_NEEDS_DEFER_KASAN		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -410,6 +413,7 @@ config AUDIT_ARCH
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
+	default 0xeffffc0000000000 if KASAN_SW_TAGS
 	default 0xdffffc0000000000
 
 config HAVE_INTEL_TXT
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index fd855e32c9b9..ba70036c2abd 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 9b7951a79753..b38a1a83af96 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,12 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_SCALE_SHIFT 4
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
 /*
  * Compiler uses shadow offset assuming that addresses start
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 7f5c11328ec1..3a5577341805 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -465,4 +465,10 @@ void __init kasan_init(void)
 
 	init_task.kasan_depth = 0;
 	kasan_init_generic();
+	pr_info("KernelAddressSanitizer initialized\n");
+
+	if (boot_cpu_has(X86_FEATURE_LAM))
+		kasan_init_sw_tags();
+	else
+		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware doesn't support LAM\n");
 }
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index a4bb610a7a6f..d13ea8da7bfd 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -112,7 +112,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman%40pm.me.
