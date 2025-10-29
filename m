Return-Path: <kasan-dev+bncBAABBGPJRHEAMGQEDEHU3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D6CAEC1D282
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:10:02 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59307b95006sf102322e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:10:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768602; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ocv2KGM5QSd9OdQtRpfxC2TOLx1MSdBzFg9dIMejov+EwLn242XRLvIQvmKDhNVcjL
         8ZTaVpjMMpBTZfKvRICl33j8zCrg8qdTeXCyX657fNoALCFYB1Cr11d2Bap3Sf4IPRAY
         NN0Tlt7eqxNN1kGBzX0AHqSRHnhQ7tAnSSecZCkwTQ8QqsaR8wbb4VThJdH3l2Q+P0GB
         zbf1NCCeOLYmaMq1a2UpD8JMhTm+RwnxB5ohwPi0xSWzZLPCTk7Qq/N6ueyz1fjqqcdl
         LjLA3fJnUrFrfwT3tfi1kd9vInfM5cDV6Og+kYrsGjr6rQLoPFZDMVutHpaSN4IUKYwj
         wUcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=iSPGcek5kmee/t6h2QprN+RrIcmPeliVcOjEUALqbDc=;
        fh=Ji/eK1V2E2WHz6Rc5trI9ex9dTkkAXN0VvY1+Ile4Bo=;
        b=kX3pOyoiOAA/htEHxjAKqXtTcRRnjSPLnvOhiNV8jGgg3u4NhO/w8Uj4GIR8/eRdE6
         j4qVq5XThdGywzNqWOLSy6PsKpqirsuhE60hVp7lTDVAlbjLRB5KiiqaxOU67R76CCUi
         m21+TPG8RZiR4NCRYJjgxNKBrawV37gZEFitKzjtcgBdJlgnghE8v2ovzOae4tpPIcaM
         PJLz0VSoOSsaVsIKVvuRJbLbebxfk/i3tgiKnENCTeJ4lHtPfIRl4/8TyXtYes4xePzN
         BO5eIdK/azzABPQElmscC5pMfZYlPDOPILgoV0CqQIQ6GG6BgHKD2TGFfyAZ+ZatEqBm
         gm+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=pBdq+49r;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768602; x=1762373402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=iSPGcek5kmee/t6h2QprN+RrIcmPeliVcOjEUALqbDc=;
        b=kkeDwc3+CSRMgUJhQAnmMkfzWJdaRMuz+VCMlQsXTDpJhgoJGyxNVxuifi6fl4BshC
         yURygtY2o8cgUk2Cz4OCg9sgqNvF6uqBGN4rlSxtGLgcVH8jDJExMtwfaCyzlbnvsGmx
         oBl701U2RR+ACN8rogS2TPnCc6uWYqI5qDeVeKXOb2DQRSYAmi3hSeI1wvoM5AeLVpGW
         nA1SoIQuY178ErSqdAgcRE8dGukGNg1BDem4OyPdjrWUDO85K2FXzxt1WJNAufuVYskx
         QVGlOiS4WX9uc7Zsbc8Dkc8Ut6qwQt0LuFy1eDo4zlbmvWhCtXXfEaycVJcKg/QOajmx
         i5HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768602; x=1762373402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iSPGcek5kmee/t6h2QprN+RrIcmPeliVcOjEUALqbDc=;
        b=khKf/qlHg8rnScLadlWy1k+HcHHPdPgIBPnZTNlk/ZZ5aXjj12er/Ysp+9nwiGcSqj
         hkX/y+xvXvgrh/Wzmf2L2bJG2wzeaeLeV9fAtDARimMibXm2b9n37GCvnbxnoavXDnXF
         pOdMBNHCpWMRjUI5s4F6Q9isuwK4S4+FCSIngx2djWHRjuPFMWiXDHzlXcfYuZxLsLV6
         cCFivQxTVRismygYB7NN8CF8We8dP50ZlW1I28BeHseiA91dEnYSJRWGWZ+44Sr5JpMT
         Wc3fYhV+z/e4GrPR7OsCLonhJRl/rffX1HjK7/rPLv1lPyP7FfjC4MFELKx/DHBDb9p0
         irUA==
X-Forwarded-Encrypted: i=2; AJvYcCUpwjduBXtaNSsPpxzkM28TYtJzRxyGlGMEYylnS4WGhRldwgpBHgwjqSIXPb4yk2cN8TOU5w==@lfdr.de
X-Gm-Message-State: AOJu0Yy5lEJC+xtPQGctcMvPnwut4lZzx+/b9As++eacLtqMMMoNDAQM
	YRp4z8Cf8EQYobJ698S5zGq9zL8vtdiCPEmODpAcHIGEWBB4agkTcPOa
X-Google-Smtp-Source: AGHT+IFy5mwgOnj7X0XcyIh6TF1VZ2DZxhp6Md7KrxLiU0k6AvYF1F6UuWalhWOG4DtzO1ayQy8KSQ==
X-Received: by 2002:a05:6512:104b:b0:594:155a:a060 with SMTP id 2adb3069b0e04-59416ef259fmr163690e87.54.1761768602063;
        Wed, 29 Oct 2025 13:10:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Za2aDxSyH6d+fK4Gq5nlGnbrmyGS/DgwonZWYKuieZHA=="
Received: by 2002:a05:6512:401b:b0:564:4dfe:5a4f with SMTP id
 2adb3069b0e04-59417645334ls36056e87.1.-pod-prod-08-eu; Wed, 29 Oct 2025
 13:09:59 -0700 (PDT)
X-Received: by 2002:a2e:ab83:0:b0:36d:54b3:9f71 with SMTP id 38308e7fff4ca-37a109284c8mr2297581fa.1.1761768599502;
        Wed, 29 Oct 2025 13:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768599; cv=none;
        d=google.com; s=arc-20240605;
        b=OImwEigxDSFDzDJBYu1OmO/OOsnrD3BiXhRGhkVKO79u64ZeOUzciWtGk4U6+Zox/v
         5IBGjXD0SDOJQSN58+V6ujlGTGs6puSeAD894kDlp+7bRMRP4Qfjq4jUL7wfIdWrr9QL
         lut4uBusoLnlURY3H+gB/HttK3Bkr8SORRzHfgZnsbfzLhrTJI5CmHvJJD0QbCJG1tso
         7wvSKSoqCoeIEBnj/Ry3rr4rWhBnXJBEr7bPaJpn+1lIqI7WCQ/NEdzj9jkesc+ny7GD
         bH4ydTh4PXxs9A6xMF3XzxS6dI77B6I3todaPUf/r5QUzdslf9LBk/vj6XEF1KLJPMHL
         jang==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=IfDaBLNxvsgHIrxT5fF1MIs0svV8id6MA4rHYub5Mv4=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Qmy20Abbhb4eXykxjkz8C8po93SFwG/Jrpbz+f8Frqc0jyCiAXElU7QEBtaKGql8XP
         RBr0AY1iWAB6djlYFTGrtZ62EMbQciWDKlmKaP5jA0zvnxWzcYlhwVq5I8QgeP9RfB4L
         j1KocQb/flen/VVyM9OwpsBlPYRVWHvdpU9OxWgJZwhyCTCm8xPc45CA07QYPqCoyMKw
         vI+urJ8151zOOrpnh7kXBaYhR3TRQwLc76t6+8LmSpsKFGTvTTAKiJHLpaxm/OPzbhM9
         +dCLj6vT1QTdeglgkSDD5sK2b9O7Mcdhcg9QQSp6oBe9nfWkLsFzNeA0h/PBf/XjtDN8
         UFyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=pBdq+49r;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef150b6si2852021fa.3.2025.10.29.13.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Wed, 29 Oct 2025 20:09:51 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 15/18] x86/kasan: Handle UD1 for inline KASAN reports
Message-ID: <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: db233bf96a7423ff32d19231938d1a80a3e5afe6
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=pBdq+49r;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
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
 arch/x86/kernel/traps.c      |  8 ++++++++
 arch/x86/mm/Makefile         |  2 ++
 arch/x86/mm/kasan_inline.c   | 21 +++++++++++++++++++++
 include/linux/kasan.h        | 23 +++++++++++++++++++++++
 7 files changed, 76 insertions(+), 1 deletion(-)
 create mode 100644 arch/x86/mm/kasan_inline.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 53cbc7534911..a6e3cc2f3cc5 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13422,7 +13422,7 @@ S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
 F:	arch/*/include/asm/*kasan*.h
-F:	arch/*/mm/kasan_init*
+F:	arch/*/mm/kasan_*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
index 880ca15073ed..428c8865b995 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -31,6 +31,7 @@
 #define BUG_UD2			0xfffe
 #define BUG_UD1			0xfffd
 #define BUG_UD1_UBSAN		0xfffc
+#define BUG_UD1_KASAN		0xfffb
 #define BUG_UDB			0xffd6
 #define BUG_LOCK		0xfff0
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 396071832d02..375651d9b114 100644
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
+void kasan_inline_handler(struct pt_regs *regs);
 #else
 #define __tag_shifted(tag)		0UL
 #define __tag_reset(addr)		(addr)
 #define __tag_get(addr)			0
+static inline void kasan_inline_handler(struct pt_regs *regs) { }
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_64BIT
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 6b22611e69cc..40fefd306c76 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -179,6 +179,9 @@ __always_inline int decode_bug(unsigned long addr, s32 *imm, int *len)
 	if (X86_MODRM_REG(v) == 0)	/* EAX */
 		return BUG_UD1_UBSAN;
 
+	if (X86_MODRM_REG(v) == 1)	/* ECX */
+		return BUG_UD1_KASAN;
+
 	return BUG_UD1;
 }
 
@@ -357,6 +360,11 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 		}
 		break;
 
+	case BUG_UD1_KASAN:
+		kasan_inline_handler(regs);
+		handled = true;
+		break;
+
 	default:
 		break;
 	}
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 5b9908f13dcf..1dc18090cbe7 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -36,7 +36,9 @@ obj-$(CONFIG_PTDUMP)		+= dump_pagetables.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o
 
 KASAN_SANITIZE_kasan_init_$(BITS).o := n
+KASAN_SANITIZE_kasan_inline.o := n
 obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o
+obj-$(CONFIG_KASAN_SW_TAGS)	+= kasan_inline.o
 
 KMSAN_SANITIZE_kmsan_shadow.o	:= n
 obj-$(CONFIG_KMSAN)		+= kmsan_shadow.o
diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
new file mode 100644
index 000000000000..65641557c294
--- /dev/null
+++ b/arch/x86/mm/kasan_inline.c
@@ -0,0 +1,21 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kasan.h>
+#include <linux/kdebug.h>
+
+void kasan_inline_handler(struct pt_regs *regs)
+{
+	int metadata = regs->cx;
+	u64 addr = regs->di;
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
index 3c0c60ed5d5c..9bd1b1ebd674 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -679,4 +679,27 @@ void kasan_non_canonical_hook(unsigned long addr);
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
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman%40pm.me.
