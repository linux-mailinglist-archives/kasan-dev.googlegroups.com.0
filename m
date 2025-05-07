Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5WG53AAMGQEAKNG6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7B3AAE88D
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:23 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e75b87a703esf211112276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641782; cv=pass;
        d=google.com; s=arc-20240605;
        b=VesOd4SRylvlVYvZtMp5Wlhth9EL5O2deWl4OI3RNk+Oz98de7s52K0ra7b9pTfI3u
         B9UOH6tADapnYC7wmNeZljVaVRlBpbfZdjpQaMfJgXzBeFIK3fu3SvEAdqSaFd8WdmW7
         Xnn9YEoANF8jewXp4ucUDN844vcD3PdVQhMJTwQZqAX4UprLHqLnxpRU+oRAAWLvTz2Y
         Onbtyevmuhnu0V11TZEkeU813TxRIC+q65qNsNc/WpLCsCAoEhS+MJTbaE92fNNnDps5
         cth8IO7HABsBumulC/p7wLrfn47cHWgt2go4x7WHYq2yqH3v2rrsj1CW+JCxJPDaPTte
         rNcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=g9BAHOCe5qPtOxRe/sSvR6SUJzqJPjZWXmzaGHbfmrQ=;
        fh=iQl+8nl/HcSWt3e6CYucLEk3WaX9Oagt6iUsUiKV6aE=;
        b=ExbgyywZZXGwwy/7XUo683MMqIFrwPufVWZcaRRoqVj8vPAJvjSe+uJ0oLVQa0QAds
         2gVbkmLbkb0nfRrg/DaylfCETIRFRY6apb4dMFruCSlcEp9u06QxZyKtwUjQbMVwTrVZ
         2cMGQudVIJuAvFlZEdkLBON++LSdxAil2qjFYxwVbgyOdbnQeVzZcHKrVfTQMSPiAsTE
         wgryyWXWLXlnXDz4+U4iUJsPqkAi8yh8Nf2s5KGXgGxxxiY0F0w7jwfo77r7Pb/Gmpyw
         nsotRjO/WoMivThgtNoNTLQlFp4igfL1MPB1oGHqvW51YrorbN7luKUOuQpfsZVM5zZ5
         rR6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VAzZdzFh;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641782; x=1747246582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=g9BAHOCe5qPtOxRe/sSvR6SUJzqJPjZWXmzaGHbfmrQ=;
        b=Oinetu1cf/2EV6xr/2peUFE3Lmvw25Wupsc0MWhGqfpl8yK4cZSRAQVPCGAEEGDCqZ
         XGp99NQSUpKLCE5srtP+lz59IIgVxNA0Kz1ZK8+ZSgQqeP4VdXNMabyrREu8Ys/cFYyy
         DUve/KL7I30ZYTEv5M4EHz01JldPZ921GwTy9E4zN/s7R8VQXD2QvsYhZeSlN9HgzbfM
         xUzBgwKEj9X49JgLGCmg3Omuwk0hOBhO63zCcxL4h4r7/IRwy2AeIe1h9vvNr8+B7kPm
         5RG6FrglUs2GWMY3mNtSUoEY0ICPMRiX+hEgzKpidKKnAobvOpao9YrfgHVBkyUhNqYG
         X0Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641782; x=1747246582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g9BAHOCe5qPtOxRe/sSvR6SUJzqJPjZWXmzaGHbfmrQ=;
        b=MIE6xmKO9q83bMZM5M4iyZStAUDkenuIUkOT7iFzdl6Q/bE2ldZNYTwusbAq2MJB1b
         e/Gh9bcFGwPGQggM4pbm5/k3dnjAA58lED4XF2EAcsJUqUQVEyJn37cxaDB5yIRDUMDg
         ss0yqpcp26NvxEiQ3fLY8SIccOCdNY2RtpzDLoHG6Cl93KtO9QU4n731Uqj+VoNhjpmA
         D/xV9XXfubGbnnqw3bbTM2S7m5vtiX3jhpEj/H6dV1GwQda2C9A1xQcLwOyLZ1vHEOBN
         I3D58wbFskI9MWwVjN65fnchf+o07lx5fjNn0CVA4rugF9yKPsOgAwygE5HP4qhT0wmj
         v+fA==
X-Forwarded-Encrypted: i=2; AJvYcCVXdBQsFQHSnTltySjFytOvuRCX2OKWE2AOIPD/n6MYYJBg8WUa6X/Bk6hE5PYjV51NLI4VIQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJzNnLB5mx7QHsZZLLjNiHpIHfW1XDfEvzcWjxb+RF1p+KZBL7
	Dhn0JFDIswRleT49kuerMn3YtSQdjLcMJaO2XYq0juPI/1nxCIrF
X-Google-Smtp-Source: AGHT+IGsN8HluOikdlLo9ttaCjJxPJ+LMUhVSF6Alo0D9T7GTFW0NMANV991xvgmGMyzCTPirJCXBg==
X-Received: by 2002:a05:6902:2503:b0:e72:bbc4:7c78 with SMTP id 3f1490d57ef6-e7881d128c9mr6204570276.49.1746641782209;
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG9UfP/srfGSCy+te3QUGa7haRWAWUAU6XW8XJSKYMDyw==
Received: by 2002:a25:3c02:0:b0:e74:7ce7:2dd8 with SMTP id 3f1490d57ef6-e78edfe29e5ls151134276.2.-pod-prod-05-us;
 Wed, 07 May 2025 11:16:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPBInWPNWfdjZFVlnscN79UqASdABlznlEQh/JZ2fgCvByaJJbu6m+INxTGT2+bs0B/NhHycgILZo=@googlegroups.com
X-Received: by 2002:a05:6902:260f:b0:e75:b4e2:d007 with SMTP id 3f1490d57ef6-e7880fb3906mr6196131276.23.1746641780199;
        Wed, 07 May 2025 11:16:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641780; cv=none;
        d=google.com; s=arc-20240605;
        b=RrKgQA+nSTbBUovCRyEPc8V1GVwy/XzFK6/r6f+E66gp/8cjs/0Y8ZR2Lio/+4dcLM
         RlHfa6AHOz05ESpk2SxyOGF2wuU374CnCCB4jxuu8/nZxaCzUJ0cJeBPlZTWLY/fENOx
         W9YjyocU/aO+PnPrS61vshPRIAFvFsgFGy3kP5cpbj+JLgyrHzvDnSGV+6Ujoxo1Gqwa
         NiLu5J3xoVlOsBK5mWYkfo4bx6dNIF9TaFUL6gYKNiXhE0ZGD7kOEnH1irrvr13uTPHF
         KD0HXEM1twMLv9NCwLvlAbrVjKjWcD4RqJy4h9R1F2f75lTvz6Hu49NTwPAKng+Oref7
         AoVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=50T9b0k96VUSO0KPZj/sjCk3W/s4hFYaIcI0UdRyXuc=;
        fh=DBjMUvVbzKqiBek+GyZd/kUF+B852LvKe56cttuSZt4=;
        b=QFefZKtnx8XnzjdOJAwhhjbEw6Os4QaQ+1zmgZieof4zIMeTm8c2FymOCRsDH9ShpQ
         IBOkVxRE1i2MxCIpZ7Cy9SJwLpFB3LLy1uNVsPJaA8M+jEz08u9tiGVVwqY29wUSkX5V
         ti9Z6DSTJaMyz0DvBadO3DLu7Z1WDT5EUcsKbT04lJwgl1xxwyr+R9GVFsBc7DXnyxc7
         jA/IiP59XLF7zXZ7ggdgjrg8tDcFzUWv77Gi450ANdI1kriiyqCdsPLCrPHc00JuFKut
         5L7gOc8TDzsKiEhABAN5JWvSz7N+wHNbHjJZjIfhrMzvBBeRP6ywMySGChJ9yfM16TjC
         OZaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VAzZdzFh;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e75bcea1256si227471276.4.2025.05.07.11.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D94634A755;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 45EB2C4CEEE;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	kasan-dev@googlegroups.com,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 2/8] init.h: Disable sanitizer coverage for __init and __head
Date: Wed,  7 May 2025 11:16:08 -0700
Message-Id: <20250507181615.1947159-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2847; i=kees@kernel.org; h=from:subject; bh=6rPKdmTAkNXJoVHpXuZmVez15fxfVheZEKRm8PRLszw=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi7MPFhcujE1p83GNUj2Vetl/6Q7ju5xS7tumPJN5t DQ2USaro5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCKXJBgZ/igUKc35wvT3UdQu sR4u1YLZi59d21ljXfz+Qtf5bvnJmowMzbyyqauq9ef6NGj9Et9r9GSFGxfTTW/fIBMRRfdvObL 8AA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VAzZdzFh;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

While __noinstr already contained __no_sanitize_coverage, it needs to
be added to __init and __head section markings to support the Clang
implementation of CONFIG_STACKLEAK. This is to make sure the stack depth
tracking callback is not executed in unsupported contexts.

The other sanitizer coverage options (trace-pc and trace-cmp) aren't
needed in __head nor __init either ("We are interested in code coverage
as a function of a syscall inputs"[1]), so this appears safe to disable
for them as well.

Link: https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcov.c?h=v6.14#n179 [1]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: <x86@kernel.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Hou Wenlong <houwenlong.hwl@antgroup.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
Cc: Luis Chamberlain <mcgrof@kernel.org>
Cc: Sami Tolvanen <samitolvanen@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: <kasan-dev@googlegroups.com>
---
 arch/x86/include/asm/init.h | 2 +-
 include/linux/init.h        | 4 +++-
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/init.h b/arch/x86/include/asm/init.h
index 8b1b1abcef15..6bfdaeddbae8 100644
--- a/arch/x86/include/asm/init.h
+++ b/arch/x86/include/asm/init.h
@@ -5,7 +5,7 @@
 #if defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 170000
 #define __head	__section(".head.text") __no_sanitize_undefined __no_stack_protector
 #else
-#define __head	__section(".head.text") __no_sanitize_undefined
+#define __head	__section(".head.text") __no_sanitize_undefined __no_sanitize_coverage
 #endif
 
 struct x86_mapping_info {
diff --git a/include/linux/init.h b/include/linux/init.h
index ee1309473bc6..c65a050d52a7 100644
--- a/include/linux/init.h
+++ b/include/linux/init.h
@@ -49,7 +49,9 @@
 
 /* These are for everybody (although not all archs will actually
    discard it in modules) */
-#define __init		__section(".init.text") __cold  __latent_entropy __noinitretpoline
+#define __init		__section(".init.text") __cold __latent_entropy	\
+						__noinitretpoline	\
+						__no_sanitize_coverage
 #define __initdata	__section(".init.data")
 #define __initconst	__section(".init.rodata")
 #define __exitdata	__section(".exit.data")
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-2-kees%40kernel.org.
