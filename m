Return-Path: <kasan-dev+bncBDCPL7WX3MKBBEFN2TAAMGQEXRF7OLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A321AA79C5
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 21:01:37 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6e8f9057432sf47712846d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 12:01:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746212496; cv=pass;
        d=google.com; s=arc-20240605;
        b=EAk3QwpCLFAMxYjpEQSRUXw+d0uDo8RbRUNTATg0UMNwxYg/0t23nGn4LJji1O8HBF
         wAEydcJDq81DnRGg1Fk7k4v751wvYGaK6W8jLoIVw7LA8H9lggKwRh8Qye8iCMFdrFvK
         FR/dRPoAD0ZdIGzeID7NQMEu05eyMhNYo01roW/suSv2jn16RbHtk5jGpMtr+i2pbPjt
         YXPdS8X4Ei4+FDwi16Ro+K06SfdmX/qvOfCZRr79ODcendIGbkKRZf4ahrN1euJ4lKfa
         4X7a5rmfnE7fYMxHnn84GrIj57c9I+XOtTa5U+Fy81L500E31br0lgVQuYpCaj6OuGh0
         t3bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dRkB3UX9T1xKEUwVRIaiFiMrprqid7st38SLCorHGow=;
        fh=JVDs6P2hjHvIeFtDufGZ5VuYCnb8uvJVvePn39LzbgM=;
        b=lxkwUWm10TYlX/UYWQ1bJZXmRRtGPwmlnn0IXeykBPF4ujHuX2Y8DhHf67MrNIHNNr
         Jf5fu/OxFj7235xW1H3Qg8EqGo3OALCLxyURhvcJ4cKDadmgoF1uLLVROFBstENduqtv
         TYX9hP3iujRRYAHlWhdmPRub6O6R8AtCbAzRv4t7vYSrF8sjiUPd2hZ1kR7rZKRCWPqr
         HHMiZQcxiuxX7VIrcMPcVoxTECKkVLiYCFbfqlXBNrx16hn/vzimv5n1FjbtlcPg/R6r
         Ib09ylkJ0Rhhs+ya5BJ0uGtZqVXDcrX7ZU12VOvp7dI/PUuo9G5mwprGQOWwQy46PMVh
         qaxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jB1YOX/W";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746212496; x=1746817296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dRkB3UX9T1xKEUwVRIaiFiMrprqid7st38SLCorHGow=;
        b=Y3EjgKmsBYYeFFJbyQ1gEykH4hQdSk2zy7nWfkUu8T8NFSRFqJUUGtJmA2+VWYJSfl
         ph6MWfAFVuxSNSE93CcS8hxvle6ZivLOXq1n9u89L8JWk0brHcQmeOqzW/mIakAx5wq3
         hcsJM/Ebr13LoabwieOOwrlZbFDXN4DtNGWTHogaE8DsMTiU3x7M4ihV7ZS7Vg4i7AnX
         V6Ad/E3/2Tzs2sQsOC6rO053x6ku1ORpyUjkPxURtyPt3rxOjMSUMd/QNpgSATLKJBJD
         /JvX2QlrfMeYlK6nMmH9DvvqSUb05cSUe0adnBVIz+gWfqsENPgk0lclf+EMMnjh26qE
         V+Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746212496; x=1746817296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dRkB3UX9T1xKEUwVRIaiFiMrprqid7st38SLCorHGow=;
        b=kVDhWjgNIdHuqvz3zyXY8G8uEc1O8g/mOakc7LWIJSOid8GcboXTLEhDQzpW7k/M32
         zvYZg80ukY6usprHI2hKLNopi/jvlsfoAet2ZbW9qrS9/2bdSkXSpgX9vEtCgYx49Pvj
         NN/QKmlKOH3jdgR4QbNNPLLW83E4XYedyuOCmzso07UeALgqOEwc/U+5s0Z0uo3QiYMt
         3qeoOOZmn7rh0lR7PfOO0w9clKEmZjUql73ZvG9eMZSoGs3h9oHnSzP0eUS3d/ymXadj
         XBKxF6MF+EEfa3VlDtJUbmUgvw6ctHxUXq6jA+sRJyXwpFZjkkzrsfAh9iyCHACtKL0b
         qUDg==
X-Forwarded-Encrypted: i=2; AJvYcCWh63+FbUx9KwRVmr/gVVFzfQZXKqJe0akGMNRIWIoXqtd8epFJ0dufl8LGFumcr4IbcaTPPw==@lfdr.de
X-Gm-Message-State: AOJu0YydE5Xi18dXdsNo89uC3/fAWVZiZdK04TubZQ5cmXTHmYtv9+bA
	8algqCVkrtGgtXERADI66hSyUUlPacoEgVq1EUi8h9BtH6HS7bVt
X-Google-Smtp-Source: AGHT+IEiYu/V2jizKBWzzgwCrgMlbt3Lj6pTUlXv+0G3sviQr8vi2uc6xrLhDSZH4hp1dfHEqlDeUg==
X-Received: by 2002:a05:6214:f21:b0:6e8:ec85:831c with SMTP id 6a1803df08f44-6f5155e92bdmr72853236d6.35.1746212496171;
        Fri, 02 May 2025 12:01:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEjBVERhVFPK0xlub5Gnj25vclN2JSAU2hENni7cdaMVw==
Received: by 2002:a0c:f98a:0:b0:6f5:457:9fd6 with SMTP id 6a1803df08f44-6f5083f34a9ls18391486d6.0.-pod-prod-06-us;
 Fri, 02 May 2025 12:01:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7uD8IUgn0LTWgW7ETDeQWETMCS9MeIS/yIu5xsc0A0vX78buY0dgPTqNT76bnIMcN4j5m2axw9ok=@googlegroups.com
X-Received: by 2002:a05:620a:2682:b0:7c5:a423:f5b0 with SMTP id af79cd13be357-7cad5b22d6emr649555085a.7.1746212494409;
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746212494; cv=none;
        d=google.com; s=arc-20240605;
        b=WqnRfIyLptBT9Ah/G7hJNiyH1WTxqJINT2WqLkpgKM8dafRoBEGSz/Bvc3oxmuX3rw
         +2jaHsTCnqws9d/KuppZQefpcyrYpHF+ySiWqOYLROU5J7DuPcCWTC6ktpHcd/uo+v3S
         CijFkLdv0kaBL9RJta4xQp545nyFwW7gQsW1Znj14nzwqnmcBSw6RW3yIMfQRJQwxWFL
         xZ73xwZrTPr5XbZze0OPYKYK0EJffD2TqOIvm6NJpduN03gEVW3SwHd9TYhTf6kD6W/a
         ELLEtMrjY9A+6K7SI3DjB/whRTYzFAjyMdEKAKE/UtxfV+3Zir3pR5NbewcWs100TGyy
         jD/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ze0pvXhySGK0L8vipVJusHHsV9ao9JZ+P8Ehobf9I4o=;
        fh=85vFmEItGaDhgLs/vjlw29hZUjCUU8/e9UyaoG9281s=;
        b=iN4p0tEA42hYScOc+byF5+L4l7LJBfmgE//+AIIP6E/dJFCr5MsUx0wUjiq4yhW58M
         NWt3axFOY6mLw6WdYziRjHxqSVoNWpGOug+DIYdXgOvdbEJx1lJ2VG9a7yR4Bsj7jMZG
         ZmfEEixyIWK1wcCAqPG4Fnk68w+OcSjb3tMHsSq0cm/x+ZX0zcjMYQXENuO8tarOlirx
         bJ33Gj7yFD70oa2K5kswz/iKpajJVp86IKRBxWYtnJv9kR24WgUxujL3uyXuMzvN8dV6
         kmCTU1exECLZ+ukFw3NIduVEsNnWd0HhVpEUUX6wc9a2h9THXXAWw2qUWQiwtx3sNHID
         N0Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jB1YOX/W";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7cad23b7d03si17742685a.1.2025.05.02.12.01.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D2296443EE;
	Fri,  2 May 2025 19:01:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9FA19C4CEED;
	Fri,  2 May 2025 19:01:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Paul Moore <paul@paul-moore.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Kai Huang <kai.huang@intel.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH RFC 4/4] stackleak: Support Clang stack depth tracking
Date: Fri,  2 May 2025 12:01:27 -0700
Message-Id: <20250502190129.246328-4-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502185834.work.560-kees@kernel.org>
References: <20250502185834.work.560-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4716; i=kees@kernel.org; h=from:subject; bh=OArrhviC9XaQ7OlcTfKqQMGsnz4armduOY/WBMGcbsA=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmiYm0eHYd/KD+/YrfhHLPdHAslHi9Fd//IiqqD/4I25 j38J1nZUcrCIMbFICumyBJk5x7n4vG2Pdx9riLMHFYmkCEMXJwCMBGBJYwMGxO93eMPrlt+5Jzt Oot7p+4nLPDlKnhnYFtxdhXvk+VS/Ax/Bd/vvaSguOh3WEFqRfyd1+x1/pxfFHj2REh++SY+fVI 9DwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="jB1YOX/W";       spf=pass
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

Wire up stackleak to Clang's proposed[1] stack depth tracking callback
option. While __noinstr already contained __no_sanitize_coverage, it was
still needed for __init and __head section markings. This is needed to
make sure the callback is not executed in unsupported contexts.

Link: https://github.com/llvm/llvm-project/pull/138323 [1]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: <x86@kernel.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Paul Moore <paul@paul-moore.com>
Cc: James Morris <jmorris@namei.org>
Cc: "Serge E. Hallyn" <serge@hallyn.com>
Cc: Kai Huang <kai.huang@intel.com>
Cc: Hou Wenlong <houwenlong.hwl@antgroup.com>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
Cc: Sami Tolvanen <samitolvanen@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-security-module@vger.kernel.org>
---
 arch/x86/include/asm/init.h |  2 +-
 include/linux/init.h        |  4 +++-
 scripts/Makefile.ubsan      | 12 ++++++++++++
 security/Kconfig.hardening  |  5 ++++-
 4 files changed, 20 insertions(+), 3 deletions(-)

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
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 9e35198edbf0..cfb3ecde07dd 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -22,3 +22,15 @@ ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
 	-fsanitize=implicit-unsigned-integer-truncation		\
 	-fsanitize-ignorelist=$(srctree)/scripts/integer-wrap-ignore.scl
 export CFLAGS_UBSAN_INTEGER_WRAP := $(ubsan-integer-wrap-cflags-y)
+
+ifdef CONFIG_CC_IS_CLANG
+stackleak-cflags-$(CONFIG_STACKLEAK)	+=	\
+	-fsanitize-coverage=stack-depth		\
+	-fsanitize-coverage-stack-depth-callback-min=$(CONFIG_STACKLEAK_TRACK_MIN_SIZE)
+export STACKLEAK_CFLAGS := $(stackleak-cflags-y)
+ifdef CONFIG_STACKLEAK
+    DISABLE_STACKLEAK		:= -fno-sanitize-coverage=stack-depth
+endif
+export DISABLE_STACKLEAK
+KBUILD_CFLAGS += $(STACKLEAK_CFLAGS)
+endif
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index edcc489a6805..e86b61e44b33 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -158,10 +158,13 @@ config GCC_PLUGIN_STRUCTLEAK_VERBOSE
 	  initialized. Since not all existing initializers are detected
 	  by the plugin, this can produce false positive warnings.
 
+config CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
+	def_bool $(cc-option,-fsanitize-coverage-stack-depth-callback-min=1)
+
 config STACKLEAK
 	bool "Poison kernel stack before returning from syscalls"
 	depends on HAVE_ARCH_STACKLEAK
-	depends on GCC_PLUGINS
+	depends on GCC_PLUGINS || CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502190129.246328-4-kees%40kernel.org.
