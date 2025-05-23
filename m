Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXYX7AQMGQE6XJHJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C0FBAC1B07
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:44 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-85c552b10b9sf768320639f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=aidG65wqrW2BmcqZO52oVqo0g9Ig5whxSddUV0WgBUdJibOLOkCKBjgFwQXdlaCkeL
         TUwE21nyYtaoCZYA5v/fwIzSUVSZiNLBTij3PsD9ZQSjO4jFYmHHRmNtNszKdRgp8QAn
         Ppe2brLHerJSSQZ8FBsSyMbXV+0p9s+VrzrfDHxJLkUZErAEGBFPkHMUtPUV4gx1xqZB
         tF0I2SIxHQu1yNv21A34KrMGj8sju53gsTFZ8KsBSRpUca6sNLGWMOCOBZxloX9T597N
         2FJaNtewUQiBKmChR1yAwzQMSiU1jhiKUl2E/eShn0eHRxJhlCEOM44GJg6dRiECA8Eu
         y9KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pijhLrBoHz3XSY2tmMaEEnKPO08ZGUBuMU8IAGP1a0w=;
        fh=lHyQ2GhCWKcWxOJaM2tvHUP6gxmNIMVQPMhshrjsV5o=;
        b=OoVzxBCGZW+INIbqV//tfMRDqw/wUtWLNxrSpRrv/z4qrpekRuNoVzEkbXTkNpFP1U
         21iFWPrFY5qVCt0uTo3HI2KQ31RdOzAiEr6YlNeZ5QGNFTQcojqyUdK+9NwgSBIMIUYC
         wpwhAeC4EA+fauhoNz7ASwCjzPADdKrNYt3koQ8zl+yX0ytrNATjGtMWrCN0zV3fl7p0
         qDwwd/JxhyR6T/vTWTCU4J96CbTcsH2su1xERbvq0eLm0xs6dMpeqFyiZ5IMru+z4zrb
         V+s7Y+6ObX9g68/LnvLa68OrfFRvhERhGZ8I/xeqNe4AT9WAECmVeMTYUBV/+dwtpyr9
         aIZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQzG9oRP;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pijhLrBoHz3XSY2tmMaEEnKPO08ZGUBuMU8IAGP1a0w=;
        b=Aot1HN7CNwoxMeyuPDK5IUYs/15amyYd77Xi+Z1w3EyhPF66Lfuu18Fhd40G0F8cNQ
         s0HafzlXERSAkb/lKaWbb1Y00IkGFy8/K8zfmdZs6AmOPsLKHhUVG5l2rwE16LcpL2La
         kzS+qTexP3KBu7TJE+QQ9DIl7vGW3lLlwVi+j9yo55af4PkCXRSPxdQdoXUTtpOaFV33
         IskdwUUonGlwK5b7hc65P0M4TNPUHwm0EIwvbX/+CwiVIipFCu8KtsIEs9l2TqR+vp3c
         LTVwHHeNX7FJX5TVNazXvzHv9w+qqaPvf97mKlTdXW+tXMnE5pHn6d5/MOaUN5w4Budq
         c95g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pijhLrBoHz3XSY2tmMaEEnKPO08ZGUBuMU8IAGP1a0w=;
        b=Xcc2LO7ZmKuw22yeWozYUVmxGvVpVZCFMS4lh/tlSMoJUJF1RaFvmQFwwHQq605aIm
         AFHom7mH0tC6klFyBghIyGwvwlTev1fxRGVQ2uRVFC+1Ul+Jv7KX7Y2hTUliMErpt6Wn
         7D2sJ9CojsoWtoSmGaUL4CfZFBYW50TiFwKWyoo5v+mdbvwTnMlUrO2PMRURrrwWMJcJ
         VAgJeY/U304zhhuVPDNCbiduHiFMxUxKlkTmgKL8tb9SfKAgXqIl6F0ua0BBp7t9KbYi
         klFvhGO8gPq4BGD/vvO1snJPzhPbtKEjngp+tJR56NJvZF1ZDLa0LviiG08xR7Bmhz2I
         s0oA==
X-Forwarded-Encrypted: i=2; AJvYcCUlgp0CIIQ7FHppgHQJ7n2N3y2s0kqxs8qq59BMFpk4LrG69ToXV2Mgs55nvCyDAH3XxkxCqg==@lfdr.de
X-Gm-Message-State: AOJu0Yx52JWVVCthzjAGbepOqURUdwHpfN+u/8gxbCwqDAkJVoj3nfnM
	P4VIH2y76u8spJJEtmzA0e/R7JyQvfM0c/KwSJWBCCtzZS1kUkw10EFr
X-Google-Smtp-Source: AGHT+IFiPUp27JmqDtqfyG20aCg9fSc9Goc8QQ477VKx6bJitViwpM1YKzI3pxLf4Yj17Pgh5E0XJw==
X-Received: by 2002:a05:6e02:1fc2:b0:3da:7176:81bf with SMTP id e9e14a558f8ab-3dc9340976bmr18149405ab.21.1747975182824;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFhib/wolqCSZErHDp8oP2mwt26BQ+CDEvnQ3LWz0rKQg==
Received: by 2002:a92:c5c5:0:b0:3db:8425:8106 with SMTP id e9e14a558f8ab-3db84258317ls38742795ab.0.-pod-prod-09-us;
 Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnrt5C8ZpywXmv7UiUXCSTRZDQxbh8TXGRvyPLLnU+mWL9GebMhspk420pUAoJiuJRXQyMRZCFdsc=@googlegroups.com
X-Received: by 2002:a05:6e02:160d:b0:3dc:8bb8:28ba with SMTP id e9e14a558f8ab-3dc93243f22mr16450895ab.1.1747975182019;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=fvIpIlaEtk7Whg+jKEn7lPp7lfMT5XY9Dxg0HUqFUTTXgfGUAqx5/jDONu4IQAyz2s
         /oN4QpwIelndYX+VkWt4QqQCK+S6y10O7XmS7J0IvqzOft+JR3TJL8dypVVHKSQIIfGY
         yZrbyv/d5rsYRK3zIg5yCoB/lnbOR31DurqulhQGOrzTqOZ44+qgFmynkDB7RE1l/9o2
         I9X0BhTxL3QcODO6/MMsNLXSB6rFWv6DLWG8FkO3uoI5JraASTJ2JnzpvmA+E7O9NCT7
         enAWRAELGmFhlqAfHfXpC1Coa3+5evHpTAamwPLiSUa+WqxLtJjBDNPjHCKDF9cRmt3s
         q2JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C8D4LxVY5xiBAnCpq4qjYfypcmK3R7vRmG4YyK+yYkI=;
        fh=DBjMUvVbzKqiBek+GyZd/kUF+B852LvKe56cttuSZt4=;
        b=QbAtbup8PygdBGn/3EgFsxnWE3sIHS3FH8gNScX/DvAxW+UXi+6Uu45zz0Ca+tZF/l
         d0L5XY9S8wKksMsg5LnglhXrSQP/L3d1lKMpvgUq/tq85+iPH3LvvQNWxnTFyVPBd7go
         +B7x25ehZ2pfcg25JUl8J5fbuekNdCuDW9L3WZoiRWhdFr6tn26vupKTiLmDp3Rg7JJf
         WtCkPdfmmic9wTfgEwFafGb0Y1EknGSvZXcdRvrgQ+XKULoRvtS8xw7AQGwrcpytHkyB
         Btzq6ROSeRf++Rr52ci6YX7sE5Dvkj0Suu6CCUxgpJXFzYa3qapN+7Ox1HjeJVQ//S6/
         P8nQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQzG9oRP;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3dc839ce3dasi122445ab.0.2025.05.22.21.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 73C0062A6B;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 382C3C4AF0C;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
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
Subject: [PATCH v2 11/14] init.h: Disable sanitizer coverage for __init and __head
Date: Thu, 22 May 2025 21:39:21 -0700
Message-Id: <20250523043935.2009972-11-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2887; i=kees@kernel.org; h=from:subject; bh=9V+bffTinVGVEjmw6TF+C5G0YfQpy53YZa3Wm2q7aj4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v39z3tX005Y/rnL4YOLkChWuJ+9Wl0ZxtHAnf5w+4 +zlC8f3dZSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAEzk8SRGhsnn/rn8m/7L8JvJ sSfzOhSq+TU4fvE+u8S/Metrj/ZaW1eGfyYVhxIUl7qsrup9tc1w3of4xW0amTu32l3mnx7BlO2 twQEA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CQzG9oRP;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
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

While __noinstr already contained __no_sanitize_coverage, it needs to
be added to __init and __head section markings to support the Clang
implementation of CONFIG_KSTACK_ERASE. This is to make sure the stack
depth tracking callback is not executed in unsupported contexts.

The other sanitizer coverage options (trace-pc and trace-cmp) aren't
needed in __head nor __init either ("We are interested in code coverage
as a function of a syscall inputs"[1]), so this is fine to disable for
them as well.

Link: https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcov.c?h=v6.14#n179 [1]
Acked-by: Marco Elver <elver@google.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-11-kees%40kernel.org.
