Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id B35B4B09748
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3141f9ce4e2sf2090217a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=XXt8GCD7HoOcqcCggzq+gkdy920/uqI5a+kIrbF59fTbTFc6FKpaRIZovo5fMviIAi
         L7TNhTkJxjGFjKgUxG0QxSYLwrADpKNC5BwbX297UvKDMY2p6ipb6ANzikdE/fv2GcXk
         kuoi2o0mzg3YY8tAptWMjWkss4twiysxLb4PQmC6qhV4QOxAgRfWEUGZffVdHCdgD7ci
         MIM0/MnC/ZnYcu1LJvDykk37cEJUX7lBTBMseygyI/c/8EL08m0YqjL+GBD4PPlFQ/xt
         3QevRvsxcAZIvld2Xq2HugGRSPrYEisacvFsPTGM1bXYgz2cfDwOkZR3Q0vf2gqUwY/c
         JzwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tD3rxPhjlQYcWDjIJ6tIbTY3OkBUpW+4mcY+tSZR2SQ=;
        fh=P7Hk+NGQfsJLAon1Q20+QfqieP/zQyNCjiBZe2Wdafk=;
        b=QWEWqyNmVSMQOa9Bz9zrAQHrldlVg5PWtU0bHL1AMxmHWXhqUs/wGiTIDcuq6mHihW
         73gNRl7wpisWhaL5LgOlCZ5XrKE/hSh1X7pEYDSgeyPyl+8wQqfJJWJ9E2YCRgR9cilA
         TCWuQCl9s1vQ2OoBbEDXmZLwImMplWM/2LJiQCLO/ul5KNpA2rADb7WfvpfB/8YAOF9s
         JnUMPF5RvNvlxeJDsQ+1KNPqmUoAr83RDEvrZiCg3Bmubx32zt290wt++GaAchtF2QJZ
         qbNsxx97DaKQzzv0HsPjJp32PvXEcU9PnC9QphlNp4JxG+xcterXnRuNpHN2vJJGmOfl
         R0Ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gez9+rF3;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tD3rxPhjlQYcWDjIJ6tIbTY3OkBUpW+4mcY+tSZR2SQ=;
        b=p0FKJ1tdbzYeIm6IKMTRmEbVTqdTBlDvZX5VnJin/J7lwOZ2D40RgKW1ngbbUwwoCG
         GPLM/DAbi2JaWvF4EHDFz50loSDAL/WA+Dc3X02+01KmimiMtHNq5ETV/kDrnG0I0YTq
         EeoUz3+VH0+KNv8w61rZ01Hcr0DPfL51WIZc0kjZ5fyS4BV4Kwtlb9r3xggNb6xNOCHA
         SKW0yX/H7nWdAC/7d+YJbRbSTFw6raWzyIH3Mzs3gqJJ4GCS7iRBilto3SDo0UyJlUhC
         7WTN2/Rv8Z1ESuQSBfXos8TWN/wHo0dkc5xOqwi04UKy9Z2O6FR8fFFTDi3cSZMrh0r0
         9xyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tD3rxPhjlQYcWDjIJ6tIbTY3OkBUpW+4mcY+tSZR2SQ=;
        b=LMRtdocsDrUP/qMcJgSNG/fAqF1YfJKOhgv7UX6hLZGEGE8NwCil7L2Y5CYgw1/xsH
         zqpuqoBAQMoFfLs+I6RzGrJyrYD0nDLIyvVlhE+EhEDfcCwqqNzVGaWmrLyif9HawgfT
         XOqspsZcYUNU5nJIqCDko4UbdphLV0fZ3a9bcaXRN8/vsaHx4VVZviOaUBM7YLyjU844
         URsubPxM+N95oG9VOKdVyUX5z89zvIXeod04C1/gvIeVQTXOsy3qGJrTk8t+DiEqAgW+
         crWYTh6nQXiR2t9+Baw4cxWLe7WGfC5O4E+2Shd/mTM4aaQy8jmE9oWwUIKqostYSoZC
         j7Ag==
X-Forwarded-Encrypted: i=2; AJvYcCXRB4xKAUoVFZMwvOxdag4QEAZ/PnsL10zXrvUZwL4MYv04BBzuFBN5Qnliogyrq/iP2LxhCw==@lfdr.de
X-Gm-Message-State: AOJu0Yym9cmXmw1X3QXUGQaA/PfLLjVQTqORKFS/5t+882f2UttPOslG
	dU9wDwanioMgwZ7eTce1KjauLy5SFO17MGML35N+qQwjfsBdy3bui1ES
X-Google-Smtp-Source: AGHT+IEx4Ukubzhm1Ez9mAnnp5Bz6DsmX+dKMUCRzSvu+jMwzCwwdBswisD4/bOLcoTxqJmHh8TZnA==
X-Received: by 2002:a17:90b:270b:b0:312:e8ed:763 with SMTP id 98e67ed59e1d1-31c9f42412cmr10193897a91.22.1752794723420;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZeP3u3CZrspsXHKHXVlv/j8Y0qtmViRVvhoEupVb+kQ==
Received: by 2002:a17:902:e352:b0:224:781:6f9c with SMTP id
 d9443c01a7336-23e2eb38838ls10383265ad.0.-pod-prod-08-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHU+3ftWeCZHYuNOKk2sVjgsjoO+t5bXAHn+RZ9pP+ATlUhs520Rhh46if+53Fw1W1X1Hvj/bD26c=@googlegroups.com
X-Received: by 2002:a17:902:f68a:b0:234:ba75:836 with SMTP id d9443c01a7336-23e25693676mr103328005ad.7.1752794722170;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=IXjv93HQKUAI/d+R6r1XFXzVK2PzOB3hqZ7VqbYxVM7IRla0PyzDu9lg2Myb+XQSuL
         SA7YTKIyAzTAby6nZyKKKhEwCGP351yyBoE6kbRx3soGz+FnJHQGg3XsihBuO+NTuGUx
         UCJ8kdqKjbKYsq+Oijkq3HLljBfbdEEZGEI7Drwx+4Axz9ruFR2lJFhdE8nR6CeDvKP5
         y8OjYTm60wGsFdEzakTbXB2OeAF7sp6G4X2s1Dnc9j8+8E5xToHOlm1wW8Ce0ez4nkGa
         gD3JhnUM9P4tlwbfyeuZ7/Vh+sSp10IrWvEQX/t3Ct/Dc2SBfHJN2qO8foJQGBe+RXwl
         CaeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C8D4LxVY5xiBAnCpq4qjYfypcmK3R7vRmG4YyK+yYkI=;
        fh=4/iarCOhhLWOpbuOF6s87xMMHEkKrVzoj/R3kSDbwEo=;
        b=FRZNmV6H0dzzBvIwL+ZNC5NQQacEk9ak9y7HE6T68Y+Olf3+Q1ZpW1KkKRKn0uIYxM
         MwlvDTDbJj9DX1T6YMM5ABEqqnDoDYfMtqC8wgeMg5vz/s3fhLmdBqTQAp+wrglW3FM3
         NgROuC7GxmaCl1NZcH0HLHEkvimXfaj+1JDt+YrXBVUS0k7yJ0WbHlHX2z95W8WiEjZS
         FClYpiqe+i+ZspWzzfJX6x5I4/lvcQ4YgZZHgW9v0DwI5ei2ipRsSzG2J76VLVemmEc5
         BRMyNz6a+hdhdRqi5190n1Gvg1Hw4YnSWVc+5PjU6xVIBTvFn8U5ic2isAf4kwnAiKEm
         pbhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gez9+rF3;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c9f2575f1si196141a91.2.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 49BB745D43;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98294C2BC9E;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
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
	Ingo Molnar <mingo@kernel.org>,
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
Subject: [PATCH v3 10/13] init.h: Disable sanitizer coverage for __init and __head
Date: Thu, 17 Jul 2025 16:25:15 -0700
Message-Id: <20250717232519.2984886-10-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2887; i=kees@kernel.org; h=from:subject; bh=9V+bffTinVGVEjmw6TF+C5G0YfQpy53YZa3Wm2q7aj4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbTGcdzX9tOWPqxw+mDi5QoXrybvVpVEcLdzJH6fPO Hv5wvF9HaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABPZXMbwT1t6VfRt+waJrHcP M97sUJ2g32a/ijfzZfGnNs2MG/kxuxgZjrSFtfu+Ewq/KH3vrQuLOt+l1c0dXpwtCrXq7Ak7wmZ yAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gez9+rF3;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-10-kees%40kernel.org.
