Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKMTQ7CAMGQEVLZT5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 67C56B10010
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:50:35 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-87c30329a56sf142085239f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 22:50:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753336233; cv=pass;
        d=google.com; s=arc-20240605;
        b=e9wjfn8qnEU88wYhcaS8ZAol7mU8fkaUhMdCdNYyMAkjyGSxBUPiHdej5bMLOtDf6v
         Cei0qYr2FTznUnlwEs5s8nnTgyQogmGH78RF3aoX099p0lTdGCZ1hrRKY6G7sh+Tgqi8
         C6P/aRZ/fvOMQXhk9v1KfVacC/9ULVGv+hI1TTEvBKJVRr1M96Ltr2dxTeVI9L+JzJ6J
         qsM6+lNuR6upow6MLj83CbvT4jWGoaVKjTArJ5kEmWsIoOuGN8XI5DPCMLIy5tnQWXit
         7X2xnjAE7yNLD4FabMBCGMldEvcCYE5W64YcrDyP8m9crZeQcB99Vrsg3Xr6+QVPwWuY
         Z9nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XJ4KHtMzULTdkc6NYNHDXnc2xrXRtWXb+CJOkqpt+9I=;
        fh=JOuYPzQ4MoONCh+nyEjxlpjG8DeWnk/aLnAwIIOMRIM=;
        b=WDQI+qiLuUp6xkH5PE6XEYxXto4SighdMeWZM/QAHAXdtYA0gics36vuAcr3yr7xNB
         i50/3ATAO6BjHIUrDsW1jStadyDvzApAnOrvt+RgrVPTuV93FuQiLhju1XkeV4tqiiUt
         BzoFaP1oeIfq8y+aXoxqky7cygZZEjP+8Tv5A3WuiSctwHFQbK1ohHoCilPfIfUvggyf
         DOGeDJqtaEKe3+TH9hUwrhBJdklJe+URn0f8l1fdtb8u+YZ1oZu+Ad07NYheZbJM97Dx
         Zu/sfKBGTebeuUIhKDXPF1BqkUuYxhgDN+RJ5HorJkSMgvL7tYAjVtYL3drr+5J0XXVy
         SkFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ooTp5DYa;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753336233; x=1753941033; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XJ4KHtMzULTdkc6NYNHDXnc2xrXRtWXb+CJOkqpt+9I=;
        b=E0PJk7mSvc3UbiXTnjLe7MKb/d9gyWPf1X5/cBrnCjSoE21ULYDUHfuMgvAI4t2Fc7
         jQh7pqrLzgYnzItW6Q2iXop0NVznPcezQ9XgO9qQAApzSD2/FDCzYrWeiseqX9/DxT2t
         943TSEFfAL6uFxhfMr2HHE7s9Mp3fj/3+6iI8Rql932lNQjsJBMQ6W9WsujCxebDsp6b
         s2H7MtCE2zgqGA19lZBASzdud0gk1S1kDk5ecwNd94WPt4CQynvuPVOinPftNFSo985R
         x5P9a8uSADNgWnfHmpqupO2GzQ8e45awqXJcffBfJQgQptGrOuOuIS9dHY5gDIxpAKDH
         /4/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753336233; x=1753941033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XJ4KHtMzULTdkc6NYNHDXnc2xrXRtWXb+CJOkqpt+9I=;
        b=HxIaERx1eGGsUEDq4+LY/FJub5kKjxtt65zhftUG6fSyjfh5fyMDwRWAwTMwAo8rxD
         K0qFcQ6TPOcmcKilA3hDlVIwpreC4OvUGIGwnPpf8GG3GOcAxPuO2PB0l0HFeavsQ7um
         IOiBtSaUVb0xx8EY7BfhYCc1lN6xjCXQUiBFswFY2VqIH9CpT8nTb+CJ2uXR5EkLAWrZ
         X8iGzim47PbWLuZ+abwmSkM1BFGun2fiyFPxbdNoFOD5iw/UpF+9XkpW+/d3ElVzguw8
         2YvWjw/qTXnAZ/eIDjJxT0co35nqiB+XnoZxcFTb9UJezscfVBP1PqdbPuqFaguJmANy
         Yf3w==
X-Forwarded-Encrypted: i=2; AJvYcCUiD28Tj3vPkbIPMfcRgh5nsDw9dm9e/3Z39tx3WK7fsIb3sg7WfrTbVx36k2k2gidWOqC3Rw==@lfdr.de
X-Gm-Message-State: AOJu0YxJNqy9C4FeRsdMPwEhgCgNUtBvqNq81F+R6cavxlLkz1ga+Ap5
	Z4q8BOHYmPz41lO6n7yYOkg5ADwpsZakuW02JOq+9sYOHvYBusYxmajy
X-Google-Smtp-Source: AGHT+IHLb9szOL/8Zra41oPH5r18tD/B37gNFIdiv2LGrxtkzagwV7Wsoptj1SHByvx1zkMNdeIVPg==
X-Received: by 2002:a05:6e02:1c09:b0:3e2:8b58:60d6 with SMTP id e9e14a558f8ab-3e3355800bemr97900895ab.12.1753336233510;
        Wed, 23 Jul 2025 22:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd8iyW06hV2uPwwBJ/ZS9mxKuJVvIXsfnSzq0RwbsJ/Wg==
Received: by 2002:a05:6e02:2182:b0:3dc:82ff:ca6b with SMTP id
 e9e14a558f8ab-3e3b4f8d57als7905835ab.0.-pod-prod-05-us; Wed, 23 Jul 2025
 22:50:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeviC1hGs7wFb2q28OAUN3XxDH67wmwYsHftV+pVnh1MBGtA5rm3nBMH9KOBaWXqBtp0sbEaTFVPI=@googlegroups.com
X-Received: by 2002:a05:6602:1501:b0:87c:45c2:7170 with SMTP id ca18e2360f4ac-87c64f66d0emr1249672239f.2.1753336232692;
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753336232; cv=none;
        d=google.com; s=arc-20240605;
        b=Y9fKIVHGq+BGZywiNUszp3a7n0PuiS6vrBd4MYxrXS4763nTKaWdGm/3Mr01rBQgO2
         F5FIFttGIgFDR2/pCWPHS4dhUFovEbw4DwlBqS6inmt0n5n+MGzjeG80V4XYpzgliqoi
         pS9GKprOjDX5VCNW+5DFiLc1WTJrU8iKwBH5SWjJNUSnIyGE7W3KmaxqSAWMLIyZMABz
         5wU6QZVbYqnkXl44ycNDeJWQfreCfGQ/LjGP5jEx+I5JSaAv0cp4tAZoVzVrQ6BNy5u0
         wJvBO48fyVkaE/BLLIj45SUFp537CTzmzI332XNS63JABmp9vta8xUZMSFUSYYCPlWK3
         kGwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C8D4LxVY5xiBAnCpq4qjYfypcmK3R7vRmG4YyK+yYkI=;
        fh=9ECjMzqIA7gVldZLWzC688kAmAqHqxFXRS2tru8KaIc=;
        b=NMdge24wdBNd3tpdkrgrPFIrombDkc2J1qcRfGv6TeS649H+Alrhgi+F4HGd2cNwf6
         vrYICDg7uDLBo1j7kqDbqwth9IDUvE3cGp+rOKfrfCCkIVEBcMWJlhnNbxjPgVgW3JAu
         WdwJTx7OY+dfMYE07qjn09KdkEWaku7AhWNd/5HnfoQF0fPHpD7erqiMVdPwKYvNt8w6
         CZs/QSVqF+7uO+pG0Umb0OMok9XQQ+fpgQVhEBCbFVNn7g/z7paOPCFCRoDLrEnwMNOc
         GVT4Vd6GRmWxq2IW89HF+wxIAttcmM9x7vRxfnOeWcaIbguMQvwABw4wkk/acZ1Y1tGs
         A/gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ooTp5DYa;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-87c7430cd70si6009039f.4.2025.07.23.22.50.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1FA8E46587;
	Thu, 24 Jul 2025 05:50:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 97F08C19421;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
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
	Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Mike Rapoport <rppt@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hansg@kernel.org>,
	=?UTF-8?q?Ilpo=20J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>,
	Brian Gerst <brgerst@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Andy Lutomirski <luto@kernel.org>,
	Baoquan He <bhe@redhat.com>,
	Alexander Graf <graf@amazon.com>,
	Changyuan Lyu <changyuanl@google.com>,
	Paul Moore <paul@paul-moore.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Jan Beulich <jbeulich@suse.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Viresh Kumar <viresh.kumar@linaro.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bibo Mao <maobibo@loongson.cn>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvm@vger.kernel.org,
	ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org,
	linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org,
	linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v4 3/4] init.h: Disable sanitizer coverage for __init and __head
Date: Wed, 23 Jul 2025 22:50:27 -0700
Message-Id: <20250724055029.3623499-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250724054419.it.405-kees@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2887; i=kees@kernel.org; h=from:subject; bh=9V+bffTinVGVEjmw6TF+C5G0YfQpy53YZa3Wm2q7aj4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmNJxdz3tX005Y/rnL4YOLkChWuJ+9Wl0ZxtHAnf5w+4 +zlC8f3dZSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAEzkYR0jQ3OLrmDdCpsGS/2v XwqtbKYZz2RJ7Lh0a141x9MPJVGnpzIydBStU54v9Wp98GqlzKdyYSda/YzleKsypsy4O3tZzgI uBgA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ooTp5DYa;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250724055029.3623499-3-kees%40kernel.org.
