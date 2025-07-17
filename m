Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYUM43BQMGQEXPFHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A90B09747
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3138e64b3f1sf2035136a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZM42iXgc7Iz3iTQku0lHlXDC/qQObLPptVVGyyHU8w3ti1V8O5OHN1cEWWShLqdo9i
         9xHZYTK0vsJh7DY+fIeOvJsa8rHtHsSjG+YdDO/8ZZ9qT3PYBSNc0VhX7qwoZw5dpAaY
         gMGy0RX8TTgOIQlKqKnkuW9GH3PSpjfJAUtzQpbyGCX6IfiGjfIBexO6SZ2a59IHbjlG
         2DDPTnLwPoJjLR0GO+R+h7xdKIosMh1qlWaS/98TPB4qTUp7h9opfTz8HNvEEvYYoivl
         9guxHtXib+wN/T3OG3WRToqFiIMjAlmZypa6L8V63ssWYXtLTwP5wCoMuO5qKh4LbLif
         /5Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=3m6AvSVP79I5JQxhSESGrgRoA+/Xj6QC92NnDLVFYtY=;
        fh=pFoidd+PiHZFKuGzVfUcb7gON6KvR6dLB7DZu++GA+c=;
        b=QWb8bbWe20ie1VBnw/PwbcAi7s3JDYI5y9MpkPZXftUy6m8pjXW4NtLbSJ8HAg+jO0
         +8oL9WhDmRHhRmbTmxPBOw7k/500ItzHQ41PKM0w4vlRdf7xyjYLXUTHZeFM1HRBbtpE
         vE9AP92lAzn6l39wLjrdnsLK4ZxsQQB6i8FtqXGHczunqMRqHqbfXVMUvyl8dfrpRF2K
         qLOxfBtPk7PnKeaccBDy73oue8FJ5otgfb8Y+U/xqmiTxFAThDzrAHUn4qvjpky7rEna
         NS35g9tEs+oQvnKJx+WJrgCy8TBnZy0t0uHFMxmEvVwGJnmv4axBJma3VucretIfzZR/
         1BZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TRbkjAx4;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3m6AvSVP79I5JQxhSESGrgRoA+/Xj6QC92NnDLVFYtY=;
        b=N8QrOKPF9MiP9YYeBALvUegW5XnriLFiIv00Srkq9Ek4CQkp7BEdFZpwsLLgrURoKN
         /QQw8+z0mj5SXJm6G6qB8MPKu4B0oYY3bCYob31EZkhh4bFfolCVAGYCWaA/yYZP5KJ9
         JEx6p+8evjJQlIH9Mwj2B8t2T5S4j6McABMNr3CnmNoowHpr85Gp+7omcsj3e7vyl0/j
         fUqRB8Rmw3nQ93TdH07aKQKlUiKpvZJc0dpabJzFKOuLX/63KX3QRH7B5AmjYtzTH7iv
         rDGbotiBiLu/JADuNAxt7gt6dlGEJU1j0As/5/9WXeSCDi5zXZuq+9CZShR6IhdvgpdM
         6KCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3m6AvSVP79I5JQxhSESGrgRoA+/Xj6QC92NnDLVFYtY=;
        b=Md4mnPo5SVMvovuyqFgwCirQac1GEe2j3mdwDJn2EiCDoH/kMvMX6lsbqLHo+hwkuj
         tmUcP3IbL16ai7SH4ny0Fd/Mvffrhqf6KMxDwvRNKNfR5dDjHLlqOCqM7URP4gCkEBzs
         9+INMNrEIx4Ii9S/eV7LbT0Ur3KDgUVpAmM5Efl4keJydlatkbDnfE62q6tXoR74Iyb5
         /vpCipUFC5rSbvUZWWpJvl3sfxg/bY9dSy0mLOYW4PPCt5HimJ/NYfxxguvdSqVr81Nc
         SlZNbMrjaLlqDCCza5siFSVjTmHgS7V1OfZN4m8SqOopyPY3Srzc0Gk3BUztgStS40kY
         I5Ng==
X-Forwarded-Encrypted: i=2; AJvYcCVbGobrlG4oQ9lxokktXvT5GMMh7ylIfrErZrd5oCE91sW6oy6N+cQk8fgOGpb7xjLC5rhEYA==@lfdr.de
X-Gm-Message-State: AOJu0Yy50IfB021JRccDy6egirFyui6X/6DJU6n/Kp/0rgU0n82mAMVu
	q7gJ3tW+DtvUdvRiraYhQNemDRdA/D3zW1d3GcVFNOEXre8kSaJhFk5L
X-Google-Smtp-Source: AGHT+IEPBtF013gJfkNQB4v71BFegrAkF1ZlTvtFVAPIIZIOv+aOOlXsqdndlZg63pSlB6imuiYy9A==
X-Received: by 2002:a17:90b:2dc4:b0:313:62ee:45a with SMTP id 98e67ed59e1d1-31c9f3c5de9mr10454965a91.13.1752794723190;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcuknZNp1Fcmg1LpyTVp6KbrwtsEdHqNHPOozxdMgYhEg==
Received: by 2002:a17:90b:1c86:b0:315:d222:ae43 with SMTP id
 98e67ed59e1d1-31cae5e52aals1408035a91.0.-pod-prod-08-us; Thu, 17 Jul 2025
 16:25:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCLiwsXko35OQxLt+t1XIz2z7tECrQb4DyvTPK0LAMk37gzE2BY5JmD55X2MgZDkz3lNrbrKk31l8=@googlegroups.com
X-Received: by 2002:a17:90b:2b4c:b0:311:eb85:96ea with SMTP id 98e67ed59e1d1-31c9f3c5719mr12324432a91.9.1752794721564;
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794721; cv=none;
        d=google.com; s=arc-20240605;
        b=YcsKV1L+A+xj4jLj73dNduN3Ek3tZO/j6exhRJwazwGDqIRq7RJ36HP//7/FRSzeiM
         GHDmFP3iOvdDS3axYZzLkVaa6Z+uMpXEerD03RMEEX/ighZj1H8vJqT52Xaqr2gEmbl2
         bm9KJ6bj7JxY+IGlgzqnksWy7wG5i6WjzH4dgj8IfxGqAPSLmgVr1sNmrr056VcdYIEn
         MaC0jGXonNit5O//4swj7azuv5a120Ak6ksSU7CFDS/3QfN7xgaDmP2EtRTnUd2tENhK
         2+b1SXcfrfnjKsz18WtH459AbTcFp8rbVpHbD+bPKyj0slqXsFwOHQeAjZsNzY05SAl5
         /71Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mGiAm0MDZ/znPl6KJ69cPmxAT1IBWppn+gQWkQ9EK4U=;
        fh=XfLtiBHEnhX+gh4iZUx9qr7sf6+19R9OjRN0L5s4YTg=;
        b=ZBdyQBXWq5ZmgGxm5od7rQ63lbP3QvkIHFbLkNXGXmLzD0gXhpJTXfFHPokD45pS/z
         7hCQRK3EpQtUF5M1O51r7kQn0SsUkdG6haYGDXF4Bg4e/0O3ZWwEfvUSeHNKiUosY5J4
         SHovbKFg7b9Rvu+9Sa7cR6Q9XE/s2XspMIkAPxu8SOlxRRiscVWVds6IFOIomXYIVr6y
         tSCwL0+MFv/Oer6B4Z1wB9N7YvUSD61r5sa7Xh1a34kqEbaTpM7U2WkZwWA+vlO80CwY
         8QI/plGRYNcV7FslacuX8IA+1AUKX6mD8zeLtBq+eAc7gH9tWCsp8iN3tZM6UvlzAQ6U
         Y84A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TRbkjAx4;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c9f2575f1si196140a91.2.2025.07.17.16.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 130FA437E2;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 50E03C4AF0D;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	=?UTF-8?q?Ilpo=20J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Mike Rapoport <rppt@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>,
	Brian Gerst <brgerst@gmail.com>,
	kvm@vger.kernel.org,
	ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org,
	linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 04/13] x86: Handle KCOV __init vs inline mismatches
Date: Thu, 17 Jul 2025 16:25:09 -0700
Message-Id: <20250717232519.2984886-4-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=7379; i=kees@kernel.org; h=from:subject; bh=h6Zg7bnGhZLJl7gzBxEvRrK024ha+iznbtZZpACm6QM=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbVEsBUWRs14v3rd2ZcSn8mMh7T+55X5XTfK6NfVtU nnon9hnHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABPx6WT4n2zhIJZwQbqtV2mf gj9/g5L3r9WHjHc+Olf9QXTtxJXKZYwMuypdt881O3ZGS1GRa0Flo/olSxb117FqYnc5ylXOiL1 mAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TRbkjAx4;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless the
__no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved. For
x86 this means forcing several functions to be inline with
__always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: <x86@kernel.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Paolo Bonzini <pbonzini@redhat.com>
Cc: Vitaly Kuznetsov <vkuznets@redhat.com>
Cc: Henrique de Moraes Holschuh <hmh@hmh.eng.br>
Cc: Hans de Goede <hdegoede@redhat.com>
Cc: "Ilpo J=C3=A4rvinen" <ilpo.jarvinen@linux.intel.com>
Cc: "Rafael J. Wysocki" <rafael@kernel.org>
Cc: Len Brown <lenb@kernel.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Michal Wilczynski <michal.wilczynski@intel.com>
Cc: Juergen Gross <jgross@suse.com>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Roger Pau Monne <roger.pau@citrix.com>
Cc: David Woodhouse <dwmw@amazon.co.uk>
Cc: Usama Arif <usama.arif@bytedance.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Thomas Huth <thuth@redhat.com>
Cc: Brian Gerst <brgerst@gmail.com>
Cc: <kvm@vger.kernel.org>
Cc: <ibm-acpi-devel@lists.sourceforge.net>
Cc: <platform-driver-x86@vger.kernel.org>
Cc: <linux-acpi@vger.kernel.org>
Cc: <linux-trace-kernel@vger.kernel.org>
Cc: <linux-efi@vger.kernel.org>
Cc: <linux-mm@kvack.org>
---
 arch/x86/include/asm/acpi.h     | 4 ++--
 arch/x86/include/asm/realmode.h | 2 +-
 include/linux/acpi.h            | 4 ++--
 include/linux/bootconfig.h      | 2 +-
 include/linux/efi.h             | 2 +-
 include/linux/memblock.h        | 2 +-
 include/linux/smp.h             | 2 +-
 arch/x86/kernel/kvm.c           | 2 +-
 arch/x86/mm/init_64.c           | 2 +-
 kernel/kexec_handover.c         | 4 ++--
 10 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/x86/include/asm/acpi.h b/arch/x86/include/asm/acpi.h
index 5ab1a4598d00..a03aa6f999d1 100644
--- a/arch/x86/include/asm/acpi.h
+++ b/arch/x86/include/asm/acpi.h
@@ -158,13 +158,13 @@ static inline bool acpi_has_cpu_in_madt(void)
 }
=20
 #define ACPI_HAVE_ARCH_SET_ROOT_POINTER
-static inline void acpi_arch_set_root_pointer(u64 addr)
+static __always_inline void acpi_arch_set_root_pointer(u64 addr)
 {
 	x86_init.acpi.set_root_pointer(addr);
 }
=20
 #define ACPI_HAVE_ARCH_GET_ROOT_POINTER
-static inline u64 acpi_arch_get_root_pointer(void)
+static __always_inline u64 acpi_arch_get_root_pointer(void)
 {
 	return x86_init.acpi.get_root_pointer();
 }
diff --git a/arch/x86/include/asm/realmode.h b/arch/x86/include/asm/realmod=
e.h
index f607081a022a..e406a1e92c63 100644
--- a/arch/x86/include/asm/realmode.h
+++ b/arch/x86/include/asm/realmode.h
@@ -78,7 +78,7 @@ extern unsigned char secondary_startup_64[];
 extern unsigned char secondary_startup_64_no_verify[];
 #endif
=20
-static inline size_t real_mode_size_needed(void)
+static __always_inline size_t real_mode_size_needed(void)
 {
 	if (real_mode_header)
 		return 0;	/* already allocated. */
diff --git a/include/linux/acpi.h b/include/linux/acpi.h
index 71e692f95290..1c5bb1e887cd 100644
--- a/include/linux/acpi.h
+++ b/include/linux/acpi.h
@@ -759,13 +759,13 @@ int acpi_arch_timer_mem_init(struct arch_timer_mem *t=
imer_mem, int *timer_count)
 #endif
=20
 #ifndef ACPI_HAVE_ARCH_SET_ROOT_POINTER
-static inline void acpi_arch_set_root_pointer(u64 addr)
+static __always_inline void acpi_arch_set_root_pointer(u64 addr)
 {
 }
 #endif
=20
 #ifndef ACPI_HAVE_ARCH_GET_ROOT_POINTER
-static inline u64 acpi_arch_get_root_pointer(void)
+static __always_inline u64 acpi_arch_get_root_pointer(void)
 {
 	return 0;
 }
diff --git a/include/linux/bootconfig.h b/include/linux/bootconfig.h
index 3f4b4ac527ca..25df9260d206 100644
--- a/include/linux/bootconfig.h
+++ b/include/linux/bootconfig.h
@@ -290,7 +290,7 @@ int __init xbc_get_info(int *node_size, size_t *data_si=
ze);
 /* XBC cleanup data structures */
 void __init _xbc_exit(bool early);
=20
-static inline void xbc_exit(void)
+static __always_inline void xbc_exit(void)
 {
 	_xbc_exit(false);
 }
diff --git a/include/linux/efi.h b/include/linux/efi.h
index 7d63d1d75f22..e3776d9cad07 100644
--- a/include/linux/efi.h
+++ b/include/linux/efi.h
@@ -1334,7 +1334,7 @@ struct linux_efi_initrd {
=20
 bool xen_efi_config_table_is_usable(const efi_guid_t *guid, unsigned long =
table);
=20
-static inline
+static __always_inline
 bool efi_config_table_is_usable(const efi_guid_t *guid, unsigned long tabl=
e)
 {
 	if (!IS_ENABLED(CONFIG_XEN_EFI))
diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index bb19a2534224..b96746376e17 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size=
,
 					  NUMA_NO_NODE);
 }
=20
-static inline void *memblock_alloc_from(phys_addr_t size,
+static __always_inline void *memblock_alloc_from(phys_addr_t size,
 						phys_addr_t align,
 						phys_addr_t min_addr)
 {
diff --git a/include/linux/smp.h b/include/linux/smp.h
index bea8d2826e09..18e9c918325e 100644
--- a/include/linux/smp.h
+++ b/include/linux/smp.h
@@ -221,7 +221,7 @@ static inline void wake_up_all_idle_cpus(void) {  }
=20
 #ifdef CONFIG_UP_LATE_INIT
 extern void __init up_late_init(void);
-static inline void smp_init(void) { up_late_init(); }
+static __always_inline void smp_init(void) { up_late_init(); }
 #else
 static inline void smp_init(void) { }
 #endif
diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
index 921c1c783bc1..8ae750cde0c6 100644
--- a/arch/x86/kernel/kvm.c
+++ b/arch/x86/kernel/kvm.c
@@ -420,7 +420,7 @@ static u64 kvm_steal_clock(int cpu)
 	return steal;
 }
=20
-static inline void __set_percpu_decrypted(void *ptr, unsigned long size)
+static inline __init void __set_percpu_decrypted(void *ptr, unsigned long =
size)
 {
 	early_set_memory_decrypted((unsigned long) ptr, size);
 }
diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index fdb6cab524f0..76e33bd7c556 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -805,7 +805,7 @@ kernel_physical_mapping_change(unsigned long paddr_star=
t,
 }
=20
 #ifndef CONFIG_NUMA
-static inline void x86_numa_init(void)
+static __always_inline void x86_numa_init(void)
 {
 	memblock_set_node(0, PHYS_ADDR_MAX, &memblock.memory, 0);
 }
diff --git a/kernel/kexec_handover.c b/kernel/kexec_handover.c
index 49634cc3fb43..e49743ae52c5 100644
--- a/kernel/kexec_handover.c
+++ b/kernel/kexec_handover.c
@@ -310,8 +310,8 @@ static int kho_mem_serialize(struct kho_serialization *=
ser)
 	return -ENOMEM;
 }
=20
-static void deserialize_bitmap(unsigned int order,
-			       struct khoser_mem_bitmap_ptr *elm)
+static void __init deserialize_bitmap(unsigned int order,
+				      struct khoser_mem_bitmap_ptr *elm)
 {
 	struct kho_mem_phys_bits *bitmap =3D KHOSER_LOAD_PTR(elm->bitmap);
 	unsigned long bit;
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250717232519.2984886-4-kees%40kernel.org.
