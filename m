Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHYX7AQMGQEGK2GJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 060C4AC1B02
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:42 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-400a20ffed7sf422362b6e.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975180; cv=pass;
        d=google.com; s=arc-20240605;
        b=GwiIiEdNgAQrD6R6NtO6x8gzYV/S5XnxTr4K9CVSmmMWqhUv5sVhpe3TYNI8blZwWB
         ZiD4CbB9VmCsV+mJOKzBo+Ftw7qQ4ybyNGcKVrHvLdzxmv4XJ+9WeYpjIe6hOhQA9mU+
         6zxFPp550vpuXWxCBjZb6rcm1cWvwTheNqqnMe3rLL2G/dQrKLRUxl5ZMZ+ViZZtZhNe
         ut8sb0qEXForVnZGIOwCgGeUMbgBvLwAhlNxPbr5QdfT+xkrxJhQJiwvSJonXq4schnW
         jsGaXw1Up4srfRYN2AaEogbqmJFMrkPbyfL/WFIYIb139aGIARB3Pjcb0pWs8HE+9jgT
         bePQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=LX9GN7yTJnr4MsL87fEKcvBgfEiAxvNanbyyUe1dBKo=;
        fh=1Daz3tiLKIqqkl/E+6f6hkOxuV0KJpr+xkqJ60uIb5A=;
        b=LSbjIJGYQrgw5P9pfuDVmNXzVUheU3Kyg//ckDHKDoEsWpA1NKUh+H/9UhHngnL60L
         z43Q/7FSObkwk3AKDOgL/r0FSaQMExzCPRGyIFRGOgKHIH1WMp6T4ZsaiJjmoldYhYpE
         hjlCLpnucB5BxGIpazhisqH9j7iWSvs6MDDEP8bZawGgn8pyFKny1Dhj+vlspKioTym+
         tEKOW4KBfkm1GFHFBfrJ7yUU9OuM5HllzFfh4SGMMajydthmHtMSiSCfwNEtIHuvGn5m
         QvzPKRgoBZedFG6OHz6kxpe7J+NfC0LPG1gQIG2cmxgUC7CWKlTfo7wznZF1QUs3rkxB
         tPQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qlCKyVVK;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975180; x=1748579980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LX9GN7yTJnr4MsL87fEKcvBgfEiAxvNanbyyUe1dBKo=;
        b=L6AodSN2VZBtP5wVuE8MYF0C+bmNusR5hQC8O76Wf7+WeXmlccbSRSjAt+XErVawzO
         qE4TL2rT7bU329r4n0R2DF9873QLa9sC3zoGTmMV25Yl2eo+8ZohlcFLnEJKpf+PNGmx
         YNZ6wK/bHvB+vrNRar/ZS1gJY+t//C0vVtoILA6ZKy/CqOOdFkxh+HazsCNOHhAh4Ih/
         hgmL6q3cpo4VMuPHW+fT7nPLdtWOqK0CioUlwJ7wWRy4TwA3xmE91ZUOGGpGme7DLB2/
         UAZsMaDCYZM0r/zuDtaVot0WScUCqxB47GhqmOgWK/OGolHsJNQLQ2sj4JHluNzOtjbo
         mkuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975180; x=1748579980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LX9GN7yTJnr4MsL87fEKcvBgfEiAxvNanbyyUe1dBKo=;
        b=WDPdmD5Cv64N5d8kDxAKag6zKkrz6JArY5j8uH/8NqlYkb/Rt2reRyit3yEbXXRRCp
         n9NMF/RQ6kMEjgYQWhEaWYy/NMc+hxMZCg7v2F+tlkPwplvef2dYKJiORBbY1RVJLXeH
         m4ipdeIsJ1LHuvdslB1IXpM5qhHEzJZOx9Z5cytH+I8IKSBXS5c4uCUPbWr2fZsHuVlD
         AUYo0DiDKDd0P8QhN92eUOHQL9BeyRtR1BlFtSLEola7OpR1X+m7SRFNVGZcTYzWASuu
         59RJ0FN+HY18WWEHeNvhVNqLbPSbMMChO9rzofe1vFyFE8xsp9YwV6U48w+Ayj0x5XnX
         QQFA==
X-Forwarded-Encrypted: i=2; AJvYcCW2sG2ksqZsZ2Gqm6deStg0uUGzO7nGZxlSYdIBWorFPm5R4NWFVvFdZYJIdw7e3jCfshHFkA==@lfdr.de
X-Gm-Message-State: AOJu0YyxjgeAushEc3W/0IfaL9jmgh1XZMcObb3EvQnYRwheggkvx1Wk
	UfE1XRgxDZgxNr8juhkWcuUA2xEY5W2hAeoqB1+mx++tFDxHDsV9tpnb
X-Google-Smtp-Source: AGHT+IH3c+sUCmypvNXC5weNSbYMdAi/jWMsOGjnP85pA4wGQ+VO3HHD+VP5NNpLnVrcmYDrgup1Rw==
X-Received: by 2002:a05:6808:3098:b0:401:e9e:5042 with SMTP id 5614622812f47-4063d0560d9mr1461476b6e.15.1747975180359;
        Thu, 22 May 2025 21:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGOv5tIzaB82x66bRXyiCMgE+KIsvMi1Zr+pDksCJZWVg==
Received: by 2002:a05:6820:1a89:b0:609:efd6:e88e with SMTP id
 006d021491bc7-609efd6e8b6ls3213755eaf.0.-pod-prod-00-us; Thu, 22 May 2025
 21:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWI2sMqnYdifzGfeWxKDlPL1g3Fi2Pe7pxU6iiDdV4YhplCrD8Opn/i61W6OiAkaZEXqI1YYBM5YG4=@googlegroups.com
X-Received: by 2002:a05:6808:3384:b0:3fa:1d22:6d28 with SMTP id 5614622812f47-4063d058aa2mr1603209b6e.18.1747975179470;
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975179; cv=none;
        d=google.com; s=arc-20240605;
        b=DrneESS36Ic4bsTK4vpx0/TcvSWi4bFFxj0JeqJyLSGPjjAPJVmNQJCSH0YeBo/tQk
         1e9rIAPDDedM5eCyRcITupiwq1oW2YpMsvGd7ByVi8i+nnpZLtT1xodPKAn8mmOpCIGG
         pFLudNakjXx56Wrs3N7vdLZKk9qwV/TLnpqODCTzhIc1jCNK9jRAwEEKzTII9IELwYX0
         03l6DubbFfj2V1Ka6A2ByjP80Xxr/FhQjYp+tHZ8FVIOQYt3t2asX0AVNstg1b14Deqx
         eVSublE5WqQt6JqKjZMqBARqUB+agzT0NexqzFX+/GhJRONJRdhxFiKvAWM8H3C8+69A
         pKgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tjfvfIVeVuhN6efUDy77xTsKvPQ+XlcesPdymh1L3qU=;
        fh=3m8vkYuJTOJanGxM3pL6MjLRY+adu9I8OlxWnu9g+IQ=;
        b=APDbpx4BFWP2ZtK2oQRRqfoq8JWYsshgsMvL+t5PC2sXAp9AAt0iCQfFDPLBWsodoB
         xPNTqogd12KXjUAkLMh2ZGhzM7WNfkBNys/ILaw4yN5c5MtGPoENobmmxIjhwbd2JQxj
         b72EsAXJlwbL3avabqAp4oKDK6kBdaWaqXoJCkOZBlkwtyyyibx70cmOxpOFhAUFmJqL
         +ccwRtwBIgL0VS5yIFdG4Oeba8nbdFIXRMW1lgRtvw/Mjg/PtbkqSnrmg3qfPculElWs
         kpCNyP7m10pnHx6t7vb4qAh1A9bJ8IKv99IPewPhtefuVm62NVoQMAWeerNKx1ut/pW9
         rlFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qlCKyVVK;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-404d97eb3b9si659837b6e.2.2025.05.22.21.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CBDF15C6D24;
	Fri, 23 May 2025 04:37:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6B20AC4AF0D;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
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
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v2 04/14] x86: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:14 -0700
Message-Id: <20250523043935.2009972-4-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=6526; i=kees@kernel.org; h=from:subject; bh=NLp+yNLHFbt0GV+WqSgZP5Jpw7SgnlmemsBZjPqNKQ0=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/M6Lj0TL3UZvEPryO2U1XiwmeUWRnm7Ltu8Tv7T fejWHWxjhIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIncPMDIMF2RL/S7vLKpfM2M t8x3m+UdDqwvS9xyTbb4p4asf8qChQw/nnGmzL67VZLb8E8Q7+r/36asCDud1Su0ufrUxFOvRAJ YAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qlCKyVVK;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
 arch/x86/include/asm/acpi.h          | 4 ++--
 arch/x86/include/asm/realmode.h      | 2 +-
 include/linux/acpi.h                 | 4 ++--
 include/linux/bootconfig.h           | 2 +-
 include/linux/efi.h                  | 2 +-
 include/linux/memblock.h             | 2 +-
 arch/x86/kernel/kvm.c                | 2 +-
 drivers/platform/x86/thinkpad_acpi.c | 4 ++--
 8 files changed, 11 insertions(+), 11 deletions(-)

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
index e72100c0684f..ae76c8915000 100644
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
diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
index 921c1c783bc1..72f13d643fca 100644
--- a/arch/x86/kernel/kvm.c
+++ b/arch/x86/kernel/kvm.c
@@ -420,7 +420,7 @@ static u64 kvm_steal_clock(int cpu)
 	return steal;
 }
=20
-static inline void __set_percpu_decrypted(void *ptr, unsigned long size)
+static __always_inline void __set_percpu_decrypted(void *ptr, unsigned lon=
g size)
 {
 	early_set_memory_decrypted((unsigned long) ptr, size);
 }
diff --git a/drivers/platform/x86/thinkpad_acpi.c b/drivers/platform/x86/th=
inkpad_acpi.c
index e7350c9fa3aa..0518d5b1f4ec 100644
--- a/drivers/platform/x86/thinkpad_acpi.c
+++ b/drivers/platform/x86/thinkpad_acpi.c
@@ -559,12 +559,12 @@ static unsigned long __init tpacpi_check_quirks(
 	return 0;
 }
=20
-static inline bool __pure __init tpacpi_is_lenovo(void)
+static __always_inline bool __pure tpacpi_is_lenovo(void)
 {
 	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_LENOVO;
 }
=20
-static inline bool __pure __init tpacpi_is_ibm(void)
+static __always_inline bool __pure tpacpi_is_ibm(void)
 {
 	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_IBM;
 }
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250523043935.2009972-4-kees%40kernel.org.
