Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKETQ7CAMGQEKAENWBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AA85B10011
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:50:35 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2369dd58602sf6781845ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 22:50:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753336233; cv=pass;
        d=google.com; s=arc-20240605;
        b=L7o16Sesh4/1/c/ebZsPao6Bk13Q/HqRDCsXIoLKCoDIHlMRNpC5aUmcKFHE/7EqUO
         drErlAsYXs9oW3yTstWjilkkL3fVxJ7mSuRG3eJdeLsHdGFqeh66Tbky2IHtufs7DKbr
         owD5/YPjfQ+zhjsdIByo+7RQnR19R6wCcGXqf/Q4KN4KcrkGtnFSr/bhi4dHq44r/oLr
         u3XMaloYqdT9AUGsOyYN1+kkflqEv2PHddQi6uBKGgwHGwbQijms5FcG+QobwAsaeXmZ
         j4mr+S1757sI0KVXGg+1Bf5cLld0kNH5dj8dQf3qbu5vC1uBNN6RJeAOvf1g8Cdub1MA
         swYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3wBy+fsnD37ErbXfmy2tB7/+I2tdwKdyu+Y+rB7iqWU=;
        fh=6BMIM8shTnawXPiSsslZObuK16O94BSysnstYMekh0Y=;
        b=FGPE8pNGlbVK86RO8ZhvzO2y/tf7lD/t2qW0MqSXzy5M7NBgV3VMf5HGKq4VySG9gY
         1lmGy8Itl8HtbSFQ63GHElIm4nO2jPz/8qOYWtM8t4sYaYdYB+ByWLQo361FSMNYyPLF
         1q9qi1AB4qYIusv/awGJ591Lx2BrB/7D0bIWcXfIZ4JaFoOIKseTKT5dv8rAuMDAOPaC
         nMCIf/rdLV3jqStyTjIbw2BRdfmpvLQWnEH96Si5bLzivkt1mOwl+WjR7GqDkIV88cqe
         62Rbqg4m/qn6pZMF5oQhabJfo/5lk88xh/egFYl925O6rw/YAS0x/L+VhleQBxf1c9gd
         R9KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s29zubue;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753336233; x=1753941033; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3wBy+fsnD37ErbXfmy2tB7/+I2tdwKdyu+Y+rB7iqWU=;
        b=TqyQuss/Ih/afSol8hdeyrIedV0VI3/YmkD7FYOUJ/XHsBlHoRUDXOZRatulqY4oxM
         EfJA1U4QX6+GYPaYLqTDcsiYU1CTaM5WXCsF5kzl9cZuy+0TQfT8MH4xpK4KX0aG1Iuk
         QkBAlmMBOZfLrxaih+HGgZPCgGEShtycIHYRAqQeT6nEkeDK951BWuhayQr80iAUTYwG
         IL7QjbHv4pgpYVGWc1x5YaP43x+OSYhbCy8Eb3j77OZJuVPUWesG/dSGRXXYznQoslXb
         xLfc+vEeBOky4eeBkD+zUuE7AFzl9WGpjM7uYWFpEjY0TF/AqAm0LsKUUOzv0BXk3eIG
         Xitw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753336233; x=1753941033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3wBy+fsnD37ErbXfmy2tB7/+I2tdwKdyu+Y+rB7iqWU=;
        b=lngqd3WZr0lcoaA45n7Mm2VywfG6sUPQXTXSxKK/+rXdLo7gpd5ICXtnZVIOK2k5hR
         AoTs7QkxpWpJV3Xb6NTFlRPsZQX8YKljjzllHd6soQyuXTwVIeCshf5Wp7CLxVu4ztVz
         DvNHfcG2M1vG3ajzMnFQTkGZbZHS/wwrh5GnwTI1SsIWwfcSkRhFMwrcclA2KWnV/ba+
         tFGIoOApAy/KksGWDlxUdhMEruuzeuVY6k9DGvZILB3/jesvjfksexnpwWlLfxpVdQck
         qM0RMqxvKc8YqiBt46Vo+BQX8TZgQRx7SCioYPCJ3S+pTm1AWIIEl5s+RP/eVEc9X+YH
         MFIw==
X-Forwarded-Encrypted: i=2; AJvYcCWbiz3WEb0NcSHVpZgqgcnXmyi9CTsDHniwRsjW5OakIppwcnV7kWjcU3XKX1QZnAC+/3o8Wg==@lfdr.de
X-Gm-Message-State: AOJu0YxMrY7vdJwQtcD06jkL+5nirhSsYEnZk+Nz+LLR3UWZDXaLrbNu
	YVvT+zQT9xFjzB+h2CDW2lO/flnAv5nzE/LB12OJ6pfrs15Q0YGNTf4w
X-Google-Smtp-Source: AGHT+IFxXxABo/j4b0SURqF+mYz1gxhaQWbkXj9dOdwL6O3wA9strZ9XMQxGzfJYWxfpyek+JT8k1g==
X-Received: by 2002:a17:903:41cf:b0:21f:4649:fd49 with SMTP id d9443c01a7336-23f981f4378mr97358335ad.49.1753336232904;
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFi7Arbu2CMdzDeSSMyJKIC2BnzolyPWz8vTlQX5WU+Q==
Received: by 2002:a17:90b:3549:b0:318:ec3b:2292 with SMTP id
 98e67ed59e1d1-31e5fac1d34ls585477a91.2.-pod-prod-07-us; Wed, 23 Jul 2025
 22:50:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQ/EXEjP5YteFMBuBmkgecBp/SIAFVXOmnc/lQRXyqEBN3g+hK/599wMmObMR7mGV+TvO1+7fSBWE=@googlegroups.com
X-Received: by 2002:a17:90b:280e:b0:311:e8cc:4255 with SMTP id 98e67ed59e1d1-31e50859034mr7501952a91.31.1753336231565;
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753336231; cv=none;
        d=google.com; s=arc-20240605;
        b=XNRQKnwH7RGcTduVUWpDN06piZRnIxj2WBul5cn9SoOhnvmHY4o6ewaVOuBtJaUheT
         UIfQsAs3Ee8BLB+htr1EXtN5L9DbvTYMDAaQHZ1ueSvxC+3Fb++sHoK9uTYgTSj2Wm/U
         iUVCtqLISfH3q8FG/u1iILfuBqPIlZ0XEMuOyFAnzcDQyx7kKQ1kTXOBfoE79zcb8WmA
         qH2NHEEKmfiV3kG5kwWbZIdD3Qgl8eUW+qB3jZWisAAREx6TN/fRXp2bY6Ig3M1Joyer
         Tr9ucjEsGl2+EEauP3fTEjK1kVrvKjnCWBZZoZVQo1BuKC3UL3SNT9V7Bu4MEVCnVMv7
         5bfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tWEmAXSsSqp0aOqLizAGvUyWWzoVjGCWN3V0l/bYucM=;
        fh=ItxDtW+PGLWnp2ucgzisQYQTqwFpIw+HVWDbClp2d+4=;
        b=W1SLB/HGmasMKwXyuDVrIt7JZzDoXQ1TRPQP9bi9JCd3SDjTBb3oy52a9FMcIPLIYj
         o3piEkH97ylWu0jrR4PpCaYjDLBhzBEEBsymnMZvXHn/K+eO4DwtZsqXWE7yya+bNNAn
         F8JjHkkYE6gm1f7sEBgOKYGLv8pZme5mzz6WNGQEL/B1vlgxTT4m9/xaV8Dt8jTUo24R
         Vo6uwK2G6GS8PnVclJIz87fR/56J2nKqOORh7NBbkMpHkX0cLiioi55PH4Faq/p34tb9
         gLVVArcIlpSHV/BHXiXghWn7VJM4pTpmtr7Wr8ntBCFjfeTLSR1/5XkHgOIxPG/Y4jHv
         6ihg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s29zubue;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e661081aasi27477a91.0.2025.07.23.22.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B0D1846538;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 50F18C4CEF8;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Will Deacon <will@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
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
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
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
	x86@kernel.org,
	kvm@vger.kernel.org,
	ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org,
	linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org,
	linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v4 1/4] arm64: Handle KCOV __init vs inline mismatches
Date: Wed, 23 Jul 2025 22:50:25 -0700
Message-Id: <20250724055029.3623499-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250724054419.it.405-kees@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2121; i=kees@kernel.org; h=from:subject; bh=HjxWaeaCv8M/oL9GQSiYPTHDkhtk+DTRYh358m2uH3A=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmNJxevUIqUu+2x4F/fOofGOacvWqgmvnqeLJv0JeJDL usnHfXgjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIn41TAyrHh499h001Vid05L Nkw14RZx7siKejb92THeWXEx6x9PFmT4K1OTc6Ms/eTviZ93fAuV7N800326HO/5hfY1V14Gh4a 0MAEA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s29zubue;       spf=pass
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

GCC appears to have kind of fragile inlining heuristics, in the
sense that it can change whether or not it inlines something based on
optimizations. It looks like the kcov instrumentation being added (or in
this case, removed) from a function changes the optimization results,
and some functions marked "inline" are _not_ inlined. In that case,
we end up with __init code calling a function not marked __init, and we
get the build warnings I'm trying to eliminate in the coming patch that
adds __no_sanitize_coverage to __init functions:

WARNING: modpost: vmlinux: section mismatch in reference: acpi_get_enable_method+0x1c (section: .text.unlikely) -> acpi_psci_present (section: .init.text)

This problem is somewhat fragile (though using either __always_inline
or __init will deterministically solve it), but we've tripped over
this before with GCC and the solution has usually been to just use
__always_inline and move on.

For arm64 this requires forcing one ACPI function to be inlined with
__always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Will Deacon <will@kernel.org>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Jonathan Cameron <Jonathan.Cameron@huawei.com>
Cc: Gavin Shan <gshan@redhat.com>
Cc: "Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>
Cc: James Morse <james.morse@arm.com>
Cc: Oza Pawandeep <quic_poza@quicinc.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: <linux-arm-kernel@lists.infradead.org>
---
 arch/arm64/include/asm/acpi.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/acpi.h b/arch/arm64/include/asm/acpi.h
index a407f9cd549e..c07a58b96329 100644
--- a/arch/arm64/include/asm/acpi.h
+++ b/arch/arm64/include/asm/acpi.h
@@ -150,7 +150,7 @@ acpi_set_mailbox_entry(int cpu, struct acpi_madt_generic_interrupt *processor)
 {}
 #endif
 
-static inline const char *acpi_get_enable_method(int cpu)
+static __always_inline const char *acpi_get_enable_method(int cpu)
 {
 	if (acpi_psci_present())
 		return "psci";
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250724055029.3623499-1-kees%40kernel.org.
