Return-Path: <kasan-dev+bncBDCPL7WX3MKBBJ4TQ7CAMGQEDQWPGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id E2A1FB1000F
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:50:33 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-87c306a1b38sf74587839f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 22:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753336232; cv=pass;
        d=google.com; s=arc-20240605;
        b=O8oMfwvEjPMQqjADkdQ9XXn/tnnvCpljilRdC/H4slnaod+o1m1LDeXNecMhV3pwlh
         htnJqgZIaTsYCKVElK4dPmmZamP6ey/UwXDWsPdufwy5/kz88O8R94+05s+phc8N4AYG
         Pzw9ss+6V4sMuvLoxQCpZNlu7W+ZeMjf9M67N5tlIKzeIpgBkOPP8dmFlAw1hHDaAO92
         a/9d9qRoKoSMtYZsXDLGCGF46zeBo5r1ZhyWC1odLsmBMQfSBplxS/BlxzVchC9k7/XS
         /4COtLI0SjqYNLrD46U1fDtsn0+QcMV9I9gaesx6zBqmAEDIbbm5fTZwvcH3TesctKS4
         QF3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=Ak37RRX3xqyfA+H8OsoY77FBvM6pRqlOuSC3geG0zoc=;
        fh=I/2HPpwnS3bniACenPZNtVr+0DQOsDAylJWHHVWG/pM=;
        b=kH4yirCHZNzYz6W9xZN6Q4FukFeBFNlt7we7NMhJKgZc8FochL+q8u7JZL31jOT+XF
         loJSslw/CCrqc9UGaweyaeKn3o03m/RLqHuH73Od7fEHpNjO95ol+rftSwSz8F+nfbs0
         8Iyq3ORr/EXRAhlmnespMPByrxNItsaaZc64RbIlbHRIjkZia41VLs4CZhJeF2qc8iB5
         6ahIMl8Mq/ifdJtRFJM7aKDQwMo2kHJ16Kl6rLA4hr1399s9qpwxnOLCml3TajgYANUD
         9K9UPCKbnbtYcaO+QMHBqkA4ruhphGgO6HdJuNM0lqppnWqVA4/euOGYV+hAbsyz7p3x
         +U0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t+HZl1rt;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753336232; x=1753941032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ak37RRX3xqyfA+H8OsoY77FBvM6pRqlOuSC3geG0zoc=;
        b=D/93rGBPMh9LxcsMI5TEH1ErxIpcUHmtaZfB3YFW1genjWe//Er6utsneFgCszqOnq
         ++7xPLOg7Fsa2eEhKhYvmjwts/0d2ZG83uXO3mBcNhdlthbD4jvHiYpNTviBgVuqNDFp
         UT82IMuCHjC2dJUo4ngWafm86p2FeFn4kNOQeZhKdir2PqXKbU218si1pdY8cEtMsMJY
         WN8T25pt91EKpot3JzXE7+G/POQppsqVGTKVVjc/zrV+JysAqqFeaK1Ic7BEVdJ4eIu2
         KRjs3z513A7bxGysB5ziZcPWgwMQY/XTT5Vi7IvWokYanUjN228ZcrgT5s9MELgc99TV
         xb2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753336232; x=1753941032;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ak37RRX3xqyfA+H8OsoY77FBvM6pRqlOuSC3geG0zoc=;
        b=cuRyEpZ9fODY2OaNf8YkZ8jV9DxwGGu9eRBPp2FyPFhXr0c2j3xachIM9TmapKj5JK
         nkbvUum9tyqa8mVmznF4cNsCT6vWmFXPTwA2bMDUlFigQBE47dMKubC4PI3mNq9F1KQJ
         PqW6o2W8cJHgdrMxoi9oUDf7L3Dm1Ihh6VRZTFQi4hcaB8kCPSbRBYvBfE6hX73xd6u9
         wtdLPEUqL6uzm7WrU9zFL8McFHw5rDGf3Hee3/oGSLkuAlzDjgfQ6Tkxqplyk7BLFsL0
         sbSSEAeiIk5QY3wB4KSVleQCPCF3I8p6R6mzcgSEjiagk6PW24/5lR5cbNjD5/Ti1uEO
         TYHA==
X-Forwarded-Encrypted: i=2; AJvYcCWtLXqrtAdSrQ26qnECgD985mRj0aQE95ziP71djqhjxOCe7gfhbkKZlBZpVuRNWkTp89zLJw==@lfdr.de
X-Gm-Message-State: AOJu0Yx9vr/iIjImWvzLtmk9eP8i7cAGV36NHFL/wqie5NyXVjxGX+Ou
	nPqmX7/OdoJTfj8Pf8iXXX3DyXwqEO2tKSRZr0L2+6O0Z2H9+kUzetP+
X-Google-Smtp-Source: AGHT+IHaDMrgOz7GBcLinhb6decLxaA+29bVMgFT+H47O/nzAPzpM5XorcRp/TMBUUzarq/JkQA4CA==
X-Received: by 2002:a05:6e02:156d:b0:3e2:aadb:2be8 with SMTP id e9e14a558f8ab-3e3355b0625mr91077015ab.15.1753336232098;
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeLKrNrHA+hJ6lZDMGPbyWF9DV5mXPtqPmKzGxxY7KkpQ==
Received: by 2002:a05:6e02:9a:b0:3dd:b672:7f90 with SMTP id
 e9e14a558f8ab-3e3b5190fc6ls5176335ab.1.-pod-prod-06-us; Wed, 23 Jul 2025
 22:50:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWiHqwM9A5e3aFTn1O959yDqGyh6scbg6YcGzQmtyAc96+2g/F5rucp4E42GBpBDd7eLvAAIaISQx4=@googlegroups.com
X-Received: by 2002:a05:6e02:1c22:b0:3df:3afa:28d6 with SMTP id e9e14a558f8ab-3e32fc920e8mr102068385ab.2.1753336231290;
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753336231; cv=none;
        d=google.com; s=arc-20240605;
        b=MnOENoUT9FZhro+Rh2qU5K9jfSNYVeB2VFw0qFIXn0uMEhRViboOek1NmuEtt+dKC+
         DLUKTio2sR9gNhIBilcuKErK/pCWoiWqjYcH9bCiSxvhCltFvGogSP3LROO2B23i0/RP
         CTTUaKXPDNfv3hO1ktn7oJf5NofmqZ5yItwlBmZDeny8OSvlTRu4EeD5fqdb+QoPlW7i
         GSSHwIJrh8NCrOLFK+bee9piRoluw6kFaSb5Cwuxk+0kEPTh0bLJsTdUVvIkJJ/aLmo4
         60EUp1FCTDxO5MENXAguYl3XQnz4nlmCar7/sIi9SCG842Dl4UyPYzU2WFz2AQ3fBdo8
         nWIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=six3Sv1/lb0L0m3zgi9cAfAD7+Gtbp9Soz+DPeVeLLo=;
        fh=hGfkXdrCNa/G93VRqSmKTTVgqFvO6scAF0USoAxgJ6A=;
        b=QmHWkp589ECE5P6K0wUzBkC549WDiC2xo5A43zwQc4QkqEdkXh/FER3p+grvC1yyjl
         73yrJt7N7JqugPvmM9+LfveomMZUxEDRkc7YKEvbJ4uxhQTIdrzdutvprD92CgxGKTGC
         A2xA0P4FrYWKHUtOu+Ew4cvyxJVxeD8gNrDFoHjVWp03Nps4nwX+Zk4kVV63OLsScYWP
         PdXFvujfiGch/khpKvQL6q4g40MzKEm3cjbXVQkaanVJqeKq7HwVDeDbsdSOvbkkfQJL
         i3T9i3QL6Jd7quwpwrzxdaSFl1v+2DdYk2dRCCgJ6CEDcMbNp40wJ6+7vv764ozKB1RT
         5Fhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t+HZl1rt;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508aebda61csi43663173.5.2025.07.23.22.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 768AF44FDF;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 469F6C4CEED;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
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
	Mike Rapoport <rppt@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	=?UTF-8?q?Ilpo=20J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
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
	Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Hans de Goede <hansg@kernel.org>,
	"Kirill A. Shutemov" <kas@kernel.org>,
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
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org,
	linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v4 2/4] x86: Handle KCOV __init vs inline mismatches
Date: Wed, 23 Jul 2025 22:50:26 -0700
Message-Id: <20250724055029.3623499-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250724054419.it.405-kees@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=8992; i=kees@kernel.org; h=from:subject; bh=wNKQONSDACRjYYu6I5glKcwwkty7zb+PKkmvdUUj3Ig=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmNJxdHq87byTrV+eeFmu+pxk9mrDErymjTSZ7z2arJo lvq7NmajlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIls1mZkeCNgEnr95wlTvr3M Ac17RX8sua+lf+fIw+nTLUNe7tJm2sTwV0gkcCqD+LfdNnp6PK+kC7LTjySv5f6gflLm/1bLzsz HjAA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=t+HZl1rt;       spf=pass
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

GCC appears to have kind of fragile inlining heuristics, in the
sense that it can change whether or not it inlines something based on
optimizations. It looks like the kcov instrumentation being added (or in
this case, removed) from a function changes the optimization results,
and some functions marked "inline" are _not_ inlined. In that case,
we end up with __init code calling a function not marked __init, and we
get the build warnings I'm trying to eliminate in the coming patch that
adds __no_sanitize_coverage to __init functions:

WARNING: modpost: vmlinux: section mismatch in reference: xbc_exit+0x8 (sec=
tion: .text.unlikely) -> _xbc_exit (section: .init.text)
WARNING: modpost: vmlinux: section mismatch in reference: real_mode_size_ne=
eded+0x15 (section: .text.unlikely) -> real_mode_blob_end (section: .init.d=
ata)
WARNING: modpost: vmlinux: section mismatch in reference: __set_percpu_decr=
ypted+0x16 (section: .text.unlikely) -> early_set_memory_decrypted (section=
: .init.text)
WARNING: modpost: vmlinux: section mismatch in reference: memblock_alloc_fr=
om+0x26 (section: .text.unlikely) -> memblock_alloc_try_nid (section: .init=
.text)
WARNING: modpost: vmlinux: section mismatch in reference: acpi_arch_set_roo=
t_pointer+0xc (section: .text.unlikely) -> x86_init (section: .init.data)
WARNING: modpost: vmlinux: section mismatch in reference: acpi_arch_get_roo=
t_pointer+0x8 (section: .text.unlikely) -> x86_init (section: .init.data)
WARNING: modpost: vmlinux: section mismatch in reference: efi_config_table_=
is_usable+0x16 (section: .text.unlikely) -> xen_efi_config_table_is_usable =
(section: .init.text)

This problem is somewhat fragile (though using either __always_inline
or __init will deterministically solve it), but we've tripped over
this before with GCC and the solution has usually been to just use
__always_inline and move on.

For x86 this means forcing several functions to be inline with
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
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: Vitaly Kuznetsov <vkuznets@redhat.com>
Cc: Henrique de Moraes Holschuh <hmh@hmh.eng.br>
Cc: Hans de Goede <hdegoede@redhat.com>
Cc: "Ilpo J=C3=A4rvinen" <ilpo.jarvinen@linux.intel.com>
Cc: "Rafael J. Wysocki" <rafael@kernel.org>
Cc: Len Brown <lenb@kernel.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>
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
index 50db7df0efab..a98cc39e7aaa 100644
--- a/include/linux/efi.h
+++ b/include/linux/efi.h
@@ -1336,7 +1336,7 @@ struct linux_efi_initrd {
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
0250724055029.3623499-2-kees%40kernel.org.
