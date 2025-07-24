Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKMTQ7CAMGQEVLZT5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 91E0BB10012
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:50:35 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6fb3bb94b5csf10095276d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 22:50:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753336234; cv=pass;
        d=google.com; s=arc-20240605;
        b=C1JVewOTGQ3X42bGJwVpmN4GlPbU/HaSDePGBUgXJ2Uc5bog7fkzu/p0eXynsq7yiz
         b0LzL00ltiid4dQKi07ytm26KbRiubxyz3n7gJozOsuAd1oqRsc3qZMrbvUvBJEc5w7Y
         iXflMZMq4bZ70O17wgCbJghaPVeft6CcLHqIogl2+mfSdGqe5FEnWkdpaSEvofsbTRZZ
         YW75z4tZqGWNz1WlTI63HbBxxIC/hx9M3nXo0et1eId4dqf+AVwZkP1S+0njk8R+/ZcM
         qpcp05qaxNmFTbs9ZW6DJSzcfSpmVq1GpvDPFPfXfyBxsqvPhpTxAc2z9ANgxXxkqsdW
         4jQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=O27Y24CCvKCdihrO/w83BBjingkaPniTtNK3nS8Sbzg=;
        fh=ZGn8JGfJjZ4ZKfjOAJFoZ+wyPDvRc6wsefIC15OHbjo=;
        b=Ojoo3+iACklK9fJWxEtF3TCnJRv1Rs5nCN282ZyNUtXx+jdP/yIHO/18+4JX84Iv3z
         do1P+8Msu24kUHPABa7coQPf7nPG93HLzUWc8hgbUV+4u0tKSJidu82u8ZAzgsIIUVIj
         wFw0pGcFQl/N1s63jTCg/zwqMo8I6reVI/fTM0t9RGQ+NDu0u+iqzKcFeJYjgKzIEXnJ
         j9LYRUzxF8QOmFtDmmt9aGTV9AdKCSjRKtoMuhyMuFqgtJnTrGHZB62yxws9yuaEtKu+
         Y3kW35SE6LLQ5TU1+BqYPCC4QVMxKzFTmXzEFT6dk2QaRjolBC7ShWsaLyHki11tZM/p
         AJSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d0/TMlHJ";
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753336234; x=1753941034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O27Y24CCvKCdihrO/w83BBjingkaPniTtNK3nS8Sbzg=;
        b=XgTccDA/yicXOTceXXm24x2HobkWfqi8NDiaw79VH4fcRSAhjUvBNjzVhPbjQbW/fv
         PuqVV62mTJQpvLP1ZTm+zVIbk8r3wm/qdxjURvmsf5gzwOQ0E2Dew1yK0/WTCCyAfjmi
         YRnsEsfI2nVBVkI5LyndcBYp5jfg0OprhP4olZF2QXSH03F3EPyonQwA+V1gykg2nba1
         qyhrFFKatwqZ5jbpnKr0yInzJtIfhtPTTE8fBfbSZLE8ASk5y3ciLSPUwj30vxWWW4b2
         12QrB59HU6YGdASps4NumH4+ypRlzlW2/pRB53m9zB3DbPMsb7Jg/jYtlBgJ84PrC1JN
         IkrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753336234; x=1753941034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=O27Y24CCvKCdihrO/w83BBjingkaPniTtNK3nS8Sbzg=;
        b=VWCErcGxAnJmtgzlvm8s3W6J8frd3IYrcYUddBOBnBYD9XRvb6Ybsy+MjPKvgoTpGS
         N3yBHd/JkRVeoMT0C0mGeJKYGwPh6xzIH29Kh8f5HOvODVnKVVBp/6p9jKmMtJ/55pt1
         LuCClW5MjYpwn+N4SKT0c/o/IwTp19Wc1xTrUjXSAeT2hRX9yZZ0rr4JtlDBb4xF1/VV
         ycemHiAeBZMx442sBgUK3o4nlCP/XKhyUKCVCHtlgqOc5HujOEk5vELzUmOQQaOeIHgT
         3lIJBgzTgbGsexRnqicYLhW90dix+AE4G8KjpaSFedv9FuazBjF2VqDomjItILHFFOUJ
         KcJw==
X-Forwarded-Encrypted: i=2; AJvYcCU/0dWhjEKcuVVY/LGt6+KA553pDPvFQfnaurSPxmys3xl6/CEUQkjq+qX/aBJFt5ZPmmHeoA==@lfdr.de
X-Gm-Message-State: AOJu0Yxq7EYLV2JF3asxbwFiK+uh2vrevdij1iJdv3iSdZHGDGxyyXjF
	K/2uTw7iuxuqdfAM559Mw0TIG02g01AWyttrVHEvufeJAIU+dP4Z3WRM
X-Google-Smtp-Source: AGHT+IEivJOe76+C+uZTYuy4qH+w3abqBJxxa1RDabbLIgkcYSZYpyEJ/iiMkqvIKZRi1WeXyCeOpg==
X-Received: by 2002:a05:6214:3015:b0:704:7df7:c1a0 with SMTP id 6a1803df08f44-707004b362amr79200686d6.7.1753336233818;
        Wed, 23 Jul 2025 22:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZddv7+ebJa5VCceJE+hTsp/iNXCVT+m/GsZOpJ9uWlueQ==
Received: by 2002:a05:6214:4407:b0:707:885:75fc with SMTP id
 6a1803df08f44-7070d2b2e07ls11664146d6.2.-pod-prod-01-us; Wed, 23 Jul 2025
 22:50:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUODuZaATDTDpj9Cew++RifXOVHSpTipnXB0o70YnNTrN5JqO73TyDuV2Iv0lZVl7opLeblY6Y8x+E=@googlegroups.com
X-Received: by 2002:ad4:5aae:0:b0:704:f3ef:cbc2 with SMTP id 6a1803df08f44-707006800c0mr66712286d6.33.1753336231829;
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753336231; cv=none;
        d=google.com; s=arc-20240605;
        b=HaCKvskte++gHrj8+8FW8eQbqFHu7HzXR50ZqsjFJofR83zszkWvix/FsE1alzeKrI
         IK7JObFToUa3W2SnTaIdI0RFUf0i5oH45de0KwY2JFvUDLWVV/jg7vW3CmOeyoU5/YMF
         FPA1SyZISmbjqqOvT0Ufy200eSQgO8GLYaLlpOSs3mx0949GKhT0CcEta5ogCc+bNjXF
         HGrINNwQDDjDO+MXz8qCFDJq67Au2+J+wcUyp9fY0IyXuvicrFUSTQde1A3/YDUCRAVL
         qt8AmJQRp8IF5uIKVYs1Flor9hnvJ4eV3qofyp3+DtU9DR1dxKC8y21PpCAZrx/c6NID
         x8dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=C2VkXjr1vmtMoAwGuzNgZ6GgP6+IF/LpC6JdENa6i7Q=;
        fh=Z6A3A3bGrDZOnmy43OuaBoIHCQFfDeo5hyYTrYOkquc=;
        b=eyzMs9TKH/qEMK4Y0YwGt3Vy5hkQsQtPg1ove6C14E+8BXRYRz6vsdBbYUlq7XVkbz
         UrL5zhK/GHG7oa89yQ7JcdtfIN41XML2TkSKyKi9l8874zT3uVARYXjl08m9ERYAf6vc
         yJs4e308ZFt//FOQoirmaFMj5lqUF+QZuaqWfm1xrWS/6QBprcR1L7TKLViBxAFQhLfZ
         1nXiJxz7nqrmDFIib494mzLSzf0VejbKTqNuxOr/ZOl9M7RByAOu8bXdbT3l/dDntbFD
         XB6Q8hkENKgo7naolPRg+HWkGov7/8H9hPDKYKpdVvBAUzJGp/HCRit7Rci0EWZOv6GW
         EKAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d0/TMlHJ";
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7070fb72d97si433906d6.1.2025.07.23.22.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 22:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A584B46522;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4ED8DC4CEF1;
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
	linux-arm-kernel@lists.infradead.org,
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
Subject: [PATCH v4 0/4] stackleak: Support Clang stack depth tracking
Date: Wed, 23 Jul 2025 22:50:24 -0700
Message-Id: <20250724054419.it.405-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=1439; i=kees@kernel.org; h=from:subject:message-id; bh=XE3wpC5OKAVRvxdPiqi/2WsaLPvDes1ay28krOB8Nyg=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmNJxc5mZrpNj5K4tORy/7TeZXhw9upF18pr/M4P+mO0 qJ1Zxv/dZSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAExkx3ZGhj3Lo9RPfd61sO3K 6ZOX39cZ7GLmn/6vehbf2xvW83qXM01nZOhJWph/qli05kP325oNd1z3S2krH/3OsOnxZQ05w52 HynkB
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="d0/TMlHJ";       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

 v4:
  - rebase on for-next/hardening tree (took subset of v3 patches)
  - improve commit logs for x86 and arm64 changes (Mike, Will, Ard)
 v3: https://lore.kernel.org/lkml/20250717231756.make.423-kees@kernel.org/
 v2: https://lore.kernel.org/lkml/20250523043251.it.550-kees@kernel.org/
 v1: https://lore.kernel.org/lkml/20250507180852.work.231-kees@kernel.org/

Hi,

These are the remaining changes needed to support Clang stack depth
tracking for kstack_erase (nee stackleak).

Thanks!

-Kees

Kees Cook (4):
  arm64: Handle KCOV __init vs inline mismatches
  x86: Handle KCOV __init vs inline mismatches
  init.h: Disable sanitizer coverage for __init and __head
  kstack_erase: Support Clang stack depth tracking

 security/Kconfig.hardening      | 5 ++++-
 scripts/Makefile.kstack_erase   | 6 ++++++
 arch/arm64/include/asm/acpi.h   | 2 +-
 arch/x86/include/asm/acpi.h     | 4 ++--
 arch/x86/include/asm/init.h     | 2 +-
 arch/x86/include/asm/realmode.h | 2 +-
 include/linux/acpi.h            | 4 ++--
 include/linux/bootconfig.h      | 2 +-
 include/linux/efi.h             | 2 +-
 include/linux/init.h            | 4 +++-
 include/linux/memblock.h        | 2 +-
 include/linux/smp.h             | 2 +-
 arch/x86/kernel/kvm.c           | 2 +-
 arch/x86/mm/init_64.c           | 2 +-
 kernel/kexec_handover.c         | 4 ++--
 15 files changed, 28 insertions(+), 17 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250724054419.it.405-kees%40kernel.org.
