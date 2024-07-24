Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBBMJQG2QMGQEIUU7SVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E4B093AA13
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 02:02:15 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5c2021e8656sf3487019eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 17:02:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721779334; cv=pass;
        d=google.com; s=arc-20160816;
        b=IesCJmO3AV3iucEI5Ru3YkxZI+zNeZ1MaLTJ2bZ0T0s3LiVsoyQelEDO6xK43eHwAk
         A7b45JCFHi5wHN48yqBoNXmZP0i3iIluaZ8+3zU7BkN3SQbPZGQRUek7ZwjDKQOlWZeW
         97rypq9YSxx+SVJjcmp3rnD8QA+tQxbk0NDMtSENeqgDcEaQ5LgRGl1aM2wfkr0MIRur
         mQ4T2CvvrWM0f2R2TIrvWmy5YUuCjtSHACNA5BvMgR2D7gu/OIIpFGN6r4/hCvJInZjZ
         Ub8ll9XwwXm4+MIWmLaQqHzTXTJZC0ZY6hbloE7sgDNdPr/AERYiOmxdc7LM/4TG/vlo
         6H8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=rQ7OlHZZ4jjnBIUZ4w+kRmv8T3znrsxmG726fBDvciw=;
        fh=NXctBxi+9oAwA4rCSgPBhspVCutP6p3QH9PpXORqS5M=;
        b=a7E6bdIFXjsNs5vjbztJJqZOeCsky4vIgc4BkEFe/lARKj9cyup9ITIs+maWsCDD8O
         OmbgDyPhPY9xwNaziGsjq6LY9vmYW5nZgohzMHyBeFNwsjQhI5HgWGT/XgkgQVqwGvd+
         7dpNLl3Ij0GlYh5cyTGSb36i/6MBooCPYQJb6ZhLEmfL+bU7r/OUVGkVNJ5kF4smsWwW
         ZVg4zM8OMSzsYusdYqt/caMGwoJWKvWcqhL+QkTVgtVfuHBCVTDac7oX99xf1XNVdze1
         369f0RimLXhpRDKsR6dFqYZEy4Uz7AvJLO4WOYxeaeppG6LKYjPLFxthKry9G12MneGp
         7Hug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C6Hkq0n7;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721779334; x=1722384134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rQ7OlHZZ4jjnBIUZ4w+kRmv8T3znrsxmG726fBDvciw=;
        b=sEUmsn5bf0kzYpuhDBD5/voQNtu/jTEfth8zVH/eYTztVdK1/ap5msKkEpJfzQdZiK
         8z/x9Sjsj4SFZw/CCQQ46o6qILXgkSKK/yikM1a0u5Ktq6GvIRYj37xFud6DuXx9qpKh
         Ryg4tR+U2zEQztYTZGXxajDEFjBsBOILiYVl5JdZN8jzFYQgxPmiCWz81WhR0mZ41VVL
         4lVlZtYyXyF8ot5aPxtxZGuH3BF/dneEELvERER75WGQkrM0/h+wEvVBO93G0GCV4j8I
         lx3uRgZBIhEyIH/irIAvf9GVaXvkYGBBRSLKtNEkJAbb8fWPsFPMqk8Y+MGXZnnGnend
         TVFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721779334; x=1722384134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=rQ7OlHZZ4jjnBIUZ4w+kRmv8T3znrsxmG726fBDvciw=;
        b=BADVYGCwRUa+mjykAJeVVHlyaWMMfBHqe2G3Wn6chUUJmtCCrAn9NJPt/KQerqHROS
         Z7wiI+okQolCSryPIfvNkDh6c2mII5d8l7I8J3hpEzHLcO3XO0xujSHXy85759fzvi8p
         EE+HIA1W7hUTWd0ZCZdrpfspxPuA4a14GsjGV1c4n/hclQ8Ftx0VCwZw6jxCJiIIHZM9
         ysGmxAhaCQK/2Mw3iaiz2v/IHlWpYcXsoTMae7FBXM1dhyMBcKYf3YE46/kqq0m/OmTS
         +wwmEjqXEq6UxTlezvpeOHqgQr87amJwvMtHMNrt5TfcZor7Np6YoGgtuGMfMARNrisi
         TSfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721779334; x=1722384134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rQ7OlHZZ4jjnBIUZ4w+kRmv8T3znrsxmG726fBDvciw=;
        b=JIM1xn5L8YunZw9HXZi0bg91wgDNQKst0gvizK3ET9vBoKeaD62JDesSZLehJPBL7N
         ztoNbESuQJEdOskus3dkZupnBjDJw84vle5nlOFDvNmU/AKWaqcWKZHucZexKsBTWV43
         wMKq2isnP/jWO7D6JCHRnkHZEGba4TEO70fUFWbLiAx4kGZ5SCPc7o85qteU6zRiy+qN
         m0Hj1Sy0Jvih60AeQ/Ql1K+0IqShcSmvMIZrBE7myH8HYCoASUA6SLI4306CPtFQX2u2
         gBY7iosfVhUZqpLrodC1nvWUP5zZWr4gi9HKkhx1eBE7fii6Z9jWD33g6jHEfZAcq/Fm
         6syg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWda+DUY5FgKK83dllINVAUoRYw8PGa/iMKviS/MGl3Lw2zB7a37bryUpFDn28wXfU7057okKW8rzRQG/eoDwNcbklEsOHZnQ==
X-Gm-Message-State: AOJu0Yy9QABBgRPldfRCWMkDuSPh92rjAANW1oDkj3yr9nJD+uK3Hyn2
	rkD60TGly947Qbgltxa2P1G67/qnZRuzSRhV4xuh8nEkq8nMqT3t
X-Google-Smtp-Source: AGHT+IHo3hPovFXeNT2Vv0t6ZoRgHebNe5LdnPtH8Zneb1maDsV4CEiXxEoOx+lz5rn7ne8jXHmpGw==
X-Received: by 2002:a05:6820:2781:b0:5c6:8e94:6fd8 with SMTP id 006d021491bc7-5d59fc97f2fmr608128eaf.0.1721779333813;
        Tue, 23 Jul 2024 17:02:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1c1:0:b0:5c6:5f2a:6f3c with SMTP id 006d021491bc7-5d51f1a6e35ls5667752eaf.2.-pod-prod-04-us;
 Tue, 23 Jul 2024 17:02:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBaKNPdvbon0Anmd2DEfpVaa8y3Rnxx2wjPP9cSNZnoXmLURFrrurGz+qecKd2Oi0Uh2DVj8KkEjTWJag8VFA3lfFJPbOIsxaVBA==
X-Received: by 2002:a05:6830:2a14:b0:703:5c3d:e3f3 with SMTP id 46e09a7af769-709252c5d84mr554580a34.14.1721779332939;
        Tue, 23 Jul 2024 17:02:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721779332; cv=none;
        d=google.com; s=arc-20160816;
        b=01+NZUgr87z80V2NzQhV05GwsQ2a7xmnW2pU6vyzzTq0aIJx8UdacDBldjBWDVbO1G
         S0qvuTtvH3JKiqoxB2/Ubj44Z+h52AISZlhG1wbY+fspT74L91OcaSy6cFVQdP0/p4t6
         9knzEU7q/BfYsSlEClCM1y/JmHMnfU9IM/tkzQ4+HfPTICGYxmfXjvShP3DHaqt1ruva
         kAUhLuzQ4dQF27ugpw/WHDseZpKwUPaNCKfoO9uxs8PRcI36PZ2UCYnH3Ed0LMXng9Hn
         uMiLcxjbexjBCc/KYmKtF7xOmzuoGGLpMssRY3Kc37wdyI6eCc5ymWKt2xz0zunMI5ZU
         aURQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=J7TczzH2tG87Dboe8Qnrv2Pil29SChCNw100rbqjvPs=;
        fh=n+5ry9Igf/EfYJz2RaBZMcFjfSDsNXC2VuS55PQ7iFo=;
        b=xen2Fpc2jZw3bLd4tAdGzTGpnV+VaXMF22qiv6SduECkF3RxGWqQc8r01+gsD6URpZ
         ZeR0edubLkGwkINFqLQAvZJ4wC3wahBySZ0eL0Re7VZ+29uVTsMic8cJbvVhvAC9+bi8
         UBap/GZSB5XCFuhkdG0E2/jmTXdmGWL0Yd9PPyLdNyiokay1nKi1F0OoWeQtetUOGWKx
         kuCb0j9tsulG1+w772GLGaVLXxiKTdk6USHvaDCvCA3DB6cFAEZu9AYzIHXNAsZFQIYx
         LYiOpJGs0KMq4Uo2WNxgJ62lY/eWvkOXhVy9DvAfFRb5e8M0XR6e3Rk5l2jM4bO2nQoc
         Hvmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C6Hkq0n7;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-708f60adf88si499574a34.2.2024.07.23.17.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jul 2024 17:02:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1fc4fccdd78so8634285ad.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Jul 2024 17:02:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0+N880Kh2mrkQh87DLwBfaRpqa1mFtnD1U8ee8EvOorrAWYb/zX6jIY9AoslmLdeaov6Db9Cs4R3Fb8oHai4FYpeZFzSUSSdIRQ==
X-Received: by 2002:a17:903:2346:b0:1fb:719a:28e2 with SMTP id d9443c01a7336-1fdd5512b9emr7633105ad.21.1721779331756;
        Tue, 23 Jul 2024 17:02:11 -0700 (PDT)
Received: from localhost.localdomain ([2604:a880:4:1d0::427:6000])
        by smtp.googlemail.com with ESMTPSA id d9443c01a7336-1fd93d3018bsm52093745ad.69.2024.07.23.17.02.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Jul 2024 17:02:11 -0700 (PDT)
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baoquan He <bhe@redhat.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Changbin Du <changbin.du@huawei.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Xin Li <xin3.li@intel.com>,
	Uros Bizjak <ubizjak@gmail.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v5] x86/traps: Enable UBSAN traps on x86
Date: Wed, 24 Jul 2024 00:01:55 +0000
Message-Id: <20240724000206.451425-1-gatlin.newhouse@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=C6Hkq0n7;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Currently ARM architectures extract which specific sanitizer
has caused a trap via encoded data in the trap instruction.[1]
Clang on x86 currently encodes the same data in ud1 instructions
but the x86 handle_bug() and is_valid_bugaddr() functions
currently only look at ud2s.

Bring x86 to parity with arm64, similar to commit 25b84002afb9
("arm64: Support Clang UBSAN trap codes for better reporting").
Enable the reporting of UBSAN sanitizer detail on x86 architectures
compiled with clang when CONFIG_UBSAN_TRAP=y.

[1] Details are in llvm/lib/Target/X86/X86MCInstLower.cpp. See:
https://github.com/llvm/llvm-project/commit/c5978f42ec8e9#diff-bb68d7cd885f41cfc35843998b0f9f534adb60b415f647109e597ce448e92d9f

EmitAndCountInstruction() uses the UD1Lm template, which uses a
OpSize32. See:
https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86InstrSystem.td#L27

Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
---
Changes in v5:
  - Added references to the LLVM commits in the commit message from
    Kees and Marco's feedback
  - Renamed incorrect defines, and removed handle_ubsan_failure()'s
    duplicated work per Peter's feedback

Changes in v4:
  - Implement Peter's suggestions for decode_bug(), and fix
    inconsistent capitalization in hex values.

Changes in v3:
  - Address Thomas's remarks about: change log structure,
    get_ud_type() instead of is_valid_bugaddr(), handle_bug()
    changes, and handle_ubsan_failure().

Changes in v2:
  - Name the new constants 'LEN_ASOP' and 'INSN_ASOP' instead of
    'LEN_REX' and 'INSN_REX'
  - Change handle_ubsan_failure() from enum bug_trap_type to void
    function

v1: https://lore.kernel.org/linux-hardening/20240529022043.3661757-1-gatlin.newhouse@gmail.com/
v2: https://lore.kernel.org/linux-hardening/20240601031019.3708758-1-gatlin.newhouse@gmail.com/
v3: https://lore.kernel.org/linux-hardening/20240625032509.4155839-1-gatlin.newhouse@gmail.com/
v4: https://lore.kernel.org/linux-hardening/20240710203250.238782-1-gatlin.newhouse@gmail.com/
---
 MAINTAINERS                  |  2 ++
 arch/x86/include/asm/bug.h   | 12 ++++++++
 arch/x86/include/asm/ubsan.h | 18 ++++++++++++
 arch/x86/kernel/Makefile     |  1 +
 arch/x86/kernel/traps.c      | 57 ++++++++++++++++++++++++++++++++----
 arch/x86/kernel/ubsan.c      | 19 ++++++++++++
 6 files changed, 104 insertions(+), 5 deletions(-)
 create mode 100644 arch/x86/include/asm/ubsan.h
 create mode 100644 arch/x86/kernel/ubsan.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 28e20975c26f..b8512887ffb1 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -22635,6 +22635,8 @@ L:	kasan-dev@googlegroups.com
 L:	linux-hardening@vger.kernel.org
 S:	Supported
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
+F:	arch/x86/include/asm/ubsan.h
+F:	arch/x86/kernel/ubsan.c
 F:	Documentation/dev-tools/ubsan.rst
 F:	include/linux/ubsan.h
 F:	lib/Kconfig.ubsan
diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
index a3ec87d198ac..751e45ea27ca 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -13,6 +13,18 @@
 #define INSN_UD2	0x0b0f
 #define LEN_UD2		2
 
+/*
+ * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
+ */
+#define INSN_ASOP	0x67
+#define OPCODE_ESCAPE	0x0f
+#define SECOND_BYTE_OPCODE_UD1	0xb9
+#define SECOND_BYTE_OPCODE_UD2	0x0b
+
+#define BUG_NONE	0xffff
+#define BUG_UD1		0xfffe
+#define BUG_UD2		0xfffd
+
 #ifdef CONFIG_GENERIC_BUG
 
 #ifdef CONFIG_X86_32
diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
new file mode 100644
index 000000000000..1d7c2b4129de
--- /dev/null
+++ b/arch/x86/include/asm/ubsan.h
@@ -0,0 +1,18 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_X86_UBSAN_H
+#define _ASM_X86_UBSAN_H
+
+/*
+ * Clang Undefined Behavior Sanitizer trap mode support.
+ */
+#include <linux/bug.h>
+#include <linux/ubsan.h>
+#include <asm/ptrace.h>
+
+#ifdef CONFIG_UBSAN_TRAP
+void handle_ubsan_failure(struct pt_regs *regs, u32 type);
+#else
+static inline void handle_ubsan_failure(struct pt_regs *regs, u32 type) { return; }
+#endif /* CONFIG_UBSAN_TRAP */
+
+#endif /* _ASM_X86_UBSAN_H */
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 74077694da7d..fe1d9db27500 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -145,6 +145,7 @@ obj-$(CONFIG_UNWINDER_GUESS)		+= unwind_guess.o
 obj-$(CONFIG_AMD_MEM_ENCRYPT)		+= sev.o
 
 obj-$(CONFIG_CFI_CLANG)			+= cfi.o
+obj-$(CONFIG_UBSAN_TRAP)		+= ubsan.o
 
 obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o
 
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 4fa0b17e5043..6350d00a6555 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -67,6 +67,7 @@
 #include <asm/vdso.h>
 #include <asm/tdx.h>
 #include <asm/cfi.h>
+#include <asm/ubsan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -91,6 +92,45 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
 	return *(unsigned short *)addr == INSN_UD2;
 }
 
+/*
+ * Check for UD1 or UD2, accounting for Address Size Override Prefixes.
+ * If it's a UD1, get the ModRM byte to pass along to UBSan.
+ */
+__always_inline int decode_bug(unsigned long addr, u32 *imm)
+{
+	u8 v;
+
+	if (addr < TASK_SIZE_MAX)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (v == INSN_ASOP)
+		v = *(u8 *)(addr++);
+	if (v != OPCODE_ESCAPE)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (v == SECOND_BYTE_OPCODE_UD2)
+		return BUG_UD2;
+	if (v != SECOND_BYTE_OPCODE_UD1)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (X86_MODRM_RM(v) == 4)
+		addr++;
+
+	*imm = 0;
+	if (X86_MODRM_MOD(v) == 1)
+		*imm = *(u8 *)addr;
+	else if (X86_MODRM_MOD(v) == 2)
+		*imm = *(u32 *)addr;
+	else
+		WARN_ONCE(1, "Unexpected MODRM_MOD: %u\n", X86_MODRM_MOD(v));
+
+	return BUG_UD1;
+}
+
+
 static nokprobe_inline int
 do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
 		  struct pt_regs *regs,	long error_code)
@@ -216,6 +256,8 @@ static inline void handle_invalid_op(struct pt_regs *regs)
 static noinstr bool handle_bug(struct pt_regs *regs)
 {
 	bool handled = false;
+	int ud_type;
+	u32 imm;
 
 	/*
 	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
@@ -223,7 +265,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * irqentry_enter().
 	 */
 	kmsan_unpoison_entry_regs(regs);
-	if (!is_valid_bugaddr(regs->ip))
+	ud_type = decode_bug(regs->ip, &imm);
+	if (ud_type == BUG_NONE)
 		return handled;
 
 	/*
@@ -236,10 +279,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 */
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_enable();
-	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
-	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
-		regs->ip += LEN_UD2;
-		handled = true;
+	if (ud_type == BUG_UD2) {
+		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
+		    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
+			regs->ip += LEN_UD2;
+			handled = true;
+		}
+	} else {
+		handle_ubsan_failure(regs, imm);
 	}
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_disable();
diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
new file mode 100644
index 000000000000..63f819928820
--- /dev/null
+++ b/arch/x86/kernel/ubsan.c
@@ -0,0 +1,19 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Clang Undefined Behavior Sanitizer trap mode support.
+ */
+#include <linux/bug.h>
+#include <linux/string.h>
+#include <linux/printk.h>
+#include <linux/ubsan.h>
+#include <asm/ptrace.h>
+#include <asm/ubsan.h>
+
+/*
+ * Checks for the information embedded in the UD1 trap instruction
+ * for the UB Sanitizer in order to pass along debugging output.
+ */
+void handle_ubsan_failure(struct pt_regs *regs, u32 type)
+{
+	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240724000206.451425-1-gatlin.newhouse%40gmail.com.
