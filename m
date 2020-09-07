Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7PQ3D5AKGQEM7EFNNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3280C25FB8E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:19 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id w200sf4318827oie.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486078; cv=pass;
        d=google.com; s=arc-20160816;
        b=jJz573IB38hEevqYb5D7PFM3HF8tbp2b1EfVEVKzT/fRp84B1ShnCNusS0ZGloSCnS
         ZdOsYlgQ6JXrjjqpBd6o3HL0ZMEbEoNGf475H/ErK1v5AEhwFCd4A1ocvlgeUjm4Hdf5
         ZRGBVjhqsURFHiRn4saAn2vCKLvkZEcoV5vLbfM5TrLZhbz5neOrIyAj3kZu9WG6P1so
         mTI6ibmE1WtNQ2buZU8W61PPvz5VcKx6yaIvYY2LlmIFzpp1Ve870fNUHcX+/AC8YP92
         WPcV3Z7NGx7WjWSLaO+iYnEedGSBncQh9Fc2qTWKdGJ4DmH/fW9gUARp8kxji4KTcq3Y
         FSQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TD0S31XORgZ5+hUCYHm4ZeQeuRE4n6zTkSiMgvLVdQI=;
        b=a7K5Tm44Wmx3xhMokJGiMIbW263f3SGqQmYgdL3DgZPdhRDJzRn/HYhRyQDRN09/Oh
         uYxiv2xIcEzJqfv4tDmeiqviYXqZmMQxZZpHptBjoHTcdDJ5JvfSNYF6WtlVBDTh5PZs
         +x0JDRGLuvqy/kinYVTyXPYvicDqyNBgwyg5V/kSfFSJoOG1iVEm2FAobFx6MhBuB4sE
         Lz2TPcclAeQoHpx4EUJxEm+Flu8ugu68PsapbwG0V3+awaAQB/FqhPuoVvvCrj9S/b6i
         sQRJFPwLctCXVQuUpT0Z1ldCit7Ux2JoRbvo5ygrPQtPjxLPohm31PzGVrbDy41xTfaA
         uPcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JLnpFrQD;
       spf=pass (google.com: domain of 3fdhwxwukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3fDhWXwUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TD0S31XORgZ5+hUCYHm4ZeQeuRE4n6zTkSiMgvLVdQI=;
        b=ghCI6bOT+5LDU5CJtqqX7eWCixwh6R9mq+f3BhFoLYXYBH41I64LGV5nIvt/ECFddu
         u6fPmGOg8xYF7xUiVX8G8cLa9M8eZsssaNXZs7oQqk26tmOm+GsbHTTAEGOnlD05CJJs
         RgxK5HGnipJbaR3ca565NTcxqHhcyNBaRr1+yfRaT97CIRo9fZgfJzG3sspsqwMYo5u8
         QjYmn65RXvaPAL9iYQKrHvtusCLdiyMRBF2AioYf7HxMkTHi3+shTUwHkebaDmgOzdVm
         ne+OtCAkJVu3xkul9mxJIES6PuYrugQi1CWLFFtfTjuNBdgDg4hUfQaQfM6hxpRbZyzs
         udHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TD0S31XORgZ5+hUCYHm4ZeQeuRE4n6zTkSiMgvLVdQI=;
        b=TEwDWSijduybq+YzKSt/ZzdQt4cqrC+s1HwSkpGZ11Y8E0VHz0pQYyBZ0E+Y7Gp2bY
         JLKBwBNK9cFdSHwolkfCtJ26iyN+MxlsqWX+ob8BZtSWSBOBjj1VzXDYb1gdLWHjlGVH
         A0H0NSfIUTynMcoBzr9gjT5nzG+KCeklFfpKwC23GhSO8BmXCyUx6cwFSZ6GT8b5IdOR
         MpR0n1VJiG/0NOAiK1Tqqbv0VV4pJEF94V8Q+eHzVdbMfgPXlvKgqjNa5gx0l8w17BSu
         gDDpunt5DtX3xl8uchpmZ4+mfuQj1xQIZBltQwbuXNsRn8wcgO+B2zdiRrs90fem7Wlv
         4lHw==
X-Gm-Message-State: AOAM5331Zs5T/r8EhpIzjE1dGDr4gmrJ6gfOIztak3Q+qXnBN1EVLJmG
	/o2Jx+Wa6qRVpbwm+nvqL7k=
X-Google-Smtp-Source: ABdhPJwSbG5oE7/ACmFqZEc2jzgAGWMne0nwq56UE6al8w2Sr+PWQfWwDLfdgRWvUKzVI1gB943QlA==
X-Received: by 2002:aca:cd55:: with SMTP id d82mr12493024oig.163.1599486077916;
        Mon, 07 Sep 2020 06:41:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:84c:: with SMTP id 70ls4305229oty.5.gmail; Mon, 07 Sep
 2020 06:41:17 -0700 (PDT)
X-Received: by 2002:a05:6830:204a:: with SMTP id f10mr12918143otp.229.1599486077562;
        Mon, 07 Sep 2020 06:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486077; cv=none;
        d=google.com; s=arc-20160816;
        b=auphqzH8Zb2+FbWgaILxDNw+GPaT9QXqe7hsR1tGafCIJGOE6A/3cY97+OnFiJ5HpG
         IA8r/0RM+kK8zkYEOUGVXkLhwkMMSxnSuPryyXx3WEizoOz+Rbi1RWLRF5fZ3H0Bh9iZ
         ZDoafHVjmuRF/RZzp3KOtGQu/w0+pmiVVntevsg/Sl7Cda96A0+7Rq4QZoD/nhHCH5qD
         7noFGOvCsVebk35+61bBWzD+yi25AvYs5n8lx9d/kLH9J9VAZpkY2jdUC9cvH4tYvvz5
         H9G/JLOkAkU7KokbSqZXR+al4AsJZZn7XluRpU2VcYynJDV0h+TjPg+CVKtKmAd9MJig
         XWWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jc0VYpbbwwHp06Vd4b4APbV9LFmrdZq9B0FcghhcNas=;
        b=ZlWQ/qHf122G9prBtn05VQ/+VTKGQl1w/rvKsY3eXCKxxJJW0LEJGkHmLhkznwYta3
         oWNHcJLX5E/9roqa4Dacom782mYtEiDHGVeQzqYBITSZC2enXV1A1sQF5FxYRO782iSG
         1L+n9CPheM9NlpHSPzFH9WhVOmdopHG6kmXNrjyLXIpxmpyXwZtwYQqmW47+Y8/+iirb
         3na6uxDEWCFeXeyXUHD2qPDJmgU8zYvNXIQTmqqRfXlW7VV/g/5VjtR02/aK5TyzwOIT
         cTIkL7EP/RMCPVCh6a2jHrn2md8DIARnS9gcfAJD36RTuIZajlgtcWpxfj1jB+LlgEuH
         nRQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JLnpFrQD;
       spf=pass (google.com: domain of 3fdhwxwukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3fDhWXwUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id k144si339576oih.5.2020.09.07.06.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fdhwxwukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id o14so6937529qtq.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:17 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:17ca:: with SMTP id
 cu10mr18279241qvb.6.1599486076914; Mon, 07 Sep 2020 06:41:16 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:48 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-4-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 03/10] arm64, kfence: enable KFENCE for ARM64
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JLnpFrQD;       spf=pass
 (google.com: domain of 3fdhwxwukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3fDhWXwUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the arm64 architecture. In particular, this implements the
required interface in <asm/kfence.h>. Currently, the arm64 version does
not yet use a statically allocated memory pool, at the cost of a pointer
load for each is_kfence_address().

Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
For ARM64, we would like to solicit feedback on what the best option is
to obtain a constant address for __kfence_pool. One option is to declare
a memory range in the memory layout to be dedicated to KFENCE (like is
done for KASAN), however, it is unclear if this is the best available
option. We would like to avoid touching the memory layout.
---
 arch/arm64/Kconfig              |  1 +
 arch/arm64/include/asm/kfence.h | 39 +++++++++++++++++++++++++++++++++
 arch/arm64/mm/fault.c           |  4 ++++
 3 files changed, 44 insertions(+)
 create mode 100644 arch/arm64/include/asm/kfence.h

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6d232837cbee..1acc6b2877c3 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
new file mode 100644
index 000000000000..608dde80e5ca
--- /dev/null
+++ b/arch/arm64/include/asm/kfence.h
@@ -0,0 +1,39 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_KFENCE_H
+#define __ASM_KFENCE_H
+
+#include <linux/kfence.h>
+#include <linux/log2.h>
+#include <linux/mm.h>
+
+#include <asm/cacheflush.h>
+
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
+
+/*
+ * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically allocated
+ * __kfence_pool, to avoid the extra pointer load for is_kfence_address(). By
+ * default, however, we do not have struct pages for static allocations.
+ */
+
+static inline bool arch_kfence_initialize_pool(void)
+{
+	const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
+	struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
+
+	if (!pages)
+		return false;
+
+	__kfence_pool = page_address(pages);
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	set_memory_valid(addr, 1, !protect);
+
+	return true;
+}
+
+#endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index f07333e86c2f..d5b72ecbeeea 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -10,6 +10,7 @@
 #include <linux/acpi.h>
 #include <linux/bitfield.h>
 #include <linux/extable.h>
+#include <linux/kfence.h>
 #include <linux/signal.h>
 #include <linux/mm.h>
 #include <linux/hardirq.h>
@@ -310,6 +311,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (kfence_handle_page_fault(addr))
+		return;
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-4-elver%40google.com.
