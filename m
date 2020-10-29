Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL5P5T6AKGQE4OEGNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E4F5D29F516
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:44 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id g187sf1552178oib.11
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999664; cv=pass;
        d=google.com; s=arc-20160816;
        b=usVVg7stKJ8yHnHN1GDn2I4drwmgag7WfEme8Wj5H1OO7FQ+umpjHfNgno8/qP9Jv4
         IcGeplx1KUgrvBmDzJaDTO+Pz3hk4sQcc737pdXF86Da5qgt5Fm+juHWoOtONMjKdVoJ
         THHyBBWtbZmFOXFY1Ct1WUBZcpkDFHpyypyNXaMWL6rip4GUeboRZEchenXaAeJoZ03q
         87bWlrxDCLhJbRc7p0GqASGEX0f2u1SRUguKildmqqRCMMFjjXYeN/wjuWgcfyDd2Z0C
         f3ygBzQ+mm9El30GCk/D23oQoTptmbaZeC8vHn9K8dKibfT94LlLTWXLfCgCpS/Sqjts
         nsEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Ssv2Xd6XsEtmVTMi0u/5SwWVWuge18z1d8eIhE+xzVo=;
        b=NTG3WUqnNeniPb8O4pfX5OlbXPipgkCxtcUIuZgJB5ulcXMlXfV0GZwMcudV2l9VYE
         afhWa/F2pTK6K6x0S/wAFQBkyEUoPST6HFeJ/MzwNnjxqeMGzJiXpGQeFuWyvapE0Lwy
         gcpW9BzCAM/fW46/yQmSjxmOFDYS3VGiqU0GdXf7s34iPOMrqeu8ncS92QgdMn+fvFKe
         w5hTZseVDnJ7+5eaErrJmvgEMoTQ6vlgAWpWznfIvxffdRlUxRUqP4ilYJwrAkw8gMqZ
         +0WljfiXrTLn1N028MrDX62/vbKhcgqWMCIe7wc/uOo4MV57HJOggeOw1tuNkIjemvTH
         jBPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c9rgrTFU;
       spf=pass (google.com: domain of 3rxebxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxebXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ssv2Xd6XsEtmVTMi0u/5SwWVWuge18z1d8eIhE+xzVo=;
        b=frrWAjGQrllVjIqmbmFtqujsvJtz7HsOmXyXR23rGjfBkSurmzqjr0/RlU2TFu6GJi
         xyewTWKU5Bm0Lyy1H3ygz608PCzZ7taOUqEjQFdI72qPqJ8qcXoT2hrlGm5YiYEINCJC
         TGu8rGU2x1mbqA4YS8HsF/gCy9PiFnc8UXIP7RBH2qTttEEsbgs+FyWxs9L1g2nAdGuH
         X8cOQfSnAqI51p14yRSrspFvQ/SYKsNGjOWe/cSioxQBAyb1O6dJiJ6nD95FIUK0NaXQ
         NOD10G0ZDOOlWPu4oGkLRTFUn5vlZNES2AddINNXZBb7YBhqHOPhjTxg1HxgGLVqW3wS
         NAkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ssv2Xd6XsEtmVTMi0u/5SwWVWuge18z1d8eIhE+xzVo=;
        b=WsR6jp1FL4yt8t5qq+gwAN2I0xMN0akiB6AcbrW3cSiFxwApqtOca8kjPgKv8POuEg
         +NX4esL653a1vSMtPGb18JO5Vcs5XB6l+f4DZxEf/ebusHFtrWz+UN6wq+iBFGxundAL
         CNo8m76O4hCi4CgvFZZdQOwWogH/THH3zahmFFerSFrQa2DLjmKSUI/27AxQWAZhMZBR
         wweCM9r3CnDFNaBVjgeKSjuZE7UuthNLTKlg3NMJxK1tX9LY0Xe6/mMNFA/69EApqQ7V
         Kcqwt14aHCn2FuCpbYD0kre3RFoe/OysVlPXlJULF+69BVw5Eh7LnKlugb3+FeRh6zNw
         NIzg==
X-Gm-Message-State: AOAM532mIJ25Q4zW9t+Xq1VAswI0a2lkLJOIcebNhvjhKOdoMCKazhcr
	vZth8BS5LlIwFFYmtl750hY=
X-Google-Smtp-Source: ABdhPJzj/DC8ph6kmJJHUCw63KVo9L9eMYlkMK1VW5lAlE3LrRETK9DIrlUL3nRKKsIPxEMd81Pj/g==
X-Received: by 2002:a54:4808:: with SMTP id j8mr886688oij.136.1603999663879;
        Thu, 29 Oct 2020 12:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:b12:: with SMTP id s18ls955740oij.3.gmail; Thu, 29
 Oct 2020 12:27:43 -0700 (PDT)
X-Received: by 2002:aca:30d7:: with SMTP id w206mr852456oiw.69.1603999663540;
        Thu, 29 Oct 2020 12:27:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999663; cv=none;
        d=google.com; s=arc-20160816;
        b=c+XFbf02zQbPwdxU8cCQi9bQY8UspKp0v8IRQ8TqsYH1Ua0aZZhLB852rH4Y2O4tk5
         ayjHURFHwWiHSURvDqRgtVo6PK889c+ZGE2dmxAh+MtEuJXXYYgeMg27vDx5cidfPmOb
         FZAOJnIMZm7nlgEmB23ahLLCC5oF16OewDB8nZBhZuZInC5JLDPun0vj6+zEa8E/DXTJ
         r9rZTawNi5q/IEGqInOH6+rVG8T8eToGjY1fVvsANvbyb75EBIYUEcF+sy5/yQstrDi4
         XCI710cBX9lZOv6C6P5lKPXM0QqODaME9I1cGjXFiK91a5wfJT0Ud1jYtZE9Gl7MVs3s
         ycSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m61njPxPjXbU7KpGf2VpyrS3MAG/f/HeOixCOkKzSfs=;
        b=Kjd5CMIcsDpczeyY0CC+U41tJrwzX54clNY/jzwdrpOam8Yss2UJqlhfMpBv88VIKW
         pYcRoxw7W97mT3jx30zOG9xNrRL/kf/I+Bro6uOrAmMehVN3sodW+7nvGsHtYqLGlMpx
         8keuJh6/tI7iVfhlHFL/53CJYZmghy/bpa3YBEuaKYQLgtY4cOxLm7S8ljZrToxoNHuK
         qoIyH48d6zroJxmop1YPC0+SvoP/B1ukk+HaCuqVMONqbka43emRIxp0HQLtV7VGyAG8
         4sx+9lUx1DJgpXIb4GFWupuVhPle1SazEfSfy39r6Y0I6zJ8iaYmZKR8iNWXhdeCHHpH
         0Jhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c9rgrTFU;
       spf=pass (google.com: domain of 3rxebxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxebXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r6si526786oth.4.2020.10.29.12.27.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rxebxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id e8so2495427qtp.18
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:43 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f14b:: with SMTP id
 y11mr6066348qvl.35.1603999663004; Thu, 29 Oct 2020 12:27:43 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:26:00 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <25b961778f590965c697f9310297d9a0cbe4c181.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 39/40] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c9rgrTFU;       spf=pass
 (google.com: domain of 3rxebxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxebXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Add documentation for hardware tag-based KASAN mode and also add some
clarifications for software tag-based mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
---
 Documentation/dev-tools/kasan.rst | 78 ++++++++++++++++++++++---------
 1 file changed, 57 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b6db715830f9..5bfafecfc033 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -5,12 +5,14 @@ Overview
 --------
 
 KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
-find out-of-bound and use-after-free bugs. KASAN has two modes: generic KASAN
-(similar to userspace ASan) and software tag-based KASAN (similar to userspace
-HWASan).
+find out-of-bound and use-after-free bugs. KASAN has three modes:
+1. generic KASAN (similar to userspace ASan),
+2. software tag-based KASAN (similar to userspace HWASan),
+3. hardware tag-based KASAN (based on hardware memory tagging).
 
-KASAN uses compile-time instrumentation to insert validity checks before every
-memory access, and therefore requires a compiler version that supports that.
+Software KASAN modes (1 and 2) use compile-time instrumentation to insert
+validity checks before every memory access, and therefore require a compiler
+version that supports that.
 
 Generic KASAN is supported in both GCC and Clang. With GCC it requires version
 8.3.0 or later. Any supported Clang version is compatible, but detection of
@@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
 Usage
 -----
@@ -28,14 +30,16 @@ To enable KASAN configure kernel with::
 
 	  CONFIG_KASAN = y
 
-and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN) and
-CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN).
+and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
+CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
+CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
 
-You also need to choose between CONFIG_KASAN_OUTLINE and CONFIG_KASAN_INLINE.
-Outline and inline are compiler instrumentation types. The former produces
-smaller binary while the latter is 1.1 - 2 times faster.
+For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
+CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
+The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
-Both KASAN modes work with both SLUB and SLAB memory allocators.
+Both software KASAN modes work with both SLUB and SLAB memory allocators,
+hardware tag-based KASAN currently only support SLUB.
 For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
@@ -196,17 +200,24 @@ and the second to last.
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
-store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
-uses shadow memory to store memory tags associated with each 16-byte memory
+Software tag-based KASAN requires software memory tagging support in the form
+of HWASan-like compiler instrumentation (see HWASan documentation for details).
+
+Software tag-based KASAN is currently only implemented for arm64 architecture.
+
+Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
+to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
+it uses shadow memory to store memory tags associated with each 16-byte memory
 cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation tag-based KASAN generates a random tag, tags the
-allocated memory with this tag, and embeds this tag into the returned pointer.
+On each memory allocation software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds this tag into the returned
+pointer.
+
 Software tag-based KASAN uses compile-time instrumentation to insert checks
 before each memory access. These checks make sure that tag of the memory that
 is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch tag-based KASAN prints a bug report.
+memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
 
 Software tag-based KASAN also has two instrumentation modes (outline, that
 emits callbacks to check memory accesses; and inline, that performs the shadow
@@ -215,9 +226,34 @@ simply printed from the function that performs the access check. With inline
 instrumentation a brk instruction is emitted by the compiler, and a dedicated
 brk handler is used to print bug reports.
 
-A potential expansion of this mode is a hardware tag-based mode, which would
-use hardware memory tagging support instead of compiler instrumentation and
-manual shadow memory manipulation.
+Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Software tag-based KASAN currently only supports tagging of slab memory.
+
+Hardware tag-based KASAN
+~~~~~~~~~~~~~~~~~~~~~~~~
+
+Hardware tag-based KASAN is similar to the software mode in concept, but uses
+hardware memory tagging support instead of compiler instrumentation and
+shadow memory.
+
+Hardware tag-based KASAN is currently only implemented for arm64 architecture
+and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
+Instruction Set Architecture, and Top Byte Ignore (TBI).
+
+Special arm64 instructions are used to assign memory tags for each allocation.
+Same tags are assigned to pointers to those allocations. On every memory
+access, hardware makes sure that tag of the memory that is being accessed is
+equal to tag of the pointer that is used to access this memory. In case of a
+tag mismatch a fault is generated and a report is printed.
+
+Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Hardware tag-based KASAN currently only supports tagging of slab memory.
 
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25b961778f590965c697f9310297d9a0cbe4c181.1603999489.git.andreyknvl%40google.com.
