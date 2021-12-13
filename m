Return-Path: <kasan-dev+bncBAABB2MC36GQMGQEQPGDLGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F8447370C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:54 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id i123-20020a2e2281000000b0021cfde1fa8esf4862371lji.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432553; cv=pass;
        d=google.com; s=arc-20160816;
        b=nJ6fd1HImaDlb7BmfYxgauz+g1LLb7qBC6QZ6Co6LAV6HIwP40U6bFgLC3LhX5vTLu
         oTDEVEpdk/CmRAtC04jTnV3v7FX4HW9T+Vz0A8R6LjdJ/oCNzHAeI5co0HYkJADIj7/O
         pDhHlx9dtcMdD7XsK5NTDW5NxKv79KmqH2O3rIm2CfVD1NCGx1SiTdcZ/Jm1/cuHHglv
         ffkGy4abzrCzriRBjukgyRGcBMpxybxzK7CDDcKOEXZkLZc9RoHmHo+J7h+dcjU6+uA3
         /rxFBZirVwjPRBcIq0m9rCjgLZg1/GFoKt7CbpbYv9PTIenrZz20NnLmNRh8vD2bUMwm
         728A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PKpDi4yhx+Ox6TcaBjLRdq/5mOlYAndyJZSp0adxsoQ=;
        b=BpRa1TraGvOi9um2A0tkNumbJh6ItvFAIs7Bw7pfN8U5grqcMhWzk/ZZJHI416tWnr
         EZWbDRN8KILjXOiSlMMhfCaoYg5hTRgzM+eVwxU+8wvqOwUdVwuEyMSxFKeyBP14svBS
         0HgYZxrBYwAGIJRmSxNjHxdjnm2Lk5r/n9jnV0iuvkrtjMu8FfhoQK+LelkEVjDjScjr
         SFpi9bjSoHp4CLqWazTMO5Nw9DdkVDj7gv6EPYIcRLw7g7z9hXUovkX0+ZzIQnsmXGnh
         UeugNcuKv8MEfPiMCh75NiFprEiI8A5HRkO2LWvcFVrnzDwgTr75+Vy/cEjhZqH9XZnN
         KQZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VrpiAL19;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKpDi4yhx+Ox6TcaBjLRdq/5mOlYAndyJZSp0adxsoQ=;
        b=hLgrcWikZMR9AvhJy44j/8/8XMnwzp/CPj3y42E9GPw3vENrPGdfR+2wLJ7jmzIbLq
         +5JEAEAOOK67ULtzrIJMKXZ4RbjRa5YotK1ewUdo7a+Z+LaTOTFZsESEgV5zhF3PR6R1
         QBQk1yFLp4wGE9BC0BfWUooVBWeLJMUBlalpsf39xTQOYJ/YrPYikG8gHUs3XXvU5PFj
         SxewfTdGLTmuCkuAGCnj3cYDIURSZJ3vd8Z2AizAvsz6+4Tw/WQWuVKVcpZQBzM9JfBu
         Zu+NV8rJwco1uxLlzsvmlOlVNbglM+NOB4pk5ImFZ2Cb5EX/8HSKpp5QygTp1B7KfEaJ
         rVNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKpDi4yhx+Ox6TcaBjLRdq/5mOlYAndyJZSp0adxsoQ=;
        b=7tebc2xbY+2weU/RJaBYPCIPleIbRqRA5jmDWL83l3bipDyD+APu8Gk/7k1jbFWRTn
         wXpL3Eyr1JErZw+WeLOsasOqpyvdj4fN2eTymluXyLnADHw139ElXvmDfVqc/VvRvDhP
         7N+Gfjcx+emMRGemXdR2wVauHzZmNf7THKux6t8g+aGRnyU7LcL8wZI6rc2m7EF4/vlD
         JwXCSmtfIB7BxWRGvsMLqIpb5AjIH3h5L32p2IptI5ZDw1N0OFWLgEx89jB1jBtqnspT
         y0Eky8ml34SM2W/4FY1Z7+81C8dALdDl+VEEI4miTH6Log8QarM1JXNXp9grPR1xQH+V
         gO0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313v7ltVEl2fn7HRzQ+t4+xVPaCl+rcivdVx9CECgCNfpw95EnN
	Ma+yjQgOrE/scY//VBp7Lo8=
X-Google-Smtp-Source: ABdhPJwkGtlDvFEcIeBxkVMHXOnS9w9n+GkxNVEBgxjVKOoJ35gG/MY0hKkku1bxNZDhW11/OUHK6A==
X-Received: by 2002:a2e:a28e:: with SMTP id k14mr1105460lja.488.1639432553798;
        Mon, 13 Dec 2021 13:55:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1552869lfu.2.gmail; Mon,
 13 Dec 2021 13:55:53 -0800 (PST)
X-Received: by 2002:a05:6512:b10:: with SMTP id w16mr952029lfu.223.1639432553048;
        Mon, 13 Dec 2021 13:55:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432553; cv=none;
        d=google.com; s=arc-20160816;
        b=BzSYPEEP75UJdgGe88VHmn56wGL+U+av7NeF4hUCWJVaXL6fhWcdna9b+RoNO7oSFP
         JdPmDMXLIdOKlJ+ZrVHI8JFgdlwHaAvyH6lY2QocGvWl/tiNhrZJrSKCShDufG52Xrcc
         JuBKqtlqMCzqE2b093uiRbRy2uoOfxH1KKTbSlFKDuvBrbFTKuiSPSHpIVcrZfAieWah
         tTpQha4hqhFW6dY4FkWYVKe+esX7pcWF5KR+Ah2MdJcXlcNZsy0lOMWb5X4FH7hL+Le7
         Y2AnRxqvyb+13bY+9qQ/xy/8t3iV+ETImlmSk5CZ4iaTGW67hl7PS8lAUzk6bpM7AJtp
         WBTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=iMjOKkeTP2Q4svlBcTkRZ68eWjZAaOVU142FAuOxR6NhedR1b3QP/IkYUq0pJRM/4l
         NbQMTlWhW4I+DO8pR6kZje+gzH+Hyx92kD+uZOoIs7kJ2MpgwSoZsdwP/BfMqW/ka3J6
         p9/vb/M6NppVhjni1Qj6ny/AOMDgxvLUkFBiPwjWHsm3yHkL0f01SqvhEj4dm6/ZsFo4
         jl2/BB/C4eE6JORS2M3CA2PVXVKFPs/+rgP2SM7Js84nqykGDzdH0r0If17o10XpH3bw
         lGrC2add7luHps0G/R3Ua+9o3YLBYgmrcrADuW0OxrlKEwvuZzJewPbvkZZ/WrptjXnf
         nnYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VrpiAL19;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y8si615445lfj.0.2021.12.13.13.55.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 37/38] kasan: documentation updates
Date: Mon, 13 Dec 2021 22:55:39 +0100
Message-Id: <7159d84eee5ade160a139a28116fceded025108c.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VrpiAL19;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Update KASAN documentation:

- Bump Clang version requirement for HW_TAGS as ARM64_MTE depends on
  AS_HAS_LSE_ATOMICS as of commit 2decad92f4731 ("arm64: mte: Ensure
  TIF_MTE_ASYNC_FAULT is set atomically"), which requires Clang 12.
- Add description of the new kasan.vmalloc command line flag.
- Mention that SW_TAGS and HW_TAGS modes now support vmalloc tagging.
- Explicitly say that the "Shadow memory" section is only applicable
  to software KASAN modes.
- Mention that shadow-based KASAN_VMALLOC is supported on arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 17 +++++++++++------
 1 file changed, 11 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 8089c559d339..7614a1fc30fa 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -30,7 +30,7 @@ Software tag-based KASAN mode is only supported in Clang.
 
 The hardware KASAN mode (#3) relies on hardware to perform the checks but
 still requires a compiler version that supports memory tagging instructions.
-This mode is supported in GCC 10+ and Clang 11+.
+This mode is supported in GCC 10+ and Clang 12+.
 
 Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
@@ -206,6 +206,9 @@ additional boot parameters that allow disabling KASAN or controlling features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
+  allocations (default: ``on``).
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
@@ -279,8 +282,8 @@ Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Software tag-based KASAN currently only supports tagging of slab, page_alloc,
+and vmalloc memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -303,8 +306,8 @@ Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
+and VM_ALLOC-based vmalloc memory.
 
 If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
 will not be enabled. In this case, all KASAN boot parameters are ignored.
@@ -319,6 +322,8 @@ checking gets disabled.
 Shadow memory
 -------------
 
+The contents of this section are only applicable to software KASAN modes.
+
 The kernel maps memory in several different parts of the address space.
 The range of kernel virtual addresses is large: there is not enough real
 memory to support a real shadow region for every address that could be
@@ -349,7 +354,7 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and powerpc.
+arm64, riscv, s390, and powerpc.
 
 This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7159d84eee5ade160a139a28116fceded025108c.1639432170.git.andreyknvl%40google.com.
