Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTUT3P4QKGQENDPNPZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA80244DE7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:47 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id e22sf3556854ejx.18
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426127; cv=pass;
        d=google.com; s=arc-20160816;
        b=vW54duuNRL4K+16bvG9ao1yNcosgCBZPV/t/TpBCDcDoWs3KcCq0soa88NRAz+IEHF
         XjsyGVXpMC3dRpO3VN0Eu0odAWC5RMf7wAJyAKt4E8YiBrBqBfSWU2ZsO23OHHQ0RcAI
         /CK7uDn0HELIA3Ex9Gk3Sv/yPC+MU2UpUebwSu2GqqIdwNjGEZzqRz06VPup6xSs+TY5
         +3oK4yT4CaBj510oVBIr0HTp4uKh4UjgSB9RZXYEbbSVSe2cGkO8Bk0YCjGz7nyjTLm0
         LMAa3uO4ISC/IXWGi3lyIRMSOLQ9uRIxw3hKQpJsdsUOoMi8R+p6tBYVHgDX9JjZEJnj
         5HCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iHsgntLbog8IP6hSN0QYwwi72uNpX7iaPw55bFcuq5I=;
        b=lvau2s8cULyXWhZO9GYoRbXuWOJh0cMhkuZnGQsIGEc6UWMySx6+DKFZgN5wug4fE9
         /90Pxt9FvUlof7CRt2ij1fh1XhE01gCrdNWr6C8R1e06iFM3B586rvmu+kjP6CN+BYvr
         cb8FyB7qe2WEgGvtKwtb0SLTWB9yFAaEPq9svGtwkQmr8sajXeNcarDfIP48/muwqppk
         AnJ6qVHEfDxKjIUI1oe8v81ay5hDtqY44bEgjhmHAL/q73aRKBmvoMU8YkF03Dh/q5Hc
         CcYACCU3rpdAE9wz5ztG0T6wleXu2pmT1mLwLZJlXbpiFiSRcRXsG4xRSZiUucftWux+
         JRvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VpPdM4Kj;
       spf=pass (google.com: domain of 3zsk2xwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zsk2XwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iHsgntLbog8IP6hSN0QYwwi72uNpX7iaPw55bFcuq5I=;
        b=PYsaskkVZJOJrmUdeJRYdkhIyitqyAc1kkblCz3070OWCR80u6LRZezqG9KUjCpzyS
         rv0KauTLfDXVi2hLzVRMydmTO5jjHap+3EQCQo/jxW2OvpwtPM2bZboF3Hei/DqQxx9U
         H3K8p+6mD44pE/2lRxHpYXaFfNkNDpm/AGCvBFlLIzm38yPecpc/TopHk6mMS07ek0uW
         iSyhbbGA37oSeET5jHl4Be40KorwWwE+6V1CPJC3yvcha64dAHXye8oQtBzJ8Up3Vkzt
         /WOUeINTYvN/eLpGOTh7AHWIDQePkQILmt5UKTwdTlfGZU+0zrktU8Qg6Rw2KZE2fzJa
         1vug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iHsgntLbog8IP6hSN0QYwwi72uNpX7iaPw55bFcuq5I=;
        b=qRp+fZ0DRvgRsyZLhsSTvGX41RkRdtF8saTN+8TBeRwHH3enwQ8aFY1TUkGrBrDjev
         R6Up69YU7A+44zN2LsmmrskGFA/zKhAegYEPtc5Dagb37D1ZIjwlipqKws5TK3Ysx3Tn
         G/pxXWSe4gkl/pmr2hajfFI4Le9HCiEIkIa8jyD/IGOX1HoWGuFavjnR4MbZlfyxraRx
         1DBjyN7Z/hSnxgBx75HuXsqGVrvRSK0fkr6PtYXlHt84orkSVLEh3G+D4H92LPfaEDeA
         54msNYSXeP61XrUiOeEcc5SvyJsd72amq/6TX7mcn/B7jLkq0QJOw4vnd9KqUwJzro54
         3WqA==
X-Gm-Message-State: AOAM53314SSOMToUaClhrQC+e3RFxa1MJYi+hKR9zjpHCNIdX3do010n
	8b2qoWODevbxucZ2rW9tgKc=
X-Google-Smtp-Source: ABdhPJwvtZozs+LWjoNIQMtuaBLqiAXPasw/bkS6qqobOoiWmxtK/FC1otjfEzsioq4wO7svohqO2Q==
X-Received: by 2002:a50:e1cf:: with SMTP id m15mr3294981edl.303.1597426126916;
        Fri, 14 Aug 2020 10:28:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bc05:: with SMTP id j5ls1080278edh.0.gmail; Fri, 14 Aug
 2020 10:28:46 -0700 (PDT)
X-Received: by 2002:a05:6402:8c3:: with SMTP id d3mr3336468edz.187.1597426126371;
        Fri, 14 Aug 2020 10:28:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426126; cv=none;
        d=google.com; s=arc-20160816;
        b=MYm6x7aFAqk+8JFljUOQqt5qJ+LF1OSw5k602cW7j1h4EJNMQwUwhswymxpApx80BC
         vGwnoz6CfYdGXMZl5Qy95yoi/RrCkfmEYuCh22045lhlTAX9JZKoFsqTZXP2olZJbwxz
         7OiRxAD3leC1D9m+UevyeTZDWz3ldILLUuKOcNX8z9i7mqRCC8DnKj1Ds75xQ7OQBZ0K
         v8HOeY3KhPFZJ/mWFbVO/1IjhyOVqQ1ffR3NrqEw4R3AQ35tCB0ib+53ahXAjbXnAWnQ
         r+y6ccN36hhx3NX5MI2rL19pqe5453l+S8HdqXl1CFH5qJO7EPoW8m9MSZZUWiUq31yR
         +Tzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZNAU/quOyDd65Y8FbbPHdMn2fE8Roa22GmWzXnVDZak=;
        b=XJzEzPD0NvbA/F/pJSvwzV6Lc/Vm32Yi1t+Jt3CrgLylv6TqfqDcWaggJ2QeN3N+bR
         s1Db7KUcZ/24/lynxNQ0u+sbRLvG75ltvRp0PXXjGN4m3sZcPAqFHDhgwv3jpxM5HXzD
         7/jiyRceUmElFVCQxMZeJQZwkjvyREhffv3/IUhxL2dKoSixeYQF1oPnFHmmgQZY0xJy
         WIv3EFWd38ohPpRRdwnQAu+1x6sdygZvLRLpo8UmmGGMCHeR9bonseTQUHaG5lpipd+h
         pMiXxfzQIUptmMvGd/oymTsCSxlKMDgAr0lv3uHdm0R1NyiKSsnH5VFvtd0UkPx56TTr
         Mmnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VpPdM4Kj;
       spf=pass (google.com: domain of 3zsk2xwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zsk2XwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b5si418449edx.4.2020.08.14.10.28.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zsk2xwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j2so3611042wrr.14
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:46 -0700 (PDT)
X-Received: by 2002:a1c:f416:: with SMTP id z22mr3308371wma.62.1597426126049;
 Fri, 14 Aug 2020 10:28:46 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:17 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <5d0f3c0ee55c58ffa9f58bdea6fa6bf4f6f973a4.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 35/35] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VpPdM4Kj;       spf=pass
 (google.com: domain of 3zsk2xwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zsk2XwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
---
 Documentation/dev-tools/kasan.rst | 73 +++++++++++++++++++++----------
 1 file changed, 51 insertions(+), 22 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a3030fc6afe5..aeed89d6eaf5 100644
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
 8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
@@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
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
@@ -196,17 +200,20 @@ and the second to last.
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
-store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
-uses shadow memory to store memory tags associated with each 16-byte memory
-cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
+Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64
+CPUs to store a pointer tag in the top byte of kernel pointers. Like generic
+KASAN it uses shadow memory to store memory tags associated with each 16-byte
+memory cell (therefore it dedicates 1/16th of the kernel memory for shadow
+memory).
+
+On each memory allocation software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds this tag into the returned
+pointer.
 
-On each memory allocation tag-based KASAN generates a random tag, tags the
-allocated memory with this tag, and embeds this tag into the returned pointer.
 Software tag-based KASAN uses compile-time instrumentation to insert checks
 before each memory access. These checks make sure that tag of the memory that
 is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch tag-based KASAN prints a bug report.
+memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
 
 Software tag-based KASAN also has two instrumentation modes (outline, that
 emits callbacks to check memory accesses; and inline, that performs the shadow
@@ -215,9 +222,31 @@ simply printed from the function that performs the access check. With inline
 instrumentation a brk instruction is emitted by the compiler, and a dedicated
 brk handler is used to print bug reports.
 
-A potential expansion of this mode is a hardware tag-based mode, which would
-use hardware memory tagging support instead of compiler instrumentation and
-manual shadow memory manipulation.
+Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses aren't
+checked).
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
+Hardware tag-based KASAN is based on both arm64 Memory Tagging Extension (MTE)
+introduced in ARMv8.5 Instruction Set Architecture, and Top Byte Ignore (TBI).
+
+Special arm64 instructions are used to assign memory tags for each allocation.
+Same tags are assigned to pointers to those allocations. On every memory
+access, hardware makes sure that tag of the memory that is being accessed is
+equal to tag of the pointer that is used to access this memory. In case of a
+tag mismatch a fault is generated and a report is printed.
+
+Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses aren't
+checked).
+
+Hardware tag-based KASAN currently only supports tagging of slab memory.
 
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d0f3c0ee55c58ffa9f58bdea6fa6bf4f6f973a4.1597425745.git.andreyknvl%40google.com.
