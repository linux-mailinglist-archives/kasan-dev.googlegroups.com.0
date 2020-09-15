Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAO7QT5QKGQEJXKWEDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id EC7BE26AF70
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:54 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id a4sf911200vkl.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204674; cv=pass;
        d=google.com; s=arc-20160816;
        b=lB5oTNQW1jFv6zeSAE04kOUmdcFfPNgn+alOaflz5/Lp5moPKtAViPErcVeDI94rH+
         dT4vJu6tPrLPmJySZaVVC6DCKzGbviQYog70R36JS8zjA7cNFxkiiql7QS0cKrwmzUY5
         2ZXL31MCwaNUx++vCHaIJ163BA/EjZTRMrLSzc1uFXS9uv+ARJbdP/Zj2OOP3wAIMvhX
         rx+6caEWHpjy4Nkp4mpfA+OMqohTKtOBrHpYnhwQ4p4Df66/kSe9IOcyS/zkaWsp8F9J
         hU2bsSQ3fsm+qP4jaJ255XvJbNN+ZcvAJYEhu5ih1442uHp2SWSXnI1jGtl+bgBglLvy
         exLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CC35zv/e3M4YPhFcc/MrDbvDfwrvD83mKoMQ5vBXkI8=;
        b=n7/HIln/SDEwezY30P8ceBegkbxqukpAaDta0kfOj0u2BXbbQAX/Jj0sbQI8EcN0OI
         gMtTImuH8ws8Yjx26cncXdySApvzTmk8wpLPKQxdEweplApUg03mMyNHZX038IYwwR4x
         LgO6XCT9HwI2UvmIuiyGvjRtpY1aZ9t7DxOwdk9+nQYZZ6SiGWPvMslvRuavh1/D8WR8
         hTWgW5xz47Nu1nTXenKH6ehGhxvePLEnj2nnR9g1VPgN+GyFqOmIgYCP9BFaT0sbngFI
         wwqQP3LrNr+wjpqs9MU29IYmXZfvTwttWVHrZP/sFGWlLR0JX2m4GZTOhvqafa297HPn
         xBEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dul3rKrx;
       spf=pass (google.com: domain of 3gc9hxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gC9hXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CC35zv/e3M4YPhFcc/MrDbvDfwrvD83mKoMQ5vBXkI8=;
        b=jZVmjMc2YIRxDr6hn/Fc+59uaJny/wSkiWmKfYSvDK5sphtae5Tv+si+dpgyUAnzGH
         FHFP97+MGWYaQHTfVpRLM17pBe89hPcXbDvfmqkQtwPDK3S3t0pReH3LsrseFseWXTzg
         QtoFl7RjDJo2qqQZq+aCnTa0DfkwK9QXY8MUmMAxr0RsVXa9hIApUuj1CIG2fAS9O95o
         /bI1qXLdvgzTwL9e+oqqtXA2B7ztCY5VFFLBdtMUDUuUf1AQt2OZGks9KS73l6TLO4hO
         z4uCQIgNLlUiMF/pPFVlvIsS06/M5kSHF+qIBOcidemeJtyo+fMFjYZShhd95K0rXN2G
         qygg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CC35zv/e3M4YPhFcc/MrDbvDfwrvD83mKoMQ5vBXkI8=;
        b=qohSfIm6YTXry1bgfy8YUuc/iNnMB56ZMkWk03pvia2Af5V1AoN3dDhiys6pU6xYUP
         7bjxJkeW7QW7zCHH3Wb6QoFWYQJXcyVOCkgKk/Y0cxAXi9ykJohK0dXEYLZSGIll+ghX
         7eTTn2CUul//44Byg5wgi2J2hlOS4Wc/NUr+8UtvadkRb2TIXQJ1z2lVBKz8C3WIo1ud
         ImV0tBLS+sv7gOisBA1D5lMRQ0z/dV8r0bU7N5oKZK/srBWhJP5CHqPr9vCFm5gel2ml
         f3cw2Yn8FJ2sc8YeYoYShoM3zyLorIC1nlVcAsyjF9nSTmD0GS6xrFMQa4KEoVppPdov
         3QAA==
X-Gm-Message-State: AOAM531IX0cvO8MUKT4jLHWn1/Fyq4pcQV4IHul5ncyBlCABCv2JVon9
	LiCMLHVpo8WDIYPldAzzPKg=
X-Google-Smtp-Source: ABdhPJz5olZcO1X4CKbCT4eEw82uP9FTgmTH7gjEog8mdnvHtlxtZDYW0D9fE/rhe1YJLtB5CPg+AA==
X-Received: by 2002:ab0:274a:: with SMTP id c10mr10623959uap.54.1600204673902;
        Tue, 15 Sep 2020 14:17:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f7c4:: with SMTP id a4ls18705vsp.10.gmail; Tue, 15 Sep
 2020 14:17:53 -0700 (PDT)
X-Received: by 2002:a67:fb90:: with SMTP id n16mr12282368vsr.22.1600204673393;
        Tue, 15 Sep 2020 14:17:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204673; cv=none;
        d=google.com; s=arc-20160816;
        b=iHiBlW52DUOLGCP5Vdtl11O19SaaHL+yu+4ZEOTB13cDCbj5DdCEJC56NfXmeyfWlB
         YOhN2bJqNQywr0J8sr5hQFi0WUIVt8rLWw+52qUlLX0R/Pv3v2x47ox3YZvO/MQbjKUH
         Ao/dfJn4HqDIgfz2Dl6epkkBaMge5sCUZ5fRZy68t/8WjIJiKPkdmuVGjzx8R8PloVdq
         kxqygxITggWIpk1gTPqX6c2dtBSJPi9J/P+3yTqzpa9ilnshC5Ry4KlvF/oFtRtpIfPM
         ISxpJMK2PTRXt9XG4FDOGi2qn6vABjUp7HOg2o3RqUiVCHWixsB9tZfJnPLerO8LwfQ0
         FFFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=efGgWAfAvEfxSZXVo3Aku/Fbu43aBpvq/2RKTLwcfy4=;
        b=sK4efRfMA4V8nv7ymgoa7822RRGyjoQoBTYZnapryl5oh8O0QneeTQmFH2xaV8NyV3
         CnLX+8Vdn7C3bjTVmii/lCPNuALxwim3GW4u4RYRG+JcBx6HfVEmHNPWtS7j3o8UDCIM
         dMLLQN/5XqxdvZlxmXrssManLY8x6s0qAmtworVilchunTY3yLSit6lHQ9mywdsVqmpH
         vvnbXkJaqPKeqhC7Pit12XASk5xLWJ54LLwCWboQIX/Dp2t/nc5dn6BXQ1L5UGNXvzAK
         s6W1eusa6hl4OBD4UpoViyGvfyy2mTnkOv78lKtEN5x1+0E6mynlSknyv+fkgFpafTt3
         frkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dul3rKrx;
       spf=pass (google.com: domain of 3gc9hxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gC9hXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id 134si792905vkx.0.2020.09.15.14.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gc9hxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id o13so4018253qtl.6
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:53 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:8645:: with SMTP id
 p63mr19966719qva.21.1600204672937; Tue, 15 Sep 2020 14:17:52 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:19 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <a4db38a91bed6614dce87c09ce7ea90f1bbc63bc.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 37/37] kasan: add documentation for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b=dul3rKrx;       spf=pass
 (google.com: domain of 3gc9hxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gC9hXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
---
 Documentation/dev-tools/kasan.rst | 78 ++++++++++++++++++++++---------
 1 file changed, 57 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a3030fc6afe5..d2d47c82a7b9 100644
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a4db38a91bed6614dce87c09ce7ea90f1bbc63bc.1600204505.git.andreyknvl%40google.com.
