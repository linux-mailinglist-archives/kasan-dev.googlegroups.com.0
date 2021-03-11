Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJE3VKBAMGQE6HQ5AQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2857D337FB5
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:41 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id a2sf10529483edx.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498661; cv=pass;
        d=google.com; s=arc-20160816;
        b=ebIa7ly1a/5dpr2IPREAATLWw3S3EtYDrffl9JHlfwzSFTIfGA9P4QXYPPFN3r4V0l
         Cv/WtbBAY8F3ihVcwkBBIApoVmhkKufPM0O9CJ88kz3sD+1jqVwhD/fd/or4OxKJtWyX
         NlyNMVjcGcOFuV9I7htNpJbksd3bu+AOs6PbRBxq6LpWx9wvphlye/bbFexVlbCeE978
         ZktGS9lv5un1ranFYac4Y9/+xh0sam+ZIc2FENwzyKbyz5AtoDgKpXWpy//MBIrnpx+E
         R521v/UmOrdE1tdGOHP/lWc7FdiwZX8rPFuUs5ZGXp12YJrCXQxRDKv4w2cbUCgGkbA7
         kYjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=x1grIkjWKkA2lwTkiR4TjfuV63WK4coxSfj3FsxtrL4=;
        b=YLDosg/C3wvvjtfhzJLyAE0eOAmNwTOVe+2qDFLYuhgVkR9uOJ+ySTQq/FZT+uVi4J
         GHEnNkEeUM9Uk6mFgr6IR/Zu4UFrohvmvkYhO0E38XEQ7TeVUXlmymh7Z6cqkY862gDb
         3FQ8GJoJzikGygkh0Z+j+7+kuQNsmkKYXSubTPZc+0fW/6oTdy6K+AHZ0WheIxTTwSNR
         P0ZFw520OPs2whgblE3FzpSklDkdH/ZdTm7wqVneCcpw8iYAqrJyt1wWPPH9NKUQnMGU
         dPop3pEfNApXN+WHreKp3T1CSR3j6F788+c03BPjfWgUtwZLc7ndzTcpDdRxaBmsD3je
         ktJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBQHfFhz;
       spf=pass (google.com: domain of 3o41kyaokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3o41KYAoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x1grIkjWKkA2lwTkiR4TjfuV63WK4coxSfj3FsxtrL4=;
        b=N3+mJhSVuI+yhS6nDziLWWEu1nwvtGDNBYdPtrnzaRz0DcBNE6lrCP6sy0o/2g/iM1
         qAWHP3w0FbXxtoCNRWT5yawt/0EDlqS21hR4EAvW/sYwa9PdyPyOXhegUVjVm17k15Ca
         MX8FwuKYnBh3CspRBZmDGwHo1tWTu/5OX9FK5atrcclbc2+Nbm8fY6MxduMuS+nXstk5
         V51RbMAnzt2HSTwO0S266hsPETaDGYI5VZtj9iKuVtYLN/drrapZ/xPqKBaNiWGFOjKR
         wSBu2V2zXidANuEwL8h3N4WHOxQNO2gQ1S/I/IxNVd9Cw/vRokkZJGrh9Xy/RGaHK7th
         32vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x1grIkjWKkA2lwTkiR4TjfuV63WK4coxSfj3FsxtrL4=;
        b=F+wkHUraGU1lefeoIda2dK8UScBlhThW81UwGHQm3uWCEq6/WnAB2nEXxDLjCrFWpB
         R8AAaD1I7jw1zEcuvCsuC7+NVkz48YAsbrPX7H3LOTHhDfcDfdmu3jnnfgRHZcH7b9kW
         rUvOkicy3s92FrIDNOunG/8L6eKCqZgQDPY0t0qIZIGZOxezcQy900tCOHqWkIAnjo+y
         y/OoDgcHdhBsZ5YKn51Mow3hc9irgz1FM4qkhEYdnTw8sBhNeDl9eeCs9McoElFskvOy
         LCgyGW1zf5LI9Ni1CguPCDCUw7XdzGPbOXlqJqYr2HV0kpKBAveVkUgBdiVVrWXXr7Yj
         zf7g==
X-Gm-Message-State: AOAM530+PxQ+fhKvNZ8Rjx/nULfXEWvCAA5+qOQbDJUuvrHkr56ZVlCq
	Bim7YDE9z6AJ5SGeD2FdIqA=
X-Google-Smtp-Source: ABdhPJxyNqsPLOUoIfqEAZqvCVP74cJ+vYBv2X6B2ar5wL62+VF5bpf6ighqi+vrX2BKDTWl5GV9Ng==
X-Received: by 2002:a17:906:a106:: with SMTP id t6mr5166959ejy.63.1615498660975;
        Thu, 11 Mar 2021 13:37:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:339b:: with SMTP id v27ls958215eja.4.gmail; Thu, 11
 Mar 2021 13:37:40 -0800 (PST)
X-Received: by 2002:a17:906:2e45:: with SMTP id r5mr4961163eji.380.1615498660115;
        Thu, 11 Mar 2021 13:37:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498660; cv=none;
        d=google.com; s=arc-20160816;
        b=lAFSuny/cxYO6bhd6N6KcUkuqErWIUN6VvJyW99EgGQjr8ttaQPx/SKBdrcqMx2q+y
         UtL+iZumEaVEU99RYHy0k4ZKsr2e3rH6UBpeEuDQ8RthiFxZS9UmoK1gXOr32FVqeQlC
         bhGQtjZmEr8qWO3FqLl13aDFnlDi7PxymocbJQu7RGZ0BULBdNKHX+lbGvhputmz/17G
         XByDr5KNZptl7CvxpRcCXSUaA68HHJFti0sh1e0UVmWEZ+mqj+/3ulzW+7nT5uaVKqxu
         z2WgkPk6vLzdkBaD3fpiAVnMWEHrQVdtbkPiIBBPFt4MLhtgfhaNHCoMY+Cd9J1C1K5w
         mgSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ftGAVPrWTX9D2SBgeD8/b0SYzBSEeTxAmVx9TpiZW0k=;
        b=v4FjSMmSqv6zrGaPZ0fJDTGf7OtqmoANmRr7IMkbz/tcJ4+E4ciONPtTihsdQi1u8i
         oaxj2w9hX7oSRZ+P7fZwEb7s03FXDtCbF8eFUOWo1GVZTtXwfpx1OrOCuhGY2IxN/b2q
         j9pkfMJw0nAFAjcNUO6JRxj7OTUTOdtlWowL4o+eflMh7qf/xyP2ta9wHusuPyOYAUqp
         l8fWiparquVuORaCTAgd/fS7XAwqbGS6SY4X3xqUiWU4U7nM8NSp45Ir5JYBtuS/v658
         hHNTphVnOH49V2ue6Rk/EI1TXzDq8xJp+esqCZfxFnt0r0kDLhEta8tLtDp7m7MDhRPj
         xcMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBQHfFhz;
       spf=pass (google.com: domain of 3o41kyaokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3o41KYAoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w12si130192edj.2.2021.03.11.13.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3o41kyaokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z6so10107750wrh.11
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:40 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6243:: with SMTP id
 w64mr1904993wmb.0.1615498659400; Thu, 11 Mar 2021 13:37:39 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:18 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <dd89dd245fe6fe0e66680a9ccd135f6778fc2c60.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 06/11] kasan: docs: update GENERIC implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uBQHfFhz;       spf=pass
 (google.com: domain of 3o41kyaokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3o41KYAoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

Update the "Implementation details" section for generic KASAN:

- Don't mention kmemcheck, it's not present in the kernel anymore.
- Don't mention GCC as the only supported compiler.
- Update kasan_mem_to_shadow() definition to match actual code.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 27 +++++++++++++--------------
 1 file changed, 13 insertions(+), 14 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2f939241349d..1fb4b715a3ce 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -200,12 +200,11 @@ Implementation details
 Generic KASAN
 ~~~~~~~~~~~~~
 
-From a high level perspective, KASAN's approach to memory error detection is
-similar to that of kmemcheck: use shadow memory to record whether each byte of
-memory is safe to access, and use compile-time instrumentation to insert checks
-of shadow memory on each memory access.
+Software KASAN modes use shadow memory to record whether each byte of memory is
+safe to access and use compile-time instrumentation to insert shadow memory
+checks before each memory access.
 
-Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
+Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (16TB
 to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
 translate a memory address to its corresponding shadow address.
 
@@ -214,23 +213,23 @@ address::
 
     static inline void *kasan_mem_to_shadow(const void *addr)
     {
-	return ((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
 		+ KASAN_SHADOW_OFFSET;
     }
 
 where ``KASAN_SHADOW_SCALE_SHIFT = 3``.
 
 Compile-time instrumentation is used to insert memory access checks. Compiler
-inserts function calls (__asan_load*(addr), __asan_store*(addr)) before each
-memory access of size 1, 2, 4, 8 or 16. These functions check whether memory
-access is valid or not by checking corresponding shadow memory.
+inserts function calls (``__asan_load*(addr)``, ``__asan_store*(addr)``) before
+each memory access of size 1, 2, 4, 8, or 16. These functions check whether
+memory accesses are valid or not by checking corresponding shadow memory.
 
-GCC 5.0 has possibility to perform inline instrumentation. Instead of making
-function calls GCC directly inserts the code to check the shadow memory.
-This option significantly enlarges kernel but it gives x1.1-x2 performance
-boost over outline instrumented kernel.
+With inline instrumentation, instead of making function calls, the compiler
+directly inserts the code to check shadow memory. This option significantly
+enlarges the kernel, but it gives an x1.1-x2 performance boost over the
+outline-instrumented kernel.
 
-Generic KASAN is the only mode that delays the reuse of freed object via
+Generic KASAN is the only mode that delays the reuse of freed objects via
 quarantine (see mm/kasan/quarantine.c for implementation).
 
 Software tag-based KASAN
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd89dd245fe6fe0e66680a9ccd135f6778fc2c60.1615498565.git.andreyknvl%40google.com.
