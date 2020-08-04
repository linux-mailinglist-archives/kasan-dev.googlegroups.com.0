Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB5PUX4QKGQE67BW34Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A19223BA8A
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:45 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id y9sf29911032plr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544903; cv=pass;
        d=google.com; s=arc-20160816;
        b=qTckPmuzuG/jmTaNEkv4eVF4sHKN9EFO6107wQyV6pIFIjnZXqnVBOsVEQ6Hc7uenh
         HP2u5A2ysiZO70o0N36EofwKbC3EcSV0K/LdSOOjPN678aj5kXRGG7LDP6Zfexuaoije
         VsomzhKZQetXlAfwnHqXm6VBFPDANkLw4GEpwdFLrMlU8ayvxOk8/7khdbDBNm2HUJj6
         cSWkR3ZzhniI4paPEHG2p8hZwM+ql71AGAaLkiykQHnvXWMUnj8Ienvxb/6tUTV4RmvX
         xih7aUZkX1t5x2H6i0JM9R1pu6iJETquLabI+Ek2k2j03DwthMhZ8CFtgHXSSeH5lRsX
         Bf0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=P78nBbiup1hHRob+Tqoh/IDnYLLcIB92va1LPRPNtEQ=;
        b=VVYuU5AX7qnsShp2iY4G+X0CC7zlkNHL3JIu+cSDJZm3IWn60zO8+4SlC4923yVvL3
         hWGciRZrIoOx97w5z4OHuqQUvmkT/FcQdf+Vk/CVh8IX8qdQimlOKTZD3GxwHURuP70L
         i+5DBgiPfXSQiurzpRPXhOiFapKtIVhXV5MmkANgeRMz2QbAp2WRIuZbAL2xb4XqQj58
         DO95MwLkozmpm83kkVYAzkIaSRtMfXvgesIdfnG72UNlj91nPNLxdM/fEIAAzn2jHiYj
         aiGps2QFZ1MPvADbjNmtiBpNtVffbVrk/9TJCiPPHGOACEM5Bsxl+1Vn+0yWn2TuQ15/
         83HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=al711nch;
       spf=pass (google.com: domain of 3hlcpxwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3hlcpXwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P78nBbiup1hHRob+Tqoh/IDnYLLcIB92va1LPRPNtEQ=;
        b=KcxRjX4J/K/Z0Ee8hzrkK9OLq7R96h2hbzrWWc341MWRB3sbQ6kWagVuRNrYoFIoQB
         EGWRMv3joKuIJXoQ942Fyf3fAE4xcTdw8hhHsxAOhsCsmDnfMC58u9U6O2HWMyQ/ecNf
         H7+VZqH9cZp+woUlUa7fCqVMU9zVfIhUl7HYqar45uXL1SkrGqq47ABHadAA64UbSwbQ
         yRuXJuwkccwA+eyl3FnF79+qple3a6gBi01DYMsYQ/yy79eH/+P6z650CWXW6trVyohb
         C0Zm04X67hFrKYRX6lH+LPse9+nvFSG/tieV4dlQsxNBmKDGNYSaQM23I6T/DIluWrSg
         XMyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P78nBbiup1hHRob+Tqoh/IDnYLLcIB92va1LPRPNtEQ=;
        b=np2VOs/5qBGLdwrIS0Cb+URDAnwotd7Cj1FKgoSLx1yGTnaaafeKCPxf5QOMEaGyoz
         /9V4MS1NpRpEXo03lcrSd04Sr5GhN5D6zDf21w25MEslv7mSKJI4/8Mp5ubG+6gBJ4EC
         b7JsDyHCQZfFFznBAFLmQIffhyi2VzOCwsF45YX+k0TaSSe2d5p4KiiRLwFZtHacOg5B
         a2JrYl2LZHGqQQ/JKqVhcsc8V0Ng9gWR6z173cKa3TamaPUzLcTk4KDOdVNvTHvlTb+A
         df57l890P61Oz8NYwVdKIOs9X8H26Ktca/spew0UB9rHCWsqAbifx4TgG4wHqGO/11uc
         cGdw==
X-Gm-Message-State: AOAM530/vCc2ZQ+xPIaEy9xa6tS/5oQyq23ugipu7HU8G7Dgl5q1Dfth
	8S4I3pyVjrwapenJpjK9NZw=
X-Google-Smtp-Source: ABdhPJwSRGJ4+BgkPOklq+XU+ZJAoqb86gVqRLW0cottZAfjregJ0B6VS5MKIfmBwi/IL8wNfu4Caw==
X-Received: by 2002:aa7:8e8d:: with SMTP id a13mr6539515pfr.250.1596544903662;
        Tue, 04 Aug 2020 05:41:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7593:: with SMTP id q141ls6806081pfc.0.gmail; Tue, 04
 Aug 2020 05:41:43 -0700 (PDT)
X-Received: by 2002:aa7:8e9e:: with SMTP id a30mr21186127pfr.319.1596544903277;
        Tue, 04 Aug 2020 05:41:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544903; cv=none;
        d=google.com; s=arc-20160816;
        b=gwwUlxx0cnf255jXNJlP874M7qv7smpBdyRdBX+BsuD+Aad3+fQYn9vy2D8iHme91l
         pKer2bB+Oc+kWPAUizuNsr+li+kSqdvVG5uK1grhbHG8pxYq0vkYdqv8H4CgfS6MlmLq
         v4fAevTR/AhGxnmuw7qo4TrWPJdFGLP4sVqOAIjH7vtst8F8TLyfMcmONhmF2r0w7xWQ
         Q/eiNm0LeG+DBQmXPEfZXvtRbsS02y3IP7rVlG9J4zN0gqaHOzpw9Kz1yXoIKBtvC/az
         hEt5Ah87ibIEkV43cno+bn2xAtzgZ+Hc1HHoI6RxlgUQoVi9fCPSK3gbkZp7PgInxZx7
         VGfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=r3AVQip2xq9L4iLlC84/aNvGhdtcJ5cWyH3sWORBbtc=;
        b=xaEykbV5p+3xkURHHzF9psUuART7a8PJYopJpR7v47VD/0Y/00qwnRN5EDYx6P03A2
         kO5lN1b7id4G0AMdhf4cXdxiRq2uth2oSAcrYbckiw5zxuuh0PWUKIi0gSWFmGuPCj/M
         jL1N9Z7QAwn1GCUnxrrrx0rk2IgrcRwE1QJKJxtnLW7MbOiU/9MT8JeLdvyjOB9KRgRA
         xlfkhaEM2eIpm+ljC7DVcWX5kTJuWa96o53KnRtbnAlxwlzajcgMfO6BloogOdVWEXIG
         ULmIvW72kyrbOQBUc9l0KumJhDt7ZuA5w+L9ef5bPFGpc55eSizANuI44+y25kt+e11M
         6t3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=al711nch;
       spf=pass (google.com: domain of 3hlcpxwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3hlcpXwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id i3si131735pjx.2.2020.08.04.05.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hlcpxwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x20so28462765qki.20
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:43 -0700 (PDT)
X-Received: by 2002:ad4:438e:: with SMTP id s14mr21419425qvr.18.1596544902628;
 Tue, 04 Aug 2020 05:41:42 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:27 +0200
In-Reply-To: <cover.1596544734.git.andreyknvl@google.com>
Message-Id: <99f7d90a4237431bf5988599fb41358e92876eb0.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 4/5] kasan: allow enabling stack tagging for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=al711nch;       spf=pass
 (google.com: domain of 3hlcpxwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3hlcpXwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
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

Use CONFIG_KASAN_STACK to enable stack tagging.

Note, that HWASAN short granules [1] are disabled. Supporting those will
require more kernel changes.

[1] https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 scripts/Makefile.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 03757cc60e06..f4beee1b0013 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -44,7 +44,8 @@ else
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		-mllvm -hwasan-instrument-stack=0 \
+		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
+		-mllvm -hwasan-use-short-granules=0 \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99f7d90a4237431bf5988599fb41358e92876eb0.1596544734.git.andreyknvl%40google.com.
