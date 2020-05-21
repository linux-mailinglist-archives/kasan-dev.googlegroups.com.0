Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA6DTH3AKGQEQRM4GFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8B211DCBB2
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:09:56 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id k54sf7206504qtb.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:09:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059395; cv=pass;
        d=google.com; s=arc-20160816;
        b=GQ/pnpZyQ5vKU+4l0lBU6HwxclIOJKqJeyos/tY/5i2E6pGr4IBTFsnS42Y9N0Jh2l
         UzfYauY64TADtuvzf/f8fkvlT5b/Okb9qgTelcw4fMGA49nm/xUoqrnlSzswnxXdr+f+
         Th+oqhC5vrcadAIBscYRBrAOzHSonlPwOrxKxZ2aqxz8J04aACI3wJ5K0y8BS2lYEIKW
         92Sb/T0HotSDDCgL/zprqCkytc2FUrFM85I/3q9OPaBb+62YmeaALf2cWZoP6yzcyAry
         5gmjH58YiZ2zUr6OkM+W5HlMHF34jADdJjhhhqpMI96im+GXnvUP7+MhsuqYJQVdpoYL
         IIJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=V7Z6A8hIiWzrXcl9uzfbDJYCGSjXCjrdq9A9u32Ka5s=;
        b=dp0tpEMhtcYH72JtSIagIsbm7jPevZBHHVIK6E4qTYggX0vfQ+gu0IjxZp/fcE/BzH
         BAHjv0H0RjtTtxLuCJfFCvQ7qHsdJCJGqqhSpC6H0kCPQH+SHRl7/X77y/1fxVxCBS9a
         n1EoOLBTaz5OqYrdTjl/6s3+LgTApWbTeAPRmQrp3wGpdXpUZ/+ribWTzoQF3SdFbDVi
         RF/XWBsqX+kTm/RUzW71XTjMvNEXrTuQeisu2UCjptvCsmzLG0cb4OhVwBwsWHa38HPQ
         DdFPD51yiCI0eRP9ykCKorgrseJBIw3MYVN415xdErrn1YFKwl+acL5MB+JbzAdt6BS5
         vn2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aQ5u9oAY;
       spf=pass (google.com: domain of 3gmhgxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3gmHGXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V7Z6A8hIiWzrXcl9uzfbDJYCGSjXCjrdq9A9u32Ka5s=;
        b=SKDlTMF84J/dnTMH0EjoMqU+Rth6q0rf5pfqxJpWh5PJJsqkXib8ogIZYPLE268p3u
         LoHvx1kb1jQoSOzX01PJCVJ43LjfaGjhBFEGejBF1x03UsDm+sBGlG7MeTPmwUYhrTRr
         SCdroAnHnn0VOyrc4HspQ8cKmDaS4WuvaeMVRLAY/BYn4GwdDkEd7fomD2AtiJQBpxfP
         THZbcAKM0bYARCiJWYJKkQ7EgcEjX5SI4rdJUrNtNZ0bhUQLcswVM5SdA2Z00jCjLFpV
         khiR4IGDVvdxEWXSzjI4qLHdiA4anAqva2hh0IjL9wqYR8j1Q6ntndYyuFcd3fdqDxBL
         kXlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V7Z6A8hIiWzrXcl9uzfbDJYCGSjXCjrdq9A9u32Ka5s=;
        b=leWJiUrOqW51ZBEBC7pMRoFtUJHqtUyfIR1wlSvGBFmirql/qA4QafP4F/dulrZnXt
         iXqoZjNF7514l2+4HPS17ta/1E16KjHFP10Y71/9fbiWV2ZRySYI7mmivrdZdWg/bYLc
         BhO3WbaxPU9pgYKYhYIbQJHEHXecS30K4owgMDlhtSOffTNcMzqqD0ynsH5G9VYTPyBo
         JNxYFx9CIZG9wq+gAwrtMQYD7md5RY3gCkHyOZkanGOQ+hbXb1MllgfpbuHAMsU4qc36
         TnJn1KIAbOXn0UL+HeNbJJArgs8W+ZiGv21uL5O9U2FADb6Y3fLDHbBb6AxA5i6QOa97
         mB0A==
X-Gm-Message-State: AOAM533hOo2fKGlMj35AAYbVZnmu8EsqPH1+EKsErIGgGMEmBMaSYY0j
	FHHh2Pp/mVzvshQY0yVWn0o=
X-Google-Smtp-Source: ABdhPJyS4BZvI2UPZTdFikEA3rEk1iCJ42aejMX12D81NCSyBeN1+1+V0Yfsz9WxpjgCYj1IbI5qVw==
X-Received: by 2002:a37:4f55:: with SMTP id d82mr8780568qkb.219.1590059395755;
        Thu, 21 May 2020 04:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2142:: with SMTP id m2ls865424qkm.1.gmail; Thu, 21
 May 2020 04:09:55 -0700 (PDT)
X-Received: by 2002:a37:a147:: with SMTP id k68mr2701579qke.62.1590059395246;
        Thu, 21 May 2020 04:09:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059395; cv=none;
        d=google.com; s=arc-20160816;
        b=hHmNrdRW6GfO3aeVYg8Hdpvv6L7vQ9h8vg51VOzth1SvpARyOsFNhXLnCXQyz7+1vG
         +MON5AsnBG749ECmhJzMkiAjbmk/4/NdymspesRPmChnhkgkV1Okq5CmUnBHRdn0SyKq
         8159SfUooJQMy6iBTQ6FI0ISW2DkQWQRvUFMU0R4gY6gQzyZB2huFzia/IOFQAq2zu7H
         VPaVr2yezXHXEmTCHg2hp4hDxOyuOAUWm3DaFn4YkyQCz66H8Yx7F9ffR0+45lVkdoX9
         tE0ePPXs3UUPxEy0DOvKH2jqCgewRi4yXkWoKNQWMeG8lcbUNN9wtidxui1kXbNhF9gw
         3ECw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=COp0SyeTFByf68VoAMfHccz/8jBHCco/jZeKm/gYFRA=;
        b=tcFsOE5qeA4k5utZidUQqXdXuUeV83k5ZmwrJc7cRJMp8yuwhHvbNv+pt4UyCyyTWH
         BrlI6ER1xluNDi5IeUrpmb6ugQc50ggp8U5IwJGyFqTggzkLZ5/Wn6cvJHZY+F/t7t7O
         5+PAF2ix34hIvZeCbzf/l5t077pUn/9DAxmkeZvb8iCkAXLj7tK1uwl5QP2tuyoCisA2
         Y/9Cvpxs+OM94EH1Y9CtM9j+3JTn6nkUJIY4nYPfzVviPx3GG3tnSGGkhfXQxze72ikH
         8hiUCIejD4C0gubyZRNVwGQanE6kTCIYvUHEfo1Mv+ziu0WQYr8fxebS0PxzMZ0rra1X
         PmyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aQ5u9oAY;
       spf=pass (google.com: domain of 3gmhgxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3gmHGXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id k5si474478qkj.2.2020.05.21.04.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gmhgxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id dm14so6769473qvb.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:09:55 -0700 (PDT)
X-Received: by 2002:a05:6214:1594:: with SMTP id m20mr693518qvw.110.1590059394941;
 Thu, 21 May 2020 04:09:54 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:45 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-3-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 02/11] kcsan: Avoid inserting __tsan_func_entry/exit
 if possible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aQ5u9oAY;       spf=pass
 (google.com: domain of 3gmhgxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3gmHGXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

To avoid inserting  __tsan_func_{entry,exit}, add option if supported by
compiler. Currently only Clang can be told to not emit calls to these
functions. It is safe to not emit these, since KCSAN does not rely on
them.

Note that, if we disable __tsan_func_{entry,exit}(), we need to disable
tail-call optimization in sanitized compilation units, as otherwise we
may skip frames in the stack trace; in particular when the tail called
function is one of the KCSAN's runtime functions, and a report is
generated, might we miss the function where the actual access occurred.
Since __tsan_func_{entry,exit}() insertion effectively disabled
tail-call optimization, there should be no observable change. [This was
caught and confirmed with kcsan-test & UNWINDER_ORC.]

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index caf1111a28ae..20337a7ecf54 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -1,6 +1,15 @@
 # SPDX-License-Identifier: GPL-2.0
 ifdef CONFIG_KCSAN
 
-CFLAGS_KCSAN := -fsanitize=thread
+# GCC and Clang accept backend options differently. Do not wrap in cc-option,
+# because Clang accepts "--param" even if it is unused.
+ifdef CONFIG_CC_IS_CLANG
+cc-param = -mllvm -$(1)
+else
+cc-param = --param -$(1)
+endif
+
+CFLAGS_KCSAN := -fsanitize=thread \
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-3-elver%40google.com.
