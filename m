Return-Path: <kasan-dev+bncBAABBZXVUWKAMGQEANWKR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B40752FFD9
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 01:51:03 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id h6-20020a7bc926000000b0039470bcb9easf4030441wml.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 16:51:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653177062; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cH8bbpQOIShPGkGEL7TfSfNXtVWVRdd9L0ynYI2Ss9Q+8mkKhY43IF0MxOC7DDv9D
         g3h8xoPpbPIaUlVILvdjSL3asar6BHi8npQlgKR6r9AUr7zvqc9vZ7c7ZKTw0MV+NU13
         NB5n10oWzfvnh4XKfriN5YRHdXNXV0cl1edYZl3mA08ToBTU69hifth7uOEKlif+xRDF
         8FSXPmulwG3FtLvfeyfU/f6/lQHJTkDfGvl9dnJ1Iw0JnPxJoOWu5vZK3cqjyBXjs+K6
         RdjBc5qGtWsU4IqMgqDiAcYHyqbULOjWYLb3l9tqa2sLJEXBQFh5ASKeOfsB2dodAylk
         WNOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=EIVMl2Rd+AEbee3UQcyfQ4gwVT4mvFFC/yArPpB9jyA=;
        b=tohbkyiWn/CHNqypRnZ/oEJN9dPFb/vPeXBrmDW9qLaupBM+ENoVnMEOfW9CVCSJnv
         mnEoX/EvbX0oRlUzVFUu5467HpatGoqWkXW+EmAIASZ+JzVxJR+6zQErsFnzeCQmnmZG
         E42xjWv0QhU1pgHKlgKlSwdoeADy3LNKmfQYL3sfoKJ0NZ1zonrf5tl+P9MiDXUUCNVU
         q5jT7mnueKgj7V+v9VUT0F4zd0a60p8TRPo0hpDLkPm8P9zAMVrCJY4lep4bD4GkFPsH
         IlFjl1pidAGNpFVWk/aBDHwInJJ1mOCdnQaVKuJbubGYCU2aYDgFvQnsfxnx/Mlmupxq
         gJXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SUmBT+dy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EIVMl2Rd+AEbee3UQcyfQ4gwVT4mvFFC/yArPpB9jyA=;
        b=mAiESMGcVUBvtT3+IjpmeVMeqo0jh8e4spCWl7Aa/i6ar/U///gLDb3dlN6m/UxYzj
         ebXLLhAqjGKuWKLeWHTruH4CzE4JMg7FUeMkBw0n3Mu/bvnH+Rd/zuK7ZNZABkp56BCd
         zHnhHUoRaSnkXnS8T50Nf5dErKVAPOkx/RMbN4VZdZD52ajdjQYLHbnA91dN12dtjO/I
         zgGlGrKUiHMirgbMachbdqMTbm8o6ACeXzpjuqleI90y9Vwxd1HzV3KAUTNHOX5JX32k
         uEMzliPhbgnD5v8h7lZe3/CwFceRhO2rPOkB9argVvEFAMfZPKvX980GGOG+r+b8JyC5
         CwGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EIVMl2Rd+AEbee3UQcyfQ4gwVT4mvFFC/yArPpB9jyA=;
        b=0CFh0kguEXWmGB5lJcIral1E/4vC8waD7wAL1XFx+bboB0OdAERbBEt01ZMXUPTOD/
         3xvuFAKK1E3CBMRzZx6GnNNCoHXxUzYoDSMuKQMg4L0srQLU5hHOod6Jk3l43F58lwUo
         INd5WdVD/k2BQpoSmALY5XKpaX1w/nYbl5A2F1drWUhySoBu0HZjveyhjrC5Tvsnh+Eb
         /CLm/lGdjZZOOhcXTlaFaiX9paHZ5e93yTzbGqDVzekmpAu3+Xyt+Sy7kY40xGUSyCbu
         Fjlv0D523tOug441PgcZEgIXNv9+OcgqD5Ml2cvQSXOQoHCRFqjCKThuro1LkzdlHwoI
         AuTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wXV6F8pEFCiLN7bZmZzyX/V1vaB3Llh1uWiV0826XNv2+uP0T
	dguPBh4iCQsL15fzfGUaUbI=
X-Google-Smtp-Source: ABdhPJzgE24D6FBc24mAYVQDIVnnkiRtDGRpaFgItct+KzkNvur4/4NLcY/wlqtux5zeQwLqB4/hLg==
X-Received: by 2002:a5d:6102:0:b0:20e:5d64:5dc8 with SMTP id v2-20020a5d6102000000b0020e5d645dc8mr13722539wrt.326.1653177062791;
        Sat, 21 May 2022 16:51:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4807:0:b0:20f:d148:f68e with SMTP id l7-20020a5d4807000000b0020fd148f68els980227wrq.3.gmail;
 Sat, 21 May 2022 16:51:02 -0700 (PDT)
X-Received: by 2002:adf:efd0:0:b0:20f:2677:8a45 with SMTP id i16-20020adfefd0000000b0020f26778a45mr7500640wrp.112.1653177062030;
        Sat, 21 May 2022 16:51:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653177062; cv=none;
        d=google.com; s=arc-20160816;
        b=BK32fzPyfFX3K1btqJbOnbBKyENWzkYoxsnxUoVm81sVFsZPVHa3CJnKct+tTzOffa
         JPxil5TnabW/s6yoRgD+fi8aMUGHA6q98rTlxidyYbTI6Yw5x3ICtA7HmRDfx60+U1La
         Vyhq6bAK3eoQss7cuCj+TFcN1hcHGlrnP5DKpUi87ZjqiZFPSU/3AV/Z6VQn1p1uJBGd
         TdIyaL/y2rfWZ6jaVhB9VMcmJ3E8opYv/M6QGzwbs75PcoScyFZBr3/JlM60BYGNzFwn
         BmjS399bbM78fBLPQbWjICqCYT2aemTKF5TPaUF3ByfuGHke3KtJ41h0mOaDEL3QvDJj
         jrtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Vy7Ak3F0cMwR4NDgJNAiMt1tqQVmnBF5Rj3rg221j68=;
        b=BvzftMoL8BBF3NJtH7JgeZppjtHiDV1ADUPHs0LfeQCs8ZmYkC1gy3QTpbc4NXiTdJ
         dQRV6LcYd39TlG5DxUUQjeZ1RK8+tojrBHU26Scl9B0rNbNr8etpZ70LfxVpgQokFXLu
         Zn2LsOoPumeTR1g5j2k9i9YXAW3eHHnwVZjb04OVYyBLrBLKjYnIbAgJjsoivyn/hNfH
         y97cR+x87OPQlBdONju7GOQH5pmt4LhX21ItBhk+aECCsDkuzHQQCoqugVWrgGHQBlHH
         LvY3wedFoDp966SR7C7kW9FNWuE67ECFkAuz50jwfIh6snw8VkT2tpyKoKckSq2haXoX
         lT6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SUmBT+dy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id az11-20020adfe18b000000b0020ee4f02214si239769wrb.1.2022.05.21.16.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 21 May 2022 16:51:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/2] arm64: kasan: do not instrument stacktrace.c
Date: Sun, 22 May 2022 01:50:58 +0200
Message-Id: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SUmBT+dy;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.

This speeds up Generic KASAN by 5-20%.

As a side-effect, KASAN is now unable to detect bugs in the stack trace
collection code. This is taken as an acceptable downside.

Also replace READ_ONCE_NOCHECK() with READ_ONCE() in stacktrace.c.
As the file is now not instrumented, there is no need to use the
NOCHECK version of READ_ONCE().

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/Makefile     | 3 +++
 arch/arm64/kernel/stacktrace.c | 4 ++--
 2 files changed, 5 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/Makefile b/arch/arm64/kernel/Makefile
index fa7981d0d917..da8cf6905c76 100644
--- a/arch/arm64/kernel/Makefile
+++ b/arch/arm64/kernel/Makefile
@@ -14,6 +14,9 @@ CFLAGS_REMOVE_return_address.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_syscall.o	 = -fstack-protector -fstack-protector-strong
 CFLAGS_syscall.o	+= -fno-stack-protector
 
+# Do not instrument to improve performance.
+KASAN_SANITIZE_stacktrace.o := n
+
 # It's not safe to invoke KCOV when portions of the kernel environment aren't
 # available or are out-of-sync with HW state. Since `noinstr` doesn't always
 # inhibit KCOV instrumentation, disable it for the entire compilation unit.
diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
index e4103e085681..33e96ae4b15f 100644
--- a/arch/arm64/kernel/stacktrace.c
+++ b/arch/arm64/kernel/stacktrace.c
@@ -110,8 +110,8 @@ static int notrace unwind_frame(struct task_struct *tsk,
 	 * Record this frame record's values and location. The prev_fp and
 	 * prev_type are only meaningful to the next unwind_frame() invocation.
 	 */
-	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
-	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
+	frame->fp = READ_ONCE(*(unsigned long *)(fp));
+	frame->pc = READ_ONCE(*(unsigned long *)(fp + 8));
 	frame->prev_fp = fp;
 	frame->prev_type = info.type;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl%40google.com.
