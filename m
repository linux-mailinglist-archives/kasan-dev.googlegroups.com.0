Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMFRHUAKGQEY6E7JXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BC47435EF
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:33:47 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id i6sf6725234oib.12
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:33:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560429226; cv=pass;
        d=google.com; s=arc-20160816;
        b=k/FudB/HkQuu5GpYqoE2Gx0ztMkLrGsZr6U7jyALMLJ2IL7uQSRbn6NjaIVuxCy+uM
         4e2hWoysvRigUG3kRg941P1mDzo75nyl3Uqa5KbPne/NO7kGTpx6CvSh4Yx2HEbhOL77
         MVWsJSP8g6Ov4f3N2zWc+IS6cVsBoL8o+5WQud6oO3SCZaBOnM2doiPmBVaB7y/ygEIK
         LgNS4fdA1PrGDLGLc9m4uIag2eXlA65fFqfsuAc9+zgA5uLAqH2fSDqVs35/WJe8oRlg
         k7KMFMr/ov06uGK/1vuefpvC8Oa93tBxy2pnxgneIyEujCISvZ+KomknGep9OcQ4xES5
         eWTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Mna1upyS8pFdAFjfpm/MBBcxp0rdwpHD0th4w9rkzKY=;
        b=h5mCtb7iavNAH4P4xg6yJrk8/cFOG9wn+i2qF1Sb5/A1alBlSflkGItWn0c2iYBvv0
         /u3xNWXRsc8Oxu4RrLlyBZl2mQgsVn0M3IJJSv2UVGVvYN5krfPV/nBl8XViY+LC3ElT
         vfU8BNGpu+SuEJ8eYVTlr5d20/hp4OpBUxSSx3XDE6x4bLTTFD+LZhZf6BPjdkyny0PT
         GKfkNWEaTAkT8n7HJTCvYUoo6ELT2q0RS62WpsASgd6KXFvKJNma1CmGU+eTyMEj0ErE
         RfRzYhgGuBi0LZDHt7E/JnMrwhq2Y0qsCicRbh3BGDLLSb/w+VqveTNHPnFiwTjzWlwv
         VB3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mEcFMq6v;
       spf=pass (google.com: domain of 3quicxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qUICXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mna1upyS8pFdAFjfpm/MBBcxp0rdwpHD0th4w9rkzKY=;
        b=AAQZSYYSqYfeykAsTuicoFM3uCIO8eS+j7SEr9CM1rH9oaHZXG8zplj/7XV3kWBYIu
         TcYu19qbIyh7/zcLSWgSSeysKoEGzWwCuqwL44drKwpx5i+sCN3Cs0PDwbdlrUNmrgMl
         HSTJy2OFaPZ7pBY0e1XOuoKjywRrqEwURbzGgSt6y+YgMtdGIi6ZhfiteQ1ESlVS0Q02
         2Z8pM+W8CL9oGa/JGQs+BNArPGnIR3KlsOMk7SDseG+pMmSiEoEPmr+eKK7vUmNRgLU/
         C3dOw3ikAPDmtAJspgEqCtWf8WQfg8WNyHPE0JUKmPs5quwzIIyrPAVhvvNBq/H3Cz9m
         +5kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mna1upyS8pFdAFjfpm/MBBcxp0rdwpHD0th4w9rkzKY=;
        b=UJaKmCVx8lo6UahGapaSc4bOMK9YGEUDUyndU6NtEUm4iJy3GBkt8XZF2qtQYI+9vf
         kO7fVhLm6sP3nRWwYVXEB88NvA5EtMvaEEImgJ2BNOiPkWMhgX1crQBNJS7ir2a7f4nx
         sSfv9knJQXkrryHgn7Dh5GRBFq1a4SQ/wZ58epx5L9BeYqlBkF935DXsyx6fvoskIzbB
         wOk11eg1M1Udbc2QvwT3+M9za/SEgzHC47SgTbiJUYGcV1RmRZb9kwFEvsWkJ16qfneC
         nK99zRJPf6O+4CiOWIHygAZY6twGt2048FZ1a307617MHBOApEwnJlJxrXM3SKbToFY/
         msKA==
X-Gm-Message-State: APjAAAXpuQFHBHj1mQBCH6kXie8Hjlm2emX4W+ml+F0RPlzSPwVYg4g/
	n4UDHj6MOlKQtEr8n1rr43o=
X-Google-Smtp-Source: APXvYqzMNUR8v50OAh2lBZz1rPlDoMKrHqS6C5SsXGYAAb4DBinOdBkwkPSvwjsJ+vhQbaIZNm5VBg==
X-Received: by 2002:aca:330b:: with SMTP id z11mr2817025oiz.27.1560429225933;
        Thu, 13 Jun 2019 05:33:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a02:: with SMTP id v2ls921283oth.16.gmail; Thu, 13 Jun
 2019 05:33:45 -0700 (PDT)
X-Received: by 2002:a9d:10c:: with SMTP id 12mr43602420otu.123.1560429225474;
        Thu, 13 Jun 2019 05:33:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560429225; cv=none;
        d=google.com; s=arc-20160816;
        b=M4/HtjOfRa0UyuoBnfr5l6mU+8w8azVkcA9bInJnmBiP9DcbDjQjpzEInHlu5m6GSN
         r0h0KMdQfvs44L1J8fT1Ui8kHLrXllI/kwzAJFemWfXI75CQj/7cOOPvhL9e55Bk/iLg
         I7U37SArEzUI5dDdLnqxVjA8anbBxOYYo1ZO8Xs0hn7KAs3gXehLF8horV8v7ernf/5P
         +6HechpTS5UAk08uN3PZg48oLKDpbktd+cEGYDBwYfJEEF6Kdz4WEnX/UdR7LHRx4e6+
         j0mBcVaIeENZBLXn6WtFZNUEml7aUbpfQzHlhqOTUoHyN2XOj4duKQIovF9Zfz63n5FC
         Pjvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qVLSMyZ68L0nEVi2BC3Nmk92s+29uFb8AJSu612sAz8=;
        b=wAlFXuHNHkEzuKtoaqrau3u5uAQJuWKhBLApk/y+ztQCBQ8Y+DOQac4bC1NJLv7Dho
         O5e2kRH4DZJWaOS4uRUfkgy0almH+L2IZCG1aOTAZvdpvhGg0MKfZG1OzHgdLUKI8O0S
         zYFkTDuMu16wxinrtPFxZWO1iHvu/qaE02rssIdVvf5i+vxeZUg/ohHqBqgeBXu+szYI
         3N8P9kSUVDmoDUJIPIQfKNy8T7vfL5//KdTXJn91qFFrAX4ZpuhQpCHhjv0VVw3+fwr7
         yEUHGv/tFT9wL3CmpRSHVWPpBnfZBT/HSfevKvWJp968Ny0EyV8aHwcVDV0kCuCcxjZ0
         6WLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mEcFMq6v;
       spf=pass (google.com: domain of 3quicxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qUICXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id y19si145885otk.1.2019.06.13.05.33.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:33:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3quicxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id w184so16452708qka.15
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 05:33:45 -0700 (PDT)
X-Received: by 2002:a05:6214:1249:: with SMTP id q9mr3260843qvv.154.1560429225061;
 Thu, 13 Jun 2019 05:33:45 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:30:27 +0200
In-Reply-To: <20190613123028.179447-1-elver@google.com>
Message-Id: <20190613123028.179447-3-elver@google.com>
Mime-Version: 1.0
References: <20190613123028.179447-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v4 2/3] x86: Use static_cpu_has in uaccess region to avoid instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mEcFMq6v;       spf=pass
 (google.com: domain of 3quicxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qUICXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

This patch is a pre-requisite for enabling KASAN bitops instrumentation;
using static_cpu_has instead of boot_cpu_has avoids instrumentation of
test_bit inside the uaccess region. With instrumentation, the KASAN
check would otherwise be flagged by objtool.

For consistency, kernel/signal.c was changed to mirror this change,
however, is never instrumented with KASAN (currently unsupported under
x86 32bit).

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: H. Peter Anvin <hpa@zytor.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
Changes in v3:
* Use static_cpu_has instead of moving boot_cpu_has outside uaccess
  region.

Changes in v2:
* Replaces patch: 'tools/objtool: add kasan_check_* to uaccess
  whitelist'
---
 arch/x86/ia32/ia32_signal.c | 2 +-
 arch/x86/kernel/signal.c    | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
index 629d1ee05599..1cee10091b9f 100644
--- a/arch/x86/ia32/ia32_signal.c
+++ b/arch/x86/ia32/ia32_signal.c
@@ -358,7 +358,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
 		put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
 
 		/* Create the ucontext.  */
-		if (boot_cpu_has(X86_FEATURE_XSAVE))
+		if (static_cpu_has(X86_FEATURE_XSAVE))
 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 		else
 			put_user_ex(0, &frame->uc.uc_flags);
diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
index 364813cea647..52eb1d551aed 100644
--- a/arch/x86/kernel/signal.c
+++ b/arch/x86/kernel/signal.c
@@ -391,7 +391,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ksig,
 		put_user_ex(&frame->uc, &frame->puc);
 
 		/* Create the ucontext.  */
-		if (boot_cpu_has(X86_FEATURE_XSAVE))
+		if (static_cpu_has(X86_FEATURE_XSAVE))
 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 		else
 			put_user_ex(0, &frame->uc.uc_flags);
-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613123028.179447-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
