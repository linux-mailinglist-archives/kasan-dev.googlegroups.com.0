Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXMRRHUAKGQEZT2VJJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C42643624
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:00:14 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id h15sf3533961pfn.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:00:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430813; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Irzh55ETEUlrND8Plk/tlJUSopd/+w7SsDTQ6Mi0AC6YLRFNWIDaPh0ppoUSSW7Nn
         aWYYMcdzlDECQ3T/Z5NvMiWrSCx8xUe2K7SKOzGaynHMjOMQqUJRQYT8+vC4relto1eJ
         V219Bql71rrYdAP1H1ViE4nJgTC7L8XI8p07SgePSzNBkw6EzIhch8DBvc5nKrcdk2HI
         iPvN61h9KVQ6tP4cmDGXebwKwoFsDZ4PYQ64+gcNvICL93DU5lQxG29yYIxSolNLS7mr
         HU6UgVa0YFh7xAFpGqWLM8nnNd0l4Mtti8DGdsBtU3JFyeMAVauSX7kWZeD1fCgmGWsC
         p0yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kMk1LlFlO3oySCpBwirdnd5QQ11OqnxGKCbHKLcIuqY=;
        b=oaa5fIEVZOLIA9XXaYd/rSua2BeXlzy3Rx+BXqitzHgOVu4PMzN7T6Hf3YuP31LE7S
         IDFfqw669xQAE7VJqxfvw9xGOKsgIBjpLRJncFKelujWq57rSzv2TudcmfznOn6vVLWF
         0fQac965IIvyMG819LnLCZFovHNLiLT1NrDX1NRXE0KjOJqAESHDZhhLHZeyEymLihVM
         se0K3Q4jGTgUqs4LGsj4fWCO2uHi0sx8MZoUTmrIzk9J68jhxSWjIcU7vJ7JUoTNpl3B
         I0iPIsY7h9no+6bVTee9Yz0XRDgFpMhmFCubFW2VYLwQ8R7JM3W/NQZQN31HWm44CZBf
         fFuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dGsiipAT;
       spf=pass (google.com: domain of 320gcxqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=320gCXQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMk1LlFlO3oySCpBwirdnd5QQ11OqnxGKCbHKLcIuqY=;
        b=NNjeM3Y4qLSvJvk6kswu8RsmnEoKpKFigp639/bZRAZV2w1JX+0dqQaDvTEJvu2UGE
         iAG8ouyC9SvcVixbSVLgwYq4gkRtSu0pIqYF+5/uf7ezRUoeYsbHvainRFmE/HKBqjx2
         i9leGywHI7g5OYa9Dyt8RydJZjbj9K3a4z+NYCR2nksC6ElAbfu7uqw/uQOyziVlSrT3
         KO8e6X3oq2ntvPI53tOtKSjii+vPAExESQNBBKxwfHRIgzZt6WvICX2EA2xqTMLXxhku
         K6ebxbv+5MGK+3iapxV/aFp5R/RMfStPnUhuY49sCo4y6KirjJZh9z4n7GGY0f/+xgkk
         qMWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMk1LlFlO3oySCpBwirdnd5QQ11OqnxGKCbHKLcIuqY=;
        b=uJCP1aOpskIEu0ybLEVp7+XE5AO8n0InXaVhZsLcLdVx7bYnbupRblhxo0VfuTISAs
         eOBc9a/+LaPsBO8QaIbzr2AyO8cvvO8GQ7tk01eXOq7TT2cfOp+VSkubFAExiUtox+j/
         LOYfjP3w3reOlFKabbiJiK1XXSWdJxblpffXlrUAb9NsTSep6wHQUaaE4Zj6vNVmwcgx
         mv6L9aC1i5pxcH3KsOEpX1AHXtTdQQvnsw/XOov8LnicoxyLobs0dLuUKAHIngvDgOyU
         1Waz5VWBk2NMZaZjdfOsonCAROrM7IYLDuHsgCI+umHYGg9bnIdpMsoJzAllbgDSna22
         s5tQ==
X-Gm-Message-State: APjAAAWtQcL1UDzrQ8ePKR375mEhXDX3ZOvVGgLmalRAHeVCsnL/iqiS
	gzSDMVURQCd4H/lkQi/XsCQ=
X-Google-Smtp-Source: APXvYqwX84UbOBn51jHkvt+PIZO1IcSbfK3TeTm1rxE0EJDxWId0gHtxBz0rR1zVZseCoVReE616Ug==
X-Received: by 2002:a65:42cd:: with SMTP id l13mr30046558pgp.72.1560430813220;
        Thu, 13 Jun 2019 06:00:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8115:: with SMTP id b21ls1259377pfi.12.gmail; Thu, 13
 Jun 2019 06:00:12 -0700 (PDT)
X-Received: by 2002:a62:b517:: with SMTP id y23mr96313729pfe.182.1560430812836;
        Thu, 13 Jun 2019 06:00:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430812; cv=none;
        d=google.com; s=arc-20160816;
        b=iCX2RkyTVQm+KfsG9iYGZc7QqyrG6Ko64ajAKn+QYxKoYjtZbwCUsPJNXMVfSk1ZnS
         XLmV1O2rfOIrawPu6HEFYzQnv5E68iHbuPndqVlFle99pBLxPiJSXcsvvnLSBPiNy9aJ
         HU0cC6XlxnfTc80FqP+fXBnbbs8ar67kmahwe0ljquo163ssPMkw53yc5cUeQ8dZC745
         ZNQ22AsNJ6KdOS+8KsmIyq9NPG3uQ37HLf7OtgCiOlWA7vyobrvLQl2QNOXKWUDGGbtO
         hccaYTuRvre0t9Dn3e+MrSTfO83VEapkfyXEilQ6LhxNTfp/YaZYzmh9B2T6wlZGrtOa
         GcHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qVLSMyZ68L0nEVi2BC3Nmk92s+29uFb8AJSu612sAz8=;
        b=lKyIE+BWIR0RGqnO+xfSgWzQU50yPvUs5tTrNceJ/gY9wWP1d8w1Tm/ajP4ZDbtzs3
         5CXYlcZnAlGM2AvlDfAijzadTy3eZdvgzdXIycUb1xh70/vj/ae+dudPWj23xFlvZcTc
         mdfBEyAzlIzAj54vIgt3Qs/HN2mVZkgw7Yf5/rMGBmFk0r8PRuEluPwQdZAm6ib5W0Bv
         tFg644H/IxAl0uEFCGvssXNnSbvP4v5JwcD1zkVQgSOcg+DJE4BXyi+IQL1eSUwv8FbB
         f7zC97BcAVnSFjOqJ0Sy15W56PsHWbSRfSXzswaJjxtj2W75yhfcUPfuVDrySB+R9Dif
         nyFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dGsiipAT;
       spf=pass (google.com: domain of 320gcxqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=320gCXQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id s125si174311pgs.1.2019.06.13.06.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:00:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 320gcxqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id b13so6341023vkf.20
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:00:12 -0700 (PDT)
X-Received: by 2002:a1f:16c9:: with SMTP id 192mr19622676vkw.54.1560430811770;
 Thu, 13 Jun 2019 06:00:11 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:59:49 +0200
In-Reply-To: <20190613125950.197667-1-elver@google.com>
Message-Id: <20190613125950.197667-3-elver@google.com>
Mime-Version: 1.0
References: <20190613125950.197667-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v5 2/3] x86: Use static_cpu_has in uaccess region to avoid instrumentation
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
 header.i=@google.com header.s=20161025 header.b=dGsiipAT;       spf=pass
 (google.com: domain of 320gcxqukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=320gCXQUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613125950.197667-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
