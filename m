Return-Path: <kasan-dev+bncBCM33EFK7EJRBB6GRT5QKGQEOWUOWVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C71426D71A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:49:12 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id h4sf614439wrb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 01:49:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600332552; cv=pass;
        d=google.com; s=arc-20160816;
        b=tUSTBOaix1EBbRix3jLXxLaAeEVEkMIkZUj8efDKJipTp0sI5WSZeTiitRlP04lVOR
         /isTQFjNhp+eiZUTE0bSP9Wgbet5ppSu7UiUpovsMakO1XQnHWN1Urs4yC23OITVB7IZ
         M82SS8tpGe+fgGUjOuhRNRLz6pfxfNS4WgUfE5vOTJa+zAoLkKhrSBVvyVSZWHMvdZUo
         Vau9F5fKCwYjc01FQy/xjK3ZoEMNLa0hSr6NouHuaNyQK6tFNOG+CnJ98d/x7OiCC56P
         8I5+60IfyXaLGQ2jWtc4QRd4QVYKRIGe1cFzVG3VYpj2R8tLIAGQJJ8U/to3YYm0tFZX
         dW3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=dVeKEMUoDVcJ2TfjcH7kVkjkz4U4GeI7MXTKqWzgmw4=;
        b=gDsGJ7N6lGxHql7orv7/8kXHY7k/5JBosLWGTDlG72W16n81vJ+XxLz9xQGJbp1aus
         E2XV0tkrSXgyW8Uou2iVW8qrMhQ6r5ZZDCXb8yf7Bo8CRwu7LV4KWYi3BKIm8G9zNeTu
         nRTLJUzeW1++DnRYPx1ND3wBxhQxYbtkILMoeJ2yZveaAKcxLXv1NoK6F8rk0z2+2Q9R
         psdeNtmDL27xcKyZlNPH4r9cWWOOIsZkJcTrhO4ZqhXo9bJXs0W9FQvXxm9XBYMqEiIn
         /L5CElKgOQMLHIDhWsvKftPR6Pa9mctRN64yBD7IXWWbarA6scCTkSNMB1cXQFQhJOLz
         MFiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=GfuKs9Cu;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVeKEMUoDVcJ2TfjcH7kVkjkz4U4GeI7MXTKqWzgmw4=;
        b=rdIEysPdhbQ40HdCkDm6WGi80AzYUDyoo+WL+XGcz6znv5DAYjcZuqyCsiaxl0sOVK
         jOHF1ybj49lAJzRvDnCpdct82l+73uwXvMGYk7UFny8M71WOkG1y9fFbZBmQp2zAeoqo
         LLqZasxr4tJV/rvRf0etKG6mcsZWf1sGM+TRiHGVinRmgnzo9AbxTrXIYEuPdtdU8muY
         P6+ebBu0tP+eQs2Mb7y2my6jTJks+O2NyLnO96kaKSFZ5+H5BllttPzjQb1HSi2Gc1ru
         fii8rkFxA7TDzA1z6rTuc8wW5f1QBc3wsSgmSBTvBQbPDZwmD7QyV8f40hwLg9XN3w/f
         lAig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dVeKEMUoDVcJ2TfjcH7kVkjkz4U4GeI7MXTKqWzgmw4=;
        b=FuZaqQ9UmPWhqaVgq+KM8QzrnSRL+tcgsPuDmcVzwEYjz6fsUmCBkJWFVsKQ/cuvOD
         gTwGJ2ECJM8JrMcF9qKTpa/wiTrqiY8CFnJrEnQcaTqcsUYexwEsJsQ9hyaBLe43u/e5
         6UXwakG2CkACbF1NzAYd4fC3fpWH/grQBTRn8FGvcVwP8SGGNuLJZUZjPFspTkTpJ5Py
         x46QBjGUkEXbepsF9A2Deor98TsCX7lEPd1F2Pqp5X8FrksZT2daq5I3YkgmXMCl2pyP
         ahX15cI4gfFXwm7wYci/8xdHbHs3rEI1rfYcxQyWFSAN94tm+K/fxugnHWm2Mf+Zobr8
         2naw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dVeKEMUoDVcJ2TfjcH7kVkjkz4U4GeI7MXTKqWzgmw4=;
        b=UTB0Lykw2DXglYc4moZJJaxEzPmdYbRjf7QGIQkvf9xTDwh1qfDm2MuAQwa9Bx+87H
         vFDWIqJLiBqfUhGQxYwhdn99AaL4fnkJOZ2kBE+GXVO8P8ep+oqkAAueINw4/wxmLP3H
         UulnLjW9OgZNuON1xIvfrLgeEMLY6Z3/f66mNOLjTg751uq7SFbsx7l69WSZQQ5RqqG1
         mc6GS25i87A4Kn3+vtCjH4OA8vmoxI+JvrbVBFMAv55mqc4eEbxVJfW9S6gNkDvu/gPE
         RkKrQROumWCb+bKlu29KEKAhXrS2GYLyENvPyIIdQCmClcOVUOuVPh3EzJap36GaFNXW
         Feiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53215UO3dqERV95Ki+wj9IgQWwHbmUhbMoJAF4TBnqfdkhOydYAL
	icbkur6JC2FRohGmqf8/+dw=
X-Google-Smtp-Source: ABdhPJyitN8tzqz3vgLI/d1O59UrojYg6aoD5i+wiqsdEPgfVogH9afxXfApgDj0Szo/29mywSQoCw==
X-Received: by 2002:a5d:4682:: with SMTP id u2mr33120000wrq.254.1600332551947;
        Thu, 17 Sep 2020 01:49:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b86:: with SMTP id b128ls700664wmb.3.canary-gmail; Thu,
 17 Sep 2020 01:49:11 -0700 (PDT)
X-Received: by 2002:a1c:b608:: with SMTP id g8mr9322472wmf.106.1600332551000;
        Thu, 17 Sep 2020 01:49:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600332550; cv=none;
        d=google.com; s=arc-20160816;
        b=BgzGFoDdYxbpzesa5C2D8gSKSrs1OaHucEyrQixbEmfUCejxxE22pGVFtgjojzbG3j
         qcY+hDmBeTAoCKIcLUVY+Pbpe6bjEuzdvhq5A1LM4SDQec88/SUovNLGAwnJaWJ447uC
         NTYYgkn1uWo7bwavObs9ljLACQuk3L3NZhUY8GjmW4K24BFndXPvpaROldEVGrEQxaSZ
         bqAJM7+t72yxR/s9gSi9e17XSXQ04vnlPoks66Pq/lg2ZU+u1QVIPTjmabNgr2G9bA4j
         znxdyuabhwywlwkzdXVzqtlOaqwC46fcZzU+45p8bVnzYGZ3rqub2XyoS34YL1OAt5oS
         AI5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oRBptC4sIuVYjiXcshYa7R4ABF1BI07mPrwI7LaWCH4=;
        b=Lw1Ufky3fvJ5TZ0uCHz4SuA14a7kvb9kH0Zcx896noTfEZy6vKeDaGLVsOS2ksl0+u
         PnkUqHHb66FT1HEJQBhDVOBMPmMwv43DTPTRtrlMITchdMKzfTvHPIegf2BIdIVkfCmw
         YAz3EGvE+t8GBiQlam8Qz6B6k8rHqG581oHfJFCBBTvfDYbEhD7wQWYtyuPplcr31n+g
         VN9Hw8MvOvAjj9l1wuRvAYe0XXu4E9irX1Y+NB6DDcevlT3VoTvCPJ8wKc0b+j0uPiC1
         sNsVyvFiD7usGvrdDWuH5DVyZ9MsGFg/cL+vvpj9fdqcQ3VFnX2L3FMWhqUPokOJXd+u
         RpoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=GfuKs9Cu;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id b1si151901wmj.1.2020.09.17.01.49.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 01:49:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id c18so1127481wrm.9;
        Thu, 17 Sep 2020 01:49:10 -0700 (PDT)
X-Received: by 2002:adf:efc9:: with SMTP id i9mr32318001wrp.187.1600332550694;
        Thu, 17 Sep 2020 01:49:10 -0700 (PDT)
Received: from localhost.localdomain ([2a02:a58:8532:8700:329c:23ff:fea8:6c81])
        by smtp.gmail.com with ESMTPSA id t22sm11973299wmt.1.2020.09.17.01.49.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Sep 2020 01:49:10 -0700 (PDT)
From: Ilie Halip <ilie.halip@gmail.com>
To: linux-kernel@vger.kernel.org
Cc: Ilie Halip <ilie.halip@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>,
	Marco Elver <elver@google.com>,
	Philip Li <philip.li@intel.com>,
	Borislav Petkov <bp@alien8.de>,
	kasan-dev@googlegroups.com,
	x86@kernel.org,
	clang-built-linux@googlegroups.com,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: [PATCH] objtool: ignore unreachable trap after call to noreturn functions
Date: Thu, 17 Sep 2020 11:49:04 +0300
Message-Id: <20200917084905.1647262-1-ilie.halip@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: ilie.halip@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=GfuKs9Cu;       spf=pass
 (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::444
 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap instruction
after a call to a noreturn function. In this case, objtool warns that the
ud2 instruction is unreachable.

objtool silences similar warnings (trap after dead end instructions), so
expand that check to include dead end functions.

Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Rong Chen <rong.a.chen@intel.com>
Cc: Marco Elver <elver@google.com>
Cc: Philip Li <philip.li@intel.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: kasan-dev@googlegroups.com
Cc: x86@kernel.org
Cc: clang-built-linux@googlegroups.com
BugLink: https://github.com/ClangBuiltLinux/linux/issues/1148
Link: https://lore.kernel.org/lkml/CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com
Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
Signed-off-by: Ilie Halip <ilie.halip@gmail.com>
---
 tools/objtool/check.c | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e034a8f24f46..eddf8bf16b05 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2612,9 +2612,10 @@ static bool is_ubsan_insn(struct instruction *insn)
 			"__ubsan_handle_builtin_unreachable"));
 }
 
-static bool ignore_unreachable_insn(struct instruction *insn)
+static bool ignore_unreachable_insn(struct objtool_file *file, struct instruction *insn)
 {
 	int i;
+	struct instruction *prev_insn;
 
 	if (insn->ignore || insn->type == INSN_NOP)
 		return true;
@@ -2639,8 +2640,11 @@ static bool ignore_unreachable_insn(struct instruction *insn)
 	 * __builtin_unreachable().  The BUG() macro has an unreachable() after
 	 * the UD2, which causes GCC's undefined trap logic to emit another UD2
 	 * (or occasionally a JMP to UD2).
+	 * CONFIG_UBSAN_TRAP may also insert a UD2 after calling a __noreturn
+	 * function.
 	 */
-	if (list_prev_entry(insn, list)->dead_end &&
+	prev_insn = list_prev_entry(insn, list);
+	if ((prev_insn->dead_end || dead_end_function(file, prev_insn->call_dest)) &&
 	    (insn->type == INSN_BUG ||
 	     (insn->type == INSN_JUMP_UNCONDITIONAL &&
 	      insn->jump_dest && insn->jump_dest->type == INSN_BUG)))
@@ -2767,7 +2771,7 @@ static int validate_reachable_instructions(struct objtool_file *file)
 		return 0;
 
 	for_each_insn(file, insn) {
-		if (insn->visited || ignore_unreachable_insn(insn))
+		if (insn->visited || ignore_unreachable_insn(file, insn))
 			continue;
 
 		WARN_FUNC("unreachable instruction", insn->sec, insn->offset);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917084905.1647262-1-ilie.halip%40gmail.com.
