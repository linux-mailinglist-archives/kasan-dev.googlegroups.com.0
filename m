Return-Path: <kasan-dev+bncBCM33EFK7EJRBLGQS35QKGQERB7ZLXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D36270B2D
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Sep 2020 08:41:48 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id b17sf2791406ljp.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 23:41:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600497708; cv=pass;
        d=google.com; s=arc-20160816;
        b=UW7LP+3A/sLYBXo/qbsU+8ZKHmc2Rx6SZMqZyVArymt/4o8yDjXXCvW/iJDrhXI26L
         RbruHoPr3eGJyFMBo0SFkhFp9amCxO3xn+CVW0938PfLuxKyyEUszbIsJw0SuDmSLIVI
         yThjpWflNySvQaFINnQvXP7Zy53K+n49XtIwJZM2iHR+qJW4inTBxHQGyhJ1+jTa2YxU
         orfW90QwmCrjlIxeXM3zh1RUpHLgBfH7i1bhZFAXijx9yhe1eKA+HNNP26PKlW2oCE7C
         i7BtZbSsGE5xCLUwfFBupVXf3v0ushMhDdo1l3mU7Dn1mnwj3UfuZq/Ist9lqkPJFscP
         Gp/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FOYrTmTKP4BtkaxYBZe2TziWdCp4s/Ne8at/ggerGe8=;
        b=Js9Rr0Jj3tqmCLiiNNGlvBItFErfdiafmV6e1Xppln7OtoYCv5XvV6AevBrFYuM5wz
         HN/L/c4mjK6LiV2M150yJkGl0pQPgNzsiNAgtzXWHU//zzpDyzaSDZyo/Yu6Lvv34RKR
         QI4oHOhv8plTwnkZOvyE4dnP7xp/fq7tjd7d1j9KHbG+TpfxuyEeuGhdsKDlaoWdEkf3
         Q8O89xrm5BSEhXwRGjsJBgIShIVXO2GeZQbVe9id6me6bU1chZVlUKu3Lp5Fnl9G5vx1
         ra2Wb5fT6yc81NxCOnMRm6XceRuWDS5/MauuMDql5Qswzt0IzJbb9JIEG1eDM5qOda8j
         qWVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gcOYcGHH;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOYrTmTKP4BtkaxYBZe2TziWdCp4s/Ne8at/ggerGe8=;
        b=dQ35Xwbph6Xy6iQkYUMLsrxtmtN2HVbA5zr6byHfbxGh0WOOkUsjbseoIdDQwv4WOH
         bp10LBYE46wP/DI3VVScvVpsrw5BU8j2KYatJsvlizyZORn9+7YQTLf5Pq/EFpq0JyqD
         hp6IOQhzgmLMq2kC3RC4THoE3uBHP69Em9eG2TaiN4KWzolDtRA65CL6tcwMDgcoDiK5
         18QIAKsCtaVoJPZhWo7hner6OutEKEhFY4Z+d1B7RkoflD1+h66aNYhwI0BqXOnHllmm
         YBNjXr82TTCxnOsV6Zs+jDr9gp1TE+vT7B+vWg/UbRWJN78EOTxDwDLS4j3jqKivCzm/
         aPxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOYrTmTKP4BtkaxYBZe2TziWdCp4s/Ne8at/ggerGe8=;
        b=GdYvppjkFoh1ylGl/OoFZkjGFZZ0K+c/aRlzmV8ur5uRO2IaNGUO0llF5XwUW+Ne5W
         XZ+MuobnQc1IFHHOMyRjIKLY3b//i8rXNbydcr6NF6305y2KpdDe4aoOV7Xe7qJfv2GH
         Cpu2M+69Z+AYi5ZJP9zqjzBFEpYWEq/x79Hho+C4F9b9XzzcyJT5psH8KrFAoFET8SJf
         fI770JxZeUmMUbF10Du3ChgjY9x3s5B38MHOm3B4MMxO2c7f0yCFIJozf6WtjacYXzWD
         jh2wy2tugQWecfYXDkaoAOZFZbn+jqKr9w8wwB69//xJMUkbfnoNCPV6I3V7N8Rro5zE
         6h1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOYrTmTKP4BtkaxYBZe2TziWdCp4s/Ne8at/ggerGe8=;
        b=WsuEiwBJnwTe8RBY1+a1McQeHVS6HkHjoBs5U8um+vF2zCIJNvLYnoj/GrpcsEqus/
         GUYS+H7Ec1y/BCfJLPe2/INU4oflDFVnY5PbURf+22haOGwI2hm5qZd2F04A4WUkKhJo
         f5HY/owpLOI8o/kwjACDOHbykiU2pv+XBO1fC6XuCrpqrohUujKeHW1uhdQ0clCnRSte
         Tb432rNbBWRS1biApwPzjY+ckigzmGmeQjygQmReq/3sPCvadkcVho0/UzYAb+dOP7Ls
         igGKTsvDafIC1j8bzOe2DEFj7teFhwDBF3oPU651lb/gIeRB+f64wlVNPt5HOr1zgKwa
         vBJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307Qlt/N0O5XXGsaChV/nwL0tr9kMgQbdXKVDfDYtQ7ty7pTlnX
	jJIODbOAmrDajFgOzT9N88Y=
X-Google-Smtp-Source: ABdhPJwvGRcdlllq45jmNUxPXYSY6UF9iAatm37e/0C0mbPrickr1r//569M3jorBPxUHD/5hk09kw==
X-Received: by 2002:a2e:99c4:: with SMTP id l4mr13736614ljj.428.1600497708326;
        Fri, 18 Sep 2020 23:41:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b0e9:: with SMTP id h9ls1103883ljl.5.gmail; Fri, 18 Sep
 2020 23:41:47 -0700 (PDT)
X-Received: by 2002:a2e:b4a5:: with SMTP id q5mr13988714ljm.200.1600497707118;
        Fri, 18 Sep 2020 23:41:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600497707; cv=none;
        d=google.com; s=arc-20160816;
        b=LH61M+xI/y64cKwFSNUgLt2Ieaqp40laXVv4ZY1UIhdR85GWGnajd7/H+jo8XbjjNE
         Ov+A8jVvX/j/Jw5z+U6aZl3E4yGS5xKBgdrtvOLC4Ru7Be0Jh29G31HLOKOqt67ikSlW
         ZbybFerPnW3iF3aqRqqIKxkUWrCXIn4wo+FA2Njtb7nRQtl3OZW7N8tcSfnF1KBMn3xp
         y41e5A379jgTYiGdUq3oNkP13TqxN501XvOFaAN7Y61lQVogMLr1KQr5CDUNHQyiHaMk
         wDkokFmAJg2KHRmd37MXPilq4R4CoQC4I/bHscr7Lg8QG1XwjINl3DROdnnwCWvlPuVA
         +/Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g5DNwEJpdlREbpxxNUWXwnzTcfAjTXzmIWah8QsBFAI=;
        b=NE4K9Ss9wV3YbQtS+W+g6C/KCdavr1EvkPi07q2smjn5lKHMmTWwR135/aPslPpP+j
         Kr4MHDnZRqSaZs+INI/iXauoWRhoW/o2RSY6djaUT8PZ+whVD/cl16hVFFgVwHdZ+dd+
         Gky0id23ZdZZQq1d7lwegKDKUWNaPG9vphsFZp+ykXyeNrhpEuoxsb6BCfLfvVjZargD
         J1h30fKaJYc07ua/s1+XgtdA7BR9pFTEeBQmsgUOhe9r/w2FlWbVTr7t3VoC6GyZCp/e
         IBGmWltJ9tRG1dCgBR8ZOv5NVGQF/egblIfSMIjN5zdT9SoS6i8OhEcDIwY7TScxFgjQ
         iJCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gcOYcGHH;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y75si127053lfa.3.2020.09.18.23.41.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 23:41:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id b79so7550348wmb.4;
        Fri, 18 Sep 2020 23:41:47 -0700 (PDT)
X-Received: by 2002:a1c:9e0e:: with SMTP id h14mr18723255wme.18.1600497706567;
        Fri, 18 Sep 2020 23:41:46 -0700 (PDT)
Received: from localhost.localdomain ([2a02:a58:8532:8700:329c:23ff:fea8:6c81])
        by smtp.gmail.com with ESMTPSA id l5sm9218927wmf.10.2020.09.18.23.41.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 23:41:45 -0700 (PDT)
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
	kbuild test robot <lkp@intel.com>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: [PATCH v2] objtool: ignore unreachable trap after call to noreturn functions
Date: Sat, 19 Sep 2020 09:41:18 +0300
Message-Id: <20200919064118.1899325-1-ilie.halip@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200918154840.h3xbspb5jq7zw755@treble>
References: <20200918154840.h3xbspb5jq7zw755@treble>
MIME-Version: 1.0
X-Original-Sender: ilie.halip@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gcOYcGHH;       spf=pass
 (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::342
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

This is a behavior seen with clang, from the oldest version capable of
building the mainline x64_64 kernel (9.0), to the latest experimental
version (12.0).

objtool silences similar warnings (trap after dead end instructions), so
so expand that check to include dead end functions.

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
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Tested-by: Nick Desaulniers <ndesaulniers@google.com>
Reported-by: kbuild test robot <lkp@intel.com>
Signed-off-by: Ilie Halip <ilie.halip@gmail.com>
---

Changed in v2:
 - added a mention that this is a clang issue across all versions
 - added Nick's Reviewed-by, Tested-by
 - added Reported-by

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200919064118.1899325-1-ilie.halip%40gmail.com.
