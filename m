Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4V3CGAMGQECXQ6HWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84EDC455692
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:56 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id z12-20020a0565120c0c00b004037427efb7sf3430927lfu.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223116; cv=pass;
        d=google.com; s=arc-20160816;
        b=RGfvq35eWWKHbJ6ttylqYwGJFCoCy2wVdRA0dbMViBr+IkwnYP7336uNEBLa0dekZ0
         dBZfxyezQcvyql2JeCvjNvaWX636hzGhUz9mAvC/mjZoPg7o1WiwQcYN1mHa6RfIcMg1
         WZULNzqOGrF4wpD8+hGRsGrATZ+iEpJAvVjW4U2UpQgkJi4kIf/q7+AiJwGj3fUTBPlj
         ikO925tJEpcYsXDr/vXUcLmfy2LeeccJJdvmJIZJMHGF+GUshiUazpBliBS5YWvX/Nml
         xZyVNFnrvh6VdiPDbzG/P+hfg8UFUdXTUrsBT+sKkytJfVFUG+sUyUmosYm2YfhLd+wd
         4ANA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xOc8x01d//QlQlegPTWB9aHp6PqFUCZI0m77i1QD/ZQ=;
        b=e6qhIAnbpZ/ve6y8mmaegpSieq1jZTWMEY36Q/d3Nsl+OgmL1T0RZ11h5qwO/f5D2j
         bSR2Ax1voIeNv6Ub0uBgXUSiBGgWf4uQAf2xBau+NylHwfxDFdZ/49KrlSupqDTUxuwZ
         6T8KcPeyR1jZtzzt3KVtFojb2ufmDeTjbgnQ4OBGSzySbN/LhTipnLmoKUMGxsMD5sxs
         yle52agNhz/gk8Akanu48r/dDzHrmaT7d8bp5jxE2OXUdPOlqr58lR5Mt0bZxsBB57WU
         RF5caYgRRoW1WNJ/Rd68iW+BF8JRSkFXhwQdeAN01esjKpafpIwaJjxtLDIy1S67Y8c5
         5nbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qq5HBBXg;
       spf=pass (google.com: domain of 3ygqwyqukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ygqWYQUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xOc8x01d//QlQlegPTWB9aHp6PqFUCZI0m77i1QD/ZQ=;
        b=ayQwFkxFkRRxvzVWzXoxT83sIB5DU+1BafR0JjThDPw65AvlSN/6ho1dG0ve2pnnP6
         uHiCJZu2coMPdZTPslBMDNCgEdJ7Vii+Npjf3FBNosRiRqk7kCYUeh3JdH9djaxKdYbL
         4RfwoTk3i23lnZVnjWq4w1X6Rh4sjwhlOPJr+NWrQ1S+L9KWstqV3TLgChOhNPxrU/Tb
         VRuEyPr3QNTiPupS4EaBzvXEz3lTDYydpqaIX6Tn6u5pNf7iqgv6CVAIZpTgosU1HTFp
         9sxv3rNtd1SLFDymZCBCVv88jxKcT6SWH0pgU2UuZNrgn5auxa5Xt0EFeP2lyane1Upt
         aU7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xOc8x01d//QlQlegPTWB9aHp6PqFUCZI0m77i1QD/ZQ=;
        b=nz9eChFuCPr/4Ms7W8KVayizhEV22wnODQASGQztnh3wUpedGmDNGiROdxxzPNCy75
         xQM35IwVKV0G8htn6/BA5OHEYgW9xgwfhDmA/WVJhWPCCDu7faBWnYra6FL40tZxSmJj
         ojAZAExdFfrGpH4C9lyDJztRYoIIRej93BBuPL7ka6qQKawnXBJlkX7OAlf1te0Zcw43
         tZYW3PCflcVW4OEe/HgUiQ+EF76892d76bGUWjPp8tLmZzdt7yisb6ASuPgmzppT3zDJ
         C3wfeVVdLJaSlm5bgNe7Jq3GHM+5cSIIO9/H2F/Ejc3hCsjLD+KUiJVf4pE6pToS6cqN
         ERBA==
X-Gm-Message-State: AOAM531GSDs/4EZIMCOk9sUeh+WWpMljhWL/hP5iMCvknvFjcce11mjO
	y8gWUlq0U0bVxmY6gWlowdo=
X-Google-Smtp-Source: ABdhPJzYI4IZYruWEbS6PA6UcmyvaczR5Zp8rtLwP7WE6D9JvsvFT75I2JMIYLX5jM0jMoIk64BBKg==
X-Received: by 2002:a05:6512:689:: with SMTP id t9mr22677221lfe.614.1637223116157;
        Thu, 18 Nov 2021 00:11:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls1605394lfv.3.gmail; Thu,
 18 Nov 2021 00:11:55 -0800 (PST)
X-Received: by 2002:a05:6512:4022:: with SMTP id br34mr22525380lfb.530.1637223115093;
        Thu, 18 Nov 2021 00:11:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223115; cv=none;
        d=google.com; s=arc-20160816;
        b=oxSjpIoT39Zp8IKXPBzyx/KaYQtfq1WCCsDntcqf5b0ikTW1915497btaqeKsvHGjd
         vhDFFs4SLNEKPmNPJkx33aJUfjWHeF7RXFKFeVvioaLw5Y/1CydLdNMXzbLCVRZBbLSC
         wYU1dcZt+9WkIRtORKc41kZBOpFlUkmh2HbOIeUiRH6MDmMGlOsoxuvvh92GXYfk0CMg
         QM4y45Hud796yGKC/5lQ8I/dgZbMY+ChP5N5SxhjJ2nTntpXIPU5WvoFNbbu/y+KEkzd
         jdN+1U7KUVw52hNPXYON9OPLVR3Raz42nuPxCaPDZtWe87+LywfSKfHz19YxBzu0b86b
         dGZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PKWjAua1xn2U34SqPEegBKZB0S4U3BBHTPl/cM5EGNo=;
        b=qCYCSHn77DzO8sOJgVmJ0XogsTZ0hVnH1uBuPgFjuN6Q/BGpj3QnJ2HFbltakGc0GB
         tqAbbGcz1ZU1QMEyYOym6Im3U5lJ8evx13NrzgUuJY7zX4lS/KW+cY8EpfrFRnYVyHpm
         gWrm5R1EDKzZ6v12Opjge12WlwTyuROHdUqwkTMti3qY0Lusjl9KaPnA0RVbsmJ+2I8M
         x7PyOsoGJN2wFjn3wP8vwOzMY3Bnuu0kBqstpH1h04wnpzmjM4+kpXL8H/B56XkZGHjI
         0ARCjTicZYPiD7KYtDXC3tlT9jxI5oPShcUoLe3HQzgOTpnDCEfAlBZd3pJoPRQVxmgs
         rTGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qq5HBBXg;
       spf=pass (google.com: domain of 3ygqwyqukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ygqWYQUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o25si142124lfo.9.2021.11.18.00.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ygqwyqukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dso1758457wmc.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:55 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a1c:7715:: with SMTP id t21mr7647569wmi.183.1637223114521;
 Thu, 18 Nov 2021 00:11:54 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:27 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-24-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Qq5HBBXg;       spf=pass
 (google.com: domain of 3ygqwyqukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ygqWYQUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Teach objtool to turn instrumentation required for memory barrier
modeling into nops in noinstr text.

The __tsan_func_entry/exit calls are still emitted by compilers even
with the __no_sanitize_thread attribute. The memory barrier
instrumentation will be inserted explicitly (without compiler help), and
thus needs to also explicitly be removed.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Rewrite after rebase to v5.16-rc1.
---
 tools/objtool/check.c               | 37 ++++++++++++++++++++++-------
 tools/objtool/include/objtool/elf.h |  2 +-
 2 files changed, 30 insertions(+), 9 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 61dfb66b30b6..2b2587e5ec69 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1071,12 +1071,7 @@ static void annotate_call_site(struct objtool_file *file,
 		return;
 	}
 
-	/*
-	 * Many compilers cannot disable KCOV with a function attribute
-	 * so they need a little help, NOP out any KCOV calls from noinstr
-	 * text.
-	 */
-	if (insn->sec->noinstr && sym->kcov) {
+	if (insn->sec->noinstr && sym->removable_instr) {
 		if (reloc) {
 			reloc->type = R_NONE;
 			elf_write_reloc(file->elf, reloc);
@@ -1991,6 +1986,32 @@ static int read_intra_function_calls(struct objtool_file *file)
 	return 0;
 }
 
+static bool is_removable_instr(const char *name)
+{
+	/*
+	 * Many compilers cannot disable KCOV with a function attribute so they
+	 * need a little help, NOP out any KCOV calls from noinstr text.
+	 */
+	if (!strncmp(name, "__sanitizer_cov_", 16))
+		return true;
+
+	/*
+	 * Compilers currently do not remove __tsan_func_entry/exit with the
+	 * __no_sanitize_thread attribute, remove them.
+	 *
+	 * Memory barrier instrumentation is not emitted by the compiler, but
+	 * inserted explicitly, so we need to also remove them.
+	 */
+	if (!strncmp(name, "__tsan_func_", 12) ||
+	    !strcmp(name, "__kcsan_mb") ||
+	    !strcmp(name, "__kcsan_wmb") ||
+	    !strcmp(name, "__kcsan_rmb") ||
+	    !strcmp(name, "__kcsan_release"))
+		return true;
+
+	return false;
+}
+
 static int classify_symbols(struct objtool_file *file)
 {
 	struct section *sec;
@@ -2011,8 +2032,8 @@ static int classify_symbols(struct objtool_file *file)
 			if (!strcmp(func->name, "__fentry__"))
 				func->fentry = true;
 
-			if (!strncmp(func->name, "__sanitizer_cov_", 16))
-				func->kcov = true;
+			if (is_removable_instr(func->name))
+				func->removable_instr = true;
 		}
 	}
 
diff --git a/tools/objtool/include/objtool/elf.h b/tools/objtool/include/objtool/elf.h
index cdc739fa9a6f..62e790a09ad2 100644
--- a/tools/objtool/include/objtool/elf.h
+++ b/tools/objtool/include/objtool/elf.h
@@ -58,7 +58,7 @@ struct symbol {
 	u8 static_call_tramp : 1;
 	u8 retpoline_thunk   : 1;
 	u8 fentry            : 1;
-	u8 kcov              : 1;
+	u8 removable_instr   : 1;
 	struct list_head pv_target;
 };
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-24-elver%40google.com.
