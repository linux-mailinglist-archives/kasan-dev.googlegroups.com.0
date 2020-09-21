Return-Path: <kasan-dev+bncBDJKZSEQ3YKRBAVUUP5QKGQEQIPNCAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f183.google.com (mail-lj1-f183.google.com [209.85.208.183])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D637272EA1
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 18:51:15 +0200 (CEST)
Received: by mail-lj1-f183.google.com with SMTP id l1sf4331492ljj.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 09:51:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600707074; cv=pass;
        d=google.com; s=arc-20160816;
        b=rE5zofdH9W+2HfLF2Fp90XIsw44rxvqIUGytU0FJV/kx2RLcOarJAl3KaBzOkFZvvY
         NrpuWia8dOMJQbicNDtttsrgglJnYZO7SpWEgZ1vJocyzfB2lpXAX5egeMS3yXkyocS9
         zQ5LiD+v+FbBBBTBeoiImWXaj8GwfHhbPS8L4sMkYSCvr0D9THevJrqN7O1HEHwQsWsV
         mEvbinTY56ysp7CXREVnwTm2itpa7f3iVaOR3y2jyMg3UmFbcowbwSCP9wdUeo+6twCP
         RSznCckm81H83CMcZwjU3VqPxzfw+jm0NlnMEnmA9wi9k/7GwWgmQroVPtrQiE15vI1T
         U7jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=5WtwtptILIar+gNsHmk7n8QRGQRfod1D38WYKAWR/9w=;
        b=RP+7KbWL8IzrPumivxPYKKERrzqv/g4uCK0ImEErC4eNs/kwrOsMspqX3KqmK5W1tW
         i6NtwSZuNmQ9FipNkcgfMSC+Ab4TQtkNPj5eU8XuB8pMgl8V9i3jeLtvOCn7lxuziYN8
         suIw90pWpl7NPfX1o4NYo3LZo6nSr8gHsjGZtTgGrrBCVk7KeHTn1uNwIeVnzx+CIdnj
         8gXAjm6JYyVFp42uSWEx0bNemqMuV6RvNyoNFKloB9wQXU00xscPEZnSWoi48NLIPnf/
         FJMcs9zO4hn06ge9k22foiJay3wSHYqY1D6m63RgbBCjOg5hId98Fmn3+tTty/WKh1v/
         w65g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=lA42DkUt;
       dkim=neutral (no key) header.i=@linutronix.de header.b=rPGj3exW;
       spf=pass (google.com: domain of tip-bot2@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:sender:reply-to:to:subject:cc
         :in-reply-to:references:mime-version:message-id:robot-id
         :robot-unsubscribe:precedence:x-original-sender
         :x-original-authentication-results:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5WtwtptILIar+gNsHmk7n8QRGQRfod1D38WYKAWR/9w=;
        b=lYshN5itawGEN3nSI73gva/6/ZOoVz5eqwEMdBH+nudtgp/wHrzft2+0d1W2XU6tLr
         iGmwWUuTzMG98kT5fO1mjwrtLFcLP4pe4ZcJQ/dSKIlE17wl96toSntt7tXDsJzyyOO5
         +rr473H1l87f8OFDxxxNFDn27J7kw3GJHCW793ZUlea4HP5NLmtuIgUVa2FSjSGebQ4+
         VZM2Hlj5TUVO1YNWxhRn0lGrCWHhomg94YHH7R7n9EuNgrm6Sdru96B5LxHs63UuEGjR
         Y8qzfkdkkSvtliPJW+mGxwzQ3MHh7jE32Yhcola4tcUIdUlXIaCPQoL3+bZPZ5TCjqo0
         740g==
X-Gm-Message-State: AOAM532BSI8Qeckf4bhv4PBUvtyryVYJylEi0HyOnFYm82RNjDX8lQUA
	tRc7DlHhJSbg+cTZLX3TvVY=
X-Google-Smtp-Source: ABdhPJyr2fKFhLHM0K15/Oj9uxc9NSFUCulgKX/mvc0x5Tm6L5C+EOZVsm7M1a9TKZbJdcCp9nX5AA==
X-Received: by 2002:a19:6147:: with SMTP id m7mr311597lfk.108.1600707074707;
        Mon, 21 Sep 2020 09:51:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls582009lfp.3.gmail; Mon, 21 Sep
 2020 09:51:13 -0700 (PDT)
X-Received: by 2002:ac2:54b4:: with SMTP id w20mr285597lfk.13.1600707073536;
        Mon, 21 Sep 2020 09:51:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600707073; cv=none;
        d=google.com; s=arc-20160816;
        b=dEecvWG4HLjFjoaw26yOPfFap8jcFZEi/O71mKwFiWg09EQXl3eC+ttRGr40FOE/ow
         N7duF0TS/zokNOIC+ehQsLikQD4IyFir641h45rmvsBO/ETn1V9AAIgGNTvBXyQr9PQw
         GSSjWnx2f9MMx3GdmlPLpv8YaKVejDWKHRy3sMJRxWaxnPtuYgGQ8Dy/Vjtw+/iB4gq8
         fih+QvgKo3xcifmYcxk+zABFsy8mdPVyqTpMmWbK/e3qtBj2O5vMus0f+tMpUiqVdPfW
         5Do3A1GkmYFVYbC0FV+fLElmp8CgZ+mCn56LQvL9ghlynQzdlfPNG9/Tx0Z/iorAbyro
         K9Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:dkim-signature:dkim-signature:date;
        bh=gVfzDlgm3AjlhLPfD/PKu06jc0A49KijvnhM+NCvAtE=;
        b=lGEatiCrj9rRGlQ59o1aw17B2GguYuWCn55xORYpD2AlJqCqyS6u0v6FlWjDlODIlD
         sZuO/+T02pNsthTZh6TR0JH0cFBQmVY/Lw4hwArqOv6a3z37XBwLiwPr2fbr5cKdmgUO
         xOs8ZWW6zZdyule4R0Y867q4pfWXS9rwJc/E5NcuYpnAhZ1qsu+Y0Y8V3BpceEyOA8YF
         KSKKhWwi6KN/MYG/DftIe0emUY8KHZ5mIQT21ou2MBLYx8qZo0RTntXlWH6LIE3sHjrS
         OX6PsVreE7anCGI45dqL+mWLlvxZTLh6Z3Cw4na60K2sYURNt5hs2ZuJsvutwFY5cTh8
         LSLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=lA42DkUt;
       dkim=neutral (no key) header.i=@linutronix.de header.b=rPGj3exW;
       spf=pass (google.com: domain of tip-bot2@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 11si277595lfl.4.2020.09.21.09.51.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Sep 2020 09:51:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of tip-bot2@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 21 Sep 2020 16:51:11 -0000
From: "tip-bot2 for Ilie Halip" <tip-bot2@linutronix.de>
Sender: tip-bot2@linutronix.de
Reply-to: linux-kernel@vger.kernel.org
To: linux-tip-commits@vger.kernel.org
Subject: [tip: objtool/core] objtool: Ignore unreachable trap after call to
 noreturn functions
Cc: Nick Desaulniers <ndesaulniers@google.com>,
 Rong Chen <rong.a.chen@intel.com>, Marco Elver <elver@google.com>,
 Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>,
 kasan-dev@googlegroups.com, x86@kernel.org,
 clang-built-linux@googlegroups.com, kbuild test robot <lkp@intel.com>,
 Ilie Halip <ilie.halip@gmail.com>, Sedat Dilek <sedat.dilek@gmail.com>,
 Josh Poimboeuf <jpoimboe@redhat.com>, LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
References: <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
MIME-Version: 1.0
Message-ID: <160070707105.15536.14094674309505985856.tip-bot2@tip-bot2>
Robot-ID: <tip-bot2.linutronix.de>
Robot-Unsubscribe: Contact <mailto:tglx@linutronix.de> to get blacklisted from these emails
Precedence: list
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tip-bot2@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=lA42DkUt;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=rPGj3exW;       spf=pass
 (google.com: domain of tip-bot2@linutronix.de designates 193.142.43.55 as
 permitted sender) smtp.mailfrom=tip-bot2@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

The following commit has been merged into the objtool/core branch of tip:

Commit-ID:     14db1f0a93331d0958e90da522c429ff0890d2d6
Gitweb:        https://git.kernel.org/tip/14db1f0a93331d0958e90da522c429ff0890d2d6
Author:        Ilie Halip <ilie.halip@gmail.com>
AuthorDate:    Sat, 19 Sep 2020 09:41:18 +03:00
Committer:     Josh Poimboeuf <jpoimboe@redhat.com>
CommitterDate: Mon, 21 Sep 2020 10:20:10 -05:00

objtool: Ignore unreachable trap after call to noreturn functions

With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap
instruction after a call to a noreturn function. In this case, objtool
warns that the UD2 instruction is unreachable.

This is a behavior seen with Clang, from the oldest version capable of
building the mainline x64_64 kernel (9.0), to the latest experimental
version (12.0).

Objtool silences similar warnings (trap after dead end instructions), so
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
Tested-by: Sedat Dilek <sedat.dilek@gmail.com>
Signed-off-by: Josh Poimboeuf <jpoimboe@redhat.com>
---
 tools/objtool/check.c | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index a4796e3..2df9f76 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2638,9 +2638,10 @@ static bool is_ubsan_insn(struct instruction *insn)
 			"__ubsan_handle_builtin_unreachable"));
 }
 
-static bool ignore_unreachable_insn(struct instruction *insn)
+static bool ignore_unreachable_insn(struct objtool_file *file, struct instruction *insn)
 {
 	int i;
+	struct instruction *prev_insn;
 
 	if (insn->ignore || insn->type == INSN_NOP)
 		return true;
@@ -2668,8 +2669,11 @@ static bool ignore_unreachable_insn(struct instruction *insn)
 	 * __builtin_unreachable().  The BUG() macro has an unreachable() after
 	 * the UD2, which causes GCC's undefined trap logic to emit another UD2
 	 * (or occasionally a JMP to UD2).
+	 *
+	 * It may also insert a UD2 after calling a __noreturn function.
 	 */
-	if (list_prev_entry(insn, list)->dead_end &&
+	prev_insn = list_prev_entry(insn, list);
+	if ((prev_insn->dead_end || dead_end_function(file, prev_insn->call_dest)) &&
 	    (insn->type == INSN_BUG ||
 	     (insn->type == INSN_JUMP_UNCONDITIONAL &&
 	      insn->jump_dest && insn->jump_dest->type == INSN_BUG)))
@@ -2796,7 +2800,7 @@ static int validate_reachable_instructions(struct objtool_file *file)
 		return 0;
 
 	for_each_insn(file, insn) {
-		if (insn->visited || ignore_unreachable_insn(insn))
+		if (insn->visited || ignore_unreachable_insn(file, insn))
 			continue;
 
 		WARN_FUNC("unreachable instruction", insn->sec, insn->offset);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/160070707105.15536.14094674309505985856.tip-bot2%40tip-bot2.
