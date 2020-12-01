Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6F6TH7AKGQE4BDL7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D321C2CA6DE
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 16:21:28 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id b12sf1143712wru.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 07:21:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606836088; cv=pass;
        d=google.com; s=arc-20160816;
        b=zFa42vYJFlKKE2YVLLw3QqS7GRCwep1ru0l/5mLl12Yc50hCQGdZS+uvB1LYOR6egO
         6aC0KXAJEGnIhFJ1EPF2YBpDIoLEj5SFeYleeiAPZW84jjjlLfeP5ePbdcpGu1Eix7R5
         J6eZPaK+bI4ZgacqLdVFX0uMbkZ5apDpkrTaXV7NjfaInj13Pjc/yaAPqe9S4Re435bf
         P7zLkq8P42mfpHt2mm4xkOfgAEq57LjCHvk/wHdii19NN5I+oqcT0BYCd6IAdqg/uAXy
         UPvjbJB+R3ny9km5jrdJ+5WXQKLBOr2YLd2Bs0es7TWXumOyL0aYovRFlu6sXOZPOIRl
         rhXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=RH8J6f2H+7LaF7p+RBuDIeAGfPUb59LVAhTr2URTovk=;
        b=Yk0N+X1XZkmyh8FZNIVEVVZLokly4sL/8Wx0LBv+DgxDw8SCO63vm/oXUD3C/cpal6
         ak/mLnvIvNneKW/ceXUnvRMdiHG4wWsBC5Kg6Jbp/0A+GoS4V2Fv89WHi/zf2sdr9zS5
         UiNQL6a+Rj5joddgWuMn2lPDUT5czol/yoTQYDGfor+MyvQB2q2wWVXe/dMGjlZhtaWv
         5YOThK8F5OoNeX7fZ3vjs4wMvf+6qQaS04Vi6fIcqRNJAEUZTVpQaDtGU5ND7rcex7ti
         M05bo+GvSxRveFVd0A8VlI6UjqtsHw29DrzBP9SmTZkc5K4Hi6fwRCiljmDaMCcWehA5
         FE+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eghANDW2;
       spf=pass (google.com: domain of 3d1_gxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3d1_GXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RH8J6f2H+7LaF7p+RBuDIeAGfPUb59LVAhTr2URTovk=;
        b=cnLMDoIw6hpoIlYv9k66955nxcA+o7zDbWJZrg3yKqe2MuVhwc2Fpm8UJ0xthovkzk
         UbJiPu/Iha+zZHlGRcyGwCvQuVsN/wFV3ANU9c0Vhhs3MyAbcRwTzIXpYQ0pEbE209MA
         CoT1/t5c2QeN3mIVR5Ws9EWHCs91Q/f5S2+uMhguh82nGRXRnmRC11cXj/IcW2Id+SAJ
         86ugXq95qZRPQGsOw0UncapCJYyZMszb2rdmtB8yTpC51qQT7Pe/6kdbZSCoyJBTj+Y0
         MWfx3fIu3IMmMaLVHifT2bdKcDTO2lS2ajWqPqpDyoHgHHv3iL6rJEdBD2vW2dqcz8+x
         USxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RH8J6f2H+7LaF7p+RBuDIeAGfPUb59LVAhTr2URTovk=;
        b=XD0SSFOrZ4rAft9pjTcVxkM9oV0Nhs/h3ZzhYm1TKB7JKeuwKcfTMryt1f2tdrbJxU
         TRarrRc21wKRh2j1OvQ4mAEDuJI2UuHp2Mixzxe/iL6rWtTUHWKJ9DFE9/t535Ch83U3
         RIOHO2VlxquUvEzW7timbXWMLlX/K4Jhgw4wrl4RYfx4CnZz8v4g/qI2qt8DqinnGzwL
         YWAbYwp08K61ROMJ+xsAaRPjsUvz65qWPmdA6Z258okzNb2JYkxLA//hIBcvlLppZJI6
         xcljJooRKhCVxDxitv5HGQIE63CBjSIlQXZ33mtYLc+1GSQxcR8KuEwZ+2gW+vSrHPn/
         h88g==
X-Gm-Message-State: AOAM531hCaaAvUuGyDom+CHL4fK+IUQE8HNeMTqZwU+Irg3Ucxb3gIzh
	V61b22wra8MGgSvS/EUy2Kw=
X-Google-Smtp-Source: ABdhPJzPEDaCakKwebnsuISiSrNdBtUciMpCY7P6YS58WB+jiCt8Yd/ytjOHFuUbGcyYMQxWlWdFHg==
X-Received: by 2002:a05:600c:2110:: with SMTP id u16mr3284934wml.4.1606836088579;
        Tue, 01 Dec 2020 07:21:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls693005wrc.2.gmail; Tue, 01 Dec
 2020 07:21:27 -0800 (PST)
X-Received: by 2002:a5d:4052:: with SMTP id w18mr4620163wrp.63.1606836087654;
        Tue, 01 Dec 2020 07:21:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606836087; cv=none;
        d=google.com; s=arc-20160816;
        b=aFPy0oM0Ids7R8mMfkbZAEsQWHScnsJyQaqaMO1eBRK7qNgdxgpAx6VYwF6x2b9AEC
         If8LoWXQjwSV1n77RRc9fEcKxDp2Xcc66XtXcBfHjsv6eMQWcjq9Tfqqddl/VsbLZOyh
         uyUr5txwAFxAQ/k37jHhsKhQwuJprBdQjHEzQZlENbssEn4tvqhZrOq2vpJAQ7QX4RBf
         DthI7cP2y8k7q6jpD+llwd+Dy/1tCM9TuHPT37FvkIMIaX0bygOFWYZAJyvlLRuhTm9V
         xVrYlIHDtIyeSZKcPwyUrwAzB63k7IhMQ2sol0FL5kGI39QkH9bpOtq6vqqAzMq4oD2E
         Ht6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=gl38stHx97yG3pBLu7/ITLy+50rUPm1B17DaXfHgCU0=;
        b=Wjbz+/eQ/IxEOZ+IhOvrOVI7YK4R0yYZped9cuusuvK3CNkAqBpTg8ZOumPD+2yoOd
         FCp4QIU7TZXGsIsfUb6ipvU2FmcEjYrUG4MU5MRh//YzsaUs1IbersuuXO6qcpF44+Dt
         urpTZzrnkOqJw2YOKGF6X/FzjXOsBeGesYAswbf/oFgqee/9xRszjgc0VRFozMSXg2yD
         kzueT4P+N1KoewYniMKdAnvreFZV90EswlkwV2qBvSYH9/DEMOr/5qTARwuF87MhC1Om
         SkjBZyGG06SeXa0xmQjolwtYItzZl4rl0TWsBhs1eVVWEByoj0FbGOKW1ptiWF7Fuh/5
         Jrug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eghANDW2;
       spf=pass (google.com: domain of 3d1_gxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3d1_GXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c20si75448wmd.2.2020.12.01.07.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 07:21:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3d1_gxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id z13so1114323wrm.19
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 07:21:27 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:7217:: with SMTP id n23mr3064828wmc.167.1606836087168;
 Tue, 01 Dec 2020 07:21:27 -0800 (PST)
Date: Tue,  1 Dec 2020 16:20:18 +0100
Message-Id: <20201201152017.3576951-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH] genksyms: Ignore module scoped _Static_assert()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	masahiroy@kernel.org, ndesaulniers@google.com, joe@perches.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eghANDW2;       spf=pass
 (google.com: domain of 3d1_gxwukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3d1_GXwUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

The C11 _Static_assert() keyword may be used at module scope, and we
need to teach genksyms about it to not abort with an error. We currently
have a growing number of static_assert() (but also direct usage of
_Static_assert()) users at module scope:

	git grep -E '^_Static_assert\(|^static_assert\(' | grep -v '^tools' | wc -l
	135

More recently, when enabling CONFIG_MODVERSIONS with CONFIG_KCSAN, we
observe a number of warnings:

	WARNING: modpost: EXPORT symbol "<..all kcsan symbols..>" [vmlinux] [...]

When running a preprocessed source through 'genksyms -w' a number of
syntax errors point at usage of static_assert()s. In the case of
kernel/kcsan/encoding.h, new static_assert()s had been introduced which
used expressions that appear to cause genksyms to not even be able to
recover from the syntax error gracefully (as it appears was the case
previously).

Therefore, make genksyms ignore all _Static_assert() and the contained
expression. With the fix, usage of _Static_assert() no longer cause
"syntax error" all over the kernel, and the above modpost warnings for
KCSAN are gone, too.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/genksyms/keywords.c |  3 +++
 scripts/genksyms/lex.l      | 27 ++++++++++++++++++++++++++-
 scripts/genksyms/parse.y    |  7 +++++++
 3 files changed, 36 insertions(+), 1 deletion(-)

diff --git a/scripts/genksyms/keywords.c b/scripts/genksyms/keywords.c
index 057c6cabad1d..b85e0979a00c 100644
--- a/scripts/genksyms/keywords.c
+++ b/scripts/genksyms/keywords.c
@@ -32,6 +32,9 @@ static struct resword {
 	{ "restrict", RESTRICT_KEYW },
 	{ "asm", ASM_KEYW },
 
+	// c11 keywords that can be used at module scope
+	{ "_Static_assert", STATIC_ASSERT_KEYW },
+
 	// attribute commented out in modutils 2.4.2.  People are using 'attribute' as a
 	// field name which breaks the genksyms parser.  It is not a gcc keyword anyway.
 	// KAO. },
diff --git a/scripts/genksyms/lex.l b/scripts/genksyms/lex.l
index e265c5d96861..ae76472efc43 100644
--- a/scripts/genksyms/lex.l
+++ b/scripts/genksyms/lex.l
@@ -118,7 +118,7 @@ yylex(void)
 {
   static enum {
     ST_NOTSTARTED, ST_NORMAL, ST_ATTRIBUTE, ST_ASM, ST_TYPEOF, ST_TYPEOF_1,
-    ST_BRACKET, ST_BRACE, ST_EXPRESSION,
+    ST_BRACKET, ST_BRACE, ST_EXPRESSION, ST_STATIC_ASSERT,
     ST_TABLE_1, ST_TABLE_2, ST_TABLE_3, ST_TABLE_4,
     ST_TABLE_5, ST_TABLE_6
   } lexstate = ST_NOTSTARTED;
@@ -201,6 +201,11 @@ repeat:
 
 		  case EXPORT_SYMBOL_KEYW:
 		      goto fini;
+
+		  case STATIC_ASSERT_KEYW:
+		    lexstate = ST_STATIC_ASSERT;
+		    count = 0;
+		    goto repeat;
 		  }
 	      }
 	    if (!suppress_type_lookup)
@@ -401,6 +406,26 @@ repeat:
 	}
       break;
 
+    case ST_STATIC_ASSERT:
+      APP;
+      switch (token)
+	{
+	case '(':
+	  ++count;
+	  goto repeat;
+	case ')':
+	  if (--count == 0)
+	    {
+	      lexstate = ST_NORMAL;
+	      token = STATIC_ASSERT_PHRASE;
+	      break;
+	    }
+	  goto repeat;
+	default:
+	  goto repeat;
+	}
+      break;
+
     case ST_TABLE_1:
       goto repeat;
 
diff --git a/scripts/genksyms/parse.y b/scripts/genksyms/parse.y
index e22b42245bcc..8e9b5e69e8f0 100644
--- a/scripts/genksyms/parse.y
+++ b/scripts/genksyms/parse.y
@@ -80,6 +80,7 @@ static void record_compound(struct string_list **keyw,
 %token SHORT_KEYW
 %token SIGNED_KEYW
 %token STATIC_KEYW
+%token STATIC_ASSERT_KEYW
 %token STRUCT_KEYW
 %token TYPEDEF_KEYW
 %token UNION_KEYW
@@ -97,6 +98,7 @@ static void record_compound(struct string_list **keyw,
 %token BRACE_PHRASE
 %token BRACKET_PHRASE
 %token EXPRESSION_PHRASE
+%token STATIC_ASSERT_PHRASE
 
 %token CHAR
 %token DOTS
@@ -130,6 +132,7 @@ declaration1:
 	| function_definition
 	| asm_definition
 	| export_definition
+	| static_assert
 	| error ';'				{ $$ = $2; }
 	| error '}'				{ $$ = $2; }
 	;
@@ -493,6 +496,10 @@ export_definition:
 		{ export_symbol((*$3)->string); $$ = $5; }
 	;
 
+/* Ignore any module scoped _Static_assert(...) */
+static_assert:
+	STATIC_ASSERT_PHRASE ';'			{ $$ = $2; }
+	;
 
 %%
 
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201152017.3576951-1-elver%40google.com.
