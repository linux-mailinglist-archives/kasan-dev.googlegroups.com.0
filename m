Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIET3P4QKGQEBSYULPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E539244DC4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:00 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id y10sf3599445ejd.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426080; cv=pass;
        d=google.com; s=arc-20160816;
        b=phY7N9Xkyjw8nYTXGf/tibev6YwmCzM83Ezap31nK2BGvBv6IGPHf7qt9+1iHdNz8m
         3Xcp3pbdM2sycY40uZYaH8oEhzUsrOXM+13aXWxY467ua43mE5U/1QYdM55qE+jLYEoz
         lowYtXgPbOayMEtTN2QN9gFoNfIH/PdNq1/6A1LvwNG0j3P1acz3HW0uJ3QMlQqqGyNW
         qfBx5atyZDJNkCQEUycVCIlLm3MvgX7MmFH6NeUEC6ZrbHMzzHBh1mAKkdzFCTpU8Gzb
         aDUmFEkYejNklOjKFq3B8cPd6qzxG5k4i9EnKPRt9+hPoiu9ZlSmMhnEsWTSbHZioCfP
         5cMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=tfWyGM0bX8QovcYGwIQ2zLf7QV8ze/pQJFeMYENc/Fc=;
        b=l4Of2N09TwkjfcI2tFojlQKJM26WOkCc1lIwhaFvyaXICWjjZ3Q5BJzVwZOCqo0ovX
         08y2+G05KUvDVtxtFAZdeCbGWUmdN8hIHLeyU75KZ5wbfKvsehiwR9qTYuPNTYtL0hgG
         HEwSCmp523GlAe47zieoFUYxvobT9JTD+SKsDyQtQaJDkmX0M2N2njdYSO1TYxqBhZkY
         nDT0X5ntslRlLw4oYoLr7ACMwlrwwFQ2KptvB4bPalGlm8Nwxzq9qms5vL6QIHJazNXm
         JUIbslnW41tIbdTe6COnsFNlzeJhz55RCwEDBc8QqeNHfKbGF+/EEV7uoG+M8JHhmY1T
         I2ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y52gb1Nw;
       spf=pass (google.com: domain of 3n8k2xwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3n8k2XwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tfWyGM0bX8QovcYGwIQ2zLf7QV8ze/pQJFeMYENc/Fc=;
        b=s7QkbjAgFZCcJn40T08XeFwcO9uwkv+gQFUN/N2OS3GHykZVBKO4COtTGa3gC4Rl8u
         2vNOxGJ1MaMtsZZ53pzqAIdE6B5//U+yNC1RPDaUNnBUBJdiL/wkaKjSHbTsQEpDB76A
         0BsDNXHILHW6w8jQhQJSlZOPLTqklfBvXL0Tu/C1+d885N6xPn/+qT00476sfKmawy0/
         16hVTYirrA7/NFMwAUd1N1fjXh2dBcg9xjAr5N7hrBSWUt+fXeiYb0Ycc/WnVSrdZi06
         q9sZzWTnMbmqThFerOW1aSvEqUmkPESZUCNNFgwNCnUsxd1X9HthsS3zC1lEsSz59si7
         om5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tfWyGM0bX8QovcYGwIQ2zLf7QV8ze/pQJFeMYENc/Fc=;
        b=czTGoW7GNcBHHmvi/Tn+BXccphrRxFbuUH/TVIE0Ck/MT45fWjCWA0j7xigziX/P5B
         q3YGVJugARvhW8nwxaDNx2QXApmbZLMGGwuU3GmUExeueiRg1TRAAJivhY5JgL3oVvAa
         kWwi10KgylgWlpJyTjOTc3LHO6bSIfvNCYGr7zX2lAILGgah3NtoxSYD2P5yaCF+08wZ
         R8wylO3NymH/2mbfFtaP2qOhIQHm4+LOYBFZBMI2kW7fJBp2a4CFJKXwDTcPvRLRRE0F
         RIjR77kj5Gg8q9pVly4DWpF1g0CpVRZLQqhLAHnifkz4WI2ntM+guMuH/wTUSJmpSf4C
         koMQ==
X-Gm-Message-State: AOAM533fuT7tgHKZNig/Z566MYdM86A2Lo1e4nCZLecgc467vs/PDlql
	nDdrstRYNbEhAduSM4n6YE4=
X-Google-Smtp-Source: ABdhPJwcnVQEsuSL7+iz3COVDctSEkSfGUe/pm1VE8FDctQ28oirkxsVSNXnh+aE12nnt0FOjs/BZA==
X-Received: by 2002:aa7:cf06:: with SMTP id a6mr3383434edy.293.1597426080265;
        Fri, 14 Aug 2020 10:28:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17ce:: with SMTP id s14ls1079002edy.1.gmail; Fri,
 14 Aug 2020 10:27:59 -0700 (PDT)
X-Received: by 2002:a05:6402:c0a:: with SMTP id co10mr3370434edb.342.1597426079780;
        Fri, 14 Aug 2020 10:27:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426079; cv=none;
        d=google.com; s=arc-20160816;
        b=mF9QqxpUq6FmMs+rbEywnk3wpm03korCHPnW8HefM7zrC6uF8fzgT6TvBzvYlU+8/A
         /pQ3UNOKkUwgN/Ncb54eQS003XB9QWd0MseqAdy+vjkNYgO+yAeYggZnR5+ll1Xgjf7w
         iqtqEDLW4xQl/nz2TzFae4mw0qTc7OjxvZ/L83YGaOtOSYIV4YusdPaJsGvbx8Ir9niH
         Y4kMeS8A58RXsfgr1O/GFgdu1SlbU2rRvnGfKMEMyx9j8rwIMZn81ze8y/Dwe/V9UB1P
         HedJIHc+yGDfpEChunDFOqw7jcmNbfbG7d6h3oTvv91IJ85Tjy/fN4G+aYdliSOseSWK
         gLQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cI4OCXXdcluQ8udPJIeOucRKN//yXw3Lt8Ci7TJhPtY=;
        b=dhS1/ZgrXukFVRfgW+V6q+r/55pb4VQOXhQAGJxOkmR/CCnkl1P2SnQvDXtDEPM+Ll
         3ehY50bP7asZ8HNtQuHHF2an9Jq0jyWe5c52E72hN47YHpnno5dA8Ooz6yTXUov0eC8n
         Hs5BkHPTIbpzoeAqvaZoz59ZSCjq94NebfbLgslMQhn/jJH6W8BH5FzZNig3Ge2edr/r
         zFro5lRjgoMwTLl8RCDIU5Cy/k4yVu2zJMkPB5H3qXQjNRoL2o7rKOcx5YLoMe4Ew9bJ
         yk3RMZO5H94dt0LmnutnCc8kxNrYHGtAlEhp9ARh9YxgAYOz2j9HAcKoOWi6d0Z3coi4
         l3WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y52gb1Nw;
       spf=pass (google.com: domain of 3n8k2xwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3n8k2XwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id o23si337708edq.5.2020.08.14.10.27.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n8k2xwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z10so3531674wmi.8
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:59 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:: with SMTP id g19mr3322924wmk.29.1597426079500;
 Fri, 14 Aug 2020 10:27:59 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:57 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <ea36f46b5223a67d6333acbcc79ba07380608010.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 15/35] kasan: rename print_shadow_for_address to print_memory_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y52gb1Nw;       spf=pass
 (google.com: domain of 3n8k2xwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3n8k2XwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ada3cfb43764..8ad1ced1607d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -255,7 +255,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -316,7 +316,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -352,7 +352,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ea36f46b5223a67d6333acbcc79ba07380608010.1597425745.git.andreyknvl%40google.com.
