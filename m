Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQET3P4QKGQEAF5XG7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD4FD244DD9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:33 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id m25sf1738532vso.20
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426113; cv=pass;
        d=google.com; s=arc-20160816;
        b=JbTSXyd2Rm7suGwfw18bZhOZVzWOJCE19HGCqv1u2a6YQjNDz9jHe66aoO0fIfJlGf
         m7c9F819X/ZUZOWiWmYyhJAcqIT6yTZijVA8oCF9i7HIksOlYdj4d9/61flhfQi6/lj5
         8qSxDh4JLCa0uWmAfLDZl8IkrNCbgRCBwFE72xfXJNifow4vgG7FJVn18AC10vFddbU4
         XOLOGEBDb0X53oIenH22Xr6N4mV1glsjHSofXenLgN04MZvM5Bpq2hPJ3wD5MGUJvuRW
         lNsnMmJ/b8ha04c3bNeOzqxzUqoaCsGzyubiN2xxgQYks+ZZ78mrEH2OUGsgEcARG920
         3LMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vZf7I07pXM3N3Dm75rC1oJiVOSHWtjj5Z5TTWTRoadA=;
        b=IkZdRE4BBXnO23CPeQtBBcWuYnXt0x5uLxYLM4n2asZsqef3MlPYcwt3fNw/DMi0IV
         2RQPqQviySmV0InzkJE+Wt+n71knXN8xcacieXUabpnlMNMMcSCcvt0srXZp4k5rBq6U
         xOmwWMGqszP5FauVJJLf+7t/eAPXQMwcBWtkL8o5sp2VGYjhqJFt94ARL1k5D5rT/0Pw
         8hFiZBAFvTS9nrYZxrXzsUvgBqBel2eoPNnaTbrSsAhHyxPbPfD5KXFxZzf42y7OmvLP
         AoBVxJrcI398gXy3cidUqfHAWEbyMUqAGQKqJs5/NrhqPgXk54+uO+mU8KAzt3yhJp93
         AmSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B++G553D;
       spf=pass (google.com: domain of 3wmk2xwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wMk2XwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZf7I07pXM3N3Dm75rC1oJiVOSHWtjj5Z5TTWTRoadA=;
        b=rmWFwsEm/kzb3w8J8qCOjS4Qsazp+IcdoRgvvBQo66Ghj7j2QWJfy4CfORKcW5rA22
         rYTTEhdR3mFbtW5knB/FxX1oNN0foPmfYqxSQbWl0uEvF16jHrk2Zk6OGKmvvEdLU7ng
         LZhFPnpRMY4Ohb5djVCS9g1Ko/B/L/iecx411jFy9zRmUM/ogTw9oQJOUQ8UNkogSgKt
         QOH5Tv8OS32TjTDKK7b3gWN/Uxx042b3dlBdHQtZ68DjQwhHnBx/jsCyczzOE9aIFdlJ
         MtYDd9UbZfBY6FEK5B8fqjVvUQ27R0yTESLk8D0Shj4bX6q5LQjyGkkX+qfjYEqSPoMx
         UGnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZf7I07pXM3N3Dm75rC1oJiVOSHWtjj5Z5TTWTRoadA=;
        b=Wd5nYdooSDJgz0CvIJS048lqh00tscBAy5MljczlvVGG5hmHABIvPE0Gc2GP5ZzAfm
         Ll4P6wzCb0oQZ9MV+qEkHrM15Hx4P3F1yEF18GAyeNsTAE2TdTamHg2D+Yn0EUoaFP+v
         9snmrjRmyfumMpTC4BLP2U+aZ5+Iw1otdelbW1gOxPcCHhMDZukZwNVFDr1Jo8TIx2VF
         BxWPARbAmS97v7tAii77CCfpLJx3b3PIDfpg6bWF7R7PSgWtTAW/vuZlP5ufeh/GjCR5
         rXGtXJuhSeCiheISZjyNFFnqH3wL3qIMgfl1oZvtFPLeEnowCpwChaK/WuY5Md18pNlq
         q9AA==
X-Gm-Message-State: AOAM533AiKhqCD/HjOPF/DBzm1PNnCJi8CfdqSIqfbTbw311pCBQhZRp
	YiLsHW+jc2zMUZBLe80BxHU=
X-Google-Smtp-Source: ABdhPJxx+HPE5J9IxQki8BEKDPhJ2/XX7wnCjzPTBsMwEq6EQSJfIMdkK6cNFIFLZzxT7ugU8BVtRg==
X-Received: by 2002:ab0:142e:: with SMTP id b43mr2238187uae.7.1597426112893;
        Fri, 14 Aug 2020 10:28:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5d84:: with SMTP id r126ls496459vkb.11.gmail; Fri, 14
 Aug 2020 10:28:32 -0700 (PDT)
X-Received: by 2002:a1f:9651:: with SMTP id y78mr2358440vkd.5.1597426112597;
        Fri, 14 Aug 2020 10:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426112; cv=none;
        d=google.com; s=arc-20160816;
        b=fclCk/DpqstZjOwTDwwhNvs1+SiPFvnv0bzinjq7+4L20Hhj3UQWTF9DpTmD22lUj/
         A+YCr/HphzgaGh2VJYAJZV3LtDY/JIfWjpkLGN1wIcNuElBjHW6cdl33mCC2c2HVw229
         1pSTGcDKWP0CD2BTkAIYnf5waIgAnmEZ58LBMlLSe2J30bW0Vhpk8tSV4dGQeIMEIjMv
         W8qGnNFzEdzz42mhhozd5QURGL0Q41e0/ch7jo0xfijxhENaSpGBCmv/eSHhBTNb8Ykz
         ezt13z9aklVUUHndoFElm/Mz8+BUm6vmywWHJ//vdqwbwoaOeYEMIraqjdDM7lM2J20u
         6XYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=lhqV5mQvN7E+6IRby7TSffIB2FjRKGUNLHJKKPPYQHw=;
        b=ndquVarM7raNldN87fllLe8C/lUPvP1QrD1mSXZ2i3dDX5DjB8VWx5259g0eb9xQ6N
         Nlq/k/6rwcGVFjSECYMGPwBhAxrsWbUDhNFFXGqp4vcSKvr+5rx+A517eaooSQRAyOPA
         SwAAiOFrSZvWjSO1T8kEtjOPvK2EPmtH0s6VQFeqi9ornANUX5YmESNKXDyJylI7wNSc
         xMluB1yHuNJizIiuFsAIniNJRfkM0zLHWJDNlJftUrsd+gW+VfqmJixgNPXKv1r0yXc7
         3qkslxVCnNAHyAbB60Vx0uecm8XEkfxefWDqAOdfLVOGtBxuJf6wSMSbm/AJpyKLXnsF
         zxsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B++G553D;
       spf=pass (google.com: domain of 3wmk2xwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wMk2XwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id s126si558812vkd.1.2020.08.14.10.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wmk2xwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q12so6493715qvm.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:32 -0700 (PDT)
X-Received: by 2002:a0c:e00c:: with SMTP id j12mr3697232qvk.127.1597426112116;
 Fri, 14 Aug 2020 10:28:32 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:11 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <042119d239d929be8d4b479825091fb088c7543a.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 29/35] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=B++G553D;       spf=pass
 (google.com: domain of 3wmk2xwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3wMk2XwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index 726e264410ff..2ac973983a8e 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/042119d239d929be8d4b479825091fb088c7543a.1597425745.git.andreyknvl%40google.com.
