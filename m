Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJFP7CCQMGQEWXFNA6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A1F039DD16
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:09 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 133-20020a19058b0000b02902a413577afbsf6229390lff.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070629; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jn+FCgNnu5pMcBRsgzLIm6Pjhmq6YkHZcA8/Nyzb3CDuE7UAkndtOV5GSZjV7fnsY0
         6WiVrzOzX2hcD4Y9MYkzOu38knXsK672F3soEuE4fmPOvdpZiPi5Zuqge4oWw+OUOA0b
         8mnEunZpOccFDBSiAPe+kjwNBDvcu6W4aPm3FV/gmCA8lTpoJqHkqgzI/ptiQfuRfDLO
         32WUyUT+5Vf2imX8nkw80vtf6WscZmiLFmYyDQ4hjoPbnLFSBS6hYNWy/FzfSQ1vwYpu
         m15th9egJaurc7sAIkYwCWAojoflDGK9/rOGMC42pI2a/2Zrr1052ZC1wF7RdQ8pRQV8
         FMLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3ca1TJpzSQX8A+OBKMJ0DqWzM6pJSwf9u1jfNJ7KrVc=;
        b=DlvWp2nU58eFQXwdC2m/fl5TKXimp47fTU9qj/ImrwVMkxYxUKKL5MBTCkZ4PKGdwA
         xj4oU4a2RsdpPIBwxDxozjWutLILHiYIJC7R9Ncn8NcgDBsAfzFywhn9RTaFuX8YSv3L
         gq8UKKS5K0Yh/kZJ2XUZEgGr9EI30ZpknyPnJ1xnUYBgv6F63X4e07fK0D8Ir5PBkDED
         k3qbV/X7Vdg80p/YjxdUXAKaIBFTdFYDscHvmSKEybAHX6+8FipOM16eMWSxeP2qxs+4
         /BMpnsOMOcetp9ZfV/dI/Zgg2vugq0mN+/ghodenw6hca3e2tCZ1R9wtn72BG9f69Qw0
         lXcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DV5h1Res;
       spf=pass (google.com: domain of 3oxe-yaukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3oxe-YAUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3ca1TJpzSQX8A+OBKMJ0DqWzM6pJSwf9u1jfNJ7KrVc=;
        b=siHoQI13ogrKU/DZ2s8xVqcepwza6OZGkFCRHQfD9y8buBi4/oF3/IEHMryACZm7x5
         IFlLl9pC/SPAOWTiuYW/dsI74oFI+yGx+bwdmbUHV9fWsJd27pl8fW6LLcfqN9ynMHYS
         7zSwIsZcdl0ZB1x9/Wh4sTkw0i+tfJ50fC2O9HSRUkqKPrvutWa+yylI89VUEEam+J3e
         kgU1Kfaow2Zahm9wQFB5Wz/3eguwZ63XQ6fa+Uh61sbQkrA6TkY/AF0Otf70PM/FWYZG
         KdWKUFRSk0gz9iS+c38T6m7EhzyHwRDDT+TKTQd2lRQ1dQ9LLKquAzFESUd5JEmPotlt
         pjbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3ca1TJpzSQX8A+OBKMJ0DqWzM6pJSwf9u1jfNJ7KrVc=;
        b=bqUznmRRVqxt9Go5ukUyKGenT14Bjc52Qs7n2Witvw55Y5/DU42ZXTpMFfE8zYYP8/
         btUglKeQxwHwC/evVjgEBO/oORzqV4jt9t+eCSo/JPB8ef7HlpjOYe8LsO0onagzRpCT
         dzu3wGZBoz9TmM2gz4O0UIEUYSVKOAZ5CYkhyT0TkMk3RGZFUARpPNwDCt+xZfHqTl/0
         EV4nGfmNQYFG3sLAiaFWLpEi1L1Gzej0mzkgXXqQX5rVK/CRySajkT+Ku+tinJc3769W
         eNLG/R44nQJSJEPB/sVRePSOJivGDD+6i6XxDJfOlnULm4Kf1fBQuJWUM9ahgFUdy7VQ
         8jPA==
X-Gm-Message-State: AOAM531K9ZuQhVWHZDROxZK9F1Oa+EzwaVKiMFrXonlXQLZrI/jvbFgk
	E32VIOcXfKFTsJRSNNZEzTc=
X-Google-Smtp-Source: ABdhPJxUIjRohRetb2MJ5W1ndbnqx08++tTo3W99k818go4JuEN7eJC0YyLo4sGXoFfnKHRtLPJZpw==
X-Received: by 2002:ac2:53ad:: with SMTP id j13mr12526904lfh.594.1623070629135;
        Mon, 07 Jun 2021 05:57:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7cf:: with SMTP id x15ls2975553ljp.2.gmail; Mon, 07 Jun
 2021 05:57:08 -0700 (PDT)
X-Received: by 2002:a2e:b4b0:: with SMTP id q16mr14559296ljm.434.1623070627979;
        Mon, 07 Jun 2021 05:57:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070627; cv=none;
        d=google.com; s=arc-20160816;
        b=kO1ippIdR77R+HJIbX1vASu+oec/Gs8BnTxwz4S1RKCQeoMWJQXXDCHKZ5vPsJ+0cP
         GHbbQrB5iQIDhIiX9QcY6+uiH8l+DERJvFBrxe0UstJIoAFHK3E/KzdajipP8kOxts3K
         AcqF0n3Fg4sMaoOqo5N/EM00B6bgBD1cLs2WLJyyK7Gay5yMgUUYYq/grqlnFwE47n2y
         Mtuy+xNYCa++F8W+uA8rg4eRJnnRj/IUoikVGFhK/85Fguj1ANYgM5x02ly8MrJ0oicG
         mOSUt1v6c6RPCsEwQzIJVt7cwNxltqg+jdz4bCuSzVM0kG8fSCHauCVp5UoA6BDkCAed
         AJbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kRfxWaVjYRUY5TBuAJktVRLGror0fniACZlCyQAsiGk=;
        b=MpwzTs8O5nKFr9RFC63Q571xPZvaXodWZkz4ntM+KGG0MM6d/WETZ7ZIVtxm+5PNXC
         ns1lSqUcOjnyoefNV0NthXI3uknaIURflSBLNkLlqgAf7H0oIDxuf9vGMR09h31p/KJ+
         n4/29F0nODrwpvaH3mpjNhlzXF7g6n0FHVlrUsFD/k96u5HnKBc88IaEhVNaES3eg5nf
         qvwMvEnKcxlrfmztEEtEhA45YdwN7LI1Lgn5vb5fD/BBWCG/pRH7r/v1uXNNwAd6RvSX
         l5ZPPSYcoHA/NlJJB6uMJUQlFrFWoJX1xruIkbC906zpdJiDMen5Y6KgD5QXL9iWocfo
         fhOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DV5h1Res;
       spf=pass (google.com: domain of 3oxe-yaukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3oxe-YAUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x23si408502lfd.5.2021.06.07.05.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oxe-yaukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z4-20020adfe5440000b0290114f89c9931so7778447wrm.17
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a7b:cb0b:: with SMTP id u11mr2583643wmj.0.1623070627116;
 Mon, 07 Jun 2021 05:57:07 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:47 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-2-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 1/7] kcsan: Improve some Kconfig comments
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DV5h1Res;       spf=pass
 (google.com: domain of 3oxe-yaukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3oxe-YAUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

Improve comment for CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE. Also shorten
the comment above the "strictness" configuration options.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 16 ++++++++--------
 1 file changed, 8 insertions(+), 8 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 0440f373248e..6152fbd5cbb4 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -40,10 +40,14 @@ menuconfig KCSAN
 
 if KCSAN
 
-# Compiler capabilities that should not fail the test if they are unavailable.
 config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
 	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
 		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-compound-read-before-write=1))
+	help
+	  The compiler instruments plain compound read-write operations
+	  differently (++, --, +=, -=, |=, &=, etc.), which allows KCSAN to
+	  distinguish them from other plain accesses. This is currently
+	  supported by Clang 12 or later.
 
 config KCSAN_VERBOSE
 	bool "Show verbose reports with more information about system state"
@@ -169,13 +173,9 @@ config KCSAN_REPORT_ONCE_IN_MS
 	  reporting to avoid flooding the console with reports.  Setting this
 	  to 0 disables rate limiting.
 
-# The main purpose of the below options is to control reported data races (e.g.
-# in fuzzer configs), and are not expected to be switched frequently by other
-# users. We could turn some of them into boot parameters, but given they should
-# not be switched normally, let's keep them here to simplify configuration.
-#
-# The defaults below are chosen to be very conservative, and may miss certain
-# bugs.
+# The main purpose of the below options is to control reported data races, and
+# are not expected to be switched frequently by non-testers or at runtime.
+# The defaults are chosen to be conservative, and can miss certain bugs.
 
 config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	bool "Report races of unknown origin"
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-2-elver%40google.com.
