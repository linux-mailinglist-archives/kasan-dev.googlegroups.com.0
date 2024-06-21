Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG4Z2WZQMGQEJZ3F2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 84F77912128
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 11:49:16 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-37623e47362sf20718155ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:49:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718963355; cv=pass;
        d=google.com; s=arc-20160816;
        b=cioi3TfP982pZcYpMJfO8FyqBAEFrvOhcmnU+zZ84Y6v/gsMO3DMYWdYWqSzm7bx/P
         1oYCyFAVIPph29F85ym1nWj82eoeVvLyn0jKhu7V5vd0oqVp7QLFstEXB22loZYf+wA6
         pGL80wxK8OU1HEF6iOfaeCqBOLsd2KCv0zlvv6rA3Q6xEZqsOv9jvPCCFnAk6CRilB86
         04P97US5kXmI3fLXWrQ599RXoDJODJjRWwQWJPoKcpLyHoVTQqTVl4AbpxPQUf9e1xaT
         O5fq1mzhtCZll5ax8EuvUhMQ9fOfBXy57XTcwtVkBDouYz5P/3lBZo+aUNrRuVWziQqh
         eO5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LCazomglVV1aAZoM5buspumH2jqNWzmAEpS020MPyyY=;
        fh=NTTje3+qTsRihFfPLaUhMTb6htiDX8Mqw/URXpHCyjI=;
        b=PiMbUckuhEb5PeQ7fCOSIhfotCiIeMk25K1xGmmRTNAAIzJALkcrIrlqLDC+sq3ylC
         pRUS6TDJiSvr/xJqU19M+plPuDjzcbApygJuwXmuEVoUfER9o7mFQ2KCk6bNh7tI/bML
         PwhxybHIPnITuqq35SM/G/WTWKYKuRyUR6Ew3FwBVHKpFkhdgyh5wni6+aAHFa705uwG
         aa/9IPsWF2076ahiRAMXgX3jS3gZO0LYJXUPnx0AE3Y5IKf930o6ZoWsN3XZHPGEr8M8
         tny6S9ttVkPCFCo1Zufbunydv8zMbJ69KPwm6Fs0DWrjTRjQEzxlQlaxAZs/ccfddtIN
         Aqfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XYI1fTsu;
       spf=pass (google.com: domain of 3mkx1zgykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3mkx1ZgYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718963355; x=1719568155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LCazomglVV1aAZoM5buspumH2jqNWzmAEpS020MPyyY=;
        b=ViAKlYSfb8LQ1GhIKO3Ws4kOKTUV9TH++UWlo/NTqaQ9qdHoeegcqu8hGsfU+AfvhY
         MTNNZMRN6oaGsk++G3WP5WYRvU3jVJfV4q1PlmMGWiLyD35l7J4m3RhZ1AZcsgTcMV8Y
         tN4iu7sH464cabzA1+BlyaKKVY+R2bwOWd+8G6CYUmd75X/Dz43+PDh16/L5gAHF1H6u
         b4EjGknO/Zngcn6EE4v2P7fFg4+v9isFiMspgf5lB8e3fwpMkgpalx+Nd0ZQ6iFzYFwg
         SxyUum6Nn25rtGQqXRKikCD4k7bVdgbPIBw+NuItALCmChDujAUxbKe1qpPAa/wEBZZp
         WFjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718963355; x=1719568155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LCazomglVV1aAZoM5buspumH2jqNWzmAEpS020MPyyY=;
        b=oH60hIPJyhk0qXsiunklibNYSkHzEoSSFNWGztTI0JEB3oNN4ZEDY3DsB3MzeD9dss
         P2TZudhVxaiietOG20y0D8dEzo1ISmszlxwfyWmEHiK8F0/RJwvsEwT1dtW5dTT9Fs1O
         6HgXIv1cjuE9U0kmu8pdMsSzXjoMG1y/crbd8ekAIGQd/bL5ypX0WAVGwla2+i43xhwi
         4eXQ6lUJrtqw2kCEbfAsEfCmRUABBkwPr/B7jr8grz8Spv2q9hSl8vBBh2ZzkiGr5e20
         JAiMUl6Dc8TtkmUAE4b98xblG/Csqtb4RN3w2qhf9FIoWkxkO2GTIIeml00TmIryckEN
         nPfw==
X-Forwarded-Encrypted: i=2; AJvYcCXXXToAYvpQH7ztS2lcQuYmitPOqJ7hgnABKhFwp2Np+QUsgeLFTU8X6aA+/VUlSUM/c+w/UufX5PP3JfQYeIH5YrPKMtOjvQ==
X-Gm-Message-State: AOJu0YxIUqPMmFqYx3hUU1791EEwdm3K4OB2SLegptrU6jHweqYcVXYE
	TKotF5XXWm8gOk1nsrl076SEzNff+Y9SNT+uiiXrlO5b1ctmCUWO
X-Google-Smtp-Source: AGHT+IERVGUQ0NsapYuy6gMAh/qydWC1v+n/5sX1wtDz23+o5tChX9g1LEqNHKDFegKodHR77PS6Nw==
X-Received: by 2002:a05:6e02:1a68:b0:374:b1d5:ed67 with SMTP id e9e14a558f8ab-3761d7351e8mr85863525ab.24.1718963355421;
        Fri, 21 Jun 2024 02:49:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b08:b0:375:b4b8:975b with SMTP id
 e9e14a558f8ab-37626afbc6els12966665ab.2.-pod-prod-01-us; Fri, 21 Jun 2024
 02:49:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBxozr1d1QJ4ZsR8rKXBKemelApqGwc9bbihpL9TW1rfHXvKYbAiuCuUCxZoi8gTRO3Z6ZnxaFSHINtv8XHxVTbzXy+5q3yEPtNg==
X-Received: by 2002:a05:6602:2c8a:b0:7eb:b025:648d with SMTP id ca18e2360f4ac-7f13ee469eamr986268639f.10.1718963354578;
        Fri, 21 Jun 2024 02:49:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718963354; cv=none;
        d=google.com; s=arc-20160816;
        b=R4Hbxlu1tjLJ75o9tJprZgYRt/tDbsXhYyRm0JB4+/TaEhEdy85hjv+q4a6w6zvnBh
         Y0DOsGrwDBYIm9Atciv1rr3qlQhceFwb686VqekhnXR5aKxbD15PCc9Clx9IB7KnXQSJ
         lPvZxqc0O+TXYU7yYsQ+7xsDWc1CAgjqshgSU1+gS5tTCdrMudc0HYFPXWDD1BVKKhSP
         3nMlWmYmqlmUiEZh4koh7ZerfcQHu8+fhwbBiLo35vp0VziaAxLWm1VbOnJk7MBVPkSE
         lARZvip+6ImtEzVpvQcX9kMxzTAaSaiuKuxA8wW5P/2+mP9ZIR6ahooVdg7mu1pADTq7
         oX6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hSCs+VWsj0iopZmQTsJ5EAfOOj9nyp4YpTWWR5DFcsQ=;
        fh=lWQszsqus2tT0rZyC3dvT7hVxvV/0JVVF4wnFiAqJnE=;
        b=hMg4K2R6eTo6UibktY+wo7WDSbb4aRUyoDGGKFBpZqeua8zkMpyy4iODkUVAmCt8/9
         6F1UkyumyxlCjUNV94p5Y2s3tmAAa1a2YKpske9bMuygOanfNPgIRHmwbeYMVCx9XYHM
         zq6FdQBf4B4pdgt/PQepucWQuTdmaT7nTFr8rm4aKb2FoQY+i+7R+Oco35JX71UXcsqC
         EG4+URO/feF1PM/I3QOnCS8v+zQSB7EZjpPhTyEexD+ZX3q6O+jwpAf5vEb3eUYsfOZS
         0M7G9baBf8bnaeaLY5XutUBYAAIjiWAWwgc0qwPQghLUvGQRBXJtqtdSYKBI5Sv8OqMt
         Qz6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XYI1fTsu;
       spf=pass (google.com: domain of 3mkx1zgykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3mkx1ZgYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f39202e398si8917639f.2.2024.06.21.02.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 02:49:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mkx1zgykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-df79945652eso3357253276.0
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 02:49:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVX/Jrx1Zg5G0p+6UWoIbo6YigABwOpsWAKByCxAuAJcCAyG1PfnOCZV6WJ4nxOmg9aTuSylMlpC4GbUrJV0W71KWvhoD4rHIWETA==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:485e:fb16:173e:13ce])
 (user=glider job=sendgmr) by 2002:a05:6902:2b85:b0:dfa:849d:3a59 with SMTP id
 3f1490d57ef6-e02be215fdfmr2036829276.13.1718963354053; Fri, 21 Jun 2024
 02:49:14 -0700 (PDT)
Date: Fri, 21 Jun 2024 11:49:01 +0200
In-Reply-To: <20240621094901.1360454-1-glider@google.com>
Mime-Version: 1.0
References: <20240621094901.1360454-1-glider@google.com>
X-Mailer: git-send-email 2.45.2.741.gdbec12cfda-goog
Message-ID: <20240621094901.1360454-3-glider@google.com>
Subject: [PATCH 3/3] x86/traps: fix an objtool warning in handle_bug()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XYI1fTsu;       spf=pass
 (google.com: domain of 3mkx1zgykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3mkx1ZgYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Because handle_bug() is a noinstr function, call to
kmsan_unpoison_entry_regs() should be happening within the
instrumentation_begin()/instrumentation_end() region.

Fortunately, the same noinstr annotation lets us dereference @regs
in handle_bug() without unpoisoning them, so we don't have to move the
`is_valid_bugaddr(regs->ip)` check below instrumentation_begin().

Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Link: https://groups.google.com/g/kasan-dev/c/ZBiGzZL36-I/m/WtNuKqP9EQAJ
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/kernel/traps.c | 15 +++++++++------
 1 file changed, 9 insertions(+), 6 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 4fa0b17e5043a..e8f330d9ba5d4 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -217,12 +217,6 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 {
 	bool handled = false;
 
-	/*
-	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
-	 * is a rare case that uses @regs without passing them to
-	 * irqentry_enter().
-	 */
-	kmsan_unpoison_entry_regs(regs);
 	if (!is_valid_bugaddr(regs->ip))
 		return handled;
 
@@ -230,6 +224,15 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * All lies, just get the WARN/BUG out.
 	 */
 	instrumentation_begin();
+	/*
+	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
+	 * is a rare case that uses @regs without passing them to
+	 * irqentry_enter().
+	 * Unpoisoning of @regs should be done before the first access to it,
+	 * but because this is a noinstr function it is fine to postpone
+	 * unpoisoning until the call of instrumentation_begin().
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	/*
 	 * Since we're emulating a CALL with exceptions, restore the interrupt
 	 * state to what it was at the exception site.
-- 
2.45.2.741.gdbec12cfda-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621094901.1360454-3-glider%40google.com.
