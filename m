Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PT4XYQKGQEV7IMPPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D54151BCE
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 15:04:29 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id k6sf13022961edq.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 06:04:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580825069; cv=pass;
        d=google.com; s=arc-20160816;
        b=YLbSkRGrndQ4dp68WSorfBy23EhD7ffcP7sV5ZNYQhy3zEut5jKEZJbvdygD1jR/tz
         Qu+eoIMaBPTceKzyBMKXSkZOvhLeWqlAne1WCzrZvVNa4YXADBCCqiYhwUYcK0OcYW9R
         5bgNxe9lPzMaH0qh6g5HkJMKEHGx5VLY3EUEYZ6EKywLbrBiu3eEK7UxfFjg34exocMl
         6PyNFR8Hmr65moxs0+S31bJUKP1ou1Fs6o6la/t9xWyuN5bQGvq905cM7FONLudY/R58
         S9kchACty3mqKPuzHZu2zW/oDu8FRfT60RpjCzu5LJqbOmsjG/POJqoRp8SCok2GQWVG
         X4nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gerfjAio8ue7HrO60myXDINQoLMY5+88JDFdPw4nXog=;
        b=lr0LCSkwGuLswNrEyoyQpJTOl6opVIdyqUO5mTL39QFm0EmXQSbpmhx/TpUWfVWEaK
         N3HqcQKpJDkOSaK64W/dY4D13hAni50QD1gWU2gIUzKbf9WbZ7GgGP7Tb1pT7QE3iJjp
         cKBrSJLJWWmGD7eaRwvRIDwAqCKQSudHoZAbZTnPksrRX6GGIKYN3CBp7E0nyvfImBaE
         b85N/95jhwXbnIZ1fm1dhHWikVM9IhJsGkqFNUjiJJyrKiMm4JdR33HtAk2f2xLaPl5F
         HgtRm2MEZhEM8GeM6ruzQRHI5YO899uB+eIlL/4SuZNv863OIbVBLGGjPTguhFLRGspW
         jdOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gXxL5y/8";
       spf=pass (google.com: domain of 37hk5xgukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37Hk5XgUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gerfjAio8ue7HrO60myXDINQoLMY5+88JDFdPw4nXog=;
        b=QsBL37qnqOt0B03eOcb3XILsOAgtqVskHjCpqHBWPGh37GV9KdfDOHC2u01OerKFLv
         87zNn4uXfaPdCj0dqdeBZHIcXENMaOpaw9W6iqx4F8OnbANvVZiVdjwRZ5UtIqbRVM0x
         UotiTU2vkazdonHxV+sHA8k6EZ01HfutsRUgZbW/y36v6VrN1P/rHgJc51H/M5E3VJbz
         nnZh/FbllFgnJmfOeIvOmj7Fr2vGKKHHyYkyxGN892lnYwcuILZGMVd49DbCpsMLGYn8
         MlVZaRcDJruREKzrOeojWPJKe3rj4QlmHvQsC8WEd1ikyZTd6CRU/BaPPYUmI1Xv0M8m
         axvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gerfjAio8ue7HrO60myXDINQoLMY5+88JDFdPw4nXog=;
        b=YveIM3QmCMirfhAgxVQRRDzeJaLA8uv9tXhsmfUEDhzuRujYBOzHGk806XZUFxCDSQ
         DQW2+B5lJWgUaNlpg4Fx93xGfuArkL0TolNF9Z/qgYDaVk4PZqovdcJ2rhfRVRre1wb7
         jQwOu7zTRzFYfZG8H/GzE/UDe+rkSnx2uefY9rStaZhPS3t0DRGXBPriRYpvnCwgJwjx
         rpf0cyfz5DCyzMeBHM9Q6qyCGEB5MMbJ9mdz0C5eNUDITv+69KwExxvhts3C+Tbg1zy6
         k5OOoyLnYjDLcEJssX+uz+Ltf61xwuWsjpl0PfVytfN9X5U5YVn9GlUiDR3tFF8nn5W7
         BzZw==
X-Gm-Message-State: APjAAAWoTDNcVqiiwlVW+nUZR5ZbacpogogElAhYkzw10FRA0hEp6+Z0
	zOHhaQ5YXvR+nk7LtGRNCNU=
X-Google-Smtp-Source: APXvYqz5PGxh9dx2kEHt9JNek/+4BrKJwpD4XX6EU+WEWvVTD4/ElyWudDb6g7WhwcXO0DqYLsDxuw==
X-Received: by 2002:a17:906:7d5:: with SMTP id m21mr27083818ejc.356.1580825069713;
        Tue, 04 Feb 2020 06:04:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6a12:: with SMTP id o18ls5745799ejr.2.gmail; Tue, 04
 Feb 2020 06:04:29 -0800 (PST)
X-Received: by 2002:a17:906:2db1:: with SMTP id g17mr26434149eji.240.1580825069056;
        Tue, 04 Feb 2020 06:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580825069; cv=none;
        d=google.com; s=arc-20160816;
        b=Mg8cHmnjdRTt8GNtGwE9jC5Gjb0PNh2NzevuNZqRe79cqmAexQtPzQlDxry0nRV7Jd
         kFD3XnBQuKQixfX28m51VkV43ojkLLqDYP4D6tRtJASS0zW1AoZmNKqf0jLQpBsBWjer
         S14rbFRA3tIxUS/Yi1nl9cHdM/v9QU9z3CXAVc80xE1Wj4Pmu5S7PrghfW3J6PnYby/d
         XpJFGWu8a7qhkg5tJZsN7NaJO24SwTgA3ICNjGOT6i0K/TumkfnI5kaiexHJn/gJesff
         fh6tDijTy3wNZ2ezopdk5cL2rgSxBWeoc4mdLlMChnZSTORFd4I58oFzlsb5M+9HtR3h
         CeDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=M5QDlwOFPFeBvx3bqm6hRs2LqKGsL5jmQQoVlW04gqY=;
        b=pesP1kQhCahC3YG9TWgWo0QWdaYCngO4pQkV/0I+YEpM5fHQlqPD//+dyp46CdtjKi
         ecBXmW145OI/VhAmcxvUolleegWVjpQ/4RECP69Y13im6kDSBobnFC8AKeuXHe3BQYgW
         EsUTVswf2UjWmjVocRXrcFBCvtpjqd6zNKpsiuEehmTEuVmYUxrxRZBHEnKgpl6zLjQh
         VLXX63xRUyAleEB7CRbLSf4mHjp3S53/xTEpysE2tw+74tWzONx9N3nVpaVKZS8XHYhm
         Wza/UTa3b5xxv1F2Fu8zJVj/rRaQeK5fJhZj3s23RM7J7IBT+J2CXxUxIh7plwZcPbwX
         o5CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gXxL5y/8";
       spf=pass (google.com: domain of 37hk5xgukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37Hk5XgUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id n1si1143318edw.4.2020.02.04.06.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 06:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 37hk5xgukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m4so1216166wmi.5
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 06:04:29 -0800 (PST)
X-Received: by 2002:a5d:4052:: with SMTP id w18mr16149162wrp.112.1580825068609;
 Tue, 04 Feb 2020 06:04:28 -0800 (PST)
Date: Tue,  4 Feb 2020 15:03:53 +0100
In-Reply-To: <20200204140353.177797-1-elver@google.com>
Message-Id: <20200204140353.177797-3-elver@google.com>
Mime-Version: 1.0
References: <20200204140353.177797-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 3/3] kcsan: Cleanup of main KCSAN Kconfig option
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="gXxL5y/8";       spf=pass
 (google.com: domain of 37hk5xgukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37Hk5XgUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

This patch cleans up the rules of the 'KCSAN' Kconfig option by:
  1. implicitly selecting 'STACKTRACE' instead of depending on it;
  2. depending on DEBUG_KERNEL, to avoid accidentally turning KCSAN on if
     the kernel is not meant to be a debug kernel;
  3. updating the short and long summaries.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 13 ++++++++-----
 1 file changed, 8 insertions(+), 5 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 35fab63111d75..0af6301061c03 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,12 +4,15 @@ config HAVE_ARCH_KCSAN
 	bool
 
 menuconfig KCSAN
-	bool "KCSAN: watchpoint-based dynamic data race detector"
-	depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE
+	bool "KCSAN: dynamic data race detector"
+	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	select STACKTRACE
 	help
-	  Kernel Concurrency Sanitizer is a dynamic data race detector, which
-	  uses a watchpoint-based sampling approach to detect races. See
-	  <file:Documentation/dev-tools/kcsan.rst> for more details.
+	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic data race
+	  detector, which relies on compile-time instrumentation, and uses a
+	  watchpoint-based sampling approach to detect data races.
+
+	  See <file:Documentation/dev-tools/kcsan.rst> for more details.
 
 if KCSAN
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204140353.177797-3-elver%40google.com.
