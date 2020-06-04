Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMMX4T3AKGQEAA72OSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 09F7B1EE711
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:56:51 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id m2sf4800972plt.17
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:56:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591282609; cv=pass;
        d=google.com; s=arc-20160816;
        b=MS3YbpYz5yCNLHZpTORKPFuv++LWXvTxZzxCFg0h+/olIVQjz+PgQ2MYSizl4inS1N
         O4cOiBaYoE2yqK6NRCQbI5XacqupqEuYzwLHO9icYB5zNohD4dnF3mId4rfSKO6jrnSH
         fDxTymqysTZX994Eco6vEuRijxTx/hDoc1zBRqkSbiso1KHd76yhdRJeCK/CQN9uPIJP
         Kt/qaTS9eSlLC+N2ucJGjPPe60i23Cc0GnEp+ZBhY6zON/wsMSnVjHTyHEF7nK9xlDmn
         8McwSdM0K/o1vcd/hicgSWvRKpKBhyxR+vZ8rNDLeOWfz6GvURJop5AlgyE525a0JNdx
         7kXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=aMzF9dJlJLA77iDZ5FRHpyw8/Qe4+thKe4LXxMawKz0=;
        b=vaW/4KZro8EaGUQCmE9PV44o6SBJs6WnU8yyKtWAvjxXVDw0Uq8E0Rcs8qJghGTAxF
         dSiQXoHd+jV8Kfordf9CVmteiO22IVPylBaTHNyISOY0yAknF5HN/kxk3jjt2bwHWVaM
         59i6eGnMKWOTP7xv0EeBmSdb8lyq+j4PHqu52bUG3Abj0udApHeRBAWpYWVQ+o1ojvDX
         f6GtZ0car6Ug1uZmFblXMSQWnEbsuMLsmNEEe3u9vSSKAhMk1MRaHo/qOHtKMqiVbPOI
         TePAxo8sYmO6nqM7jnSX6sVZPzgqQooHR7Dmwjco6wW0Ld2BAJ5gcma17jAzby2PEbR2
         4lxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tFAsnU+f;
       spf=pass (google.com: domain of 3savzxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sAvZXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aMzF9dJlJLA77iDZ5FRHpyw8/Qe4+thKe4LXxMawKz0=;
        b=Y7Yw8iVN4uS8SKoxIZCIVvbRGRHEGCZBtHRQWGwdG7JyI88nW/Ef7SxJpOV1F4f3eS
         dwBE+Nmc4zYKBOSZ9Aqa0imiKA7JW6gRovaCL8/wVW9VsIPXRDz0T9M/iY7ib+TlY9ur
         5ZV9uysC3MvrnXW2mf3evo7EdV3nYEITD3+x5Wk12quq2h7bDYeCbGeFtDTrT1FrwQiN
         pNPe+3COCC3yuy0+RyiHcT7aOYsobedWunUaIJYKZTqz3FNluAbL3XfRWXyxEbIUa3Ia
         TJezGxmjgCJaFtcHmsimB2IdvXRxZ1G9gzJZiPQm8BotCoi8LxPkYT6DlbrXRIXW4Hyg
         FLXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aMzF9dJlJLA77iDZ5FRHpyw8/Qe4+thKe4LXxMawKz0=;
        b=kC73PJx1XpjDZOkqZiHSfIrUcvWEYhXAr9h1eY80qQ1IrRVviTc1+vwypvIwMI3CAa
         I98HeJz0REcocbx6C653sk1gCWB23Vc6OVHUaFNLl8bBHNss86yo1r5aq2uBw78t6xu7
         xyRsSohWsP2Pwit4Ump++hD22R5ShT+Qgox6md5bF/4Gw5Y6BSamU6UX3RWbWb3ytCE5
         Q9Hee7MDkJP8cwS3iHtIx17anOqdkA0b9v8Q2qfLbvIcpMJjNjrPpw8DzEfMWDlwqvnZ
         scQErC2uDoDXV00zmkOZgYJ+DagTW9DvGE8lnxyP5vUiC4dPVbO+eK8bOhR+AlHXCmqb
         j4pQ==
X-Gm-Message-State: AOAM532KxPYai/jwxLjbLFspRHszjDq7enu2ycYSWJy6wmRgTzXrjI3t
	CooxtRKzSjmTqWTLWEp/Lzc=
X-Google-Smtp-Source: ABdhPJxRS7t1xvEW/J7ci8Em/lltg2y0YRNsq1Qn/2qk2t0TSEXZsPQUrDT6IOJQm7UHLnAg3QtIQw==
X-Received: by 2002:a62:2bc6:: with SMTP id r189mr3639392pfr.11.1591282609699;
        Thu, 04 Jun 2020 07:56:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b702:: with SMTP id d2ls2268881pls.6.gmail; Thu, 04
 Jun 2020 07:56:49 -0700 (PDT)
X-Received: by 2002:a17:902:7847:: with SMTP id e7mr5219390pln.157.1591282609161;
        Thu, 04 Jun 2020 07:56:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591282609; cv=none;
        d=google.com; s=arc-20160816;
        b=CCNBNOnzuXOHVfMX9jTYZBs+7oE/50qds5bQtD5ZWkjtbmf6SgvXqo3RMKKIuWUVza
         x1G3+aEIEyrq3qBtmk9VNhVSH1zbhyZC/s1UVlCLA3oOlZ0gtmyAutSvwxvM289t6meI
         mZZ8YPQlV84Kt6CFI6/aat0KWwkknwVJztRm+3/Z0tP7EuTrJCIZXcGjcr9ZVH47KvYH
         KyGXMb+NWodCyVbUe0spk/BG5pMo75x5WkPu9DyD2F99JxtNJLMZjobLpusVzBnAsIwB
         ITvDZYjKOitiEYdrj5erMOi/RZ0+J15OXcLnUy6XMaQpEY6upX7Tf63wCvrxfDF2knaE
         Q9Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8zjrUygx4E8TnS8rYes620O5p8GaLeCkMw8lBo+Hhy8=;
        b=ls13BeyZpcWR/8FNQfiEkTBV4CCUslCOQJ57qE32uIh95oxjhvndZxZJKB5SkeGFXt
         PnIo/GObZZlQIRDFViQ1udwU/+1XHesUieeKy8sUF47O8olmXcKPCY2xcbQ8Iha+EZSG
         Qsk15BeBBS5BPM00IL1XSUbzW9/e/jthmi/+Y5B82Yudrq4g4gJqeHP/2dkccFigTpD2
         2iDjYYn0zX2yUzTZHwYTEVdqdwtisjYGlTEMzfuFootS/1IfBUx2+eAOUo2MwZ5HacZw
         9cxLJJHTQS+/6xFY0o1+PShnVabupARkPNeiyEXQ6Y4iu0WyP1qLxylkDmU8+phZ66e9
         2QmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tFAsnU+f;
       spf=pass (google.com: domain of 3savzxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sAvZXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id x70si305286pfc.6.2020.06.04.07.56.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:56:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3savzxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id y7so8244166ybj.15
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 07:56:49 -0700 (PDT)
X-Received: by 2002:a25:6f44:: with SMTP id k65mr9347038ybc.101.1591282608295;
 Thu, 04 Jun 2020 07:56:48 -0700 (PDT)
Date: Thu,  4 Jun 2020 16:56:35 +0200
In-Reply-To: <20200604145635.21565-1-elver@google.com>
Message-Id: <20200604145635.21565-2-elver@google.com>
Mime-Version: 1.0
References: <20200604145635.21565-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH v2 2/2] kcov: Pass -fno-stack-protector with Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	clang-built-linux@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tFAsnU+f;       spf=pass
 (google.com: domain of 3savzxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sAvZXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

For Clang, correctly pass -fno-stack-protector via a separate cc-option,
as -fno-conserve-stack does not exist with Clang.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index ce8716a04d0e..82153c47d2a6 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
-CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) $(call cc-option, -fno-stack-protector)
 
 # cond_syscall is currently not LTO compatible
 CFLAGS_sys_ni.o = $(DISABLE_LTO)
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604145635.21565-2-elver%40google.com.
