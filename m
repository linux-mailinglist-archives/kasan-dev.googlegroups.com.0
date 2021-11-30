Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5M5TCGQMGQEOMS47II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B7064632FF
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:58 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id g80-20020a1c2053000000b003331a764709sf13625613wmg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272757; cv=pass;
        d=google.com; s=arc-20160816;
        b=t7MYsyMMMZaeSMB9c+SGaLZ4kr++XwcOTOyKbocQibxcaXYa80va95fc3zXgRn0/Ys
         NFA9GxGUnhB1pQy9Ml1WmCSW8BLhDOTOBkZmfmxRTa0j1/d6/9VgL9Xqdw+o5OXtEsx7
         pRCdjfKBmbS51lv6sLniWljaLTrtAo3VPUGqEyhqCT1FDEXoHe5I0V85hjdmbLOj3pNU
         V1C4VsqQTmzrmI/7f1Kqdc8U+8gplS29xPP5BkB23XIzNshFqc7ostE+BUxqsKEC8zQ8
         yU79hdaaW/7yia34I4+0wavUdIhTZ0nsMc5niKUrd9I1etJ9JIx58m3BCdkEYUl0Zl86
         GTcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0Jgnj38ct4RoYddsr94/00zrJSBO9O1SE4XhXzo9gEA=;
        b=WZ3J5oZ3aviwrdklJpabDYMKhWKsWw2/DWXiq7n7E5aQS+hL5EmUw6AE1yI+/Wrlq6
         LB5XNV3Ti3FY4ULbO0p8oWdqzctLb2xkrNiFWY2o+lQyrHUUiLK1nw64RP4qSjHcQu05
         iCe2tQI7XnvhSxb+65j/JaV7uxP+nnYnhEKcyyBiLksfFboGN2/HeUyb7qV/cTIQ0xqA
         0QQM2gxxcnKoxkrvzaF4lkmkjagwGVtLa7eeWyhbzHIvzMdyFYE4zC96rkJiFeok85kq
         3HfuSZ/T6IipwM9HqDWg3u5sFWyzSHlNpcGIpfc8pFqNA/QjLgae9Jw+nanyGeaBIjVj
         xDtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pHRgTgtB;
       spf=pass (google.com: domain of 39a6myqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39A6mYQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Jgnj38ct4RoYddsr94/00zrJSBO9O1SE4XhXzo9gEA=;
        b=IjXZo65MuIEprMIbKZlWPFzSy+jnskdvqi99MAMAeoNSQuuIN2nBAU8si0JmSyQcFS
         1T+81AvYCRcpkS4X02L7D57NNi/m4nH7jxZ2cG73ZUxnVAb4ngpApnlzcLU9tN5s+Or4
         aP/p5Qxyvl3ceZlYyzcrBdQ7VD8YREQExyIJVlE5W/IBFtj2P3C7uIXhF8zdCJgx+GfO
         rWRODKzncFarveYfZnY+aPIdELqtY/hPHfTGZpbrvkUCKuRovlgFxgnCfm0W+Yuay6/a
         B8rXivJnIFhdkbld9BWH8GC5nzjM+UpTTGw2yKh48AgIsuYbfjRKCYp21CS3b2hthqTd
         vuNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Jgnj38ct4RoYddsr94/00zrJSBO9O1SE4XhXzo9gEA=;
        b=oxPNE5Yr1rXYkLN8b0gtKgjHVTylMjX399uqreIR4nQQOauVxXKMRDwtnJ3/X7m8c9
         wnUBABI7TKltWPDzip59SuxslBI0LfdsZgeii4IT5xDM612D6car4bjCxbK1AnqgqFwO
         uwWW2W5vliHkaoLjMZKSRTcaLbcaOBv/J6R5u8lzKcuS5fq+XuZglCr+vP2togwZGcse
         hlc/kM653NjnFTLrBxG1DOGvT0O9Ml3aYoRIEMliiDc7WsgTTr6NwEBtgiybUK8cHG/r
         GvQsPkYN1Ui36KxZctRBuBOJst7iuTuGMpUek9ohYaEMuBqGnrVtkpRS2YQtc4Jk/JEV
         rIrA==
X-Gm-Message-State: AOAM532q4rsUPmti6StZpcHIX/kdIAHM8JAtunI9s6V/uy4lBZKVjLXe
	C1EVQTeLfXF8rYIaDeWpXEE=
X-Google-Smtp-Source: ABdhPJwISn2N23hmu8ImcIXHaNvunpjvsAU8JwtdeNZDSPylGtFxVkoE64I57QxjWI40xhu3o+fT4A==
X-Received: by 2002:a7b:c24a:: with SMTP id b10mr4381506wmj.166.1638272757809;
        Tue, 30 Nov 2021 03:45:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls13082113wrp.3.gmail; Tue, 30 Nov
 2021 03:45:56 -0800 (PST)
X-Received: by 2002:adf:edc6:: with SMTP id v6mr40339176wro.461.1638272756866;
        Tue, 30 Nov 2021 03:45:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272756; cv=none;
        d=google.com; s=arc-20160816;
        b=EMmvu2ormbvfnHHS6PyxLuveZYKtzhv6wW1jiUrAGqBtC9A1oisGOwnoFON1F9Yito
         AP5bC2uwpx59fD7vIGltmWE4pBTW/PPyM/zJmd5ZyBV1GyNtoRdBglpQEGsOGP/rorYW
         UhhdFHmaRo+dCcpyRarKt5mu4mLdRzpxowWn9J3Ahto9lNzGqmRqRUlAbiCjlDuWo80i
         hMsVFD8UELhZd9cXGKDZcqBWmB2rULAriXxsnDQgKxMboT98OQ3Mebm64wODyZzBOK7U
         4KRTCYjRR5KRFdX72f0IPGppbaBdL8r/nGXgudDu4VFuNbK6NU9F9fHr0MMiM8Sfjp4k
         N08g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JzBhpw0Qm81Z9lbF5IGyZhQAb+5o04LDLkCFlxupKLc=;
        b=XnFi+PaUrknljpj9NY2QSE2ERa96KfCvtG4rcHAL4cNu0u0iNs77pqD1lc1GTS0cwu
         BgjMrz+OhqaNsL7enRoyyk4WXEqaFWjSfZxW1kvq6YmhJCocYh1KFRGmcXi4pRS4iQjT
         S7JX/7lEeiGeyw4DcOuCp2um3Mqu5ZXtNltqzNWCC9i9xXMM1hSwbvrJGIB97PoWeP/k
         rwW6MZMuIV+pi1zB/ZICojdEGGR9U+YBY/k/RI8nhjW4yA0ZF5com8Po0NIuDFRhie4Y
         pR4GDhoijLEbwnXtRQsqXgWG8xJiWtuDyMojNJTvo7REWpc7/8WoYL7z3vMFk3hIvH8J
         U6QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pHRgTgtB;
       spf=pass (google.com: domain of 39a6myqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39A6mYQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o29si395542wms.1.2021.11.30.03.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 39a6myqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n41-20020a05600c502900b003335ab97f41so12709996wmr.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:56 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a7b:cc8f:: with SMTP id p15mr4408290wma.129.1638272756667;
 Tue, 30 Nov 2021 03:45:56 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:30 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-23-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 22/25] objtool, kcsan: Add memory barrier instrumentation
 to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pHRgTgtB;       spf=pass
 (google.com: domain of 39a6myqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39A6mYQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

Adds KCSAN's memory barrier instrumentation to objtool's uaccess
whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 21735829b860..61dfb66b30b6 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -849,6 +849,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store16_noabort",
 	/* KCSAN */
 	"__kcsan_check_access",
+	"__kcsan_mb",
+	"__kcsan_wmb",
+	"__kcsan_rmb",
+	"__kcsan_release",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
 	"kcsan_check_scoped_accesses",
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-23-elver%40google.com.
