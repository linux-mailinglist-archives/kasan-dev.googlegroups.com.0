Return-Path: <kasan-dev+bncBC7OBJGL2MHBB76H3H3AKGQEF2MU2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A62DA1EBE43
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 16:36:48 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 187sf6895986oor.18
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 07:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591108607; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKm//u1l8lh47eE+WaO5iC6KKVl+zol+pGC+HZ/cwY5R6v6iW90ZL8cxSeD//kYHHI
         lLLeW7OmbPoIotpGpKRNfp86cJh745l70rwhh0IYxlLrXSY/dxgg8XCfn9FwJJtJamGH
         4kGFU1bM0Kob/sAiRGaIOzBaeCUjPgnYhF8YimZKJ/j8Oz21PEY3p9nHNhOik0DAMPLV
         ++God6PdUQFU/vP4fjrfXguKjH3jinFzRAVFBXiybW7zvHpH2pjxKEbBDH7yIBdr7UOI
         aCCRmSdiYTM/fs026KehCg2a+c89jmb7gs3Ha5kcCWchFWctUG7wTu0HzlQ1txjnbWFj
         YKDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=uO3LOma9KaNURhD7ed65PMAQQhE+3GeSItTYfkpcdRs=;
        b=a/ZK6I/Icb1GzXAjF2WJSlHduGAyT+EzRA2I3exrQnrRpS3XlDJefKDn53F5vwupCW
         /cvg4sTjEMFDQFEWcGfrqdw/m88rKOoOhK0cmQfsRAo8bDPqCydA0U3G6E0v13k5U5nJ
         ZKv/l5GQDMalBciO6s8sOELDJtjcXQElB4HhlK/3BiVh6DdbS+GGTXe8gBvHWdcIV5x8
         Mmfr11mU/SGr737jzKB0pgjxxpC6qYCmV8zXaVTYodZCUIjxxxySjFYyDMdztPPm78iy
         hHo8ABTI7fSytkTpB+Nso+dKEonhg5BvHX1BdgGTHg4SHJSpeJLPwMtU43UcgE4G9DyN
         E6SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X9DIcWm0;
       spf=pass (google.com: domain of 3_mpwxgukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_mPWXgUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uO3LOma9KaNURhD7ed65PMAQQhE+3GeSItTYfkpcdRs=;
        b=cE+lqq4gWgQHFe7i9rEtFiopuJuYgEMjK3c74Mf7CrrdK7FDUN8oD2vzG88UdGmeiG
         7P6U+3YfClrL31g/WEs/W3GKKxm490K7YYFz+1pUK5b0tWnqymlojHH28X5r5JGsiIaa
         mRwquyjmpeZFj0Z/cxZkTbqLWElD5ZE+gZhFeJvaGhDjIMXonsgOaQA45XxCPUi0NYFh
         9jpUsYhtvHHLebjDjVQWmPDTtY8INNhN/s7+lfHn2dYighr+Cyk6FLtOMnBIUj9e9DMR
         +PbSfZ6/ETIHPGDu8GLjkr5en4N3o3iS01KY/9w2VIctLlzIyWNBazHTWkMic6r+p4q7
         nruQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uO3LOma9KaNURhD7ed65PMAQQhE+3GeSItTYfkpcdRs=;
        b=Q440JBTlLdlCXR9NR/2+TsO8IptC0/9RO9nAc00G6JTfbBWIimYIYC3wjSae/YyoN2
         +ScGZ3rBcPLGisAukam/nwJxt4xnGGX1ntyFoFHne5XvR1jK/rHKt5c1rwl8i/Cxoqfs
         qinP27rr+Cnx8pn7mQPQEKVf4uwcvg0inmbBaQ/zVb7tRd6FjY1hOqHapYYS1FmiIgAS
         lIC2SDdZ/So5D7ZWZp1lJUmiFb/l0QIpD/LPWSh251RMT3KBmqzKNmOXUe2nObWf3mqX
         6tjvQRVEpbgWTUqa7EuP5pB7K4ERDU0qIjWs0OeNnypyCLSlDkF7sCPUWxM+ZbL2d1wj
         ++Mw==
X-Gm-Message-State: AOAM530J/gNmCrQ9QcjfGP4g/x+uf0wvQmaLIHMAzuhOwMw+mg1GGSkG
	TN6AApCbYrmIgA4SnNhSVtI=
X-Google-Smtp-Source: ABdhPJzOU2ATopSUiXBeu3c+85HTJu7Ks8dKymOT9adIGXJsHoQsAuLXImSfmA70s4cH6LlhAvIEVA==
X-Received: by 2002:a9d:62c2:: with SMTP id z2mr719207otk.145.1591108607244;
        Tue, 02 Jun 2020 07:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4810:: with SMTP id v16ls3419160oia.5.gmail; Tue, 02 Jun
 2020 07:36:46 -0700 (PDT)
X-Received: by 2002:aca:915:: with SMTP id 21mr3240502oij.168.1591108606919;
        Tue, 02 Jun 2020 07:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591108606; cv=none;
        d=google.com; s=arc-20160816;
        b=DIPjQeO+9smDKFTZ7qZfK+z1RczsX/Y9Wayv2Su+9OQS0hveTvALii9kJVuQx6oN+l
         UDDIpL2OvzNEhQuOV6Vnw8rweTSgN3zSF5pLo4DhhpCb4LWzG+2ePj/WLpc+U/cDvzue
         Li8dfEIUFcnALmdCVf2nNJYkUNvvgdTV4APRJ549sJVGfxdfa3ZTmQuuRNM+sZpd2b4j
         a3gxRc+218Mg4YoSzLy6+I76wgziEp1Dtd6mYlWWW6wjAFo1/LIcZteLWJWHQRluOJOq
         WvZuvmoAnpG10yjNoXtyKWDxulzCRFXunTpvuLWo/Dw3hIAKdzCRxpA08ZsUdCunEMnY
         WvBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=8vggNqY3GSAouo8x9FrTGZVFgabBzu+O3KL9Xujh+3U=;
        b=FJxsWpxGjyiL3hvCkCG9XKJVOHofdpeU0oHvCpNsZG6aebLmTRAUfYp+qeTxbgSKqU
         ySvtpoKAC0jGwXUhuoGKaODxupAwDzUxDGhcr/qnPbjKfLMCDB7zPH+hxEySx4cEMwbl
         uWYU/G32UJm/Fj2qXwmqb79UhBm250hPsdAklQr6Pgl0cqadPlX3NgLRVEsuUooEN+ik
         xllSVW9eCpHXu6Od35lpJcNJzZ5LNJ9z5//iR/6KDh6nNGiWarpj/WIIM7AFH+8ollhE
         /aS2edbWX6Owlh9EzDXhi+xDKgrBEI2Y0No0TET2eJ9KhwpoR6l5f31UOPDSSN1tjPPG
         2ztw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X9DIcWm0;
       spf=pass (google.com: domain of 3_mpwxgukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_mPWXgUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id f133si100088oib.5.2020.06.02.07.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 07:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_mpwxgukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id u186so8803085ybf.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 07:36:46 -0700 (PDT)
X-Received: by 2002:a25:31c6:: with SMTP id x189mr4868765ybx.402.1591108606409;
 Tue, 02 Jun 2020 07:36:46 -0700 (PDT)
Date: Tue,  2 Jun 2020 16:36:33 +0200
Message-Id: <20200602143633.104439-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH] kcsan: Prefer '__no_kcsan inline' in test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X9DIcWm0;       spf=pass
 (google.com: domain of 3_mpwxgukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_mPWXgUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

Instead of __no_kcsan_or_inline, prefer '__no_kcsan inline' in test --
this is in case we decide to remove __no_kcsan_or_inline.

Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---

Hi Paul,

This is to prepare eventual removal of __no_kcsan_or_inline, and avoid a
series that doesn't apply to anything other than -next (because some
bits are in -tip and the test only in -rcu; although this problem might
be solved in 2 weeks). This patch is to make sure in case the
__kcsan_or_inline series is based on -tip, integration in -next doesn't
cause problems.

This came up in
https://lkml.kernel.org/r/20200529185923.GO706495@hirez.programming.kicks-ass.net

Thanks,
-- Marco

---
 kernel/kcsan/kcsan-test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index a8c11506dd2a..3af420ad6ee7 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -43,7 +43,7 @@ static struct {
 };
 
 /* Setup test checking loop. */
-static __no_kcsan_or_inline void
+static __no_kcsan inline void
 begin_test_checks(void (*func1)(void), void (*func2)(void))
 {
 	kcsan_disable_current();
@@ -60,7 +60,7 @@ begin_test_checks(void (*func1)(void), void (*func2)(void))
 }
 
 /* End test checking loop. */
-static __no_kcsan_or_inline bool
+static __no_kcsan inline bool
 end_test_checks(bool stop)
 {
 	if (!stop && time_before(jiffies, end_time)) {
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602143633.104439-1-elver%40google.com.
