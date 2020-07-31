Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVHR74QKGQES422PDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0691A2340F7
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:39 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id w7sf8893380wrt.9
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183458; cv=pass;
        d=google.com; s=arc-20160816;
        b=me9QmmJSFnLBWkuPs2qwCNTTajua5OHLjqnm7a19X2c990HoKm8fsORdAvqYFAhVCj
         u+OBELx7Mza8zPWD3wo1B4dV4DlkSIge4PoxU4eprASfIdgO1LepPKKh2T+ZJDiJ/LLt
         anRCSdvMV+sgZaGWJeYFGWR8DxWWNZDSXs2/yR1QxKIr0dEIP+wTCm+wmqCuNt3YsHKh
         4oDuEA9IMuZk0/E5HAKP6WFNrjIqreaVy4FkuceIyVkcaAjb+M4w539qFriEa0q8nZuA
         4TPfAYCkKNN8tD0vfgrzf4W70DVYHW8dWqNKliv3ncVrSjp5/Gpg6Jr1UJmRipuiOIn7
         avlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DdbvajXyOSeJgqFOuqAWHmdQvMlKUY0aGXVP0RI65fA=;
        b=GcREOqaPSBwVz2HGGu4sLJqppr0ekTlzYHmCQ8HS7mtr6lOBokzUSKOfDm0+J4A5mk
         tQ1UJYhDC+WWILeft5U+F0Zf7NOzP6R1PCOh8fVF2hW59YkMuIl+sGUvQuUjq0/lP2xN
         fhnrXuUFmKY+tKMuWXZUYedXDpnv9JCbFDgzFN+xUowY2amCoLjnXiR7AetWnmMKa0mg
         4do3KerrmU1JBqJ5kzBl4jZWU3WYeeLFGVFQFiIddSRnOE0fxZIdKLzqJkSH2cBg/2Xg
         UVQcm9BkIcE2L8yTdd8A+GW75mRRE+Yi7CPp2jXmdydk8yYE1hL1kJaryJEIKrT438EF
         g6Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tzPCA8cb;
       spf=pass (google.com: domain of 3odmjxwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3odMjXwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DdbvajXyOSeJgqFOuqAWHmdQvMlKUY0aGXVP0RI65fA=;
        b=ZHT1U2bucF72rYun+SRHjvRTBMCSgsz9bXkWJK4bfVsMVh4ON+bVHJyrNE9t7YG5Qt
         4WOzVbjqboNtj0sg9JNrHURvV2l+YQObDxjRa4O3d0xixKUj4kQyeV5zN523ld08C06b
         tKjwpSS2oc0hrCXkqTTo3pJDRDIaMTYRCYZqlO3TA/4a/dArDe8JnRFoamLX16iKATGv
         0bxpj8oKHgJ1IXLB7j0bGabEn2M8KY5lSfH29KG52eeGUKM0Uj43f4IKL0pmNiUnpxJF
         80l5ek3zdWmnr1lxEhNlC4s24MZdeDt8to3xXTzdNEjusnMQol1HNZZiaBGBcGl6l7MG
         ASYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DdbvajXyOSeJgqFOuqAWHmdQvMlKUY0aGXVP0RI65fA=;
        b=VuEqX21+sA3Cs+aYjtF7IQhFG9AUXav+N/GgyFbpn7P3N6UGAu86w9HTGpUBBBbG6x
         Z8HbX160QYHXWcVg2aYzpwsRW8/vivBu7ARNRnRTtLxDTpm91nSJICo2TYNCeKDEjxXw
         MrKdpMKhx+WBpHUgnOR2Fkvrw/BaOfves580raj0UwGiHCRs2buRUaZfNrqGU+sA8be/
         Dm5aK8SQETgo8MPRg+/Wcz6s04pocq347FtgdQEQUlwvOALoyl59yUfHJMCt75lOPBZm
         tODe2sPLU+UFJrYlcQ4KpO+aaKzW/TVdb+B4xyVGNjT5/rBWACMMHM5vs3pQKOpxZh4F
         NFUw==
X-Gm-Message-State: AOAM531SWgPJ4ij802hWAlvCBOZQmpnEghcv31KF5OhkE3UEGkXdKx1G
	s0LEFWuvWSYO/d8mbw5mADU=
X-Google-Smtp-Source: ABdhPJzcpBnV13DN0wM5+pAWoBo/uBQXht6igvAvVruJoX9NLBWVnCj+njpWFgck7ad8ptOXP4WhDw==
X-Received: by 2002:a7b:c1c3:: with SMTP id a3mr2887609wmj.111.1596183458800;
        Fri, 31 Jul 2020 01:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9c95:: with SMTP id f143ls3854921wme.3.gmail; Fri, 31
 Jul 2020 01:17:38 -0700 (PDT)
X-Received: by 2002:a1c:cc12:: with SMTP id h18mr3012086wmb.56.1596183458170;
        Fri, 31 Jul 2020 01:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183458; cv=none;
        d=google.com; s=arc-20160816;
        b=sgXpzVmzfaVGtCSpElNx29ZxTpw17fazfto+9cnOzV8S/9D2auXJRmZbJWIGZUtwjh
         08nt7NNAazuLvs+gjemmHDNDsmDnChjfjFiiRRMOWOH5hcw+HkGExsnudwOMJs1qGRx2
         RZi/fJp1p4DkB2BfWvzWlcgQ8SAJGT3C4kKrm/yd8jCkA5okNrvBZAYe3uWHkI3I2hxR
         1pNoXIm02Tp5WYGmdTYgIncVwssfs7trQRD+SYAd0/pHwV6Ke6vby8/7duGvzVRlt9m3
         lAMMrfzYbuH1cI1s6DaIvSKDF2oUmQDjBxRpK77PVjy+Un1yGvMP5SmFGVrHJ49K/UEw
         V+Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3xl2dBv96+m8d7hzKFanUDmjJZM8uPb0EPNFmjdms4A=;
        b=NFbUX9wauv55yjfvfe8SOlAiOAfIcbrf73ymBrMhgWdly6BM++6yAaTH8R5TiY2JIF
         xwiH1l4hbtm365pnOXOj3A6wT0UjWQRHX/lLMHlWUHoHDwfN7leTNUpp1Axv/SRnb/iX
         X7gufXqKXfMte95y9Er/a6gqEr1+XT00eIGBVbGbfeWGNvXuR57JudHC/5a2j9Y+KvrD
         R4JwPVhurcQvd/scxSF0uRBN2gqSfF73ZpzkqbZllrOzqtueNGkN2DyAQ+8vIGWQxmjP
         5HGJL7lS5w4ecfHmx7aR9UUGFRJHcAdVrmus9Ect9yqIKTKCbjPaWR3/8F8a/XKzsaCA
         4Cqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tzPCA8cb;
       spf=pass (google.com: domain of 3odmjxwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3odMjXwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w6si661932wmk.2.2020.07.31.01.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3odmjxwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 89so8858085wrr.15
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:38 -0700 (PDT)
X-Received: by 2002:a1c:964d:: with SMTP id y74mr2912866wmd.80.1596183457812;
 Fri, 31 Jul 2020 01:17:37 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:19 +0200
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
Message-Id: <20200731081723.2181297-2-elver@google.com>
Mime-Version: 1.0
References: <20200731081723.2181297-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 1/5] kcsan: Simplify debugfs counter to name mapping
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tzPCA8cb;       spf=pass
 (google.com: domain of 3odmjxwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3odMjXwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

Simplify counter ID to name mapping by using an array with designated
inits. This way, we can turn a run-time BUG() into a compile-time static
assertion failure if a counter name is missing.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 33 +++++++++++++--------------------
 1 file changed, 13 insertions(+), 20 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 023e49c58d55..3a9566addeff 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -19,6 +19,18 @@
  * Statistics counters.
  */
 static atomic_long_t counters[KCSAN_COUNTER_COUNT];
+static const char *const counter_names[] = {
+	[KCSAN_COUNTER_USED_WATCHPOINTS]		= "used_watchpoints",
+	[KCSAN_COUNTER_SETUP_WATCHPOINTS]		= "setup_watchpoints",
+	[KCSAN_COUNTER_DATA_RACES]			= "data_races",
+	[KCSAN_COUNTER_ASSERT_FAILURES]			= "assert_failures",
+	[KCSAN_COUNTER_NO_CAPACITY]			= "no_capacity",
+	[KCSAN_COUNTER_REPORT_RACES]			= "report_races",
+	[KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN]		= "races_unknown_origin",
+	[KCSAN_COUNTER_UNENCODABLE_ACCESSES]		= "unencodable_accesses",
+	[KCSAN_COUNTER_ENCODING_FALSE_POSITIVES]	= "encoding_false_positives",
+};
+static_assert(ARRAY_SIZE(counter_names) == KCSAN_COUNTER_COUNT);
 
 /*
  * Addresses for filtering functions from reporting. This list can be used as a
@@ -39,24 +51,6 @@ static struct {
 };
 static DEFINE_SPINLOCK(report_filterlist_lock);
 
-static const char *counter_to_name(enum kcsan_counter_id id)
-{
-	switch (id) {
-	case KCSAN_COUNTER_USED_WATCHPOINTS:		return "used_watchpoints";
-	case KCSAN_COUNTER_SETUP_WATCHPOINTS:		return "setup_watchpoints";
-	case KCSAN_COUNTER_DATA_RACES:			return "data_races";
-	case KCSAN_COUNTER_ASSERT_FAILURES:		return "assert_failures";
-	case KCSAN_COUNTER_NO_CAPACITY:			return "no_capacity";
-	case KCSAN_COUNTER_REPORT_RACES:		return "report_races";
-	case KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN:	return "races_unknown_origin";
-	case KCSAN_COUNTER_UNENCODABLE_ACCESSES:	return "unencodable_accesses";
-	case KCSAN_COUNTER_ENCODING_FALSE_POSITIVES:	return "encoding_false_positives";
-	case KCSAN_COUNTER_COUNT:
-		BUG();
-	}
-	return NULL;
-}
-
 void kcsan_counter_inc(enum kcsan_counter_id id)
 {
 	atomic_long_inc(&counters[id]);
@@ -271,8 +265,7 @@ static int show_info(struct seq_file *file, void *v)
 	/* show stats */
 	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
 	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i)
-		seq_printf(file, "%s: %ld\n", counter_to_name(i),
-			   atomic_long_read(&counters[i]));
+		seq_printf(file, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));
 
 	/* show filter functions, and filter type */
 	spin_lock_irqsave(&report_filterlist_lock, flags);
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-2-elver%40google.com.
