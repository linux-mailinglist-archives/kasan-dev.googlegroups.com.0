Return-Path: <kasan-dev+bncBC6OLHHDVUOBB4WFYKCQMGQEYWQJY3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B632393E4B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 May 2021 09:59:47 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id j19-20020a62b6130000b02902e93e6ca980sf2010677pff.10
        for <lists+kasan-dev@lfdr.de>; Fri, 28 May 2021 00:59:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622188786; cv=pass;
        d=google.com; s=arc-20160816;
        b=acywCblKJU2lEwLOCJkkRAzhi257dgdFzyaf7Dlispo8TPxf6TzSuO0SvTEpIxZHwx
         PqoqaIMr/qGzFOx1tyig2j3ZAT9+k/P5009/DXDUwVV7vAVKmISc3GqlpH77QXAecTpU
         Fx9e0X/JpxYplm6AINjNHAtS/HRdjBxZ630NbYvkldMbanqQBFLj7CjHZ5+QDSio524U
         A2Hdeo9S6Q36czoiwbjEErwfgHAlhLofS2mzZWcDWWfRpZMXLQFG1lX1VqDAbOKj7O2h
         6NTI9ol987h9J9R42NhHqqrCjK92oV/lvFKYMVae4FkN7eRFigHLpHBOKV1Jl4MyKm2g
         +4pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xQXqoALJTwxiVSatD4Vr8ZrRz6R4EIYRvqJPEj5dah8=;
        b=na3JW8X5cdohFyskUNJzg76UbUhu90I2cNew3yL78iQZ6k8EQo82iuOV637PfPG7Ys
         ARVsjikxQhHq5WoUpFpcfb86L3K0tEQUsuQLTtvX/H6QIBu44p+BfUrjSyNRB0wfbcho
         THQ1Kb24RMvWWKLibFz//xiEJahemIAMy+roPkWEXAf/UuOdcuI7epB4MEKzD92jMHMu
         FoO130L7s3Z/bqmUwXQSRywvMjUJ6n998KsMHiRlZQsLc/9abah0fQYDnOSalGEgRDTp
         W53A3Xq/LCjN9B+JCN4NONrpNchJSH40aIEVuHoQhfDNk0Nv9d3SXbRRDl640ps7tUu6
         CvdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A9wEfeV2;
       spf=pass (google.com: domain of 38kkwyagkcquif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38KKwYAgKCQUif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xQXqoALJTwxiVSatD4Vr8ZrRz6R4EIYRvqJPEj5dah8=;
        b=JQJoYRbR4ZSvFcWnM7eP9Qqx2SYpqF2WRIp9D0OeUdSzympLJ8vpd7Uf59hwDagwX/
         T/3nJ9H04G6kjIrKxHEfqYk/1/zAw6dezforegGFUyNYkfmXMkGkpAfrcnverQfFDWEG
         H+psMrRFS6aNp2tgH+8en3JWX010MUwCGOzWMmiZYDliA+o7wR/9jWdYTNPJBpWu53v1
         xuydHqTSEKasV9huEbfUFhCPcJG6X+l8sXr+mkJlkane0W+jWTYNAuTgWQLDb8D2aR8E
         UKRyZHZ2QzrAdcLLTi0ShXMNBSZHmZjJXAUwQWo+aIRyumFzEGWiWK33Mb90rsTQYF+C
         WBPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xQXqoALJTwxiVSatD4Vr8ZrRz6R4EIYRvqJPEj5dah8=;
        b=dvQrGaE92k6z/Az2lAvBUaEbWCdvKVNGBvjz2AZHAAQ2e4o4DRnlVhuhsmV25qU61z
         F/n2nDugu/u4E9KOgMFpDVkXIFGzvNkkUUh4aM292nG5pz24kaAGNV7yfLXY6gUZW9il
         9E7mpSDC5P0W+Ce9hoc8JvTpa43R5RBEzmgy/hHD2Oj5TUwISyo/aL//fQK682dckux1
         zWkRzu6SmjqaezOO9nmsucu//GX1QcNcFE+6CbaxGpq8mXTCgImDR5vBsBPIaOr/dM9t
         G4cuGMRef94AieTI7X1P2wDiNGVVR64yQ75yUgkR4xwMtN4qVpdZy/HqhLVLxqghKQv/
         yKSg==
X-Gm-Message-State: AOAM533UI45PGR2miMsaFS99T2ozxYhqrHa6f84PghAmLx485MFUQSsU
	tVmHDN9UaCl879BlhWWrJAA=
X-Google-Smtp-Source: ABdhPJxBTAJlWTgXh5Ny6KvMK0Q9YvR9zODHmbmc/e+ws9/AvHQ0nIuK+6WelRVBtOa1/OxwA+9L7g==
X-Received: by 2002:a63:ed58:: with SMTP id m24mr7737731pgk.436.1622188786265;
        Fri, 28 May 2021 00:59:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3593:: with SMTP id mm19ls7842956pjb.3.canary-gmail;
 Fri, 28 May 2021 00:59:45 -0700 (PDT)
X-Received: by 2002:a17:902:bd90:b029:f2:c88c:5b2c with SMTP id q16-20020a170902bd90b02900f2c88c5b2cmr6991218pls.8.1622188785598;
        Fri, 28 May 2021 00:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622188785; cv=none;
        d=google.com; s=arc-20160816;
        b=SOq0zEIX/BHazyAHHelDnwgBX4pW5jHx3RYmdeuVR+ZX9yJ/h/9jhi0n9BFaFHDkQX
         c+ti9J+urpJVL0u1w+3yLg7QKsGJCt0SPOPqjxXK0aOwb9xiZfmTz0WhrQh44dEatfeF
         rXqvp8/7veKAJbvsv/fQYO8yttejJceGeiyjSZ6n17VanFyAjOUUDN2zXyexvA1V8qYL
         cXsTrj+dAkTvG1by5PhhrrxGI6c4wjm6afhqIMTpWqQJWsVwZm5akLnlsCxamAIgfWCW
         Q5tQbLhzT90cFvB1PfHL9ZEZLjPCLqsZyW1e/GNPdiBkpxD8cN1Vt4RTS+GyCeX7s5AU
         hg2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Nv+J3ke0GgapMp0UwGNPvITZFCUM1uizFSit9ptyMQc=;
        b=nKnYC5bDyUkYpJacouUk9GG102GB5bAtwF5ORuQpkAMiuPGOk358VvKpi6uud688Lc
         NR0KMmW4vN0dDIlPy18DEQVFuSFgywkURDWReLY7ni36UEzfLlr4LlJF6tK3moCK52ij
         wpyCdck5fRmy4FCmLoDekBpCURsjTgak3DOP3mdK3pekkmxV4NM/vhe5HBho8gXuF3D9
         xw8vRSvLRf3zSVRoKikPGISA/9jFb409/D8rA9/Rbi8mLdxCY1t5lyfY5cM6yvJHNtnm
         0s8TPhF4vqiOZLn50hmBGrXb9ZKlVPb45sxmQ8WHFDnM9qsC6HxdlYfo7sD9hXdGEGSp
         66dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A9wEfeV2;
       spf=pass (google.com: domain of 38kkwyagkcquif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38KKwYAgKCQUif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id a6si364498pgk.0.2021.05.28.00.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 May 2021 00:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38kkwyagkcquif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id v184-20020a257ac10000b02904f84a5c5297so3504507ybc.16
        for <kasan-dev@googlegroups.com>; Fri, 28 May 2021 00:59:45 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:621b:e8e2:f86a:41f])
 (user=davidgow job=sendgmr) by 2002:a25:d341:: with SMTP id
 e62mr10161864ybf.197.1622188784739; Fri, 28 May 2021 00:59:44 -0700 (PDT)
Date: Fri, 28 May 2021 00:59:32 -0700
In-Reply-To: <20210528075932.347154-1-davidgow@google.com>
Message-Id: <20210528075932.347154-4-davidgow@google.com>
Mime-Version: 1.0
References: <20210528075932.347154-1-davidgow@google.com>
X-Mailer: git-send-email 2.32.0.rc0.204.g9fa02ecfa5-goog
Subject: [PATCH v2 4/4] kasan: test: make use of kunit_skip()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>
Cc: Marco Elver <elver@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-kernel@vger.kernel.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A9wEfeV2;       spf=pass
 (google.com: domain of 38kkwyagkcquif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38KKwYAgKCQUif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Marco Elver <elver@google.com>

Make use of the recently added kunit_skip() to skip tests, as it permits
TAP parsers to recognize if a test was deliberately skipped.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 lib/test_kasan.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..0a2029d14c91 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-	if (!IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " required");	\
-		return;							\
-	}								\
+	if (!IS_ENABLED(config))					\
+		kunit_skip((test), "Test requires " #config "=y");	\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {			\
-	if (IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " enabled");	\
-		return;							\
-	}								\
+	if (IS_ENABLED(config))						\
+		kunit_skip((test), "Test requires " #config "=n");	\
 } while (0)
 
 static void kmalloc_oob_right(struct kunit *test)
-- 
2.32.0.rc0.204.g9fa02ecfa5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210528075932.347154-4-davidgow%40google.com.
