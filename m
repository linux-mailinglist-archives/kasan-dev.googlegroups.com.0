Return-Path: <kasan-dev+bncBAABBGWUXTBQMGQEZT4BC6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23E0AAFF70C
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:49:00 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-315b60c19d4sf480381a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:49:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115738; cv=pass;
        d=google.com; s=arc-20240605;
        b=MPHNLXKV9PIEcaXJ8j8yNnuHo8k3S7pTR38N/otbmLW9Tui4oOMtWYZ2Lv1/h2jZNp
         8zKrhIu9OibV6lVxejLZwgMl3lEyeRfhNsIlve+a7EZ+De9pI+4S5tt4V3FBA8EnqaIn
         mfCezWDWi4HNm2kpJ5hXTKN7qksX5bcUHUlsWlNont/mCvFce0B+yyD3ADrC3XbTPSLL
         nUw48B9uoX/hETaHRvclGUyQxWxX456Ei/2cu8oawvnzBWCSng1mpFhvp3y0rk1G1UZ4
         1F1/R55SU3YWlcA5iqhrn30b7LDtL0beYg0QXSkjMcXea05q8DMjWvrDISEyQvjPJPeE
         xGwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=O+4YzH7YCXgfJV6JBBxiPaXpXJNeYWxUS4OlnWcTgos=;
        fh=J1Pozo9cMiape9gZoGdwyb7zcwkakSRjZzOb9ToCL0Y=;
        b=QPtj1j4KgvvrLduapTEIn5pYUcZx0QiGCDhzc8b/xrlQmxQqtZZkJuObluIG6Zf5fX
         c2uyBXNlcnv+izqJ2UBYzxjANR83b9x8tbxl+J3Jf/6oKt3/uPmW8fv12Sncy/so/O2U
         vCYJGcwMd+t9d9Y9g7pPKxcqgtM3WqrkykvJxapoK8TNn4zkwPAWCIjjZ7XebkJmg9uF
         UUmPla5yh1ZoJ5UpcnknQ9UhV6nOjx7mgwKnQ97vJ3X2iYlVZ8s6q55B4dCUey0utRJM
         ddtjVRCTwO8aO3irBbYlZ9trPbSwUx6qetl1KIthg1DCUvY6ojywIRxqPam/asXKSgRG
         b54Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TJ555ojK;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115738; x=1752720538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=O+4YzH7YCXgfJV6JBBxiPaXpXJNeYWxUS4OlnWcTgos=;
        b=nasGT5KjfEvffjKpPB1e9+bYUlRWBC06MtpamYLbBcMl/2aCflROfnVkXXsyDiG4wf
         LXR9gLl8opWGtZoLIg3YTm2dL+2yLKtpNrPEC6K8Q1PkifquKV1H27Cc9eMbr5IydJyH
         05/F4f8l3qjJHka/7rnFLMI6ucHr36vPm3GKhTvNnDZN6Fvmyrs5BTofx4/YPjbPAO/g
         IkwjlBQn6k3Yt9/+Q9piOdfy4QqNT0XJS4fElELSlVyB706UKKK8vntB5bHCV5o/kz0b
         dIJscsZ3akTqROQ9rCYtP8361wx2NPvs1aFFpw1yGfTgM3vsxy+p9f31u56relTvGBQb
         q6vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115738; x=1752720538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O+4YzH7YCXgfJV6JBBxiPaXpXJNeYWxUS4OlnWcTgos=;
        b=xGG5HLw3nCEAh8CgaHQtGTy1tjHLUYDWf1z3YaNcCiKaJJAYJIxyocdRm/zp8qk5Re
         AOr9ZAV2LHMNc4ifEToVjPx9IgCN1w0ptgybavkRPURIF52Qg6RuckZFogY0J0zkElJH
         B9SNkP/MiTl/hDWAPHcsS+KzzDqh7mFY1WywKiWJmNJcLjMmeQoS1Q/LHL1YMng7rjBC
         vFTdUqPQ5paZme+ba/MMSV4o7mt8KekTvwKSPh1ozRVQi09NvQPTc5paipoiCs9aXbjB
         xAkEytvx2Fa2nfFIhwA26lI2l8J5O05FGLvvD/sTjydnx6VgquaqEALZvnELEI2VoJGL
         5Fnw==
X-Forwarded-Encrypted: i=2; AJvYcCV7lv40+BUQloNyLWbyIjeoQ1C84vGPJKSNqVBPRTtDMHQXbZJ75Pl45RkUQmqCUIreLfFX7A==@lfdr.de
X-Gm-Message-State: AOJu0YwrF8irkjpA/uIO/XpRCjdEBx3Msx8Ny+e6pjO9pz0nA7nd/mcx
	U/x3Ve9u4/qQs3gFQNmCX6PSgA/QhGSqHuBU7//PHX09MNJRFudIRjSV
X-Google-Smtp-Source: AGHT+IG+RhYc3PTA3qGKaIkLyYV7yMHuV9grPuMEQuHWzYnsiFHy4dV+gsQKxcy5LGXN2o1RWsNSJg==
X-Received: by 2002:a17:90b:2542:b0:313:fa28:b223 with SMTP id 98e67ed59e1d1-31c3c255a7dmr3237285a91.3.1752115738486;
        Wed, 09 Jul 2025 19:48:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeMyJl97ysnIMfIrP7vEyA45TLHS1hvoHLDpaXhvvVO6Q==
Received: by 2002:a17:90b:5683:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-31c3c7a16a5ls560403a91.1.-pod-prod-05-us; Wed, 09 Jul 2025
 19:48:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSaZfvjBWkHYn9LjTGAdMgO+xX/c4leBPXH9Q3WTmtFiPwWy81jMKC1IVGJ8nRPJfUzOfpfq349Qo=@googlegroups.com
X-Received: by 2002:a17:90b:3d89:b0:315:c77b:37d6 with SMTP id 98e67ed59e1d1-31c3c2e27e6mr2885279a91.23.1752115737338;
        Wed, 09 Jul 2025 19:48:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115737; cv=none;
        d=google.com; s=arc-20240605;
        b=E/3H43hiKPNb7j4EzEzjRECYn8F8WWEfVomgU9rIY+58BjhH3VTAUx1q+Z7HnWM5I9
         wh/qi6LOPUwgYUEm2hQ2FMbuGVV84kd30x49V8Ww/WLBoKwM8/PYGm4rrIP8FbI+00MT
         ie3CuX+0J6EpomZvs8YXMZZ+mJCubDQoLOfhTBFvbkq59S+zx/pqcJ+ykgjZGAuH56kV
         7hOr8ofHRjk4Ute9HVxZBDhgk44FHUio1115PfnsEYntR//9EXmHqyyF0VsTjSI7dcoY
         +vnW0bA9RazHcU0aH+eBNDsDM3iBaigKp1fuYe8R8LTnonZ4rJzl8ftFLX+2JdJvo1qS
         7vCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=A60N8FD+fPkaE6xz5lXx6d3HJmhqmVa4D/2eE+ZRcKM=;
        fh=8i7xJvsiGf4yUULLJ/7XBejLPdEaq/gMsT/gLvaxDeI=;
        b=Va3yZgu2Dm73bca/uFJZrgWQdc0V+dNTlYcvrk99sMI0lgPvV7EZdfIEQ26zDFhmPR
         +ZXs8nNM8X8cnqufdTHJdTC4aJfuKJ2jZjazK9DrPNXmatgUCnBHbpMh3cBqaeKBQhFr
         5znYTnKYEmvHLtQg+rCFkH0R8u7MV4RI9q9o94NtmYwQHwVD+AT8n8N5f1a6/syONI/7
         Kb1PyoeXViTSX9Id1VD1HDDG99iyX25OlYdxtsu8NrHemSZhbJazmv5oTVtAw0aclbRA
         9Y0gLLNTf9cPn/StSjHKI2FrGAZfjn7gZJLrjWgidxueU2K18/oMBa6/HJUt90G+gy7+
         S/Eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TJ555ojK;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c3e813286si27371a91.0.2025.07.09.19.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8CC9FA50119;
	Thu, 10 Jul 2025 02:48:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53A6AC4CEEF;
	Thu, 10 Jul 2025 02:48:51 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:49 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Jann Horn <jannh@google.com>
Subject: [RFC v4 5/7] mm: Fix benign off-by-one bugs
Message-ID: <44a5cfc82acfdef6d339e71f1b214c443f808598.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TJ555ojK;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
doesn't write more than $2 bytes including the null byte, so trying to
pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
the situation isn't different: seprintf() will stop writing *before*
'end' --that is, at most the terminating null byte will be written at
'end-1'--.

Acked-by: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 4 ++--
 mm/kmsan/kmsan_test.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index bae382eca4ab..c635aa9d478b 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expect[0];
-	end = &expect[0][sizeof(expect[0]) - 1];
+	end = ENDOF(expect[0]);
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
@@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access information */
 	cur = expect[1];
-	end = &expect[1][sizeof(expect[1]) - 1];
+	end = ENDOF(expect[1]);
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index e48ca1972ff3..9bda55992e3d 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expected_header;
-	end = &expected_header[sizeof(expected_header) - 1];
+	end = ENDOF(expected_header);
 
 	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/44a5cfc82acfdef6d339e71f1b214c443f808598.1752113247.git.alx%40kernel.org.
