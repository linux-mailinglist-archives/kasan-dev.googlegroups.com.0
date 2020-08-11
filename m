Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGO6ZD4QKGQEF5KGE5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id DE765241603
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:38 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id s27sf2791712vsj.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124377; cv=pass;
        d=google.com; s=arc-20160816;
        b=huE1Yo/LBjhc+AzqmUEtm0+4I0Bwa2lbDDOpX2dyIUkTn4k0ekHV12d+E6tnZSKSB6
         IApComH+AXkCCXfunsj+yDZi5wMZZd+41wvjgzSp5a+h2MBiusIupoxjZnQrElhUZpp4
         4VV8Rav+A3lh9j5WeGhZ61YxZhtKyHNgXFUIbHcj8ZuDqcErM1whml+qq8CjxC8rABNe
         c8B/NfjOxg/xjgsn8QtJKfxNDl73wbGeelI1ob7AL52c0iBF6n/RBnbplOfn0nBXiCnl
         lUaV18eKRKXmkK+uEAFSWIbhZLoqI3oQ7JsH6zJNbs0P8OepUdqbHfwYUhlGOcjHM4OI
         pNHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=RSfuDLsrAMb9+V2BZ9CkqMA1D+IQQjEA6+808OjMOzk=;
        b=UKEg/0LplyItyAcVnnROOjJa1aPPKS+xBDRCgdqM1cXQPDcqCFplyVOgvdAYceluPD
         8yZOMa9JvbI9Ia0j9bHfDzws4N4Ti8XU75FXSMzMhVopLAhumCb72LSF1yFHBZjP7fYX
         5MKXpIpy0v0q1htdPOCoOaSrwNjUFtyZW2jAxNSq+W4Xx+YLmhR1iNu8JnM0zTHT3OV1
         xpL17NYXdELWTWK2Sfslsi/cgkPPT6Pi3xCgoqJ5XtX/rPq9yA4JdEXL9Gb9a5UmQ4ap
         BnNW7I4hpUl2ORvKQbkxr8upPKY03ghumC0mORkuVg1nIcDr7SW05fp2h3Z67gm3W4z6
         /Uog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ex3UMkvi;
       spf=pass (google.com: domain of 3gc8yxwgkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3GC8yXwgKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSfuDLsrAMb9+V2BZ9CkqMA1D+IQQjEA6+808OjMOzk=;
        b=i0CIgO7dU+eYJg9eMwf4eIxR4ZdM3kpUJK9VpuFmKVPmn5mQh6TX61jF1huciMYr2M
         lzmyAHKCDg7ZnN020TFCYhJpFO2ouli6fNOvzWi8g/vjhnoQH/v5fV5k/fCz/Hdra+Gj
         US/+WKLLC0YDhAG6AEdkrqGpdXu3aVzCEeZn87uqN9zoaVY1mDu0/kjvdXv7tFImVB/6
         8wbYOFXQ4UMPO45W8yHPIP1P64agLsfSS0iy9dx1ELpAsD4uup9Pg5bLduuujFf+d5gy
         4l7uXXAKCaoSszGtNNwuBvie90fA3LU5voua+mLAHxKzXXAd4hrwjEUcdbZExMtn8qxH
         jdlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSfuDLsrAMb9+V2BZ9CkqMA1D+IQQjEA6+808OjMOzk=;
        b=qdQ1l5CjuQR1RR2oeXfuIv7HFb+jRhFt1RMoSeb3OOXAwrEOdjfjje4dktvi5j5r1E
         mtYTcg3JFh1GizL9S6i6o1kyZNC5g1Y4YIvoYbyZ5MKrWcza5U0Ky1tYzGrTcUtLW/2M
         24MA5aaY0oQTp1BL8vo8z8XlC+KHOummU2uUI3X7L0SrLxCpO2N5/Uc7v1PBx/Gxjijm
         oy5drUFg8GgyAWWPS6rHOXuefF6sg49AiAUaDd1ohqXkZRDWssJAKs0RQvtbe6wGOb6K
         hazOayoWeV2hVDrTGBnQsZipsJGs+cXmYw1p57NsE98FI7URuErlDonu7p6XDlvnQukz
         Gcfw==
X-Gm-Message-State: AOAM532E+Yv1ca3hdycOSowKzAisoYIbZIssQb5BJKQc+TDywcQIZB/S
	wxyQtr9xd21vzPD77FamL8Y=
X-Google-Smtp-Source: ABdhPJzy/3+m8a7nIOp06N8r0pSnJk6sWxXnQtAG06xoWbOAl/+IOQtVtJj75tiEBKe7Hs2MkM8kbQ==
X-Received: by 2002:a67:8c06:: with SMTP id o6mr22689439vsd.200.1597124377623;
        Mon, 10 Aug 2020 22:39:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2254:: with SMTP id i81ls771674vki.6.gmail; Mon, 10 Aug
 2020 22:39:37 -0700 (PDT)
X-Received: by 2002:ac5:cbfc:: with SMTP id i28mr23771930vkn.16.1597124377206;
        Mon, 10 Aug 2020 22:39:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124377; cv=none;
        d=google.com; s=arc-20160816;
        b=YZzoWg94L8KVF/zDJ2Reg7C7h2TqAyJXuon/JBqkSm/5d77GMjlteouRSTifNReAIq
         huDWkqKxQ4kd4Wm4wlwl82agmXZ1Xr6trQc8mKPZp8j7r6zMzmsaLoO74wLRBttlF4AX
         57pXIbMXncA/Aew2X8yqtASKHUt8wY0/7zyYJZaci+B3Zqe2KHGglqAdREWNJRoSjHfq
         CtjP/0jk7Tnw43mpWd5uOqnXfdjcNz9dcfhexIonf3iB1Q5YIDr0gtsH6BswRgUchRw9
         Ms5MPZhdEnrbRMYQWvoHJ86OUICenI5O+alJEtnjNuBhwonD2huHt7QHyoUtA+RwNoCF
         YO2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7T9CW/c7Zee0z3O+ssd8ugkXYgOmzh7dNULbFDDyxII=;
        b=PsKRL8qwJdoH0j4uw8sKl79P6KAqh6yOCmRoGtb01Zgkv/4WO9gzhhdqJTGx1H8fSi
         u3buqtyWtFCcssmeIE/zxTHw9WXlWcjgFJcleodNgAqUnxPp6oZ+dOS7Lh6lV5dBFGYb
         BVWhwyapW8vnm+xo3mcOjc8BGjHq5e4Yo7itJqEP1kBaq0PEwT+okke4dDr7Qr/hrjH2
         pmC/E772L5xm1DlAq85fHf3I8rz5pGtKW2hStshOD3udmIpbvA/ctiORuHO8ELrxn6bb
         g/INz7oGFsecmTtNsqp/lhFTYbflJupr7tdrM8qVZO7G31jpCvrXMnS1VSxZcVV/iVR7
         qckg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ex3UMkvi;
       spf=pass (google.com: domain of 3gc8yxwgkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3GC8yXwgKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p197si1318909vkp.0.2020.08.10.22.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gc8yxwgkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id e24so9644726pfl.13
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:37 -0700 (PDT)
X-Received: by 2002:a17:90b:3684:: with SMTP id mj4mr2854429pjb.195.1597124376232;
 Mon, 10 Aug 2020 22:39:36 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:10 -0700
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
Message-Id: <20200811053914.652710-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 1/6] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ex3UMkvi;       spf=pass
 (google.com: domain of 3gc8yxwgkct8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3GC8yXwgKCT8ebwjehpxhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--davidgow.bounces.google.com;
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index f92d03087b5c..3db26aa88971 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1203,6 +1203,10 @@ struct task_struct {
 #endif
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-2-davidgow%40google.com.
