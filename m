Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT47475AKGQEGVH5WZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 365B8263DE5
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:03:45 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id x10sf4534465ybj.19
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599721424; cv=pass;
        d=google.com; s=arc-20160816;
        b=mR3Fr/zeGXC3xpfrDx9FUmYchAWi2IB6ZIv2aPTtWmTWOMblFlmOBb83USKzV8r8XK
         vQ4JofuBmSfq4PHYNfsvuIFKfYP+pWTdbrh7db2RdkAr0n/JmNgbGypdBgMHRZEn88Q7
         F+8eP+6tPnzl7uS9rvmELZy5UgNe4GVZgdM2p9YUno40qtCzcIXLxlBolzZaTmA7cV9S
         fLNb+BNt11di4Wygt61okWOkc9z3pDQc7Yno/HBBFyC12Q+5MiIyXemX9zJSYWNumc1/
         vu8EE4ozTm9uOdLb1Yb/x2/azuP82FlW6I1ojSYgA2WBHErsIg2spbKS4iljCp7tMd6q
         jaVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oCVmBQ8Eh5oA2vO8PDVY+xGpKePI5iGPvILDrvF0lBc=;
        b=tw2JqJ2GhRckX3PLuGnQcedsLVNXF5wIM+MuUb0xKQwQUhDy7z5G6cccAkiVsbQa/c
         Vl03w6ObkrJ3YGnx8XXifU8bgn9gnReqQ5JmG6Ipl/a5glHyc/dC2QEg93ReEZoxoPU0
         uhB2bHYQf8z14zBaupA9soVFcvyGkfwRanu5ULMABWHKfpC+qV/xnlpHzTWdxlxPuO5e
         LyRGclnC7Ie6Mp/FUJrA1tlJ7h5dR0/tAka1MNw0S8AOjfdWYRFvjzYCKobvYlacTOM8
         88GhJkrgvnD0JxDQYiJ4hLBtKrcg9rb4L4UozQUokk6I3wOWVgdNM9VRZConX721+3dl
         +vhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ecV7GTgP;
       spf=pass (google.com: domain of 3z89zxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3z89ZXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oCVmBQ8Eh5oA2vO8PDVY+xGpKePI5iGPvILDrvF0lBc=;
        b=o7ahRcJ9CIXnfjmoBcd915G5eW1EOe9MFCT7Wsby4YjH99SHL8X+OI2u4eDRCEcd9I
         fwLUNteot0fg1/BfREWoDdnxcf6YV77Y4lIQrPEXPUjqFJalo+ChFiQmZ6F5bm7nFCbn
         gIg90h//qAd45XIPLAj9mWBSdp4F9EKDIU2eR+Zg/H+oIo9vFo7a19GNM2trXH9keMKX
         ol4pw9mAHMrSfuyHo3fm2wpm32wOVlq//PrcipPX9O2E5dVy67U5XGh2SS+dujEN7iJu
         euStfKpxbGEKqa2WRNh4WPFwIe5rDgsCLi86GD+R32u7c68XBoyhGAOfHe4iExZweDK+
         Rqzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oCVmBQ8Eh5oA2vO8PDVY+xGpKePI5iGPvILDrvF0lBc=;
        b=NBFZ2I/wD+nS2Og/Ts4cWiikMDl+obBGoawKiOYgPX33Hy1OmrW8bPe3sy6nJ79sGF
         NUTb3aNkiOMCC0klSst2hrJahJLItTGJ++u9+cS6KRRPxROWWlCbs3Bwyur5dzyd08K8
         RWoeLkHc++Co3QMlpiac6JDMQpJlWgAfzHX8Wu3naGy4IheA1eXinWC1asMXyDS8CJ30
         thOlWC8hVUTFwSPKr4PbAThwTTH+H9f7b8S5A0DN3qjEnXD6veL7y8yrM1cyWQzab5Uz
         caR6kjt0Vc7m0QF8cNxSqoX8KuWLLs96ti3im1QML2TdzgYNgrMHjedpRGWCD2Tzhot3
         YzDw==
X-Gm-Message-State: AOAM532uzE4SaDdhppG6rT96evmVgYewHzN5LHCLNzfnZUnypOvUKYMG
	LuYw2q0wSdk3Cxjw/FEJg20=
X-Google-Smtp-Source: ABdhPJySy3J1nxCX6VrkEBswTIx847KJ28Tj+6p0FeQBODAD5PO+Wewf+GxfrHjTePcyNZ2caSM5ow==
X-Received: by 2002:a25:d4d6:: with SMTP id m205mr10760733ybf.157.1599721424059;
        Thu, 10 Sep 2020 00:03:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c550:: with SMTP id v77ls2346181ybe.8.gmail; Thu, 10 Sep
 2020 00:03:43 -0700 (PDT)
X-Received: by 2002:a25:df15:: with SMTP id w21mr11332419ybg.138.1599721423619;
        Thu, 10 Sep 2020 00:03:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599721423; cv=none;
        d=google.com; s=arc-20160816;
        b=VCxpHsazxfLW5m6yKHvg8QbXx7bhS+fJTfx6xDVqupHXffo1Dnm3SvDINTTRhxWEHi
         41g41Yj2rtsU1oMMk4qvVVvEQLZ2RjHhZ37tm/lzkVXCiu+WkRY2B5gNoxF1fb/yyBNF
         Dfd7U0WJrWHEjVVt70+qvYYqEpKJfmzyvbhPBia/upeZLsA1mkYSg2mNC+rqpHhHFdS2
         VW2TIQu7c00abK4g5JR46/90G1WO1mjpkdfy9rNAW9uAYtH7ulDTi/tBwh4j4nuZ1OL+
         lx+AoYO6kDnNSAsxF6bPeDsOptLD+6Aj32LwnfzgfhU7pIDlKZ42AB95pXE5HtkTymAi
         NTcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=W2nrS/kBK4lWw8uYN1BB5WUGx+sqFHBHeS5Oy6sIX6M=;
        b=sP2SGdd+jTBB/7VOPEs4oryC/xg5z6Ay/dK8SkeNLp57WPB7Uk4Srff1wFvZxehNJi
         Fndmm7w/Kf7sfDZ1cXe+v06p6Pz9g/ajAnvi1sQW1DuO04jRaZMe0bKYNAqOMIqbHpXU
         lV8yjyLBZqW8W0joP2BO0pecM3f9jIsh8A7dbc66OB2nwCKfo/OhtM045Kt8VgsXeB2T
         KBbmNFwK7PjG059jUuf5GTjnCBiyWbzX/PKioACWRMAMhTJFDUCS8WBubhBgSxc6iRtj
         Lzc4ce6MNcWvSu8/o3MYVh/R0xR08O9f/snHkrVJ2hmlL4LB71iTWq56P3ub0dHbMTkU
         oJLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ecV7GTgP;
       spf=pass (google.com: domain of 3z89zxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3z89ZXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r7si475748ybk.5.2020.09.10.00.03.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 00:03:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z89zxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id m13so3481874qtu.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 00:03:43 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:ad4:5a53:: with SMTP id
 ej19mr7590337qvb.54.1599721423196; Thu, 10 Sep 2020 00:03:43 -0700 (PDT)
Date: Thu, 10 Sep 2020 00:03:26 -0700
In-Reply-To: <20200910070331.3358048-1-davidgow@google.com>
Message-Id: <20200910070331.3358048-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200910070331.3358048-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH v13 1/5] Add KUnit Struct to Current Task
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
 header.i=@google.com header.s=20161025 header.b=ecV7GTgP;       spf=pass
 (google.com: domain of 3z89zxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3z89ZXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
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
index afe01e232935..9df9416c5a40 100644
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910070331.3358048-2-davidgow%40google.com.
