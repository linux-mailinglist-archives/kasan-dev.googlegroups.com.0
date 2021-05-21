Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFHATWCQMGQE3DY2VEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B66E638C1DF
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 10:32:21 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id g19-20020a4a6b130000b029020ebe83598fsf6327234ooc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 01:32:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621585940; cv=pass;
        d=google.com; s=arc-20160816;
        b=PbQB4QR02Or3ahUy7lv50oADf+ODQS2eq/orocCTwHqmKJE2yrKggxUqeSCCvw9CoK
         hyd4/Ux79qM0XgDPUQpeFmKF1SG4iTjO11bMEFv8X8HmeafdMsapqRDtEzpjipF9yV/k
         wcaa+MnbPJD2t6z2W/BJnm0gfS04Gx4cVejj04SDUtVDNH/CEvAcm1sWMlHhz4flCyXv
         Q0PB9xwGIuT+ash2PLoY03l6a9FRSLaDVXWqzghtyL+48iCcfQRm3pFKrzgduLhSKlTA
         IYdz/wpdDhYvwZ+Bv4/F32DBoIcj8u5UhXEKLYj7gr/tIzoZuMtai4/6DMQrWu5wNz6/
         u6BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ZlMmA4uBL1O4eJsD4/bkioDWEVGFUWPE0PFUHsCMVX4=;
        b=dar4sE2RNYbqYDq/4SVWdHCkjRJn7wKmixjIzfojalFJrU9KsuOdAchTl17c6gm87E
         IQh4HKmowXz4xJbAtnv3yXL8L0pynfVJXvQukyL9BnBd/I5AYuP/edPkF3TvIfSaw7bE
         G4zGJ2pDzCGNU1aEELARBWmGjvjTqftzOnfGSubzT7OOnY1kOG5lszBY9iG1ChsnBwer
         WuPrKK92fexP5XdV+fvvzs4naFalN1mvORhtYP3VW4emKFI1GwM+cpu4emicB4jjWwK2
         f4c72Tzdqnbv77V3PNfXPWE4N3y5yqTr1QZ79KYqKb0a0okEGgq8BdbKzuB0HRi4lPu+
         LAWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XraWczXc;
       spf=pass (google.com: domain of 3e3cnyaukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E3CnYAUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZlMmA4uBL1O4eJsD4/bkioDWEVGFUWPE0PFUHsCMVX4=;
        b=SQdy5+MFPmF5Qugs6lp7+SsKpjgOmvXZBjROXAHtaar8vI2E2ZNI/oZSUy7qYHYYld
         orvMFgj4OlybdToAJbo3/Yy/aNQj5xHe6COkOHWlkDHt1FO2NlV7UFaZckGih5/0nl7N
         G2NovLfQLX0tTlESehUevR6yQ4lW3ORTSPklxOlBNVkOE3upBAWmEAvJLL9/OkpIJ7ic
         fWlqye1e8enx0u4F6ybpZhb0q60fR0wcq38D/m02ikGfVtBJvlvjrdcTmpB1t3pJvG/0
         WfEl+wDtgnmkNZxtT3ZKAs9+JoVDUGhapfnLN6cEExuF/5M1KviAM7XIuYeVpaVrEjgs
         /MiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZlMmA4uBL1O4eJsD4/bkioDWEVGFUWPE0PFUHsCMVX4=;
        b=MLxHwlW4hnnwaZ1VEAkqE/x14SRdIRFtYdxGEvY1sy91B9lLcZ5vA1gxUK6EBmuUK1
         ZQSngQIOtu8xe5DcPhrddVVqY3g4zcVZ+4mgAOzSlqqwkYMjx44guo/WvIZnfMKOAvbU
         B2ql3/aJsPFWxhg43SxI8IzJ3B8HnZvVNBmj6mo4MNStRh85mTQxL02wNeKz9IbS4SRh
         BYmJ2DUYkf2fGV25drdBvjwTxiMuwmX8A7uTp+dbaKs0AqlEKrJJL2FulI81a2GjJWeI
         09RGuFH5A97Fs4fYsziY4X/R5qmqWT13z9Hy6rFiGnw13RXCoHmYWK38Sp/3gcvhW4ZT
         UJgA==
X-Gm-Message-State: AOAM53256Ckro7d1uwk4QlDAtcLGxFB1TqYX6EC9DuASNMnKYqVo6Hfu
	ixGMveQtaxZEgBSRXjmHjr4=
X-Google-Smtp-Source: ABdhPJzq6gejGcLQ+FLnbhaihEDZdj7Vs+A+hZinKuI+TaML8ury4VhKEHcKQFqN605oB8ayyRSikQ==
X-Received: by 2002:a9d:63d3:: with SMTP id e19mr7180307otl.64.1621585940723;
        Fri, 21 May 2021 01:32:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:83c2:: with SMTP id r2ls448926oog.7.gmail; Fri, 21 May
 2021 01:32:20 -0700 (PDT)
X-Received: by 2002:a4a:250e:: with SMTP id g14mr7222703ooa.31.1621585940181;
        Fri, 21 May 2021 01:32:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621585940; cv=none;
        d=google.com; s=arc-20160816;
        b=w9s9SeASU4QnNKQroFfwGe2Vzru3vEIHSv34P7LHxkYN7WdgxnhcTvIHEt1aXkgJnV
         00PMnRL2SKH3iNNd5HW9bgu+e8dT+LTZXxJjmCh568bFA/oeSw3y63k8pFS3WuAwY6p7
         xoJXmnT3818Ozksx5m3/U3ansyvVScLx/j4IlityzfpH2VPm7HsvJl63vI5j5g0OIdQH
         mnH4/+nbRm2NDvpyr0szbWzIMLNgt/I89+bq38aHwRtI1cGDGMRLDl/+Bv+Krg+OFLpN
         V7pW8yCIAkmRhlLblGqGVZTcan173OHtDpnCkVjCGfR9QeomIkpyg7fd8t1tc55/YyM6
         HtiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=eNYE7zpSOCj7plZZAyS+5aDrL5u+MfadoSDP0vm8/WQ=;
        b=H/bCJk0n+Cy3vyt629E4tiaV5ZySa4Yo0fK90hSaheKhHp0fe2lYOKbqWP4UXawDps
         d08lX1y+mkL2Q27YMoV6L249LhD8s97q4lgS3+AI0iKn6oBxpVf+ACz1s37hobS5m6Hw
         LkjotGGBRmqeL+pJuH8XBUdk5K8Cvhtcg1Ls7xMNB6mYpKmDHh/VQ9W9AEwjrO20FOqM
         UtinLX9KFGC0IiiWO0+oLstggc+oKQpuNG01XjxbmJ86oX0G24YnefhJwdy/1jb4Ln3u
         Ng6NvUhjqW60PUWya5XTic6OC28uvql75L3Q7+39swFQrMI1Cfphls0dz9wi7iUGZSKy
         z/ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XraWczXc;
       spf=pass (google.com: domain of 3e3cnyaukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E3CnYAUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k4si630603oot.1.2021.05.21.01.32.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 01:32:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e3cnyaukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id o14-20020a05620a0d4eb02903a5eee61155so5094426qkl.9
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 01:32:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:a932:cdd6:7230:17ba])
 (user=elver job=sendgmr) by 2002:a0c:dc07:: with SMTP id s7mr11433864qvk.26.1621585939685;
 Fri, 21 May 2021 01:32:19 -0700 (PDT)
Date: Fri, 21 May 2021 10:32:09 +0200
Message-Id: <20210521083209.3740269-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH] kfence: use TASK_IDLE when awaiting allocation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, Mel Gorman <mgorman@suse.de>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XraWczXc;       spf=pass
 (google.com: domain of 3e3cnyaukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E3CnYAUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
allocation counts towards load. However, for KFENCE, this does not make
any sense, since there is no busy work we're awaiting.

Instead, use TASK_IDLE via wait_event_idle() to not count towards load.

BugLink: https://bugzilla.suse.com/show_bug.cgi?id=1185565
Fixes: 407f1d8c1b5f ("kfence: await for allocation using wait_event")
Signed-off-by: Marco Elver <elver@google.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: <stable@vger.kernel.org> # v5.12+
---
 mm/kfence/core.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index e18fbbd5d9b4..4d21ac44d5d3 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -627,10 +627,10 @@ static void toggle_allocation_gate(struct work_struct *work)
 		 * During low activity with no allocations we might wait a
 		 * while; let's avoid the hung task warning.
 		 */
-		wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
-				   sysctl_hung_task_timeout_secs * HZ / 2);
+		wait_event_idle_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
+					sysctl_hung_task_timeout_secs * HZ / 2);
 	} else {
-		wait_event(allocation_wait, atomic_read(&kfence_allocation_gate));
+		wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
 	}
 
 	/* Disable static key and reset timer. */
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210521083209.3740269-1-elver%40google.com.
