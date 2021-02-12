Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPPQTKAQMGQETWWN3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 38AAD31A367
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:17:51 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id j7sf7903573pfa.14
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:17:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150270; cv=pass;
        d=google.com; s=arc-20160816;
        b=yFLHigPHfbzAjP95gj6PArt1qINXJdOJvXfOWR/Wsh/+8y5hnU6lR/99srjNfrLx4p
         1ZwAPQCT1HX1OAnh4ikzyVXSiEF2w5OUZADY0KIT2w/Qbn897hHhznjx1v96+GpgI1RL
         7zVVYCjLYvTp04IFoGjrothB6qyLGcFCORMQa+n2k5JWB8lNVY1dnK7yUZ7u9JeE7WA5
         wQ8kaJz2490Qx91jC5JVyL7JZXRTZdOlc+0AjrmcKMGoUCo70BeWTs4dDcf42AsMwSmd
         x7slThWSbGsi+96wSzfgzrcawdlcLaYE/21+046bbcS64mbt/EpEMdtc0mTo+MCBbLLD
         q7lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=PXxAqiu5u+FCIN0tgDX4nDHrEUfRNXffqpSH1/R1B/0=;
        b=vs8McGc8Q/cd8NaUrKX5yZXl7o/A8mpkSp8JI+IQ/DfIrrhhWr9hKODDWFv5IBVvmE
         y4Xthtdnt+EBXVzP5jmH6OG4xeEWCud9BqMNQ7yp1wpyYdlWFuPK2wni9N3QZPxYpF9w
         PAykQ8VbRauVEVQsJ9rasu3WD8AgLGjcnoe/EQXLF2OjQJEizoteUsvDfgl5ZmC0q81X
         qn6aCxwHdBZL1Jc2QzJBQx8EZg7ascEXMZbzrNSKStNvdlpPWb3cq5hFQ3mBI4Z532TB
         C5CBLckk0NMh27JSLiltwSthg3hd7pYccfkrtmUUJsjcrXKzrPi4VHInhZ55gXEXEqhU
         JZtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g3huwr6+;
       spf=pass (google.com: domain of 3plgmyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PLgmYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PXxAqiu5u+FCIN0tgDX4nDHrEUfRNXffqpSH1/R1B/0=;
        b=lixtg+vdzUOFGCOAXb7h3Un0KOgl1/U2MUhMJygFCbGGE2N3GYQDtsI4bYnIOWTdzp
         WkMkHT3v1IKG7ETO3xfzfvDU1AlQqRN7FospcCsTs7qwIsmSy/6/aSMe8gb53AR4BHUT
         CHJo/mgoRPiHOhaaFRg4D3iczaZac1zmp+sYFNwbJeROCavL8X9tMs3AnCtr8AzSD9lG
         csg7JqZDGGR+flBLMtqdRlJ1nvm3MWgXRuZlcY1XrecQJEuKO0+EwwWECfpDUSOuSBw4
         eE2xcSi66T/FXNdojDfyenqP/+0VGDpNC0Tn0SG/aR5RzcF4oB18VlHe7h0m+txTqYo9
         wvdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PXxAqiu5u+FCIN0tgDX4nDHrEUfRNXffqpSH1/R1B/0=;
        b=hOcsM4R/YTMlI07jubg+wT/mAxzGNzgxzAFz9I5AB/kzVT/mFRAXaC8YMai2jjET8e
         cgB4aRe3Qb/SD4ZK5c2ppjS7Fsw1hU2gu9fOlR4oKJBgZ33tkiWflbbwOZK8sFnPvdDa
         VDmpHjTDGy/GIJ9+0C9M3y7ypON5M57OL6Eljii+dC2yfmHV9j/l6dKGp4KwAimNAuyb
         Xva5PS54fgP+9tfuUAUUUBWasBZkjEgiyBO/sl2ox4RQHSS8cj1UfELTlORC5bzU+kWD
         qr54wxf5vVVOd9KmY6zw5nSQybMnt/5xyJpuA0hhmsFIzoaC2yt2uME9wr/1+NDCTiHq
         1BwQ==
X-Gm-Message-State: AOAM530WPF+1/WdhZ0gBsnKVHaaDTeM9wFWg2Os6W+bDdOjROVd65Rep
	zvISlGmsNLJIrrqFxEx7y9M=
X-Google-Smtp-Source: ABdhPJwoHD6k01PcetXOlusnTYLAhUBj5uYcMKl06P3nsqhJ2mbkfL/GzOU7BXYyzSDqy5GYlbi5Uw==
X-Received: by 2002:a63:c54c:: with SMTP id g12mr3983619pgd.449.1613150269860;
        Fri, 12 Feb 2021 09:17:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31c7:: with SMTP id v7ls4192479ple.2.gmail; Fri, 12
 Feb 2021 09:17:49 -0800 (PST)
X-Received: by 2002:a17:90a:ba08:: with SMTP id s8mr3453163pjr.112.1613150269246;
        Fri, 12 Feb 2021 09:17:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150269; cv=none;
        d=google.com; s=arc-20160816;
        b=rl8KY8SpfTgXORAoV+VLfekkzFoiFgxQJe7Dqr1ptd5gShs0Ab0NClD/ysztIlkc7A
         KQzSighj6JucakfvsA2IQ9HTN3AU6QIkungq0wajCSya+Hvk+vA8bt3+4w6E+ddj+EnK
         c6y21yAN/6Fv7BsLjp7H325yZL4tURk4a4TxtzBWhw0RdyNTC/57GNNQwq34raNNZrnK
         xY504F2/KshRtlPCIZpNwL6PjejnncmG0pkZRlfBFpimhChHEOG+VbFH74Fxg2TU1JEE
         A1aNv90acL8WednvU4snXQhhAh3E2UFjgs4T9JFR1yEuu1KAO7lH5U+QOWqjgXCHN2CK
         /mog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sjPAwZpJiXhVxPtqxJm1Bx7G/I0f+vTY0LWrgQk7G2I=;
        b=ID1kGxAetVX6CGBou+dR7dd+5lOVvmh+/BM2ej61v3ET5GgjvZAYoGP+8uDrvu+nZQ
         aIM+v++LbMLo9e4k5nyWvGsUE7xh/CQ+1wqjCZiiCmEnk2xfJ88uXOycYeB1pCzzNEWn
         wbx6VC2uKY72unZeeVA2ozeRK6Y8uyDY+KHkMR32gy00iZdi9fAIcaAhyI7Dh460X7Jh
         XHI+0eSOdlhsYlBvJu8qN0y/0AePH4zO+Q4TJcGHNedRCnIw8uZKvcePtJjglMu949Gv
         Qfb25v9J3mtuDBYGqBRSYydb/IhyvdIoMyuC4Y0vQRkeAqF4GojvSbPmFHpGcDL7ykPm
         8uRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g3huwr6+;
       spf=pass (google.com: domain of 3plgmyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PLgmYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id n13si480199pfd.1.2021.02.12.09.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:17:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3plgmyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k14so6840876qvw.17
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 09:17:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:19dd:6137:bedc:2fae])
 (user=andreyknvl job=sendgmr) by 2002:ad4:54ad:: with SMTP id
 r13mr3510435qvy.48.1613150268429; Fri, 12 Feb 2021 09:17:48 -0800 (PST)
Date: Fri, 12 Feb 2021 18:17:39 +0100
In-Reply-To: <7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl@google.com>
Message-Id: <c1ce89a7aae0e2d6852249c280b1eb59aeac30c0.1613150186.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH 3/3] MAINTAINERS: add Andrey Konovalov to KASAN reviewers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g3huwr6+;       spf=pass
 (google.com: domain of 3plgmyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PLgmYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Add my personal email address to KASAN reviewers list.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 7b3d374c858d..e9fccfb27e2d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9561,6 +9561,7 @@ F:	drivers/hwmon/k8temp.c
 KASAN
 M:	Andrey Ryabinin <ryabinin.a.a@gmail.com>
 R:	Alexander Potapenko <glider@google.com>
+R:	Andrey Konovalov <andreyknvl@gmail.com>
 R:	Dmitry Vyukov <dvyukov@google.com>
 L:	kasan-dev@googlegroups.com
 S:	Maintained
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1ce89a7aae0e2d6852249c280b1eb59aeac30c0.1613150186.git.andreyknvl%40google.com.
