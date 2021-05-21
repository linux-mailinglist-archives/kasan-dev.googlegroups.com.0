Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF5NT2CQMGQEPEY5IVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E25A38C584
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 13:16:40 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id z14-20020ac8710e0000b029020e9ce69225sf4405987qto.7
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 04:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621595799; cv=pass;
        d=google.com; s=arc-20160816;
        b=r1GZUU0ql7HTUfAGIC971Yccj9vlm5/0K0AMAvuJ+wUem1CAwyrOE55yCNI77AA0FF
         c6i1bEK6oZq8fwCBEs1tz1vc3CGZaBC8IamFXoXgYU2LELgLfP3DAjgAPujtbIdSDxfS
         UOMc5+jx+2JqlsvobcTLFuk4ElIiFUJnN+yDZ0IhpUDj8/yxgytjSlVAo9aGGIKDtdlN
         BqUNfpiJxr+z3pi2cb49I4y4RO7eQIo1KY/JNZXBlZ8ihckT2bb1o+MFGq8K88NnrVG1
         EWF44+DMP6Fv3svMv7zKRpEzfKe1gluYo0FSGPzXmRp9kbsy+hnCXsodynKeap2rKXV+
         4fTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=2U9B+izvbRnBrMIXE1CE7ZIorzudUziZxdU5s5+bRwI=;
        b=XRMtb58Af6fl+qLKutGxLpB/CPcKJhup/J+P7GnSXlhCTY7JJizCSV/rFUKLhwUQkZ
         70oSlLNqx6UXRwLwt0db3/J3olUy4orQw0VXcf8tx6x95sTUryqujjbJchtUC9cRZi4j
         +xjlHdEFJpK/Y/EPpegvYUq6NhV936cE45RDQ0eEKLjBF+mBcXcEaJF4du1qIhY5rfYF
         xmlNLAivYgxyfXjjua8KxSkWol+6U+SSY62zxbyJRkrZ5E5hRNDdoOUv2EK733WObr8S
         RghzX5M/lYsOa63eHwVeOQDLbVvgYqzT68HU7tFAka8kisMFDcEPJht8hXoEytBB+kgk
         NI7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SjYh/4Oe";
       spf=pass (google.com: domain of 3lpanyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lpanYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2U9B+izvbRnBrMIXE1CE7ZIorzudUziZxdU5s5+bRwI=;
        b=OZOWJCZuZ9EWl1SRTl9XrUkQ39MK9a2+6yaEhX7lHHsIfdvq1I3yJu4/Vjyqdc7RLm
         rDAsfjf/McFMCs1MgtRP+fMzLQIg2T8/026oWWvZ9peJSDxxg5RtHBfZw/RrmCUADU+q
         fjyh/wrxjfmZ4ZvQoPokLMBlGYUqqU86F0CV35OV25c3TQCyBcDK7uxCUBzSwWY5v86K
         xYxXDm2NkmzQgQ0JGPBr/Hv1e7pjeS9B5hZhcXkO3k1P71uBDGBqEpRmImI3z46QEIJj
         EKLhs5tX+XB5LrRNl9y+n6drnOdyrh8wMgpYl8xCTNdfUJKq1pxY/vWwxljRYo6Y+3k6
         8OYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2U9B+izvbRnBrMIXE1CE7ZIorzudUziZxdU5s5+bRwI=;
        b=fdAYGgU2re8yKjLO9C3JA+e/FMEZgOwP+a6unaQM7q+3xY7KOnM7X0aFJz0U0Pg620
         k7HIA3HLjr6sbm/tqEX5MjzrHOaa7l7hCbrZ95hii9Fw2MbJzUn5SYwyBBXdAdBAL3Wr
         fogZAhfJ/NrOZI9BxrUqg4UXVQlGoObYEWIwwdAE8DJgZFtUMR8A8cOttbhlJTzglqh+
         uOrvgQqQy1KNDX3VTQNiVLFnakxo6ka6p/ISSW/Yh7qVG8tKM5OLiWWwSbESr8qUvBIR
         VFeQJo5+Bv0HWbocxrKVh6/AUv6eJ25YNZboMMVChmv5enhtdNihgPPRKorKeq5uPK2a
         fT3A==
X-Gm-Message-State: AOAM5313CxAgdIwlF0qh5mjh6uQkb84E8oJ93Ve1ZQycqjckrwmmlqbE
	ffQngifVduolxnT1iVm06ZM=
X-Google-Smtp-Source: ABdhPJwfQu2AzF97zoMQTmrRGB4UyC+zYnpxTKaIHNoBWpO74505FWRI4gxj3yd1pIuxiFjuKDjlDA==
X-Received: by 2002:a05:620a:13a5:: with SMTP id m5mr11611569qki.119.1621595799641;
        Fri, 21 May 2021 04:16:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9e1e:: with SMTP id p30ls1807135qve.10.gmail; Fri, 21
 May 2021 04:16:39 -0700 (PDT)
X-Received: by 2002:a05:6214:154c:: with SMTP id t12mr12340674qvw.38.1621595799216;
        Fri, 21 May 2021 04:16:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621595799; cv=none;
        d=google.com; s=arc-20160816;
        b=qIQzQ2YUZSNXrBt/7wk8gBajWVyz3p/eWhju/45Du4iju/kLhahoEKI7Z9099kcLqF
         D7DSM5af8+IAKqlW8dpvjvyBjqrsC2tHp2ru+XOXUojw2NF0LuO/cJdse/XTW6rPhV/0
         JSlzV7Rx6HXNJoo7pBtm0mhcgazsXofLV1Vhw0CrsqFFN4R8cqXXWmLyHLc++uVvrSf1
         zbmVIqJwHwAXBw7mUkBe1gE51198IgRZqzhqyeKQVG2l+AEyfrV9Drg+sUJLloigVgMJ
         33BzS+4z0Ociw07MSWQAybQyd/UrmDmg8Z6WBRLjgUgYy/ElPBS1ShqXvqL6eIJPY6nT
         360A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=+QJiicZEZmfMKgY/pq0Y5eLW/e6KZlrhFiiHdcX6gWY=;
        b=uF+2Vf4sbin9nE97fAQJxM9p1Xw7B7cR9kOMs3HM1UdsD9Z/ab/MtqyEaJsWorpumG
         IYuF5q1UlwrkLTtl2S4Qq+iu1MRYbjLejuwvaAm98+CjcxDfpBJV6taBBRN+5iuwnOuR
         QnJ3g4N6x9I7ipUoFs38/z8+HZxpNmNAflTV1aKv8RpKW387nrU80BZhewuaIfhCqvNO
         WGKDMts4M0wxw+XjsnZlMWPLUTNPn2+Fj/eodBBXXkmbKoi2oHYsGxQbKc37VS0E4gjs
         BQekcEikfZADKNJO3Z0uq4YX0Sy1boaVWaGVcA+VJ6Gk69+R3GeI1trLkRrt+wVjD2vE
         Zaxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SjYh/4Oe";
       spf=pass (google.com: domain of 3lpanyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lpanYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p5si930586qkj.2.2021.05.21.04.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 04:16:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lpanyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id e13-20020ac84e4d0000b02901e0f0a55411so15101323qtw.9
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 04:16:39 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:a932:cdd6:7230:17ba])
 (user=elver job=sendgmr) by 2002:a0c:ba0c:: with SMTP id w12mr11900436qvf.41.1621595798787;
 Fri, 21 May 2021 04:16:38 -0700 (PDT)
Date: Fri, 21 May 2021 13:16:30 +0200
Message-Id: <20210521111630.472579-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH] kfence: unconditionally use unbound work queue
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Hillf Danton <hdanton@sina.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="SjYh/4Oe";       spf=pass
 (google.com: domain of 3lpanyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lpanYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

Unconditionally use unbound work queue, and not just if
wq_power_efficient is true. Because if the system is idle, KFENCE may
wait, and by being run on the unbound work queue, we permit the
scheduler to make better scheduling decisions and not require pinning
KFENCE to the same CPU upon waking up.

Fixes: 36f0b35d0894 ("kfence: use power-efficient work queue to run delayed work")
Reported-by: Hillf Danton <hdanton@sina.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4d21ac44d5d3..d7666ace9d2e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -636,7 +636,7 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
 #endif
-	queue_delayed_work(system_power_efficient_wq, &kfence_timer,
+	queue_delayed_work(system_unbound_wq, &kfence_timer,
 			   msecs_to_jiffies(kfence_sample_interval));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
@@ -666,7 +666,7 @@ void __init kfence_init(void)
 	}
 
 	WRITE_ONCE(kfence_enabled, true);
-	queue_delayed_work(system_power_efficient_wq, &kfence_timer, 0);
+	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210521111630.472579-1-elver%40google.com.
