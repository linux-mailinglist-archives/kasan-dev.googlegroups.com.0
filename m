Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44I6WBQMGQENXDZU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 284D8363E00
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 10:51:01 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id h10-20020a9d554a0000b02901d8bed80c43sf9519661oti.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 01:51:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618822260; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ku746W3Fr+CgPhZ2E2OP41G8ON779rAK2uKqf1tQnCFNkAJ0AdsP8s0oJmUGfEA8Yp
         bZpKcQBd/YOXtx6CPNDJm0MaEvp9Sat1V1IqGkLbwGWDAkVxouQgvroQh5VMcMDOQaNM
         WwoANindNQ8HWRY9pAbcxrTYDLx5M4+jylgO1R+M0yQrtQoFEWUS/zQBmo+Kup4CHTO+
         YWfg8L0v8N+UVEXNvsLVD8GnrAhcaAZM/rm8AzF4uZtiEWdiQf+b39/Ma8o0zuOxIeFw
         GH9GMhaVkmhX1O6J5LI8m+n0eYoa8Ahog+XGzWXzGTQd0BMnka+Llse7shKakd/H6Lc6
         6OdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0jGwvufVoZEa/QbmEFE2WyAmF/SCcmSqTmHA/QrblXA=;
        b=fPQvqt0Ek3EdqnuSAWcRcJXrG4lg9KIrfiNJVCNmSZ3oPKbvGTStMQZ6//gQ3bSgSH
         I8xfCGuhh2EhsXSix59wz4JSIK6Ni6E/cLkfEuXEH3fO55nO8nXbzsKWyNz6BLF+CYHT
         keJ+u5VfxikKLQ0m5JzD+deh6P8iUSAsIMXVxDiBo6TFEqY2LwLWwOptW8xfQx8lr7iw
         r1etl0mKaJdeFQhWgR3zxr3yIv/MY4RtOi5m4x/uxi7l/0o/wikhX1dFy/fOAdU2TsGb
         G3+0j8ljlBE3POE+ECgnmde9/6TURw4vriabaWvYy/11tK+L7Mys/yho3SY3lpv8pEdq
         jdiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TMBkauBI;
       spf=pass (google.com: domain of 3ckr9yaukcfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ckR9YAUKCfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0jGwvufVoZEa/QbmEFE2WyAmF/SCcmSqTmHA/QrblXA=;
        b=BDntDvvFQgSLh7Ecx4jFkwhN29gQx/nRYjRagPGIDPXDxtbG5kGIC/+a0amp9OuGZD
         yp5d1d0s253Our8mllJupcIASQ6DNJYqzwMP6wCOF75VGa/FCwslhWjU80XujSsF+SS5
         Hyc1ZVLXx8nN+gyCjRTclntVP555jZ2RdfVjD5bfbZyoo7yS0ItWpwTTUBZKBcLwBkyt
         kr+ljaHdyItS5eG+m1dBWWVPymEvVnrKdZKMqXgOu5s0MTPcyAUmqZLoV+NTK3VDJWxU
         0Q7ebI1crAzbki1SEmB7HlruFE1Rnxn5yhD0XNKhc51bHKsF09ZeOiAURPSeW5xjDxbh
         wHGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0jGwvufVoZEa/QbmEFE2WyAmF/SCcmSqTmHA/QrblXA=;
        b=WIIVDVml1a9ZiOFhNZvNAK1UH6lVhHOPNJhIxnJDlbsiD05BLbFb9Dmje/4hNBEm3G
         WxKmCB86JC3QEz1SneWq0HCXg6AuxpZeXByy+GDW0TqP2WxDSo79R9gNm2SvaPpiYgKN
         Fovr8Mzi6siYFuw6VJlP0FxnXJryxzBaFkuBwaID3L8dh5KFBfsNRuWKMd55IFjyIYud
         uw6GAmi2lUPEm3s5nWgcN0AXmSwXSdsH48Yzj05O3FjRvu2cRqsDTIjC3Bib7QU/iDfj
         l0WUtvol53EDWC6979KA/SMdqt/dpqw220QxfJ6r9y2GLMz1Xkq0llqz8rBSIYghixhR
         pWIw==
X-Gm-Message-State: AOAM5316Cdudr+g+nk+zoCzMfp6gdbgaoFvVEKJVFFouYQH3Ef39p156
	dIck5QvVBDx8l6zdJLGfxoo=
X-Google-Smtp-Source: ABdhPJzK0GX3vfJi196Ho/lsUaB4ifjTP7eZRQCqnq7e5xWIMOFFmglm5jsc6E4uzUT8SqyaM6tt0Q==
X-Received: by 2002:a9d:6d1a:: with SMTP id o26mr14534638otp.122.1618822259871;
        Mon, 19 Apr 2021 01:50:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls3702516oif.6.gmail; Mon, 19 Apr
 2021 01:50:59 -0700 (PDT)
X-Received: by 2002:aca:4b90:: with SMTP id y138mr4923854oia.169.1618822259489;
        Mon, 19 Apr 2021 01:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618822259; cv=none;
        d=google.com; s=arc-20160816;
        b=aUG6C2AGCwqC2GtOytNyL8m2PB8mOVjcD2FTSFsBl7qDdURoBkoEwbbxa5WHylTP4o
         fuK42wyURV6J+NVeGpYxhcXbuK4I6Z7RVUTOoaW5OvMhjVlj5Xr8R5x44L+bfEMq97df
         zPxiaZsQFMcvWmxzpGepdUMdXVdYPMgW8BbAXNGhsSOzTdx9YeL3TzMnRj877+StctzG
         oC8C54SVIyZKR4XHbs4mWYWCcSDwRuvOHj3iDj5NOO9XltjHjJGkODtfkDkyDdObohAB
         /6raxlYo3JTfYpXNNl0L+P3ebHimxuVYvsyq4LE4gWOVGxCFK8Buysg41S7b11tD7VE4
         oZUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1R4Jr4Y0fNVqtFmGdn7fmPgc472QE3HJBlQ1cDdhzt4=;
        b=dDld5wfSa/Ii2b/AyNbJce7AXJAP4nFXFZCq1I4Bnit9wOLZBxJfdwaRvVKk68Esia
         ZEJmp0n9Tfo5t/qL2M0+I0qZvHgZlexvLRaPrweo//mlSwDSgS/jLnFjx3j34MkzqJXe
         12mzms85CvkBHUCN5AqhZNaAnxGz71OfvMEjo1d3HNbmViBArGOZmaLgvAIqZlxNwqAv
         P+McQ1QzAxjkEp4f9m9Q5jMgqR3ApAoCwdXuXcSD8TStbjm+cJTmgEjovmxZ5bDYLaKa
         r3X5/ZU/atn0EoXJqNyOOBkZcRO605qY6E7h4H5vxFvL9Fh2vYtwHIE2uZrqtfSgt+SJ
         jB8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TMBkauBI;
       spf=pass (google.com: domain of 3ckr9yaukcfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ckR9YAUKCfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u14si184214otg.0.2021.04.19.01.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 01:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ckr9yaukcfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id m19-20020a0cdb930000b029019a25080c40so8826962qvk.11
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 01:50:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:92f8:c03b:1448:ada5])
 (user=elver job=sendgmr) by 2002:a0c:a98d:: with SMTP id a13mr4682439qvb.39.1618822258947;
 Mon, 19 Apr 2021 01:50:58 -0700 (PDT)
Date: Mon, 19 Apr 2021 10:50:26 +0200
In-Reply-To: <20210419085027.761150-1-elver@google.com>
Message-Id: <20210419085027.761150-3-elver@google.com>
Mime-Version: 1.0
References: <20210419085027.761150-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH 2/3] kfence: maximize allocation wait timeout duration
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TMBkauBI;       spf=pass
 (google.com: domain of 3ckr9yaukcfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ckR9YAUKCfkfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

The allocation wait timeout was initially added because of warnings due
to CONFIG_DETECT_HUNG_TASK=y [1]. While the 1 sec timeout is sufficient
to resolve the warnings (given the hung task timeout must be 1 sec or
larger) it may cause unnecessary wake-ups if the system is idle.
[1] https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com

Fix it by computing the timeout duration in terms of the current
sysctl_hung_task_timeout_secs value.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 12 +++++++++++-
 1 file changed, 11 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5f0a56041549..73e7b621fb36 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -20,6 +20,7 @@
 #include <linux/moduleparam.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -626,7 +627,16 @@ static void toggle_allocation_gate(struct work_struct *work)
 
 	WRITE_ONCE(kfence_timer_waiting, true);
 	smp_mb(); /* See comment in __kfence_alloc(). */
-	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
+	if (sysctl_hung_task_timeout_secs) {
+		/*
+		 * During low activity with no allocations we might wait a
+		 * while; let's avoid the hung task warning.
+		 */
+		wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
+				   sysctl_hung_task_timeout_secs * HZ / 2);
+	} else {
+		wait_event(allocation_wait, atomic_read(&kfence_allocation_gate));
+	}
 	smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
 
 	/* Disable static key and reset timer. */
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419085027.761150-3-elver%40google.com.
