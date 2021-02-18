Return-Path: <kasan-dev+bncBDGIV3UHVAGBB36IXKAQMGQE7Z6T7IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D654C31ED55
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 18:31:27 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id p8sf1470673wmq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 09:31:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613669487; cv=pass;
        d=google.com; s=arc-20160816;
        b=CXbjZrYU1dco4iG52efvqeoH/Zo5FK1OswVubXr4iUfYRd+7aX8cOd+jJSmPP4GXbh
         25Bg+gY5EEv9CsQcxsLY76GLcjHg1asTuSyfS5AXImACy/U6NenoKReAbu60M/3t7DVl
         HS/6NywIvZK/JqFukW25T8NTH3GKk7f8dSq3wDm7wt+T54mCBxOYPgEN7bwuJ0nxouoZ
         fUXUuD8cmRxPZ+2oSgH0Ibu8xFOUDj9MmpNRn+gCgCsmcbI8JiVuASS1soqYV0cSY/8I
         35oZpQvzDunBe2COWngcs1cT/p98g5ODqghrobj5O64uRznHppcgNLUYPnj7AZttHgdP
         oYcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=7BrDfhJk4fA0EBPoB2RxKcjjwfv6zIm3vN7iyFAkL70=;
        b=XvlKP9MZG5dqa40VA5Bvgjf5e1RqDpVc0SYnwer1YffpVQSDd/flMK5Ze8gyPMlcCX
         sjA5+IeZXYXCXkSpSdxI/iik7SCSABKdTAhFn96UeBE8I7cqJXRezHn5OX4wM/dJKpIF
         2FQK6u01ZPZsObSgXFmotJczJkPcL+ZUML355eg5DTAQnUDFYtxUrMb+TN4vTBEIQilh
         w4WsHm4p7Gvg4W2fyYYhka3wHqVB+62KozI7nzE+xia42oM6aefpauzkCQMGlmofQ6Dv
         w9F6FM83kdAz8m7KMdCrt7nUgDS1+AwF5ew7mt2oD800phLYrTMTPziaBFxXid3n8to2
         DlOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=vE8Bl+8a;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7BrDfhJk4fA0EBPoB2RxKcjjwfv6zIm3vN7iyFAkL70=;
        b=sW/S0FVFPjxhDgzg4SfRrNCOeRsXdcnjGoDGUwEIAZ1cycq6US8rDeODIPxCW4DYdr
         RXMrY8J7ygxxQL8pkmhjAJD9XloTlRLZ+ZfBQn3nnz8eId/cHe2vAT1/ve8cvSfFQyf+
         MyXEqltFFjBi2tsdNOd/ZPTxci+afPyzzXYpLrwbDJABGXm6FE5y9L+u9DAL6Jrxa6qN
         yV46SZ4Nmkpmi1l4dAge3fvA8M1fwCsqw4cWqOeZ3KH0kPT9sKlWXqlqlC+Q6cksdek1
         UOVRwcOEa+MRxDAhj3YWIF1oEIFasNPIHURx3r4p4XBaOuvVFF7lX9hPzfznzpac06p8
         P25Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7BrDfhJk4fA0EBPoB2RxKcjjwfv6zIm3vN7iyFAkL70=;
        b=nrZ4QNKSf9Avwzni5a3dkcrWY7yGMY/7RnHXERaz+FvnFmdXbzFoRJi0Nlt9Uf9Cky
         JcIeFwS42yvbGEpPhoKsJ1QgmXIzbe3shKDL4NTP6F0hWdGw66Fhmpn85dZuaHsMa43C
         h3X6+xZMcwfDZOMlMKZisbUGumb4KNNuDWeVK9xOys6912hzsTuNI/ifNimlsE2dgtWY
         MxaHVS2dJGUq7zAZrtPAa7lvrhYKQZmNab1tYRLNJKHXKR7HFjrXLMPJTQ+6Py6Ile+w
         LG6/x1S4gOq/vo2JDQvqX/uOhoAFSwbpBiIXMix3v8VWiNzMmxbwcIDcgueB3D0WQxQV
         i5LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xp3QIs0qo0D76dwg7oJeuu9RR5RFd8O8IOMUNZ+Mf/KIvTb9E
	dcqu8Jmjs23kJNzU/pS86nU=
X-Google-Smtp-Source: ABdhPJyd7NhU02qcDQqdMj0NCHwsCM1zwiPcAUXTA6LRzfGDKEJAvOinoGc4TVmmgl8am/j2otd3wg==
X-Received: by 2002:a5d:6448:: with SMTP id d8mr5353668wrw.401.1613669487583;
        Thu, 18 Feb 2021 09:31:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:385:: with SMTP id 127ls2673581wmd.0.canary-gmail; Thu,
 18 Feb 2021 09:31:26 -0800 (PST)
X-Received: by 2002:a05:600c:4fd5:: with SMTP id o21mr4452779wmq.20.1613669486872;
        Thu, 18 Feb 2021 09:31:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613669486; cv=none;
        d=google.com; s=arc-20160816;
        b=mYfMBMhOHWSKbTwFhuFmNjT1p4NIQzEwh1ovq5xyoCLIh3DSVAUPTQrbNZlCuRBqXU
         rmRSHFgx03XbL0V9ImCny8Iq7ghGxQ6WFwNoegymjheCi1SpbFLyTEH0JQtVIQfD1I6c
         A/0r72RrM/11rm2JuIJ3+lkWi6HQ7imf+mcg96u+yX+o9F199K8yx8C1e+MxisoWZvkZ
         R4ScfN+W7qEUdX5lUwmBEPu45UaY8xQGDS1Tfiqrz8lqYsxJz0JqR8oDAL2SyepcFm2d
         4cN810mR1TV05CNiRNdVNkm1BnQT9frlUf7/oz2aPIUnjJzDu0oQDaj9ptFxWjIJpjDw
         6ZxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=nLRBuVVWvc8V3uVW45ibYaABYhWDXpjkZ5kiNjBTKQk=;
        b=SVX8kOG8TTJTetjTfTneX0w4j1z8ivULUQEjiZXZj0AGWipAO6Vyvxkn8IbbVZTiDL
         pwa9mIGb+f53wQ1ib4uq2DARSJZ3wki25B0Y6ZtZmhvhCYGswChWufGHeshaTggqNN6J
         Nwc6JtHJB2ae4u3ao0VO72ypnueYzBmCSoBgIpY7J5FtyBa/z5XwAz7EpbkOAxxyYnva
         0II1cbwAYziuhVxyEZBI8myU6O+MSaLWasC53QAPBHwYqzHQ4Zw9qRI9CkBc19GQG4GJ
         TNLJZfgaq9pUxHUo4PWH62eRFS735EZbR4DfKb/1yd4gFGLEbXVVUnVyr7YY4RxqEeCS
         ERSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=vE8Bl+8a;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id z16si162656wml.1.2021.02.18.09.31.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Feb 2021 09:31:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Thu, 18 Feb 2021 18:31:24 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Ingo Molnar <mingo@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Jakub Kicinski <kuba@kernel.org>,
	Johannes Berg <johannes@sipsolutions.net>, netdev@vger.kernel.org
Subject: [PATCH] kcov: Remove kcov include from sched.h and move it to its
 users.
Message-ID: <20210218173124.iy5iyqv3a4oia4vv@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=vE8Bl+8a;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

The recent addition of in_serving_softirq() to kconv.h results in
compile failure on PREEMPT_RT because it requires
task_struct::softirq_disable_cnt. This is not available if kconv.h is
included from sched.h.

It is not needed to include kconv.h from sched.h. All but the net/ user
already include the kconv header file.

Move the include of the kconv.h header from sched.h it its users.
Additionally include sched.h from kconv.h to ensure that everything
task_struct related is available.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 include/linux/kcov.h  | 1 +
 include/linux/sched.h | 1 -
 net/core/skbuff.c     | 1 +
 net/mac80211/iface.c  | 1 +
 net/mac80211/rx.c     | 1 +
 5 files changed, 4 insertions(+), 1 deletion(-)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 4e3037dc12048..55dc338f6bcdd 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KCOV_H
 #define _LINUX_KCOV_H
 
+#include <linux/sched.h>
 #include <uapi/linux/kcov.h>
 
 struct task_struct;
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 7337630326751..183e9d90841cb 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -14,7 +14,6 @@
 #include <linux/pid.h>
 #include <linux/sem.h>
 #include <linux/shm.h>
-#include <linux/kcov.h>
 #include <linux/mutex.h>
 #include <linux/plist.h>
 #include <linux/hrtimer.h>
diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 785daff48030d..e64d0a2e21c31 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -60,6 +60,7 @@
 #include <linux/prefetch.h>
 #include <linux/if_vlan.h>
 #include <linux/mpls.h>
+#include <linux/kcov.h>
 
 #include <net/protocol.h>
 #include <net/dst.h>
diff --git a/net/mac80211/iface.c b/net/mac80211/iface.c
index b31417f40bd56..39943c33abbfa 100644
--- a/net/mac80211/iface.c
+++ b/net/mac80211/iface.c
@@ -15,6 +15,7 @@
 #include <linux/if_arp.h>
 #include <linux/netdevice.h>
 #include <linux/rtnetlink.h>
+#include <linux/kcov.h>
 #include <net/mac80211.h>
 #include <net/ieee80211_radiotap.h>
 #include "ieee80211_i.h"
diff --git a/net/mac80211/rx.c b/net/mac80211/rx.c
index 972895e9f22dc..3527b17f235a8 100644
--- a/net/mac80211/rx.c
+++ b/net/mac80211/rx.c
@@ -17,6 +17,7 @@
 #include <linux/etherdevice.h>
 #include <linux/rcupdate.h>
 #include <linux/export.h>
+#include <linux/kcov.h>
 #include <linux/bitops.h>
 #include <net/mac80211.h>
 #include <net/ieee80211_radiotap.h>
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210218173124.iy5iyqv3a4oia4vv%40linutronix.de.
