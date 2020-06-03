Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJUZ333AKGQE3CYXAJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F4BA1ECEAC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:32 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id e143sf1766711pfh.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgnfJocIbBczaJy19NJvtQ9SI6A6zDfDeXXW+j33SSuhYkwjDVOh56Lyv5GCJYFMpY
         o46qh2J75M5QH3OIlxekbxIzSciG7hxhqYDsDyP4EYhl/HozMYlhGZL0wW8pfp9zWCPN
         PyC7k8/PfSCk/6UghtCH7+wm5aS/pUHgQN0bVfSERgWX+ZJXS9OE7ymB9PQn9WnDcg+3
         qouniyBEvtccTvOHSy8uaUAo5go+I5iWY2AYj0B1wtqu7AVdy88H3xhGbS3/AsfwnU0q
         f+BRJsHL96kj53ZUZccbfAPNfPN4QcCOfsIXJCSWF6w6oN3RaATHFbNp1VllvGGkjGga
         uWog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=7KHt3jhWSyFf647hPzG7jA2vnIDhx7s/MYf0ogsUARU=;
        b=YsMZDeOjWT2OYLICiO4daHrzVDUC/JNDT8GU238o0sFRr9E49opQWemtH1hnN2p5QT
         Rg6dK1+aJev1EsChi9WRV+QAFcoZ8KNF0sT4AXiMG80sqV09OXD5rQGcxFVWCBVVKnxH
         6U5eYXIe13D2cD5NfegUFRJIXSVkBqxnxXMLMBe7iKg6+KT7jtvkI8TRD4YAbBLrCbGX
         QBQ9IxudmB1S8dVgcp3SQJXclzRs3gp02mPLvwvH5HgCqgGgpVzy0TwctXxBi/aVqczF
         keuB6Ar6tN0RZAvQXOAS+7kL0MQqfo+D8Jg7KMfSq/QQt0g3FoOi+BpP/nfv/xPx5FeM
         Ealw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=WlkGKt1M;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7KHt3jhWSyFf647hPzG7jA2vnIDhx7s/MYf0ogsUARU=;
        b=Qr4+oIzyTqVLfnxgjZYdYZYNMJkbDo+8mkbTCSII/k8jO2Kos75JxFqCyack3GZzxi
         7DWMMfm1Eq1UGLa3dLy+2154IptEohyo4+RCSBV3c0O8pahkT3+5SuLqDu3tU+AWE9cQ
         s+hANiosTYF4QIAbPkZ2DJ+MIOru+Tm/JVi619O/AfbX5ufy1tT4vcEFRJ/bKeywrjWe
         io4ZvWf/oyJh2GJKLjCerZ9XDDM1+YR8ho2IKOd05rjlpA1fTgaF2iLy/FzT+dz9mCuR
         lqM3AF9JO54G55r979k5j1B9Rd2iFj9/PnQIF9PU3VNa01ohOF2xi/pJdammC/y6bJ+3
         iskw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7KHt3jhWSyFf647hPzG7jA2vnIDhx7s/MYf0ogsUARU=;
        b=gQUDYvzSOlFe39hujV+pO9ibpWDYgqLqv/YOoj92NpFQk3WfDQi8rCS0T7Z6GpOz5c
         ySCVct4cQBJpWYan8ZFbtSjU1ZKuuC/c6d6p9oZr7FsPMmhBDO0hMjtrV7VmLxzD3RYJ
         RtnwgCMJ8dYUyd2InNYCRMDWtjaxiDr5qqjuJKLgckGEZdOjpqZmcREoBHOvJ+paNFXx
         RTMd6gN+nLI/jXYv2H45y4zgn73iW9JFkmtg5n6CzzOtpenQIyna7bjYLWUlzliNqPr+
         4f4oX1TXBYn7TnuFUbpwGoR4qnUy6N7cNIaZntNTSTHL3twcHRXBZ49zM9As9OKtx2H/
         RLgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318k78XDOsMM6fyCM7TSP0PKmhTPG2BZQtDQ62/zxl1Bz3mH/NY
	ato4ybGD/+okDr1fPuttaxk=
X-Google-Smtp-Source: ABdhPJy+DpK6Ui0qPTBSfHHqtTftv96semwEUWfNk1ox6RVWAwjyd/T91P4agaJJgw56vV1W5LQRpA==
X-Received: by 2002:a17:90a:a617:: with SMTP id c23mr5469607pjq.86.1591184550720;
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6845:: with SMTP id f5ls668203pln.8.gmail; Wed, 03
 Jun 2020 04:42:30 -0700 (PDT)
X-Received: by 2002:a17:90b:1955:: with SMTP id nk21mr5521115pjb.66.1591184550375;
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184550; cv=none;
        d=google.com; s=arc-20160816;
        b=JsQWi0/gDbktqUB7sa9nFwyBnhSh0rqZt4IWqf5AOmFP8O6JqdsZ0INKcdJNYrEsU5
         ZKWg12i9rHYn7eUpq61vguEgmp1T3ubDau9RLtDA95K93M/iLFwiQb4oSjt0bm/h9v6R
         bAZIeK7KI3HoBA0GWiYQFp3FuClN8MZpauAGtbmYGuR8W4ucvsMWCUT8duR9ps0U9mZ0
         TLs1Nsm49sYEdFcg9Cl0vvImKecbVj7Rbe0cZfeDigt2qbzZbslUzURHeo1UEt/70nie
         jpw6HiwyrMBWnZrB1N62gxUUHC5NjAqIoG4RctnOlw31lJWSRGfnpe5+/B7ymGuwFfqZ
         ZJHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=T+DOFpWbn6w2E0hTbTLLAKKN4dYF4a47Ffrg1miQE+s=;
        b=tRf94s43cSy0B7E7bOVuccbALcqFbQHmNu31Om3peOo6zuo/wRjHkTAVX7+dBrYxyE
         UagSZGz53fEWweMcYjcaxOdXONTMoqkcbTpq9Q2pHlvvdZYnDT5wHTJqMb8Uw61eYk/9
         llJCA6/WrWzLE7m9zNyuIDjH/sk4ODdLh/tgnpcgMQEGPSScIaXn6bpQZoooGOm/TGUW
         C6oz/OrXxBv/B5LtZlZboAEEM5OgFHvLm+f1mbyv79V/on9+oQlK5cNLfIDhNH3XXxVX
         TPb8NR4gok+k7GFQiJ+zMKQrFWZ/Xkfb+mTjO2KeutnIoNJygOgxFroyUcZwmZMcPbGE
         evqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=WlkGKt1M;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id b2si86864plz.5.2020.06.03.04.42.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmr-0005oU-FK; Wed, 03 Jun 2020 11:42:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B673230008D;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A62B0209C23E0; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114051.838509047@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:15 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com,
 Qian Cai <cai@lca.pw>
Subject: [PATCH 1/9] x86/entry: Fix irq_exit()
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=WlkGKt1M;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Because if you rename a function, you should also rename the users.

Fixes: b614345f52bc ("x86/entry: Clarify irq_{enter,exit}_rcu()")
Reported-by: Qian Cai <cai@lca.pw>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Tested-by: Qian Cai <cai@lca.pw>
Link: https://lkml.kernel.org/r/20200602150511.GH706478@hirez.programming.kicks-ass.net
---
 kernel/softirq.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/kernel/softirq.c
+++ b/kernel/softirq.c
@@ -438,7 +438,7 @@ void irq_exit_rcu(void)
  */
 void irq_exit(void)
 {
-	irq_exit_rcu();
+	__irq_exit_rcu();
 	rcu_irq_exit();
 	 /* must be last! */
 	lockdep_hardirq_exit();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114051.838509047%40infradead.org.
