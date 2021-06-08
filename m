Return-Path: <kasan-dev+bncBCV5TUXXRUIBBAXA72CQMGQEU7VSI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EB1339FE4F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jun 2021 19:59:31 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id t8-20020a05651c2048b029012eb794d268sf8320352ljo.14
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jun 2021 10:59:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623175170; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+DmN1UAA2qJL3JkFGjFGlC/z/KyTtSjb3pgSNjQFnCrybc0aX+F2rXcCkDn4eb54m
         avC1+44U6LbBSwqNxUUaaG96tq2UylvpyUFIYCQ1WDAawDSN0Vh/xr5E8K06vi/OoU/s
         BTzwh0mGtGzx4pLLKwcJBDB6OgexplNb6nKMJOwd7/udGbMGJaO6qfWoLRXcAhgrUB7X
         dSvjFleMjISXgjlQk6cBZyyzd/6/MbuPNeaaI3jnfOo5QlTVD6AOZ/eJtfOzymh7Jve8
         F6eSp2L8a1JNuxtKE4IwpFLJnFLC+fRzEMg4PowoBFW4SiL1QuX98yjYeGpZNP0GMcKH
         /6RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JMauNfuHqygaP057RWDYjYJ7W5cKIv83q4jGTvNlVNo=;
        b=E4pc7neLSRxALzpOuNqU9I29MnQXv9RzququInCbe3n1ig2Bdez1J0R/t2At+QcTfw
         lttLG3haqwbnFJOu0uDZSCVc4LpJfRbMun0RW13fJQ3jAc3nQYAulo0a9MT+pixBhgD6
         mfXda1XN/wCaUfeu9/Ia4VbXwKb6pqJneZtfYogQlpklnvz+wmpEJ7+yhUubrH5P4scL
         5wFVdKaq94m7iM5BPtYxqhSzzQU44jqQx8PDe8QFJ3CmBmPr4Jr7nVQxiiTpOiInALUl
         cuSDqOB8O5zVtsjI/lp1+JTUNqkl72+baw2bjteH5ze4wwOjxCxxVCsoTDir2z1R7kA+
         yaEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="K3hlsFJ/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JMauNfuHqygaP057RWDYjYJ7W5cKIv83q4jGTvNlVNo=;
        b=J6ASJn0Bxizco5p+q/vK0tUk9a+7CvbBt1ZYvZAhYvWZZBav2OjjPCAPk18F+TBsSN
         7ndo72NQbxpzmWe93eZL37pjpZ684yU4p+CUD7mC701wzFIvojtmfj5UQyvPSfX6kSCm
         414h51dh9gJc9rxerRW43bUnfy/VJhQEyaLLKnTWVOHIqYXkz1W5C3pWY2OkC8+yNa7D
         cqeAIG5oCFxXH+RGls3jnpQoGfi/rl9LQF4BHbThpBSM5fqdWx257cMSbxAiZfMhfHYt
         WTppiETtnqTMedNb5zR5ked8NmFm266I2/8i+G+yWMHLn4+cqnPxj7DN+sqT8IQ8DRs2
         G5tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JMauNfuHqygaP057RWDYjYJ7W5cKIv83q4jGTvNlVNo=;
        b=GBfsqVuaad4pgpKzYxfHgOd1nL9kWW79sPWCcctEofQLuDKQ5Jj7Crypw1XiyEdFWF
         muhwPd4FsZ4cXlcSlRQNummQLiEfXllqGvXWiVlPCCNu0EoUwKNtMNrV+9ZRq42Mrybg
         9tjjah57B1nrfWOa/Qz4I0QyqXXMIouGV16Cn7mW3No06bZRBUa3ulp1ygv+Kr7ZlZ/B
         D6aXk+Z+ydgQqM1XjU1iG7YlAet1B8qZ9WxH8w7gvGM0jkB7WVb7l6OyN/W+FBSJQm4p
         3LZDpq+YXOr5YxINE4s3gjph1schQI05XE4bStqiWMUCykPzXzB0R4TnYf9nhi+Yooti
         RTxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Rgjzc9FnB8P++ywpJ4mSNCtEONqzQzSIfTVzRwIW/XwoVfwpA
	NvO/DS8zGnq8K1FUYI06pcQ=
X-Google-Smtp-Source: ABdhPJwUm1GZvXLo0dujyLWzanf0jMxJYxhBcIBeaDod5YlO+4AqFS7PFUBlXe8r5MmAVyU23fztfg==
X-Received: by 2002:a2e:5c87:: with SMTP id q129mr19022890ljb.161.1623175170831;
        Tue, 08 Jun 2021 10:59:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f94:: with SMTP id x20ls1501258lfa.0.gmail; Tue,
 08 Jun 2021 10:59:29 -0700 (PDT)
X-Received: by 2002:a19:c357:: with SMTP id t84mr16200147lff.25.1623175169822;
        Tue, 08 Jun 2021 10:59:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623175169; cv=none;
        d=google.com; s=arc-20160816;
        b=gBLS6tyw0ovGHtUOQdCv5tfliebO+vMYDxlCK6ybvDBEVJyXyWInhS/WIeEgTJHTAu
         bX7iNQDLr5PJjfQW/mX8778F7GCDb3f1ykeu+fV2bWQ6/xA7S9SCPJL5R8FXPlpaZfXP
         3g/JsebSmQC/6+PnODsGg5abFS2JIrom7ov5uw98qb7kQXznP9J+u50t8JcvCoevJSdA
         fzGdHDJU+o4KO2NQIKym83YVcJ7tZRG19naP8J2NEvCOP7y1UPVIzNldUQAVKgZdr+sJ
         615KGGADnWqUVR3QNSE4tbmULcecVf6FXwEbLgN97YlPQNyeOB9SHjz5aFE7gpj/F624
         7E2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kEDBey//uODOhAAOZPxn7gDKkNRZBwUx1r7R/fxovBg=;
        b=tcZQj99Ioa8GZEl85hKXdUlw0M6hj6qTMqfNMACaWUclzih9MHAUIt8lqK0ETGzQUt
         jwAnJnXCGMDEsEstwdtqz/MgufD5gSiOBJPu+lGGkAYcqtzzOB5fbeRNnGgQQKJm99Xf
         bfgV4xPYAZ7f0mj5hbJEyDT01wBt0NsnAfNwpqh/SmmyXk9rH9Ku3DwTrnOogEIHoBrH
         B9td0w9aRUoXcNeL8Wrz1ebNWTWj9kyyN5Mgqbym+p5aOIXlTVpnlP8jPicROujYCezV
         bbt48s0HM5msHz0idmKZlda5Fkc1c/Nzz7TAZcmvc1SNbjt9IkggT37KGdDMjDFrjwyH
         SUng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="K3hlsFJ/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id d11si16347lfs.2.2021.06.08.10.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jun 2021 10:59:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1lqg0T-004pG6-Ad; Tue, 08 Jun 2021 17:59:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4AFF530018A;
	Tue,  8 Jun 2021 19:59:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 32B3E201DEF0B; Tue,  8 Jun 2021 19:59:23 +0200 (CEST)
Date: Tue, 8 Jun 2021 19:59:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: qiang.zhang@windriver.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	matthias.bgg@gmail.com, andreyknvl@google.com,
	akpm@linux-foundation.org, oleg@redhat.com,
	walter-zh.wu@mediatek.com, frederic@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH] irq_work: Make irq_work_queue() NMI-safe again
Message-ID: <YL+v+yMA1dZegUN9@hirez.programming.kicks-ass.net>
References: <20210331063202.28770-1-qiang.zhang@windriver.com>
 <YL+uBq8LzXXZsYVf@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YL+uBq8LzXXZsYVf@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="K3hlsFJ/";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jun 08, 2021 at 07:51:02PM +0200, Peter Zijlstra wrote:
> On Wed, Mar 31, 2021 at 02:32:02PM +0800, qiang.zhang@windriver.com wrote:
> 
> > @@ -70,6 +70,9 @@ bool irq_work_queue(struct irq_work *work)
> >  	if (!irq_work_claim(work))
> >  		return false;
> >  
> > +	/*record irq_work call stack in order to print it in KASAN reports*/
> > +	kasan_record_aux_stack(work);
> > +
> >  	/* Queue the entry and raise the IPI if needed. */
> >  	preempt_disable();
> >  	__irq_work_queue_local(work);
> 
> Thanks for the Cc :/ Also NAK.
> 
> I shall go revert this instantly. KASAN is not NMI safe, while
> irq_work_queue() is very carefully crafted to be exactly that.

The below goes in tip/perf/urgent ASAP.

---
Subject: irq_work: Make irq_work_queue() NMI-safe again
From: Peter Zijlstra <peterz@infradead.org>
Date: Tue Jun  8 19:54:15 CEST 2021

Someone carelessly put NMI unsafe code in irq_work_queue(), breaking
just about every single user. Also, someone has a terrible comment
style.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 kernel/irq_work.c |    3 ---
 1 file changed, 3 deletions(-)

--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -70,9 +70,6 @@ bool irq_work_queue(struct irq_work *wor
 	if (!irq_work_claim(work))
 		return false;
 
-	/*record irq_work call stack in order to print it in KASAN reports*/
-	kasan_record_aux_stack(work);
-
 	/* Queue the entry and raise the IPI if needed. */
 	preempt_disable();
 	__irq_work_queue_local(work);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YL%2Bv%2ByMA1dZegUN9%40hirez.programming.kicks-ass.net.
