Return-Path: <kasan-dev+bncBCV5TUXXRUIBBW6PYHYQKGQEWZGJENI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7734114BE24
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 17:57:00 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id dr18sf6821130qvb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 08:57:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580230619; cv=pass;
        d=google.com; s=arc-20160816;
        b=uOL7wSZYYhr5VpsoQ/BsEi0xH4KtOqGU8ECoZJZRL8QpvaGlojlzRWb/x81nghu35x
         tCyQLiYwRUoVWJD9XSaWJsJy1sg0FM3pqRa64/cgRBKkUp4gzuhqnrns3z0uueFUA5d5
         l61r9Aca4nGpTaNHiHJciQ19RKxmxjZ9L0yN1YOPxyFbVrRinynhUDsHQOYjwkQVCGkm
         nhkRYhqV5l5B9tpbJojQ5uuJCkGjejjXvjF49rYDarBWNmCnwu6j/D9DCjDZPtfoc9ib
         6bfujd0LE13yInAOfRtKa4/4qRJ0m+B5FanAj011i2NS36fD0277cAhF0uHoBnDUyZf2
         bMGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=p6Zo84jBOCCM0Syxduk6VCpvWL3ubqiKM+MaQWAZD/0=;
        b=Dw844wBhfFrOO9X23x2K285433rc3j067Nk5BTEUaUqWhffNJ8hiiDpbqfLknd05kf
         69SUrNI6HrK0nC6+HOPza9E1/7sMbLeXIT5cJIpnoM++OC7/2FLhgUpUCqr8OaKeDtKm
         2KQXh/5QMgzJb7fusEhoCXGSNFUAqz2FeD/Q337Z12TAlcAWR+KzCxq2wQaaGDwwazeJ
         x2Hxm5I/Hxbztupt+6LTsGYQJkEjhIyDLOR8f3g07jvwGI0TAEDw+xo/2GudUUDj6gl/
         0pbXwtXBUOzRv25LZR2hujcQqHCWImRvOt0AYPLyOlAAr2tEuTCusJ2rkcIsp7aYX0SX
         BADA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=NUg4BVZs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p6Zo84jBOCCM0Syxduk6VCpvWL3ubqiKM+MaQWAZD/0=;
        b=FFQdm4QCUxpS8jczm0TsJ/wAu1iWaH424EknDqVG+/5zo+35MjyWcJ40jcSgr9rbLN
         rzOMByacZpmNOBIJLOhmy11OXYHwRhJKM1qK9FatVpykMzzCYOAm+fo84LqVDFuzptJw
         HBZd7MdPKzJXdimaG5kL3PDqX/m11S4yWYPcnbdFxcZa3MSWxj/JMoea2Afm4XS6WEr7
         wEbQQJAL7YF/JdexZVm06eVA7BAdq6YVTpniYM0RwXBMkGVtCCNbCIMSMMzpvnUwyLEg
         Q22Q4sBFgxQXKyquU1FqpMfl6lpL73Gp3iObnQg6BuMVT/c3jNmZcHYHmrknQU5A1YCc
         v1kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p6Zo84jBOCCM0Syxduk6VCpvWL3ubqiKM+MaQWAZD/0=;
        b=F8jr747rebtyvzAC5khZTBPcRrYRwG88/FGv3KP6MqH1f4Xabtg/mA2z1GJYcjmJIW
         Fv1G/MLeEuP0l1W7dQxjCaKJlFblM1CDDtwSQjLHwp/PKuTWdJydfXfx0KdSmZhTIBQX
         jf4FmYZ1DPZBFp6BtGJjUvVrGHvwBipOYghpYr+KXn3PDyNnpWBsF0Iv0VTRIVxnwBJq
         67ngqt/EvAbiKEurf58CGLvTO03aocGAC+DaiPqS0r4b3puPGhZQ7ad0a8Yo0ie5b/9g
         hBYH8EUU/e/KDpZmz77gcXUpn2K/B2oYL2dhL77+xnBT7XenCPG/nyJPk9NRs+YmXB89
         247Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU82AsNaaJsa/C3rlOQ4cmZQeHeJnOgkka5YJ7X9EwnwZoie2w6
	AbLGqiJr1wPWfL2C5qYwpIY=
X-Google-Smtp-Source: APXvYqz1lTfSzu2ck1a3J0Ej9pq8+ejjTgdPAdxP8Y2XMZ5haKdJrS6VNDg0yp2v5WnsXN70kPBUPA==
X-Received: by 2002:a05:6214:118d:: with SMTP id t13mr22670665qvv.5.1580230619440;
        Tue, 28 Jan 2020 08:56:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:321:: with SMTP id j1ls476042qvu.6.gmail; Tue, 28
 Jan 2020 08:56:59 -0800 (PST)
X-Received: by 2002:a05:6214:20c:: with SMTP id i12mr23480595qvt.48.1580230618962;
        Tue, 28 Jan 2020 08:56:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580230618; cv=none;
        d=google.com; s=arc-20160816;
        b=ctOv4jrdaslZBlHOKSI/XpQErTXJwX3p4LwBbn8QiWlDnI946hQ6KvpWl6eZx9BmR5
         joPNCPQfXA7TA9Ju3m1EALThh71P2E76RTRONlm7UqI8nrvCTH4Br4H8U6raitd98OK7
         jKJmuAqb//A3PsOBB+gYaSssMEjuijLIGA3HPpJTDpmPRqpN1VmomOWfqIcNXGJ/gcHc
         eecHE+yrL8fgUvOBEn5hAUlEsz4cyNVZcWPMURsFIRYHp6N6xptoYPSSm/dfDdQwUJwJ
         jUQ7RlMUyhwHdI8kH53BY23ILSbOWnJY20GrE70MXcOzM42rL2vVIszKn7lAQ/b+Yrmp
         Rd5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xqLkdksTAn4mILhz/FZa+hmKnpwus5eIvV60Ofg9aS8=;
        b=Fbjh6fL4ZmYwrworV7lxDoXqnb8sMWDc114XVgyQqmeIup0sKbVqjlRggaFIC5Wxwk
         wg56OYZCQl2DAEfQjpzByV2A58nQBbdilW5KVwNLj5TQ101YYays3J3Wq4rhZaygTfYR
         yMCJgVs5ZGp32oydWh0yhidZh0ZYOr5NjxahUVmyTaHGl17NUSHhXhhvA9Fgq+OWdJOE
         tMoY4zmvy3gLwlAMNfbdrvF5VJQNLjqRZr/87WZ2fgNQERF+iCrdsWbh1hA6yJj8jzW1
         cD43jw7KTAPvsQKb2dcIf9LXY1KX+k0I23IxRQq8W/P0AMaPRIG7HwcPS+uOSjOIzx58
         xhzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=NUg4BVZs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id l18si528732qtb.4.2020.01.28.08.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jan 2020 08:56:58 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iwUAa-0001KE-Ju; Tue, 28 Jan 2020 16:56:56 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 96E16302524;
	Tue, 28 Jan 2020 17:55:12 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0CBB3201F06F7; Tue, 28 Jan 2020 17:56:55 +0100 (CET)
Date: Tue, 28 Jan 2020 17:56:55 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>, Will Deacon <will@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	"paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200128165655.GM14914@hirez.programming.kicks-ass.net>
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=NUg4BVZs;
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

On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:

> > Marco, any thought on improving KCSAN for this to reduce the false
> > positives?
> 
> Define 'false positive'.

I'll use it where the code as written is correct while the tool
complains about it.

> From what I can tell, all 'false positives' that have come up are data
> races where the consequences on the behaviour of the code is
> inconsequential. In other words, all of them would require
> understanding of the intended logic of the code, and understanding if
> the worst possible outcome of a data race changes the behaviour of the
> code in such a way that we may end up with an erroneously behaving
> system.
> 
> As I have said before, KCSAN (or any data race detector) by definition
> only works at the language level. Any semantic analysis, beyond simple
> rules (such as ignore same-value stores) and annotations, is simply
> impossible since the tool can't know about the logic that the
> programmer intended.
> 
> That being said, if there are simple rules (like ignore same-value
> stores) or other minimal annotations that can help reduce such 'false
> positives', more than happy to add them.

OK, so KCSAN knows about same-value-stores? If so, that ->cpu =
smp_processor_id() case really doesn't need annotation, right?

> What to do about osq_lock here? If people agree that no further
> annotations are wanted, and the reasoning above concludes there are no
> bugs, we can blacklist the file. That would, however, miss new data
> races in future.

I'm still hoping to convince you that the other case is one of those
'simple-rules' too :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200128165655.GM14914%40hirez.programming.kicks-ass.net.
