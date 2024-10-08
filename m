Return-Path: <kasan-dev+bncBAABBWVBSO4AMGQERSHLQVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 068C9993EAF
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 08:27:40 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6cb25c3c532sf33830086d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 23:27:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728368859; cv=pass;
        d=google.com; s=arc-20240605;
        b=gT2vY7ln3nrAoLVbqBci1YHFnfLZLNQhkLannIHWPbj1K9JgQTYU6Kv/1mjxQs9L2E
         3F0TE/hPCrSrZry6S7aT+5l2lkxBj3kalqrFrNSMUucqX3HWhoo1tQjt9evMCjkRJae1
         Aohv9VahWkiFR+oAHi7ug04LevQ2pupq8ldAag9nTmhcu3cpusETcpSwKHc6mzot3W+2
         lf7/iRKBEmd2MOZWpbTUP48RGNUqphHspOtECdmAw2bKx17yfiAK+3/MxxeuAOKSYzZe
         gDQhCncpZQkoeNa7lUxRZO7ZSGauDnCNOpoJJ2G0R0NnoqAYmkLhD3HEXs+42FTIQ6NQ
         Ru3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SaMAfI17p4prpaJVmJKfeyLhuUas0H4DqmM7EIQfuQE=;
        fh=K6leThCWIdrWQge3qLRl+xzpDBEt5jFND4VTBvBD2aI=;
        b=bIJU1U3nCAu98SWUd48LQ1A6hqtp6uuuOwjgVg9hNL4HWQKhJuWV/Fq65+dFc5AG1c
         yUZ1m1oCuK1s4OZ870j0KyKdNc/xhkuXf3yIg0ZgrsSLDZHxG9EFO/uRprxlYSyYbRZz
         iJjweW9sDJsT36mt4vDL1hY99ifGk+MQ1NM5IDtEvMtolRbV2gmjObomKb96PqheCySU
         e34YLMN6koUW5Ye+uUJB+J/JZ89Mq87F43TvNePvpil63NGlLPVc8895GB7Us0/oyCGm
         XwlwmD1OYSyeOofYYvGu9GgRDcFoxuIghxPxM/Ksr0H8REFrxSkeu7gNrmKGnDRXuc1H
         CKWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=cvKhxu3f;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.2 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728368859; x=1728973659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SaMAfI17p4prpaJVmJKfeyLhuUas0H4DqmM7EIQfuQE=;
        b=Psc5Zxmdt3kmT7XLpHdu1pwmBoNRCWVOptLwJbfasQnwnyGnADK1bWsRnvYyXP5O/Q
         un6U/aWRib/lAUxrbcnWM5HnIJQg5Ms/d2b2KgzRrnp1na8/z9rDaZLI8O9u4QVPbMS0
         LGUQ862aTXeZJzqcY62jAqxiU100o2brqcfm2WmbXNnLNDyWIhkGnRlnqjCIR4l/rFVK
         Lo7ULp13NFL3Sa2VTgfKdkgSVdskEGQJN/2gotBQHiCiE3QI73nadKvLmjMHAm5h9XcN
         JsIdpWMKI0kmGWLbz+zz/HbpO/UluSDG+RQTxDvwUHo26R6kQPL6jyKfsVX90/v9h4oR
         peLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728368859; x=1728973659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SaMAfI17p4prpaJVmJKfeyLhuUas0H4DqmM7EIQfuQE=;
        b=LjZvLkCxVFQTswG7D0ty3iWHz5aIWcte/BSVEFShyCZib96ho4FotiO7MtbFrPvmT8
         C30DneJdPbjvSD2fy2J4hQ4o+HbUIH1jT51rUlawHbj1Wz3UELzzoejH3AzNkdU2ig1M
         GgBldbfC5/tBlNHJyi6Ud2ppR38Y85L86g15y4uaU95EII1H7dideqkjqEYtr6yEs7yr
         Llb6VcIecoWdiju+yVm/fOZTRIwt3JDlXK4j9R4AtYrt7M7DRmjMVDfosZWbKOPkS7iZ
         nLVkZUWdIX2BEhUsgEVibnuDxXyqNKQYIfDA4HosC0HolZW4AWHYrex+q8uXSSXSIJpH
         7dbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUTbiOZMr1CHMZ2otugx6crkZvGenbpQb+PTXcZfgrqX6oTWBQoQn4iT6BinVDJo5VudY9Ag==@lfdr.de
X-Gm-Message-State: AOJu0Yzh0q3L35Mvc+N7eABwKnL0Avatz26E25OQbaeYlMmlZmVC073K
	1Zj1x5RxU064ekjncmrEc5g04jJsW7KSTlxaMWvXfAwKcIhOultv
X-Google-Smtp-Source: AGHT+IFZ2Kj1p8lG8ghk2ROW09T4FJjpc9zhdp9PgWEqbqTo3AG4+QGH4ssV9MCt/SvELLhfz9znhg==
X-Received: by 2002:a05:6214:3a03:b0:6cb:2aa7:3e4 with SMTP id 6a1803df08f44-6cb9a464affmr184074006d6.47.1728368858636;
        Mon, 07 Oct 2024 23:27:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c0b:b0:6cb:2dc5:6bb5 with SMTP id
 6a1803df08f44-6cb90136fc6ls24473826d6.2.-pod-prod-02-us; Mon, 07 Oct 2024
 23:27:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTiOJkXVMSYxOpvdzOsSFupr6BRhidGu172ykqM1duq8UlyN+/foE9uV0U42AYoWmM/1DZNRG/WBs=@googlegroups.com
X-Received: by 2002:a05:6122:1688:b0:50a:b604:2b9e with SMTP id 71dfb90a1353d-50c854b95fdmr11359951e0c.7.1728368857940;
        Mon, 07 Oct 2024 23:27:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728368857; cv=none;
        d=google.com; s=arc-20240605;
        b=fNUk9pF8t33jDcn2k1yHmuKMwmvTEwiQFNihbOsQKNLf6u1WYLkvKQqr/adNiHz6w5
         UrDywYej1BhToOa4eWMPbYCN5Yb/D+7YWOqZ6eHvGV90LUWhWCFiShZn6Ntddod9bTqB
         Z0a6NbO5fDuDd/Ma2mTnnud6pTMbFzZ58FEGOT5V1lEX0ec59rQepToFE1SP2oWJp8ED
         ZYc2ZON9Jf+zTgvMor+UCdc1MoldFBpO0uOI9l/2JFGnlz6bTjSAGrFZwGt4tdDnbslo
         qNmsgnAkGcZj0FrMnbME1KASk3GGqRdsCLuRH1+V7iUX+qxhjG4ZcG8qym3homAF9uAM
         YpVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cnM9ddcUZFZ+Luy5237hCVz5GR0zgN46TwtoqrzWf90=;
        fh=5be6bAz+XC8rVYemSSimNozjuqLpWKDyg7mXsZNrK8c=;
        b=kCXJHbDlv5SybMSEzHN7vU8UBq7yYZ7HfiZ7qaGKznxKPaem+poawvGGJYQvWx7+ZC
         mQoBG5Tbj7k8RQ7+yv6xLDqcPpzsBawiSSKaMySXvcTQTiS+22EvwZttN5GGprEwiybx
         UUuTcn4csoNulNL/Rl/+/Kdlc8SonQ8sChnJqiMaO7gziTiP1AIf/iqPOASaMEe5vLy/
         80sBQaWUbq7hu0D3sXcyLBs7qGjoK08vJMr8G6MaaGJ0MOX2cmG10mm7QHwWZI8cp1b5
         RefoNfOJO/a0v2UAzyFSlFlT7zFMpC59lkAYu0vtpPWAZ3+xkByRKZctC82HO52Jiiu8
         KBaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=cvKhxu3f;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.2 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [220.197.31.2])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-50c9aec6e54si512348e0c.5.2024.10.07.23.27.35
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2024 23:27:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.2 as permitted sender) client-ip=220.197.31.2;
Received: from localhost.localdomain (unknown [193.203.214.57])
	by gzga-smtp-mtada-g0-2 (Coremail) with SMTP id _____wBXT7+g0ARno_BXBg--.55594S4;
	Tue, 08 Oct 2024 14:26:41 +0800 (CST)
From: Ran Xiaokai <ranxiaokai627@163.com>
To: elver@google.com
Cc: dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	ran.xiaokai@zte.com.cn,
	ranxiaokai627@163.com,
	tglx@linutronix.de
Subject: Re: [PATCH 3/4] kcsan, debugfs: fix atomic sleep by converting spinlock_t to rcu lock
Date: Tue,  8 Oct 2024 06:26:39 +0000
Message-Id: <20241008062639.2632455-1-ranxiaokai627@163.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <ZvwDevIahZ5352mO@elver.google.com>
References: <ZvwDevIahZ5352mO@elver.google.com>
MIME-Version: 1.0
X-CM-TRANSID: _____wBXT7+g0ARno_BXBg--.55594S4
X-Coremail-Antispam: 1Uf129KBjvJXoW3WF1fWw13GFWkJF17JFWxCrg_yoWfJr1fpa
	43Ww1DtFyqvFy7Cr1DAry5Wr1rK34DXr17Za42kry7CFs0qrs5uw4S9r90g398ur1xAr4k
	XF4vqrn7Aws8AaDanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x0JUbjjDUUUUU=
X-Originating-IP: [193.203.214.57]
X-CM-SenderInfo: xudq5x5drntxqwsxqiywtou0bp/1tbiqR1yTGcEzZ9LIAAAsQ
X-Original-Sender: ranxiaokai627@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=cvKhxu3f;       spf=pass
 (google.com: domain of ranxiaokai627@163.com designates 220.197.31.2 as
 permitted sender) smtp.mailfrom=ranxiaokai627@163.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=163.com
Content-Type: text/plain; charset="UTF-8"
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

>> -	spin_lock_irqsave(&report_filterlist_lock, flags);
>> -	if (report_filterlist.used == 0)
>> +	rcu_read_lock();
>> +	list = rcu_dereference(rp_flist);
>> +
>> +	if (!list)
>> +		goto out;
>> +
>> +	if (list->used == 0)
>>  		goto out;
>>  
>>  	/* Sort array if it is unsorted, and then do a binary search. */
>> -	if (!report_filterlist.sorted) {
>> -		sort(report_filterlist.addrs, report_filterlist.used,
>> +	if (!list->sorted) {
>> +		sort(list->addrs, list->used,
>>  		     sizeof(unsigned long), cmp_filterlist_addrs, NULL);
>> -		report_filterlist.sorted = true;
>> +		list->sorted = true;
>>  	}
>
>This used to be under the report_filterlist_lock, but now there's no
>protection against this happening concurrently.
>
>Sure, at the moment, this is not a problem, because this function is
>only called under the report_lock which serializes it. Is that intended?
>
>> -	ret = !!bsearch(&func_addr, report_filterlist.addrs,
>> -			report_filterlist.used, sizeof(unsigned long),
>> +	ret = !!bsearch(&func_addr, list->addrs,
>> +			list->used, sizeof(unsigned long),
>>  			cmp_filterlist_addrs);
>> -	if (report_filterlist.whitelist)
>> +	if (list->whitelist)
>>  		ret = !ret;
>[...]
>> +
>> +	memcpy(new_list, old_list, sizeof(struct report_filterlist));
>> +	new_list->whitelist = whitelist;
>> +
>> +	rcu_assign_pointer(rp_flist, new_list);
>> +	synchronize_rcu();
>> +	kfree(old_list);
>
>Why not kfree_rcu()?
>
>> +out:
>> +	mutex_unlock(&rp_flist_mutex);
>> +	return ret;
>>  }
>[...]
>> +	} else {
>> +		new_addrs = kmalloc_array(new_list->size,
>> +					  sizeof(unsigned long), GFP_KERNEL);
>> +		if (new_addrs == NULL)
>> +			goto out_free;
>> +
>> +		memcpy(new_addrs, old_list->addrs,
>> +				old_list->size * sizeof(unsigned long));
>> +		new_list->addrs = new_addrs;
>>  	}
>
>Wait, for every insertion it ends up copying the list now? That's very
>wasteful.
>
>In general, this solution seems overly complex, esp. the part where it
>ends up copying the whole list on _every_ insertion.
>
>If the whole point is to avoid kmalloc() under the lock, we can do
>something much simpler.
>
>Please test the patch below - it's much simpler, and in the common case
>I expect it to rarely throw away the preemptive allocation done outside
>the critical section because concurrent insertions by the user should be
>rarely done.

I have tested this, it works.
Yes, this patch is much simpler. 
Another consideration for me to convert the spinlock to a RCU lock was that
this would reduce the irq-latency when kcsan_skip_report_debugfs() called from
hard-irq context, but as you said, insertions by the user should not be a frequent 
operation, this should not be a problem. 

>Thanks,
>-- Marco
>
>------ >8 ------
>
>From: Marco Elver <elver@google.com>
>Date: Tue, 1 Oct 2024 16:00:45 +0200
>Subject: [PATCH] kcsan: turn report_filterlist_lock into a raw_spinlock
>
><tbd... please test>
>
>Reported-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
>Signed-off-by: Marco Elver <elver@google.com>
>---
> kernel/kcsan/debugfs.c | 76 +++++++++++++++++++++---------------------
> 1 file changed, 38 insertions(+), 38 deletions(-)
>
>diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
>index 1d1d1b0e4248..5ffb6cc5298b 100644
>--- a/kernel/kcsan/debugfs.c
>+++ b/kernel/kcsan/debugfs.c
>@@ -46,14 +46,8 @@ static struct {
> 	int		used;		/* number of elements used */
> 	bool		sorted;		/* if elements are sorted */
> 	bool		whitelist;	/* if list is a blacklist or whitelist */
>-} report_filterlist = {
>-	.addrs		= NULL,
>-	.size		= 8,		/* small initial size */
>-	.used		= 0,
>-	.sorted		= false,
>-	.whitelist	= false,	/* default is blacklist */
>-};
>-static DEFINE_SPINLOCK(report_filterlist_lock);
>+} report_filterlist;
>+static DEFINE_RAW_SPINLOCK(report_filterlist_lock);
> 
> /*
>  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
>@@ -110,7 +104,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
> 		return false;
> 	func_addr -= offset; /* Get function start */
> 
>-	spin_lock_irqsave(&report_filterlist_lock, flags);
>+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
> 	if (report_filterlist.used == 0)
> 		goto out;
> 
>@@ -127,7 +121,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
> 		ret = !ret;
> 
> out:
>-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
> 	return ret;
> }
> 
>@@ -135,9 +129,9 @@ static void set_report_filterlist_whitelist(bool whitelist)
> {
> 	unsigned long flags;
> 
>-	spin_lock_irqsave(&report_filterlist_lock, flags);
>+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
> 	report_filterlist.whitelist = whitelist;
>-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
> }
> 
> /* Returns 0 on success, error-code otherwise. */
>@@ -145,6 +139,9 @@ static ssize_t insert_report_filterlist(const char *func)
> {
> 	unsigned long flags;
> 	unsigned long addr = kallsyms_lookup_name(func);
>+	unsigned long *delay_free = NULL;
>+	unsigned long *new_addrs = NULL;
>+	size_t new_size = 0;
> 	ssize_t ret = 0;
> 
> 	if (!addr) {
>@@ -152,32 +149,33 @@ static ssize_t insert_report_filterlist(const char *func)
> 		return -ENOENT;
> 	}
> 
>-	spin_lock_irqsave(&report_filterlist_lock, flags);
>+retry_alloc:
>+	/*
>+	 * Check if we need an allocation, and re-validate under the lock. Since
>+	 * the report_filterlist_lock is a raw, cannot allocate under the lock.
>+	 */
>+	if (data_race(report_filterlist.used == report_filterlist.size)) {
>+		new_size = (report_filterlist.size ?: 4) * 2;
>+		delay_free = new_addrs = kmalloc_array(new_size, sizeof(unsigned long), GFP_KERNEL);
>+		if (!new_addrs)
>+			return -ENOMEM;
>+	}
> 
>-	if (report_filterlist.addrs == NULL) {
>-		/* initial allocation */
>-		report_filterlist.addrs =
>-			kmalloc_array(report_filterlist.size,
>-				      sizeof(unsigned long), GFP_ATOMIC);
>-		if (report_filterlist.addrs == NULL) {
>-			ret = -ENOMEM;
>-			goto out;
>-		}
>-	} else if (report_filterlist.used == report_filterlist.size) {
>-		/* resize filterlist */
>-		size_t new_size = report_filterlist.size * 2;
>-		unsigned long *new_addrs =
>-			krealloc(report_filterlist.addrs,
>-				 new_size * sizeof(unsigned long), GFP_ATOMIC);
>-
>-		if (new_addrs == NULL) {
>-			/* leave filterlist itself untouched */
>-			ret = -ENOMEM;
>-			goto out;
>+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
>+	if (report_filterlist.used == report_filterlist.size) {
>+		/* Check we pre-allocated enough, and retry if not. */
>+		if (report_filterlist.used >= new_size) {
>+			raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+			kfree(new_addrs); /* kfree(NULL) is safe */
>+			delay_free = new_addrs = NULL;
>+			goto retry_alloc;
> 		}
> 
>+		if (report_filterlist.used)
>+			memcpy(new_addrs, report_filterlist.addrs, report_filterlist.used * sizeof(unsigned long));
>+		delay_free = report_filterlist.addrs; /* free the old list */
>+		report_filterlist.addrs = new_addrs;  /* switch to the new list */
> 		report_filterlist.size = new_size;
>-		report_filterlist.addrs = new_addrs;
> 	}
> 
> 	/* Note: deduplicating should be done in userspace. */
>@@ -185,8 +183,10 @@ static ssize_t insert_report_filterlist(const char *func)
> 		kallsyms_lookup_name(func);
> 	report_filterlist.sorted = false;
> 
>-out:
>-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+
>+	if (delay_free)
>+		kfree(delay_free);
> 
> 	return ret;
> }
>@@ -204,13 +204,13 @@ static int show_info(struct seq_file *file, void *v)
> 	}
> 
> 	/* show filter functions, and filter type */
>-	spin_lock_irqsave(&report_filterlist_lock, flags);
>+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
> 	seq_printf(file, "\n%s functions: %s\n",
> 		   report_filterlist.whitelist ? "whitelisted" : "blacklisted",
> 		   report_filterlist.used == 0 ? "none" : "");
> 	for (i = 0; i < report_filterlist.used; ++i)
> 		seq_printf(file, " %ps\n", (void *)report_filterlist.addrs[i]);
>-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
>+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
> 
> 	return 0;
> }
>-- 
>2.46.1.824.gd892dcdcdd-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241008062639.2632455-1-ranxiaokai627%40163.com.
