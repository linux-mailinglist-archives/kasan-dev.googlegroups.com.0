Return-Path: <kasan-dev+bncBC33FCGW2EDRBMOJ42BAMGQE7LYI3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C658A34598B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 09:20:01 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id p4sf1008811ljj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 01:20:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616487601; cv=pass;
        d=google.com; s=arc-20160816;
        b=y71raffX11jw0+VEDW/lz0Ia0AjuSnF4dkVERsD/zS/kVyG18CttTO2TQ8LI21RDyy
         0pK54Umn+nUXin9X/76mZSyLCoijPwzy6sDsVwa1sPN4vqpRyh0vPp/ncfflo3NySkw0
         kZmXf7KKkyll3IcorEHuqlZYlhNMFakLM/v+jxIzHUMQO1W0hD7kam/0cRZ8Of5Bza8W
         jymuD+oGepbX7qhi/fugUt4/i1dmlW9jisf4X7vsueB1tRx3GHMRaex/6IQ3dMSGEuXa
         54Pj+EulK4pXxowhhbphziZJmDJjVVDmQcUloNBMt+RQGhV3whRSOYW8tmGLWV47gj4s
         Pa3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=64RbRf8NS/DK6vLrvn7WimXR7rACaM8O9y+ZdvmWJ10=;
        b=LvJAr9ynlb2bKbxcDI/HVfvoBAEgqrXiAtIyCtw0IBnrZ5ERnA+3Fa5GRP/EZu3gvh
         i8ROpx5SUBqLk4YNoXq3+djq52jFef01HUfyK5kAf672NzOytREulZgIopsQqGxAXoei
         AKvOXhoc8vged16ufxnNwqge1kdetFZcIkBlNBDyMO9ileqTeyy8HYk5jrMvYT0nusj+
         rKdiO4DPWYw3yueoeQaDvMBUEpqw4RJA5DyQU72B0BSSrpzCrxDIpMtjlDaCjkhrRmBC
         XOz5APNYTmOOy/tPvxSX1Kp42ROkEvay4E9s6sQmYePaxfb025uSMxVC7uROP2OIW/LT
         5ppA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b="Tqf/j6Go";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 185.244.194.184 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=64RbRf8NS/DK6vLrvn7WimXR7rACaM8O9y+ZdvmWJ10=;
        b=ATefdBoAsiDWtR+DRKpoJuTZEroFAs/E40N+CAOqfZuEVTy1SDBHbxXpxwWLwnVfwS
         xG7h5+uAFngEDMQ4Ig+sDUAsYsYs1pd0Hb63Vq7/UV5YJY6jfoF8B09fWmZEArIVyV5Z
         OjDy4havP0uCPh74ojCsFKIQaLqOSf9EkGBG6d7XeqM9QzuWUSMupq3yUr2yYPVoJah1
         Zue1qRAxvnwIohras1bg8eV/lHDRXxmPp1b7PGitOV/AHaedeZhPh0zOlFssnOdbewMe
         9V7adAwgod10Zj16dJ6mHLLVMvudVrdr7rP8rk7osqzojlmjaUjQwTKFU9zXZ9uDyore
         00GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=64RbRf8NS/DK6vLrvn7WimXR7rACaM8O9y+ZdvmWJ10=;
        b=P6qNrca+GCHNwPZLt6Ll3DaCi/Nfo1sFSka2Jkc49zW8V/wTV5O6ktdnHL+MMkLGPg
         /6ycpN/GzzY8Ysw/lrBEsdgbOmc7EABkr5PH62pmiRuy2KDDkwYOxS3JWDg7ZYStzHE1
         7JM/Jx80gBL2EIcbIgPyuxuw1xBOpSHR0AA72EbmKXAidEGR4i39mJh5tEcWh0GiA3Uf
         u/VlKKmW9QsfJQ2+a+FiUUxylzvSrgKkcAHPZlFCUoVzgR3ulNxFSnMIpJeGyzXRnQ58
         9CCvHAHOm/kJYgqyJWuSDz8tMKkqevzl430wQfYYKXHO4L2b3woZxQzC1yOIJ0AGMdol
         mBOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324lt/Eyu7UiAWasra45zo1WqUxvDFvS/5wbDYrPnzEQBgeRoTn
	SbHl+OkhCd6bNAN12yu6XXM=
X-Google-Smtp-Source: ABdhPJxs9LZ9wIAGFILFJhI5AA8TzQXMBIonrPw1N4tAMQphyFjTP15z0OoAy5/Xfil10cJViKCqkg==
X-Received: by 2002:a2e:91c2:: with SMTP id u2mr2402255ljg.301.1616487601366;
        Tue, 23 Mar 2021 01:20:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9191:: with SMTP id f17ls2960333ljg.11.gmail; Tue, 23
 Mar 2021 01:20:00 -0700 (PDT)
X-Received: by 2002:a2e:b606:: with SMTP id r6mr2374719ljn.327.1616487600279;
        Tue, 23 Mar 2021 01:20:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616487600; cv=none;
        d=google.com; s=arc-20160816;
        b=g53vUiDPp8WNfesu/tD4Eo0EnsfWQQrS3g32iy6B8r6AsOuSyA5sIFnhdObSH45Ddj
         QjP5DC31bAxZaVR4cE3fkfuyx2p89aagG6Ojvm5Gi/RmIH4iPEo90wuhFdhSosAWkvQP
         4RLdGcnNApJveGveawCVB8xeAyU9VJMFlZZ3sMQiZ3JPultUjj+aaO5De569qqFQshvU
         w9WMVWxLmHiDvdsrdakkKGqYarWgxaxy8qvXfYiiO67q1NvDFwiraZrkJUUXU569pf5Z
         29LtTSNBOwRmAlrbihbrFiL4RfXpMvx6uO1byp+htxdJmsJlKXOFffOWrl6Qtt7xGTcv
         DguQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=DVZtG6cOo95PoGGBdDqWvTMXGoNbL3OhX0+8JITFxMo=;
        b=I0rYeYE8k6GwKQBCitcHigT13vsVjnl2T3UPyWBU+9aH4B+YXDmAHQbsr9B5MnrYmN
         imT8xNH4xDU2aqgPHiacHsjbQaQJdkDmd7tPXu/3HoWpyu2Baj5Hx6rqPBF+wsyyWuJv
         RaFdXSxpZeQTQEKGi/F7/Dq+g8NDunGlSpPuULLDHhvPIVlEjB65L6dV8VdRzuTyp214
         KXT4RvV4DgKZxXLK5p3T0EeVwkozB4saK2iyeH6DjmcTvRwDCQ7HjwNOHD4rBcO+aLw7
         3Barco583WSndqaHP8K+NaIVU35wzhD7rJP2w+lJ9L4drkSl4upSajjbiFNQ50Rvyhn5
         cYSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b="Tqf/j6Go";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 185.244.194.184 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [185.244.194.184])
        by gmr-mx.google.com with ESMTPS id z5si545680ljj.5.2021.03.23.01.19.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 01:19:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 185.244.194.184 as permitted sender) client-ip=185.244.194.184;
Received: from relay01-mors.netcup.net (localhost [127.0.0.1])
	by relay01-mors.netcup.net (Postfix) with ESMTPS id 4F4PRz1xJhz8tSG;
	Tue, 23 Mar 2021 09:19:59 +0100 (CET)
Received: from policy02-mors.netcup.net (unknown [46.38.225.35])
	by relay01-mors.netcup.net (Postfix) with ESMTPS id 4F4PRz1Wnnz8901;
	Tue, 23 Mar 2021 09:19:59 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at policy02-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.9
X-Spam-Level: 
X-Spam-Status: No, score=-2.9 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001, URIBL_BLOCKED=0.001]
	autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy02-mors.netcup.net (Postfix) with ESMTPS id 4F4PRt2j8Jz8t10;
	Tue, 23 Mar 2021 09:19:54 +0100 (CET)
Received: from [IPv6:2001:638:50d:132b::37] (chulak.cs.uni-dortmund.de [IPv6:2001:638:50d:132b::37])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id 20F73A166A;
	Tue, 23 Mar 2021 09:19:53 +0100 (CET)
Received-SPF: pass (mx2e12: connection is authenticated)
Subject: Re: [PATCH] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet
 <corbet@lwn.net>, Miguel Ojeda <ojeda@kernel.org>,
 Randy Dunlap <rdunlap@infradead.org>,
 Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Aleksandr Nogikh <nogikh@google.com>, Jakub Kicinski <kuba@kernel.org>,
 Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>,
 kasan-dev <kasan-dev@googlegroups.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>
References: <CACT4Y+bdXrFoL1Z_h5s+5YzPZiazkyr2koNvfw9xNYEM69TSvg@mail.gmail.com>
 <20210321184403.8833-1-info@alexander-lochmann.de>
 <CACT4Y+Z=d0WmcGV+Tt-g4G=XVDruxbpvOPJSAN6JZ1rXbOQ=2Q@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Message-ID: <3ccb3274-b179-99e1-a317-b8c176bdac8e@alexander-lochmann.de>
Date: Tue, 23 Mar 2021 09:19:52 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Z=d0WmcGV+Tt-g4G=XVDruxbpvOPJSAN6JZ1rXbOQ=2Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: de-DE
X-PPP-Message-ID: <161648759337.962.3256402245034528508@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: Kss/iMZsYNwjhJRgpnXIfPtQsPoSkXR8Dfz7pI9DUq3OasaLQGF4Q1NN
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b="Tqf/j6Go";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 185.244.194.184 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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



On 23.03.21 08:23, Dmitry Vyukov wrote:
>> diff --git a/kernel/kcov.c b/kernel/kcov.c
>> index 80bfe71bbe13..1f727043146a 100644
>> --- a/kernel/kcov.c
>> +++ b/kernel/kcov.c
>> @@ -24,6 +24,7 @@
>>  #include <linux/refcount.h>
>>  #include <linux/log2.h>
>>  #include <asm/setup.h>
>> +#include <asm/sections.h>
> 
> Is this for __always_inline?
> __always_inline is defined in include/linux/compiler_types.h.
> 
This is for the symbols marking start and end of the text segment
(_stext/_etext).
> 
>>
>>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>>
>> @@ -151,10 +152,8 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
>>         list_add(&area->list, &kcov_remote_areas);
>>  }
>>
>> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
>> +static __always_inline notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t, unsigned int *mode)
>>  {
>> -       unsigned int mode;
>> -
>>         /*
>>          * We are interested in code coverage as a function of a syscall inputs,
>>          * so we ignore code executed in interrupts, unless we are in a remote
>> @@ -162,7 +161,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>>          */
>>         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
>>                 return false;
>> -       mode = READ_ONCE(t->kcov_mode);
>> +       *mode = READ_ONCE(t->kcov_mode);
>>         /*
>>          * There is some code that runs in interrupts but for which
>>          * in_interrupt() returns false (e.g. preempt_schedule_irq()).
>> @@ -171,7 +170,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>>          * kcov_start().
>>          */
>>         barrier();
>> -       return mode == needed_mode;
>> +       return ((int)(*mode & (KCOV_IN_CTXSW | needed_mode))) > 0;
> 
> This logic and the rest of the patch looks good to me.
> 
> Thanks
Thx.
> 
>>  }
>>
>>  static notrace unsigned long canonicalize_ip(unsigned long ip)
>> @@ -191,18 +190,27 @@ void notrace __sanitizer_cov_trace_pc(void)
>>         struct task_struct *t;
>>         unsigned long *area;
>>         unsigned long ip = canonicalize_ip(_RET_IP_);
>> -       unsigned long pos;
>> +       unsigned long pos, idx;
>> +       unsigned int mode;
>>
>>         t = current;
>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t, &mode))
>>                 return;
>>
>>         area = t->kcov_area;
>> -       /* The first 64-bit word is the number of subsequent PCs. */
>> -       pos = READ_ONCE(area[0]) + 1;
>> -       if (likely(pos < t->kcov_size)) {
>> -               area[pos] = ip;
>> -               WRITE_ONCE(area[0], pos);
>> +       if (likely(mode == KCOV_MODE_TRACE_PC)) {
>> +               /* The first 64-bit word is the number of subsequent PCs. */
>> +               pos = READ_ONCE(area[0]) + 1;
>> +               if (likely(pos < t->kcov_size)) {
>> +                       area[pos] = ip;
>> +                       WRITE_ONCE(area[0], pos);
>> +               }
>> +       } else {
>> +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
>> +               pos = idx % BITS_PER_LONG;
>> +               idx /= BITS_PER_LONG;
>> +               if (likely(idx < t->kcov_size))
>> +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
>>         }
>>  }
>>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>> @@ -213,9 +221,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>>         struct task_struct *t;
>>         u64 *area;
>>         u64 count, start_index, end_pos, max_pos;
>> +       unsigned int mode;
>>
>>         t = current;
>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t, &mode))
>>                 return;
>>
>>         ip = canonicalize_ip(ip);
>> @@ -362,7 +371,7 @@ void kcov_task_init(struct task_struct *t)
>>  static void kcov_reset(struct kcov *kcov)
>>  {
>>         kcov->t = NULL;
>> -       kcov->mode = KCOV_MODE_INIT;
>> +       kcov->mode = KCOV_MODE_INIT_TRACE;
>>         kcov->remote = false;
>>         kcov->remote_size = 0;
>>         kcov->sequence++;
>> @@ -468,12 +477,13 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>>
>>         spin_lock_irqsave(&kcov->lock, flags);
>>         size = kcov->size * sizeof(unsigned long);
>> -       if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
>> +       if (kcov->mode & ~(KCOV_INIT_TRACE | KCOV_INIT_UNIQUE) || vma->vm_pgoff != 0 ||
>>             vma->vm_end - vma->vm_start != size) {
>>                 res = -EINVAL;
>>                 goto exit;
>>         }
>>         if (!kcov->area) {
>> +               kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
>>                 kcov->area = area;
>>                 vma->vm_flags |= VM_DONTEXPAND;
>>                 spin_unlock_irqrestore(&kcov->lock, flags);
>> @@ -515,6 +525,8 @@ static int kcov_get_mode(unsigned long arg)
>>  {
>>         if (arg == KCOV_TRACE_PC)
>>                 return KCOV_MODE_TRACE_PC;
>> +       else if (arg == KCOV_UNIQUE_PC)
>> +               return KCOV_MODE_UNIQUE_PC;
>>         else if (arg == KCOV_TRACE_CMP)
>>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>>                 return KCOV_MODE_TRACE_CMP;
>> @@ -562,12 +574,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>>  {
>>         struct task_struct *t;
>>         unsigned long size, unused;
>> -       int mode, i;
>> +       int mode, i, text_size, ret = 0;
>>         struct kcov_remote_arg *remote_arg;
>>         struct kcov_remote *remote;
>>         unsigned long flags;
>>
>>         switch (cmd) {
>> +       case KCOV_INIT_UNIQUE:
>> +               /* fallthrough here */
> 
> Looking at "git log --grep fallthrough", it seems that the modern way
> to say this is to use the fallthrough keyword.
> 
> Please run checkpatch, it shows a bunch of other warnings as well:
> 
> git diff HEAD^ | scripts/checkpatch.pl -
Yeah. I'll do that.

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ccb3274-b179-99e1-a317-b8c176bdac8e%40alexander-lochmann.de.
