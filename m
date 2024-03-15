Return-Path: <kasan-dev+bncBCM3H26GVIOBBEXQ2GXQMGQEKHISBYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FCD787D133
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 17:32:20 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2218da55d89sf2726092fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 09:32:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710520339; cv=pass;
        d=google.com; s=arc-20160816;
        b=MhV5U+QmSqZLFOhXqGyL37aLcvEeoPvT0IEq9Ys8y8396OiD5i4Gn/STPpeQThGVE8
         GsTZ9G7v1jkme4pNBf6GTqW+AKnMaks+QzhL5XClr6XmK/sH9CuBxQtL4L/dPLMQx/WJ
         VyTKs8V2S6R9rvp7Soh39ETBmxyrKAewFeZt+NsceHUq82Jt6ceGx+fXeYznVYjmy2B0
         ZIhP39ZD6YuntzfN3pNKN4tCfate21s5VlZUwbAhjFKe2XLjiSZa1PvWRekrqazdG4Vh
         JB6C2q+O7yZEgpwFBTj1bApvgJRkrnFtxawMj24B+6583haGnlty7qe7mZqgcfwMweOa
         Ui9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XekgYxvjfak7bF0xtETTfMPxFjhF7hDx0uka8ZTG8Bk=;
        fh=GbtZywSg+Dlx3MO1/CXs25ZZqOJVui9SuDqIj1q6/e4=;
        b=GvPnj8imy0m/IvaTQjzg0wgF08NhNo60m/pqz0m++aMwoymPX1JEn1bQ0nTrLaABML
         Lw22tiuohduHYzawaeCbeYYEbwOUnZPcdRJulQpCa9QS50LmSC6WC1TqOUm0rTM8y8x8
         YrkK/SG1KiRt7L9/uzLptrg0AlVwuAgkr1Wo/5TK7bYwOeVZwnps+D50AYjbPmehWyfg
         s8936IFVI3thGN4jRiNrKb1EXOGL/Qh6nvh1ZKLWk+huhhTtZobVSIhGj4ZbviivxjBY
         TlB5Y/QcYsf3bi/KAZgmlmPpBgpfCDk/tslWTIvOodxTpQ9tf241GlfZu9QZlkiibqNm
         kJmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sexsV4ds;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710520339; x=1711125139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XekgYxvjfak7bF0xtETTfMPxFjhF7hDx0uka8ZTG8Bk=;
        b=oqLWkYgi0a3q6nOH1YyYp+sL/pv2r9x3/lb3gGEOeGd9LN+cbOLkwrFi/JN4reAEo/
         qAikeesVxF763GEsP/p6iuvQcSUNaTohKNsLcOypsM04eADjyRCf5dz5iO4sjuaLpqjl
         4L4blxwFj2hxAWBA5HTFVECxTwiUInjcvrIqWHmv8q/3ui3XsCE6x1YXXDBFDCZKi3Bb
         9cvKDkeT73qdn9zhs1ZfG8OeTKVsQz8L899uY/wIOjtH4N3/CKbXhVvnli1F+swtl8I4
         kibsiaQ4tQz6QQkKT6foBMQityg+6yqGdZ55OIu7us2w3nvvLYBhPIQ5F+xdBsNd1x/T
         oXKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710520339; x=1711125139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XekgYxvjfak7bF0xtETTfMPxFjhF7hDx0uka8ZTG8Bk=;
        b=Zg/xVy3k7jHM46H9Fx+gD9RrPWS154B7KDiiLSRsrq+kBQcLVFRWrFa2jeyHtJT8lO
         GsbSZuuLJ4TJCZYShN6x17zGu93uQ+DjRr8n6syqUrteoGI+FgszWH76OO6nUKgI/jH2
         JRqawY78pvxmH+mWKKnZ7A3lya/sOIPsaO83iVnK7qUgWjSw4WvStA1HHvQ0vG5clFpN
         aPWK9ItRaItv6bgVr8ZWsFlsd104Um9LbO8IQf7NZlxeeDk9SieF3UXkijuvL/4klZe4
         YGoVpWx49bsxAuDeBMUCSRWDl0APcyUffAGKJGtpqZRHaUPVb7q2Ij8m1czOSKCWjL0z
         7qkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNl+QIpcZM91YXdvTmpWzjCwbo4Jl57l8QOYXwWRbiOLhCeB1PFbNPIMCHA5dF0vVVbI2EZtN/sfqowLbObi4SSZ1Oq8o/Kg==
X-Gm-Message-State: AOJu0Yw2KjueJwmDxu1xU2N6LwQ22m6ISBh2a48W0Tv/mzi0m3qGRcvi
	OzgxwdUoE6wjv65BJvK7r3PDZfq5mfqwGW3hHTOaFgAtPXpVqiNB
X-Google-Smtp-Source: AGHT+IF0Xn21gffMwvvs4Nvslmjk6bGznxyAXt15Dg+ih6CeI7rD3lh7pyD3Y2L9V0cVwhYS2Wx1LQ==
X-Received: by 2002:a05:6870:241a:b0:21e:b096:2494 with SMTP id n26-20020a056870241a00b0021eb0962494mr4696979oap.50.1710520338943;
        Fri, 15 Mar 2024 09:32:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8549:b0:222:4483:33e with SMTP id
 w9-20020a056870854900b002224483033els1516707oaj.2.-pod-prod-06-us; Fri, 15
 Mar 2024 09:32:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGZH0d+r+iSIhmIuYlTHBdIIBQbeWBYamf3r+claM0BnZhVaEDkXkiAdyp839x5hZOkRJ6bCNzXe2dYKUtLYDc1bGpWJiyMJSawg==
X-Received: by 2002:a05:6808:159b:b0:3c3:7c09:9562 with SMTP id t27-20020a056808159b00b003c37c099562mr881984oiw.18.1710520337407;
        Fri, 15 Mar 2024 09:32:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710520337; cv=none;
        d=google.com; s=arc-20160816;
        b=MvAUzDNGK0uWj/iXMglNOg9rJRzRmWBr8tPR55u4Ttu7w3WPyj9UfkpMNGY3dKHtmF
         AyMhkm0W+ZBqVOi5BtGyJnb58awdCFX0MPUdvIylROIOs211u+LzJP4VeePKTCh14MDY
         2hBBdj5n7ZfRomf6E6uoWtDRNF5D4ImvCRGEjr3kYt2WgVFwznVG0dSXvGQAmbGvGuXp
         Tjc68kpdu2gz2uTH/z34d2MoNq1kLPvJxwwOIAL8Te4z4H400/5r82THpsXXEodQ35xx
         757lj5WW2Zxr9EDUy8P+JKX8PBde1HIeUSirLGMg/brN/vLEnEZU4jLmujQoQ//qXPRV
         FYlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YsVfEyh+PeyjprJYlAXtRWWK3GSAClwznohLSbdhhlw=;
        fh=u7Gq0ttLk/tRGDCAtTZaHqNjI1f8CGnnv2zXvR9Q1FE=;
        b=As5ylkVUZOxc3s0L6FUuqh/GMKy33HmkaUu8N8X9M6E7+qbmWnNmN32AycS5/hKcXW
         mvF18x+HWGO/Q+BJsnwTsFpWM8H3wJ1cxHHxiD2ME2V3hTc+ERiBLVh7J8yqXcRRlFg6
         iQtND81zqntTV6Xgu+2RZIuTFczAa8Lik+F4UJkxZvtkWvdC6oyzn8Fvs7lqRvrcqXQP
         l26VNW1kOie1W/80gacrTtUVrYaKr/hN6RDJZCCM7OSdON2yMP3i0tKfWI9HanSMI7Nm
         fwmerR3QuycRd4uEpJ5nmmRqjfYNBcqp+aupda48Omft2h3PJDCvRuXozJm/tOpUdFzG
         h3hA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sexsV4ds;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id e131-20020a256989000000b00dcd2dd6bba7si288418ybc.1.2024.03.15.09.32.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Mar 2024 09:32:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 42FFt4G6023912;
	Fri, 15 Mar 2024 16:32:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wvsd08g06-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 15 Mar 2024 16:32:13 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 42FGGswF014915;
	Fri, 15 Mar 2024 16:32:12 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3wvsd08g02-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 15 Mar 2024 16:32:12 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 42FDbpcJ015492;
	Fri, 15 Mar 2024 16:32:11 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ws2g0d32e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 15 Mar 2024 16:32:11 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 42FGW7Os25625236
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 15 Mar 2024 16:32:10 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D9E9520043;
	Fri, 15 Mar 2024 16:32:07 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 00C5E20040;
	Fri, 15 Mar 2024 16:32:07 +0000 (GMT)
Received: from heavy (unknown [9.179.26.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 15 Mar 2024 16:32:06 +0000 (GMT)
Date: Fri, 15 Mar 2024 17:32:05 +0100
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Mark Rutland <mark.rutland@arm.com>, Changbin Du <changbin.du@huawei.com>
Cc: Ingo Molnar <mingo@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
        Peter Zijlstra <peterz@infradead.org>,
        Juri Lelli <juri.lelli@redhat.com>,
        Vincent Guittot <vincent.guittot@linaro.org>,
        Dietmar Eggemann <dietmar.eggemann@arm.com>,
        Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>,
        Mel Gorman <mgorman@suse.de>,
        Daniel Bristot de Oliveira <bristot@redhat.com>,
        Valentin Schneider <vschneid@redhat.com>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, Alexander Potapenko <glider@google.com>,
        linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>
Subject: Re: [PATCH] mm: kmsan: fix instrumentation recursion on preempt_count
Message-ID: <lisylv2horoqxszuajysz6gp5nv4pkfhtdehi7wkp3oidao6dj@djh3zzri56dt>
References: <20240311112330.372158-1-changbin.du@huawei.com>
 <Ze7uJUynNXDjLmmn@FVFF77S0Q05N>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ze7uJUynNXDjLmmn@FVFF77S0Q05N>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: viS-32uWKrtprKrxz8TdP1dZPeC3-Lyr
X-Proofpoint-ORIG-GUID: oIJbDiMm3TdMoKCHl9gu2j7Eoj6QY3c7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-03-15_03,2024-03-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 phishscore=0 malwarescore=0 suspectscore=0 adultscore=0 bulkscore=0
 priorityscore=1501 clxscore=1011 spamscore=0 mlxlogscore=922
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2403150134
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sexsV4ds;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Mar 11, 2024 at 11:42:29AM +0000, Mark Rutland wrote:
> On Mon, Mar 11, 2024 at 07:23:30PM +0800, Changbin Du wrote:
> > This disables msan check for preempt_count_{add,sub} to fix a
> > instrumentation recursion issue on preempt_count:
> > 
> >   __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() ->
> > 	preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > 
> > With this fix, I was able to run kmsan kernel with:
> >   o CONFIG_DEBUG_KMEMLEAK=n
> >   o CONFIG_KFENCE=n
> >   o CONFIG_LOCKDEP=n
> > 
> > KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> > LOCKDEP still introduces instrumenting recursions issue. But these are
> > other issues expected to be fixed.
> > 
> > Cc: Marco Elver <elver@google.com>
> > Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > ---
> >  kernel/sched/core.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> > index 9116bcc90346..5b63bb98e60a 100644
> > --- a/kernel/sched/core.c
> > +++ b/kernel/sched/core.c
> > @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
> >  	}
> >  }
> >  
> > -void preempt_count_add(int val)
> > +void __no_kmsan_checks preempt_count_add(int val)
> >  {
> >  #ifdef CONFIG_DEBUG_PREEMPT
> >  	/*
> > @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
> >  		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
> >  }
> 
> What prevents a larger loop via one of the calles of preempt_count_{add,sub}()
> 
> For example, via preempt_latency_{start,stop}() ?
> 
> ... or via some *other* instrumentation that might be placed in those?
> 
> I suspect we should be using noinstr or __always_inline in a bunch of places to
> clean this up properly.
> 
> Mark.

Hi,

I tried the patch with the ftrace testsuite, and this uncovered another
loop, as predicted here:

preempt_count_add():int3
  function_trace_call()
    __msan_metadata_ptr_for_load_8()
      kmsan_get_shadow_origin_ptr()
        kmsan_get_metadata()
          virt_to_page_or_null()
            preempt_count_add()

Best regards,
Ilya

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/lisylv2horoqxszuajysz6gp5nv4pkfhtdehi7wkp3oidao6dj%40djh3zzri56dt.
