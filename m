Return-Path: <kasan-dev+bncBAABBA7I2SFAMGQERAKVRTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E393A41D1FD
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 05:50:27 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id e7-20020a50d4c7000000b003d871ecccd8sf4711278edj.18
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 20:50:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632973827; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWToXj3IEMBiOu2ylbuB9HKPz7iRHMlegD++9oB6iGGN1kalG1aaMHvWN62XjN11BQ
         aOvwTl76bHiHX6dg+tCCv1jmclWHS0yAfo7ZaaPkZ6B4oq46ybhc0XpqmcO/IAc7fCbI
         jf/kMNBoCFeUhmDO8oGIMygLvXTO88meSwCXVrAiR3tH2wkCZSHfa+VP/VeZxM8sH0CU
         5OWTRn6kPcA6SvbKQFvIKE+rEgReCep2Piv8Or5WkklvnxbYx5TfJB+srVlXtO+Fjbjn
         ld2KvdJiyWbtxCiG0ytvm25pAUppMmZJ/YAyg1vkoUEGghxv6GhbDr5Q6Psc+jmP7E+i
         199g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:message-id:from:date:mime-version:sender:dkim-signature;
        bh=0duG2pl6dP7S9rLwsSoR3DZ1TBJKdmwSwDo+DXA8TvE=;
        b=YQ8Pw7X6YZ95VtwLI9uu6XXHWl2TVe/tUw8tdSkDh/M/xoyV52+u459QK2jr/BwL0m
         z29DK3jtdndoGbQx3h8Hg6jPT1aHZczKX0aRCM4ENhujKETY6s74CudISoUOLu+3DSg8
         e33H8wWPyQyw5jHQ72MZ+3eTrNSbXp9PGfgEJjRePysoCUvMLJQaCHwpIeMJU1/nHYZf
         8SoKAFqUfeI7dPp7WRkOoKXB9twNxp1ZIuKBLevGqIYuKNr3blop1IRAtkQEzWo/GcKK
         7Mb61ds+YHWHsXcPe4lDyuEf0YYHoMd3LavuSUzaFPtZV/jqn56MsPeEYFTcboAubvuw
         Df5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=USXVkRlc;
       spf=pass (google.com: domain of yanjun.zhu@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:from:message-id:subject:to:cc:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0duG2pl6dP7S9rLwsSoR3DZ1TBJKdmwSwDo+DXA8TvE=;
        b=Azb+ctjB2g+ODPDep8vetWwPL0bRR77oIjVPIeNvwMOsdxfvKKGXS0hTYOJn4oUJ9s
         qwJ9RO0PhE923w0SJAjo3ibzogEdNtbbN15279NeiiA3pIM8Kwsh+Haq5f+AsEJDLlyn
         Zy1K3aB9d5wQVlCx7rJpVEXrVJ1NOHrkBYkkrjMMfvGJRh4SZ3gy5spL51kKM/CtQZdq
         9ssOzpL2eSfcsQvCxWkrxHPlIV5hulgorbeduIWU1artXnWmLwdamASAuT0Jv9X5/H3W
         trMLEETl/W3u3P2+/NwLm9mq+fdL24LelsMY04MLvRsvlapfQH+OaTlPU6AKxXp43AOr
         DEfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:from:message-id:subject
         :to:cc:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0duG2pl6dP7S9rLwsSoR3DZ1TBJKdmwSwDo+DXA8TvE=;
        b=cu3Y/dZW/qvIciQXO3FTtGl43YIgSPxxgTsbGZvYn5fqCL0b3yXvunVrEI9Z/Gz/1+
         Cw7etf+En8e+VjTxXlS1QrDqw8M32lhYwXf0ZzVnUZkxvLkOtKX51hksEnFbMY2kP+lt
         pN+wmdAMi5YG/RxAuWJyEZ2R/6S7UPxElx6VgSHUTcG88uXxY/DLDuyVw2Hzp08rpiId
         H1pofoZe9R3W1tVJurEKDr6InwlbqWULwijrZySoAbvawPQ/s56/rrFJpfOExI0E0wt6
         b60p5iImDCfC/lJHU2GPCGDlxfXvd9nouegac9/FlVysS1cpnCEM8hjPxEhzGcF0Y7hv
         goeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uQTEpUKTjwFftAQsaGtLZLCEzqDWhDVDCvWHzKppFSvgkl/+6
	JvEQIon2I5oUuw/5yVjdVLc=
X-Google-Smtp-Source: ABdhPJyaurXIt/xO03S+s0D08pY+/10P6oajQlspQ5pbBUI3FX1enSBTILlWbHyL74GD9TmMTCMKqA==
X-Received: by 2002:a05:6402:1778:: with SMTP id da24mr4526479edb.398.1632973827695;
        Wed, 29 Sep 2021 20:50:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5941:: with SMTP id g1ls1923271ejr.10.gmail; Wed, 29
 Sep 2021 20:50:26 -0700 (PDT)
X-Received: by 2002:a17:906:a08a:: with SMTP id q10mr4072442ejy.100.1632973826885;
        Wed, 29 Sep 2021 20:50:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632973826; cv=none;
        d=google.com; s=arc-20160816;
        b=A1S5UMTqF0TwgbSR3RXwrOOepaHULH/ajxXybtVcOHb/WhtCC88ugzbmF4z7e4RaR/
         m94TdnYg4xCKMPPSIkWkjvsXsRBr4HlVB4oUM26OBipVxoEKEgKeTKNIJ6M8osGy+vjm
         AyV+AhnM5cvNH7zaHkUjGvf1uANeumA2G3YSLQBuO6wIdkbVcmn0gJtrYHTHGPv/8axb
         /BMKjTAEa/xYYESVfp6bNlihre5upDJfwpALxuVxRA+EE8a64lUBYJRR3en2Wcz7DDsD
         pGsATz1S1J15vzBXzWCCZPqBoYknDqjFWLaMTLsAlkGbs/lIQOaBDYASHFwK/m5zXZM7
         42Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:cc:to:subject:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=cLt1QOP0nG0RwyKQN81qWRsnvEYhlKdhKe+ZjaSzveE=;
        b=shjgbyl/ElKIiedbRwYGW5+eT6tgGoSaXXD15TeHqlF63n9R4Ku+RnjcqZCnpQuarB
         VbKYczzKvs+W+y6OssSXrOgM7rlG6Tw4lY8spr4JlNzrMNeMF90N4VupoCsRprBQLcua
         CZhzLtQmZusRmDCSBSPBxkGCsAjQg5Xc/CwUIABNfPukldaro0glz9NNLmKLcXACXwoC
         3vdH2FciEUunz3lVvHKhLc0m+1WzrBwAqHJ8yyai2DSQXY8IQnPMbj5Jh4ZLpGGUAgQF
         4kr1aak6It53t+n4UZcvymAjEQ2ydJIEIygQBVtjS2BQVvQrMWeX719ixsRniL22LwhN
         H7mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=USXVkRlc;
       spf=pass (google.com: domain of yanjun.zhu@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id r23si153218edy.3.2021.09.29.20.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 Sep 2021 20:50:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of yanjun.zhu@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
MIME-Version: 1.0
Date: Thu, 30 Sep 2021 03:50:25 +0000
Content-Type: text/plain; charset="UTF-8"
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: yanjun.zhu@linux.dev
Message-ID: <606c859b9df4c8a1019a7fbc3c13afcb@linux.dev>
Subject: Re: [PATCH 1/1] mm/kasan: avoid export __kasan_kmalloc
To: "Marco Elver" <elver@google.com>
Cc: ryabinin.a.a@gmail.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
In-Reply-To: <CANpmjNMKCmEHUnKz5rdUkd1HSuLj_S_vaMu+Hr7MuB79ghMERA@mail.gmail.com>
References: <CANpmjNMKCmEHUnKz5rdUkd1HSuLj_S_vaMu+Hr7MuB79ghMERA@mail.gmail.com>
 <20210929234929.857611-1-yanjun.zhu@linux.dev>
 <YVRfQDK0bZwJdmik@elver.google.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: yanjun.zhu@linux.dev
X-Original-Sender: yanjun.zhu@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=USXVkRlc;       spf=pass
 (google.com: domain of yanjun.zhu@linux.dev designates 2001:41d0:2:aacc:: as
 permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

September 29, 2021 8:45 PM, "Marco Elver" <elver@google.com> wrote:

> On Wed, 29 Sept 2021 at 14:42, Marco Elver <elver@google.com> wrote:
> 
>> On Wed, Sep 29, 2021 at 07:49PM -0400, yanjun.zhu@linux.dev wrote:
>> From: Zhu Yanjun <yanjun.zhu@linux.dev>
>> 
>> Since the function __kasan_kmalloc is only used in kasan module,
>> remove EXPORT_SYMBOL to this function.
>> 
>> This is incorrect, see below.
>> 
>> @@ -521,7 +521,6 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void
>> *object
>> {
>> return ____kasan_kmalloc(cache, object, size, flags);
>> }
>> -EXPORT_SYMBOL(__kasan_kmalloc);
>> 
>> Sorry, but this will break all users of kmalloc() with KASAN on if
>> !TRACING:
> 
> *module users.
> 
> An allmodconfig but with CONFIG_TRACING=n will probably show you the problem.

Follow your advice, I changed CONFIG_TRACING=n in .config. Then I run "make -jxx modules".
But CONFIG_TRACING is changed to y. 
So what you mentioned does not appear.

Zhu Yanjun

> 
>> __always_inline kmalloc() include/linux/slab.h
>> -> __always_inline kmem_cache_alloc_trace() include/linux/slab.h
>> -> __always_inline kasan_kmalloc() include/linux/kasan.h
>> -> __kasan_kmalloc() mm/kasan/common.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/606c859b9df4c8a1019a7fbc3c13afcb%40linux.dev.
