Return-Path: <kasan-dev+bncBAABBLUTQWJQMGQEQU4OD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 46127509F58
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 14:10:24 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id g5-20020a62f945000000b0050578328060sf2927682pfm.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 05:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650543023; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z2w0Pisls0DC4n0GjKJfwY2qDeW2byE0OWsc44vLjMEpW6TaiZpJQidDeH2B+vj7JB
         ck0H5u5BcM1RIcruxpS6+2YYoo9+9GiPbpFEtnSOmxRBve99Ly8Wme2FSgVqdOQ6PBV9
         Fh0Loiv7eG+d7HNyj8PlFvHLYVzqBdzHIMYWlziqt2DLPQWV6/f8yPjy/ibGc4uH94/g
         fK/GzSs53OhH+c8CMvX2Jv92z+o0pE0/Wu3qa8Y4h6YnDrz4becS0lGHV3vFmuDucQ5B
         ZQ6fyDNc/KsdH7cwd8VQ6qmsH0KgGS6iJBsNjBkSMk3+Vg3z6+W6E7ou2pdLKTfj7uIS
         TAFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=K3q09j1TbAwJNaBSaLQH59Ju5v3AxmIiRsaH3oTdJss=;
        b=jhKVgy11qb5JKUrTG2B+T52OdDix+AqBxGnwrtgBEbOYbtK96ON3dLOYALQzlgbrGL
         vzrnZj1LdiWjKGogvWFh1CYQ+R7KoD7WRaoD4GJIJscJ3Ipn8KnNTkfdRnKD3JDutsxY
         HRKmZZsn1jvKpqoxoDFxER5Ufr3S2wfUByDNrcEEwaOHk48l/k4MhosEBEpsvnTf1jch
         lF8mQnw27UuYIh7pfwTaN/tV2c7wBA4l5GYsw8A7u4rQd4C4a6VN5DD/gjspBe0OL3Vb
         NH7PlHDX9fq9SHaqVsLT9SIXJFds3uorsmmTvp9g7hxb8j/8w0jFpFwIGTgZ8rLqIp+O
         Zv6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=K3q09j1TbAwJNaBSaLQH59Ju5v3AxmIiRsaH3oTdJss=;
        b=GZRln4TjW5+nEK7/Y+1ZVFAzDQCMK0Vgu2zqOs+ljp43jnAv9THfBarL6qHqlMqQ+O
         qOjLIZ0pPqkghAbz/hdpenegZyoY1mu2sIAeHg82wcZ9DIEdf4jlGuLG+1UbwIG/FCma
         L5OgjIyZprVAUSGGhjKzgto+VF6LNb57jsrAjk+8ELjw1tYB6Vu+Kd3XWpj1Z2w4mboX
         m1LHkJk5FZiyluAALfKw2mumo0ugehwG3DG9ei9WFbpPis5TXcnQC3dy8sO6NX9EImru
         +qGi/pJwC9pRvSe8gJrbeSHrO9YAgRmd9scfoxEJaCh1Z8jgn5wBPNec8Jucn0rSCXeI
         S6fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K3q09j1TbAwJNaBSaLQH59Ju5v3AxmIiRsaH3oTdJss=;
        b=RONNlaAeNvOkhh8jAynSArbgBqkJ3+ljqXocell9hqS0JStzWLzxb+14X5KNIMTbZR
         MSpc+/JeWpuXiwxi3AbbnL4fS0K5MuzpRzQ+eI175O6SUVdA559JLEYehZKhmLh03e+h
         Mvgcv5N/c7C3m5FYhZZRGnjiIvbk9rgwjv+sX9k0U0AvQA7B2GHKfNPvGK+PMFKeWJ85
         hKNMNWFpOEGKuIccej3qGcV5oPKqsfyPltqvnOxqbNBPpnoqEGwMbxCtv28L4YaGIgK+
         kznlvye9BbXi3JdMTqkXxB563ty2whiwx9olFpjv7RBS0Y5Bi80eidUcbyvAAx7BOdIp
         NT4w==
X-Gm-Message-State: AOAM530mk/BID9FUOqVQGQsR5IKVHgGefWTx/X0uY4E+Vm0RGXw/N/rq
	HoyEIqogHM5IZWnvykOoHIs=
X-Google-Smtp-Source: ABdhPJy5x1FVi15vuRNSfLb2b8Sl5hZxIp/ZxnT1wmbw2XuR4S7GsMHgEBZ658vuA/+9CHOABHqCZQ==
X-Received: by 2002:a17:903:11c9:b0:154:be2d:eb9 with SMTP id q9-20020a17090311c900b00154be2d0eb9mr25135157plh.91.1650543022678;
        Thu, 21 Apr 2022 05:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f96:b0:1cb:abf5:517e with SMTP id
 o22-20020a17090a9f9600b001cbabf5517els4823648pjp.1.gmail; Thu, 21 Apr 2022
 05:10:22 -0700 (PDT)
X-Received: by 2002:a17:902:820f:b0:158:c308:d4c5 with SMTP id x15-20020a170902820f00b00158c308d4c5mr25318300pln.155.1650543022171;
        Thu, 21 Apr 2022 05:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650543022; cv=none;
        d=google.com; s=arc-20160816;
        b=CzQZat1cRIgevxY+0zBNryCTwneolKCkd+p6MuOivfen7eFMnHETJJ5JSbInC8OAQY
         Ys5xhMcVDJMshWqKFaqe+pMtgO4hxM/BbyUAt/hB1WexQMGrIZ4EvHKQ3mz69wWbX7oo
         snuv5L52CS3GkpbkNWdwQntRGv2DmB6YZqawO6v03OpApfBdJyq3/ql/4dpikpiB5tSA
         wlRLLwdKjexUWjPTPqb+2YWovnR7p6WXq8u57emlUl+sW9So/b5vAA3JDL0WGb/KxRgC
         Cj7k6d7sZwuqWHBvnsL4uVKy4G7y64vXYwmPBdgrP4beNJka2804SPud2aNDcx2wyrLM
         ad8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ZLa3mj1BafjI6Pfi/3QbYDXE16oVRf/GNCONyAPEwGs=;
        b=PDAhmOEujHqRspQXL5WyYd/VJsok6naYPeolyv3YoVRyNKV9ZXhIhWJXzUdJ9WNK/x
         hUodvK3ed24y3xJMwVZMfQnd3k62MYsnp4h3ZIxZi6932RPpZ6SDCYtAXCYnDN4wmBwD
         OMTsgelWzN41Q4HrCRCFRaJU3hP8WurL+EqsCPlTt2Wh+CJANSoC6qtotxE3m7c+bpcA
         xMABG+fCLYXVL3cpYOKMWjSNNaDgAZok+G+albMbcoSYSLR9J+NIL9GnWKMTGcGtanxo
         aKazy2e5eUGoGBn1duRMrzDHmI5KLaLJdN9RPp4Fqz0U7IzDmgpqodXZ5kmBfao8cxOM
         qxsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id q20-20020a170902edd400b0014f3d55ede2si344923plk.2.2022.04.21.05.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 05:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi100020.china.huawei.com (unknown [172.30.72.54])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4Kkbv119BkzfZXb;
	Thu, 21 Apr 2022 20:09:33 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100020.china.huawei.com (7.221.188.48) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 20:10:19 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 20:10:19 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <elver@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Date: Thu, 21 Apr 2022 20:10:18 +0800
Message-ID: <20220421121018.60860-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <CAG_fn=Xs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug@mail.gmail.com>
References: <CAG_fn=Xs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Shaobo Huang <huangshaobo6@huawei.com>
Reply-To: Shaobo Huang <huangshaobo6@huawei.com>
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

> > From: huangshaobo <huangshaobo6@huawei.com>
> >
> > when writing out of bounds to the red zone, it can only be detected at
> > kfree. However, there were many scenarios before kfree that caused this
> > out-of-bounds write to not be detected. Therefore, it is necessary to
> > provide a method for actively detecting out-of-bounds writing to the red
> > zone, so that users can actively detect, and can be detected in the
> > system reboot or panic.
> >
> >
> After having analyzed a couple of KFENCE memory corruption reports in the
> wild, I have doubts that this approach will be helpful.
> 
> Note that KFENCE knows nothing about the memory access that performs the
> actual corruption.
> 
> It's rather easy to investigate corruptions of short-living objects, e.g.
> those that are allocated and freed within the same function. In that case,
> one can examine the region of the code between these two events and try to
> understand what exactly caused the corruption.
> 
> But for long-living objects checked at panic/reboot we'll effectively have
> only the allocation stack and will have to check all the places where the
> corrupted object was potentially used.
> Most of the time, such reports won't be actionable.
 
The detection mechanism of kfence is probabilistic. It is not easy to find a bug.
It is a pity to catch a bug without reporting it. and the cost of panic detection
is not large, so panic detection is still valuable.
 
> > for example, if the application memory is out of bounds and written to
> > the red zone in the kfence object, the system suddenly panics, and the
> > following log can be seen during system reset:
> > BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70
[...]

thanks,
ShaoBo Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421121018.60860-1-huangshaobo6%40huawei.com.
