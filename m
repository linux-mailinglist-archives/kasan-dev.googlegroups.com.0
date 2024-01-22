Return-Path: <kasan-dev+bncBCMIZB7QWENRB2PHW6WQMGQEPLX464Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CDC6835A1F
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 05:49:47 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50e7ddf4dacsf1900918e87.1
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jan 2024 20:49:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705898987; cv=pass;
        d=google.com; s=arc-20160816;
        b=MzVqlrC7As4vdafl77cqKtdgMaHwjjb/aVFTiFMpCrIW7JG8Xm+SmtN0OHKJ666M45
         S8paoIZZas7ZWUNh9p18ZHq+54EOHjSjtqJqyAVjlePd8Tuj1z1aFeD1n9WnWTWWP0UC
         r7Gp31US8kuQi7oEsa7/wS1L2QqDM2qOLi6zrOse09aJPofrX8igQvfDS47zY3OGzRil
         T4bOjHpKE2rETQYbDMLsTjU46ct2U7zHCVTYQ4DG4ipwOfG1TPY+mBB6p+vrVr1YfMMh
         RTGc8VfT10X/ro72Y9FaLFYrlJIgv3dUATkG94ldMbibjbiT0voJwlUa1N+GAQ72okVY
         /81g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c5zkSECJ0OfDzSVBWJPSDVFFwpmKXqVMRXkJkYIaZ9k=;
        fh=LmYkCFwU9EJZckSCWTerIBisMmVL+GPjQxMbEI0waDk=;
        b=F0TegtAag/k152l42ngJM1YeJ8roNg2JSjsXWPggzodiofv/CCrEBl6D8gabmRhlOM
         PmsaUWng9kTpeNco4OR3q0hPWWW+RuQTO/mGamdf/RlOQ+oLV7lRehLjOGA5LENkC4qo
         xDJgIdFWrz3M+/DKVpqkk8dPK2mI5aF2ccJGyOyK/sbKhfUsdN1fCrhjI7jflsaFyFtK
         xtqthGR2EXsdtL5gKKs95FgeIZfHf9mTFyybI/oX09B4rvkEMUPzrghQeWTW6nn+9x95
         0GJBbm/cBoFeGDM+ppp7q5IBdlLzv08X3L3Ed1gW4K34gVqWBXurB3wppBv6LkjqcJn+
         SK1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WV0E1geL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705898986; x=1706503786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c5zkSECJ0OfDzSVBWJPSDVFFwpmKXqVMRXkJkYIaZ9k=;
        b=dnPFbDMHKS7n57S/ukRQV8TR7qVX9dSRQJEsHe+Yday5nkHi5V8kMJCwY09GN1j8cu
         Q6vCZnwbO5KTo3d/jmryRZ1mKbtg7VO56yzy7S6s9lwhiKXvG7ufuNJ2Zea8g85zTCF6
         G1u14KDsmeBK9OGFk2Ms25Ei3NYcjRCGXv+kOC8p1VwWzLCC1LzXdRafIZkVZFSSr/1f
         KMYMAJaCR/d/c1QwWRo7IKo0uSOMQL5QlvcDigcEEJHE2vx3eoYBoDr9vuSMinplXpru
         ZmbH1Kg/dnZzqxAbW88/prJJlzmcMIBLdoSbYPHlVpFlWQVYu2lfeMVNbu5NCltKA9n1
         y3ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705898987; x=1706503787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c5zkSECJ0OfDzSVBWJPSDVFFwpmKXqVMRXkJkYIaZ9k=;
        b=ojB9BW5yTC6UjqLNChUtgMvEPSFHagdS4pIyv2agibQonQPqqn23ZGeXpq6CSGhPu9
         ZY3OHGKUv7DQuzfj9vcVHwfgGWsOfvmhysnYe8UcuDMt8hBlw5PAHZCl6e92j8yc7/sj
         JdyoQE2q/FVO/FTsOtuf/mGg72rufq98+RLWRKd41CdXGtHW7zkXPWoKil3Q62S/vXW2
         vdk+j3+HtHvxyFne51oDbzw9zNj7Aouo5mLbAltzcSa8oXjzIbaSCioeE0CG4J0Q26ec
         53cow44PNkTzzTv4XCnpPsTZwihNbo+PlihmHD68RqK2arb+3LvihgNzybxQzEbbDLv1
         NniQ==
X-Gm-Message-State: AOJu0YxPUYI9YH5M9KgibvTBvfXH2iHAy+raADXDIstC/iTpnNq+oy5N
	ZMCnOMVuCBtySI/9UJhyd0mnmpaUB9j4CwnqL3r5+VMsJl2TlESM
X-Google-Smtp-Source: AGHT+IEROTPg23f9bwKlRQxdNVDI1QMTZmgAudCQgTgqe4W9M6CmcBhLeezwXbyLiQSKc2pSoBNjqw==
X-Received: by 2002:a05:651c:222:b0:2cd:f639:e42b with SMTP id z2-20020a05651c022200b002cdf639e42bmr1291514ljn.22.1705898986225;
        Sun, 21 Jan 2024 20:49:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210c:b0:2cd:24e9:7305 with SMTP id
 a12-20020a05651c210c00b002cd24e97305ls892442ljq.2.-pod-prod-03-eu; Sun, 21
 Jan 2024 20:49:44 -0800 (PST)
X-Received: by 2002:a2e:9813:0:b0:2cc:eefc:20af with SMTP id a19-20020a2e9813000000b002cceefc20afmr1215134ljj.52.1705898983972;
        Sun, 21 Jan 2024 20:49:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705898983; cv=none;
        d=google.com; s=arc-20160816;
        b=ECJDwl8ALSltsIH5OszeH35lsyaBiCAtIK7UeDZJY+a13/+vgJdL+b2U+SZQ2uM+ss
         l3wXkNb4tUL9Z8JnSYxiXDEMdDr3gWwhX4yXD4iQAFBjd8cj9jRMsU4F+QAOsO5vKaOt
         8vcQ6Q/M0nIl/HAkn0H/zrWU1AUF+ssS5/quDAAgDNq7gHIeAtCkh5QzpXEpgjSSlXvG
         Uc8tky1zDf/w7FyBjvPoNTAAt8yRKuHiar/WuTIjUosFw6mea39IUoR8N2okCtxd+xdX
         s+I6yXiJWQguVRwrhBSF5pu1hc1ystNaUgJ9eGFwRUKSWd36vjovHK4CSjqf7Fb0I+sG
         CLLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v7lHM4FRzCJbagQaJUuF7i1/f1Gd/G/CT3X864K81zY=;
        fh=LmYkCFwU9EJZckSCWTerIBisMmVL+GPjQxMbEI0waDk=;
        b=ev5UdJP0WVzBSt5dikDwBcfFIeYPMU/N3r7YKppF1e2O65e+QUtOgKwWml5Lsxa/uV
         7vmc7pVdvAyIiGHurjoYetWzBNu/gT2Vs0YZvAKjIg3TdkPfEy81I2A0UOQLy9GJBnSm
         l4nPevE/4ca6Fzx9Spie1ZdFuZR3a2PFoPJ0+eEV89hvwYMO3MCz/O23HaKbHO/qMgdK
         NlrYVrM1O17BcpKR93/OjAByTlcaFnE4qlLA0leq1IISpQYBL0W7ArYkUYER/RoYIUzF
         IZAh+weNcivdmKy747gR05oRLL8vS9L7eOIo0OPlZD9+oTB8ZY43xg2FikD0XcN+nQX0
         eh3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WV0E1geL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id w25-20020a2e9999000000b002cd6347ba65si766305lji.5.2024.01.21.20.49.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Jan 2024 20:49:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-55c24a32bf4so3156a12.0
        for <kasan-dev@googlegroups.com>; Sun, 21 Jan 2024 20:49:43 -0800 (PST)
X-Received: by 2002:a05:6402:b50:b0:55c:5f2a:6091 with SMTP id
 bx16-20020a0564020b5000b0055c5f2a6091mr27edb.4.1705898983098; Sun, 21 Jan
 2024 20:49:43 -0800 (PST)
MIME-Version: 1.0
References: <20240118124109.37324-1-lizhe.67@bytedance.com>
In-Reply-To: <20240118124109.37324-1-lizhe.67@bytedance.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Jan 2024 05:49:29 +0100
Message-ID: <CACT4Y+Y8_7f7xxdkEdEMhqHZE5Nru2MMp9=hX6QU6PtdmXU32g@mail.gmail.com>
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
To: lizhe.67@bytedance.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, lizefan.x@bytedance.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WV0E1geL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 18 Jan 2024 at 13:41, <lizhe.67@bytedance.com> wrote:
>
> From: Li Zhe <lizhe.67@bytedance.com>
>
> 1. Problem
> ==========
> KASAN is a tools for detecting memory bugs like out-of-bounds and
> use-after-free. In Generic KASAN mode, it use shadow memory to record
> the accessible information of the memory. After we allocate a memory
> from kernel, the shadow memory corresponding to this memory will be
> marked as accessible.
> In our daily development, memory problems often occur. If a task
> accidentally modifies memory that does not belong to itself but has
> been allocated, some strange phenomena may occur. This kind of problem
> brings a lot of trouble to our development, and unluckily, this kind of
> problem cannot be captured by KASAN. This is because as long as the
> accessible information in shadow memory shows that the corresponding
> memory can be accessed, KASAN considers the memory access to be legal.
>
> 2. Solution
> ===========
> We solve this problem by introducing mem track feature base on KASAN
> with Generic KASAN mode. In the current kernel implementation, we use
> bits 0-2 of each shadow memory byte to store how many bytes in the 8
> byte memory corresponding to the shadow memory byte can be accessed.
> When a 8-byte-memory is inaccessible, the highest bit of its
> corresponding shadow memory value is 1. Therefore, the key idea is that
> we can use the currently unused four bits 3-6 in the shadow memory to
> record relevant track information. Which means, we can use one bit to
> track 2 bytes of memory. If the track bit of the shadow mem corresponding
> to a certain memory is 1, it means that the corresponding 2-byte memory
> is tracked. By adding this check logic to KASAN's callback function, we
> can use KASAN's ability to capture allocated memory corruption.
>
> 3. Simple usage
> ===========
> The first step is to mark the memory as tracked after the allocation is
> completed.
> The second step is to remove the tracked mark of the memory before the
> legal access process and re-mark the memory as tracked after finishing
> the legal access process.

KASAN already has a notion of memory poisoning/unpoisoning.
See kasan_unpoison_range function. We don't export kasan_poison_range,
but if you do local debuggng, you can export it locally.

> The first patch completes the implementation of the mem track, and the
> second patch provides an interface for using this facility, as well as
> a testcase for the interface.
>
> Li Zhe (2):
>   kasan: introduce mem track feature base on kasan
>   kasan: add mem track interface and its test cases
>
>  include/linux/kasan.h        |   5 +
>  lib/Kconfig.kasan            |   9 +
>  mm/kasan/generic.c           | 437 +++++++++++++++++++++++++++++++++--
>  mm/kasan/kasan_test_module.c |  26 +++
>  mm/kasan/report_generic.c    |   6 +
>  5 files changed, 467 insertions(+), 16 deletions(-)
>
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY8_7f7xxdkEdEMhqHZE5Nru2MMp9%3DhX6QU6PtdmXU32g%40mail.gmail.com.
