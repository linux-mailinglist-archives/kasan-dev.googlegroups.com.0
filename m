Return-Path: <kasan-dev+bncBC5NVH6TWYJRBUM27DWAKGQEOT5UUKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id EA988D143F
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2019 18:39:46 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id r21sf738551uao.16
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2019 09:39:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570639185; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUKAJYpnXFtckZA5zbMjZLOseRWv1Y/Ev6KzU9JpNX9mwEQO3tf+aRoa2YXR//O8lC
         JFkChCS92k6EYIyrUEuxBYhKbOlb/bsiJTy6yOSqDnauUWX7GPdCOjIx9SMzWtUE4Eww
         3It9hGbFPuzqVLEL2GKm1PcSjTdNXEgW8DTvtHINyFbj5cInoOYOfEY5aZ0Z+IA36z5j
         rlw9HmcT4m7or9kIzTBmmvgoPwdw7/EbsaXXjglv25qWJRaNmy9fNtfwlUBEKzFfNa+c
         hi66W5rpPDRtzMx6KGAgXHdriSyXzOSz8XTH24mwz4vEK5aFn8SigMVppg7Mgyr4qlY/
         HTPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=tWugsatGrKD0Ay9dCmpfj6Gfsc0VktOfxqJWXR8GE9g=;
        b=NMQfOjjd1XN4kf+M2Ju+CtrVBSA+fIkYsZgPWwDtnqOl7w8NTQq6j67rlJ7aRjeDf2
         s+cN8KVfv4dSRP01KOrAiGIgiWhavkKd4rb/RFzJOwXmIOgHhb4KXGwH4vhXmiW8gOr8
         hx9MwbVb/76wYO3+H2iLKSJl3ukmsEILK3f0A0tbMCa3+lfqXYC+PzNYA2kXdyILZT/n
         az1sk4k7z3Y5lox9GS1w98kvdON1ElYYp3Z6P0IFteVfYXLhHwGJvfd1GOFbGn5WFbMS
         UAAIstXmhihq4kwRMsGKg08QM0we9c/gzp6SLaTZmduxtu/RU29rkSfA0WA+sSuwIc2M
         J/8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=k2ve4K34;
       spf=pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tWugsatGrKD0Ay9dCmpfj6Gfsc0VktOfxqJWXR8GE9g=;
        b=jM8xP+rviy+JBXJIGOSX4lAAyhQBJSU3cRzb/wd1DqID2Xd3RtuhZ6U2tZGvASU1bG
         4axS63S3OQW0ycE3BwABbD0TiD4fY0Rh7cA6phgid/XYnugGRG9ZvOVSINYBYfri7DEH
         zuP3/DiQqosxo+6sSErCqcMwAKvzAggvrZeFyUgkEu3pZRCVBuniLWs1Juz5sQOKpyxe
         vMu7HOda8n9mxVluhdAfWsZRbsFDY5i4z3Ry9pTpRWRidnk3DSoKv9z/eP4rUw0P2wNB
         TFGCm86zM/bOzWMv+w8hpcjuHyr5ZeAy+zy8fC8VDSNolJL2MM5lnwPNxdwpuXRkZRZJ
         DCNg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tWugsatGrKD0Ay9dCmpfj6Gfsc0VktOfxqJWXR8GE9g=;
        b=KeCwDQxFWIJEyosptGhKHUK6T9XEwzJ9aDDgWMDM5xBYDysmJPMSQP6qChTdMFpBpD
         0/+nLClMnI/IDBfZzEFkqiHHF4+zYnzhG/TP05m4vLVYn7nzSi7ByGI2SEpmMwp9Nygi
         RtkcmGgdeLA5ofoj8/PsmKAucm3c0GyqcxcLIzeJfToNljcQIsewmfOtad2IKUiShvI0
         pPhdv2KxikxWRZE5fS9SbvdE4Pdxz0raQyeYOwZgiInyfGU5cPEWR+XBDYk3uWiSNrrG
         K/QDopxyUIfPxrwVUjouxH5yH5dn3psjzqRN3iA5DpdSJM4wWpufdhTtsjoE2+FRZapi
         0kOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tWugsatGrKD0Ay9dCmpfj6Gfsc0VktOfxqJWXR8GE9g=;
        b=JGLCKcYJB+K2xaZk1rpbi87Z1FrhqsfzXDQjvTQAJS+ILGON6pwY9CT2grxHqlW03u
         QZcKpVeHQptAyDNLNihGyQZw2q02Z0FV2ZOx5svfWiXrO70v+wfgNZKE/z99w/ToFEMP
         6hBLblKQE4U3b70MIwqFgIwO3f+WLMfGm5znZSyz+zqxCgVFoFor7j4t80vmfW+6vEgt
         rpK+YgUY7sA6WXixk4qwhhdJINODitERIi9thzkG02U0nztDQ9RS9FUit3gVjFjVN2tn
         w86Y8/siF2BXfgSKBNyTYKl00UiXNAl0E4VwKfQam74El3F1GvzdpOOkOI8XneH6LnrV
         HHjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU5d/2YbZVrjZIyL2vZdoIUjHFzzbMlarZxO1NHbgJM+PbXRdhU
	ETt3TsTvlS0gV4PQcjNlLPA=
X-Google-Smtp-Source: APXvYqy+BlixLj9kLmV90pmufUKulZCFGFuJgYluj0eju1Zqb56I8dJeeAn0ZarK5FRVvO3r1eN0vw==
X-Received: by 2002:a05:6102:1251:: with SMTP id p17mr2462618vsg.141.1570639185796;
        Wed, 09 Oct 2019 09:39:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:35e8:: with SMTP id u37ls43279uad.10.gmail; Wed, 09 Oct
 2019 09:39:45 -0700 (PDT)
X-Received: by 2002:ab0:3090:: with SMTP id h16mr2607314ual.59.1570639185344;
        Wed, 09 Oct 2019 09:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570639185; cv=none;
        d=google.com; s=arc-20160816;
        b=ltc3LL7rj7BdA8u8K2Rq/z9dhzssqfF2ZX0qC5gjUTi1/P8k/ITD/pKmTQQ1kSvuEa
         ZBtPAOJ2wCksGa2sdD1wzSwqD57eLHAs6+QsOaMUsUzUiyY7NLlnXS89wbF9pVs53fyS
         +MIp/lthxSWopISWHpEX17nUU9R02tFgv3Qd+GHJ54oDfV7jFqSoRU4cLYSntaXhcO1E
         VP7v6bzKoZcW4CE3tXz4k1r89cKmQtf/5F1ws+QWzRwCfolWPNwqGkeXkJBzcFw/8tiq
         GaeyWKbBCCg68DZOZaMQRydUGiVyxK6ahJxeSl01jZWEtppeAAKNm5myiRH4cvt8fm4V
         tcQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=iTXErS40hwDITsEWC+0LMux5phAFBMz4ZCrgGz4WsI0=;
        b=MKhXvibJgJfQhKYuJW+Uvjtmx70TSbXhYuXyWd96uG4bhzMKZMTkqO6MQLQQpiy9rV
         8SCvM05honXWqd6lf4NfQrTWkWXdflUZZgicnmRS3axdEYM4eGyhkT255ClzgdsCpylm
         djzw6J1+ow5K1WyjQTiSU+XjDBujtKZZfw7iIMs15XnIIGwFnbcU6RzMcB5mCHEWi/VD
         T1XaETLvzHj1RD5tnq7YaEGI8nnRMpmmrAoVwAJRjrQunFtK1vzt2QpVGmH4lgeraORH
         u/M7SSefejNQ2QsoGh3jDxZVuATbiASjbr1y/pCnJ/LanRD026uqB+y8mF/p9uVu6fGF
         KHEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=k2ve4K34;
       spf=pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id 136si211603vkx.4.2019.10.09.09.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2019 09:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id s17so1306421plp.6
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2019 09:39:45 -0700 (PDT)
X-Received: by 2002:a17:902:a717:: with SMTP id w23mr4184536plq.27.1570639184433;
        Wed, 09 Oct 2019 09:39:44 -0700 (PDT)
Received: from ?IPv6:2620:15c:2c1:200:55c7:81e6:c7d8:94b? ([2620:15c:2c1:200:55c7:81e6:c7d8:94b])
        by smtp.gmail.com with ESMTPSA id ce16sm2742759pjb.29.2019.10.09.09.39.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2019 09:39:43 -0700 (PDT)
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <eric.dumazet@gmail.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>,
 Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>,
 Andrea Parri <parri.andrea@gmail.com>, Alan Stern
 <stern@rowland.harvard.edu>,
 LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
 Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>,
 Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>,
 Luc Maranget <luc.maranget@inria.fr>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
 <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
 <CACT4Y+bdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q@mail.gmail.com>
 <CACT4Y+Z+rX_cvDLwkzCvmudR6brCNM-8yA+hx9V6nXe159tf6A@mail.gmail.com>
From: Eric Dumazet <eric.dumazet@gmail.com>
Message-ID: <a47cfff6-e5b7-bf05-fe42-73d9545f3ffb@gmail.com>
Date: Wed, 9 Oct 2019 09:39:42 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Z+rX_cvDLwkzCvmudR6brCNM-8yA+hx9V6nXe159tf6A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: eric.dumazet@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=k2ve4K34;       spf=pass
 (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 10/9/19 12:45 AM, Dmitry Vyukov wrote:
> On Sat, Oct 5, 2019 at 6:16 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Sat, Oct 5, 2019 at 2:58 AM Eric Dumazet <eric.dumazet@gmail.com> wrote:
>>>> This one is tricky. What I think we need to avoid is an onslaught of
>>>> patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
>>>> code being modified. My worry is that Joe Developer is eager to get their
>>>> first patch into the kernel, so runs this tool and starts spamming
>>>> maintainers with these things to the point that they start ignoring KCSAN
>>>> reports altogether because of the time they take up.
>>>>
>>>> I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
>>>> to have a comment describing the racy access, a bit like we do for memory
>>>> barriers. Another possibility would be to use atomic_t more widely if
>>>> there is genuine concurrency involved.
>>>>
>>>
>>> About READ_ONCE() and WRITE_ONCE(), we will probably need
>>>
>>> ADD_ONCE(var, value)  for arches that can implement the RMW in a single instruction.
>>>
>>> WRITE_ONCE(var, var + value) does not look pretty, and increases register pressure.
>>
>> FWIW modern compilers can handle this if we tell them what we are trying to do:
>>
>> void foo(int *p, int x)
>> {
>>     x += __atomic_load_n(p, __ATOMIC_RELAXED);
>>     __atomic_store_n(p, x, __ATOMIC_RELAXED);
>> }
>>
>> $ clang test.c -c -O2 && objdump -d test.o
>>
>> 0000000000000000 <foo>:
>>    0: 01 37                add    %esi,(%rdi)
>>    2: c3                    retq
>>
>> We can have syntactic sugar on top of this of course.
> 
> An interesting precedent come up in another KCSAN bug report. Namely,
> it may be reasonable for a compiler to use different optimization
> heuristics for concurrent and non-concurrent code. Consider there are
> some legal code transformations, but it's unclear if they are
> profitable or not. It may be the case that for non-concurrent code the
> expectation is that it's a profitable transformation, but for
> concurrent code it is not. So that may be another reason to
> communicate to compiler what we want to do, rather than trying to
> trick and play against each other. I've added the concrete example
> here:
> https://github.com/google/ktsan/wiki/READ_ONCE-and-WRITE_ONCE#it-may-improve-performance
> 

Note that for bit fields, READ_ONCE() wont work.

Concrete example in net/xfrm/xfrm_algo.c:xfrm_probe_algs(void)
...
if (aalg_list[i].available != status)
        aalg_list[i].available = status;
...
if (ealg_list[i].available != status)
        ealg_list[i].available = status;
...
if (calg_list[i].available != status)
        calg_list[i].available = status;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a47cfff6-e5b7-bf05-fe42-73d9545f3ffb%40gmail.com.
