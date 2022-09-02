Return-Path: <kasan-dev+bncBDR5N7WPRQGRBV56ZGMAMGQEFXE7PHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 641775AB8FE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 21:54:01 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-33dc390f26csf23409227b3.9
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 12:54:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662148440; cv=pass;
        d=google.com; s=arc-20160816;
        b=0PKY4eJ7YKW0AK2HjHRqoBH0Jrcui9/3aoDJoe1WDqYG77ui0EQUnTPf/jSpmhi6GF
         I+TYWPr0NxTqs6WliqRyGjo/hiLHhmA18rUR9O2xC9SZ5/YzVTmJrhiEyaJ3wMfYt2cs
         g19J7CqZ5R4+FPmvul8eOsvTU5A7zthpYfLrznUtZai+WH6C5K6P531Cg6I0FBNXvLxp
         0ptkZrrFh4/51VPAGR3ChX1X0iNbAs/+2yoJ3K2l7JHUT6sxbkPZhuc70xFFLtmbgsHH
         sZn8n0lxrDOcQ+4SV8qcWIhJIRnSsY04+I81374CRLoL3xWm6HTJzVFuCBpQlzIO+YSd
         JUhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Air62PqbKvH4eqjDNTuxIS1EfsIHE+Qd5Gh1A80Iee4=;
        b=Kojs4Xv8u9C3tPXkatSyiFStObWsYeQmo0XBfhcNCsW4lEAVh4iyW+PqiINZn9AKHx
         4p6A3nCe3Ce07iTKSw5yJ/w9MMgjBY2sS03MLvJsmxO7vkt6lmKUQZOAQPnW24dk06Gp
         jDh80+5JPOLxtxb6xHf7tjsKWS+TGmjw/tCAJFIHYfiROkB2O5dX2XR4RQgH3wF16itc
         W+KKBgT/xFc7sMkjXvnE+1LSjbhs3HuexxX2tEDBdOOTwq0mvRuDDZr6fiIPwr7HVrZ0
         DVU+xkYrdEU4kIhgq8fE7w7zvWOAoJ7+JQw+4Sya72cl41IE4mEduvJwt/8X0Ci9ugkw
         8nCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=4q1ObG8W;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=Air62PqbKvH4eqjDNTuxIS1EfsIHE+Qd5Gh1A80Iee4=;
        b=S5ai1205YeczvfsdPtevwUJXjy8h0ip8hGyU2GeLinhuWI7fvhNEe7miWo3PCTqvPw
         eurqP/er9R6s8pmNXUQS+Mz12ZfG6jBkCOom3E7SeHD3tbgZnMb9rc7SXgYsQXYFloEb
         nadK/rHbR+7KUvFbE+7EyocnYNZci7aRwBB2eIMowYv3X+uC8ouOZPxfJYAE01vPUy+B
         ZQv/dJV8dlyIY7neme1OpMjap/1GSYYqAFzY083W7nRuhuNP/z3pJeNW3iZYdsIj2ePD
         y1MCcCLUjM6Bqwnq/zu9K2qx4JaIV/lAlz+TLrJ9rB/csqz+FkskXkWFvOJOLatIOxVK
         p7yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=Air62PqbKvH4eqjDNTuxIS1EfsIHE+Qd5Gh1A80Iee4=;
        b=GhWNLjSEiQySEp1uuN+EF3VbEYvs4Wz8/xFvYJATlAtbYZ6GuVqGIu2L8HJD99kRnO
         1OgN6zFHX8DhlZpd+YYoyrnt+HPnjhGtR898j2MTOzpuykNdRXXamVdGWKTqnDgBVzbS
         RkXZUbhFsYg4/D60V5QOPrl3lBLUjgCguC0gImArQAj+/yzmhkuy3+bro8v8NYSht5DE
         6Ef6Shxcx6VwYewF/HZBtYbO53te7bgJ4LM41OVSZcv2qIiyxN+qzmzKDZVxUWqe4A2l
         XEDw9caCtSX3fmCooGNpj56mcIPWm9LCp2IMdjEjif7Q45btDWBGVk90FzxezuwCMIrs
         72Vw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0ggQwVSbCQ0jBI87EsJpKfZW6+77QIyu8MHOdoIiLyU40LkTmr
	V4QIOjzOxLEvaoDYgG6YwZ4=
X-Google-Smtp-Source: AA6agR4gHHss+VyFkfwlexJZhfQ/0HlP5Ehs5UQSdkopW+AGO6wGXo6BjHb25fCTQy7SZInz98PiTw==
X-Received: by 2002:a81:94e:0:b0:33d:bfb0:ff55 with SMTP id 75-20020a81094e000000b0033dbfb0ff55mr28315988ywj.322.1662148439933;
        Fri, 02 Sep 2022 12:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a187:0:b0:696:3e78:dce5 with SMTP id a7-20020a25a187000000b006963e78dce5ls3100752ybi.5.-pod-prod-gmail;
 Fri, 02 Sep 2022 12:53:59 -0700 (PDT)
X-Received: by 2002:a25:2d59:0:b0:696:2e34:bf29 with SMTP id s25-20020a252d59000000b006962e34bf29mr24371018ybe.525.1662148439310;
        Fri, 02 Sep 2022 12:53:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662148439; cv=none;
        d=google.com; s=arc-20160816;
        b=IlMMHBl/fdL0Lnku2OUD46R2ywa8e3p7CdjoNRTV+BCxx2TtjogwY2Kqpc1Ts0GKip
         JfuVj7ij8THh21i93kJj3SN9ehWRhx76S30c30H34NQz+MW9Yn7OJbBt/VTv4Kso/EFQ
         nbRTEiM62ypvTEc8hgdCRFjqqjRKhbEPc9/QO/+d8nKEgqPgT9+pR8EU1SXS8CkKba5s
         Q72VUcOlIu95BhJlSjsZDiphBh82WgQhd1KxoYE/gMN3NTQQWCML5x39kP2JcP9WPgZD
         fXN7iZRxqB8NZeWdGfwshaOwH28m72uxYcvxZRRxtMp2pmBA0QHQ1TOJVgU/Bcglgn2o
         ZgMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=BgSQRPeP2vU+fzfPkC5136xUIsrQV+zIPc0zX8WqYvQ=;
        b=y3LCFLG+40/kdensUU+gQvg1wvg8B3hvPGECdqLQFtRXrP/WirvffLUghf+fP44mwj
         SZ4odoyZ5R6PaXZJDhA7wU5QX25J3bB61oJO4GOQx+zVSdqt3Ng9Izqhlfdp5nYxofC9
         9O3qAmiDJyTlnu9Mgb9j3SW9KgmCjNqXR3j4k5fLAMm6sVZb+e3KLsOe970EmLu12WMq
         anq/PGIfuEHl1pq34n5ZcVS4wbzmisDXu50Pzu0pm3FfL8aQ6rzghXnL8QEVOkbFmtEh
         EWc6wOGGBgJiTAsuuhRS7vH25yXQXzaK2i1vrjUShVUYDnR4HiPjIGRumuwlo/Bj9He+
         hwpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=4q1ObG8W;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id m2-20020a81d242000000b0031f111d36bbsi192416ywl.1.2022.09.02.12.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 12:53:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id p8-20020a17090ad30800b001fdfc8c7567so8243935pju.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Sep 2022 12:53:59 -0700 (PDT)
X-Received: by 2002:a17:90b:b16:b0:1fd:b47c:6ab with SMTP id bf22-20020a17090b0b1600b001fdb47c06abmr6698292pjb.203.1662148438176;
        Fri, 02 Sep 2022 12:53:58 -0700 (PDT)
Received: from [192.168.1.136] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id c6-20020a170902c1c600b00172ccb3f4ebsm2008369plc.160.2022.09.02.12.53.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 12:53:57 -0700 (PDT)
Message-ID: <d5526090-0380-a586-40e1-7b3bb6fe6fb8@kernel.dk>
Date: Fri, 2 Sep 2022 13:53:53 -0600
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.2
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Roman Gushchin <roman.gushchin@linux.dev>,
 Yosry Ahmed <yosryahmed@google.com>, Michal Hocko <mhocko@suse.com>,
 Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
 Suren Baghdasaryan <surenb@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>,
 Johannes Weiner <hannes@cmpxchg.org>, dave@stgolabs.net,
 Matthew Wilcox <willy@infradead.org>, liam.howlett@oracle.com,
 void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, Steven Rostedt <rostedt@goodmis.org>,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>,
 arnd@arndb.de, jbaron@akamai.com, David Rientjes <rientjes@google.com>,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
References: <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
 <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
 <20220902194839.xqzgsoowous72jkz@moria.home.lan>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <20220902194839.xqzgsoowous72jkz@moria.home.lan>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=4q1ObG8W;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 9/2/22 1:48 PM, Kent Overstreet wrote:
> On Fri, Sep 02, 2022 at 06:02:12AM -0600, Jens Axboe wrote:
>> On 9/1/22 7:04 PM, Roman Gushchin wrote:
>>> On Thu, Sep 01, 2022 at 08:17:47PM -0400, Kent Overstreet wrote:
>>>> On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
>>>>> I'd suggest to run something like iperf on a fast hardware. And maybe some
>>>>> io_uring stuff too. These are two places which were historically most sensitive
>>>>> to the (kernel) memory accounting speed.
>>>>
>>>> I'm getting wildly inconsistent results with iperf.
>>>>
>>>> io_uring-echo-server and rust_echo_bench gets me:
>>>> Benchmarking: 127.0.0.1:12345
>>>> 50 clients, running 512 bytes, 60 sec.
>>>>
>>>> Without alloc tagging:	120547 request/sec
>>>> With:			116748 request/sec
>>>>
>>>> https://github.com/frevib/io_uring-echo-server
>>>> https://github.com/haraldh/rust_echo_bench
>>>>
>>>> How's that look to you? Close enough? :)
>>>
>>> Yes, this looks good (a bit too good).
>>>
>>> I'm not that familiar with io_uring, Jens and Pavel should have a better idea
>>> what and how to run (I know they've workarounded the kernel memory accounting
>>> because of the performance in the past, this is why I suspect it might be an
>>> issue here as well).
>>
>> io_uring isn't alloc+free intensive on a per request basis anymore, it
>> would not be a good benchmark if the goal is to check for regressions in
>> that area.
> 
> Good to know. The benchmark is still a TCP benchmark though, so still useful.
> 
> Matthew suggested
>   while true; do echo 1 >/tmp/foo; rm /tmp/foo; done
> 
> I ran that on tmpfs, and the numbers with and without alloc tagging were
> statistically equal - there was a fair amount of variation, it wasn't a super
> controlled test, anywhere from 38-41 seconds with 100000 iterations (and alloc
> tagging was some of the faster runs).
> 
> But with memcg off, it ran in 32-33 seconds. We're piggybacking on the same
> mechanism memcg uses for stashing per-object pointers, so it looks like that's
> the bigger cost.

I've complained about memcg accounting before, the slowness of it is why
io_uring works around it by caching. Anything we account we try NOT do
in the fast path because of it, the slowdown is considerable.

You care about efficiency now? I thought that was relegated to
irrelevant 10M IOPS cases.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d5526090-0380-a586-40e1-7b3bb6fe6fb8%40kernel.dk.
