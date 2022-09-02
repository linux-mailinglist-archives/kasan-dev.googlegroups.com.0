Return-Path: <kasan-dev+bncBDR5N7WPRQGRBTOMZGMAMGQELDLYWHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EA635AB964
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 22:23:43 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id f6-20020a4a9206000000b0044e001dc716sf1650609ooh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 13:23:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662150222; cv=pass;
        d=google.com; s=arc-20160816;
        b=IttBD+97upVt06xBP0nFxx0xr44JUkejzsAsmnlvxejj9KTJHGuuvEyd11oCVso0KX
         ozXHNiSD58txzPXYSodtFZ/iStRZJL+pIUSmf8P3/IKB+wc9IgsJrMWNX4Vk9mCRDg05
         g2iF0aN8Bks9SHF4oOaZ0NPAB/ZwZ4gqdOMbeJVOOmoTdqhuwNS3CjETydOaUkmJkrdw
         TsD5LR8+ChsOHkf73nXRkQ7WvSebWihiXU9m0q6iNDwoTcMXFZvAt6rlgiP5TnHzm1Sg
         hYFz+JzFiBAGN7kkiIOTjax44DmrugYiI7uMbHA5CJ6OoJDsAlBrv/vze7agcYAm9y+f
         rmnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9oh9SkHlVi4YqB7pnbYs1jISzOiaQvkauqBF3zR6D6k=;
        b=D99fPm3WD7TeSr9htwMK6NMm+T02bGJEK7p87cBAJvDzqP720PGGG0MtbhkYT3Jxne
         lVKuszKcWsv7A5a580NcJZsdfyEtNa9eePWU3pM2j6NKgYa1F3DKXvdIIE/iofJmv/1k
         AUM1XFwACPDbTaOtR4D7Lrtc4IwCS+JXloDHapKnBU6gfIG2XUsrVy9Bpc2xkLH9cmCU
         gjPiBH71ybY1GArsl/L685/i5tVaRVNycFDR82eXfLEL5gEQ8JLbErymLOBQka4pmFJ5
         shcUxUGzpA90xdDrkU2knq4/lyDyg3plbnr+3iOu6BJ60XJhUOg2gtdfLtGDajk1wxgv
         NpGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=atNBwFgI;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=9oh9SkHlVi4YqB7pnbYs1jISzOiaQvkauqBF3zR6D6k=;
        b=TV29zk9h6lQ7d9FEu/Qe8KdxZ1qHWLr22aFiOfUdhx/sZDEswnvclf5vrX0GwTwc/I
         Hl2inai00Xkp1LGdS0uO7PnMQaz6K6XuQH0XEQx+2E/J9TL3Ex+w6H4hmjmU+5s1679t
         17fxCldaeFHrsu/gOnLwS594vjso5AfyeWmESVNgS3eOojxh3DQ0eduAfGM/Cuy0qZbg
         q88x9mTQs15eK/W+IbzL9N0lfKVL6VGwmwYDwhMUovbLMJ5G9fbih3EkIfVVzm75VEaN
         Mse/+RbdFfbm/ijbNqoNsRJ1nkB9nogaSotE1G7tTjM8k+LDExyi1osfj+J3dksYKa0Z
         q5JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=9oh9SkHlVi4YqB7pnbYs1jISzOiaQvkauqBF3zR6D6k=;
        b=bEKgUi2AHQhi0QI/PaM6ezhULzTKAazdLtcwxW2vzvaDeHXindgBOpGMCRADzjC16P
         rUISqWvWQ42MaS4r8n1yKDvvW3ZCyDmuQN+b9qzRG7tM10meGrdvCNxILscavxsmlcLh
         BX03ROIEQY2VdAq59TDsBUZYiC878UiL/NqJfTGg3eZ4QZ2WfUOP/8jNQEGf8G0eSmnr
         VNcBx8ypdMEH3BHmM2BGDZh5L3vpxZZDdsXzPo4nvZhzKeHODbyMfUiqeBbD69ko/AbE
         x5s4EIVuoDd9p1E1UMXkZn+1NtBGl+CegpF/0/ivXgO7TOm9OyiCSsqzgEvhHMeLuwNj
         NJVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo25QNlBFUBp+34o+MbSJ2HwQ//i341527RuTXfq3ta1rsHhzIra
	p2wFYiDMreQ6s7bFdWiMWqc=
X-Google-Smtp-Source: AA6agR43M96ddWBVQs+56M+MYc+lEo45H4hBe/ComBbywPawesEqdlseslQbik7SFiQvFV914pDAEw==
X-Received: by 2002:a05:6808:f8d:b0:345:6ee0:9a65 with SMTP id o13-20020a0568080f8d00b003456ee09a65mr2590111oiw.299.1662150221961;
        Fri, 02 Sep 2022 13:23:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5381:b0:10e:c5cb:acd1 with SMTP id
 h1-20020a056870538100b0010ec5cbacd1ls2420397oan.5.-pod-prod-gmail; Fri, 02
 Sep 2022 13:23:41 -0700 (PDT)
X-Received: by 2002:a05:6870:332c:b0:122:4dbf:c03 with SMTP id x44-20020a056870332c00b001224dbf0c03mr2982579oae.79.1662150221285;
        Fri, 02 Sep 2022 13:23:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662150221; cv=none;
        d=google.com; s=arc-20160816;
        b=Q64nvPBOlhJlOO5SIDITSD9QezxnFxJsgl9Koh6UOpO/XaUO9x3TyyGhD3yidCl8Hi
         j3odV7ra+w8A0CTSh+TQgR4bHyG8LGb05Dk4enRgItCbqDJBEQmJnQxMsp6t6Xqq9qCs
         cgkvdYHcVdgRNPI3GBIdCYSbYvJVJbSvp7Nh78C/KaukD0zSayNBggsR0moibWFLsjfZ
         K5+n2HQIYe6s8nO6dez1ZJfVcfpMb7tsJ21rLDzauU/wbmf6Eg25URushvmb/WzpTo5k
         mWIt/xjUGp0oxoJNutekxSD/Q97CEAqK3Pao/0lj7PId3RbE5uQIzthOvyTvPRL0dHEG
         8SRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=k6pQn9EMMlV6BZtQiNF0XvMyejT4MeXWM0SLMVDUfUA=;
        b=AVcLHJMysEOlckCyPa3hggQUGK3hpVBq29OPawWg3mSjsEPyJXR/PGxH2gYaohxgBt
         uqeQh+iruVNWsbbm4cYJtHufApW9rsbuop7vbef4QLtjvpI8TOCL1dG5B9F0Q/z23b8/
         OjWqqQXMlqYQDWZdltcCboovfCNjmRTwKHaIPcPsAVVOWEECk9FdcR2RNnKqywoqf5+j
         Hum8gjw+XBav4jhnqS2Cteo1DzBLSqa6/iO0WF1ImcbtQQeHi+ZI62C2bDdZIM0PpVyZ
         P/jjKecx4gzwDkhWory9NYvndUmSHV6X3O8H9MU/29G3E0hBlo3zulniWW+KqvwS9lnb
         b6tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=atNBwFgI;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 38-20020a9d0829000000b0061c81be91e8si187191oty.4.2022.09.02.13.23.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 13:23:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id jm11so2867267plb.13
        for <kasan-dev@googlegroups.com>; Fri, 02 Sep 2022 13:23:41 -0700 (PDT)
X-Received: by 2002:a17:902:c94d:b0:16d:c10a:650e with SMTP id i13-20020a170902c94d00b0016dc10a650emr36139251pla.29.1662150220589;
        Fri, 02 Sep 2022 13:23:40 -0700 (PDT)
Received: from [192.168.1.136] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id z10-20020a62d10a000000b00535d094d6ecsm2197822pfg.108.2022.09.02.13.23.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 13:23:38 -0700 (PDT)
Message-ID: <002ab1f2-078e-2bce-83a0-257a573b1f95@kernel.dk>
Date: Fri, 2 Sep 2022 14:23:34 -0600
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
References: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
 <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
 <20220902194839.xqzgsoowous72jkz@moria.home.lan>
 <d5526090-0380-a586-40e1-7b3bb6fe6fb8@kernel.dk>
 <20220902200555.h5fyamst6lyamjnw@moria.home.lan>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <20220902200555.h5fyamst6lyamjnw@moria.home.lan>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=atNBwFgI;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 9/2/22 2:05 PM, Kent Overstreet wrote:
> On Fri, Sep 02, 2022 at 01:53:53PM -0600, Jens Axboe wrote:
>> I've complained about memcg accounting before, the slowness of it is why
>> io_uring works around it by caching. Anything we account we try NOT do
>> in the fast path because of it, the slowdown is considerable.
> 
> I'm with you on that, it definitely raises an eyebrow.
> 
>> You care about efficiency now? I thought that was relegated to
>> irrelevant 10M IOPS cases.
> 
> I always did, it's just not the only thing I care about.

It's not the only thing anyone cares about.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/002ab1f2-078e-2bce-83a0-257a573b1f95%40kernel.dk.
