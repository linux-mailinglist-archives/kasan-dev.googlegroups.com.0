Return-Path: <kasan-dev+bncBCAP7WGUVIKBBHUZWCRQMGQEAHFXDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 84ADC70CFB4
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:45:20 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-76fffd0116esf560260539f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:45:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684802719; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLs3DjVsWUEamu5eipZyrTQV7TGTjUEA3BfuKUxEYdhrwHOPuwkvN6q+u12UhnIrfl
         buGXXstLnoFHpYbFO6npn4WaHjQmltVTOdleEb4EkV9+8gJP3pQuEHWzW7e63HxG+rJ9
         p/AeVgu1bxJxgtgHzQ0g1i4fXfUQi+xg5QqRjcy6qpO5KVXHBbYjjZ4QDLqO4krKtA6L
         deL21cGzDrfojkkTMz7iIculIGqqUGuZEm5aOeZOr1iwWGmW9fx/+sVY3v4hYB5vuHqa
         4QKJeKM63j9lG6ISJiAbOLPMSzH/J210LDW7E7a0vTOWJT7iRhFZknmhA6wdbwaXmaUm
         DuRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=lZuy2pgZBv0H0kJlCAmKEJouHLOZrW3SEFK5sszesrU=;
        b=JuUYF7GiGjjkQ+KiOjTj9FAUyL2U2tQvjKFhTNBbM39xAWLUbq47JTHXaCu//38tYB
         ILQTC/XQp6F2O4wtBl49/3bPZBPutMxx4r/015IsLYhTMbb8ONr5EfkLuM0BPLp9G6+A
         Dvmj4duI9CFyWopnZF82OywZ37JPP/v9mQNkXNuECmOVjGPVfno9cjX+K4ZawozgT7FA
         f7VHhyZEz+8m8yKas4TuuwjsCBDzEh73Ky70JfVKjkK+gTikjPEO5IcWmiZ/tYR442N5
         6SbFUD6ptF4+3OsYRyjW5J5cgQPXk08qqGzUpTGunEVBaZggQxXueq64WupjXRZbRkKC
         N28w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684802719; x=1687394719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lZuy2pgZBv0H0kJlCAmKEJouHLOZrW3SEFK5sszesrU=;
        b=lcZjQsCbNsmldtqM5gWQ6S2CYDFe2zsKGqhyKVNOvrg9jxUCUy0sCxGw15VC5FeZ9q
         QinGL3Nq8VwAL4+2oHzllRjJAtrlIXfJToS5sd2egQhNgzWR1itpS28/816iJkLci7n1
         DjW6VLT48zEaXr/K2YWS4/6eXhm1B6TJLBN/AZPwb5zK7OO9RYj57MWtjSJDM3BJTqwX
         /M+Z2wND8Myc5NJ0gtvRGMBJtWkyc7pwaWYhFm0s2DRxu0jVBaP9hpVCEPCQsTj8KyFU
         vkWKD057MiBtZQg2BGhtwV60LX4YB76xS572OlzKMVg59WUjHHZFlP9lNENmhbhjf6Oc
         X3cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684802719; x=1687394719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lZuy2pgZBv0H0kJlCAmKEJouHLOZrW3SEFK5sszesrU=;
        b=dIJY95ZfsZuQLZtwrigarUjNc/nCLLfDxSs7a8KvuqCA2b2y8JNDzWnlssDvmROG7S
         erEG9gRHj6bDvZapRCv7AvKxOzuTwuJMWZOpqXiA9moiU8RCKOY+uSzeSZ4MAHmYLIyG
         7c8iJ9oyXelyQFeEnRd0J3O+QMcn55dAVnbwU+/NKnN0zRcc0XzTb4PZJqU5tH/UaZak
         v2KzPI1F5+qsuJtJ96Cg7CnAy7gjOt9i7VBJywYJf/mq80VVRWAUzInia41munMLZTaW
         gfSodYEHRL+ND1qrzGQXPp66QeLyeVHNk4Gx8B3GPg8NtfhetMm4Lu2fI94E447Brmlf
         3jHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzWS1HPxFcJ+csWqz1BEGByH+A9mbiARQKLVSdk1SKwuS/HBgo/
	6jMrjet37jq4AgJdosHcKGk=
X-Google-Smtp-Source: ACHHUZ5iaGIQ7fBMwwnOYOCIe97ez0TLBiwXXxhnskrjeE/wgseARcso1F9mAmrQQ8LGn2LaSC0LvA==
X-Received: by 2002:a05:6638:1133:b0:418:9673:b7bb with SMTP id f19-20020a056638113300b004189673b7bbmr6298106jar.2.1684802719131;
        Mon, 22 May 2023 17:45:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f08:b0:32e:2d9d:f290 with SMTP id
 x8-20020a056e020f0800b0032e2d9df290ls638227ilj.1.-pod-prod-07-us; Mon, 22 May
 2023 17:45:18 -0700 (PDT)
X-Received: by 2002:a92:ce8d:0:b0:331:a0d2:7fc with SMTP id r13-20020a92ce8d000000b00331a0d207fcmr8186566ilo.29.1684802718187;
        Mon, 22 May 2023 17:45:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684802718; cv=none;
        d=google.com; s=arc-20160816;
        b=PCc7dhKFDoU2oC8d/wiztJbQvEuAfkzHjSHUsrc6sgJT76UmYsjxzCqhFYPCsvAeOj
         kq86NuVfQ/km5WwAHWmt9dGLvR6iEWk+ephe+Du8z8UJ/bN2i24yykU/WNuVsJl0OFdp
         2iuuBGeF3w+sHVvy5Q3HygD98KtveJzjlEG/oiXNiADyJTvsDQk9YR1cCNnzH2gtkxt3
         szgpkhZ5wEAKeAXG2ZCvZiI38fDsyAwvO3b7b0Nc+Vf6Su6MKCcJymnz7pJK7QiTOyRJ
         XOSC/FO5vFCMzhk5Kgt/GujAHDvE6/HpG0sQmv9lNAuhkSLFjvkctFNeO+USM6TJ5Dbv
         IKjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=XP5gJZLpwu9etC9/wGSQmBWiQVYCbfrqG5XzKhYr7qQ=;
        b=0yT9Ep2xOHiv+AtOmX7z1RPbKZ5OWWu3OD8K5n3s4oK6FMOCtwrHjX48rIuJLcBl6u
         ybSuKPtDydjJBN4VWGpOpHlUpGJAflOjDgFKJg9W0ueQueki1a0LBb7hz4vDbmfvouNz
         6Y3ulumL2b6AsGR2/WMPfy2xjOUlg5LiI3+Ag7Hq3J+LPvRZTRBKPypLNcK9hWzHBrwD
         Fe6KfaDJRgsn4EV9EJmRJZoZDd5RMgWK/xBxuEcrtVuN3d7MZOme5WD5vjowpGOcKCi7
         1aNAyyfM61Qx6xt3ue39Rvtk4hmQ3dlBF2ctTIkLWdU/yRQnMdxLTTSdvANGF8mk/PNU
         OnKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id ay12-20020a5d9d8c000000b0077006b0ddb6si656682iob.3.2023.05.22.17.45.17
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 17:45:17 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav414.sakura.ne.jp (fsav414.sakura.ne.jp [133.242.250.113])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34N0j3to015017;
	Tue, 23 May 2023 09:45:03 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav414.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp);
 Tue, 23 May 2023 09:45:03 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34N0j3W9015012
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Tue, 23 May 2023 09:45:03 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <dc660fa4-1d0d-75e1-5496-36bef9117469@I-love.SAKURA.ne.jp>
Date: Tue, 23 May 2023 09:45:02 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
Content-Language: en-US
To: "Huang, Ying" <ying.huang@intel.com>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
 <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
 <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
 <87a5xx2hdk.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <b3a5b8be-8a45-a72c-334d-0462cdc582d5@I-love.SAKURA.ne.jp>
 <871qj7zz8z.fsf@yhuang6-desk2.ccr.corp.intel.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <871qj7zz8z.fsf@yhuang6-desk2.ccr.corp.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/05/23 9:07, Huang, Ying wrote:
>>> Except debug code, where do you find locking issues for waking up kswapd?
>>
>> I'm not aware of lockdep reports except debug code.
>>
>> But due to too many locking dependency, lockdep gives up tracking all dependency (e.g.
>>
>>   https://syzkaller.appspot.com/bug?extid=8a249628ae32ea7de3a2
>>   https://syzkaller.appspot.com/bug?extid=a70a6358abd2c3f9550f
>>   https://syzkaller.appspot.com/bug?extid=9bbbacfbf1e04d5221f7
>>   https://syzkaller.appspot.com/bug?extid=b04c9ffbbd2f303d00d9
>>
>> ). I want to reduce locking patterns where possible. pgdat->{kswapd,kcompactd}_wait.lock
>> and zonelist_update_seq are candidates which need not to be held from interrupt context.
> 
> Why is it not safe to wake up kswapd/kcompactd from interrupt context?

I'm not saying it is not safe to wake up kswapd/kcompactd from interrupt context.
Please notice that I'm using "need not" than "must not".

Since total amount of RAM a Linux kernel can use had been increased over years,
watermark gap between "kswapd should start background reclaim" and "current thread
must start foreground reclaim" also increased. Then, randomly allocating small
amount of pages from interrupt context (or atomic context) without waking up
will not needlessly increase possibility of reaching "current thread must start
foreground reclaim" watermark. Then, reducing locking dependency by not waking up
becomes a gain.





KASAN developers, I'm waiting for your response on

  How is the importance of memory allocation in __stack_depot_save() ?
  If allocation failure is welcome, maybe we should not trigger OOM killer
  by clearing __GFP_NORETRY when alloc_flags contained __GFP_FS ...

part.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc660fa4-1d0d-75e1-5496-36bef9117469%40I-love.SAKURA.ne.jp.
