Return-Path: <kasan-dev+bncBCAP7WGUVIKBBI6PXOYQMGQETFEDT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 763E08B4EDE
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 02:19:49 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1e278ebfea1sf49278395ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Apr 2024 17:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714349988; cv=pass;
        d=google.com; s=arc-20160816;
        b=ceNI0BRwrZAuxvxK07bqoUr6RNG0bwnlx94yRLdhWOUpxNfDQigKLzJ94tCv0krDnT
         GrhHUNDBOsPQDyme/zORUOOdC7A0XCJOieiBuhuhK6aejEPPhexdiauGDjq7fd6OAwuN
         yZ645Hdapi+xM+DSxgAUbdN+5GFfGCrY1bZymByFn4bnknFHESMBrmwjsCFDT1CSVfCg
         e3R0GHeUS2rARfOcVDB2T0KrDXT2DjHf2g5eyvTV5p2jUDLlrc1YAeIX/JH8OV8Ou7wt
         idRn8yQmzcFbfyYBowkj+SDTrFaU+Sm5UsYHO+/19DNexUgMklIXFcDZus6I2eXplF48
         n0bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=g13p3erQs5j8s0aatRMJhhnVykZezajCgypBtGM1qBw=;
        fh=9miKUahij32XxGOjieR1grnoxJ2AKZckPolsLVr0drE=;
        b=AKlJPv812TxA6QxsgaR9HAGnZDGoZ3mbg9MhA3ELrV3P2jo6i0a8Oc6bn2i36yUGy8
         /Q8P6whcwqcLzYBLR+V9DQQzpElwn6UuTMJq0Cje39FJEkP7EwUj+juX2XplUKSDUgfT
         2UuAXtMjdFvYB2uvGzSW2ddpkcTzqfjDV+CvjJZmf25CJrmKxYY+bzMz9UVfYSJeD/tP
         R3UJWhgVgM6CxrhM0xKFZ0AdRpyPB6bwdhQK+VfA3VgGDm2lS1wBA71asEzwHDIOtypV
         ES0o16FhU+AAJIi36KZm19xR0LPK/Lqoa3ez847+tHG6H65jc33JPKTGpVerhMhkQDd3
         y9Zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714349988; x=1714954788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g13p3erQs5j8s0aatRMJhhnVykZezajCgypBtGM1qBw=;
        b=jda8PQJCXVAjbkkO2peg7TvFjJmEgtczhN5saAKE8aJSDMUo6ZJHiavqusVgeNkN3E
         u4xjkesI1ScPdh5FgWbf87Udhme5HdXxhQXxUJnN+VfWx7129G9scylZp4BO343aFdWG
         NheQCz8+EnT5tT+Q4vU6sNXEKYZ2gB4fKuwBMvWRybCzpD8NYZEMfrxpE1OlNiGjXcCf
         raZbYQVO7jmCe6oRt/uQrDPImeAL8+l747VauEGJLZDDIMvjrOZPOtgk6Ax866LjH1PB
         ned95AdSs4mEqLDpahXvQBy07FFjD85TenDl34RT6MPyACGvQ/Dbc1Xae/49HSuWYATi
         k6lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714349988; x=1714954788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g13p3erQs5j8s0aatRMJhhnVykZezajCgypBtGM1qBw=;
        b=Yokxgwwskw1C1aWjNpYIkzomQ9VWbKHfTt1M1HUVpnzTHel3j7efxl2+SZVEHUANV7
         QCNkAQ7eU5ZTPRI8m19Kg6J+zfRoXFTO+VvS8GVzhiKXH6FvLGjpzCY4LRxA7VzNozKQ
         R7++rkKoHdKDsmP0pZ6Z/SrQtJ/jVYq21cSYgATlh1/uLSmWbiTng+0fdX/QyRgj3Y9p
         vJepL06DlR6wr0OwcfXkLjYHtsc6Dbtm8Qn100M5oLoFEB3HRAlM0/mL68iwzAW9RKz2
         lR6KB/j0M8Lv+nWQhkzo335L464dj6gZazUlC2lS5ndf185f+6C9MNMtLBhxBqh05/03
         meGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUC7GzLV/92Edgsl6IMoxDV+PZIOzR13fj8351Mi95cEum2e9ab0/9PdXGvH8tfpnaXz/xb89Ogh3DR9vrp9qRB5zf+/i8Yiw==
X-Gm-Message-State: AOJu0Yy1+mKSvQONL0h4+9fdQFS4NOWlYc4tFUKT0FC+Af1RU9wPUups
	9XwZK2cr/m5kaiLEX8LGNnAsDlQS1Eq97Ej+bMTsIEhBD/w6+geP
X-Google-Smtp-Source: AGHT+IHOGysCKpbVzVXW6PJsHEnx3i7Xagj3wLkkrHFse0Dh7EWxuC8JFyre6H2CDuMlA45cik0xGA==
X-Received: by 2002:a17:902:da8f:b0:1e4:b16e:7f10 with SMTP id j15-20020a170902da8f00b001e4b16e7f10mr11620319plx.33.1714349987736;
        Sun, 28 Apr 2024 17:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f687:b0:1e2:306e:bcec with SMTP id
 d9443c01a7336-1eaa0631acbls23486055ad.0.-pod-prod-03-us; Sun, 28 Apr 2024
 17:19:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXl9FkYS+sBDUmJnQ2M8HFpw5L6DlBTbILgNKhSDzP+0nBpKdUAqx5yYnmFP1R/uM+zzs2uspRCU63JN6q6gexP4Ru6t0SGDyrtZQ==
X-Received: by 2002:a05:6a21:3e14:b0:1a7:63ac:a3aa with SMTP id bk20-20020a056a213e1400b001a763aca3aamr10368759pzc.30.1714349986165;
        Sun, 28 Apr 2024 17:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714349986; cv=none;
        d=google.com; s=arc-20160816;
        b=WlVzv1guY9Y3TaRp7qmAxMT+ti+39QzmiFgAfAYgIEcAHmlWCwKUaVnebeY5EQdRlj
         WpfHhEzlxa3PAZKyLDHQyXoGcQxxRmf623Za2iy31Djbs1Fl9UVGGeoXqTsDqU76AV34
         bDXww13YT8R8tIMZ5IP8zF6z9GQc6GW9JRxPENhz73RICuPhejn6VWeVUnMp5rLFsbWU
         sbp2uVccXtNEgNLN3R+DdrjCw1DuSd6JUYH+hjgqQpz4GgpS3GXW1U5Y1YN6xwvLuxN4
         ocYsWNsodu+DEN7Up84rfo1HG0HSO/AYmH7ItiuZp7fq74aDOkAHFQSHcoogqPy9j7ha
         Hk8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id;
        bh=LbwvzxNDK9h4A6FD7/0s1aUhK3DO5EMqxrWOsQ6pHzM=;
        fh=Db1MpVq+1eZLHJFdc8nM05UhcmlxoCO2IDN6/MRAw94=;
        b=ExK3cBG6Z2rhRAc/7vEQtrvID+wEU8mGH8OqJwikJf0IUw3v5klT8w45BuJn5meSYU
         e6p5Mvxn9SfeX9mQkbBu6PC/d4JGqSf8MhVhjqrL1EmDMT3Bg5VTzx+ZPx8XfXf/s/0z
         BlFIF3CjBgiycFiTSWcXn8rPjvQ5Ftbrj7IVLYEQTzx3g/b9zUu/7e1t+VWgwaNa3Z9R
         6eMkDs0Y+sm1F9/YhOgXecuvldfHOe7t3E9t7N95m4NflPOPG7kar/neftj6r5onwfL4
         6jNag2AVplZUwnoaGyfnpJCrEwZ7wKSS/hJzZF5w+8T2n5Gc+zPNQLPDogGifZj4ckWG
         nQNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id u30-20020a17090a51a100b002aabb55e983si1216809pjh.1.2024.04.28.17.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 Apr 2024 17:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav414.sakura.ne.jp (fsav414.sakura.ne.jp [133.242.250.113])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 43T0JcKS032648;
	Mon, 29 Apr 2024 09:19:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav414.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp);
 Mon, 29 Apr 2024 09:19:38 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 43T0JcnZ032645
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 29 Apr 2024 09:19:38 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <314a8e87-8348-4f40-9260-085695ac2dcc@I-love.SAKURA.ne.jp>
Date: Mon, 29 Apr 2024 09:19:38 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3] tty: tty_io: remove hung_up_tty_fops
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>
References: <e1fe6a44-3021-62ad-690a-69146e39e1ac@I-love.SAKURA.ne.jp>
 <20230424004431.GG3390869@ZenIV>
 <8e21256a-736e-4c2d-1ff4-723775bcac46@I-love.SAKURA.ne.jp>
 <2fca7932-5030-32c3-dd61-48dd78e58e11@I-love.SAKURA.ne.jp>
 <20230425160344.GS3390869@ZenIV>
 <1b405689-ea0a-6696-6709-d372ce72d68c@I-love.SAKURA.ne.jp>
 <5cebade5-0aa9-506c-c817-7bcf098eba89@I-love.SAKURA.ne.jp>
 <c95c62ba-4f47-b499-623b-05627a81c601@I-love.SAKURA.ne.jp>
 <2023053005-alongside-unvisited-d9af@gregkh>
 <8edbd558-a05f-c775-4d0c-09367e688682@I-love.SAKURA.ne.jp>
 <2023053048-saved-undated-9adf@gregkh>
 <18a58415-4aa9-4cba-97d2-b70384407313@I-love.SAKURA.ne.jp>
 <CAHk-=wgSOa_g+bxjNi+HQpC=6sHK2yKeoW-xOhb0-FVGMTDWjg@mail.gmail.com>
 <a3be44f9-64eb-42e8-bf01-8610548a68a7@I-love.SAKURA.ne.jp>
 <CAHk-=wj6HmDetTDhNNUNcAXZzmCv==oHk22_kVW4znfO-HuMnA@mail.gmail.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAHk-=wj6HmDetTDhNNUNcAXZzmCv==oHk22_kVW4znfO-HuMnA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/04/29 3:50, Linus Torvalds wrote:
> On Sun, 28 Apr 2024 at 03:20, Tetsuo Handa
> <penguin-kernel@i-love.sakura.ne.jp> wrote:
>>
>>
>> If we keep the current model, WRITE_ONCE() is not sufficient.
>>
>> My understanding is that KCSAN's report like
> 
> I find it obnoxious that these are NOT REAL PROBLEMS.
> 
> It's KCSAN that is broken and doesn't allow us to just tell it to
> sanely ignore things.
> 
> I don't want to add stupid and pointless annotations for a broken tooling.
> 
> Can you instead just ask the KCSAN people to have some mode where we
> can annotate a pointer as a "use one or the other", and just shut that
> thing up that way?
> 
> Because no, we're not adding some idiotic "f_op()" wrapper just to
> shut KCSAN up about a non-issue.
> 
>                      Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/314a8e87-8348-4f40-9260-085695ac2dcc%40I-love.SAKURA.ne.jp.
