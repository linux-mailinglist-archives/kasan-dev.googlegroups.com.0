Return-Path: <kasan-dev+bncBCPILY4NUAFBB6WUUOGQMGQE36BQNFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1409346671A
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 16:47:08 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id az44-20020a05620a172c00b0046a828b4684sf215881qkb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 07:47:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638460027; cv=pass;
        d=google.com; s=arc-20160816;
        b=hylbL33qDJEFtsKjIwC18/VGdKGysmzBl2jMVTSjLBRjPfndZG07mIByRnAXjnA8Gd
         0vWc+d1/xzzViGM0wiTNABBWowTIzzNOm/OyB8cebO62KiHMphFS+aGxtPCCeJKIfbA/
         +bjwcYvLrSpMkErKGTaltO3fw5QT6Q0CUVZEq/ebqbF2tKYfRuFLwNL6ib2P3N3aEYHN
         XXodxXmTuQDCFNp2aM15B1mGpccn4md066hGrKNkANNsiJeBEb1OI3O95dMsCIyV4KUL
         Tvm9FHSjG8ApG+ay0TAnTzTJSteTO1SzoEdrcjRe7tvUSenBYNV2ZVI0V0G4LG/RLnRM
         f7sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=GNxKmhljhOzzy1EEpq5jNAQS3W/0KoIrIllFqgpqk1M=;
        b=ZriJlF4sppMkgNsZjdx2tYRgU+7D7J4Z3N9jwLVGGFBE8uWyAFr/MIZq5P6R4+C814
         knnWXyRbpq3OPMBL0lPHSCjp3MHiHa+vDRN+opZoR6w55+q4Pib/9ExbgbU01ugJTbYf
         FHq4QyToTrX2qhfUKE6IoysjRgc7TNSCCd1OiibZtq1jgQkXwI0S+kKQQkiZ55xUy9cQ
         UsUgAQ53uy6LsnQU3B6blgUuGMHgzOsuu88JS69cIwDre8FLXSTpJBeQvSfxFY0W8kZG
         BfyK9R1zkQbo/84nut6erw679eQO63eLtTvhfONdiEaNHKjn+ZhsRAj+TX6ht70377fi
         J+eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g7nMqNmk;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GNxKmhljhOzzy1EEpq5jNAQS3W/0KoIrIllFqgpqk1M=;
        b=HFwZMSoSouTYscUw+feds21vH9nC7Q9dNfSSRBfHItVTtkua0kI0P+e4M/YSm9TG/Z
         8rcLTThm6swga4KBvZgLDhkVK8rzlc8Cfi8vWjkKBR4d6wzpP3mYX0bvhAfSTAJiT7bu
         gkPKEYkQPyzZr7DedzniQ9mrczz2DUQnuvtXO03h3sW9sEDPvF40/vFlAqOAQ2V4J95g
         SmLT3qd/at5ZtdlPa1jgg4oHSGvntlRdhiBIUQmxSP2HeRd7SQmFBhm822jcQbCibY+U
         uMTg9oFjJ3iNwP3JX+nCXfZ3ueRlcPEjNX0AtOUKDbqX9/hhgNclwzPSdQjIAvGro1x1
         LrQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GNxKmhljhOzzy1EEpq5jNAQS3W/0KoIrIllFqgpqk1M=;
        b=eWgf4R1QuEPsm+fIUjRJoFGHjNHCA/CEQ4YK7rN6qgQ16vvWySjv7t6eeON6FPEsw6
         13kYVSyFl7GmNQj7APS/sLYBAYk0vew3Ubf0nfwq1YE6GitIIhNpB/sGOqAVqZAl3zRB
         EJLMwLkHDZIOAsqgsm6aIs9jArNDcHSvQo6YJ+tMsam9dZertd3FJ3gudjBsnbn3AYDR
         r5s4TDXoM3p9Cu71crV2yDmPSo+GhczAX+WokiYOTBkTHbB8Vf+jga2J2MNJGV3NVCZ2
         WYHpp5QcmhFkubKmtJsCPok33/OfYerChEkHEYByw+QnGSAv1IyD89RsuqI+1lb1J/rh
         QpCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530G3DaE+rmsGRESQ6xooy8rnR745nBDKKjSxqySIYbIyoSs0olo
	EtikBPInogs6H6FomwORriA=
X-Google-Smtp-Source: ABdhPJyEwwMy1PKeqzK6xACYdl3MpHNIDEgp6KXTxRVwef6lxwFnLOnPj+bNIBgUOISZ/9t6SKcGLw==
X-Received: by 2002:a05:622a:388:: with SMTP id j8mr14549275qtx.366.1638460027062;
        Thu, 02 Dec 2021 07:47:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1926:: with SMTP id bj38ls4282349qkb.7.gmail; Thu,
 02 Dec 2021 07:47:06 -0800 (PST)
X-Received: by 2002:a05:620a:4006:: with SMTP id h6mr13124153qko.559.1638460026668;
        Thu, 02 Dec 2021 07:47:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638460026; cv=none;
        d=google.com; s=arc-20160816;
        b=DycIOW3H59FN5wvf9HalwQx2zpWQruPoBaBfcuCHKaiXkOKCp3scgqbmrVKy6xnHv5
         4KMgLEgdAHY6WS/1UVp9dMmap0TXLhgYnoOGqeCVN1cf7nbFB4nq3IomE517Q6+5SHGy
         LUau4GuIUulqHSdh0kHqASczDuehJ43Ns3jfj+zCfCAmj+Q+/KkuZ559kh2SMvEu/9xK
         pAZaOhnE8duttMBwVbr37+8UCxsL/uf5pDewU1w3NyWO9ijMBnu4yFl3wpu5gRM6eK5u
         ZB0XbVbEF/Eass/wELMOpLtFf5XpQbsn1oTxwtYJK3Oviqx5DKnnQjij/moAW+UioqeH
         H2gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1QXpG/U1Vsg/4uKa21qXS5jgoVnEShvvUuealgGuJJw=;
        b=EZczKCbz0At8ioY2XAvi+oDw1grjBbOQKhTJMUk3awLBvOOkc3EnhEyJRHm2Pb2o2H
         xDqRONmFPSV7kzV6Iufjp+HrOIvXAPnyYhdZ00//bHWZfL5cbYaepBaodInAdjBPXV1M
         i1jXtK7t6it3ckyo1HraCoaqkh4QGah/tMkV+qADyGJywKFW2keKXmL/KzCgfLW0RH+g
         AxuQDtsW94N6dPugIUNzoTeHydiYNBNZbSzGGb7EAlMUwZ8XS+ggnylzDQHiFA34rVwd
         ayGntJPE12v8oiu6jJ6tE9bZzMSLdR+lSNNt6UDGjlmSVQ0bSD7dgSD/vBkonVC4JrOi
         YExg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g7nMqNmk;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d14si34666qkn.4.2021.12.02.07.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Dec 2021 07:47:06 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-122-hQDi2Ru_MfqdMskLlbh9bg-1; Thu, 02 Dec 2021 10:46:59 -0500
X-MC-Unique: hQDi2Ru_MfqdMskLlbh9bg-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 9350780A1BF;
	Thu,  2 Dec 2021 15:46:54 +0000 (UTC)
Received: from [10.22.18.96] (unknown [10.22.18.96])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 5C2E35D9D5;
	Thu,  2 Dec 2021 15:46:53 +0000 (UTC)
Message-ID: <2f67a2d9-98d6-eabd-fb5e-4c89574ce52c@redhat.com>
Date: Thu, 2 Dec 2021 10:46:52 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.0
Subject: Re: [PATCH] locking/mutex: Mark racy reads of owner->on_cpu
Content-Language: en-US
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
 Boqun Feng <boqun.feng@gmail.com>, linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
 Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney"
 <paulmck@kernel.org>, Kefeng Wang <wangkefeng.wang@huawei.com>
References: <20211202101238.33546-1-elver@google.com>
 <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
From: Waiman Long <longman@redhat.com>
In-Reply-To: <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=g7nMqNmk;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 12/2/21 06:53, Marco Elver wrote:
> On Thu, 2 Dec 2021 at 11:13, Marco Elver <elver@google.com> wrote:
>> One of the more frequent data races reported by KCSAN is the racy read
>> in mutex_spin_on_owner(), which is usually reported as "race of unknown
>> origin" without showing the writer. This is due to the racing write
>> occurring in kernel/sched. Locally enabling KCSAN in kernel/sched shows:
>>
>>   | write (marked) to 0xffff97f205079934 of 4 bytes by task 316 on cpu 6:
>>   |  finish_task                kernel/sched/core.c:4632 [inline]
>>   |  finish_task_switch         kernel/sched/core.c:4848
>>   |  context_switch             kernel/sched/core.c:4975 [inline]
>>   |  __schedule                 kernel/sched/core.c:6253
>>   |  schedule                   kernel/sched/core.c:6326
>>   |  schedule_preempt_disabled  kernel/sched/core.c:6385
>>   |  __mutex_lock_common        kernel/locking/mutex.c:680
>>   |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
>>   |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
>>   |  mutex_lock                 kernel/locking/mutex.c:283
>>   |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
>>   |  ...
>>   |
>>   | read to 0xffff97f205079934 of 4 bytes by task 322 on cpu 3:
>>   |  mutex_spin_on_owner        kernel/locking/mutex.c:370
>>   |  mutex_optimistic_spin      kernel/locking/mutex.c:480
>>   |  __mutex_lock_common        kernel/locking/mutex.c:610
>>   |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
>>   |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
>>   |  mutex_lock                 kernel/locking/mutex.c:283
>>   |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
>>   |  ...
>>   |
>>   | value changed: 0x00000001 -> 0x00000000
>>
>> This race is clearly intentional, and the potential for miscompilation
>> is slim due to surrounding barrier() and cpu_relax(), and the value
>> being used as a boolean.
>>
>> Nevertheless, marking this reader would more clearly denote intent and
>> make it obvious that concurrency is expected. Use READ_ONCE() to avoid
>> having to reason about compiler optimizations now and in future.
>>
>> Similarly, mark the read to owner->on_cpu in mutex_can_spin_on_owner(),
>> which immediately precedes the loop executing mutex_spin_on_owner().
>>
>> Signed-off-by: Marco Elver <elver@google.com>
> [...]
>
> Kefeng kindly pointed out that there is an alternative, which would
> refactor owner_on_cpu() from rwsem that would address both mutex and
> rwsem:
> https://lore.kernel.org/all/b641f1ea-6def-0fe4-d273-03c35c4aa7d6@huawei.com/
>
> Preferences?

I would like to see owner_on_cpu() extracted out from 
kernel/locking/rwsem.c into include/linux/sched.h right after 
vcpu_is_preempted(), for instance, and with READ_ONCE() added. Then it 
can be used in mutex.c as well. This problem is common to both mutex and 
rwsem.

Cheers,
Longman

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2f67a2d9-98d6-eabd-fb5e-4c89574ce52c%40redhat.com.
