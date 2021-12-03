Return-Path: <kasan-dev+bncBCPILY4NUAFBBA7ZVCGQMGQEWSUOPVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D09B467A8A
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 16:49:24 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id 77-20020a1f1950000000b002fec8b725c5sf1528603vkz.14
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 07:49:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638546563; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZoPZXxux0eb80tih3GmRS4zUmjQ0eOwk6nKEoNZplfLjdGoJQicnya7v5T7pwtUAQS
         Qv/7p6+uJyteSHXADEEMolVG0o6waYKAmcaI5SnXb7PYLiwbmTQuEttGDUQuCeo8fBY+
         HzTCbftF3rzIz8llSlqLp+/Eo8kM6dmrk9FDYMnyjofMIw/K7iUTNYlfzXRLzrf+F9vS
         m5W9FEn+T0+b01LbGoFXXsgZrW3B3XKXEZALkX6+wgIjaA1HbtO6qzyG4R2BVRKbAVm/
         rAJif5bQZq9uk4W3Y7hHS6TTweDcyWjmafS23dzouoVz7/ZMqUZlAotmi82GUmBA+Tzp
         ikng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Ac9NQQscN7uAwdn/781mTbAyhb6X0Z8FGlgydp6+458=;
        b=qg7z7V4KwBhEXLmxPgcFhgdhWJajxlr9B10h1nG1UjXxgOjjSpC8Amvvn3+XHieQ9D
         Ig7s+BuoXoOdXjWXlet8S7Th/FOWARNwMI7U+j5ZAT7T4fBcn/tPC0H87jYq497QkkC2
         jR97q/pZgAcFh0tPPopK+2CJsX245oZHWU+m0LjNETr1QO3Qb6K2zltHgtmOuBpsP7XY
         Zoq6sQOQTbW/p+T+7HBWDiSF1FKPd3n7xhZjL1KQCUQA3cswsm8r779dRVS061tIrmYd
         NTcEf4jtmvj2xvOaOMshSt2UxSI2fV3v8xYMujE82MxNSPml0kkODc3JVDHVtOmyWVjO
         MyEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iz545Ge+;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ac9NQQscN7uAwdn/781mTbAyhb6X0Z8FGlgydp6+458=;
        b=HYuJaSC1ug/OTfuNOYX9HOlbsHEtBuXDvCeVxqy5qUszRMKf2QQMKeU2SMjXXjatVi
         O43VMtXkPh294dFq4AQNuGgzuizC5ajO2wYKoQ8p9zYwejXoh5/Wn6pmIlj2uVsCgZ98
         canxLh45VUa0cZfTV+QnRLZZ5k+4B2O7Onq5tNh1Jf2KeGD8N6k5u2lZ+utoTayUl/CU
         2Nk8yzvveYfuHtqO+aMtxeIXoRDLmjfIAPnQGpvJ7CkUnrgE0LL0m95xMSG5aMWb0wQE
         Gmj+a3YSUeyX/BPYt22DTc9bcJ2GaXjgriuAaHYREgiqfeC0s7d9MsijdoQilmcyFlji
         Ixww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ac9NQQscN7uAwdn/781mTbAyhb6X0Z8FGlgydp6+458=;
        b=ruNTqGm9YwYmx0+p5tAhCbgCLPEdtpX+iR+iKvMzKQ7KCGk1wKBAztQonRzIzCh1CI
         a+9gSMzQ10MWoYTCI8CR1ryzkbECRV2sgxxXyE9zhQOFPTU3HFdRSAh8I+z9aB2e5kmO
         CHs8ZzsK/+1G4Ye5g2Dcj2uCNcI7KMrh5A/cewFyCt4Pg7wKs2NDmr91Lovz7Hrs1Meg
         iu6K/CzxfVa5NqjHA4DPOtjG1yGIFj4+wEAKwI/QNaZTZ/z6pEzisFXhwGj5dxtLqSzq
         zuvuACS3nF6QOWIxqKRtqjYKIpveuLGthruZe6Z0hOo16lRobpNY+uNUiYuxS6kMkSTE
         PpWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vEA9wbR+A70L1WaiH0eiGRA89TCsj0LOR7Nz3cMLu+y6ljxQm
	bAihTFjeTRnEwj7fyZP+6EQ=
X-Google-Smtp-Source: ABdhPJyNpats7KIBumztOUOse0axr5EEzP8dUNNkcpHOMOQ86Yp+wlLE2v5Z+vgci3q+tn3SNdwA+w==
X-Received: by 2002:a67:f64c:: with SMTP id u12mr21357886vso.69.1638546563418;
        Fri, 03 Dec 2021 07:49:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:4ac:: with SMTP id r12ls2925012vsa.8.gmail; Fri, 03
 Dec 2021 07:49:22 -0800 (PST)
X-Received: by 2002:a05:6102:ac3:: with SMTP id m3mr21841776vsh.1.1638546562865;
        Fri, 03 Dec 2021 07:49:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638546562; cv=none;
        d=google.com; s=arc-20160816;
        b=vPD+he+sUkGCm73wYeqwJilKXh1oB/LnPZ1Xr6syJY38Sjqwt5G/ZBc6uk8zVQLuim
         AUOe1E3wmiK/W38SO04UaZj1237djKEcK6SMMdExfPdQCvMzah4ybtcZXi5M7fP/q8V1
         vkX5Dkp8fiaRz3GhszP8xpJt7kRWoxRZEHUdb2ewqk+B0nxld7bBxAOi+IiZQqXaOREn
         05lt25nIkPavsj/9iBt3Xfwn28A21ooh59MZTN5Ycf7hI3Vnbe1+SlDBS5ju2ovnfUg8
         MjIjk9hnt36QY6LsGKWms0ZnApcFuZfOdCQCx537qJzpU9hsW6zSvrjbC9l5i5CPwUf1
         6tow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=wn/B+NRo5r0JBN9o4MkIX7l2zDFt6F/saJZ6BQL4N2U=;
        b=gstYiIvBwRf7RXahD0CQjh8nZ0eZVR0h5H2okeV8+wFcWsw8t1t/0PjULelE6YbbUs
         cq9lvqTStsjY5VphsFe4CNbMa4PGQta+gTkNG5p23JOZafqFqZK6DTOoubjTosMTED15
         pJjmBgO+1sjwYp7EVb3ydsGPXplSsrf+WVMYIPcLqvy9OrHiGWNH7/fJM2xffP392psF
         QFPAyJ2NT6wOB4MuYgSvIp5H5gDL/O5R4h2s6Q/fxfqPBcJixh+hAkmJoA8PYshvC1KG
         2zFkqURRMzxIC34D0DDx+2glbH0gVrsUsBdt6/iKUhhdlsS0BHQ9a8WTBCWwGY1IJ/mF
         EuWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iz545Ge+;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id g8si488862vsk.0.2021.12.03.07.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 07:49:22 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-501-HOKEf28RNnitHRFnrAW8XA-1; Fri, 03 Dec 2021 10:49:20 -0500
X-MC-Unique: HOKEf28RNnitHRFnrAW8XA-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 2898881CCBA;
	Fri,  3 Dec 2021 15:49:19 +0000 (UTC)
Received: from [10.22.32.36] (unknown [10.22.32.36])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 10ABE5DAA5;
	Fri,  3 Dec 2021 15:49:17 +0000 (UTC)
Message-ID: <7961d0f7-d1e4-d631-5806-58607e50279d@redhat.com>
Date: Fri, 3 Dec 2021 10:49:17 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.0
Subject: Re: [PATCH v2 0/2] locking: Fix racy reads of owner->on_cpu
Content-Language: en-US
To: Kefeng Wang <wangkefeng.wang@huawei.com>,
 Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
 Boqun Feng <boqun.feng@gmail.com>, Thomas Gleixner <tglx@linutronix.de>,
 Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney"
 <paulmck@kernel.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
From: Waiman Long <longman@redhat.com>
In-Reply-To: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iz545Ge+;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 12/3/21 02:59, Kefeng Wang wrote:
> v2:
> - adding owner_on_cpu() refactor, shared by mutex/rtmutex/rwsem
>
> v1: https://lore.kernel.org/all/20211202101238.33546-1-elver@google.com/
>
> Kefeng Wang (1):
>    locking: Make owner_on_cpu() into <linux/sched.h>
>
> Marco Elver (1):
>    locking: Mark racy reads of owner->on_cpu
>
>   include/linux/sched.h    |  9 +++++++++
>   kernel/locking/mutex.c   | 11 ++---------
>   kernel/locking/rtmutex.c |  5 ++---
>   kernel/locking/rwsem.c   |  9 ---------
>   4 files changed, 13 insertions(+), 21 deletions(-)
>
LGTM

Acked-by: Waiman Long <longman@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7961d0f7-d1e4-d631-5806-58607e50279d%40redhat.com.
