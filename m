Return-Path: <kasan-dev+bncBAABBRF7SKKAMGQEQVBN4PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7790152B332
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:27:01 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id x36-20020a056512132400b0044b07b24746sf706996lfu.8
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652858821; cv=pass;
        d=google.com; s=arc-20160816;
        b=y/A2KP9tq+Ajut6u6OwmVAsiP2YOJ7L7z8pJzkDJLXkKt6bPjaz4um4AW9MizGJbgj
         wA3yaeoO6oaG2oNWrMKPNwaBuA6PTSkAs/tueu0kdYd6oUjj6pO4zfDeWXoIbMq8pTdQ
         6JgApZRZblK31z9KswgCYoUCdeA630kHp4MZpyAAbGiN6yqIgyJPlcg9AMtWg9qgo263
         RQ25Cc0K+NtIySdyAhuBb+Ue/TBoOZFSOULJDDgC+PK+yPEqos+nIMndGOirTXUCkhwb
         TuS6gU+gGogJZcReC1+gQmFjrOCb2illBsAxAsFZf49T0qYTzp1/9hFF1sY6I525syJt
         iYzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:date:message-id:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=pxWRuvLB9cx+9tlRAlFcv1zcnBZ8CIpQ+lZ3tP+8Oew=;
        b=HYIJ2JM5bXRF0jREYOJQN4GIJ7eYsEVIcDFe6gWe5PGLrKs/Zvik5kvb1fZjNUxbuF
         CfJGwfoAo9eAEDdm4HIUU6EM3oweIoH9P13o1lvtUj1DSq2AXhYcNFWGcEd/sEi0D5qa
         kEQapMLJm+vL2ZA6TcJHgFUvnu0AZizXft8t8PHa6S9ACYxWbqZ5rmQaz8QyZ68iOGq5
         nxK4/pnDUATgI/pukCYzt0XVOdXbznOMBxS+KwDKqiRsmxmsi1/2pfWyXVXbAlLzyqg3
         5WfrhJ+kD/XJsMw3fryQKj4F46Xb3VAVG0ib/rCbqpcDpw6LXLPkpDjgQ1TY8MmVteoz
         FOyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZtfLMMXk;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:mime-version
         :in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pxWRuvLB9cx+9tlRAlFcv1zcnBZ8CIpQ+lZ3tP+8Oew=;
        b=S7JCZVXvejJpvx807UTzBQrR645Q7e5NeVFvyQHn7OckVCY58oiY9yzFuJGXbNhfTb
         Q9AUgmUv1ayrC3amqWI3PrzLtblcmzxOdki1iu+O8Ep6xzIZhC1M4Qkxt7NESNi0AE16
         rHlubpvQiL+hk7hM8UeqL1koNo4jv3SYtfDBoxsAcaEoXLZYReJ7RH5qabNxJNGpQMxH
         CGwsE8TStd1p3wY7VYiB47CisY6pMbnZodxE92oatyUZycwrJYUgbLO6Ym4PizMotzyP
         yC1Vdit1R52my6xSqf2NJXwHyd/l1uesPaBg8cTBJJQWiTzhUXk8ar/y3Ct5/lSwTZ6A
         HL4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pxWRuvLB9cx+9tlRAlFcv1zcnBZ8CIpQ+lZ3tP+8Oew=;
        b=u5Ved3L05TGOK84zdSOpNkOm7Sv7qkE/9xxds+Ne2wO7cN2kJuIXTEZPpx1zx2wfBR
         ak46zWVbB8pFOTT/mi46gTLpgAwtoR1GNIYI2J6se9taF4cw6I0sBi+y/BBRhBZqZMDH
         ah2bI2WTQJ6MNCkSALCd9cpbk1RZ73rEAAXJU2c/cm3yyBb2Lzx/K366MOnyw4UairUt
         sjyEJXFfDRUHsQNpP2tavCcWQUXTecpShT2vUHJMWrm9UDlfJvYX/1hguO6Ns0eKHLdD
         cB62K9BrMiA7Z3lbhp9wwtrBtDGMsBhj1DFfLzKp9kvZvRDp/H505M/ep1adBytZtPSG
         kAXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZpNBQKJsjR/of0Ba0ug6GPoWV9jDIBpjBz13h+UgVmxmejRn2
	InqPqzWMG5DRotPPLXRLxgA=
X-Google-Smtp-Source: ABdhPJwOLAkgCac1uXonfkg1ZmZ18KtiNIJevjvEPpJxKH1lSHVML8csjUuY0/v2VM5rmGLB/Ctt4Q==
X-Received: by 2002:a2e:b0f7:0:b0:253:c5da:2357 with SMTP id h23-20020a2eb0f7000000b00253c5da2357mr1747588ljl.395.1652858820622;
        Wed, 18 May 2022 00:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls3459620lfv.3.gmail; Wed, 18 May 2022
 00:26:59 -0700 (PDT)
X-Received: by 2002:a05:6512:3d91:b0:472:5f7a:28a7 with SMTP id k17-20020a0565123d9100b004725f7a28a7mr19363955lfv.429.1652858819794;
        Wed, 18 May 2022 00:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652858819; cv=none;
        d=google.com; s=arc-20160816;
        b=usFqvpuV5tX5JFLKRmoX1GIIXroyfZHhYnhrd0DVG1NGWRAaFATFwOwxa7eLILCbM8
         f+e6RcLvjIPrJJsr+Dmw/3o9OK4AV7trRKAFHPng4xSFD/t/ttbf0d/sHbkrPeBZXYlZ
         en5mgZ2ceBRfFPPOfnyxxRRtPpf+ER97tzFbBKOwxjYvo5qmuoqvBdizS8iDAxwtF1gD
         SRaXmydaZDV8+RJc3nAxvJqn8o7n10MiG/OCZWvfqCHDJV/oqdsuSTeJiVz1+07I/rag
         NjRPXsLio4WMZFk6PCv/81/YaRTk86U2ktT3T/8+w4q71DL2eeMVN3KALyBz2L+UQdgT
         9VFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :date:message-id:from:references:cc:to:dkim-signature:subject;
        bh=ZqfBdkcmlkwWYIyfRhtrFzKDZTsuUSEPNTrzwyKaxFg=;
        b=gCI5NIPnVKlP/dh3UeL+r0LK8/Sc3ojymk4puskUaqzvdCM+gKHcUD64xLdeLiI/gC
         igwekRzWI9jd10LSox8ZHDtFaGnwf8EZ2yghZU+j2+8nZ/AzK89mHY9UJrkdBAUtpnAn
         2a5nW1NR2lSdQvMI/cvJAEDsLiFsqixrdClDzqq/Fafa61xTxiBryTalwYx7t5of59ce
         36a8uu1ZEYGb8TM8fkhj8Ma4giDlXeP+HjQoRnnL0e5hcztbJrK5jiG2PhB/5mw2jN+i
         sV4wxhnlKmvKnAkqpnlh66dOIDZfAWHvNhqgluQi2FTlYtvpBIpD7zX7OsuxRA1snl8I
         UZ6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZtfLMMXk;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id c5-20020a056512238500b00473a659879csi53680lfv.13.2022.05.18.00.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 18 May 2022 00:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Subject: Re: [PATCH v3] mm/kfence: print disabling or re-enabling message
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20220518010319.4161482-1-liu.yun@linux.dev>
 <CANpmjNMSnvKVYOwof1WSxVX+qRsKUK3QPjPuWk5KdNjwMkEfPQ@mail.gmail.com>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
Message-ID: <baee3714-65fa-c768-83ff-f1448323dfc5@linux.dev>
Date: Wed, 18 May 2022 15:26:48 +0800
MIME-Version: 1.0
In-Reply-To: <CANpmjNMSnvKVYOwof1WSxVX+qRsKUK3QPjPuWk5KdNjwMkEfPQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZtfLMMXk;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 94.23.1.103 as permitted
 sender) smtp.mailfrom=liu.yun@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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



=E5=9C=A8 2022/5/18 =E4=B8=8B=E5=8D=883:24, Marco Elver =E5=86=99=E9=81=93:
> On Wed, 18 May 2022 at 03:03, Jackie Liu <liu.yun@linux.dev> wrote:
>>
>> From: Jackie Liu <liuyun01@kylinos.cn>
>>
>> By printing information, we can friendly prompt the status change
>> information of kfence by dmesg and record by syslog.
>>
>> Co-developed-by: Marco Elver <elver@google.com>
>> Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
>> ---
>>   v1->v2:
>>     fixup by Marco Elver <elver@google.com>
>>   v2->v3:
>>     write kfence_enabled=3Dfalse only true before
>>
>>   mm/kfence/core.c | 10 ++++++++--
>>   1 file changed, 8 insertions(+), 2 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 11a954763be9..41840b8d9cb3 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -67,8 +67,13 @@ static int param_set_sample_interval(const char *val,=
 const struct kernel_param
>>          if (ret < 0)
>>                  return ret;
>>
>> -       if (!num) /* Using 0 to indicate KFENCE is disabled. */
>> -               WRITE_ONCE(kfence_enabled, false);
>> +       /* Using 0 to indicate KFENCE is disabled. */
>> +       if (!num) {
>> +               if (READ_ONCE(kfence_enabled)) {
>=20
> Now you could just write
>=20
>    if (!num && READ_ONCE(kfence_enabled)) {

Sure.

>      ....
>=20
>> +                       pr_info("disabled\n");
>> +                       WRITE_ONCE(kfence_enabled, false);
>> +               }
>> +       }
>>
>>          *((unsigned long *)kp->arg) =3D num;
>>
>> @@ -874,6 +879,7 @@ static int kfence_enable_late(void)
>>
>>          WRITE_ONCE(kfence_enabled, true);
>>          queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>> +       pr_info("re-enabled\n");
>>          return 0;
>>   }
>>
>> --
>> 2.25.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/baee3714-65fa-c768-83ff-f1448323dfc5%40linux.dev.
