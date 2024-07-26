Return-Path: <kasan-dev+bncBC4KTZOM34PBBF6ERW2QMGQEUBNIO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 172C693CFC5
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 10:45:13 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-397052a7bcbsf19893675ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 01:45:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721983512; cv=pass;
        d=google.com; s=arc-20160816;
        b=NeX0DcAGqLR+pd3cozp6KVHU+kiqAUc9sP41Zth0nx8YsZ+wHp2Q+mgu/URfrfqJVP
         SaYwObEjmVJgWLx20AWPJ+oYWu5Ul2rhN2Ln7c54K/25AW8YEoxqQPSngFDmbtK4/LRA
         WdK1ck+V9kri3x0HXhp2VbKjPLxNruM1/5n/YEt05EZNrxnK0biz8bbp3tsp54ANV3Lz
         HwP7h+vA61CvHlFsO9zYXfWmzUt2D+IShfjBpVFEot2kVS7lrJP7TOmHwS/NaPIDnmVY
         eS9ROe6L8Flc9nN4fw3ydojCOtOe+8BhjY6sTdzz+okM2f/v4zUoHY4M2uXkm5d9ie5I
         zK5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=iUUduxdv7aGCzv1dokpxWcyDh/IeF7v1pS+eHvFzLKE=;
        fh=bRUInz7kKG2c6oXThW75NrTebrV8BDucNQDK8ZT53p4=;
        b=OEdNjU3rentkmOVsvCk9TbTybiIW5jUegM+riDgOGlJ8vBI67PpXR3b0HMHiLWlgGk
         NiWRKEXz2rjAON1BUvCg0U46YsnNeOQN+r3hC32QXOtYtv6JO79Bpp0xB4Mo2DNBXXxl
         1tY5V7hFVX8yWDaMJ2MIzz2kvsZZzYbo401Rk4e2v6YnN7nKlcvfrxBxpG+x57Z+YNre
         qSTAWUSIS6GHIFnSGBc1/6y0snmFy1tAQUhPCx/sO1V5xstR24EPCSMO88ukbzjGOATK
         PX33GRGCLDMp+lLYNTUvSMaVHsxte+sULLVZ8vjfJ/AA8sB9uqYK/Pp+2WhLcW3d50n7
         bucw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dzm91@hust.edu.cn designates 162.243.161.220 as permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721983512; x=1722588312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iUUduxdv7aGCzv1dokpxWcyDh/IeF7v1pS+eHvFzLKE=;
        b=DGns60kXfFDtdDQzqyTC8a4vOLtZuhpGQVbyga2QrAm6fZVNuuN5ROUCLhk23o7STe
         DCmld6Q+3iDX8j0Cytl/y15siu/bBVbOPhZ/7CsVpElqQn8V7dx2ai/YKtsz/FDc89tK
         E5IoeZ0sw5LAE9XMP2L6xf4+13Tcd8YxBhGoWS6XHFwmPmBfv/P3ggTJrXfCEHYbVSw5
         40VzsroBowsI6gVWx3VLof7vYbzVAh1xS4uCooUAaKPuCU/PgT6ICh37lxk24AOdZOfO
         RZqw/jq/StV4DC4Sia6qbJ2WtpV6XTdEelhx9Q0/gxTEGAPfIi8yWogt4wjPhn8w2rs4
         KUUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721983512; x=1722588312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iUUduxdv7aGCzv1dokpxWcyDh/IeF7v1pS+eHvFzLKE=;
        b=M8FjyvQ4GlB4ZtQJ8EzeZU61n8UnoIG0O3ITcwhXaO9j46GW3etFvUgdPhhc8Vbwnh
         ABhjVszsF1Nmz7V3tetrn4ihdqZmdUorWSFYQIbtoXy5Un103C8a+3laILlF1Kdsgjsv
         nxbLKtnH785g31gYjqPjZxZVai0v9ZL6muI68vK3vKiVWMGdPsZaqJ1LCRuSPYbbP5a6
         JGKdVB1FkHpNOAc1JQ5xf0OA+Xq8F5HoQ//gsV8VYpFKrVOBTjz6YhuiLanrRwv81HZo
         tB3FMQIEPJ1LsXpVvX2hl+IFIf+qToS7SIBetRsUXwHq9Gv2x6QBWgXMBbRmlLB73AdI
         eHCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdIvTMpuuBd5UlXLAgl6AOpju9Q+J40jNY5y3NT6vIBn4uNqxQ71kg6eCZzJsv+9Rttu+iUtfjkw0/s2kHXdvJY3aHlZN2Wg==
X-Gm-Message-State: AOJu0YxQ4dC5xi+xj49MRINZ2N6RmCoP4+gZZBZlpudcaue2Do+nltnA
	A43k7K4prEweq6dIORa0Zm4/pK6dIN63Dn8OsLXyQXHnb108WWcJ
X-Google-Smtp-Source: AGHT+IHgam4IUbvUbu3y5RI4vQBBGP2P/GxHhcvUjYqKgU1/NvMn6MgKUGZ87DazN9VliGrODMJmFA==
X-Received: by 2002:a92:c561:0:b0:380:f340:ad66 with SMTP id e9e14a558f8ab-39a2185cc91mr65369955ab.26.1721983511590;
        Fri, 26 Jul 2024 01:45:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c83:b0:383:6552:77c6 with SMTP id
 e9e14a558f8ab-39a21798556ls13638235ab.1.-pod-prod-04-us; Fri, 26 Jul 2024
 01:45:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSCdVvUAThTlUqMdTk/Y40pVMryRVeqjjYJJ5bdOzMrDEgngKrZDK0H/dVpTlLOGzghkzS+8hd+WNC7jP/G4P9tDs0lN8YBz60ow==
X-Received: by 2002:a05:6e02:190e:b0:36c:4688:85aa with SMTP id e9e14a558f8ab-39a217d807fmr73324355ab.10.1721983510849;
        Fri, 26 Jul 2024 01:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721983510; cv=none;
        d=google.com; s=arc-20160816;
        b=lqvOUjkJoNsXxs75FneFcDK/NICeXeriBkIM+Ovlf7ug2dq65slKTjl9qVCYg5NKwj
         R9JGKP0JznX7j4tCtRnUeBMPRYV5mfEqn3vatV37ekDGP6Bu6D/tP7gKDFSJSYGQBDnc
         JIwTUdh2JVP9zlid0vcvJPj2JXVG8/QIis/C7wyE7Frd2OA5rPPVu4XC7ma+gywq6hnp
         F4B1aI7MbdTq/eZYeDFGZ8tM8LSh9U2K0/s2A3drtBvaxJf8fdwmXR/oTmp45oUp03vk
         IRCnfG8aG65TkuCA8JdBTCaUHmeI0FufjaA074tnD1LzFE4myJ/0blwAJLlVvSTwCZJo
         zcUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Y+xptRAiU8HEv6MU9lWTyNs1jjsPOXvjx/YHrRd/ogk=;
        fh=3neaDV2KDXi/D1xDlDh5KKkt8MnbLM5MdhdG3QBG/Vo=;
        b=XpXDmHOtZH28bu6jkaobn8ibJb5RfLEkn1r9afvlZBmwjQ6lcjfY5mE8M0sXILpqWZ
         KTUBQunT4rucYq2dFkqNY14thHwhzwjMSZang03i7M71Y9Tj5EWKt8wWijdrLzoLgypL
         mwKp2deiYx08kk2S4GcbCGhESHMMckbNVdfLN8tjPZdY6IQtEjdxrgWJIOPngq27eXoP
         FTQaJVY6IbWI0iiDma8rZSgW5UwrpPGxCA38rr6t5kqFz6fnXXrhUVHUwJr2lJFq9zUs
         1zPPv2O3KIpNAR4dgEzJG/l5mU5S7UdYAwQgWRcJQ2VV5jkxyEEYvF0A85QoYw2MjpHI
         ThjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dzm91@hust.edu.cn designates 162.243.161.220 as permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
Received: from zg8tmtyylji0my4xnjeumjiw.icoremail.net (zg8tmtyylji0my4xnjeumjiw.icoremail.net. [162.243.161.220])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-70ead8ec914si166092b3a.5.2024.07.26.01.45.10;
        Fri, 26 Jul 2024 01:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dzm91@hust.edu.cn designates 162.243.161.220 as permitted sender) client-ip=162.243.161.220;
Received: from hust.edu.cn (unknown [172.16.0.52])
	by app1 (Coremail) with SMTP id HgEQrACX92wAYqNmsTUCAg--.25305S2;
	Fri, 26 Jul 2024 16:44:48 +0800 (CST)
Received: from [10.12.164.29] (unknown [10.12.164.29])
	by gateway (Coremail) with SMTP id _____wDn0Nb9YaNmiJMFAA--.5993S2;
	Fri, 26 Jul 2024 16:44:47 +0800 (CST)
Message-ID: <221f644f-c085-4873-93e2-4918375b1747@hust.edu.cn>
Date: Fri, 26 Jul 2024 16:44:44 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Marco Elver <elver@google.com>
Cc: Haoyang Liu <tttturtleruss@hust.edu.cn>,
 Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
 <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
 <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
Content-Language: en-US
From: Dongliang Mu <dzm91@hust.edu.cn>
In-Reply-To: <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: HgEQrACX92wAYqNmsTUCAg--.25305S2
X-Coremail-Antispam: 1UD129KBjvJXoW7Cw1kGFWrWFWfAry3uF45Jrb_yoW8Zw1xpa
	yfuFyIkr4ktr17K3yIgw10yFW0yFZxtr1Ut3WUG3WFvrsIvFnaqrW29w4FgFyUZrWrCFW2
	vF1jva4Fv3W5AaUanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUPFb7Iv0xC_Cr1lb4IE77IF4wAFc2x0x2IEx4CE42xK8VAvwI8I
	cIk0rVWrJVCq3wA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjx
	v20xvE14v26w1j6s0DM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26rxl6s0DM28EF7xvwVC2
	z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2vYz4IE04k24V
	AvwVAKI4IrM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l
	5I8CrVACY4xI64kE6c02F40Ex7xfMcIj64x0Y40En7xvr7AKxVW8Jr0_Cr1UMcIj6x8Erc
	xFaVAv8VW8uFyUJr1UMcIj6xkF7I0En7xvr7AKxVW8Jr0_Cr1UMcvjeVCFs4IE7xkEbVWU
	JVW8JwACjcxG0xvEwIxGrwCF04k20xvY0x0EwIxGrwCF04k20xvE74AGY7Cv6cx26r4fZr
	1UJr1l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l4IxYO2xFxVAFwI0_Jw0_GFylx2IqxVAqx4xG
	67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MI
	IYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E
	14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVW8JV
	WxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuYvjxUsrWF
	UUUUU
X-CM-SenderInfo: asqsiiirqrkko6kx23oohg3hdfq/
X-Original-Sender: dzm91@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dzm91@hust.edu.cn designates 162.243.161.220 as
 permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
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


On 7/26/24 16:38, Marco Elver wrote:
> On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
>>
>> On 2024/7/26 01:46, Haoyang Liu wrote:
>>> The KTSAN doc has moved to
>>> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
>>> Update the url in kcsan.rst accordingly.
>>>
>>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>> Although the old link is still accessible, I agree to use the newer one.
>>
>> If this patch is merged, you need to change your Chinese version to
>> catch up.
>>
>> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
>>
>>> ---
>>>    Documentation/dev-tools/kcsan.rst | 3 ++-
>>>    1 file changed, 2 insertions(+), 1 deletion(-)
>>>
>>> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
>>> index 02143f060b22..d81c42d1063e 100644
>>> --- a/Documentation/dev-tools/kcsan.rst
>>> +++ b/Documentation/dev-tools/kcsan.rst
>>> @@ -361,7 +361,8 @@ Alternatives Considered
>>>    -----------------------
>>>
>>>    An alternative data race detection approach for the kernel can be found in the
>>> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
>>> +`Kernel Thread Sanitizer (KTSAN)
>>> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
>>>    KTSAN is a happens-before data race detector, which explicitly establishes the
>>>    happens-before order between memory operations, which can then be used to
>>>    determine data races as defined in `Data Races`_.
> Acked-by: Marco Elver <elver@google.com>
>
> Do you have a tree to take your other patch ("docs/zh_CN: Add
> dev-tools/kcsan Chinese translation") through? If so, I would suggest

Thanks Marco.

That patch will be merged to lwn tree maintained by Jon if all issues 
are resolved.

> that you ask that maintainer to take both patches, this and the
> Chinese translation patch. (Otherwise, I will queue this patch to be
> remembered but it'll be a while until it reaches mainline.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/221f644f-c085-4873-93e2-4918375b1747%40hust.edu.cn.
