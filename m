Return-Path: <kasan-dev+bncBC5L5P75YUERBOFUYLUQKGQEGSN43PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F7A16D187
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 18:11:36 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id i6sf13811152wre.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 09:11:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563466296; cv=pass;
        d=google.com; s=arc-20160816;
        b=X26gK1eirE4UilzYQ+uVw1FGuKZuCVhCgeUOEZHaoEP9kSBh8RhKeG0bNsxOk0gwvG
         ayVYcIOIC8OlYERpHFZloU/p31AzLqwMgU+5zwyxDWqdPcvoGPnRk1T4FDavNkAP1JN2
         eSSaCl2SCoQM1oh0zNo/Nm5EtZoBvYPOt/M8xtnVpitUQtiRo5eelHD6fJgE0UHZdwwb
         ZD0Tays8HV4xeTHxUZTmoZ2uQKggs8MxsIvvQFZSZA2RGtXwDm/iody1fqNrq4StrFNw
         sDkXJKFFn1GbMbTjCIBHF3T9nKdNpSysrNr73MNCdrZsB+vukbWxWXzUbs2Udy5XpGN3
         WjMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=QKDbDnjy1baRkW6uYEWLXJ7Dzokxb92h3lxUnXmlwAc=;
        b=e9f0Oe20Eq9XixyRMjJgJxaFrATfnGMP6UIvFkTHLEinsR5aBTygU0s4bUeQqsRjrp
         khMwlunqRdy4y3wpCnwK6LeoFn+m8zPyr3froaveVe5RGbuq2onHIAdCKmNDK39VGE1/
         xSDaFq9cnGZ0bBOEjYBFv5ZTzM1Kr/XS5A7+/snAtiKOHXziDbLYm0wWZmxSDh1MCkLt
         YEmtwxAC5JvED/G9rvx5sfoYVTLrb4lK+0/MjV61qphZMMULaDpjt56CuQDucrUeKJVr
         9YlAhEeZFANWZxvhDQnagaZzuU2hMNzla1acRNrycwbrc0/oSodRSrn1zcFAO7Nehfy5
         3Xhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QKDbDnjy1baRkW6uYEWLXJ7Dzokxb92h3lxUnXmlwAc=;
        b=Hfi8VHmpvnq9U09C/1ATHuh4XBfjnxm6H5/gVcN3lToET7qirrBS4idclIGEnX+la+
         FOl5VJUbEn3P25TUwmF5IhEOLG1YUF5gKR8y7WBmGm4KFgtgoR1YO+Z24Pjgv7J5yiky
         oYscGWA5oHgrE1KPj1DQxz87jANBAB7kLgM8BBhuFRiAhkq6Y0ntHZqi3JDlHcyBe1aE
         5B3pYPf3mwoCIVk45rBc6LWcS6e+O9wHmocWcKhRfPvD+lC9AKE6q6OjFShb++nlrZAp
         MqLr8509WoRL1x3+VkXKCezjINPIYtNmN32WgRj3Jtyjiyi+H9roniJizZabMwEpGbHo
         U2mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QKDbDnjy1baRkW6uYEWLXJ7Dzokxb92h3lxUnXmlwAc=;
        b=HFLpwA1lGzOyseIwVTo9tkTH7j86PfQaBeY9UrC4JG7V4oVKWz5geLx9C9Jc21uz/N
         bUk7bAZlTH1wAiqhusuSyV5U0R3aOwTtNaDvUQfaHT2bi5dGJKOt0poj0VEn8vmqnCGo
         q5p7a/OGoiSH79+v6kX0diMPMKC8EMxpvAlLm3rQ9UsK0ENgIZCK8JI0iVWl4y1kUG0k
         4WlbMH79RZOBFxmNXvKLjPOvmJ2RrYj69MUqAsWO01gKvk323x8WJ9DHOoKmgLN3e2Qs
         I7rwCZYIyLYapYshr9o9926oaLhnz8WkrdoZxRPq/Xq3rbvNcxxhm6rtAFawW40cJiq/
         JlkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtedGmLcbS89X1z0SCGHeQO5eRfVHq8cj0Y8hNp7wjo4cBkvne
	pH8Flaj7fp00oWZHIr2MJY0=
X-Google-Smtp-Source: APXvYqymZ/PhJTGFacEKcL5AxCTpKgT8vHr1YqG4rEuKNInSnsGtFBQOr6oupYzzokpMrrixdgSe3g==
X-Received: by 2002:adf:e8d0:: with SMTP id k16mr50789019wrn.31.1563466296202;
        Thu, 18 Jul 2019 09:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec02:: with SMTP id x2ls8870054wrn.6.gmail; Thu, 18 Jul
 2019 09:11:35 -0700 (PDT)
X-Received: by 2002:a5d:6a90:: with SMTP id s16mr41505805wru.288.1563466295756;
        Thu, 18 Jul 2019 09:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563466295; cv=none;
        d=google.com; s=arc-20160816;
        b=Dugl4onK7l87TDFe6pFCLlEfd4Eq6BTmxnbnwm0ebiRSsIrIWUSGm1oTmTwPkwqfgH
         whE/M/aE3IYj8rbQq3h+BXMZf13m2JwXUvWKseBJVrze+V9aldDU/it3iRIXRGAQfMI8
         N6K3MZqTCoRZ2azqCEIYsd0QF0elOszJ3bOk3q/un1pNyIEbY2VUSxZyksxnbrlqc3Kj
         3iePyb1ELvI9IUGx9CWgxeRS/42Ov/fTcfmAF1BYdBHfz5tGIKE7+bdmyx+3fgJ0EM2r
         714wdNsW/LBHvwEqyNooiWM8HOG/gJnIy2ZQvK+YhnjgTsKPw8vSi3zE7tWsXsgSMfU9
         LS+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Ka7PIt6i9Q88JwccYuiYHqGAECqE20Y+n7xYlOq9DlY=;
        b=HB/qPFRPXS1m4lE9T8yY521JKd1vWrNbpDc51QEvOOKw1lSmIW7OeAXWwcSTc5tbS0
         qjeGjFaueJG2Thmc3s3c7xnK4+9P2jQkcEEChcV6AX+RFwc7cGNLQEPDvrPuuEQ2ZFbh
         oEStk59KjasVAX0Wa22i27eIiL3YxKaw3gwktBPpZVPjA9F6+o8Ak5fDy14dElTDalla
         pDKPbwWMFYCPwdnyJezKoQXRLRIEvGxGIO0fDbkbKmXnOmFxfRYEihMJILoro6BTTTtg
         jv8kLoc+Klpr6FDX3AwwsksL8WSPMa5R7ImVNh0NnBqydLsWFAHp0l0uBQbsTOCvANWg
         Uvtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id r13si1526695wrn.3.2019.07.18.09.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jul 2019 09:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1ho902-00080M-Ln; Thu, 18 Jul 2019 19:11:18 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <1560447999.15814.15.camel@mtksdccf07> <1560479520.15814.34.camel@mtksdccf07>
 <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
 <1562640832.9077.32.camel@mtksdccf07>
 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
 <1562839579.5846.12.camel@mtksdccf07>
 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
 <1563160001.4793.4.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
Date: Thu, 18 Jul 2019 19:11:21 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1563160001.4793.4.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 7/15/19 6:06 AM, Walter Wu wrote:
> On Fri, 2019-07-12 at 13:52 +0300, Andrey Ryabinin wrote:
>>
>> On 7/11/19 1:06 PM, Walter Wu wrote:
>>> On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
>>>>
>>>> On 7/9/19 5:53 AM, Walter Wu wrote:
>>>>> On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
>>>>>>
>>>>>> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
>>>>>>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.co=
m> wrote:
>>>>
>>>>>>>
>>>>>>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
>>>>>>> promise any dates because the next week I am on a conference, then
>>>>>>> again a backlog and an intern starting...
>>>>>>>
>>>>>>> Andrey, do you still have concerns re this patch? This change allow=
s
>>>>>>> to print the free stack.
>>>>>>
>>>>>> I 'm not sure that quarantine is a best way to do that. Quarantine i=
s made to delay freeing, but we don't that here.
>>>>>> If we want to remember more free stacks wouldn't be easier simply to=
 remember more stacks in object itself?
>>>>>> Same for previously used tags for better use-after-free identificati=
on.
>>>>>>
>>>>>
>>>>> Hi Andrey,
>>>>>
>>>>> We ever tried to use object itself to determine use-after-free
>>>>> identification, but tag-based KASAN immediately released the pointer
>>>>> after call kfree(), the original object will be used by another
>>>>> pointer, if we use object itself to determine use-after-free issue, t=
hen
>>>>> it has many false negative cases. so we create a lite quarantine(ring
>>>>> buffers) to record recent free stacks in order to avoid those false
>>>>> negative situations.
>>>>
>>>> I'm telling that *more* than one free stack and also tags per object c=
an be stored.
>>>> If object reused we would still have information about n-last usages o=
f the object.
>>>> It seems like much easier and more efficient solution than patch you p=
roposing.
>>>>
>>> To make the object reused, we must ensure that no other pointers uses i=
t
>>> after kfree() release the pointer.
>>> Scenario:
>>> 1). The object reused information is valid when no another pointer uses
>>> it.
>>> 2). The object reused information is invalid when another pointer uses
>>> it.
>>> Do you mean that the object reused is scenario 1) ?
>>> If yes, maybe we can change the calling quarantine_put() location. It
>>> will be fully use that quarantine, but at scenario 2) it looks like to
>>> need this patch.
>>> If no, maybe i miss your meaning, would you tell me how to use invalid
>>> object information? or?
>>>
>>
>>
>> KASAN keeps information about object with the object, right after payloa=
d in the kasan_alloc_meta struct.
>> This information is always valid as long as slab page allocated. Current=
ly it keeps only one last free stacktrace.
>> It could be extended to record more free stacktraces and also record pre=
viously used tags which will allow you
>> to identify use-after-free and extract right free stacktrace.
>=20
> Thanks for your explanation.
>=20
> For extend slub object, if one record is 9B (sizeof(u8)+ sizeof(struct
> kasan_track)) and add five records into slub object, every slub object
> may add 45B usage after the system runs longer.=20
> Slub object number is easy more than 1,000,000(maybe it may be more
> bigger), then the extending object memory usage should be 45MB, and
> unfortunately it is no limit. The memory usage is more bigger than our
> patch.

No, it's not necessarily more.
And there are other aspects to consider such as performance, how simple rel=
iable the code is.

>=20
> We hope tag-based KASAN advantage is smaller memory usage. If it=E2=80=99=
s
> possible, we should spend less memory in order to identify
> use-after-free. Would you accept our patch after fine tune it?

Sure, if you manage to fix issues and demonstrate that performance penalty =
of your
patch is close to zero.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9ab1871a-2605-ab34-3fd3-4b44a0e17ab7%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
