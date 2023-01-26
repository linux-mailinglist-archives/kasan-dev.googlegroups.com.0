Return-Path: <kasan-dev+bncBDLKPY4HVQKBBP6PZCPAMGQEO6HXCNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 68EBB67C4B0
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 08:12:00 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id k1-20020a05651210c100b004cae66ea2bfsf589808lfg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 23:12:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674717119; cv=pass;
        d=google.com; s=arc-20160816;
        b=D2b8hDfXDPOtsxCH9XWi+7SbpQOx7ELFyTqVw9ihkja2Gwoj94rduMn0P+CbWsp0qS
         d+caXDPJN/wdNVgbzLY/fsk4ShRKyrkoRlDbcpZ6jhb8GSr9tm2GjftiCCXXiNPvt/dZ
         lVZoQEZMUhf6COX8gCyZXuMPIlU8uIxCCX/AW4pVbkUX1jtOPuZJCZqP+eOlY+FanXOp
         6/1fBk3//WQaRF7abDw0BOUSr5d6nk9cJfGB+qCt9RO3xIkd5BrzlNneJSRHDLCZsWuO
         nPElB00HD2PAC3KIxccW3iewQETJjQ4/nrwjLzrW9cR9EGjV/eUJxFRHEypOPTCuV/JS
         pLsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=93+HjvjWMxpcCopmEA7eyXUYumZixE/w8Tf8L55GKGw=;
        b=ljHW0jK7CFbb3OGmsm0gTmj7Wbx7J9asGwnLgH/blUqOrM1OnIIfoRDCsJeyiE72Fk
         8mpDVb86wgO6jyMq2gJam04NmdjLRDIfM/KWQC67lhQfQmPUt0CHVwT1iHbkSXX5IOD1
         ic49hdAQhT2lGc5yjdS0G7M1suR3gK5q9WQ0MQcKjb97LHZ08cIKh6nP+sGTwkGVpdST
         5GVpY5R2tHdIBw4jpyPnPfSEPZRt8QYZbZ79NVxCETxuQHZozSKFood+BmZq2II1z7dr
         ZgTo3WKAeL5DPAqFtJMrJCI49UcrbqFYQtIw6E4aCzUvhaXEiKIzlBw7U23+zTaiWoXg
         xTdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=93+HjvjWMxpcCopmEA7eyXUYumZixE/w8Tf8L55GKGw=;
        b=SbWHyyzc3+QTNVRupiJh/x/wN49UaOYEf/HatLqfzjnhvU0LZd20vrXmoup+NfBVOq
         vh5WPaSGZcz0qtNJ/pBYdqDeHRZ/jZz7mGHtB78aptCqwyWGGsMVcMOTK2ssFX0yMwGN
         g11N+evBy6J+PbPds6KNzBdT4Thua0dMbDhQbt6SPpVwoFzkAksldYxR8TxSiOZze9Nf
         Nn6FJGzCne56tvJBNyYGe5E9iwty3GQ1d35r4hkW4o+uiUWII9dHLF4ipRCj3yFhdz79
         jMzlIfYkVgcGQCmEXvyMHTQPFiASQZTwPEfN0jMGxeALl0RVjiDpeaf/6cbmPujTi8FG
         9W4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=93+HjvjWMxpcCopmEA7eyXUYumZixE/w8Tf8L55GKGw=;
        b=1pmYEMsuVds5IBl9zXFJFYHUldEeT+DWFK2+MyC9uUpbm7l0x6iFpS/Rq2YjV2Lr1+
         yDoMlSkW2pz91xR2OvqkXO1XZv7RfZETLdV5CDKjZThM3+r3xgRqfyylzKBMArnEjDag
         vqzZzn0PbwiXJoR/evV+MpSAmWJGaozSFIakICWyfz6C2iIue+tkQxNvHCFwngrcZmhA
         2qQYxoCWVpnWJOvCiy7C8ASOcEWQ4dvxw/YtyaVeMWokdM9kRTrMkj/8K25nY63NRzuc
         LfS4vvh2YGA8LNpTVe7eBER3wCHw48ZsYNBDNB4h0uJYDLDmO9Z/Tf8bjQ0SYokWBnUP
         sk3A==
X-Gm-Message-State: AFqh2kq9w2UwiGJGM8f2DSY7M1egEKW9h+UP1058Fv1yIORugWIOCdxy
	l3VJHojmS+XlkW882JBdD+I=
X-Google-Smtp-Source: AMrXdXspI4zA4/fQYlTSf+hKPM3GCW+i/5IJLXgZiGJbr0pI3ersSmtTJsMpU6POnPWEJecuBgNEUQ==
X-Received: by 2002:a2e:9ecd:0:b0:280:4f2:762c with SMTP id h13-20020a2e9ecd000000b0028004f2762cmr2167191ljk.58.1674717119690;
        Wed, 25 Jan 2023 23:11:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls728320lfc.0.-pod-prod-gmail;
 Wed, 25 Jan 2023 23:11:58 -0800 (PST)
X-Received: by 2002:ac2:4290:0:b0:4cc:8484:58b1 with SMTP id m16-20020ac24290000000b004cc848458b1mr8421183lfh.40.1674717118576;
        Wed, 25 Jan 2023 23:11:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674717118; cv=none;
        d=google.com; s=arc-20160816;
        b=gqB539FkZsFkc+LzhaVXUQPW33s+eBi1eeY8Wb3bQytBEBnxF85yPVhKVzYiGccFr+
         NfhVZJWCNQqo87ly1SPZaV92x1k5Fx2gXRjWiMRNNu8c2JF7EFWOdlu5HL/kZ+epgRaH
         lpGN6fPeYLP0H4JOT3NEpLcUysoIH4DBbbIFjrgXVJVFt0jCK6RU2TUvR0rShoXY6UPs
         kxj175hg+SEqnyW9dkQQM0aOYgAIadebCn/42XNZjAzNfjl211Wtmti/zHqJiL4RarjO
         0kxeuSdZc7xt2v2fMwLfnhgEP3BwlGoCfCYyCHSpuuqLWR/WCYerURUSL8jHrfpm4GIt
         LZjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=JeakGdRP5yKoL0WAPlAgj6ZXOkb+bLBtYoel8UmVfYA=;
        b=WNM+Mg6AFqI76iY8HpHu4dtuNUhus2JBa4+sliIn6YYgwJZnCKNWMe+kJJrjF3l+VR
         pvlawWLPAGknjQXJx70ElcXetiCCRyoNTM3DK0/fuaLFdbb4yTzwRwTaBBEUIKj1Zy4+
         jkNCv6q8cu+5N1lWZHlei5XjL1luuNSz14sAtYZfl9S7CM9gUr3zzjQ4qbNb7E1gprE+
         8Sgfj3FEoehDtQya0YbAoNwu6fl8AxyZlMqng4cmeE/gH02pmN/0lpGUzsM9aVTsy8BQ
         kN7rLNEPHFfGylGulh3vmVKNlx+lSGrZ+T2e+1W2ERgAjh5XsmzF8YxhMrSbrfpoJyt/
         /dkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id c39-20020a05651223a700b004d57ca1c967si22288lfv.0.2023.01.25.23.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 23:11:58 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4P2X2P6ns3z9sdG;
	Thu, 26 Jan 2023 08:11:57 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 4w64rmqn36fk; Thu, 26 Jan 2023 08:11:57 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4P2X2G1D81z9sd7;
	Thu, 26 Jan 2023 08:11:50 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1B2B28B76D;
	Thu, 26 Jan 2023 08:11:50 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id AphlReuE6EUW; Thu, 26 Jan 2023 08:11:50 +0100 (CET)
Received: from [192.168.5.2] (unknown [192.168.5.2])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id CBFF28B763;
	Thu, 26 Jan 2023 08:11:49 +0100 (CET)
Message-ID: <6f15e5fb-e02f-5b2e-86fe-ec271866330f@csgroup.eu>
Date: Thu, 26 Jan 2023 08:11:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Michael Ellerman <mpe@ellerman.id.au>,
 Nathan Lynch <nathanl@linux.ibm.com>
Cc: "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
 <87h70for01.fsf@mpe.ellerman.id.au> <8735bvbwgy.fsf@linux.ibm.com>
 <87v8oqn0hy.fsf@mpe.ellerman.id.au>
 <0c46ba45-1fff-d067-159c-1951c5985de0@csgroup.eu>
In-Reply-To: <0c46ba45-1fff-d067-159c-1951c5985de0@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 11/10/2022 =C3=A0 12:25, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 11/10/2022 =C3=A0 12:00, Michael Ellerman a =C3=A9crit=C2=A0:
>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>> Michael Ellerman <mpe@ellerman.id.au> writes:
>>>> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>>>>> + KASAN list
>>>>>
>>>>> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>>>>>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>>>>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>>>>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>>>>>> KASAN support"):
>>>>>>>
>>>>>>>      A kernel with CONFIG_KASAN=3Dy will crash during boot on a mac=
hine
>>>>>>>      using HPT translation because not all the entry points to the
>>>>>>>      generic KASAN code are protected with a call to kasan_arch_is_=
ready().
>>>>>>
>>>>>> I guess I thought there was some plan to fix that.
>>>>>
>>>>> I was thinking the same.
>>>>>
>>>>> Do we have a list of the said entry points to the generic code that a=
re
>>>>> lacking a call to kasan_arch_is_ready() ?
>>>>>
>>>>> Typically, the BUG dump below shows that kasan_byte_accessible() is
>>>>> lacking the check. It should be straight forward to add
>>>>> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it =
?
>>>>
>>>> Yes :)
>>>>
>>>> And one other spot, but the patch below boots OK for me. I'll leave it
>>>> running for a while just in case there's a path I've missed.
>>>
>>> It works for me too, thanks (p8 pseries qemu).
>>
>> It works but I still see the kasan shadow getting mapped, which we would
>> ideally avoid.
>>
>>   From PTDUMP:
>>
>> ---[ kasan shadow mem start ]---
>> 0xc00f000000000000-0xc00f00000006ffff  0x00000000045e0000       448K    =
     r  w       pte  valid  present        dirty  accessed
>> 0xc00f3ffffffe0000-0xc00f3fffffffffff  0x0000000004d80000       128K    =
     r  w       pte  valid  present        dirty  accessed
>>
>> I haven't worked out how those are getting mapped.
>=20
>=20

Alternative patch proposed at=20
https://patchwork.ozlabs.org/project/linuxppc-dev/patch/150768c55722311699f=
dcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu/

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6f15e5fb-e02f-5b2e-86fe-ec271866330f%40csgroup.eu.
