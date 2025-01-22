Return-Path: <kasan-dev+bncBDLKPY4HVQKBBCHPYS6AMGQEJRQ6KMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id C88D2A1985F
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 19:23:05 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-385e00ebb16sf2872960f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 10:23:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737570185; cv=pass;
        d=google.com; s=arc-20240605;
        b=NJ2CHd6S1SAg43x6z8qokRKrq2gkbtG290JiTZYzmZ/V8tTVoKKCbOiOG6zl6zLtHi
         2Yx11nPL4IDa6KOL+EfnBzU2flBtC2Mm7CkR3O58hDgnFQJnofeEpVlznYpYBxRgF606
         PbyuSVrWNV1yDcEZlUkCTkn8vjm+SpMK7T0z40VkDzXMMVY3Iap0wEwXvwVjdjbMqEu5
         Hwx5htKijJ/k727VP/zrAn9Uy7pFgFD+Hi6yX+aLHzQTZDwluK0CJUzU3ZofzDhr6mfE
         lljbwuf/fU762/RbrN6vfqAyttWw5Dj1xGlEhuOBUovq2AP898dlYP1oDOiRgF1n299w
         dCRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:from:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=zzKFZlks/qKHhdyeE6utViSCZXyWUG6M8Go0Dp0HNNc=;
        fh=l2PAkLH13VTsgH6/XnqxgtgG9aceTYjg8luuvWCsaaU=;
        b=jS9v6f1bEBebVoV5eUM5HkGOdWGKJE2YTVdLPceR6fo2nWCSBUC7opprNW7osudkKV
         L3fwTGqv5TNBs7pyqCWaQWRDxLP3U7lLCcMbMNrvU2Lcqq973I4/M+u2mZDGWuM6+Nzk
         2FkKuAp0X+vYxLSR5ufbhGg5Kn41uMi+Z9FJUre5YDRdO/H0G7I6CEDq4/veCwIGGNH9
         EfDTZ3o61XPo7yKw968XisKmSyldAMgXq1ExCuR7NImmOE4ZwDHmSRKBf9RSjCgj7Y3n
         eTCUMnztPQlTClWEXyNEOG6UN+3zZAC/2iulWEbxVBYZlrz3b7R7k+s11Lqo9MjR1lA8
         K5Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737570185; x=1738174985; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zzKFZlks/qKHhdyeE6utViSCZXyWUG6M8Go0Dp0HNNc=;
        b=gMGdhTkHvrikX6mQAK2J77qzljPkPAwAjLJ6Uej8d1CyHxrSloqBqpSdd63YZMfHAX
         N8CQf9IcY8GXyYvbrTXhgGB0QwfdvblX1EZcb7Xs/JbNC1sMsn4rw32+SYyKPHkCH0BG
         GbqGXteo3F8wuKidBKgUUACNfp2Ka0CSYExPTUeIS2tTv7JrtnyzlPlGjFGkzkXaiEcb
         WPRPUNLhuyZnWQiS+1a/TYQYzFLGl7zhVnJcXHvB0/s8aNa0s5Gjd2SfC8HQvi6oU9DF
         csMGA7Hh7YjebZqvwLRKPuZxVHrrq62h7f2rM6qCSqQ+8ax9+IHqsbwtJvZsJAQichfi
         1XSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737570185; x=1738174985;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zzKFZlks/qKHhdyeE6utViSCZXyWUG6M8Go0Dp0HNNc=;
        b=NwlTF3iXmL/rJBCDf06vq4ZTMWBTeuaSr2tN5OiujxnH6CmAEf4WehFjOLiHJrwmaG
         ib+uG3pWPQX8h5sd6oFbSzRnrZcFglgkgIM1YXb5ctYqyC/DcOsVozcH4tTiI+nOhX9a
         +t2PT6mbDKVcZ1chWF5KVEj685jZdb2Sco2urVOB4LJaO60yNGe1KsAiowxWk7lCNHuP
         u+lXSuWKovTv671VRjcHHGEKiEDiT64Lns02Wq6InNLUJrIwDssi7qsF+7MXuA1Z1aFx
         hNOacnQ/Pi2Jbg6tqURkdTyGGgomloDScgmZL+cKLZeVaXIMLcO0SHUqCk9em3xl292s
         V0Qg==
X-Forwarded-Encrypted: i=2; AJvYcCXOYrKzRBWYHuUC/9Dsk4gPx8dIBK56i6RT8wnWHIsZNqZSfoOS7asmvBNGC08O7rtWKAS08g==@lfdr.de
X-Gm-Message-State: AOJu0YwUUJFcTxclLHIpMpFekIT8Aqrb53BdQWc9gVixzP89I/NPuKzR
	3MKkmkYk3lE10dJd8GpYFuVVqwXYdHgiFdWJYRE2U+mbWyI9Shiq
X-Google-Smtp-Source: AGHT+IFGy9ENp8xgpQsMjvo8OyUS8W9mdmcf+I32Ze6wdDRjRveEmXztZ/CpcsbOzonpFGc3YS4wYA==
X-Received: by 2002:a5d:6d86:0:b0:38a:8e2e:9fcc with SMTP id ffacd0b85a97d-38bf57befa9mr22007212f8f.45.1737570184440;
        Wed, 22 Jan 2025 10:23:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1393:b0:434:f3a1:b20d with SMTP id
 5b1f17b1804b1-438b874ec4dls595795e9.2.-pod-prod-04-eu; Wed, 22 Jan 2025
 10:23:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7lhQWS5RHPiAhH3Zffp/jFz6lzxFugGlTtj50eiJxfV+BFX3BomE48eGHyllOVM94T/dRK8Co9Fs=@googlegroups.com
X-Received: by 2002:a05:600c:3d85:b0:436:488f:4f3 with SMTP id 5b1f17b1804b1-438913f8926mr226189245e9.17.1737570182246;
        Wed, 22 Jan 2025 10:23:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737570182; cv=none;
        d=google.com; s=arc-20240605;
        b=klgxj4lRigdaSsmvV36on0fQrl5pHzqaiFBAyd2wPPUME2TgPfiTlvUC0Jq8x7hneA
         9m8JvVyEKSVqOcrETGp/vJ94ZtvldAy7VhP3iUU/m6GBQd795hK/y6pOBIil31qswhAa
         n6WNvRYZSbrPkgDnTEwsTMXTzIFYr7bh8Edzp/7uiRbz99ENgdybmAMX7SXwmvWi9hLE
         hJuQdwL6H5Uk1I5U5RPOLWnDJ2StYi60qMh7TKOIxwaCpZ5J9YFa0kbkuThgtFRQ9KCx
         CIAMMEEif7jVoM6KbQCkNwiNRF6FFhOsspSuiJTV9oGOIadsDvY5TytUTHWdscGnCb0K
         Z7zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id;
        bh=LN/KjvgNM9UDaYvGL/kD9+KdvO0FK2Qr6j5jfboXUS4=;
        fh=roIeQjIF3/jvpZnIRVdYV//b5cNiyg7DggcCYnXw7DU=;
        b=jA9uz6aFS4kjc3uvhQv7vBUUu+w+kBpEeV5SvEkGBEJ2X+iqt7qPoIGllgJWhedMSL
         kSAnRtZ87apE+E5SZDXsFAtx7Ar83yFPJOsuKAokZHRUkq+sPA8so4VoEO+NCn6CC7gu
         lkFzl21NPFV0rdgE39m7MOtz7d/OGKvsZ8KrjkvIJzW+MhCbbsTEpMwMW8RGh+2lf6SD
         aV1gJbxo8LMWM5VKk2KqgBzFxR9HPN2+ABQOQJT41Fy1rLR5IQUhq3s7EFuY2keNTzIb
         fCuCMLb2cy2aAJUUH5ZpqfoH5lg1ir8xumCYBTJbrvOhsD3En8q1YiU5Us24qXvfM4hS
         37MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-438b171e65asi2019325e9.0.2025.01.22.10.23.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Jan 2025 10:23:02 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4YdXW95lmCz9sPd;
	Wed, 22 Jan 2025 19:23:01 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id uda0rZH_uMMJ; Wed, 22 Jan 2025 19:23:01 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4YdXW94f35z9rvV;
	Wed, 22 Jan 2025 19:23:01 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8C3048B775;
	Wed, 22 Jan 2025 19:23:01 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id hWR4dql6iXIn; Wed, 22 Jan 2025 19:23:01 +0100 (CET)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 34C298B763;
	Wed, 22 Jan 2025 19:23:01 +0100 (CET)
Message-ID: <8acd6ef8-adf0-4694-a3e5-72ec3cf09bf1@csgroup.eu>
Date: Wed, 22 Jan 2025 19:23:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in
 copy_to_kernel_nofault+0xd8/0x1c8 (v6.13-rc6, PowerMac G4)
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Erhard Furtner <erhard_f@mailbox.org>,
 Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
 Balbir Singh <bsingharora@gmail.com>
Cc: Madhavan Srinivasan <maddy@linux.ibm.com>, linuxppc-dev@lists.ozlabs.org,
 torvalds@linux-foundation.org, kasan-dev <kasan-dev@googlegroups.com>
References: <20250112135832.57c92322@yea>
 <af04e91f-0f44-457e-9550-d1d49789158e@linux.ibm.com>
 <20250121220027.64b79bab@yea>
 <f06de018-34ae-4662-8a35-1c55dff1024a@csgroup.eu>
 <20250122002159.43b367f0@yea>
 <ca7568ef-5032-4a80-9350-a9648b87f0b5@csgroup.eu>
Content-Language: fr-FR
In-Reply-To: <ca7568ef-5032-4a80-9350-a9648b87f0b5@csgroup.eu>
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



Le 22/01/2025 =C3=A0 16:32, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 22/01/2025 =C3=A0 00:21, Erhard Furtner a =C3=A9crit=C2=A0:
>> On Tue, 21 Jan 2025 23:07:25 +0100
>> Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>>
>>>> Meanwhile I bisected the bug. Offending commit is:
>>>>
>>>> =C2=A0=C2=A0 # git bisect good
>>>> 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d is the first bad commit
>>>> commit 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d
>>>> Author: Linus Torvalds <torvalds@linux-foundation.org>
>>>> Date:=C2=A0=C2=A0 Mon Dec 9 10:00:25 2024 -0800
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 futex: fix user access on powerpc
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 The powerpc user access code is special=
, and unlike other=20
>>>> architectures
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 distinguishes between user access for r=
eading and writing.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 And commit 43a43faf5376 ("futex: improv=
e user space accesses")=20
>>>> messed
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 that up.=C2=A0 It went undetected elsew=
here, but caused ppc32 to=20
>>>> fail early
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 during boot, because the user access ha=
d been started with
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 user_read_access_begin(), but then fini=
shed off with just a plain
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 "user_access_end()".
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Note that the address-masking user acce=
ss helpers don't even=20
>>>> have that
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 read-vs-write distinction, so if powerp=
c ever wants to do address
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 masking tricks, we'll have to do some e=
xtra work for it.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 [ Make sure to also do it for the EFAUL=
T case, as pointed out by
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Christophe Leroy ]
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Reported-by: Andreas Schwab <schwab@lin=
ux-m68k.org>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Cc: Christophe Leroy <christophe.leroy@=
csgroup.eu>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Link: https://eur01.safelinks.protectio=
n.outlook.com/?=20
>>>> url=3Dhttps%3A%2F%2Flore.kernel.org%2Fall%2F87bjxl6b0i.fsf%40igel.home=
%2F&data=3D05%7C02%7Cchristophe.leroy%40csgroup.eu%7Cb4c1dc7184f54a410a0e08=
dd3a7270b6%7C8b87af7d86474dc78df45f69a2011bb5%7C0%7C0%7C638730985407902881%=
7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJ=
XaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DE5Yp9jopCPE1=
NFuBM8rs%2B1jXZ%2FXAaKvBGpcEP%2BaMyz0%3D&reserved=3D0
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Signed-off-by: Linus Torvalds <torvalds=
@linux-foundation.org>
>>>>
>>>> =C2=A0=C2=A0 kernel/futex/futex.h | 4 ++--
>>>> =C2=A0=C2=A0 1 file changed, 2 insertions(+), 2 deletions(-)
>>>>
>>>>
>>>> Indeed, reverting 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d on top of=
=20
>>>> v6.13 makes the KASAN hit disappear.
>>>
>>> That looks terribly odd.
>>>
>>> On G4, user_read_access_begin() and user_read_access_end() are no-op
>>> because book3s/32 can only protect user access by kernel against write.
>>> Read is always granted.
>>>
>>> So the bug must be an indirect side effect of what user_access_end()
>>> does. user_access_end() does a sync. Would the lack of sync (once
>>> replaced user_access_end() by user_read_access_end() ) lead to some odd
>>> re-ordering ? Or another possibility is that user_access_end() is calle=
d
>>> on some kernel address (I see in the description of commit 43a43faf5376
>>> ("futex: improve user space accesses") that the replaced __get_user()
>>> was expected to work on kernel adresses) ? Calling user_access_begin()
>>> and user_access_end() is unexpected and there is no guard so it could
>>> lead to strange segment settings which hides a KASAN hit. But once the
>>> fix the issue the KASAN resurfaces ? Could this be the problem ?
>>>
>>> Do you have a way to reproduce the bug on QEMU ? It would enable me to
>>> investigate it further.
>>
>> Attached v6.13 .config plays nicely with qemu ttyS0 (forgot to disable=
=20
>> SERIAL_8250 and set SERIAL_PMACZILOG + SERIAL_PMACZILOG_CONSOLE=20
>> instead as I prefer the PCI Serial card in my G4).
>>
>> The KASAN hit also shows up on qemu 8.2.7 via via:
>> qemu-system-ppc -machine mac99,via=3Dpmu -cpu 7450 -m 2G -nographic -=20
>> append console=3DttyS0 -kernel vmlinux-6.13.0-PMacG4 -hda Debian-VM_g4.i=
mg
>>
>=20
> I was able to reproduce it with v6.13 with QEMU when loading test_bpf=20
> module.
>=20
> On my side, the problem doesn't disappear when reverting of commit=20
> 32913f348229 ("futex: fix user access on powerpc")
>=20
> I bisected it to commit e4137f08816b ("mm, kasan, kmsan: instrument=20
> copy_from/to_kernel_nofault"), which makes a lot more sense to me.
>=20
> It might be a problem in the way patch_instruction() is implemented on=20
> powerpc, to be investigated.

I think the problem is commit 37bc3e5fd764 ("powerpc/lib/code-patching:=20
Use alternate map for patch_instruction()")

Can you try the change below:

diff --git a/arch/powerpc/lib/code-patching.c=20
b/arch/powerpc/lib/code-patching.c
index af97fbb3c257..8a378fc19074 100644
--- a/arch/powerpc/lib/code-patching.c
+++ b/arch/powerpc/lib/code-patching.c
@@ -108,7 +108,7 @@ static int text_area_cpu_up(unsigned int cpu)
  	unsigned long addr;
  	int err;

-	area =3D get_vm_area(PAGE_SIZE, VM_ALLOC);
+	area =3D get_vm_area(PAGE_SIZE, 0);
  	if (!area) {
  		WARN_ONCE(1, "Failed to create text area for cpu %d\n",
  			cpu);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
acd6ef8-adf0-4694-a3e5-72ec3cf09bf1%40csgroup.eu.
