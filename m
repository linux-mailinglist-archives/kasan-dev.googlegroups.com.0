Return-Path: <kasan-dev+bncBDLKPY4HVQKBBLFHYS6AMGQE6I3SFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EB64A195C3
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 16:50:06 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4361d4e8359sf53781995e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 07:50:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737561005; cv=pass;
        d=google.com; s=arc-20240605;
        b=aq+BDeGMYv8LaM9Y63fEyCiodp+3Y9Pas3lZeL0L5xBSfXR6aJfi7dGxJ/1ULCxa/T
         JcDlYRAN3UY8YlsfHdOVaaFvVuoCSbO/nCcWn6+m5CwiVDQu89WHR0TewbPTZpehMPBc
         s8a1nBV8RnZVxD2Kcm+caaFGn8NIfmb7EshqZDW+XcjEyYpmgrRMbR0kbGNt0bAD+m1O
         dY79R9LP+eIYDqWdJI27h0WJrJvqrUR2MSJdGnE5E/FXUxUFvOPWzyNdCKmU6cugBQ9L
         BagYH15DM0CMVShfuoEu5SvKS67Rg6F0+O3RR8QWLpXsJSHQFb/uRDXc89azZEm0dEnb
         Ptww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=4GgWYf5qNQB2ZboEgJIigh+k0a1P+SSLCS5jQgCJcP8=;
        fh=MiEs8gcsYLtQYS6xugvGUPFi3elYMLtIsaLoz5an/jM=;
        b=IqzuU84uqYg7yGjm0EVT4aNu8vcCkEfM9lnyZ13hVXn/NvKNhL6olbEVcX2fjM91Kn
         1tHLcfBVc0B+8yuQm1QrfRs+Ch7QDy894RAj23INUHS/3SdndfXo72wwbMwXLMU1Xu/r
         NpdX7zHJvdLbS5oLsPaGeGjEoXQw2BfAC403f8hyz85lue9ey4xH++qE9rYp+9NORP+W
         6WFN6dIgp72gHqSRAZik303ajEVZdpMAG6I84eiSbiudyzqsmgtx9nJq/gIgUdZcoAmE
         KLy4BaUhw6/aUdNSmbfeMjj6BPkFk5kdhLThwpnqD0BBfn/0ub0tNSZ2CfkHS/L14nFT
         8k3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737561005; x=1738165805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4GgWYf5qNQB2ZboEgJIigh+k0a1P+SSLCS5jQgCJcP8=;
        b=wMF6pfWu1sjMlehqBgpKSikPk5eeqDj8BsS0NAtU5RuXnpavPlp5C+kEvHZk/6qDMs
         2LdclFQK/jyCqM9y0HbmoSHpDlJeASDqkLKXiGPbG6d1IHHVBc5i0TnBozlQF2VId8LB
         eQwZI+LnSZQGMCqn+FJbBYSuAquWF4aipc0kvB+K814i+bWdNhHBB1vkZfWmKknWYaL6
         0AU7wQHg3rZaZhOCVw8YhxT6m/l1k1Am+Rz/ZNmw59Y45AwkfDJqdiegHjZu4Xc1YhIK
         wTXhze6T50XxS/WGg7q+EUv56HK6TBDT0afBn4JYlX8saCR1ANLNQrKbLUzjwv7CgdBf
         c8VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737561005; x=1738165805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4GgWYf5qNQB2ZboEgJIigh+k0a1P+SSLCS5jQgCJcP8=;
        b=AfwdIE6jyUwqHlNjwybcWux6scO0wiX0hxs1jjvByZv8jT+gxTbu7AF1uB3/Ce16o3
         3DHzsmKJ+gfOtITrogINaIeD/6B2YWsO/YBAHyQ3ut+8vkNF3FUTvzPthcN55Wc25Iar
         pmZ5GnYY2T2jo9F94V5Su6hsf14ba+aktYw1SM98ua2/M3HulB13FJMq85SF43NR91Q0
         JqCwx2fMloB9rQ3v05tgLNYpy5WRFn6JBgS2/uGGZVb1z+vyKKRGruYCYR+mofMnetb+
         uNa9+l7O8VWPEmhXjWQU0w8DAdeOGUzFMg7IXXN4vlBZIPC+178+n7X9hviwu+ifJlk0
         y7ZQ==
X-Forwarded-Encrypted: i=2; AJvYcCV3/kaOdCHcU0cj+hOwQazYsYunddW0FvSNY2KCbQ6U5+7S434bGJgdxwcghLBXP4WC0ngicA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1SP8etSOX8OrGOH19JY1PA24RlfjDjgXPuHQQGLn/DXVwCFhv
	HGUa/ls6VE8pqJOGtf7gKMuqBts8vUwlm03W2lyXH3ATHR6sgr0Z
X-Google-Smtp-Source: AGHT+IFHFsVxhIq198rGp1+WwKc3pbDPOS0W73KaDxbCcDlb6neAf+pi6Jn+C9Vv42scBXAFO/Ga0g==
X-Received: by 2002:a05:600c:1f8e:b0:435:d22:9c9e with SMTP id 5b1f17b1804b1-4389141c352mr171532295e9.19.1737561004887;
        Wed, 22 Jan 2025 07:50:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:870d:b0:435:9218:d76f with SMTP id
 5b1f17b1804b1-4388ab3dab3ls15615585e9.0.-pod-prod-07-eu; Wed, 22 Jan 2025
 07:50:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW4aHBXrStuet7JYWniRySkqxNwnrqJsOHY6S66kK4xm6vwIm7vFLCQS1Qf4IyX4r+3TYthOO6C5GY=@googlegroups.com
X-Received: by 2002:a05:600c:1c0f:b0:431:44f6:566f with SMTP id 5b1f17b1804b1-438913deb12mr186453465e9.13.1737561002556;
        Wed, 22 Jan 2025 07:50:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737561002; cv=none;
        d=google.com; s=arc-20240605;
        b=EsUayzI72e319IqaccM2vdNKFrCHR5BDBxkGts4V40JG1WUa4m15hWBIanNIA31gfe
         Z8FcjTHpzfasAUIvAEllhDNN76756fUtrgw04OyXPR4DLArArBhb0NvBrQFZTIvqNQTv
         Eg74U7CjNfL2eOb6mMrlO258YuWrU3ef0OpPz6LMAwAvPgJ9mJg7Qx9bYb421qZzBl0y
         rjVyGHm690aXEma2I/RqrIbxrUYhmssLY4k5Wf0uddDuT9kXeQ7EaObmscmnklQNcT4R
         tPG63ggbd6n+Z2tovjehhvWqq+6mJROIbff7hQVbY+T7cxyX7XA+YbqumEQCMj25gZbA
         WlMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=ddmu6H7W9SOftXDbUNQZENGkRNuW40ddMfkkirojTWE=;
        fh=YatxHLvtfQ3SHAAUhKNMrj2nEpiSj1ucpDBLoX8bwHY=;
        b=VE4Y4jAe77ydmpeeCmvnPkBOcH6MSXwV7tbyqHdPt7qHJUscCb/0AzEl39YBsi3n+P
         R2ynWWmPgfSjE4SycYkt3BDjsBXvyZNnqelpivaY947aj9jsFBRQhuuMHYkfuCd+hoTT
         mqVv7MIDRcsCAzKn1nHtCPwzhUrOUI0S+UHw2g6T85BMjEjia+MdR6KEARiJBPmuGJNt
         SmqIPx7cfQjKotNAUFfWcK03yIUDlX1B5dC2lXm27ol/NkdchW1hKJ3Vf2JoGc1fLuAW
         dPaxmNQ8SjKLotJ3VnkxqJw2MDrWwTHd2vIn44HlAD23NgBVtpCdK4sf1LZZ+eaQZMtS
         p2Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTP id 5b1f17b1804b1-438b319f687si284725e9.1.2025.01.22.07.50.02
        for <kasan-dev@googlegroups.com>;
        Wed, 22 Jan 2025 07:50:02 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4YdSk76fSLz9sSX;
	Wed, 22 Jan 2025 16:32:15 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id y0ziEzDSpIL0; Wed, 22 Jan 2025 16:32:15 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4YdSk75dfWz9sRr;
	Wed, 22 Jan 2025 16:32:15 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B0ECD8B778;
	Wed, 22 Jan 2025 16:32:15 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 0ud7eRkH3-ok; Wed, 22 Jan 2025 16:32:15 +0100 (CET)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 39FB98B763;
	Wed, 22 Jan 2025 16:32:15 +0100 (CET)
Message-ID: <ca7568ef-5032-4a80-9350-a9648b87f0b5@csgroup.eu>
Date: Wed, 22 Jan 2025 16:32:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in
 copy_to_kernel_nofault+0xd8/0x1c8 (v6.13-rc6, PowerMac G4)
To: Erhard Furtner <erhard_f@mailbox.org>,
 Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: Madhavan Srinivasan <maddy@linux.ibm.com>, linuxppc-dev@lists.ozlabs.org,
 torvalds@linux-foundation.org, kasan-dev <kasan-dev@googlegroups.com>
References: <20250112135832.57c92322@yea>
 <af04e91f-0f44-457e-9550-d1d49789158e@linux.ibm.com>
 <20250121220027.64b79bab@yea>
 <f06de018-34ae-4662-8a35-1c55dff1024a@csgroup.eu>
 <20250122002159.43b367f0@yea>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250122002159.43b367f0@yea>
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



Le 22/01/2025 =C3=A0 00:21, Erhard Furtner a =C3=A9crit=C2=A0:
> On Tue, 21 Jan 2025 23:07:25 +0100
> Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>=20
>>> Meanwhile I bisected the bug. Offending commit is:
>>>
>>>    # git bisect good
>>> 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d is the first bad commit
>>> commit 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d
>>> Author: Linus Torvalds <torvalds@linux-foundation.org>
>>> Date:   Mon Dec 9 10:00:25 2024 -0800
>>>
>>>       futex: fix user access on powerpc
>>>      =20
>>>       The powerpc user access code is special, and unlike other archite=
ctures
>>>       distinguishes between user access for reading and writing.
>>>      =20
>>>       And commit 43a43faf5376 ("futex: improve user space accesses") me=
ssed
>>>       that up.  It went undetected elsewhere, but caused ppc32 to fail =
early
>>>       during boot, because the user access had been started with
>>>       user_read_access_begin(), but then finished off with just a plain
>>>       "user_access_end()".
>>>      =20
>>>       Note that the address-masking user access helpers don't even have=
 that
>>>       read-vs-write distinction, so if powerpc ever wants to do address
>>>       masking tricks, we'll have to do some extra work for it.
>>>      =20
>>>       [ Make sure to also do it for the EFAULT case, as pointed out by
>>>         Christophe Leroy ]
>>>      =20
>>>       Reported-by: Andreas Schwab <schwab@linux-m68k.org>
>>>       Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
>>>       Link: https://eur01.safelinks.protection.outlook.com/?url=3Dhttps=
%3A%2F%2Flore.kernel.org%2Fall%2F87bjxl6b0i.fsf%40igel.home%2F&data=3D05%7C=
02%7Cchristophe.leroy%40csgroup.eu%7Cb4c1dc7184f54a410a0e08dd3a7270b6%7C8b8=
7af7d86474dc78df45f69a2011bb5%7C0%7C0%7C638730985407902881%7CUnknown%7CTWFp=
bGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjo=
iTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DE5Yp9jopCPE1NFuBM8rs%2B1jXZ%=
2FXAaKvBGpcEP%2BaMyz0%3D&reserved=3D0
>>>       Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
>>>
>>>    kernel/futex/futex.h | 4 ++--
>>>    1 file changed, 2 insertions(+), 2 deletions(-)
>>>
>>>
>>> Indeed, reverting 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d on top of v6=
.13 makes the KASAN hit disappear.
>>
>> That looks terribly odd.
>>
>> On G4, user_read_access_begin() and user_read_access_end() are no-op
>> because book3s/32 can only protect user access by kernel against write.
>> Read is always granted.
>>
>> So the bug must be an indirect side effect of what user_access_end()
>> does. user_access_end() does a sync. Would the lack of sync (once
>> replaced user_access_end() by user_read_access_end() ) lead to some odd
>> re-ordering ? Or another possibility is that user_access_end() is called
>> on some kernel address (I see in the description of commit 43a43faf5376
>> ("futex: improve user space accesses") that the replaced __get_user()
>> was expected to work on kernel adresses) ? Calling user_access_begin()
>> and user_access_end() is unexpected and there is no guard so it could
>> lead to strange segment settings which hides a KASAN hit. But once the
>> fix the issue the KASAN resurfaces ? Could this be the problem ?
>>
>> Do you have a way to reproduce the bug on QEMU ? It would enable me to
>> investigate it further.
>=20
> Attached v6.13 .config plays nicely with qemu ttyS0 (forgot to disable SE=
RIAL_8250 and set SERIAL_PMACZILOG + SERIAL_PMACZILOG_CONSOLE instead as I =
prefer the PCI Serial card in my G4).
>=20
> The KASAN hit also shows up on qemu 8.2.7 via via:
> qemu-system-ppc -machine mac99,via=3Dpmu -cpu 7450 -m 2G -nographic -appe=
nd console=3DttyS0 -kernel vmlinux-6.13.0-PMacG4 -hda Debian-VM_g4.img
>=20

I was able to reproduce it with v6.13 with QEMU when loading test_bpf=20
module.

On my side, the problem doesn't disappear when reverting of commit=20
32913f348229 ("futex: fix user access on powerpc")

I bisected it to commit e4137f08816b ("mm, kasan, kmsan: instrument=20
copy_from/to_kernel_nofault"), which makes a lot more sense to me.

It might be a problem in the way patch_instruction() is implemented on=20
powerpc, to be investigated.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
a7568ef-5032-4a80-9350-a9648b87f0b5%40csgroup.eu.
