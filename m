Return-Path: <kasan-dev+bncBDLKPY4HVQKBBQHU7C6AMGQEKEHOJ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 362DBA249AE
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Feb 2025 16:14:10 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-436379713basf14080595e9.2
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Feb 2025 07:14:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738422849; cv=pass;
        d=google.com; s=arc-20240605;
        b=R2b6m7qbXg/yx7cdpNSj/wmnV3hcnRFK6m1HZsndX3DAnzGKnJ8kOv6hCcSWtZfTdR
         pyXJKuF775WL+jyo86WsqjXYI+z+lX8H/hV/fNN2FWNMIT04pA55VZf7xlBDZTd7WBcV
         KcyGF8MuZba6jebiIsV+Jeary4NnRqAYjmT8mdnQ6SDlUUAKtgBnZXj5HxvK4exwaDoJ
         5eq7Mp/bt8LGXabQBUyCyrdUx0fATifraiaiNjaH3h8wYzjFG9nK9hfX7WGDMerPTUO6
         2PCN1KKvHc/0/fGyxX9F3MWfvFJ0iXzNaTkgSdz5mcOjB/ERpSJGAbxBq8cEUkKtp4w1
         teVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=YtjxVVoo7NXM63finJpsEWmFcIj6YcFaV4wd0qkkt1w=;
        fh=3qmfJf2qQ+RRiDOxzjSWvOmda6XpG4AmTorDSgaODhE=;
        b=ewCUSTpwoFUlgFr1/Gr8aEzXqnCeNk0OTmfyMZE47Xcc9pNdhIytfXBzjVT+MZjt1s
         jfEsYFXKWrplWdQotVnsqceYHGZQnF3tkhKZKhioVYlN/uILVUFLllBAtng979dVdi6i
         Mdq4FXhDIfk5qRIo5ZF1zM8OysADr6aFdTOGty3LASg4LehgDOD4ugn3NiGfgLgT/4By
         rCFDGxNYNHhcsGHFvrs8C7ej266Tr5jOiOKgE73EiXk+uctFrMDPY6awhux+pjf+Snhj
         OtQAO9Mf2KnnjWAoWLbG3isH4KxaZe/eVuWGP5iZxvjz4XLtqKlvsCykc92Ltp/QX5Ks
         2r3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738422849; x=1739027649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YtjxVVoo7NXM63finJpsEWmFcIj6YcFaV4wd0qkkt1w=;
        b=cIfuxtmfwNALWrVoUFoXZZUluEeIWV4Mkzt9ub8YFY2SPIzHa8zFzcg8QYSiemH8NF
         eakMAr2Ll2wk0DrBX0SdWgw/mcChURouXrPoo54x1w7i/BQdXmMG/wDDbqsKAQvHRXQV
         iZbyrYdrqZXkiIRtdH7Z5pLB5YLxFKJd5D3/mYsJZt4io61s2HPBQGXYLfEE+YEyag44
         YFutm9heDg7CqYnydOZ7Q2Li3n+xbR5P9AYLjLgoBJhtqyu8RrF4FsP9WLMJKickUyzZ
         F04cLAwAaQeSDwJsezrt8U56HnJeoIABl4WGjNILW5D6DsbojA+jCfXKVDrHzlYqXG+t
         pQVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738422849; x=1739027649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YtjxVVoo7NXM63finJpsEWmFcIj6YcFaV4wd0qkkt1w=;
        b=MFJlXN6ijdsmdnFkxjvLIA1WttM35SGSSEfiCTYjBLd3SrmvRxUKf73Fe0ZHpZJp+5
         P3yYI6AE8UYuP5/Dos/vrFqzbcKFAV5uzi9ZxOsvt9DHmoyMsR01V8gmCB9E1lmM2f4D
         kC+DPPId3HZDQLOtlJHmTThqWbZ1YBHPvw0VgBmdbQd3lQr/iMnd0QV3xJ0qlN4QXPGk
         9uX9nyWcBQcbBHMflzPwpPS6W9wMqAyw0CzMbwZ+LR3ZDQeK0ko0YjCv+59N3vGittxX
         P+xlw6TbJg8+n4Lg29BK7goJo8CadWcVpAE8jR/goPi/rjdHW9uwJ1Zdqxgdbr850c3W
         G4Ow==
X-Forwarded-Encrypted: i=2; AJvYcCW+4Ep8CMDukOkqbFStQmOkM7BuFLp16+/JWrCM9fZau09DBvfbwu2PAcGPPdRuPDXlQv/7jA==@lfdr.de
X-Gm-Message-State: AOJu0Yypz4V9xvhtCKezRK9JN8sAa2S6nMhn/iHYxqp/oGQnLGJfFX0s
	8B3/WKuMSb7e7Abf8HDACdh0N8qVfoXzB/DVmlbQ3qCVlimzJWvK
X-Google-Smtp-Source: AGHT+IEy7DCMDspj3iKaSdRbNHdoacFariT5/uLIKRgETiVtZtV9kvcFuVQb2lyAhu1O4vKEdDWWnw==
X-Received: by 2002:a05:600c:1391:b0:431:60ec:7a96 with SMTP id 5b1f17b1804b1-438dc4223c4mr113414565e9.25.1738422848381;
        Sat, 01 Feb 2025 07:14:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb9a:0:b0:434:aa6f:2408 with SMTP id 5b1f17b1804b1-438e13dd138ls15272065e9.0.-pod-prod-03-eu;
 Sat, 01 Feb 2025 07:14:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMmNYTVZfZMYjDOK7yZUgt2DbezJAm2RRAYGW+3NNrDmvRtlh4nDuHRWPTDXVpHddOF9E1u3Uone0=@googlegroups.com
X-Received: by 2002:a5d:6d85:0:b0:382:4b52:ffcc with SMTP id ffacd0b85a97d-38c516664cfmr13439934f8f.0.1738422846166;
        Sat, 01 Feb 2025 07:14:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738422846; cv=none;
        d=google.com; s=arc-20240605;
        b=S+8EvXxBLs5tPds4IsjffrKgeVfttdXmEru+JrwIwXRo+mLblUeBqEF+ifjpoJw7tl
         2UjpZrMW/YjR0QNgkQHfGYPUg26y+chBXB+JA3TV3AEg0e1tifgvMoRA0JZONy+YH1wX
         3aqRZhaZTJx6fbYYCtI/84OfGb4GDclbLx0okKZO4cl8Ohpc0uMrYB27KujvQjK8cqF/
         WrgYRgsJIJtKtgwsqILIxIeu3iOYrpD31ktLl7EyrWghlApzdcQf5ge97Y9jzykmevO5
         6TlxxA2MZcqBY2RjTcm7w/+TtS/vpYKBUwNksO5mmPgRrhO6afXCXHx5NaTu8M69xWWb
         KUsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=wFIN+auOPs+dYqh8kBNWuHix6Ny5XSTC0b0lOVMceI8=;
        fh=xY9t9Rs2VhjVF/R6B5VewIRdSTHJka/Jro6H8Y72q88=;
        b=Pa9bgPu2pNuAoEGOFVdt0jVQ7bdeCOmJgXO32NrwA1/5qf8bPA3WL6vdw9A1YGPhmW
         koCpXfDdDeQkULourijojvEUEbsWk6pRYFIGC0018+jLP2LCECWWnpLUJGN9P/AVPAxB
         PMJjL8JzAN5nwr4DCJwmQnp3GkE1Bu74LeoX7r9Ijk1emXGdiTO3hqdsyMPuXjdkDw0E
         MpVSOgvtWHMhaOTvTR5PW8vaUaTnZl9UfRbcOQwLMH+dzcH4beUvv5VECicKgPHKwetJ
         e0bFBJN53FbVMYWGMAAf2JYlPKIJx92bta2gkECQKqTAGrQGM/1M4WuEmt7lhCllntzU
         7h5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-438d7aab6fesi9022765e9.1.2025.02.01.07.14.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 01 Feb 2025 07:14:06 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4YlbrY0Q8Nz9sRr;
	Sat,  1 Feb 2025 16:14:05 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id vcTJnK3UAy8Y; Sat,  1 Feb 2025 16:14:04 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4YlbrX6gvwz9sRk;
	Sat,  1 Feb 2025 16:14:04 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D2D858B764;
	Sat,  1 Feb 2025 16:14:04 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id HHMZ0FDlXTeB; Sat,  1 Feb 2025 16:14:04 +0100 (CET)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 75F378B763;
	Sat,  1 Feb 2025 16:14:04 +0100 (CET)
Message-ID: <1ff477a4-85f6-4330-aa0c-add315abfff9@csgroup.eu>
Date: Sat, 1 Feb 2025 16:14:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in
 copy_to_kernel_nofault+0xd8/0x1c8 (v6.13-rc6, PowerMac G4)
To: Erhard Furtner <erhard_f@mailbox.org>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
 Balbir Singh <bsingharora@gmail.com>,
 Madhavan Srinivasan <maddy@linux.ibm.com>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <20250112135832.57c92322@yea>
 <af04e91f-0f44-457e-9550-d1d49789158e@linux.ibm.com>
 <20250121220027.64b79bab@yea>
 <f06de018-34ae-4662-8a35-1c55dff1024a@csgroup.eu>
 <20250122002159.43b367f0@yea>
 <ca7568ef-5032-4a80-9350-a9648b87f0b5@csgroup.eu>
 <8acd6ef8-adf0-4694-a3e5-72ec3cf09bf1@csgroup.eu>
 <20250201151435.48400261@yea>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250201151435.48400261@yea>
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



Le 01/02/2025 =C3=A0 15:14, Erhard Furtner a =C3=A9crit=C2=A0:
> On Wed, 22 Jan 2025 19:23:00 +0100
> Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>>>
>>> I was able to reproduce it with v6.13 with QEMU when loading test_bpf
>>> module.
>>>
>>> On my side, the problem doesn't disappear when reverting of commit
>>> 32913f348229 ("futex: fix user access on powerpc")
>>>
>>> I bisected it to commit e4137f08816b ("mm, kasan, kmsan: instrument
>>> copy_from/to_kernel_nofault"), which makes a lot more sense to me.
>>>
>>> It might be a problem in the way patch_instruction() is implemented on
>>> powerpc, to be investigated.
>>
>> I think the problem is commit 37bc3e5fd764 ("powerpc/lib/code-patching:
>> Use alternate map for patch_instruction()")
>>
>> Can you try the change below:
>>
>> diff --git a/arch/powerpc/lib/code-patching.c
>> b/arch/powerpc/lib/code-patching.c
>> index af97fbb3c257..8a378fc19074 100644
>> --- a/arch/powerpc/lib/code-patching.c
>> +++ b/arch/powerpc/lib/code-patching.c
>> @@ -108,7 +108,7 @@ static int text_area_cpu_up(unsigned int cpu)
>>    	unsigned long addr;
>>    	int err;
>>
>> -	area =3D get_vm_area(PAGE_SIZE, VM_ALLOC);
>> +	area =3D get_vm_area(PAGE_SIZE, 0);
>>    	if (!area) {
>>    		WARN_ONCE(1, "Failed to create text area for cpu %d\n",
>>    			cpu);
>>
>=20
> Checked on my Talos II (POWER9) too, to see whether ppc64 is also affecte=
d and here I still see the KASAN hit despite Christophes patch applied:
>=20
> BUG: KASAN: user-memory-access in copy_to_kernel_nofault+0x8c/0x1a0
> Write of size 8 at addr 0000187e458f2000 by task systemd/1


Thanks for the report.

That's something different. Previous report was:

BUG: KASAN: vmalloc-out-of-bounds in copy_to_kernel_nofault+0xd8/0x1c8

This is what my patch fixes.

New report is:

BUG: KASAN: user-memory-access in copy_to_kernel_nofault+0x8c/0x1a0

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
ff477a4-85f6-4330-aa0c-add315abfff9%40csgroup.eu.
