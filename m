Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2EJTHTQKGQE4643FGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA2F427661
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:59:53 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id m19sf2470352otl.9
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:59:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558594792; cv=pass;
        d=google.com; s=arc-20160816;
        b=a9Asz0Szijnqgrj2edcR06KbnmCsUTZ4Uy0qYGf0KKTVCe/oczROhRn4ImbN9Bxsbr
         Qb14NtxXQwqhUR66VRkBdW6PdJWtkcER181w3QJr8C1PYj8wNpi/cr/rtYrIF7eONFNa
         tN4qbBJ28J6rd9jzQ1xT6YlXbvIiXdGdRvsfgxQOCgGJ6zeHsuOyMyhsMc8Zt94psK1J
         VDl/V2vlzaPQWDzlU70R/JJ3veq8W5HbJB3gncgQguLo0HdJk0MQdsqZoElnjzUYnon8
         v9Vhl4GkdlS7uv3CCptA/vUORdW4EwDVaDqif3U+Z+RRqIvzDVZQgD1Ynbgn34DEHQUZ
         mIgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=TPzlFXgkCT/28e6N6YL9Q6FRDxEa9lVtGNjnymoL868=;
        b=n/DUw4q2HVQUMBk4iUR4iMjuSKhcoDvRKGBJDOuMFcpNJIJr16QTlRjpxrFyI30Yk0
         q6DiXAN8dxeaLkUvHBoAs+aVHP1+Gzexob0zme6pofXX0NuRgWxNeDMKmW7CJYoSp8ti
         ODyYt2e1i+sR4dXGKkeQ6/udNVxxYWIQAxyTthmg+zPJTT3/yKx++2tV936nxUpViugY
         SBzkR/utCQiirUyjYBoHa1hO+sYD6eJvQFa7GU2bV676DGm5TefjRZ4FuZ4GBlkeT1CX
         13IQRNIRRPfLSS9hNlqjCSkqybXfQOzgxm0IJLLjOT0LHgWiBXKFnpIStJbxdZ67MSKU
         T2/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Oe+r78Ud;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TPzlFXgkCT/28e6N6YL9Q6FRDxEa9lVtGNjnymoL868=;
        b=LRJGbVzPwzTLMDkyjf1ywjJu137POb3ywxJuIGlnbxfeNERfCfneyiAzAL95B5lnZc
         b2FzivvxbVZP/jliSBUCAvv3mJ9n3BCwTksHRVxTjGPgKP7O3n2hOFEkWpYl1AwMrYHi
         WqB3sQG0W4QOLDJ7+/hurbo14e2sy3rLMJKKlFDi0xv/Qh0dxauv4a8G5+H66C0wHgkG
         PmQaIECGuZaxITNpkkfYSp5ZFKEARuwWVHWM8RAK0ze/QP4Wz7MwWORNXw7542cIrn2P
         fv6wtLIJ1sPn4osNI8+AvA/d+5+8sGTpImSsdFdwGBgHwUAoxRh8u2V+1o82I8wj+iVx
         75/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TPzlFXgkCT/28e6N6YL9Q6FRDxEa9lVtGNjnymoL868=;
        b=MDD81c2CFJa6Eiq2kq43gjHdDqSbK9W716SYjeHg7QSwY/d4tJbNMqz5aJUiZF+wqm
         PrNVXYFidEjMvNDzA88Dlr6Yeq+A52Ckf1SJMBgrjfOUJz3UxJSgChd25ftwF78KhQns
         2NpHyweuux2L5XBXX1HrtaSI/qjMJKiQPYiz5Bog16oGhIjCd0901G94cfsExNMFFtzj
         bdxZ7ewyF50qYpR5epEF0/7CPskabiibGZncIguyPqScX+2XzfT0KiBhLiFBDmG4bab5
         iINVgyeNS2Rr4TA2OhHywAjIh+lws67UnTz0pDAwH0ZEIEXSXoiUSnl4wfJXFxaIHt8N
         9tgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWSUvKelnbA7OplSAe+2uGNZKcxI0jVxlcNrlgo0vh6dc0TcBIi
	ktchtSglKoKJ4bwLOsD8TCA=
X-Google-Smtp-Source: APXvYqy0x+9pj1XOw44YG0aM+NJsl2VpZlBqvoiUzJp2zGV1uU8qOO5Fy/DoZ60a7Z/VbPe8ww0kNA==
X-Received: by 2002:a9d:2f08:: with SMTP id h8mr55804461otb.42.1558594792687;
        Wed, 22 May 2019 23:59:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:14f:: with SMTP id j15ls947344otp.9.gmail; Wed, 22
 May 2019 23:59:52 -0700 (PDT)
X-Received: by 2002:a9d:6c89:: with SMTP id c9mr5882157otr.52.1558594792369;
        Wed, 22 May 2019 23:59:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558594792; cv=none;
        d=google.com; s=arc-20160816;
        b=o5tv3tQqyPXziMJHqCQUmS2vDAzDad+WzFzh4jpdSXq17wcBiUcXaBGlRPNJ/QQOHS
         04GSXBDu5VdCDJ43bLhnoUREjWLGje0axSDHTJA9AHdht8HFm1E7jWRd2ITlphT0E9gS
         Rb5bQWaS6djQh7xplmxZ/jSZwfZgVXJFv41pZoJBdmR6lOwCY+zuceeKDmUSBO08tN8M
         S3og0RV4HahvVLbJ0Sb/8xg9H0bcYQ1bnWQZGpNsMNBW7M3GXiSAWi18z2eylXvH+1jO
         ztgUjOd2ZeyZIGOr3pI/6N2jQh4xKLSXXCZ06Ay4M99A5H99VTozWkTpTmQL8lzngiQH
         YF2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=sTVf2HlQGeeweyPoper6ABpd3ug5oigjMesp2xkd4m0=;
        b=Pa0kzrbuIuv6VXc9WM4gWOktwvtvasTmrIs9moPHvM1dSApGDVRQr4tYVb+2GDMlff
         FVILp0zS+tuf3Lp6XCg5S0X3JDbsjxnwHAY4tE+2/rObfgpXakFIyTCxgs4D7K4740jI
         tAHHr7zkBABscrQmeXHAVrlWSXTOp8oEm6toZezhWCiCXZzG+C4smCiVsUUvpGSXoeGW
         Wf2EJ8L9O+Fqi5LCJVV8fYU3mQ9XNpqeIDssMf6yXPD7eEcUK3APTqNq/26OJDEuVdGW
         9Poy4/xGh0Abm3cbDhTbMA96u573bnVci/uJ6MkauKQ4psCgIcNcJBGllCmeJ+5vTRkU
         mpQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Oe+r78Ud;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id 9si1007572oti.2.2019.05.22.23.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:59:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id c13so2633476pgt.1
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 23:59:52 -0700 (PDT)
X-Received: by 2002:a17:90a:2590:: with SMTP id k16mr219167pje.11.1558594791623;
        Wed, 22 May 2019 23:59:51 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id v81sm52690410pfa.16.2019.05.22.23.59.50
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 23:59:50 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [RFC PATCH 6/7] kasan: allow arches to hook into global registration
In-Reply-To: <b7f23406-c1dc-de50-d477-86cdf8f0d471@c-s.fr>
References: <20190523052120.18459-1-dja@axtens.net> <20190523052120.18459-7-dja@axtens.net> <b7f23406-c1dc-de50-d477-86cdf8f0d471@c-s.fr>
Date: Thu, 23 May 2019 16:59:47 +1000
Message-ID: <87h89lzme4.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Oe+r78Ud;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 23/05/2019 =C3=A0 07:21, Daniel Axtens a =C3=A9crit=C2=A0:
>> Not all arches have a specific space carved out for modules -
>> some, such as powerpc, just use regular vmalloc space. Therefore,
>> globals in these modules cannot be backed by real shadow memory.
>
> Can you explain in more details the reason why ?

At this point, purely simplicity. As you discuss below, it's possible to
do better.

>
> PPC32 also uses regular vmalloc space, and it has been possible to=20
> manage globals on it, by simply implementing a module_alloc() function.
>
> See=20
> https://elixir.bootlin.com/linux/v5.2-rc1/source/arch/powerpc/mm/kasan/ka=
san_init_32.c#L135
>
> It is also possible to easily define a different area for modules, by=20
> replacing the call to vmalloc_exec() by a call to __vmalloc_node_range()=
=20
> as done by vmalloc_exec(), but with different bounds than=20
> VMALLOC_START/VMALLOC_END
>
> See https://elixir.bootlin.com/linux/v5.2-rc1/source/mm/vmalloc.c#L2633
>
> Today in PPC64 (unlike PPC32), there is already a split between VMALLOC=
=20
> space and IOREMAP space. I'm sure it would be easy to split it once more=
=20
> for modules.
>

OK, good to know, I'll look into one of those approaches for the next
spin!

Regards,
Daniel


> Christophe
>
>>=20
>> In order to allow arches to perform this check, add a hook.
>>=20
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> ---
>>   include/linux/kasan.h | 5 +++++
>>   mm/kasan/generic.c    | 3 +++
>>   2 files changed, 8 insertions(+)
>>=20
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index dfee2b42d799..4752749e4797 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -18,6 +18,11 @@ struct task_struct;
>>   static inline bool kasan_arch_is_ready(void)	{ return true; }
>>   #endif
>>  =20
>> +#ifndef kasan_arch_can_register_global
>> +static inline bool kasan_arch_can_register_global(const void * addr)	{ =
return true; }
>> +#endif
>> +
>> +
>>   #ifndef ARCH_HAS_KASAN_EARLY_SHADOW
>>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
>> index 0336f31bbae3..935b06f659a0 100644
>> --- a/mm/kasan/generic.c
>> +++ b/mm/kasan/generic.c
>> @@ -208,6 +208,9 @@ static void register_global(struct kasan_global *glo=
bal)
>>   {
>>   	size_t aligned_size =3D round_up(global->size, KASAN_SHADOW_SCALE_SIZ=
E);
>>  =20
>> +	if (!kasan_arch_can_register_global(global->beg))
>> +		return;
>> +
>>   	kasan_unpoison_shadow(global->beg, global->size);
>>  =20
>>   	kasan_poison_shadow(global->beg + aligned_size,
>>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87h89lzme4.fsf%40dja-thinkpad.axtens.net.
For more options, visit https://groups.google.com/d/optout.
