Return-Path: <kasan-dev+bncBCR5PSMFZYORB3GQRGBQMGQEHPSNICY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 31BF234DCA3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 01:53:18 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id c20sf8630060qtw.9
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 16:53:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617061997; cv=pass;
        d=google.com; s=arc-20160816;
        b=SD4Eavkka7s21j9HZHypNCghvrBKsj8XqcgpUvkIT2qHGSXtKjs1uknacFTO3blDGF
         JO1C5/A1IxjrxV0fB+S9aafp2bNhh2Vx9U2C1TGmMneZueqbt8rmBs6wviUYRm3WN6D1
         zsB1ZwTOTSmR7lXOkNd99h9wuRw7nM8nZDs5hLfAtOJUTcjvU+dh51/0AfP+U2OXp7uf
         IX7LzYmuq4WMjmE15+dkYtDztxEodRxV7BUZYZUus4GXgbqDQHa3WYqCQ5VK+XJGb6Xy
         Blj8xdiqRrJZMVgA4HhKU5JCrncDz8o6nf7rjopAkvp9zrFZK+Kn+2kap3O3ilHls0b9
         QT4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=oc84ATApbzKHtjPU1nqnz6r8aqDvQ7hT7gZE8Fo10ho=;
        b=JfR87CyYGR33Og2fl52Cg98O7sD3MhFbOa0zrPsa0K40meNmNloQwiFHsNEoxOuri1
         PL3qZF7UsNMccnEGpio2Ex1k7yQlyOk7IKaAfHeKs4LHrbFiOHNvlCcoDIHR6Pa8XSji
         Q5gpudpTARfwYlJnA6/VrhxTQ53LoxYsl+W2XU5gj6Zb9A1PW3jEtAGrp8A9D8f6skQN
         +vR6J4aeeeMXoCvZVJq+Ui8ZnUccpzY66SJoIcd4W7hrxSRA0nEmMbNZgpfYkhHB6jv0
         mvN58TeW+I/7+ngZWiGVa0wbRRK8bxya6FDmwDkNlU+PxjZqYVVh79zGH6ZYCSPH9eh1
         we1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=fH44ZpLz;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oc84ATApbzKHtjPU1nqnz6r8aqDvQ7hT7gZE8Fo10ho=;
        b=m+GxyX/R3DNA8fehZoE9pkOZTJdAQ63a50y2X6T+nIcW0Pyk/ypMtvPRmL6yQZaZJC
         v5xcOR4Hh31ML6UKsX9YczOvDb3jKkoeqZjQbWAVFtS+mEajnjet6V/X93V0lONAJL4z
         7aEQT/AzWsKZseOAc6DlW0Rw31ZlZ+lcXKZw8vnNUdl/WM52WylFY/W8WRkxwSmJs53z
         QRWwFlAsZoB2UVP3cDad2EJfskJDJ8yX5Zylk3ZxBgyQ+r3HB7gXoNpUEMyDJzLEvrDk
         6wbUxWhyoah3FzuMrFYWP0BminE4eqKqFQBWZ+7mjRTsvs6gIyun3a3GPwmwlr2KilfZ
         EtWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oc84ATApbzKHtjPU1nqnz6r8aqDvQ7hT7gZE8Fo10ho=;
        b=rlZYY850HGu6g6Y+DqjiM3+Z8XAClxU3itUSa0zcN77SVLkFDhL7GJrC3g/z0qTAyH
         8mJv7p0O3HJdmNP1Bg9J+p2YomrXZiAEHwJJmAN1J1YeKD2VIUhgMn9J2N8qaE4yduQr
         P7eUAvcGO3X8DquyemAZwkBbt/2O1O9Cr7HVXcZP/rY1D6fAEM7lfS/6Od70XhXdB93a
         hhFJEs4t7IaHtov91Xqi+BpvT4CXOyRihlhMLBmFWSD79Yok1hkFb3B6P4eX/5SYn7ad
         P+FEPB07cRcskohbc4Dt/OVzkGLsw4A/Ls3gqp5kiGN/19z9moUO22ICyRriYQhVGNwi
         xj6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314i0xmLRd9DKLGpnlpW8gc8ga+7oi9j+EaA1DZaBBGIXk3FplV
	qp802+doTAuMrCYYH4d4t+s=
X-Google-Smtp-Source: ABdhPJyq7KPSVJ2CBQIJQN5Ckz6Re5gnUQ6KG6RekdmXmvPxMSlkbINFp7ZQzWe29kTctwCFI00WFw==
X-Received: by 2002:a05:620a:e:: with SMTP id j14mr27233886qki.117.1617061997214;
        Mon, 29 Mar 2021 16:53:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c83:: with SMTP id r3ls4749990qvr.5.gmail; Mon, 29
 Mar 2021 16:53:16 -0700 (PDT)
X-Received: by 2002:a0c:e1c7:: with SMTP id v7mr27595396qvl.30.1617061996462;
        Mon, 29 Mar 2021 16:53:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617061996; cv=none;
        d=google.com; s=arc-20160816;
        b=VFLkfjxbFUIuhOKLpRKPK8++UEACutWYSReiXTS3VEVxtncHefvSwSKmQCZoV34fdl
         DhzBLnD9y3XbpMNDVE4ypFiEHI7b4g1pQR3bNJzNGZfFSlrmoWuIZlaReUihjFcQ0DKu
         mpPfoNGhjuU5aQW/aUYV9HXmW3zYoXUbkc6SAJOGp+mKR4SU3siaiu+50DBSJ3OJkZm5
         l4SrQ8pp9ES+U0Duj4jwec3MQFlgIjdDB/mNWZ6fvhjzK1UEHVFaBZYCO/kmbTES6q43
         gtwLrnE1j25jUN2/20yxbecTvYC7ZV+B8HXc55Hmn8Sj8xS+vvpwl/a2kyMZWnPZPLOt
         L2sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:dkim-signature;
        bh=1NEBkgMZRDaimfxw2YViqUmMFjvU7xQ9OgrCx+plfX0=;
        b=PKsOdddB7nqfkXTAZxKNcNRspd1Pl2rAm4u4jmTNn5VZEg9py0VSBxB0Vei6J30JYF
         i8BkapU+kM/Ka6WGcG1n7RTN92qxl8fgudtaNQFP+ZpTQ4js6VWj1i2FzmTKDfbXJSJ+
         j/9Lbbpsqo9k5DXHnzqbC4Ew3f+ctR1710tNH6RvAmLrU9MHwIwnHRYxWPD6Y7MeU2sB
         90X3KAQR9Zum93Q6ILHccfUPLzxmXLou1dJDFupMC0e4j9fnHUx/+GyR84cfDWCp/8ox
         1qq8dNCfS6/U/44uNQl6uCRzkhNZJ0pG0AUDw79RyR12ffjbu12xfalvwQb/beLZh4Xi
         zBGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=fH44ZpLz;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (bilbo.ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id n9si915668qkg.0.2021.03.29.16.53.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 16:53:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4F8Tsy0BpZz9sWT;
	Tue, 30 Mar 2021 10:53:09 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Daniel Axtens
 <dja@axtens.net>, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v11 0/6] KASAN for powerpc64 radix
In-Reply-To: <a5e1d7c5-3ebc-283c-2c9d-55d36d03cf48@csgroup.eu>
References: <20210319144058.772525-1-dja@axtens.net>
 <5a3b5952-b31f-42bf-eaf4-ea24444f8df6@csgroup.eu>
 <87ft0mbr6r.fsf@dja-thinkpad.axtens.net>
 <a5e1d7c5-3ebc-283c-2c9d-55d36d03cf48@csgroup.eu>
Date: Tue, 30 Mar 2021 10:53:05 +1100
Message-ID: <87wntpfrfi.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=fH44ZpLz;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:
> Le 23/03/2021 =C3=A0 02:21, Daniel Axtens a =C3=A9crit=C2=A0:
>> Hi Christophe,
>>=20
>>> In the discussion we had long time ago,
>>> https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20190806233827.=
16454-5-dja@axtens.net/#2321067
>>> , I challenged you on why it was not possible to implement things the s=
ame way as other
>>> architectures, in extenso with an early mapping.
>>>
>>> Your first answer was that too many things were done in real mode at st=
artup. After some discussion
>>> you said that finally there was not that much things at startup but the=
 issue was KVM.
>>>
>>> Now you say that instrumentation on KVM is fully disabled.
>>>
>>> So my question is, if KVM is not a problem anymore, why not go the stan=
dard way with an early shadow
>>> ? Then you could also support inline instrumentation.
>>=20
>> Fair enough, I've had some trouble both understanding the problem myself
>> and clearly articulating it. Let me try again.
>>=20
>> We need translations on to access the shadow area.
>>=20
>> We reach setup_64.c::early_setup() with translations off. At this point
>> we don't know what MMU we're running under, or our CPU features.
>
> What do you need to know ? Whether it is Hash or Radix, or
> more/different details ?

Yes, as well as some other details like SLB size, supported segment &
page sizes, possibly the CPU version for workarounds, various other
device tree things.

You also need to know if you're bare metal or in a guest, or on a PS3 ...

> IIUC, today we only support KASAN on Radix. Would it make sense to say th=
at a kernel built with=20
> KASAN can only run on processors having Radix capacility ? Then select CO=
NFIG_PPC_RADIX_MMU_DEFAULT=20
> when KASAN is set, and accept that the kernel crashes if Radix is not ava=
ilable ?

I would rather not. We already have some options like that
(EARLY_DEBUG), and they have caused people to waste time debugging
crashes over the years that turned out to just due to the wrong CONFIG
selected.

>> To determine our MMU and CPU features, early_setup() calls functions
>> (dt_cpu_ftrs_init, early_init_devtree) that call out to generic code
>> like of_scan_flat_dt. We need to do this before we turn on translations
>> because we can't set up the MMU until we know what MMU we have.
>>=20
>> So this puts us in a bind:
>>=20
>>   - We can't set up an early shadow until we have translations on, which
>>     requires that the MMU is set up.
>>=20
>>   - We can't set up an MMU until we call out to generic code for FDT
>>     parsing.
>>=20
>> So there will be calls to generic FDT parsing code that happen before th=
e
>> early shadow is set up.
>
> I see some logic in kernel/prom_init.c for detecting MMU. Can we get the =
information from there in=20
> order to setup the MMU ?

You could find some of the information, but you'd need to stash it
somewhere (like the flat device tree :P) because you can't turn the MMU
on until we shutdown open firmware.

That also doesn't help you on bare metal where we don't use prom_init.

>> The setup code also prints a bunch of information about the platform
>> with printk() while translations are off, so it wouldn't even be enough
>> to disable instrumentation for bits of the generic DT code on ppc64.
>
> I'm sure the printk() stuff can be avoided or delayed without much proble=
ms, I guess the main=20
> problem is the DT code, isn't it ?

We spent many years making printk() work for early boot messages,
because it has the nice property of being persisted in dmesg.

But possibly we could come up with some workaround for that.

Disabling KASAN for the flat DT code seems like it wouldn't be a huge
loss, most (all?) of that code should only run at boot anyway.

But we also have code spread out in various files that would need to be
built without KASAN. See eg. everything called by of_scan_flat_dt(),
mmu_early_init_devtree(), pseries_probe_fw_features()
pkey_early_init_devtree() etc.

Because we can only disable KASAN per-file that would require quite a
bit of code movement and related churn.

> As far as I can see the code only use udbg_printf() before MMU is on, and=
 this could be simply=20
> skipped when KASAN is selected, I see no situation where you need early p=
rintk together with KASAN.

We definitely use printk() before the MMU is on.

>> Does that make sense? If you can figure out how to 'square the circle'
>> here I'm all ears.
>
> Yes it is a lot more clear now, thanks you. Gave a few ideas above,
> does it help ?

A little? :)

It's possible we could do slightly less of the current boot sequence
before turning the MMU on. But we would still need to scan the flat
device tree, so all that code would be implicated either way.

We could also rearrange the early boot code to put bits in separate
files so they can be built without KASAN, but like I said above that
would be a lot of churn.

I don't see a way to fix printk() though, other than not using it during
early boot. Maybe that's OK but it feels like a bit of a backward step.

There's also other issues, like if we WARN during early boot that causes
a program check and that runs all sorts of code, some of which would
have KASAN enabled.

So I don't see an easy path to enabling inline instrumentation. It's
obviously possible, but I don't think it's something we can get done in
any reasonable time frame.

cheers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87wntpfrfi.fsf%40mpe.ellerman.id.au.
