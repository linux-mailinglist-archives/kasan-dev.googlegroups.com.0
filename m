Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBEXRHZQKGQEL6BNHWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6933E17BDCA
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 14:09:25 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id p4sf1427392ioo.4
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 05:09:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583500164; cv=pass;
        d=google.com; s=arc-20160816;
        b=KPd/QRT4Hbv1MtAxJc6nhzZa+wJcEtWrFDwv6w7iGJzEjZh5BPCm2q+6Z7qX2CNa6B
         GU5L6knK0Fxrsj7dCLOz0CGNO60TcdXXBiQhsxU5BZCJe+iKltew9N60GoUdvCi1+Tuj
         /FIpXWBej3o+OXDttE22HJK94p7mL0f1bFsYv3qJ5oa+z+IYdZRvM2cI+hh1SbcuuGyN
         gB/5tiE07V7/m50KU5V+MQP3AgAwbrAnPHHstYL17/yKVN9EOVNIHnXoSuafHphL7Q7v
         fCtzzoRoJ/lH9Rz/xwyNB4pCZ5oe2Tw4ZTK355ScNjnWGUDe1K0OWmJrM461FD4uGs6U
         rYew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=zPm5vTz2/dBuXD9Uu4I0ZueOU8byr4shY7yZUqKhwHk=;
        b=q0FlXumHqXIoWDwir7sYmeqGVczyAK+ZM9OOu6L8fCS+ILYrLufPNOscp60QsucRF4
         1wHEaYGkDr/k/TfsLKKJxUyWi6QJ5E1YI2eftfp65Mzrq5OvpLtbyAnDp7gBoIBfrmVv
         EEMRXzcDOZrU60S1nssphJYxA67kPDjPfF7x859jujiPbxR4u8Y7spuP67Gj94Pe2f/S
         DBOUe9ca0Z5tXmmAler5ZXmmvtsKzGaKqm1Al1TGEcTRj86Z0I69CSg2fyD6wFNsBEjp
         9e0nkwUqTt9vFAXw6l+lapdU1i6OSHWjfYBlcSpYIk1trQGQgVP/99Hyp5L/0x0q5Z02
         on3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gDWywhmb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zPm5vTz2/dBuXD9Uu4I0ZueOU8byr4shY7yZUqKhwHk=;
        b=fmNKChV2dnFZt7ALhgK49ZT9E1aGLrgnQ7qUkoppjOfljzZcd5dymxTOW0bVYiMthz
         u7LTeJNMQ1qpF8oBL2jz+GaxW11tBdxTVj6GhxaJdJb7NwIv+mNzJ4N0jZXOxKHaqPER
         mcYknmqwaMR6i2iD/NblQ8E/WzhVlPpPbVaO91SLis4RrjEv8BwOerWjjujPu/Mb2zSg
         eOrz1RjFCf3OTz5THFW3TN3ZnfAPBg0veQBuh2LFZa8mSmxVE76fbeDuJJ6WnjyPd3v4
         4xwHq15YUGiV18mtUXDmPt7/4l76tFkxYju/zKOtIAYKXd/OLSG6xi/bXHX6BABVDEwo
         ahpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zPm5vTz2/dBuXD9Uu4I0ZueOU8byr4shY7yZUqKhwHk=;
        b=J5rYcBHv59G9xrQ8NzmCtdURPl2cm1T/eLtHijV3tA1UQQU3wVh1sr/pKWsd9v4PsZ
         gGOwm0ck6Hf7MzhXQsbpPHkvp1xPmfKrHGsfkh+H4QYxPP/RipF0T4a25a2zxa+rDQhT
         Wxaql6I1yDhX8lC8TFa15skG2XH6mBAfVnMXWs8jfP3e/FNGLoCHOUvvc0GMSzW7n3aH
         TLO3Bwr5Ax5RKGHc+Dz9IfB6LFxbfhWGOqLKAo7gDxLI301JhuwXu6pAta7KXlAHa63Q
         SlVaqFRQFx9QXqwATMU7C8Cj3jPsrNMvA5/oDUuLD1A0GtSmSV6FyVzClCAl9IdFfslN
         50gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ11UOesIp4vPXqWf+QsQdA0Ngiu1JiT739MVU5KA2zWVFIzcu89
	LbMD+O0Dw1QA3PZjUM8TY4w=
X-Google-Smtp-Source: ADFU+vt3myXA5BpvvPZC+BFi6R4u/zKHfRzSE7MvxTkjAYxa5uKP7ayZlPw2pofQmyS+na+uC/jqYA==
X-Received: by 2002:a92:c9cb:: with SMTP id k11mr3301691ilq.132.1583500164352;
        Fri, 06 Mar 2020 05:09:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c9cb:: with SMTP id k11ls602821ilq.10.gmail; Fri, 06 Mar
 2020 05:09:23 -0800 (PST)
X-Received: by 2002:a92:187:: with SMTP id 129mr3032256ilb.24.1583500163767;
        Fri, 06 Mar 2020 05:09:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583500163; cv=none;
        d=google.com; s=arc-20160816;
        b=s3/Vfm89ADE9trbzZY+iwOdIN1/D/Sp/hDKXG9SVdZxNSPu1C56In7M1vzf+Fdp0nm
         zC0T0ypiFdHFA9cEurtdUqGHFhdfKl77lnpT1f4FayEhZ+zvFU5R9SopqpEW8wbOVlQT
         Scylr2N51PomrDAM81HTc8f10/VVbY5NV3o+ubqWNH2FqUtA5q2JIwfGKPFPgKJ6y+E5
         05F3ahUMbv9Ik3m4/zRK+eqyZLyCK9lSyw6qZmsERbyXTyqgrAX5BL5IhpLaydWe/ABx
         MTEWjjmW5dklqngK2TrSkKlT0uPd4pj2hrX8FaHw0P110S7jewFXARv+YIurCRTzNTQl
         oWhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=QwvL99c3sTAWScS17ZDj22BvXW0QqQWIhRt4cYTFYXI=;
        b=O9aunyg6ULXV8Yu03riq8TDb6SRLdJNd95wcZBU88yxkF9eblf+eXSpPIJzYwgfOKf
         MlL9bcNokxYdY9ZkvSIG/RdPQKiTxLb8sQlUA7mLrtDe0IYdtG0sH9dIHhud3T3WLV6/
         CsQ5XkwMIe322TroyMlzH4rpMPS1/6lyfBbdr3DaALpKLmCr1zpYtKPh3peUQ1xRF447
         pw0FEKvZO/GuYO1wfOoniFUKUO80OU8FOpTcFlsv0a2yadds96ZpFu4bXt8jRDQwDxuJ
         pGyhzZtRxwiSi8GParRd/bd7Zs/SWSPMgu6OkFa0YHdb/1TrV7sGjE0q/YRUbkCn9iV8
         W+/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gDWywhmb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id q10si95192ilm.0.2020.03.06.05.09.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 05:09:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id l184so1099190pfl.7
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 05:09:23 -0800 (PST)
X-Received: by 2002:a63:a351:: with SMTP id v17mr3195903pgn.319.1583500163031;
        Fri, 06 Mar 2020 05:09:23 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b120-f113-a8cb-35fd.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b120:f113:a8cb:35fd])
        by smtp.gmail.com with ESMTPSA id k5sm9354724pju.29.2020.03.06.05.09.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 05:09:21 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v7 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <abcc9f7d-995d-e06e-ef04-1dbd144a38e0@c-s.fr>
References: <20200213004752.11019-1-dja@axtens.net> <20200213004752.11019-5-dja@axtens.net> <abcc9f7d-995d-e06e-ef04-1dbd144a38e0@c-s.fr>
Date: Sat, 07 Mar 2020 00:09:17 +1100
Message-ID: <87wo7xpr42.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gDWywhmb;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
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

> Le 13/02/2020 =C3=A0 01:47, Daniel Axtens a =C3=A9crit=C2=A0:
>> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
>> index 497b7d0b2d7e..f1c54c08a88e 100644
>> --- a/arch/powerpc/Kconfig
>> +++ b/arch/powerpc/Kconfig
>> @@ -169,7 +169,9 @@ config PPC
>>   	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
>>   	select HAVE_ARCH_JUMP_LABEL
>>   	select HAVE_ARCH_KASAN			if PPC32
>> +	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU
>
> That's probably detail, but as it is necessary to deeply define the HW=20
> when selecting that (I mean giving the exact amount of memory and with=20
> restrictions like having a wholeblock memory), should it also depend of=
=20
> EXPERT ?

If it weren't a debug feature I would definitely agree with you, but I
think being a debug feature it's not so necessary. Also anything with
more memory than the config option specifies will still boot - it's just
less memory that won't boot. I've set the default to 1024MB: I know
that's a lot of memory for an embedded system but I think for anything
with the Radix MMU it's an OK default.

I'm sure if mpe disagrees he can add EXPERT when he's merging :)

> Maybe we could have
>
> -  	select HAVE_ARCH_KASAN_VMALLOC		if PPC32
> +	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN

That's a good idea. Done.

Thanks for the review!

Regards,
Daniel

>
>>   	select HAVE_ARCH_KGDB
>>   	select HAVE_ARCH_MMAP_RND_BITS
>>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
>
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87wo7xpr42.fsf%40dja-thinkpad.axtens.net.
