Return-Path: <kasan-dev+bncBCXLBLOA7IGBBUFFW3VAKGQE7FBIVAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7081987E19
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 17:35:44 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id l16sf1430293wmg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 08:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565364944; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9zroKhLAE5lHh/q8pUBECJru9nB874cXSKKZPSud89QizAMJwKqssEclXYtiHdzny
         58UGmTq68fZH0upfaksUu7Jt1u0I2u7XladZRYYfPXdiZZpd4rF991kZ5eCFfXx8MSyN
         FcpxjrBHG22MoyNOanSbNEg/tHJf9hrkTq+2SamkAt99l9aRTUPHCmVPvhVpH4j90N1Q
         uRB88MSAHXShMx2XhiWeYbrQL0bQlml/Hi2+jjtsW+VRmlLkxzF92mAjIJN+lk31sfu6
         79SJzFJiWuMqnyOjH/wpxpeX1wHp75qqIGG8dwONIT9tFSpABq3IJC6d3jsyUbiUuzI0
         12fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Xuh7M5I8h3fFt0G0aUzWjy6azcSCYmU7nnZUBayZS+o=;
        b=OhrOZFvx2b+opi9BW0/qc18GerWQrNOxUbc3okCvbsonlDEcIGEzg3PWHf1z/n4GN4
         Nawb0Tg1gFVMKjks5y5W+BEHgZ2/YsKZesodm5l9EGwryFoxge1mqxAK9JppkE0GZMgp
         EHVPJ2EOeRvuL4SdXt0y82uI1bKUsbfZwz8R0ez459xgMeEzVk6RxodTHYap+hqg6FRh
         rgwwgefO2Ehp6j4RRLRkDuj0cCtKa6q61p+tJ4z3dt3/x+vH3HT4GEchoNyNwxI/W4sz
         aLGno74kpFdcfnMSVA09eUx9nh+IqMMkK74xotDDQ8QTuIsUNrMHwG+JnbMWQXdStycE
         DRww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=XiJKbl8O;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xuh7M5I8h3fFt0G0aUzWjy6azcSCYmU7nnZUBayZS+o=;
        b=AUtE+VFmvMPpUTGCEIsTO1UZZFpRxUr+Ar2d3jkc7Vjxma+t5ObmeHk/GiqVVtSoja
         ZzXLTuf2bbbTedaEUxZrsgOibgbpdEqaCCtT7nkh53DUe9KZkpA3GsdAYRD+xzxQ2VWm
         eudvetkH8p/nWbi1k7zBFUwMMJOUoAyZx4XoBjYOCtcz6Q7qTKgCZwj8yjbDzr1IP35C
         DWL9y6AhjPVUhXZLzKDvEudQuJSWNpgHQbMpK4A+LTkWQqEtagyfmRzbUlEjfHvgz0Vq
         CwimWIwuOvDBwayHY52XtrRvALVqMisCMkK1RJmdMLUXDFYYSZk1k/dur2RbCLbYLPjQ
         xdIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xuh7M5I8h3fFt0G0aUzWjy6azcSCYmU7nnZUBayZS+o=;
        b=USR74qnyGeW8FwFhTe8O2jKht+hkBudoxRYfDF8SY1P/QIt+YjkB1MeydAEr7rE/qG
         vro9jG9vkOJEKOznnEruw5BSVzV9voe9Gr8gRhbo2D2AgZh3kYaR3Av5f0ufodMxoHdg
         ItrKvz7kx8Ad0NJewFN9UAfU9sTaUGktT8RsRAvL1zCq7Gop09uhLcxbZxa7bRyFUf1/
         eKg4EB08eVYuhb5tyl4KKkCUnPUnKIYXwj6FLUlFon8xEOcFnAO6qEyS0eKa5nGB2RiM
         fqV+vGvpy21ZvJYCprzjJO3gfkdcFqCU9L50U4/l7nRMwfblOqNw5Rh+awrlXhhrcGpA
         dYJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUh7wchMAEyjAvKns4vsJfm5liHSHUHiEmGFmpd+KVQP24F26h3
	chCjPIe0k5fHmydSnU4b7N4=
X-Google-Smtp-Source: APXvYqzeCbj0iov/oYVGfAVli8zi3/2KauKSXrDJ6Y03xqtLVKVDr8Je9MK6n9r7QKY7vD27dn6DWA==
X-Received: by 2002:a1c:345:: with SMTP id 66mr11830449wmd.8.1565364944141;
        Fri, 09 Aug 2019 08:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cc10:: with SMTP id f16ls2255747wmh.2.gmail; Fri, 09 Aug
 2019 08:35:43 -0700 (PDT)
X-Received: by 2002:a7b:c00b:: with SMTP id c11mr11876657wmb.46.1565364943729;
        Fri, 09 Aug 2019 08:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565364943; cv=none;
        d=google.com; s=arc-20160816;
        b=nymUN+0YDjHHOxfveJDYqhgkqOm2stb+VXWbp9IH/lGrsaCAQnXIyzjjz3n0Cc6KxN
         h56iRtTF/J7NGdpQDSy4cJUJ6TFHNk8Qd1euLNHokjUVYI2zy59e/X9lYBwLKhxVk7Ha
         fS5IfqJdeyud3UfFBYChVNcFAgBqq0mtPZFVAoBW7qKQ+B/4+EQxoHFSzcH49MGwvB/+
         5GRk+JC/IHSrCwR58ba3EA5Id+jt+94yhLUEvetl8oZNqZUl4H3tP4vbYPfWoZYQBOTh
         nwZT1uI6zX6c6QKHjC5A252s1OGhXbKUUnk8ODL58DwSUOslUkYk46pdMD1g6rctaamE
         BsBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=MW9yLrwQEfrYZbXEf6+OUywwvutO0iJiW13AR54u9Wc=;
        b=w0/Ke/Ak1Ntju9HZcLxRryYaCRUqbieEamYxi8YjsiB5hQB06FqSnqliYIitwJOC9R
         InBrb2UuPPKkm0NBNSpEc7JvSDz9kRrbDFVOhAjdTftQ96U4ZOOSdJU3vRQDoMPvJTor
         FSoaHb/EiEV5kBfcQQmjOuIIh1IueGGuIRbEhEGyTCvH4JwPfbyXWU9bYCeaytxFN+v4
         o3nCgHWggp3dzc9jHXAtJB+MQOgim4AbV6NHBe9ChBHbyryuwDUKnzuI/vKPmiYWcmlq
         LoLmNKtUka1KJ5BQfnSQXi93VPBb76wmR35ziOTgeXDfy4glhuO9fGvdQfSIxm5OcPkV
         kUVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=XiJKbl8O;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id q14si220063wmc.1.2019.08.09.08.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 08:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 464q7x3x3Rz9v0Xm;
	Fri,  9 Aug 2019 17:35:41 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id ZfxJ1eKhQBmK; Fri,  9 Aug 2019 17:35:41 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 464q7x2jsnz9v0XK;
	Fri,  9 Aug 2019 17:35:41 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0DAF08B8C1;
	Fri,  9 Aug 2019 17:35:43 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id qwWvU-4DqhAu; Fri,  9 Aug 2019 17:35:42 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C2FD98B8BB;
	Fri,  9 Aug 2019 17:35:42 +0200 (CEST)
Subject: Re: [PATCH 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>
Cc: aneesh.kumar@linux.ibm.com, bsingharora@gmail.com,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 Michael Ellerman <mpe@ellerman.id.au>
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-5-dja@axtens.net>
 <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <a47d9112-775f-1e04-3ff4-08681b4a6349@c-s.fr>
Date: Fri, 9 Aug 2019 17:35:42 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=XiJKbl8O;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Hi Daniel,

Le 07/08/2019 =C3=A0 18:34, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
>> KASAN support on powerpc64 is interesting:
>>
>> =C2=A0 - We want to be able to support inline instrumentation so as to b=
e
>> =C2=A0=C2=A0=C2=A0 able to catch global and stack issues.
>>
>> =C2=A0 - We run a lot of code at boot in real mode. This includes stuff =
like
>> =C2=A0=C2=A0=C2=A0 printk(), so it's not feasible to just disable instru=
mentation
>> =C2=A0=C2=A0=C2=A0 around it.
>=20
> Have you definitely given up the idea of doing a standard implementation=
=20
> of KASAN like other 64 bits arches have done ?
>=20
> Isn't it possible to setup an early 1:1 mapping and go in virtual mode=20
> earlier ? What is so different between book3s64 and book3e64 ?
> On book3e64, we've been able to setup KASAN before printing anything=20
> (except when using EARLY_DEBUG). Isn't it feasible on book3s64 too ?
>=20

I looked at it once more, and cannot find that "We run a lot of code at=20
boot in real mode. This includes stuff like printk()".

Can you provide exemples ?

AFAICS, there are two things which are run in real mode at boot:
1/ prom_init() in kernel/prom_init.c
2/ early_setup() in kernel/setup_64.c

1/ KASAN is already inhibited for prom_init(), and prom_init() only uses=20
prom_printf() to display stuff.
2/ early_setup() only call a subset of simple functions. By regrouping=20
things in a new file called early_64.c as done for PPC32 with=20
early_32.c, we can easily inhibit kasan for those few stuff. printk() is=20
not used there either, there is even a comment at the startup of=20
early_setup() telling /* -------- printk is _NOT_ safe to use here !=20
------- */. The only things that perform display is the function=20
udbg_printf(), which is called only when DEBUG is set and which is=20
linked to CONFIG_PPC_EARLY_DEBUG. We already discussed that and agreed=20
that CONFIG_PPC_EARLY_DEBUG could be made exclusive of CONFIG_KASAN.

Once early_setup() has run, BOOK3S64 goes in virtual mode, just like=20
BOOK3E does.

What am I missing ?

Thanks
Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a47d9112-775f-1e04-3ff4-08681b4a6349%40c-s.fr.
