Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBTPJRP2AKGQEIAWPNCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 98108198D43
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 09:44:13 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id l17sf12614088wro.3
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 00:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585640653; cv=pass;
        d=google.com; s=arc-20160816;
        b=oEwultjYRxLHGeASvkx19tvpF2OLQnh0cSAMfclxwTcFQ6UCR3Detrr08WSE+wksUh
         jlCjMflJOJX19uTAvzzLo+/H5halWCER0TgG2RoBMNOyPqTHoHr2wgo6k8TiL+o/u4Pe
         rmyrm+wESYeRR1yiyyOAj1gPbA+oOJltc5E+fMYVVVDJiQqi0xnOUQYI27u3ATSkUTJ7
         l75MXKMQ6qUqt6vznW8gCBu/dnxLLvII6NiVijkgBVisClrpTzuLQL3V98R+Pm9SS7JH
         DxP1LG+wBLsBRsF+Sy3Awu3ZQjgqxekMy+rbBZ3avE469hjcDZ7A1vXEAPpF9j3UKvPX
         7dFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=J8L1oK+x8w2GQYiklUhUN6X4zLHPXMAazbVF0yHGNqE=;
        b=v/dU2DV6jpZsL68femffuh6JJgGnoPX/LQkyJUaj9RPcLBuWu8C2j53UYbYQqsoD5L
         y06KrmplnBPPWRe5YsnAlE0fF3UW0Jo2XUcAONBnZ4EZ8wvcZzOrw0eWAAlDMDLFA5Dv
         1fgPSlRn1N97p20jnus0aN7jMrWknUm9UTzk6Kq4+xZtRpKvCHfIbHWogQzKTE3EIWLP
         vtADC8mmL+4vlK+SIKFTWQ4fh2NYeD96ng6ZKMN/CnKNFbXopkQU4lcUayJk6bNRh43M
         Kskvphu+dKsAka/Z7FCyABXtsONk/bsH7iL0wCbsrKpQh3+7WL9z+5j91oBLRlreltHr
         WCpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J8L1oK+x8w2GQYiklUhUN6X4zLHPXMAazbVF0yHGNqE=;
        b=qVb4ZJq9vTyH3HMsTfXKb2OaGk8TuhvsKmHYvPGfomc8W2aK29cKjQfaZMJ3VNf9t2
         hDoNQ1/6KiIyGLNiiHKTHSzom0dfBsoTTJDsGe1JsG48rtq/LuF4/5HtTjXl9c7yZAyj
         ReYAHwqn7z7ejKBRt3blKoQnDQdyCMUmFWII0iE3+GxNcwuSEZD0aEUkBP6dLEZVP3tk
         YSyB3buDCRohP4n35hyvaC0LNFRHg3rUdYC8ns7h2SufZJpEsG/1vPSXvRF4u/eTHWcT
         lGQXrOyNz6MkFbI5VDcTXNebEPWRMncr3jgHrTsdyCkvJuYKJ4O3FV6242FwxK/zdPs8
         CeSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J8L1oK+x8w2GQYiklUhUN6X4zLHPXMAazbVF0yHGNqE=;
        b=H7ilqDWK7R9VcjMUNU/nGxL/1U6f51i3W7isVtjwDGuBrrOjNt3UPwuCkGEFxMjQxp
         bZ5jCp62+sNJ1Q5IJdKSOVoWfTiDVqI2lUZLJYAnTW0VdjLPKeBLs4VvS9fQDpDj0HJH
         6ohRwIklGkyNdh8AwCiRE4sSh/PhoLjelaHnHw2dsQstzIDqE9g6jQUVyx4I/pqSrrI9
         yteMf+WzCLMFE7fXao+/nsmtIS3P7UcTrjZus2ijO1YCoS2hZa6v6gF0xwfvliZIz6OI
         dpxcpYE7Km2GAxqVoiOgHmLeUGk1mKAKMsQT/KAJscBK5HaBM6J1a6OoDAr6CJKqi23f
         hDFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0pEAfEvxBdlWaHTJYWWy38bZUH5g/+3sOERtXeIbGi5oFijPFx
	XZZ1piEdiSrr4cnCUZq6v1Y=
X-Google-Smtp-Source: ADFU+vvwksAfRV7PoXybUfRpBc7P+jSVtgsOA+/UmZLFVfdoEcofKLPurZHu7jYa4KK6qFxhu/NrFQ==
X-Received: by 2002:a7b:c5cb:: with SMTP id n11mr2159581wmk.160.1585640653237;
        Tue, 31 Mar 2020 00:44:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4b07:: with SMTP id y7ls982550wma.2.canary-gmail; Tue,
 31 Mar 2020 00:44:12 -0700 (PDT)
X-Received: by 2002:a7b:ce12:: with SMTP id m18mr2129859wmc.135.1585640652702;
        Tue, 31 Mar 2020 00:44:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585640652; cv=none;
        d=google.com; s=arc-20160816;
        b=SYnB/wHPnROT3WDMcva3Mm3Ol6uAr5krVDgIHUxHK4r2Vm9myWx58d1XxVH4Sim8tG
         Dewi7nl1ZY8OYPxXLokwFF0HYPFU5zS3TIuacMC5LLxxCUDR6fU4GD/GPugs20lau4o4
         s3FvE+nMHznI91DczMSubpZuODI2tDQjzvCyN2EC5xId/l/C4MqrwNA17+/p3RYCsbIy
         rBoWtKlgEzAfe5ev4mObsROvvUNlOJVayVs1g66u4tyyZtNvXzAOdmiPXXNNz81eKc+/
         dLlRSt4Sv2WOwCZVnNaouDNDKMdbfS0bku1xONRWUUeOuxmx3jDMlLA1PZFNZJ/k+r3c
         Llfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=mY+wh5Q6q1wCCnpfeGfqbJIfuTMV93y/MYraoa9jzyA=;
        b=x25wudVLUHmU4MO6uS2kP9l8r3/rkpX4RzcaHZ27Atb9yeXsOA6X22/y9KmDVFAQXn
         +Uqp/1Ora6B/PwW1ss3BC9hljfz2lIknP8FBXewFj1swFdnlcxG2m//Xd0ii8V/IN55s
         sYuCKp375Z0leTYS0ALQHBMt7dCmqmV8LRcXHa2yQfY8zCG0IUW66cLRcPWud1VvBq3q
         upa6ArtshZetoxbYLshrztq3eDV6rPhz7ZKZKLp9u1SGn2ydEK+r+dzqIFCKuPU/kxsf
         rkWn5yEpLSbSunjGDO9yEMlMAyOyzB1u2mLWbEP+AMX/jKZRl7lnpVgYy0GjvAP24hTX
         Rkgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id b81si58413wmc.2.2020.03.31.00.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 31 Mar 2020 00:44:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jJBZ3-008Kx7-9S; Tue, 31 Mar 2020 09:44:01 +0200
Message-ID: <19cf82d3c3d76ad62a47beee162fa9ff768a3a01.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Patricia Alfonso
 <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, Richard
 Weinberger <richard@nod.at>, Anton Ivanov
 <anton.ivanov@cambridgegreys.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>,
 linux-um <linux-um@lists.infradead.org>, LKML
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Date: Tue, 31 Mar 2020 09:43:59 +0200
In-Reply-To: <CABVgOSnz2heYvXytvhwA3RO_3dX=8vKrC+b8a6GLZV8eD3Fcow@mail.gmail.com> (sfid-20200331_081511_061239_730E62F6)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
	 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
	 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
	 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
	 <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
	 <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com>
	 <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
	 <CABVgOSnz2heYvXytvhwA3RO_3dX=8vKrC+b8a6GLZV8eD3Fcow@mail.gmail.com>
	 (sfid-20200331_081511_061239_730E62F6)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4 (3.34.4-1.fc31)
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Mon, 2020-03-30 at 23:14 -0700, David Gow wrote:
>=20
> I spent a little time playing around with this, and was able to get
> mac80211=20

mac80211, or mac80211-hwsim? I can load a few modules, but then it
crashes on say the third (usually, but who knows what this depends on).

> loading if I force-enabled CONFIG_KASAN_VMALLOC (alongside
> bumping up the shadow memory address).

Not sure I tried that combination though.

> The test-bpf module was still failing, though =E2=80=94 which may or may =
not
> have been related to how bpf uses vmalloc().

I think I got some trouble also with just stack unwinding and other
random things faulting in the vmalloc and/or shadow space ...

> I do like the idea of trying to push the shadow memory allocation
> through UML's PTE code, but confess to not understanding it
> particularly well.=20

Me neither. I just noticed that all the vmalloc and kasan-vmalloc do all
the PTE handling, so things might easily clash if you have
CONFIG_KASAN_VMALLOC, which we do want eventually.

> I imagine it'd require pushing the KASAN
> initialisation back until after init_physmem, and having the shadow
> memory be backed by the physmem file? Unless there's a clever way of
> allocating the shadow memory early, and then hooking it into the page
> tables/etc when those are initialised (akin to how on x86 there's a
> separate early shadow memory stage while things are still being set
> up, maybe?)

Pretty sure we should be able to hook it up later, but I haven't really
dug deeply yet.

johannes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/19cf82d3c3d76ad62a47beee162fa9ff768a3a01.camel%40sipsolutions.net=
.
