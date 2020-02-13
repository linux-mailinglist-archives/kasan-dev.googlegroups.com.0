Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBFVBSTZAKGQE6EW4HQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id AB43A15BB13
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 10:02:14 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id a189sf1756995wme.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:02:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581584534; cv=pass;
        d=google.com; s=arc-20160816;
        b=XhbOtaB9fGCnmfxs5YEza2cjauVfdRdSl8BfxepcL8DUkq97MyR/kt3eEWdm6LDybk
         4+byw51Y1tgNcj9TaauauE+jpBuzRQKjbQHexqhSy4Ed0OWzB/vz490HvMGBp2DQPuRR
         XZVxJTAtyhRf2TU61YCjlhui8sti75+ORpwJ2PUR1k70O77vbWC98ZXyTTImM/U1vq6u
         FKz0mATDwzjhpFsPEjXlfFXUxP78M7KI48G4ckg0X95byJwd7CsghYKut0hW4b9hPf4J
         Ethkm9ZAFGjPEeBv7v73R+ZFjPXYcNswWleZQUjNQQTToUjXibB4/GLYrOkuN2ZXS3eu
         HrtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=YtyWH5n/I/93OCIZq/b2woBDHKF1TW9kg4Sj2JKBjY4=;
        b=n37m6UX53ViL+ytBlZgJVloMT/yxuU5AmXwLqa0m3R+IQHFbm3JhblM0XiSBByzh7D
         XQnUv/f2CORHe46oGDjzzIqoEvw1Zgso2lrKAeoYK/CqoYm4aOeuBbGHYwYl7z2HZDaj
         3Q9tfdT204wgDBTbJn9GtqQtoQI90TmfED6zo2RvuxXPWOn/3M7MTlubJ7qS8w2iBlrV
         MGZTdob7wprhgm7FOSuamVV9JsPCknNKTubQGJ79vAsg6ksymisXHmiqe0oQPmJqDF9K
         rnGfEZeYXqa8LhOff/HLtG33aCSwKgmazo7Hx+TYBt+/TUjenM2lvz0cTIJMv5W3kpzZ
         r9sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YtyWH5n/I/93OCIZq/b2woBDHKF1TW9kg4Sj2JKBjY4=;
        b=Pcrb4ZYcBTKSRaiJrbxmpLfyVHYBPoggEl1YxSZmfsrqlN3gF6xUGiVW1diDXvgu3O
         SQamqQEHhThUYBmc7GhdvQAlp665SkJX9dcNzo0FveLPAxSWv0OuGByceF/fWsJ8mxn1
         vNUeAvO6L/gGsc2v6oqdR7fCM05YVXgh3k8TyyMmxH3rROoKq2zWdopTFI0LtD/M9rP8
         ULqBZAy22QsRsbtzIJbWMJYcYfHLKRcAyQDWCfaQE/d5hjlx0QIHIXQCm43ir+MUETqh
         RE934GMNTiMsDbXPFKnO6Zr2laFvmDA0qL7rN7t1K7EGsGflLoaILjG6M+pdkgF3DayK
         0g3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YtyWH5n/I/93OCIZq/b2woBDHKF1TW9kg4Sj2JKBjY4=;
        b=SHEx6uYyLDtis81U4FtN0P0UAeFcEeMi2eMAcQ1H1ysx4YmPpK3LsEHb96GHxLXBGp
         xekfjTqh2UcYw4JRWSs+UwjGVoGQq2tMnfbyBfqffjCy4MVf4rCC2FvoJ6RMQ84C5N6k
         u2JC1WtkkQemgDUg4NhjfKZpO7RXa40kVI2qZWYgRdmB0Abxb3QBHb4qeQNwfDh6OAjp
         B7eZXdM7hTSdKKk28hauSZTwyPru7TfiOovm4+NERH5iLx605P8ttzGTXsl0/HFhVPTB
         5LCabZk8V5gHl6ZiaP6D9UUTgLrssZIRLox6mz6QvSzC/5nHc3SmF043JXlptycQN/rC
         GNEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFS9lW3rgJuyRksupCO0qS1vSWIxEo8tIVDTWRd/oAvD0c5lID
	u3nVmO29EPpGnosep+ma38Y=
X-Google-Smtp-Source: APXvYqzTargR4NjflwSVDRAlzwyXknAcxKJWzTDwowysFLzaeKndDpgRO5C1yJ6QXLqERX9RssXfLA==
X-Received: by 2002:a5d:4d4a:: with SMTP id a10mr21738932wru.220.1581584534422;
        Thu, 13 Feb 2020 01:02:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e50:: with SMTP id z77ls2316385wmc.2.canary-gmail; Thu,
 13 Feb 2020 01:02:13 -0800 (PST)
X-Received: by 2002:a1c:3803:: with SMTP id f3mr4762037wma.134.1581584533752;
        Thu, 13 Feb 2020 01:02:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581584533; cv=none;
        d=google.com; s=arc-20160816;
        b=Lhnbj35E/qon9GzHM6sQjXbUHMLGS0XgNLVva3EvyFxDHgzxbHAxULjg2I6wfpbXYD
         b7fwrJ42eEl3pUaPPGfDD8q04Ha7F2c8zWMWKrYVNYXIJ5/N7mloKXSDNieLRuO0ctcu
         Sns5LgIBQ1nbNmylCIJ/ELx34ecLpsxwC1twyJ63L+u+GZ7jXqKhTvIZWi58Sl1w3wX1
         7kD0Es0YaVUGnWTpJ5DhwuJLjalgCxcDTAjCuJ88muITe2aTRSDa8V3VWZXWvNh/kmQC
         5exMQfGp92dG+TigdxxOpb7BeAqWfGFC6qKqLtpIL2lvvbThDl1Zd6aezL19CsPCn43d
         zcTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=XRHT+2FKuH+IeuXt38xy7quFZIkPkHYxtykAdZTCriM=;
        b=1BQl5Kgeb7HhXCN0gTDXDcxTXRbeO2lB6mbblyBjJTwTSeYe6f+Vzxs0MMavpI0WtU
         o7zPzheFXje0EN7ez0bcwGNgUPU29YHOUoJ98WSrlUqp3yqzECs7KpizXw6X1IjYAmXc
         t0zeV+ZyrdcBA3JY6BFZEc0QkznHRKlFr/RsBGNf7icywrJUxgaPflNTcLoUvcn+zv37
         58CzT6ZeQbX6RIusziudloq8GfNdXyuYOyzA8TTdwsIap3heStU/W8+Ex2jSqygx+Q2f
         kjF5JCJYlbeUOM2zitjygdkv1tz6rEQgiKHKQESbcMJ/dHfjmA3kXCYHYt0pHVwAg9Yk
         kcJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id u9si87568wri.3.2020.02.13.01.02.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2020 01:02:13 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1j2ANq-008F19-Gs; Thu, 13 Feb 2020 10:02:06 +0100
Message-ID: <817580a4bcfbd3ef3ce31dfc5876bb99c3fca832.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 David Gow <davidgow@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
 <linux-kernel@vger.kernel.org>, linux-um@lists.infradead.org
Date: Thu, 13 Feb 2020 10:02:05 +0100
In-Reply-To: <CACT4Y+ZB3QwzeogxVFVXW_z=eE2n5fQxj7iYq9-Jw68zdS=mUA@mail.gmail.com> (sfid-20200213_094451_311672_27C02820)
References: <20200210225806.249297-1-trishalfonso@google.com>
	 <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
	 <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com>
	 <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
	 <CACT4Y+ZB3QwzeogxVFVXW_z=eE2n5fQxj7iYq9-Jw68zdS=mUA@mail.gmail.com>
	 (sfid-20200213_094451_311672_27C02820)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
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

On Thu, 2020-02-13 at 09:44 +0100, Dmitry Vyukov wrote:

> > Right, but again like below - that's just mapped, not actually used. But
> > as far as I can tell, once you actually start running and potentially
> > use all of your mem=1024 (MB), you'll actually also use another 128MB on
> > the KASAN shadow, right?
> > 
> > Unlike, say, a real x86_64 machine where if you just have 1024 MB
> > physical memory, the KASAN shadow will have to fit into that as well.
> 
> Depends on what you mean by "real" :)

:)

> Real user-space ASAN will also reserve 1/8th of 47-bit VA on start
> (16TB).

Ah, but I was thinking of actual memory *used*, not just VA.

And of KASAN, not user-space, but yeah, good point.

> This implementation seems to be much closer to user-space ASAN
> rather than to x86_64 KASAN (in particular it seems to be mostly
> portable across archs and is not really x86-specific, which is good).

Indeed.

> I think it's reasonable and good, but the implementation difference
> with other kernel arches may be worth noting somewhere in comments.

Right, I guess that's the broader point. I was thinking mostly of the
memory consumption: if you run with UML KASAN, your UML virtual machine
will use around 12.5% more memory than before, unlike if you say have a
KVM virtual machine - whatever you reserve outside will be what it can
use inside, regardless of KASAN being enabled or not.

This is totally fine, I just thought it should be documented somewhere,
perhaps in the Kconfig option, though I guess there isn't a UML specific
one for this... Not sure where then.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/817580a4bcfbd3ef3ce31dfc5876bb99c3fca832.camel%40sipsolutions.net.
