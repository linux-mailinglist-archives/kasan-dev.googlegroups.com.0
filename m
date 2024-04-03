Return-Path: <kasan-dev+bncBDAMN6NI5EERBCWTW2YAMGQER5T4LLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F5D88978D3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 21:10:04 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33ec308655esf40477f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 12:10:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712171404; cv=pass;
        d=google.com; s=arc-20160816;
        b=yZw57R1YEUm9Qwx3D5FbaFCIQmb/7v0Wb0djYv7GHe5ApZ2EQTSXSLtlltw3n9VkxR
         OAAjBatV+sSoUHWZ77aCwJOppaC66N7BZrH1Ubfd5EeQrzQilsxU4LZnptCeEycaTNc7
         4B8rALEZX20FMT9wuAX7cERaFl4t59maF9wNXTXvK4Jwp3bG89yYuyDoB4rsjWYMCW7N
         7jD7AsfyBYtV0EJx1IXhj0wcwEse+kfK8kQ/b1IElmNlC+hgRj1m5vzBThX70FbwvU/X
         PkLD4gn/+ZxPTSCgtpGc+qCQy5baROsLCHnn8dG8/mem/rJldUDCn1Qq7RIya15+MBJj
         LjrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=zw1lM6UrltfK++zsbTUyYD3r0NWCOuZkBU3l0c5u6iA=;
        fh=6zsOppeZXWlnXR3zFFHHSATvTIk8uB+MDOoML1JOoQs=;
        b=I/+kHf8GJ/VlgYBp09iDtmOo4JIJo8LdJ4ZsgKVHwFUaM3DDq1fgRR+ncy9HdjMlSb
         PWnc7Gf8Da3OuP7NFZoAbUmEEJQH3CieansK3PT7rbVdynRmKbZ7vuGcnKeZoLYgXwIt
         Xnd808fzRcYgPYR+EYlCPnTxnkJ7kWdzPCinlCUg6G6axftHN73bNKyv+AKyM078WwMb
         94dfhdPicvhrN9dHpBqW3DJE5w0hBnCBz6kFJcplag0EYTkz1DIRhOZ91spUwJLDC9OI
         Out1raUNGlU896tqksSKDNJBmEmoDAU3F72BmAnJ8rFIS9BwO8DnttUoDEgw1EC4C102
         npPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=xShiaKJt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=yQTIGrSR;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712171404; x=1712776204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zw1lM6UrltfK++zsbTUyYD3r0NWCOuZkBU3l0c5u6iA=;
        b=Z4KIqxpAHFmvIf6G2O+aEC259fXdG8QutV3ecl1Kzv7g/IdhxQTnNLQJvy0Ab4fNr0
         FMGSKglLtLEr/sETBPrXNoUFKKUWOw9x3Hy/Ljv5scs4zAtVgqMMvUkBnvVQC4yg1ToD
         Fy8XS/9r30ydiLUKjqBNf2UfNJdgqMPlrrXX7SlR9W5Uch+AjrqWSCfFFG/sKb+8wHzs
         EHdUFcZsPYPi4w/5W6HYEiTS9KXzHlKlsmxBrChGKjEPQ36HaPL+SZkZrHpGXZptY40B
         Hm1hYOxeoV1T95b3p9BdLyZWePIHWGWRLl2RYXtfGxXpFuEdwVSz5X/NaDML6i/uwV+X
         tX0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712171404; x=1712776204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zw1lM6UrltfK++zsbTUyYD3r0NWCOuZkBU3l0c5u6iA=;
        b=o9m3fvJpaq4uD1GcLhDP6U2fXJactwISLIC7Mbrsq4RiHthpEUCeUXJUkD7jqSrbcR
         bC2FhqnXRdICO2pY7iYn2AztBODXBldlh7AopWia/G/G4M1poGuYqI0WQdT9GbkGNuMt
         PIPOWB/QQOxmnDduYke5TaRnpvTsymO7qWMPCow5avWDdfaArhu0qdsQH0Ax34dgCFx1
         7ZtqTOx+vurgAdhDqYuZ0aQTjpLXqH7rRmCisYXPy5AUjlBzt8uJXtX8IZU9zIoLRZOn
         x72ehzUWazSLtb9VjgVH1v47YkmLlhZNh1eEzjEuaUDWrWgXqx0uvRTW402aV5J5Z2ME
         NabA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVah/d5Hn+ZAiWl//cTsHZAVzpjWrKOsva848BC6XeC95rleR9CIGo3omY2WWmDzFVyBihQfib76xEMbbP36w/slYnDKGvKlA==
X-Gm-Message-State: AOJu0YwRE3Fpm21/8bsI99tbcsrHQW6cVxPUKollYmd2rDxf84YncL/x
	MEYI5KW1yZxfBttfZAxB0pRovepy026wTj0ep1aNMmKPBBMeuFcN
X-Google-Smtp-Source: AGHT+IHodIsjdQyZhjMQViLDBuBIMe6u6MQQQHpow/QHcQSlVT+aepweILO1yM4MZVYoDC7PdnBrWg==
X-Received: by 2002:adf:b309:0:b0:341:db6c:1eec with SMTP id j9-20020adfb309000000b00341db6c1eecmr308704wrd.0.1712171403258;
        Wed, 03 Apr 2024 12:10:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e702:0:b0:343:a70e:dfbc with SMTP id c2-20020adfe702000000b00343a70edfbcls82644wrm.2.-pod-prod-08-eu;
 Wed, 03 Apr 2024 12:10:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz0vzDdjxULFbC9BbP9q/6xrH+YABjxVS9dlxqULGCIT4LLr9eqcMYKSe+uWnzsj2uyzMc8PeNOgMScl7VKIhjoYWXFN+Hk6Ehtw==
X-Received: by 2002:adf:fac6:0:b0:33d:d7be:3bec with SMTP id a6-20020adffac6000000b0033dd7be3becmr288873wrs.58.1712171401260;
        Wed, 03 Apr 2024 12:10:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712171401; cv=none;
        d=google.com; s=arc-20160816;
        b=CwYpDzKf8Tc7VEggUedAH94O6nG4O9lu6T3jzqI2NUfgyqL5o5gKrBQ+jcKBQCaKHJ
         A5lh5RS1+FkBaIGa05gSdeYtwVTYHeJmhrozIpn9lHedw9YPW+SYPiseenW7rAMr1rJE
         1Nq+oqT2wmR7IdGCcKyiC8NCcVUtAF8/jUB3ObXPKFzG10xPKEi4WAZR0sZ37ctu5rge
         mwvR/VT9wuVD16JSBv+drF3mdOncL/m1xtevx5IQFdoCdb5yTIAkj9TotAaPgjXUAs2E
         jx3RYIm43UTmr4RhAUHX6u5zkv5BVzKmUyWNTB1/6LI9i/TAbAU6gLyaSHKyohHteXs4
         PtEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=pzIK4B66bc749NQfKqD2bPVYkt2kauVqKBN7X+SGq3E=;
        fh=G67xwWJgg4YQhqnTeUhp4AIhy/KgFs0OqB6nXUYmW+Q=;
        b=qeU3CuB9BJwmBIA8BCtch9jspqzOQ7JgDfxO5xxJZCfo5SQvwbPW6yvkvl5qRKdjmS
         Tzq1Pdmml+KJlHTpouVb3Pl8XOOru6cvbljyC7QLv4LdRoGfxCXyhTwvtU4SRJcOfz+4
         6U/8AzLjBgbrtVvlAKNeFU052qORdHTrB4s7JA2c6uNBnLZcFF0mpQhSx9DtKjZDaJxF
         nKEQhhpZrHBPL2J0bdmBz8s6geZkMH51JCg1u+wRB+eD9UKeEusj3CGOjM+HNv31+0TX
         Q+4m/riwieow3TB0nYHF3rRYwTwkJVV6N3Zf4g/TsDoqwtvWiUSFU13KnLSlmOT2uHJW
         JBOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=xShiaKJt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=yQTIGrSR;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id v11-20020adfedcb000000b00343b2a78b5fsi13353wro.0.2024.04.03.12.10.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 12:10:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: John Stultz <jstultz@google.com>
Cc: Oleg Nesterov <oleg@redhat.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
Date: Wed, 03 Apr 2024 21:09:59 +0200
Message-ID: <87o7aqb6uw.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=xShiaKJt;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=yQTIGrSR;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Apr 03 2024 at 11:16, John Stultz wrote:
> On Wed, Apr 3, 2024 at 9:32=E2=80=AFAM Thomas Gleixner <tglx@linutronix.d=
e> wrote:
> Thanks for this, Thomas!
>
> Just FYI: testing with 6.1, the test no longer hangs, but I don't see
> the SKIP behavior. It just fails:
> not ok 6 check signal distribution
> # Totals: pass:5 fail:1 xfail:0 xpass:0 skip:0 error:0
>
> I've not had time yet to dig into what's going on, but let me know if
> you need any further details.

That's weird. I ran it on my laptop with 6.1.y ...

What kind of machine is that?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87o7aqb6uw.ffs%40tglx.
