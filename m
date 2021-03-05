Return-Path: <kasan-dev+bncBCR5PSMFZYORBW5VRCBAMGQE35AA6HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 82A6432E769
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 12:49:48 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id n10sf2151367ybb.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 03:49:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614944987; cv=pass;
        d=google.com; s=arc-20160816;
        b=xYSiP2sKRZjhXhPlDYNhjK3DNxRNT/Eo4EjAjoZOWKErrYivwHLnj+6Rxhbq86M3k0
         CuKllPKJeF/TToI/Jw4o4oLMXiECEewYLqqbgniCd47G/MX2TiaFTe9Yb8qs3yYezSGw
         82R+iv4Smjn3+W9EmiGkoTR2+zlU41IOw14vG0mrvJCel/gMxLEV930f4dkD7PMAR/M/
         0kUlIvwNl5lXPbXqAxNmIB1oKeMpp6soKpNcOGf6PCopx9Men95xgg0YB4PiuXirvyPT
         PknEvpcJbYBEMBd9ho7XohBV5c4caeXyDh5Zycxlzsqo6Ny2GJ5obqLb7tcb9kXEoc9J
         z0wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=KBrgEygNN0KolqZze2+3682UWElQ6Bopzf0bIqYrBl4=;
        b=CxTtwynaYaR2PA3YISapw6ZRWpEgdi+z727weObNa3RTJ6f/DrIthnguOf+VprwgkH
         9SUFMKVap1ScR/v+ueH34CJo4iqOXCS2uU7wOYCURBVnzthdvCxZswMf/ujsj/4aDz6Z
         w3bENU57UPt4QSSqpxgW+xkXc5BDyUghACLGIVzyvjoNj0Xl+vWvPL778ye2LCTlUq8i
         eCMG5xk9hRcP2o7STfuzHj8rGv3Lhm0kWkpmSAkoWTHlor3A0Fq+EZb4paJ+T4VzUWyP
         BOz1Aj4kp9+yzQttgWNuxEgI1/erFqYqmqCWaRtwDXoLEusob2U8+l/xLruan3Hzbh35
         USfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=iqqfOFNX;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KBrgEygNN0KolqZze2+3682UWElQ6Bopzf0bIqYrBl4=;
        b=ke0JagX5c2LOeLplFtQnA0nlXwWRMJAViyM1z2/0GKwDp5+kw13WMykC21pSC1CONv
         RSv9h93Qv/zgoYmxnfZWYblN24xag+5tqfBXSDfMfrR9prtS8QPPeAEv/tgSk/3khQLw
         K67Gf3o4DrdK8OsCegI0TDWx+d22HN0Gz4bafiqniEC97m19yqZ2OB7/Btxa9RTmAK+p
         tVZw/X3TzQU22++1q6jAvbQWGGtHfmQxDunm4GYuv2fp3swh56qFCYzRTfrcIF49aSfG
         KYx9ZjnxRBigMsiyaARkmeJhN9EHKjTpMFJ1+IwA1Jm7T89HQ/dBQc+ickZ5l4XsBimo
         83RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KBrgEygNN0KolqZze2+3682UWElQ6Bopzf0bIqYrBl4=;
        b=SFT5TeJysIB8L6vEL39seobP9YGoQS6ZWru11YdYEQeIPACLjJJ6OgmhPnQRR3iHHA
         4yp+ivAUwiet1wuruWFDwQRoZe05TpuiHXKlW7CPsXrqI2k5cS6Q6AHTJtQF8vC9E08m
         zY7jsfELuFY5Nv4aXuMs4yVadcIPjfx9YQXs4E0V8mHK5B+PjSw0BBbSETFhqiETDv/Z
         Xp9aGM1ubhyxG5tNG3CC2O5xW9VC6J4ybNyIUiNKRofiCkRueXxx9K5qDRJSnxVb40NM
         iiXcbKXPBoM3gYhDvs8O0mk7mPbfy/CzfpgnTjgcckfn5qfheWe6NecghVPk/09605TS
         iz4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PECn6dNC0rVfMKc5We4NK5r6TwX+R/10Y1OuU+T6vReokXNyp
	CVUNH7/Av5seCYBG3XKCkDc=
X-Google-Smtp-Source: ABdhPJwWnlVMsDewtVjcOF6jXRXDn7Z4NBq93NCj9WX54obRmSLK75KhkWt5PfmgdhbGRIJezyS7tw==
X-Received: by 2002:a25:7456:: with SMTP id p83mr13469401ybc.299.1614944987579;
        Fri, 05 Mar 2021 03:49:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7343:: with SMTP id o64ls4557710ybc.8.gmail; Fri, 05 Mar
 2021 03:49:47 -0800 (PST)
X-Received: by 2002:a25:2d6a:: with SMTP id s42mr13585167ybe.376.1614944986947;
        Fri, 05 Mar 2021 03:49:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614944986; cv=none;
        d=google.com; s=arc-20160816;
        b=BBpNURG1Sz84pfzulKFXLguIKnCbICSHVjv/kYsEjXXoY7nt1Bz3aCBbjs+9ErurbN
         aFsL6fVENxwtpAQfotyBwGj56bdI7Bl7Fp+xrZyNqy10zV9dSFeFNcFvqSH2LFXzt28R
         oJ3fsubtuFITwo9NL5lVx+oORZcye9WEx7MOLV8pbP5AO+xDsQ34LECjYOdzigmJbR4u
         F5tVbnLXL5duTXBmA686ZHqxAJmOXS2nut1TaqFCuLbllBLkiZGC0uCV6gZzrmT8ZLkT
         ILmI8IEJAfJVtp6loXEj4fr5fZi/Flp/YF060H/so+WUuIftlO5PUS6/7mjQCNGJqmZN
         GtAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=MFuEr/zpCREmU8rWGDeBRzuATbhdbCM1oGMnXg6xVJA=;
        b=01JtW/1YSIK01vYrgeMrWrMZAjZl9OagLr6T7foSsz3jQOh+uJlaOSwah2iD4ktGX1
         2cxsN2/iKRHvFXJ/pib56A9T5GfnX1x0ORwvxEGzh3JMTpXpzBuqMB4Cz1bI+drPbdUW
         sY/xuXxNZ+//PHco1oyY+i17/xN1AxVMpW8qH7Ozu/n8neN+8LneB6XFYl1rIY9DXZjv
         a7OfLWNssiGC1pDzK3lyuM7F4N5Vw1QOFVNTbyhJFoLft/v38Ra9TZGG6cBS0J5rTW/f
         Uf/d/UtoE1OIfD/BO1I64xjsWKCB32podlsLhEeWYOXUutJCqAC9w559OtAQCxez+D9f
         Ucaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=iqqfOFNX;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id x23si69739ybd.1.2021.03.05.03.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Mar 2021 03:49:46 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4DsQy96jkXz9sWL;
	Fri,  5 Mar 2021 22:49:37 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Marco Elver <elver@google.com>, Christophe Leroy
 <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt
 <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Dmitry
 Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
In-Reply-To: <CANpmjNM9o1s4O4v2T9HUohPdCDJzWcaC5KDrt_7BSVdTUQWagw@mail.gmail.com>
References: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
 <YEDXJ5JNkgvDFehc@elver.google.com> <874khqry78.fsf@mpe.ellerman.id.au>
 <YEHiq1ALdPn2crvP@elver.google.com>
 <f6e47f4f-6953-6584-f023-8b9c22d6974e@csgroup.eu>
 <CANpmjNM9o1s4O4v2T9HUohPdCDJzWcaC5KDrt_7BSVdTUQWagw@mail.gmail.com>
Date: Fri, 05 Mar 2021 22:49:36 +1100
Message-ID: <87tupprfan.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=iqqfOFNX;       spf=pass
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

Marco Elver <elver@google.com> writes:
...
>
> The choice is between:
>
> 1. ARCH_FUNC_PREFIX (as a matter of fact, the ARCH_FUNC_PREFIX patch
> is already in -mm). Perhaps we could optimize it further, by checking
> ARCH_FUNC_PREFIX in buf, and advancing buf like you propose, but I'm
> not sure it's worth worrying about.
>
> 2. The dynamic solution that I proposed that does not use a hard-coded
> '.' (or some variation thereof).
>
> Please tell me which solution you prefer, 1 or 2 -- I'd like to stop
> bikeshedding here. If there's a compelling argument for hard-coding
> the '.' in non-arch code, please clarify, but otherwise I'd like to
> keep arch-specific things out of generic code.

It's your choice, I was just trying to minimise the size of the wart you
have to carry in kfence code to deal with it.

The ARCH_FUNC_PREFIX solution is fine by me.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87tupprfan.fsf%40mpe.ellerman.id.au.
