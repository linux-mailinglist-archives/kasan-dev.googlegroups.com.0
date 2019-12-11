Return-Path: <kasan-dev+bncBD42DY67RYARBWOLYTXQKGQEDUK7UVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C11D11BA19
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 18:22:35 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id l3sf6333689uan.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 09:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576084954; cv=pass;
        d=google.com; s=arc-20160816;
        b=St6Q7cPlkIbpbP0hz/ivIIcrjx/TxYpBnqdxrsmqHYoWJb9yet3HjyFsRjTp3CgTfs
         CIwZ4R7TGXoSQZgWt1Dv8It/dDksMjWIsfCuZpDO7gW6YjIaABbMwqMZ8TN+9lp67Ds+
         E7oiWp691rFWZHSYKubjIhKrj6gLEeTCHh0UFHYEYBZIrnX1CyCp54nJwbjiwK81AJ8w
         QuhYiCHH/NSn5BUjQC7QW9OqJDpD6HCK5jipVVGdsGERNiLu03/D72G9pP0dV1I6uMQn
         BG3xPTbnRLw/2DLHpMBg37nA4Yq/UORNtbtszE+HCcqMKOwtxWNF+vEE0JVoSL66IGsA
         SMRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=MwYutoKpoBZaY2uiWYgHHD0+grfW3SfPva5ZJsUDuQE=;
        b=pitIePx/K/ZW6NZnJ7ezKDmmwRANrhyhfrLzydiGYDGKIAc2znJthqkkdJ0r5jH565
         cAr3sJCEnSvqU61gWONY+m2gDUVm2ycEOCXdUvnU50Hdd7kYMQmmOjMvDnqY0KMF7Kkz
         D+t4bPGJNNlM693qtCsB7ElKs92mcLaK9yXJKa1PVCdjdQdDtkZhNs4F5FTVcqzDVmUq
         4NAj7MgLFpY39H4jLkPJza3IevAgnQYL3s3WAJQmIocR7VdnpvVyAzL9KnU9mtC+PS1e
         kUOCobb3leZJxjplENxRiJJFAay9lNqw4pyeEo4Vm/sLrRE57GUu/TrF4gDCuNFxyNxa
         iy+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=PbO4pb1g;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MwYutoKpoBZaY2uiWYgHHD0+grfW3SfPva5ZJsUDuQE=;
        b=hzS3RZhSLATDJPrQ8ajwFFbVwt5xXtLRHlS+EMxoXJx65wVSfpZCq+vZLAas2xCym7
         nmHXdARepnUmJWyd9zNHP0Yymr8UVDd7nkA6ElW5evD7Qgi3gOUkHpvyVXvy4e8gvGGn
         HKKe9E4asgG68fuRHSMVDXr+KNHc3a+OYzgD7AeRnSQrn4GTi6RUOEQKe5ojUfHz+XXu
         rqiIecP7dYtIlTLUiBlqQuHegEffKVfL6P4qGjGK3lPkRQ9eh7/w8yBL8dTn7XVXyqd5
         QgzOLt8E8pTYHWIaY1MGgXapkgEno8cBhJ317yOKpqMKpDOqwRRaRKxCB8QImzKvUJAJ
         7/HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MwYutoKpoBZaY2uiWYgHHD0+grfW3SfPva5ZJsUDuQE=;
        b=FP9jhZ/FCDm2OM7tMXfgsi2xuFegeR2+Sx78HweTCFJIuc1RgUvowUkl54ZnqD3h8g
         h3nlo0ezOzn27vwRq8PFudBdWMiPvEUklHyHs2nFmjYDMLOnkaXtEDIBb/cW6wBuvh0p
         dZPaVVeJcFEFtf7N6jUXi4BY84FR/Lr9VVuLsIblRTwY9PQXJVMfzzF/7CZwm0syN5c4
         nKkb+eHA4nX176JN9a7PiFskD38JASpPVOI18Km1HVyuH8kGuFyun3gucmzsO1G9iE24
         /L/bB+TZdhQdiu0u+q5uQp0GznuHnBPBe4RE0KWbAa0vs4jaSuImAMY+TIcqUKvWMLYn
         fZ0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX6fDFougWjfa+ho8KvhxFUbBE1eWHscJtEhrJw1/pVW6iEDKu+
	AJQLzZm+cDHMuGWMdka9N9Y=
X-Google-Smtp-Source: APXvYqxIypIYmmRsSLzZJ1iSrDUrRd6ldxVFdHnTdPu0Cu7+pP6Lnzu8IQPBmqSw0hBQr52YKySLlw==
X-Received: by 2002:ab0:1c3:: with SMTP id 61mr4189195ual.80.1576084953827;
        Wed, 11 Dec 2019 09:22:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3752:: with SMTP id a18ls221952uae.7.gmail; Wed, 11 Dec
 2019 09:22:33 -0800 (PST)
X-Received: by 2002:ab0:266:: with SMTP id 93mr4164554uas.58.1576084953407;
        Wed, 11 Dec 2019 09:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576084953; cv=none;
        d=google.com; s=arc-20160816;
        b=TNr6l2B6I3MZRI9g5u8BAEwVvSLQxsOJvAvFIOShvQONfBzQvJyP+yr3w33OFFPKd0
         9mbEBz+npHPB3peZlCKdSKiXrzSpJaLPlO7+3CfodNJGOcJkH8CgvlpIz+8yillkYzf1
         k9s+iBQP5pjuA2A5wf5+ncfjYbbAdLRgxZQV1h80/L3IpTTLDbG4wrNv0PhjnLrzEzBG
         BlVknsgY2gNevWqySNYci6+gEmVR2FkntQryF2MTL61217IOIgM89gGJQ3tbINuqo/V5
         JlEktavjDMo6EQF+ZDPNlim4tC6urZtWg4cLNaAmvf8+0vXMdRfIgDMwdTMBXdE6G/C8
         3SSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=spw+W66PwysKgYjLUTMzmWWpPtpOjK/KGVzC9TUKzdw=;
        b=km2fTNJ46s38HBrc6waJmLXes3MaGTj89Dizhzb7pzeQMOrrzCuralE9u2iYNvWWUt
         14KiLTB3heoezydHrqPh07a/jlgg3jmi5zQX/A1Kd7hxOw9Tqf71kX13Yb8vcyTIRKvt
         VXhlGsMoOhtC4dP4vCqv42pQy5cuBmmJYHgtx2dVIkz5AxyJkOpC7RagNU7VaqYgMwPg
         UwBqEZSBuhEccCEIXJnbnonpgyhEfB5Pcfy1J9X4RYILCfzXL2CCaYOsEMye0LnCm4Ql
         Nd11lx0lt8aLJE3JZ1s94ldA5I92n9nsiIL3JB1oZng/YLF2cyml0NEKOS6kH3wIy/NG
         BciQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=PbO4pb1g;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id n13si62370vsm.0.2019.12.11.09.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 09:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id x8so11071896pgk.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 09:22:33 -0800 (PST)
X-Received: by 2002:a05:6a00:9c:: with SMTP id c28mr4977641pfj.234.1576084952380;
        Wed, 11 Dec 2019 09:22:32 -0800 (PST)
Received: from ?IPv6:2600:1010:b005:489c:fc8f:334b:9230:8615? ([2600:1010:b005:489c:fc8f:334b:9230:8615])
        by smtp.gmail.com with ESMTPSA id y29sm3742573pfo.155.2019.12.11.09.22.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 09:22:31 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Andy Lutomirski <luto@amacapital.net>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
Date: Wed, 11 Dec 2019 09:22:30 -0800
Message-Id: <BC48F4AD-8330-4ED6-8BE8-254C835506A5@amacapital.net>
References: <20191211170632.GD14821@zn.tnic>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
 x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>,
 Sean Christopherson <sean.j.christopherson@intel.com>
In-Reply-To: <20191211170632.GD14821@zn.tnic>
To: Borislav Petkov <bp@alien8.de>
X-Mailer: iPhone Mail (17A878)
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=PbO4pb1g;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=luto@amacapital.net
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



> On Dec 11, 2019, at 9:06 AM, Borislav Petkov <bp@alien8.de> wrote:
>=20
> =EF=BB=BFOn Mon, Dec 09, 2019 at 03:31:18PM +0100, Jann Horn wrote:
>>    I have already sent a patch to syzkaller that relaxes their parsing o=
f GPF
>>    messages (https://github.com/google/syzkaller/commit/432c7650) such t=
hat
>>    changes like the one in this patch don't break it.
>>    That patch has already made its way into syzbot's syzkaller instances
>>    according to <https://syzkaller.appspot.com/upstream>.
>=20
> Ok, cool.
>=20
> I still think we should do the oops number marking, though, as it has
> more benefits than just syzkaller scanning for it. The first oops has alw=
ays
> been of crucial importance so having the number in there:
>=20
> [    2.542218] [1] general protection fault while derefing a non-canonica=
l address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
>        ^
>=20
> would make eyeballing oopses even easier. Basically the same reason why
> you're doing this enhancement. :)
>=20

Could we spare a few extra bytes to make this more readable?  I can never k=
eep track of which number is the oops count, which is the cpu, and which is=
 the error code.  How about:

OOPS 1: general protection blah blah blah (CPU 0)

and put in the next couple lines =E2=80=9C#GP(0)=E2=80=9D.

> So let me know if you don't have time to do it or you don't care about
> it etc, and I'll have a look. Independent of those patches, of course -
> those look good so far.
>=20
> Thx.
>=20
> --=20
> Regards/Gruss,
>    Boris.
>=20
> https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/BC48F4AD-8330-4ED6-8BE8-254C835506A5%40amacapital.net.
