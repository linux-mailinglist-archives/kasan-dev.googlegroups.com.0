Return-Path: <kasan-dev+bncBCMIZB7QWENRB2E3TX7AKGQEPBNQKUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C0352CB69A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 09:18:49 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id w2sf369605ooo.12
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 00:18:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606897128; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUrLSwVUes9Z/+4Ugq4KHCmzGofsmrLBtuRBPo9rm4PczWEEqlQb31G0xjUiVor+Jm
         5bPawlc6X80izXam7kGbma9istUYhAeYuoZ0zsNBHrDe/6MvkGG0968xQoVLIUJ35gaI
         047cvewqQqSFAtaKyBn7m5exbBio9CxM1SRkqjq/cGVs9B51hJiTju3CbrNpiV4SlGug
         45bA4qKUmxPnEkHQQas7suNDwNr8Yq8eSD5CdW0wFjDYrIkPNUiewK/Oosx2SYWOjg13
         FkExxXhl5EBLin2sH93+SUOVXfGujlWHeaVg+EBhx3fP6coeKa0yqPqR5MGo0jZ4pSOw
         sAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FYVMVA2c/pST++FQhONg2QlAP7tryT5n3FJr1DfkoCU=;
        b=AuW82enIgqnwOEBBR9b5G05mjenrvjr6BYXiPAyal8oxTtV+cGj32DNsN1yJJ0demL
         PaKvz9MVvDeR6s+pGsRrk0IsSQbbtcmnPaptgXyXv/zJtkKwTlpV8B1NQfTaIo1M2wwD
         vrBC5p4wKT3m8k4lIOphcSoicvP+oEghwjy5z5pnfvK3EqAYpjJT5DyOWjtwNXADdfx+
         aPM4qNLy5vEHnjLmIB+DzLZi8FlwEzO38WRBzsrdYk8hjKF6e4bMtOi/d9kApHJCO7Gu
         RSC49EdmMAEeWumeQa/K6Sejb4wHdbqku4U/5jA+x1+6IrlDH9zxnv+tI+isk+PLJU9s
         DpvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tC4I2zix;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FYVMVA2c/pST++FQhONg2QlAP7tryT5n3FJr1DfkoCU=;
        b=a7DvZ3RKk6vOnFDbJr0uewa1cKSYC9CsBx4Q1Rxb20Z2z1+6H42tjNdzZ2DMU/jdzT
         gbEFrnRDAG0J0yyJ44C0ikjdiPsa/CQFxgkTKTTjpPFlJo644LnkCYqdNfs3R4Wc6V2j
         SeDO1ePRHulA15Xic5pkoaI/V1jcruGCvPYRUNWCt6cC60r/9pdQmCGmivOeGbhkzQuz
         o0eIJQKZg1eWtL5QXT1PXrCgADr3p0Ko1hBX7ahUTDu3d//w6Nb4OO+OnSqvQu4Wtrkf
         ql5owcyiZuiyCoR6gW5KPQCeQB5B8l9j6vfcbEOVMQy4Y8/KibjjwQcvLt4uLRDE1PMr
         8EEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FYVMVA2c/pST++FQhONg2QlAP7tryT5n3FJr1DfkoCU=;
        b=VucO8eQntSconLS7Gp5VPYOLJQK2+Cc/YhzdpeRV2+EVS+WvfrsfVj6/UyCuldREUt
         5ws3pK12AOWSOct/knQR4xe2thLZDhaWMnkoYi7xGL6hQMAgbUdkr0ITroVJhqu8I/I2
         VhBts3I7ZnoKXPupVahAq+5XtgpeRPH2xcQUUHmipoKSOX4oBqCaa8RgdjMSrVLdqsWa
         wLL1dwsKuqpg1IrY4olcY3UKe27TxpLpvMZ/F1FQQnhYSKeIl9XZdKs4yge3RJJ044f3
         RVEg80wz3FcKD3+ZhNhfa6y1dUN4qihmwICrr51Xj4u+1M8H05ryxDlt8VNCfF7249x6
         jxag==
X-Gm-Message-State: AOAM530CDala3VfmeEVmNvwih0ZSXSpJSjtkjUmB7/oyYGalkT9T5eq0
	+ld/GoDmbvfQS5nPyHIxHMM=
X-Google-Smtp-Source: ABdhPJzj2/XpyhB+/qJBXlLWzeFvBSI3gFZZGzTRWF9QKq/PfaCpOwIm1xdDdAmFeSvk71DWKQAWpA==
X-Received: by 2002:a05:6830:1494:: with SMTP id s20mr1028705otq.272.1606897128241;
        Wed, 02 Dec 2020 00:18:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd84:: with SMTP id u126ls237134oig.6.gmail; Wed, 02 Dec
 2020 00:18:48 -0800 (PST)
X-Received: by 2002:aca:bac3:: with SMTP id k186mr788009oif.93.1606897127909;
        Wed, 02 Dec 2020 00:18:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606897127; cv=none;
        d=google.com; s=arc-20160816;
        b=waWZJdiAF00lAQhO3rWEmIy1KULA+TaCJthc7jqzTso1fQUWDeWEsAxxg3riCIniu/
         TJPkO7RSDl3mgqY6swF/Rk2+Nlfq51qAHcCgf0D6G8Thlsj4HT/FmdiC9MgPsLgAeXv/
         UP1IWDwf+HyxMszL/AaRhg+knetKEXM7AR+WpSJtVXPZPHzOA3qS1V+JzYKiFE2AE8zS
         fYOK3mHPXCIUWfdAbhA1H+gNOEQNMq/qKNOVxrdfzr6JPKsC+aQDV/2j5AScGvbPXYlW
         v9IQgO9gh33hcyJZdVlgbKv5H2KmHuL7seibwf/YaI6rGMe5JhV+PVeF5JHTtluW/BYg
         kcFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BtfTfrwn1MOnpw/jSxfyCYAgx2QZltkEQEp/kmBnG2U=;
        b=Tw/WrKsK3HML3uNWB0ta8q78+VhA2/P82HFLCo+bX1UX3rr4HMIBfjnU9rrAbk+xMm
         8EOmeOnL4JIJUI/FfNeYYHjXDukIybz4jaH2EDhAtwrAWQwmXNWWByu+tUCehMcWMvst
         nq29uWgvGx+yDpdKC8Bzd6VWwTHT9013FXvU7SDqoqYpslZSaH9r5ERp1q49ENgbas6m
         vcz61jmomdjrhPsCFxOtYkaJBC52nsTgqRRr2AAYyFR94/xceTXvBba88IsmhQBLHPRp
         RV5CK3uStnJ1s0R6MESG6CGIkFUYcMkwxI2Iwsx++8BFpQV8lIAQOxndRggtQ5Mpc/d+
         UTGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tC4I2zix;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id i23si84939oto.5.2020.12.02.00.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 00:18:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id x13so319047qvk.8
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 00:18:47 -0800 (PST)
X-Received: by 2002:a05:6214:58d:: with SMTP id bx13mr1424272qvb.44.1606897127239;
 Wed, 02 Dec 2020 00:18:47 -0800 (PST)
MIME-Version: 1.0
References: <8f21ac5c-853e-47b6-a249-0e0d6473c4e5n@googlegroups.com> <CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg@mail.gmail.com>
In-Reply-To: <CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Dec 2020 09:18:35 +0100
Message-ID: <CACT4Y+YpZQ+ApRa=YF0=1hT-5d9a5gEsA7hnKKE+4HAmqYLPnA@mail.gmail.com>
Subject: Re: Is it possible to reproduce KCSAN crash reports?
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tC4I2zix;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Dec 2, 2020 at 9:09 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangabcd=
@gmail.com> wrote:
>
> +kasan-dev mailing list
>
> On Wed, Dec 2, 2020 at 4:08 PM mudongl...@gmail.com <mudongliangabcd@gmai=
l.com> wrote:
>>
>> Hi all,
>>
>> I am writing to ask the possibility to reproduce KCSAN crash reports. I =
once picked up one KCSAN crash reports and tried to reproduce the crash wit=
h logged syscall sequence. However, no matter how long I took (with thread =
mode, collide mode, repeat time on), I cannot see any crash report appear. =
So my questions come:
>>
>> 1. Is it possible to locate a PoC from the log file?
>> 2. If the answer to Question 1 is yes, is there any guidance or tricks t=
o help reproduce KCSAN crash reports?
>>
>> Thanks in advance. Looking forward to your reply.

Hi,

Frequently it's possible to local tentative reproducer from the log file, s=
ee:
https://github.com/google/syzkaller/issues/613

Then you can use syz-execprog to test these reproducers:
https://github.com/google/syzkaller/blob/master/docs/executing_syzkaller_pr=
ograms.md

See some hints on reproducing KCSAN reports here:
https://github.com/google/syzkaller/issues/1684

syz-repro utility may find the reproducer as well:
https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md
though, it may take lots of time and may arrive at a wrong reproducer.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYpZQ%2BApRa%3DYF0%3D1hT-5d9a5gEsA7hnKKE%2B4HAmqYLPnA%40m=
ail.gmail.com.
