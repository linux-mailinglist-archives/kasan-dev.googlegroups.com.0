Return-Path: <kasan-dev+bncBCMIZB7QWENRBGWZ6SBQMGQE36AHV3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F702363C27
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 09:09:16 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id u28-20020a67d11c0000b02901ff2b687065sf3527802vsi.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 00:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618816155; cv=pass;
        d=google.com; s=arc-20160816;
        b=mpA7lh+rFe7Pow6+Ye1VBGiV3xqFKjnCVS4rapE0Fy37z4c8RxPqM/1kJrpgSkDspT
         WmOM7j9/0jwfenGRczQCCl7u8vy3XWr6/bTXgB3ltRuViPdRxsgPfhbZ5nFwI7ZsNb/0
         8AJZGnZS0lTrqJPSmirjI9/P4MjNDuOIIypSKWlAUKzA9okS8niBPQEkvU+VNch+JLvg
         1EdpmtYFjLUuKjGUDeXu38WLLuxjdLC83xEG6PK9ZBmVrkI5qW7EXBlCByuzs95BzIQw
         OTOem55qYdiEronwTJjSqTelsfiJzwSfYobA8XtToVAOELl/Ej8p9jlThyuL8nUAhBLH
         OqlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cBp+wqFwtBhBHFU5yBpCa9NChxuTrXzZH2KC0UEuzgY=;
        b=m7ojjlujsG9U0hdOW6mRLFcaWojHCcsVMJiw5wWfAmDYhwrHOwolr1l1lQ45kchp85
         pp1mdVaMcBtlqZdMyI61fKwVp8EGBERyhBAViUjEBCv6/bC6dSXmShgVpKBcpt9gTkzt
         n1H1+KhKFkYgoLHWpNdtJgY6XVOqYUcrPpV8v98dGbXlGO9xgbm3QvHpN81zyLicg9c4
         UU49oQsSOHnEEshltSOguHAdjaQJ0XFDK9n7GGIxxC631BOcIJDtKM7SWyYEJph1ZxzQ
         Ok1pmcx8kmxKOB8ktYipp2oOrd10CuZPOd5ixGtoxRbiXdqoq8UtM1lg4ltwPIeTLRRY
         h1Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QXxTf+M4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cBp+wqFwtBhBHFU5yBpCa9NChxuTrXzZH2KC0UEuzgY=;
        b=odDIH4YAWlaYLrMTrZjGkQsJlzbAV04djuygSDvRD0MDUqtGI71lIIz/j3qXHudzR6
         LJXmJc8+X3jIpT1xOphqSJNlNHEwcctQzZl2LOhV6sQUFI/i56OTxzlEBnJ7g2VyW/jw
         O8NbQ1ImkfrrwttdzaCgOkObSEHeZrccqG2NnKvZQrlQ7ZqRqj9pU2rpWTn0IPM9XpRt
         huy6vR0vTQWPm84mJnXPOJ5ckPq8RE/1qEnNaVUQZgHEO3e5bMwMopOsyWGyKwqpvItN
         sIDBhpkRFUgpZc/VB/bFsB/wvzttF52apxBUzJKx7JXfiRTHHKcX5X5QaNLdk9M2TVTg
         XDCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cBp+wqFwtBhBHFU5yBpCa9NChxuTrXzZH2KC0UEuzgY=;
        b=evG0KPVJwj+xPDP1CIkzX0eXxw/jPmQtjkIhA8ffQk/b8eTpOHUhNiWnzucxM2s2iH
         kRVeGYejwA52ZRscvg69YN6iD4iNsr4OU++fUftrgIfeq2gl17QCyWnQ9aVMitsNG3H6
         1ZmVzbF99H+tLv4feswRXIR7k1p6REt4R+uAfEOJ9dc2s9nZ+wAKZJmk4PRRfg5Gj5hY
         tLzlD72nHmfUIdFdoQcCcwvR4ouGo6KaVCwju1hOyXJZlQjli1SQunsFZHQAHUF3Qum4
         R19h19frAA7cxr60vkUiM1OGOT7XzCPsnM2GC5mtklzrpuKpv33KL5H9lDw/gsZjjQxW
         mjjA==
X-Gm-Message-State: AOAM530m9zvEyF9Uw4vDyNZCMYwl/GM+wYhcrgXMKpQFOcjcY1MOMC9o
	KeMzjpQvMCMD+C9ilTp5AdA=
X-Google-Smtp-Source: ABdhPJz8qfjdlB7IgACyT7hTDRl4S1UcSG8UenkmZI8ciOxv9F9IyRFrvvcrBl48y1gy2+hTsaboYw==
X-Received: by 2002:a1f:1c09:: with SMTP id c9mr13721136vkc.16.1618816155069;
        Mon, 19 Apr 2021 00:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9985:: with SMTP id b127ls1150669vke.4.gmail; Mon, 19
 Apr 2021 00:09:14 -0700 (PDT)
X-Received: by 2002:a1f:aac2:: with SMTP id t185mr13320930vke.1.1618816154624;
        Mon, 19 Apr 2021 00:09:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618816154; cv=none;
        d=google.com; s=arc-20160816;
        b=wiDqyHdUp0CaoSNtkv9stkYP2E9XseyUb/HdHMoNTdEhWuFfYTp7AU4zRykDgd+KnE
         1SmA/n4M14Ecps6o3AH0q38CL0vNZXZhDIzvdqIeNg7G1zbGyK95SPh6bEyIWftMWmsU
         v9/WEs4IL5V7jDnIMcJwh76dYHU71mQOdhlcQCg6QzTUYcyDzKnTOu35vhRNggjq8ztH
         /mZcveVzcxJEL4KIxte7tmoR/bEhA9DGxdGsmYWiEfwYqqwmGXSaZxKAY9Aum0vDevRb
         mZW0ioWHNqyF9TroxQuL8GZEP7mPsPfVF83Yd8GihVUQH6i2EAzJrJLIHviv6UsUZOq3
         a8mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xTzkGRSxH4kMDOtlC/eyhWFQgEW18AARUjDrJR37zfs=;
        b=u0heqkMl262XI3MIxLb4uAYxlHA2CpSMlYA2gcgP/pFBW9TMfcPxOEFlubHoYUh6fV
         Ky16YQGwW2ArUowpSjsztDUDMm6aTf24TXRyyjS/Gr5JP9iVGlY/c6Hno4Up6oess3JZ
         0H31HZmJ/RX7mo+SKcTawxgRMihqap5ppn2ir0ObSKp00yRoMteKbRx+hz5cpBJKWV6E
         HSbHYeCdIc458bPu3TAAwd776TjKqMB7D6Tz1ZEbPXaKszxw4Hmb26TPmlc3FelDsT9a
         et6ddPDk1hxmiKCxIuUPSeTzPgqUHBT8Xf53Ttqjb3rKwM8eOEFEBsgbeDQxBELQ1YVQ
         bgdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QXxTf+M4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id h7si1218472uad.1.2021.04.19.00.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 00:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id v7so6786416qkj.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 00:09:14 -0700 (PDT)
X-Received: by 2002:a37:a854:: with SMTP id r81mr9571839qke.350.1618816154092;
 Mon, 19 Apr 2021 00:09:14 -0700 (PDT)
MIME-Version: 1.0
References: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com>
 <CACT4Y+ZHyat_KE+yQ5z7xpF+RfW39tbpYS6t=9A82dvbZcuuKQ@mail.gmail.com> <CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T+r4OQ@mail.gmail.com>
In-Reply-To: <CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T+r4OQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Apr 2021 09:09:03 +0200
Message-ID: <CACT4Y+Z-YdwcML7+JVOWNQ=38MqRzGkS47hKo4Qhqt6t7ZGHyQ@mail.gmail.com>
Subject: Re: Regarding using the KASAN for other OS Kernel testing other that LInux
To: Tareq Nazir <tareq97@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QXxTf+M4;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
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

On Sat, Apr 17, 2021 at 10:27 PM Tareq Nazir <tareq97@gmail.com> wrote:
>
> Dear Dmitry Vyukov,
>
> Thanks for the reply,
>
> I have few questions as listed below
>
> 1 ) I would like to know if there is any open source repo that has adapte=
d KASAN for running it on the BSDs or Fuchsia kernels.

There should be. BSDs and Fuchsia are open-source. I don't have links
ready. But it should be possible to find.

> 2) Oh so what I was able to understand from your statement was the curren=
t implementation of KASAN is only specific to Linux kernel but it can be ad=
apted to other kernels as well. It is the same analogy as implementing Amer=
ican Fuzzy lop fuzzer for running its new language programs. Just let me kn=
ow if I am right on this or not?

In some sense, yes.
KASAN itself is a port of the user-space ASAN, which is ported to
multiple operating systems.

> Thanks and Regards
> Tareq Mohammed Nazir
>
> On Sat, Apr 17, 2021 at 12:28 PM Dmitry Vyukov <dvyukov@google.com> wrote=
:
>>
>> On Fri, Apr 16, 2021 at 9:50 PM Tareq Nazir <tareq97@gmail.com> wrote:
>> >
>> > Hi,
>> >
>> > Would like to know if I can use KASAN to find bugs of other open sourc=
e Real time operating systems other than linux kernels.
>>
>> Hi Tareq,
>>
>> The Linux KASAN itself is part of the Linux kernel codebase and is
>> highly integrated into the code base, it's not separate and something
>> directly reusable. Think of, say, Linux TCP/IP stack implementation.
>> However, the idea, algorithm and compiler instrumentation is perfectly
>> reusable and KASAN is ported to several BSDs and Fuchsia kernels at
>> least.
>
>
>
> --
> Thanks and Regards,
>
> Tareq Mohammed Nazir
> tareq97@gmail.com
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZ-YdwcML7%2BJVOWNQ%3D38MqRzGkS47hKo4Qhqt6t7ZGHyQ%40mail.=
gmail.com.
