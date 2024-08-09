Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQHI3C2QMGQE5BYKO3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55AA994D354
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 17:22:42 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2649a361ecfsf2259940fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 08:22:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723216961; cv=pass;
        d=google.com; s=arc-20160816;
        b=jWOmfuGsYQumzAyueoWxFMnHz+EvQbIp96R8kI3oKLxTNfyiFCOQYkkedF2mtpFgy0
         FIysx/R2LlV4HCZT4vIQHK1NyE+ffMU/Vw/YLUcFSZuGukn4DgI0TZQba2f6CaDwGzR7
         GrgSM30XW6bDvYhIhfF+3tGnRuMCNeS5VFu/uqxguZsaehOuIriAgkBZ7iZIW9R2z9pI
         9ZGjJUqDY/0WDWUWohUJzw+h2ri6thtIl7/C6OCbuae7wmQ7jYsgeAYpumPwoN4+XBB4
         Hi1b0ItCfBjAZ/y4m2M0Dmw8PNI93YuJFd+tkxat3YEAceOeOEsjHzQvIBK5qd3i8hhq
         S92g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X+WcmkccUW/8/ex5PrRYxHUENxa24Pwaxn6XtosN7bA=;
        fh=mn3TFY4xJfCBWl8CeCfGyG+kou719Jj/BAdF2UroODk=;
        b=w3AkWgxqTGNDrTzUFV5qZgB0BJJ3NGm9/uTmO8XAPiFjSepsb7rYhe4B9M6Q16x//l
         x9qbEzWpEaYlgEgVGlH09S7snsXaVpv/IL+C6/3Zfh4Kt7tFI1iRb2O3enu5yywNsBbe
         ck8KSIFFxUArwLfRFCw1vYxqyqUskNz5kYV2K/qwSbO0kB3AOrxtS58BYGXRbgvvEnM2
         ksrVxx/tBh0U28tKQbKwqA1BzhDHWOCmEy+Yd3dIr9kTRfSdj1/1pk+83tRLAjliSXeL
         AWWAo6xwIKzcf6QP+VfrklpwJ2HK4Jcr7xMl1T0raWlmVjvF+I1mmeOEYdDv72cHlM7O
         RLrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iyuqqY2k;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723216961; x=1723821761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X+WcmkccUW/8/ex5PrRYxHUENxa24Pwaxn6XtosN7bA=;
        b=CwklXQ92gXMsOZDANqLtCvGKznEQ7UHZXpt0EiqdrRA3PdhzeYN6s/1U11+wJW2/yj
         +XLz5EgXCu4rfRABloriHSHMbeTbrUnEopLYKEw/xB3j/5uCVlgLa9Wbg2tkOgRBJRSI
         eEApFI5tzrCu1tNvAjhjAI42WTTOWog6Rmnmxl99XHCOQrVYF1nMW+GUXkiKiyFwVdY3
         rVm+3CGBxWRodWgK3f2ftfoHqS/HW1WWjUQzlXWx/4oykxaMX07Xy671GqPi0jd2kTbQ
         6tBlWOnPmXuoHdh1rBrWh6JfagAwNo88hNL4NA3AavfgmuUUGP+0UbYIyUbn9HUe1Wxx
         EguA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723216961; x=1723821761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X+WcmkccUW/8/ex5PrRYxHUENxa24Pwaxn6XtosN7bA=;
        b=oxJxdu2F+Uo4iowqovzozDWK4uXaAI55qGejLs+tpSOa7OJG5xpkdbNXkPpy3cQK0k
         2if/LST3E5bnniRj19pIdJmdkMGWzh0YXX64SzrhaSynjkgXLdRPpP7nQXuCshHqm8lP
         pxAzEmF+plIqyk9QJ+kGZ6DpwUgjT7PWzjghqF2k5QbiAqjDyARGGxpsExNidM/JgiqC
         9WVQ3+ZBn03x7Ryd303xkKREuFLQuVYXmZHYvPfzrJYhrzWIYEh0O228g4LHcD41qj4N
         O3+I6fh0LvELvuhP125pgRZ/WuFjPtQFcp1el+z1YzHK4I54XC7AEXUlAFmN4HpXS+Y2
         sq/Q==
X-Forwarded-Encrypted: i=2; AJvYcCUhIuyIaqaL1MgjiX3FsJ+b1lgOgj0mNuVBX7z/JiQFQ/AoW+00NI4aQ3XBaSqHFYLe9rof84g2Mr0PYVn463pFldZc+fywnA==
X-Gm-Message-State: AOJu0YxNwl9zUOJuHlkQsZYxho2ajeuAeccs2Mi/rg8NEum1TTz9yQft
	V3nWAx1jegQqYI3PJ+o46EvNzEVDWkZr9ngapZguiI6CELajG6d6
X-Google-Smtp-Source: AGHT+IG5v66A0tYMI34EZ9qv1PbTgFhxhFFcfQHgBSEACDa5JNEPRLq54aam4/rskOKJ09cDO6kxlA==
X-Received: by 2002:a05:6871:5213:b0:25d:7d7d:c96a with SMTP id 586e51a60fabf-26c64530fdcmr815234fac.16.1723216961068;
        Fri, 09 Aug 2024 08:22:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7819:b0:24f:f6d5:2d15 with SMTP id
 586e51a60fabf-26925078de1ls1004120fac.0.-pod-prod-00-us; Fri, 09 Aug 2024
 08:22:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3eTMO5p6gYdR2EhfkNh57tm5SF1tW1iWiOnO5aSQZzG2Ee14nua8f6hsmhgshVJLvO4HWLtJKURQ6ix9WWnbVUyguWYi96xuMcA==
X-Received: by 2002:a05:6870:1ce:b0:25e:bc61:6f49 with SMTP id 586e51a60fabf-2692d438040mr2357776fac.19.1723216960371;
        Fri, 09 Aug 2024 08:22:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723216960; cv=none;
        d=google.com; s=arc-20160816;
        b=XZpQ23jMGe1U7jZ0g3JOjSTAZDRl5Dx/A2t41T9KQMMhqcmNvDGIJwCV8X0QWnEJIk
         nJM2t38bTPchglSpvLEbXLHCFdHF8C1XiNbN9Yiv0rI1zyb1GmKbauiG1LumMS7baKlY
         fpzFUvXLFB3o03tJj6aqod9wtkUbfYMfTYbCPejG41akdxTZkHxlJe+0oFT9PVtlKzRj
         x4FOlohjxxMJ2gYSfewMJhLtt/V/qIfm8jBr4UgA5IEQ1GzU3zP7HiVoxjZuiwOOfJ/v
         tq4m63DsVhGQa4gnpMFHnVKCluem6H9zE71y6huOP7FosnbmAhKzL5wxA6nKDi4lvzu7
         I4NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I9JBh8Nx6R1OMk1r9f3wJyh5ZFLMFcAl4c+4i4VGcvY=;
        fh=SFGHs9+NqZpZCIbo1+Uy012+Naj4bozP4H9+1L7VimY=;
        b=KYV07DA4IzjihIlajVvGxh3ae1PBODR5VSHZ5Ye4gK/oCHXjemY21oXrECgkGb8qTP
         +BYZSsjUmSdwGASw+4+3zrn5cjtTB1MjOJ7UkgDLR6ytn9SL8XZcHP1p/jddwXmXGOKr
         0czeqGcQ7arCkx0l+5FCqhFv1LkwkJmFP+Jiw0WgW7VH4sReFdHUNWcfuV9Rt/u5B3aA
         A0i8mx6i8b638urBhBHNBNHxDQnh8J2mkWhvvJiq/b2/2kzWl0LQHYnvk9Wu3RXlW1JX
         A8lYPko/ldLgbgfvS0Sn+BrN0WRtwgX6Z9jHqb5bmDeJtggIQTpiCERv9dGIMpb+WK9S
         0Ixg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iyuqqY2k;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2689a6326c7si787939fac.3.2024.08.09.08.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 08:22:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-45007373217so26898741cf.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 08:22:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfNzqoitjFHRPgl4DepsrNbJnjApsBdbrj9nJJz8AsV9gez6ScviypcKjAQj3i8cBYI5Ci1StK1UwVI2yPA5lnOsW3V6DtIhc52A==
X-Received: by 2002:a05:6214:5c02:b0:6b5:8015:d72d with SMTP id
 6a1803df08f44-6bd79b4b3f0mr27122676d6.8.1723216959717; Fri, 09 Aug 2024
 08:22:39 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240729022316.92219-1-andrey.konovalov@linux.dev>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Aug 2024 17:22:00 +0200
Message-ID: <CAG_fn=Uafd4y9eetxBKWWROpSdDYWTOpjhOsCU4ZVf2Z1LvvVA@mail.gmail.com>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
To: andrey.konovalov@linux.dev
Cc: Alan Stern <stern@rowland.harvard.edu>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marcello Sylvester Bauer <sylv@sylv.io>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, linux-usb@vger.kernel.org, 
	linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com, stable@vger.kernel.org, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iyuqqY2k;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jul 29, 2024 at 4:23=E2=80=AFAM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Commit a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer
> scheduler") switched dummy_hcd to use hrtimer and made the timer's
> callback be executed in the hardirq context.
>
> With that change, __usb_hcd_giveback_urb now gets executed in the hardirq
> context, which causes problems for KCOV and KMSAN.
>
> One problem is that KCOV now is unable to collect coverage from
> the USB code that gets executed from the dummy_hcd's timer callback,
> as KCOV cannot collect coverage in the hardirq context.
>
> Another problem is that the dummy_hcd hrtimer might get triggered in the
> middle of a softirq with KCOV remote coverage collection enabled, and tha=
t
> causes a WARNING in KCOV, as reported by syzbot. (I sent a separate patch
> to shut down this WARNING, but that doesn't fix the other two issues.)
>
> Finally, KMSAN appears to ignore tracking memory copying operations
> that happen in the hardirq context, which causes false positive
> kernel-infoleaks, as reported by syzbot.

Hi Andrey,

FWIW this problem is tracked as
https://github.com/google/kmsan/issues/92, I'll try to revisit it in
September.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUafd4y9eetxBKWWROpSdDYWTOpjhOsCU4ZVf2Z1LvvVA%40mail.gmai=
l.com.
