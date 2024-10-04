Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAM5763QMGQEW5ZKXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id D1CED9901E9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 13:16:19 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2e18d5b9a25sf2617625a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 04:16:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728040578; cv=pass;
        d=google.com; s=arc-20240605;
        b=EXtjdLC451doavPkDTHlFODIyDQzDhdvkMxF0Tujp2ZbgrpqlgSmKQ4nbZyldq+Jes
         O+jANNKiPHZXwXG4m+GOHI8E1dM/Ry8AuGAJmp4zWSfOrlFRtcSTVTV0uBEohpSaL5F2
         cZblrOEASY6po7Ilpn74yeBBvN7L7ORXU/98ZSdB0hkCPp02aMei4Wpj1dfr/h4uXBNw
         A/tmqVKv1+nsWgj069DDH9RSSzgeCdQoMdYVpNl/6OMaZ1FAjWiEyfyX6U4/4bojMTjc
         Esyieor4GrVpudv2hNsK0LLQF42M48kyFmwJg799kddNqkPP4pV+qLLuyQd8+J2Mv9xY
         9++Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WGeTIxAY+njLvwUMsXNYV70K3UoOM47nlbydOhyeUHA=;
        fh=yswAgq9CWUoq4uLCevAW436u3/F6IZdt3TDdg7Y0F0Q=;
        b=eh5t61cZTPauUuFVKITCV2z4xHdQyo9/FmWcCyQJQ6F89+EFhdsc5RoyrBqpW1t7Xv
         4dpZ18KEWy9eTJoXCn6AHCQJv1jr5vgVcPfL/ydBBTQSVYy+VffSObonsGSZItTZfUHX
         7A9zA7Reidj/DtNciIUGF/gexhJFK5/6n4bVXEOEo/SMBJFqwvgkxaWM+COMK6qVam6y
         vPIL3BTdbO41tBasTxGnr1BaBgmdh4t031sGJNnGqBq6AywzGtMH9Nq8Mez8/RwRuzaq
         VvVHyQXhCzyVHhkxIoyGWCsHIcRMXAYWFQNWFKPMkZrlll+XxYE6kQhA2+akOQTE8SyZ
         bA1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A14oX+1q;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728040578; x=1728645378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WGeTIxAY+njLvwUMsXNYV70K3UoOM47nlbydOhyeUHA=;
        b=rJmXJbDG1NLDPfMO/O1TfKhgZYjjW9Gn4LESK2CCarBNEFUux/3hzFmnvT54AfU2mg
         cW34eLT31TVMzCz5cfM+YkMMw6oIuMWfX1ed+zf0iSxf8puvU1ZZAeGzmaWsykVgSzPv
         e0e3crF1YklnMd3LWp3om/dNgBhsITtIY6arzVlkngnux90ihxudZdXF/f5jqQESaEXE
         0AcMMbVvSxYJnL35677N0GBHca5VvVaVDQw2z6qfNPfI8uUFOCxnXppgpoX6GoeHVQrt
         GNy9lhw3x1xMC2OdMj6K9gBSZsBAIf/jHx0bDiVKmF5izU0dLasCkBifBo5a1/HCgiiI
         qWYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728040578; x=1728645378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WGeTIxAY+njLvwUMsXNYV70K3UoOM47nlbydOhyeUHA=;
        b=kkY42bbmguYfbqNLhUWyy34MTFKNyQ0AIus0xIKbF2v1DhoEVP3krKs+XSM8yXw3Vp
         rwr1LZZuX0udQihVcs7ddrTb5aD7CXZdW5JMy5yycTs0gh/w0ECOQKqsyp+B/OWfjC85
         gjlJagHUdRz2pQSeP+gSnSFuLlfnnvuTUFRdx8Ux5BN6vn87jWRAgGtOnB/olOE3R3ex
         FQVnLCr8pt3mX17nbOecLioZhSeHq+DHZ02NTW9iX1IyXOqE2w4RXB+XktO9XKdRN8Xk
         PlnT7hUkJC2qkhdTqrC4JH04+cxwsWPS+v1Rc8ri1Bl1OxXzlannIdrrxsSkWk9DUHWC
         jSXg==
X-Forwarded-Encrypted: i=2; AJvYcCUkiC247JKAftxzRr5AUFl/wuezEup7rrSzJaF8QpvBYF4WdGZIb4FVU5SPcHLDvrGycwVCVQ==@lfdr.de
X-Gm-Message-State: AOJu0YzTQ1p0WQALl1kW9KNGGo6hMgr6NeR1XwhXUKAk6DvTC9yD3HHK
	N4yKBleznKpgKyXm6QcCaDglgiJsXwVDEa8YkMcQsf7gW93xEpe+
X-Google-Smtp-Source: AGHT+IFTMG1nVRhuIiiuiMTdJXAf4ubfilAgAmWm6CtlagshFzeLUY4cQRSz8c4D3z/F2LYrNxYg7Q==
X-Received: by 2002:a17:90a:cb04:b0:2e0:b262:8fad with SMTP id 98e67ed59e1d1-2e1e636509fmr2886297a91.34.1728040578119;
        Fri, 04 Oct 2024 04:16:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:65c8:b0:2d8:8504:88d4 with SMTP id
 98e67ed59e1d1-2e1b3987002ls1530619a91.1.-pod-prod-08-us; Fri, 04 Oct 2024
 04:16:17 -0700 (PDT)
X-Received: by 2002:a17:90a:5511:b0:2e1:89aa:65b7 with SMTP id 98e67ed59e1d1-2e1e621d451mr3080519a91.9.1728040576968;
        Fri, 04 Oct 2024 04:16:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728040576; cv=none;
        d=google.com; s=arc-20240605;
        b=Mg89ZpK1Ys2rp9l1aYqouMnfyYOwus9IF2w0xqWHG9CNDNJqTROf9zWjLnSeYsyHtU
         PNzp08c09pin0tRixmXECP6hA54N1jmBAyswtjqJrHXzhB+hOcWsDX5t0SAO+Ep9EXfA
         kXeOHjf9i5eRvPV6SeR78EvJh1dhf4jbD+JZUP2nMCoEYFdM+uerYRw126Aitg9pjG9H
         q5ocjgUT12p2z2domV3X3/tTNev3XLfjoCQou2IDLDNrDq/aHMyIzeA+OmHCnG2d4O5m
         WONQiWcJT2KtY7W9zfBbPIrsz6APVbJG5hgP+V6nelZp8e2otLd6EsCteLyPz6mn6376
         9u/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZZ6R/lIX5+QKhtE2QZ7ScVkc64z6k/v89EPYNq8kic4=;
        fh=UAeXtNxKh0BM+AxS008YifsPDP5nTivO2JMNWVUqVnQ=;
        b=LiVa7VBBQIRejJFIp0XqH2hQc9LQHBT1p3EzsPO6dtxJWh+yAuAPkRpEiqlBp1PPTf
         lgTPVRrJ6XRkh0QEZWCl8rEg8zbsbcy7H0sa3rDUszH3k9CRvyZTpoIBUC48gSbvCYMI
         Vyf46AprLgnphZtyeXxSyb0Y7qNxwdhfQdAR+bWgxFYmPNwX+oR/ZWTX99/dbnU5fQU7
         GIgyLeoMGenQPD4Ip3cpnoI+uvxVwgJ7xI0zXpRgyxC0YZwiSF44u03LaBLM8JmXdJSb
         Jzi/oGoiPXU+KS/ZYZZYEiaCrYgA3XfEACrZ6or5VrQgL1VilWNBnbdppY3YUFil7rul
         sK7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A14oX+1q;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e1e83ca39fsi43654a91.1.2024.10.04.04.16.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2024 04:16:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-6cb2a6d3144so10268856d6.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2024 04:16:16 -0700 (PDT)
X-Received: by 2002:a05:6214:440f:b0:6cb:7ca4:a82e with SMTP id
 6a1803df08f44-6cb9a54426bmr33239566d6.50.1728040575823; Fri, 04 Oct 2024
 04:16:15 -0700 (PDT)
MIME-Version: 1.0
References: <b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn@googlegroups.com>
 <CAG_fn=UM_J6n2Rem5-kYY-Pd1FzMykVsod_heXMaw=S1o2TUSg@mail.gmail.com> <CACzwLxiD-_DqfK0ykNpGp+cRPNXS1--p1uk-TBp7kZR7574NHw@mail.gmail.com>
In-Reply-To: <CACzwLxiD-_DqfK0ykNpGp+cRPNXS1--p1uk-TBp7kZR7574NHw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2024 13:15:36 +0200
Message-ID: <CAG_fn=UzFJbkSfcJe=siXdGBmdfOKeaT-s3-EhsiQAJji1V1Hg@mail.gmail.com>
Subject: Re: booting qemu with KMSAN is stuck
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=A14oX+1q;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Fri, Oct 4, 2024 at 12:59=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
>
>
> On Fri, Oct 4, 2024, 14:11 Alexander Potapenko <glider@google.com> wrote:
>>
>> On Thu, Oct 3, 2024 at 8:05=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@g=
mail.com> wrote:
>> >
>> > Hello,
>> >
>> > I need help with the Linux boot issue with KMSAN.
>> > On x86_64 I've enabled KMSAN and KMSAN_KUNIT_TEST
>> > to work with adding kmsan check in one of kernel function.
>> >
>> > Booting is stuck after this line:
>> > "ATTENTION: KMSAN is a debugging tool! Do not use it on production mac=
hines!"
>> >
>> > I couldn't figure out the guidance myself browsing the internet
>> > or looking for the documentation:
>> > https://docs.kernel.org/dev-tools/kmsan.html
>> >
>> > Please suggest. Not sure if this is the right group to ask.
>> >
>> > Kernel config (linux-next, next-20241002 tag):
>> > https://gist.github.com/novitoll/bdad35d2d1d29d708430194930b4497b
>> Hm, interesting, I can't even build KMSAN with this config:
>>
>>   SORTTAB vmlinux
>> incomplete ORC unwind tables in file: vmlinux
>> Failed to sort kernel table
>
> Hello,
>
> I have compiled it with clang 11.
>
> make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-strip =
OBJCOPY=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-readelf HOSTCC=
=3Dclang HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld ARCH=3Dx86_64

Per KMSAN documentation
(https://www.kernel.org/doc/Documentation/dev-tools/kmsan.rst), you
need at least Clang 14 to build.
Can you please try again with a fresh compiler?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUzFJbkSfcJe%3DsiXdGBmdfOKeaT-s3-EhsiQAJji1V1Hg%40mail.gm=
ail.com.
