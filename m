Return-Path: <kasan-dev+bncBCMIZB7QWENRB3MZQOVAMGQE4DDQ52Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AEA037DC9D0
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Oct 2023 10:46:23 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-507cee14477sf6548546e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Oct 2023 02:46:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698745583; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGkcmoPKqHdmBdbm70yGyI/IlMlUoxttiiFZnL7Y2P8Nl3MRBqjtTQGPoe31wo981g
         0dEzuKTCD7qjot+rytaDq0XS5GQHokgZf6ST2jlhQHlll3FIQxrn06mZhFITCQJQoaYi
         LrY1S4/eW+K8YXB1Zw3Bnt/EELpMw8nLUH3Wue/NWyRsGsF+40IbLBzojnW7co0DrSMo
         WHaQ2fm7d8BVAtA10P3jE0TEFuYUY4hbpsXGxK31a9l8tOkywGc+dF7JAAhAjFwrAvSp
         Lplq9OMxi060aKUG+xNAyYLc0h6Va800RAd29LeyQjiUIIu0W+57oK1VXYo1S9bML2Pf
         hlSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wIhCHxhTQkzJTQZgUjqelK9sXdtgnQz7PkS7qvt6s3M=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=qDXoh+WC9AK4c9Yrxq/LbJ+cSVlL3N+jp14kt23ttheYaZBHZA4vAdwtdY3+k5mKrF
         5Jc3b03F5Cp85eL4rHNRUaZ+CN8+Va8AOmzxwe8bh4dQHUHu87mXXLkJ3sRBsipCTIWx
         pR3u7N4nwgwWQ/hYsQTD4X15xNobpqEcPBOCGVQ1zv1t+puF5RN2tmuwPkfVturFssoM
         XAGwbXnTJ93pOfOsOX4K0f1nnQ3pBPmaeY1bKB+sMBYVX+h+KDuhY1LBZ4hcJJjO+6mw
         FwQsDmNfKpLl0Y9SlGmLJ/eE4NqIAk+n0yGilbgPGHrRGpYTa58HdXNy6gbATUP69mdR
         hAqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eAIDSzKJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698745583; x=1699350383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wIhCHxhTQkzJTQZgUjqelK9sXdtgnQz7PkS7qvt6s3M=;
        b=gSyrdSeJbg0ItxQruzrokvnY3mBVbv6xGH/lIkgc87++ZX6wlZVaOXggy88/0bW5Kg
         bG1Fa6slgdhKvcwIDkJ+wFBbn13lujgtqdpEsAHPs7JFBLPVa3AbzzU0a421ouFbYk7d
         GEyk5s04Qf41fa+DxqVIwcfG+cRwmNn3mJxSJ9fgYNn4RdNeYj85/rpsvOQFfIKDUrCy
         WowD/oK/nsULQrjA+OoIpWiWWyjMFajPhJ91OJ3lS9ZtKmB8+jBBRZoVG+3nDDH9chwk
         LlptNhrjGn6x9ViiFh9T3gfcNX8WDivJJVIz7O0XBGndmaLkoJsppUbWwGDVCZhYcf6D
         6g4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698745583; x=1699350383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wIhCHxhTQkzJTQZgUjqelK9sXdtgnQz7PkS7qvt6s3M=;
        b=F5kLWAywPdl0MQEpmeTR+bQDa0LDRUyAjjgiCUQTQsjTFcAg0UoVp0oeKss1TmLbpO
         j3XqjM+h3bxiAaQII2+MkqS7MZGImkdmQwrGpavriJRTZIjTNMTAf5lmmQk3Q7H/MICY
         J4FCeElhlIuq9S5I3aF7ixrf3z6wOktIRH623kZ0TMp0YRX1otMK8OP9jXxvBmdutBFV
         PzmVzNEZP43dE+WhQFyqImQe7MBwAPwOrK8rV9XYHmQxdvlLb2ghxbSMgYwJuQONZeu7
         mEVcW9twYUigdzVMT4RnBir6jEGxJI73c5IPNU8bN+G0tZhG4/CTEPitP7r1sb28UD+t
         jHeA==
X-Gm-Message-State: AOJu0YyVCQ7N5mUYEyLvZoDPWq+WCcGniHXY9gawyiYAYWaXKvUm5hUH
	GWX2efqzE2nO71tB3n4pchc=
X-Google-Smtp-Source: AGHT+IFFWiACoNo2/FPf2yFAxjpx5TGAOlyJOhwo6oXKLWkwtHhEzfYX3EpwI0EgShmaYjvxVjxe9w==
X-Received: by 2002:ac2:4850:0:b0:507:a1e0:22f4 with SMTP id 16-20020ac24850000000b00507a1e022f4mr8706177lfy.29.1698745582206;
        Tue, 31 Oct 2023 02:46:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:dd02:0:b0:53f:9578:1b14 with SMTP id i2-20020aa7dd02000000b0053f95781b14ls14492edv.0.-pod-prod-02-eu;
 Tue, 31 Oct 2023 02:46:20 -0700 (PDT)
X-Received: by 2002:a50:d0d5:0:b0:542:dcb4:37f with SMTP id g21-20020a50d0d5000000b00542dcb4037fmr6845731edf.41.1698745580464;
        Tue, 31 Oct 2023 02:46:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698745580; cv=none;
        d=google.com; s=arc-20160816;
        b=wMURj1Gwr7QDsOQnvrB7G9bDCPJ8qFoRl3cQtRKJaMmNnH1Zj4x/v/W3gbNsdJY/ee
         FPVAAnY+iwdDMHdUBvlx7f9Pm64elJ4TJgKOqKuEfBq1upnWjJ4AEK8wKPKItzGXqKoA
         w01rV45yd7ZSN5eFhcqOGllBNidTu2X0mMtTg6v/0Zkwj1waClcoZkvttUiLA9tAMBbU
         pJJ3eIIi0pVhCL+7ryRCVRiEg+yzvheGsq7WOQpszwnqlPuQ+MRJXiUXFcssVe+H69Cg
         pQmd4rnwX8mQTK3aOZqWkHvFci1G1ese5u1iasqkSZwkn5sQbaAIbmHFX/Oj2eIKYQOL
         IUiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qTxwVslDLW3XYJPo7d6erwK3L6Z/wP0aOPPJa5+jpt4=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=wG9Q4xobFp/8Lsx1ixP6IAQ11AAIOGory331ZaFVo4XrQ8vx2w/o/Ldkt8nKiDcKSf
         1FfTnd8YNUh9kyMxa2G/4hNRop+p/zm9FUVaKHQ8X3rqRf7m/IvovY3PHGLnH9G8wZ/W
         j5cmcrZaeWajoPeLBdvq0GwjASOnmAQTa0NAu5ow+WnWvb+ZFLlXelCvtOEH5mr9N55k
         YkIn7cLBcSzVCNQFGIeMWsubacoYcyXrHcK7dgccVhXFjWzcrmoa3QSkGudj20bobg+H
         SIa7ujCIsbgzw2I7F3f9+CoYfUYlHwXXz+cYByvq0GvFUB/XDZg4CybY80RQ4sPxqsko
         /ltg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eAIDSzKJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id p13-20020a05640243cd00b0053f83dfaf54si51976edc.4.2023.10.31.02.46.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Oct 2023 02:46:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-54366bb1c02so7314a12.1
        for <kasan-dev@googlegroups.com>; Tue, 31 Oct 2023 02:46:20 -0700 (PDT)
X-Received: by 2002:a50:d514:0:b0:543:3f97:aa0f with SMTP id
 u20-20020a50d514000000b005433f97aa0fmr77047edi.4.1698745579834; Tue, 31 Oct
 2023 02:46:19 -0700 (PDT)
MIME-Version: 1.0
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
 <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com> <VI1P193MB0752753CB059C9A4420C875799A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752753CB059C9A4420C875799A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Oct 2023 10:46:07 +0100
Message-ID: <CACT4Y+ZS5cz9wZgxLVo2EsGtt-tkFXkFPA6CGAA8Gy7+sEyDUQ@mail.gmail.com>
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN report
To: Juntong Deng <juntong.deng@outlook.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, ryabinin.a.a@gmail.com, glider@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-kernel-mentees@lists.linuxfoundation.org" <linux-kernel-mentees@lists.linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eAIDSzKJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532
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

On Mon, 30 Oct 2023 at 12:32, Juntong Deng <juntong.deng@outlook.com> wrote=
:
>
> On 2023/10/30 18:10, Dmitry Vyukov wrote:
> > On Mon, 30 Oct 2023 at 10:28, Juntong Deng <juntong.deng@outlook.com> w=
rote:
> >>
> >> On 2023/10/30 14:29, Dmitry Vyukov wrote:
> >>> On Sun, 29 Oct 2023 at 10:05, Juntong Deng <juntong.deng@outlook.com>=
 wrote:
> >>>>
> >>>> On 2023/10/26 3:22, Andrey Konovalov wrote:
> >>>>> On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@=
outlook.com> wrote:
> >>>>>>
> >>>>>> The idea came from the bug I was fixing recently,
> >>>>>> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
> >>>>>>
> >>>>>> This bug is caused by subtle race condition, where the data struct=
ure
> >>>>>> is freed early on another CPU, resulting in use-after-free.
> >>>>>>
> >>>>>> Like this bug, some of the use-after-free bugs are caused by race
> >>>>>> condition, but it is not easy to quickly conclude that the cause o=
f the
> >>>>>> use-after-free is race condition if only looking at the stack trac=
e.
> >>>>>>
> >>>>>> I did not think this use-after-free was caused by race condition a=
t the
> >>>>>> beginning, it took me some time to read the source code carefully =
and
> >>>>>> think about it to determine that it was caused by race condition.
> >>>>>>
> >>>>>> By adding timestamps for Allocation, Free, and Error to the KASAN
> >>>>>> report, it will be much easier to determine if use-after-free is
> >>>>>> caused by race condition.
> >>>>>
> >>>>> An alternative would be to add the CPU number to the alloc/free sta=
ck
> >>>>> traces. Something like:
> >>>>>
> >>>>> Allocated by task 42 on CPU 2:
> >>>>> (stack trace)
> >>>>>
> >>>>> The bad access stack trace already prints the CPU number.
> >>>>
> >>>> Yes, that is a great idea and the CPU number would help a lot.
> >>>>
> >>>> But I think the CPU number cannot completely replace the free timest=
amp,
> >>>> because some freeing really should be done at another CPU.
> >>>>
> >>>> We need the free timestamp to help us distinguish whether it was fre=
ed
> >>>> a long time ago or whether it was caused to be freed during the
> >>>> current operation.
> >>>>
> >>>> I think both the CPU number and the timestamp should be displayed, m=
ore
> >>>> information would help us find the real cause of the error faster.
> >>>>
> >>>> Should I implement these features?
> >>>
> >>> Hi Juntong,
> >>>
> >>> There is also an aspect of memory consumption. KASAN headers increase
> >>> the size of every heap object. So we tried to keep them as compact as
> >>> possible. At some point CPU numbers and timestamps (IIRC) were alread=
y
> >>> part of the header, but we removed them to shrink the header to 16
> >>> bytes.
> >>> PID gives a good approximation of potential races. I usually look at
> >>> PIDs to understand if it's a "plain old single-threaded
> >>> use-after-free", or free and access happened in different threads.
> >>> Re timestamps, I see you referenced a syzbot report. With syzkaller
> >>> most timestamps will be very close even for non-racing case.
> >>> So if this is added, this should be added at least under a separate c=
onfig.
> >>>
> >>> If you are looking for potential KASAN improvements, here is a good l=
ist:
> >>> https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&compone=
nt=3DSanitizers&list_id=3D1134168&product=3DMemory%20Management
> >>
> >> Hi Dmitry,
> >>
> >> I think PID cannot completely replace timestamp for reason similar to
> >> CPU number, some frees really should be done in another thread, but it
> >> is difficult for us to distinguish if it is a free that was done some
> >> time ago, or under subtle race conditions.
> >
> > I agree it's not a complete replacement, it just does not consume
> > additional memory.
> >
> >> As to whether most of the timestamps will be very close even for
> >> non-racing case, this I am not sure, because I do not have
> >> enough samples.
> >>
> >> I agree that these features should be in a separate config and
> >> the user should be free to choose whether to enable them or not.
> >>
> >> We can divide KASAN into normal mode and depth mode. Normal mode
> >> records only minimal critical information, while depth mode records
> >> more potentially useful information.
> >>
> >> Also, honestly, I think a small amount of extra memory consumption
> >> should not stop us from recording more information.
> >>
> >> Because if someone enables KASAN for debugging, then memory consumptio=
n
> >> and performance are no longer his main concern.
> >
> > There are a number of debugging tools created with the "performance
> > does not matter" attitude. They tend to be barely usable, not usable
> > in wide scale testing, not usable in canaries, etc.
> > All of sanitizers were created with lots of attention to performance,
> > attention on the level of the most performance critical production
> > code (sanitizer code is hotter than any production piece of code).
> > That's what made them so widely used. Think of interactive uses,
> > smaller devices, etc. Please let's keep this attitude.
>
> Yes, I agree that debugging tools used at a wide scale need to have
> more rigorous performance considerations.
>
> Do you think it is worth using the extra bytes to record more
> information? If this is a user-configurable feature.

If it's user-configurable, then it is OK.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZS5cz9wZgxLVo2EsGtt-tkFXkFPA6CGAA8Gy7%2BsEyDUQ%40mail.gm=
ail.com.
