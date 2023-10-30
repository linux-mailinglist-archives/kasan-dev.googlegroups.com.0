Return-Path: <kasan-dev+bncBCMIZB7QWENRBRU27WUQMGQELOLLO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 791AD7DB336
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 07:29:28 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c4fe286a5dsf40960591fa.3
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Oct 2023 23:29:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698647367; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/awXRu7Kng+6TouIDqXPvLUghb2Z4cm5xBv9glpMu6DCdok0BTMHQKrfqfu7efiFJ
         zpCnoX8BdwK3btMKHE91snM5qOfimr1LpuenX8aaE3T6V74hWbidY+7T29oIN0NSaK+c
         n+N2pOl8VFoofrJ9//Zxx745r++MrWxZIGanN4aMtTwhX3u7c3px2ttP7XxMhiFcUQvt
         BAFmBeusGBDA3JK0tHLj9WzJZc4o5jv7tUYuKficedzOkkuTgwrvdVOIWUOFY4cTLq1X
         q0X0FgdzLwmRK6Jc2VMal8aoHoyvn28Wdn4YJG0xKSKJCAvyDH1pZ4kzSKkZuCsbnkS+
         Ge7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k/7GduEK+qqxG36naJ81GWhQpSP4fksmdnd6HfPq4y4=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=MgY79aY71ZWmb6sKjrAh4sL/3tWS6vtGqdLXTQQwsgAlsqwITTtlujlBkQf+Eoe+se
         dmkBxfNexu5+4aEi/wdKyyr/E9QPY5eSdRd0YYPzYj7v58KGYyZDumap/Xfy5whZPXEW
         fNgMsgpZIPYRTGCmWqpNH4P87eeKqCA1v9rCvWxr7NLeQgBglejPrmrLgGTbJ0l/tjK5
         QVJJyocd1+r5AhFbUspFKeM2l1VE2m7rsgGVJ2J5BamgtM1F3ZMsYJ8UwCyN6mIYO7eF
         L1aCMeLWxeSc5wBAiELIoekip2OkDmSkInG42t2pccHpM6U2RD3WO/W39oYf3I7VHUOx
         QrqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dmzN64DQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698647367; x=1699252167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k/7GduEK+qqxG36naJ81GWhQpSP4fksmdnd6HfPq4y4=;
        b=JhO/8hU+XVz17aw7AAVHepLVIeO4jpmrw0btUxNfgKnaK3KBQDCiH70S/peR+a/81p
         DOmIgywktXSI/DqMsYZlDCcP3j1atQdBHwfOYcOEFIeg58bnoE20EUFHff2GCtmR7bjM
         toudlp0D6hnDiyqxyGDLS26E+MhHs+hETTz/6WvP7aTjqdGEzYUpe4qBKU4y6SBKQ3Im
         dTci6WMKm/V7l0bdUkqrWmeTLLrjAfKJRxKXqieJ70/sXByH1MsbHraTugWG1BvFkffj
         bTzcu3brVmF9P+q3683srh82UIJiB0tRx3sMS5+uYWk+rxYDCN9qpCZX41TJBuL1/AHm
         wWRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698647367; x=1699252167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k/7GduEK+qqxG36naJ81GWhQpSP4fksmdnd6HfPq4y4=;
        b=NUN4uLDiDy2XzAfJBeo5ndrwytnJQ9v73y1c0z2OFdcWGqV94FbJDOSD+U0baRKa24
         xoXpaWM1IcJ0p8b8wJhVdSF07U70eDMDu2Oy42qy1BLNDlg0PDcgN56gC6pFKVr1xUiP
         h9Pq11RGFAp3ipOC8x25sguinX302/tWkJIM0acC12k/355sO+VtPBsIB6lV2Ll4+3AP
         gW8SLtO3HpzQw+kq2DHoFNl/JtuZhI7lrPqeHrMEuM55hKO6lzjyZg4x7nFMeBPZTmYc
         JlmLyy72ErScqgFLH4iJw93NFowFnz33/cYtqezFC8p1g5dxao4KJoI1w5iS4wtXoDQR
         p4BA==
X-Gm-Message-State: AOJu0Yzjsu9IBTODen3TVAbXIZxMQ9HXA4b21m23xE/YOBxVvSbpsfER
	Zmf15QMNUMaKochShKiA1Xk=
X-Google-Smtp-Source: AGHT+IFCTiXSZDxNE/Pk/tafcEqt7zS6aziRtiWTJmzAL2CElWzIje3iIA7E+B/5n3y3jCkpb/42Mg==
X-Received: by 2002:a2e:9d47:0:b0:2c2:c450:c2d0 with SMTP id y7-20020a2e9d47000000b002c2c450c2d0mr6159949ljj.24.1698647366764;
        Sun, 29 Oct 2023 23:29:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2126:b0:2c5:14f8:2ef3 with SMTP id
 a38-20020a05651c212600b002c514f82ef3ls797133ljq.1.-pod-prod-04-eu; Sun, 29
 Oct 2023 23:29:25 -0700 (PDT)
X-Received: by 2002:a2e:be10:0:b0:2c4:fdc9:c8a3 with SMTP id z16-20020a2ebe10000000b002c4fdc9c8a3mr7706838ljq.50.1698647364865;
        Sun, 29 Oct 2023 23:29:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698647364; cv=none;
        d=google.com; s=arc-20160816;
        b=Wwzp7EVLFuyZFxwummMG2ghouKKZonEpJ/H3TadN9Cr1y7hvZDLzVLKqqbuuf6Q2yd
         4uP6QhnCk1SJgEEcnExycl+oAjg5QL37q0xr0unTQma10vZ/T4ZcYvUd5+hywXROfZxo
         LJySQdYnt4GcsFsSjfJ1/YSu4kFf3L8FDIjXEUlrG8AHukoSJBOZ1FNAKRxDhPNlGGak
         LG6sORz6KdrsxZ90V17VD3LL2i/sBVOf6brKf3ZSHTVGvVvWmb/oQ9o4lk+CIJ+/DXir
         thjxsayZctt0twGk5HDvxzcAtJT/3Cr4WQXiOgZaI587f8Oo/bDdvWZEH4N1yaH/0mlc
         C4sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rzVHmjEI+YpEe4gZLECBFUB4/fthvdQpMU6WpBuzUV0=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=hevSGH9EA7mJFg24ScJQPFFGiimQjdN6lv++4fAu5092j8tDvAQ2o5Zf4bpoAYsPrG
         7RmK7GXbavRPJi8g+e59/E1DOr+u+U+Itddwt4aS79eyOAzOx2KSK36TW7Lei7gA5uLM
         4AKNf7IC+wRLbfDGDN1NmtITeqJHmLH+lNStP/TnBV/hqfqEa40XHTVqs1g0oH0S2Q7U
         BsUxhO0uttrOJaDg6mks9G0+XFp9XVB8j/Ff4n6XQPX8GSeFBJMqtaUkoZhZH39v3NB5
         d2WQBWL4c8QVQvXxqnSKfF5ZTGpuHuwXBo7eqhYh+EGeqrcy8WouBPqNDZzB409gT6xQ
         /Pxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dmzN64DQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id az18-20020a05600c601200b00407c8777ecasi652596wmb.0.2023.10.29.23.29.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Oct 2023 23:29:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-507a5edc2ebso3625e87.1
        for <kasan-dev@googlegroups.com>; Sun, 29 Oct 2023 23:29:24 -0700 (PDT)
X-Received: by 2002:ac2:4e85:0:b0:501:b029:1a47 with SMTP id
 o5-20020ac24e85000000b00501b0291a47mr58180lfr.1.1698647363870; Sun, 29 Oct
 2023 23:29:23 -0700 (PDT)
MIME-Version: 1.0
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com> <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Oct 2023 07:29:10 +0100
Message-ID: <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=dmzN64DQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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

On Sun, 29 Oct 2023 at 10:05, Juntong Deng <juntong.deng@outlook.com> wrote=
:
>
> On 2023/10/26 3:22, Andrey Konovalov wrote:
> > On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@outl=
ook.com> wrote:
> >>
> >> The idea came from the bug I was fixing recently,
> >> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
> >>
> >> This bug is caused by subtle race condition, where the data structure
> >> is freed early on another CPU, resulting in use-after-free.
> >>
> >> Like this bug, some of the use-after-free bugs are caused by race
> >> condition, but it is not easy to quickly conclude that the cause of th=
e
> >> use-after-free is race condition if only looking at the stack trace.
> >>
> >> I did not think this use-after-free was caused by race condition at th=
e
> >> beginning, it took me some time to read the source code carefully and
> >> think about it to determine that it was caused by race condition.
> >>
> >> By adding timestamps for Allocation, Free, and Error to the KASAN
> >> report, it will be much easier to determine if use-after-free is
> >> caused by race condition.
> >
> > An alternative would be to add the CPU number to the alloc/free stack
> > traces. Something like:
> >
> > Allocated by task 42 on CPU 2:
> > (stack trace)
> >
> > The bad access stack trace already prints the CPU number.
>
> Yes, that is a great idea and the CPU number would help a lot.
>
> But I think the CPU number cannot completely replace the free timestamp,
> because some freeing really should be done at another CPU.
>
> We need the free timestamp to help us distinguish whether it was freed
> a long time ago or whether it was caused to be freed during the
> current operation.
>
> I think both the CPU number and the timestamp should be displayed, more
> information would help us find the real cause of the error faster.
>
> Should I implement these features?

Hi Juntong,

There is also an aspect of memory consumption. KASAN headers increase
the size of every heap object. So we tried to keep them as compact as
possible. At some point CPU numbers and timestamps (IIRC) were already
part of the header, but we removed them to shrink the header to 16
bytes.
PID gives a good approximation of potential races. I usually look at
PIDs to understand if it's a "plain old single-threaded
use-after-free", or free and access happened in different threads.
Re timestamps, I see you referenced a syzbot report. With syzkaller
most timestamps will be very close even for non-racing case.
So if this is added, this should be added at least under a separate config.

If you are looking for potential KASAN improvements, here is a good list:
https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&component=3DS=
anitizers&list_id=3D1134168&product=3DMemory%20Management

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba%2BxfzXBgqVz3Gxv4Ri1CqHTV1m%3Di%3Dh4j5KWxsmdP%2Bt5A%40m=
ail.gmail.com.
