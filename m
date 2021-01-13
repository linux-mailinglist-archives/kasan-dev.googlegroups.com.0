Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDEC7T7QKGQEIG7JZYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6948B2F4CF0
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 15:17:50 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id k21sf1570000pgh.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 06:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610547469; cv=pass;
        d=google.com; s=arc-20160816;
        b=FykTrQYjJN/JRqGHtOsvULkPztdtAXQh39MQ6DQlpHqwSQ6BeQ6j450DeLxL6n8RVj
         4Kc024mp8n5iq5D5aqstAMKaGV/CnT4IQg9ZHfV9wAVfrwApIKXtpkhLorlvs0hp/6Lf
         83W+iaaBPPROibChwrqj1htLw9KWRuFA+dtPVK4yIYkxsFXreGoKxuDeiPXtSl9/3fBj
         NYUBxf5HUmg5QBNzw9ztc96MHM2PaX61SAPajNWyX76sJpuRRAKknNn789jcRhAXAf+T
         pW5Tu4/s5PCg7s08iq47CTi32cUCpzG17ybYpwQ+QwzicMLvcm9qj2exjahrUrdnkKwj
         2bGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qZS2kBtTl6TL3bzGzciG5RqTWp+1y0/+HCdmNswwQ4M=;
        b=A3scK8kxEEfuKMbsghPS/4uI24u2lJ8MMqdPWx6kz6jkTNcb29DyB3y3b1NGW7cePj
         y4uasLDExiSyu0dHxyAcv88VBP2Vh7fDtei1myrz5LBDQ/PgitLA2LdA5eBUrVwEDRl3
         lXHlKFnXqSQofyNvijuJr6Q0yKzFohnggIkU3MJQmovL50aVZfxvhmZeYc4n/DbCpc6w
         R14EsMm4UX1ddGipdaeCTnUgS3+SjG6KH3klhaHmJdhcY2VNQxZlAD1vHvj3o77qVYrk
         MHxNlDvQzOdYKZlgAmMlyExuEUz4cAcj7d1dNmY6tFqNTw5EciiSfZgQhglwnoZ2aB3j
         mJFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pYCw4Ilz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qZS2kBtTl6TL3bzGzciG5RqTWp+1y0/+HCdmNswwQ4M=;
        b=RScsKXK7wzG2nhUreANt3ydUePxUSr0HGlmnH70rT7XApu2wioePgqOWlG0BT1rWY1
         6UrBuqZqdFWD7KuVNYjmHoZ/a6XQRKhra5N+bzonwdRpoYLvU71fzDNsTWCG5UAlAZGq
         9GItHWpiMz9C5U48l9cIStZClbp0B/aoqatjV50GjoNSygBfvOq0StFdSJDO3aPFbT9I
         9eA1XkfIwNw+NDcQ+VTqgnmeUdV1O53pLaS1piSNrNMhSA4dl+hdgtfXrGEKL8csXeHw
         qbadPXZoBwrgdJOUJiAxYh/1Dc9dy0mHuU6eKijqWeIvgy9saZamrnNv7DHdKgpO7euq
         MnBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qZS2kBtTl6TL3bzGzciG5RqTWp+1y0/+HCdmNswwQ4M=;
        b=Po1nwTVfbxs1+TeEniqZDvydUgnjkGkgiEiTrcesmo6pNahfEvLxpCygrAMdsJeRh1
         Yk6FslK25Zs7KrZb8YJNBqA9s3wqHimSyFyVtxKC7bFHVkWRR73gEyueryL6bLsB0Dcj
         uspixntlIUDd+M342LPaMXZIP2Y+6+KEIX1OQ1J9TgKDjxfrt0xqHjW0ekAe4ZPFRcAs
         aN61YiQ2v3mEtU5kMY8a6zIkUX5iFo11eNy/j9LOP3kONLExgWK9EXDDmv4cV4g8aL/v
         Ds0/WTVafm590SBhQdhe5XQk95RG7lKJam3cpnj2RiFGx9/ogp8sVmZI3fXdVCV9fQue
         ClxA==
X-Gm-Message-State: AOAM533SP2Owqy1TEfntzW4XSPvLnObTQZECD/A6qkDbJXoGpUiyGC7E
	5BAVdvg10It2i8FVXkkTzSU=
X-Google-Smtp-Source: ABdhPJxYWPF0Q3oYkHXWnRW7Ut87dMgRRSmTfSv+OWhYsjl1enKuQTJD0PuIZ/3rx2IUYXBWpSPzKA==
X-Received: by 2002:a17:902:6acb:b029:dc:2e9d:7ca with SMTP id i11-20020a1709026acbb02900dc2e9d07camr2485222plt.56.1610547469144;
        Wed, 13 Jan 2021 06:17:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d97:: with SMTP id y145ls942213pfc.10.gmail; Wed, 13
 Jan 2021 06:17:48 -0800 (PST)
X-Received: by 2002:a63:d650:: with SMTP id d16mr2239616pgj.277.1610547468536;
        Wed, 13 Jan 2021 06:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610547468; cv=none;
        d=google.com; s=arc-20160816;
        b=vGZaTVhsGhzD/tGywVib94TVeVcAdETOX78P0yjU4Xc+MierYFD3sfbIP689HfiGHU
         z3Omk8L4qjZgth7+AtcEhxWICRxPMi41X79ISySi2w18RW37tVjCK1L5DBnXp2pJO9xt
         wo7No8Pfa2xmfXT9f3fCsapcsgqD+bCIQw8EZqoHViIeGaNDDStJPGfoA8RAI5rA9/BP
         kWm7Socv66lPBLe1asvB2yeEPqpBpG7jrh/Gy6VNiBt4T0XkVXle2xY0Y0hj/Oqp3kgt
         Duvqms0N4T/z5oYJNWNEMXfuH2ypJ9Pmx8KwBywJzgtyJ4a+XpXDKBTr62a779y3pEHc
         iEcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PjHicHfzMDkIE8SqKcQGVFbwUsSOluhy2ZJBVMyEn1U=;
        b=tEZsOemnjdZpIhvGZkGW/c0AVoZOzOW4zx1DEskjJHfTwZ/BEoQfq3wREI0ONNlIEs
         xvB346NEQPXFkcrK62iUqrnkfnyz+qlBnSbhH5qMh8pLN9A1lu1oH2RqiST/2AvTpd4R
         thbiPdUZxx3d6IMGI0J7xFiUQIewpvZcLrLEK9KDgwjdd6PFg2wpYKh1S/8p17BRfkgC
         +1QhdxlNj//4DJjw/UJ6K+hg/lwHKcmIujNure5eAZc9U8uAwmNw6QaRdLyX8pVX9tgt
         GWARvWY2PypypUYWSuItVkGVlGyJyNo1mqj36XvbdwPa3eDPNXKlwtd1eyNZ4F8U3xrg
         XKBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pYCw4Ilz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id i12si144523plt.3.2021.01.13.06.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 06:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id z21so1585188pgj.4
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 06:17:48 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr2229362pgq.130.1610547468098;
 Wed, 13 Jan 2021 06:17:48 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
In-Reply-To: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 15:17:37 +0100
Message-ID: <CAAeHK+y7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4xa6g@mail.gmail.com>
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000bb628c05b8c8cdda"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pYCw4Ilz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

--000000000000bb628c05b8c8cdda
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Jan 13, 2021 at 9:38 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangabc=
d@gmail.com> wrote:

> Hi Dmitry:
>
> I would like to verify if "KASAN: use-after-free Read in
> ath9k_hif_usb_rx_cb (2)" shares the same root cause with "KASAN:
> slab-out-of-bounds Read in ath9k_hif_usb_rx_cb (2)".
>
> However, I cannot reproduce these two cases since the firmware for
> htc_9271.fw is no available. Do I need to take some special steps to get
> the firmware working? Thanks in advance.
>

You need to install the firmware-atheros package, as done by the
create-image.sh script.

https://github.com/google/syzkaller/blob/master/tools/create-image.sh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2By7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4xa6g%40mail.gmai=
l.com.

--000000000000bb628c05b8c8cdda
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr">On Wed, Jan 13, 2021 at 9:38 AM =E6=85=95=
=E5=86=AC=E4=BA=AE &lt;<a href=3D"mailto:mudongliangabcd@gmail.com">mudongl=
iangabcd@gmail.com</a>&gt; wrote:<br></div><div class=3D"gmail_quote"><bloc=
kquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:=
1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr"><div>Hi Dmitr=
y:</div><div><br></div><div>I would like to verify if &quot;KASAN: use-afte=
r-free Read in ath9k_hif_usb_rx_cb (2)&quot; shares the same root cause wit=
h &quot;KASAN: slab-out-of-bounds Read in ath9k_hif_usb_rx_cb (2)&quot;.</d=
iv><div><br></div><div>However, I cannot reproduce these two cases since th=
e firmware for htc_9271.fw is no available. Do I need to take some special =
steps to get the firmware working? Thanks in advance.</div></div></blockquo=
te><div><br></div><div>You need to install the=C2=A0firmware-atheros packag=
e, as done by the create-image.sh script.</div><div><br></div><div><a href=
=3D"https://github.com/google/syzkaller/blob/master/tools/create-image.sh">=
https://github.com/google/syzkaller/blob/master/tools/create-image.sh</a>=
=C2=A0</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAAeHK%2By7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4xa6g%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAAeHK%2By7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4=
xa6g%40mail.gmail.com</a>.<br />

--000000000000bb628c05b8c8cdda--
