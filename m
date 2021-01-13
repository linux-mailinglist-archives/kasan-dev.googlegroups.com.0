Return-Path: <kasan-dev+bncBCMIZB7QWENRBF5N7P7QKGQEITEP5KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E3E42F49BE
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 12:16:40 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id v21sf2307430iol.8
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 03:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610536599; cv=pass;
        d=google.com; s=arc-20160816;
        b=VtAX/uS2Y0OqFEACUwNXWE6IB0jOYEr6tDfKjqjyUCt98rwAQ+M4+/6lTIObI4r17w
         BLwuMGLVIsLPldQgiv1Nrl3SzNG/5WyJLwEoCiQTNtvwNw4KPKbYcvP2ULAqn+kf4v36
         3nlSoWJKWpi6GKIlXi+E8Jm4u7lC88ZnfDzVcqi7WEeKKc8OMKhMa6fK4sessm6pIVuq
         3TFAMgwPCI1lELYsTzH31AlqLgqlhSbUFpzPy1FGqRj8AJ7nD2d+7kVo78VeatMXVq4m
         Qd6ZF21GEoRsGX7Nw7iRWlBwrLJhyogeMHnzFjQHJTS8AEeMkGmg2jrmea5e5jVipRh7
         TQBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sZ9glonJEg8SP+fRbo4BrEmVg9ktxYgOwXe/fCwSdrE=;
        b=uEqRxmXTGoMrdKIoaQAC3iDZI5q3JG2s6EDJC2SxTt7bBMnnbZoeM/AQsWQG5M6Kxf
         ZHajxb7A+yf7DpHWbJMDgNaaY1AjNZcR/6SNxZHKnAuwzR+BcNf854jEaqPpeI66Z4uI
         9DbjtFoTdEtpkQqgpyPBRijS7IceDhgI0Q+U5hrXLy5MLB/ruUKBgggUiu0veN08Duy0
         AvfsCL2TbzUC+HUJXg3nYF5DvR3Wz0GsX38dVyUfEay6iTn107fGB1/dRJq+qxFnr5w6
         L9XyJhcry/tJ10WMkMSNzlpSz4m6j5cpLtqjbk8ObY2cmo+eExg2nYtse4xCiX9FlhB7
         Rmsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kvqf5Ok1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sZ9glonJEg8SP+fRbo4BrEmVg9ktxYgOwXe/fCwSdrE=;
        b=UJMG188KvCTV6FohM86VKjAk1vEegAtdc0Ri7h7ED+y0g5eviYbYnncSV9pYS8BkxN
         mUurjjX4j2XSGqV5MTOj0O6CG4TmXD2Z46XLz2XyvON/GIGVfgKWH3UfWVSOStNCIQQc
         TfP+Yoo1rLnJx87GoMaZp3etboCOIf3ziM8z2wF5zXiMvnnOiHD4JQoN/UQHRAAq/pLq
         iV0Ma1eTJzua+oBjBzrAd0hG9LKauumyDJzEHkQd1lrBu1gWWGANSgn8rvU+riCxb9x+
         BNGdN9jnNPq1ZmPFgLjyjqMPo/3dspr6N1JkJRUFZGLwo2xWHcQkktE3yPDQGAe/2RJN
         wVaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sZ9glonJEg8SP+fRbo4BrEmVg9ktxYgOwXe/fCwSdrE=;
        b=cjXXUVzd7wUfAjqszvnaVi0bokOU7x03FnT1Coq69OfHJmEad4dvUFzHS7MzKu4jyf
         aOrzLhnEb6kza7ARSsq7+j59qB6/+3fIbuiBOs2FY/gJahkR1waoDfT5Z1k081RXUf8m
         z2UsqAnJOEQ/m+3mhZY+TenhXjPDzqArQwmIgZwdwgMPLBzrn2RAdZ9hbjTSeA5yK6Kt
         e2Fa0Thf+OMefKnolkhKymnPoULPPS+UbMkI7Q02E32iKVj9ui6OAFqGlXVe0VO9FJXa
         2avYlEZnnL1z2EM+jxj2yPjbzfpGUJZAhjC6AAjnbc88971Javl4D7A5BI6p/zP+keyw
         PPfQ==
X-Gm-Message-State: AOAM53226Fx0y2FPBFHai0nZUcCeA4S2G4u+iC45ymaM2nXbqjW1Uo53
	aw9o0SpOrWvJ4vuz8aaIxVY=
X-Google-Smtp-Source: ABdhPJyU2IfdfaJvChxKNXo4COwlbeG4PvzxruIf9Jfzk0ayOLUFGbi82V9ujRrctcv6IZi/amL4zQ==
X-Received: by 2002:a05:6e02:1787:: with SMTP id y7mr1779362ilu.233.1610536599564;
        Wed, 13 Jan 2021 03:16:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:fb06:: with SMTP id h6ls212952iog.9.gmail; Wed, 13 Jan
 2021 03:16:39 -0800 (PST)
X-Received: by 2002:a6b:ea08:: with SMTP id m8mr1337056ioc.140.1610536599229;
        Wed, 13 Jan 2021 03:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610536599; cv=none;
        d=google.com; s=arc-20160816;
        b=RmB6Xt3I2Zc9/V7hDTM6UBemW/cP5GWtEXeDg6ef6JTGcI/F9I1YIi4T8NzkTzQ4XN
         a/Ev0VR9kVywTGak4jldjm4VhMeH8+wQ8xN1KtVFo+mELVw3P6xjA3KjyDa7dH5EosLl
         4Q404T3S4TN1RexMnHh5xW1bVs3mHEPp5jT/DVf4+NV7yPRidDEBpxjaXi4ClUr4hdeA
         CYz8nOhVg9pqQWbz0Ifh3qzbO3/aReANbPCR7ocyketjyZG3/6gD0FCj2qFEkjgLT7rV
         WxW4gETzvjXlnutRnCETWQy/clHgQQZwbNbWOqI415Jwp0CmVUEeCidcG3EBhsbdvTtK
         5pXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WEMoJoDyQNCV7tQskjaPvtVF4XLKFze7dLSeEdXKWro=;
        b=oCwKzTuy5P4V6EEZ+9QFlolNqEa5Gvvauwpj0fvyOuYcPx7a2e5PaU5STbZO6GfkIK
         N8TTtN6cS14ECtIo/+xG0ESeDccfTuWP4a+JFGUVH8xcHE9HH/R5czB52tPYhwOwQTT4
         trgU7tUQJo2zVssRhgYoMggyMiIOzXbM55xHKLV2v77VKQ1f78gJvIY7TLo2w4adq8IZ
         FlRf4Z4dnE6VLi3Wz1uXLBVqg8aaXqXGi3K0BT3XEskEGihoWpfwLgqhPG+Tyzgwu/k3
         qwE/0Aoxr+3/oqk3QvB6zOpwXpQ5/D/N2useShDXJVi9KLRoFalZqgOiAxbcRO6kK/Wv
         ReoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kvqf5Ok1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id y16si232379iln.0.2021.01.13.03.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 03:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id j26so819966qtq.8
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 03:16:39 -0800 (PST)
X-Received: by 2002:aed:208f:: with SMTP id 15mr1637861qtb.290.1610536598467;
 Wed, 13 Jan 2021 03:16:38 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
 <CACT4Y+Yh=qjm4Ov8XbTXFWeTbgnreab+3QBm5mLZ6vm7+JLQiw@mail.gmail.com> <CAD-N9QWQVg1nRhHQi1+e_FmF4nyxQAANktbsjmiGWMkXCPN0RQ@mail.gmail.com>
In-Reply-To: <CAD-N9QWQVg1nRhHQi1+e_FmF4nyxQAANktbsjmiGWMkXCPN0RQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 12:16:26 +0100
Message-ID: <CACT4Y+Y-Lu=UMsapj8Z4WR6_Qh-dwAcgXFuShso72Fd-gzQNtA@mail.gmail.com>
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kvqf5Ok1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::834
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

On Wed, Jan 13, 2021 at 11:44 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangab=
cd@gmail.com> wrote:
> > >
> > > Hi Dmitry:
> > >
> > > I would like to verify if "KASAN: use-after-free Read in ath9k_hif_us=
b_rx_cb (2)" shares the same root cause with "KASAN: slab-out-of-bounds Rea=
d in ath9k_hif_usb_rx_cb (2)".
> > >
> > > However, I cannot reproduce these two cases since the firmware for ht=
c_9271.fw is no available. Do I need to take some special steps to get the =
firmware working? Thanks in advance.
> > >
> > >
> > > --
> > > My best regards to you.
> > >
> > >      No System Is Safe!
> > >      Dongliang Mu
> >
> > Hi Dongliang,
> >
> > I don't see these errors in syzbot logs:
> > https://syzkaller.appspot.com/bug?id=3D6ead44e37afb6866ac0c7dd121b4ce07=
cb665f60
> > However, we don't do anything special to add that firmware.
> > syzbot uses the provided kernel config and the Stretch image:
>
> It seems like the problem of image. I change the image to Stretch. The
> driver for ath9k_htc works well.
>
> > https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-do=
es-not-reproduce
> > Where is the firmware searched for?
>
> I don't know. However, it seems that Stretch installs this driver by defa=
ult.

FTR,  I see in the Debian Stretch image these blobs are located in
/lib/firmware:

# ls -1 /lib/firmware/
ar3k
ar5523.bin
ar7010.fw
ar7010_1_1.fw
ar9271.fw
ath10k
ath3k-1.fw
ath6k
ath9k_htc
htc_7010.fw
htc_9271.fw
qca

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BY-Lu%3DUMsapj8Z4WR6_Qh-dwAcgXFuShso72Fd-gzQNtA%40mail.gm=
ail.com.
