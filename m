Return-Path: <kasan-dev+bncBDE6RCFOWIARBF4G2P3AKGQEQRFICDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 76DC01EA064
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 10:58:00 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id x4sf1975440lff.21
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jun 2020 01:58:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591001880; cv=pass;
        d=google.com; s=arc-20160816;
        b=n8g2FUqPZR8PwykdgFLDd68tUjuN3CIFsp3pdY/qGnzDr9MSRl3cF0gIN0Uey5t8x+
         /HGDoK6iWzYFlwXRs+klmDtfe4cH7teYGDrL67eBicRehJYGq/QduuMzkKEBZzVevzqc
         Q4tdxXvkTYIiOjIXkfcXqVWr02KaI2LW8cRQNjSn5CvsBui78aIJvoPeXe7R1E7M4mxL
         jmCGRqkRy+R7shUVcpL6HMMliqa37q+Qu8OFHGPFKgC9tgZilqLjx79MAPJfSfaFDWQJ
         sIOFVG9QEDEu30MRHE8VCah00pN3U8352b4w5flWZXt61naf7LKSdVSHla0oRQjOEIcY
         sHQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=VudEJa6ig9Buray+J219wRz7kDP4B8wFqaVENYyeddI=;
        b=keeBaUrp8OB3q3vaFP9kQbDdJQTu78ZLT/ckIE5icgHzA6YSrYAyxiZ+LeQ3i07xmW
         iGidinCCBrkBNirqSzyFsacPdoRCzYGmmsCrCkVYXkCZyx3doDBCYGS0lRedzKBatD2h
         I7+yxOI34V7Bz59dV7AK2Z7mWSuoEhUjHUwG/fxSgJMW+KwOih8e0PGBOKymISjP4xAF
         x7hNR3sVOt0ULqFPlHTKFPgna2thxjH8pT7FmDeKT3Rl10c5cQDg2DVo4M56HaAl5438
         jJ4LM9tjtlhQW6iz12rLZ58tiCvKrCj3ttJbUNKF9d21Xmdb7cMm4EuJ5q65yxWs/oUL
         er6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nuCJXSSk;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VudEJa6ig9Buray+J219wRz7kDP4B8wFqaVENYyeddI=;
        b=EQilK9BbqFEurxHvHg9Zq00yOQU3+a4Rzo5BynzuYdD5AREsdWMKfEzRomxfLDR5l9
         4LjPPqnDodN2KtDYhofsTok/o1pIWrt5gpE751RpcFr+jmWpNVaEbwDlfRocNuFSvasv
         w/wkOMExsG9NJimY/oLJXXXFayygZvHbT/CxM6gl5iaEvebe36syyJSEYIBYI79xuvSW
         Mr0SNO/t2tInpnh/3od7nRIw8fxkFaZSVgNHC9MFivRwhMSkCEpUK19WVylYLAcTosrN
         JxxMIKCttnWmORPoUXpm0pycPhw+YgsUed2DWEisdYcsfaBp6HwztZrxoeEKmIE8RHKM
         3y0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VudEJa6ig9Buray+J219wRz7kDP4B8wFqaVENYyeddI=;
        b=GveBgBRKLrk/uJkV9Wq8eAQZ5KnmcG/xRbLGqN8HUhO+FwUxJmja2k/mSd2scD1+Pf
         ON0Vuie2hg/ICzjrpN7eVtRc99HqiL+QVtIw24d6KSD0Yq2pCh67oNPnWdpWXXZf/3lg
         aEqsEmbeEHvj7j9SQsgmuyLekljuG4TpPqWMAkg1xq1oYDInkPyjqhfbOfmJ8GQC5NHH
         XiTOZQfvdlFU6cStQk5TTh1F6R635IXQDFsiat2Ch5ldxclIIuE4f/tU/v3hy2TKH/hL
         gPXOzxGEr0px1PenaPHOejALjy8ICyayLelvD7gegx07niY7ercMUfAutZoh0CYIFbru
         mbxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cj16TrMl1HGt24rcIQRh6oMsFYZcTEGgdSImyatNgEihhjf4v
	xlEWRmjZmElq7kVtMUs3DUM=
X-Google-Smtp-Source: ABdhPJzSvXQjhXzCfVoKoyWeGukrPlMAGzblKsomQv/NBR5wqSbKpbmzqcqPPaksQjJZTjzaFEDZ9g==
X-Received: by 2002:a05:651c:2007:: with SMTP id s7mr2364735ljo.418.1591001879985;
        Mon, 01 Jun 2020 01:57:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8092:: with SMTP id i18ls1597174ljg.7.gmail; Mon, 01 Jun
 2020 01:57:59 -0700 (PDT)
X-Received: by 2002:a19:b06:: with SMTP id 6mr10732838lfl.104.1591001879435;
        Mon, 01 Jun 2020 01:57:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591001879; cv=none;
        d=google.com; s=arc-20160816;
        b=W1BueBqt7iUAS0YolPxBPuLPMVYmp+71Pa408yv6nA1VbBjEVq2VGLoI/kXi/4yQJg
         86SMfZUDZ4+JyNowhEnGD+JModdrnjFj9/cJXY+Xtnp8ZFYyb384dXK4QrMWLO0o5/ON
         st4mH4f/3qo1tZQ9vfX6hQkz6m6qI2RGj4FRpR4Z6K6EodK290IiSJCr5jXhnrjTC1/U
         e7z7rRwoPUQM7MIpo0yIXWOaSqyBvxtaXmREE1bZd3Z9qGF0AYqnw3HUY9iqSVlH0fIZ
         GdF+ix+wxxWGx+TOxaEoX94hmHubE9djOMpKTBhxxkV6RQTnjew1kglG3a4o9e0Np/ha
         1Clg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c9Ly2lWZlozDI5lugZ7MIQbCgsQA4pzvpFcGSYKg4MM=;
        b=O7qc04cOc6eiVQuBOakUZfC9IHEadGUaYMlfkbDnE8qBloshJdoLh6gTB+/iD1I//p
         1Lhq9kMRHPmn57jauG3F82/kQuSYp2Nmvoq8vsP7F1MCeFFZQNUvh/uE9N/SnqULEXGw
         h7aV1UnsQotF0WsM19LIhgTEWmcy0OenQLw7k90G4eJkwWeCytnMd47tn1xTlhKRCQ/r
         lQ1Bwg/oX62K+CUdP4ylYOzsblRO7CjPBxj+gLAHg61vX0+lJpwVvr4mDvvlCqf/qUcr
         ru78Hdf6cnfM79PxWKh5agjyt9eKJ0ej+VujPLRlAOlmqI9W8ilOrCMfnJ763T2buygh
         sYbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nuCJXSSk;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 14si942591lfy.1.2020.06.01.01.57.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Jun 2020 01:57:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id z18so7106069lji.12
        for <kasan-dev@googlegroups.com>; Mon, 01 Jun 2020 01:57:59 -0700 (PDT)
X-Received: by 2002:a2e:544a:: with SMTP id y10mr5294708ljd.144.1591001879160;
 Mon, 01 Jun 2020 01:57:59 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com> <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
In-Reply-To: <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 1 Jun 2020 10:57:48 +0200
Message-ID: <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="000000000000d83d9705a701fddc"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=nuCJXSSk;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

--000000000000d83d9705a701fddc
Content-Type: text/plain; charset="UTF-8"

On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com> wrote:

And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm
> 0x44000000"
>

Hm... can you try loading it at 0x50000000 and see what happens?

We had issues with non-aligned physical base.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdY9pbM--gBU2F_3Q%3DAdB1Fsx4vHzc5O-3Fq0M105SQWLg%40mail.gmail.com.

--000000000000d83d9705a701fddc
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><div class=3D"gmail_default" style=3D"fon=
t-family:courier new,monospace"><span style=3D"font-family:Arial,Helvetica,=
sans-serif">On Mon, Jun 1, 2020 at 1:07 AM Raju Sana &lt;<a href=3D"mailto:=
venkat.rajuece@gmail.com">venkat.rajuece@gmail.com</a>&gt; wrote:</span><br=
></div><div class=3D"gmail_default" style=3D"font-family:courier new,monosp=
ace"><span style=3D"font-family:Arial,Helvetica,sans-serif"><br></span></di=
v></div><div class=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=
=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding=
-left:1ex"><div dir=3D"ltr">And I am=C2=A0 loading image=C2=A0@ 0x44000000 =
in DDR and boot=C2=A0 using=C2=A0 &quot;bootm=C2=A0=C2=A0

0x44000000&quot;</div></blockquote><div><br></div><div class=3D"gmail_defau=
lt" style=3D"font-family:&quot;courier new&quot;,monospace">Hm... can you t=
ry loading it at 0x50000000 and see what happens?</div><div class=3D"gmail_=
default" style=3D"font-family:&quot;courier new&quot;,monospace"><br></div>=
<div class=3D"gmail_default" style=3D"font-family:&quot;courier new&quot;,m=
onospace">We had issues with non-aligned physical base.</div><div class=3D"=
gmail_default" style=3D"font-family:&quot;courier new&quot;,monospace"><br>=
</div><div class=3D"gmail_default" style=3D"font-family:&quot;courier new&q=
uot;,monospace">Yours,</div><div class=3D"gmail_default" style=3D"font-fami=
ly:&quot;courier new&quot;,monospace">Linus Walleij</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACRpkdY9pbM--gBU2F_3Q%3DAdB1Fsx4vHzc5O-3Fq0M105SQWLg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CACRpkdY9pbM--gBU2F_3Q%3DAdB1Fsx4vHzc5O-3Fq0M105S=
QWLg%40mail.gmail.com</a>.<br />

--000000000000d83d9705a701fddc--
