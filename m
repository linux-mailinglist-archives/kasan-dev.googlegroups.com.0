Return-Path: <kasan-dev+bncBCVL5GMC3MJBBF4TSHVAKGQEDIPPYEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FCC37FC47
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2019 16:32:56 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id n25sf18229476wmc.7
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2019 07:32:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564756375; cv=pass;
        d=google.com; s=arc-20160816;
        b=ki6gSKrQ/0AC6vRQKfX+5o6tseQ/3zc5/wvYd78MV3q7avhXGqcNrcLEwJNfaRdjFo
         d2cIEnV5wCoOhLx055d2AXcxOZMyYJag25imRcLlkXzADJVoWxo9nB7tno+r/ksH6LNE
         W1wShhLx1sgz+u9S92DwB5c5ype7GzJuZtOaNmv7A9I7X7eUQEaxb6/ZwPe3OhQNQCHM
         /ReCJQ8j8ysnAvZ8nDBwg5nJLWqUumLMWgDXCDCK9i5DFriZT5UQ2U37zvIM5fbApi8A
         ruYklnrdXZYB7P2aCABxPA1RDlNzGP7PcexzdvvZJuDd9kOivY9MONRJsLPpRdAC5710
         ohVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=QZzMveCqd1P9Z8bau5k7kr2YpNP5jjhZ5as/lyrjsmY=;
        b=paGB4Rjag8Xh0eAlC5nlaVo8aKS5B4yQy7RauyK+BrIXOWZhksR6Yy68a0uLPXlW6g
         Bj39KSsFecRryrHGfdMeqbh0N1/y3z7n6sEE0fAw7c6iJWhWa3Z6cyB37g8BAHRV9dtc
         os6Fh47up6mNZucXN0msRAMn4zvXVA6SiAIQWuXEtnGJKMNvni4EcB0hWeGVeOXURFXA
         4ci8HOWulowUoCfw5uLorS0ad82tjV4QvFc9gZUOziAPI1ymmFevzf9ojI+ZjWrNIe7W
         8vxLRfvOHCAicpdx8omIYMA++7F0/e9Xu19pCzGmmPY13Ng4vUY14EjM7+qdHphUggH/
         FR3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bN8nxThP;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZzMveCqd1P9Z8bau5k7kr2YpNP5jjhZ5as/lyrjsmY=;
        b=M4Hm/MEYKc0m7Yr/tpPR85hTx0UJKxx1YG2CRokkUmY20EQR0NKfsQopUlzSK2i3IN
         zdvimxCMja8bsXlQjybm37FpKWuWY+WX/EZ2OrsR121eVRIMXYNv8fNJ70ViHZ8B0dii
         Ui60DPR4YB+MJpn9K4At2qE1hhNJc8d25j+aesV2PlL+UuNLi+rQAQhJxqDcP62JFMg+
         5g9JX9Kz3MXh7EE+yBOqyJxFkPJm0+qoq5O7cSBYZLlJOMhEiRVQEHGLv9MLr1rA0p6M
         65XcAs/HY+nyycNoe+f6Hfyr5dHqnLcZ4XfWYeCaskkQRdoiS9IVZ2IN8pAnJJW9/XWl
         Nf+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZzMveCqd1P9Z8bau5k7kr2YpNP5jjhZ5as/lyrjsmY=;
        b=spUwjA4RdpR2jCW5kSXitFqYwZnZLBwbVcJ9cnQ8RwEoSksKyFtQZAZAnEdAvlKCwW
         b1UOtm6QWZO/Y25ObSLdSf0vaDjofOTmG45+B+FQqJ3sZMJrfBKc6Xi8yLq6hg4LhLXJ
         +pWTtHvmYwBwU8r5CstwgZ6OpNCe0GlPfr2Wl6obbgTJFefaN7XFvMbRBWrbo29ZcjeU
         m7wLHSva2a5S2z60uP+S5h9F+eWed+xsn69v2Q5aSvH0EY4KF2xDrWJQDZKGau7OZmWO
         eMR7a+3poIVkdFdSLNmZq9Sh3sQim5vwRT3e7Lp8OjCNBeGNSZiozznuVF+phkcqb+gv
         NvNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZzMveCqd1P9Z8bau5k7kr2YpNP5jjhZ5as/lyrjsmY=;
        b=Uf9dZZJ3T8rkreOAHPi/KzGqLzyfENsThVySRkTL+jXdWWDuiA/F2JmIww9xfnSq+l
         a3rhuLKGlweXjhgtxHBoOvSo9EpbhhnP5yNfUhZI5GjqUm7L4zD2irmBojGl4IiGXPHK
         iwjx9O/dtI7onqMFfBDvKen887Kizlm8b1xgsof0zTQ0ZlhVi3kJU8Ac4sQWkpVnEbKn
         /C7u7atLP2TY6ORUv/YhAndy5c96B+B7NBrdiQCjz+QJNrLQkle6GLidzPYKN+ahOm2p
         Y7rNFiQVftGecJxuEFPKhxvAcNLvaPCpfp4qeE37lihmcLtbE6WmFgFUppCFBaWg16Nj
         T3mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUEX0VVufQKIB3QNFhrnZJ02xZZ4eJo/OYbbtzNO6LL3M1Oe7lK
	xNitI976PTxMyyz8b/nHRkk=
X-Google-Smtp-Source: APXvYqxIfeyNxF95FXCgl2Hchnx6GVmpg5m0dH/eKP557EMn8QOGnXoh5YS562b5bDq+iJvLaxxdHg==
X-Received: by 2002:adf:cd81:: with SMTP id q1mr146218207wrj.16.1564756375770;
        Fri, 02 Aug 2019 07:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f711:: with SMTP id v17ls21751121wmh.4.gmail; Fri, 02
 Aug 2019 07:32:55 -0700 (PDT)
X-Received: by 2002:a05:600c:2c7:: with SMTP id 7mr4921756wmn.45.1564756375220;
        Fri, 02 Aug 2019 07:32:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564756375; cv=none;
        d=google.com; s=arc-20160816;
        b=GIUZj7/TeWpaSjvjobWV6szXPO/406tfO8riv1HL6Ud5fz15+LBTzn4ouiZxAuS/cX
         te81DgxoLorSuxRB9BkdLgzzrhU47JidEgy//WxoLsa16PlXOjRHUAz6EsInLXtdZ2dQ
         xkZ7kcjCdckjj7FJrurn+rXOCkiX48kqMW9RWxsQ62iGgJWg1CKsJKEHbvxoeKApfiA4
         csYzUp4zzk6KcXo7FizTJiE6tXFI8AS1wOGYpM5wsa3o7T6GxJNjyLopyD16uFCMnkwU
         sBseHFG9dZqlGSW5i8xBbwQJDauATQB/t0RVK0c+VQEDTHbzmCTR4T1rwFU9Y+Vt3bEa
         gCzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=JCQtEE0KBhaIwIF8Z7Gy74OMaAFI3IbnKsI8H6I5yGQ=;
        b=LAfC/4jcn7pKdJD6LbX0DiTge3l/MYgYyYMnH/qmgblL9qRxFISHS7DAUcisasFlAI
         WZu/1GjgVRr95DSVZ2j/tyal0whn3L2a6v8GpTHaUMOGNR7nCfukwwKsiTTnHdRhCITf
         3rv+tTvyZL7HXna04omRzpOGhmAdgotkuWb4WlkGbDKUG0boGYwTvxoN76e/myI+C6uJ
         biS7QqVXtBEfLdOX83o/vZPnffTpBW0wwMdBCQ3sut6hRZqjDRc088s6ZvmfSYIztG0a
         osdnq4X0sSxMEolzUoiPG3PFLS9fWPCxlgNaYRtFxH8uk9C2UYkeMqj0MyUv+98redzu
         k/SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bN8nxThP;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id b15si92607wmg.1.2019.08.02.07.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Aug 2019 07:32:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id i11so9077332edq.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2019 07:32:55 -0700 (PDT)
X-Received: by 2002:a17:906:7f16:: with SMTP id d22mr105677391ejr.17.1564756374970;
 Fri, 02 Aug 2019 07:32:54 -0700 (PDT)
MIME-Version: 1.0
Reply-To: moneygram.1820@outlook.fr
From: "MR. Goodluck Jonathan Former President of Nigeria," <eco.bank1204@gmail.com>
Date: Fri, 2 Aug 2019 15:33:19 +0100
Message-ID: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
Subject: I have already sent you Money Gram payment of $5000.00 today, MTCN 10288059
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000e3ea65058f233bde"
X-Original-Sender: eco.bank1204@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=bN8nxThP;       spf=pass
 (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::542
 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000e3ea65058f233bde
Content-Type: text/plain; charset="UTF-8"

*Attn Beneficiary,GoodNewsI have already sent you Money Gram payment of
$5000.00 today, MTCN 10288059because we have finally concluded to effect
your transferfunds of $4.8,000.000usdthrough MONEY GRAM International Fund
transfer ServiceEach payment will be sending to you by $5000.00 daily until
the($4.8,000.000usd) is completely transferredwe have this morning sent
MONEY GRAM payment of $5,000.00 ready to pick up by you, Money Gram payment
of $5000.00 sent today, MTCN 10288059So contact the MONEY GRAM Agent to
pick up this first payment of $5000 nowContact person Dr. Don
JamesDireector MONEY GRAM Service,BeninPhone number: +229 98856728E-mail:
moneygram.1820@outlook.fr <moneygram.1820@outlook.fr>Ask him to give you
the complete, sender name, question andanswer to enable you pick up the
$5.000.00 sent today, Also you are instructed to re-confirm to him your
information's as listed below to avoid wrong transactions(1) Receiver
Name--------------(2) Contact address--------------(3)
Country---------------------(4) Telephone numbers-------------Contact Dr.
Don James for your MONEY GRAM payment of $4.8,000.000usdNote: I have paid
the deposit and insurrance fees for you but the only money you are required
to send to them is just $19.00 dollars only for transfer feeYou must make
sure that you send this required transfer to office before you can be avle
to pick up your first $5000.00 at your addrss today.We need your urgent
replyBest RegardsMrs,Mary J. Anold*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOE%2BjABoFq5K%3Ds7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA%40mail.gmail.com.

--000000000000e3ea65058f233bde
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><b>Attn Beneficiary,<br><br>GoodNews<br>I=
 have already sent you Money Gram payment of $5000.00 today, MTCN 10288059<=
br>because we have finally concluded to effect your transfer<br>funds of $4=
.8,000.000usd<br>through MONEY GRAM International Fund transfer Service<br>=
Each payment will be sending to you by $5000.00 daily until the<br>($4.8,00=
0.000usd) is completely transferred<br>we have this morning sent=C2=A0 MONE=
Y GRAM payment of $5,000.00 <br>ready to pick up by you, Money Gram payment=
 of $5000.00 sent today, MTCN 10288059<br>So contact the MONEY GRAM Agent t=
o pick up this first payment of $5000 now<br><br>Contact person Dr. Don Jam=
es<br>Direector MONEY GRAM Service,Benin<br>Phone number: +229 98856728<br>=
E-mail: <a href=3D"mailto:moneygram.1820@outlook.fr">moneygram.1820@outlook=
.fr</a><br><br>Ask him to give you the complete, sender name, question and<=
br>answer to enable you pick up the $5.000.00 sent today, Also you are inst=
ructed to re-confirm to him your information&#39;s as listed below to avoid=
 wrong transactions<br><br>(1) Receiver Name--------------<br>(2) Contact a=
ddress--------------<br>(3) Country---------------------<br>(4) Telephone n=
umbers-------------<br><br>Contact Dr. Don James for your MONEY GRAM paymen=
t of $4.8,000.000usd<br>Note: I have paid the deposit and insurrance fees f=
or you but the only money you are required to send to them is just $19.00 d=
ollars only for transfer fee<br>You must make sure that you send this requi=
red transfer to office before you can be avle to pick up your first $5000.0=
0 at your addrss today.<br>We need your urgent reply<br><br>Best Regards<br=
>Mrs,Mary J. Anold<br></b></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOE%2BjABoFq5K%3Ds7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjd=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAOE%2BjABoFq5K%3Ds7JvuJSkC4PgocZSytUPcsniYT6gY=
UcgOVjdA%40mail.gmail.com</a>.<br />

--000000000000e3ea65058f233bde--
