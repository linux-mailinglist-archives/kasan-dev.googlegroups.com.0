Return-Path: <kasan-dev+bncBDAJT2FJZINBBPE76DZAKGQEK5CBFXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC7E8174F3D
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 20:40:45 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id o7sf449051oie.21
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2020 11:40:45 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SKy32HWInSjP+PDadoJwqdGqnGHHm0bNOnEVgBODuGc=;
        b=YBy8I2Adlg7xhXXh+HBk21MqLQGKCmpUpj/Xla5B/pJg5htsb1OQ0eVK505ka9Pqxc
         e8wpmrh/SOyp2X0H1FXC+kgmwiI75runX8QX9RFhyJH4wf8XeD0pzDpLXGGHHTGxf9TM
         DyW2yzmAIORfrRYlJqZej0yBczb8MuIiHbDAM8EtfoNxPD09qvGxkj/0Lsuq3r+IBuyZ
         kWXfPd+ddRmj+zCROCI7Rjw0MFx/NI5V0ZFBrrWYUyaaUq/E18WtOjttzn5i2eo57Wxm
         NM4PQk+A3nZgT/chT4BxAeK3wT8rbaN3JUmcHh0/TumII+sCJBJnYSMwKA+oIFU346Pq
         lCQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SKy32HWInSjP+PDadoJwqdGqnGHHm0bNOnEVgBODuGc=;
        b=kL6N8/q8g0LNjpKRlLc2J0x2qbMwvfuEAwaNarrBv274c8zQyFJ33QNGgZAQXfULus
         tUd8oTXazS67mBMtRJPq4aGCfvZ+BkD8V1xiOp57t9h1bLvSjURM9gleb8nYODjKjJTC
         PXlDgpDSsj9vux+Ye9sIW/HSy0yp1ARIldiExTEqMLxHc3A09bnwSvtmSk0i1nfHUhTa
         HFlANX//ZOsXWRgxj0zIhpCZsvDrvkqVWn2LSxU6kBtA7to6uHG0ECh6PAW6Lllfw2j7
         GlAS2Shd0J42wNHf6aJugdVdzWLKccAbrAmN9cI8bi5nJe9Q6aiGOIGafvtLdr8KtFpu
         KwLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SKy32HWInSjP+PDadoJwqdGqnGHHm0bNOnEVgBODuGc=;
        b=ixU89sfYlN2unWNcvRz9hPSiRQ2/HMke8pPDYNPj0z/JkcyvQrpUrxE73X67E0nXPl
         32WuJqGvZvA/sYKuvNNz2F7OaO9S+Q1V84t93+D/NQUU5jorZFJLOfqVresP7Pqg3RnR
         FipA2xfsFJO4txkmp5Dj2L9IcPBnVNSU0VNUMdR5A9ccg/eoMSYFp8kx1ueff4F3jOtt
         xoZqEjOqkxlnBT6kOoliwWeAFBeeVtdp92bnzjSd1N5I92S+md+YINcpr+0LREonXyuV
         GKigE74N37RD+VT7W741P4X62qw1yS8BVHT1bQE9+viH4PJRSkxtMm8UJfpEVIDS1YFU
         cQsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxKW0N7nmHAXboz8FXNituRHAQD6sItABnFMACiOsCpNpLPgnP
	1GV608W3nwpUHFiDxRIyHfw=
X-Google-Smtp-Source: APXvYqwTrZdY5JqcHrfCHOaBmJoN86iGu0KR9VokKOlIuujCVZdHFQ3w5a8+YSZSpZNa5uMiv5Qjqg==
X-Received: by 2002:aca:f305:: with SMTP id r5mr9700903oih.174.1583091644526;
        Sun, 01 Mar 2020 11:40:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7558:: with SMTP id b24ls400213otl.1.gmail; Sun, 01 Mar
 2020 11:40:43 -0800 (PST)
X-Received: by 2002:a9d:6b98:: with SMTP id b24mr2130973otq.200.1583091643391;
        Sun, 01 Mar 2020 11:40:43 -0800 (PST)
Date: Sun, 1 Mar 2020 11:40:42 -0800 (PST)
From: korona <karaatdilay@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <bfb48cb8-2d96-4391-b3a7-683463aa25d2@googlegroups.com>
Subject: korona
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_794_191677529.1583091642710"
X-Original-Sender: karaatdilay@gmail.com
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

------=_Part_794_191677529.1583091642710
Content-Type: multipart/alternative; 
	boundary="----=_Part_795_79454500.1583091642710"

------=_Part_795_79454500.1583091642710
Content-Type: text/plain; charset="UTF-8"

https://fancyhabermagazin.blogspot.com/2020/03/mipim-koronavirsunden-etkilendi.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfb48cb8-2d96-4391-b3a7-683463aa25d2%40googlegroups.com.

------=_Part_795_79454500.1583091642710
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><a href=3D"https://fancyhabermagazin.blogspot.com/2020/03/=
mipim-koronavirsunden-etkilendi.html">https://fancyhabermagazin.blogspot.co=
m/2020/03/mipim-koronavirsunden-etkilendi.html</a><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/bfb48cb8-2d96-4391-b3a7-683463aa25d2%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/bfb48cb8-2d96-4391-b3a7-683463aa25d2%40googlegroups.com</a>.<br =
/>

------=_Part_795_79454500.1583091642710--

------=_Part_794_191677529.1583091642710--
