Return-Path: <kasan-dev+bncBDYJPJO25UGBBCU52KFAMGQEPG5OPKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 379F241C97E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 18:04:27 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id h6-20020a50c386000000b003da01adc065sf2927658edf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 09:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632931467; cv=pass;
        d=google.com; s=arc-20160816;
        b=RQib3/D2pFGC+vlTX1oLF1qhhDraGxmhMGmXepA/6rC4dkbgmLSdmBH32ID4KrOX+o
         ysxUIPqRFW9gzOwMNy5G8ooMKtW15ahvbvkrtrlO8nlndk1QO/Z9hCZQ4HMl+Er60jDT
         QFxgLiEYtyhPWwrejL6wcPBam8ZwgX0t9vzorDXia714Sxe9NYGqKrmJnQGqtrHWgaue
         d9ZY3ftzXnpq9CwGFCnNoeSqpqnv7uPxFDrV/hCEIZvpWldbLgT3Lb2OzYPGHrot1V2W
         VKiG1nelVfkGMZvMkkSg0SlTsEG8s/E5LGKoYI9QttmCZJl3tfX1yqMR3gyyj97lXCUw
         D+Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:date:message-id
         :sender:reply-to:mime-version:dkim-signature;
        bh=MVtfN9eZXOGaBJVAvd1sOBGlO7FOH9tYc8I1fA5ydHU=;
        b=HwZREFgnoMTGRf4ziUHVV6FxeNCqcQRgzz665QgrPQ/D1ltr3Yp3go6X+Ms0EnZjed
         TxafLEo/gJdWBzun3riaQ4x+y9CzE1E9GGoveSc8FRRl3ZEDnCFGkhc5xGiys0TEb9u8
         or1IOvXpykkjEMK9N3Dr/wrjibQQJwK5g/LvJwqUONkzRu2JRAb0JvO5bUOlNpE5BMJr
         m8ls4t9yW/a/9WEzDFuTuSbthuHiossO0fP8Iz0yN2Dm/2Gwb19VbjI5avJogdXwY7D8
         m/7qjiAMjAd4pjJ9frbpz9J1eA3lzT2HYfkDOAwJ9PF5fcSzNgip05Ncjie33w9EeFc0
         ADfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z1WF69Nd;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:reply-to:sender:message-id:date:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVtfN9eZXOGaBJVAvd1sOBGlO7FOH9tYc8I1fA5ydHU=;
        b=sdyF34KXMVzCn81wWt8OBfF3fJ9FYuikAk3p+B/GYfZxubK50tsYKzcJOCRhUDRDEp
         7Zfy+quA06QOfBmUjUv6W0qxkUOhcrzYpcuKnGfrRSEsFi0opxY+ZRZiTiPILLKnFKgR
         f1Fh+E3ttcFUEEWRRUKGGnC1Yr7ZAXuKDY2Lu3btgyckWbrke4MWuBQz9PB2qZ+3muVp
         mr+W07E4mWOvK8jigMLwn8uopLFWOL6yBddQ2pOttcnvRdVh9frZV8FRy6nGNcB25x+B
         mf7WRNqBOkovZ+PwDx2eeGwrLm3JRrN05wWjke7fd55QbOpMYcQBPIguCCRIdila1/c8
         FYzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:reply-to:sender:message-id:date
         :subject:from:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVtfN9eZXOGaBJVAvd1sOBGlO7FOH9tYc8I1fA5ydHU=;
        b=P+TgMpk96d+gXWGukoE/48duiSIpC4WCGj/LpsAE4GJhIgO8MNKhp3EiwFNfWWoyaE
         TAZzzQ/xL8RmeU6HWJwm2/V2DGNLd9dDkNHWR9aShPNwUoOofWCQhhsDF4VerC4WuTcd
         hlTq7z0boq9Ps/yeELY19EAtpOxfMIrdRAzMrHAkZFmwwnnMR8GqoOnBBvx6cv7WIIWh
         LPbKyYKMmvtZ3xedmI+nwYowAdDrHNsYmqRyXTbB0QvTo2fWrYPW2G9fLZSsRz9hi/xU
         SQ9GWaROnL2d/kDQF4DXH5r/h8ZHft0CunDcx7Qu9QQ+N685ig9HVW7GozbJmtaFTwaj
         485A==
X-Gm-Message-State: AOAM532lrf1gg4V3j530STbn9+eJiviLHh6YPgEhr467eWyasPi7AxrC
	lXspNxUqWW3clhdEOLgxu/8=
X-Google-Smtp-Source: ABdhPJw+ozijAcXXfAh5WEhPHAIR1Lgdpnpf+SyuFB5P6oahIllfbT/e33MquffhpN+Q2k8xu5CLTw==
X-Received: by 2002:a17:907:9686:: with SMTP id hd6mr550837ejc.331.1632931466820;
        Wed, 29 Sep 2021 09:04:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2f8a:: with SMTP id w10ls1225362eji.9.gmail; Wed, 29
 Sep 2021 09:04:25 -0700 (PDT)
X-Received: by 2002:a17:906:2cd6:: with SMTP id r22mr572878ejr.398.1632931465649;
        Wed, 29 Sep 2021 09:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632931465; cv=none;
        d=google.com; s=arc-20160816;
        b=Hk+56vB09sLxNPdROYrcL781MlHrfJdJXQSNj6PnZjXya8m5fh0v6DfhUZBT/LbkIv
         ZSeCFqghlXU5ZcO23GZxW0ktAOSj4JwmuYXWWy2rYkP7e6utccPhmlbkckQzfrJ8adgZ
         Bl78ACjODkYm6YCYo0jvLegRpiw7egfD0ymEImE51ohe87Kc8uaNkUSrgpLz5xBArwdw
         r9oRLI1ugjDH8v1157wINi1NJv6rUGWUZadmLorzpznpSG5tXmSen1lbU1Pn2zFHwyas
         3O7FdQqLSAMhNzOnYq5jgw7ocAtxSBX0nhdFBVXAeoBiyaWNLxq20eN1luNi7f6KE54j
         wxcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:date:message-id:sender:reply-to:mime-version
         :dkim-signature;
        bh=SSv4gBtczJwSJquJwb+BJ3MhywkJoyWW4t05dEtsipU=;
        b=JKP7JKIdFwfSsOFCykNcuaFsr4r+3lS2wd6xaFPe1h6rK0yxXYnqYU40tvCd7VoKHP
         nMddm56aVmd/MesuN+vUXNNyfXAYlQpH/R+Ax4oD9V4eZ8MaA9zD5cpVzhIskBgXZMv0
         TwGH/L9+X8LgzliMqmUoBfwdRFj8a5uvNHvRwXBT4DAon1N2mx9RBEsx4zhqkESWt6Nv
         ge+SoCqOUGv1Twmd8zc6GED/zMLHre2xakGvXHttRErJFPKVtxXGtoYsPErqncwZxtsD
         poZnLT6iDQhXrZJy6ca4P3or9W537KyPXyONpos71f/Cj4ZooyxzrK6Bqt5v3NEb+JCn
         f0GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z1WF69Nd;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id s18si8989ejo.1.2021.09.29.09.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Sep 2021 09:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id 12-20020ac2484c000000b003fcb3298d00so2801412lfy.13
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 09:04:25 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a2e:96c2:: with SMTP id d2mr691467ljj.405.1632931464816;
 Wed, 29 Sep 2021 09:04:24 -0700 (PDT)
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
Sender: Google Calendar <calendar-notification@google.com>
Message-ID: <000000000000e7f04a05cd247b42@google.com>
Date: Wed, 29 Sep 2021 16:04:24 +0000
Subject: Invitation: Fellowship of the Clang Built Linux Kernels @ Wed Oct 6,
 2021 12pm - 12:25pm (PDT) (kasan-dev)
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev <kasan-dev@googlegroups.com>, nhuck@google.com, 
	clang linux fellowship <clang-linux-fellowship@google.com>, 
	Clang Built Linux <clang-built-linux@googlegroups.com>, Dan Rue <dan.rue@linaro.org>, 
	abdulras@google.com
Cc: randy.linnell@linaro.org
Content-Type: multipart/mixed; boundary="000000000000e7f03105cd247b41"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Z1WF69Nd;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::149
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
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

--000000000000e7f03105cd247b41
Content-Type: multipart/alternative; boundary="000000000000e7f03005cd247b3f"

--000000000000e7f03005cd247b3f
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
Content-Transfer-Encoding: quoted-printable

You have been invited to the following event.

Title: Fellowship of the Clang Built Linux Kernels
Let's meet up some time to discuss topics like:
* patch sets
* compiler bugs
* upstreaming efforts
* etc

Calendar invite:
https://calendar.google.com/calendar/embed?src=3Dgoogle.com_bbf8m6m4n8nq5p2=
bfjpele0n5s%40group.calendar.google.com

Hangouts Meet invite:
https://meet.google.com/yjf-jyqk-iaz
When: Wed Oct 6, 2021 12pm =E2=80=93 12:25pm Pacific Time - Los Angeles
Where: SVL-MAT2-4-Phone Room 4L5 (1) [GVC, No external guests]

Joining info: Join with Google Meet
https://meet.google.com/yjf-jyqk-iaz?hs=3D224

Join by phone
(US) +1 475-299-8945 (PIN: 274655)

More phone numbers: https://tel.meet/yjf-jyqk-iaz?pin=3D8933515835024&hs=3D=
0

Calendar: kasan-dev
Who:
     * Nick Desaulniers - creator
     * nhuck@google.com
     * clang linux fellowship
     * Clang Built Linux
     * Bob Haarman
     * Brian Foley
     * Dan Rue
     * abdulras@google.com
     * kasan-dev
     * randy.linnell@linaro.org - optional

Event details: =20
https://calendar.google.com/calendar/event?action=3DVIEW&eid=3DOWs5dDFjM2px=
bzk3dDIzNHFwY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi1kZXZAZ29vZ2xlZ3JvdXB=
zLmNvbQ&tok=3DNjMjZ29vZ2xlLmNvbV9iYmY4bTZtNG44bnE1cDJiZmpwZWxlMG41c0Bncm91c=
C5jYWxlbmRhci5nb29nbGUuY29tMjNhZDA1NGEwMDFhZTQ2MWFjZWM3MTE5MTUzYjg3ZDQ2N2Fl=
MWRkZQ&ctz=3DAmerica%2FLos_Angeles&hl=3Den&es=3D0

Invitation from Google Calendar: https://calendar.google.com/calendar/

You are receiving this courtesy email at the account =20
kasan-dev@googlegroups.com because you are an attendee of this event.

To stop receiving future updates for this event, decline this event. =20
Alternatively you can sign up for a Google account at =20
https://calendar.google.com/calendar/ and control your notification =20
settings for your entire calendar.

Forwarding this invitation could allow any recipient to send a response to =
=20
the organizer and be added to the guest list, or invite others regardless =
=20
of their own invitation status, or to modify your RSVP. Learn more at =20
https://support.google.com/calendar/answer/37135#forwarding

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/000000000000e7f04a05cd247b42%40google.com.

--000000000000e7f03005cd247b3f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span itemscope itemtype=3D"http://schema.org/InformAction"><span style=3D"=
display:none" itemprop=3D"about" itemscope itemtype=3D"http://schema.org/Pe=
rson"><meta itemprop=3D"description" content=3D"Invitation from Nick Desaul=
niers"/></span><span itemprop=3D"object" itemscope itemtype=3D"http://schem=
a.org/Event"><div style=3D""><table cellspacing=3D"0" cellpadding=3D"8" bor=
der=3D"0" summary=3D"" style=3D"width:100%;font-family:Arial,Sans-serif;bor=
der:1px Solid #ccc;border-width:1px 2px 2px 1px;background-color:#fff;"><tr=
><td><meta itemprop=3D"eventStatus" content=3D"http://schema.org/EventSched=
uled"/><h4 style=3D"padding:6px 0;margin:0 0 4px 0;font-family:Arial,Sans-s=
erif;font-size:13px;line-height:1.4;border:1px Solid #fff;background:#fff;c=
olor:#090;font-weight:normal"><strong>You have been invited to the followin=
g event.</strong></h4><div style=3D"padding:2px"><span itemprop=3D"publishe=
r" itemscope itemtype=3D"http://schema.org/Organization"><meta itemprop=3D"=
name" content=3D"Google Calendar"/></span><meta itemprop=3D"eventId/googleC=
alendar" content=3D"9k9t1c3jqo97t234qpcd0rn2m6_20211006T190000Z"/><h3 style=
=3D"padding:0 0 6px 0;margin:0;font-family:Arial,Sans-serif;font-size:16px;=
font-weight:bold;color:#222"><span itemprop=3D"name">Fellowship of the Clan=
g Built Linux Kernels</span></h3><table style=3D"display:inline-table" cell=
padding=3D"0" cellspacing=3D"0" border=3D"0" summary=3D"Event details"><tr>=
<td style=3D"padding:0 1em 10px 0;font-family:Arial,Sans-serif;font-size:13=
px;color:#888;white-space:nowrap;width:90px" valign=3D"top"><div><i style=
=3D"font-style:normal">When</i></div></td><td style=3D"padding-bottom:10px;=
font-family:Arial,Sans-serif;font-size:13px;color:#222" valign=3D"top"><div=
 style=3D"text-indent:-1px"><time itemprop=3D"startDate" datetime=3D"202110=
06T190000Z"></time><time itemprop=3D"endDate" datetime=3D"20211006T192500Z"=
></time>Wed Oct 6, 2021 12pm =E2=80=93 12:25pm <span style=3D"color:#888">P=
acific Time - Los Angeles</span></div></td></tr><tr><td style=3D"padding:0 =
1em 10px 0;font-family:Arial,Sans-serif;font-size:13px;color:#888;white-spa=
ce:nowrap;width:90px" valign=3D"top"><div><i style=3D"font-style:normal">Wh=
ere</i></div></td><td style=3D"padding-bottom:10px;font-family:Arial,Sans-s=
erif;font-size:13px;color:#222" valign=3D"top"><div style=3D"text-indent:-1=
px"><span itemprop=3D"location" itemscope itemtype=3D"http://schema.org/Pla=
ce"><span itemprop=3D"name" class=3D"notranslate">SVL-MAT2-4-Phone Room 4L5=
 (1) [GVC, No external guests]</span><span dir=3D"ltr"> (<a href=3D"https:/=
/www.google.com/maps/search/SVL-MAT2-4-Phone+Room+4L5+%281%29+%5BGVC,+No+ex=
ternal+guests%5D?hl=3Den" style=3D"color:#20c;white-space:nowrap" target=3D=
"_blank" itemprop=3D"map">map</a>)</span></span></div></td></tr><tr><td sty=
le=3D"padding:0 1em 4px 0;font-family:Arial,Sans-serif;font-size:13px;color=
:#888;white-space:nowrap;width:90px" valign=3D"top"><div><i style=3D"font-s=
tyle:normal">Joining info</i></div></td><td style=3D"padding-bottom:4px;fon=
t-family:Arial,Sans-serif;font-size:13px;color:#222" valign=3D"top"><div st=
yle=3D"text-indent:-1px">Join with Google Meet</div></td></tr><tr><td style=
=3D"padding:0 1em 10px 0;font-family:Arial,Sans-serif;font-size:13px;color:=
#888;white-space:nowrap;width:90px"></td><td style=3D"padding-bottom:10px;f=
ont-family:Arial,Sans-serif;font-size:13px;color:#222" valign=3D"top"><div =
style=3D"text-indent:-1px"><div style=3D"text-indent:-1px"><span itemprop=
=3D"potentialaction" itemscope itemtype=3D"http://schema.org/JoinAction"><s=
pan itemprop=3D"name" content=3D"meet.google.com/yjf-jyqk-iaz"><span itempr=
op=3D"target" itemscope itemtype=3D"http://schema.org/EntryPoint"><span ite=
mprop=3D"url" content=3D"https://meet.google.com/yjf-jyqk-iaz?hs=3D224"><sp=
an itemprop=3D"httpMethod" content=3D"GET"><a href=3D"https://meet.google.c=
om/yjf-jyqk-iaz?hs=3D224" style=3D"color:#20c;white-space:nowrap" target=3D=
"_blank">meet.google.com/yjf-jyqk-iaz</a></span></span></span></span></span=
> </div></div></td></tr><tr><td style=3D"padding:0 1em 10px 0;font-family:A=
rial,Sans-serif;font-size:13px;color:#888;white-space:nowrap;width:90px"></=
td><td style=3D"padding-bottom:10px;font-family:Arial,Sans-serif;font-size:=
13px;color:#222" valign=3D"top"></td></tr><td style=3D"padding:0 1em 4px 0;=
font-family:Arial,Sans-serif;font-size:13px;color:#888;white-space:nowrap;w=
idth:90px"></td><td style=3D"padding-bottom:4px;font-family:Arial,Sans-seri=
f;font-size:13px;color:#222" valign=3D"top"><div style=3D"text-indent:-1px"=
>Join by phone</div></td><tr><td style=3D"padding:0 1em 10px 0;font-family:=
Arial,Sans-serif;font-size:13px;color:#888;white-space:nowrap;width:90px"><=
/td><td style=3D"padding-bottom:10px;font-family:Arial,Sans-serif;font-size=
:13px;color:#222" valign=3D"top"><div style=3D"text-indent:-1px"><div style=
=3D"text-indent:-1px"><span style=3D"color:#888">(US) </span><a href=3D"tel=
:+1-475-299-8945;274655#" style=3D"color:#20c;white-space:nowrap" target=3D=
"_blank">+1 475-299-8945</a> <span style=3D"color:#888">(PIN: 274655)</span=
></div></div></td></tr><tr><td style=3D"padding:0 1em 10px 0;font-family:Ar=
ial,Sans-serif;font-size:13px;color:#888;white-space:nowrap;width:90px"></t=
d><td style=3D"padding-bottom:10px;font-family:Arial,Sans-serif;font-size:1=
3px;color:#222" valign=3D"top"></td></tr><tr><td style=3D"padding:0 1em 10p=
x 0;font-family:Arial,Sans-serif;font-size:13px;color:#888;white-space:nowr=
ap;width:90px"></td><td style=3D"padding-bottom:10px;font-family:Arial,Sans=
-serif;font-size:13px;color:#222" valign=3D"top"><div style=3D"text-indent:=
-1px"><a href=3D"https://tel.meet/yjf-jyqk-iaz?pin=3D8933515835024&amp;hs=
=3D0" style=3D"color:#20c;white-space:nowrap" target=3D"_blank">More phone =
numbers</a></div></td></tr><tr><td style=3D"padding:0 1em 10px 0;font-famil=
y:Arial,Sans-serif;font-size:13px;color:#888;white-space:nowrap;width:90px"=
 valign=3D"top"><div><i style=3D"font-style:normal">Calendar</i></div></td>=
<td style=3D"padding-bottom:10px;font-family:Arial,Sans-serif;font-size:13p=
x;color:#222" valign=3D"top"><div style=3D"text-indent:-1px">kasan-dev</div=
></td></tr><tr><td style=3D"padding:0 1em 10px 0;font-family:Arial,Sans-ser=
if;font-size:13px;color:#888;white-space:nowrap;width:90px" valign=3D"top">=
<div><i style=3D"font-style:normal">Who</i></div></td><td style=3D"padding-=
bottom:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222" valign=
=3D"top"><table cellspacing=3D"0" cellpadding=3D"0"><tr><td style=3D"paddin=
g-right:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222;width:1=
0px"><div style=3D"text-indent:-1px"><span style=3D"font-family:Courier New=
,monospace">&#x2022;</span></div></td><td style=3D"padding-right:10px;font-=
family:Arial,Sans-serif;font-size:13px;color:#222"><div style=3D"text-inden=
t:-1px"><div><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" =
itemscope itemtype=3D"http://schema.org/Person"><span itemprop=3D"name" cla=
ss=3D"notranslate">Nick Desaulniers</span><meta itemprop=3D"email" content=
=3D"ndesaulniers@google.com"/></span><span style=3D"font-size:11px;color:#8=
88"> - creator</span></div></div></div></td></tr><tr><td style=3D"padding-r=
ight:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222;width:10px=
"><div style=3D"text-indent:-1px"><span style=3D"font-family:Courier New,mo=
nospace">&#x2022;</span></div></td><td style=3D"padding-right:10px;font-fam=
ily:Arial,Sans-serif;font-size:13px;color:#222"><div style=3D"text-indent:-=
1px"><div><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" ite=
mscope itemtype=3D"http://schema.org/Person"><span itemprop=3D"name" class=
=3D"notranslate">nhuck@google.com</span><meta itemprop=3D"email" content=3D=
"nhuck@google.com"/></span></div></div></div></td></tr><tr><td style=3D"pad=
ding-right:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222;widt=
h:10px"><div style=3D"text-indent:-1px"><span style=3D"font-family:Courier =
New,monospace">&#x2022;</span></div></td><td style=3D"padding-right:10px;fo=
nt-family:Arial,Sans-serif;font-size:13px;color:#222"><div style=3D"text-in=
dent:-1px"><div><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attende=
e" itemscope itemtype=3D"http://schema.org/Person"><span itemprop=3D"name" =
class=3D"notranslate">clang linux fellowship</span><meta itemprop=3D"email"=
 content=3D"clang-linux-fellowship@google.com"/></span></div></div></div></=
td></tr><tr><td style=3D"padding-right:10px;font-family:Arial,Sans-serif;fo=
nt-size:13px;color:#222;width:10px"><div style=3D"text-indent:-1px"><span s=
tyle=3D"font-family:Courier New,monospace">&#x2022;</span></div></td><td st=
yle=3D"padding-right:10px;font-family:Arial,Sans-serif;font-size:13px;color=
:#222"><div style=3D"text-indent:-1px"><div><div style=3D"margin:0 0 0.3em =
0"><span itemprop=3D"attendee" itemscope itemtype=3D"http://schema.org/Pers=
on"><span itemprop=3D"name" class=3D"notranslate">Clang Built Linux</span><=
meta itemprop=3D"email" content=3D"clang-built-linux@googlegroups.com"/></s=
pan></div></div></div></td></tr><tr><td style=3D"padding-right:10px;font-fa=
mily:Arial,Sans-serif;font-size:13px;color:#222;width:10px"><div style=3D"t=
ext-indent:-1px"><span style=3D"font-family:Courier New,monospace">&#x2022;=
</span></div></td><td style=3D"padding-right:10px;font-family:Arial,Sans-se=
rif;font-size:13px;color:#222"><div style=3D"text-indent:-1px"><div><div st=
yle=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" itemscope itemtype=
=3D"http://schema.org/Person"><span itemprop=3D"name" class=3D"notranslate"=
>Bob Haarman</span><meta itemprop=3D"email" content=3D"inglorion@google.com=
"/></span></div></div></div></td></tr><tr><td style=3D"padding-right:10px;f=
ont-family:Arial,Sans-serif;font-size:13px;color:#222;width:10px"><div styl=
e=3D"text-indent:-1px"><span style=3D"font-family:Courier New,monospace">&#=
x2022;</span></div></td><td style=3D"padding-right:10px;font-family:Arial,S=
ans-serif;font-size:13px;color:#222"><div style=3D"text-indent:-1px"><div><=
div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" itemscope item=
type=3D"http://schema.org/Person"><span itemprop=3D"name" class=3D"notransl=
ate">Brian Foley</span><meta itemprop=3D"email" content=3D"bpfoley@google.c=
om"/></span></div></div></div></td></tr><tr><td style=3D"padding-right:10px=
;font-family:Arial,Sans-serif;font-size:13px;color:#222;width:10px"><div st=
yle=3D"text-indent:-1px"><span style=3D"font-family:Courier New,monospace">=
&#x2022;</span></div></td><td style=3D"padding-right:10px;font-family:Arial=
,Sans-serif;font-size:13px;color:#222"><div style=3D"text-indent:-1px"><div=
><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" itemscope it=
emtype=3D"http://schema.org/Person"><span itemprop=3D"name" class=3D"notran=
slate">Dan Rue</span><meta itemprop=3D"email" content=3D"dan.rue@linaro.org=
"/></span></div></div></div></td></tr><tr><td style=3D"padding-right:10px;f=
ont-family:Arial,Sans-serif;font-size:13px;color:#222;width:10px"><div styl=
e=3D"text-indent:-1px"><span style=3D"font-family:Courier New,monospace">&#=
x2022;</span></div></td><td style=3D"padding-right:10px;font-family:Arial,S=
ans-serif;font-size:13px;color:#222"><div style=3D"text-indent:-1px"><div><=
div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" itemscope item=
type=3D"http://schema.org/Person"><span itemprop=3D"name" class=3D"notransl=
ate">abdulras@google.com</span><meta itemprop=3D"email" content=3D"abdulras=
@google.com"/></span></div></div></div></td></tr><tr><td style=3D"padding-r=
ight:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222;width:10px=
"><div style=3D"text-indent:-1px"><span style=3D"font-family:Courier New,mo=
nospace">&#x2022;</span></div></td><td style=3D"padding-right:10px;font-fam=
ily:Arial,Sans-serif;font-size:13px;color:#222"><div style=3D"text-indent:-=
1px"><div><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"attendee" ite=
mscope itemtype=3D"http://schema.org/Person"><span itemprop=3D"name" class=
=3D"notranslate">kasan-dev</span><meta itemprop=3D"email" content=3D"kasan-=
dev@googlegroups.com"/></span></div></div></div></td></tr><tr><td style=3D"=
padding-right:10px;font-family:Arial,Sans-serif;font-size:13px;color:#222;w=
idth:10px"><div style=3D"text-indent:-1px"><span style=3D"font-family:Couri=
er New,monospace">&#x2022;</span></div></td><td style=3D"padding-right:10px=
;font-family:Arial,Sans-serif;font-size:13px;color:#222"><div style=3D"text=
-indent:-1px"><div><div style=3D"margin:0 0 0.3em 0"><span itemprop=3D"atte=
ndee" itemscope itemtype=3D"http://schema.org/Person"><span itemprop=3D"nam=
e" class=3D"notranslate">randy.linnell@linaro.org</span><meta itemprop=3D"e=
mail" content=3D"randy.linnell@linaro.org"/></span><span style=3D"font-size=
:11px;color:#888"> - optional</span></div></div></div></td></tr></table></t=
d></tr></table><div style=3D"float:right;font-weight:bold;font-size:13px"> =
<a href=3D"https://calendar.google.com/calendar/event?action=3DVIEW&amp;eid=
=3DOWs5dDFjM2pxbzk3dDIzNHFwY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi1kZXZA=
Z29vZ2xlZ3JvdXBzLmNvbQ&amp;tok=3DNjMjZ29vZ2xlLmNvbV9iYmY4bTZtNG44bnE1cDJiZm=
pwZWxlMG41c0Bncm91cC5jYWxlbmRhci5nb29nbGUuY29tMjNhZDA1NGEwMDFhZTQ2MWFjZWM3M=
TE5MTUzYjg3ZDQ2N2FlMWRkZQ&amp;ctz=3DAmerica%2FLos_Angeles&amp;hl=3Den&amp;e=
s=3D0" style=3D"color:#20c;white-space:nowrap" itemprop=3D"url">more detail=
s &raquo;</a><br></div><div style=3D"padding-bottom:15px;font-family:Arial,=
Sans-serif;font-size:13px;color:#222;white-space:pre-wrap!important;white-s=
pace:-moz-pre-wrap!important;white-space:-pre-wrap!important;white-space:-o=
-pre-wrap!important;white-space:pre;word-wrap:break-word"><span>Let&#39;s m=
eet up some time to discuss topics like:<br>* patch sets<br>* compiler bugs=
<br>* upstreaming efforts<br>* etc<p>Calendar invite:<br><a href=3D"https:/=
/calendar.google.com/calendar/embed?src=3Dgoogle.com_bbf8m6m4n8nq5p2bfjpele=
0n5s%40group.calendar.google.com" target=3D"_blank">https://calendar.google=
.com/calendar/embed?src=3Dgoogle.com_bbf8m6m4n8nq5p2bfjpele0n5s%40group.cal=
endar.google.com</a> </p><p>Hangouts Meet invite:<br><a href=3D"https://mee=
t.google.com/yjf-jyqk-iaz" target=3D"_blank">https://meet.google.com/yjf-jy=
qk-iaz</a></p></span><meta itemprop=3D"description" content=3D"Let&#39;s me=
et up some time to discuss topics like:
* patch sets
* compiler bugs
* upstreaming efforts
* etc

Calendar invite:
https://calendar.google.com/calendar/embed?src=3Dgoogle.com_bbf8m6m4n8nq5p2=
bfjpele0n5s%40group.calendar.google.com=20

Hangouts Meet invite:
https://meet.google.com/yjf-jyqk-iaz"/></div></div><p style=3D"color:#222;f=
ont-size:13px;margin:0"><span style=3D"color:#888">Going (kasan-dev@googleg=
roups.com)?&nbsp;&nbsp;&nbsp;</span><wbr><strong><span itemprop=3D"potentia=
laction" itemscope itemtype=3D"http://schema.org/RsvpAction"><meta itemprop=
=3D"attendance" content=3D"http://schema.org/RsvpAttendance/Yes"/><span ite=
mprop=3D"handler" itemscope itemtype=3D"http://schema.org/HttpActionHandler=
"><link itemprop=3D"method" href=3D"http://schema.org/HttpRequestMethod/GET=
"/><a href=3D"https://calendar.google.com/calendar/event?action=3DRESPOND&a=
mp;eid=3DOWs5dDFjM2pxbzk3dDIzNHFwY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi=
1kZXZAZ29vZ2xlZ3JvdXBzLmNvbQ&amp;rst=3D1&amp;tok=3DNjMjZ29vZ2xlLmNvbV9iYmY4=
bTZtNG44bnE1cDJiZmpwZWxlMG41c0Bncm91cC5jYWxlbmRhci5nb29nbGUuY29tMjNhZDA1NGE=
wMDFhZTQ2MWFjZWM3MTE5MTUzYjg3ZDQ2N2FlMWRkZQ&amp;ctz=3DAmerica%2FLos_Angeles=
&amp;hl=3Den&amp;es=3D0" style=3D"color:#20c;white-space:nowrap" itemprop=
=3D"url">Yes</a></span></span><span style=3D"margin:0 0.4em;font-weight:nor=
mal"> - </span><span itemprop=3D"potentialaction" itemscope itemtype=3D"htt=
p://schema.org/RsvpAction"><meta itemprop=3D"attendance" content=3D"http://=
schema.org/RsvpAttendance/Maybe"/><span itemprop=3D"handler" itemscope item=
type=3D"http://schema.org/HttpActionHandler"><link itemprop=3D"method" href=
=3D"http://schema.org/HttpRequestMethod/GET"/><a href=3D"https://calendar.g=
oogle.com/calendar/event?action=3DRESPOND&amp;eid=3DOWs5dDFjM2pxbzk3dDIzNHF=
wY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbQ&amp=
;rst=3D3&amp;tok=3DNjMjZ29vZ2xlLmNvbV9iYmY4bTZtNG44bnE1cDJiZmpwZWxlMG41c0Bn=
cm91cC5jYWxlbmRhci5nb29nbGUuY29tMjNhZDA1NGEwMDFhZTQ2MWFjZWM3MTE5MTUzYjg3ZDQ=
2N2FlMWRkZQ&amp;ctz=3DAmerica%2FLos_Angeles&amp;hl=3Den&amp;es=3D0" style=
=3D"color:#20c;white-space:nowrap" itemprop=3D"url">Maybe</a></span></span>=
<span style=3D"margin:0 0.4em;font-weight:normal"> - </span><span itemprop=
=3D"potentialaction" itemscope itemtype=3D"http://schema.org/RsvpAction"><m=
eta itemprop=3D"attendance" content=3D"http://schema.org/RsvpAttendance/No"=
/><span itemprop=3D"handler" itemscope itemtype=3D"http://schema.org/HttpAc=
tionHandler"><link itemprop=3D"method" href=3D"http://schema.org/HttpReques=
tMethod/GET"/><a href=3D"https://calendar.google.com/calendar/event?action=
=3DRESPOND&amp;eid=3DOWs5dDFjM2pxbzk3dDIzNHFwY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMD=
AwWiBrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbQ&amp;rst=3D2&amp;tok=3DNjMjZ29vZ2xl=
LmNvbV9iYmY4bTZtNG44bnE1cDJiZmpwZWxlMG41c0Bncm91cC5jYWxlbmRhci5nb29nbGUuY29=
tMjNhZDA1NGEwMDFhZTQ2MWFjZWM3MTE5MTUzYjg3ZDQ2N2FlMWRkZQ&amp;ctz=3DAmerica%2=
FLos_Angeles&amp;hl=3Den&amp;es=3D0" style=3D"color:#20c;white-space:nowrap=
" itemprop=3D"url">No</a></span></span></strong>&nbsp;&nbsp;&nbsp;&nbsp;<wb=
r><a href=3D"https://calendar.google.com/calendar/event?action=3DVIEW&amp;e=
id=3DOWs5dDFjM2pxbzk3dDIzNHFwY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi1kZX=
ZAZ29vZ2xlZ3JvdXBzLmNvbQ&amp;tok=3DNjMjZ29vZ2xlLmNvbV9iYmY4bTZtNG44bnE1cDJi=
ZmpwZWxlMG41c0Bncm91cC5jYWxlbmRhci5nb29nbGUuY29tMjNhZDA1NGEwMDFhZTQ2MWFjZWM=
3MTE5MTUzYjg3ZDQ2N2FlMWRkZQ&amp;ctz=3DAmerica%2FLos_Angeles&amp;hl=3Den&amp=
;es=3D0" style=3D"color:#20c;white-space:nowrap" itemprop=3D"url">more opti=
ons &raquo;</a></p></td></tr><tr><td style=3D"background-color:#f6f6f6;colo=
r:#888;border-top:1px Solid #ccc;font-family:Arial,Sans-serif;font-size:11p=
x"><p>Invitation from <a href=3D"https://calendar.google.com/calendar/" tar=
get=3D"_blank" style=3D"">Google Calendar</a></p><p>You are receiving this =
courtesy email at the account kasan-dev@googlegroups.com because you are an=
 attendee of this event.</p><p>To stop receiving future updates for this ev=
ent, decline this event. Alternatively you can sign up for a Google account=
 at https://calendar.google.com/calendar/ and control your notification set=
tings for your entire calendar.</p><p>Forwarding this invitation could allo=
w any recipient to send a response to the organizer and be added to the gue=
st list, or invite others regardless of their own invitation status, or to =
modify your RSVP. <a href=3D"https://support.google.com/calendar/answer/371=
35#forwarding">Learn More</a>.</p></td></tr></table></div></span></span>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/000000000000e7f04a05cd247b42%40google.com?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/0=
00000000000e7f04a05cd247b42%40google.com</a>.<br />

--000000000000e7f03005cd247b3f
Content-Type: text/calendar; charset="UTF-8"; method=REQUEST
Content-Transfer-Encoding: 7bit

BEGIN:VCALENDAR
PRODID:-//Google Inc//Google Calendar 70.9054//EN
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:America/Los_Angeles
X-LIC-LOCATION:America/Los_Angeles
BEGIN:DAYLIGHT
TZOFFSETFROM:-0800
TZOFFSETTO:-0700
TZNAME:PDT
DTSTART:19700308T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:-0700
TZOFFSETTO:-0800
TZNAME:PST
DTSTART:19701101T020000
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=America/Los_Angeles:20211006T120000
DTEND;TZID=America/Los_Angeles:20211006T122500
DTSTAMP:20210929T160424Z
ORGANIZER;CN=Clang Built Linux Calendar:mailto:google.com_bbf8m6m4n8nq5p2bf
 jpele0n5s@group.calendar.google.com
UID:9k9t1c3jqo97t234qpcd0rn2m6_R20210922T190000@google.com
ATTENDEE;CUTYPE=RESOURCE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE;C
 N=US-SVL-MP1-5-G-Joule (5) [GVC];X-NUM-GUESTS=0:mailto:google.com_726f6f6d5
 f75735f73766c5f6d70315f355f356730@resource.calendar.google.com
ATTENDEE;CUTYPE=RESOURCE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE;C
 N=US-MTV-1667-1-G-Drive my car (5) [GVC];X-NUM-GUESTS=0:mailto:google.com_7
 26f6f6d5f75735f6d74765f313636375f315f316734@resource.calendar.google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=nhuck@google.com;X-NUM-GUESTS=0:mailto:nhuck@google.com
ATTENDEE;CUTYPE=RESOURCE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE;C
 N=US-SVL-CRSM1240-3-Q-Pastelitos (5) [GVC];X-NUM-GUESTS=0:mailto:google.com
 _726f6f6d5f75735f73766c5f6372736d313234305f335f337133@resource.calendar.goo
 gle.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=clang linux fellowship;X-NUM-GUESTS=0:mailto:clang-linux-fellowship
 @google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=Clang Built Linux;X-NUM-GUESTS=0:mailto:clang-built-linux@googlegro
 ups.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=OPT-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=randy.linnell@linaro.org;X-NUM-GUESTS=0:mailto:randy.linnell@linaro
 .org
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE
 ;CN=Bob Haarman;X-NUM-GUESTS=0:mailto:inglorion@google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE
 ;CN=Brian Foley;X-NUM-GUESTS=0:mailto:bpfoley@google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=Dan Rue;X-NUM-GUESTS=0:mailto:dan.rue@linaro.org
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=TENTATIVE;RSVP=TRU
 E;CN=abdulras@google.com;X-NUM-GUESTS=0:mailto:abdulras@google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=kasan-dev;X-NUM-GUESTS=0:mailto:kasan-dev@googlegroups.com
X-MICROSOFT-CDO-OWNERAPPTID:66058506
RECURRENCE-ID;TZID=America/Los_Angeles:20211006T120000
CLASS:PUBLIC
CREATED:20190422T181636Z
DESCRIPTION:Let's meet up some time to discuss topics like:\n* patch sets\n
 * compiler bugs\n* upstreaming efforts\n* etc\n\nCalendar invite:\nhttps://
 calendar.google.com/calendar/embed?src=google.com_bbf8m6m4n8nq5p2bfjpele0n5
 s%40group.calendar.google.com \n\nHangouts Meet invite:\nhttps://meet.googl
 e.com/yjf-jyqk-iaz\n\n-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~
 :~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-\nDo not edit this section of the descrip
 tion.\n\nThis event has a video call.\nJoin: https://meet.google.com/yjf-jy
 qk-iaz\n(US) +1 475-299-8945 PIN: 274655#\nView more phone numbers: https:/
 /tel.meet/yjf-jyqk-iaz?pin=8933515835024&hs=7\n\nView your event at https:/
 /calendar.google.com/calendar/event?action=VIEW&eid=OWs5dDFjM2pxbzk3dDIzNHF
 wY2Qwcm4ybTZfMjAyMTEwMDZUMTkwMDAwWiBrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbQ&tok
 =NjMjZ29vZ2xlLmNvbV9iYmY4bTZtNG44bnE1cDJiZmpwZWxlMG41c0Bncm91cC5jYWxlbmRhci
 5nb29nbGUuY29tMjNhZDA1NGEwMDFhZTQ2MWFjZWM3MTE5MTUzYjg3ZDQ2N2FlMWRkZQ&ctz=Am
 erica%2FLos_Angeles&hl=en&es=1.\n-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:
 ~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-
LAST-MODIFIED:20210929T160418Z
LOCATION:SVL-MAT2-4-Phone Room 4L5 (1) [GVC\, No external guests]
SEQUENCE:3
STATUS:CONFIRMED
SUMMARY:Fellowship of the Clang Built Linux Kernels
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR

--000000000000e7f03005cd247b3f--
--000000000000e7f03105cd247b41
Content-Type: application/ics; name="invite.ics"
Content-Disposition: attachment; filename="invite.ics"
Content-Transfer-Encoding: base64

QkVHSU46VkNBTEVOREFSDQpQUk9ESUQ6LS8vR29vZ2xlIEluYy8vR29vZ2xlIENhbGVuZGFyIDcw
LjkwNTQvL0VODQpWRVJTSU9OOjIuMA0KQ0FMU0NBTEU6R1JFR09SSUFODQpNRVRIT0Q6UkVRVUVT
VA0KQkVHSU46VlRJTUVaT05FDQpUWklEOkFtZXJpY2EvTG9zX0FuZ2VsZXMNClgtTElDLUxPQ0FU
SU9OOkFtZXJpY2EvTG9zX0FuZ2VsZXMNCkJFR0lOOkRBWUxJR0hUDQpUWk9GRlNFVEZST006LTA4
MDANClRaT0ZGU0VUVE86LTA3MDANClRaTkFNRTpQRFQNCkRUU1RBUlQ6MTk3MDAzMDhUMDIwMDAw
DQpSUlVMRTpGUkVRPVlFQVJMWTtCWU1PTlRIPTM7QllEQVk9MlNVDQpFTkQ6REFZTElHSFQNCkJF
R0lOOlNUQU5EQVJEDQpUWk9GRlNFVEZST006LTA3MDANClRaT0ZGU0VUVE86LTA4MDANClRaTkFN
RTpQU1QNCkRUU1RBUlQ6MTk3MDExMDFUMDIwMDAwDQpSUlVMRTpGUkVRPVlFQVJMWTtCWU1PTlRI
PTExO0JZREFZPTFTVQ0KRU5EOlNUQU5EQVJEDQpFTkQ6VlRJTUVaT05FDQpCRUdJTjpWRVZFTlQN
CkRUU1RBUlQ7VFpJRD1BbWVyaWNhL0xvc19BbmdlbGVzOjIwMjExMDA2VDEyMDAwMA0KRFRFTkQ7
VFpJRD1BbWVyaWNhL0xvc19BbmdlbGVzOjIwMjExMDA2VDEyMjUwMA0KRFRTVEFNUDoyMDIxMDky
OVQxNjA0MjRaDQpPUkdBTklaRVI7Q049Q2xhbmcgQnVpbHQgTGludXggQ2FsZW5kYXI6bWFpbHRv
Omdvb2dsZS5jb21fYmJmOG02bTRuOG5xNXAyYmYNCiBqcGVsZTBuNXNAZ3JvdXAuY2FsZW5kYXIu
Z29vZ2xlLmNvbQ0KVUlEOjlrOXQxYzNqcW85N3QyMzRxcGNkMHJuMm02X1IyMDIxMDkyMlQxOTAw
MDBAZ29vZ2xlLmNvbQ0KQVRURU5ERUU7Q1VUWVBFPVJFU09VUkNFO1JPTEU9UkVRLVBBUlRJQ0lQ
QU5UO1BBUlRTVEFUPURFQ0xJTkVEO1JTVlA9VFJVRTtDDQogTj1VUy1TVkwtTVAxLTUtRy1Kb3Vs
ZSAoNSkgW0dWQ107WC1OVU0tR1VFU1RTPTA6bWFpbHRvOmdvb2dsZS5jb21fNzI2ZjZmNmQ1DQog
Zjc1NzM1ZjczNzY2YzVmNmQ3MDMxNWYzNTVmMzU2NzMwQHJlc291cmNlLmNhbGVuZGFyLmdvb2ds
ZS5jb20NCkFUVEVOREVFO0NVVFlQRT1SRVNPVVJDRTtST0xFPVJFUS1QQVJUSUNJUEFOVDtQQVJU
U1RBVD1ERUNMSU5FRDtSU1ZQPVRSVUU7Qw0KIE49VVMtTVRWLTE2NjctMS1HLURyaXZlIG15IGNh
ciAoNSkgW0dWQ107WC1OVU0tR1VFU1RTPTA6bWFpbHRvOmdvb2dsZS5jb21fNw0KIDI2ZjZmNmQ1
Zjc1NzM1ZjZkNzQ3NjVmMzEzNjM2Mzc1ZjMxNWYzMTY3MzRAcmVzb3VyY2UuY2FsZW5kYXIuZ29v
Z2xlLmNvbQ0KQVRURU5ERUU7Q1VUWVBFPUlORElWSURVQUw7Uk9MRT1SRVEtUEFSVElDSVBBTlQ7
UEFSVFNUQVQ9TkVFRFMtQUNUSU9OO1JTVlA9DQogVFJVRTtDTj1uaHVja0Bnb29nbGUuY29tO1gt
TlVNLUdVRVNUUz0wOm1haWx0bzpuaHVja0Bnb29nbGUuY29tDQpBVFRFTkRFRTtDVVRZUEU9UkVT
T1VSQ0U7Uk9MRT1SRVEtUEFSVElDSVBBTlQ7UEFSVFNUQVQ9REVDTElORUQ7UlNWUD1UUlVFO0MN
CiBOPVVTLVNWTC1DUlNNMTI0MC0zLVEtUGFzdGVsaXRvcyAoNSkgW0dWQ107WC1OVU0tR1VFU1RT
PTA6bWFpbHRvOmdvb2dsZS5jb20NCiBfNzI2ZjZmNmQ1Zjc1NzM1ZjczNzY2YzVmNjM3MjczNmQz
MTMyMzQzMDVmMzM1ZjMzNzEzM0ByZXNvdXJjZS5jYWxlbmRhci5nb28NCiBnbGUuY29tDQpBVFRF
TkRFRTtDVVRZUEU9SU5ESVZJRFVBTDtST0xFPVJFUS1QQVJUSUNJUEFOVDtQQVJUU1RBVD1ORUVE
Uy1BQ1RJT047UlNWUD0NCiBUUlVFO0NOPWNsYW5nIGxpbnV4IGZlbGxvd3NoaXA7WC1OVU0tR1VF
U1RTPTA6bWFpbHRvOmNsYW5nLWxpbnV4LWZlbGxvd3NoaXANCiBAZ29vZ2xlLmNvbQ0KQVRURU5E
RUU7Q1VUWVBFPUlORElWSURVQUw7Uk9MRT1SRVEtUEFSVElDSVBBTlQ7UEFSVFNUQVQ9TkVFRFMt
QUNUSU9OO1JTVlA9DQogVFJVRTtDTj1DbGFuZyBCdWlsdCBMaW51eDtYLU5VTS1HVUVTVFM9MDpt
YWlsdG86Y2xhbmctYnVpbHQtbGludXhAZ29vZ2xlZ3JvDQogdXBzLmNvbQ0KQVRURU5ERUU7Q1VU
WVBFPUlORElWSURVQUw7Uk9MRT1PUFQtUEFSVElDSVBBTlQ7UEFSVFNUQVQ9TkVFRFMtQUNUSU9O
O1JTVlA9DQogVFJVRTtDTj1yYW5keS5saW5uZWxsQGxpbmFyby5vcmc7WC1OVU0tR1VFU1RTPTA6
bWFpbHRvOnJhbmR5Lmxpbm5lbGxAbGluYXJvDQogLm9yZw0KQVRURU5ERUU7Q1VUWVBFPUlORElW
SURVQUw7Uk9MRT1SRVEtUEFSVElDSVBBTlQ7UEFSVFNUQVQ9REVDTElORUQ7UlNWUD1UUlVFDQog
O0NOPUJvYiBIYWFybWFuO1gtTlVNLUdVRVNUUz0wOm1haWx0bzppbmdsb3Jpb25AZ29vZ2xlLmNv
bQ0KQVRURU5ERUU7Q1VUWVBFPUlORElWSURVQUw7Uk9MRT1SRVEtUEFSVElDSVBBTlQ7UEFSVFNU
QVQ9REVDTElORUQ7UlNWUD1UUlVFDQogO0NOPUJyaWFuIEZvbGV5O1gtTlVNLUdVRVNUUz0wOm1h
aWx0bzpicGZvbGV5QGdvb2dsZS5jb20NCkFUVEVOREVFO0NVVFlQRT1JTkRJVklEVUFMO1JPTEU9
UkVRLVBBUlRJQ0lQQU5UO1BBUlRTVEFUPU5FRURTLUFDVElPTjtSU1ZQPQ0KIFRSVUU7Q049RGFu
IFJ1ZTtYLU5VTS1HVUVTVFM9MDptYWlsdG86ZGFuLnJ1ZUBsaW5hcm8ub3JnDQpBVFRFTkRFRTtD
VVRZUEU9SU5ESVZJRFVBTDtST0xFPVJFUS1QQVJUSUNJUEFOVDtQQVJUU1RBVD1URU5UQVRJVkU7
UlNWUD1UUlUNCiBFO0NOPWFiZHVscmFzQGdvb2dsZS5jb207WC1OVU0tR1VFU1RTPTA6bWFpbHRv
OmFiZHVscmFzQGdvb2dsZS5jb20NCkFUVEVOREVFO0NVVFlQRT1JTkRJVklEVUFMO1JPTEU9UkVR
LVBBUlRJQ0lQQU5UO1BBUlRTVEFUPU5FRURTLUFDVElPTjtSU1ZQPQ0KIFRSVUU7Q049a2FzYW4t
ZGV2O1gtTlVNLUdVRVNUUz0wOm1haWx0bzprYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbQ0KWC1N
SUNST1NPRlQtQ0RPLU9XTkVSQVBQVElEOjY2MDU4NTA2DQpSRUNVUlJFTkNFLUlEO1RaSUQ9QW1l
cmljYS9Mb3NfQW5nZWxlczoyMDIxMTAwNlQxMjAwMDANCkNMQVNTOlBVQkxJQw0KQ1JFQVRFRDoy
MDE5MDQyMlQxODE2MzZaDQpERVNDUklQVElPTjpMZXQncyBtZWV0IHVwIHNvbWUgdGltZSB0byBk
aXNjdXNzIHRvcGljcyBsaWtlOlxuKiBwYXRjaCBzZXRzXG4NCiAqIGNvbXBpbGVyIGJ1Z3Ncbiog
dXBzdHJlYW1pbmcgZWZmb3J0c1xuKiBldGNcblxuQ2FsZW5kYXIgaW52aXRlOlxuaHR0cHM6Ly8N
CiBjYWxlbmRhci5nb29nbGUuY29tL2NhbGVuZGFyL2VtYmVkP3NyYz1nb29nbGUuY29tX2JiZjht
Nm00bjhucTVwMmJmanBlbGUwbjUNCiBzJTQwZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbSBcblxu
SGFuZ291dHMgTWVldCBpbnZpdGU6XG5odHRwczovL21lZXQuZ29vZ2wNCiBlLmNvbS95amYtanlx
ay1pYXpcblxuLTo6fjp+Ojp+On46fjp+On46fjp+On46fjp+On46fjp+On46fjp+On46fjp+On46
fjp+On4NCiA6fjp+On46fjp+On46fjp+On46fjp+On46fjo6fjp+OjotXG5EbyBub3QgZWRpdCB0
aGlzIHNlY3Rpb24gb2YgdGhlIGRlc2NyaXANCiB0aW9uLlxuXG5UaGlzIGV2ZW50IGhhcyBhIHZp
ZGVvIGNhbGwuXG5Kb2luOiBodHRwczovL21lZXQuZ29vZ2xlLmNvbS95amYtankNCiBxay1pYXpc
bihVUykgKzEgNDc1LTI5OS04OTQ1IFBJTjogMjc0NjU1I1xuVmlldyBtb3JlIHBob25lIG51bWJl
cnM6IGh0dHBzOi8NCiAvdGVsLm1lZXQveWpmLWp5cWstaWF6P3Bpbj04OTMzNTE1ODM1MDI0Jmhz
PTdcblxuVmlldyB5b3VyIGV2ZW50IGF0IGh0dHBzOi8NCiAvY2FsZW5kYXIuZ29vZ2xlLmNvbS9j
YWxlbmRhci9ldmVudD9hY3Rpb249VklFVyZlaWQ9T1dzNWRERmpNMnB4YnprM2RESXpOSEYNCiB3
WTJRd2NtNHliVFpmTWpBeU1URXdNRFpVTVRrd01EQXdXaUJyWVhOaGJpMWtaWFpBWjI5dloyeGxa
M0p2ZFhCekxtTnZiUSZ0b2sNCiA9TmpNaloyOXZaMnhsTG1OdmJWOWlZbVk0YlRadE5HNDRibkUx
Y0RKaVptcHdaV3hsTUc0MWMwQm5jbTkxY0M1allXeGxibVJoY2kNCiA1bmIyOW5iR1V1WTI5dE1q
TmhaREExTkdFd01ERmhaVFEyTVdGalpXTTNNVEU1TVRVellqZzNaRFEyTjJGbE1XUmtaUSZjdHo9
QW0NCiBlcmljYSUyRkxvc19BbmdlbGVzJmhsPWVuJmVzPTEuXG4tOjp+On46On46fjp+On46fjp+
On46fjp+On46fjp+On46fjp+On46fjoNCiB+On46fjp+On46fjp+On46fjp+On46fjp+On46fjp+
On46fjp+Ojp+On46Oi0NCkxBU1QtTU9ESUZJRUQ6MjAyMTA5MjlUMTYwNDE4Wg0KTE9DQVRJT046
U1ZMLU1BVDItNC1QaG9uZSBSb29tIDRMNSAoMSkgW0dWQ1wsIE5vIGV4dGVybmFsIGd1ZXN0c10N
ClNFUVVFTkNFOjMNClNUQVRVUzpDT05GSVJNRUQNClNVTU1BUlk6RmVsbG93c2hpcCBvZiB0aGUg
Q2xhbmcgQnVpbHQgTGludXggS2VybmVscw0KVFJBTlNQOk9QQVFVRQ0KRU5EOlZFVkVOVA0KRU5E
OlZDQUxFTkRBUg0K
--000000000000e7f03105cd247b41--
