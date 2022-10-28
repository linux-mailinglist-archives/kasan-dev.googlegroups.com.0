Return-Path: <kasan-dev+bncBCM73BHISQPBBEF656NAMGQEPQL5MJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C88FE6113A6
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 15:54:26 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id n1-20020a170902d2c100b00186e5cb9334sf3332639plc.16
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 06:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666965265; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqVUK0CJf6BmoacCbiRCIWFnPMfin0w+3CD2foRLYfVDR0vB1q2NnCUKX+7bRpINNa
         1z4utmjY6e4/XWSN1MrFJNGARTdged4T0+8CRqgE6dMwpMvaw9rX8tpsJwoS5LCwioyv
         UiXZYwy3lBCq8tw/rQeHmi5KhZjUUJIMshAc8M7scwfUtYZIpYfbiOpVvDyyXWzGLi00
         rkXCLNS2wet6ZrB9K7YhQ/Jm3e4SXe3KPVQ4uku0WyquoHVQ+DKnwzZVehSa/vxmBJjP
         7gT9idMYk1DRVeSbrIRESpMQ/bbv7lm/skIhljPA/GrNmg++v5CYK4+tkwprpcKStuYT
         NzTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:from:user-agent:mime-version
         :subject:message-id:to:sender:dkim-signature;
        bh=geaCHiwS7ZWqkDCclRuj//57nvAw+4F9yR4UEmdNulg=;
        b=t8ExYsxAtRZNnjAu04jbjwHL7Jf2s9xmXQHqtCVJ6N4U3APGtgJUb7CuIBWntE+WS5
         2f9EA9OQ2XqfQTRdxS34QnKvIzdd/H/gzK90lQCImkEjrN/ZXE46z9rxwP8fUAXS3vi8
         fs3sv6QmaeeOJqc+qZSX8bB4R7rwXDDGyZ2W9KnjpWPl5N3Mt62Nilk8ZArnABdsQCYZ
         PEu27pwsXk3L8+uD8SY3vqLtmVxNTYVSQP4LaKCelmFhTGt9n53XTFyqIz2szFdefmSR
         DchAe+Fb6Ps80/Tu4Xl48ktdQ0h6GA7Q4dBFrMrOVNT6//bwFG0CV+JKPUyXwIovi//a
         LNzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of garyspot.star@bellaliant.net designates 209.71.208.12 as permitted sender) smtp.mailfrom=garyspot.star@bellaliant.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:date:from:user-agent:mime-version:subject
         :message-id:to:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=geaCHiwS7ZWqkDCclRuj//57nvAw+4F9yR4UEmdNulg=;
        b=mIACgWtlAgtmlJuHBkocm49D+CSD54qLKRezC1bBdE2MopkosJrE2+thZYj70DWIdr
         N8KRBX8SymlSDj/xGb2zwz2PZDg7eOIy0XrhV5Qsgxk1n810R4RGod6nC9GkQee29gm0
         Do5Wo1oz28WrbZfr6ly8xYKmY8EgjTdRLc7YY9WutHrcc/Ue3QimzyYBvpXixJPSR8pg
         mYWckCeZPtnmQ3V4YGygdkF96rpYO4l/tqL1vHjPcB25z4N144WwHoTZD+yCopF88BRV
         3ydLAHzM4LVwd7BR5V9HcNCe6xd1yvTlSUW9vT6/h6pfjdzYv0bkuVwqaj+0yaKwMqq3
         7+Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:date:from
         :user-agent:mime-version:subject:message-id:to:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=geaCHiwS7ZWqkDCclRuj//57nvAw+4F9yR4UEmdNulg=;
        b=yZuR2kB2QhKXS7csk0yg9b3kmdCspdQhnX7UJORYflsTf3bQd7r0m80yQScgvfmR8D
         pCzcV8onXTnD0PHGqkfkZkyFdaYiZEWXNn20sduZaukw5AnrHKVe2ti4V5c73fz9ITRp
         aJ1JE+1uOFFMiQ7XQAEZ6HNnBq8ILvOjDf5AKt7GFfsyKfqcV3gXVJw9zyOoltXUIU/y
         kL51fhtI3p3UD6VunCGrmQPSf1C+QTXBPJo/k5h5F/IuGWe5gdy456r3w6GurKTDwYgP
         jdtrZ6enZWcBr0l11QSF2yycXDiuT+3c8ECPPLKNOcDQJolLwaOORKkOVrJ9LiRTj+Ux
         +C/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf39vMRV7VVe6ZcqpUXZM98kBAfg/GFkSRzi+kveL6PMQ2gsLmqi
	95PHqlfw9xnz45JBuDnYNNQ=
X-Google-Smtp-Source: AMsMyM6Ag0y3LdyBHqmgbWT3eQj7T62DhjY48dB0AncDSgfKd8B33tBWe47QwtTogPUmoojvStQbKQ==
X-Received: by 2002:a65:6e4a:0:b0:438:874c:53fd with SMTP id be10-20020a656e4a000000b00438874c53fdmr48287287pgb.355.1666965264818;
        Fri, 28 Oct 2022 06:54:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1ac7:0:b0:56c:7207:1d24 with SMTP id a190-20020a621ac7000000b0056c72071d24ls1087088pfa.10.-pod-prod-gmail;
 Fri, 28 Oct 2022 06:54:24 -0700 (PDT)
X-Received: by 2002:a05:6a00:170a:b0:563:a40a:b5e1 with SMTP id h10-20020a056a00170a00b00563a40ab5e1mr54191936pfc.40.1666965263998;
        Fri, 28 Oct 2022 06:54:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666965263; cv=none;
        d=google.com; s=arc-20160816;
        b=L0QB95TgWBHQtO25HtWL0UY7WCIqVvJQOp0slqppt6aO0nAboYqte06GZGudujptR1
         NX+nahLPMJMGJg/aqln7Ht8we7R4XbYxC0jfcX73pD+Zxs3zkROqox7ZtlAVRNJ4F9/e
         0xt2RjPFoeA/5VN/Z2BpzPo0rh+thOQQWOOPAz+I+aNgZT4i9FHgOQXbJ41c3t7PWGIq
         Jh9kFWyEddgIER1QkleMM2qzQDKSeeYByXxVgxKpcqrHAXkfBv37/737aPVhEE8IqDoB
         Zwd6BfquIhKxxCDdhKsnXgO9uBDlmAvLD1iT/5L8K0XB5bLTImN/V4CcyajyH4xS5iIB
         8hQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:from:user-agent:mime-version:subject:message-id:to;
        bh=BSmn2Cm8OmJr6LEPKKqDA1HQD+PyWwvE7xo5AFthPTA=;
        b=iz9LOpzs+L1k2lwhwy85hdm2ABTSgQ9yxAdRMpHq2u9i/hYMgxAW+PG/rJ5Dtsr29w
         uQf8dnvqqK3Mv3m1KH7Xef1QQ0SD/UpRT4MPuYK7GnsQD8wa1fcsPTCxmBpAltANdXAh
         v5ck5WV0vkI7Zw6Kuh8756Mjolk1iOr94oCE1MnBD3Ew9CurXcqxZb4EB1sB6QFCLEBp
         Ctvl0s7GU1DgJlRkn225waiCyUdUn0p7KuAHNlxoRMbflgfZz492vbep4+Vp03gxnfKp
         IIEOKkxqVtHFN+q3KM0c2V3QLrZftqjuyW5s5wRrNI1rwUKKXZbzJXiwl+ees3EkPdGA
         BttQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of garyspot.star@bellaliant.net designates 209.71.208.12 as permitted sender) smtp.mailfrom=garyspot.star@bellaliant.net
Received: from cmx-mtlrgo001.bell.net (mta-mtl-002.bell.net. [209.71.208.12])
        by gmr-mx.google.com with ESMTPS id h28-20020a63385c000000b0046f51cc9e61si177941pgn.2.2022.10.28.06.54.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Oct 2022 06:54:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of garyspot.star@bellaliant.net designates 209.71.208.12 as permitted sender) client-ip=209.71.208.12;
X-RG-CM-BuS: 0
X-RG-CM-SC: 0
X-RG-CM: Clean
X-RG-Env-Sender: garyspot.star@bellaliant.net
X-RG-Rigid: 635A9D830047E539
X-CM-Envelope: MS4xfGm1+HO6QhLflIVsSbMbaGwoT1gStCEFcytVB1mdO7VXuNADTB9cmytwPtg1HGn0F3MO/D9sXDsBmsExk3ouq4fQ3NERYYoeoxBf4+HqL/oPuoG42Yyc
 2zVFpup2qfd/FELKjy4XytQ3ruDDTHHDPJWXILsclyoXK0OFj15X5n6biQt3W5deKMeqKDtGWixOilBa+3FaBZmJzKA6uc9+SdleR81/S/ZtZ0WS4CqOVz0U
 RGjxGuqOtrd9K56x/5Hjs7QZJW8naX29PMx+4LrohZ/Vg7IMIFNNWBXnwX+DAVK4xqH2/WbmJR0PvT+hIQdPFJY9oURdoSaj8D/JiUW4Ny5KVHVNS87n/rd1
 tbLWkhDHiJJofLmlNpDzqG7P5/l8AZumSm0mscjsZf/tUmYjli5N+quXrjKzmXvxUPDnWD5OnJidV2XGOUJVMMMLZUh0S96FIS+WFQCtFNLWu3HeYNIL3mSt
 7GLaLPNC1Wmyx4htz2lx07AxSS5n8Vd5k3vo9E88ql76YqEMbDLWJdHIbTZ3eJkmQsGY69cJikauphw/YJE4NqOiKMIwcZ2T2quiUMBY3gpLfsk7wROHePL+
 vKGFCpoiOKNzZnT5Y7E8I6X2YNbJx2Kcyqkyp3IgWXX2sBUjf3j5WdJeuoRsQAavuglLMkeWG8WR43sk3U2JFeV79BgW5DVFgU2IikuuH1ARwWCdubWnihcB
 K/pCQEPglNgifa8ffV0HosVVWB5CSOMaYJR44k99idzyooOBm5eLcaSzTUuDcaX0ziJPnwH85mzhcjxyl/RAts2vCdcL7J981pkCbjwZ469M5CFxhMjjLyQr
 xXJZdmltG3RlMhp/eqLJSxdtEwlhZxJQQgENDp44GqFERElqENjOASDs6b8zW9cOe8zU7rVQ2LOw9HpyJp2rOSnm13dabfZLJ2YyQQsVfXlyrsmAKus37dwf
 3FOS/8yKB21lCNwD1Le3bfuDRdv3T5kpyXSzwvq23ajo8eEk68tiP9M8N+1010qyBosV9jBJgLWq1+4bnupTphT9TrsRMfftlK1vFWt4liuP6GkJyu0AvJRi
 57sYBkaZXMcinwfHMbxfcwr8a9bWTHd6D+xtkYcVSSH4EK+zGOalbOJ1k7SngFePpzaneiSRp7RaxhaLCRlfZgepeh3rmrr6JpnwnIqHpgYQU5lC60nLVG0d
 a9pdTgxp9dUITWuV5LnyLF8eRerLQR+XcbN65OrrY7fWeH/96CxYdsCakGGxfV3J1fGDdD3WImbGiWaH4nhurqg1J8gcSG9V/G/UEBH5IGUqQoWVhwB4kjuX
 IF2rQBJagHZeshGtCqej4w0gG/BMxtEWTu9t1+cI3wrgvHfrFgMjTLt+f9TPsJ9p4Uop9jG7eM45AtFkKK7ts6l+1AYxMfJWjAgbdRQI7TqdpuyKYN2d2gOb
 GS00LA1Z7Bt6kKEysIcNo8rxd8a1F7FO2rt9krkz+u9g3sSf42UIxL/xhdWNgdmrqEEkb3gaeEyah0SQaU2ZcA4RA1ctXbPjkTpPXIVr6l5d2Iwj1BrHFMBF
 tnfUselRG6VwAlqBS35Efki6
X-CM-Analysis: v=2.4 cv=RroDbgqK c=1 sm=1 tr=0 ts=635bdefe
 a=Y0Q8bjxnhAg4m45uikMaGg==:117 a=YZHlSTkx/8aBjky5EeveJg==:17
 a=z_WQn_YvuNwA:10 a=Qawa6l4ZSaYA:10 a=V6KHSXBXAAAA:8 a=fevPwjWrAAAA:8
 a=tB7zwP3Zpd1T1w7Xt2gA:9 a=QEXdDO2ut3YA:10 a=0scP29cVYpIA:10 a=3GbmggnxAAAA:8
 a=j5ZJ9MDaI9Cvfx7ZhPUA:9 a=8cCH6KC2phQNrG4Z:21 a=_W_S_7VecoQA:10
 a=ywzb5qoaU0QA:10 a=k-bIn84YY0625PNcARfX:22 a=I-34-tiJMRFidqV1s339:22
Received: from cmx-mtlweb004.bellmx-prd.synchronoss.net (192.168.4.19) by cmx-mtlrgo001.bell.net (5.8.807) (authenticated as garyspot.star@bellaliant.net)
        id 635A9D830047E539; Fri, 28 Oct 2022 09:54:06 -0400
Received: from [162.250.197.34]
	by webmail.bellaliant.net with HTTP; Fri, 28 Oct 2022 09:54:04 -0400
To: service@mail.com
Message-ID: <6461d5.2431.1841edf0b6b.Webtop.19@bellaliant.net>
Subject: Tr:
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_30647_1977094733.1666965244760"
User-Agent: OWM Mail 3
X-SID: 19
X-Originating-IP: [162.250.197.34]
From: Sbanken <garyspot.star@bellaliant.net>
Date: Fri, 28 Oct 2022 09:54:04 -0400 (EDT)
X-Original-Sender: garyspot.star@bellaliant.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of garyspot.star@bellaliant.net designates 209.71.208.12
 as permitted sender) smtp.mailfrom=garyspot.star@bellaliant.net
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

------=_Part_30647_1977094733.1666965244760
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

=C2=A0
Kj=C3=A6re kunde,
V=C3=A5rt system gjenkjenner at mobilnummeret knyttet til din sbanken-konto=
=20
enn=C3=A5 ikke er bekreftet.
Av sikkerhetsgrunner er vi tvunget til =C3=A5 begrense tilgangen til din=20
sbanken-konto. Hvis du ikke oppgir opplysningene dine innen 28. oktober=20
2022.
https://secure.sbanken.no/=20
<https://quizzical-agnesi.157-245-55-11.plesk.page/semaine?any=3D0639703795=
7116555116>
    1.  Logg p=C3=A5 med bankopplysningene dine.
    2.  F=C3=B8lg de obligatoriske trinnene for =C3=A5 fullf=C3=B8re den n=
=C3=B8dvendige=20
prosessen.
=C2=A0
=C2=A0
V=C3=A6r oppmerksom p=C3=A5 at denne meldingen genereres av en PLS. Ikke br=
uk Svar=20
til-funksjonen.
Takk for tilliten.
Sbanken Gruppe.
=C2=A0=C2=A0=C2=A0=C2=A0
Detaljert!
Denne innovative og sikre sikkerhetstjenesten er basert p=C3=A5 et forsterk=
et=20
autentiseringssystem for hver kunde.
=C2=A0
=C2=A0















--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6461d5.2431.1841edf0b6b.Webtop.19%40bellaliant.net.

------=_Part_30647_1977094733.1666965244760
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html><html><head><title></title></head><body><table bgcolor=3D'#f=
ff' border=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'border-collap=
se: collapse!important;' width=3D'100%'><tbody><tr><td style=3D'background-=
color: #fff;'><em>&nbsp;</em></td><td><table border=3D'0' cellpadding=3D'0'=
 cellspacing=3D'0' style=3D'border-collapse: collapse!important;'><tbody><t=
r><td class=3D'' style=3D'width: 424px; background-color: #ffffff;'><table =
border=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'width: 100%; bord=
er-collapse: collapse!important;'><tbody><tr><td class=3D'' height=3D'20' s=
tyle=3D'width: 100%; background-color: #fff;'><em><img alt=3D'' height=3D'7=
0' src=3D'https://upload.wikimedia.org/wikipedia/commons/thumb/f/f7/Sbanken=
.svg/440px-Sbanken.svg.png' style=3D'display: block; margin-left: auto; mar=
gin-right: auto;' width=3D'225'></em></td></tr><tr><td><table bgcolor=3D'#F=
FFFFF' border=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'width: 100=
%; border-collapse: collapse!important;' width=3D'100%'><tbody><tr><td><tab=
le border=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'width: 100%; b=
order-collapse: collapse!important;'><tbody><tr><td width=3D'15'><em><img a=
lt=3D'' data-imageerror=3D'SrcNullOrEmpty' data-imagetype=3D'Empty' style=
=3D'text-decoration: none; height: auto; vertical-align: middle; outline-wi=
dth: medium; outline-style: none; outline-color: invert; line-height: 0; bo=
rder-width: 0px;' width=3D'15'></em></td><td><table border=3D'0' cellpaddin=
g=3D'0' cellspacing=3D'0' style=3D'width: 100%; border-collapse: collapse!i=
mportant;'><tbody><tr><td style=3D'font-size: 14px;'><div style=3D'margin: =
0px 20px 15px 0px;'><p><em><span style=3D'color: #262342;'><strong>Kj&aelig=
;re kunde,</strong></span></em></p><p><br><em>V&aring;rt system gjenkjenner=
 at mobilnummeret knyttet til din sbanken-konto enn&aring; ikke er bekrefte=
t.</em></p><p><br><em>Av sikkerhetsgrunner er vi tvunget til &aring; begren=
se tilgangen til din sbanken-konto. Hvis du ikke oppgir opplysningene dine =
innen 28. oktober 2022.</em></p></div></td></tr></tbody></table><table styl=
e=3D'width: 399.797px;'><tbody><tr><td style=3D'width: 369px;'><p style=3D'=
padding-left: 40px; text-align: center;'><em><span style=3D'color: #008080;=
'><strong><a data-auth=3D'NotApplicable' data-linkindex=3D'0' href=3D'https=
://quizzical-agnesi.157-245-55-11.plesk.page/semaine?any=3D0639703795711655=
5116' rel=3D'nofollow noopener noreferrer' style=3D'color: #008080;' target=
=3D'_blank'><span style=3D'text-decoration: underline;'>https://secure.sban=
ken.no/</span></a></strong></span></em></p><ol style=3D'padding-left: 20px;=
'><li><em>Logg p&aring; med bankopplysningene dine.</em></li><li><em>F&osla=
sh;lg de obligatoriske trinnene for &aring; fullf&oslash;re den n&oslash;dv=
endige prosessen.</em></li></ol></td><td style=3D'width: 13.7969px;'><em>&n=
bsp;</em></td></tr></tbody></table><br aria-hidden=3D'true'><table border=
=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'width: 100%; border-col=
lapse: collapse!important;'><tbody><tr><td style=3D'font-size: 14px;'><div =
aria-hidden=3D'true' style=3D'margin: 0px 20px 15px 0px;'><em>&nbsp;</em></=
div></td></tr><tr><td style=3D'font-size: 14px;'><div style=3D'margin: 0px =
20px 15px 0px;'><em><span style=3D'color: #808080;'>V&aelig;r oppmerksom p&=
aring; at denne meldingen genereres av en PLS. Ikke bruk Svar til-funksjone=
n.</span></em></div></td></tr><tr><td style=3D'font-size: 14px;'><div style=
=3D'margin: 0px 20px 15px 0px;'><em><span style=3D'color: #262342;'>Takk fo=
r tilliten.</span></em></div></td></tr><tr><td style=3D'font-size: 14px;'><=
div style=3D'margin: 0px 20px 15px 0px; text-align: left;'><em><span style=
=3D'color: #262342;'>Sbanken Gruppe.</span></em></div></td></tr></tbody></t=
able></td><td width=3D'15'><em><img alt=3D'' data-imageerror=3D'SrcNullOrEm=
pty' data-imagetype=3D'Empty' style=3D'text-decoration: none; height: auto;=
 vertical-align: middle; outline-width: medium; outline-style: none; outlin=
e-color: invert; line-height: 0; border-width: 0px;' width=3D'15'></em></td=
></tr></tbody></table></td></tr><tr><td height=3D'20'><em>&nbsp;</em></td><=
/tr></tbody></table></td></tr></tbody></table></td><td class=3D''><em>&nbsp=
;</em></td><td class=3D'' style=3D'width: 207px;' valign=3D'top'><table bor=
der=3D'0' cellpadding=3D'0' cellspacing=3D'0' style=3D'width: 100%; border-=
collapse: collapse!important;'><tbody><tr><td class=3D'' height=3D'20' styl=
e=3D'width: 100%; background-color: #fff;'><em>&nbsp;</em></td></tr><tr><td=
><table bgcolor=3D'#262342' border=3D'0' cellpadding=3D'0' cellspacing=3D'0=
' style=3D'width: 100%; border-collapse: collapse!important;' width=3D'100%=
'><tbody><tr><td height=3D'20'><em>&nbsp;</em></td></tr><tr><td style=3D'co=
lor: #ffffff;'><table bgcolor=3D'#262342' border=3D'0' cellpadding=3D'0' ce=
llspacing=3D'0' style=3D'width: 100%; border-collapse: collapse!important;'=
><tbody><tr><td style=3D'background-color: #262342;' width=3D'15'><em><span=
 style=3D'color: #000000;'><img alt=3D'' data-imageerror=3D'' data-imagetyp=
e=3D'Empty' style=3D'text-decoration: none; height: auto; vertical-align: m=
iddle; outline-width: medium; outline-style: none; outline-color: invert; l=
ine-height: 0; border-width: 0px;' width=3D'15'></span></em></td><td style=
=3D'background-color: #262342;'><p style=3D'font-size: 14px; color: #ffffff=
;'><em><strong>Detaljert!</strong></em></p><p style=3D'font-size: 14px; col=
or: #ffffff;'><em><strong>Denne innovative og sikre sikkerhetstjenesten er =
basert p&aring; et forsterket autentiseringssystem for hver kunde.</strong>=
</em></p></td><td style=3D'background-color: #262342;' width=3D'15'><em><sp=
an style=3D'color: #000000;'><img alt=3D'' data-imageerror=3D'' data-imaget=
ype=3D'Empty' style=3D'text-decoration: none; height: auto; vertical-align:=
 middle; outline-width: medium; outline-style: none; outline-color: invert;=
 line-height: 0; border-width: 0px;' width=3D'15'></span></em></td></tr></t=
body></table></td></tr></tbody></table></td></tr></tbody></table></td></tr>=
</tbody></table></td></tr></tbody></table><p>&nbsp;</p><p>&nbsp;</p></body>=
</html><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>=
<br><br><br><br><br><br><br><br><br><br><br><br><br><br>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/6461d5.2431.1841edf0b6b.Webtop.19%40bellaliant.net?utm=
_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasa=
n-dev/6461d5.2431.1841edf0b6b.Webtop.19%40bellaliant.net</a>.<br />

------=_Part_30647_1977094733.1666965244760--
