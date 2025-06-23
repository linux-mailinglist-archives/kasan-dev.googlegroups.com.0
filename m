Return-Path: <kasan-dev+bncBDGP5RHEZUHRBFVS4TBAMGQEYOIDNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FB12AE396B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 11:06:32 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2ea76b45c6asf824374fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 02:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750669591; cv=pass;
        d=google.com; s=arc-20240605;
        b=lRtznDInbjkJbMNTyqQclhAu1r5+i7xAmVM9ydjRXo8q1EI5kFSC3Qgoy3uqQL3SAX
         9g8KwubyP33undAqdyjG+bFCDnkrF4U6/gQzqd1wokNJejQJKAQuVC3RQg4wKx/K7L+G
         LaDKi1A9m7Bdr2NvgaE/zZyGmYTXCu+gMYlQWt/C+0KSKRBl3pTuDSRx1j/J4nVszSei
         vv8gqfjNMwuTwF6ZDAgMg51PvIsQIZfompu2ncyRPkacT8a9Hq3PhusHRGtx6rlfRgvK
         f1y5xiFeGv64xE8hU7PpDnpiAcKi/iRPLgxvlOg2lx0YFj0S4PrEp9/JqsBFzaefF4OB
         unSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=5fPI0XSIwIV2KcG+E43TJM9l6gW9qqNlG+sPet+0wSk=;
        fh=Ee0MYPcnU2zxqQC3CNOGPbcAo0sPtZwMZb879e5jpMk=;
        b=B4EdjKu6p3JbXX9/0c2mClxdJ9b+x6Oo2YvDrc62ZzKSsnoOGEXZ0Ayqjn2Hoixtg8
         rHHqbUy1BPllN2vGC2GI8X0aQKriFimqWh8iYRKh+U8aKSPjviqFY7M0/WXF3SDN7xX4
         qu6ETGsaYDXZhjnpY9IlDy69SPxy74vTi+VGS6++N/aHzx73p6R+OZjCCQGJpzqqJgKR
         +ssczEjhaA3x7LxsSODn4ieKugI5yKBGKcK47EG59jGIQG0zNii1g88bH1HFPSwp82j2
         fvAvz/x9+X3rDo8Jjp3KkChN5c3xRJSBb7y7rHOTEHIBoioIgFiKI/OCUD7yRzU0A5h5
         idMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UJ65HeJQ;
       spf=pass (google.com: domain of atuzun230@gmail.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=atuzun230@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750669591; x=1751274391; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5fPI0XSIwIV2KcG+E43TJM9l6gW9qqNlG+sPet+0wSk=;
        b=wFM1nD8bYClQas93mnrTqycjQfmQmMOXt0mtHcFytYHvVBsMKRRtlBp/+JIKsPy4hT
         AwFFgEryoQ7gIez4Fmff2iN7LtKQaZ97JeZ7S0dk5kXbWm4/y55R2zgxPmLNhv1BOuKt
         gGwJv1HkapJ95ukSBqKyYjFdhCl1qYlFcStvx9XynLlPL1rQ+YJo966A70JJxr32cG1J
         IHN3eDD1zBqz3g1InBGcUAep9dKOAnXKiCt7EjoPX+BiNmIhZuZWWEVugRc3Ioa6ciyo
         c/vOl4rZUm7uvd9gqqNhQmTbRMtXywP29NHEEIHFrg4RS2QUxHPgz3rpY8HBiPF4g+NH
         ugBg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750669591; x=1751274391; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5fPI0XSIwIV2KcG+E43TJM9l6gW9qqNlG+sPet+0wSk=;
        b=TRCh+JoANz2B/Ytgrn/h4/LoY1mBgpL0WVVgHxscewjz/zgdipfWM3G0X8HZz/DkLp
         yfL7zO5adjrDQofk2ZJ958Sa/WtH8J8/ESp3+IHAisAmHGVk0KRtpoQ3hp0/ik86n+pC
         /2k6Kl+tG4YLhjN+tsjtxO1OC5bWkeTzfySrXMgAGIZHKFT31o3K2pwrXVjTADeRVIB+
         6VU4crUfVoqNiz2b4oziq2eXi2liq11ONXGMybtZ1qxtRXvQlC/WUflj0GGq2UGicmIi
         EcaFJW6HBLFacrgci8pKDkVHryLC7tVaYM5BAEa/aepFz4REv8YyKZdOF+tZJKNJ2oAU
         POxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750669591; x=1751274391;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5fPI0XSIwIV2KcG+E43TJM9l6gW9qqNlG+sPet+0wSk=;
        b=vWpRLqXi7HRtUuRA12WSyizDhRtIvCT8YgzghzyCeOrWcuCnewD7R/QTn0Q52/HcQi
         gn1M4yoN0pDQhzhur+X6qt5TQmAtbr0OSTzVZdIywocFLftXtChylSNwLcQlS3hfFh7I
         Ove2AqX/Fs1t8iEf6q3B8VG3dtNYabTJgoyFpjkrsvKFy05w9t0hnEOd12VnOf2Mosn8
         CcQvJvofTGFni8izT+/5rFtbD9jaKkUawlATNJgkm+Mt+H9vDcBvQv6Z0bxYx2eMJ9Hs
         YzSSp+kToRtsba1uIYlJATUQMkxAHYaXhPLZ5zvaMHHKO1XKjztj7AcSBSWbkmYI2MKl
         4Rhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuN8Dz7Fa4kCGnNwnUHaOxLeElwBlvR6feWxiryjMoEI3FHICghAy+KLkNbg6O/TwM5OpB1A==@lfdr.de
X-Gm-Message-State: AOJu0YypDJIxN+iaiOZ3tNrmayv6VZYXTAgzGVptkJXC7Fj6j/MKTVxu
	IDqcrcvpmJhGZWY+EFqB2keCqq/5QksVnzSleh80KEs470UWklcCZf0W
X-Google-Smtp-Source: AGHT+IG/1HKhgQTsfQe5ezyHRr2uvI1rXr7adqnICphVkfURfHH3rewnk16T7FtGqyf3RQ26ougvDg==
X-Received: by 2002:a05:6870:b490:b0:2d6:b7b:a83 with SMTP id 586e51a60fabf-2eeda5665b5mr7876351fac.13.1750669590826;
        Mon, 23 Jun 2025 02:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZkDFQg2r3yDv7GXUSVDT1bLK+yD3LsofouA7E15YcWA==
Received: by 2002:a05:6870:3043:b0:2ea:87da:e554 with SMTP id
 586e51a60fabf-2eba2e6ad9dls1698563fac.2.-pod-prod-02-us; Mon, 23 Jun 2025
 02:06:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7WgC4KqU3CfkAJzN+l3jTGvazoJwC8TmxBmZk1cBsRVgo6uoBQC6Ie+01ZjRSZ26Ivh2FGoVmjkI=@googlegroups.com
X-Received: by 2002:a05:6870:b490:b0:2d6:b7b:a83 with SMTP id 586e51a60fabf-2eeda5665b5mr7876331fac.13.1750669589953;
        Mon, 23 Jun 2025 02:06:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750669589; cv=none;
        d=google.com; s=arc-20240605;
        b=QSdGfyRUNjuqxiHZZ411JkBSl4LLdu8dY8LdokaEfhO2FAER4wcTOX1CeSj2EvBiul
         oIYHtm/B9IhxUE3l1zFLGQCTE4RE7yi4HLLOoXUPEiX14mAThcUpnhCYujdtGcayZ26B
         M1axe5cV2t641UzlNmQfjoafF2U38bXdSoV9Fgx1Jw6Pth5v/jegtrLbZRzjdwam9nkp
         h92TDNF4UQL2DhcURKFF62npy4yKCvJH++7gUU4r+tCDB5WsA1gDOEgDVugzilveAkRW
         MSVV31ra+zfkNK6VwLbXFBAQ6ty8CN7e0Fc3BgQOI6QDkkSN1FdU8LNYmUE0UrpdwyfR
         1qmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=5+9F1MdZG12zUBEF6UJhw+ipA5AcrVLT9wp196Q/zx0=;
        fh=aPD1lWn0CYuuyEXaYkBYQLlsOUjRqwFvXlCCd9/bn0U=;
        b=HVhQAvUwLK+kWVXQulAKiCfSXkiOirbG2qTWV9huNXzDwqtkoTC5xUmNQJZM3kdUPA
         W9PrPxAaEUnGoHrlhT25pz99hKg+5H4ZEDvPn/1gIZz+AkUu0znat1gDZn4zQtOEJ4J5
         8zzMMXLfr1ClvjzKRYnx+159fliqN5VdjalHsXdU3KZ0+HbyL4Vqt+OCEeuEENpXGOIc
         SKuJOO8ti/OZFrW3XXdXfrnf1SMXYSdpyWdpRdmd4zEGp/NhRLJwV5MzTl5LMxrbTMaE
         CbeFxBVbCymlv3Ctxrs3nxuq/S6zHhXq/HlNGrG2MMXClBXKziR1HgWZkgSD2nw6r1KX
         LYuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UJ65HeJQ;
       spf=pass (google.com: domain of atuzun230@gmail.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=atuzun230@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ee664f0964si336463fac.1.2025.06.23.02.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jun 2025 02:06:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of atuzun230@gmail.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-e819aa98e7aso3290400276.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Jun 2025 02:06:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoboEB7UhFJLwhwd2LGvie9U/XcnyvHHT0J+KofrRDG3dE8SvUBhqrnabRhjme//BPj9IeQws+a4o=@googlegroups.com
X-Gm-Gg: ASbGncsuaPqmWZAlW+sLSbdUkWpn6QBPt2xEGrpzXfMB5p3mTI+9uGwUZOmHkfCJp0s
	Gh2qs7h6dCazf0LKu6zZ0ZbTSJDEmtcbBYaEWNK3ONZi6EiGqkJ7U0Fw7geKWag3se2dES5laxo
	8WYXvBIfatGWfNPbKM5WQGlPtm4vm1WlEkP+/mE2VxYNEigkcPU09XstU=
X-Received: by 2002:a05:6902:230e:b0:e84:20f5:a6ed with SMTP id
 3f1490d57ef6-e842bc76521mr15905590276.2.1750669589338; Mon, 23 Jun 2025
 02:06:29 -0700 (PDT)
MIME-Version: 1.0
From: Jin Xiulan <atuzun230@gmail.com>
Date: Mon, 23 Jun 2025 16:06:18 +0700
X-Gm-Features: AX0GCFtVZJLHyhSET2EOk8uXb7ntWgjdFMEh7cESJhZdz3LWM1GeHulIYdEVeKA
Message-ID: <CAKPZfrVMnwn7CTcuFHsB-Bc1tsc_MVpTGyuDKqdfcOW_4aLfyw@mail.gmail.com>
Subject: =?UTF-8?B?5L2g55+l6YGT5ZCX77yf6ZO26KGM5pyA5oCV5L2g55So4oCc6L+ZM+aLm+KAneWtmOmSsQ==?=
To: dipeng.chen@utxgroup.com, kunz.steven@mayo.edu, kasan-dev@googlegroups.com, 
	tsmile2@mail.ustc.edu.cn, 161101999@student.chuhai.edu.hk
Content-Type: multipart/alternative; boundary="000000000000fde0cd063839861d"
X-Original-Sender: atuzun230@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UJ65HeJQ;       spf=pass
 (google.com: domain of atuzun230@gmail.com designates 2607:f8b0:4864:20::b34
 as permitted sender) smtp.mailfrom=atuzun230@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--000000000000fde0cd063839861d
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

KuS9oOWlvSEqDQoNCuiusOS9j++8jOWtmOmSseWPr+aYr+S4quaKgOacr+a0u++8jOWPr+WIq+ma
j+maj+S+v+S+v+WwseaKiumSseWtmOi/m+mTtuihjOS6huOAgumTtuihjOihqOmdouS4iueskeiE
uOebuOi/ju+8jOWFtuWunuacgOaAleWSseaOjOaPoei/mTPmi5vlrZjpkrHms5XvvIznlKjkuobo
v5nkupvmlrnms5XvvIzliKnmga/og73lpJrmi7/kuI3lsJHjgIINCg0K5Lul5LiL5pivIOKAnOi/
mTPmi5vigJ3lrZjpkrHvvIzog73lpJrmi7/kuI3lsJHliKnmga/vvJoNCg0K6Zi25qKv5a2Y6ZKx
5rOV44CCDQrpop3lrZjljZXms5XjgIINCuWIqeeOh+avlOi+g+azleOAgg0KDQrliKvplJnov4fv
vIHov5nmnaHkv6Hmga/lj6/og73kvJrmlLnlj5jmgqjnmoTnnIvms5XvvIENCg0KaHR0cHM6Ly90
aW55dXJsLmNvbS96aGVpLTMtemhhby1jdW4tcWlhbg0KDQrnpZ3kvaDkuIDliIfpg73lpb3vvIEN
Cg0KLS0tDQoNCuS6uuW/g+WQkeWWhO+8jOacquadpeWPr+acnw0KDQotLSAKWW91IHJlY2VpdmVk
IHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdy
b3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFu
ZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1k
ZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24g
dmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQUtQWmZy
Vk1ud243Q1RjdUZIc0ItQmMxdHNjX01WcFRHeXVES3FkZmNPV180YUxmeXclNDBtYWlsLmdtYWls
LmNvbS4K
--000000000000fde0cd063839861d
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><p class=3D"gmail-auto-style1" style=3D"font-size:medium;c=
olor:rgb(0,0,0)"><strong>=E4=BD=A0=E5=A5=BD!</strong></p><p style=3D"color:=
rgb(0,0,0);font-family:&quot;Times New Roman&quot;;font-size:medium"><span =
class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sans-serif=
">=E8=AE=B0=E4=BD=8F=EF=BC=8C=E5=AD=98=E9=92=B1=E5=8F=AF=E6=98=AF=E4=B8=AA=
=E6=8A=80=E6=9C=AF=E6=B4=BB=EF=BC=8C=E5=8F=AF=E5=88=AB=E9=9A=8F=E9=9A=8F=E4=
=BE=BF=E4=BE=BF=E5=B0=B1=E6=8A=8A=E9=92=B1=E5=AD=98=E8=BF=9B=E9=93=B6=E8=A1=
=8C=E4=BA=86=E3=80=82=E9=93=B6=E8=A1=8C=E8=A1=A8=E9=9D=A2=E4=B8=8A=E7=AC=91=
=E8=84=B8=E7=9B=B8=E8=BF=8E=EF=BC=8C=E5=85=B6=E5=AE=9E=E6=9C=80=E6=80=95=E5=
=92=B1=E6=8E=8C=E6=8F=A1=E8=BF=993=E6=8B=9B=E5=AD=98=E9=92=B1=E6=B3=95=EF=
=BC=8C=E7=94=A8=E4=BA=86=E8=BF=99=E4=BA=9B=E6=96=B9=E6=B3=95=EF=BC=8C=E5=88=
=A9=E6=81=AF=E8=83=BD=E5=A4=9A=E6=8B=BF=E4=B8=8D=E5=B0=91=E3=80=82</span><b=
r class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sans-ser=
if"><br class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sa=
ns-serif"><span class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helv=
etica,sans-serif">=E4=BB=A5=E4=B8=8B=E6=98=AF =E2=80=9C=E8=BF=993=E6=8B=9B=
=E2=80=9D=E5=AD=98=E9=92=B1=EF=BC=8C=E8=83=BD=E5=A4=9A=E6=8B=BF=E4=B8=8D=E5=
=B0=91=E5=88=A9=E6=81=AF=EF=BC=9A</span><br class=3D"gmail-auto-style1" sty=
le=3D"font-family:Arial,Helvetica,sans-serif"><br class=3D"gmail-auto-style=
1" style=3D"font-family:Arial,Helvetica,sans-serif"><span class=3D"gmail-au=
to-style1" style=3D"font-family:Arial,Helvetica,sans-serif">=E9=98=B6=E6=A2=
=AF=E5=AD=98=E9=92=B1=E6=B3=95=E3=80=82</span><br class=3D"gmail-auto-style=
1" style=3D"font-family:Arial,Helvetica,sans-serif"><span class=3D"gmail-au=
to-style1" style=3D"font-family:Arial,Helvetica,sans-serif">=E9=A2=9D=E5=AD=
=98=E5=8D=95=E6=B3=95=E3=80=82</span><br class=3D"gmail-auto-style1" style=
=3D"font-family:Arial,Helvetica,sans-serif"><span class=3D"gmail-auto-style=
1" style=3D"font-family:Arial,Helvetica,sans-serif">=E5=88=A9=E7=8E=87=E6=
=AF=94=E8=BE=83=E6=B3=95=E3=80=82</span><br class=3D"gmail-auto-style1" sty=
le=3D"font-family:Arial,Helvetica,sans-serif"><br class=3D"gmail-auto-style=
1" style=3D"font-family:Arial,Helvetica,sans-serif"><span class=3D"gmail-au=
to-style1" style=3D"font-family:Arial,Helvetica,sans-serif">=E5=88=AB=E9=94=
=99=E8=BF=87=EF=BC=81=E8=BF=99=E6=9D=A1=E4=BF=A1=E6=81=AF=E5=8F=AF=E8=83=BD=
=E4=BC=9A=E6=94=B9=E5=8F=98=E6=82=A8=E7=9A=84=E7=9C=8B=E6=B3=95=EF=BC=81</s=
pan><br class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sa=
ns-serif"><br class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvet=
ica,sans-serif"><span class=3D"gmail-auto-style1" style=3D"font-family:Aria=
l,Helvetica,sans-serif"><a href=3D"https://tinyurl.com/zhei-3-zhao-cun-qian=
" target=3D"_blank">https://tinyurl.com/zhei-3-zhao-cun-qian</a></span><br =
class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sans-serif=
"><br class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvetica,sans=
-serif"><span class=3D"gmail-auto-style1" style=3D"font-family:Arial,Helvet=
ica,sans-serif">=E7=A5=9D=E4=BD=A0=E4=B8=80=E5=88=87=E9=83=BD=E5=A5=BD=EF=
=BC=81</span></p><p class=3D"gmail-auto-style9" style=3D"font-size:11.5pt;c=
olor:rgb(91,102,116)">---</p><p style=3D"color:rgb(0,0,0);font-family:&quot=
;Times New Roman&quot;;font-size:medium"><span class=3D"gmail-auto-style1" =
style=3D"font-family:Arial,Helvetica,sans-serif"></span></p><p class=3D"gma=
il-auto-style14" style=3D"font-family:&quot;Microsoft YaHei&quot;;color:rgb=
(0,123,255);font-size:medium">=E4=BA=BA=E5=BF=83=E5=90=91=E5=96=84=EF=BC=8C=
=E6=9C=AA=E6=9D=A5=E5=8F=AF=E6=9C=9F</p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAKPZfrVMnwn7CTcuFHsB-Bc1tsc_MVpTGyuDKqdfcOW_4aLfyw%40mail.gmail.=
com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msg=
id/kasan-dev/CAKPZfrVMnwn7CTcuFHsB-Bc1tsc_MVpTGyuDKqdfcOW_4aLfyw%40mail.gma=
il.com</a>.<br />

--000000000000fde0cd063839861d--
