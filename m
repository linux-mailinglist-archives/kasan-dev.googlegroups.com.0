Return-Path: <kasan-dev+bncBDN6TT4BRQPRBF5IV6CAMGQESZJZQ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-f64.google.com (mail-vs1-f64.google.com [209.85.217.64])
	by mail.lfdr.de (Postfix) with ESMTPS id B158B36F834
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 11:55:36 +0200 (CEST)
Received: by mail-vs1-f64.google.com with SMTP id h1-20020a67b7010000b02902085e833adesf16590550vsf.11
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 02:55:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619776535; cv=pass;
        d=google.com; s=arc-20160816;
        b=zbGM3L3zmouAK6RxtpuGH3UrFIyNIebhFGhfyvbAqOWSBKYQxFrO8sltZdF4CrVpV/
         M8wsGS1FawZPvjOOqUP6WXabRDoy/oQJ5JytSURzLAraLhfOLcCTHQH+xMjDK25qFL5z
         Lcp48gg+iC+8mbCrlCJWN/CwHyqwYxoLOikENZ/0WVghCcWPucjTWD2E+EgZtQP1OgxB
         ZkG4FL3eUuNH+/xNk29xdQBIijvN+acUXlaz8my7HNRfjET77EN1NQ/F+8fINM1vap5e
         GkbogFmXFQztCjlvotWF7kbOmfAS9f4yP3wGYmqI80LO8Bval+SkO58naP5wuchGNbVa
         tkDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-transfer-encoding:date:message-id:cc:to:from:sender
         :reply-to:subject:mime-version:dkim-filter;
        bh=1GWwecefzrSovw1b2wQt3SaI3vuIAjvDj72E7HD6jhM=;
        b=ZnSverPogdYWxQAyTewTvdea4BS7Ic7+6nqA1YNQZ6w4XXVc05QtHxzANHJHtC7yBm
         nAXdiXqdQL5CR3HuBno4EAheDNHH4nRE8/txEFiaL6shYH0kBKbLoZoSIMasgU5VR72n
         6v0sbcUO6mL7GR9PAWl8O7ZQK8pzlpXr9yS2LOgJfJ94Q5wY/MmhKei7e+GyxeUm9yOh
         QcR7mI7zxgtjBt1gd9Ei0vm13WQh2UDJ92dR2GE4bgw3zs4T+N8CA0Gl6Nn26dlrP++6
         NqhrkGlu9D3CwT+sz9bCK5zCja8vZ8xs5vRPjo9Lnr8xH3klLf+yaa4W3YgCFKdD+Gmz
         pAbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=p23mXhWN;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.34 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:dkim-filter:mime-version:subject:reply-to:sender
         :from:to:cc:message-id:date:content-transfer-encoding:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1GWwecefzrSovw1b2wQt3SaI3vuIAjvDj72E7HD6jhM=;
        b=GbT5V4WHmYOB/grHQSlLzXmkYeTUUZzoSarwrDJt9gf8qgeKCi496R593yrRavniOd
         FfBoX3CEMJ5thxYITHSoKP2uwTawrVxD1bNrK11i5aDfHaaUwhCwfsiBYii4d1kH0YT2
         IYNWA0L23YQyvkpOPX5I8Hg81Cll+KrecNn3Ci79j5KqDcrniLVhsjQfrzhzbegT7ceN
         7b3uWpLmsWoBNC6xlriD21p4zPTG+O6brEP4zoE6DRr3TIbL94KSp7xWYcjCfcsbT25J
         qu17+ZZCZ2GaIiViZpJh/uG50DLj/+rt7J349IrR5zOY/q/wCj4jcQN05RBOawzNlxAQ
         2Luw==
X-Gm-Message-State: AOAM5319CG9C2JzP0QMv74Z2AGTed65fbuviiiatsz2zTifpvGdBOErh
	UwgvUXgtjWxnIgV6MeYtMt4=
X-Google-Smtp-Source: ABdhPJztd3rnRjVPD7naZqK1pSWDNqN6W/T+Eq/DvCrPWKlkPffdJ6o6NfVcgHyQphzt58FaGFTPGw==
X-Received: by 2002:a9f:2404:: with SMTP id 4mr3724426uaq.48.1619776535548;
        Fri, 30 Apr 2021 02:55:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3309:: with SMTP id z9ls1111972vsz.7.gmail; Fri, 30 Apr
 2021 02:55:34 -0700 (PDT)
X-Received: by 2002:a67:ed95:: with SMTP id d21mr5011310vsp.49.1619776534904;
        Fri, 30 Apr 2021 02:55:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619776534; cv=none;
        d=google.com; s=arc-20160816;
        b=hMRg5EUtFJA0n3Ie7rvyQnm6MLS9tYLPWXyKySXYQ8fU/Y8Dy2qAXNn1nevFz7zAL5
         7Hm0TsROyFaC+X4Zkn4zm/0eDQgYNlsxt+AT8YBxQg5TSXVpvggDBb8L/48oBJ1hkjwc
         d1hXN3HGT4KssvZYCmH4X+IYXaC6K0qkuL0z0EUK8xff98lVjaVaTP8rj+PjpS9DtSVi
         5EU6+0m3oWHamgu3tMnOTJClGU+slf6lR5crja5Y92+2kiExUpoRy9eyWoduCSNeBev1
         OXEAAiVcR+/u4CgF6PSpmEezrZNXaH9C0h33SsM5XQnUsZt7zca4aa52gJvlT3MAaDm1
         fKVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-transfer-encoding:date:message-id:cc:to
         :from:sender:reply-to:subject:mime-version:dkim-signature
         :dkim-filter;
        bh=uSqL/N/2DSTcGGCi0K+7p33lEueoqIaUGi/6k7rkfTY=;
        b=PebPm7cRjU9ZFG1tI4UzEJLxBA+U540CaObJMLeCLkZlpkGKnQ1qdvO0AbCNHNkLTP
         PmDPP4hH8oOiK61qFyGBr3fzSJCcEEotlcur8N/3yd8QzSrYeFzkuCQDm3lB9zYdVqKE
         jcT6jGH07TsZOxLlTcQmHBMDq6ttW9fsbu9GcWf7s3qByhrHVyz+s2thXirmdsa9yBi7
         87595W4AD1NZxnf4BKqIRvfvnE+6+mv5dmX50W6tWqPjrBpFgk87Jp/qZg9weCi9cqhR
         epdZe4dlub98MeuoMR9bPMBZSlyQZZbARDiDYnQaYlqC8Z7Z/+JXT0b49lpbmw6/CebB
         MgGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=p23mXhWN;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.34 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout4.samsung.com (mailout4.samsung.com. [203.254.224.34])
        by gmr-mx.google.com with ESMTPS id m184si491941vkg.5.2021.04.30.02.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Apr 2021 02:55:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.34 as permitted sender) client-ip=203.254.224.34;
Received: from epcas5p1.samsung.com (unknown [182.195.41.39])
	by mailout4.samsung.com (KnoxPortal) with ESMTP id 20210430095531epoutp04ee0b29d6cbce48985a32081dc5dddf2e~6mix8YqcG2795027950epoutp04a
	for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 09:55:31 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout4.samsung.com 20210430095531epoutp04ee0b29d6cbce48985a32081dc5dddf2e~6mix8YqcG2795027950epoutp04a
Received: from epsmges5p1new.samsung.com (unknown [182.195.42.73]) by
	epcas5p1.samsung.com (KnoxPortal) with ESMTP id
	20210430095531epcas5p1aba86c36c84bbe54529cbbf1cac3da1c~6mixbq5D51593315933epcas5p13;
	Fri, 30 Apr 2021 09:55:31 +0000 (GMT)
X-AuditID: b6c32a49-bf1ff70000002586-a6-608bd4132d2e
Received: from epcas5p3.samsung.com ( [182.195.41.41]) by
	epsmges5p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	4B.8F.09606.314DB806; Fri, 30 Apr 2021 18:55:31 +0900 (KST)
Mime-Version: 1.0
Subject: RE:[PATCH 2/2] mm/kasan: proc interface to read KASAN errors at any
 time
Reply-To: maninder1.s@samsung.com
Sender: Maninder Singh <maninder1.s@samsung.com>
From: Maninder Singh <maninder1.s@samsung.com>
To: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: Marco Elver <elver@google.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrew
	Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, AMIT
	SAHRAWAT <a.sahrawat@samsung.com>, Vaneet Narang <v.narang@samsung.com>
X-Priority: 3
X-Content-Kind-Code: NORMAL
X-Drm-Type: N,general
X-Msg-Generator: Mail
X-Msg-Type: PERSONAL
X-Reply-Demand: N
Message-ID: <20210430095433epcms5p53089199bdd0411193fb9a1154c57a24f@epcms5p5>
Date: Fri, 30 Apr 2021 15:24:33 +0530
X-CMS-MailID: 20210430095433epcms5p53089199bdd0411193fb9a1154c57a24f
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFprHKsWRmVeSWpSXmKPExsWy7bCmpq7wle4Egw3/eCwu7k61mLN+DZvF
	94nT2S0mPGxjt2g7s53Vov3jXmaLFc/uM1lc3jWHzeLemv+sFse3bmG2OHRyLqMDt8fOWXfZ
	PRZsKvXYM/Ekm8emT5PYPU7M+M3i0bdlFaPH501yAexRXDYpqTmZZalF+nYJXBlP171nK5go
	XvFii2sD42GxLkZODgkBE4l7X2YzdTFycQgJ7GaUePBkF0sXIwcHr4CgxN8dwiA1wgLBEvef
	X2cDsYUEFCUuzFjDCFIiLGAg8WurBkiYTUBPYtWuPSwgtohAoMSyHcfARjILPGKSWLviCBvE
	Ll6JGe1PWSBsaYnty7cyQtiiEjdXv2WHsd8fmw8VF5FovXeWGcIWlHjwczdUXEZi9eZeFpAF
	EgLdjBKPfzRDNc9hlPixxAfCNpfYvWEe2DJeAV+J9c0NYDaLgKpE++UGVogaF4m1ExaDDWUW
	0JZYtvA1M8hjzAKaEut36UOUyEpMPbWOCaKET6L39xMmmF92zIOxVSVabm5ghfnr88ePUD96
	SCw8/poFEm6BEhsXb2OZwCg/CxG6s5AsnoWweAEj8ypGydSC4tz01GLTAsO81HK94sTc4tK8
	dL3k/NxNjOAkpOW5g/Hugw96hxiZOBgPMUpwMCuJ8P5e15kgxJuSWFmVWpQfX1Sak1p8iFGa
	g0VJnFfQuTpBSCA9sSQ1OzW1ILUIJsvEwSnVwDSld1HtNLfjN3esk/4kwpx21Omn6YxDO9aY
	+MkdeqsvoHiAW/3M+a49qy9K/BGdKqnu+czlYyrf0uaZMrMc7x6fceyedqGmWOctmVSR23e2
	LucXm9VxIOig4p13y02fs6wLOWzmHaFXGMYpY6pyh8X4yM+kBWFaf/sUAibLtYXOE3KpaGEN
	sY8w05Zd/4PlSQTvvdopke3flpf/McjZ3lGWOoNpVbWjXuDZ2V+8I8V3P0w88aFHJFjY2/KL
	sJC8pQuv6DNf/+MKl6LfSwVIFU6Rly//mSN2qaiNZdq+o4+by8Lf5nT4z/oWHL5Z4s7S8FMy
	u3h2Nayq4+SUqdEJU7JcNenSpw08fPrVVu2/lFiKMxINtZiLihMBkoJfNrEDAAA=
X-CMS-RootMailID: 20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a
References: <CGME20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a@epcms5p5>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=p23mXhWN;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.34 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

Hi=C2=A0Alex,
=C2=A0
=C2=A0
>We've=C2=A0recently=C2=A0attempted=C2=A0to=C2=A0build=C2=A0a=C2=A0universa=
l=C2=A0library=C2=A0capturing=C2=A0every
>error=C2=A0report,=C2=A0but=C2=A0then=C2=A0were=C2=A0pointed=C2=A0to=C2=A0=
tracefs,=C2=A0which=C2=A0was=C2=A0just=C2=A0enough
>for=C2=A0our=C2=A0purpose=C2=A0(https://protect2.fireeye.com/v1/url?k=3D36=
bfb191-6924888b-36be3ade-0cc47a6cba04-0e7fd520f09636ee&q=3D1&e=3Da6b7f23a-9=
8d4-4084-af0a-a88af0b4c9d0&u=3Dhttps%3A%2F%2Flkml.org%2Flkml%2F2021%2F1%2F1=
5%2F609).
>Greg=C2=A0also=C2=A0stated=C2=A0that=C2=A0procfs=C2=A0is=C2=A0a=C2=A0bad=
=C2=A0place=C2=A0for=C2=A0storing=C2=A0reports:
>https://protect2.fireeye.com/v1/url?k=3D924a3ffc-cdd106e6-924bb4b3-0cc47a6=
cba04-882467cbf9e8b46f&q=3D1&e=3Da6b7f23a-98d4-4084-af0a-a88af0b4c9d0&u=3Dh=
ttps%3A%2F%2Flkml.org%2Flkml%2F2021%2F1%2F15%2F929.
>=C2=A0
>Maninder,=C2=A0which=C2=A0exactly=C2=A0problem=C2=A0are=C2=A0you=C2=A0tryi=
ng=C2=A0to=C2=A0solve?
=C2=A0
=C2=A0
We=C2=A0focussed=C2=A0on=C2=A02=C2=A0problems,=C2=A01=C2=A0is=C2=A0to=C2=A0=
remove=C2=A0duplicate=C2=A0error=C2=A0reporting
from=C2=A0KASAN=C2=A0when=C2=A0multishot=C2=A0is=C2=A0ON
=C2=A0
and=C2=A0second=C2=A0was=C2=A0to=C2=A0save=C2=A0KASAN=C2=A0metadata=C2=A0(m=
inimal)=C2=A0to=C2=A0regenerate=C2=A0same=C2=A0KASAN=C2=A0warnings
when=C2=A0user=C2=A0reads=C2=A0new=C2=A0proc=C2=A0interface.
=C2=A0
>Note=C2=A0that=C2=A0KASAN=C2=A0already=C2=A0triggers=C2=A0a=C2=A0trace_err=
or_report_end=C2=A0tracepoint
>on=C2=A0every=C2=A0error=C2=A0report:
>https://protect2.fireeye.com/v1/url?k=3D2d128c9c-7289b586-2d1307d3-0cc47a6=
cba04-3e939a06aa0346db&q=3D1&e=3Da6b7f23a-98d4-4084-af0a-a88af0b4c9d0&u=3Dh=
ttps%3A%2F%2Felixir.bootlin.com%2Flinux%2Fv5.12-rc8%2Fsource%2Fmm%2Fkasan%2=
Freport.c%23L90
>Would=C2=A0it=C2=A0help=C2=A0if=C2=A0you=C2=A0used=C2=A0that=C2=A0one?=C2=
=A0It=C2=A0could=C2=A0probably=C2=A0be=C2=A0extended=C2=A0with
>more=C2=A0parameters.
>=C2=A0
>Another=C2=A0option=C2=A0if=C2=A0you=C2=A0want=C2=A0verbatim=C2=A0reports=
=C2=A0is=C2=A0to=C2=A0use=C2=A0the=C2=A0console
>tracepoints,=C2=A0as=C2=A0this=C2=A0is=C2=A0done=C2=A0in
>https://protect2.fireeye.com/v1/url?k=3D5f368dc2-00adb4d8-5f37068d-0cc47a6=
cba04-fe4efc4f73dbea2f&q=3D1&e=3Da6b7f23a-98d4-4084-af0a-a88af0b4c9d0&u=3Dh=
ttps%3A%2F%2Felixir.bootlin.com%2Flinux%2Fv5.12-rc8%2Fsource%2Fmm%2Fkfence%=
2Fkfence_test.c
>Note=C2=A0that=C2=A0there=C2=A0are=C2=A0many=C2=A0caveats=C2=A0with=C2=A0e=
rror=C2=A0report=C2=A0collection=C2=A0(see=C2=A0the
>links=C2=A0above),=C2=A0but=C2=A0for=C2=A0testing=C2=A0purpose=C2=A0it=C2=
=A0might=C2=A0be=C2=A0enough.
>=C2=A0
=C2=A0
Ok=C2=A0We=C2=A0will=C2=A0check=C2=A0these=C2=A0tracing=C2=A0methods=C2=A0a=
lso.
=C2=A0
Thanks
Maninder Singh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210430095433epcms5p53089199bdd0411193fb9a1154c57a24f%40epcms5p5=
.
