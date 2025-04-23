Return-Path: <kasan-dev+bncBCHMJHUU54JBBVO7UTAAMGQEXX4OPGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 32A50A997C3
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 20:22:15 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-440667e7f92sf612745e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 11:22:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745432534; cv=pass;
        d=google.com; s=arc-20240605;
        b=j9HpWtsF/NjOUh6bf3ScO2z0UxUZ1ZspyUwvFLhvFZgKF/sqw6h+uQfw0LeICSEVjJ
         IV6G9WKJ7r7Se6ydwvQgWr5lwgExhogwkSgqF64RObFPDB4kpnfgCsb7o6BrxzFwFR74
         hx3at6OFmNYNEZjqtyZz4t6ImGmXpKB2LbtYD0mNxKYMamsLrvPqnXISiXvymb+sxChR
         qdMPCo91lURzU5n9xwuBWC9bDXpXAmLsXFlrdqntaB3Rz4P48mzKssMC/76SOtagQRh3
         B5lD6SI1Q3HokLxFOwhFTCGJ+jbb/cB4K/IMxFQwPFvh5JMczbHgzajs0dKffpICiEcw
         Sr4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=NMNvpdH4UsdFNfckJmPDbx5dlFIZEZAJHJWTaBEw48M=;
        fh=qzuccy8mxo5lBDIJZLLOBxPIR9tcOK2XXsH0qGcSYh0=;
        b=ZU/8vh3bcOuZe3FbjrU++qqYq/vpWbXPxIiGz6J6MCl1x/Gnrc2XTdtfF0iIJyq+Px
         822ePnWKOVZwF1gRKXmAf9SnaVidlsiCPLJrDkgQomVXW2y9fhw24ux4EGPxOq9zhm46
         zbE2hoMc8ttafH97mcbntTQWCU9qeKoO2yKUi9gtz5mf07jJOcoSEcz8XEdNj5Itznym
         soxqsuKXM1zTLuq1rDPI8PjQHCx7PoXqj/68dlyo0/3zNA/YiQlw4p3nKHZ9mfGXiMHV
         6nICMysPDIzPzoG1cwcJ3m7fxiuSLWaC3NSZhR6S7UxPJd+TiamvZoQcQETNxBT8ozcW
         xojA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=2EwDIfym;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="K/ad8wVV";
       spf=pass (google.com: domain of 0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745432534; x=1746037334; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NMNvpdH4UsdFNfckJmPDbx5dlFIZEZAJHJWTaBEw48M=;
        b=PiZ77KRy+hXjmDvlKuSCSk1X0RnClAiHyBxlRZ3b3k7MnuWRgISvhQ8wlpJE0bEeOf
         WHLSXfpGkNUyphvHww50EslCkote6i6UX1KAdnx8r4J6sBwB3FEagt6NLmQQaWvPtDX4
         3b5nyi2S+pgdytgh3VR1msTHmDLsX+NNewAgeAKL2y5SYJGOMhdeqKiZDxyHYlYHwY+j
         Ck4ulfZC1SolWReMAX0/h1fmvla9TTikxOzvOh5wMZXgBms2gqB/Hu5/tN7mc7iOIMMj
         nZ7x7PWPFqWT8AWkURfIGUQ/vF4nnPj1zV+zjXGESZ7fz6Ay9qCpZZn9rBL8FUhSao+E
         bm/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745432534; x=1746037334;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NMNvpdH4UsdFNfckJmPDbx5dlFIZEZAJHJWTaBEw48M=;
        b=WqaHNWma3ohHcwacby7TjqIOYvJmUVdZouiQB+5vm/YQn1DjkJPiv5fKksijFev0I1
         7psoWTgtIHhUynvZgWIgqej485yG6aSixbP0FSl+HANXsUPYREnBPwDAwujvf1NfWhmG
         zKBjEmvKmcDsAQ9Z1apVEzo0/nuMLTbrASnn6cdGrbjtsDbCPO/Bxx3p54PsG09SFABl
         7qN2hnUum3yC8cukdhs3bvurkSf+dn7luL6JhVfAM5pW8f6SCz31jvM2VMWVVs2mCp0k
         4Cf33ux+x5CTwNg0vsqjcg1gfn9CkYH6nSewxItvKlRBAhifehQxqlWx/N+U3cJqHfRO
         t70Q==
X-Forwarded-Encrypted: i=2; AJvYcCV056qhsDGfQtpcm0KiXPG9kmSjeKTTFfJEpR9/gCjEf2471CMmdTuKHp4DvUccTgU2IHhIUg==@lfdr.de
X-Gm-Message-State: AOJu0YxSrW6Ly8NQr8DLgdH/xYJZKtrFN6OxMzmsJqO1KPyd99npo36l
	ys1rSZD9ADHvosyx3Sd5vkT38pgK2LOTVBqvZVGr9tB4eL9kif0f
X-Google-Smtp-Source: AGHT+IGUqQ2QKlrCXRWkYvzwMDgRG5PYNDxcIVpM8XrL4AqYdO/tEYsDAR3j+XyxsYcwDRAK//Ztgw==
X-Received: by 2002:a05:600c:cc4:b0:440:6a1a:d89f with SMTP id 5b1f17b1804b1-4406ab6c569mr203029635e9.4.1745432533773;
        Wed, 23 Apr 2025 11:22:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIF8kRnvL9Qvhv1d0QWllkZqnqO2MW6E6m73/pNWVTuCw==
Received: by 2002:a05:600c:1c93:b0:43d:1776:2ec2 with SMTP id
 5b1f17b1804b1-44099e4b2e2ls1036945e9.2.-pod-prod-09-eu; Wed, 23 Apr 2025
 11:22:11 -0700 (PDT)
X-Received: by 2002:a05:600c:4f8a:b0:43c:fe85:e4ba with SMTP id 5b1f17b1804b1-4406aba6346mr197922295e9.15.1745432530939;
        Wed, 23 Apr 2025 11:22:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745432530; cv=none;
        d=google.com; s=arc-20240605;
        b=NZM7gOBdWOvULZ7ELEP3O8eSNCL2O+/4nyfGO+3NwFqrBX+iu3+VRMtPyDKrnqHGmi
         hoS2FER9JSTf0mpJ1lVzWxRR7ZAHneNMjSZ2XNw/LQCkXJlqZlq8VVfwYmMIci+nJsnP
         RBsjxCxEJ2byyN+jyePgbnDhnKJO7L+VzSxjDyYA5SAPu/DWFAEPtEVTFe+6iJapLqFq
         MWYMTm1sycbUKJnHggENGsSuRzKKittNpx4bSjbPd8heAvBEyeF1FtuBr0Dgu6lBz7MV
         0AyTO07eKjAUB2L7uAG3Lkn7kj9aICFyFepY8785aeClINi7hoRYZUXfJ67yNHhuMmC4
         MtZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=nj4H1VB4M9GRHpz/lvaXaBrdWPofL4Whop6Ef7qTqvs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=U8W31EPG6VviDBX/vwkqESXGqzCj1vhhduKK9V8pegictoasNbSX655scXUSsRXF1T
         qb86HOtlnj/SxK/ADx4fUATROLwnNy4UvvuuMcCp4zl1W1Py9BNN0YkfaD63KW+Q1ryE
         aMqiQTemz4dWuyB7+Icj8QudnEC4LwAXGyh1Wt3EmPZKUMsbPZ/tp/n58ac/rH4NZUhq
         YDBC812V2EzjySEx32XJNWaP9dIc8NAKkP4XeXMtzdeJ3UlrN4Bm8hn/b1tcv+aIuvRD
         D+Gs92DA9t5dVaJTDF5t2ztQuCcTTrnEv+fvIiI8ACCrUsU0IcxtulzRKppd5PZvzyUb
         bLJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=2EwDIfym;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="K/ad8wVV";
       spf=pass (google.com: domain of 0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from a106-73.smtp-out.eu-west-1.amazonses.com (a106-73.smtp-out.eu-west-1.amazonses.com. [54.240.106.73])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44092d230a4si515515e9.1.2025.04.23.11.22.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Apr 2025 11:22:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com designates 54.240.106.73 as permitted sender) client-ip=54.240.106.73;
Date: Wed, 23 Apr 2025 18:22:10 +0000
To: kasan-dev@googlegroups.com
From: =?UTF-8?B?J0bDs3J1bSBYWEknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
Reply-To: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2025@forumxxi.net>
Subject: =?UTF-8?Q?Convocatoria/Call_for_papers/Chiamata/Chamada/Appel_Congreso_CUIC?=
 =?UTF-8?Q?IID_2025_(no_presencial)__F=C3=B3rum_XXI_(SCOPUS)_y_La_Muralla?=
Message-ID: <0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: H2AaNz3PSmvkLSnNtHiJOw
X-FBL: H2AaNz3PSmvkLSnNtHiJOw-k7MPHMqVFXaeyfU0hp1YPQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_R6hnluezuG6gYEA7SN2bFZJafkqm9TsGr78vYtXEU"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2025.04.23-54.240.106.73
X-Original-Sender: cuiciid2025=forumxxi.net@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw
 header.b=2EwDIfym;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="K/ad8wVV";       spf=pass
 (google.com: domain of 0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com
 designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
X-Original-From: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2025=forumxxi.net@crlsrv.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>

This is a multi-part message in MIME format.
--b1_R6hnluezuG6gYEA7SN2bFZJafkqm9TsGr78vYtXEU
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DH2AaNz3PSmvkL=
SnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ]=20
=20
=20
=20
 [https://www.email-index.com/click.php?L=3DjW1a6EivQaabHz7xNaBpOA&J=3DH2Aa=
Nz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
=20
 Congreso Internacional CUICIID 2025
=20
=20
=20
=20
 Estimados colegas, caros colegas, chers coll=C3=A8gues, cari colleghi, dea=
r colleagues:Estamos orgullosos de presentar ante la Academia la XV edici=
=C3=B3n del Congreso VIRTUAL y EN L=C3=8DNEA (no presencial) CUICIID 2025 (=
Congreso Universitario Internacional sobre Contenidos, Investigaci=C3=B3n, =
Innovaci=C3=B3n y Docencia) www.cuiciid.netLos idiomas oficiales son: espa=
=C3=B1ol, portugu=C3=A9s, italiano, ingl=C3=A9s y franc=C3=A9s y se podr=C3=
=A1n presentar 2 ponencias por autor (individualmente o en coautor=C3=ADa) =
publicables en Libro electr=C3=B3nico de la =E2=80=9CColecci=C3=B3n Acad=C3=
=A9mica Iberoamericana del siglo XXI=E2=80=9D indizado en SCOPUS BOOKS INDE=
X en 2026 o en Libro electr=C3=B3nico de la editorial LA MURALLA (indizado =
en SPI Q1) en 2026.
 CUICIID 2025 destaca por su vocaci=C3=B3n internacional y su amplia visibi=
lizaci=C3=B3n ya que sus resultados curriculares (tras revisi=C3=B3n por do=
bles pares ciegos) ser=C3=A1n publicados en:
	PONENCIAS
Para autores iberoamericanos en exclusiva: Como cap=C3=ADtulo de libro elec=
tr=C3=B3nico de la =E2=80=9CColecci=C3=B3n Acad=C3=A9mica Iberoamericana de=
l siglo XXI=E2=80=9D (indizada en SCOPUS BOOKS INDEX) en idioma ingl=C3=A9s=
 con 10 p=C3=A1ginas como m=C3=A1ximo.
Para autores europeos y los iberoamericanos que lo deseen: Como cap=C3=ADtu=
lo de libro electr=C3=B3nico de la colecci=C3=B3n =E2=80=9CInnovaci=C3=B3n =
y Formaci=C3=B3n" de la editorial La Muralla (Q1 en SPI) en cualquiera de l=
os idiomas oficiales del congreso, con 14 p=C3=A1ginas como m=C3=A1ximo.
RES=C3=9AMENES: En Libro de Actas con ISBN.Fechas clave:
	26 de mayo (lunes). =C3=9Altimo d=C3=ADa para el env=C3=ADo de Res=C3=BAme=
nes (1 p=C3=A1gina).	Desde 29 de mayo (jueves). Env=C3=ADo de informes de a=
ceptaci=C3=B3n o denegaci=C3=B3n tras revisi=C3=B3n por pares ciegos.	30 de=
 junio (lunes). Cierre de pago de matr=C3=ADcula (225 =E2=82=AC por cada au=
tor y por cada ponencia, m=C3=A1ximo 2 ponencias). Se puede fraccionar el p=
ago en 4 mensualidades de 75 50 50 50 =E2=82=AC.	7 de julio (lunes). =C3=9A=
ltimo d=C3=ADa para el env=C3=ADo de ponencias.	28 de julio (lunes). Volunt=
ario. Env=C3=ADo de v=C3=ADdeos (.mov, .mp4 o .mpeg) para la defensa grabad=
a.	15 de septiembre (lunes). Voluntario. Solicitud de defensa en directo.	2=
2, 23 y 24 de octubre (mi=C3=A9rcoles, jueves y viernes). Celebraci=C3=B3n =
del Congreso (virtual y en l=C3=ADnea, no presencial).Compuesto por 6 =C3=
=81reas tem=C3=A1ticas:
	Comunicaci=C3=B3n: Comunicaci=C3=B3n persuasiva, Alfabetizaci=C3=B3n medi=
=C3=A1tica, Influencers, Bulos, Marketing digital, Neuromarketing, Publicid=
ad, Relaciones P=C3=BAblicas, Periodismo, Eventos, Protocolo, Lo audiovisua=
l (cine, radio, TV e Internet), Comunicaci=C3=B3n legal y m=C3=A9dica, RSC,=
 COVID-19, Alfabetizaci=C3=B3n medi=C3=A1tica...	Docencia: Nueva metodolog=
=C3=ADas, e-learnig, b-learning, flipped classrom, TIC, STEAM, F=C3=B3rmula=
s y contenidos docentes, Pol=C3=ADticas educativas, EEES, LOSU, pol=C3=ADti=
cas educativas...	Ciencias Sociales y Humanismo: Turismo, Patrimonio, Antro=
polog=C3=ADa, Cultura, Derecho, Ling=C3=BC=C3=ADstica, Semi=C3=B3tica, Hist=
oria, Religi=C3=B3n, Filosof=C3=ADa, G=C3=A9nero, Psicolog=C3=ADa, Sociolog=
=C3=ADa, Sociedad, Agenda 2030, ODS.	Innovaci=C3=B3n: Trabajos doctorales, =
Tem=C3=A1ticas emergentes, Redes Sociales, Meta, Contenidos acad=C3=A9micos=
 actuales, Emprendimiento.	Investigaci=C3=B3n e Inteligencia Artificial: Nu=
evos proyectos, Investigaciones I D i, Art=C3=ADculos 60, Investigaciones n=
o regladas, Biblioteconom=C3=ADa, Ingenier=C3=ADas, Criterios de evaluaci=
=C3=B3n, Inteligencia Artificial, ChatGPT, Deepseek, Dall-e.	Miscel=C3=A1ne=
a: =C3=81rea abierta a contribuciones transversales.	Paneles tem=C3=A1ticos=
: Propuestos por autores (m=C3=ADnimo 4 ponencias por panel). Ideal para Gr=
upos de Investigaci=C3=B3n.=20
CUICIID es el espacio id=C3=B3neo para la visibilizaci=C3=B3n de trabajos d=
e doctorandos e investigadores de nuevo cu=C3=B1o en los =C3=A1mbitos acad=
=C3=A9micos de mayor relevancia y es enmarcable dentro de los Congresos de =
mayor impacto, los ubicados bajo el concepto =E2=80=98Congresos de Calidad =
de la formaci=C3=B3n docente=E2=80=99, por aunar la innovaci=C3=B3n y la do=
cencia y, merced a la revisi=C3=B3n por dobles pares ciegos de los trabajos=
 presentados, sus resultados tienen un alto valor curricular.
 Como =C3=BAltimo punto de inter=C3=A9s, CUICIID quiere focalizar sus esfue=
rzos en animar a los Grupos y Equipos de Investigaci=C3=B3n que desean visi=
bilizar sus resultados investigadores en publicaciones de primer nivel. Par=
a cualquier duda, los emplazamos en la web: www.cuiciid.net [https://www.em=
ail-index.com/click.php?L=3DGmnVHWYk6hv6klg07635763pJA&J=3DH2AaNz3PSmvkLSnN=
tHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw] y en nuestro =
correo: cuiciid2025@forumxxi.net [mailto:cuiciid2024@forumxxi.net]
 Reciban mi m=C3=A1s cordial saludo. David Caldevilla Dom=C3=ADnguezUnivers=
idad ComplutenseDirector del Congreso CUICIID 2025
=20
 [https://www.email-index.com/click.php?L=3D7mXVhg53j0yAUBm763mRB892XQ&J=3D=
H2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3DolQ0cr5gB5dhJx6KLe7RZQ&J=3DH2=
AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
 [https://www.email-index.com/click.php?L=3D7yhyngRLi4Z2c9tznr763jow&J=3DH2=
AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ] | Actualizar mis dato=
s [https://www.email-index.com/update.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7=
MPHMqVFXaeyfU0hp1YPQ] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine n=C2=BA =
38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000%40eu-west-1.ama=
zonses.com.

--b1_R6hnluezuG6gYEA7SN2bFZJafkqm9TsGr78vYtXEU
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=
=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJ=
Ow&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk=
7MPHMqVFXaeyfU0hp1YPQ');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMq=
VFXaeyfU0hp1YPQ');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHM=
qVFXaeyfU0hp1YPQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DH2=
AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}}</style>
                    <meta http-equiv=3D"X-UA-Compatible" content=3D"IE=3Ded=
ge">
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8">
<meta name=3D"viewport" content=3D"width=3Ddevice-width; initial-scale=3D1.=
0; maximum-scale=3D1.0;">
<title id=3D"template_title"></title>
<style type=3D"text/css" id=3D"acrstyle">
td{/*position:relative*/}
html{width:100%;}
body{width:100%;background-color:#ffffff;margin:0;padding:0;}
#template_body a img{border:none;}
*{margin-top:0px;margin-bottom:0px;padding:0px;border:none;outline:none;lis=
t-style:none;-webkit-text-size-adjust:nonel}
div{line-height:}
body{margin-top:0 !important;margin-bottom:0 !important;padding-top:0 !impo=
rtant;padding-bottom:0 !important;width:100% !important;-webkit-text-size-a=
djust:100% !important;-ms-text-size-adjust:100% !important;-webkit-font-smo=
othing:antialiased !important;}
img{border:0 !important;outline:none !important;}
table{border-collapse:collapse;mso-table-lspace:0px;mso-table-rspace:0px;}
td {border-collapse:collapse;mso-line-height-rule:exactly;}
a {border-collapse:collapse;mso-line-height-rule:exactly;}
span {border-collapse:collapse;mso-line-height-rule:exactly;}
.ExternalClass * {line-height: 100%;}
.ExternalClass, .ExternalClass p, .ExternalClass span, .ExternalClass font,=
 .ExternalClass td, .ExternalClass a, .ExternalClass div {line-height: 100%=
;}
.copy a {color: #444444;text-decoration:none;}
.preheader1 {display: none !important; font-size:0px; visibility: hidden; o=
pacity: 0; color: transparent; height: 0; width: 0;}
#preheader1 {display: none !important; font-size:0px; visibility: hidden; o=
pacity: 0; color: transparent; height: 0; width: 0;}
</style><style type=3D"text/css" id=3D"block_social_css">=20
.block_social table{border-collapse:collapse;mso-table-lspace:0pt;mso-table=
-rspace:0pt;}                  =20
.block_social a img{border:0;}
.block_social a, .block_social a:hover, .block_social a:visited{text-decora=
tion:none;}

@media only screen and (max-width:480px){
.block_social table[class*=3Dmain_table]{width:320px !important;}          =
           =20
.block_social td[class*=3Dpad_both]{padding-left:20px !important;padding-ri=
ght:20px !important;}          =20
} </style><style type=3D"text/css" id=3D"block_spacer_css"> .block_spacer t=
able{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}  =
                =20
.block_spacer a img{border:0;}
.block_spacer a, .block_spacer a:hover, .block_spacer a:visited{text-decora=
tion:none;}         =20
@media only screen and (max-width:480px){
.block_spacer table[class*=3Dmain_table]{width:320px !important;}          =
           =20
.block_spacer td[class*=3Dpad_both]{padding-left:20px !important;padding-ri=
ght:20px !important;}          =20
} </style><style type=3D"text/css" id=3D"block_texto_css">=20
.block_texto table{border-collapse:collapse;mso-table-lspace:0pt;mso-table-=
rspace:0pt;}                  =20
.block_texto a img{border:0;}
.block_texto .texto{word-wrap:break-word;}
.block_texto a, .block_texto a:hover, .block_text a:visited{text-decoration=
:none;}         =20
@media only screen and (max-width:480px){
.block_texto table[class*=3Dmain_table]{width:320px !important;}           =
          =20
.block_texto td[class*=3Dpad_both]{padding-left:20px !important;padding-rig=
ht:20px !important;}          =20
} </style><style type=3D"text/css" id=3D"block_seccion_css">=20
.block_seccion table{border-collapse:collapse;mso-table-lspace:0pt;mso-tabl=
e-rspace:0pt;}                  =20
.block_seccion a img{border:0;}
.block_seccion a, .block_seccion a:hover, .block_seccion a:visited{text-dec=
oration:none;}         =20
@media only screen and (max-width:480px){
.block_seccion table[class*=3Dmain_table]{width:280px !important;}         =
=20
} </style><style type=3D"text/css" id=3D"block_logo_css"> .block_logo table=
{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}      =
            =20
.block_logo a img{border:none;}                 =20
.block_logo img{border:none;}
.block_logo a, .block_logo a:hover, .block_logo a:visited{text-decoration:n=
one !important;}          =20
@media only screen and (max-width:480px){
.block_logo table[class*=3Dmain_table]{width:320px !important;}            =
         =20
.block_logo td[class*=3Dpad_both]{padding-left:20px !important;padding-righ=
t:20px !important;}          =20
} </style><style type=3D"text/css" id=3D"acrstyle2">tr[class*=3D'block'] *{=
list-style:inherit} tr[class*=3D'block'] ul{margin-bottom:10px;list-style-t=
ype:disc !important;} tr[class*=3D'block'] ol{margin-bottom:10px;list-style=
-type:decimal !important;} tr[class*=3D'block'] ul{margin-left:15px !import=
ant;  list-style-position:inside;} tr[class*=3D'block'] ol{margin-left:15px=
 !important;  list-style-position:inside;}</style><!--[if gte mso 9]><style=
 type=3D'text/css'>li{margin-left:20px;}</style><![endif]-->
<style id=3D"block_link_browser" type=3D"text/css">
.block_link_browser table[class*=3Dmain_table]{width:580px;}
.block_link_browser table{border-collapse:collapse;mso-table-lspace:0pt;mso=
-table-rspace:0pt;}                  =20
.block_link_browser a img{border:0;}          =20
@media only screen and (max-width:480px){
body {width:auto;}
.block_link_browser table[class=3D"BoxWrap"]{width:280px;}
.block_link_browser table[class*=3Dmain_table]{width:320px !important;}
.block_link_browser td[class*=3Dpad_both]{padding-left:20px !important;padd=
ing-right:20px !important;}
}
</style>
<style id=3D"block_links_footer" type=3D"text/css">
.block_links_footer table[class=3D"BoxWrap"]{width:580px;}
.block_links_footer table{border-collapse:collapse;mso-table-lspace:0pt;mso=
-table-rspace:0pt;}                  =20
.block_links_footer a img{border:0;}          =20
@media only screen and (max-width:480px){
body {width:auto;}
.block_links_footer table[class=3D"BoxWrap"]{width:280px;}
.block_links_footer table[class*=3Dmain_table]{width:320px !important;}
.block_links_footer td[class*=3Dpad_both]{padding-left:20px !important;padd=
ing-right:20px !important;}  =20
}
</style>
<style id=3D"block_links_footer" type=3D"text/css">
.block_spacer table{border-collapse:collapse;mso-table-lspace:0pt;mso-table=
-rspace:0pt;}                  =20
.block_spacer a img{border:0;}
.block_spacer a, .block_spacer a:hover, .block_spacer a:visited{text-decora=
tion:none;}         =20
@media only screen and (max-width:480px){
.block_spacer table[class*=3Dmain_table]{width:320px !important;}          =
           =20
.block_spacer td[class*=3Dpad_both]{padding-left:20px !important;padding-ri=
ght:20px !important;}          =20
}
</style>
<style type=3D"text/css">@media only screen and (max-width:480px){.wrapper,=
.main_table,#Imgfull,.BoxWrap,.block_texto table,.block_texto img,.block_se=
ccion table,.block_seccion img,.block_2col table,.block_2col img,.block_2co=
l_complete table,.block_2col_complete img,.block_2col_image table,.block_2c=
ol_image img,.block_3col table,.block_3col img,.block_3col_complete table,.=
block_3col_complete img,.block_3col_image table,.block_3col_image img,.bloc=
k_image table,.block_image img,.block_image_full_complete table,.block_imag=
e_full_complete img,.block_image_left table,.block_image_left img,.block_im=
age_left_text table,.block_image_left_text img,.block_image_right table,.bl=
ock_image_right img,.block_image_right_text table,.block_image_right_text i=
mg,.block_image_small_left table,.block_image_small_left img,.block_image_s=
mall_right table,.block_image_small_right img,.block_logo table,.block_logo=
 img,.block_qrcode table,.block_qrcode img,.block_video table,.block_video =
img,.block_button table,.block_button img,.block_seccion_titulo_texto_boton=
 table,.block_seccion_titulo_texto_boton img,.block_spacer table,.block_spa=
cer table.main_table,.block_spacer .main_table,.qrimage{max-width:100%!impo=
rtant;width:100%!important;min-width:100%!important}tbody{display:table!imp=
ortant;min-width:100%!important;width:100%!important;max-width:100%!importa=
nt}.block_3col_complete table[class*=3Dwrapper]{display:table!important}.bl=
ock_qrcode table.main_table td[width=3D"20"]{height:0px!important;width:0px=
!important;display:none!important;visibility:hidden!important}.block_qrcode=
 table.main_table td[height=3D"20"]{height:0px!important;width:0px!importan=
t;display:none!important;visibility:hidden!important}img,.qrimage,table,td[=
class*=3D"pad_both"],table[class=3D"wrapper"],table[class=3D"main_table"],#=
Imgfull,.wrapper,.main_table,.BoxWrap{max-width:100%!important;width:100%!i=
mportant;min-width:100%!important}.block_seccion img,.HeadTxt img,.title1 i=
mg,.texto img,tr.block_footer img,tr.block_social img,.Txt img,.Section img=
,.Title img{width:inherit!important;min-width:inherit!important;max-width:i=
nherit!important}tr[class*=3D"block_"] td[class*=3D"pad_both"],td.pad_both{=
padding:0px!important}tr.block_links_footer .pad_both{padding-left:20px!imp=
ortant;padding-right:20px!important}tr.block_links_footer a{display:block!i=
mportant}tr.block_links_footer td>span{display:block!important;padding-bott=
om:10px!important}tr[class*=3D"block_"]{width:100px!important}.block_spacer=
 td.pad_both{padding-left:0px!important;padding-right:0px!important;max-wid=
th:100%!important;width:100%!important}}</style>


<!--[if gte mso 9]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPer=
Inch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]--><styl=
e type=3D"text/css">.preheader1{display:none !important;font-size:0px;visib=
ility:hidden;opacity:0;color:transparent;height:0;width:0;}
  #preheader1{display:none !important;font-size:0px;visibility:hidden;opaci=
ty:0;color:transparent;height:0;width:0;}</style></head><body><span style=
=3D" display:none !important;visibility:hidden;opacity:0;color:transparent;=
height:0;width:0;font-size:1px !important" id=3D"preheader1" class=3D"prehe=
ader1">Env&iacute;o de res&uacute;menes: 26 de mayo de 2025 Congreso CUICII=
D 2025</span><div style=3D"display:none;max-height:0px;overflow:hidden;">&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;</div><table height=3D"" bgcolor=3D" #fdfbfc" width=
=3D"100%" cellpadding=3D"0" cellspacing=3D"0" align=3D"center" class=3D"ui-=
sortable" style=3D"background-color: rgb(253, 251, 252); border-width: init=
ial; border-style: none; border-color: initial; margin-top: 0px; padding: 0=
px; margin-bottom: 0px;">
	<tbody>
		<tr class=3D"block_link_browser">
			<td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: =
rgb(253, 251, 252); padding: 0px;">
				<table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" a=
lign=3D"center" style=3D"margin: 0px auto; width: 580px; " class=3D"main_ta=
ble ">                  =20
                    <tbody><tr>
                      <td class=3D"pad_both">
                        <table width=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0" align=3D"center" style=3D"">
                          <tbody><tr>
                            <td>
                                <table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D"">
                                    <tbody><tr>
                                      <td height=3D"25" style=3D"text-align=
:center; font-size: 11px; color: #b3b3b3; font-family: Helvetica, Arial, sa=
ns-serif; vertical-align: middle;">
                                            <a href=3D"https://www.campaign=
-index.com/view.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
style=3D"text-decoration: underline; color:#333;"><span>Ver en navegador</s=
pan></a>
                                      </td>
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                        </tbody></table>
                      </td>
                    </tr>                  =20
                 </tbody></table>
			</td>
		</tr>
		<tr class=3D"block_spacer">=20
	<td width=3D"100%" valign=3D"top" style=3D"background-color: rgb(253, 251,=
 252); height: 20px; border-width: initial; border-style: none; border-colo=
r: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D"" =
height=3D"20" bgcolor=3D" #fdfbfc">
		<table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D=
"0" align=3D"center" style=3D"margin:0 auto; height:100%">
			<tbody><tr>
				<td height=3D"100%" style=3D"height: 100%; line-height: 20px;">
                    <table width=3D"580" height=3D"100%" border=3D"0" cells=
pacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=
=3D"height: 100%; width: 580px;">                      =20
                        <tbody><tr>
                            <td class=3D"pad_both" style=3D"background-colo=
r: inherit; height: 100%; line-height: 20px;" height=3D"100%">
                                <table width=3D"100%" height=3D"100%" borde=
r=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-=
width: initial; border-style: none; border-color: initial; margin-top: 0px;=
 padding: 0px; margin-bottom: 0px;" class=3D"">
                                    <tbody><tr>
                                      <td width=3D"100%" height=3D"100%" st=
yle=3D"display: block; height: 100%; line-height: 20px; padding: 0px;">&nbs=
p;</td>                                    =20
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                    </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr>
		<tr class=3D"block_logo">=20
	<td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: rg=
b(253, 251, 252);">
		<table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"cen=
ter" style=3D"margin:0 auto;">
			<tbody><tr>
				<td>
                    <table width=3D"580" border=3D"0" cellspacing=3D"0" cel=
lpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"width:580px;"=
>                      =20
                        <tbody><tr>
                            <td class=3D"pad_both" style=3D"background-colo=
r: inherit;">
                                <table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" style=3D" border-width: initial; border-style: =
none; border-color: initial; margin-top: 0px; padding: 0px; margin-bottom: =
0px;" class=3D"">
                                    <tbody><tr>                            =
        =20
                                      <td style=3D"padding: 0px;"><table wi=
dth=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"cent=
er">                                         =20
                                          <tbody><tr>
                                            <td>
                                                <table align=3D"center" sty=
le=3D"font-size: 13px; font-weight: 400; font-family: Helvetica, Arial, san=
s-serif;  border-width: initial; border-style: none; border-color: initial;=
 padding: 0px; margin: 0px auto;" class=3D"">
                                                    <tbody><tr>
                                                        <td style=3D"paddin=
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3DktaxhLZ0BLked=
rrET0q3CA&J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCb=
cnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=3D""=
><img align=3D"absbottom" border=3D"0" id=3D"Imgfull" width=3D"123" src=3D"=
https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/L=
OGO%20PEQUE%C3%91O%20CUICIID%202025.png?1745364023509" alt=3D"CUICIID" styl=
e=3D"width: 123px; max-width: 123px; text-align: center; font-size: 18px; c=
olor: rgb(255, 255, 255); font-weight: 700; text-shadow: black 0.1em 0.1em =
0.2em; text-transform: uppercase;" class=3D"acre_image_editable" ac:percent=
=3D"44"></a></td>
                                                    </tr>
                                                </tbody></table>
                                            </td>
                                          </tr>                            =
             =20
                                        </tbody></table></td>              =
                       =20
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                    </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr>
		<tr class=3D"block_seccion">=20
	<td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: rg=
b(253, 251, 252);">
		<table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"cen=
ter" style=3D"margin:0 auto;">
			<tbody><tr>
				<td>
            <table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=
=3D"0" align=3D"center" class=3D"main_table" style=3D"width:580px;">       =
               =20
                <tbody><tr>
                    <td style=3D"padding: 4px 20px;  border-width: initial;=
 border-style: none; border-color: initial; margin-top: 0px; margin-bottom:=
 0px;" class=3D"">
                        <table width=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0">
                            <tbody><tr>                                    =
 =20
                              <td><table width=3D"100%" border=3D"0" cellsp=
acing=3D"0" cellpadding=3D"0" align=3D"center">
                                  <tbody><tr>
                                   =20
                                  <td block=3D"" style=3D"word-break: break=
-word; overflow-wrap: break-word; text-align: left; padding-bottom: 3px; fo=
nt-size: 16px; margin-bottom: 7px; padding-top: 4px; font-family: Helvetica=
, Arial, sans-serif; text-decoration: none; color: rgb(69, 72, 78);">
<div style=3D"line-height: 20px; text-align: center;"><span style=3D"font-s=
ize:16px"><span style=3D"color:#000000"><strong>Congreso Internacional </st=
rong></span><span style=3D"color:#008000"><strong>CUICIID 2025</strong></sp=
an></span></div>
</td></tr>
                                </tbody></table></td>                      =
               =20
                            </tr>
                          </tbody></table>
                      </td>
                  </tr>
            </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr><tr class=3D"block_spacer">=20
	<td width=3D"100%" valign=3D"top" class=3D"" style=3D"height: 20px;" heigh=
t=3D"20">
		<table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D=
"0" align=3D"center" style=3D"margin:0 auto; height:100%">
			<tbody><tr>
				<td height=3D"100%" style=3D"height: 100%; line-height: 20px;">
            <table width=3D"580" height=3D"100%" border=3D"0" cellspacing=
=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"hei=
ght: 100%;width:580px;">                      =20
                <tbody><tr>
                    <td class=3D"pad_both" style=3D"background-color: inher=
it; height: 100%; line-height: 20px;" height=3D"100%">
                        <table width=3D"100%" height=3D"100%" border=3D"0" =
cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-width: i=
nitial; border-style: none; border-color: initial; margin-top: 0px; padding=
: 0px; margin-bottom: 0px;" class=3D"">
                            <tbody><tr>
                              <td width=3D"100%" height=3D"100%" style=3D"d=
isplay: block; height: 100%; line-height: 20px; padding: 0px;">&nbsp;</td> =
                                   =20
                            </tr>
                          </tbody></table>
                      </td>
                  </tr>
            </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr><tr class=3D"block_texto">=20
	<td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: rg=
b(253, 251, 252);">
		<table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"cen=
ter" style=3D"margin:0 auto;">
			<tbody><tr>
				<td>
          <table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=
=3D"0" align=3D"center" class=3D"main_table" style=3D"width:580px;">       =
               =20
              <tbody><tr>
                  <td class=3D"pad_both" style=3D"background-color: inherit=
;">
                      <table width=3D"100%" border=3D"0" cellspacing=3D"0" =
cellpadding=3D"0" style=3D"background-color: rgb(255, 255, 255); border: no=
ne;  margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D"" bgcolor=
=3D" #ffffff">
                          <tbody><tr>
                            <td style=3D"background-color: rgb(255, 255, 25=
5); padding: 0px; width: 20px;" width=3D"20">&nbsp;</td>
                            <td style=3D"background-color: rgb(255, 255, 25=
5); padding: 0px;"><table width=3D"100%" border=3D"0" cellspacing=3D"0" cel=
lpadding=3D"0" align=3D"center">
                                <tbody><tr>
                                  <td height=3D"20">&nbsp;</td>
                                </tr>
                                <tr>
                                 =20
                                <td block=3D"" class=3D"texto" style=3D"wor=
d-break: break-word; overflow-wrap: break-word; font-size: 13px; line-heigh=
t: initial; font-family: Helvetica, Arial, sans-serif; color: rgb(123, 123,=
 123);">
<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">Estimados colegas, caros colegas, chers coll&=
egrave;gues, cari colleghi, dear colleagues:<br>
<br>
Estamos orgullosos de presentar ante la Academia la XV&nbsp;edici&oacute;n =
del <strong>Congreso VIRTUAL</strong> y </span><strong><span style=3D"color=
:#000000">EN L&Iacute;NEA (no presencial)</span> <span style=3D"color:#0080=
00">CUICIID 2025</span></strong> <span style=3D"color:#000000">(Congreso Un=
iversitario Internacional sobre Contenidos, Investigaci&oacute;n, Innovaci&=
oacute;n y Docencia) </span><span style=3D"color:#0000FF"><u>www.cuiciid.ne=
t</u></span><br>
<br>
<span style=3D"color:#000000">Los <strong>idiomas oficiales</strong> son: <=
strong>espa&ntilde;ol, portugu&eacute;s, italiano, ingl&eacute;s y franc&ea=
cute;s</strong> y se podr&aacute;n presentar 2 ponencias por autor (individ=
ualmente o en coautor&iacute;a) publicables en <strong>Libro electr&oacute;=
nico de la&nbsp;</strong></span><span style=3D"color:rgb(0, 0, 0)">&ldquo;<=
/span><strong style=3D"color:rgb(0, 0, 0)">Colecci&oacute;n Acad&eacute;mic=
a Iberoamericana del siglo XXI</strong><span style=3D"color:rgb(0, 0, 0)">&=
rdquo;</span><strong style=3D"color:rgb(0, 0, 0)">&nbsp;indizado en SCOPUS =
BOOKS INDEX</strong><span style=3D"color:rgb(0, 0, 0)"> en 2026 o en </span=
><strong style=3D"color:rgb(0, 0, 0)">Libro electr&oacute;nico de la editor=
ial LA MURALLA </strong><span style=3D"color:rgb(0, 0, 0)">(indizado en SPI=
 Q1) en 2026.</span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">&nbsp;</span><br>
<span style=3D"color:#008000"><strong>CUICIID 2025</strong> </span><span st=
yle=3D"color:#000000">destaca por su vocaci&oacute;n internacional y su amp=
lia <strong>visibilizaci&oacute;n</strong> ya que sus <strong>resultados cu=
rriculares </strong>(<strong>tras revisi&oacute;n por dobles pares ciegos</=
strong>) ser&aacute;n publicados en:</span>
</div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000"><u>PONENCIAS</u></span>

	<ul>
		<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"colo=
r:#000000">Para <strong>autores iberoamericanos</strong> en exclusiva: Como=
 cap&iacute;tulo de libro electr&oacute;nico de la&nbsp;&ldquo;<strong>Cole=
cci&oacute;n Acad&eacute;mica Iberoamericana del siglo XXI</strong>&rdquo; =
(<strong>indizada en S</strong><strong>COPUS BOOKS INDEX</strong>) en <stro=
ng>idioma ingl&eacute;s&nbsp;</strong>con 10 p&aacute;ginas como m&aacute;x=
imo.</span></li>
		<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"colo=
r:#000000">Para <strong>autores europeos y los iberoamericanos que lo desee=
n</strong>: Como cap&iacute;tulo de libro electr&oacute;nico de la colecci&=
oacute;n&nbsp;&ldquo;<strong>Innovaci&oacute;n y Formaci&oacute;n</strong>"=
 de la editorial La Muralla (Q1 en SPI) en cualquiera de los idiomas oficia=
les del congreso, con 14 p&aacute;ginas como m&aacute;ximo.</span></li>
	</ul>
	</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><u>RES&Uacute;MENES</u>: En&nbsp;<em>Libro de Actas</em> con ISBN=
.</span></li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Fechas clave:</strong></span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>26 de mayo</strong> (lunes). &Uacute;ltimo d&iacute;a&nbs=
p;para el env&iacute;o de Res&uacute;menes (1 p&aacute;gina).</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Desde 29 de mayo</strong> (jueves). Env&iacute;o de infor=
mes de aceptaci&oacute;n o denegaci&oacute;n tras revisi&oacute;n por pares=
 ciegos.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>30 de junio</strong> (lunes). Cierre de pago de matr&iacu=
te;cula (225&nbsp;&euro; por cada autor y por cada ponencia, m&aacute;ximo =
2&nbsp;ponencias). Se puede fraccionar el pago en 4 mensualidades de 75 + 5=
0 + 50 + 50 &euro;.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>7 de julio</strong> (lunes). &Uacute;ltimo d&iacute;a par=
a el env&iacute;o de ponencias.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>28 de julio</strong> (lunes).&nbsp;<strong>Voluntario</st=
rong>. Env&iacute;o de <strong>v&iacute;deos</strong> (.mov, .mp4 o .mpeg) =
para la defensa grabada.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>15 de septiembre </strong>(lunes).&nbsp;<strong>Voluntari=
o</strong>. Solicitud de <strong>defensa en directo</strong>.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>22, 23 y 24 de octubre</strong> (mi&eacute;rcoles,&nbsp;j=
ueves y viernes). Celebraci&oacute;n del Congreso (virtual y en l&iacute;ne=
a, <strong>no presencial</strong>).</span></li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000">Compuesto por <strong>6 &Aacute;reas tem&aacute;ticas</strong>:</=
span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Comunicaci&oacute;n: </strong>Comunicaci&oacute;n persuas=
iva, Alfabetizaci&oacute;n medi&aacute;tica, Influencers, Bulos, Marketing =
digital, Neuromarketing, Publicidad, Relaciones P&uacute;blicas, Periodismo=
, Eventos, Protocolo, Lo audiovisual (cine, radio, TV e Internet), Comunica=
ci&oacute;n legal y m&eacute;dica, RSC,&nbsp;COVID-19, Alfabetizaci&oacute;=
n medi&aacute;tica...</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Docencia: </strong>Nueva metodolog&iacute;as, e-learnig, =
b-learning, flipped classrom, TIC, STEAM, F&oacute;rmulas y contenidos doce=
ntes, Pol&iacute;ticas educativas,&nbsp;EEES,&nbsp;LOSU, pol&iacute;ticas e=
ducativas...</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Ciencias Sociales y Humanismo: </strong>Turismo, Patrimon=
io, Antropolog&iacute;a, Cultura, Derecho, Ling&uuml;&iacute;stica, Semi&oa=
cute;tica, Historia, Religi&oacute;n, Filosof&iacute;a, G&eacute;nero, Psic=
olog&iacute;a, Sociolog&iacute;a, Sociedad, Agenda 2030, ODS.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Innovaci&oacute;n: </strong>Trabajos doctorales, Tem&aacu=
te;ticas emergentes, Redes Sociales, Meta, Contenidos acad&eacute;micos act=
uales, Emprendimiento.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Investigaci&oacute;n e Inteligencia Artificial: </strong>=
Nuevos proyectos, Investigaciones I+D+i, Art&iacute;culos 60, Investigacion=
es no regladas, Biblioteconom&iacute;a, Ingenier&iacute;as, Criterios de ev=
aluaci&oacute;n, Inteligencia Artificial, ChatGPT, Deepseek, Dall-e.</span>=
</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Miscel&aacute;nea: </strong>&Aacute;rea abierta a contrib=
uciones transversales.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Paneles tem&aacute;ticos: </strong>Propuestos por autores=
 (m&iacute;nimo 4 ponencias por panel). Ideal para <u>Grupos de Investigaci=
&oacute;n</u>.</span></li>
</ul>

<div style=3D"line-height:20px;"><span style=3D"color:#008000">&nbsp;</span=
></div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#008000"><strong>CUICIID</strong></span><span style=3D=
"color:#000000"><strong> </strong>es el espacio id&oacute;neo para la visib=
ilizaci&oacute;n de trabajos de <strong>doctorandos</strong> e <strong>inve=
stigadores</strong> de nuevo cu&ntilde;o en los &aacute;mbitos acad&eacute;=
micos de mayor relevancia. Recordamos que es enmarcable dentro de los Congr=
esos de mayor impacto, los ubicados bajo el concepto &lsquo;<strong>Congres=
os de Calidad de la formaci&oacute;n docente</strong>&rsquo;, por aunar la =
<strong>innovaci&oacute;n</strong> y la <strong>docencia</strong> y, merced=
 a la <strong>revisi&oacute;n por dobles pares ciegos</strong> de los traba=
jos presentados, sus resultados tienen un alto valor curricular.</span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">&nbsp;<br>
Como &uacute;ltimo punto de inter&eacute;s, </span><span style=3D"color:#00=
8000"><strong>CUICIID </strong></span><span style=3D"color:#000000">quiere =
focalizar sus esfuerzos en animar a los <strong>Grupos y Equipos de Investi=
gaci&oacute;n</strong> que desean visibilizar sus resultados investigadores=
 en publicaciones de primer nivel.<br>
&nbsp;<br>
Para cualquier duda, los emplazamos en la web:</span> <u><a href=3D"https:/=
/www.email-index.com/click.php?L=3Dh7DNyLDCWnifjyjWiZm30A&J=3DH2AaNz3PSmvkL=
SnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"=
_blank"><span style=3D"color:#0000FF">www.cuiciid.net</span></a></u><span s=
tyle=3D"color:#0000FF"> </span><span style=3D"color:#000000">y en nuestro c=
orreo: </span><u><a href=3D"mailto:cuiciid2024@forumxxi.net" target=3D"_bla=
nk"><span style=3D"color:#0000FF">cuiciid2025@forumxxi.net</span></a></u>
</div>

<div style=3D"line-height:20px;"><span style=3D"color:#000000">&nbsp;</span=
></div>

<div style=3D"line-height:20px;">
<span style=3D"color:#000000">&nbsp;<br>
Reciban mi m&aacute;s cordial saludo.<br>
&nbsp;<br>
<strong>David Caldevilla Dom&iacute;nguez</strong><br>
Universidad Complutense<br>
<strong>Director del Congreso </strong></span><span style=3D"color:#008000"=
><strong>CUICIID 2025</strong></span>
</div>
</td></tr>
                                <tr>
                                  <td height=3D"20">&nbsp;</td>
                                </tr>
                              </tbody></table></td>
                            <td style=3D"background-color: rgb(255, 255, 25=
5); padding: 0px; width: 20px;" width=3D"20">&nbsp;</td>
                          </tr>
                        </tbody></table>
                    </td>
                </tr>
          </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr><tr class=3D"block_social">
    <td valign=3D"top" style=3D""><table width=3D"100%" border=3D"0" cellsp=
acing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D"">
        <tbody><tr>
          <td align=3D"center"><table width=3D"580" border=3D"0" cellspacin=
g=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"wi=
dth:580px;">             =20
              <tbody><tr>
                <td class=3D"pad_both"><table width=3D"100%" border=3D"0" c=
ellspacing=3D"0" cellpadding=3D"0" style=3D"background-color: rgb(255, 255,=
 255); border: none;  margin-top: 0px; padding: 0px; margin-bottom: 0px;" c=
lass=3D"" bgcolor=3D" #ffffff">
                    <tbody><tr>
                      <td width=3D"20" class=3D"hide" style=3D"width: 20px;=
 background-color: rgb(255, 255, 255); padding: 0px;">&nbsp;</td>
                      <td style=3D"background-color: rgb(255, 255, 255); pa=
dding: 0px;"><table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpaddi=
ng=3D"0" align=3D"center">
                          <tbody><tr>
                            <td height=3D"20">&nbsp;</td>
                          </tr>
                          <tr>
                            <td align=3D"center">                          =
 =20
                                <table border=3D"0" cellpadding=3D"0" cells=
pacing=3D"0" width=3D"100%" style=3D"min-width:100%;">
                                <tbody><tr>
                                    <td align=3D"center" valign=3D"top">
                                        <table align=3D"center" border=3D"0=
" cellpadding=3D"0" cellspacing=3D"0">
                                            <tbody><tr>
                                                <td align=3D"center" valign=
=3D"top">                                                   =20
                                                    <table align=3D"center"=
 border=3D"0" cellspacing=3D"0" cellpadding=3D"0">
                                                    <tbody><tr>            =
                                                                           =
             =20
                                                        <td align=3D"center=
" valign=3D"top">                                                 =20
                                                            <table align=3D=
"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:in=
line;">
                                                                <tbody><tr>
                                                                    <td val=
ign=3D"top">
                                                                        <ta=
ble border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%">
                                                                           =
 <tbody><tr>
                                                                           =
     <td align=3D"left" valign=3D"middle" style=3D"padding:3px">
                                                                           =
         <table align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" width=3D"">
                                                                           =
             <tbody><tr>   =20
                                                                           =
                     <td align=3D"center" valign=3D"middle" width=3D"38" st=
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dq3=
3Dv7be0QGfn7PDwD4flg&J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;"=
 title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" st=
yle=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: bl=
ock; text-align: center; font-size: 18px; color: rgb(255, 255, 255); font-w=
eight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase=
;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-facebook-38.jp=
g" alt=3D"facebook CUICIID" class=3D"acre_image_editable"></a></td>
                                                                           =
             </tr>
                                                                           =
         </tbody></table>
                                                                           =
     </td>
                                                                           =
 </tr>
                                                                        </t=
body></table>
                                                                    </td>
                                                                </tr>
                                                            </tbody></table=
>                                              =20
                                                        </td>
                                                        <td align=3D"center=
" valign=3D"top">
                                                            <table align=3D=
"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:in=
line;">
                                                                <tbody><tr>
                                                                    <td val=
ign=3D"top">
                                                                        <ta=
ble border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%">
                                                                           =
 <tbody><tr>
                                                                           =
     <td align=3D"left" valign=3D"middle" style=3D"padding:3px">
                                                                           =
         <table align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" width=3D"">
                                                                           =
             <tbody><tr>
                                                                           =
                     <td align=3D"center" valign=3D"middle" width=3D"38" st=
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DL7=
xCJiYMOXGxWK4QRu78Fw&J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;"=
 title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" st=
yle=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: bl=
ock; text-align: center; font-size: 18px; color: rgb(255, 255, 255); font-w=
eight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase=
;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twitter-38.jpg=
" alt=3D"twitter CUICIID" class=3D"acre_image_editable"></a></td>
                                                                           =
             </tr>
                                                                           =
         </tbody></table>
                                                                           =
     </td>
                                                                           =
 </tr>
                                                                        </t=
body></table>
                                                                    </td>
                                                                </tr>
                                                            </tbody></table=
>                                                                          =
                                    =20
                                                        </td>              =
                                   =20
                                                        <td align=3D"center=
" valign=3D"top">                                                          =
                                          =20
                                                            <table align=3D=
"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:in=
line;">
                                                                <tbody><tr>
                                                                    <td val=
ign=3D"top">
                                                                        <ta=
ble border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%">
                                                                           =
 <tbody><tr>
                                                                           =
     <td align=3D"left" valign=3D"middle" style=3D"padding:3px;">
                                                                           =
         <table align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" width=3D"">
                                                                           =
             <tbody><tr>
                                                                           =
                     <td align=3D"center" valign=3D"middle" width=3D"38" st=
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DIi=
ZfCNAIhjLFyw7763SGGzsg&J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YP=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block=
;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" =
style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: =
block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); font=
-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upperca=
se;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-linkedin-38.=
jpg" alt=3D"linkedin CUICIID" class=3D"acre_image_editable"></a></td>
                                                                           =
             </tr>
                                                                           =
         </tbody></table>
                                                                           =
     </td>
                                                                           =
 </tr>
                                                                        </t=
body></table>
                                                                    </td>
                                                                </tr>
                                                            </tbody></table=
>                                                      =20
                                                        </td>
                                                       =20
                                                       =20
                                                       =20
                                                    </tr>
                                                    </tbody></table>
                                                </td>
                                            </tr>
                                        </tbody></table>
                                    </td>
                                </tr>
                            </tbody>
                            </table>
                            </td>
                          </tr>
                          <tr>
                            <td height=3D"20">&nbsp;</td>
                          </tr>
                        </tbody></table></td>
                      <td width=3D"20" class=3D"hide" style=3D"width: 20px;=
 background-color: rgb(255, 255, 255); padding: 0px;">&nbsp;</td>
                    </tr>
                  </tbody></table></td>
              </tr>           =20
            </tbody></table></td>
        </tr>
      </tbody></table></td>
  </tr><tr class=3D"block_spacer">=20
	<td width=3D"100%" valign=3D"top" style=3D"background-color: rgb(253, 251,=
 252);" class=3D"">
		<table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D=
"0" align=3D"center" style=3D"margin:0 auto; height:100%">
			<tbody><tr>
				<td height=3D"100%" style=3D"height: 100%; line-height:25px">
                    <table width=3D"580" height=3D"100%" border=3D"0" cells=
pacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=
=3D"height: 100%; width: 580px;">                      =20
                        <tbody><tr>
                            <td class=3D"pad_both" style=3D"background-colo=
r: inherit; height:100%" height=3D"100%">
                                <table width=3D"100%" height=3D"100%" borde=
r=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-=
width: initial; border-style: none; border-color: initial; margin-top: 0px;=
 padding: 0px; margin-bottom: 0px;" class=3D"">
                                    <tbody><tr>
                                      <td width=3D"100%" height=3D"100%" st=
yle=3D"display: block; height: 100%; line-height: 25px; padding: 0px;">&nbs=
p;</td>                                    =20
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                    </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr>
		<tr class=3D"block_links_footer">
        	<td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-c=
olor: rgb(253, 251, 252);">
        		<table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=
=3D"0" align=3D"center" class=3D"main_table " style=3D"margin: 0px auto; wi=
dth: 580px; ">                  =20
                    <tbody><tr>
                      <td class=3D"pad_both">
                        <table width=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0" align=3D"center" style=3D"">
                          <tbody><tr>
                            <td>
                                <table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D" border-wi=
dth: initial; border-style: none; border-color: initial; margin-top: 0px; p=
adding: 0px; margin-bottom: 0px;">
                                    <tbody><tr>
                                      <td height=3D"20" style=3D"text-align=
: center; font-size: 11px; color: rgb(51, 51, 51); font-family: Helvetica, =
Arial, sans-serif; vertical-align: middle; padding: 0px;">
                                        <a href=3D"https://www.email-index.=
com/unsubscribe.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
style=3D"text-decoration: underline; color:#333;"><span>Darme de baja de es=
ta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" style=
=3D"text-decoration: underline; color:#333;"><span>Actualizar mis datos</sp=
an></a>
                                        <br><br>
                                      <span>HISTORIA DE LOS SISTEMAS INFORM=
ATIVOS - Cine n&ordm; 38. Bajo derecha, 28024, Madrid</span>
                                      </td>
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                        </tbody></table>
                      </td>
                    </tr>                  =20
                 </tbody></table>
        	</td>
        </tr>
       =20
        <tr class=3D"block_spacer">=20
	<td width=3D"100%" valign=3D"top" style=3D"background-color: rgb(253, 251,=
 252);" class=3D"">
		<table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D=
"0" align=3D"center" style=3D"margin:0 auto; height:100%">
			<tbody><tr>
				<td height=3D"100%" style=3D"height: 100%; line-height:25px">
                    <table width=3D"580" height=3D"100%" border=3D"0" cells=
pacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=
=3D"height: 100%; width: 580px;">                      =20
                        <tbody><tr>
                            <td class=3D"pad_both" style=3D"background-colo=
r: inherit; height:100%" height=3D"100%">
                                <table width=3D"100%" height=3D"100%" borde=
r=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-=
width: initial; border-style: none; border-color: initial; margin-top: 0px;=
 padding: 0px; margin-bottom: 0px;" class=3D"">
                                    <tbody><tr>
                                      <td width=3D"100%" height=3D"100%" st=
yle=3D"display: block; height: 100%; line-height: 25px; padding: 0px;">&nbs=
p;</td>                                    =20
                                    </tr>
                                  </tbody></table>
                              </td>
                          </tr>
                    </tbody></table>               =09
				</td>
			</tr>
		</tbody></table>
	</td>
</tr>
       =20
       =20
	</tbody>
</table>























































































                        <table id=3D"ac_footer_email" width=3D"100%" style=
=3D"width:100%">
                            <tr>
                                <td width=3D"100%" valign=3D"top" align=3D"=
center">
                                    <table width=3D"" align=3D"center">
                                        <tr>
                                            <td style=3D"text-align:center;=
"><a href=3D"https://www.email-index.com/click.php?L=3DsXKuUJu763892sUBYOcU=
DXsKig&J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCbcnm=
xmc4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"border-=
style:none;min-width: initial !important;max-width: initial !important;widt=
h: initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/upload=
s/user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA=
 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DH2AaNz3PSmvkLSnNtHiJOw&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" alt=3D""=
 border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px,border=
:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01804cc9dc4-000000%40eu=
-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">https://group=
s.google.com/d/msgid/kasan-dev/0102019663e2cde7-2d8ad485-a4a8-4f5d-8c24-b01=
804cc9dc4-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_R6hnluezuG6gYEA7SN2bFZJafkqm9TsGr78vYtXEU--

