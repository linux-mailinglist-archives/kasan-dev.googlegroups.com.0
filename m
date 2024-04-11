Return-Path: <kasan-dev+bncBDUPD5FQ6MORBZVW4CYAMGQE6GIVLZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 563408A1B07
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 19:18:31 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-343bc1e4ef3sf5136278f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 10:18:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712855911; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSK+rqSGFRL/G3ACHzY8C3CM1nMcmKXCvYoJgPtNDoEv2XLDKOo9l5ABzaaf1MNSsh
         f7zdBcppQwq5ptb65S8CSTBk29YAeX/UcAE+24UrxjaAL2XPbRR2TBUCS06NXjVbIDuS
         eYLkOAceeOVWzOtuCo3ygnG2/T34d430uuqVtEz2eAYP3sUr+k2wTC1qwVt/qS4L1ekE
         LyMikQVX5ckARvCVrVTaPBZ3oAK2Lr02D4tbbMz8MxmSeQJFJ2QOiBVzeVLmFMEiWvVW
         3h0TkkHDGhOW2blJn+y3Yb2O66Q74JSIhKvuz9xn+vD7cl83RrVjooladd8bJFIXERZ9
         /yEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=RVUbGKB0hmrOG3A9OQX09uUigOnkZLJZ9YVvPsVd+7k=;
        fh=oEaIJzUT1xP1oiNZoIU558GcRzbQDE+b9yPtXoQ/8iQ=;
        b=ci2ngxC+yQoqF9PZDBlu4DfxBIEKk42HDLKn8v21eHkFnMb7jDEQBu2/E4Ql2Jvcdi
         rGZhFDXK6MTKM/QCtBH0h+5p2JNXWVEytY4wLdCf0xKX5d7hI256FEu3j9FR4D7LGI0P
         jviEWQZ2B9RX3MdUsIu3UxPvmm8SnY2thVX7tN8cQudGQ0FrainXQ6jvzVWvUDOcYBvd
         o7EbFFlZ873yQ0nm8ozC1P98Uw/98eyT9/cWlM+1DmAr6ZvRa5W/aPfPsSYrWI2nR5cL
         BnKtAqliD99dgGuDwZCpav0+m+5PRcOYJuc2k3FWyuOQPESxJS4fm/1XueHbUvPols5E
         LIVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b="tybT5z/N";
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=YID0rI8D;
       spf=pass (google.com: domain of 0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com designates 69.169.231.80 as permitted sender) smtp.mailfrom=0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712855911; x=1713460711; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RVUbGKB0hmrOG3A9OQX09uUigOnkZLJZ9YVvPsVd+7k=;
        b=Z3H3awFiJ8Zrwoy6dlmeyFfqmLmUxBDWMBukEqeweZr6tOy+KchZYxwMW+CRA32aL5
         SPfw72OyaN4Ul2rC8fDVDYZonb4v6MtU6ReJupCEe74EQr0k0oEA6+wX2KcOtw2X5FGS
         fF3wNqimpmfUI1gjPR02FrikMeIjjYrk2A96UP/gL5AlZQ/aZdpWVbNGntQ3oodDk9N7
         UBNKhlCe2mawflFXufyrpwHk7Q2F0hyDbt9LAqJnIuzavekImegE/HoF8ogwOnTRJFyY
         dnT5jokVeE0+HUNgwqSug0tAJjzaGBrs67iDrxPmYBA5ueZ5Ml8FG2NJC4rYmZsxWBNj
         l/dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712855911; x=1713460711;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RVUbGKB0hmrOG3A9OQX09uUigOnkZLJZ9YVvPsVd+7k=;
        b=OeJn91n1Bha4CFSsqm3DLBxQiJRaiFpSzxJ3kxmRC0h9obCWFV8YGyWbi1GxrCbfMM
         6ZLmwFSPamk5sphtfuvGvf9vCZoIBf6DI9C0K85LxO5Rk0P3UKTvrOgTYlELHDKYG0D9
         bWlYVM+y8oeIQuguZj4jAXmtfpTiu2rIaoLD7QTcrDBw2yXxxhTd3HE3KRvZfTb14n36
         +CG4Y8lU3koMA+djfTRsW2agkRYDmgmAK0uzq3E5vd0tQxT8cMBStVbmR9Oczm6IoeeP
         RLDBPkmRFtuEtTQ/mFLfawq8/6QlwFEeFRInD7shOT1GFMY0IVb2LCmA4VJi8LUwOjvZ
         FZrA==
X-Forwarded-Encrypted: i=2; AJvYcCXOgRekn8gpOqp+1cAqi14UR7tf+sR6cLoSY2z1nztBFoXwE3kLjv6cNF3dLk49qszkc+Dd98qfj0/ApMHI/B6tcE3Z461wGQ==
X-Gm-Message-State: AOJu0Yzlt+TA5N3fBhM+1lecmnvLKdtmju+l8dw8maCx8QTFKVjaDoed
	w4DLmtii2RXxOml7g9Ha6NnKm9/1srB/THwq0uvUBQvcZa+88Xhd
X-Google-Smtp-Source: AGHT+IGEAES3XnBfxvkk4DNmjPBbQasV8B55szWFgsmtiRBVhkOFx781C5NZdcLIS54vR4fZziIL8Q==
X-Received: by 2002:adf:f352:0:b0:343:81ea:c539 with SMTP id e18-20020adff352000000b0034381eac539mr154799wrp.28.1712855910252;
        Thu, 11 Apr 2024 10:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:16cf:b0:33e:77b4:c05d with SMTP id
 h15-20020a05600016cf00b0033e77b4c05dls67870wrf.0.-pod-prod-05-eu; Thu, 11 Apr
 2024 10:18:28 -0700 (PDT)
X-Received: by 2002:a05:600c:45cd:b0:417:dfbb:2ba8 with SMTP id s13-20020a05600c45cd00b00417dfbb2ba8mr406247wmo.41.1712855908255;
        Thu, 11 Apr 2024 10:18:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712855908; cv=none;
        d=google.com; s=arc-20160816;
        b=vyt2kHUkIs/klYB3dtPnQmdMoArvh50mdYx2xOgoMLvYuOa055UrAbL9ZXLHvA6Rlt
         rRidEZXnieCDfSzNLHFfFvZTa+IyzeLCqik4/kfVmDHnlIYIcTeB9cDzfRCH+keMMXTb
         9gXq6sLN5GJtX8hIdPCufRr16f3bmnAO6aKtRU1xS9YGwFT8PfLhKd3sFwckufk5x4Zy
         7K3aFHQJXpOFuAbHwl5J2HGYdKlNmFVNcFxdPaWBiZmXlAVqh16OTgnw0CXXawTpQpG7
         Bp6vn120lPGJJWcgJy+d6h+3ZYzijdP6JFkO4hHl+rElDfLVDEj3d6qw0mUqOZT9eJ4q
         r81w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=7XcUqFwS7T4EFYRue79lnyK75JXrG1OOj43gHgX7hts=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=U2G4gXeZ6x+71zlW5Oit4hPsl9XoYYOaHGPYVaOgGgvJ7XYjFR9op6jL3OJXz+v2Vs
         Wk/ytpv1HrmXDkRXmKu6ND/e5lNiuvDtLxySublHHRhlJgeOGP7Fhc/40Zdw4/ZLCwLi
         y06k+adPsCbpFXt9RykSJSWMZmjrgsrxZuBdLhTvYHGOfnbL+PTsppWpL7v6pikQMguP
         RnA2jq5j3d0U5F15QCqPbLSxxmo/FA73hCeZ04bI8j97MD0sOqjfQCnmBJNV0s85HdVW
         gCCUC7iIEB+CoHrn0/LvY2zjGa8RtCQjI5US9Mgve52feYbTkoL8pLflHLVJjK6YMvTt
         ozkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b="tybT5z/N";
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=YID0rI8D;
       spf=pass (google.com: domain of 0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com designates 69.169.231.80 as permitted sender) smtp.mailfrom=0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-80.smtp-out.eu-west-1.amazonses.com (b231-80.smtp-out.eu-west-1.amazonses.com. [69.169.231.80])
        by gmr-mx.google.com with ESMTPS id t20-20020a05600c199400b004166a35d7e4si377525wmq.1.2024.04.11.10.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Apr 2024 10:18:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com designates 69.169.231.80 as permitted sender) client-ip=69.169.231.80;
Date: Thu, 11 Apr 2024 17:18:27 +0000
To: kasan-dev@googlegroups.com
From: =?UTF-8?B?J0bDs3J1bSBYWEknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
Reply-To: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2024@forumxxi.net>
Subject: =?UTF-8?Q?Convocatoria/Call_for_papers/Chiamata/Chamada/Appel_Congreso_CUIC?=
 =?UTF-8?Q?IID_2024_(no_presencial)_organizado_por_la_revista_EPSIR_(SCOPUS)?=
 =?UTF-8?Q?_y_F=C3=B3rum_XXI?=
Message-ID: <0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: arqDaRHkzV7639S8muIHoO2g
X-FBL: arqDaRHkzV7639S8muIHoO2g-v5xC763optCzAXRysMgAhF4Q
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_NE26kAh3hWuj6KRMWODaOpjSgiGkW5hrZ9XUBiOwrE8"
Feedback-ID: cuiciid2024=forumxxi.net@crlsrv.com:1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2024.04.11-69.169.231.80
X-Original-Sender: cuiciid2024=forumxxi.net@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2
 header.b="tybT5z/N";       dkim=pass header.i=@amazonses.com
 header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=YID0rI8D;       spf=pass
 (google.com: domain of 0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com
 designates 69.169.231.80 as permitted sender) smtp.mailfrom=0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
X-Original-From: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2024=forumxxi.net@crlsrv.com>
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
--b1_NE26kAh3hWuj6KRMWODaOpjSgiGkW5hrZ9XUBiOwrE8
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DarqDaRHkzV763=
9S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q]=20
=20
=20
=20
 [https://www.email-index.com/click.php?L=3D440IM7JRPnZ3PH892ra763b8Rg&J=3D=
arqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVn=
jlQzw]=20
=20
 Congreso Internacional CUICIID 2024
=20
=20
=20
=20
 Estimados colegas, caros colegas, chers coll=C3=A8gues, cari colleghi, dea=
r colleagues:Estamos orgullosos de presentar ante la Academia la XIV edici=
=C3=B3n del Congreso VIRTUAL y EN L=C3=8DNEA (no presencial) CUICIID 2024 (=
Congreso Universitario Internacional sobre Contenidos, Investigaci=C3=B3n, =
Innovaci=C3=B3n y Docencia) www.cuiciid.net.Los idiomas oficiales son: espa=
=C3=B1ol, portugu=C3=A9s, italiano, ingl=C3=A9s y franc=C3=A9s y se podr=C3=
=A1n presentar 2 ponencias por autor (individualmente o en coautor=C3=ADa) =
publicables en 2024 y 2025. Este a=C3=B1o se desarrolla en colaboraci=C3=B3=
n entre la revista EPSIR (www.epsir.net) indizada en SCOPUS Q-4 y la Asocia=
ci=C3=B3n F=C3=B3rum XXI.
CUICIID 2024 destaca por su vocaci=C3=B3n internacional y su amplia visibil=
izaci=C3=B3n ya que sus resultados curriculares (tras revisi=C3=B3n por dob=
les pares ciegos) ser=C3=A1n publicados en:
	Ponencia completa como art=C3=ADculo en la revista EPSIR (www.epsir.net) (=
Q-4 en SCOPUS).	Libro de Actas con los Res=C3=BAmenes con ISBN, lo que conl=
leva certificado de ponente-asistente.Fechas clave:
	20 de mayo (lunes). =C3=9Altimo d=C3=ADa para el env=C3=ADo de Res=C3=BAme=
nes (1 p=C3=A1gina).	Desde 27 de mayo (lunes). Env=C3=ADo de informes de ac=
eptaci=C3=B3n o denegaci=C3=B3n tras revisi=C3=B3n por pares ciegos.	28 de =
junio (lunes). Cierre de pago de matr=C3=ADcula (215 =E2=82=AC por cada aut=
or y por cada ponencia, m=C3=A1ximo 2 ponencias).Se puede fraccionar el pag=
o en 4 mensualidades de 65 50 50 50 =E2=82=AC.	8 de julio (lunes). =C3=9Alt=
imo d=C3=ADa para el env=C3=ADo de ponencias-art=C3=ADculos de 20 p=C3=A1gi=
nas m=C3=A1ximo que ser=C3=A1n publicados en monogr=C3=A1ficos en 2024 y 20=
25 (la mitad por a=C3=B1o) de la revista EPSIR (Q-4 de SCOPUS).	29 de julio=
 (lunes). Voluntario. Env=C3=ADo de v=C3=ADdeos (.mov, .mp4 o .mpeg) para l=
a defensa grabada.	16 de septiembre (lunes). Voluntario. Solicitud de defen=
sa en directo.	16, 17 y 18 de octubre (mi=C3=A9rcoles, jueves y viernes). C=
elebraci=C3=B3n del Congreso (virtual y en l=C3=ADnea, no presencial).Compu=
esto por 6 =C3=81reas tem=C3=A1ticas:=20
	Comunicaci=C3=B3n: Comunicaci=C3=B3n persuasiva, Alfabetizaci=C3=B3n medi=
=C3=A1tica, Marketing digital, Neuromarketing, Publicidad, Relaciones P=C3=
=BAblicas, Periodismo, Protocolo, Lo audiovisual, Comunicaci=C3=B3n legal y=
 m=C3=A9dica, Crisis de la COVID-19.	Docencia: Nueva metodolog=C3=ADas, TIC=
, STEAM, F=C3=B3rmulas y contenidos docentes, Pol=C3=ADticas educativas, el=
 EEES, la LOSU, pol=C3=ADticas educativas.	Ciencias Sociales y Humanismo: T=
urismo, G=C3=A9nero, Antropolog=C3=ADa, Cultura, Derecho, Patrimonio, Ling=
=C3=BC=C3=ADstica, Semi=C3=B3tica, Historia, Religi=C3=B3n, Filosof=C3=ADa,=
 G=C3=A9nero, Psicolog=C3=ADa, Sociolog=C3=ADa, Sociedad, Agenda 2030, ODS.=
	Innovaci=C3=B3n: Tem=C3=A1ticas emergentes, Redes Sociales, Meta, Los nuev=
os trabajos doctorales, Contenidos acad=C3=A9micos actuales, Emprendimiento=
.	Investigaci=C3=B3n e Inteligencia Artificial: Nuevos proyectos, Investiga=
ciones I D i, Art=C3=ADculos 60 (anteriormente 83), Investigaciones no regl=
adas, Ingenier=C3=ADas, Criterios de evaluaci=C3=B3n, Inteligencia Artifici=
al, ChatGPT, Dall-e.	Miscel=C3=A1nea: =C3=81rea abierta a contribuciones tr=
ansversales.	Paneles tem=C3=A1ticos: Propuestos por autores (m=C3=ADnimo 4 =
ponencias por panel). Ideal para Grupos de Investigaci=C3=B3n.=20
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
ail-index.com/click.php?L=3DKPbGUE892w60ths4FRAYtD0A&J=3DarqDaRHkzV7639S8mu=
IHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVnjlQzw] y en nuestr=
o correo: cuiciid2024@forumxxi.net [mailto:cuiciid2024@forumxxi.net]
 Reciban mi m=C3=A1s cordial saludo. David Caldevilla Dom=C3=ADnguezUnivers=
idad ComplutenseDirector del Congreso CUICIID 2024
=20
 [https://www.email-index.com/click.php?L=3DR4x3sv9YvI6vnV1viL06BA&J=3DarqD=
aRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3DapKVRdmKrGwlBL0wUw82Gg&J=3Dar=
qDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVnjl=
Qzw] [https://www.email-index.com/click.php?L=3DmqmZQuJ0IlcUcak6A4qFrg&J=3D=
arqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVn=
jlQzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q] | Actualizar mis =
datos [https://www.email-index.com/update.php?J=3DarqDaRHkzV7639S8muIHoO2g&=
C=3Dv5xC763optCzAXRysMgAhF4Q] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine =
n=C2=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-000000%40eu=
-west-1.amazonses.com.

--b1_NE26kAh3hWuj6KRMWODaOpjSgiGkW5hrZ9XUBiOwrE8
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DarqDaRHkzV7639S8muIHoO2g&=
C=3Dv5xC763optCzAXRysMgAhF4Q');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DarqDaRHkzV7639S8muIH=
oO2g&C=3Dv5xC763optCzAXRysMgAhF4Q');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=
=3Dv5xC763optCzAXRysMgAhF4Q');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC7=
63optCzAXRysMgAhF4Q');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC=
763optCzAXRysMgAhF4Q');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3Dar=
qDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q');}}</style>
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
ader1">Env&iacute;o de res&uacute;menes: 20 de mayo de 2024 Congreso CUICII=
D 2024</span><div style=3D"display:none;max-height:0px;overflow:hidden;">&#=
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
-index.com/view.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF=
4Q" style=3D"text-decoration: underline; color:#333;"><span>Ver en navegado=
r</span></a>
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3D2SPh4fHhk9aKU=
UMnk7638uxQ&J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DH=
KFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" titl=
e=3D""><img align=3D"absbottom" border=3D"0" id=3D"Imgfull" width=3D"280" s=
rc=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAy=
ZIqw/LOGO%20CUICIID%202024%20redondo.png?1712834856007" alt=3D"CUICIID" sty=
le=3D"width: 280px; max-width: 280px; text-align: center; font-size: 18px; =
color: rgb(255, 255, 255); font-weight: 700; text-shadow: black 0.1em 0.1em=
 0.2em; text-transform: uppercase;" class=3D"acre_image_editable"></a></td>
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
rong></span><span style=3D"color:#0000FF"><strong>CUICIID 2024</strong></sp=
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
Estamos orgullosos de presentar ante la Academia la XIV&nbsp;edici&oacute;n=
 del <strong>Congreso VIRTUAL</strong> y </span><strong><span style=3D"colo=
r:#000000">EN L&Iacute;NEA (no presencial)</span> <span style=3D"color:#000=
0FF">CUICIID 2024</span></strong> <span style=3D"color:#000000">(Congreso U=
niversitario Internacional sobre Contenidos, Investigaci&oacute;n, Innovaci=
&oacute;n y Docencia) </span><span style=3D"color:#0000FF"><u>www.cuiciid.n=
et</u></span><span style=3D"color:#000000">.</span><br>
<br>
<span style=3D"color:#000000">Los <strong>idiomas oficiales</strong> son: <=
strong>espa&ntilde;ol, portugu&eacute;s, italiano, ingl&eacute;s y franc&ea=
cute;s</strong> y se podr&aacute;n presentar 2 ponencias por autor (individ=
ualmente o en coautor&iacute;a) publicables en 2024 y 2025.<br>
&nbsp;<br>
Este a&ntilde;o se desarrolla en colaboraci&oacute;n entre la<strong>&nbsp;=
revista&nbsp;</strong></span><strong><strong style=3D"color:rgb(0, 0, 0)">E=
PSIR</strong><strong style=3D"color:rgb(0, 0, 0)"> </strong></strong><stron=
g style=3D"color:rgb(0, 0, 0)">(</strong><strong style=3D"color:rgb(0, 0, 0=
)"><span style=3D"color:#0000FF"><u>www.epsir.net</u></span></strong><stron=
g style=3D"color:rgb(0, 0, 0)">),</strong><span style=3D"color:rgb(0, 0, 0)=
">&nbsp;indizada en <strong>SCOPUS Q-4 </strong>, y la Asociaci&oacute;n Cu=
ltural&nbsp;<strong>F&oacute;rum XXI</strong>.</span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"color:#0000FF"><strong>CUICIID 2024</strong> </span><span st=
yle=3D"color:#000000">destaca por su vocaci&oacute;n internacional y su amp=
lia <strong>visibilizaci&oacute;n</strong> ya que sus <strong>resultados cu=
rriculares </strong>(<strong>tras revisi&oacute;n por dobles pares ciegos</=
strong>) ser&aacute;n publicados en:</span>
</div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">Ponencia completa como art&iacute;culo en la =
revista EPSIR (</span><span style=3D"color:#0000FF"><u>www.epsir.net</u></s=
pan><span style=3D"color:#000000">)&nbsp;(<strong>Q-4 en SCOPUS</strong>).<=
/span>
</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000">Libro de Actas con los Res&uacute;menes con ISBN, lo que conlleva=
 certificado de ponente-asistente.</span></li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Fechas clave:</strong></span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>20 de mayo</strong> (lunes). &Uacute;ltimo d&iacute;a&nbs=
p;para el env&iacute;o de Res&uacute;menes (1 p&aacute;gina).</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Desde 27 de mayo</strong> (lunes). Env&iacute;o de inform=
es de aceptaci&oacute;n o denegaci&oacute;n tras revisi&oacute;n por pares =
ciegos.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>28 de junio</strong> (lunes). Cierre de pago de matr&iacu=
te;cula (215&nbsp;&euro; por cada autor y por cada ponencia, m&aacute;ximo =
2&nbsp;ponencias).Se puede fraccionar el pago en 4 mensualidades de 65 + 50=
 + 50 + 50 &euro;.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>8 de julio</strong> (lunes). &Uacute;ltimo d&iacute;a par=
a el env&iacute;o de ponencias-art&iacute;culos&nbsp;de 20 p&aacute;ginas m=
&aacute;ximo que ser&aacute;n&nbsp;publicados&nbsp;en monogr&aacute;ficos e=
n 2024 y 2025 (la mitad por a&ntilde;o) de la revista&nbsp;<strong>EPSIR</s=
trong>&nbsp;(<strong>Q-4&nbsp;de SCOPUS</strong>).</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>29 de julio</strong> (lunes).&nbsp;<strong>Voluntario</st=
rong>. Env&iacute;o de <strong>v&iacute;deos</strong> (.mov, .mp4 o .mpeg) =
para la defensa grabada.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>16 de septiembre </strong>(lunes).&nbsp;<strong>Voluntari=
o</strong>. Solicitud de <strong>defensa en directo</strong>.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>16, 17 y 18 de octubre</strong> (mi&eacute;rcoles,&nbsp;j=
ueves y viernes). Celebraci&oacute;n del Congreso (virtual y en l&iacute;ne=
a, <strong>no presencial</strong>).</span></li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">Compuesto por <strong>6 &Aacute;reas tem&aacu=
te;ticas</strong>:</span><br>
&nbsp;</div>

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
Nuevos proyectos, Investigaciones I+D+i, Art&iacute;culos 60 (anteriormente=
 83), Investigaciones no regladas, Biblioteconom&iacute;a, Ingenier&iacute;=
as, Criterios de evaluaci&oacute;n, Inteligencia Artificial, ChatGPT, Dall-=
e.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Miscel&aacute;nea: </strong>&Aacute;rea abierta a contrib=
uciones transversales.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><strong>Paneles tem&aacute;ticos: </strong>Propuestos por autores=
 (m&iacute;nimo 4 ponencias por panel). Ideal para <u>Grupos de Investigaci=
&oacute;n</u>.</span></li>
</ul>

<div style=3D"line-height:20px;"><span style=3D"color:#000000">&nbsp;</span=
></div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#0000FF"><strong>CUICIID</strong></span><span style=3D=
"color:#000000"><strong> </strong>es el espacio id&oacute;neo para la visib=
ilizaci&oacute;n de trabajos de <strong>doctorandos</strong> e <strong>inve=
stigadores</strong> de nuevo cu&ntilde;o en los &aacute;mbitos acad&eacute;=
micos de mayor relevancia y es enmarcable dentro de los Congresos de mayor =
impacto, los ubicados bajo el concepto &lsquo;<strong>Congresos de Calidad =
de la formaci&oacute;n docente</strong>&rsquo;, por aunar la <strong>innova=
ci&oacute;n</strong> y la <strong>docencia</strong> y, merced a la <strong>=
revisi&oacute;n por dobles pares ciegos</strong> de los trabajos presentado=
s, sus resultados tienen un alto valor curricular.</span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000">&nbsp;<br>
Como &uacute;ltimo punto de inter&eacute;s, </span><span style=3D"color:#00=
00FF"><strong>CUICIID</strong></span><span style=3D"color:#000000"><strong>=
 </strong>quiere focalizar sus esfuerzos en animar a los <strong>Grupos y E=
quipos de Investigaci&oacute;n</strong> que desean visibilizar sus resultad=
os investigadores en publicaciones de primer nivel.<br>
&nbsp;<br>
Para cualquier duda, los emplazamos en la web:</span> <u><a href=3D"https:/=
/www.email-index.com/click.php?L=3DQMOkEx396bDN5AjPUgvwqA&J=3DarqDaRHkzV763=
9S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" target=
=3D"_blank"><span style=3D"color:#0000FF">www.cuiciid.net</span></a></u><sp=
an style=3D"color:#0000FF"> </span><span style=3D"color:#000000">y en nuest=
ro correo: </span><u><a href=3D"mailto:cuiciid2024@forumxxi.net" target=3D"=
_blank"><span style=3D"color:#0000FF">cuiciid2024@forumxxi.net</span></a></=
u>
</div>

<div style=3D"line-height:20px;"><span style=3D"color:#000000">&nbsp;</span=
></div>

<div style=3D"line-height:20px;">
<span style=3D"color:#000000">&nbsp;<br>
Reciban mi m&aacute;s cordial saludo.<br>
&nbsp;<br>
<strong>David Caldevilla Dom&iacute;nguez</strong><br>
Universidad Complutense<br>
<strong>Director del Congreso </strong></span><span style=3D"color:#0000FF"=
><strong>CUICIID 2024</strong></span>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Drp=
KgZET7N6UUwT3zlKjFVA&J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAh=
F4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
ck;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38=
" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display=
: block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); fo=
nt-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upper=
case;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-facebook-3=
8.jpg" alt=3D"facebook CUICIID" class=3D"acre_image_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3D2d=
pLiPaj763nQ8892w2hVuZBJA&J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRys=
MgAhF4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display:=
 block;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=
=3D"38" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; d=
isplay: block; text-align: center; font-size: 18px; color: rgb(255, 255, 25=
5); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform:=
 uppercase;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twit=
ter-38.jpg" alt=3D"twitter CUICIID" class=3D"acre_image_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DVb=
FRbuOngoCpAxDynhvGNg&J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAh=
F4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
ck;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38=
" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display=
: block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); fo=
nt-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upper=
case;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-linkedin-3=
8.jpg" alt=3D"linkedin CUICIID" class=3D"acre_image_editable"></a></td>
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
com/unsubscribe.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF=
4Q" style=3D"text-decoration: underline; color:#333;"><span>Darme de baja d=
e esta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q" s=
tyle=3D"text-decoration: underline; color:#333;"><span>Actualizar mis datos=
</span></a>
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
"><a href=3D"https://www.email-index.com/click.php?L=3DKYLY892b892tvAHTzlM3=
h83F763g&J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DHKFR=
cCbcnmxmc4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"b=
order-style:none;min-width: initial !important;max-width: initial !importan=
t;width: initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/=
uploads/user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO =
LATINA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DarqDaRHkzV7639S8muIHoO2g&C=3Dv5xC763optCzAXRysMgAhF4Q" alt=
=3D"" border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px,b=
order:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/0102018ece2afd43-83e14ea5-5670-426d-b8c2-a7d83cf4115d-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/0102018ece2afd43-83e14ea5-5670-42=
6d-b8c2-a7d83cf4115d-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_NE26kAh3hWuj6KRMWODaOpjSgiGkW5hrZ9XUBiOwrE8--

