Return-Path: <kasan-dev+bncBDLJXDHV7QBRBNG24HCQMGQELXUJJWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F5DB426EF
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 18:30:46 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-55f5f436648sf4343e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 09:30:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756917046; cv=pass;
        d=google.com; s=arc-20240605;
        b=hR+ATs8hkezjzdQZ2bbf+jlqmJrCDsefBwTHmD+ORFvyRF9LTHt4eiHrBrTqTacR7y
         uj2wFmH7A8aA0eMSBAYCa3Nk+26ll/XrCo54z3Abp8HiSb6pz9Oly8w2J9J0KluC98Jn
         4ROZfR3CSFAl9mipZesR1ilec5IxsG3EdRy1+5XT5PaAldj3nKp5bUcn/Q88mO0aB7Cq
         4R+9VLZYD+j/yv3mgWkosZMdB/D1tAy2Xf0vbTOr0SU93QFHKCLoDkkfnMPazajLhjUf
         kqCAny+CYLrSEEzYyY0nJ4xzyeaTlB1+3KkTpcSkzV7npwfd/afqzA+/DmldsEoTjjRY
         gfbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=bn3/pgNyctmDmYbtkj49hbkPJTy91D4vu4YFLPe12MY=;
        fh=juYDp+lZamuvANP2AsqbSGnAZs7307z4Tpq7DkrWpx8=;
        b=gZa07YsoVh5hDIAtB3L8q+y+4FczjMe6oBIXW4WVBzuUxYSdPDr6xI2iq2QdHppJ/B
         EPnlug844nTckxmk3atjYvlsKtb6/Gru599qWp0+V/u+euQf/YbnHWDIR9xQJVCC7ulN
         zK2OyO0ISQ02S/gWmfMD+2OyweYvDbc7NCsACTVGKueymsqo8YhP2s8m8cVUt/W8itXR
         hyO7tDJMqMCuf0lQVuzQA3gsK9XRLipU6igbg2Vg2RpTFvKaxuAPx5czPF7MzY6if+yE
         WHXn0r5NL0964PnfUQfa9hlW+PuWVtdaI0E6NszdGBRBehBm8qj4KOQsMAyQLC94MFdo
         kOlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=QyORgsfl;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=qGZLEgeR;
       spf=pass (google.com: domain of 01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756917046; x=1757521846; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bn3/pgNyctmDmYbtkj49hbkPJTy91D4vu4YFLPe12MY=;
        b=M1VaBlhbWGg+zpf+LPmyIC/qkiTXS+GaIfkbeaupwXoigvL042lgMh7hq8DBnRgfo9
         YztPYtC+RGwnCcZtVFD7xLMv6UrwmxZ+xh0VtHKjCXk7+YYZVpTeGajpFd0ixaR/QzJE
         JJ9RyqZGUUzxi54MsqYWJjp+6P5f3CeXZ+RZVVJdZKVcIX0nAyHjypt7XAnNogxDXuSf
         1vjGmcfsm/1fm0SANCGfJtpyAgMU3bwFuecAAu7T5BKpPcLLCuwsqKSCJqNpzIiY4Z68
         ttN0U93yE0Qj0vmnqNoM+FsHg590LsldsqjExr+G8lWhLw43dZsGpSiZ7uO+Wa4C13mD
         1MrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756917046; x=1757521846;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bn3/pgNyctmDmYbtkj49hbkPJTy91D4vu4YFLPe12MY=;
        b=RYzKXmf8YAU6eWrbwOQL68mFfbPbNIOIit5U8y1agdYSpSb7R/qxcyHD4Z3+cYA4YX
         KA8vPk+8eICUeXufjiY903yPZHqbHMgzIowXGpXYhSu3eOIW+30II+6qmXCa1rS5q20+
         N+8VY3b2A9mJDYPMwfAPOt4F9uZYOSdldVvfF8YCjy0OX7GZ7ZLmkbT9eiWKmHe3iuwn
         CsENXRnG+DoB50jHsVcTIbmbO5QqEn07NlawVtJZ/MMGY0pMxxVYeqp9j6iC8wx6mUz+
         S1jD6Zp6mUYo3Kft/FSKfoTp03bn4b3k6Ee6Sw2JoUHV7IdSGzpXxDMqV8b/8yXiR/r1
         7Ehg==
X-Forwarded-Encrypted: i=2; AJvYcCUq1KTrj0k7D5UwKxnnp7te9mk78f4y/Kn6WlUctZdt+KI8T+NuSodEWVON5Qn1O+weLPXA5g==@lfdr.de
X-Gm-Message-State: AOJu0YwcfJJADFrr237Zl3QgTDCQJAto0baEwtmh8Xg9f1BRaZh5rDTz
	o1HpJ0u2toRaX8sUAXxbpJAHylFDnQAH3E/pNCtfiB2N6YfmKueZ9P+g
X-Google-Smtp-Source: AGHT+IHLSQmInWJ8Gsp999xX23gy/wP1gpN/VPK6ZIyO4Ujsgi/FMfMJ6ykBoYK166CaNn2xmWC0yw==
X-Received: by 2002:a05:6512:258c:b0:55f:43ba:9410 with SMTP id 2adb3069b0e04-55f708b4592mr4551231e87.15.1756917045571;
        Wed, 03 Sep 2025 09:30:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd65//OeqX3PsJDevsbv3Ej2cgqTPUsiu07P0X3UQPTKA==
Received: by 2002:a05:6512:318d:b0:55c:e2a0:5ac with SMTP id
 2adb3069b0e04-55f791e881cls1483440e87.1.-pod-prod-04-eu; Wed, 03 Sep 2025
 09:30:43 -0700 (PDT)
X-Received: by 2002:a2e:a713:0:b0:336:7e31:6708 with SMTP id 38308e7fff4ca-336caf5eb14mr29372281fa.37.1756917042702;
        Wed, 03 Sep 2025 09:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756917042; cv=none;
        d=google.com; s=arc-20240605;
        b=d/JKy7zRhAfkMnm0uHLXcL5JO1J66GFT7yW7b8uB9oE4PKAZ7LvlG6qnGC/M2SJX5u
         a+8iLtYtf1JmojiQTHwAOvCjZ0PbD7lMMDv87IEtUxAUrN/+0RDbteTnia9J/aC9hFO/
         JKqxiXIOJWnVd1Ei/Uk9BYimC/NIZhj4zxvV2PyAWYSNfMjPW+iLF7l8xWn49Vto9W6v
         e5EC6O9DpxSkK4Dp95IR060RA01t74KZSdFuEpmh/UTqNUqpl07cyZhSWo6WK7Q3QU7Z
         RoAcdHmlxBu/c0HQd/kZrccHkRzRJhLWdCOTgn3Sr632+HK5ha0wzuYnJ80YfpAOrJiQ
         6d/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=/mmTc+XiWPaZUpBsV2CJ62pD8p+Iu6W02v6VKw1SalI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Ulpco51rPtVAJ5nomGWCBtiRuzz3JOiQYGKw+6PmlU9S0LV/4ww8gfGGtu8zyy74dy
         QpmmqI7D8vyomRFwkbpn0QzEly5wEZQ12L2ypGLCjokY/WxSGAL/OI2Gb0WBVcG8IAQO
         zFK8MvOXQ79IssAB1s8mo69rAAm0zioHrJey//qadqrBV5h+XdpIAUcw8EUHf7TrOQNE
         hgkwLJHkFziWeZ/vL/y0SwqD7AVFnG4j5UiH8AQnU5Worb3MfzzCVeqyrZCNNxreD8yO
         KG6cCluOFEYqyut6rMuWO2Qg0+gWECCdAjbgi4qVanMnn+Cs+f1ZG2bBT9nyBYNhCOnC
         iCpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=QyORgsfl;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=qGZLEgeR;
       spf=pass (google.com: domain of 01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-75.smtp-out.eu-west-1.amazonses.com (b231-75.smtp-out.eu-west-1.amazonses.com. [69.169.231.75])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4f72a71si898661fa.3.2025.09.03.09.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 09:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) client-ip=69.169.231.75;
Date: Wed, 3 Sep 2025 16:30:41 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@hisin.org>
Subject: =?UTF-8?Q?Convocatoria_/_Call_for_papers._CONGRESO_INTERNACIONAL_LATINA_DE_?=
 =?UTF-8?Q?COMUNICACI=C3=93N_SOCIAL_2025_(no_presencial)_organizado_por_revi?=
 =?UTF-8?Q?sta_Latina_SCOPUS_Q1?=
Message-ID: <01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: A4qv3gVHBXHIKwyTEJvxyg
X-FBL: A4qv3gVHBXHIKwyTEJvxyg-kF6K5qd4mAeEXe7635lLHrEQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_F1rx4Lu80CMdimjrVODQEL6u3MVQO8HyArf1r8bO0"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2025.09.03-69.169.231.75
X-Original-Sender: congresolatina=hisin.org@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw
 header.b=QyORgsfl;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=qGZLEgeR;       spf=pass
 (google.com: domain of 01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com
 designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
X-Original-From: Historia de los sistemas informativos <congresolatina=hisin.org@crlsrv.com>
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
--b1_F1rx4Lu80CMdimjrVODQEL6u3MVQO8HyArf1r8bO0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DA4qv3gVHBXHIK=
wyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ]=20
=20
=20
=20
 Congreso Internacional LATINA DE COMUNICACI=C3=93N SOCIAL 2024
=20
=20
 [https://www.email-index.com/click.php?L=3D763dKJyAs763B3W4wmMGJt66Ng&J=3D=
A4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjl=
Qzw]=20
=20
=20
=20
 Estimad@s amig@s y colegas:Estamos muy ilusionad@s con el lanzamiento del =
XVI CONGRESO INTERNACIONAL LATINA DE COMUNICACI=C3=93N SOCIAL 2024 (CILCS) =
que se celebrar=C3=A1 los pr=C3=B3ximos d=C3=ADas 11, 12 y 13 de diciembre =
en modalidad online www.congresolatina.netLos idiomas del congreso son: esp=
a=C3=B1ol, italiano, portugu=C3=A9s, ingl=C3=A9s y franc=C3=A9s.Los espacio=
s de trabajo propuestos son actuales, interesantes e imprescindibles en una=
 sociedad que cambia cada d=C3=ADa y cada vez a mayor velocidad. EDUCACI=C3=
=93N, TURISMO, DEPORTE, POL=C3=8DTICA, MARKETING, PUBLICIDAD, LEGALIDAD, IN=
TELIGENCIA ARTIFICIAL=E2=80=A6 Siempre vinculados a la COMUNICACI=C3=93N.Es=
pacios tem=C3=A1ticos: (https://www.email-index.com/click.php?L=3D5BnhGRiXu=
AP0qw1V2I6z7A&J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Dd=
ybgAwNZwARmi9SVnjlQzw)
	Educando en comunicaci=C3=B3n	Comunicaci=C3=B3n digital	Nuevas tendencias =
e investigaci=C3=B3n en la comunicaci=C3=B3n	Comunicaci=C3=B3n persuasiva	C=
omunicaci=C3=B3n empresarial	Comunicaci=C3=B3n especializada	L=C3=ADmites d=
e la comunicaci=C3=B3n	El negocio de los medios	Propuestas de comunicacione=
s libres	PanelesCurricularmente CILCS presenta:
	Libro de Actas con ISBN 978-84-09-59705-5 (res=C3=BAmenes aceptados tras r=
evisi=C3=B3n por pares ciegos)	y, adem=C3=A1s, da a elegir entre seis posib=
ilidades de publicaci=C3=B3n:	Libro de papel con versi=C3=B3n electr=C3=B3n=
ica de la editorial ESIC (Q1 =C3=ADndice SPI General). Compuesto por los te=
xtos aceptados tras revisi=C3=B3n de mejora mediante dobles pares ciegos po=
r parte del Comit=C3=A9 Evaluador del Congreso.	Revista Latina de Comunicac=
i=C3=B3n Social -RLCS- (Scopus Q-1 y SJR Q-1). Se publicar=C3=A1 un m=C3=A1=
ximo de 6 textos en 2025 tras ser aceptados por el Comit=C3=A9 Editorial de=
 la misma.	Revista del =C3=A1rea de Humanidades (Scopus Q-1 y SJR Q-2). Se =
publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2025 tras ser aceptados por el=
 Comit=C3=A9 Editorial de la misma.	Revista del =C3=A1rea de Ciencias Socia=
les (Scopus Q-3 y SJR Q-3). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en=
 2025 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	Revista =
SOCIAL REVIEW, International Social Sciences Review (EBSCO) Se publicar=C3=
=A1 un m=C3=A1ximo de 6 en 2025 textos tras ser aceptados por el Comit=C3=
=A9 Editorial de la misma.	Revista EDU REVIEW International Education and L=
earning Review (EBSCO). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 202=
5 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.Se podr=C3=A1=
 participar:
	Enviando un v=C3=ADdeo (emitido el 11 de diciembre) o 	En directo a trav=
=C3=A9s de zoom (12 o 13 de diciembre)Fechas clave:
Env=C3=ADo de resumen
Hasta el 7 de octubre
Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n
Desde el 10 de octubre
Abono de matr=C3=ADcula: (180 =E2=82=AC por cada firmante y por cada ponenc=
ia)
Hasta el 25 de octubre
Env=C3=ADo de ponencia completa
Hasta el 8 de noviembre
Env=C3=ADo de v=C3=ADdeo para ser emitido el 11 de diciembre o env=C3=ADo d=
e correo electr=C3=B3nico informando que desea defender la ponencia en dire=
cto el 12 o 13 de diciembre
Hasta el 15 de noviembre
Celebraci=C3=B3n (online)
11, 12 y 13 de diciembre
M=C3=A1s informaci=C3=B3n en: www.congresolatina.net 2024congresolatina@his=
in.org
Tel=C3=A9fono y WhatsApp ( 34) 663 935 312 (de 9 a 19 horas de Madrid)Un ab=
razo y =C2=A1=C2=A1SEGUIMOS COMUNICANDO!!Almudena Barrientos-B=C3=A1ez y Te=
resa Pi=C3=B1eiro OteroUniversidad Complutense de Madrid y Universidad de l=
a Coru=C3=B1a (Espa=C3=B1a)Directoras del XVI CILCS
=20
 [https://www.email-index.com/click.php?L=3DKjHHf7HQE4hV7hTgMgjgOg&J=3DA4qv=
3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
 [https://www.email-index.com/click.php?L=3DgvEiEToF0drl5XrbhIBTtw&J=3DA4qv=
3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
 [https://www.email-index.com/click.php?L=3DgNlurzQ8923lMCrv892yZiSEvA&J=3D=
A4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjl=
Qzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ] | Actualizar mis da=
tos [https://www.email-index.com/update.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3D=
kF6K5qd4mAeEXe7635lLHrEQ] F=C3=93RUM XXI - Cine n=C2=BA 38. Bajo derecha, 2=
8024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
1020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000%40eu-west-1.ama=
zonses.com.

--b1_F1rx4Lu80CMdimjrVODQEL6u3MVQO8HyArf1r8bO0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvx=
yg&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3Dk=
F6K5qd4mAeEXe7635lLHrEQ');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd=
4mAeEXe7635lLHrEQ');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5q=
d4mAeEXe7635lLHrEQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DA4=
qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}}</style>
                    <meta http-equiv=3D"X-UA-Compatible" content=3D"IE=3Ded=
ge"> <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-=
8"> <meta name=3D"viewport" content=3D"width=3Ddevice-width; initial-scale=
=3D1.0; maximum-scale=3D1.0;"> <title id=3D"template_title"></title> <style=
 type=3D"text/css" id=3D"acrstyle"> td{/*position:relative*/} html{width:10=
0%;} body{width:100%;background-color:#ffffff;margin:0;padding:0;} #templat=
e_body a img{border:none;} *{margin-top:0px;margin-bottom:0px;padding:0px;b=
order:none;outline:none;list-style:none;-webkit-text-size-adjust:nonel} div=
{line-height:} body{margin-top:0 !important;margin-bottom:0 !important;padd=
ing-top:0 !important;padding-bottom:0 !important;width:100% !important;-web=
kit-text-size-adjust:100% !important;-ms-text-size-adjust:100% !important;-=
webkit-font-smoothing:antialiased !important;} img{border:0 !important;outl=
ine:none !important;} table{border-collapse:collapse;mso-table-lspace:0px;m=
so-table-rspace:0px;} td {border-collapse:collapse;mso-line-height-rule:exa=
ctly;} a {border-collapse:collapse;mso-line-height-rule:exactly;} span {bor=
der-collapse:collapse;mso-line-height-rule:exactly;} .ExternalClass * {line=
-height: 100%;} .ExternalClass, .ExternalClass p, .ExternalClass span, .Ext=
ernalClass font, .ExternalClass td, .ExternalClass a, .ExternalClass div {l=
ine-height: 100%;} .copy a {color: #444444;text-decoration:none;} .preheade=
r1 {display: none !important; font-size:0px; visibility: hidden; opacity: 0=
; color: transparent; height: 0; width: 0;} #preheader1 {display: none !imp=
ortant; font-size:0px; visibility: hidden; opacity: 0; color: transparent; =
height: 0; width: 0;} </style><style type=3D"text/css" id=3D"block_social_c=
ss"> .block_social table{border-collapse:collapse;mso-table-lspace:0pt;mso-=
table-rspace:0pt;} .block_social a img{border:0;} .block_social a, .block_s=
ocial a:hover, .block_social a:visited{text-decoration:none;} @media only s=
creen and (max-width:480px){ .block_social table[class*=3Dmain_table]{width=
:320px !important;} .block_social td[class*=3Dpad_both]{padding-left:20px !=
important;padding-right:20px !important;} } </style><style type=3D"text/css=
" id=3D"block_spacer_css"> .block_spacer table{border-collapse:collapse;mso=
-table-lspace:0pt;mso-table-rspace:0pt;} .block_spacer a img{border:0;} .bl=
ock_spacer a, .block_spacer a:hover, .block_spacer a:visited{text-decoratio=
n:none;} @media only screen and (max-width:480px){ .block_spacer table[clas=
s*=3Dmain_table]{width:320px !important;} .block_spacer td[class*=3Dpad_bot=
h]{padding-left:20px !important;padding-right:20px !important;} } </style><=
style type=3D"text/css" id=3D"block_texto_css"> .block_texto table{border-c=
ollapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;} .block_texto a=
 img{border:0;} .block_texto .texto{word-wrap:break-word;} .block_texto a, =
.block_texto a:hover, .block_text a:visited{text-decoration:none;} @media o=
nly screen and (max-width:480px){ .block_texto table[class*=3Dmain_table]{w=
idth:320px !important;} .block_texto td[class*=3Dpad_both]{padding-left:20p=
x !important;padding-right:20px !important;} } </style><style type=3D"text/=
css" id=3D"block_seccion_css"> .block_seccion table{border-collapse:collaps=
e;mso-table-lspace:0pt;mso-table-rspace:0pt;} .block_seccion a img{border:0=
;} .block_seccion a, .block_seccion a:hover, .block_seccion a:visited{text-=
decoration:none;} @media only screen and (max-width:480px){ .block_seccion =
table[class*=3Dmain_table]{width:280px !important;} } </style><style type=
=3D"text/css" id=3D"block_logo_css"> .block_logo table{border-collapse:coll=
apse;mso-table-lspace:0pt;mso-table-rspace:0pt;} .block_logo a img{border:n=
one;} .block_logo img{border:none;} .block_logo a, .block_logo a:hover, .bl=
ock_logo a:visited{text-decoration:none !important;} @media only screen and=
 (max-width:480px){ .block_logo table[class*=3Dmain_table]{width:320px !imp=
ortant;} .block_logo td[class*=3Dpad_both]{padding-left:20px !important;pad=
ding-right:20px !important;} } </style><style type=3D"text/css" id=3D"acrst=
yle2">tr[class*=3D'block'] *{list-style:inherit} tr[class*=3D'block'] ul{ma=
rgin-bottom:10px;list-style-type:disc !important;} tr[class*=3D'block'] ol{=
margin-bottom:10px;list-style-type:decimal !important;} tr[class*=3D'block'=
] ul{margin-left:15px !important; list-style-position:inside;} tr[class*=3D=
'block'] ol{margin-left:15px !important; list-style-position:inside;}</styl=
e><!--[if gte mso 9]><style type=3D'text/css'>li{margin-left:20px;}</style>=
<![endif]--> <style id=3D"block_link_browser" type=3D"text/css"> .block_lin=
k_browser table[class*=3Dmain_table]{width:580px;} .block_link_browser tabl=
e{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;} .blo=
ck_link_browser a img{border:0;} @media only screen and (max-width:480px){ =
body {width:auto;} .block_link_browser table[class=3D"BoxWrap"]{width:280px=
;} .block_link_browser table[class*=3Dmain_table]{width:320px !important;} =
.block_link_browser td[class*=3Dpad_both]{padding-left:20px !important;padd=
ing-right:20px !important;} } </style> <style id=3D"block_links_footer" typ=
e=3D"text/css"> .block_links_footer table[class=3D"BoxWrap"]{width:580px;} =
.block_links_footer table{border-collapse:collapse;mso-table-lspace:0pt;mso=
-table-rspace:0pt;} .block_links_footer a img{border:0;} @media only screen=
 and (max-width:480px){ body {width:auto;} .block_links_footer table[class=
=3D"BoxWrap"]{width:280px;} .block_links_footer table[class*=3Dmain_table]{=
width:320px !important;} .block_links_footer td[class*=3Dpad_both]{padding-=
left:20px !important;padding-right:20px !important;} } </style> <style id=
=3D"block_links_footer" type=3D"text/css"> .block_spacer table{border-colla=
pse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;} .block_spacer a im=
g{border:0;} .block_spacer a, .block_spacer a:hover, .block_spacer a:visite=
d{text-decoration:none;} @media only screen and (max-width:480px){ .block_s=
pacer table[class*=3Dmain_table]{width:320px !important;} .block_spacer td[=
class*=3Dpad_both]{padding-left:20px !important;padding-right:20px !importa=
nt;} } </style> <style type=3D"text/css">@media only screen and (max-width:=
480px){.wrapper,.main_table,#Imgfull,.BoxWrap,.block_texto table,.block_tex=
to img,.block_seccion table,.block_seccion img,.block_2col table,.block_2co=
l img,.block_2col_complete table,.block_2col_complete img,.block_2col_image=
 table,.block_2col_image img,.block_3col table,.block_3col img,.block_3col_=
complete table,.block_3col_complete img,.block_3col_image table,.block_3col=
_image img,.block_image table,.block_image img,.block_image_full_complete t=
able,.block_image_full_complete img,.block_image_left table,.block_image_le=
ft img,.block_image_left_text table,.block_image_left_text img,.block_image=
_right table,.block_image_right img,.block_image_right_text table,.block_im=
age_right_text img,.block_image_small_left table,.block_image_small_left im=
g,.block_image_small_right table,.block_image_small_right img,.block_logo t=
able,.block_logo img,.block_qrcode table,.block_qrcode img,.block_video tab=
le,.block_video img,.block_button table,.block_button img,.block_seccion_ti=
tulo_texto_boton table,.block_seccion_titulo_texto_boton img,.block_spacer =
table,.block_spacer table.main_table,.block_spacer .main_table,.qrimage{max=
-width:100%!important;width:100%!important;min-width:100%!important}tbody{d=
isplay:table!important;min-width:100%!important;width:100%!important;max-wi=
dth:100%!important}.block_3col_complete table[class*=3Dwrapper]{display:tab=
le!important}.block_qrcode table.main_table td[width=3D"20"]{height:0px!imp=
ortant;width:0px!important;display:none!important;visibility:hidden!importa=
nt}.block_qrcode table.main_table td[height=3D"20"]{height:0px!important;wi=
dth:0px!important;display:none!important;visibility:hidden!important}img,.q=
rimage,table,td[class*=3D"pad_both"],table[class=3D"wrapper"],table[class=
=3D"main_table"],#Imgfull,.wrapper,.main_table,.BoxWrap{max-width:100%!impo=
rtant;width:100%!important;min-width:100%!important}.block_seccion img,.Hea=
dTxt img,.title1 img,.texto img,tr.block_footer img,tr.block_social img,.Tx=
t img,.Section img,.Title img{width:inherit!important;min-width:inherit!imp=
ortant;max-width:inherit!important}tr[class*=3D"block_"] td[class*=3D"pad_b=
oth"],td.pad_both{padding:0px!important}tr.block_links_footer .pad_both{pad=
ding-left:20px!important;padding-right:20px!important}tr.block_links_footer=
 a{display:block!important}tr.block_links_footer td>span{display:block!impo=
rtant;padding-bottom:10px!important}tr[class*=3D"block_"]{width:100px!impor=
tant}.block_spacer td.pad_both{padding-left:0px!important;padding-right:0px=
!important;max-width:100%!important;width:100%!important}}</style> <!--[if =
gte mso 9]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPerInch>96<=
/o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]--><style type=
=3D"text/css">.preheader1{display:none !important;font-size:0px;visibility:=
hidden;opacity:0;color:transparent;height:0;width:0;}
  #preheader1{display:none !important;font-size:0px;visibility:hidden;opaci=
ty:0;color:transparent;height:0;width:0;}</style></head><body><span style=
=3D" display:none !important;visibility:hidden;opacity:0;color:transparent;=
height:0;width:0;font-size:1px !important" id=3D"preheader1" class=3D"prehe=
ader1">XVII Congreso LATINA 2025 (res&uacute;menes hasta 10/10/2024) organi=
zado por editorial ESIC e HISIN</span><div style=3D"display:none;max-height=
:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
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
px; margin-bottom: 0px;"> <tbody> <tr class=3D"block_link_browser"> <td wid=
th=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: rgb(253, 2=
51, 252); padding: 0px;"> <table width=3D"580" border=3D"0" cellspacing=3D"=
0" cellpadding=3D"0" align=3D"center" style=3D"margin: 0px auto; width: 580=
px; " class=3D"main_table "> <tbody><tr> <td class=3D"pad_both"> <table wid=
th=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"cente=
r" style=3D""> <tbody><tr> <td> <table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D""> <tbody>=
<tr> <td height=3D"25" style=3D"text-align:center; font-size: 11px; color: =
#b3b3b3; font-family: Helvetica, Arial, sans-serif; vertical-align: middle;=
"> <a href=3D"https://www.campaign-index.com/view.php?J=3DA4qv3gVHBXHIKwyTE=
Jvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"text-decoration: underline; co=
lor:#333;"><span>Ver en navegador</span></a> </td> </tr> </tbody></table> <=
/td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> <tr cl=
ass=3D"block_spacer"> <td width=3D"100%" valign=3D"top" style=3D"background=
-color: rgb(253, 251, 252); height: 20px;" class=3D"" height=3D"20"> <table=
 class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D"0" alig=
n=3D"center" style=3D"margin:0 auto; height:100%"> <tbody><tr> <td height=
=3D"100%" style=3D"height: 100%; line-height: 20px;"> <table width=3D"580" =
height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"c=
enter" class=3D"main_table" style=3D"height: 100%; width: 580px;"> <tbody><=
tr> <td class=3D"pad_both" style=3D"background-color: inherit; height: 100%=
; line-height: 20px;" height=3D"100%"> <table width=3D"100%" height=3D"100%=
" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  =
border-width: initial; border-style: none; border-color: initial; margin-to=
p: 0px; padding: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr> <td widt=
h=3D"100%" height=3D"100%" style=3D"display: block; height: 100%; line-heig=
ht: 20px; padding: 0px;">&nbsp;</td> </tr> </tbody></table> </td> </tr> </t=
body></table> </td> </tr> </tbody></table> </td> </tr> <tr class=3D"block_s=
eccion"> <td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-c=
olor: rgb(253, 251, 252);"> <table class=3D"BoxWrap" cellpadding=3D"0" cell=
spacing=3D"0" align=3D"center" style=3D"margin:0 auto;"> <tbody><tr> <td> <=
table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=
=3D"center" class=3D"main_table" style=3D"width:580px;"> <tbody><tr> <td st=
yle=3D"padding: 4px 20px;  border-width: initial; border-style: none; borde=
r-color: initial; margin-top: 0px; margin-bottom: 0px;" class=3D""> <table =
width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0"> <tbody><tr=
> <td><table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0=
" align=3D"center"> <tbody><tr> <td block=3D"" style=3D"word-break: break-w=
ord; overflow-wrap: break-word; text-align: left; padding-bottom: 3px; font=
-size: 16px; margin-bottom: 7px; padding-top: 4px; font-family: Helvetica, =
Arial, sans-serif; text-decoration: none; color: rgb(69, 72, 78);"> <div st=
yle=3D"line-height: 20px; text-align: center;"><span style=3D"font-size:16p=
x"><strong><font color=3D"#000000">CONG</font><span style=3D"color:#000000"=
>RESO INTERNACIONAL&nbsp;LATINA DE COMUNICACI&Oacute;N SOCIAL</span><span s=
tyle=3D"color:#FF8C00"><strong> </strong></span><span style=3D"color:#0000C=
D">2025</span></strong></span></div> </td></tr> </tbody></table></td> </tr>=
 </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></table>=
 </td> </tr><tr class=3D"block_logo" style=3D"display: table-row;"> <td wid=
th=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: rgb(253, 2=
51, 252);"> <table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" al=
ign=3D"center" style=3D"margin:0 auto;"> <tbody><tr> <td> <table width=3D"5=
80" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=
=3D"main_table" style=3D"width:580px;"> <tbody><tr> <td class=3D"pad_both" =
style=3D"background-color: inherit;"> <table width=3D"100%" border=3D"0" ce=
llspacing=3D"0" cellpadding=3D"0" style=3D" border-width: initial; border-s=
tyle: none; border-color: initial; margin-top: 0px; padding: 0px; margin-bo=
ttom: 0px;" class=3D""> <tbody><tr> <td style=3D"padding: 0px;"><table widt=
h=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center=
"> <tbody><tr> <td> <table align=3D"center" style=3D"font-size: 13px; font-=
weight: 400; font-family: Helvetica, Arial, sans-serif;  border-width: init=
ial; border-style: none; border-color: initial; padding: 0px; margin: 0px a=
uto;" class=3D""> <tbody><tr> <td style=3D"padding: 0px;"><a href=3D"https:=
//www.email-index.com/click.php?L=3DLlgNg3kOrLPSMZ8d1KSujQ&J=3DA4qv3gVHBXHI=
KwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=
=3D" vertical-align: top; display: block;" title=3D"Web del XIII CLCS"><img=
 align=3D"absbottom" border=3D"0" id=3D"Imgfull" width=3D"188" src=3D"https=
://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/LOGO%2=
0CILCS%202025%20peque%C3%B1o%20con%20fondo.png?1756743596018" alt=3D"XIII C=
ILCS" style=3D"width: 188px; max-width: 188px; text-align: center; font-siz=
e: 18px; color: rgb(255, 255, 255); font-weight: 700; text-shadow: black 0.=
1em 0.1em 0.2em; text-transform: uppercase;" class=3D"acre_image_editable" =
ac:percent=3D"67"></a></td> </tr> </tbody></table> </td> </tr> </tbody></ta=
ble></td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> <=
/tbody></table> </td> </tr> <tr class=3D"block_texto"> <td width=3D"100%" v=
align=3D"top" class=3D"" style=3D"background-color: rgb(253, 251, 252);"> <=
table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"center=
" style=3D"margin:0 auto;"> <tbody><tr> <td> <table width=3D"580" border=3D=
"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_tabl=
e" style=3D"width:580px;"> <tbody><tr> <td class=3D"pad_both" style=3D"back=
ground-color: inherit;"> <table width=3D"100%" border=3D"0" cellspacing=3D"=
0" cellpadding=3D"0" style=3D"background-color: rgb(255, 255, 255); border:=
 none;  margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D"" bgco=
lor=3D" #ffffff"> <tbody><tr> <td style=3D"background-color: rgb(255, 255, =
255); padding: 0px; width: 20px;" width=3D"20">&nbsp;</td> <td style=3D"bac=
kground-color: rgb(255, 255, 255); padding: 0px;"><table width=3D"100%" bor=
der=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center"> <tbody><tr>=
 <td height=3D"20">&nbsp;</td> </tr> <tr> <td block=3D"" class=3D"texto" st=
yle=3D"word-break: break-word; overflow-wrap: break-word; font-size: 13px; =
line-height: initial; font-family: Helvetica, Arial, sans-serif; color: rgb=
(123, 123, 123);"> <div style=3D"line-height: 20px; text-align: justify;"> =
<span style=3D"font-size:14px">Estimad@s amig@s y colegas:<br> <br> Estamos=
 muy ilusionad@s con el lanzamiento&nbsp;del&nbsp;<strong><span style=3D"co=
lor:#0000FF">XVII CONGRESO INTERNACIONAL LATINA DE COMUNICACI&Oacute;N SOCI=
AL 2025&nbsp;</span><span style=3D"color:#003366">(</span><span style=3D"co=
lor:#000080">CILCS</span><span style=3D"color:#003366">)</span> </strong>qu=
e se celebrar&aacute; los pr&oacute;ximos d&iacute;as 10, 11&nbsp;y 12&nbsp=
;de diciembre en modalidad <em><strong>online</strong></em>&nbsp;<u><span s=
tyle=3D"color:#0000CD">www.congresolatina.net</span></u><br> <br> Los idiom=
as del congreso son: <span style=3D"color:#000000"><strong>espa&ntilde;ol, =
italiano, portugu&eacute;s, ingl&eacute;s </strong>y<strong> franc&eacute;s=
</strong></span>.<br> <br> <span style=3D"color:#000000"><strong>Los&nbsp;e=
spacios de trabajo</strong></span>&nbsp;propuestos son actuales, interesant=
es e imprescindibles en una sociedad que cambia cada d&iacute;a y cada vez =
a mayor velocidad.&nbsp;EDUCACI&Oacute;N, TURISMO, DEPORTE, POL&Iacute;TICA=
, MARKETING, PUBLICIDAD, LEGALIDAD, INTELIGENCIA ARTIFICIAL&hellip; Siempre=
 vinculados a la COMUNICACI&Oacute;N.</span><br> <br> <span style=3D"font-s=
ize:14px"><span style=3D"color:#000000"><strong>Espacios tem&aacute;ticos: =
</strong></span><span style=3D"color:#0000FF">(https://congresolatina.net/2=
025-espacios-tematicos/)</span></span> </div> <ol> <li style=3D"line-height=
: 20px; text-align: justify;"><span style=3D"color:#000000">Educando en com=
unicaci&oacute;n</span></li> <li style=3D"line-height: 20px; text-align: ju=
stify;"><span style=3D"color:#000000"><span style=3D"font-size:14px">Comuni=
caci&oacute;n digital</span></span></li> <li style=3D"line-height: 20px; te=
xt-align: justify;"><span style=3D"color:#000000"><span style=3D"font-size:=
14px">Nuevas tendencias e investigaci&oacute;n en la comunicaci&oacute;n</s=
pan></span></li> <li style=3D"line-height: 20px; text-align: justify;"><spa=
n style=3D"color:#000000"><span style=3D"font-size:14px">Comunicaci&oacute;=
n persuasiva</span></span></li> <li style=3D"line-height: 20px; text-align:=
 justify;"><span style=3D"color:#000000"><span style=3D"font-size:14px">Com=
unicaci&oacute;n empresarial</span></span></li> <li style=3D"line-height: 2=
0px; text-align: justify;"><span style=3D"color:#000000"><span style=3D"fon=
t-size:14px">Comunicaci&oacute;n especializada</span></span></li> <li style=
=3D"line-height: 20px; text-align: justify;"><span style=3D"color:#000000">=
<span style=3D"font-size:14px">L&iacute;mites de la comunicaci&oacute;n</sp=
an></span></li> <li style=3D"line-height: 20px; text-align: justify;"><span=
 style=3D"color:#000000"><span style=3D"font-size:14px">El negocio de los m=
edios</span></span></li> <li style=3D"line-height: 20px; text-align: justif=
y;"><span style=3D"color:#000000"><span style=3D"font-size:14px">Propuestas=
 de comunicaciones libres</span></span></li> <li style=3D"line-height: 20px=
; text-align: justify;"><span style=3D"color:#000000"><span style=3D"font-s=
ize:14px">Paneles</span></span></li> </ol> <div style=3D"line-height: 20px;=
 text-align: justify;"><span style=3D"font-size:14px"><span style=3D"color:=
#003366"><strong>Curricularmente&nbsp;</strong></span><span style=3D"color:=
#000080"><strong>CILCS</strong></span><span style=3D"color:#0000FF"><strong=
> </strong></span>presenta:</span></div> <ul> <li style=3D"line-height: 20p=
x; text-align: justify;"><span style=3D"color:#000000"><strong>Libro electr=
&oacute;nico de Actas&nbsp;con ISBN</strong>&nbsp;979-13-87819-03-3&nbsp;(c=
on los res&uacute;menes aceptados tras&nbsp;revisi&oacute;n por pares ciego=
s)</span></li> <li style=3D"line-height: 20px; text-align: justify;"><span =
style=3D"font-size:14px">y, adem&aacute;s, da a elegir entre <span style=3D=
"color:#0000CD"><strong>seis posibilidades de publicaci&oacute;n</strong></=
span>:</span></li> </ul> <ol style=3D"margin-left: 40px;"> <li style=3D"lin=
e-height: 20px; text-align: justify;"><span style=3D"font-size:14px"><span =
style=3D"color:#000000"><strong>Libro electr&oacute;nico </strong>de la edi=
torial<strong> </strong></span><span style=3D"color:#008000"><strong>TIRANT=
 LO BLANCH</strong></span><span style=3D"color:#00FF00">&nbsp;</span>(<span=
 style=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;<span style=3D"color:rgb(0,=
 0, 205)"><u>&iacute;ndice SPI General</u></span>). <span style=3D"color:#0=
00000">Compuesto por los&nbsp;textos aceptados tras&nbsp;revisi&oacute;n de=
 mejora mediante dobles pares ciegos por parte del Comit&eacute; Evaluador =
del Congreso. Publicable en 2026.</span></span></li> <li style=3D"line-heig=
ht: 20px; text-align: justify;"> <span style=3D"color:#A52A2A"><strong>Revi=
sta Latina de Comunicaci&oacute;n Social&nbsp;-RLCS-</strong></span>&nbsp;<=
strong><span style=3D"color:#0000CD">(Scopus Q-1&nbsp;y&nbsp;SJR Q-1)</span=
></strong>.&nbsp;<span style=3D"color:#000000">Se publicar&aacute; un m&aac=
ute;ximo de&nbsp;6 textos en&nbsp;2026 tras ser aceptados por el Comit&eacu=
te; Editorial de la misma.</span> </li> <li style=3D"line-height: 20px; tex=
t-align: justify;"> <span style=3D"color:#800080"><strong>European Public &=
amp; Social Innovation Review</strong></span><span style=3D"color:#0000CD">=
<strong>&nbsp;(Scopus Q-3&nbsp;y SJR Q-3)</strong></span>.&nbsp;<span style=
=3D"color:#000000">Se publicar&aacute;&nbsp;un m&aacute;ximo de 6&nbsp;text=
os en&nbsp;2026&nbsp;tras ser aceptados por el Comit&eacute; Editorial de l=
a misma.</span> </li> <li style=3D"line-height: 20px; text-align: justify;"=
> <span style=3D"color:#FF0000"><strong>Bibliotecas, Anales de Investigaci&=
oacute;n</strong></span>&nbsp;<span style=3D"color:#0000CD"><strong>(Scopus=
 Q-4&nbsp;y SJR Q-4)</strong></span>.&nbsp;<span style=3D"color:#000000">Se=
 publicar&aacute; un m&aacute;ximo de&nbsp;6 textos en 2026 tras ser acepta=
dos por el Comit&eacute; Editorial de la misma.</span> </li> <li style=3D"l=
ine-height: 20px; text-align: justify;"> <span style=3D"color:#FFA500"><str=
ong>Revista SOCIAL REVIEW,&nbsp;International Social Sciences Review</stron=
g></span>&nbsp;<span style=3D"color:#000000">(</span><span style=3D"color:#=
0000CD"><strong>EBSCO</strong></span><span style=3D"color:#000000">) Se pub=
licar&aacute;&nbsp;un m&aacute;ximo de 6 en 2026 textos&nbsp;tras ser acept=
ados por el Comit&eacute; Editorial de la misma.</span> </li> <li style=3D"=
line-height: 20px; text-align: justify;"> <span style=3D"color:#00FF00"><st=
rong>Revista EDU REVIEW, International Education and Learning Review</stron=
g></span> <span style=3D"color:#000000">(</span><strong><span style=3D"colo=
r:#0000CD">EBSCO</span></strong><span style=3D"color:#000000">).&nbsp;Se pu=
blicar&aacute;&nbsp;un m&aacute;ximo de 6&nbsp;textos en 2026 tras ser acep=
tados por el Comit&eacute; Editorial de la misma.</span> </li> </ol> <div s=
tyle=3D"line-height: 20px; text-align: justify;"> <span style=3D"color:#000=
000"><span style=3D"font-size:14px">Si una propuesta para una revista no es=
 aceptada,<strong> ser&aacute; publicada&nbsp;</strong></span></span><span =
style=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px">por<strong>&nbs=
p;</strong></span></span><span style=3D"color:rgb(0, 128, 0)"><span style=
=3D"font-size:14px"><strong>TIRANT LO BLANCH</strong></span></span><span st=
yle=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px">, si los autores =
lo desean, en un libro&nbsp;electr&oacute;nico</span></span><span style=3D"=
color:rgb(0, 0, 0)"><span style=3D"font-size:14px"><strong>.</strong></span=
></span> </div> <div style=3D"line-height: 20px; text-align: justify;"> <br=
> <span style=3D"color:#000000"><span style=3D"font-size:14px"><strong>Se p=
odr&aacute; participar:</strong></span></span> </div> <ol> <li style=3D"lin=
e-height: 20px; text-align: justify;"><span style=3D"color:#000000"><span s=
tyle=3D"font-size:14px"><strong>Enviando un v&iacute;deo (emitido el 10&nbs=
p;de diciembre)&nbsp;o </strong></span></span></li> <li style=3D"line-heigh=
t: 20px; text-align: justify;"><span style=3D"color:#000000"><span style=3D=
"font-size:14px"><strong>En directo a trav&eacute;s de zoom (11&nbsp;o 12&n=
bsp;de diciembre)</strong></span></span></li> </ol> <div style=3D"line-heig=
ht: 20px; text-align: justify;"> <span style=3D"color:#0000FF"><span style=
=3D"font-size:14px"><strong>Fechas clave:</strong></span></span> <table bor=
der=3D"1" cellpadding=3D"1" cellspacing=3D"1" style=3D"width:750px"> <tbody=
> <tr> <td><strong><span style=3D"font-family:arial,sans-serif; font-size:1=
2px">Env&iacute;o de resumen</span></strong></td> <td> <strong><span style=
=3D"border:1pt none windowtext; font-family:arial,sans-serif; font-size:9pt=
; line-height:13.8px; padding:0cm">Hasta</span></strong><span style=3D"font=
-family:arial,sans-serif; font-size:9pt; line-height:13.8px">&nbsp;<strong>=
<span style=3D"border:1pt none windowtext; padding:0cm">el&nbsp;<span style=
=3D"color:#0000FF">10 de octubre</span></span></strong></span> </td> </tr> =
<tr> <td><span style=3D"font-family:arial,sans-serif; font-size:12px"><stro=
ng>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute;n</spa=
n></td> <td> <strong><span style=3D"border:1pt none windowtext; font-family=
:arial,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Desde el=
&nbsp;</span></strong><span style=3D"color:#0000FF"><span style=3D"border:1=
pt none windowtext; font-family:arial,sans-serif; font-size:9pt; line-heigh=
t:13.8px; padding:0cm"><strong>14 de octubre</strong></span></span> </td> <=
/tr> <tr> <td> <span style=3D"font-family:arial,sans-serif; font-size:12px"=
>Abono de&nbsp;</span><strong style=3D"font-family:arial,sans-serif; font-s=
ize:12px"><span style=3D"border:1pt none windowtext; padding:0cm">matr&iacu=
te;cula</span></strong><span style=3D"color:rgb(0, 112, 192); font-family:a=
rial,sans-serif; font-size:12px">:&nbsp;</span><span style=3D"font-family:a=
rial,sans-serif; font-size:12px">(195 &euro; por cada firmante y por cada p=
onencia)</span> </td> <td><strong><span style=3D"border:1pt none windowtext=
; font-family:arial,sans-serif; font-size:9pt; line-height:13.8px; padding:=
0cm">Hasta el&nbsp;<span style=3D"color:#0000FF">7 de noviembre</span></spa=
n></strong></td> </tr> <tr> <td><span style=3D"font-family:arial,sans-serif=
; font-size:12px"><strong>Env&iacute;o de ponencia completa</strong></span>=
</td> <td><strong><span style=3D"border:1pt none windowtext; font-family:ar=
ial,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nb=
sp;<span style=3D"color:#0000FF">14 de noviembre</span></span></strong></td=
> </tr> <tr> <td> <span style=3D"font-family:arial,sans-serif; font-size:12=
px">Env&iacute;o de v&iacute;deo</span><span style=3D"font-family:arial,san=
s-serif; font-size:12px">&nbsp;para ser emitido el 10 de diciembre o env&ia=
cute;o de correo electr&oacute;nico informando que desea defender la ponenc=
ia en directo el 11 o 12 de diciembre</span> </td> <td><strong><span style=
=3D"border:1pt none windowtext; font-family:arial,sans-serif; font-size:9pt=
; line-height:13.8px; padding:0cm">Hasta el <span style=3D"color:#0000FF">2=
1 de noviembre</span></span></strong></td> </tr> <tr> <td><span style=3D"fo=
nt-family:arial,sans-serif; font-size:12px"><strong>Celebraci&oacute;n </st=
rong>(online)</span></td> <td><strong><span style=3D"border:1pt none window=
text; font-family:arial,sans-serif; font-size:9pt; line-height:13.8px; padd=
ing:0cm"><span style=3D"color:#0000FF">10, 11&nbsp;</span>y&nbsp;<span styl=
e=3D"color:#0000FF">12 de diciembre</span></span></strong></td> </tr> </tbo=
dy> </table> <br> <span style=3D"font-size:14px"><span style=3D"color:#0033=
66"><strong><span style=3D"font-family:arial,sans-serif; line-height:115%">=
M&aacute;s informaci&oacute;n en:&nbsp;</span></strong></span></span> <div =
style=3D"line-height:22px;"> <span style=3D"font-size:14px"><span style=3D"=
color:#0000CD"><u>www.congresolatina.net</u></span><span style=3D"font-fami=
ly:arial,sans-serif; line-height:115%">&nbsp;</span></span><br> <u style=3D=
"font-size:14px"><span style=3D"color:#0000CD">2025congresolatina@hisin.org=
</span></u> </div> </div> <div style=3D"line-height: 20px; text-align: just=
ify;"><span style=3D"font-size:14px"><strong>Tel&eacute;fono y&nbsp;WhatsAp=
p (+34) 663 935 312 (de 9 a 19 horas de Madrid)</strong><br> <br> <strong><=
span style=3D"color:#FF0000">Un abrazo y &iexcl;&iexcl;SEGUIMOS COMUNICANDO=
!!</span></strong><br> <br> <span style=3D"color:#003366"><strong>Almudena =
Barrientos-B&aacute;ez</strong>&nbsp;y <strong>Paola Eunice Rivera Salas</s=
trong><br> Universidad&nbsp;Complutense&nbsp;(Espa&ntilde;a) y Benem&eacute=
;rita Universidad Aut&oacute;noma de Puebla (M&eacute;xico)</span><br> <str=
ong><span style=3D"color:#000080">Directoras del XVII CILCS</span></strong>=
</span></div> </td></tr> <tr> <td height=3D"20">&nbsp;</td> </tr> </tbody><=
/table></td> <td style=3D"background-color: rgb(255, 255, 255); padding: 0p=
x; width: 20px;" width=3D"20">&nbsp;</td> </tr> </tbody></table> </td> </tr=
> </tbody></table> </td> </tr> </tbody></table> </td> </tr><tr class=3D"blo=
ck_social"> <td valign=3D"top" style=3D""><table width=3D"100%" border=3D"0=
" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D"=
"> <tbody><tr> <td align=3D"center"><table width=3D"580" border=3D"0" cells=
pacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=
=3D"width:580px;"> <tbody><tr> <td class=3D"pad_both"><table width=3D"100%"=
 border=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"background-color=
: rgb(255, 255, 255); border: none;  margin-top: 0px; padding: 0px; margin-=
bottom: 0px;" class=3D"" bgcolor=3D" #ffffff"> <tbody><tr> <td width=3D"20"=
 class=3D"hide" style=3D"width: 20px; background-color: rgb(255, 255, 255);=
 padding: 0px;">&nbsp;</td> <td style=3D"background-color: rgb(255, 255, 25=
5); padding: 0px;"><table width=3D"100%" border=3D"0" cellspacing=3D"0" cel=
lpadding=3D"0" align=3D"center"> <tbody><tr> <td height=3D"20">&nbsp;</td> =
</tr> <tr> <td align=3D"center"> <table border=3D"0" cellpadding=3D"0" cell=
spacing=3D"0" width=3D"100%" style=3D"min-width:100%;"> <tbody><tr> <td ali=
gn=3D"center" valign=3D"top"> <table align=3D"center" border=3D"0" cellpadd=
ing=3D"0" cellspacing=3D"0"> <tbody><tr> <td align=3D"center" valign=3D"top=
"> <table align=3D"center" border=3D"0" cellspacing=3D"0" cellpadding=3D"0"=
> <tbody><tr> <td align=3D"center" valign=3D"top"> <table align=3D"left" bo=
rder=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"> <=
tbody><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cellsp=
acing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"middle=
" style=3D"padding:3px"> <table align=3D"left" border=3D"0" cellpadding=3D"=
0" cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valign=3D=
"middle" width=3D"38" style=3D"width:38px;"><a href=3D"https://www.email-in=
dex.com/click.php?L=3D9ILQPqOLPN4l4rYh21QnvQ&J=3DA4qv3gVHBXHIKwyTEJvxyg&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-=
align: top; display: block;" title=3D""><img ac:social=3D"1" border=3D"0" w=
idth=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38=
px; border: 0px; display: block; text-align: left; font-size: 12px; color: =
rgb(17, 85, 204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; t=
ext-transform: uppercase; font-family: Arial;" src=3D"https://d1nn1beycom2n=
r.cloudfront.net/news/img/ico-facebook-38.jpg" alt=3D"facebook CILCS" class=
=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> </tr> </tbo=
dy></table> </td> </tr> </tbody></table> </td> <td align=3D"center" valign=
=3D"top"> <table align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" style=3D"display:inline;"> <tbody><tr> <td valign=3D"top"> <table bo=
rder=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"> <tbody><tr> =
<td align=3D"left" valign=3D"middle" style=3D"padding:3px"> <table align=3D=
"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D""> <tbody>=
<tr> <td align=3D"center" valign=3D"middle" width=3D"38" style=3D"width:38p=
x;"><a href=3D"https://www.email-index.com/click.php?L=3DOl6cw3Aa763VMMxs6h=
CAC892XQ&J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcC=
bcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=3D"=
"><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" style=3D"wid=
th: 38px; max-width: 38px; height: 38px; border: 0px; display: block; text-=
align: left; font-size: 12px; color: rgb(17, 85, 204); font-weight: 700; te=
xt-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; font-family:=
 Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twitter-=
38.jpg" alt=3D"twitter CILCS" class=3D"acre_image_editable"></a></td> </tr>=
 </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></table>=
 </td> <td align=3D"center" valign=3D"top"> <table align=3D"left" border=3D=
"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"> <tbody><=
tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"middle" sty=
le=3D"padding:3px;"> <table align=3D"left" border=3D"0" cellpadding=3D"0" c=
ellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valign=3D"mid=
dle" width=3D"38" style=3D"width:38px;"><a href=3D"https://www.email-index.=
com/click.php?L=3DkJUcdb9f3ymmRi08m6L6oQ&J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6=
K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align:=
 top; display: block;" title=3D""><img ac:social=3D"1" border=3D"0" width=
=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38px; =
border: 0px; display: block; text-align: left; font-size: 12px; color: rgb(=
17, 85, 204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-=
transform: uppercase; font-family: Arial;" src=3D"https://d1nn1beycom2nr.cl=
oudfront.net/news/img/ico-linkedin-38.jpg" alt=3D"linkedin CILCS" class=3D"=
acre_image_editable"></a></td> </tr> </tbody></table> </td> </tr> </tbody><=
/table> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </t=
r> </tbody></table> </td> </tr> </tbody> </table> </td> </tr> <tr> <td heig=
ht=3D"20">&nbsp;</td> </tr> </tbody></table></td> <td width=3D"20" class=3D=
"hide" style=3D"width: 20px; background-color: rgb(255, 255, 255); padding:=
 0px;">&nbsp;</td> </tr> </tbody></table></td> </tr> </tbody></table></td> =
</tr> </tbody></table></td> </tr><tr class=3D"block_spacer"> <td width=3D"1=
00%" valign=3D"top" style=3D"background-color: rgb(253, 251, 252);" class=
=3D""> <table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspaci=
ng=3D"0" align=3D"center" style=3D"margin:0 auto; height:100%"> <tbody><tr>=
 <td height=3D"100%" style=3D"height: 100%; line-height:25px"> <table width=
=3D"580" height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" a=
lign=3D"center" class=3D"main_table" style=3D"height: 100%; width: 580px;">=
 <tbody><tr> <td class=3D"pad_both" style=3D"background-color: inherit; hei=
ght:100%" height=3D"100%"> <table width=3D"100%" height=3D"100%" border=3D"=
0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-width=
: initial; border-style: none; border-color: initial; margin-top: 0px; padd=
ing: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr> <td width=3D"100%" h=
eight=3D"100%" style=3D"display: block; height: 100%; line-height: 25px; pa=
dding: 0px;">&nbsp;</td> </tr> </tbody></table> </td> </tr> </tbody></table=
> </td> </tr> </tbody></table> </td> </tr> <tr class=3D"block_links_footer"=
> <td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-color: r=
gb(253, 251, 252);"> <table width=3D"580" border=3D"0" cellspacing=3D"0" ce=
llpadding=3D"0" align=3D"center" class=3D"main_table " style=3D"margin: 0px=
 auto; width: 580px; "> <tbody><tr> <td class=3D"pad_both"> <table width=3D=
"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" st=
yle=3D""> <tbody><tr> <td> <table width=3D"100%" border=3D"0" cellspacing=
=3D"0" cellpadding=3D"0" align=3D"center" class=3D"" style=3D" border-width=
: initial; border-style: none; border-color: initial; margin-top: 0px; padd=
ing: 0px; margin-bottom: 0px;"> <tbody><tr> <td height=3D"20" style=3D"text=
-align: center; font-size: 11px; color: rgb(51, 51, 51); font-family: Helve=
tica, Arial, sans-serif; vertical-align: middle; padding: 0px;"> <a href=3D=
"https://www.email-index.com/unsubscribe.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"text-decoration: underline; color:#33=
3;"><span>Darme de baja de esta lista</span></a> | <a href=3D"https://www.e=
mail-index.com/update.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635=
lLHrEQ" style=3D"text-decoration: underline; color:#333;"><span>Actualizar =
mis datos</span></a> <br><br> <span>F&Oacute;RUM XXI - Cine n&ordm; 38. Baj=
o derecha, 28024, Madrid</span> </td> </tr> </tbody></table> </td> </tr> </=
tbody></table> </td> </tr> </tbody></table> </td> </tr> <tr class=3D"block_=
spacer"> <td width=3D"100%" valign=3D"top" style=3D"background-color: rgb(2=
53, 251, 252);" class=3D""> <table class=3D"BoxWrap" cellpadding=3D"0" heig=
ht=3D"100%" cellspacing=3D"0" align=3D"center" style=3D"margin:0 auto; heig=
ht:100%"> <tbody><tr> <td height=3D"100%" style=3D"height: 100%; line-heigh=
t:25px"> <table width=3D"580" height=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"height: =
100%; width: 580px;"> <tbody><tr> <td class=3D"pad_both" style=3D"backgroun=
d-color: inherit; height:100%" height=3D"100%"> <table width=3D"100%" heigh=
t=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height=
: 100%;  border-width: initial; border-style: none; border-color: initial; =
margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr>=
 <td width=3D"100%" height=3D"100%" style=3D"display: block; height: 100%; =
line-height: 25px; padding: 0px;">&nbsp;</td> </tr> </tbody></table> </td> =
</tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody> </=
table>=20
                        <table id=3D"ac_footer_email" width=3D"100%" style=
=3D"width:100%">
                            <tr>
                                <td width=3D"100%" valign=3D"top" align=3D"=
center">
                                    <table width=3D"" align=3D"center">
                                        <tr>
                                            <td style=3D"text-align:center;=
"><a href=3D"https://www.email-index.com/click.php?L=3DTRW763YAgcgzvi892GYS=
l7GHmg&J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbc=
nmxmc4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"borde=
r-style:none;min-width: initial !important;max-width: initial !important;wi=
dth: initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/uplo=
ads/user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LATI=
NA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DA4qv3gVHBXHIKwyTEJvxyg&C=3DkF6K5qd4mAeEXe7635lLHrEQ" alt=3D=
"" border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px,bord=
er:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f9bfa5c6e8-000000%40eu=
-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">https://group=
s.google.com/d/msgid/kasan-dev/01020199106a8a68-7469c5cd-48ef-4645-ae1f-a7f=
9bfa5c6e8-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_F1rx4Lu80CMdimjrVODQEL6u3MVQO8HyArf1r8bO0--

