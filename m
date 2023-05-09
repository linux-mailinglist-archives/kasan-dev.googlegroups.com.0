Return-Path: <kasan-dev+bncBD2457WDXMPBB2NC42RAMGQEE3SHJEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C71B16FBBE9
	for <lists+kasan-dev@lfdr.de>; Tue,  9 May 2023 02:18:50 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4edc5d704a0sf3059276e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 17:18:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683591530; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRwvJs0v2c6VsLcjSVoTKf/U2w0bTi+XXNIGfjhRjRKU+KaQkH3E2uSnxjDjCs1go2
         FODkFq1/k19W8Hoi8iCKMaCiargQhAA0xmBaRvymKW/P3YtoggP9tUuTuD4bBTsXGSUT
         0S2futOZUo2aNVCMqpjycYz0S76m+Bc2KVLkOV5Pjct+kiO+MWtdEbf4nirNjAmnOvxo
         1zZYzYGOPIF55AyWezIMWpbTvfZT1k4tZcNGZpJ6pc8eil7MTqf37LDv2eOrQhDG0p/U
         AjkL1WRl6QmMh5QFHHO2819KgTZVDSXWMq/q0aa/Y9XgSZrcvg6oDuaWLKHQ6lVfcW++
         8+7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=gSMQiU+kiW0ZdwzapXzDhrAjOUSGj0q8ziCgqh5aMvg=;
        b=qP9qPWgwoNY0T/aWeBeteOaE2fZmvYra62CxSDORRArGI5sWQBXwzVdF7UxXlCuYu4
         oyHcKvi5l08aao1a6b2ndH2ZEFas63tAXNe5hPAxfidoYEYiBY32cWvlRmqNEz/fj7PU
         HYJoMRuRiIWNVFPPx3Hmb17zA0kObLj9SueLjqUosCXvmB8GT3xl0ITyqHoY7+cptQOd
         7BclVccKEt+DVXd6c/ec7OXQrF1Cx7YBBFjfedMabqplktbRXg+0Na+EhDcGDblAToRj
         E0ZG6puOYY2wqLasHoWasZyPjX7zNExRrprYVVa+c20gi1DPDJTYsS+i25AQU4cfMxhj
         jUlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh header.b=U2a6adpv;
       dkim=pass header.i=@amazonses.com header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=w3TSU0k7;
       spf=pass (google.com: domain of 01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683591530; x=1686183530;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gSMQiU+kiW0ZdwzapXzDhrAjOUSGj0q8ziCgqh5aMvg=;
        b=EHA/ohKmcpgyUdT1hWIW7LMM6lWuMi4kP52DdgJd5tC4v5pIQxL1opAUd+gPxuNol6
         x/LRLigYRxaJKU/5g0EHV5JiHu024nkvW+H/R+ulftDrULBAAPcTYPtF3NCjrU1hG9/G
         ky5S2kM/kt9/1Fx9foNl2xBK0JqnMR3RCGHJOx4EoInfnnParkH5DXuu9Uyj9CcHh3Me
         td47GEfhiKgB0FGDs80arTPt5VzTnsmVxCSwcfC30TZxlUVrNb8gCzxyd2+HgSZgrgkd
         NboYmFCSLUnFkiD28vSClwgxioyC0f5sLfOaRKcNr3azu/YKTNGQ0u8ywlbZuBAuT065
         yrcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683591530; x=1686183530;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gSMQiU+kiW0ZdwzapXzDhrAjOUSGj0q8ziCgqh5aMvg=;
        b=fXEw2bsMPFzLLf0s6PHNBvNfqQ4b3r5eXyrGymZP6RcEhqciENH/Czi4RBtwroFCXk
         5aqYpYq0EBFlruLTurnFFy3sOufDsmhfftsomMELI2tgglma4TmFvvM2eI4PJLk49DGB
         X1mKA7pjHZ+HtdnS0C/X4v7kGJU30QL8HqI60uyWfBjpEAOb02uH1WmzJqawNhchVbTx
         MbFNroMmHhIsNH/W6HrTmq/mRzoD8x0x5+jet62DZ57lTnICJDhGm3VnjTJSGkUZf68s
         6WFaoOpkChTvXnY8RF5olTMv7lUk0/s5fraeCot57/t5PnTtEXwcysOPhskkRU31s/YP
         IkCw==
X-Gm-Message-State: AC+VfDwjPipKc7QcvZxf/sR9Ye1pYpKL1lcnuNMbkn945RIu5nyosBbW
	AvYS2W0ukdYuk84YhzLFByQ=
X-Google-Smtp-Source: ACHHUZ44pVPS8FQDO0z4uuZD2bxg9rQKMYqPmjn5dYVgTDRe/0zU9SCZYWX2N8YBZgdTbJsqH20MBA==
X-Received: by 2002:ac2:4d06:0:b0:4f2:4d32:236c with SMTP id r6-20020ac24d06000000b004f24d32236cmr217014lfi.1.1683591529787;
        Mon, 08 May 2023 17:18:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a803:0:b0:2a8:a9ee:a216 with SMTP id l3-20020a2ea803000000b002a8a9eea216ls149997ljq.1.-pod-prod-04-eu;
 Mon, 08 May 2023 17:18:48 -0700 (PDT)
X-Received: by 2002:a2e:7e0e:0:b0:2ac:a011:b91d with SMTP id z14-20020a2e7e0e000000b002aca011b91dmr183555ljc.20.1683591528297;
        Mon, 08 May 2023 17:18:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683591528; cv=none;
        d=google.com; s=arc-20160816;
        b=0FI3gkExakusykC2yq0kB8DNrqCY8JGnrs39m+vE7U01r2ZeSzPMehY4RPdr+FJ9L0
         N9N654fTYHD76wKNpEZ+wPcDflkAWk9NwKZTUvVJMDdSa9FbB2UU0fzoF+E8Jav9kC+A
         RdLEbSToPTghsfFEAHwBTfn7Na/RnBuwrWPfj4Dg1O88mne1ibVs/JZ6m3qmsodjKKFd
         i/Xi5plW/D6i/qU7yCp/9/IhogTEKJM4/CdME1po5alkztjXBF2/WJ8H+2J9/jB4KkCX
         dqx86lWWv6S+EWN61a++A+HNMegih5AYiLcnTH42V3cyZZi5/x0qHixjoH1q5lAndYK2
         W7wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=MLJFlvb0B8F2v4mRUVC5AHlb0xSn38edw+I0y36lZ4w=;
        b=OfQi9BGAcfL6/jFsHKmnEXgnLPN5Z8Get4QameC1vZ/0hojHGzX7650YDcwG98Ib4r
         LM1Up4IWjKE2X+lVahGobxEySlQe32unvi2ZlfXlouga2kF4xuP1xadESAg0omPVQQ4G
         keV7oy9Zhl8vBsWuiFwMPqdRL4Xt7RKH0pAKUF2qFwR76l1/no4uVGf/nIXBMn97Qv5Z
         XyoWPpBn/zpyimVNy7T6zvXA4W/B9Cm4LydEZiRBtGBw4KbNZd7I93kpwF/RnDZTVui5
         lpFSRnwEI6QNWsLbvB3gbxbs1IUlD0hYtT91U747fJUFs31rAKngZ2SdqHM1DKH+t7KX
         nl4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh header.b=U2a6adpv;
       dkim=pass header.i=@amazonses.com header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=w3TSU0k7;
       spf=pass (google.com: domain of 01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-75.smtp-out.eu-west-1.amazonses.com (b231-75.smtp-out.eu-west-1.amazonses.com. [69.169.231.75])
        by gmr-mx.google.com with ESMTPS id h5-20020a2ebc85000000b002ac885a8f29si535855ljf.3.2023.05.08.17.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 May 2023 17:18:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) client-ip=69.169.231.75;
Date: Tue, 9 May 2023 00:18:47 +0000
To: kasan-dev@googlegroups.com
From: =?UTF-8?B?J0bDs3J1bSBYWEknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
Reply-To: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2023@forumxxi.net>
Subject: =?UTF-8?Q?Ampliaci=C3=B3n_de_fechas/Call_for_papers/Chiamata/Chamada/Appel_?=
 =?UTF-8?Q?Congreso_CUICIID_2023_(no_presencial)_organizado_por_la_editorial?=
 =?UTF-8?Q?_PETER_LANG_y_F=C3=B3rum_XXI?=
Message-ID: <01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: 7IDPQHOlinW1IcpVQg763WuQ
X-FBL: 7IDPQHOlinW1IcpVQg763WuQ-7892qhiZJ9KvgCIS2cDtvvmQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_muFnkCdzxYOUkefYDUnvdLU6hIEDUPCzRgplr8w6GI"
Feedback-ID: 1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2023.05.09-69.169.231.75
X-Original-Sender: cuiciid2023=forumxxi.net@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh
 header.b=U2a6adpv;       dkim=pass header.i=@amazonses.com
 header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=w3TSU0k7;       spf=pass
 (google.com: domain of 01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com
 designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
X-Original-From: =?UTF-8?Q?F=C3=B3rum_XXI?= <cuiciid2023=forumxxi.net@crlsrv.com>
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
--b1_muFnkCdzxYOUkefYDUnvdLU6hIEDUPCzRgplr8w6GI
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3D7IDPQHOlinW1I=
cpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ]=20
=20
=20
=20
 [https://www.email-index.com/click.php?L=3DMysPl4SPbgXypSaWgyVrbw&J=3D7IDP=
QHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAwNZwARmi9SVnjlQz=
w]=20
=20
 Congreso Internacional CUICIID 2023
=20
=20
=20
=20
 Estimados colegas, caros colegas, chers coll=C3=A8gues, cari colleghi, dea=
r colleagues:=20
Se ha ampliado la fecha para el env=C3=ADo de RES=C3=9AMENES hasta el 16 de=
 mayo.
XIII Congreso VIRTUAL y EN L=C3=8DNEA (no presencial) CUICIID 2023 (Congres=
o Universitario Internacional sobre Contenidos, Investigaci=C3=B3n, Innovac=
i=C3=B3n y Docencia) www.cuiciid.net.Los idiomas oficiales son: espa=C3=B1o=
l, portugu=C3=A9s, italiano, ingl=C3=A9s y franc=C3=A9s y se podr=C3=A1n pr=
esentar 3 ponencias por autor (individualmente o en coautor=C3=ADa) publica=
bles en 2024. Este a=C3=B1o se desarrolla en colaboraci=C3=B3n entre la pre=
stigiosa Editorial Suiza PETER LANG indizada en Primer Cuartil (Q-1) del =
=C3=ADndice SPI (https://www.email-index.com/click.php?L=3DBK1bhcHJ7Vt9pZ95=
1laIEQ&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAw=
NZwARmi9SVnjlQzw) y F=C3=B3rum XXI.CUICIID 2023 destaca por su vocaci=C3=B3=
n internacional y su amplia visibilizaci=C3=B3n ya que sus resultados curri=
culares (tras revisi=C3=B3n por dobles pares ciegos) ser=C3=A1n publicados =
en:
	Ponencia completa como cap=C3=ADtulo en libro de papel y electr=C3=B3nico =
de la editorial suiza PETER LANG (Q-1 en SPI).	Libro de Actas con los Res=
=C3=BAmenes con ISBN, lo que conlleva certificado de ponente-asistente.Fech=
as clave:
	16 de mayo (lunes). Cierre de env=C3=ADo de Res=C3=BAmenes (1 p=C3=A1gina)=
 (pesta=C3=B1a =E2=80=98ENV=C3=8DOS').	30 de mayo (lunes). Fecha tope para =
el env=C3=ADo de informes de aceptaci=C3=B3n o denegaci=C3=B3n tras revisi=
=C3=B3n por pares ciegos.	5 de junio (lunes). Cierre de matriculaci=C3=B3n =
(215 =E2=82=AC por cada autor y por cada ponencia, m=C3=A1ximo 3 ponencias)=
.Se puede fraccionar el pago en 4 mensualidades de 65 + 50 + 50 + 50 =E2=82=
=AC.	3 de julio (lunes). Env=C3=ADo de ponencias-cap=C3=ADtulos de 14 p=C3=
=A1ginas m=C3=A1ximo (pesta=C3=B1a =E2=80=98ENV=C3=8DOS') que se publicar=
=C3=A1n en libros de papel de PETER LANG (Q-1 de SPI).	28 de julio (lunes).=
 Voluntario. Env=C3=ADo de v=C3=ADdeos (.mov, .mp4 o .mpeg) para la defensa=
 grabada.	11 de septiembre (lunes). Voluntario. Solicitud de defensa en dir=
ecto.	4, 5 y 6 de octubre (mi=C3=A9rcoles, jueves y viernes). Celebraci=C3=
=B3n del Congreso (virtual y en l=C3=ADnea, no presencial).Compuesto por 6 =
=C3=81reas tem=C3=A1ticas:=20
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
.	Investigaci=C3=B3n: Nuevos proyectos, Investigaciones I+D+i, Art=C3=ADcul=
os 83, Investigaciones no regladas, Ingenier=C3=ADas, Criterios de evaluaci=
=C3=B3n, Inteligencia Artificial, ChatGPT, Dall-e.	Miscel=C3=A1nea: =C3=81r=
ea abierta a contribuciones transversales.	Paneles tem=C3=A1ticos: Propuest=
os por autores (m=C3=ADnimo 4 ponencias por panel). Ideal para Grupos de In=
vestigaci=C3=B3n.=20
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
ail-index.com/click.php?L=3DToRqTagQde0JOemMZWxXrQ&J=3D7IDPQHOlinW1IcpVQg76=
3WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAwNZwARmi9SVnjlQzw] y en nuestro =
correo: cuiciid2023@forumxxi.net [mailto:cuiciid2021@forumxxi.net]
 Reciban mi m=C3=A1s cordial saludo. David Caldevilla Dom=C3=ADnguezUnivers=
idad ComplutenseDirector del Congreso CUICIID 2023
=20
 [https://www.email-index.com/click.php?L=3Dl8r7m763x6zAASff5gYvIxlQ&J=3D7I=
DPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAwNZwARmi9SVnjl=
Qzw] [https://www.email-index.com/click.php?L=3Db8DPVKgUZ2YrL7400rOscg&J=3D=
7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAwNZwARmi9SVn=
jlQzw] [https://www.email-index.com/click.php?L=3DTHiIJPPZa5lcu5veCe7jcA&J=
=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DdybgAwNZwARmi9=
SVnjlQzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ] | Actualizar mis =
datos [https://www.email-index.com/update.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&=
C=3D7892qhiZJ9KvgCIS2cDtvvmQ] F=C3=93RUM XXI - Cine n=C2=BA 38. Bajo derech=
a, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-000000%40eu=
-west-1.amazonses.com.

--b1_muFnkCdzxYOUkefYDUnvdLU6hIEDUPCzRgplr8w6GI
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&=
C=3D7892qhiZJ9KvgCIS2cDtvvmQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3D7IDPQHOlinW1IcpVQg76=
3WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=
=3D7892qhiZJ9KvgCIS2cDtvvmQ');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892q=
hiZJ9KvgCIS2cDtvvmQ');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892=
qhiZJ9KvgCIS2cDtvvmQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3D7I=
DPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ');}}</style>
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
ader1">Env&iacute;o de res&uacute;menes ampliado: 16 de mayo de 2023 Congre=
so CUICIID 2023</span><div style=3D"display:none;max-height:0px;overflow:hi=
dden;">&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&n=
bsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp=
;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#=
847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847=
;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&z=
wnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj=
;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&n=
bsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp=
;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#=
847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847=
;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&z=
wnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj=
;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&n=
bsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp=
;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#=
847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847=
;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&z=
wnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj=
;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&n=
bsp;</div><table height=3D"" bgcolor=3D" #fdfbfc" width=3D"100%" cellpaddin=
g=3D"0" cellspacing=3D"0" align=3D"center" class=3D"ui-sortable" style=3D"b=
ackground-color: rgb(253, 251, 252); border-width: initial; border-style: n=
one; border-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0=
px;">
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
-index.com/view.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvv=
mQ" style=3D"text-decoration: underline; color:#333;"><span>Ver en navegado=
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3Dn1WQ400SOSCnG=
LangdT89g&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DHKF=
RcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=
=3D""><img align=3D"absbottom" border=3D"0" id=3D"Imgfull" width=3D"280" sr=
c=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZ=
Iqw/LOGO-CUICIID-ROJOSA-1.png?1680607686177" alt=3D"CUICIID" style=3D"width=
: 280px; max-width: 280px; text-align: center; font-size: 18px; color: rgb(=
255, 255, 255); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; tex=
t-transform: uppercase;" class=3D"acre_image_editable"></a></td>
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
rong></span><span style=3D"color:#ff00cc"><strong>CUICIID 2023</strong></sp=
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
<span style=3D"font-size:14px"><span style=3D"color:#000000">Estimados cole=
gas, caros colegas, chers coll&egrave;gues, cari colleghi, dear colleagues:=
</span></span><br>
&nbsp;</div>

<div style=3D"line-height: 20px;">
<span style=3D"font-size:14px"><span style=3D"color:#FF0000"><strong>Se ha&=
nbsp;ampliado la fecha&nbsp;</strong></span></span><strong style=3D"color:r=
gb(255, 0, 0); font-size:14px">para el&nbsp;env&iacute;o de RES&Uacute;MENE=
S&nbsp;</strong><strong style=3D"color:rgb(255, 0, 0); font-size:14px">hast=
a el 16 de mayo.</strong>
</div>

<div style=3D"line-height: 20px;">
<span style=3D"font-size:14px"><span style=3D"color:#000000"><strong>XIII C=
ongreso VIRTUAL</strong> y </span><strong><span style=3D"color:#000000">EN =
L&Iacute;NEA (no presencial)</span> <span style=3D"color:#ff33cc">CUICIID 2=
023</span></strong> <span style=3D"color:#000000">(Congreso Universitario I=
nternacional sobre Contenidos, Investigaci&oacute;n, Innovaci&oacute;n y Do=
cencia) </span><span style=3D"color:#0000FF"><u>www.cuiciid.net</u></span><=
span style=3D"color:#000000">.</span></span><br>
<br>
<span style=3D"color:#000000">Los <strong>idiomas oficiales</strong> son: <=
strong>espa&ntilde;ol, portugu&eacute;s, italiano, ingl&eacute;s y franc&ea=
cute;s</strong> y se podr&aacute;n presentar 3 ponencias por autor (individ=
ualmente o en coautor&iacute;a) publicables en 2024.<br>
&nbsp;<br>
Este a&ntilde;o se desarrolla en colaboraci&oacute;n entre la <strong>prest=
igiosa Editorial Suiza PETER LANG</strong> indizada en <strong>Primer Cuart=
il (Q-1) del &iacute;ndice SPI</strong></span> (<span style=3D"color:#0000F=
F"><u>https://spi.csic.es/indicadores/prestigio-editorial/2022-clasificacio=
n-general</u></span>) <span style=3D"color:#000000">y <strong>F&oacute;rum =
XXI</strong>.</span><br>
<br>
<span style=3D"color:#ff33cc"><span style=3D"font-size:14px"><strong>CUICII=
D 2023</strong></span></span><span style=3D"color:rgb(0, 0, 0); font-size:1=
4px"> </span><span style=3D"color:#000000"><span style=3D"font-size:14px">d=
</span><span style=3D"font-size:14px">estaca por su vocaci&oacute;n interna=
cional y su amplia <strong>visibilizaci&oacute;n</strong> ya que sus <stron=
g>resultados curriculares </strong>(<strong>tras revisi&oacute;n por dobles=
 pares ciegos</strong>) ser&aacute;n publicados en:</span></span>
</div>

<ul>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px">Ponencia completa como cap&iacute;tulo en libro de pape=
l y electr&oacute;nico de la <strong>editorial suiza&nbsp;PETER LANG</stron=
g>&nbsp;(<strong>Q-1 en SPI</strong>).</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px">Libro de Actas con los Res&uacute;menes con ISBN, lo qu=
e conlleva certificado de ponente-asistente.</span></span></li>
</ul>

<div style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>Fechas clave:</strong></span></span></div>

<ul>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>16 de mayo -AMPLIADO-</strong> (martes). Cierre=
 de env&iacute;o de Res&uacute;menes (1 p&aacute;gina) (pesta&ntilde;a &lsq=
uo;ENV&Iacute;OS').</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>30 de mayo</strong> (lunes). Fecha tope para el=
 env&iacute;o de informes de aceptaci&oacute;n o denegaci&oacute;n tras rev=
isi&oacute;n por pares ciegos.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>5 de junio</strong> (lunes). Cierre de matricul=
aci&oacute;n (215&nbsp;&euro; por cada autor y por cada ponencia, m&aacute;=
ximo 3&nbsp;ponencias).Se puede fraccionar el pago en 4 mensualidades de 65=
 + 50 + 50 + 50 &euro;.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>3 de julio</strong> (lunes). Env&iacute;o de po=
nencias-cap&iacute;tulos&nbsp;de 14 p&aacute;ginas m&aacute;ximo (pesta&nti=
lde;a &lsquo;ENV&Iacute;OS') que se publicar&aacute;n en libros de papel de=
 <strong>PETER LANG</strong> (<strong>Q-1 de SPI</strong>).</span></span></=
li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>28 de julio</strong> (lunes).&nbsp;<strong>Volu=
ntario</strong>. Env&iacute;o de <strong>v&iacute;deos</strong> (.mov, .mp4=
 o .mpeg) para la defensa grabada.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"color:#000000"><span style=
=3D"font-size:14px"><strong>11 de septiembre </strong>(lunes).&nbsp;<strong=
>Voluntario</strong>. Solicitud de <strong>defensa en directo</strong>.</sp=
an></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>4, 5 y 6 de octubre</strong> (mi&eacute;rcoles,=
&nbsp;jueves y viernes). Celebraci&oacute;n del Congreso (virtual y en l&ia=
cute;nea, no presencial).</span></span></li>
</ul>

<div style=3D"line-height: 20px;">
<span style=3D"font-size:14px"><span style=3D"color:#000000">Compuesto por =
<strong>6 &Aacute;reas tem&aacute;ticas</strong>:</span></span><br>
&nbsp;</div>

<ul>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Comunicaci&oacute;n: </strong>Comunicaci&oacute=
;n persuasiva, Alfabetizaci&oacute;n medi&aacute;tica, Marketing digital, N=
euromarketing, Publicidad, Relaciones P&uacute;blicas, Periodismo, Protocol=
o, Lo audiovisual, Comunicaci&oacute;n legal y m&eacute;dica, Crisis de la =
COVID-19.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Docencia: </strong>Nueva metodolog&iacute;as, T=
IC, STEAM, F&oacute;rmulas y contenidos docentes, Pol&iacute;ticas educativ=
as, el EEES, la LOSU, pol&iacute;ticas educativas.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Ciencias Sociales y Humanismo: </strong>Turismo=
, G&eacute;nero, Antropolog&iacute;a, Cultura, Derecho, Patrimonio, Ling&uu=
ml;&iacute;stica, Semi&oacute;tica, Historia, Religi&oacute;n, Filosof&iacu=
te;a, G&eacute;nero, Psicolog&iacute;a, Sociolog&iacute;a, Sociedad, Agenda=
 2030, ODS.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Innovaci&oacute;n: </strong>Tem&aacute;ticas em=
ergentes, Redes Sociales, Meta, Los nuevos trabajos doctorales, Contenidos =
acad&eacute;micos actuales, Emprendimiento.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Investigaci&oacute;n: </strong>Nuevos proyectos=
, Investigaciones I+D+i, Art&iacute;culos 83, Investigaciones no regladas, =
Ingenier&iacute;as, Criterios de evaluaci&oacute;n, Inteligencia Artificial=
, ChatGPT, Dall-e.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Miscel&aacute;nea: </strong>&Aacute;rea abierta=
 a contribuciones transversales.</span></span></li>
	<li style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000"><strong>Paneles tem&aacute;ticos: </strong>Propuestos p=
or autores (m&iacute;nimo 4 ponencias por panel). Ideal para Grupos de Inve=
stigaci&oacute;n.</span></span></li>
</ul>

<div style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000">&nbsp;</span></span></div>

<div style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#ff33cc"><strong>CUICIID</strong></span><span style=3D"color:#00=
0000"><strong> </strong>es el espacio id&oacute;neo para la visibilizaci&oa=
cute;n de trabajos de <strong>doctorandos</strong> e <strong>investigadores=
</strong> de nuevo cu&ntilde;o en los &aacute;mbitos acad&eacute;micos de m=
ayor relevancia y es enmarcable dentro de los Congresos de mayor impacto, l=
os ubicados bajo el concepto &lsquo;<strong>Congresos de Calidad de la form=
aci&oacute;n docente</strong>&rsquo;, por aunar la <strong>innovaci&oacute;=
n</strong> y la <strong>docencia</strong> y, merced a la <strong>revisi&oac=
ute;n por dobles pares ciegos</strong> de los trabajos presentados, sus res=
ultados tienen un alto valor curricular.</span></span></div>

<div style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000">&nbsp;<br>
Como &uacute;ltimo punto de inter&eacute;s, </span><span style=3D"color:#ff=
33cc"><strong>CUICIID</strong></span><span style=3D"color:#000000"><strong>=
 </strong>quiere focalizar sus esfuerzos en animar a los <strong>Grupos y E=
quipos de Investigaci&oacute;n</strong> que desean visibilizar sus resultad=
os investigadores en publicaciones de primer nivel.<br>
&nbsp;<br>
Para cualquier duda, los emplazamos en la web:</span> <u><a href=3D"https:/=
/www.email-index.com/click.php?L=3Dxx3oRYUe7U2M0mJFyWHyFA&J=3D7IDPQHOlinW1I=
cpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DHKFRcCbcnmxmc4f43DJP5g">www.cu=
iciid.net</a></u><span style=3D"color:#000000"> y en nuestro correo: </span=
><u><a href=3D"mailto:cuiciid2021@forumxxi.net">cuiciid2023@forumxxi.net</a=
></u></span></div>

<div style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000">&nbsp;</span></span></div>

<div style=3D"line-height: 20px;"><span style=3D"font-size:14px"><span styl=
e=3D"color:#000000">&nbsp;<br>
&nbsp;<br>
Reciban mi m&aacute;s cordial saludo.<br>
&nbsp;<br>
<strong>David Caldevilla Dom&iacute;nguez</strong><br>
Universidad Complutense<br>
<strong>Director del Congreso </strong></span><span style=3D"color:#ff33cc"=
><strong>CUICIID 2023</strong></span></span></div>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dgc=
HWiBG763tNOIzc8HiJAmKg&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cD=
tvvmQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: b=
lock;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"=
38" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; displ=
ay: block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); =
font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upp=
ercase;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-facebook=
-38.jpg" alt=3D"facebook CUICIID" class=3D"acre_image_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DGP=
HPryrMeLU2BG4QSumc0A&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtv=
vmQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
ck;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38=
" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display=
: block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); fo=
nt-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upper=
case;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twitter-38=
.jpg" alt=3D"twitter CUICIID" class=3D"acre_image_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DWt=
VUWh763Vs27An0Bhl07s6g&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cD=
tvvmQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: b=
lock;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"=
38" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; displ=
ay: block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); =
font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upp=
ercase;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-linkedin=
-38.jpg" alt=3D"linkedin CUICIID" class=3D"acre_image_editable"></a></td>
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
com/unsubscribe.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvv=
mQ" style=3D"text-decoration: underline; color:#333;"><span>Darme de baja d=
e esta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ" s=
tyle=3D"text-decoration: underline; color:#333;"><span>Actualizar mis datos=
</span></a>
                                        <br><br>
                                      <span>F&Oacute;RUM XXI - Cine n&ordm;=
 38. Bajo derecha, 28024, Madrid</span>
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
"><a href=3D"https://www.email-index.com/click.php?L=3DU8PJ9p4Hs25dcHTWM763=
qk892Q&J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ&F=3DHKFRcC=
bcnmxmc4f43DJP5g"><img alt=3D"" border=3D"0" style=3D"border-style:none" sr=
c=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZ=
Iqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3D7IDPQHOlinW1IcpVQg763WuQ&C=3D7892qhiZJ9KvgCIS2cDtvvmQ" alt=
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
om/d/msgid/kasan-dev/01020187fddffb4b-26f3bbf5-85bd-4c81-ab70-8b9961eec86a-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/01020187fddffb4b-26f3bbf5-85bd-4c=
81-ab70-8b9961eec86a-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_muFnkCdzxYOUkefYDUnvdLU6hIEDUPCzRgplr8w6GI--

