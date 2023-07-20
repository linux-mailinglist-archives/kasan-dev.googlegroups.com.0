Return-Path: <kasan-dev+bncBDLJXDHV7QBRBLFK4WSQMGQESWHQOXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 040B575B317
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 17:39:26 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2b70c44b5fdsf9759181fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 08:39:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689867565; cv=pass;
        d=google.com; s=arc-20160816;
        b=QbSDTLGAQVKbmS4c0oBS0Tzv3etqLofrl2bQnJWIVK2Re3BTVYZr1qRbptb168AMY+
         b1p12yRlmH2dCuTGsYeivp0bfPUqZWrdunDKYzEjuV74fMgGsUy68FhFE19L6XBTuTS6
         mNfJpwYN6yQW6+EDIeOljJNhcvhwZ8y+XK4MOt3IOrEklgutbonZ5QT5vliYTfohZZRy
         a1EcDAsC9ciUyApyCEYBtxydfZCJ+KM4njh9O8yXf660P0qXI2+JPxB6iENyV59H93WS
         ki5hSKiYoVv6qAW7cqJrjFpOzl3CJ7PAB/Dy+HsiqOxZiSC+xiFr68c37h4sO5lsrDlT
         nNow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=I+HuX0vzMjcBJlv9cun8SlcuTuEMA//dbx9MpYrJd8Y=;
        fh=2Zu8tQ6GDl5kigKM+7l+auKpJZ5v2uFJaWqjMIS4Owg=;
        b=m1tMHksmQNrGB7JJ0/HkjCsy0Rn+cACMHNgMy8fsNl3lX9idaeqYzBs4z59p+502AB
         LVuS6FLN1+TZn/M2vkvJ5gIZU1xQhbyfBJWRgyr1OgWfEl4xTC2+JvTEl0kMMJypTlVK
         iL8L8AaU+bNkXSXEmkL7zQ4DP7jI+GjF74pDu2LMuLGw07MPOwyTx+U07GfkUkrxu3p8
         RtDcOAtYsp4RMcDrgYkV3+19pX8irYsFJhXWqSVxEMR2KTRBAEwFC10bE2TE3D6bBJD4
         4CZnFjp4DXp8udyareBFKoUBZjYQUR8aRYoRZxrELOco2NAsXRA4bW8zejUSx+2I4vbz
         owbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh header.b=J4Nad8XH;
       dkim=pass header.i=@amazonses.com header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=t1szQm6A;
       spf=pass (google.com: domain of 0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com designates 69.169.231.73 as permitted sender) smtp.mailfrom=0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689867565; x=1690472365;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I+HuX0vzMjcBJlv9cun8SlcuTuEMA//dbx9MpYrJd8Y=;
        b=B8NPYES4ddWTyQ68dmGx3uoemVD584J47gyEkwImAdDzCjpbht1trNRx3LxG1DADd2
         TPQg4P/bVsmXYyjksfEDWosG7GdIl9DbtGK5HaJd0otUK5VrD5hcKBPrcvhs81OnY3wX
         OLJiBhJYN5+ql6GpT5Q8y03lCH+TpwE8x0ti2oIiqRbf4U9nUcfCQvVs1C5/duaR8v1H
         Dpc7UpnDjPEtwqjjKomxzBhyIKPF6ZaRb0vjOHIvISXI2Ir66CoHfZFFuwP1PaM1H5dj
         MccmFJSN9td/FUKDAbUsUD6XIovf1EB3qKhoAZam2jdMOgqrg+e/aeo+xN4do1NftBB2
         U/NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689867565; x=1690472365;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I+HuX0vzMjcBJlv9cun8SlcuTuEMA//dbx9MpYrJd8Y=;
        b=SI6irfOk96vti4ojZPz+yacDBDnjoiNAbKqSRzExkiXhZVvJpcN9F3ylJ8NNLUq807
         Ftgny+K2iAxQHO7Bxj37/84f/wpyobVaty93Gd7o0ybZtrmsbPHR1Gt7a6BiL4Pxkudv
         O32wFaupO5zrzWLDwRLyt1YgB9RUp3DFk8oK5MfyJmviEWBL73PDDoWbG3QKFJ1hdcbC
         MTpy0ZfTSrdCfyt9CRciRGqjUPW6cuwAvDwG6G0H2nAqLBA6rpRNwn72E4uHio47Uj7F
         NSkrR7LfbJ+8lVURgF/huRH1q54aHfrbSh5NG75yTzANmwSnWzjfDBrD0la0Vx25iyVm
         LdtA==
X-Gm-Message-State: ABy/qLbZNaoCiw/21ofn3L1DaaThjSG6aTasVhjt2b8FT6Sj5y//KYF9
	LjkkF3HfwXsLr8OzqaM/Sj8=
X-Google-Smtp-Source: APBJJlHaYnUul4dT7z/4nNQmOOdmclOi/FN7FQNoCcom1EwevZpHOMWz8pwjh6b52yuakbuZQpesYg==
X-Received: by 2002:a2e:92c4:0:b0:2b9:581d:5c76 with SMTP id k4-20020a2e92c4000000b002b9581d5c76mr2133650ljh.24.1689867564422;
        Thu, 20 Jul 2023 08:39:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:60d:b0:2b9:47f5:1aba with SMTP id
 k13-20020a05651c060d00b002b947f51abals61232lje.1.-pod-prod-06-eu; Thu, 20 Jul
 2023 08:39:22 -0700 (PDT)
X-Received: by 2002:a2e:86c9:0:b0:2b6:fe67:1f97 with SMTP id n9-20020a2e86c9000000b002b6fe671f97mr2196325ljj.26.1689867562623;
        Thu, 20 Jul 2023 08:39:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689867562; cv=none;
        d=google.com; s=arc-20160816;
        b=BG8VsvgvvKLuYHjtM67PW0Pcm5Kh0Nne/Pad5hZebVPaOO/cKx+/Y+ZrwjBTFVgnHm
         w0hw9BVicQWSLSojKnRG+Hw4VTUyyP7J0gPK0CnUNJNp91dWq652S4sfktqDacZjx/+i
         JjVF+o5MRBiOY871WDHggPqL4YcSd7gouAwFLwP4b3ygSAXeG/4a6JxjIB1J3g3DZQa3
         7+7io+5zRwx8X/7slsYP2Pg2nS68xsRDD3jReLdAxK2SN8FaVpA8WvbZ0lInLTM9+Bct
         DaNGOOv/2SE/cXGK1qISYhJ/136nunOZp6HNF7kUQHvnrZoWIKFe2DHG5OQFStoamkZI
         HPrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=OhElJM2DvzOgM4Ecucgjt7xoNqzJ5ag5WZNf4Msk+j0=;
        fh=rcvPpCXIWH1R9tB4gm0H27tusrFxAj8TLnMaAqPlhf0=;
        b=klGmVxL1wowu00fL2uSzTOTwf62lnXD9W0UeuIWYAz908BrDflMDABNHXc3/Ssf0J+
         aD3FKwtVSS8xaaLBjrl0UWQgzO3TkrdQiar0hPayyle9F88zSYGk+VnT5oNx9XsN9Hnz
         xaSgx+UI4XzPdzMaU8VQwiGnTf7HkpYu+RXbFbwtwwEUmkr4q6KMkEWt0StgnzBEyB8+
         KDXfsXctN4+FVl+MWV+OxGZGvqZIMYFrJq0NnJx7e/eYKaM5E422vVfKxCb8IwIvEks2
         Qpvz5IVu/oK7zgbBv449KFObTBInZt3e3KEjXqoIJO3hDQZWHo5ujksDURu+wsHUv7zi
         1bRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh header.b=J4Nad8XH;
       dkim=pass header.i=@amazonses.com header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=t1szQm6A;
       spf=pass (google.com: domain of 0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com designates 69.169.231.73 as permitted sender) smtp.mailfrom=0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-73.smtp-out.eu-west-1.amazonses.com (b231-73.smtp-out.eu-west-1.amazonses.com. [69.169.231.73])
        by gmr-mx.google.com with ESMTPS id y3-20020a2ebb83000000b002b935cd67e9si78056lje.3.2023.07.20.08.39.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jul 2023 08:39:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com designates 69.169.231.73 as permitted sender) client-ip=69.169.231.73;
Date: Thu, 20 Jul 2023 15:39:21 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@hisin.org>
Subject: Convocatoria / Call for papers. Congreso LATINA (no presencial) con revista
 Latina SCOPUS Q1
Message-ID: <0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: wX1RMvOzyAfKs7639oasYgLA
X-FBL: wX1RMvOzyAfKs7639oasYgLA-v5xC763optCzAXRysMgAhF4Q
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_2SqriD93coZM5PtD60Sx091NWMTHJhXRiuvvMOR6YQ"
Feedback-ID: 1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2023.07.20-69.169.231.73
X-Original-Sender: congresolatina=hisin.org@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=jrt2xqh34kgxn26c7h3vz5kgqgg2otxh
 header.b=J4Nad8XH;       dkim=pass header.i=@amazonses.com
 header.s=shh3fegwg5fppqsuzphvschd53n6ihuv header.b=t1szQm6A;       spf=pass
 (google.com: domain of 0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com
 designates 69.169.231.73 as permitted sender) smtp.mailfrom=0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000@email.crlsrv.com;
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
--b1_2SqriD93coZM5PtD60Sx091NWMTHJhXRiuvvMOR6YQ
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DwX1RMvOzyAfKs=
7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q]=20
=20
=20
=20
 Congreso Internacional LATINA DE COMUNICACI=C3=93N SOCIAL 2023
=20
=20
 [https://www.email-index.com/click.php?L=3DrsTXMc4pWLYnzFJDdWLZkw&J=3DwX1R=
MvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVnjlQz=
w]=20
=20
=20
=20
 Estimad@s amig@s y colegas:Estamos muy ilusionad@s con el lanzamiento del =
XV CONGRESO INTERNACIONAL LATINA DE COMUNICACI=C3=93N SOCIAL 2023 (CILCS) q=
ue se celebrar=C3=A1 los pr=C3=B3ximos d=C3=ADas 22, 23 y 24 de noviembre e=
n modalidad online www.congresolatina.netLos idiomas del congreso son: espa=
=C3=B1ol, italiano, portugu=C3=A9s, ingl=C3=A9s y franc=C3=A9s.Los espacios=
 de trabajo propuestos son actuales, interesantes e imprescindibles en una =
sociedad que cambia cada d=C3=ADa y cada vez a mayor velocidad. EDUCACI=C3=
=93N, TURISMO, DEPORTE, POL=C3=8DTICA, MARKETING, PUBLICIDAD, INTELIGENCIA =
ARTIFICIAL=E2=80=A6 Siempre vinculados a la Comunicaci=C3=B3n.Espacios tem=
=C3=A1ticos: (https://www.email-index.com/click.php?L=3DAeAOqvs8v9aXAzpyhpW=
CJw&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZw=
ARmi9SVnjlQzw)
	Educando en comunicaci=C3=B3n	Comunicaci=C3=B3n digital	Nuevas tendencias =
e investigaci=C3=B3n en la comunicaci=C3=B3n	Comunicaci=C3=B3n persuasiva	C=
omunicaci=C3=B3n empresarial	Comunicaci=C3=B3n especializada	L=C3=ADmites d=
e la comunicaci=C3=B3n	Ense=C3=B1anza de la comunicaci=C3=B3n	Propuestas de=
 comunicaciones libres	PanelesCurricularmente CILCS presenta:
	Libro de Actas con ISBN (res=C3=BAmenes aceptados tras revisi=C3=B3n por p=
ares ciegos)y, adem=C3=A1s, da a elegir entre cinco posibilidades de public=
aci=C3=B3n:=20
	Libro de papel con versi=C3=B3n electr=C3=B3nica de la editorial MARCIAL P=
ONS (Q1 =C3=ADndice SPI General). Compuesto por los textos aceptados tras r=
evisi=C3=B3n de mejora mediante dobles pares ciegos por parte del Comit=C3=
=A9 Evaluador del Congreso.	Revista Latina de Comunicaci=C3=B3n Social -RLC=
S- (Scopus Q-1 y SJR Q-1). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en =
2024 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	PASOS, Re=
vista de Turismo y Patrimonio Cultural (Scopus Q-2 y SJR Q-2, Sello FECYT y=
 ESCI). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2024 tras ser acept=
ados por el Comit=C3=A9 Editorial de la misma.	Revista Methaodos, Revista d=
e Ciencias Sociales (Sello FECYT, Dialnet M=C3=A9tricas C1 y ESCI). Se publ=
icar=C3=A1 un m=C3=A1ximo de 6 textos tras ser aceptados por el Comit=C3=A9=
 Editorial de la misma.	Revista Ciencia y Deporte (SciELO). Se publicar=C3=
=A1 un m=C3=A1ximo de 6 textos tras ser aceptados por el Comit=C3=A9 Editor=
ial de la misma.Se podr=C3=A1 participar enviando un v=C3=ADdeo (emitido el=
 22 de noviembre) o en directo a trav=C3=A9s de zoom (23 o 24 de noviembre)
Fechas clave:=20
Env=C3=ADo de resumen obligatorio
Hasta el 15 de septiembre
Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n:
Desde el 29 de septiembre
Abono de matr=C3=ADcula: (180 =E2=82=AC por cada firmante y por cada ponenc=
ia)
Hasta el 20 de octubre
Env=C3=ADo de ponencia completa
Hasta el 27 de octubre
Env=C3=ADo de V=C3=ADdeo para ser emitido el 22 de noviembre o env=C3=ADo d=
e correo electr=C3=B3nico informando que desea defender la ponencia en dire=
cto el 23 o 24 de noviembre.
Hasta el 5 de noviembre
Celebraci=C3=B3n (online):
22, 23 y 24 de noviembre
M=C3=A1s informaci=C3=B3n en: www.congresolatina.net 2023congresolatina@his=
in. org
Tel=C3=A9fono y WhatsApp (+34) 663 965 312Un abrazo y =C2=A1=C2=A1SEGUIMOS =
COMUNICANDO!!Comit=C3=A9 Organizador XV Congreso CILCS
=20
 [https://www.email-index.com/click.php?L=3Dx763AFNhHOHKXOK892a3LB1sXQ&J=3D=
wX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi9SVn=
jlQzw] [https://www.email-index.com/click.php?L=3Deb892AC2p6nBW0dgN8d505mA&=
J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwARmi=
9SVnjlQzw] [https://www.email-index.com/click.php?L=3DRf8j76ktLaC5oU846jk4p=
A&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DdybgAwNZwAR=
mi9SVnjlQzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q] | Actualizar mis =
datos [https://www.email-index.com/update.php?J=3DwX1RMvOzyAfKs7639oasYgLA&=
C=3Dv5xC763optCzAXRysMgAhF4Q] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine =
n=C2=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-000000%40eu=
-west-1.amazonses.com.

--b1_2SqriD93coZM5PtD60Sx091NWMTHJhXRiuvvMOR6YQ
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DwX1RMvOzyAfKs7639oasYgLA&=
C=3Dv5xC763optCzAXRysMgAhF4Q');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DwX1RMvOzyAfKs7639oas=
YgLA&C=3Dv5xC763optCzAXRysMgAhF4Q');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=
=3Dv5xC763optCzAXRysMgAhF4Q');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC7=
63optCzAXRysMgAhF4Q');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC=
763optCzAXRysMgAhF4Q');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DwX=
1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q');}}</style>
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
ader1">XV Congreso LATINA 2023 (res&uacute;menes hasta 15/09/2023) organiza=
do por editorial TECNOS e HISIN</span><div style=3D"display:none;max-height=
:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbs=
p;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&=
#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#84=
7;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&=
zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwn=
j;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&=
nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbs=
p;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&=
#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#84=
7;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&=
zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwn=
j;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&=
nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbs=
p;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;<=
/div><table height=3D"" bgcolor=3D" #fdfbfc" width=3D"100%" cellpadding=3D"=
0" cellspacing=3D"0" align=3D"center" class=3D"ui-sortable" style=3D"backgr=
ound-color: rgb(253, 251, 252); border-width: initial; border-style: none; =
border-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;">
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
-index.com/view.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF=
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
 252); height: 20px;" class=3D"" height=3D"20">
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
ize:16px"><span style=3D"color:#000000"><strong>Congreso Internacional</str=
ong></span><span style=3D"color:#0000FF"><strong> </strong></span><strong><=
span style=3D"color:#003366">LATINA DE COMUNICACI&Oacute;N SOCIAL</span><sp=
an style=3D"color:#FF8C00"><strong> </strong></span>2023</strong></span></d=
iv>
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
</tr><tr class=3D"block_logo" style=3D"display: table-row;">=20
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3Dyj892nEyQldwG=
xaUh44AI85w&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DH=
KFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" titl=
e=3D"Web del XIII CLCS"><img align=3D"absbottom" border=3D"0" id=3D"Imgfull=
" width=3D"280" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/f=
BxrW1jUkXDcz7BTAyZIqw/images/LOGO%20LATINA%2023%20Rectangular%20FONDO%20BLA=
NCO%20(1).png?1689445911358" alt=3D"XIII CILCS" style=3D"width: 280px; max-=
width: 280px; text-align: center; font-size: 18px; color: rgb(255, 255, 255=
); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: =
uppercase;" class=3D"acre_image_editable"></a></td>
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
</tr>
		<tr class=3D"block_texto">=20
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
<span style=3D"font-size:14px">Estimad@s amig@s y colegas:<br>
<br>
Estamos muy ilusionad@s con el lanzamiento&nbsp;del&nbsp;<strong><span styl=
e=3D"color:#003366">XV CONGRESO INTERNACIONAL LATINA DE COMUNICACI&Oacute;N=
 SOCIAL 2023 (</span><span style=3D"color:#FFA500">CILCS</span><span style=
=3D"color:#003366">)</span> </strong>que se celebrar&aacute; los pr&oacute;=
ximos d&iacute;as 22, 23 y 24 de noviembre en modalidad <strong>online</str=
ong>&nbsp;<u><span style=3D"color:#0000CD">www.congresolatina.net</span></u=
><br>
<br>
Los idiomas del congreso son: <span style=3D"color:#000000"><strong>espa&nt=
ilde;ol, italiano, portugu&eacute;s, ingl&eacute;s </strong>y<strong> franc=
&eacute;s</strong></span>.<br>
<br>
<span style=3D"color:#000000"><strong>Los&nbsp;espacios de trabajo</strong>=
</span>&nbsp;propuestos son actuales, interesantes e imprescindibles en una=
 sociedad que cambia cada d&iacute;a y cada vez a mayor velocidad.&nbsp;EDU=
CACI&Oacute;N, TURISMO, DEPORTE, POL&Iacute;TICA, MARKETING, PUBLICIDAD, IN=
TELIGENCIA ARTIFICIAL&hellip; Siempre vinculados a la Comunicaci&oacute;n.<=
/span><br>
<br>
<span style=3D"font-size:14px"><span style=3D"color:#000000"><strong>Espaci=
os tem&aacute;ticos: </strong></span><span style=3D"color:#0000FF">(https:/=
/congresolatina.net/espacios-tematicos-2023/)</span></span>
</div>

<ol>
	<li style=3D"line-height: 20px; text-align: justify;">Educando en comunica=
ci&oacute;n</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Comunicaci&oacute;n digital</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Nuevas tendencias e investigaci&oacute;n en la comunicaci&oacute=
;n</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Comunicaci&oacute;n persuasiva</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Comunicaci&oacute;n empresarial</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Comunicaci&oacute;n especializada</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">L&iacute;mites de la comunicaci&oacute;n</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Ense&ntilde;anza de la comunicaci&oacute;n</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Propuestas de comunicaciones libres</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Paneles</span></li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#003366"><strong>Curricularmente&nbsp;CILCS=
 </strong></span>presenta:</span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000"><strong>Libro de Actas&nbsp;con ISBN</strong>=
&nbsp;</span>(res&uacute;menes aceptados tras&nbsp;revisi&oacute;n por pare=
s ciegos)</li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"font-size:14px">y, adem&aacute;s, da a elegir entre <span st=
yle=3D"color:#003366"><strong>cinco posibilidades de publicaci&oacute;n</st=
rong></span>:</span><br>
&nbsp;</div>

<ol style=3D"margin-left: 40px;">
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#000000"><strong>Libro de papel</strong> </=
span><span style=3D"color:rgb(0, 51, 102)">con versi&oacute;n electr&oacute=
;nica de la editorial<strong> </strong></span><span style=3D"color:#008000"=
><strong>MARCIAL PONS</strong></span><span style=3D"color:#00FF00">&nbsp;</=
span>(<span style=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;<span style=3D"c=
olor:rgb(0, 0, 205)"><u>&iacute;ndice SPI General</u></span>). Compuesto po=
r los&nbsp;textos aceptados tras&nbsp;revisi&oacute;n de mejora mediante do=
bles pares ciegos por parte del Comit&eacute; Evaluador del Congreso.</span=
></li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#B22222"><strong>Revista Latina de Comunicaci&oacute;n=
 Social</strong></span><span style=3D"color:#003366"><strong>&nbsp;-RLCS-</=
strong></span>&nbsp;(<span style=3D"color:#003366">Scopus Q-1</span>&nbsp;y=
<span style=3D"color:#003366">&nbsp;SJR Q-1</span>).&nbsp;Se publicar&aacut=
e; un m&aacute;ximo de&nbsp;6 textos en&nbsp;2024 tras ser aceptados por el=
 Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#800080"><strong>PASOS, Revista de Turismo y Patrimoni=
o Cultural</strong></span><span style=3D"color:#0000CD"><strong>&nbsp;</str=
ong></span>(<span style=3D"color:#003366">Scopus Q-2 y SJR Q-2, Sello FECYT=
&nbsp;y&nbsp;ESCI</span>).&nbsp;Se publicar&aacute;&nbsp;un m&aacute;ximo d=
e 6&nbsp;textos en&nbsp;2024&nbsp;tras ser aceptados por el Comit&eacute; E=
ditorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#FF0000"><strong>Revista Methaodos, Revista de Ciencia=
s Sociales</strong></span>&nbsp;(<span style=3D"color:#003366">Sello FECYT,=
 Dialnet M&eacute;tricas C1 y ESCI)</span>.&nbsp;Se publicar&aacute; un m&a=
acute;ximo de&nbsp;6 textos tras ser aceptados por el Comit&eacute; Editori=
al de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#FFA500"><strong>Revista Ciencia y Deporte</strong></s=
pan>&nbsp;(<span style=3D"color:#003366">SciELO</span>).&nbsp;Se publicar&a=
acute;&nbsp;un m&aacute;ximo de 6&nbsp;textos&nbsp;tras ser aceptados por e=
l Comit&eacute; Editorial de la misma.</li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"color:#000000"><span style=3D"font-size:14px"><strong>Se pod=
r&aacute; participar enviando un v&iacute;deo (emitido el 22 de noviembre)&=
nbsp;o en directo a trav&eacute;s de zoom (23 o 24 de noviembre)</strong></=
span></span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"font-size:14px"><span style=3D"color:#003366"><strong>Fechas=
 clave:</strong></span></span><br>
&nbsp;
<table border=3D"1" cellpadding=3D"1" cellspacing=3D"1" style=3D"width:750p=
x">
	<tbody>
		<tr>
			<td><strong><span style=3D"font-family:arial,sans-serif; font-size:12px"=
>Env&iacute;o de resumen</span></strong></td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta</span></strong>=
<span style=3D"font-family:arial,sans-serif; font-size:9pt; line-height:13.=
8px">&nbsp;<strong><span style=3D"border:1pt none windowtext; padding:0cm">=
el&nbsp;<span style=3D"color:rgb(0, 112, 192)">15 de septiembre</span></spa=
n></strong></span>
</td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute;n</span>=
</td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Desde el&nbsp;</span>=
</strong><span style=3D"border:1pt none windowtext; color:rgb(0, 112, 192);=
 font-family:arial,sans-serif; font-size:9pt; line-height:13.8px; padding:0=
cm"><strong>29 de septiembre</strong></span>
</td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Abono de&nbsp;=
</span><strong style=3D"font-family:arial,sans-serif; font-size:12px"><span=
 style=3D"border:1pt none windowtext; padding:0cm">matr&iacute;cula</span><=
/strong><span style=3D"color:rgb(0, 112, 192); font-family:arial,sans-serif=
; font-size:12px">:&nbsp;</span><span style=3D"font-family:arial,sans-serif=
; font-size:12px">(180 &euro; por cada firmante y por cada ponencia)</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 112, 192)">20 de octubre</span></span></strong>=
</td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Env&iacute;o de ponencia completa</strong></span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 112, 192)">27 de octubre</span></span></strong>=
</td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Env&iacute;o d=
e v&iacute;deo</span><span style=3D"font-family:arial,sans-serif; font-size=
:12px">&nbsp;para ser emitido el 22 de noviembre o env&iacute;o de correo e=
lectr&oacute;nico informando que desea defender la ponencia en directo el 2=
3 o 24 de noviembre</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 112, 192)">5 de noviembre</span></span></strong=
></td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Celebraci&oacute;n </strong>(online)</span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm"><span style=3D=
"color:rgb(0, 112, 192)">22</span>,<span style=3D"color:rgb(0, 112, 192)"> =
23&nbsp;</span>y&nbsp;<span style=3D"color:rgb(0, 112, 192)">24 de noviembr=
e</span></span></strong></td>
		</tr>
	</tbody>
</table>
<br>
<span style=3D"font-size:14px"><span style=3D"color:#003366"><strong><span =
style=3D"font-family:arial,sans-serif; line-height:115%">M&aacute;s informa=
ci&oacute;n en:&nbsp;</span></strong></span><br>
<span style=3D"color:#0000CD"><u>www.congresolatina.net</u></span><span sty=
le=3D"font-family:arial,sans-serif; line-height:115%">&nbsp;</span></span><=
br>
<u style=3D"font-size:14px"><span style=3D"color:#0000CD">2023congresolatin=
a@hisin. org</span></u>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"font-size:14px">Tel&eacute;fono y&nbsp;</span><span style=3D=
"font-size:14px">WhatsApp (+34) 663 965 312<br>
<br>
<strong><span style=3D"color:#FF0000">Un abrazo y &iexcl;&iexcl;SEGUIMOS CO=
MUNICANDO!!</span></strong><br>
<br>
<span style=3D"color:#003366">Comit&eacute; Organizador <strong>XV Congreso=
 </strong></span><span style=3D"color:#FF8C00"><strong>CILCS</strong></span=
></span>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DkR=
nOoR5Y1WHs892MyEbmn8hw&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMg=
AhF4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: b=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DmR=
1jzGrcHB9a4jrApeuUcA&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAh=
F4Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Doh=
t7mDwPng65BCe0SaDtJA&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAh=
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
com/unsubscribe.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF=
4Q" style=3D"text-decoration: underline; color:#333;"><span>Darme de baja d=
e esta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q" s=
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
"><a href=3D"https://www.email-index.com/click.php?L=3DXwzAAEojlY4SMK7KyXfD=
Lg&J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q&F=3DHKFRcCbcnm=
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
log_pic.php?J=3DwX1RMvOzyAfKs7639oasYgLA&C=3Dv5xC763optCzAXRysMgAhF4Q" alt=
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
om/d/msgid/kasan-dev/0102018973f4aa56-8fdbbc0c-8ac0-442a-b0a7-ea2b35b18793-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/0102018973f4aa56-8fdbbc0c-8ac0-44=
2a-b0a7-ea2b35b18793-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_2SqriD93coZM5PtD60Sx091NWMTHJhXRiuvvMOR6YQ--

