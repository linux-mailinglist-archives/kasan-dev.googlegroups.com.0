Return-Path: <kasan-dev+bncBDP3RYOQSQBBBKMG5SLAMGQEVM5454Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CAB5957E7E1
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 22:06:02 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id k30-20020a0565123d9e00b0048a716121bcsf1889298lfv.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 13:06:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658520362; cv=pass;
        d=google.com; s=arc-20160816;
        b=PAyiqg1qauJJBu71xLpoiWN/vIhbw9FBjjC2iZK5p33oDePk6q9r1V2CP/BjpWIDhM
         sQyZa14jSj7LaH6IRwfputhxfLu98yz6jLmpccp+mg0HkJnXHXWcLMl1/gkCM7DwT24T
         g/MWqPHl8Pva1KLLeVFLocR3PcVnCrH4rrqeq9S6h967Drb5vZatBZTMpOjQfkbMgob4
         HYEAJBuYnnxfXzliJjkg7hb9e2UY3ITWfVh1D4Xbi6FkV6O9XGudRaaOEUcHwLp20Edf
         gRnzhzCWdHVme2F5zK+QOiRdtsEqRxrYLPPpHhkP1EjgEVINzopZxCSJEhzjN/M+6aTY
         NntA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=xS0UeLYVbPICFtNlhKATD4oIEvf4gXmW17HEXWCm6o4=;
        b=n5XRAzKsyXH0T47W1tuGMW4+/jDQ7+DaPGzQbH/+I/vc05Hkz6vqjI3ZjKlwTMnoIZ
         HGDIuhesgZjgGJGvoMubRJO+hb3jXwZ9TgLyFtfTJ/J2clVrjbxhVENY33TJHiZ4Z6HO
         +5gZdRXbVpGNbyogllVaXpR7/S4kuljV/tKPTAHUPqkB6R4Xd02/0vUpBhcoHzv+arPU
         DwoOOsLKDd/93zI4itupYmHxpdu2pG5ltvou3sGU9ANN+5Nu9jZ2B+/KUqL4wqKUXPwJ
         8jf7H3pwHLMfLhVroHhRbM6BUdzDIGl1lLewZSXP9eCuPrTxDZ6EMy95nIbWrTftrq/C
         JOjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=QeDbUzMI;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="y/x5R0Co";
       spf=pass (google.com: domain of 01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:to:from:reply-to:subject:message-id:list-unsubscribe
         :mime-version:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe;
        bh=xS0UeLYVbPICFtNlhKATD4oIEvf4gXmW17HEXWCm6o4=;
        b=Eyz8keqC9MZQrHTHRZRicmownlmkKj0g5FFmlSjsI3ONwVZP4lg0TbaI8QrTFPzoiO
         C8+ykXEYRP+AOpGPUAUzGiOImI2jbLhxzjFbdTYsW6fJbC5dUvHH5Kx1I368iVsSx+y6
         Hns0T/mulWEQNthLylxXirTTRcQZLn1Z/dcGyhJJulYCq7FBwmQdSfcKffnm4QJFyXXj
         m1Aq1vFJkO6lYLtFCk7SjRLivYaXZxWnIMYJfKJSWLnYciGrIt1F2FndE8hYLhg+78CN
         HX2kGvWqESxtcfFFZv+tW1owk5izuppv89UfwxIfDIOwNWF+UkF3DUXGwZ0DxEGwVH2g
         gxdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:to:from:reply-to:subject:message-id
         :list-unsubscribe:mime-version:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe;
        bh=xS0UeLYVbPICFtNlhKATD4oIEvf4gXmW17HEXWCm6o4=;
        b=CDmAGNK5a8kyEqfi3mdQErcDRZ8Kop00kOz8PJw0D3h6NMqWoW/LeOZCpUYm7I2+hU
         C8cPsg+r/TBaZKpbbTzwIuU+jqB+65aYCnlVXWFaRkLJ5GAV/qtwDMKBNCY1ghUQaopO
         AXtQG+hoysEL0+gim/ie+hLZMBWo1LgeBVgh+NayAjDwoTczmyo7gKKW3TcA6p60/Cnp
         PBgGY1KDHU24+De2VKRjPwPhwwcmyzk8YOqHKqSURSKkK94fcmHdBHISwDg2T4C4L2wL
         jFAKqurkcF1Hk3YKxNNnyRuHyTAEGueD/mM1k0Y+TOHLozomHouPTPMRFf5PBJ8cD2q/
         3gdA==
X-Gm-Message-State: AJIora929Y41HcqDlhrjgYATOsVbLUWyAkeo/wwbhBH+RAMXJm0aEV1n
	AzxvvsEu9wgmejWtK4sbRQc=
X-Google-Smtp-Source: AGRyM1vZJQ08X+FMEFCTw0+HVklZBKAHSgIO5GsCfYesVFqumYzD5eEQkY6MCFELBp39G3u0/RPyAQ==
X-Received: by 2002:a2e:901a:0:b0:25d:7d6d:42a6 with SMTP id h26-20020a2e901a000000b0025d7d6d42a6mr521246ljg.301.1658520361742;
        Fri, 22 Jul 2022 13:06:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2095:b0:489:cd40:7a25 with SMTP id
 t21-20020a056512209500b00489cd407a25ls2164520lfr.3.-pod-prod-gmail; Fri, 22
 Jul 2022 13:06:00 -0700 (PDT)
X-Received: by 2002:a05:6512:1506:b0:47f:79c6:eb36 with SMTP id bq6-20020a056512150600b0047f79c6eb36mr667268lfb.168.1658520360453;
        Fri, 22 Jul 2022 13:06:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658520360; cv=none;
        d=google.com; s=arc-20160816;
        b=akZOW8VOMHu08LBaR34IY5x8uKEmbw8u8wdRMhMkqMMqL2l9inkEJp7+U532AQE9oA
         Bq5AxQxnYgMv2Otpl/M3rxm6tWPjJb0DHGxjmNu/U5F8yS5qGrrzVxbxtMJ44auEA33l
         gfb9TR0W9M0rOTYKlLaKSjoo34VzgkGMKx5JSDANk264GZWvurJ5V9J/F0dU0cFsR0Nx
         B0nwmmVv3XYjoo/KTW5i3TyO4PbquiBzjladVKIyOA9EEy76/FajAJYm+egkh80UMlFx
         +GDGLmG2D+9y4nVc9Cr+dWaCG9wyxcbwEIde0sqZQOiypgHqvueMStm1noQ5VDW3W13H
         9t/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=YeHnCeJ+UJX4KtX2FI/BeeC5liU/F4yGs7SuJWfKqu8=;
        b=ErZUaztUJnAXIMvN24CfTnWiZcSnrxbgna2IejVSNbaqkwPUHKSg2tMoMSaupThCty
         Mf8YCtnKq2+DENfL42jMaPR10zms8qr+A4PFkONgOtZ4ZPATfbRAdttuDmEwOHO1SOQI
         FEiz3Bsms27Wro2bUHrjGJCSaysFYSWRAszzNg9MHeixXqfHt3S7qx2ggPm7nyKzq2DP
         OV9QUEMquZ9Z7J9BUFs0V38qY/1CZAL/BaIBsGF2T0IkpAUDg/VRvG1O+e6/kyNmtMH1
         5aHqH7bWAnYunxVQ2YYalGa9zTLR40szqZwXDJUcm2YDtL7dZxlaK9KDlFMC/7BmsaDQ
         smjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=QeDbUzMI;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="y/x5R0Co";
       spf=pass (google.com: domain of 01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-75.smtp-out.eu-west-1.amazonses.com (b231-75.smtp-out.eu-west-1.amazonses.com. [69.169.231.75])
        by gmr-mx.google.com with ESMTPS id z3-20020a05651c11c300b0025d8f98aed4si221439ljo.8.2022.07.22.13.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jul 2022 13:06:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) client-ip=69.169.231.75;
Date: Fri, 22 Jul 2022 20:05:59 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@congresolatina.net>
Subject: Convocatoria / Call for papers. Congreso Internacional LATINA (no presencial)
Message-ID: <01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: OhOFjKmrEYQRuB7D547ktg
X-FBL: OhOFjKmrEYQRuB7D547ktg-VDTpwwH7M763I3cPLRDSlm3Q
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_ASEC1JzOvyQzcXRePhB0OLKnRto3HbHTcp8mfIyngk"
Feedback-ID: 1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2022.07.22-69.169.231.75
X-Original-Sender: congresolatina=congresolatina.net@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw
 header.b=QeDbUzMI;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b="y/x5R0Co";       spf=pass
 (google.com: domain of 01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com
 designates 69.169.231.75 as permitted sender) smtp.mailfrom=01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
X-Original-From: Historia de los sistemas informativos <congresolatina=congresolatina.net@crlsrv.com>
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
--b1_ASEC1JzOvyQzcXRePhB0OLKnRto3HbHTcp8mfIyngk
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DOhOFjKmrEYQRu=
B7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q]=20
=20
=20
=20
 Congreso Internacional LATINA DE COMUNICACI=C3=93N SOCIAL 2021
=20
=20
 [https://www.email-index.com/click.php?L=3D72b3Y7jAUIpMh2WhTxNrYg&J=3DOhOF=
jKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
=20
=20
=20
 Estimados Amigos y Colegas:El pr=C3=B3ximo mes de diciembre celebramos el =
XIII CONGRESO INTERNACIONAL LATINA DE COMUNICACI=C3=93N SOCIAL www.congreso=
latina.net que este a=C3=B1o ser=C3=A1 virtual y en l=C3=ADnea (no presenci=
al).Los espacios de trabajo propuestos son actuales, interesantes e impresc=
indibles en una sociedad que cambia cada d=C3=ADa y cada vez a mayor veloci=
dad.Espacios tem=C3=A1ticos:
	Competencias comunicativas en la Educaci=C3=B3n Superior	Comunicaci=C3=B3n=
 digital	Nuevas tendencias e investigaci=C3=B3n en la comunicaci=C3=B3n	Com=
unicaci=C3=B3n persuasiva	Comunicaci=C3=B3n empresarial	Comunicaci=C3=B3n e=
specializada	L=C3=ADmites de la comunicaci=C3=B3n	Ense=C3=B1anza de la comu=
nicaci=C3=B3n	Propuestas de comunicaciones libres	P=C3=B3steresCurricularme=
nte el XIII Congreso Internacional Latina de Comunicaci=C3=B3n Social prese=
nta:
	Libro de actas con ISBN (son los res=C3=BAmenes)y, adem=C3=A1s da a elegir=
 entre:
	Dos posibilidades de publicaci=C3=B3n. Los autores elegir=C3=A1n enviar su=
s ponencias completas al ESPACIO TEM=C3=81TICO de su elecci=C3=B3n seg=C3=
=BAn una de estas opciones:	POSIBILIDAD: Env=C3=ADo para optar a publicaci=
=C3=B3n en Revista Latina de Comunicaci=C3=B3n Social -RLCS- (www.revistala=
tinacs.org) (Scopus Q-1 y Scimago Q-2). Se publicar=C3=A1n 5 textos en el 2=
022 de entre los postulados por los autores para esta revista y que sean ac=
eptados por el Comit=C3=A9 Editorial de la misma. Los que no sean aceptados=
 ser=C3=A1n publicados en Libro de papel de GEDISA (Posibilidad 2=C2=AA).	P=
OSIBILIDAD: Libro de papel con ISBN de la editorial GEDISA (2=C2=AA en el =
=C3=ADndice SPI [https://www.email-index.com/click.php?L=3D5cqJSksZpAeKcgJg=
lczyaQ&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZ=
wARmi9SVnjlQzw)] de Comunicaci=C3=B3n. Los textos aceptados tras revisi=C3=
=B3n mediante pares ciegos por parte del Congreso y aquellos que no vayan a=
 ser publicados en RLCS (Posibilidad 1=C2=AA) ser=C3=A1n publicados en dich=
os libros de papel.=E2=80=8BF=C3=B3rmulas de participaci=C3=B3n:Este a=C3=
=B1o presenta 2 modalidades de participaci=C3=B3n optativas (voluntarias) y=
a que el texto es obligatorio:OPCI=C3=93N VOLUNTARIA 1=C2=AA- Virtual media=
nte la proyecci=C3=B3n de los v=C3=ADdeos que los ponentes env=C3=ADen. D=
=C3=ADa 1 de diciembre (mi=C3=A9rcoles)OPCI=C3=93N VOLUNTARIA 2=C2=AA- En l=
=C3=ADnea a trav=C3=A9s de videoconferencia en directo por cada mesa. D=C3=
=ADas 2 y 3 de diciembre (jueves y viernes)=20
Fechas clave:
=20
Env=C3=ADo de resumen obligatorio (en espa=C3=B1ol, ingl=C3=A9s, italiano, =
franc=C3=A9s o portugu=C3=A9s):
Hasta el viernes 3 de septiembre
Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n:
En torno al lunes 4 de octubre
Abono de matr=C3=ADcula:=20
Hasta el lunes 11 de octubre
Env=C3=ADo de ponencia completa (en espa=C3=B1ol, ingl=C3=A9s, franc=C3=A9s=
 o portugu=C3=A9s):
Hasta el lunes 2 de noviembre
Env=C3=ADo de V=C3=ADdeo (-opcional-) para ser emitido durante el congreso:
Hasta el lunes 22 de noviembre
Celebraci=C3=B3n (virtual y en l=C3=ADnea):
Del mi=C3=A9rcoles 1 al viernes 3 de diciembre
Matr=C3=ADcula =C3=BAnica hasta el lunes 11 de octubre 180 =E2=82=AC por ca=
da ponente firmante y por cada ponencia firmada. Para cualquier duda, los e=
mplazamos en la web www.congresolatina.net y en nuestro correo: congresolat=
ina@congresolatina.net en nuestro Whasapp (+34) 663 965 312 o en nuestros t=
el=C3=A9fonos (+34) 91 512 03 05 y (+34) 615 963 719.Almudena Barrientos-B=
=C3=A1ezUniversidad Europea de Madrid (Espa=C3=B1a)Directora del Congreso C=
UICIID 2021
=20
 [https://www.email-index.com/click.php?L=3DTh29zsAu7763IrcnwEFJ2bdQ&J=3DOh=
OFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3DkL1KpdQpE6qH763Qu7bX763gZw&J=
=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SV=
njlQzw] [https://www.email-index.com/click.php?L=3D4ontzkUnRpGRmJat1fFNzQ&J=
=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SV=
njlQzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q] | Actualizar mis da=
tos [https://www.email-index.com/update.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3D=
VDTpwwH7M763I3cPLRDSlm3Q] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine n=C2=
=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-000000%40eu=
-west-1.amazonses.com.

--b1_ASEC1JzOvyQzcXRePhB0OLKnRto3HbHTcp8mfIyngk
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=
=3DVDTpwwH7M763I3cPLRDSlm3Q');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DOhOFjKmrEYQRuB7D547k=
tg&C=3DVDTpwwH7M763I3cPLRDSlm3Q');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DV=
DTpwwH7M763I3cPLRDSlm3Q');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH=
7M763I3cPLRDSlm3Q');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpww=
H7M763I3cPLRDSlm3Q');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DOh=
OFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q');}}</style>
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
ader1">XIV Congreso LATINA 2022 (res&uacute;menes hasta 16/09/2022) organiz=
ado por editorial TECNOS e HISIN</span><div style=3D"display:none;max-heigh=
t:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nb=
sp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;=
&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#8=
47;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;=
&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zw=
nj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;=
&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nb=
sp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;=
&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#8=
47;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;=
&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zw=
nj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;=
&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nb=
sp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;</div><table heigh=
t=3D"" bgcolor=3D" #fdfbfc" width=3D"100%" cellpadding=3D"0" cellspacing=3D=
"0" align=3D"center" class=3D"ui-sortable" style=3D"background-color: rgb(2=
53, 251, 252); border-width: initial; border-style: none; border-color: ini=
tial; margin-top: 0px; padding: 0px; margin-bottom: 0px;">
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
-index.com/view.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q=
" style=3D"text-decoration: underline; color:#333;"><span>Ver en navegador<=
/span></a>
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
span style=3D"color:#0000FF">LATINA DE COMUNICACI&Oacute;N SOCIAL</span><sp=
an style=3D"color:#FF8C00"><strong> </strong></span>2022</strong></span></d=
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3DpaZFutdh8Xyo7=
6379huZQYuA&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DHKF=
RcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=
=3D"Web del XIII CLCS"><img align=3D"absbottom" border=3D"0" id=3D"Imgfull"=
 width=3D"280" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fB=
xrW1jUkXDcz7BTAyZIqw/images/LOGO%20LATINA%2022.png?1658354193663" alt=3D"XI=
II CILCS" style=3D"width: 280px; max-width: 280px; text-align: center; font=
-size: 18px; color: rgb(255, 255, 255); font-weight: 700; text-shadow: blac=
k 0.1em 0.1em 0.2em; text-transform: uppercase;" class=3D"acre_image_editab=
le"></a></td>
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
<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Estimad@s Amig@s y Colegas:<br>
<br>
El pr&oacute;ximo mes de noviembre celebramos el&nbsp;<strong><span style=
=3D"color:#0000FF">XIV CONGRESO INTERNACIONAL LATINA DE COMUNICACI&Oacute;N=
 SOCIAL 2022 (CILCS)</span> </strong>en modalidad virtual y en l&iacute;nea=
 (no presencial)&nbsp;<u><span style=3D"color:#0000CD">www.congresolatina.n=
et</span></u><br>
<br>
Los idiomas del congreso son: <strong>espa&ntilde;ol, italiano, portugu&eac=
ute;s, ingl&eacute;s </strong>y<strong> franc&eacute;s</strong>.<br>
<strong>Los&nbsp;espacios de trabajo</strong>&nbsp;propuestos son actuales,=
 interesantes e imprescindibles en una sociedad que cambia cada d&iacute;a =
y cada vez a mayor velocidad.<br>
<br>
<span style=3D"color:#0000FF"><strong>Espacios tem&aacute;ticos:</strong></=
span></span></div>

<ol>
	<li style=3D"line-height: 20px; text-align: justify;">Educando en comunica=
ci&oacute;n: competencias comunicativas en la Educaci&oacute;n Superior</li=
>
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
size:14px">&nbsp;<br>
<strong><span style=3D"color:#0000CD">Curricularmente&nbsp;CILCS </span></s=
trong>presenta:</span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<strong>Libro de Actas&nbsp;con ISBN</strong>&nbsp;(res&uacute;menes acepta=
dos tras&nbsp;revisi&oacute;n por pares ciegos)</li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">y, adem&aacute;s, da a elegir entre:</span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<strong>Dos posibilidades&nbsp;de publicaci&oacute;n</strong>.&nbsp;Los aut=
ores&nbsp;enviar&aacute;n sus ponencias completas al ESPACIO TEM&Aacute;TIC=
O de su elecci&oacute;n seg&uacute;n una de estas <strong>dos opciones</str=
ong>:</li>
</ul>

<ol style=3D"margin-left: 40px;">
	<li style=3D"line-height: 20px; text-align: justify;">Env&iacute;o para op=
tar a publicaci&oacute;n en&nbsp;<strong><span style=3D"color:#0000CD">Revi=
sta Latina de Comunicaci&oacute;n Social&nbsp;-RLCS-&nbsp;</span></strong>(=
<u><span style=3D"color:#0000CD">www.revistalatinacs.org</span></u>) (<span=
 style=3D"color:#FF0000">Scopus Q-1</span>&nbsp;y&nbsp;<span style=3D"color=
:#FF0000">Scimago Q-1</span>).&nbsp;Se publicar&aacute;n 5 textos en el 202=
3 de entre los postulados&nbsp;por los autores para esta revista tras ser a=
ceptados por el Comit&eacute; Editorial de la misma.&nbsp;<strong>Los que n=
o sean aceptados para RLCS&nbsp;ser&aacute;n publicados&nbsp;en un Libro de=
 papel de</strong>&nbsp;<strong>TECNOS -GRUPO ANAYA-</strong>&nbsp;(Posibil=
idad 2&ordf;).</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><strong><span style=3D"color:#0000CD">Libro de papel con ISBN de=
 la editorial TECNOS -GRUPO ANAYA-</span></strong>&nbsp;(8&ordf; en el&nbsp=
;<span style=3D"color:#0000CD"><u>&iacute;ndice SPI General</u></span>). Lo=
s textos aceptados tras&nbsp;revisi&oacute;n de mejora mediante dobles pare=
s ciegos por parte del Congreso&nbsp;y aquellos que no vayan a ser publicad=
os en&nbsp;<strong><span style=3D"color:#0000CD">RLCS</span></strong>&nbsp;=
(Posibilidad 1&ordf;) ser&aacute;n impresos en dichos libros de papel.</spa=
n></li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#0000CD"><strong>&#8203;F&oacute;rmulas de =
participaci&oacute;n:</strong></span></span></div>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"font-size:14px">Este a&ntilde;o presenta<strong>&nbsp;para e=
legir 2 modalidades de participaci&oacute;n&nbsp;voluntarias</strong>:<br>
<br>
-&nbsp;<span style=3D"color:#0000CD"><strong>Virtual</strong></span>&nbsp;m=
ediante la proyecci&oacute;n de los v&iacute;deos que los ponentes env&iacu=
te;en.&nbsp;<strong>D&iacute;a 23 de noviembre&nbsp;(mi&eacute;rcoles)</str=
ong><br>
-&nbsp;<strong><span style=3D"color:#0000CD">En l&iacute;nea&nbsp;</span></=
strong>a trav&eacute;s de videoconferencia en directo. <strong>D&iacute;as =
24 y 25 de noviembre&nbsp;(jueves y viernes)</strong><br>
<br>
<span style=3D"color:#0000CD"><strong>Fechas clave:</strong></span></span>

<table border=3D"1" cellpadding=3D"1" cellspacing=3D"1" style=3D"width:750p=
x">
	<tbody>
		<tr>
			<td>
<strong><span style=3D"font-family:arial,sans-serif; font-size:12px">Env&ia=
cute;o de resumen&nbsp;</span><strong style=3D"font-family:arial,sans-serif=
; font-size:12px"><span style=3D"border:1pt none windowtext; padding:0cm">o=
bligatorio</span></strong></strong><span style=3D"font-family:arial,sans-se=
rif; font-size:12px">&nbsp;(en espa&ntilde;ol, ingl&eacute;s, italiano, fra=
nc&eacute;s o portugu&eacute;s):</span>
</td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta</span></strong>=
<span style=3D"font-family:arial,sans-serif; font-size:9pt; line-height:13.=
8px">&nbsp;<strong><span style=3D"border:1pt none windowtext; padding:0cm">=
el&nbsp;<span style=3D"color:rgb(0, 112, 192)">viernes 16 de septiembre</sp=
an></span></strong></span>
</td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute;n:</span=
></td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Desde el&nbsp;<span s=
tyle=3D"color:rgb(0, 112, 192)">viernes</span></span></strong><span style=
=3D"border:1pt none windowtext; color:rgb(0, 112, 192); font-family:arial,s=
ans-serif; font-size:9pt; line-height:13.8px; padding:0cm">&nbsp;<strong>23=
 de septiembre</strong></span>
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
<span style=3D"color:rgb(0, 112, 192)">lunes 14 de octubre</span></span></s=
trong></td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Env&iacute;o de ponencia completa</strong> (en espa&ntilde;ol, ingl&eacute=
;s, italiano, franc&eacute;s o portugu&eacute;s):</span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 112, 192)">viernes 28 de octubre</span></span><=
/strong></td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Env&iacute;o d=
e V&iacute;deo (-</span><strong style=3D"font-family:arial,sans-serif; font=
-size:12px"><span style=3D"border:1pt none windowtext; padding:0cm">volunta=
rio</span></strong><span style=3D"font-family:arial,sans-serif; font-size:1=
2px">-) para ser emitido durante el CILCS y aviso de defensa&nbsp;</span>de=
 la ponencia (-<strong style=3D"font-family:arial,sans-serif; font-size:12p=
x">voluntaria</strong><span style=3D"font-family:arial,sans-serif; font-siz=
e:12px">-) en directo :</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 112, 192)">lunes 31 de octubre</span></span></s=
trong></td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Celebraci&oacute;n </strong>(virtual y en l&iacute;nea):</span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Del&nbsp;<span=
 style=3D"color:rgb(0, 112, 192)">mi&eacute;rcoles 23&nbsp;</span>al&nbsp;<=
span style=3D"color:rgb(0, 112, 192)">viernes 25 de noviembre</span></span>=
</strong></td>
		</tr>
	</tbody>
</table>
<br>
<span style=3D"font-size:14px"><strong><span style=3D"color:#0000CD"><span =
style=3D"font-family:arial,sans-serif; line-height:115%">Matr&iacute;cula:<=
/span></span><span style=3D"color:rgb(0, 112, 192); font-family:arial,sans-=
serif; line-height:115%">&nbsp;</span></strong>Hasta el&nbsp;<span style=3D=
"color:#0000CD"><strong>lunes&nbsp;14 de octubre</strong></span>&nbsp;supon=
e 180 &euro; por <strong>cada ponente</strong> firmante y por <strong>cada =
ponencia</strong> firmada.<br>
&nbsp;<br>
Para cualquier duda los emplazamos a nuestra web&nbsp;<span style=3D"color:=
#0000CD"><u>www.congresolatina.net</u></span><span style=3D"font-family:ari=
al,sans-serif; line-height:115%">&nbsp;</span>y en:</span>
</div>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Correo:&nbsp;<u><span style=3D"color:#0000CD">congresolatina@con=
gresolatina.net&nbsp;</span></u><br>
WhatsApp (+34) 663 965 312<br>
Tel&eacute;fonos (+34) 91 512 03 05 y (+34) 615 963 719<br>
<br>
<br>
<strong>Almudena Barrientos-B&aacute;ez</strong><br>
Universidad Complutense de Madrid (Espa&ntilde;a)<br>
<span style=3D"color:#0000CD"><strong>Directora del XIV Congreso </strong><=
/span><strong>CILCS</strong><span style=3D"color:#0000CD"><strong> 2022</st=
rong></span></span></div>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DgX=
RU9Exy2zGPPryT1i1QaQ&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block=
;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" =
style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: =
block; text-align: center; font-size: 18px; color: rgb(255, 255, 255); font=
-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: upperca=
se;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-facebook-38.=
jpg" alt=3D"facebook CUICIID" class=3D"acre_image_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dn4=
huGjw3j6MCVBjq18Y763Ow&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSl=
m3Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DLC=
WquH55e4WzGq2905EYqg&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3=
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
com/unsubscribe.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q=
" style=3D"text-decoration: underline; color:#333;"><span>Darme de baja de =
esta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q" sty=
le=3D"text-decoration: underline; color:#333;"><span>Actualizar mis datos</=
span></a>
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
"><a href=3D"https://www.email-index.com/click.php?L=3Dpq5y77PvIgNTVX0lvi9i=
XQ&J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DHKFRcCbcnmxm=
c4f43DJP5g"><img alt=3D"" border=3D"0" style=3D"border-style:none" src=3D"h=
ttps://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/im=
ages/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DOhOFjKmrEYQRuB7D547ktg&C=3DVDTpwwH7M763I3cPLRDSlm3Q" alt=3D=
"" border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px,bord=
er:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/01020182278451c8-658f70b7-b36e-48c1-a382-a520dfdf4eb8-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/01020182278451c8-658f70b7-b36e-48=
c1-a382-a520dfdf4eb8-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_ASEC1JzOvyQzcXRePhB0OLKnRto3HbHTcp8mfIyngk--

