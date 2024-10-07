Return-Path: <kasan-dev+bncBDLJXDHV7QBRBOXDR64AMGQEGY6MKFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 87F01992F81
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2024 16:35:40 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-42cb471a230sf40874195e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 07:35:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728311740; cv=pass;
        d=google.com; s=arc-20240605;
        b=ay23E+ywnzybLn8v4oGnadINLfPDkK4acgz6AqfZ/DzLArvsJIF2q6ZZrDNBaWBfrC
         IQauHLN1bIG8VRXvRI5fI/B7ob9/ANrxjKpne4E+rQJb6XhUMARzkN5Z8pTvPHCvUub7
         v6UfqDhwUdbGlayTlPKLkzV9gKMhV+k/Lg8UFzrdA8rfVELDGMWcT6aE/G6Xh5lU3SEO
         ZEfZ4Xt2cT5sk2VkdfhGwJgi3ozW5iJ1Ey6QtFfA+Qkmwy0+dX9knq3IeNruY0omt37w
         4khk2xVyXa5V+yzaaf6wPpe5BOfvgJkTjR/whKgRDaweFAlsMw/ob9EsW4uKDf0MaJXp
         VWZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=/YjWW0H+qkFqB/DWxmRwuMlmFFwSQjbF53BAucHsipE=;
        fh=kER1CFjCLiBV7RcBDNc8CVm1eUR0XiQfDrM9vIaTPw0=;
        b=TwpnAMSiVnXN8ENf15Dt/V9tB2cTi3RKStfvS3FBBQ9CA6RNBYtb3M4agOmg4j2WE3
         cqATuWA+83TMGddB28DX92CTI4f8OAExkUMcT971EaCZAoIWk2x2JDdEtx/qz9HjNPvu
         FLBCQqZZoc8BMFHjimQ2noopXCuQDPO7W6agU1yQuSfIHiO3i4W/U6SmYGb1PgRJI+0u
         CqXM60TQ81CKa3x9sBA4fIVMaeu1XK3Mdntwi45I2tN3voxqqtOB7nHJ9wwHoMkMO0X7
         6S7na6oXD2A+vv5aWQ4SdUkb4RclJO3xU2Vf4XzOrqr8Be1jR1bew/sXYCMlmQmQ7XeF
         JZwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b=SgOFkuCe;
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=Kh+lHSiv;
       spf=pass (google.com: domain of 0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com designates 69.169.231.77 as permitted sender) smtp.mailfrom=0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728311740; x=1728916540; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/YjWW0H+qkFqB/DWxmRwuMlmFFwSQjbF53BAucHsipE=;
        b=LXxHcNvhC2V31K+hGZ+KF+xr6urrhJMxQ0vNcZL1y6MiFByRAfFtSYdccRQGVuhSdJ
         912j9H9j/a6neerYXGx/FDRvp+t2Mv66AAZ0971Xiw1nhbpgaB3klaNk070bN/0zrkWX
         rWA/b2bXFXAO11pwHLvGywt3cqKS36xMgN2Fdvbjb3YMykL64z7ee214dd5VES+M6RvK
         iMen59CgRWlhh3YQSoNdXI187L+tMMKgrmHmc+a5HHBEOS2hs40Chl/P3p4vwrBmZB/e
         zfYvJDwIIeLnq49n9j+rMQdogeNJnhKEJAhVO+sFO+LD+/0N3FqnoEk40fA9TCfl9vf7
         Ay6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728311740; x=1728916540;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/YjWW0H+qkFqB/DWxmRwuMlmFFwSQjbF53BAucHsipE=;
        b=tHD5DLNj/cM82TDVkkB3N58UAS3ip0RI7HveEr6qANoLlF53BFRYkS+a4QABzoo5r8
         5N4PYS6//4iT3k0+XQIE6R8H/k8cBm4ZtiXS5TwjbB8G23HyvwBcZj/wKSxNVen5iZ+k
         FdzKY8yiNvvjTPykKaUdcqF8Jrsz5KURuBA5zRPE9C8ho6t/LktPkLivaatEWUvGIKti
         8gMNMGhFzc0s4jzDhmqtmd9GdaeXW/GXGn+4x/6V91jGdkOD6EGAeRdWo9q0/8CoBCva
         BxuQNzI7yWEAGTbUFu6PDwzNx+sHN40WGJD8AMb56ntsW9Qt8yA+vOu9PGb0p26WWt9e
         NABg==
X-Forwarded-Encrypted: i=2; AJvYcCWq2byFPjPgEYDHszzMYGIFHt96Ea/P9Ft5PffOhhrR1RQnBi1IYNFwvpJd9GPiyhopE18XGw==@lfdr.de
X-Gm-Message-State: AOJu0YyPsT/jgAlG6wrqoX7RG7BO7PZ79kNocQ/8Ya2n7u99spaigdky
	62pPPsi9zjeeZZ1ZwhPPBsRP+24S3gacqLXEeGEAOFOt0n52KCG6
X-Google-Smtp-Source: AGHT+IFNmH1CkujKT3sC7gfmjChKfxx4tjTWvX2CIHZtc++FzHmVb8Xobk/pItMwABoTsvUwbiFqGQ==
X-Received: by 2002:a05:600c:3b08:b0:42c:b63e:fea6 with SMTP id 5b1f17b1804b1-42f85ae927fmr98526985e9.22.1728311739112;
        Mon, 07 Oct 2024 07:35:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c01:b0:42c:af5b:facd with SMTP id
 5b1f17b1804b1-42f7dfac529ls22683475e9.1.-pod-prod-02-eu; Mon, 07 Oct 2024
 07:35:37 -0700 (PDT)
X-Received: by 2002:a05:600c:1ca5:b0:42c:b3e5:f688 with SMTP id 5b1f17b1804b1-42f85a6c5bfmr83736575e9.4.1728311736954;
        Mon, 07 Oct 2024 07:35:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728311736; cv=none;
        d=google.com; s=arc-20240605;
        b=SI5vTFDBQwVKQSrSxPNxjno6w2+pSIhUWbcNWscKLr7nRW/d23ayoGFpBu4PmH4KjX
         UHKvIsJI8rzosRFtbOUed+JxSaffnT6w3tmIXwgZHkqW/29N2tPPO7QxT3U/YNOcDeau
         fPuIyf/8hBWRFU3WtwRRyj3+QMP3RK93Z1i9bquyC2NkYnNq8oW4IsgO/3Iu81x+hENR
         YzD+J7FmaRwyXX3twP+5QPx1muYIH+QEOD29AQsJp+Tqk5nIjQ2a4xNMsstBWSxrYXoJ
         3kaaJgBcf66f9woPHjjUbgUxypfTn45C4QtpSFPZJnvr11HY8g+y3PuiPvsbiwLpP6qo
         k/BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=JJ70vSxClkS9VeXemRvYm1AMW+xDK5V1f4MSBdCMzG8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=J5t/x+cdpp8Q7ca1gO2UJHhr7KN+ENEJ5k6kmxd8NN/8D1dIdRYjL0x/oe91E4cvgw
         MUYghRKonN70a5WMB+wLtEU+2YZcOZuRKgsG0Bz3uH4rSRdPIsivBPXdy+eNuW6y6w9E
         MolFr+u3twg9FrBryJcQ1PmvCmuQaLIvrRs9tCuDmTm0IEq6C5sii0JzhwuIjBafwYAH
         S2v5gmfuuHk0DibaHC3aKZZ0bLlrcDnwusLewLPf81OXvIp9GU9ww/jqS08Ifidc2xye
         nyrL8byojImTbKdQ4Rpvf7sdEYLhXrtu+BGByYN3nfd1nHK7k86KHLqYAfXMbiWVcEBB
         Kh8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b=SgOFkuCe;
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=Kh+lHSiv;
       spf=pass (google.com: domain of 0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com designates 69.169.231.77 as permitted sender) smtp.mailfrom=0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-77.smtp-out.eu-west-1.amazonses.com (b231-77.smtp-out.eu-west-1.amazonses.com. [69.169.231.77])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f86719c6asi3546775e9.1.2024.10.07.07.35.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2024 07:35:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com designates 69.169.231.77 as permitted sender) client-ip=69.169.231.77;
Date: Mon, 7 Oct 2024 14:35:36 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@hisin.org>
Subject: =?UTF-8?Q?Ampliaci=C3=B3n_de_fechas_/_Extension_of_dates._CONGRESO_INTERNAC?=
 =?UTF-8?Q?IONAL_LATINA_DE_COMUNICACI=C3=93N_SOCIAL_2024_(no_presencial)_con?=
 =?UTF-8?Q?_revista_Latina_SCOPUS_Q1?=
Message-ID: <0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: ju0EQTwcVCPCbDgpis2nog
X-FBL: ju0EQTwcVCPCbDgpis2nog-k7MPHMqVFXaeyfU0hp1YPQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_9pseSUnagGyIqGHw4XcE3GGXadAyVaLFc8AS98dM"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2024.10.07-69.169.231.77
X-Original-Sender: congresolatina=hisin.org@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2
 header.b=SgOFkuCe;       dkim=pass header.i=@amazonses.com
 header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=Kh+lHSiv;       spf=pass
 (google.com: domain of 0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com
 designates 69.169.231.77 as permitted sender) smtp.mailfrom=0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000@email.crlsrv.com;
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
--b1_9pseSUnagGyIqGHw4XcE3GGXadAyVaLFc8AS98dM
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3Dju0EQTwcVCPCb=
Dgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ]=20
=20
=20
=20
 CONGRESO INTERNACIONAL LATINA DE COMUNICACI=C3=93N SOCIAL 2024
=20
=20
 [https://www.email-index.com/click.php?L=3DNBBYIGRp3JIJnEe5oZFJ1A&J=3Dju0E=
QTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
=20
 Estimad@s amig@s y colegas:Ampliamos la fecha de recepci=C3=B3n de RES=C3=
=9AMENES hasta el 15 de Octubre para el XVI CONGRESO INTERNACIONAL LATINA D=
E COMUNICACI=C3=93N SOCIAL 2024 (CILCS) que se celebrar=C3=A1 los pr=C3=B3x=
imos d=C3=ADas 11, 12 y 13 de diciembre en modalidad online www.congresolat=
ina.netLos idiomas del congreso son: espa=C3=B1ol, italiano, portugu=C3=A9s=
, ingl=C3=A9s y franc=C3=A9s.Los espacios de trabajo propuestos son actuale=
s, interesantes e imprescindibles en una sociedad que cambia cada d=C3=ADa =
y cada vez a mayor velocidad. EDUCACI=C3=93N, TURISMO, DEPORTE, POL=C3=8DTI=
CA, MARKETING, PUBLICIDAD, LEGALIDAD, INTELIGENCIA ARTIFICIAL=E2=80=A6 Siem=
pre vinculados a la COMUNICACI=C3=93N.Espacios tem=C3=A1ticos: (https://www=
.email-index.com/click.php?L=3DXiR6yiCICSudGPEEJHkvvw&J=3Dju0EQTwcVCPCbDgpi=
s2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw)
	Educando en comunicaci=C3=B3n	Comunicaci=C3=B3n digital	Nuevas tendencias =
e investigaci=C3=B3n en la comunicaci=C3=B3n	Comunicaci=C3=B3n persuasiva	C=
omunicaci=C3=B3n empresarial	Comunicaci=C3=B3n especializada	L=C3=ADmites d=
e la comunicaci=C3=B3n	El negocio de los medios	Propuestas de comunicacione=
s libres	PanelesCurricularmente CILCS presenta:
	Libro de Actas con ISBN 978-84-09-59705-5 (res=C3=BAmenes aceptados tras r=
evisi=C3=B3n por dobles pares ciegos)	y, adem=C3=A1s, da a elegir entre sie=
te posibilidades de publicaci=C3=B3n:	Libro de papel con versi=C3=B3n elect=
r=C3=B3nica de la Editorial ESIC (Q1 =C3=ADndice SPI General). Compuesto po=
r los textos aceptados tras revisi=C3=B3n de mejora mediante dobles pares c=
iegos por parte del Comit=C3=A9 Evaluador del Congreso.	Revista Latina de C=
omunicaci=C3=B3n Social -RLCS- (Scopus Q-1 y SJR Q-1). Se publicar=C3=A1 un=
 m=C3=A1ximo de 6 textos en 2025 tras ser aceptados por el Comit=C3=A9 Edit=
orial de la misma.	Revista del =C3=A1rea de Humanidades (Scopus Q-1 y SJR Q=
-2). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2025 tras ser aceptado=
s por el Comit=C3=A9 Editorial de la misma.	Revista del =C3=A1rea de Cienci=
as Sociales (Scopus Q-3 y SJR Q-3). Se publicar=C3=A1 un m=C3=A1ximo de 6 t=
extos en 2025 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	=
Revista SOCIAL REVIEW, International Social Sciences Review (EBSCO). Se pub=
licar=C3=A1 un m=C3=A1ximo de 6 en 2025 textos tras ser aceptados por el Co=
mit=C3=A9 Editorial de la misma.	Revista EDU REVIEW, International Educatio=
n and Learning Review (ERIHPLUS). Se publicar=C3=A1 un m=C3=A1ximo de 6 tex=
tos en 2025 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	Re=
vista IROCAMM-International Review of Communication and Marketing Mix (ERIH=
PLUS). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2025 tras ser acepta=
dos por el Comit=C3=A9 Editorial de la misma.Si una propuesta para una revi=
sta no es aceptada para su publicaci=C3=B3n, =C3=A9sta ser=C3=A1 publicada,=
 tras revisi=C3=B3n por dobles pares ciegos, como cap=C3=ADtulo de libro de=
 papel y electr=C3=B3nico de la Editorial ESIC.=20
Fechas clave:
Env=C3=ADo de resumen
Ampliado hasta el 15 de octubre
Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n
Desde el 10 de octubre
Abono de matr=C3=ADcula para ponentes (180 =E2=82=AC por cada firmante y po=
r cada ponencia)
Hasta el 25 de octubre
Abono de matr=C3=ADcula para asistentes en general con certificado (50 =E2=
=82=AC)=20
Abono de matr=C3=ADcula para asistentes alumnos con certificado (10 =E2=82=
=AC)
Hasta el 10 de diciembre
Env=C3=ADo de ponencia completa
Hasta el 8 de noviembre
Env=C3=ADo de v=C3=ADdeo para ser emitido el 11 de diciembre o =E2=80=8Benv=
=C3=ADo de correo informando de la
defensa en directo el 12 o 13 de diciembre
Hasta el 15 de noviembre
Celebraci=C3=B3n online
11, 12 y 13 de diciembre

M=C3=A1s informaci=C3=B3n en: www.congresolatina.net 2024congresolatina@his=
in.org
Tel=C3=A9fono y WhatsApp ( 34) 663 935 312 (de 9 a 19 horas de Madrid)Un ab=
razo y =C2=A1=C2=A1SEGUIMOS COMUNICANDO!!XVI CILCS 2024
=20
 [https://www.email-index.com/click.php?L=3DeUA2ktkrtGtJJKzB77uIrA&J=3Dju0E=
QTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw] [=
https://www.email-index.com/click.php?L=3DnjYj1AlskC4T2nASxCE1MQ&J=3Dju0EQT=
wcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw] [ht=
tps://www.email-index.com/click.php?L=3DBEk892m7gg1b9JXHc2ZO8MXQ&J=3Dju0EQT=
wcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ] | Actualizar mis dato=
s [https://www.email-index.com/update.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7=
MPHMqVFXaeyfU0hp1YPQ] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine n=C2=BA =
38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-000000%40eu=
-west-1.amazonses.com.

--b1_9pseSUnagGyIqGHw4XcE3GGXadAyVaLFc8AS98dM
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=
=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3Dju0EQTwcVCPCbDgpis2n=
og&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk=
7MPHMqVFXaeyfU0hp1YPQ');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMq=
VFXaeyfU0hp1YPQ');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHM=
qVFXaeyfU0hp1YPQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3Dju=
0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}}</style>
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
ader1">Ampliaci&oacute;n XVI Congreso LATINA 2024 (res&uacute;menes hasta 1=
5/10/24) organizado por editorial ESIC e HISIN</span><div style=3D"display:=
none;max-height:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;=
&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;</div><table height=3D"" bgcolor=3D" =
#fdfbfc" width=3D"100%" cellpadding=3D"0" cellspacing=3D"0" align=3D"center=
" class=3D"ui-sortable" style=3D"background-color: rgb(253, 251, 252); bord=
er-width: initial; border-style: none; border-color: initial; margin-top: 0=
px; padding: 0px; margin-bottom: 0px;">
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
-index.com/view.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
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
ize:16px"><strong><font color=3D"#000000">CONGRESO INTERNACIONAL&nbsp;</fon=
t><span style=3D"color:#003366">LATINA DE COMUNICACI&Oacute;N SOCIAL</span>=
<span style=3D"color:#FF8C00"><strong> </strong></span>2024</strong></span>=
</div>
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3DFCDBvvIqgnCJz=
4ULrREJfw&J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCb=
cnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=3D"W=
eb del XIII CLCS"><img align=3D"absbottom" border=3D"0" id=3D"Imgfull" widt=
h=3D"280" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1j=
UkXDcz7BTAyZIqw/images/Logo%20CILCS%202024%20para%20ACRELIA%201.jpg?1724671=
036172" alt=3D"XIII CILCS" style=3D"width: 280px; max-width: 280px; text-al=
ign: center; font-size: 18px; color: rgb(255, 255, 255); font-weight: 700; =
text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase;" class=3D"=
acre_image_editable"></a></td>
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
<span style=3D"font-size:14px"><span style=3D"color:#000000">Estimad@s amig=
@s y colegas:</span><br>
<br>
<strong><span style=3D"color:#FF0000">Ampliamos</span></strong> <span style=
=3D"color:#000000">la fecha de </span><span style=3D"color:#0000CD"><strong=
>recepci&oacute;n de RES&Uacute;MENES hasta el 15 de Octubre</strong></span=
>&nbsp;<span style=3D"color:#000000">para el&nbsp;</span><strong><span styl=
e=3D"color:#0000FF">XVI CONGRESO INTERNACIONAL LATINA DE COMUNICACI&Oacute;=
N SOCIAL 2024</span> <span style=3D"color:#003366">(</span><span style=3D"c=
olor:#000080">CILCS</span><span style=3D"color:#003366">)</span></strong>&n=
bsp;<span style=3D"color:#000000">que&nbsp;se celebrar&aacute; los pr&oacut=
e;ximos d&iacute;as 11, 12 y 13 de diciembre en modalidad</span> <strong>on=
line</strong>&nbsp;<u><span style=3D"color:#0000CD">www.congresolatina.net<=
/span></u><br>
<br>
Los idiomas del congreso son: <span style=3D"color:#000000"><strong>espa&nt=
ilde;ol, italiano, portugu&eacute;s, ingl&eacute;s </strong>y<strong> franc=
&eacute;s</strong></span>.<br>
<br>
<span style=3D"color:#000000"><strong>Los&nbsp;espacios de trabajo</strong>=
</span>&nbsp;propuestos son actuales, interesantes e imprescindibles en una=
 sociedad que cambia cada d&iacute;a y cada vez a mayor velocidad.&nbsp;EDU=
CACI&Oacute;N, TURISMO, DEPORTE, POL&Iacute;TICA, MARKETING, PUBLICIDAD, LE=
GALIDAD, INTELIGENCIA ARTIFICIAL&hellip; Siempre vinculados a la COMUNICACI=
&Oacute;N.</span><br>
<br>
<span style=3D"font-size:14px"><span style=3D"color:#000000"><strong>Espaci=
os tem&aacute;ticos: </strong></span><span style=3D"color:#0000FF">(https:/=
/congresolatina.net/espacios-tematicos-2024/)</span></span>
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
size:14px">El negocio de los medios</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Propuestas de comunicaciones libres</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Paneles</span></li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#003366"><strong>Curricularmente&nbsp;</str=
ong></span><span style=3D"color:#000080"><strong>CILCS</strong></span><span=
 style=3D"color:#0000FF"><strong> </strong></span>presenta:</span></div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000"><strong>Libro de Actas&nbsp;con ISBN</strong>=
&nbsp;978-84-09-59705-5&nbsp;</span>(res&uacute;menes aceptados tras&nbsp;r=
evisi&oacute;n por dobles pares ciegos)</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">y, adem&aacute;s, da a elegir entre <span style=3D"color:#0000CD=
"><strong>siete&nbsp;posibilidades de publicaci&oacute;n</strong></span>:</=
span></li>
</ul>

<ol style=3D"margin-left: 40px;">
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#000000"><strong>Libro de papel</strong> </=
span><span style=3D"color:rgb(0, 51, 102)">con versi&oacute;n electr&oacute=
;nica de la </span><strong><span style=3D"color:#006400">Editorial</span></=
strong><span style=3D"color:rgb(0, 51, 102)"><strong> </strong></span><span=
 style=3D"color:#008000"><strong>ESIC</strong></span><span style=3D"color:#=
00FF00">&nbsp;</span>(<span style=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;=
<span style=3D"color:rgb(0, 0, 205)"><u>&iacute;ndice SPI General</u></span=
>). Compuesto por los&nbsp;textos aceptados tras&nbsp;revisi&oacute;n de me=
jora mediante dobles pares ciegos por parte del Comit&eacute; Evaluador del=
 Congreso.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#B22222"><strong>Revista Latina de Comunicaci&oacute;n=
 Social</strong></span><span style=3D"color:#003366"><strong>&nbsp;-RLCS-</=
strong></span>&nbsp;(<span style=3D"color:#003366">Scopus Q-1</span>&nbsp;y=
<span style=3D"color:#003366">&nbsp;SJR Q-1</span>).&nbsp;Se publicar&aacut=
e; un m&aacute;ximo de&nbsp;6 textos en&nbsp;2025 tras ser aceptados por el=
 Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#800080"><strong>Revista del &aacute;rea de Humanidade=
s</strong></span><span style=3D"color:#0000CD"><strong>&nbsp;</strong></spa=
n>(<span style=3D"color:#003366">Scopus Q-1&nbsp;y SJR Q-2</span>).&nbsp;Se=
 publicar&aacute;&nbsp;un m&aacute;ximo de 6&nbsp;textos en&nbsp;2025&nbsp;=
tras ser aceptados por el Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#FF0000"><strong>Revista del &aacute;rea de Ciencias S=
ociales</strong></span>&nbsp;(<span style=3D"color:#003366">Scopus Q-3&nbsp=
;y SJR Q-3)</span>.&nbsp;Se publicar&aacute; un m&aacute;ximo de&nbsp;6 tex=
tos en 2025 tras ser aceptados por el Comit&eacute; Editorial de la misma.<=
/li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#FFA500"><strong>Revista SOCIAL REVIEW,&nbsp;Internati=
onal Social Sciences Review</strong></span>&nbsp;(EBSCO). Se publicar&aacut=
e;&nbsp;un m&aacute;ximo de 6 en 2025 textos&nbsp;tras ser aceptados por el=
 Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#008000"><strong>Revista EDU REVIEW, International Edu=
cation and Learning Review</strong></span> (ERIHPLUS).&nbsp;Se publicar&aac=
ute;&nbsp;un m&aacute;ximo de 6&nbsp;textos en 2025 tras ser aceptados por =
el Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#800000"><strong>Revista IROCAMM-International Review =
of Communication and Marketing Mix</strong> </span>(ERIHPLUS). Se publicar&=
aacute; un m&aacute;ximo de 6 textos en 2025 tras ser aceptados por el Comi=
t&eacute; Editorial de la misma.</li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"color:#000000"><span style=3D"font-size:14px">Si una propues=
ta para una revista no es aceptada para su publicaci&oacute;n, &eacute;sta<=
strong>&nbsp;ser&aacute; publicada,&nbsp;</strong></span></span><span style=
=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px">tras revisi&oacute;n=
 por dobles pares ciegos, como cap&iacute;tulo de libro de&nbsp;</span></sp=
an><span style=3D"color:rgb(0, 0, 0); font-size:14px">papel y electr&oacute=
;nico&nbsp;</span><span style=3D"color:rgb(0, 0, 0)"><span style=3D"font-si=
ze:14px">de la </span></span><span style=3D"color:#008000"><span style=3D"f=
ont-size:14px"><strong>Editorial&nbsp;ESIC</strong></span></span><span styl=
e=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px"><strong>.</strong><=
/span></span><br>
&nbsp;</div>

<div style=3D"line-height: 20px; text-align: justify;">
<strong style=3D"color:rgb(0, 0, 255); font-size:14px">Fechas clave:</stron=
g>

<table border=3D"1" cellpadding=3D"1" cellspacing=3D"1" style=3D"width:700p=
x">
	<tbody>
		<tr>
			<td><strong><span style=3D"font-family:arial,sans-serif; font-size:12px"=
>Env&iacute;o de resumen</span></strong></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm"><span style=3D=
"color:#FF0000">Ampliado</span> hasta</span><span style=3D"font-family:aria=
l,sans-serif; font-size:9pt; line-height:13.8px">&nbsp;<span style=3D"borde=
r:1pt none windowtext; padding:0cm">el&nbsp;<span style=3D"color:rgb(0, 0, =
255)">15 de octubre</span></span></span></strong></td>
		</tr>
		<tr>
			<td>
<strong style=3D"font-family:arial,sans-serif; font-size:12px">Notificaci&o=
acute;n&nbsp;</strong><span style=3D"font-family:arial,sans-serif; font-siz=
e:12px">de aceptaci&oacute;n/denegaci&oacute;n</span>
</td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Desde el&nbsp;</span>=
</strong><span style=3D"color:rgb(0, 0, 255)"><span style=3D"border:1pt non=
e windowtext; font-family:arial,sans-serif; font-size:9pt; line-height:13.8=
px; padding:0cm"><strong>10 de octubre</strong></span></span>
</td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Abono de&nbsp;=
</span><strong style=3D"font-family:arial,sans-serif; font-size:12px"><span=
 style=3D"border:1pt none windowtext; padding:0cm">matr&iacute;cula para po=
nentes</span></strong><span style=3D"color:rgb(0, 112, 192); font-family:ar=
ial,sans-serif; font-size:12px">&nbsp;</span><span style=3D"font-family:ari=
al,sans-serif; font-size:12px">(180 &euro; por cada firmante y por cada pon=
encia)</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 0, 255)">25 de octubre</span></span></strong></=
td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Abono de</span=
><strong style=3D"font-family:arial,sans-serif; font-size:12px">&nbsp;matr&=
iacute;cula para asistentes en general&nbsp;</strong><span style=3D"font-fa=
mily:arial,sans-serif; font-size:12px">con certificado (50 &euro;)&nbsp;</s=
pan><br style=3D"font-family: arial, sans-serif; font-size: 12px;">
			<span style=3D"font-family:arial,sans-serif; font-size:12px">Abono de&nb=
sp;</span><strong style=3D"font-family:arial,sans-serif; font-size:12px">ma=
tr&iacute;cula para asistentes alumnos&nbsp;</strong><span style=3D"font-fa=
mily:arial,sans-serif; font-size:12px">con certificado (10 &euro;)</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 0, 255)">10 de diciembre</span></span></strong>=
</td>
		</tr>
		<tr>
			<td><strong style=3D"font-family:arial,sans-serif; font-size:12px">Env&i=
acute;o de ponencia completa</strong></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 0, 255)">8 de noviembre</span></span></strong><=
/td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Env&iacute;o d=
e <strong>v&iacute;deo</strong></span><span style=3D"font-family:arial,sans=
-serif; font-size:12px">&nbsp;para ser emitido el 11 de diciembre o &#8203;=
env&iacute;o de correo informando de la<br>
			defensa&nbsp;en<strong> directo </strong>el 12 o 13 de diciembre</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:rgb(0, 0, 255)">15 de noviembre</span></span></strong>=
</td>
		</tr>
		<tr>
			<td>
<strong style=3D"font-family:arial,sans-serif; font-size:12px">Celebraci&oa=
cute;n&nbsp;</strong><em style=3D"font-family:arial,sans-serif; font-size:1=
2px">online</em>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm"><span style=3D=
"color:rgb(0, 0, 255)">11, 12&nbsp;</span>y&nbsp;<span style=3D"color:rgb(0=
, 0, 255)">13 de diciembre</span></span></strong></td>
		</tr>
	</tbody>
</table>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"font-size:14px"><span style=3D"color:#003366"><strong><span =
style=3D"font-family:arial,sans-serif; line-height:115%">M&aacute;s informa=
ci&oacute;n en:&nbsp;</span></strong></span></span>

<div style=3D"line-height:22px;">
<span style=3D"font-size:14px"><span style=3D"color:#0000CD"><u>www.congres=
olatina.net</u></span><span style=3D"font-family:arial,sans-serif; line-hei=
ght:115%">&nbsp;</span></span><br>
<u style=3D"font-size:14px"><span style=3D"color:#0000CD">2024congresolatin=
a@hisin.org</span></u>
</div>
</div>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#000000"><strong>Tel&eacute;fono y&nbsp;Wha=
tsApp (+34) 663 935 312 (de 9 a 19 horas de Madrid)</strong></span><br>
<br>
<span style=3D"color:#800080"><strong>Un abrazo y &iexcl;&iexcl;SEGUIMOS CO=
MUNICANDO!!</strong></span><br>
<br>
<strong><span style=3D"color:#000080">XVI CILCS 2024</span></strong></span>=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3D7e=
aHx892YDf08iwlayeTML1Q&J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YP=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block=
;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" =
style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: =
block; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-wei=
ght: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; =
font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/=
ico-facebook-38.jpg" alt=3D"facebook CILCS" class=3D"acre_image_editable"><=
/a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3D9I=
WMAKTKtARhHWqvdePAFg&J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;"=
 title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" st=
yle=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: bl=
ock; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-weigh=
t: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; fo=
nt-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ic=
o-twitter-38.jpg" alt=3D"twitter CILCS" class=3D"acre_image_editable"></a><=
/td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Djz=
83gJBAwlzkt2HlVW5WRg&J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;"=
 title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" st=
yle=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: bl=
ock; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-weigh=
t: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; fo=
nt-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ic=
o-linkedin-38.jpg" alt=3D"linkedin CILCS" class=3D"acre_image_editable"></a=
></td>
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
com/unsubscribe.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
style=3D"text-decoration: underline; color:#333;"><span>Darme de baja de es=
ta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" style=
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
"><a href=3D"https://www.email-index.com/click.php?L=3DzIVQh8TVIYhHYx4dj6x1=
MQ&J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCbcnmxmc4=
f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"border-styl=
e:none;min-width: initial !important;max-width: initial !important;width: i=
nitial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/us=
er/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA 202=
1.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3Dju0EQTwcVCPCbDgpis2nog&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" alt=3D""=
 border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px,border=
:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/0102019267683815-bea45a81-8137-4177-be35-1f5cc6f1af93-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/0102019267683815-bea45a81-8137-41=
77-be35-1f5cc6f1af93-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_9pseSUnagGyIqGHw4XcE3GGXadAyVaLFc8AS98dM--

