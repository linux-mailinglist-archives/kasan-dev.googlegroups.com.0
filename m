Return-Path: <kasan-dev+bncBDLJXDHV7QBRBQWWWK3AMGQEO65XM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55CD895F650
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 18:20:20 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-a8696019319sf371555966b.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 09:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724689220; cv=pass;
        d=google.com; s=arc-20240605;
        b=lROrLh0hMxeU5Ey8AnG7NaUFvhCdJizuEb6HB7eY1edcVfY6LAj7nDj2IDCjRtjlqw
         4Zx2/jFyjCs43Cmst39A0nT65kAt/cFDXMpQgnVnlKF5UCgBXx93J3qHX2Codly4d5WW
         k7LQQ+bKagVAlszjjQifGjU1b+zL76zPvnZzbsQP1BPrQDFm+9vNhAy3kexYmJLOHCdw
         A1jl4A8LNH9RVU3s2hrUEBa2A+jvXgsxtsfxlP76/8LBm4sCoGamWHyCH8nD4VWm3HSD
         qyYRUXGEJhyXLSk6N5sst92XYgxKvsgpHA5NdJ7tKRSADYd2BVq2bVNCbONTfpITDOHc
         +e/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=Hk/8nWpJg5PxBIBrpuq1z4nD7rXzw9DJ+EE15Rvbpxw=;
        fh=V5GRysT4mv2/Hk1KpXxjNk3yUbHhwWfcc8vh+2ynXVs=;
        b=PCwIWKwdERp01/IA/4Yoqtdhd6ei/4xqhP/hyOyCPbDj4nORm07j+IgQ2Gtlwg+Qd1
         4WtaVgchBtQdiB5yBp2tEMw+AmPKVddmWULqLyDYR+2ERko0LJcpirQeY+fWGlTPXXKo
         2aC8li5IQl3CBVJjEhqH97OhsNOq1iC+xec9Fgdks6bLSQusMcMbIP6iK27Uj77Zl+ER
         jBP1S9m7cI6cfVi0atTUnqP1IQvDBaemiLs6sjD9ipEfUiM1/Fug2FSw3c4F/UB1CU3v
         0oTy/adol9nddxSUc4y/98PL7eo4N4rQf85uLVh90HbRH1xlj1AQYh5vSt8FWBgh2nLP
         A+Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b=ZvfOGXlr;
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=bUlQwXso;
       spf=pass (google.com: domain of 010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724689220; x=1725294020; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hk/8nWpJg5PxBIBrpuq1z4nD7rXzw9DJ+EE15Rvbpxw=;
        b=RzRmADVJDcLUzNus7pQnPzOHaDg6v3IirNxBPAw1UrrSOnWNhdZEqblV/7YObqikQc
         ggsBKOIeFM9eDi20Txcd4Q482mm7FOlMToufkxi4vLiKI5E6bHjeLWaCKbpcns2HGOAH
         lIbKYmhaeaRHeNMC+ROiRE0wUwYejZ5/EiK0+VGuu3cSA7C1E7+r3HeMD3mYpyM205V/
         y50eZ/WvB5oPZrk+HabJ4AMaVpvBh8gJoSUifGuKyP2NymCNrB726GE43RFJvkgbLk3h
         20sxA4wD1yFCzquJ6Qv/A8u9WWVudPgYpxASojbFZvtygAuJaEVQqjUrZLeJZ+wm7gpP
         A4BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724689220; x=1725294020;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hk/8nWpJg5PxBIBrpuq1z4nD7rXzw9DJ+EE15Rvbpxw=;
        b=rKIatTNE90SQC89pyoQ7cRq2HH7goWBMUwSxUDpRnllgKIzu+WQJLaJKvfug5xzRYY
         WFAw0r5SWnAZMpJ0zn27exHGjbxO7GrkZM3JKylWexq1z1HmPGdvBxYMNHXGYbYusP05
         L7ofZX+ytAqvMgIHHvBnrgpY9U88fD5qePGa1cnloDPyddz1f2iBawdUWejyHp7nTWC4
         Bpo3Y+0zgvqgyZpT6cYzQAfMHNnKOgm9+LfM1DkKSyE4GqdVvbSCwHvBiJaBXNL9h/T/
         vxoEYEStBCm393G/lse5VAwEAEXi7+ghnBCiyV5ammdFtVhLH4S2cOkSNVSxZIn5jBuP
         CByQ==
X-Forwarded-Encrypted: i=2; AJvYcCVdcAuzaW6j8TebcXnlhnf20Osb2vqbvX9hfo3fWUgjLYR2Vl2HkAT0iS+zlC9Iw8ix785pGA==@lfdr.de
X-Gm-Message-State: AOJu0YwaHwWfTiwru1Vd0UpzX6ifZdOZbonNZtNrPZpNJOZEccc+2KXR
	FVKcV7QBNah8+ft1AXlwKKxGCqOlEVLqly2wxIdaF+OSuUw7XNrR
X-Google-Smtp-Source: AGHT+IEQHvQXPtpYgZdU+t3tkEEbB1IVoQJSSaFWQbhqATkHZrAH8cQfd0mI3gJYISJgu/0ULWiBsg==
X-Received: by 2002:a05:6402:3582:b0:5a2:6e1c:91e9 with SMTP id 4fb4d7f45d1cf-5c08915b9fcmr7320792a12.7.1724689218595;
        Mon, 26 Aug 2024 09:20:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2690:b0:57d:555d:8ddd with SMTP id
 4fb4d7f45d1cf-5bf38f9b08dls1159849a12.0.-pod-prod-02-eu; Mon, 26 Aug 2024
 09:20:16 -0700 (PDT)
X-Received: by 2002:a05:6402:2553:b0:5be:f404:9c4c with SMTP id 4fb4d7f45d1cf-5c08910fd1fmr6953526a12.0.1724689216360;
        Mon, 26 Aug 2024 09:20:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724689216; cv=none;
        d=google.com; s=arc-20160816;
        b=HuLKLrk6D9W1yUUIHwxbiSH7NgIqjpLK1F4Bhse/gVPpMPFE13IjpBYiJj4mw63Kc4
         1ly+HEw9xsupTmnTtZL67zfr8dBm20zf+oStuIwAN3a5EvR7nbuEKwwuLQJJ/pysUmKK
         6OC6wKaKjsRaFtAbHhLR9wpLHjuOrX0jDAWz/V8nUSlvKDqrxcY61wShzm4m6JPUAO1h
         R4isEFJRWL0PVsYAU+/Ybnwwu60uWphhB8DWWvAeYcGq0E0eCKwIq0Tfh7X6TxREGbUy
         mQoPlGnIT876yCijG9keIn7B5W1LMHDfpe6LSEk9QscbZuWomCEbJLTl9oiWfmwEiUoK
         KbyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=qUDqGrOGu3YYikOjMaQ1DoFLgai99KYJPT8TrA5ssq0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=UHnPBldZvxe5pqwJK6R6qnVzapYyavBoWgl+AJh1mk7VtAEP02X7gdmkb9JEBXzkcW
         2DCfQqLWkoe0WHMEedufvaV2nFDvE992WMGXh72N0zl639Up/1oahJbRiIx9LYVYZT9I
         kHs3crVIATPzXNMJibLJUn2Sx5s1Lq7SXbI99UrCtP/tCTrykD7VsUycIJxSJHXwuw/U
         /bQQpzVSnfIQx1rDEpZa2IIHAWtd4Pilq24T7tfU6Wd14HlKjunRTd1UCddAigCweKyy
         1/4V9spQm2NFMuBgtKVMq/VIUP06lJXCtn+vh3NHlE0BLYan385+zkFcDBzig17lBCm5
         Z2Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2 header.b=ZvfOGXlr;
       dkim=pass header.i=@amazonses.com header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=bUlQwXso;
       spf=pass (google.com: domain of 010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) smtp.mailfrom=010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-75.smtp-out.eu-west-1.amazonses.com (b231-75.smtp-out.eu-west-1.amazonses.com. [69.169.231.75])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c03d98b767si287517a12.0.2024.08.26.09.20.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Aug 2024 09:20:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com designates 69.169.231.75 as permitted sender) client-ip=69.169.231.75;
Date: Mon, 26 Aug 2024 16:20:15 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@hisin.org>
Subject: =?UTF-8?Q?Convocatoria_/_Call_for_papers._CONGRESO_INTERNACIONAL_LATINA_DE_?=
 =?UTF-8?Q?COMUNICACI=C3=93N_SOCIAL_2024_(no_presencial)_con_revista_Latina_?=
 =?UTF-8?Q?SCOPUS_Q1?=
Message-ID: <010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: ZaA0zOUT3QIk7ZPynaqVmg
X-FBL: ZaA0zOUT3QIk7ZPynaqVmg-k7MPHMqVFXaeyfU0hp1YPQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_bSMHVvQopzoozlzpqKyu13io7V1yABScqFEJRzBlY"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2024.08.26-69.169.231.75
X-Original-Sender: congresolatina=hisin.org@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=fqytg3s46ckfollo7rpm6uo5etyg5af2
 header.b=ZvfOGXlr;       dkim=pass header.i=@amazonses.com
 header.s=uku4taia5b5tsbglxyj6zym32efj7xqv header.b=bUlQwXso;       spf=pass
 (google.com: domain of 010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com
 designates 69.169.231.75 as permitted sender) smtp.mailfrom=010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000@email.crlsrv.com;
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
--b1_bSMHVvQopzoozlzpqKyu13io7V1yABScqFEJRzBlY
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DZaA0zOUT3QIk7=
ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ]=20
=20
=20
=20
 Congreso Internacional LATINA DE COMUNICACI=C3=93N SOCIAL 2024
=20
=20
 [https://www.email-index.com/click.php?L=3DqUstu3Y5isPkl1iYeLcntA&J=3DZaA0=
zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
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
pacios tem=C3=A1ticos: (https://www.email-index.com/click.php?L=3DoIGIki22F=
ECqc7RKfjlKpA&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3Ddyb=
gAwNZwARmi9SVnjlQzw)
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
 [https://www.email-index.com/click.php?L=3Dh763kR0PffUQSetVaq892Qa3iQ&J=3D=
ZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3Dz8YtEQvYTuUT0w7aKB5QRw&J=3DZa=
A0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
 [https://www.email-index.com/click.php?L=3DfaIPerQGFMb4nh763uSRqe5w&J=3DZa=
A0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DdybgAwNZwARmi9SVnjlQzw]=
=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ] | Actualizar mis dato=
s [https://www.email-index.com/update.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7=
MPHMqVFXaeyfU0hp1YPQ] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine n=C2=BA =
38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-000000%40eu=
-west-1.amazonses.com.

--b1_bSMHVvQopzoozlzpqKyu13io7V1yABScqFEJRzBlY
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=
=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqV=
mg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk=
7MPHMqVFXaeyfU0hp1YPQ');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMq=
VFXaeyfU0hp1YPQ');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHM=
qVFXaeyfU0hp1YPQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DZa=
A0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ');}}</style>
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
ader1">XVI Congreso LATINA 2024 (res&uacute;menes hasta 7/10/2024) organiza=
do por editorial ESIC e HISIN</span><div style=3D"display:none;max-height:0=
px;overflow:hidden;">&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#84=
7;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;</di=
v><table height=3D"" bgcolor=3D" #fdfbfc" width=3D"100%" cellpadding=3D"0" =
cellspacing=3D"0" align=3D"center" class=3D"ui-sortable" style=3D"backgroun=
d-color: rgb(253, 251, 252); border-width: initial; border-style: none; bor=
der-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;">
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
-index.com/view.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3DIVQvRmOKleQFN=
v3znIZCJA&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCb=
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
e=3D"color:#0000FF">XVI CONGRESO INTERNACIONAL LATINA DE COMUNICACI&Oacute;=
N SOCIAL 2024</span> <span style=3D"color:#003366">(</span><span style=3D"c=
olor:#000080">CILCS</span><span style=3D"color:#003366">)</span> </strong>q=
ue se celebrar&aacute; los pr&oacute;ximos d&iacute;as 11, 12 y 13 de dicie=
mbre en modalidad <strong>online</strong>&nbsp;<u><span style=3D"color:#000=
0CD">www.congresolatina.net</span></u><br>
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
evisi&oacute;n por pares ciegos)</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">y, adem&aacute;s, da a elegir entre <span style=3D"color:#0000CD=
"><strong>seis posibilidades de publicaci&oacute;n</strong></span>:</span><=
/li>
</ul>

<ol style=3D"margin-left: 40px;">
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><span style=3D"color:#000000"><strong>Libro de papel</strong> </=
span><span style=3D"color:rgb(0, 51, 102)">con versi&oacute;n electr&oacute=
;nica de la editorial<strong> </strong></span><span style=3D"color:#008000"=
><strong>ESIC</strong></span><span style=3D"color:#00FF00">&nbsp;</span>(<s=
pan style=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;<span style=3D"color:rgb=
(0, 0, 205)"><u>&iacute;ndice SPI General</u></span>). Compuesto por los&nb=
sp;textos aceptados tras&nbsp;revisi&oacute;n de mejora mediante dobles par=
es ciegos por parte del Comit&eacute; Evaluador del Congreso.</span></li>
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
onal Social Sciences Review</strong></span>&nbsp;(EBSCO) Se publicar&aacute=
;&nbsp;un m&aacute;ximo de 6 en 2025 textos&nbsp;tras ser aceptados por el =
Comit&eacute; Editorial de la misma.</li>
	<li style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#008000"><strong>Revista EDU REVIEW, International Edu=
cation and Learning Review</strong></span> (EBSCO).&nbsp;Se publicar&aacute=
;&nbsp;un m&aacute;ximo de 6&nbsp;textos en 2025 tras ser aceptados por el =
Comit&eacute; Editorial de la misma.</li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#000000"><span style=3D"font-size:14px">Si una propues=
ta para una revista no es aceptada,<strong> ser&aacute; publicada&nbsp;</st=
rong></span></span><span style=3D"color:rgb(0, 0, 0)"><span style=3D"font-s=
ize:14px">por<strong>&nbsp;</strong></span></span><span style=3D"color:rgb(=
0, 128, 0)"><span style=3D"font-size:14px"><strong>ESIC</strong></span></sp=
an><span style=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px">, si l=
os autores lo desean, en un libro de papel y electr&oacute;nico</span></spa=
n><span style=3D"color:rgb(0, 0, 0)"><span style=3D"font-size:14px"><strong=
>.</strong></span></span>
</div>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"color:#000000"><span style=3D"font-size:14px"><strong>Se pod=
r&aacute; participar:</strong></span></span>
</div>

<ol>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><span style=3D"font-size:14px"><strong>Enviando un v&iacute;deo (=
emitido el 11 de diciembre)&nbsp;o </strong></span></span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#000000"><span style=3D"font-size:14px"><strong>En directo a trav&eacute;s=
 de zoom (12 o 13 de diciembre)</strong></span></span></li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;">
<span style=3D"color:#0000FF"><span style=3D"font-size:14px"><strong>Fechas=
 clave:</strong></span></span>

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
el&nbsp;<span style=3D"color:#0000FF">7 de octubre</span></span></strong></=
span>
</td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute;n</span>=
</td>
			<td>
<strong><span style=3D"border:1pt none windowtext; font-family:arial,sans-s=
erif; font-size:9pt; line-height:13.8px; padding:0cm">Desde el&nbsp;</span>=
</strong><span style=3D"color:#0000FF"><span style=3D"border:1pt none windo=
wtext; font-family:arial,sans-serif; font-size:9pt; line-height:13.8px; pad=
ding:0cm"><strong>10 de octubre</strong></span></span>
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
<span style=3D"color:#0000FF">25 de octubre</span></span></strong></td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Env&iacute;o de ponencia completa</strong></span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el&nbsp;=
<span style=3D"color:#0000FF">8 de noviembre</span></span></strong></td>
		</tr>
		<tr>
			<td>
<span style=3D"font-family:arial,sans-serif; font-size:12px">Env&iacute;o d=
e v&iacute;deo</span><span style=3D"font-family:arial,sans-serif; font-size=
:12px">&nbsp;para ser emitido el 11 de diciembre o env&iacute;o de correo e=
lectr&oacute;nico informando que desea defender la ponencia en directo el 1=
2 o 13 de diciembre</span>
</td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm">Hasta el <span=
 style=3D"color:#0000FF">15 de noviembre</span></span></strong></td>
		</tr>
		<tr>
			<td><span style=3D"font-family:arial,sans-serif; font-size:12px"><strong=
>Celebraci&oacute;n </strong>(online)</span></td>
			<td><strong><span style=3D"border:1pt none windowtext; font-family:arial=
,sans-serif; font-size:9pt; line-height:13.8px; padding:0cm"><span style=3D=
"color:#0000FF">11, 12&nbsp;</span>y&nbsp;<span style=3D"color:#0000FF">13 =
de diciembre</span></span></strong></td>
		</tr>
	</tbody>
</table>
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
size:14px"><strong>Tel&eacute;fono y&nbsp;WhatsApp (+34) 663 935 312 (de 9 =
a 19 horas de Madrid)</strong><br>
<br>
<strong><span style=3D"color:#FF0000">Un abrazo y &iexcl;&iexcl;SEGUIMOS CO=
MUNICANDO!!</span></strong><br>
<br>
<span style=3D"color:#003366"><strong>Almudena Barrientos-B&aacute;ez</stro=
ng>&nbsp;y <strong>Teresa Pi&ntilde;eiro-Otero</strong><br>
Universidad&nbsp;Complutense y Universidade de la Coru&ntilde;a (Espa&ntild=
e;a)</span><br>
<strong><span style=3D"color:#000080">Directoras del XVI CILCS</span></stro=
ng></span></div>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DmE=
X15uBAwBpow8nOmPOFLg&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;"=
 title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" st=
yle=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: bl=
ock; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-weigh=
t: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; fo=
nt-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ic=
o-facebook-38.jpg" alt=3D"facebook CILCS" class=3D"acre_image_editable"></a=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dsu=
eLrZ12CCxXbQU10hNYpw&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&=
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DPa=
Dlwg3hzl04o298927vud9g&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YP=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block=
;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" =
style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: =
block; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-wei=
ght: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercase; =
font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/=
ico-linkedin-38.jpg" alt=3D"linkedin CILCS" class=3D"acre_image_editable"><=
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
com/unsubscribe.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" =
style=3D"text-decoration: underline; color:#333;"><span>Darme de baja de es=
ta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" style=
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
"><a href=3D"https://www.email-index.com/click.php?L=3DoLlk1h5fxioOtJCbea89=
2dXQ&J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ&F=3DHKFRcCbcnmxm=
c4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"border-st=
yle:none;min-width: initial !important;max-width: initial !important;width:=
 initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/=
user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA 2=
021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DZaA0zOUT3QIk7ZPynaqVmg&C=3Dk7MPHMqVFXaeyfU0hp1YPQ" alt=3D""=
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
om/d/msgid/kasan-dev/010201918f7cf137-2da74f13-3f21-483a-a9fc-22c727840dd2-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/010201918f7cf137-2da74f13-3f21-48=
3a-a9fc-22c727840dd2-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_bSMHVvQopzoozlzpqKyu13io7V1yABScqFEJRzBlY--

