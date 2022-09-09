Return-Path: <kasan-dev+bncBDLJXDHV7QBRBK5L5KMAMGQEZ4J2DHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CA7F5B2B7B
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 03:23:56 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id m2-20020adfc582000000b0021e28acded7sf25097wrg.13
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 18:23:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662686636; cv=pass;
        d=google.com; s=arc-20160816;
        b=qtyz7xmYVovFroAW/yg10q4g0BBehsdLaRpDBmQFcg/5VpEHdACEkhEDK1t8mcOfZj
         QKHAfnqhiDd2O0ix1O/t4ochpmJ22AtyPV/oApMtKPbxpmEwwqmH1W1AUXW8Nt2M250D
         E2CVAedPBs3JN7mOO91gAX5nbvY6sUnD2merxqlnA3uA6BM3dNhq9zvYuuAkFyTjAHv7
         CQAGkgMPOiNR1uooZnlZL/z3RyomlRaPcO0Wk4PnQzs3D5IV3vDaICM3MxObWkv1WF0h
         KrML2EIZc2LlnmuNtnb24rotWubxG8bTqeNpR/K8ch4XvIyjVIKVPWPilNtSMjRaHD4X
         0hrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature;
        bh=bsrwlaFe62Q8Afe28zGc8WKs3YGHIWIy93erqyzGk5Y=;
        b=eaDIdoR7mmBSA7sQDzF7zmwiJ52FGnyDUCPpfn0EgbrnCk0xX2EpG/zLVhcdg+xU0z
         iU/hpD8gTrKpWOHjiwQhFJ2Egd8jBoq1TvP3EcAJHAWauigjr0RLRvsziRcbwzXifN9C
         EC6K5t91hJ4HZKqibh07Cgtg5wKuJwx7LItSz3RkLXk3de/aanc8+afdXtMaQ6sD4K+t
         kC22HB8nbJIdbhP8+VeZj/QQef7xTI2/icIN1ofCB97zVFBB7jtEcBd8BDl7HM+OvA50
         xeS7JwWQgzb+wpmlcGTdkvLxFyBjgczjRTSwkidFrp/NeSLMd6PE1G9B6M+htEJ6iDWj
         A0Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=BpGoWz1O;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Kc7dwoIQ;
       spf=pass (google.com: domain of 010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com designates 69.169.231.76 as permitted sender) smtp.mailfrom=010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:from:to:cc:subject:date;
        bh=bsrwlaFe62Q8Afe28zGc8WKs3YGHIWIy93erqyzGk5Y=;
        b=RgL7Kt1nZSaAht0VFNF2RJc58FOAry8EC1ezqNmfhtSDp4eU+wlN6AhoPsI5s3OsHH
         u+pV6yXQFN0MymODj4UYAxsBkYW7GRjo98B3ma5usHJ4lrnEOz+Srw536BNUZ2GWHhhL
         ApS8Fvk785eaEOgfH8hYDShskwpNQBAkdKPN5W2xlvKP4c9TrktE9RZOENgoqq3AG8L2
         hO/dIKI+uqjC3M/rN7TUie94jud2HRZJMFeGqM+ofJQReEI5evUgtjBGuFti1PyWifed
         aoAiZPdmcqOCXmKMLtmi0K9ZN7wdAJdbADUG29mHAK4L6iia7Tc9MPZ/cWxOxfTa7U+6
         AI6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-gm-message-state:from:to:cc:subject:date;
        bh=bsrwlaFe62Q8Afe28zGc8WKs3YGHIWIy93erqyzGk5Y=;
        b=U8Z6+dXE2l/nYpn9JLmHn+x0aVvEpTPHNwYAFLs1/wXQL+XcZReZ19/bjFKJWbLUZ7
         hvq0rVi2hOM9DB6OJgR2K3ni0idf01IUHv3T7lMMbo6lnDbFgEOYA/vLDIzqv1raZqr0
         yZsyW66C3l44t6DydGZph12iNx7GPChF4q3YV4xPj2PJkxddAZgO8FrbVinnpzVKUnb9
         zb9L2WSUFLxdIWSNvssBOKl5bd4E+IxBaoZkNNEEVnjfJBn5XIH2LqvUGWOP/+SqQBZ+
         50IdVOjLFypC+MulDPKMHQaNRDOx120MM8lY+AOdY1B7i2rVaWgxLVUesG0ZORtTjBti
         9ugw==
X-Gm-Message-State: ACgBeo0mmBa2hSuf63Z5zUGJDnFhHYCUp7z/C9zUL4j97oLysIjpFbup
	lnHy2aZV+odtWd6LLxWj+V4=
X-Google-Smtp-Source: AA6agR4SRyqjj+TiskVEyUo9jDn6VYUFTtCkJb1Mkdxma8u6fyBYld/0utEeZpOMnKW2Ho6sQH98rQ==
X-Received: by 2002:a5d:47a6:0:b0:22a:3764:cdfa with SMTP id 6-20020a5d47a6000000b0022a3764cdfamr2016483wrb.547.1662686635917;
        Thu, 08 Sep 2022 18:23:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6187:0:b0:228:c8fc:9de8 with SMTP id j7-20020a5d6187000000b00228c8fc9de8ls5608311wru.1.-pod-prod-gmail;
 Thu, 08 Sep 2022 18:23:55 -0700 (PDT)
X-Received: by 2002:a5d:4904:0:b0:228:610b:296d with SMTP id x4-20020a5d4904000000b00228610b296dmr6997977wrq.450.1662686634932;
        Thu, 08 Sep 2022 18:23:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662686634; cv=none;
        d=google.com; s=arc-20160816;
        b=xq1oPQMMO0Q8MZIdy8qz8IRcunWbeE6/YgK3ZGJn4BmBvjIuCQSODTjreBTkNklkTE
         pmlTVgzkshGNwFWBthl88oPkp1BjEj8kKAakMr926oVD1lr59ZnxL1zugemuuFdAoIps
         sX6YE3Em0/bg7jaxu+q+HyC/XVYfBIvMNcDwyd1CAhppYVapO1XK1kg5Egppm7Gea2I1
         bIzt94wL2zwvKoOO/rMTAsL10ruVMxTCj22l4Ed4h1kg5lH3+Vm/XQo3A0eVGJET/WHt
         vywlCujBajDFM9jH/redNkSjR4jFCPDI8uyB90UrYdBOY31/1YCL6fWcBhK9HWP4QxtQ
         pN6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=uOvFppUoCfqoSwBsQ8NmHxZFpZNV3cfaoMk7akRQbhQ=;
        b=Wnir80ESeIq1AhJqClqCruo2BYsSEIsw5718+oqkREs6XRf0C9cTg33lya1nciDFqt
         v2wL/4CKkoMuQVSDhv8de1mRwreq8eDaeT09Mu+3MDNO1BqYnKUPYFWoMV4AePoHCqO4
         8FSrMqVZF9RUl1+Mf+f6f1zPDPPK2LjcJO2s34z1UcmN71FWnPUxyFwVp1WRGAsVZQXt
         7qiWvhvH6ZgMMCBsDsBkNxze+5pA++TgLXTZ4qcBaGiqAG8CgqPHtT9esi86ALn3b5nC
         s0mDfGCLSlYl+AP9lzSddaMCvdJcLsFP0Gar4rF3gb0AHkXzad4D//TbgzrQlHjEVaKb
         lVug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw header.b=BpGoWz1O;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Kc7dwoIQ;
       spf=pass (google.com: domain of 010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com designates 69.169.231.76 as permitted sender) smtp.mailfrom=010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=crlsrv.com
Received: from b231-76.smtp-out.eu-west-1.amazonses.com (b231-76.smtp-out.eu-west-1.amazonses.com. [69.169.231.76])
        by gmr-mx.google.com with ESMTPS id fc14-20020a05600c524e00b003a54f1563c9si177553wmb.0.2022.09.08.18.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Sep 2022 18:23:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com designates 69.169.231.76 as permitted sender) client-ip=69.169.231.76;
Date: Fri, 9 Sep 2022 01:23:54 +0000
To: kasan-dev@googlegroups.com
From: "'Historia de los sistemas informativos' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Historia de los sistemas informativos <congresolatina@hisin.org>
Subject: Ampliada Convocatoria / Call for papers / Chamada. Congreso Internacional
 LATINA (no presencial)
Message-ID: <010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: dD9wu8guIRjvqXAGmpemiw
X-FBL: dD9wu8guIRjvqXAGmpemiw-VDTpwwH7M763I3cPLRDSlm3Q
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_ee3GcRGhUm2q0iA66ccfRdrQ71MpH5A2N8smaN0no"
Feedback-ID: 1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2022.09.09-69.169.231.76
X-Original-Sender: congresolatina=hisin.org@crlsrv.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@crlsrv.com header.s=txwjkgz2vsssqqiqln6mfnmzc2o7zyxw
 header.b=BpGoWz1O;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Kc7dwoIQ;       spf=pass
 (google.com: domain of 010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com
 designates 69.169.231.76 as permitted sender) smtp.mailfrom=010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000@email.crlsrv.com;
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
--b1_ee3GcRGhUm2q0iA66ccfRdrQ71MpH5A2N8smaN0no
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://www.campaign-index.com/view.php?J=3DdD9wu8guIRjvq=
XAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q]=20
=20
=20
=20
 Congreso Internacional LATINA DE COMUNICACI=C3=93N SOCIAL 2022
=20
=20
 [https://www.email-index.com/click.php?L=3D892RKnbMhPaafY61892FSPIlpQ&J=3D=
dD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjl=
Qzw]=20
=20
=20
=20
 Estimad@s Amig@s y Colegas:Ampliamos las fechas del XIV CONGRESO INTERNACI=
ONAL LATINA DE COMUNICACI=C3=93N SOCIAL (CILCS) en l=C3=ADnea (no presencia=
l) que se celebrar=C3=A1 los d=C3=ADas 23, 24 y 25 de noviembre www.congres=
olatina.netLos idiomas del congreso son: espa=C3=B1ol, italiano, portugu=C3=
=A9s, ingl=C3=A9s y franc=C3=A9s.Los espacios de trabajo propuestos son act=
uales, interesantes e imprescindibles en una sociedad que cambia cada d=C3=
=ADa y cada vez a mayor velocidad.Espacios tem=C3=A1ticos:
	Educando en comunicaci=C3=B3n: competencias comunicativas en la Educaci=C3=
=B3n Superior	Comunicaci=C3=B3n digital	Nuevas tendencias e investigaci=C3=
=B3n en la comunicaci=C3=B3n	Comunicaci=C3=B3n persuasiva	Comunicaci=C3=B3n=
 empresarial	Comunicaci=C3=B3n especializada	L=C3=ADmites de la comunicaci=
=C3=B3n	Ense=C3=B1anza de la comunicaci=C3=B3n	Propuestas de comunicaciones=
 libres	Paneles Tem=C3=A1ticos (a propuesta de los ponentes con un m=C3=ADn=
imo de 3 textos) Curricularmente CILCS presenta:
	Libro de Actas con ISBN (res=C3=BAmenes aceptados tras revisi=C3=B3n por p=
ares ciegos)y, adem=C3=A1s, da a elegir entre:
	Dos posibilidades de publicaci=C3=B3n. Los autores enviar=C3=A1n sus ponen=
cias completas al ESPACIO TEM=C3=81TICO de su elecci=C3=B3n seg=C3=BAn una =
de estas dos opciones:	Env=C3=ADo para optar a publicaci=C3=B3n en Revista =
Latina de Comunicaci=C3=B3n Social -RLCS- (www.revistalatinacs.org) (Scopus=
 Q-1 y Scimago Q-1). Se publicar=C3=A1n 5 textos en 2023 tras ser aceptados=
 por el Comit=C3=A9 Editorial. Los que no sean aceptados para publicaci=C3=
=B3n en RLCS ser=C3=A1n publicados en un Libro de papel de TECNOS -GRUPO AN=
AYA- (Posibilidad 2=C2=AA).	Cap=C3=ADtulo de libro de papel de la editorial=
 TECNOS -GRUPO ANAYA- (Q-1 en SPI). Todos los textos aceptados tras revisi=
=C3=B3n de mejora por pares ciegos y aquellos que no vayan a ser publicados=
 en RLCS (Posibilidad 1=C2=AA).=E2=80=8BF=C3=B3rmulas de participaci=C3=B3n=
:
Este a=C3=B1o presenta para elegir 2 modalidades de participaci=C3=B3n volu=
ntarias:- Virtual mediante la proyecci=C3=B3n de los v=C3=ADdeos que los po=
nentes env=C3=ADen. D=C3=ADa 23 de noviembre (mi=C3=A9rcoles)- En l=C3=ADne=
a a trav=C3=A9s de videoconferencia en directo. D=C3=ADas 24 y 25 de noviem=
bre (jueves y viernes)Fechas clave:
	Env=C3=ADo de res=C3=BAmenes: Ampliado hasta el 30 de septiembre.	Matricul=
aci=C3=B3n (180 =E2=82=AC por cada autor y cada ponencia): Hasta el 21 de O=
ctubre.	Env=C3=ADo de ponencias: Ampliado hasta el 11 de noviembre.	Celebra=
ci=C3=B3n del congreso: 23, 24 y 25 de noviembre.Visite nuestra web www.con=
gresolatina.net
Correo: congresolatina@hisin.org WhatsApp (+34) 663 965 312Tel=C3=A9fonos (=
+34) 91 512 03 05 y (+34) 615 963 719Un abrazo y a vuestra disposici=C3=B3n=
,Almudena Barrientos-B=C3=A1ezUniversidad Complutense de Madrid (Espa=C3=B1=
a)Directora del XIV Congreso CILCS 2022
=20
 [https://www.email-index.com/click.php?L=3DIfG763UPNH04jfwp9D49o7pg&J=3DdD=
9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3DaE2k72RrCSioGGDoUlDsYA&J=3DdD=
9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjlQz=
w] [https://www.email-index.com/click.php?L=3DBv87scJSzXK1Ik7Z9OJ0QQ&J=3DdD=
9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DdybgAwNZwARmi9SVnjlQz=
w]=20
=20
 	=20
 Darme de baja de esta lista [https://www.email-index.com/unsubscribe.php?J=
=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q] | Actualizar mis da=
tos [https://www.email-index.com/update.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3D=
VDTpwwH7M763I3cPLRDSlm3Q] HISTORIA DE LOS SISTEMAS INFORMATIVOS - Cine n=C2=
=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-000000%40eu=
-west-1.amazonses.com.

--b1_ee3GcRGhUm2q0iA66ccfRdrQ71MpH5A2N8smaN0no
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
www.email-index.com/email_forward_log_pic.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=
=3DVDTpwwH7M763I3cPLRDSlm3Q');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://www.email-index.com/email_forward_log_pic.php?J=3DdD9wu8guIRjvqXAGmpem=
iw&C=3DVDTpwwH7M763I3cPLRDSlm3Q');}
                    blockquote #t20141110{background-image:url('https://www=
.email-index.com/email_forward_log_pic.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DV=
DTpwwH7M763I3cPLRDSlm3Q');}
                    div.gmail_quote{background-image:url('https://www.email=
-index.com/email_forward_log_pic.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH=
7M763I3cPLRDSlm3Q');}
                    div.yahoo_quoted{background-image:url('https://www.emai=
l-index.com/email_forward_log_pic.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpww=
H7M763I3cPLRDSlm3Q');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://www.email-index.com/email_print_log_pic.php?J=3DdD=
9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q');}}</style>
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
ader1">Ampliado Congreso LATINA 2022 (res&uacute;menes hasta 30/09/22) orga=
nizado por editorial TECNOS e HISIN</span><div style=3D"display:none;max-he=
ight:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;=
&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nb=
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
&nbsp;</div><table height=3D"" bgcolor=3D" #fdfbfc" width=3D"100%" cellpadd=
ing=3D"0" cellspacing=3D"0" align=3D"center" class=3D"ui-sortable" style=3D=
"background-color: rgb(253, 251, 252); border-width: initial; border-style:=
 none; border-color: initial; margin-top: 0px; padding: 0px; margin-bottom:=
 0px;">
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
-index.com/view.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q=
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
g: 0px;"><a href=3D"https://www.email-index.com/click.php?L=3DmZN5nGbdCnGmO=
7WfhLxquQ&J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DHKFRc=
Cbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" title=3D=
"Web del XIII CLCS"><img align=3D"absbottom" border=3D"0" id=3D"Imgfull" wi=
dth=3D"280" src=3D"https://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW=
1jUkXDcz7BTAyZIqw/images/LOGO%20LATINA%2022.png?1662508202387" alt=3D"XIII =
CILCS" style=3D"width: 280px; max-width: 280px; text-align: center; font-si=
ze: 18px; color: rgb(255, 255, 255); font-weight: 700; text-shadow: black 0=
.1em 0.1em 0.2em; text-transform: uppercase;" class=3D"acre_image_editable"=
></a></td>
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
Ampliamos las fechas de recepci&oacute;n de res&uacute;menes para el&nbsp;<=
strong><span style=3D"color:#800080">XIV CONGRESO INTERNACIONAL LATINA DE C=
OMUNICACI&Oacute;N SOCIAL </span>(CILCS) en l&iacute;nea (no presencial) </=
strong>que se celebrar&aacute; los d&iacute;as 23, 24 y 25 de noviembre&nbs=
p;<u><span style=3D"color:#0000CD">www.congresolatina.net</span></u><br>
<br>
Los idiomas del congreso son: <strong>espa&ntilde;ol, italiano, portugu&eac=
ute;s, ingl&eacute;s </strong>y<strong> franc&eacute;s</strong>.<br>
<strong>Los&nbsp;espacios de trabajo</strong>&nbsp;propuestos son actuales,=
 interesantes e imprescindibles en una sociedad que cambia cada d&iacute;a =
y cada vez a mayor velocidad.<br>
<br>
<span style=3D"color:#B22222"><strong>Espacios tem&aacute;ticos:</strong></=
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
size:14px">Paneles Tem&aacute;ticos (a propuesta de los ponentes con un m&i=
acute;nimo de 3 textos)</span></li>
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
tar a <strong>publicaci&oacute;n en</strong>&nbsp;<strong><span style=3D"co=
lor:#0000CD">Revista Latina de Comunicaci&oacute;n Social&nbsp;-RLCS-&nbsp;=
</span></strong>(<u><span style=3D"color:#0000CD">www.revistalatinacs.org</=
span></u>) (<span style=3D"color:#FF0000">Scopus Q-1</span>&nbsp;y&nbsp;<sp=
an style=3D"color:#FF0000">Scimago Q-1</span>).&nbsp;<strong>Se publicar&aa=
cute;n 5 textos </strong>en 2023&nbsp;tras ser aceptados por el Comit&eacut=
e; Editorial de la Revista.&nbsp;<strong>Los que no sean aceptados para pub=
licaci&oacute;n en&nbsp;RLCS&nbsp;ser&aacute;n publicados&nbsp;en un Libro&=
nbsp;de</strong>&nbsp;la editorial&nbsp;<strong>TECNOS -GRUPO ANAYA-</stron=
g>&nbsp;(Posibilidad 2&ordf;).</li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><strong><span style=3D"color:#0000CD">Cap&iacute;tulo de libro d=
e papel de la editorial TECNOS -GRUPO ANAYA-</span></strong>&nbsp;(<strong>=
Q-1 </strong>en<strong> SPI</strong>). Todos los textos aceptados tras&nbsp=
;revisi&oacute;n de mejora por pares ciegos&nbsp;y aquellos que no vayan a =
ser publicados en&nbsp;<strong><span style=3D"color:#0000CD">RLCS</span></s=
trong>&nbsp;(Posibilidad 1&ordf;).</span></li>
</ol>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"color=
:#B22222"><span style=3D"font-size:14px"><strong>&#8203;F&oacute;rmulas de =
participaci&oacute;n:</strong></span></span></div>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Este a&ntilde;o presenta<strong>&nbsp;para elegir 2 modalidades =
de participaci&oacute;n&nbsp;voluntarias</strong>:<br>
<br>
-&nbsp;<span style=3D"color:#0000CD"><strong>Virtual</strong></span>&nbsp;m=
ediante la proyecci&oacute;n de los v&iacute;deos que los ponentes env&iacu=
te;en.&nbsp;<strong>D&iacute;a 23 de noviembre&nbsp;(mi&eacute;rcoles)</str=
ong><br>
-&nbsp;<strong><span style=3D"color:#0000CD">En l&iacute;nea&nbsp;</span></=
strong>a trav&eacute;s de videoconferencia en directo. <strong>D&iacute;as =
24 y 25 de noviembre&nbsp;(jueves y viernes)</strong><br>
<br>
<span style=3D"color:#B22222"><strong>Fechas clave:</strong></span></span><=
/div>

<ul>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Env&iacute;o de <strong>res&uacute;menes</strong>: Ampliado hast=
a el 30 de septiembre.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><strong>Matriculaci&oacute;n </strong>(180 &euro; por cada autor=
 y cada ponencia): Hasta el 21 de Octubre.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Env&iacute;o de <strong>ponencias</strong>: Ampliado hasta el 11=
 de noviembre.</span></li>
	<li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px"><strong>Celebraci&oacute;n </strong>del congreso: 23, 24 y 25 de=
 noviembre.</span></li>
</ul>

<div style=3D"line-height: 20px; text-align: justify;">
<br>
<span style=3D"font-size:14px">Visite nuestra web&nbsp;<span style=3D"color=
:#0000CD"><u>www.congresolatina.net</u></span></span>
</div>

<div style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-=
size:14px">Correo:&nbsp;<u><span style=3D"color:#0000CD">congresolatina@his=
in.org</span></u><br>
WhatsApp (+34) 663 965 312<br>
Tel&eacute;fonos (+34) 91 512 03 05 y (+34) 615 963 719<br>
<br>
Un abrazo y a vuestra disposici&oacute;n,<br>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3DWQ=
ZRxBwf1KsxdWqrUA8tiw&J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block=
;" title=3D"Facebook CILCS"><img ac:social=3D"1" border=3D"0" width=3D"38" =
height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38px; border: =
0px; display: block; text-align: left; font-size: 12px; color: rgb(17, 85, =
204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transfor=
m: uppercase; font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront=
.net/news/img/ico-facebook-38.jpg" alt=3D"facebook CUICIID" class=3D"acre_i=
mage_editable"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dp2=
GVc763Wd8892Lk8dnHqxIMvA&J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRD=
Slm3Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: b=
lock;" title=3D"Twitter de CILCS"><img ac:social=3D"1" border=3D"0" width=
=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38px; =
border: 0px; display: block; text-align: left; font-size: 12px; color: rgb(=
17, 85, 204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-=
transform: uppercase; font-family: Arial;" src=3D"https://d1nn1beycom2nr.cl=
oudfront.net/news/img/ico-twitter-38.jpg" alt=3D"" class=3D"acre_image_edit=
able"></a></td>
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
yle=3D"width:38px;"><a href=3D"https://www.email-index.com/click.php?L=3Dme=
pNj1M2Od2GiW7635FJILrg&J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSl=
m3Q&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
ck;" title=3D"Linkedin CILCS"><img ac:social=3D"1" border=3D"0" width=3D"38=
" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38px; border=
: 0px; display: block; text-align: left; font-size: 12px; color: rgb(17, 85=
, 204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transf=
orm: uppercase; font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudfro=
nt.net/news/img/ico-linkedin-38.jpg" alt=3D"" class=3D"acre_image_editable"=
></a></td>
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
com/unsubscribe.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q=
" style=3D"text-decoration: underline; color:#333;"><span>Darme de baja de =
esta lista</span></a> |=20
                                        <a href=3D"https://www.email-index.=
com/update.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q" sty=
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
"><a href=3D"https://www.email-index.com/click.php?L=3DBesevbBh0YD9IORHPw0B=
HQ&J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q&F=3DHKFRcCbcnmxm=
c4f43DJP5g"><img alt=3D"" border=3D"0" style=3D"border-style:none" src=3D"h=
ttps://d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/im=
ages/R_9ea7e3_LINKEDIN LOGO CONGRESO LATINA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>               =20
                        <img src=3D"https://www.email-index.com/email_open_=
log_pic.php?J=3DdD9wu8guIRjvqXAGmpemiw&C=3DVDTpwwH7M763I3cPLRDSlm3Q" alt=3D=
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
om/d/msgid/kasan-dev/010201831fd8a1b2-5822fd7f-7a74-4f43-a6b2-b8a0d9c4e92b-=
000000%40eu-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/010201831fd8a1b2-5822fd7f-7a74-4f=
43-a6b2-b8a0d9c4e92b-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_ee3GcRGhUm2q0iA66ccfRdrQ71MpH5A2N8smaN0no--

