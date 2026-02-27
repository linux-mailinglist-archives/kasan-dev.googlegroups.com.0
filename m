Return-Path: <kasan-dev+bncBCXZRKHG3YOBBSULQTGQMGQEEFLEUZA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id BHsoKVQHoWlLpwQAu9opvQ
	(envelope-from <kasan-dev+bncBCXZRKHG3YOBBSULQTGQMGQEEFLEUZA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 03:54:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1FA51B2204
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 03:54:11 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-65fade0fa54sf1802371a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 18:54:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772160851; cv=pass;
        d=google.com; s=arc-20240605;
        b=dXt5tMXwjfTFroCqhi1xxJUnduR5CjrnrFNiboPHQw+L7Ks91e272EfGMpdsWmv4eU
         FgQCMryGB6bXpUFtio060l197e5TLjZe9TdM9ZegTp6Vtcwm9on2ocAsBO5oiUqKdXRk
         7j8Envfldc0h7WnXjXw0jU2kWsbRE4xhdo+G14PCFutqUCT3KzJBtCKf1ueL7UpR4yBa
         JtCQMeV5bxc52lmSakHCELkGnhX+I8+kfuuO3ws1lugBGP5OQqUmU8Ng/Why//nz/xMM
         4Gw2z45y7sA6g6D+D6SP8w8hXT4LBlzbWCYb6yJvj+C7oGun0GRIP0x1wuk2IQyvDQTP
         Fczg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:sender:dkim-signature;
        bh=l4wp2vAzqJb8rPCMSK+UV3CqE6UJw3TsLaCJjinKmkw=;
        fh=CSpphKpz/6OAgahvlt3xueHns/4zoiQ0EgEeYxiP+b8=;
        b=RPAKZ2Kmv52MilO7NqpdBFDukndctXvE5Ol6882zBbde6rEoZgFca+RDgT2CV7id25
         sNA9cUAH3Odp15zXpiGLYqZlSpmKSin55RNFqNbnF/LH9XyFIIc5+gCo7O4ia+Ft6DZF
         minpNrPy4sSXGauKPqaq4eQzigMsAWGmIunU/VVK/AchHALEg3pAq9XT+1WGkbkYVTGk
         ZlngRNXdfkYeFJD3O+1qwQdpqzaBuqlTeFac8HvzKzXVcRP+wbhEMFljvDky7UlvhprJ
         jRgNcNYursQfOccW31s55B6Om4Zh4lczdt5Y+x4pZvM+6awO3ZZ7RMFcxhLDoaHosiX6
         zVIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@congresoia365.net header.s=7dk25fmq6enelqg6gwuuijkqddeemmzf header.b=Opa7WK7L;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Tcq3PCO2;
       spf=pass (google.com: domain of 0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresoia365.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772160851; x=1772765651; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=l4wp2vAzqJb8rPCMSK+UV3CqE6UJw3TsLaCJjinKmkw=;
        b=Nkoo3YXTkO0jT5nHxtBi7YyWgKgFX7qNqb4J4wnoIw0Q8lJxZ0jXzoz2oOCGdqA7VE
         U+xM5vNicdaj0qF3vdkrHzbZMGST7ciZfrbtAX7xTYHuLznF4bzgnGOUpvzHyZXtPcks
         SfquvJPMFC2ffuBM15CmuLSw8TnBgQUaULdlCC5UqhX4Cz0RR/BUkAWEG+kcSNqE6mS9
         OfEurFyNbXN6k5+4qMqZXCF0Dbq/KtwevrpA3/6fHRi4V0IM7WgVDKgj8FT0sEJ5Vxv8
         I7xB5N39rSyFMXYU7q0cl80CgzgjbT/Oxc6MIog/EdeeYeBfYiCNbzRaAy02qE3rnQOa
         gRFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772160851; x=1772765651;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l4wp2vAzqJb8rPCMSK+UV3CqE6UJw3TsLaCJjinKmkw=;
        b=AQB9EvEydw+Lkj9okR57ZVrXh5Qk+g9RatWgPspg0nBwsDmiBNwxcqu6km+xxRJcfu
         Ugm+nDfHinSplqfqB/Hm9F8LIjp0K4IM0/hBRT/p4xwNgIbYP60gKy9RO4sVcL7J9/Yu
         zqMrfHcpXjm7HXG499pcgNL/+tR6mCpkVujK/HxRFZXA6S//u9wE8Nfmg2ejrAf+bUDk
         pktwKVJpDGsx40HUlgZbj1T0YbHaZTlqdk2PJfcngq8j/NG467bfkS/H9XjtaerXqO1E
         O5KfrQyCtElQja4QNsKZtd3HtNQmSlOP0LRvZxf6TWetj8aJQeZeH7OIh3HMXjRNUEPZ
         dtmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUI7amqUnZS7YJNz+kfx92bRZMcow11kzH6RUZPhnJ81nbQWYXY/SF++Zyy2seKNhoU1DvAjg==@lfdr.de
X-Gm-Message-State: AOJu0YwsBnPWm+6pJbGSFxCBctcfY7+70ZWudFjRrd6vSfUVaOT6UXwA
	ptTo4rwly7abBpFWuC+tXruopuHPrkwqPPL1eOk/MayvgNAhhjaHnkmV
X-Received: by 2002:a17:907:1706:b0:b80:4108:f826 with SMTP id a640c23a62f3a-b9376523d41mr46352566b.36.1772160459440;
        Thu, 26 Feb 2026 18:47:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HE6m4lyRfxd/oo6fbv2at03w8LFrrYey5f081l5xVrMg=="
Received: by 2002:aa7:de06:0:b0:65f:71e6:9fb3 with SMTP id 4fb4d7f45d1cf-65f88d12c97ls1973670a12.1.-pod-prod-06-eu;
 Thu, 26 Feb 2026 18:47:37 -0800 (PST)
X-Received: by 2002:a17:907:97c7:b0:b93:715f:ced with SMTP id a640c23a62f3a-b93763a22c8mr67392166b.18.1772160457058;
        Thu, 26 Feb 2026 18:47:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772160457; cv=none;
        d=google.com; s=arc-20240605;
        b=Sp4YYK8z9gGKGiP0AjMMQ8973Ioj9Gz1v+riHwFYRgRD858ZlaBsVmmlydGCWw+tsX
         wOXDGbcgCtH605htc57EBXMKm5Ncf8SwVWKQRVlAfiUKaHtepVbf1NF6U/IRt4vNttvU
         eC/v8/eMSLvxdu/FHkhHTLZ+BPLfjgozD0BeVJ2Eo5ZU8dVEQKiHmxPsR2ZqH3CM3DMD
         Z1hpCUlpJwYIt0Wy2JqTbrEisEnWWVNWYuW6yee+zX043OSY3obWznV9oN8eN7PUtEqN
         b7UNzLDKH9xqfwfvC8XwVvbfUEwVTy+aVktmmUTi3uiy8/KiOYAVu9VdRXVmB57NeVLZ
         6UMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=w3S8e/twf8u22Na0JBC0wr/Gyco5Ow73U7Z5mwtZhng=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ip51lemZDZJob8kzSXlfrhMg2MGvSnbFI8mtmIyZUGpJWIHjK+N207n8lvecdLk7Sg
         HcJcuaErPBsPrPDfHGq3+9cKm1tha7nIUs2y7sA5raUNNqADY16LHW9wu6oUz+b2Exlw
         7sMgoRluutkcYZ6WhcykbaIW2v2mMjHCyjFAHvX+l2G9PjQ0vqWWpuqBwSh03WuW0PTP
         8KqYLBbPpMNpUeYQBUsHEm5RdLKef1ho6R4SP4wjSwu4aHyhipNSrhFh7S92iMA+Sk1o
         5b5KhFWuIgJwltNqYLK6qPVipdcqQXJNe957v3E50iPgQjd9xBr0q5vSBCdCrOf8z1RB
         5Vbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@congresoia365.net header.s=7dk25fmq6enelqg6gwuuijkqddeemmzf header.b=Opa7WK7L;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Tcq3PCO2;
       spf=pass (google.com: domain of 0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresoia365.net
Received: from a106-73.smtp-out.eu-west-1.amazonses.com (a106-73.smtp-out.eu-west-1.amazonses.com. [54.240.106.73])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65fabe67ceesi81250a12.3.2026.02.26.18.47.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Feb 2026 18:47:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com designates 54.240.106.73 as permitted sender) client-ip=54.240.106.73;
Date: Fri, 27 Feb 2026 02:47:36 +0000
To: kasan-dev@googlegroups.com
From: Historia de los sistemas informativos <contacto@congresoia365.net>
Reply-To: Historia de los sistemas informativos <contacto@congresoia365.net>
Subject: =?UTF-8?Q?Convocatoria/Call_for_papers._CONGRESO_INTERNACIONAL_de_INTELIGEN?=
 =?UTF-8?Q?CIA_ARTIFICIAL_365=C2=BA_(no_presencial)?=
Message-ID: <0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: tDSyMhC1a2BetBmbRE6nvA
X-FBL: tDSyMhC1a2BetBmbRE6nvA-kF6K5qd4mAeEXe7635lLHrEQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_9hSeJIekyWPmuRQBOXdEKMiuryYhICwGwVQiC0hg2M"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2026.02.27-54.240.106.73
X-Original-Sender: contacto@congresoia365.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@congresoia365.net header.s=7dk25fmq6enelqg6gwuuijkqddeemmzf
 header.b=Opa7WK7L;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=Tcq3PCO2;       spf=pass
 (google.com: domain of 0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com
 designates 54.240.106.73 as permitted sender) smtp.mailfrom=0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresoia365.net
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [4.26 / 15.00];
	PHISHING(3.76)[congresoia365.net->congresolatina.net];
	URI_COUNT_ODD(1.00)[41];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	AUTOGEN_PHP_SPAMMY(1.00)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[multipart/alternative,text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[congresoia365.net : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MANY_INVISIBLE_PARTS(0.10)[2];
	HAS_LIST_UNSUB(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_ONE(0.00)[1];
	MIME_TRACE(0.00)[0:+,1:+,2:~];
	GREYLIST(0.00)[pass,body];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_PHPMAILER_SIG(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[contacto@congresoia365.net,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBCXZRKHG3YOBBSULQTGQMGQEEFLEUZA];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	HAS_REPLYTO(0.00)[contacto@congresoia365.net];
	NEURAL_SPAM(0.00)[1.000];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_EQ_FROM(0.00)[]
X-Rspamd-Queue-Id: F1FA51B2204
X-Rspamd-Action: no action

This is a multi-part message in MIME format.
--b1_9hSeJIekyWPmuRQBOXdEKMiuryYhICwGwVQiC0hg2M
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://online.congresolatina.net/view.php?J=3DtDSyMhC1a2=
BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ] I CONGRESO INTERNACIONAL SOBRE I=
NTELIGENCIA ARTIFICIAL CISIA 365=C2=BA=20
 [https://track.congresolatina.net/click.php?L=3DF281ueAFzBBVAk5ww74q2Q&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] Estimad@s amig@s y colegas:Hoy lanzamos el I CONGRESO INTERNACIONAL=
 SOBRE INTELIGENCIA ARTIFICIAL 365=C2=BA (CISIA 365=C2=BA [https://track.co=
ngresolatina.net/click.php?L=3DRPWaqR3HIG0vR70XqB6YfQ&J=3DtDSyMhC1a2BetBmbR=
E6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]) que se cele=
brar=C3=A1 los pr=C3=B3ximos d=C3=ADas 6, 7 y 8 de mayo en modalidad h=C3=
=ADbrida (en l=C3=ADnea y presencial no obligatoria) www.congresoia365.net =
[https://track.congresolatina.net/click.php?L=3DM4LGHQgJ3qDt8dyM3WC17g&J=3D=
tDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjl=
Qzw con Ortega, nuestro Gu=C3=ADa Virtual, quien te responder=C3=A1 con voz=
 humana sobre todo lo que quieras saber del CISIA 365=C2=BA y lo que quiera=
s, lo sabe todo. Mantente informado sobre avances en la Galaxia IA en nuest=
ra pesta=C3=B1a de NOTICIAS SOBRE IA (https://track.congresolatina.net/clic=
k.php?L=3DKR0YLpdUU9U1FXnY1VLbwQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAe=
EXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw) y participa como ponente o asiste=
nte.
CISIA 365=C2=BA [https://track.congresolatina.net/click.php?L=3DZpswHOEtRTW=
XyR7EvkVx892Q&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Dd=
ybgAwNZwARmi9SVnjlQzw] define la IA como la creadora del espacio en el que =
vamos a vivir el futuro por lo que pretende erigirse como un espacio de enc=
uentro entre la realidad social, el =C3=A1mbito acad=C3=A9mico (investigado=
r y docente) y el sector empresarial, con el prop=C3=B3sito de analizar el =
impacto de la Inteligencia Artificial en la ciudadan=C3=ADa, su reflejo en =
la Educaci=C3=B3n Superior de hoy y anticipar las titulaciones de futuro, a=
s=C3=AD como ahondar en sus efectos en la sociedad de la tecnolog=C3=ADa.El=
 evento es h=C3=ADbrido: combina dos jornadas en l=C3=ADnea (directos y v=
=C3=ADdeos) y una presencial en la Facultad de Ciencias de la Informaci=C3=
=B3n de la Universidad Complutense (de asistencia no obligatoria).Durante t=
res d=C3=ADas, profesionales, universidades, empresas tecnol=C3=B3gicas y e=
scuelas de negocio debatir=C3=A1n sobre c=C3=B3mo la IA transformar=C3=A1 l=
a empleabilidad y qu=C3=A9 nuevas competencias deber=C3=A1n incorporarse a =
los planes de estudio, tanto en Estudios T=C3=A9cnicos como en las =C3=A1re=
as de Ciencias Sociales, Salud y Artes y Humanidades. Y todo ello como resp=
uesta a la cuesti=C3=B3n: =C2=BFQu=C3=A9 es y c=C3=B3mo nos ayuda la IA?Los=
 idiomas del congreso son: espa=C3=B1ol, portugu=C3=A9s, ingl=C3=A9s, franc=
=C3=A9s e italiano.Ejes Sin=C3=A1pticos (Mesas Tem=C3=A1ticas): (https://tr=
ack.congresolatina.net/click.php?L=3DunyOUy5woLpJcBZaEUVauw&J=3DtDSyMhC1a2B=
etBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw [https:=
//track.congresolatina.net/click.php?L=3DXMueJ14twsmKhWUqd5e0bw&J=3DtDSyMhC=
1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw])	E=
JE 1 =C2=B7 Formaci=C3=B3n y Academia	EJE 2 =C2=B7 Tecnolog=C3=ADa, Datos y=
 Calidad	EJE 3 =C2=B7 Aplicaciones por dominios	EJE 4 =C2=B7 Mercado, Profe=
siones y Ecosistema	EJE 5 =C2=B7 Perspectiva, Territorio y Normativa	EJE 6 =
=C2=B7 Paneles de propuestas de autores Curricularmente CISIA [https://trac=
k.congresolatina.net/click.php?L=3Dtl3lLbakDa9gNtUx9Jfxbw&J=3DtDSyMhC1a2Bet=
BmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] 365=C2=
=BA [https://track.congresolatina.net/click.php?L=3DhZr5VAxWx3O1phXVt9xziw&=
J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9S=
VnjlQzw] presenta:	Libro electr=C3=B3nico de Actas con ISBN 979-13-87819-07=
-1 (con los res=C3=BAmenes aceptados tras revisi=C3=B3n por pares ciegos) y=
, adem=C3=A1s, da a elegir entre nueve posibilidades de publicaci=C3=B3n:
	Libro electr=C3=B3nico de la editorial ESIC [https://track.congresolatina.=
net/click.php?L=3DLBfUMlKT3HtWcRC2DaUhww&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6=
K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Q1 =C3=ADndice SPI Gener=
al [https://track.congresolatina.net/click.php?L=3Dl5V3KNgfaeA7z6lqBqo68A&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw]). Compuesto por los textos aceptados tras revisi=C3=B3n de mejora m=
ediante dobles pares ciegos por parte del Comit=C3=A9 Evaluador del Congres=
o. Publicable en 2027.	Revista Latina de Comunicaci=C3=B3n Social -RLCS- [h=
ttps://track.congresolatina.net/click.php?L=3DAtTNcvVJbk8tAkQOTyzmRQ&J=3DtD=
SyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQz=
w] (Scopus Q-1, SJR Q-1 y Qualis Capes A1). Se publicar=C3=A1 un m=C3=A1xim=
o de 3 textos en 2027 tras ser aceptados por el Comit=C3=A9 Editorial de la=
 misma.	Revista Palabra Clave [https://track.congresolatina.net/click.php?L=
=3DVICR763GPPajCeyBZq4RwIBA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe76=
35lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (SCOPUS Q2, Red ALyC y Scielo). Se pub=
licar=C3=A1 un m=C3=A1ximo de 2 textos en 2027 tras ser aceptados por el Co=
mit=C3=A9 Editorial de la misma.	Revista de Comunicaci=C3=B3n de la SEECI [=
https://track.congresolatina.net/click.php?L=3Dok9L7632qgs5BrnfqUdUx40Q&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] (ESCI, Sello FECYT, Dialnet Q1 y Qualis Capes A1). Se publicar=C3=
=A1 un m=C3=A1ximo de 3 textos en 2026 tras ser aceptados por el Comit=C3=
=A9 Editorial de la misma.	Revista VIVAT ACADEMIA [https://track.congresola=
tina.net/click.php?L=3D6cqz9SspUNq5YpG6892SrDXw&J=3DtDSyMhC1a2BetBmbRE6nvA&=
C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (ESCI, Sello FECYT=
, Dialnet Q1 y Qualis Capes B2). Se publicar=C3=A1 un m=C3=A1ximo de 3 text=
os en 2026 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	Rev=
ista de Ciencias de la Comunicaci=C3=B3n e Informaci=C3=B3n [https://track.=
congresolatina.net/click.php?L=3Dq03kM6evYRifsPeoyGBH9g&J=3DtDSyMhC1a2BetBm=
bRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Sello FEC=
YT y Dialnet Q1). Se publicar=C3=A1 un m=C3=A1ximo de 3 textos en 2026 tras=
 ser aceptados por el Comit=C3=A9 Editorial de la misma.	Revista SOCIAL REV=
IEW, International Social Sciences Review [https://track.congresolatina.net=
/click.php?L=3DZIMOM76376338KYfcuWGnwCvzw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF=
6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (EBSCO) Se publicar=C3=
=A1 un m=C3=A1ximo de 6 en 2026 textos tras ser aceptados por el Comit=C3=
=A9 Editorial de la misma.	Revista AWARI [https://track.congresolatina.net/=
click.php?L=3DmSPAjFGYRN60njIjiMvvvQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd=
4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Dimensions y Qualis Capes B4=
). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2026 tras ser aceptados =
por el Comit=C3=A9 Editorial de la misma.	Revista Social Sciences in brief =
[https://track.congresolatina.net/click.php?L=3DPsGXjJHXmtB7m58uRxF892XQ&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] (Dimensions). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2026 =
tras ser aceptados por el Comit=C3=A9 Editorial de la misma.	Revista Decisi=
onTech Review [https://track.congresolatina.net/click.php?L=3D8KniauOozHouP=
9Ud892aiIaQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Ddyb=
gAwNZwARmi9SVnjlQzw] (Dimensions). Se publicar=C3=A1 un m=C3=A1ximo de 6 te=
xtos en 2026 tras ser aceptados por el Comit=C3=A9 Editorial de la misma.Si=
 una propuesta para una revista no es aceptada, ser=C3=A1 publicada por ESI=
C [https://track.congresolatina.net/click.php?L=3DeNr4KIeFT5S9BBDtMhi1iw&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw], si los autores lo desean, en un libro electr=C3=B3nico con ISBN.
Se podr=C3=A1 participar voluntariamente en l=C3=ADnea (zoom), diferido (v=
=C3=ADdeo) o presencial (asistencia) (no obligatoria ninguna de las 3 modal=
idades):	En directo a trav=C3=A9s de zoom (6 de mayo) o	Enviando un v=C3=AD=
deo (emitido el 7 de mayo) o	Asistiendo a la jornada en la Facultad de Cien=
cias de la Informaci=C3=B3n (8 de mayo)
Fechas clave:
Env=C3=ADo de resumen (m=C3=A1ximo 1 p=C3=A1gina)
Hasta el 9 de marzo
Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n
Desde el 9 de marzo
Abono de matr=C3=ADcula: (225 =E2=82=AC por cada firmante y por cada ponenc=
ia)
Hasta el 23 de marzo
Env=C3=ADo de ponencia completa (m=C3=A1ximo 14 p=C3=A1ginas)
Hasta el 13 de abril
Env=C3=ADo de correo electr=C3=B3nico informando que desea defender la pone=
ncia en directo el 6 de mayo o env=C3=ADo de v=C3=ADdeo para ser emitido el=
 7 de mayo
Hasta el 17 de abril
Celebraci=C3=B3n (EN L=C3=8DNEA (6 y 7 de mayo) y PRESENCIAL -no obligatori=
o- 8 de mayo)
6, 7 y 8 de mayo
M=C3=A1s informaci=C3=B3n en: www.congresoia365.net 2026cisia365@cisia365.n=
et
Tel=C3=A9fono y WhatsApp (+34) 624 880 374 (de 9 a 19 horas de Madrid)Salud=
os neuronales y un fuerte abrazo sin=C3=A1ptico=20
Juan Pablo Mateos AbarcaUniversidad Complutense de Madrid (Espa=C3=B1a)Dire=
ctor del I CISIA 365=C2=BA
 [https://track.congresolatina.net/click.php?L=3DAiZefHPtuOM72XYAmOj66g&J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] [https://track.congresolatina.net/click.php?L=3DttB892pnSQ9MWt892az=
tQQHZzQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwN=
ZwARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=3DGvWa9Zd7bD=
U1Z7EA4KK4zw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Ddy=
bgAwNZwARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=3DTxKaR=
BLNEtw763OLeQz00gUA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ=
&F=3DdybgAwNZwARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=
=3D0LY763JHXeyuMo0klr23ixvg&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe76=
35lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] Darme de baja de esta lista [https://t=
rack.congresolatina.net/unsubscribe.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K=
5qd4mAeEXe7635lLHrEQ] | Actualizar mis datos [https://track.congresolatina.=
net/update.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ] F=
=C3=93RUM XXI - Cine n=C2=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000%40eu-west-1.ama=
zonses.com.

--b1_9hSeJIekyWPmuRQBOXdEKMiuryYhICwGwVQiC0hg2M
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
track.congresolatina.net/email_forward_log_pic.php?J=3DtDSyMhC1a2BetBmbRE6n=
vA&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://track.congresolatina.net/email_forward_log_pic.php?J=3DtDSyMhC1a2BetBm=
bRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    blockquote #t20141110{background-image:url('https://tra=
ck.congresolatina.net/email_forward_log_pic.php?J=3DtDSyMhC1a2BetBmbRE6nvA&=
C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    div.gmail_quote{background-image:url('https://track.con=
gresolatina.net/email_forward_log_pic.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF=
6K5qd4mAeEXe7635lLHrEQ');}
                    div.yahoo_quoted{background-image:url('https://track.co=
ngresolatina.net/email_forward_log_pic.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3Dk=
F6K5qd4mAeEXe7635lLHrEQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://track.congresolatina.net/email_print_log_pic.php?J=
=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}}</style>
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
ader1">I Congreso CISIA  365&ordm; (res&uacute;menes hasta 9/3/2026) organi=
zado por editorial ESIC y SEECI</span><div style=3D"display:none;max-height=
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
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#=
847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;</div><table height=3D"" bg=
color=3D" #fdfbfc" width=3D"100%" cellpadding=3D"0" cellspacing=3D"0" align=
=3D"center" class=3D"ui-sortable" style=3D"background-color: rgb(253, 251, =
252); border-width: initial; border-style: none; border-color: initial; mar=
gin-top: 0px; padding: 0px; margin-bottom: 0px;"> <tbody> <tr class=3D"bloc=
k_link_browser"> <td width=3D"100%" valign=3D"top" class=3D"" style=3D"back=
ground-color: rgb(253, 251, 252); padding: 0px;"> <table width=3D"580" bord=
er=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" style=3D"marg=
in: 0px auto; width: 580px; " class=3D"main_table "> <tbody><tr> <td class=
=3D"pad_both"> <table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpad=
ding=3D"0" align=3D"center" style=3D""> <tbody><tr> <td> <table width=3D"10=
0%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=
=3D"" style=3D""> <tbody><tr> <td height=3D"25" style=3D"text-align:center;=
 font-size: 11px; color: #b3b3b3; font-family: Helvetica, Arial, sans-serif=
; vertical-align: middle;"> <a href=3D"https://online.congresolatina.net/vi=
ew.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"te=
xt-decoration: underline; color:#333;"><span>Ver en navegador</span></a> </=
td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody=
></table> </td> </tr> <tr class=3D"block_spacer"> <td width=3D"100%" valign=
=3D"top" style=3D"background-color: rgb(253, 251, 252); height: 20px;" clas=
s=3D"" height=3D"20"> <table class=3D"BoxWrap" cellpadding=3D"0" height=3D"=
100%" cellspacing=3D"0" align=3D"center" style=3D"margin:0 auto; height:100=
%"> <tbody><tr> <td height=3D"100%" style=3D"height: 100%; line-height: 20p=
x;"> <table width=3D"580" height=3D"100%" border=3D"0" cellspacing=3D"0" ce=
llpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"height: 100%=
; width: 580px;"> <tbody><tr> <td class=3D"pad_both" style=3D"background-co=
lor: inherit; height: 100%; line-height: 20px;" height=3D"100%"> <table wid=
th=3D"100%" height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0=
" style=3D"height: 100%;  border-width: initial; border-style: none; border=
-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=
=3D""> <tbody><tr> <td width=3D"100%" height=3D"100%" style=3D"display: blo=
ck; height: 100%; line-height: 20px; padding: 0px;">&nbsp;</td> </tr> </tbo=
dy></table> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td>=
 </tr> <tr class=3D"block_seccion"> <td width=3D"100%" valign=3D"top" class=
=3D"" style=3D"background-color: rgb(253, 251, 252);"> <table class=3D"BoxW=
rap" cellpadding=3D"0" cellspacing=3D"0" align=3D"center" style=3D"margin:0=
 auto;"> <tbody><tr> <td> <table width=3D"580" border=3D"0" cellspacing=3D"=
0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"width:5=
80px;"> <tbody><tr> <td style=3D"padding: 4px 20px;  border-width: initial;=
 border-style: none; border-color: initial; margin-top: 0px; margin-bottom:=
 0px;" class=3D""> <table width=3D"100%" border=3D"0" cellspacing=3D"0" cel=
lpadding=3D"0"> <tbody><tr> <td><table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" align=3D"center"> <tbody><tr> <td block=3D"" st=
yle=3D"word-break: break-word; overflow-wrap: break-word; text-align: left;=
 padding-bottom: 3px; font-size: 16px; margin-bottom: 7px; padding-top: 4px=
; font-family: Helvetica, Arial, sans-serif; text-decoration: none; color: =
rgb(69, 72, 78);"> <div style=3D"line-height: 20px; text-align: center;"><s=
pan style=3D"color:#008000"><span style=3D"font-size:16px"><strong>I CONGRE=
SO INTERNACIONAL SOBRE INTELIGENCIA ARTIFICIAL CISIA 365&ordm;&nbsp;</stron=
g></span></span></div> </td></tr> </tbody></table></td> </tr> </tbody></tab=
le> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr><t=
r class=3D"block_logo" style=3D"display: table-row;"> <td width=3D"100%" va=
lign=3D"top" class=3D"" style=3D"background-color: rgb(253, 251, 252);"> <t=
able class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"center"=
 style=3D"margin:0 auto;"> <tbody><tr> <td> <table width=3D"580" border=3D"=
0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table=
" style=3D"width:580px;"> <tbody><tr> <td class=3D"pad_both" style=3D"backg=
round-color: inherit;"> <table width=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0" style=3D" border-width: initial; border-style: none; bo=
rder-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;" cl=
ass=3D""> <tbody><tr> <td style=3D"padding: 0px;"><table width=3D"100%" bor=
der=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center"> <tbody><tr>=
 <td> <table align=3D"center" style=3D"font-size: 13px; font-weight: 400; f=
ont-family: Helvetica, Arial, sans-serif;  border-width: initial; border-st=
yle: none; border-color: initial; padding: 0px; margin: 0px auto;" class=3D=
""> <tbody><tr> <td style=3D"padding: 0px;"><a href=3D"https://track.congre=
solatina.net/click.php?L=3DJEVZ2CKArSfQPyws892SZ6Cw&J=3DtDSyMhC1a2BetBmbRE6=
nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vert=
ical-align: top; display: block;" title=3D"Web del I CISIA 365&ordm;"><img =
align=3D"absbottom" border=3D"0" id=3D"Imgfull" width=3D"280" src=3D"https:=
//d1nn1beycom2nr.cloudfront.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/Logo%20=
para%20multienv%C3%ADo-1.jpg?1772104571806" alt=3D"I CISIA 365&ordm;" style=
=3D"width: 280px; max-width: 280px; text-align: left; font-size: 12px; colo=
r: rgb(17, 85, 204); font-weight: 700; text-shadow: black 0.1em 0.1em 0.2em=
; text-transform: uppercase; font-family: Arial;" class=3D"acre_image_edita=
ble" ac:percent=3D"100"></a></td> </tr> </tbody></table> </td> </tr> </tbod=
y></table></td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> <=
/tr> </tbody></table> </td> </tr> <tr class=3D"block_texto"> <td width=3D"1=
00%" valign=3D"top" class=3D"" style=3D"background-color: rgb(253, 251, 252=
);"> <table class=3D"BoxWrap" cellpadding=3D"0" cellspacing=3D"0" align=3D"=
center" style=3D"margin:0 auto;"> <tbody><tr> <td> <table width=3D"580" bor=
der=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"mai=
n_table" style=3D"width:580px;"> <tbody><tr> <td class=3D"pad_both" style=
=3D"background-color: inherit;"> <table width=3D"100%" border=3D"0" cellspa=
cing=3D"0" cellpadding=3D"0" style=3D"background-color: rgb(255, 255, 255);=
 border: none;  margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=
=3D"" bgcolor=3D" #ffffff"> <tbody><tr> <td style=3D"background-color: rgb(=
255, 255, 255); padding: 0px; width: 20px;" width=3D"20">&nbsp;</td> <td st=
yle=3D"background-color: rgb(255, 255, 255); padding: 0px;"><table width=3D=
"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center"> <=
tbody><tr> <td height=3D"20">&nbsp;</td> </tr> <tr> <td block=3D"" class=3D=
"texto" style=3D"word-break: break-word; overflow-wrap: break-word; font-si=
ze: 13px; line-height: initial; font-family: Helvetica, Arial, sans-serif; =
color: rgb(123, 123, 123);"> <div style=3D"line-height: 20px; text-align: j=
ustify;"> <span style=3D"font-size:12px"><span style=3D"font-family:arial,h=
elvetica,sans-serif"><span style=3D"color:#000000">Estimad@s amig@s y coleg=
as:</span><br> <br> <span style=3D"color:#000000">Hoy lanzamos el</span>&nb=
sp;<strong><span style=3D"color:#008000">I CONGRESO INTERNACIONAL SOBRE INT=
ELIGENCIA ARTIFICIAL 365&ordm;</span> (<u><a href=3D"https://track.congreso=
latina.net/click.php?L=3DnODn892PPTRBAp8eaFMDsxAg&J=3DtDSyMhC1a2BetBmbRE6nv=
A&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g"><span style=3D"c=
olor:#0000CD">CISIA 365&ordm;</span></a></u>)&nbsp;</strong><span style=3D"=
color:#000000">que se celebrar&aacute; los pr&oacute;ximos d&iacute;as <str=
ong>6</strong>,<strong> 7&nbsp;</strong>y<strong> 8 de mayo</strong>&nbsp;e=
n modalidad h&iacute;brida (en l&iacute;nea y presencial no obligatoria)</s=
pan>&nbsp;<u><a href=3D"https://track.congresolatina.net/click.php?L=3DPmNh=
lNGbR93tdg6bjZ4gcA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&=
F=3DHKFRcCbcnmxmc4f43DJP5g"><span style=3D"color:#0000CD">www.congresoia365=
.net</span></a>.</u><br> <br> <span style=3D"color:#000000"><strong>Habla c=
on Ortega, nuestro Gu&iacute;a Virtual, quien te responder&aacute; con voz =
humana sobre todo lo que quieras saber del CISIA 365&ordm; y lo que quieras=
, lo sabe todo. Mantente informado sobre avances en la Galaxia IA&nbsp;</st=
rong></span></span></span><span style=3D"color:#000000"><strong style=3D"fo=
nt-family:arial,helvetica,sans-serif; font-size:12px">en nuestra pesta&ntil=
de;a de NOTICIAS SOBRE IA&nbsp;</strong></span><span style=3D"font-size:12p=
x"><span style=3D"font-family:arial,helvetica,sans-serif"><strong><span sty=
le=3D"color:#000000">&nbsp;</span>(</strong></span></span><u><span style=3D=
"color:#0000CD">https://congresoia365.net/noticias-sobre-ia/</span></u><spa=
n style=3D"color:#000000"><span style=3D"font-size:12px"><span style=3D"fon=
t-family:arial,helvetica,sans-serif"><strong>) y participa como ponente o a=
sistente.</strong></span></span></span> </div> <div style=3D"line-height: 2=
0px; text-align: justify;"> <br> <span style=3D"font-size:12px"><span style=
=3D"font-family:arial,helvetica,sans-serif"><strong><a href=3D"https://trac=
k.congresolatina.net/click.php?L=3Dnl98i7Rg7UvObxqqajjzTg&J=3DtDSyMhC1a2Bet=
BmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=
=3D"_blank"><span style=3D"color:#008000">CISIA 365&ordm;</span></a>&nbsp;<=
/strong><span style=3D"color:#000000">define la </span><strong><span style=
=3D"color:#008000">IA como la creadora del&nbsp;espacio en el que vamos a v=
ivir el futuro</span><span style=3D"color:#000000"> </span></strong><span s=
tyle=3D"color:#000000">por lo que pretende erigirse como un espacio de encu=
entro entre la <strong>realidad social</strong>, el&nbsp;<strong>&aacute;mb=
ito acad&eacute;mico</strong>&nbsp;(investigador y docente) y el&nbsp;<stro=
ng>sector empresarial</strong>, con el prop&oacute;sito de&nbsp;<strong>ana=
lizar el impacto de la Inteligencia Artificial </strong><strong>en la</stro=
ng><strong> ciudadan&iacute;a, su reflejo </strong><strong>en la</strong><s=
trong> Educaci&oacute;n Superior de hoy</strong> y <strong>anticipar las&nb=
sp;titulaciones de futuro</strong>, as&iacute; como ahondar en sus efectos =
<strong>en la sociedad de la tecnolog&iacute;a</strong>.</span><br> <br> <s=
pan style=3D"color:#000000">El evento es h&iacute;brido: combina&nbsp;<stro=
ng>dos jornadas en l&iacute;nea (directos y v&iacute;deos)</strong>&nbsp;y =
una&nbsp;<strong>presencial</strong>&nbsp;en la Facultad de Ciencias de la =
Informaci&oacute;n de la Universidad Complutense (de asistencia no obligato=
ria).<br> <br> Durante tres d&iacute;as, profesionales, universidades, empr=
esas tecnol&oacute;gicas y escuelas de negocio debatir&aacute;n sobre c&oac=
ute;mo la&nbsp;<strong>IA</strong>&nbsp;transformar&aacute; la empleabilida=
d y qu&eacute;&nbsp;<strong>nuevas competencias deber&aacute;n incorporarse=
 a los planes de estudio</strong>, tanto en Estudios T&eacute;cnicos como e=
n las &aacute;reas de Ciencias Sociales, Salud y Artes y Humanidades. Y tod=
o ello como respuesta a la cuesti&oacute;n:&nbsp;</span><span style=3D"colo=
r:#0000CD"><strong>&iquest;Qu&eacute; es y c&oacute;mo nos ayuda la IA?</st=
rong></span><br> <br> <span style=3D"color:#000000">Los idiomas del congres=
o son: <strong>espa&ntilde;ol</strong>, <strong>portugu&eacute;s</strong>,<=
strong> ingl&eacute;s</strong>, <strong>franc&eacute;s&nbsp;</strong>e <str=
ong>italiano</strong>.</span><br> <br> <strong><span style=3D"color:#008000=
">Ejes Sin&aacute;pticos (Mesas Tem&aacute;ticas):</span>&nbsp;</strong>(<a=
 href=3D"https://track.congresolatina.net/click.php?L=3D4kkbcXMRCm4sftxeLev=
vzw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmx=
mc4f43DJP5g"><span style=3D"color:#0000CD">https://congresoia365.net/ejes-s=
inapticos/</span></a>)</span></span> <ol> <li><span style=3D"font-size:12px=
"><span style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"col=
or:#008000"><strong>EJE 1 &middot; Formaci&oacute;n y Academia</strong></sp=
an></span></span></li> <li><span style=3D"font-size:12px"><span style=3D"fo=
nt-family:arial,helvetica,sans-serif"><span style=3D"color:#008000"><strong=
>EJE 2 &middot; Tecnolog&iacute;a, Datos y Calidad</strong></span></span></=
span></li> <li><span style=3D"font-size:12px"><span style=3D"font-family:ar=
ial,helvetica,sans-serif"><span style=3D"color:#008000"><strong>EJE 3 &midd=
ot; Aplicaciones por dominios</strong></span></span></span></li> <li><span =
style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-se=
rif"><span style=3D"color:#008000"><strong>EJE 4 &middot; Mercado, Profesio=
nes y Ecosistema</strong></span></span></span></li> <li><span style=3D"font=
-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span st=
yle=3D"color:#008000"><strong>EJE 5 &middot; Perspectiva, Territorio y Norm=
ativa</strong></span></span></span></li> <li><span style=3D"font-size:12px"=
><span style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"colo=
r:#008000"><strong>EJE 6 &middot; Paneles de propuestas de autores</strong>=
</span></span></span></li> </ol> <span style=3D"font-size:12px"><span style=
=3D"font-family:arial,helvetica,sans-serif"> <strong><span style=3D"color:#=
000000">Curricularmente&nbsp;</span><a href=3D"https://track.congresolatina=
.net/click.php?L=3DegGiVeSTD0RPlZF6Dle763qA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3D=
kF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><spa=
n style=3D"color:#0000CD">CISIA</span></a><a href=3D"https://track.congreso=
latina.net/click.php?L=3DABn8szl7zM08G3Ibd892cJmg&J=3DtDSyMhC1a2BetBmbRE6nv=
A&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank=
"><span style=3D"color:#0000CD">&nbsp;365&ordm;</span></a><span style=3D"co=
lor:#0000CD"> </span></strong><span style=3D"color:#000000">presenta:</span=
></span></span> <ul> <li><span style=3D"font-size:12px"><span style=3D"font=
-family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><strong>L=
ibro electr&oacute;nico de Actas&nbsp;con ISBN</strong>&nbsp;979-13-87819-0=
7-1&nbsp;</span><span style=3D"color:#000000">(con los res&uacute;menes ace=
ptados tras&nbsp;revisi&oacute;n por pares ciegos)</span>&nbsp;<span style=
=3D"color:#000000">y, adem&aacute;s, da a elegir entre</span> <span style=
=3D"color:#0000CD"><strong>nueve posibilidades de publicaci&oacute;n</stron=
g></span>:</span></span></li> </ul> </div> <ol style=3D"margin-left: 40px;"=
> <li style=3D"line-height: 20px; text-align: justify;"><span style=3D"font=
-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span st=
yle=3D"color:#000000"><strong>Libro electr&oacute;nico </strong>de la edito=
rial<strong> </strong></span><a href=3D"https://track.congresolatina.net/cl=
ick.php?L=3DmIaUdFt9pR892G7Sb1763iZ2Yg&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5=
qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span sty=
le=3D"color:#0000FF"><strong>ESIC</strong></span></a><span style=3D"color:#=
00FF00">&nbsp;</span>(<span style=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;=
<a href=3D"https://track.congresolatina.net/click.php?L=3DO7qhjwAtNx3lUMctf=
2t892lA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCb=
cnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:rgb(0, 0, 205)"><u>=
&iacute;ndice SPI General</u></span></a>). <span style=3D"color:#000000">Co=
mpuesto por los&nbsp;textos aceptados tras&nbsp;revisi&oacute;n de mejora m=
ediante dobles pares ciegos por parte del Comit&eacute; Evaluador del Congr=
eso. Publicable en 2027.</span></span></span></li> <li style=3D"line-height=
: 20px; text-align: justify;"><span style=3D"font-size:12px"><span style=3D=
"font-family:arial,helvetica,sans-serif"><a href=3D"https://track.congresol=
atina.net/click.php?L=3DcEOE2j3P7OZ9Xu9LR763PnvQ&J=3DtDSyMhC1a2BetBmbRE6nvA=
&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"=
><span style=3D"color:#A52A2A"><strong>Revista Latina de Comunicaci&oacute;=
n Social&nbsp;-RLCS-</strong></span></a>&nbsp;<strong><span style=3D"color:=
#0000CD">(Scopus Q-1,&nbsp;SJR Q-1 y&nbsp;Qualis Capes A1)</span></strong>.=
&nbsp;<span style=3D"color:#000000">Se publicar&aacute; un m&aacute;ximo de=
&nbsp;3 textos en&nbsp;2027 tras ser aceptados por el Comit&eacute; Editori=
al de la misma.</span></span></span></li> <li style=3D"line-height: 20px; t=
ext-align: justify;"><span style=3D"font-size:12px"><span style=3D"font-fam=
ily:arial,helvetica,sans-serif"><strong style=3D"text-indent:-21.25pt"><u><=
span style=3D"color:rgb(0, 32, 96)"><a href=3D"https://track.congresolatina=
.net/click.php?L=3DefOx3KFryR5OnuJo4Gairw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF=
6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank">Revist=
a Palabra Clave</a></span></u></strong><strong style=3D"text-indent:-21.25p=
t"><span style=3D"color:rgb(0, 32, 96)"> </span></strong><span style=3D"tex=
t-indent:-21.25pt">(</span><strong style=3D"text-indent:-21.25pt"><span sty=
le=3D"color:mediumblue">SCOPUS Q2, Red ALyC y Scielo</span></strong><span s=
tyle=3D"text-indent:-21.25pt">).<span style=3D"color:#000000"> Se publicar&=
aacute; un m&aacute;ximo de 2 textos en 2027 tras ser aceptados por el Comi=
t&eacute; Editorial de la misma.</span></span></span></span></li> <li style=
=3D"line-height: 20px; text-align: justify;"><span style=3D"font-size:12px"=
><span style=3D"font-family:arial,helvetica,sans-serif"><a href=3D"https://=
track.congresolatina.net/click.php?L=3DSGqe3saDPIJFuoGfgqxnQw&J=3DtDSyMhC1a=
2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" targ=
et=3D"_blank"><span style=3D"color:#800080"><strong>Revista de Comunicaci&o=
acute;n de la SEECI</strong></span></a><span style=3D"color:#0000CD"><stron=
g>&nbsp;(ESCI, Sello FECYT, Dialnet Q1 y Qualis Capes A1)</strong></span>.&=
nbsp;<span style=3D"color:#000000">Se publicar&aacute;&nbsp;un m&aacute;xim=
o de 3&nbsp;textos en&nbsp;2026&nbsp;tras ser aceptados por el Comit&eacute=
; Editorial de la misma.</span></span></span></li> <li style=3D"line-height=
: 20px; text-align: justify;"><span style=3D"font-size:12px"><span style=3D=
"font-family:arial,helvetica,sans-serif"><a href=3D"https://track.congresol=
atina.net/click.php?L=3DBjW3b892OdPyFyVyLuOsJRLA&J=3DtDSyMhC1a2BetBmbRE6nvA=
&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"=
><font color=3D"#ff0000"><strong>Revista VIVAT ACADEMIA</strong></font></a>=
&nbsp;<span style=3D"color:#0000CD"><strong>(ESCI, Sello FECYT, Dialnet Q1 =
y Qualis Capes B2)</strong></span>.&nbsp;<span style=3D"color:#000000">Se p=
ublicar&aacute; un m&aacute;ximo de&nbsp;3 textos en 2026 tras ser aceptado=
s por el Comit&eacute; Editorial de la misma.</span></span></span></li> <li=
 style=3D"line-height: 20px; text-align: justify;"><span style=3D"font-size=
:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><a href=3D"ht=
tps://track.congresolatina.net/click.php?L=3D8di51R810JHQ2C5zoGAViQ&J=3DtDS=
yMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g=
" target=3D"_blank"><span style=3D"color:rgb(0, 255, 0)"><strong>Revista de=
 Ciencias de la Comunicaci&oacute;n e Informaci&oacute;n</strong></span></a=
>&nbsp;<span style=3D"color:rgb(0, 0, 0)">(</span><strong><span style=3D"co=
lor:rgb(0, 0, 205)">Sello FECYT y&nbsp;Dialnet Q1</span></strong><span styl=
e=3D"color:rgb(0, 0, 0)">).&nbsp;Se publicar&aacute;&nbsp;un m&aacute;ximo =
de 3&nbsp;textos en 2026 tras ser aceptados por el Comit&eacute; Editorial =
de la misma.</span></span></span></li> <li style=3D"line-height: 20px; text=
-align: justify;"><span style=3D"font-size:12px"><span style=3D"font-family=
:arial,helvetica,sans-serif"><a href=3D"https://track.congresolatina.net/cl=
ick.php?L=3DInMCxnstyoz1sdrCe10QQg&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4m=
AeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=
=3D"color:#FFA500"><strong>Revista SOCIAL REVIEW,&nbsp;International Social=
 Sciences Review</strong></span></a>&nbsp;<span style=3D"color:#000000">(</=
span><span style=3D"color:#0000CD"><strong>EBSCO</strong></span><span style=
=3D"color:#000000">) Se publicar&aacute;&nbsp;un m&aacute;ximo de 6&nbsp;en=
 2026 textos&nbsp;tras ser aceptados por el Comit&eacute; Editorial de la m=
isma.</span></span></span></li> <li style=3D"line-height: 20px; text-align:=
 justify;"><span style=3D"font-size:12px"><span style=3D"font-family:arial,=
helvetica,sans-serif"><a href=3D"https://track.congresolatina.net/click.php=
?L=3D1shHou0Qq2763YR3Sb1kdBnQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe=
7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"col=
or:#00FFFF"><strong>Revista AWARI</strong></span></a><span style=3D"color:#=
000000"> (</span><strong><span style=3D"color:#0000FF">Dimensions y Qualis =
Capes&nbsp;B4</span></strong><span style=3D"color:#000000">). Se publicar&a=
acute; un m&aacute;ximo de 6 textos en 2026 tras ser aceptados por el Comit=
&eacute; Editorial de la misma.</span></span></span></li> <li style=3D"line=
-height: 20px; text-align: justify;"><span style=3D"font-size:12px"><span s=
tyle=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#00800=
0"><a href=3D"https://track.congresolatina.net/click.php?L=3D9wH6G0v91fx489=
2vl42F11Rw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFR=
cCbcnmxmc4f43DJP5g" target=3D"_blank"><strong>Revista Social Sciences in br=
ief</strong></a> </span><span style=3D"color:#000000">(</span><span style=
=3D"color:#0000FF"><strong>Dimensions</strong></span><span style=3D"color:#=
000000">). Se publicar&aacute; un m&aacute;ximo de 6 textos en 2026 tras se=
r aceptados por el Comit&eacute; Editorial de la misma.</span></span></span=
></li> <li style=3D"line-height: 20px; text-align: justify;"><span style=3D=
"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><st=
rong style=3D"text-indent:-21.25pt"><span style=3D"color:rgb(79, 98, 40)"><=
a href=3D"https://track.congresolatina.net/click.php?L=3DTgwlxz9EAsuVrGv44E=
W892mQ&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbc=
nmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#4F6228; mso-style-t=
extfill-fill-alpha:100.0%; mso-style-textfill-fill-color:#4F6228; mso-style=
-textfill-fill-colortransforms:lumm=3D50000; mso-style-textfill-fill-themec=
olor:accent3; mso-themecolor:accent3; mso-themeshade:128">Revista DecisionT=
ech Review</span></a></span></strong><span style=3D"color:black; text-inden=
t:-21.25pt"> (</span><strong style=3D"text-indent:-21.25pt"><span style=3D"=
color:blue">Dimensions</span></strong><span style=3D"color:black; text-inde=
nt:-21.25pt">). </span><span style=3D"color:#000000"><span style=3D"text-in=
dent:-21.25pt">Se publicar&aacute; un m&aacute;ximo de 6 textos en 2026 tra=
s ser aceptados por el Comit&eacute; Editorial de la misma.</span></span></=
span></span></li> </ol> <div style=3D"line-height: 20px; text-align: justif=
y;"><span style=3D"font-size:12px"><span style=3D"font-family:arial,helveti=
ca,sans-serif"><span style=3D"color:#000000"><u><strong>Si una propuesta pa=
ra una revista no es aceptada</strong></u>,<strong> ser&aacute; publicada&n=
bsp;</strong>por<strong>&nbsp;</strong></span><a href=3D"https://track.cong=
resolatina.net/click.php?L=3D1Ky6bLdT39nkmL8IfRcudg&J=3DtDSyMhC1a2BetBmbRE6=
nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_bla=
nk"><span style=3D"color:#0000FF"><strong>ESIC</strong></span></a><span sty=
le=3D"color:#000000">, si los autores&nbsp;lo desean, en un libro&nbsp;elec=
tr&oacute;nico con ISBN<strong>.</strong></span></span></span></div> <div s=
tyle=3D"line-height: 20px; text-align: justify;"> <br> <span style=3D"font-=
size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span sty=
le=3D"color:#000000"><strong>Se podr&aacute; participar voluntariamente en =
l&iacute;nea (zoom), diferido (v&iacute;deo) o presencial (asistencia) (no =
obligatoria ninguna de las 3 modalidades):</strong></span></span></span> <o=
l> <li><span style=3D"font-size:12px"><span style=3D"font-family:arial,helv=
etica,sans-serif"><span style=3D"color:#000000"><strong>En directo a trav&e=
acute;s de zoom (6&nbsp;de mayo) o</strong></span></span></span></li> <li><=
span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sa=
ns-serif"><span style=3D"color:#000000"><strong>Enviando un v&iacute;deo (e=
mitido el 7 de mayo)&nbsp;o</strong></span></span></span></li> <li><span st=
yle=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-seri=
f"><span style=3D"color:#000000"><strong>Asistiendo a la jornada en la Facu=
ltad de Ciencias de la Informaci&oacute;n (8 de mayo)</strong></span></span=
></span></li> </ol> </div> <div style=3D"line-height: 20px; text-align: jus=
tify;"> <span style=3D"font-size:12px"><span style=3D"font-family:arial,hel=
vetica,sans-serif"><span style=3D"color:#0000FF"><strong>Fechas clave:</str=
ong></span></span></span> <table border=3D"1" cellpadding=3D"1" cellspacing=
=3D"1" style=3D"width:750px"> <tbody> <tr> <td><span style=3D"font-size:12p=
x"><span style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"co=
lor:#000000"><strong>Env&iacute;o de resumen (m&aacute;ximo 1 p&aacute;gina=
)</strong></span></span></span></td> <td><span style=3D"font-size:12px"><sp=
an style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#0=
00000"><strong><span style=3D"border:1pt none windowtext; line-height:13.8p=
x; padding:0cm">Hasta</span></strong></span><span style=3D"line-height:13.8=
px"><span style=3D"color:#000000">&nbsp;</span><strong><span style=3D"borde=
r:1pt none windowtext; padding:0cm"><span style=3D"color:#000000">el</span>=
 <span style=3D"color:#0000FF">9&nbsp;de marzo</span></span></strong></span=
></span></span></td> </tr> <tr> <td><span style=3D"font-size:12px"><span st=
yle=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#000000=
"><strong>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute=
;n</span></span></span></td> <td><span style=3D"font-size:12px"><span style=
=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><=
strong><span style=3D"border:1pt none windowtext; line-height:13.8px; paddi=
ng:0cm">Desde el&nbsp;</span></strong></span><span style=3D"color:#0000FF">=
<span style=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm"=
><strong>&nbsp;9 de marzo</strong></span></span></span></span></td> </tr> <=
tr> <td><span style=3D"font-size:12px"><span style=3D"font-family:arial,hel=
vetica,sans-serif"><span style=3D"color:#000000">Abono de&nbsp;<strong styl=
e=3D"font-family:arial,sans-serif; font-size:12px"><span style=3D"border:1p=
t none windowtext; padding:0cm">matr&iacute;cula</span></strong>:&nbsp;(225=
 &euro; por cada firmante y por cada ponencia)</span></span></span></td> <t=
d><span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica=
,sans-serif"><strong><span style=3D"border:1pt none windowtext; line-height=
:13.8px; padding:0cm"><span style=3D"color:#000000">Hasta el </span><span s=
tyle=3D"color:#0000FF">23 de marzo</span></span></strong></span></span></td=
> </tr> <tr> <td><span style=3D"font-size:12px"><span style=3D"font-family:=
arial,helvetica,sans-serif"><strong style=3D"color:rgb(0, 0, 0); font-famil=
y:arial,sans-serif; font-size:12px">Env&iacute;o de ponencia completa (m&aa=
cute;ximo 14 p&aacute;ginas)</strong></span></span></td> <td><span style=3D=
"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><st=
rong><span style=3D"border:1pt none windowtext; line-height:13.8px; padding=
:0cm"><span style=3D"color:#000000">Hasta el&nbsp;</span><span style=3D"col=
or:#0000FF">13 de abril</span></span></strong></span></span></td> </tr> <tr=
> <td><span style=3D"font-size:12px"><span style=3D"font-family:arial,helve=
tica,sans-serif"><span style=3D"color:#000000">Env&iacute;o de&nbsp;<strong=
>correo electr&oacute;nico informando</strong>&nbsp;que desea defender la&n=
bsp;<strong>ponencia en directo</strong>&nbsp;el 6 de mayo&nbsp;o env&iacut=
e;o de&nbsp;<strong style=3D"color:rgb(0, 0, 0)">v&iacute;deo</strong>&nbsp=
;para ser emitido el 7 de mayo</span></span></span></td> <td><span style=3D=
"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><st=
rong><span style=3D"border:1pt none windowtext; line-height:13.8px; padding=
:0cm"><span style=3D"color:#000000">Hasta el</span>&nbsp;<span style=3D"col=
or:#0000FF">17 de abril</span></span></strong></span></span></td> </tr> <tr=
> <td><span style=3D"font-size:12px"><span style=3D"font-family:arial,helve=
tica,sans-serif"><span style=3D"color:#000000"><strong>Celebraci&oacute;n <=
/strong>(<strong>EN L&Iacute;NEA&nbsp;(</strong></span><span style=3D"color=
:#0000CD"><strong>6 y 7 de mayo</strong></span><span style=3D"color:#000000=
"><strong>) y PRESENCIAL -no obligatorio- </strong></span><span style=3D"co=
lor:#0000FF"><strong>8 de mayo</strong></span><span style=3D"color:#000000"=
>)</span></span></span></td> <td><span style=3D"font-size:12px"><span style=
=3D"font-family:arial,helvetica,sans-serif"><strong><span style=3D"border:1=
pt none windowtext; line-height:13.8px; padding:0cm"><span style=3D"color:#=
0000FF">6, 7&nbsp;</span><span style=3D"color:#000000">y</span>&nbsp;<span =
style=3D"color:#0000FF">8 de mayo</span></span></strong></span></span></td>=
 </tr> </tbody> </table> <br> <span style=3D"font-size:12px"><span style=3D=
"font-family:arial,helvetica,sans-serif"><span style=3D"color:#008000"><str=
ong><span style=3D"line-height:115%">M&aacute;s informaci&oacute;n en:&nbsp=
;</span></strong></span></span></span> <div style=3D"line-height:22px;"><sp=
an style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans=
-serif"><span style=3D"color:#0000CD"><u>www.congresoia365.net</u></span><s=
pan style=3D"line-height:115%">&nbsp;</span><br> <u style=3D"font-size:14px=
"><span style=3D"color:#0000CD">2026cisia365@cisia365.net</span></u></span>=
</span></div> </div> <div style=3D"line-height: 20px; text-align: justify;"=
> <span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica=
,sans-serif"><span style=3D"color:#000000"><strong>Tel&eacute;fono y&nbsp;W=
hatsApp (+34) 624 880 374&nbsp;(de 9 a 19&nbsp;horas de Madrid)</strong></s=
pan></span></span><br> <br> <span style=3D"font-size:14px"><span style=3D"f=
ont-family:arial,helvetica,sans-serif"><strong><span style=3D"color:#FF0000=
">Saludos neuronales y un fuerte abrazo&nbsp;sin&aacute;ptico</span></stron=
g></span></span><br> &nbsp;</div> <div style=3D"line-height:16px;"><span st=
yle=3D"font-size:14px"><span style=3D"font-family:arial,helvetica,sans-seri=
f"><span style=3D"color:#008000"><strong>Juan Pablo Mateos Abarca</strong><=
br> Universidad&nbsp;Complutense de Madrid (Espa&ntilde;a)<br> <strong>Dire=
ctor&nbsp;del I CISIA 365&ordm;</strong></span></span></span></div> </td></=
tr> <tr> <td height=3D"20">&nbsp;</td> </tr> </tbody></table></td> <td styl=
e=3D"background-color: rgb(255, 255, 255); padding: 0px; width: 20px;" widt=
h=3D"20">&nbsp;</td> </tr> </tbody></table> </td> </tr> </tbody></table> </=
td> </tr> </tbody></table> </td> </tr><tr class=3D"block_social"> <td valig=
n=3D"top" style=3D""><table width=3D"100%" border=3D"0" cellspacing=3D"0" c=
ellpadding=3D"0" align=3D"center" class=3D"" style=3D""> <tbody><tr> <td al=
ign=3D"center"><table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadd=
ing=3D"0" align=3D"center" class=3D"main_table" style=3D"width:580px;"> <tb=
ody><tr> <td class=3D"pad_both"><table width=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" style=3D"background-color: rgb(255, 255, 255); =
" class=3D""> <tbody><tr> <td width=3D"20" class=3D"hide" style=3D"width:20=
px;">&nbsp;</td> <td><table width=3D"100%" border=3D"0" cellspacing=3D"0" c=
ellpadding=3D"0" align=3D"center"> <tbody><tr> <td height=3D"20">&nbsp;</td=
> </tr> <tr> <td align=3D"center"> <table border=3D"0" cellpadding=3D"0" ce=
llspacing=3D"0" width=3D"100%" style=3D"min-width:100%;"> <tbody><tr> <td a=
lign=3D"center" valign=3D"top"> <table align=3D"center" border=3D"0" cellpa=
dding=3D"0" cellspacing=3D"0"> <tbody><tr> <td align=3D"center" valign=3D"t=
op"> <table align=3D"center" border=3D"0" cellspacing=3D"0" cellpadding=3D"=
0"> <tbody><tr> <td align=3D"center" valign=3D"top"> <table align=3D"left" =
border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;">=
 <tbody><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cell=
spacing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"midd=
le" style=3D"padding:3px"> <table align=3D"left" border=3D"0" cellpadding=
=3D"0" cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valig=
n=3D"middle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.co=
ngresolatina.net/click.php?L=3DhiThFhUtGCtuwCTysXYiHA&J=3DtDSyMhC1a2BetBmbR=
E6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" ve=
rtical-align: top; display: block;" title=3D""><img ac:social=3D"1" border=
=3D"0" width=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; he=
ight: 38px; border: 0px; display: block; text-align: left; font-size: 12px;=
 color: rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2n=
r.cloudfront.net/news/img/ico-facebook-38.jpg" alt=3D"Facebook CISIA 365&or=
dm;" class=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> <=
/tr> </tbody></table> </td> </tr> </tbody></table> </td> <td align=3D"cente=
r" valign=3D"top"> <table align=3D"left" border=3D"0" cellpadding=3D"0" cel=
lspacing=3D"0" style=3D"display:inline;"> <tbody><tr> <td valign=3D"top"> <=
table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"> <tbo=
dy><tr> <td align=3D"left" valign=3D"middle" style=3D"padding:3px"> <table =
align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"">=
 <tbody><tr> <td align=3D"center" valign=3D"middle" width=3D"38" style=3D"w=
idth:38px;"><a href=3D"https://track.congresolatina.net/click.php?L=3D892mZ=
zL892GKMGvzXCZ0kR4Ynw&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHr=
EQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: bloc=
k;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38"=
 style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display:=
 block; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-fa=
mily: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twi=
tter-38.jpg" alt=3D"X de CISIA 365&ordm;" class=3D"acre_image_editable"></a=
></td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tb=
ody></table> </td> <td align=3D"center" valign=3D"top"> <table align=3D"lef=
t" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline=
;"> <tbody><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" c=
ellspacing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"m=
iddle" style=3D"padding:3px;"> <table align=3D"left" border=3D"0" cellpaddi=
ng=3D"0" cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" val=
ign=3D"middle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.=
congresolatina.net/click.php?L=3Dc0rySLblJcrS2UQzqJCl8w&J=3DtDSyMhC1a2BetBm=
bRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" =
vertical-align: top; display: block;" title=3D""><img ac:social=3D"1" borde=
r=3D"0" width=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; h=
eight: 38px; border: 0px; display: block; text-align: left; font-size: 12px=
; color: rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2=
nr.cloudfront.net/news/img/ico-linkedin-38.jpg" alt=3D"Linkedin CISIA 365&o=
rdm;" class=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> =
</tr> </tbody></table> </td> </tr> </tbody></table> </td> <td align=3D"cent=
er" valign=3D"top"> <table align=3D"left" border=3D"0" cellpadding=3D"0" ce=
llspacing=3D"0" style=3D"display:inline;"> <tbody><tr> <td valign=3D"top"> =
<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"> <tb=
ody><tr> <td align=3D"left" valign=3D"middle" style=3D"padding:3px"> <table=
 align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D""=
> <tbody><tr> <td align=3D"center" valign=3D"middle" width=3D"38" style=3D"=
width:38px;"><a href=3D"https://track.congresolatina.net/click.php?L=3DACCK=
7631JieaB7FE0u1892jhfA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLH=
rEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: blo=
ck;" title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38=
" style=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display=
: block; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-f=
amily: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-in=
stagram-38.jpg" alt=3D"Instagram CISIA" class=3D"acre_image_editable"></a><=
/td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbod=
y></table> </td> <td align=3D"center" valign=3D"top"> <table align=3D"left"=
 border=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"=
> <tbody><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cel=
lspacing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"mid=
dle" style=3D"padding:3px"> <table align=3D"left" border=3D"0" cellpadding=
=3D"0" cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valig=
n=3D"middle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.co=
ngresolatina.net/click.php?L=3DFvo2dbU2D6ArB5iSm6m0Rw&J=3DtDSyMhC1a2BetBmbR=
E6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" ve=
rtical-align: top; display: block;" title=3D""><img ac:social=3D"1" border=
=3D"0" width=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; he=
ight: 38px; border: 0px; display: block; text-align: left; font-size: 12px;=
 color: rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2n=
r.cloudfront.net/news/img/ico-youtube-38.jpg" alt=3D"Canal de YOUTUBE CISIA=
 365&ordm;" class=3D"acre_image_editable"></a></td> </tr> </tbody></table> =
</td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbo=
dy></table> </td> </tr> </tbody></table> </td> </tr> </tbody> </table> </td=
> </tr> <tr> <td height=3D"20">&nbsp;</td> </tr> </tbody></table></td> <td =
width=3D"20" class=3D"hide" style=3D"width:20px;">&nbsp;</td> </tr> </tbody=
></table></td> </tr> </tbody></table></td> </tr> </tbody></table></td> </tr=
><tr class=3D"block_spacer"> <td width=3D"100%" valign=3D"top" style=3D"bac=
kground-color: rgb(253, 251, 252);" class=3D""> <table class=3D"BoxWrap" ce=
llpadding=3D"0" height=3D"100%" cellspacing=3D"0" align=3D"center" style=3D=
"margin:0 auto; height:100%"> <tbody><tr> <td height=3D"100%" style=3D"heig=
ht: 100%; line-height:25px"> <table width=3D"580" height=3D"100%" border=3D=
"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_tabl=
e" style=3D"height: 100%; width: 580px;"> <tbody><tr> <td class=3D"pad_both=
" style=3D"background-color: inherit; height:100%" height=3D"100%"> <table =
width=3D"100%" height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=
=3D"0" style=3D"height: 100%;  border-width: initial; border-style: none; b=
order-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;" c=
lass=3D""> <tbody><tr> <td width=3D"100%" height=3D"100%" style=3D"display:=
 block; height: 100%; line-height: 25px; padding: 0px;">&nbsp;</td> </tr> <=
/tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></table> <=
/td> </tr> <tr class=3D"block_links_footer"> <td width=3D"100%" valign=3D"t=
op" class=3D"" style=3D"background-color: rgb(253, 251, 252);"> <table widt=
h=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center"=
 class=3D"main_table " style=3D"margin: 0px auto; width: 580px; "> <tbody><=
tr> <td class=3D"pad_both"> <table width=3D"100%" border=3D"0" cellspacing=
=3D"0" cellpadding=3D"0" align=3D"center" style=3D""> <tbody><tr> <td> <tab=
le width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D=
"center" class=3D"" style=3D" border-width: initial; border-style: none; bo=
rder-color: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;"> <=
tbody><tr> <td height=3D"20" style=3D"text-align: center; font-size: 11px; =
color: rgb(51, 51, 51); font-family: Helvetica, Arial, sans-serif; vertical=
-align: middle; padding: 0px;"> <a href=3D"https://track.congresolatina.net=
/unsubscribe.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ" s=
tyle=3D"text-decoration: underline; color:#333;"><span>Darme de baja de est=
a lista</span></a> | <a href=3D"https://track.congresolatina.net/update.php=
?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"text-dec=
oration: underline; color:#333;"><span>Actualizar mis datos</span></a> <br>=
<br> <span>F&Oacute;RUM XXI - Cine n&ordm; 38. Bajo derecha, 28024, Madrid<=
/span> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr=
> </tbody></table> </td> </tr> <tr class=3D"block_spacer"> <td width=3D"100=
%" valign=3D"top" style=3D"background-color: rgb(253, 251, 252);" class=3D"=
"> <table class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=
=3D"0" align=3D"center" style=3D"margin:0 auto; height:100%"> <tbody><tr> <=
td height=3D"100%" style=3D"height: 100%; line-height:25px"> <table width=
=3D"580" height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" a=
lign=3D"center" class=3D"main_table" style=3D"height: 100%; width: 580px;">=
 <tbody><tr> <td class=3D"pad_both" style=3D"background-color: inherit; hei=
ght:100%" height=3D"100%"> <table width=3D"100%" height=3D"100%" border=3D"=
0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-width=
: initial; border-style: none; border-color: initial; margin-top: 0px; padd=
ing: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr> <td width=3D"100%" h=
eight=3D"100%" style=3D"display: block; height: 100%; line-height: 25px; pa=
dding: 0px;">&nbsp;</td> </tr> </tbody></table> </td> </tr> </tbody></table=
> </td> </tr> </tbody></table> </td> </tr> </tbody> </table>=20
                        <table id=3D"ac_footer_email" width=3D"100%" style=
=3D"width:100%">
                            <tr>
                                <td width=3D"100%" valign=3D"top" align=3D"=
center">
                                    <table width=3D"" align=3D"center">
                                        <tr>
                                            <td style=3D"text-align:center;=
"><a href=3D"https://track.congresolatina.net/click.php?L=3DTTHdvZWoaq2oF2R=
9Fo6YEA&J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCb=
cnmxmc4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"bord=
er-style:none;min-width: initial !important;max-width: initial !important;w=
idth: initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/upl=
oads/user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO LAT=
INA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://track.congresolatina.net/email_=
open_log_pic.php?J=3DtDSyMhC1a2BetBmbRE6nvA&C=3DkF6K5qd4mAeEXe7635lLHrEQ" a=
lt=3D"" border=3D"0" height=3D"1" width=3D"1" style=3D"width:1px;height:1px=
,border:0"/><div id=3D't20141110'></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/0102019c9cfe9729-9d307626-4553-429d-847e-c839c04045a6-000000%40eu=
-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">https://group=
s.google.com/d/msgid/kasan-dev/0102019c9cfe9729-9d307626-4553-429d-847e-c83=
9c04045a6-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_9hSeJIekyWPmuRQBOXdEKMiuryYhICwGwVQiC0hg2M--

