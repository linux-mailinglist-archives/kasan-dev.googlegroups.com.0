Return-Path: <kasan-dev+bncBC2K5BVS2YJBB7W5XTGQMGQETUWVFQQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wL8dMHYwr2mWPQIAu9opvQ
	(envelope-from <kasan-dev+bncBC2K5BVS2YJBB7W5XTGQMGQETUWVFQQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2026 21:41:26 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D3D3240FAC
	for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2026 21:41:26 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5a118530219sf3753989e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2026 13:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1773088885; cv=pass;
        d=google.com; s=arc-20240605;
        b=St92rIrq9QrhrDRkTe06Ds++nKUyRizsy9rfEIa8aGqjvv2vzx3sRcDn12zzevU0r5
         D+B41r1ftfHP1eMOXtK7q0pSIYXwhesP8E6JI1f0WXRusCJtGqMi5YFYMpFuwSS66h7L
         7e7uIivYTzvhfW4KjI3NlMyPADHKMzgBSytXIMCOuuASRb7BqD8VEKqLR1Tb4s5XH93+
         d4R8tTAdGC1jj2FJM8uC9BH2KqTIi2gRdYC38xrkvisQqU9gQhiGeL0Wp5FcA1yMr+Re
         pXhRJJtMaeQeIlbGsHQOZv7NlmS7+Z//5pUC8yTZYYil7aKDY15WK+QGN3zk0ZMGFLuh
         MAAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:sender:dkim-signature;
        bh=IsfD+DFMnYGpwTh7lEqvSU3rgudHLyI3KTbwMJIrRvc=;
        fh=vJwdE3GW/qjI1IW1k8PUVEPLClPPVvtUkJC41ZKmVz0=;
        b=QdAVbO6L5uAUc5zgxFxuobbjEpEBVa7lYj+2MUmsIUVAa1fXwWnF9t/uifS8Wz3qkM
         Iqxbe9mppAezucCewxvmuqFlpGYFqOKmGyuZ2j78f3qhYDP83zCv0dYhPf+WUbif/W2I
         d9it/9LNzAwpsslR7h9giA8MrvDHao2hWfET16ji/nMCzyzDW6bfc+QCwWVaFegZ+jIT
         BpZQuwOCSP14p9dVP0i/As88McOdK1vr2Sfd2ahl0Od0/fvEawgmBErl6rFlZFS1yotw
         XJkuiW2Nx5WAMCnxaJ5c31da/r+vxnFJVTOnilxFxeKX4ys2EsxcfAPBN+sfRE7dVQRN
         iySg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@congresolatina.net header.s=cfhcshbroh67vvzt75zzgfh3x2lcgewe header.b=C+BM5fI0;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=pzZB5IXO;
       spf=pass (google.com: domain of 0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com designates 69.169.231.74 as permitted sender) smtp.mailfrom=0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresolatina.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1773088885; x=1773693685; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IsfD+DFMnYGpwTh7lEqvSU3rgudHLyI3KTbwMJIrRvc=;
        b=Rfz5js3JN3FSKcOj0KBOCfVKKImIE9Jxv0cMuUjt3eAEL0q0ztixjCBuAl+7wVE8pG
         Qw+2cOHGAMqIEXynVgq9A9am44VQNXT9LGBobv0uh99Kzm3n9YWwSxuVxKtvaZoH3ZV4
         ZhUaI9EO6lFtFfowXAWBumrR34KfCw70XCNpYnnSkIruoUoEEIMvCCisIsPIYFJXea4a
         n2i6NSqia7BFEAbmbMocerDUU/TyhLhwNM678ntoAGhm1PUcPfxDwOmjuh5tRMhoaiz+
         olxGQge/LbFIIkKQd8yxpYA5QGj9XfT/Lk5z1Gt1e0UKuudrmKYitQCVwT72bElKtwut
         gtTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1773088885; x=1773693685;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:list-unsubscribe:message-id:subject:reply-to:from:to
         :date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IsfD+DFMnYGpwTh7lEqvSU3rgudHLyI3KTbwMJIrRvc=;
        b=gi7Sw54Vg+D8GjP2BiK41P3g7THIR08f7vtOLu8Ku7FCjOiA9XTARamP6+GsknLF4f
         4f+5YXfbdEjnLRsvvLkbf6/MYqlf/IegqC47okd6qzq7tK5JBIwBCmKzRTv0gi/FuENO
         66rX7rUS+WMuwWRrc/UzGcIsWm2hCe22XFOWE1VJn/W4P+oRolFTm7wg4ZoeMF1Ez58a
         h+lKixn6Jhewgr7wfHSVaNyuujcHHcjlBngBPy+FV8KWw3QPSWXGAPqMcXNa2hFEXN+a
         HAGN3cGue6SoeDLXEMUIgcYQsjF5PV0LW09N8FV/0i33LzoBqkHY6m89zCKV9nrnk9iW
         j6Vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKv52/27fGoQvTh2J8vzZr+8Yc1l5GstrjgYazvUg8r92L6NmD5P7bytawsKnPKYYmYz/sVQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz3RaTeJ95eyK6tio1xJ4+YKuTNfq/ktRS89n2wE6PK3K59IKfC
	rfyjwdnQ3Y3cV7S8EN3QbN+7VsJ62hkljM1dgN95eQlcqili+11hQngj
X-Received: by 2002:a05:6512:1458:20b0:5a1:19ee:3883 with SMTP id 2adb3069b0e04-5a13ccde348mr2758588e87.27.1773088510938;
        Mon, 09 Mar 2026 13:35:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HXQYhYzldCNYWV6NODac2lS3doyWZ7Ew0i1e9f5TAqFA=="
Received: by 2002:a05:6512:33cf:b0:5a1:29e6:12e8 with SMTP id
 2adb3069b0e04-5a12fc765c0ls976544e87.2.-pod-prod-04-eu; Mon, 09 Mar 2026
 13:35:08 -0700 (PDT)
X-Received: by 2002:a05:6512:2308:b0:5a1:4b9f:376d with SMTP id 2adb3069b0e04-5a14b9f37e3mr1231193e87.46.1773088508040;
        Mon, 09 Mar 2026 13:35:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1773088508; cv=none;
        d=google.com; s=arc-20240605;
        b=USWPS2D8bDs2qABcMv1JZKLt1UAexv8cDI4fy+NvMh2pUJd2Kf0Ft/3t2FsrNSk+5c
         fXHNlKOSGHJgyXVv2zaQLuZqfA2oS7Gl+I0j0EPiJ8+mQpdG81fnyV0IiTJ0RV5GIq0L
         7LeMOkatX/iYvzTvSNxSYrxxwgV/6yDuEMBuu15OgvI8MDVOjVstWfqjZspjOJaG7fAy
         kLO/mgOB29FiXGFeWijJLTkqP3WJTsKUpN1HdAameXf6QNR5R9uVjDhyid8rMICRNSqH
         9B3NP+siJMpuzOblOOEBVQot7KqSVcBnzSewsT4C/9FzOQmY5gNQg68OrgeO8nNXKpvA
         /Ahg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:mime-version:list-unsubscribe:message-id:subject
         :reply-to:from:to:date:dkim-signature:dkim-signature;
        bh=FIZK6x8H9JiU1MeCHAPbLpDpnc3Eq4ChUr5qTe0NmeA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=knwj+LEXhhuULyJa76hT/4vIYQwGUpsXKQKL88Au09nWOhzbkYI/Bc/YMxrQFLqwVx
         patMUQ9iUxZeU9e/F09+VTId0vbcW/VgyveV5QMrvRuf1H4DhLkSFr2COszdIW0Ji1ES
         D1mU3IAtV17T3SK/Tx3milhLTVD/JtewsWTJADdZ59nvtUI2CAr0GkP7ZM/GfZsaLEmo
         asKecaRlTeiurOY34Zt2DPJv/abATlRRnJut1PTFCnWvvf3iUPfgnhXT2I8VlDhTkHQv
         tBqtV42E/9ke8KuerzIyXEpPypkI1R2jeG+qjohYh0sjiYPjitOZpFi6AomqU1dw2moG
         5tNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@congresolatina.net header.s=cfhcshbroh67vvzt75zzgfh3x2lcgewe header.b=C+BM5fI0;
       dkim=pass header.i=@amazonses.com header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=pzZB5IXO;
       spf=pass (google.com: domain of 0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com designates 69.169.231.74 as permitted sender) smtp.mailfrom=0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresolatina.net
Received: from b231-74.smtp-out.eu-west-1.amazonses.com (b231-74.smtp-out.eu-west-1.amazonses.com. [69.169.231.74])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5a13d01ad37si236648e87.2.2026.03.09.13.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Mar 2026 13:35:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com designates 69.169.231.74 as permitted sender) client-ip=69.169.231.74;
Date: Mon, 9 Mar 2026 20:35:07 +0000
To: kasan-dev@googlegroups.com
From: Historia de los sistemas informativos <congresolatina@congresolatina.net>
Reply-To: Historia de los sistemas informativos <congresolatina@congresolatina.net>
Subject: =?UTF-8?Q?Ampliaci=C3=B3n_de_fechas_/_Call_for_papers._CONGRESO_INTERNACION?=
 =?UTF-8?Q?AL_SOBRE_INTELIGENCIA_ARTIFICIAL_365=C2=BA_del_2026_(no_presencia?=
 =?UTF-8?Q?l)_organizado_por_revista_Latina_SCOPUS_Q1?=
Message-ID: <0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com>
X-Mailer: Acrelia News
X-Report-Abuse: Please report abuse for this campaign
 here:https://www.acrelianews.com/en/abuse-desk/
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
X-Campaign: AkD4GjH6HWANyVB6zYPRig
X-FBL: AkD4GjH6HWANyVB6zYPRig-kF6K5qd4mAeEXe7635lLHrEQ
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_I9jnX7bBmLJ3N2FitKsAWjzdNOBb7vIrEJasKYrQ"
Feedback-ID: ::1.eu-west-1.CZ8M1ekDyspZjn2D1EMR7t02QsJ1cFLETBnmGgkwErc=:AmazonSES
X-SES-Outgoing: 2026.03.09-69.169.231.74
X-Original-Sender: congresolatina@congresolatina.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@congresolatina.net header.s=cfhcshbroh67vvzt75zzgfh3x2lcgewe
 header.b=C+BM5fI0;       dkim=pass header.i=@amazonses.com
 header.s=ihchhvubuqgjsxyuhssfvqohv7z3u4hn header.b=pzZB5IXO;       spf=pass
 (google.com: domain of 0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com
 designates 69.169.231.74 as permitted sender) smtp.mailfrom=0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000@eu-west-1.amazonses.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=congresolatina.net
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
X-Rspamd-Queue-Id: 4D3D3240FAC
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [3.26 / 15.00];
	PHISHING(3.76)[congresoia365.net->congresolatina.net];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	AUTOGEN_PHP_SPAMMY(1.00)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[multipart/alternative,text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[congresolatina.net : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MANY_INVISIBLE_PARTS(0.10)[2];
	HAS_LIST_UNSUB(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-lf1-x13e.google.com:rdns,mail-lf1-x13e.google.com:helo];
	RCPT_COUNT_ONE(0.00)[1];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+,1:+,2:~];
	TAGGED_FROM(0.00)[bncBC2K5BVS2YJBB7W5XTGQMGQETUWVFQQ];
	NEURAL_SPAM(0.00)[1.000];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[congresolatina@congresolatina.net,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	HAS_PHPMAILER_SIG(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[congresolatina@congresolatina.net];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_EQ_FROM(0.00)[]
X-Rspamd-Action: no action

This is a multi-part message in MIME format.
--b1_I9jnX7bBmLJ3N2FitKsAWjzdNOBb7vIrEJasKYrQ
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ver en navegador [https://online.congresolatina.net/view.php?J=3DAkD4GjH6HW=
ANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ] I CONGRESO INTERNACIONAL SOBRE I=
NTELIGENCIA ARTIFICIAL CISIA 365=C2=BA=20
 [https://track.congresolatina.net/click.php?L=3D7639KnpRFJQGGu763jsMzAvmJg=
&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9=
SVnjlQzw] Estimad@s amig@s y colegas: Ampliamos la fecha de recepci=C3=B3n =
de RES=C3=9AMENES hasta el 16 de marzo para el I CONGRESO INTERNACIONAL SOB=
RE INTELIGENCIA ARTIFICIAL 365=C2=BA (CISIA 365=C2=BA [https://track.congre=
solatina.net/click.php?L=3DTOVoSpXrhfwopOdwXkBxnQ&J=3DAkD4GjH6HWANyVB6zYPRi=
g&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]) que se celebrar=
=C3=A1 los pr=C3=B3ximos d=C3=ADas 6, 7 y 8 de mayo en modalidad h=C3=ADbri=
da (en l=C3=ADnea y presencial no obligatoria) www.congresoia365.net [https=
://track.congresolatina.net/click.php?L=3D22LjCFkj33LL2fIAd3XK8A&J=3DAkD4Gj=
H6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]. =
Habla con Ortega, nuestro Gu=C3=ADa Virtual, quien te responder=C3=A1 con v=
oz humana sobre todo lo que quieras saber del CISIA 365=C2=BA y lo que quie=
ras, lo sabe todo. Mantente informado sobre avances en la Galaxia IA en nue=
stra pesta=C3=B1a de NOTICIAS SOBRE IA (https://track.congresolatina.net/cl=
ick.php?L=3DpZ6yw0OCqJN11fThRpxYCw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4m=
AeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw) y participa como ponente o asis=
tente.=20
 CISIA 365=C2=BA [https://track.congresolatina.net/click.php?L=3DUdbQcDdDou=
oN1evkq8YEuw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Ddy=
bgAwNZwARmi9SVnjlQzw] define la IA como la creadora del espacio en el que v=
amos a vivir el futuro por lo que pretende erigirse como un espacio de encu=
entro entre la realidad social, el =C3=A1mbito acad=C3=A9mico (investigador=
 y docente) y el sector empresarial, con el prop=C3=B3sito de analizar el i=
mpacto de la Inteligencia Artificial en la ciudadan=C3=ADa, su reflejo en l=
a Educaci=C3=B3n Superior de hoy y anticipar las titulaciones de futuro, as=
=C3=AD como ahondar en sus efectos en la sociedad de la tecnolog=C3=ADa. El=
 evento es h=C3=ADbrido: combina dos jornadas en l=C3=ADnea (directos y v=
=C3=ADdeos) y una presencial en la Facultad de Ciencias de la Informaci=C3=
=B3n de la Universidad Complutense (de asistencia no obligatoria), que podr=
=C3=A1 ser seguida por nuestro canal de YOUTUBE [https://track.congresolati=
na.net/click.php?L=3DhBaS892KBo7892YUNZjXu07Otw&J=3DAkD4GjH6HWANyVB6zYPRig&=
C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]. Durante tres d=C3=
=ADas, profesionales, universidades, empresas tecnol=C3=B3gicas y escuelas =
de negocio debatir=C3=A1n sobre c=C3=B3mo la IA transformar=C3=A1 la emplea=
bilidad y qu=C3=A9 nuevas competencias deber=C3=A1n incorporarse a los plan=
es de estudio, tanto en Estudios T=C3=A9cnicos como en las =C3=A1reas de Ci=
encias Sociales, Salud y Artes y Humanidades. Y todo ello como respuesta a =
la cuesti=C3=B3n: =C2=BFQu=C3=A9 es y c=C3=B3mo nos ayuda la IA? Los idioma=
s del congreso son: espa=C3=B1ol, portugu=C3=A9s, ingl=C3=A9s, franc=C3=A9s=
 e italiano. Ejes Sin=C3=A1pticos (Mesas Tem=C3=A1ticas): (https://track.co=
ngresolatina.net/click.php?L=3DjvOmfs9C8pKIAfjG022htQ&J=3DAkD4GjH6HWANyVB6z=
YPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw [https://trac=
k.congresolatina.net/click.php?L=3DyzprXnHpq84PYffGIPEoXQ&J=3DAkD4GjH6HWANy=
VB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw]) EJE 1 =
=C2=B7 Formaci=C3=B3n y Academia EJE 2 =C2=B7 Tecnolog=C3=ADa, Datos y Cali=
dad EJE 3 =C2=B7 Aplicaciones por dominios EJE 4 =C2=B7 Mercado, Profesione=
s y Ecosistema EJE 5 =C2=B7 Perspectiva, Territorio y Normativa EJE 6 =C2=
=B7 Paneles de propuestas de autores Curricularmente CISIA [https://track.c=
ongresolatina.net/click.php?L=3DufAbljsthz2LHm892NIGF763iA&J=3DAkD4GjH6HWAN=
yVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] 365=C2=
=BA [https://track.congresolatina.net/click.php?L=3DohNVoo1r0UOnTGCNdrYizg&=
J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9S=
VnjlQzw] presenta: Libro electr=C3=B3nico de Actas con ISBN 979-13-87819-07=
-1 (con los res=C3=BAmenes aceptados tras revisi=C3=B3n por pares ciegos) y=
, adem=C3=A1s, da a elegir entre nueve posibilidades de publicaci=C3=B3n:=
=20
 Libro electr=C3=B3nico de la editorial ESIC [https://track.congresolatina.=
net/click.php?L=3DJRLOQPHVCaOaEe1X7634KLGA&J=3DAkD4GjH6HWANyVB6zYPRig&C=3Dk=
F6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Q1 =C3=ADndice SPI Gen=
eral [https://track.congresolatina.net/click.php?L=3D3892MrmjKoL5gAKPrdFjCd=
Ow&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARm=
i9SVnjlQzw]). Compuesto por los textos aceptados tras revisi=C3=B3n de mejo=
ra mediante dobles pares ciegos por parte del Comit=C3=A9 Evaluador del Con=
greso. Publicable en 2027. Revista Latina de Comunicaci=C3=B3n Social -RLCS=
- [https://track.congresolatina.net/click.php?L=3DiQ763ue0VPg6E3Lw50lhdwiA&=
J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9S=
VnjlQzw] (Scopus Q-1, SJR Q-1 y Qualis Capes A1). Se publicar=C3=A1 un m=C3=
=A1ximo de 3 textos en 2027 tras ser aceptados por el Comit=C3=A9 Editorial=
 de la misma. Revista Palabra Clave [https://track.congresolatina.net/click=
.php?L=3DTES65JffRuUl763D763BK2ZiKQ&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4=
mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (SCOPUS Q2, Red ALyC y Scielo)=
. Se publicar=C3=A1 un m=C3=A1ximo de 2 textos en 2027 tras ser aceptados p=
or el Comit=C3=A9 Editorial de la misma. Revista de Comunicaci=C3=B3n de la=
 SEECI [https://track.congresolatina.net/click.php?L=3D8rsEcKjF8cVKYpIzHnm0=
Aw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARm=
i9SVnjlQzw] (ESCI, Sello FECYT, Dialnet Q1 y Qualis Capes A1). Se publicar=
=C3=A1 un m=C3=A1ximo de 3 textos en 2026 tras ser aceptados por el Comit=
=C3=A9 Editorial de la misma. Revista VIVAT ACADEMIA [https://track.congres=
olatina.net/click.php?L=3Do7SXWn0dJKIa5GE892wXvIDg&J=3DAkD4GjH6HWANyVB6zYPR=
ig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (ESCI, Sello FE=
CYT, Dialnet Q1 y Qualis Capes B2). Se publicar=C3=A1 un m=C3=A1ximo de 3 t=
extos en 2026 tras ser aceptados por el Comit=C3=A9 Editorial de la misma. =
Revista de Ciencias de la Comunicaci=C3=B3n e Informaci=C3=B3n [https://tra=
ck.congresolatina.net/click.php?L=3DHmTdqdhmb10KpJpTlWJ1yw&J=3DAkD4GjH6HWAN=
yVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Sello =
FECYT y Dialnet Q1). Se publicar=C3=A1 un m=C3=A1ximo de 3 textos en 2026 t=
ras ser aceptados por el Comit=C3=A9 Editorial de la misma. Revista SOCIAL =
REVIEW, International Social Sciences Review [https://track.congresolatina.=
net/click.php?L=3DSY1CrfNVrbOuLXjflPqOBQ&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6=
K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (EBSCO) Se publicar=C3=A1=
 un m=C3=A1ximo de 6 en 2026 textos tras ser aceptados por el Comit=C3=A9 E=
ditorial de la misma. Revista AWARI [https://track.congresolatina.net/click=
.php?L=3DLFVIlzltb763892OkT09LJm892Mg&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5q=
d4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] (Dimensions y Qualis Capes B=
4). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2026 tras ser aceptados=
 por el Comit=C3=A9 Editorial de la misma. Revista Social Sciences in brief=
 [https://track.congresolatina.net/click.php?L=3DLT9utAXidRnZc1kp8FqItg&J=
=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] (Dimensions). Se publicar=C3=A1 un m=C3=A1ximo de 6 textos en 2026 =
tras ser aceptados por el Comit=C3=A9 Editorial de la misma. Revista Decisi=
onTech Review [https://track.congresolatina.net/click.php?L=3DjYkE5phNFto8z=
X5cXVv31A&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgA=
wNZwARmi9SVnjlQzw] (Dimensions). Se publicar=C3=A1 un m=C3=A1ximo de 6 text=
os en 2026 tras ser aceptados por el Comit=C3=A9 Editorial de la misma. Si =
una propuesta para una revista no es aceptada, ser=C3=A1 publicada por ESIC=
 [https://track.congresolatina.net/click.php?L=3DSVI8927px7CZIAlqDZ8JasLw&J=
=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw], si los autores lo desean, en un libro electr=C3=B3nico con ISBN.
 Se podr=C3=A1 participar voluntariamente en l=C3=ADnea (zoom), diferido (v=
=C3=ADdeo) o presencial (asistencia) (no obligatoria ninguna de las 3 modal=
idades): En directo a trav=C3=A9s de zoom (6 de mayo) o Enviando un v=C3=AD=
deo (emitido el 7 de mayo) o Asistiendo a la jornada en la Facultad de Cien=
cias de la Informaci=C3=B3n (8 de mayo)=20
 Fechas clave: Env=C3=ADo de resumen (m=C3=A1ximo 1 p=C3=A1gina) Ampliado h=
asta el 16 de marzo Notificaci=C3=B3n de aceptaci=C3=B3n/denegaci=C3=B3n De=
sde el 9 de marzo Abono de matr=C3=ADcula: (225 =E2=82=AC por cada firmante=
 y por cada ponencia) Hasta el 23 de marzo Env=C3=ADo de ponencia completa =
(m=C3=A1ximo 14 p=C3=A1ginas) Hasta el 13 de abril Env=C3=ADo de correo ele=
ctr=C3=B3nico informando que desea defender la ponencia en directo el 6 de =
mayo o env=C3=ADo de v=C3=ADdeo para ser emitido el 7 de mayo Hasta el 17 d=
e abril Celebraci=C3=B3n (EN L=C3=8DNEA (6 y 7 de mayo) y PRESENCIAL -no ob=
ligatorio- 8 de mayo) 6, 7 y 8 de mayo M=C3=A1s informaci=C3=B3n en: www.co=
ngresoia365.net 2026cisia365@cisia365.net
 Tel=C3=A9fono y WhatsApp (+34) 624 880 374 (de 9 a 19 horas de Madrid) Sal=
udos neuronales y un fuerte abrazo sin=C3=A1ptico=20
 Juan Pablo Mateos Abarca Universidad Complutense de Madrid (Espa=C3=B1a) D=
irector del I CISIA 365=C2=BA
 [https://track.congresolatina.net/click.php?L=3DFo6Cle1Fi763T81QICcCV5sw&J=
=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZwARmi9SV=
njlQzw] [https://track.congresolatina.net/click.php?L=3D6mcl7OrRjzFb9892i1O=
FSN8A&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DdybgAwNZw=
ARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=3DirZaY8wW4e2F=
rMVLvEdHlg&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3Ddybg=
AwNZwARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=3DlggE51H=
jRRcl9vOcnOjQQg&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=
=3DdybgAwNZwARmi9SVnjlQzw] [https://track.congresolatina.net/click.php?L=3D=
L9kJlImex9rqHip892VGXrLw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635l=
LHrEQ&F=3DdybgAwNZwARmi9SVnjlQzw] Darme de baja de esta lista [https://trac=
k.congresolatina.net/unsubscribe.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd=
4mAeEXe7635lLHrEQ] | Actualizar mis datos [https://track.congresolatina.net=
/update.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ] F=C3=
=93RUM XXI - Cine n=C2=BA 38. Bajo derecha, 28024, Madrid

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000%40eu-west-1.ama=
zonses.com.

--b1_I9jnX7bBmLJ3N2FitKsAWjzdNOBb7vIrEJasKYrQ
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w=
3.org/TR/REC-html40/loose.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso=
ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office"><head>
                    <style type=3D'text/css'>
                    div.OutlookMessageHeader{background-image:url('https://=
track.congresolatina.net/email_forward_log_pic.php?J=3DAkD4GjH6HWANyVB6zYPR=
ig&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    table.moz-email-headers-table{background-image:url('htt=
ps://track.congresolatina.net/email_forward_log_pic.php?J=3DAkD4GjH6HWANyVB=
6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    blockquote #t20141110{background-image:url('https://tra=
ck.congresolatina.net/email_forward_log_pic.php?J=3DAkD4GjH6HWANyVB6zYPRig&=
C=3DkF6K5qd4mAeEXe7635lLHrEQ');}
                    div.gmail_quote{background-image:url('https://track.con=
gresolatina.net/email_forward_log_pic.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF=
6K5qd4mAeEXe7635lLHrEQ');}
                    div.yahoo_quoted{background-image:url('https://track.co=
ngresolatina.net/email_forward_log_pic.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3Dk=
F6K5qd4mAeEXe7635lLHrEQ');}
                    </style>                                               =
        =20
                    <style type=3D'text/css'>@media print{#t20141110{backgr=
ound-image: url('https://track.congresolatina.net/email_print_log_pic.php?J=
=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ');}}</style>
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
ader1">I Congreso CISIA  365&ordm; (res&uacute;menes hasta 16/3/2026) organ=
izado por editorial ESIC y SEECI</span><div style=3D"display:none;max-heigh=
t:0px;overflow:hidden;">&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&#847;&zwnj;&nbsp;&#8199;&=
#847;&zwnj;&nbsp;&#8199;</div><table height=3D"" bgcolor=3D" #fdfbfc" width=
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
"> <a href=3D"https://online.congresolatina.net/view.php?J=3DAkD4GjH6HWANyV=
B6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"text-decoration: underline;=
 color:#333;"><span>Ver en navegador</span></a> </td> </tr> </tbody></table=
> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> <tr=
 class=3D"block_spacer"> <td width=3D"100%" valign=3D"top" style=3D"backgro=
und-color: rgb(253, 251, 252); height: 20px;" class=3D"" height=3D"20"> <ta=
ble class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D"0" a=
lign=3D"center" style=3D"margin:0 auto; height:100%"> <tbody><tr> <td heigh=
t=3D"100%" style=3D"height: 100%; line-height: 20px;"> <table width=3D"580"=
 height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"=
center" class=3D"main_table" style=3D"height: 100%; width: 580px;"> <tbody>=
<tr> <td class=3D"pad_both" style=3D"background-color: inherit; height: 100=
%; line-height: 20px;" height=3D"100%"> <table width=3D"100%" height=3D"100=
%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=3D"height: 100%; =
 border-width: initial; border-style: none; border-color: initial; margin-t=
op: 0px; padding: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr> <td wid=
th=3D"100%" height=3D"100%" style=3D"display: block; height: 100%; line-hei=
ght: 20px; padding: 0px;">&nbsp;</td> </tr> </tbody></table> </td> </tr> </=
tbody></table> </td> </tr> </tbody></table> </td> </tr> <tr class=3D"block_=
seccion"> <td width=3D"100%" valign=3D"top" class=3D"" style=3D"background-=
color: rgb(253, 251, 252);"> <table class=3D"BoxWrap" cellpadding=3D"0" cel=
lspacing=3D"0" align=3D"center" style=3D"margin:0 auto;"> <tbody><tr> <td> =
<table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=
=3D"center" class=3D"main_table" style=3D"width:580px;"> <tbody><tr> <td st=
yle=3D"padding: 4px 20px;  border-width: initial; border-style: none; borde=
r-color: initial; margin-top: 0px; margin-bottom: 0px;" class=3D""> <table =
width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0"> <tbody><tr=
> <td><table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0=
" align=3D"center"> <tbody><tr> <td block=3D"" style=3D"word-break: break-w=
ord; overflow-wrap: break-word; text-align: left; padding-bottom: 3px; font=
-size: 16px; margin-bottom: 7px; padding-top: 4px; font-family: Helvetica, =
Arial, sans-serif; text-decoration: none; color: rgb(69, 72, 78);"> <div st=
yle=3D"line-height: 20px; text-align: center;"><span style=3D"color:#008000=
"><span style=3D"font-size:16px"><strong>I CONGRESO INTERNACIONAL SOBRE INT=
ELIGENCIA ARTIFICIAL CISIA 365&ordm;&nbsp;</strong></span></span></div> </t=
d></tr> </tbody></table></td> </tr> </tbody></table> </td> </tr> </tbody></=
table> </td> </tr> </tbody></table> </td> </tr><tr class=3D"block_logo" sty=
le=3D"display: table-row;"> <td width=3D"100%" valign=3D"top" class=3D"" st=
yle=3D"background-color: rgb(253, 251, 252);"> <table class=3D"BoxWrap" cel=
lpadding=3D"0" cellspacing=3D"0" align=3D"center" style=3D"margin:0 auto;">=
 <tbody><tr> <td> <table width=3D"580" border=3D"0" cellspacing=3D"0" cellp=
adding=3D"0" align=3D"center" class=3D"main_table" style=3D"width:580px;"> =
<tbody><tr> <td class=3D"pad_both" style=3D"background-color: inherit;"> <t=
able width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" style=
=3D" border-width: initial; border-style: none; border-color: initial; marg=
in-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D""> <tbody><tr> <td=
 style=3D"padding: 0px;"><table width=3D"100%" border=3D"0" cellspacing=3D"=
0" cellpadding=3D"0" align=3D"center"> <tbody><tr> <td> <table align=3D"cen=
ter" style=3D"font-size: 13px; font-weight: 400; font-family: Helvetica, Ar=
ial, sans-serif;  border-width: initial; border-style: none; border-color: =
initial; padding: 0px; margin: 0px auto;" class=3D""> <tbody><tr> <td style=
=3D"padding: 0px;"><a href=3D"https://track.congresolatina.net/click.php?L=
=3DqYhuAfUT31jAZQiiS6IJLQ&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635=
lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: =
block;" title=3D"Web del I CISIA 365&ordm;"><img align=3D"absbottom" border=
=3D"0" id=3D"Imgfull" width=3D"280" src=3D"https://d1nn1beycom2nr.cloudfron=
t.net/uploads/user/fBxrW1jUkXDcz7BTAyZIqw/Logo%20para%20multienv%C3%ADo-1.j=
pg?1772104571806" alt=3D"I CISIA 365&ordm;" style=3D"width: 280px; max-widt=
h: 280px; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-=
weight: 700; text-shadow: black 0.1em 0.1em 0.2em; text-transform: uppercas=
e; font-family: Arial;" class=3D"acre_image_editable" ac:percent=3D"100"></=
a></td> </tr> </tbody></table> </td> </tr> </tbody></table></td> </tr> </tb=
ody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td=
> </tr> <tr class=3D"block_texto"> <td width=3D"100%" valign=3D"top" class=
=3D"" style=3D"background-color: rgb(253, 251, 252);"> <table class=3D"BoxW=
rap" cellpadding=3D"0" cellspacing=3D"0" align=3D"center" style=3D"margin:0=
 auto;"> <tbody><tr> <td> <table width=3D"580" border=3D"0" cellspacing=3D"=
0" cellpadding=3D"0" align=3D"center" class=3D"main_table" style=3D"width:5=
80px;"> <tbody><tr> <td class=3D"pad_both" style=3D"background-color: inher=
it;"> <table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0=
" style=3D"background-color: rgb(255, 255, 255); border: none;  margin-top:=
 0px; padding: 0px; margin-bottom: 0px;" class=3D"" bgcolor=3D" #ffffff"> <=
tbody><tr> <td style=3D"background-color: rgb(255, 255, 255); padding: 0px;=
 width: 20px;" width=3D"20">&nbsp;</td> <td style=3D"background-color: rgb(=
255, 255, 255); padding: 0px;"><table width=3D"100%" border=3D"0" cellspaci=
ng=3D"0" cellpadding=3D"0" align=3D"center"> <tbody><tr> <td height=3D"20">=
&nbsp;</td> </tr> <tr> <td block=3D"" class=3D"texto" style=3D"word-break: =
break-word; overflow-wrap: break-word; font-size: 13px; line-height: initia=
l; font-family: Helvetica, Arial, sans-serif; color: rgb(123, 123, 123);"> =
<div style=3D"line-height: 20px; text-align: justify;"> <span style=3D"font=
-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span st=
yle=3D"color:#000000">Estimad@s amig@s y colegas:</span></span></span><br> =
<br> <strong><span style=3D"color:#FF0000">Ampliamos</span></strong><span s=
tyle=3D"color:rgb(0, 0, 0)"><strong> </strong>la fecha de&nbsp;recepci&oacu=
te;n de </span><span style=3D"color:#FF0000"><strong>RES&Uacute;MENES hasta=
 el 16 de marzo</strong>&nbsp;</span><span style=3D"color:rgb(0, 0, 0)">par=
a el</span><span style=3D"font-size:12px"><span style=3D"font-family:arial,=
helvetica,sans-serif">&nbsp;<strong><span style=3D"color:#008000">I CONGRES=
O INTERNACIONAL SOBRE INTELIGENCIA ARTIFICIAL 365&ordm;</span> (<u><a href=
=3D"https://track.congresolatina.net/click.php?L=3DrSvyuQAhd892nhmrHY4V8wAA=
&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4=
f43DJP5g"><span style=3D"color:#0000CD">CISIA 365&ordm;</span></a></u>)&nbs=
p;</strong><span style=3D"color:#000000">que se celebrar&aacute; los pr&oac=
ute;ximos d&iacute;as <strong>6</strong>,<strong> 7&nbsp;</strong>y<strong>=
 8 de mayo</strong>&nbsp;en modalidad h&iacute;brida (en l&iacute;nea y pre=
sencial no obligatoria)</span>&nbsp;<u><a href=3D"https://track.congresolat=
ina.net/click.php?L=3DZIbZQgWxhP6RDdwk5EYQiw&J=3DAkD4GjH6HWANyVB6zYPRig&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g"><span style=3D"colo=
r:#0000CD">www.congresoia365.net</span></a>.</u></span></span><br> <br> <sp=
an style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans=
-serif"><span style=3D"color:#FF0000"><strong>Habla con Ortega, nuestro Gu&=
iacute;a Virtual</strong></span><span style=3D"color:#000000"><strong>, qui=
en te responder&aacute; con voz humana sobre todo lo que quieras saber del =
CISIA 365&ordm; y lo que quieras, lo sabe todo. Mantente informado sobre av=
ances en la Galaxia IA&nbsp;</strong></span></span></span><span style=3D"co=
lor:#000000"><strong style=3D"font-family:arial,helvetica,sans-serif; font-=
size:12px">en nuestra pesta&ntilde;a de NOTICIAS SOBRE IA&nbsp;</strong></s=
pan><span style=3D"font-size:12px"><span style=3D"font-family:arial,helveti=
ca,sans-serif"><strong><span style=3D"color:#000000">&nbsp;</span>(</strong=
></span></span><u><span style=3D"color:#0000CD">https://congresoia365.net/n=
oticias-sobre-ia/</span></u><span style=3D"color:#000000"><span style=3D"fo=
nt-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><stron=
g>) y participa como ponente o asistente.</strong></span></span></span> </d=
iv> <div style=3D"line-height: 20px; text-align: justify;"> <br> <span styl=
e=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"=
><strong><a href=3D"https://track.congresolatina.net/click.php?L=3DZgp2dCPb=
rK9aE0yXVjP2dw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3D=
HKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#008000">CIS=
IA 365&ordm;</span></a>&nbsp;</strong><span style=3D"color:#000000">define =
la </span><strong><span style=3D"color:#008000">IA como la creadora del&nbs=
p;espacio en el que vamos a vivir el futuro</span><span style=3D"color:#000=
000"> </span></strong><span style=3D"color:#000000">por lo que pretende eri=
girse como un espacio de encuentro entre la <strong>realidad social</strong=
>, el&nbsp;<strong>&aacute;mbito acad&eacute;mico</strong>&nbsp;(investigad=
or y docente) y el&nbsp;<strong>sector empresarial</strong>, con el prop&oa=
cute;sito de&nbsp;<strong>analizar el impacto de la Inteligencia Artificial=
 </strong><strong>en la</strong><strong> ciudadan&iacute;a, su reflejo </st=
rong><strong>en la</strong><strong> Educaci&oacute;n Superior de hoy</stron=
g> y <strong>anticipar las&nbsp;titulaciones de futuro</strong>, as&iacute;=
 como ahondar en sus efectos <strong>en la sociedad de la tecnolog&iacute;a=
</strong>.</span><br> <br> <span style=3D"color:#000000">El evento es h&iac=
ute;brido: combina&nbsp;<strong>dos jornadas en l&iacute;nea (directos y v&=
iacute;deos)</strong>&nbsp;y una&nbsp;<strong>presencial</strong>&nbsp;en l=
a Facultad de Ciencias de la Informaci&oacute;n de la Universidad Compluten=
se (de asistencia no obligatoria), que podr&aacute; ser seguida por nuestro=
 canal de <a href=3D"https://track.congresolatina.net/click.php?L=3D4N4LnWD=
znHsK72l1JmBJqg&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=
=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank">YOUTUBE</a>.<br> <br> Durante =
tres d&iacute;as, profesionales, universidades, empresas tecnol&oacute;gica=
s y escuelas de negocio debatir&aacute;n sobre c&oacute;mo la&nbsp;<strong>=
IA</strong>&nbsp;transformar&aacute; la empleabilidad y qu&eacute;&nbsp;<st=
rong>nuevas competencias deber&aacute;n incorporarse a los planes de estudi=
o</strong>, tanto en Estudios T&eacute;cnicos como en las &aacute;reas de C=
iencias Sociales, Salud y Artes y Humanidades. Y todo ello como respuesta a=
 la cuesti&oacute;n:&nbsp;</span><span style=3D"color:#0000CD"><strong>&iqu=
est;Qu&eacute; es y c&oacute;mo nos ayuda la IA?</strong></span><br> <br> <=
span style=3D"color:#000000">Los idiomas del congreso son: <strong>espa&nti=
lde;ol</strong>, <strong>portugu&eacute;s</strong>,<strong> ingl&eacute;s</=
strong>, <strong>franc&eacute;s&nbsp;</strong>e <strong>italiano</strong>.<=
/span><br> <br> <strong><span style=3D"color:#008000">Ejes Sin&aacute;ptico=
s (Mesas Tem&aacute;ticas):</span>&nbsp;</strong>(<a href=3D"https://track.=
congresolatina.net/click.php?L=3DCVXT5Za2cZHH6pwwz1Tq8Q&J=3DAkD4GjH6HWANyVB=
6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g"><span styl=
e=3D"color:#0000CD">https://congresoia365.net/ejes-sinapticos/</span></a>)<=
/span></span> <ol> <li><span style=3D"font-size:12px"><span style=3D"font-f=
amily:arial,helvetica,sans-serif"><span style=3D"color:#008000"><strong>EJE=
 1 &middot; Formaci&oacute;n y Academia</strong></span></span></span></li> =
<li><span style=3D"font-size:12px"><span style=3D"font-family:arial,helveti=
ca,sans-serif"><span style=3D"color:#008000"><strong>EJE 2 &middot; Tecnolo=
g&iacute;a, Datos y Calidad</strong></span></span></span></li> <li><span st=
yle=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-seri=
f"><span style=3D"color:#008000"><strong>EJE 3 &middot; Aplicaciones por do=
minios</strong></span></span></span></li> <li><span style=3D"font-size:12px=
"><span style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"col=
or:#008000"><strong>EJE 4 &middot; Mercado, Profesiones y Ecosistema</stron=
g></span></span></span></li> <li><span style=3D"font-size:12px"><span style=
=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#008000"><=
strong>EJE 5 &middot; Perspectiva, Territorio y Normativa</strong></span></=
span></span></li> <li><span style=3D"font-size:12px"><span style=3D"font-fa=
mily:arial,helvetica,sans-serif"><span style=3D"color:#008000"><strong>EJE =
6 &middot; Paneles de propuestas de autores</strong></span></span></span></=
li> </ol> <span style=3D"font-size:12px"><span style=3D"font-family:arial,h=
elvetica,sans-serif"> <strong><span style=3D"color:#000000">Curricularmente=
&nbsp;</span><a href=3D"https://track.congresolatina.net/click.php?L=3D1ZZH=
TupAU763boR093i4T8nQ&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrE=
Q&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#0000C=
D">CISIA</span></a><a href=3D"https://track.congresolatina.net/click.php?L=
=3Djb9SYdcgCmUfF8atla6l7Q&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635=
lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#=
0000CD">&nbsp;365&ordm;</span></a><span style=3D"color:#0000CD"> </span></s=
trong><span style=3D"color:#000000">presenta:</span></span></span> <ul> <li=
><span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,=
sans-serif"><span style=3D"color:#000000"><strong>Libro electr&oacute;nico =
de Actas&nbsp;con ISBN</strong>&nbsp;979-13-87819-07-1&nbsp;</span><span st=
yle=3D"color:#000000">(con los res&uacute;menes aceptados tras&nbsp;revisi&=
oacute;n por pares ciegos)</span>&nbsp;<span style=3D"color:#000000">y, ade=
m&aacute;s, da a elegir entre</span> <span style=3D"color:#0000CD"><strong>=
nueve posibilidades de publicaci&oacute;n</strong></span>:</span></span></l=
i> </ul> </div> <ol style=3D"margin-left: 40px;"> <li style=3D"line-height:=
 20px; text-align: justify;"><span style=3D"font-size:12px"><span style=3D"=
font-family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><stro=
ng>Libro electr&oacute;nico </strong>de la editorial<strong> </strong></spa=
n><a href=3D"https://track.congresolatina.net/click.php?L=3D033Y8JzNmiEtDkg=
848wfAw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCb=
cnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#0000FF"><strong>ES=
IC</strong></span></a><span style=3D"color:#00FF00">&nbsp;</span>(<span sty=
le=3D"color:rgb(0, 51, 102)">Q1</span>&nbsp;<a href=3D"https://track.congre=
solatina.net/click.php?L=3Dl6FpESUQ8V0V4L7639X892TC1w&J=3DAkD4GjH6HWANyVB6z=
YPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_b=
lank"><span style=3D"color:rgb(0, 0, 205)"><u>&iacute;ndice SPI General</u>=
</span></a>). <span style=3D"color:#000000">Compuesto por los&nbsp;textos a=
ceptados tras&nbsp;revisi&oacute;n de mejora mediante dobles pares ciegos p=
or parte del Comit&eacute; Evaluador del Congreso. Publicable en 2027.</spa=
n></span></span></li> <li style=3D"line-height: 20px; text-align: justify;"=
><span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,=
sans-serif"><a href=3D"https://track.congresolatina.net/click.php?L=3DNz0XX=
xSg892eBJgAR1fHMZ9A&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ=
&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#A52A2A=
"><strong>Revista Latina de Comunicaci&oacute;n Social&nbsp;-RLCS-</strong>=
</span></a>&nbsp;<strong><span style=3D"color:#0000CD">(Scopus Q-1,&nbsp;SJ=
R Q-1 y&nbsp;Qualis Capes A1)</span></strong>.&nbsp;<span style=3D"color:#0=
00000">Se publicar&aacute; un m&aacute;ximo de&nbsp;3 textos en&nbsp;2027 t=
ras ser aceptados por el Comit&eacute; Editorial de la misma.</span></span>=
</span></li> <li style=3D"line-height: 20px; text-align: justify;"><span st=
yle=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-seri=
f"><strong style=3D"text-indent:-21.25pt"><u><span style=3D"color:rgb(0, 32=
, 96)"><a href=3D"https://track.congresolatina.net/click.php?L=3DEYwAPpccJy=
xWjyRKdGr9Ng&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHK=
FRcCbcnmxmc4f43DJP5g" target=3D"_blank">Revista Palabra Clave</a></span></u=
></strong><strong style=3D"text-indent:-21.25pt"><span style=3D"color:rgb(0=
, 32, 96)"> </span></strong><span style=3D"text-indent:-21.25pt">(</span><s=
trong style=3D"text-indent:-21.25pt"><span style=3D"color:mediumblue">SCOPU=
S Q2, Red ALyC y Scielo</span></strong><span style=3D"text-indent:-21.25pt"=
>).<span style=3D"color:#000000"> Se publicar&aacute; un m&aacute;ximo de 2=
 textos en 2027 tras ser aceptados por el Comit&eacute; Editorial de la mis=
ma.</span></span></span></span></li> <li style=3D"line-height: 20px; text-a=
lign: justify;"><span style=3D"font-size:12px"><span style=3D"font-family:a=
rial,helvetica,sans-serif"><a href=3D"https://track.congresolatina.net/clic=
k.php?L=3DPhZe892qukFlQrLVUg892JDJ7Q&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd=
4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=
=3D"color:#800080"><strong>Revista de Comunicaci&oacute;n de la SEECI</stro=
ng></span></a><span style=3D"color:#0000CD"><strong>&nbsp;(ESCI, Sello FECY=
T, Dialnet Q1 y Qualis Capes A1)</strong></span>.&nbsp;<span style=3D"color=
:#000000">Se publicar&aacute;&nbsp;un m&aacute;ximo de 3&nbsp;textos en&nbs=
p;2026&nbsp;tras ser aceptados por el Comit&eacute; Editorial de la misma.<=
/span></span></span></li> <li style=3D"line-height: 20px; text-align: justi=
fy;"><span style=3D"font-size:12px"><span style=3D"font-family:arial,helvet=
ica,sans-serif"><a href=3D"https://track.congresolatina.net/click.php?L=3Dn=
w1ZwVqNch1ChciiEA825Q&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHr=
EQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><font color=3D"#ff0000"><s=
trong>Revista VIVAT ACADEMIA</strong></font></a>&nbsp;<span style=3D"color:=
#0000CD"><strong>(ESCI, Sello FECYT, Dialnet Q1 y Qualis Capes B2)</strong>=
</span>.&nbsp;<span style=3D"color:#000000">Se publicar&aacute; un m&aacute=
;ximo de&nbsp;3 textos en 2026 tras ser aceptados por el Comit&eacute; Edit=
orial de la misma.</span></span></span></li> <li style=3D"line-height: 20px=
; text-align: justify;"><span style=3D"font-size:12px"><span style=3D"font-=
family:arial,helvetica,sans-serif"><a href=3D"https://track.congresolatina.=
net/click.php?L=3D892pYcdLbW5STdPobjmATy763w&J=3DAkD4GjH6HWANyVB6zYPRig&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><=
span style=3D"color:rgb(0, 255, 0)"><strong>Revista de Ciencias de la Comun=
icaci&oacute;n e Informaci&oacute;n</strong></span></a>&nbsp;<span style=3D=
"color:rgb(0, 0, 0)">(</span><strong><span style=3D"color:rgb(0, 0, 205)">S=
ello FECYT y&nbsp;Dialnet Q1</span></strong><span style=3D"color:rgb(0, 0, =
0)">).&nbsp;Se publicar&aacute;&nbsp;un m&aacute;ximo de 3&nbsp;textos en 2=
026 tras ser aceptados por el Comit&eacute; Editorial de la misma.</span></=
span></span></li> <li style=3D"line-height: 20px; text-align: justify;"><sp=
an style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans=
-serif"><a href=3D"https://track.congresolatina.net/click.php?L=3DrWjryon89=
21yoEysC5jEWXCA&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=
=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#FFA500">=
<strong>Revista SOCIAL REVIEW,&nbsp;International Social Sciences Review</s=
trong></span></a>&nbsp;<span style=3D"color:#000000">(</span><span style=3D=
"color:#0000CD"><strong>EBSCO</strong></span><span style=3D"color:#000000">=
) Se publicar&aacute;&nbsp;un m&aacute;ximo de 6&nbsp;en 2026 textos&nbsp;t=
ras ser aceptados por el Comit&eacute; Editorial de la misma.</span></span>=
</span></li> <li style=3D"line-height: 20px; text-align: justify;"><span st=
yle=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-seri=
f"><a href=3D"https://track.congresolatina.net/click.php?L=3Dhe5wYjclu0763q=
gMad0sIyEQ&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFR=
cCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"color:#00FFFF"><strong=
>Revista AWARI</strong></span></a><span style=3D"color:#000000"> (</span><s=
trong><span style=3D"color:#0000FF">Dimensions y Qualis Capes&nbsp;B4</span=
></strong><span style=3D"color:#000000">). Se publicar&aacute; un m&aacute;=
ximo de 6 textos en 2026 tras ser aceptados por el Comit&eacute; Editorial =
de la misma.</span></span></span></li> <li style=3D"line-height: 20px; text=
-align: justify;"><span style=3D"font-size:12px"><span style=3D"font-family=
:arial,helvetica,sans-serif"><span style=3D"color:#008000"><a href=3D"https=
://track.congresolatina.net/click.php?L=3DjcnZjwRsnRCJ6OKw8aMymQ&J=3DAkD4Gj=
H6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" t=
arget=3D"_blank"><strong>Revista Social Sciences in brief</strong></a> </sp=
an><span style=3D"color:#000000">(</span><span style=3D"color:#0000FF"><str=
ong>Dimensions</strong></span><span style=3D"color:#000000">). Se publicar&=
aacute; un m&aacute;ximo de 6 textos en 2026 tras ser aceptados por el Comi=
t&eacute; Editorial de la misma.</span></span></span></li> <li style=3D"lin=
e-height: 20px; text-align: justify;"><span style=3D"font-size:12px"><span =
style=3D"font-family:arial,helvetica,sans-serif"><strong style=3D"text-inde=
nt:-21.25pt"><span style=3D"color:rgb(79, 98, 40)"><a href=3D"https://track=
.congresolatina.net/click.php?L=3DEYXU892fQDMTUjadq892bkaXjg&J=3DAkD4GjH6HW=
ANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" targe=
t=3D"_blank"><span style=3D"color:#4F6228; mso-style-textfill-fill-alpha:10=
0.0%; mso-style-textfill-fill-color:#4F6228; mso-style-textfill-fill-colort=
ransforms:lumm=3D50000; mso-style-textfill-fill-themecolor:accent3; mso-the=
mecolor:accent3; mso-themeshade:128">Revista DecisionTech Review</span></a>=
</span></strong><span style=3D"color:black; text-indent:-21.25pt"> (</span>=
<strong style=3D"text-indent:-21.25pt"><span style=3D"color:blue">Dimension=
s</span></strong><span style=3D"color:black; text-indent:-21.25pt">). </spa=
n><span style=3D"color:#000000"><span style=3D"text-indent:-21.25pt">Se pub=
licar&aacute; un m&aacute;ximo de 6 textos en 2026 tras ser aceptados por e=
l Comit&eacute; Editorial de la misma.</span></span></span></span></li> </o=
l> <div style=3D"line-height: 20px; text-align: justify;"><span style=3D"fo=
nt-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span =
style=3D"color:#000000"><u><strong>Si una propuesta para una revista no es =
aceptada</strong></u>,<strong> ser&aacute; publicada&nbsp;</strong>por<stro=
ng>&nbsp;</strong></span><a href=3D"https://track.congresolatina.net/click.=
php?L=3Da9Mu0mHKfDiQgXF3HgT7Jg&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEX=
e7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" target=3D"_blank"><span style=3D"co=
lor:#0000FF"><strong>ESIC</strong></span></a><span style=3D"color:#000000">=
, si los autores&nbsp;lo desean, en un libro&nbsp;electr&oacute;nico con IS=
BN<strong>.</strong></span></span></span></div> <div style=3D"line-height: =
20px; text-align: justify;"> <br> <span style=3D"font-size:12px"><span styl=
e=3D"font-family:arial,helvetica,sans-serif"><span style=3D"color:#000000">=
<strong>Se podr&aacute; participar voluntariamente en l&iacute;nea (zoom), =
diferido (v&iacute;deo) o presencial (asistencia) (no obligatoria ninguna d=
e las 3 modalidades):</strong></span></span></span> <ol> <li><span style=3D=
"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><sp=
an style=3D"color:#000000"><strong>En directo a trav&eacute;s de zoom (6&nb=
sp;de mayo) o</strong></span></span></span></li> <li><span style=3D"font-si=
ze:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><span style=
=3D"color:#000000"><strong>Enviando un v&iacute;deo (emitido el 7 de mayo)&=
nbsp;o</strong></span></span></span></li> <li><span style=3D"font-size:12px=
"><span style=3D"font-family:arial,helvetica,sans-serif"><span style=3D"col=
or:#000000"><strong>Asistiendo a la jornada en la Facultad de Ciencias de l=
a Informaci&oacute;n (8 de mayo)</strong></span></span></span></li> </ol> <=
/div> <div style=3D"line-height: 20px; text-align: justify;"> <span style=
=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif">=
<span style=3D"color:#0000FF"><strong>Fechas clave:</strong></span></span><=
/span> <table border=3D"1" cellpadding=3D"1" cellspacing=3D"1" style=3D"wid=
th:750px"> <tbody> <tr> <td><span style=3D"font-size:12px"><span style=3D"f=
ont-family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><stron=
g>Env&iacute;o de resumen (m&aacute;ximo 1 p&aacute;gina)</strong></span></=
span></span></td> <td><span style=3D"font-size:12px"><span style=3D"font-fa=
mily:arial,helvetica,sans-serif"><span style=3D"color:#000000"><strong><spa=
n style=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm">Amp=
liado hasta</span></strong></span><span style=3D"line-height:13.8px"><span =
style=3D"color:#000000">&nbsp;</span><strong><span style=3D"border:1pt none=
 windowtext; padding:0cm"><span style=3D"color:#000000">el</span>&nbsp;<spa=
n style=3D"color:#0000FF">16 de marzo</span></span></strong></span></span><=
/span></td> </tr> <tr> <td><span style=3D"font-size:12px"><span style=3D"fo=
nt-family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><strong=
>Notificaci&oacute;n </strong>de aceptaci&oacute;n/denegaci&oacute;n</span>=
</span></span></td> <td><span style=3D"font-size:12px"><span style=3D"font-=
family:arial,helvetica,sans-serif"><span style=3D"color:#000000"><strong><s=
pan style=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm">D=
esde el&nbsp;</span></strong></span><span style=3D"color:#0000FF"><span sty=
le=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm"><strong>=
&nbsp;9 de marzo</strong></span></span></span></span></td> </tr> <tr> <td><=
span style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sa=
ns-serif"><span style=3D"color:#000000">Abono de&nbsp;<strong style=3D"font=
-family:arial,sans-serif; font-size:12px"><span style=3D"border:1pt none wi=
ndowtext; padding:0cm">matr&iacute;cula</span></strong>:&nbsp;(225 &euro; p=
or cada firmante y por cada ponencia)</span></span></span></td> <td><span s=
tyle=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-ser=
if"><strong><span style=3D"border:1pt none windowtext; line-height:13.8px; =
padding:0cm"><span style=3D"color:#000000">Hasta el </span><span style=3D"c=
olor:#0000FF">23 de marzo</span></span></strong></span></span></td> </tr> <=
tr> <td><span style=3D"font-size:12px"><span style=3D"font-family:arial,hel=
vetica,sans-serif"><strong style=3D"color:rgb(0, 0, 0); font-family:arial,s=
ans-serif; font-size:12px">Env&iacute;o de ponencia completa (m&aacute;ximo=
 14 p&aacute;ginas)</strong></span></span></td> <td><span style=3D"font-siz=
e:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><strong><spa=
n style=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm"><sp=
an style=3D"color:#000000">Hasta el&nbsp;</span><span style=3D"color:#0000F=
F">13 de abril</span></span></strong></span></span></td> </tr> <tr> <td><sp=
an style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans=
-serif"><span style=3D"color:#000000">Env&iacute;o de&nbsp;<strong>correo e=
lectr&oacute;nico informando</strong>&nbsp;que desea defender la&nbsp;<stro=
ng>ponencia en directo</strong>&nbsp;el 6 de mayo&nbsp;o env&iacute;o de&nb=
sp;<strong style=3D"color:rgb(0, 0, 0)">v&iacute;deo</strong>&nbsp;para ser=
 emitido el 7 de mayo</span></span></span></td> <td><span style=3D"font-siz=
e:12px"><span style=3D"font-family:arial,helvetica,sans-serif"><strong><spa=
n style=3D"border:1pt none windowtext; line-height:13.8px; padding:0cm"><sp=
an style=3D"color:#000000">Hasta el</span>&nbsp;<span style=3D"color:#0000F=
F">17 de abril</span></span></strong></span></span></td> </tr> <tr> <td><sp=
an style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans=
-serif"><span style=3D"color:#000000"><strong>Celebraci&oacute;n </strong>(=
<strong>EN L&Iacute;NEA&nbsp;(</strong></span><span style=3D"color:#0000CD"=
><strong>6 y 7 de mayo</strong></span><span style=3D"color:#000000"><strong=
>) y PRESENCIAL -no obligatorio- </strong></span><span style=3D"color:#0000=
FF"><strong>8 de mayo</strong></span><span style=3D"color:#000000">)</span>=
</span></span></td> <td><span style=3D"font-size:12px"><span style=3D"font-=
family:arial,helvetica,sans-serif"><strong><span style=3D"border:1pt none w=
indowtext; line-height:13.8px; padding:0cm"><span style=3D"color:#0000FF">6=
, 7&nbsp;</span><span style=3D"color:#000000">y</span>&nbsp;<span style=3D"=
color:#0000FF">8 de mayo</span></span></strong></span></span></td> </tr> </=
tbody> </table> <br> <span style=3D"font-size:12px"><span style=3D"font-fam=
ily:arial,helvetica,sans-serif"><span style=3D"color:#008000"><strong><span=
 style=3D"line-height:115%">M&aacute;s informaci&oacute;n en:&nbsp;</span><=
/strong></span></span></span> <div style=3D"line-height:22px;"><span style=
=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-serif">=
<span style=3D"color:#0000CD"><u>www.congresoia365.net</u></span><span styl=
e=3D"line-height:115%">&nbsp;</span><br> <u style=3D"font-size:14px"><span =
style=3D"color:#0000CD">2026cisia365@cisia365.net</span></u></span></span><=
/div> </div> <div style=3D"line-height: 20px; text-align: justify;"> <span =
style=3D"font-size:12px"><span style=3D"font-family:arial,helvetica,sans-se=
rif"><span style=3D"color:#000000"><strong>Tel&eacute;fono y&nbsp;WhatsApp =
(+34) 624 880 374&nbsp;(de 9 a 19&nbsp;horas de Madrid)</strong></span></sp=
an></span><br> <br> <span style=3D"font-size:14px"><span style=3D"font-fami=
ly:arial,helvetica,sans-serif"><strong><span style=3D"color:#FF0000">Saludo=
s neuronales y un fuerte abrazo&nbsp;sin&aacute;ptico</span></strong></span=
></span><br> &nbsp;</div> <div style=3D"line-height:16px;"><span style=3D"f=
ont-size:14px"><span style=3D"font-family:arial,helvetica,sans-serif"><span=
 style=3D"color:#008000"><strong>Juan Pablo Mateos Abarca</strong><br> Univ=
ersidad&nbsp;Complutense de Madrid (Espa&ntilde;a)<br> <strong>Director&nbs=
p;del I CISIA 365&ordm;</strong></span></span></span></div> </td></tr> <tr>=
 <td height=3D"20">&nbsp;</td> </tr> </tbody></table></td> <td style=3D"bac=
kground-color: rgb(255, 255, 255); padding: 0px; width: 20px;" width=3D"20"=
>&nbsp;</td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr=
> </tbody></table> </td> </tr><tr class=3D"block_social"> <td valign=3D"top=
" style=3D""><table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpaddi=
ng=3D"0" align=3D"center" class=3D"" style=3D""> <tbody><tr> <td align=3D"c=
enter"><table width=3D"580" border=3D"0" cellspacing=3D"0" cellpadding=3D"0=
" align=3D"center" class=3D"main_table" style=3D"width:580px;"> <tbody><tr>=
 <td class=3D"pad_both"><table width=3D"100%" border=3D"0" cellspacing=3D"0=
" cellpadding=3D"0" style=3D"background-color: rgb(255, 255, 255); " class=
=3D""> <tbody><tr> <td width=3D"20" class=3D"hide" style=3D"width:20px;">&n=
bsp;</td> <td><table width=3D"100%" border=3D"0" cellspacing=3D"0" cellpadd=
ing=3D"0" align=3D"center"> <tbody><tr> <td height=3D"20">&nbsp;</td> </tr>=
 <tr> <td align=3D"center"> <table border=3D"0" cellpadding=3D"0" cellspaci=
ng=3D"0" width=3D"100%" style=3D"min-width:100%;"> <tbody><tr> <td align=3D=
"center" valign=3D"top"> <table align=3D"center" border=3D"0" cellpadding=
=3D"0" cellspacing=3D"0"> <tbody><tr> <td align=3D"center" valign=3D"top"> =
<table align=3D"center" border=3D"0" cellspacing=3D"0" cellpadding=3D"0"> <=
tbody><tr> <td align=3D"center" valign=3D"top"> <table align=3D"left" borde=
r=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"> <tbo=
dy><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cellspaci=
ng=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"middle" s=
tyle=3D"padding:3px"> <table align=3D"left" border=3D"0" cellpadding=3D"0" =
cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valign=3D"mi=
ddle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.congresol=
atina.net/click.php?L=3DoNFqFL0OtmV6ObrjthjdmA&J=3DAkD4GjH6HWANyVB6zYPRig&C=
=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-=
align: top; display: block;" title=3D""><img ac:social=3D"1" border=3D"0" w=
idth=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 38=
px; border: 0px; display: block; text-align: left; font-size: 12px; color: =
rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloudf=
ront.net/news/img/ico-facebook-38.jpg" alt=3D"Facebook CISIA 365&ordm;" cla=
ss=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> </tr> </t=
body></table> </td> </tr> </tbody></table> </td> <td align=3D"center" valig=
n=3D"top"> <table align=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" style=3D"display:inline;"> <tbody><tr> <td valign=3D"top"> <table bo=
rder=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"> <tbody><tr> =
<td align=3D"left" valign=3D"middle" style=3D"padding:3px"> <table align=3D=
"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D""> <tbody>=
<tr> <td align=3D"center" valign=3D"middle" width=3D"38" style=3D"width:38p=
x;"><a href=3D"https://track.congresolatina.net/click.php?L=3D03892GaIJxiSg=
5ag1g763iNlrw&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DH=
KFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" titl=
e=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" style=
=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: block=
; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-family: =
Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-twitter-3=
8.jpg" alt=3D"X de CISIA 365&ordm;" class=3D"acre_image_editable"></a></td>=
 </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></=
table> </td> <td align=3D"center" valign=3D"top"> <table align=3D"left" bor=
der=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"> <t=
body><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cellspa=
cing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"middle"=
 style=3D"padding:3px;"> <table align=3D"left" border=3D"0" cellpadding=3D"=
0" cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valign=3D=
"middle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.congre=
solatina.net/click.php?L=3DH6X7ccWfDO6BWXhYAsh892Xw&J=3DAkD4GjH6HWANyVB6zYP=
Rig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vert=
ical-align: top; display: block;" title=3D""><img ac:social=3D"1" border=3D=
"0" width=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; heigh=
t: 38px; border: 0px; display: block; text-align: left; font-size: 12px; co=
lor: rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2nr.c=
loudfront.net/news/img/ico-linkedin-38.jpg" alt=3D"Linkedin CISIA 365&ordm;=
" class=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> </tr=
> </tbody></table> </td> </tr> </tbody></table> </td> <td align=3D"center" =
valign=3D"top"> <table align=3D"left" border=3D"0" cellpadding=3D"0" cellsp=
acing=3D"0" style=3D"display:inline;"> <tbody><tr> <td valign=3D"top"> <tab=
le border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"> <tbody>=
<tr> <td align=3D"left" valign=3D"middle" style=3D"padding:3px"> <table ali=
gn=3D"left" border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D""> <t=
body><tr> <td align=3D"center" valign=3D"middle" width=3D"38" style=3D"widt=
h:38px;"><a href=3D"https://track.congresolatina.net/click.php?L=3DoNTt1e6T=
w7D8923IyXxJJpjA&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=
=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical-align: top; display: block;" =
title=3D""><img ac:social=3D"1" border=3D"0" width=3D"38" height=3D"38" sty=
le=3D"width: 38px; max-width: 38px; height: 38px; border: 0px; display: blo=
ck; text-align: left; font-size: 12px; color: rgb(17, 85, 204); font-family=
: Arial;" src=3D"https://d1nn1beycom2nr.cloudfront.net/news/img/ico-instagr=
am-38.jpg" alt=3D"Instagram CISIA" class=3D"acre_image_editable"></a></td> =
</tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></t=
able> </td> <td align=3D"center" valign=3D"top"> <table align=3D"left" bord=
er=3D"0" cellpadding=3D"0" cellspacing=3D"0" style=3D"display:inline;"> <tb=
ody><tr> <td valign=3D"top"> <table border=3D"0" cellpadding=3D"0" cellspac=
ing=3D"0" width=3D"100%"> <tbody><tr> <td align=3D"left" valign=3D"middle" =
style=3D"padding:3px"> <table align=3D"left" border=3D"0" cellpadding=3D"0"=
 cellspacing=3D"0" width=3D""> <tbody><tr> <td align=3D"center" valign=3D"m=
iddle" width=3D"38" style=3D"width:38px;"><a href=3D"https://track.congreso=
latina.net/click.php?L=3DWUtJgEO3AQXxeQ5wTtvWVg&J=3DAkD4GjH6HWANyVB6zYPRig&=
C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRcCbcnmxmc4f43DJP5g" style=3D" vertical=
-align: top; display: block;" title=3D""><img ac:social=3D"1" border=3D"0" =
width=3D"38" height=3D"38" style=3D"width: 38px; max-width: 38px; height: 3=
8px; border: 0px; display: block; text-align: left; font-size: 12px; color:=
 rgb(17, 85, 204); font-family: Arial;" src=3D"https://d1nn1beycom2nr.cloud=
front.net/news/img/ico-youtube-38.jpg" alt=3D"Canal de YOUTUBE CISIA 365&or=
dm;" class=3D"acre_image_editable"></a></td> </tr> </tbody></table> </td> <=
/tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbody></ta=
ble> </td> </tr> </tbody></table> </td> </tr> </tbody> </table> </td> </tr>=
 <tr> <td height=3D"20">&nbsp;</td> </tr> </tbody></table></td> <td width=
=3D"20" class=3D"hide" style=3D"width:20px;">&nbsp;</td> </tr> </tbody></ta=
ble></td> </tr> </tbody></table></td> </tr> </tbody></table></td> </tr><tr =
class=3D"block_spacer"> <td width=3D"100%" valign=3D"top" style=3D"backgrou=
nd-color: rgb(253, 251, 252);" class=3D""> <table class=3D"BoxWrap" cellpad=
ding=3D"0" height=3D"100%" cellspacing=3D"0" align=3D"center" style=3D"marg=
in:0 auto; height:100%"> <tbody><tr> <td height=3D"100%" style=3D"height: 1=
00%; line-height:25px"> <table width=3D"580" height=3D"100%" border=3D"0" c=
ellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=3D"main_table" st=
yle=3D"height: 100%; width: 580px;"> <tbody><tr> <td class=3D"pad_both" sty=
le=3D"background-color: inherit; height:100%" height=3D"100%"> <table width=
=3D"100%" height=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" =
style=3D"height: 100%;  border-width: initial; border-style: none; border-c=
olor: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;" class=3D=
""> <tbody><tr> <td width=3D"100%" height=3D"100%" style=3D"display: block;=
 height: 100%; line-height: 25px; padding: 0px;">&nbsp;</td> </tr> </tbody>=
</table> </td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </=
tr> <tr class=3D"block_links_footer"> <td width=3D"100%" valign=3D"top" cla=
ss=3D"" style=3D"background-color: rgb(253, 251, 252);"> <table width=3D"58=
0" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center" class=
=3D"main_table " style=3D"margin: 0px auto; width: 580px; "> <tbody><tr> <t=
d class=3D"pad_both"> <table width=3D"100%" border=3D"0" cellspacing=3D"0" =
cellpadding=3D"0" align=3D"center" style=3D""> <tbody><tr> <td> <table widt=
h=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"center=
" class=3D"" style=3D" border-width: initial; border-style: none; border-co=
lor: initial; margin-top: 0px; padding: 0px; margin-bottom: 0px;"> <tbody><=
tr> <td height=3D"20" style=3D"text-align: center; font-size: 11px; color: =
rgb(51, 51, 51); font-family: Helvetica, Arial, sans-serif; vertical-align:=
 middle; padding: 0px;"> <a href=3D"https://track.congresolatina.net/unsubs=
cribe.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D=
"text-decoration: underline; color:#333;"><span>Darme de baja de esta lista=
</span></a> | <a href=3D"https://track.congresolatina.net/update.php?J=3DAk=
D4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ" style=3D"text-decoration=
: underline; color:#333;"><span>Actualizar mis datos</span></a> <br><br> <s=
pan>F&Oacute;RUM XXI - Cine n&ordm; 38. Bajo derecha, 28024, Madrid</span> =
</td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </tr> </tbo=
dy></table> </td> </tr> <tr class=3D"block_spacer"> <td width=3D"100%" vali=
gn=3D"top" style=3D"background-color: rgb(253, 251, 252);" class=3D""> <tab=
le class=3D"BoxWrap" cellpadding=3D"0" height=3D"100%" cellspacing=3D"0" al=
ign=3D"center" style=3D"margin:0 auto; height:100%"> <tbody><tr> <td height=
=3D"100%" style=3D"height: 100%; line-height:25px"> <table width=3D"580" he=
ight=3D"100%" border=3D"0" cellspacing=3D"0" cellpadding=3D"0" align=3D"cen=
ter" class=3D"main_table" style=3D"height: 100%; width: 580px;"> <tbody><tr=
> <td class=3D"pad_both" style=3D"background-color: inherit; height:100%" h=
eight=3D"100%"> <table width=3D"100%" height=3D"100%" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0" style=3D"height: 100%;  border-width: initial; =
border-style: none; border-color: initial; margin-top: 0px; padding: 0px; m=
argin-bottom: 0px;" class=3D""> <tbody><tr> <td width=3D"100%" height=3D"10=
0%" style=3D"display: block; height: 100%; line-height: 25px; padding: 0px;=
">&nbsp;</td> </tr> </tbody></table> </td> </tr> </tbody></table> </td> </t=
r> </tbody></table> </td> </tr> </tbody> </table>=20
                        <table id=3D"ac_footer_email" width=3D"100%" style=
=3D"width:100%">
                            <tr>
                                <td width=3D"100%" valign=3D"top" align=3D"=
center">
                                    <table width=3D"" align=3D"center">
                                        <tr>
                                            <td style=3D"text-align:center;=
"><a href=3D"https://track.congresolatina.net/click.php?L=3DJZxYSSUU7O2892K=
UdpBcLq9w&J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ&F=3DHKFRc=
Cbcnmxmc4f43DJP5g"><img alt=3D"" class=3D"img_nor" border=3D"0" style=3D"bo=
rder-style:none;min-width: initial !important;max-width: initial !important=
;width: initial !important;" src=3D"https://d1nn1beycom2nr.cloudfront.net/u=
ploads/user/fBxrW1jUkXDcz7BTAyZIqw/images/R_9ea7e3_LINKEDIN LOGO CONGRESO L=
ATINA 2021.png"/></a></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                        <style>@media only screen and (max-width:480px){.im=
g_nor{border-style:none;min-width: initial !important;max-width: initial !i=
mportant;width: initial !important;}}</style>               =20
                        <img src=3D"https://track.congresolatina.net/email_=
open_log_pic.php?J=3DAkD4GjH6HWANyVB6zYPRig&C=3DkF6K5qd4mAeEXe7635lLHrEQ" a=
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
kasan-dev/0102019cd44f84e4-2e55241a-9075-4059-a5f5-7551fec7c350-000000%40eu=
-west-1.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">https://group=
s.google.com/d/msgid/kasan-dev/0102019cd44f84e4-2e55241a-9075-4059-a5f5-755=
1fec7c350-000000%40eu-west-1.amazonses.com</a>.<br />

--b1_I9jnX7bBmLJ3N2FitKsAWjzdNOBb7vIrEJasKYrQ--

