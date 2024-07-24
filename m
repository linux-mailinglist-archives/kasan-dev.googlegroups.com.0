Return-Path: <kasan-dev+bncBD47LZVWXQIBBJUHQK2QMGQEWZTEZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id D26B993ABF2
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 06:31:35 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2644f74f733sf2784914fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 21:31:35 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721795494; x=1722400294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gtYEEcowrtSA5rglebW1AK+76rG/Go0EfRkxVyJC+ig=;
        b=cAIwxc5TdBv6iL+2C94jdEZLAz6iZh4+6CJGQnGu67XYcUbFaCgkMrBZz7sn1ieUeH
         ianhLbkhj0SroHvHsfFU22hUtRF03L3Vi1Kq15IvaQLqumHH9lu2252ENJjFyhmfSQPk
         J9QfkKZbwS+4vRn2PqpNgT7Gj4GPYnVtO5usrPjcN9OfPrGroJIPTXuPlZYsjR6OgdQK
         opWHCMLLem9r397IX47M0famgqRtGHHoHjjtJN8DuEoAKHJ68No4R6vARdyGBppsw2/h
         TR+kSkVXnBY6EEq5w4K+j4UtrwG1XRxFYGDdW8uaFfgsanv2Npddzb33ue4mO2GwioNn
         2HZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721795494; x=1722400294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gtYEEcowrtSA5rglebW1AK+76rG/Go0EfRkxVyJC+ig=;
        b=ht3r95ZPGNAi2YACUzYDfsPZOwej19sRIeh5UtqPdIML4b3DR30H9AG02ux/RyUcBG
         ANuBMiIeOxdzugYD2zVmb20gJcXMs2tUQ/p+kfgqi6yIlfTS49fFTu+bhYyZtoKO3Kod
         7HnHKfA2etpOZe+nBy0uZ6FK1CC/0iIbo5OLw3Tp2WsKjMt02xTI2J4lA2OfqLfvo/5c
         gs38y/dPhNFBAUMXT3HQvGsBtA5+SYnCZXYtKThJmDKolu0vXs5l6eOfK1VP8YKoatRt
         uZqbQx3xY7EpPpNU+1zFWsX4lnzDIrgt0Cxcn6xarFsKFvVrZ+hqooCLsj+xP0kIyWOE
         i6Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721795494; x=1722400294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gtYEEcowrtSA5rglebW1AK+76rG/Go0EfRkxVyJC+ig=;
        b=VSpH/JJa9pOjQ8UbOp+HWGg/qp2eUaDUGZp+EDiYJVAKrNnoEoI+WFTibMIbZ4RW2K
         jfs8q5AxpxWwljN7IduuUrZtCCZqaJ3Pzwvnlu6HGKtffsO2bnqB2EIxp+Svt/cl8tV7
         jVqAXkosIVmbo6FSU/tcUbEeBdKNheF4nt0tnOps3lIRjB4Hz4Bys1pCBonUMcoWNDOg
         8lA5hFL16dQXco6KRLyyEjFAUlDjcIXfij9XL6/qvkakT0wqC3tPn9H+9DOTfmpElITs
         awoXRYllpdm5UmeGgEmXSigucoFSR+motcGpxNmgS+GK+7Do0UEBzCKKxkt1AgCMaVjb
         37QA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUpQ63X6Mhno2Hlye/adB9imo8KPRQXFDJ+IElKZ+yzLJAJYg+cziQcSRhUiP1F9TY8WWIc9l4ONJ3EXZTt5A1ESd+IkQvZwg==
X-Gm-Message-State: AOJu0Yy+abzcU3qv3o0W0ZthdQJB9szX637rprf0q5wkTP6dvsXmU+dN
	ktO16IG/GPkYqC3yTahNrvsHJxALDmi6yYmlS1UHIgR2RPIKIsxG
X-Google-Smtp-Source: AGHT+IH/i7ly25nNbFVCEwqz0MgcDP8xsvKS0S0aub15aMYVieAT9BW8BNkUxVX1j2lw1cJ3nXripA==
X-Received: by 2002:a05:6870:3d94:b0:261:87:fe1f with SMTP id 586e51a60fabf-2648cc7a88cmr962060fac.44.1721795494345;
        Tue, 23 Jul 2024 21:31:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ed94:b0:251:cbd:f69f with SMTP id
 586e51a60fabf-260ec4e8dafls1098553fac.2.-pod-prod-00-us; Tue, 23 Jul 2024
 21:31:33 -0700 (PDT)
X-Received: by 2002:a05:6808:16ab:b0:3d9:3f45:775f with SMTP id 5614622812f47-3db09d0a4e5mr21902b6e.1.1721795493362;
        Tue, 23 Jul 2024 21:31:33 -0700 (PDT)
Date: Tue, 23 Jul 2024 21:31:32 -0700 (PDT)
From: Jeremy Shurtleff <jeremyshurtleff54@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <79204d79-f9f7-432d-9fc4-6320783bb6d6n@googlegroups.com>
Subject: =?UTF-8?Q?Re:_KSA_-_=D8=AD?=
 =?UTF-8?Q?=D8=A8=D9=88=D8=A8_=D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6?=
 =?UTF-8?Q?_=D9=81=D9=8A_=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A?=
 =?UTF-8?Q?=D8=A9_-_Saudi_A?= =?UTF-8?Q?rabia_=D8=AD=D8=A8=D9=88=D8=A8_?=
 =?UTF-8?Q?=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83_=D8=A7=D9=84=D8=B3?=
 =?UTF-8?Q?=D8=B9=D9=88=D8=AF=D9=8A=D8=A9_-_00971553031846?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1206404_860133488.1721795492665"
X-Original-Sender: jeremyshurtleff54@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_1206404_860133488.1721795492665
Content-Type: multipart/alternative; 
	boundary="----=_Part_1206405_371321933.1721795492665"

------=_Part_1206405_371321933.1721795492665
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

>  *00971553031846 <http://wa.me/971553031846>*
>
>  *00971553429899* <http://971553429899>
>
>  =D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9=D9=86=D8=A7 =D8=B9=D8=A8=D8=
=B1 =D8=A7=D9=84=D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8 =D8=A3=D9=88 =D8=A7=D9=
=84=D8=AA=D9=8A=D9=84=D8=AC=D8=B1=D8=A7=D9=85
=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/79204d79-f9f7-432d-9fc4-6320783bb6d6n%40googlegroups.com.

------=_Part_1206405_371321933.1721795492665
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

&gt; =C2=A0<u><a href=3D"http://wa.me/971553031846">00971553031846</a></u><=
br />&gt;<br />&gt; =C2=A0<a href=3D"http://971553429899"><u>00971553429899=
</u></a><br />&gt;<br />&gt; =C2=A0=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=
=B9=D9=86=D8=A7 =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D9=88=D8=A7=D8=AA=D8=B3=D8=
=A7=D8=A8 =D8=A3=D9=88 =D8=A7=D9=84=D8=AA=D9=8A=D9=84=D8=AC=D8=B1=D8=A7=D9=
=85<br />=C2=A0<br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/79204d79-f9f7-432d-9fc4-6320783bb6d6n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/79204d79-f9f7-432d-9fc4-6320783bb6d6n%40googlegroups.com</a>.<b=
r />

------=_Part_1206405_371321933.1721795492665--

------=_Part_1206404_860133488.1721795492665--
