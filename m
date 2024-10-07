Return-Path: <kasan-dev+bncBAABBOFER24AMGQEATUB2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 11223992644
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2024 09:48:10 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2870ed29f50sf6068142fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 00:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728287289; cv=pass;
        d=google.com; s=arc-20240605;
        b=RGisGk8+CfCOEjLusznW0wwymfi5ClJtvKkfbjWNGOIXWNtcBpRtCbeHWE4eTJ/EGG
         arpX0VuLJ1Udn0J8t/iEsrOSq6XVVyOPWBq6tf95+11f390mDZkHLmE+5RD2iFX+OwU5
         JdSqN7PbviNueo7chRFQfInlPqiwYsJZN3kOLacH1y+5v9eonx6qF/l2FSjSgd61TFYE
         0trR1NtmaHHxc8aQYiHn07pwp/Zf1YAB+75APhIEYDEurO3LsX3VqzoZn7QJNkjuySqE
         OkDFvV3R4z/2cXq48HZUYEUXU33J1S6BK4FsLjo2nEpKySAGMJNMNX47xw3YrKhTt+Kl
         ZMNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:to:from:mime-version
         :message-id:date:sender:dkim-signature;
        bh=OPaESUZgNQbOaUw2S0l4Ccfc3aTFvndWWQFyPAnk1cA=;
        fh=9hdi9gqzL3MK+wu1lwEQ4x9bxXGC46C93X1wKxX8qjM=;
        b=VGnrWvS3tLWkIwS1qTIi2ztm5jx7SnoIYxlGjOKmLy3h0X9kjD1CAP0S7cMi7FgEdk
         PdFPyvUANVW7t7XCkG6MzxrW8zsHo9qMUT7Ba5t+uGE661klMfaSSVo542EYf7W0BRjS
         TxSINWCIzg11ROOTIIdLcVQWu8ZeZgp8z0786axLrDJYFT/iqXJa76Mzqf+/KHeIAqnq
         ZVyzaJHF2M/N23sQ6NYhoqbzLaE+LqX4mqtKqsuV9oRWyMu6DocNHqP/8dKG90vdY0wY
         /VYuHb/M5pjC7PBj2G5sYTfWCfv1ARpntCa09WjxmaaLSYR8KqXhPot6xqLQxptBliyC
         CoIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dkim.uni5.net header.s=uni51 header.b=HMqB5ihW;
       spf=neutral (google.com: 191.6.221.116 is neither permitted nor denied by best guess record for domain of nfe@meuamericanetempresas.com.br) smtp.mailfrom=nfe@meuamericanetempresas.com.br
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728287289; x=1728892089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:to:from:mime-version:message-id:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OPaESUZgNQbOaUw2S0l4Ccfc3aTFvndWWQFyPAnk1cA=;
        b=vKiXVTmt6nxLWKjrYebcmzg2gAax0XiIR6kRJSvsszqo2hnBGHNw1Bgba5NuVR0t6L
         knpBHknu9wfAZAX9LONPJatwR+zgAxVX8HAKmAjSBI2wSB/PqYNJ5YQgf1k3U9gh+rF3
         zabxhX+arpYNjusEd4au6yjJCzH8LJpm11lRPIjStVeKMHzLURUwkbx3DyVEttPoMEse
         OrhWzv3oP2BrHQzXiCB4hRqfMVtgCtKpOSneEcKq/Ie930hLQ//2YnHwCoR8hK7GPea4
         W82SNUMsj3EHnM9sM/P4BEa0elIYMALDgpYAquLYeUkdX8zrweRvdrfzWnoK2ToaOQxt
         cnSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728287289; x=1728892089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:to:from
         :mime-version:message-id:date:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OPaESUZgNQbOaUw2S0l4Ccfc3aTFvndWWQFyPAnk1cA=;
        b=dxuZ0G4ccqEmpZLcez4QcniATme7WgObpN8Esi7RWoCoOM0wKnLF4Q7EzL5L11suNZ
         6BlyVtoZpu+ffbBwlear5edSYPf96POxzQSTGMwEA46K/OyAFUEZ3irLij0O+rAYi2Ou
         ID9vafchx/NIr/uDIXgzMwXl8HELY0cy5DOs/Hzbi+lg5Z1KTpHn9f7sWWZiKKsgU8nJ
         VJMCOhpDhYJ+llJQyWvpGEOiReIjuGFTWFEPb8liYtMjWR3GZRFGdjszc+QmibmPmdKM
         /JMJDuNtATQLl0EHx6On1WLCcf+2E83bmp01vJvys9zY6wH2I5OKWTrVRVSBbY/6Z+sH
         Ptrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGCaph/V6vOaz870SGedfwbiszhNuaBHNiuKRnOyI5EqWDbPrWjz20EXqcNwS0Y/lAsHDeYQ==@lfdr.de
X-Gm-Message-State: AOJu0YyXWXuYhq8l7CkbNbHN8E6jeP/vazWOJscxRdz+Q9XvN5+nvBi1
	5YSXxdUhePcfMivvNFxcYqUxIvosrfzWg/9+4Ih4aXkyAsMHzK5P
X-Google-Smtp-Source: AGHT+IH3iDFomvefcitvBBWDOrmTEmGnINw4l9/HKl8adzV4ar/oP7FagvWquFauoyx8kLmuuAXktQ==
X-Received: by 2002:a05:6870:b4a6:b0:270:6890:9a2e with SMTP id 586e51a60fabf-287c1e15ademr6241017fac.21.1728287288469;
        Mon, 07 Oct 2024 00:48:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:410a:b0:278:2606:8489 with SMTP id
 586e51a60fabf-287a419821dls177610fac.0.-pod-prod-09-us; Mon, 07 Oct 2024
 00:48:07 -0700 (PDT)
X-Received: by 2002:a05:6808:3a16:b0:3e3:ce57:b11b with SMTP id 5614622812f47-3e3ce57b533mr3499749b6e.36.1728287287495;
        Mon, 07 Oct 2024 00:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728287287; cv=none;
        d=google.com; s=arc-20240605;
        b=YmealYTRzxv7gGe4Cn7/zKVLEJUtpumkUZ+zYrWXt3/pc79/f0qjnAOJGRQh7YtdSB
         GS9wlQj8tXZ9wfznbnVvMZ4Oj9zxUd1bX6R0iNKP6PHpAtMjOOCIJW6R7Nf7a/+PToPd
         lUtF+qDyjlPamkXv3QyTpAkarnf0h+BgdUwcawg+ZeIB4PZK4YbKbbZ+vBsRfdU1yRU2
         3CU2I+UARy2uhmHfGIA9ekB+lRaPD3iwvikx3qZEsBU/uFZHD1YkPN8ICSiqYPPHvUhu
         xyHE3s2SqDU0oRCn04LVJ1C2HVHyV4hnohlJ/BdeXSgcFL9Sxfg64MqappF+ljvcM7aO
         LC3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=subject:to:from:mime-version:dkim-signature:message-id:date;
        bh=dGdLT9o5J8kOkLcJay+ger0b2nMQWtpFL4wbeZUD+DI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JRu9q7SwIQwmL6zsFnP9IZ/uGfQ7ZruPXFLafCsFxHuCKy3vrwbk1guAb7iCgl2anq
         mxzw0FlHTecPGSpGDAtvZO88rMaZpNeiJR3Z9/A8/1JdbimJhZCYmsy2miMy65JQCmbS
         tkwVEVHEBvmpJ2NYHcAlHZo0MRzDtPDwGB4kQGSjM1bDkq/omArkQFx61qgfMXo23IiI
         T8xmGhGyZJCSwYZXzXP9AonO4rOgGTLH1WRAs0yNByg2onKuHvNAjO76tWD+sKQuNmqf
         DBkOmRoj2WX6U67po0dvJGEafb6LtuhmymfiE7kE3bs8aagj62mUW5esyZNhD5G9cYiv
         Vt6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dkim.uni5.net header.s=uni51 header.b=HMqB5ihW;
       spf=neutral (google.com: 191.6.221.116 is neither permitted nor denied by best guess record for domain of nfe@meuamericanetempresas.com.br) smtp.mailfrom=nfe@meuamericanetempresas.com.br
Received: from smtp-sp221-116.uni5.net (smtp-sp221-116.uni5.net. [191.6.221.116])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e3c907de34si198956b6e.3.2024.10.07.00.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Oct 2024 00:48:06 -0700 (PDT)
Received-SPF: neutral (google.com: 191.6.221.116 is neither permitted nor denied by best guess record for domain of nfe@meuamericanetempresas.com.br) client-ip=191.6.221.116;
Date: Mon, 07 Oct 2024 00:48:07 -0700 (PDT)
Message-ID: <67039237.050a0220.3a1aa.7ca8SMTPIN_ADDED_MISSING@gmr-mx.google.com>
Received: from [192.168.100.153] (unknown [IPv6:2804:1e68:c201:5cce:9c95:251f:5ba1:5e54])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: nfe@meuamericanetempresas.com.br)
	by smtp-sp221-116.uni5.net (Postfix) with ESMTPSA id 4D9FA20208C3
	for <kasan-dev@googlegroups.com>; Mon,  7 Oct 2024 04:48:04 -0300 (-03)
Content-Type: multipart/mixed; boundary="===============2018109761871285365=="
MIME-Version: 1.0
From: nfs-e<nfe@meuamericanetempresas.com.br>
To: kasan-dev@googlegroups.com
Subject: NF gerada - 0957728
X-SND-ID: 94qlC/3BkHTH3c88MHrfKGL95NjxzkVnsht14eA7bOCoPBSt5633E5PcLgqw
	R3coXV1A4uVEo+fiOSbVVvR4MFUytLALonZdNpxAYZHJb/eb1pr0IckrLs5M
	Jyigyg0O/uhWQOX74+yqtZQcq4M0UnbKokP9zaGa0vCbrTcqvpHzFw2GVtkx
	M02Gv0q1531sWGTPi/g96R74ouXxwFF2vcVa85tmLtq22zpsBu/GsL04tLvr
	RNz8JfFSaYawIKwyh3M2MYlEkLtJG0FYmEdFuRwmNUuDMHx4WHBBJpQ+8Pyi
	hLguYue4lUYVVIGt3MTJs082nE8HtUADS0sKbu8xRe8v7oRiYs7bFMB7tvCK
	6hAoQgixCaUJcwBUDd4A4s1sE3/f8hYLz/7QFa71K61w/Ih9MtV6yO53VSWr
	FT+gKmg3kxTKFuRFd9EzRM75rkKx7mTfXEH7HOu+tXRkHLWfiioHxq3RXWk7
	1BirMqOAUtj1TFRKmWlcw4MioQZfciC5DW4RjPdn2YLpK4iTVnTEennxwRzp
	cCSF8pmpm1B64mM=
X-Original-Sender: nfe@meuamericanetempresas.com.br
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dkim.uni5.net header.s=uni51 header.b=HMqB5ihW;       spf=neutral
 (google.com: 191.6.221.116 is neither permitted nor denied by best guess
 record for domain of nfe@meuamericanetempresas.com.br) smtp.mailfrom=nfe@meuamericanetempresas.com.br
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

--===============2018109761871285365==
Content-Type: text/html; charset="UTF-8"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html lang=3D"pt-BR">
<head>
    <meta charset=3D"UTF-8">
    <meta name=3D"vp0957728" content=3D"width=3Ddevice-width, initial-scale=
=3D1.0">
    <title>0957728 NF gerada</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            -webkit-text-size-adjust: none;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            background-color: #34495e; /* Azul mais vibrante */
            color: white;
            padding: 15px 0;
            border-radius: 8px 8px 0 0;
        }
        .header h2 {
            margin: 0;
            font-size: 24px;
        }
        .content {
            padding: 20px;
            color: #333333;
            text-align: left;
        }
        .content p {
            line-height: 1.6;
            font-size: 16px;
        }
        .content strong {
            color: #333333;
        }
        .button-container {
            text-align: center;
            margin: 20px 0;
        }
        .button {
            background-color: #34495e; /* Azul mais vibrante */
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
        }
        .button:hover {
            background-color: #2c3e50; /* Azul mais escuro no hover */
        }
        .footer {
            text-align: center;
            font-size: 12px;
            color: #666666;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class=3D"container">
        <div class=3D"header">
            <h2>NF gerada</h2>
        </div>
        <div class=3D"content">
            <p>Prezado(a) cliente,</p>
	    <!-- Random comment: 0957728 -->
            <p>Informamos que a Nota Fiscal Eletr=C3=B4nica foi emitida em =
seu nome com os seguintes dados:</p>
	    <!-- Random comment: 0957728 -->
            <p>N=C3=BAmero da Nota:<strong> 0957728</strong></p>
	    <!-- Random comment: 0957728 -->
            <p>Valor:<strong> R$ 888,00</strong></p>
	    <!-- Random comment: 0957728 -->
            <p>Data de Emiss=C3=A3o:<strong> 07 de outubro de 2024</strong>=
</p>
	    <!-- Random comment: 0957728 -->
            <div class=3D"button-container">
                <a href=3D"https://is.gd/1agQCN?0957728" class=3D"button" t=
arget=3D"_blank" rel=3D"noopener noreferrer" rnd-attr=3D"0957728">Visualiza=
r Nota Fiscal</a>
            </div>
            <p>Para visualizar a nota, acesse o nosso site clicando no bot=
=C3=A3o acima.</p>
        </div>
        <div class=3D"footer">
	    <!-- Random comment: 0957728 -->
            <p>Este =C3=A9 um email autom=C3=A1tico, por favor, n=C3=A3o re=
sponda.</p>
        </div>
    </div>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/67039237.050a0220.3a1aa.7ca8SMTPIN_ADDED_MISSING%40gmr=
-mx.google.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/67039237.050a0220.3a1aa.7ca8SMTPIN_ADDED_MISSING%40=
gmr-mx.google.com</a>.<br />

--===============2018109761871285365==--
