Return-Path: <kasan-dev+bncBAABBPNI6G2QMGQET2UYXDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 08F7A9514D2
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 08:52:47 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5da50ab90c0sf3290216eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 23:52:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723618365; cv=pass;
        d=google.com; s=arc-20160816;
        b=d64xzx2P2EFLc/0ppJAvXglJx8jFyN9VC2JGVI/7Aum+8pFkPUDzpjiLEGD3f6HlIr
         fCtGo7+gu2WxbDotA7OGpPImOC6qyAs24F2uEEGh2PJ88oHZufpIYpF3Rm14NnUXQK/1
         U5XfBjW2KrxlhkcfiYewYwGC+/vCOQhYB3H2sPphp1YDEoa5A8lomsvPsnFZ1G+PWD8h
         yChsgAmj6Si01DzvZfs6hYRCt6LWwAMi52GYJLTULCjHRQZmc8sgCv78luKMEDtGtjel
         Zi+6DcRGK27n2g9yHsnEUCewvSk2sbmA+4QgVmgCD/25hqtlTlWmDpINRYkql9FB1Zxk
         TZPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:to:from:mime-version
         :message-id:date:sender:dkim-signature;
        bh=mVOehgxx1SkmqUh4PRQV9Ta5kMUVSFsYQjBcYCqNkZg=;
        fh=pZPI26WJpnfVuH32b9mvOytMfNaYGcMfUpHxjWU467w=;
        b=Xl+Cnsky//1RDCKbmcxbZgOFCB7LW60EVO1AHBphBeP7Zf8nrMFsZKNt1to3mvoNCp
         /dnM4pXlKC7memdsNiIQNEWIrHtx5PnsSIpSIjQwI55hJJM7wEYr8iM8ze53F3la3O8s
         YhrUU/R8rdor2/VPaRO6ioPWMBiD16HGK776XY9wmhiAacJjiNZRtOYZ0oo8oSW7MqP5
         bFedOhnQz1Y9epcwt3LRcmK7TtOSCRlI2DqNMzwW9cUxOWeFBB9aSKaUztd4e5FfWUKX
         AsRW+OO8nkXYNElekYyn/TjJZXMwR8o0fEXyvwqca1tofiVVNoVq2g2fH8sqIm0PDZbp
         eT5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dkim.uni5.net header.s=uni51 header.b=Jsbs6jDH;
       spf=softfail (google.com: domain of transitioning notafiscal@amgeng.com.br does not designate 2804:10:8028::221:35 as permitted sender) smtp.mailfrom=notafiscal@amgeng.com.br;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=amgeng.com.br
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723618365; x=1724223165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:to:from:mime-version:message-id:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mVOehgxx1SkmqUh4PRQV9Ta5kMUVSFsYQjBcYCqNkZg=;
        b=qEQtiGJKo/SUnuvHBonOg2M9GXLeq1UF+hoHle6VBG54T+n6jSPkrRb5u6LjJrcad4
         g9MPlmlMQinb/kRBlxpWnpHc0qPxEOHCksw5H8JJdjNS33fpinSAFvGuSdFlMGUHiIoz
         rJYy/OGRS/fIy2lHe/gxvKHPqE723ZtMC4Z6qAS9d+XoxQHrzYEBeP74V5IMOHPhcRTY
         xDyWj/Ux8rusyXzHtQefP/1w5UoO/FV/JcN/WNfGY0YuveM+GExA9Dx/Hnu5sTY8bo0g
         5ipIrHthfM81Y587z/eOPbYjeVm5YboXGIzva65xey9By1i33SMMHaD4MH+eczvr3G2j
         7dOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723618365; x=1724223165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:to:from
         :mime-version:message-id:date:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mVOehgxx1SkmqUh4PRQV9Ta5kMUVSFsYQjBcYCqNkZg=;
        b=EKo3qKkV33pJQZR76AAEiRMlLNA97uqzXtXfDtr2g3hoIyITSK0gRyGrcuau2jFLF+
         AXOtgGyJnM5bUt38lUJ3LbAV+agSqKq7m3Oo+EUA97+NV0qayZlwBR/EXrGNiMYVEYN+
         B1EbqKxbygwpWfdIKNJPeiw/A4po7qq3QkjQxES56eV7mP86cNMfCWbQ1mBTm0wmAUDe
         N6Mhs2nwBMUFRX9+uoKdiDQ99zQkX+C6h0ZdfmgIOMrvyPXsraZ9z4d+R7cb1PWhL1Nf
         l+sWSE3/26j/9WLOWR2vJpicNL1Sl6D5h2LJOA5hmHyczIiYzqZBuzttpOcjSQ0+dVH1
         UreA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlytGU7zRw4nmuUAU73HMFC3VkKDxCiY9v0Axyrf2Y3oYbmNjSZ4vTavJzFGRr6/xLKLPea2T/ZA3vdu9AmjQktTKElcYpsQ==
X-Gm-Message-State: AOJu0YzxZdQBYO6ci5+gtFCS404SIVnPIc3tN69GMaCOhUYFSoID58pt
	G9q2jTpcQDM5rUE4PzWBj/lhSoXH1dZiGRLNCQi2UrRzlNIF6vy5
X-Google-Smtp-Source: AGHT+IGy6m3zQy6x2UJqaBp9R+xh3QA+UdN4im4/YDobTnde/lb9AiOxoQ+D6/YGKq278/4JAd8R5g==
X-Received: by 2002:a05:6870:82a0:b0:261:1339:1cb8 with SMTP id 586e51a60fabf-26fe5c173c7mr2059943fac.35.1723618365449;
        Tue, 13 Aug 2024 23:52:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3929:b0:710:66a5:bd95 with SMTP id
 d2e1a72fcca58-710c7327b89ls4640506b3a.1.-pod-prod-08-us; Tue, 13 Aug 2024
 23:52:44 -0700 (PDT)
X-Received: by 2002:a05:6300:668b:b0:1c8:da09:5311 with SMTP id adf61e73a8af0-1c8eae2f66cmr2208504637.4.1723618364366;
        Tue, 13 Aug 2024 23:52:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723618364; cv=none;
        d=google.com; s=arc-20160816;
        b=G+4vTAEb5KCn5i7MtO2CFQ9DxGhUx+dCsnNHYoFHAE0fRMY8pCXTv22xplCrR9Bn5k
         PNTwZGxLakWgNCQxLJwVS4FLamYh81U1200NzXsfFzT2yLOQutAtHZrA39ssxRxId7GQ
         fO90bVaa2I0BWesPhCrsUNFZKSumrusY8u/+bxxzpVHzQS6N6DE90h5xJaGB48x7Ht1C
         HiKIHA2Rs5eztRl5qTqoNX36xmUM1a5bAnYaxdal5yg3I065vtLiwCiY7nuOE0bJxGgO
         F/51TcS7IPLBE6sgry7fUnBhzAcRhOHnm0wF1YHMckXE6zUKpBeVpIXwXMkLlyMS1ouf
         KPJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:to:from:mime-version:dkim-signature:message-id:date;
        bh=7gYX88W6oBsRV1EL6dHkFuW7ktCUfX1SJgUFPunkxrY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kbXYOADuw44upVLC4VexLrX7v4Wje/fFyiykvjvC8uPqJqlTioZkfDB/sPT5mZ478e
         FLM6clFLSHcGustGdTfBl6+dCmH78ztHm9vkoX7A+CEaUSefP0ccLonpclHRI9BWXWSB
         oXWJIPJcd4ap4XIn1zJGbqf349BIxB+rhZh/A9kyPMHADOQ0jFZMhLryEqM5gKiJKtlB
         pZSIzwZWsKHnUeqxuBYDcoxMDNrWUKwuhVFJFwXuijsTfk9XZ+xNVG6IEq4ooAqGS+91
         tai7Y05CY+fq/NMfKHaHWl1U3MRP0BW5d76ARFM+Ue4eS1sYUpcZfkPffsDk1mVlUjfE
         vAog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dkim.uni5.net header.s=uni51 header.b=Jsbs6jDH;
       spf=softfail (google.com: domain of transitioning notafiscal@amgeng.com.br does not designate 2804:10:8028::221:35 as permitted sender) smtp.mailfrom=notafiscal@amgeng.com.br;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=amgeng.com.br
Received: from smtp-sp221-35.uni5.net (smtp-sp221-35.uni5.net. [2804:10:8028::221:35])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-201cd1422cfsi1108985ad.6.2024.08.13.23.52.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Aug 2024 23:52:44 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning notafiscal@amgeng.com.br does not designate 2804:10:8028::221:35 as permitted sender) client-ip=2804:10:8028::221:35;
Date: Tue, 13 Aug 2024 23:52:44 -0700 (PDT)
Message-ID: <66bc543c.170a0220.12048e.4aa5SMTPIN_ADDED_MISSING@gmr-mx.google.com>
Received: from [192.168.100.153] (unknown [IPv6:2804:1e68:c201:214f:5410:9c53:8f8c:313f])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: notafiscal@amgeng.com.br)
	by smtp-sp221-35.uni5.net (Postfix) with ESMTPSA id 551186148E28
	for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 03:52:42 -0300 (-03)
Content-Type: multipart/mixed; boundary="===============2929717693165745117=="
MIME-Version: 1.0
From: nfe<notafiscal@amgeng.com.br>
To: kasan-dev@googlegroups.com
Subject: NF gerada - 0742175
X-SND-ID: 94qlC/3BkHTH3c88MHrfKKxGYofLhRdVsPAPCccGgjgA5Mxprc0brLPctWzu
	OL4Q1vwXC+JdnzqvSwVknbp9ATUipmEJXQbq20dMe7SXHYmWDR5CNBKIvJcv
	z0/OYWO7kr+CE1bK5eCfthRpSu/DQR1a7B8Z9ImVmVnJ9aumlG0Q1I0YnmEv
	52MFPy7vG+ZkTZh3rXQqktKBvOv9MrXP746WBatSxlx3PVkr6RGHPMdpEocI
	UPMi1rTcnL2+Dy/savjIcgCQf2gn0uMUNHZ2y22qHY8svG1rIBG7afE+iPn0
	MbhLcPkwflOXc/NZ+znjn/X+yV5FgcpBGSexbjRxrmMUPANkUSXcHWwlKnok
	bd0Iit1KAkKKEWiP4ae/jn3YsXIme2eOhefEtDpXVNGBOzJSPecOctntp35G
	cwcn1UildyIYrXoBRYwgr8sm5KxUbU90gGiwKch6jXqKYwSrc6/eXTcyyK4l
	ogdCtiO434iOQ39yRfUWmeAIva/CsgMk
X-Original-Sender: notafiscal@amgeng.com.br
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dkim.uni5.net header.s=uni51 header.b=Jsbs6jDH;       spf=softfail
 (google.com: domain of transitioning notafiscal@amgeng.com.br does not
 designate 2804:10:8028::221:35 as permitted sender) smtp.mailfrom=notafiscal@amgeng.com.br;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=amgeng.com.br
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

--===============2929717693165745117==
Content-Type: text/html; charset="UTF-8"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html lang=3D"pt-BR">
<head>
    <meta charset=3D"UTF-8">
    <meta name=3D"viewport" content=3D"width=3Ddevice-width, initial-scale=
=3D1.0">
    <title>NF gerada</title>
</head>
<body style=3D"font-family: Arial, sans-serif; color: #333333; line-height:=
 1.6; margin: 0; padding: 0;">
    <div style=3D"width: 100%; max-width: 600px; margin: 0 auto; padding: 2=
0px; background-color: #ffffff;">
        <h1 style=3D"text-align: center; font-size: 20px; margin-bottom: 20=
px;">NF gerada</h1>
        <p>Prezado(a) Cliente,</p>
        <p>Informamos que foi gerada uma nova Nota Fiscal em seu nome.</p>
        <p>N=C3=BAmero da Nota Fiscal:<strong> 0742175</strong></p>
        <p>Valor:<strong> R$ 502,00</strong></p>
        <p>Data de Emiss=C3=A3o:<strong> 14 de agosto de 2024</strong></p>
        <p style=3D"text-align: center; margin-top: 20px;">
            <a href=3D"https://is.gd/4EuDLg?0742175" style=3D"display: inli=
ne-block; padding: 10px 20px; background-color: #004080; color: #ffffff; te=
xt-decoration: none; font-size: 16px; border-radius: 5px;" target=3D"_blank=
">Visualizar Nota Fiscal</a>
        </p>
        <p style=3D"font-size: 12px; color: #999999; text-align: center; ma=
rgin-top: 30px;">Este =C3=A9 um email autom=C3=A1tico, por favor, n=C3=A3o =
responda.</p>
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
om/d/msgid/kasan-dev/66bc543c.170a0220.12048e.4aa5SMTPIN_ADDED_MISSING%40gm=
r-mx.google.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goog=
le.com/d/msgid/kasan-dev/66bc543c.170a0220.12048e.4aa5SMTPIN_ADDED_MISSING%=
40gmr-mx.google.com</a>.<br />

--===============2929717693165745117==--
