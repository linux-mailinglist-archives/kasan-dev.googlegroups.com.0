Return-Path: <kasan-dev+bncBC6K3RUV2ELBBUX7TOYQMGQE75YP33Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 322938ADAFC
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Apr 2024 02:24:52 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3c61160609csf7454510b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 17:24:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713831890; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnSRYDIghxYeK4EmLK4k+irVhi2Dk+cABnOkBb7F7gW7QammjF9/d5bNf5olMBRRTg
         YyVB3Jruoi7zHgjBi6XqX/vWstL3pO9a6mWbPwg94QeB+mg1ri/F1pWyDj6TnqHQmfPX
         eSuUF2zNVRYW8+c0nAFns7mCYF3ZyNal48KBRNemsU8zF2KvzbQzI+fOyuF6XdQpLxO6
         dWFYwEGQMc+Uk1c5rMrQ42jTVn1PDZcYtOmj1iscC6Qs0m6ABxRNENAkJT9K6uGmjc9s
         zObvT4M8iRcDGLdajIOQFESqSX0y5UFnwkDAeWs/CXSMBNI1v04UoSi7Lc+ysD59SCVy
         wC6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:from:subject:reply-to:mime-version
         :date:message-id:to:content-transfer-encoding:dkim-signature;
        bh=h1J9vpFqrayIHz2yo0szwPUCU5ut+/6AClZpgQ64Fxg=;
        fh=YApOLrapr/GBq7rFn997uMsQpwEQs7oygzbqgH61BR4=;
        b=wqR236RcvdwMm0syB7WUr2XiUThBeuN/aixZ4J4VojDqPhozjJqu9tVlhQFDAIOgsK
         OsaLdqHcqIFPCF4M5SPkvFuDN/rMfD9rMs7BXIB1iGcYT0kXPw0nmAJ1Ql1zOozqgmh/
         OEy82t1/m0ownTOR6lkpot+D8mNUnj9FgVBUvjhjfa5II7ub4C9f6EJBtt/4OluEy2lv
         /6Q06srJodWGWTp55yceOQ0+x2LviShSRkr831lUXEP2+Fci5eX37QxIbDU+1mIsEWLq
         VO8b/MeP/AoiOT9Mh4ThS+MWw2COohiNbjAlxnecFRW3Xg7HIBC0gjrkL86nTelMoLte
         OCHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wufoo.com header.s=scph0817 header.b=oanyiYCq;
       spf=pass (google.com: domain of bounces@bounces.wufoo.com designates 192.174.81.59 as permitted sender) smtp.mailfrom=bounces@bounces.wufoo.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wufoo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713831890; x=1714436690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:from:subject:reply-to:mime-version:date
         :message-id:to:content-transfer-encoding:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h1J9vpFqrayIHz2yo0szwPUCU5ut+/6AClZpgQ64Fxg=;
        b=H/XSQUQGE6sLAtgrZh4jNKN/OZvOUZQ1lhY7IajQHRNyfgePHXOsORkaymK/E/EdSk
         ZAWX0F5fnVWLX4YB/dbSH2iRZaHYehg8ukbuUKl2mI8sTeaWPFbrdDx0d6ihglWH6015
         WEoMc0TmbwPn80wQ3yGKVMN72+dYbQmpdAjLrJJ7LdD4G39NadMQpntQ+7OCXoUq8GW+
         NK7JnJf8aEiQZQpDWopkXE2djQktVAk5bqF96Iln1wlUjNTlgRBr2oyuAzik13mRP3uI
         dvazMnRhDUrhu7ehIYQRdcZggkG/FQhk+rXKgJ2nJQT02F1xN6aWi3y/ZFHatALSNhzs
         mIeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713831890; x=1714436690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:from:subject
         :reply-to:mime-version:date:message-id:to:content-transfer-encoding
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h1J9vpFqrayIHz2yo0szwPUCU5ut+/6AClZpgQ64Fxg=;
        b=vGMcyJrwTgnB3nyEDlCtjEcAeyHREu27Y+nIMQsat1Fopg262yfUPn+gK2EgcqQG60
         faE1qO2XEaKOeFq9egCgkzbdyCvse8cxXqnC57SsoC80bewnkfwUCWUiD+tpHTSwsX6T
         S4S4jCN0m7CUkay8ghb71n8dzCfJg6LKbmAW4U3063Mc/FEkfpnw+4sslcjP3AvolizZ
         OXY0JXQjqjQYHAEEOyIvNOcVNKjrlJ+K/XGAu1PJmSGdtFqZrRiMSBQ6lYxkVqNriWCE
         Ka0S0Z7L78Fj2pd9yl698ofC+hMvvkfTt6amt3ox8RceaADof/Zg381iHH8l6jcOMQPO
         hyxA==
X-Forwarded-Encrypted: i=2; AJvYcCXtqNQSLL7Ttx8PPPOVxK8h1H2GuQ2Fxt2pOPxeCoYNmZg5bZF5xxg5UR5ROrnjDXmQE/VLzxhkkPNYfJZ6eSHHxdcr5VmaoQ==
X-Gm-Message-State: AOJu0Yxyg549OL9J8Q2FByibuBJJDv8jldBmd1cOxw0rGMts1mmm8AZY
	lDcfbguu/y9Es2BTpXmkUkfmpJoe/jeU6kzq5yc+fpWZiPsOz7Gh
X-Google-Smtp-Source: AGHT+IEVEM2l9UKj84sW9agfzX1ZzZ1wyIoGnayj20WvH5J/n8qNkGxXaTQCVAw1npCYYk1LSuep8Q==
X-Received: by 2002:a05:6870:a3d1:b0:221:8b50:f1a0 with SMTP id h17-20020a056870a3d100b002218b50f1a0mr16256199oak.19.1713831890393;
        Mon, 22 Apr 2024 17:24:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:338e:b0:23a:4af0:c15f with SMTP id
 586e51a60fabf-23a4af0c35dls930193fac.0.-pod-prod-08-us; Mon, 22 Apr 2024
 17:24:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVRXbefJyjCKGQvfx57735JksunFcN5WoEhTgXHvR5Lir4K+vht350E6TOdkI6toGpNIjJjLY1x3zIox1l3zgV1leT+W1P6eRkvA==
X-Received: by 2002:aca:1216:0:b0:3c7:5031:7e6 with SMTP id 22-20020aca1216000000b003c7503107e6mr11316223ois.29.1713831889556;
        Mon, 22 Apr 2024 17:24:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713831889; cv=none;
        d=google.com; s=arc-20160816;
        b=WBjQjRE9ly5AMG1LGZiAEGUJHFSx3g0ZmS9tXp4u3uQ8LKKMaeiuGeMsIKrNek+UmY
         rivSdsjy4p1QlXy4u/M6HAWhlZ/LbvcndWM4Kg/yJGNkdK3n3eor7Bc8+/sHfEupdQze
         reZwM7BAhRaS/A/VHohBRh0dOYwEX3eNHKr/Fy9HbSZdTAVhQOKT1UY+akfHpYrVQ8wV
         UVn7OG2ROgZ5TpFvhSTbzrItfQcjJyUVdf1jxp6J09u1EU4atoOxJl/BAvLxRBAmEj/5
         Gxokq3hGV2X/3SjAD4xwEAn7OxVcGSY5w9Gvm4NJFTSRXHNI4FmukKor4hQAjytHTpPU
         Dfbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=from:subject:reply-to:mime-version:date:message-id:to
         :content-transfer-encoding:dkim-signature;
        bh=cvubprsx6iqdX+anZy31X5UKDkEL6pZKqufQ+poXsVE=;
        fh=Enfpeo/6o/VYlRaVeDeI2c1ipeCEQuKIBrY+skoGByU=;
        b=c7lCWpusmFnYtyZ+otM4bqAH4ye+sIxIUQJduQiwWrJuFMgntOFB9d+hL42SkWd4YY
         IMUEoe8hPnxoRjD8dS3nh6YHEVSqbDWIkg8Ikzb7YjIArIPx1WtVZD3dWsirsIHaQpHp
         SsnN58PVp3qvMLQKZD4a808J/hET6SDdl//tt1cE/tHbsLUCupEIBsaCtJYq0lXYSM98
         vQ2BvKKUCLkshXTNVLNr6HD3n5H8/W78ZWaXBYielkkMwE1VbCDnezrUjNRRLO97C5LS
         6s3pWDvPRgvBtAPWA/nMIIhZad8kX1SI/B8O8DC+3eHv3+zuOJ2pc0cLEHZqTbMoNt9Q
         zUrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@wufoo.com header.s=scph0817 header.b=oanyiYCq;
       spf=pass (google.com: domain of bounces@bounces.wufoo.com designates 192.174.81.59 as permitted sender) smtp.mailfrom=bounces@bounces.wufoo.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wufoo.com
Received: from mta-81-59.sparkpostmail.com (mta-81-59.sparkpostmail.com. [192.174.81.59])
        by gmr-mx.google.com with ESMTPS id bf7-20020a056808190700b003c614d0a6b2si911639oib.1.2024.04.22.17.24.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Apr 2024 17:24:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounces@bounces.wufoo.com designates 192.174.81.59 as permitted sender) client-ip=192.174.81.59;
X-MSFBL: QNnx0wZ4oWoxh9dRc4TpQQ+lxsS9eIxu0/94cDgTQ34=|eyJzdWJhY2NvdW50X2l
	kIjoiNSIsInIiOiJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsImN1c3RvbWV
	yX2lkIjoiMSIsIm1lc3NhZ2VfaWQiOiI2NjIwZDBmZjI2NjYzNDcwMDk0NiIsInR
	lbmFudF9pZCI6InN1cnZleW1vbmtleSJ9
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="UTF-8"
To: danedone@gmail.com
Message-ID: <64.90.04063.0DFF6266@hs.mta2vrest.cc.prd.sparkpost>
Date: Tue, 23 Apr 2024 00:24:48 +0000
MIME-Version: 1.0
Reply-To: ismailabdullah8686@gmail.com
Subject: HI
From: "'HI' via kasan-dev" <kasan-dev@googlegroups.com>
X-Original-Sender: no-reply@wufoo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wufoo.com header.s=scph0817 header.b=oanyiYCq;       spf=pass
 (google.com: domain of bounces@bounces.wufoo.com designates 192.174.81.59 as
 permitted sender) smtp.mailfrom=bounces@bounces.wufoo.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wufoo.com
X-Original-From: "HI" <no-reply@wufoo.com>
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

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns=3D"http://www.w3.org/1999/xhtml">
<head>

<title></title>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8" />
<meta http-equiv=3D"Content-Language" content=3D"en-us" />

<style type=3D"text/css">

* .location a:hover address, * .location a:hover span {
	color:blue !important;
	text-decoration:underline;
}
* .file a:hover .file-name{
	color:green !important;
}
.rtl .info .var{
	float:left;
	padding:0 10px 0 0;
	margin:0 10px 12px 0;
}
.rtl .info h2{
	clear:none;
}
.rtl .createTD{
	padding:0 0 0 12px !important;
}
.rtl .updateTD{
	padding:0 12px 0 0 !important;
}
.rtl #entryInfo *{
	text-align:center !important;
}
.rtl table .h2{
	padding:0 0 7px 10px !important;
}
.rtl table .var{
	padding:0 10px 0 0 !important;
}
.rtl .mapicon{
	float:right !important;
}
.rtl .adr{
	padding:2px 25px 2px 0 !important;
}

</style>
</head>

<body title=3D"3895604">
<div style=3D"font-family:'Lucida Grande','Lucida Sans Unicode', Tahoma, sa=
ns-serif;">
HI<br />
I Have tried reaching you but failed. Please are you available to speak soo=
n.<br />
<br />
Regards,<br />
Smith Johnson<br />
<br /><br /><br />


=20


</div>

<img border=3D"0" width=3D"1" height=3D"1" alt=3D"" src=3D"https://click.ou=
tbound.surveymonkey.com/q/cv4GwHcfezMgfMlXyC_ZRw~~/AAAAAQA~/RgRoCYTQPlcMc3V=
ydmV5bW9ua2V5QgpmIND_JmY0cAlGUhprYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbVgEAAAABQ=
~~">
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
om/d/msgid/kasan-dev/64.90.04063.0DFF6266%40hs.mta2vrest.cc.prd.sparkpost?u=
tm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/ka=
san-dev/64.90.04063.0DFF6266%40hs.mta2vrest.cc.prd.sparkpost</a>.<br />
