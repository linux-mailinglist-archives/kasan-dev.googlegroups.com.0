Return-Path: <kasan-dev+bncBCH2XPOBSAERBFUB737QKGQETBY6GFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1016F2F5527
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 00:22:00 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id d7sf2807097qkb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 15:22:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610580119; cv=pass;
        d=google.com; s=arc-20160816;
        b=SczUfxQWL/zAa/t9iCX1nyxUCLB+CUWqezoJ+1sv6s07rNaPJjB0tS3FXf7P8jFQ5C
         1cXfztKxy0m9AaZEMIZsSgFOyOw2wUpLB9c5jH5Qy21wH+ck3XgGQrQUOQUJOO5iyUY1
         NdD2lStqycHmeQKWsySaFrPjGWhQ0aJV6nghOeNVci+FdYfFhPyjv8j1JObng3STZSl7
         MutUWXNbopfO4r91VozmABTN0+PR3lBjVPkt0Alc36ZMSGkY/qFeH5lbtz0esLBK5qgS
         SK5gvNYwJ9RnhYGKw965+CddOA3p9NsHhAY3eGdXlNVqobLFaPgstMtauC+BhAUUK+X6
         tkUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature:dkim-signature;
        bh=4+ELZNkouOlH2wq7rlb5/Y2M5W+tGVl3BCHRV6kN3KE=;
        b=oED64ckpeT5gTcCEXy77av71XvxbxMQ3eAUnJ5lxdwpaVoeL6JvY5/4BeiVgWK8EBB
         M4nMA/+5oUkHV5wbKfJrfWyFn8x9MIYZQtCUL4xSJrpcF4WZkf1klbsI6cw2DHk0aklG
         bfvgsvK96iIiau5/7Y6b8mjTlFt352EO8sMAFSWh0wMAGC71ZXiaw2l6rRMSAz8K/gQ7
         7pAVx+J7cqtUVN2nCRZAkRbjr+jGJOtvzd0eVyS9FjISEeNHbxU8ZuwC6poIy2th71N8
         W5ZLOFyFvJ+MkhZBp5MDEZ5tpmFG7a+nkkDIilNMdY/KHBYO4Um/sZp78MIRclPadvRf
         udgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LWvIQxVi;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4+ELZNkouOlH2wq7rlb5/Y2M5W+tGVl3BCHRV6kN3KE=;
        b=BHKJY2CVd5RuZSNe2CDhDIZqw+I78bWB4MPSv6bwOjJakMV0FLXGOCkkHyZU+6xiM7
         nmfzG6BbQFB4h5LEaq5jY2XMqPkhsheZBXYixjXv2OGPotV8OXrOG0VXucnbKAjwQCVi
         i+0fd/b5vdSOD1/nNONONQesTzuSk5+YLazvi/PGOdOWULQyzFVyhWpCRmyBzGYhmrT2
         5sFOqm2V2O1XFZ+PikXUtEBUKQve9/fjcWGbquDIPZ8KMr9TqhCPNFIT+B5kexjk3bJy
         jLcjDTQ9q/DrXXnjjm1nHnIGCEnoFqkGlYEFOrVp10RZFd1EBF97Cn1M13zpnr9gd0Ly
         KVyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=content-transfer-encoding:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4+ELZNkouOlH2wq7rlb5/Y2M5W+tGVl3BCHRV6kN3KE=;
        b=JOKe0WGSPct0hvO1WqNkJPf3Q7+tkAVFlnn3Pfsk9GLl2guBX9MButIUkNdtEadoNg
         gy77mjQufKDooLEY1ogaGySrFjtHmZKcv+wkYhtoQ3DFmAqLxlATTvbxZ95vmZr5THLD
         QTtahJa/GXJs4Q4rL/fv0V0DdLBuOpzsizuv3bd5/cKsRc9OvJ8VuUyZAfP4gZ4b068v
         e8zGdYUJx6lb9Wlo38LfFYVIvtNoMlJIqJmAZRMhrTyIsm4keaMfLZcPonhFZnf3wR+a
         NBhpZxSsj4MI+Fdf1mUrBbKinTOBH7lUoSccelE7fN1E3mobJbo0QoNuZme2xOwd0OiT
         GsEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4+ELZNkouOlH2wq7rlb5/Y2M5W+tGVl3BCHRV6kN3KE=;
        b=k/wW2ChX4kMgaqTVsHqjrlS1RBIdqx7BedXRPqhnbwVuTCCz68HyoTl7Cc6TP4cv6S
         65BfywozrIkWDmyUWTGLV1FfDiOtsMeuwtvDfywBVH3zWc6mCHFUHk3XKNFOteqELsws
         LeadESSLfE1g8lYWwBPsbiKIddvqbEGgyel1mPzuk4cK4Itb/jX4fuby9eHkDJmLYSO+
         ZVJRPiO2m/is+W+J/+7PrDEWdDpYONVIXCjJiWYubeNGDhwPvizMZfBMyDcsxnFyuLtD
         b4ASPRq9osZ15TOVV7cEVuY/PPqbWAud5SO8QDQQ6OlSbwExAUbyj+RQRq1NFSkQ4amQ
         bsAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532T9OzwCwFIxU6wjXAiix/jX+m+ujMpnXiP+w2AdlABJFn/kcBh
	q30U9EVFkVO3GLBj9F3Sq/M=
X-Google-Smtp-Source: ABdhPJxGdJlfbuqS/6DH/XNsmwHfTgfU32uLYsyVMoalvV2I6Muu0YuYLFQ36ASJQWTLcEVB+LTyVQ==
X-Received: by 2002:ac8:7654:: with SMTP id i20mr4524778qtr.291.1610580118960;
        Wed, 13 Jan 2021 15:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:702:: with SMTP id 2ls1873561qkc.11.gmail; Wed, 13
 Jan 2021 15:21:58 -0800 (PST)
X-Received: by 2002:a37:8087:: with SMTP id b129mr4643411qkd.138.1610580118455;
        Wed, 13 Jan 2021 15:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610580118; cv=none;
        d=google.com; s=arc-20160816;
        b=A4SzZUWsoPOgFEQiUZO8PRUewnl8dTExZvbh5BjvMse6oebq1m78OkdTv0LzmzowDM
         F4LQ2hq5dx/eq1NNeR1mhTAv1J5rBAzZwC9Qw7JOZlM5bZDQqz87a8msFEpDVjy7TW6C
         MBjZSGQihGrSF6eGAgeE5H6Ze5YkhZcI5br9KBodWbiPg8e+nnOoPqIAk2PuvW0aJJPe
         3OeiRLU1Wsf9s2Q1cAFg+w3aR9UijDZgN/12z8iVwzm5MvqCr8L6saudLG0WrFuR1Tvw
         hk9og1Nzx0EugAGN50h2nHmgwmmcuX1NvCD6xgCCM8T/vhqWtU+7qYELDyXxo5QlJO7h
         eE5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=k1M9lmOLZO2GOLwUA/lZ2QYfUehL3IPJ5GZ4x3Wza2M=;
        b=l7ttND6PURpi6+81Rt70wjVRbPqyv/Kpi13gs6W5FgYW7Xcwv+2sLe9QXgd60kM7+R
         wg7y9LqTlgvTVoq88Khb2Q4euiUvFUV4LJnMCCGW0JujMRSjuZFF7rwRGsoMc2Q01UYm
         nAx1mRu2ruo94nraufz10bdKAGWR9pUbkA/eDn6wU8p3uCcs1qb3+9O8eCaE7tbpLH8r
         jwIIvegEne/Gg/KQEZIk1pCIoZjujscO9dSNT6jRgC4eulecSXk7qtxe7rZy72tWAjfa
         jXL6Mnz/vHBJDI+c47EqMhgwcoQrVYBKMskQt7dZtoqR7/Gx+TxmFUodP8MxxPK0UsKR
         Xxlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LWvIQxVi;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id z94si400243qtc.0.2021.01.13.15.21.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 15:21:58 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d4so1943728plh.5;
        Wed, 13 Jan 2021 15:21:58 -0800 (PST)
X-Received: by 2002:a17:90a:4545:: with SMTP id r5mr1787274pjm.212.1610580117344;
        Wed, 13 Jan 2021 15:21:57 -0800 (PST)
Received: from [10.188.0.206] ([45.135.186.83])
        by smtp.gmail.com with ESMTPSA id c14sm3510041pfd.37.2021.01.13.15.21.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 15:21:55 -0800 (PST)
Content-Type: multipart/alternative; boundary=Apple-Mail-EA7B5BFE-EEE9-4737-A521-E45AC5C55A8F
Content-Transfer-Encoding: 7bit
From: =?utf-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Mime-Version: 1.0 (1.0)
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
Date: Thu, 14 Jan 2021 07:21:53 +0800
Message-Id: <66960526-F9D5-4668-9DBA-A8A399BF5AA4@gmail.com>
References: <CAAeHK+y7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4xa6g@mail.gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 syzkaller <syzkaller@googlegroups.com>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <CAAeHK+y7NQQaxKgYmWZQKvV55zg79NGb3CHZG4vbuJrPi4xa6g@mail.gmail.com>
To: Andrey Konovalov <andreyknvl@google.com>
X-Mailer: iPhone Mail (18C66)
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=LWvIQxVi;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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


--Apple-Mail-EA7B5BFE-EEE9-4737-A521-E45AC5C55A8F
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable



> =E5=9C=A8 2021=E5=B9=B41=E6=9C=8813=E6=97=A5=EF=BC=8C=E4=B8=8B=E5=8D=8810=
:17=EF=BC=8CAndrey Konovalov <andreyknvl@google.com> =E5=86=99=E9=81=93=EF=
=BC=9A
>=20
> =EF=BB=BF
>> On Wed, Jan 13, 2021 at 9:38 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliang=
abcd@gmail.com> wrote:
>=20
>> Hi Dmitry:
>>=20
>> I would like to verify if "KASAN: use-after-free Read in ath9k_hif_usb_r=
x_cb (2)" shares the same root cause with "KASAN: slab-out-of-bounds Read i=
n ath9k_hif_usb_rx_cb (2)".
>>=20
>> However, I cannot reproduce these two cases since the firmware for htc_9=
271.fw is no available. Do I need to take some special steps to get the fir=
mware working? Thanks in advance.
>=20
> You need to install the firmware-atheros package, as done by the create-i=
mage.sh script.
>=20
> https://github.com/google/syzkaller/blob/master/tools/create-image.sh=20

No wonder stretch image has this driver. Thanks for your information. It=E2=
=80=99s really helpful.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/66960526-F9D5-4668-9DBA-A8A399BF5AA4%40gmail.com.

--Apple-Mail-EA7B5BFE-EEE9-4737-A521-E45AC5C55A8F
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><head><meta http-equiv=3D"content-type" content=3D"text/html; charset=
=3Dutf-8"></head><body dir=3D"auto"><br><div dir=3D"ltr"><br><blockquote ty=
pe=3D"cite">=E5=9C=A8 2021=E5=B9=B41=E6=9C=8813=E6=97=A5=EF=BC=8C=E4=B8=8B=
=E5=8D=8810:17=EF=BC=8CAndrey Konovalov &lt;andreyknvl@google.com&gt; =E5=
=86=99=E9=81=93=EF=BC=9A<br><br></blockquote></div><blockquote type=3D"cite=
"><div dir=3D"ltr">=EF=BB=BF<div dir=3D"ltr"><div dir=3D"ltr">On Wed, Jan 1=
3, 2021 at 9:38 AM =E6=85=95=E5=86=AC=E4=BA=AE &lt;<a href=3D"mailto:mudong=
liangabcd@gmail.com">mudongliangabcd@gmail.com</a>&gt; wrote:<br></div><div=
 class=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=3D"margin:0p=
x 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><d=
iv dir=3D"ltr"><div>Hi Dmitry:</div><div><br></div><div>I would like to ver=
ify if "KASAN: use-after-free Read in ath9k_hif_usb_rx_cb (2)" shares the s=
ame root cause with "KASAN: slab-out-of-bounds Read in ath9k_hif_usb_rx_cb =
(2)".</div><div><br></div><div>However, I cannot reproduce these two cases =
since the firmware for htc_9271.fw is no available. Do I need to take some =
special steps to get the firmware working? Thanks in advance.</div></div></=
blockquote><div><br></div><div>You need to install the&nbsp;firmware-athero=
s package, as done by the create-image.sh script.</div><div><br></div><div>=
<a href=3D"https://github.com/google/syzkaller/blob/master/tools/create-ima=
ge.sh">https://github.com/google/syzkaller/blob/master/tools/create-image.s=
h</a>&nbsp;</div></div></div>
</div></blockquote><br><div>No wonder stretch image has this driver. Thanks=
 for your information. It=E2=80=99s really helpful.</div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/66960526-F9D5-4668-9DBA-A8A399BF5AA4%40gmail.com?utm_m=
edium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-=
dev/66960526-F9D5-4668-9DBA-A8A399BF5AA4%40gmail.com</a>.<br />

--Apple-Mail-EA7B5BFE-EEE9-4737-A521-E45AC5C55A8F--
