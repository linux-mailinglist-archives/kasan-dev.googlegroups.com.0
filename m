Return-Path: <kasan-dev+bncBCUZDTX4YQNBBI4ZTOIAMGQEUFTG7HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 836A34B2EDE
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 21:52:52 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id i7-20020a056e020ec700b002be118c9b21sf6682298ilk.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 12:52:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644612771; cv=pass;
        d=google.com; s=arc-20160816;
        b=NS8Xk25nBu/6ZuSQSH34P08qGujlKHP2COthsVZBBpg2brag7KrLP7avTXmHShEHkz
         xmVONtzg2NGMdf4phu6HJV1H8UACXktLmn/avzyVos/lCWq5kn/FZEFXPD9nhb3Ov62E
         3QC7lgYtCw/WPdivCVTm4cXwuGBjv0AxYXi9tyNDxF9c1+IIfhs2JO2cdBPWr1GA5G3Y
         2e74NOopn/4IMwvx+HR06gApx+J6C6cG5i5C+393HdTM89n1wkStfCCI94bIUgAImiGE
         kSp7uUCFIiVCUKW3Cc88wjjAjVJU1F0hQh3cPf5uZlfxpMEOjSj1HgieKTLxtGz8MkvS
         Rylw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=GcwYutKf/wfMpZtS19A9z8vNNM6x5j+rwFOUDpgp65Y=;
        b=0piJ7d7jpRgczvVYh7DJv66nMP7UHHW9FeTk4jiIgXMAuQtqTCe+kg7RsRlV4y3GPd
         jPrhmJTY7DtV+GlXz6+OI51nuBas27N/zmuWnPqc9rZVhegPwA4Roj02bEu4bwAGn8Gq
         8j9WptEN5n4WYG9SEodyIZDfNQ46ERtDqRBDTamKnZ78+8dkvrRIO3x4qmm18PF4b5YJ
         eqPDuQaNTun+OE3pjolOvVepoo9LMP2SXiQyYj/JxXlabYY1tgwgTgYgecVA37RherAI
         UEIMD6Mtui52YHMLkwqNmL/uoqePH4b8pn/7lMtt//ieOa9kODB6BnOUlu8pp+ePz+6Z
         8LZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZxtKosrb;
       spf=pass (google.com: domain of morganblakechurch42@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=morganblakechurch42@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GcwYutKf/wfMpZtS19A9z8vNNM6x5j+rwFOUDpgp65Y=;
        b=DVKRuQ7Vskk4Iz7WuwuR7Q56TxZm799D0I9P3KDiAHGW4h+EaauKlHTTqpJN969mnp
         MICNXJGHxeDhdn5Ejg/1XdcO23CplmDFiLJdvanYsAbOtlTe3Byd+tRNyjqs5k6ALRlv
         hevPNp5DKaA1HbIoJfEs1iPGOdUpl9Z00fAPSo0w++ob1URGMv8fz8CKt9jQMNcAPjgZ
         DJhWvZuYtdB4K6fdQg0Iyc18B/qK0okGZPLLgRjRGr5qj+iusDqadEaJcXjgOmQlBh2X
         8y/O9IRVGDTU3GZY5kcVVZP9ytnqBbkD8AngH/p6/VJfTjAveSFt+n032i+gzFLmQdej
         CHvw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GcwYutKf/wfMpZtS19A9z8vNNM6x5j+rwFOUDpgp65Y=;
        b=j49PIQLeRV1R5Bs2971RQLLVruG6hGuAyc4oS1Jn7r84BNBsoTgsdV2jAxMiJD/53P
         +4EXDfSfArAXQFpZE8dZjY2T2dj2sAj1DaXG9xccUcZtlJ2QfbI7mju1yzv5OuICeyFA
         L4XNGdvvA6Yg2aHmTIhIU1aQ9XVYmoNKwjjQWR7fSEZlDeF/q9iOFiU77kshWazQgaJW
         nC04esyfkasC4emUAcAdEYGH7xw20o8rOInx1XqxnZ0Jbl6Uvvln6fRpZas9/+GpjTPT
         dwZYQ6hQPXDZlMM33DRdls7L/qyzkX36Jn2TbffCYjCg/4+uxjRANZlQumBMGCg/HayH
         Hc0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GcwYutKf/wfMpZtS19A9z8vNNM6x5j+rwFOUDpgp65Y=;
        b=R9uAwlU4LgCyasvy6hSUCcl2Le/fUNfLJxbP7P+xACdjUVGmyrs6591IPlzlJ1tq+W
         b65jkEFF2b12qViO/MBtuXcpNq1yvp4Zw3E2Ntko/zchayyLSR0tykG7uAZ+5s68vrod
         RoJzbdQVUqNMb/YAbACB+9Isd3tOowI9f0H6XuEq+oQnBMyhoOipM2gR/Bmz7o9IAhVJ
         TqlnWgLRx9nFPE8S3xFYtJ0/8zOMow7Ghf7qcpLavs3nKck9D5tTUXJkqo0bhdm7FN3I
         ZxBPl79El9j6+537uh3WWF9uEVA56F//Tw4bbIc8cVVD694qo1fFgXWCJvQlKxSubRGE
         4Oqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533d3aXWYaD2PcnJ8sLYqNpSss5HTSCRvWNBkS9SkaFTOQBKvaq5
	sKy4tkxfxOUw8uyipXwDtPg=
X-Google-Smtp-Source: ABdhPJyGKulgpHSKugpbb6pVJ6I+erpj4ewvTFBi0jpkmayjAbVbK9Zv0vU72guvZTDMtvC2nsrNYQ==
X-Received: by 2002:a05:6e02:1786:: with SMTP id y6mr1881775ilu.152.1644612771289;
        Fri, 11 Feb 2022 12:52:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1490:: with SMTP id a16ls1118336iow.7.gmail; Fri,
 11 Feb 2022 12:52:50 -0800 (PST)
X-Received: by 2002:a5e:8a45:: with SMTP id o5mr1740061iom.169.1644612770857;
        Fri, 11 Feb 2022 12:52:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644612770; cv=none;
        d=google.com; s=arc-20160816;
        b=rJghochZweg6Z3RJLH/COXHSUPLIyyv5ubKlL79009EkX0QrAs5pDf0e6kSdMi7rNd
         4jqUxOd7HTVRL7mAfI5fwoV66YEk2gVj/e8z0X84oT90/eD/8/fU+cOYBdwRoi3OJSHQ
         WJUCxmfLL1siOix4PG6Zj1Z/J6mjSmcrZ2bXk+5t7LcVbmV0t+0qN3LzYwCJExFmvn1c
         qxsqd3NX52+ugChKczLFe+v+80912xo7n/ExavMGBfqLriWDNnlcfwUMsYPQIRl3o+KK
         K73BVAXtseJYyTHrIKKlbA7GzMFG2/eTB5/PLQfqexKvJv707ArRiS6aXPWtJQJDn06M
         Zowg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=TEb0GIOxViSIITSa/u5KZScyU1V70ms7NEJGPl6eucE=;
        b=RjwMYl1M78rp+lOTXw+8FEY/BGHb5bgL3BpyEKYYn3/ZWHOsokNxz+442w+5GNlhcJ
         Kr/vNp2qcZw0pfQGZdcuBD7LVtS9BcNDCieUHh5N8fG5L/kbzP1N7R+6NLM11+LoGwJb
         /EV6Bd595ob5SQagy9OuixWx2Bm27rL7rMso29YYl8Od+Po3ohA0gZ1XpywoG9pZVMcY
         UhjBIz1nH/m7da8PgYNW2XgFfGwN02S447QX0dIc33KejgJN3r7Z9tOvImvF1wT2qYLz
         YTimRG+3PgVqrnbEcCA2cU2ebRChj/XbRpV9gzeAYLgcVBIsElXv7d5ZvrlFzPkiNI1y
         GYmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZxtKosrb;
       spf=pass (google.com: domain of morganblakechurch42@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=morganblakechurch42@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id d15si2727528jak.1.2022.02.11.12.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 12:52:50 -0800 (PST)
Received-SPF: pass (google.com: domain of morganblakechurch42@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id f13so7801247ilq.5
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 12:52:50 -0800 (PST)
X-Received: by 2002:a92:da0b:: with SMTP id z11mr1719169ilm.321.1644612770282;
 Fri, 11 Feb 2022 12:52:50 -0800 (PST)
MIME-Version: 1.0
From: akeem owonikoko <morganblakechurch42@gmail.com>
Date: Fri, 11 Feb 2022 21:52:36 +0100
Message-ID: <CAO-qwSYA-Dnu17ti+w8BwA+XHC0pgjxv9AnL5py=nB2HGtViUA@mail.gmail.com>
Subject: EMPLOYMENT
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000f745fd05d7c43f8c"
X-Original-Sender: morganblakechurch42@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZxtKosrb;       spf=pass
 (google.com: domain of morganblakechurch42@gmail.com designates
 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=morganblakechurch42@gmail.com;
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

--000000000000f745fd05d7c43f8c
Content-Type: text/plain; charset="UTF-8"

SEMEN INDONESIA (PERSERO) TBK
The East Tower 18th floor
Jl. DR Ide Anak Agung Gde Agung
Jakarta Kav.E.3.2 1-12950
Email: <Email%3Amorganblakechurch07@gmail.com>morganblakechurch42@gmail.com


I am Mr Morgan Blake Church , Job Instructor for PT Semen Indonesia
(Persero) Tbk and Accountant/HR Manager here to present to you a Part
Time Job.

Work from Home/Temporarily and get paid weekly. We are glad to offer
you a job position in our organization, We need someone to work for
the company as a Representative/Bookkeeper in the USA and CANADA. This
is in view of our not having an office presently in the USA and
CANADA. You don't need to have an office and this certainly won't
disturb any form of employment you have presently.

Our Customers in the USA usually make payments for our supplies in the
form of PayPal , Bank Transfer within the USA and Credit card. All
these are not readily acceptable here in Indonesia. They can only be
acceptable in the USA instantly Payment/24hour Deposit. Major
responsibilities include:

-Receiving payments from existing and new customers
-Distributing received funds according to given instructions Initial
requirements:
-Ability to manage payments between the company and its clients
-Ability to plan and organize his/her work
-Ability to contribute 3-4 hours daily.
-Full legal age.
-Authorized to work in the USA or CANADA

Advantages: You do not have to go out as you will work as an
independent contractor right from your home/office. Your job is
absolutely legal. You can earn up to $3000-$4000 monthly depending on
time you will spend for this job.

You do not need any capital to start. You can do the Work easily
without leaving or affecting your present Job.

Pay: A commission of 10% on every transaction. The Issue of trust is
very Vital, however, I believe I am protected by the Terms and
Conditions above as going against the Terms and Conditions will mean a
breach of Contract. We do hope that you find the offer attractive.

OUR REQUIREMENTS:

*VALID FIRST NAME:

*VALID LAST NAME:

*VALID ADDRESS

* VALID CITY:

* VALID STATE:

* VALID PROVINCE/TERRITORY

*VALID ZIP CODE:

* VALID COUNTRY:

*VALID PHONE NUMBER CELL:

* AGE:

* GENDER :

* VALID E Mail:

*OCCUPATION {PRESENT JOB}

* VALID DATE OF BIRTH :

*COPY OF YOUR IDENITITY ID OR DRIVING ID {FRONT & BACK}


ATTN :- PLEASE IF YOU ARE NOT ABLE TO PROVIDE THE ABOVE LISTED
REQUIREMENTS , KINDLY DON'T RESPOND BACK TO US.

Thank You

SEMEN INDONESIA (PERSERO) TBK
Morgan Blake Church
ReplyForward
<https://drive.google.com/u/0/settings/storage?hl=en&utm_medium=web&utm_source=gmail&utm_campaign=storage_meter&utm_content=storage_normal>
<https://www.google.com/intl/en/policies/terms/>
<https://www.google.com/intl/en/policies/privacy/>
<https://www.google.com/gmail/about/policy/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAO-qwSYA-Dnu17ti%2Bw8BwA%2BXHC0pgjxv9AnL5py%3DnB2HGtViUA%40mail.gmail.com.

--000000000000f745fd05d7c43f8c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><table class=3D"gmail-Bs gmail-nH gmail-iY gmail-bAt" cell=
padding=3D"0" role=3D"presentation" style=3D"border-spacing:0px;padding:0px=
;border-collapse:collapse;width:887.111px;display:block;color:rgb(32,33,36)=
;font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:medium=
"><tbody><tr class=3D"gmail-xHfw3"><td class=3D"gmail-Bu gmail-yM" style=3D=
"vertical-align:top;padding:0px;width:0px;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial"></td><td class=3D"gmail-Bu gm=
ail-bAn" style=3D"vertical-align:top;padding:0px;display:block;background-i=
mage:initial;background-position:initial;background-size:initial;background=
-repeat:initial;background-origin:initial;background-clip:initial"><div cla=
ss=3D"gmail-nH gmail-if" style=3D"margin:0px 16px 0px 0px;padding:0px"><div=
 class=3D"gmail-nH gmail-aHU" style=3D""><div class=3D"gmail-nH gmail-hx" s=
tyle=3D"background-color:transparent;color:rgb(34,34,34);min-width:502px;pa=
dding:0px"><div class=3D"gmail-nH" role=3D"list"><div class=3D"gmail-h7 gma=
il-ie gmail-nH gmail-oy8Mbf" role=3D"listitem" aria-expanded=3D"true" tabin=
dex=3D"-1" style=3D"clear:both;padding-bottom:0px;max-width:100000px;outlin=
e:none"><div class=3D"gmail-Bk" style=3D"margin-bottom:0px;border-width:0px=
;border-top-style:solid;border-right-style:initial;border-bottom-style:init=
ial;border-left-style:initial;border-top-color:rgb(239,239,239);border-righ=
t-color:initial;border-left-color:initial;border-bottom-color:initial;borde=
r-radius:0px;float:left;width:871.111px"><div class=3D"gmail-G3 gmail-G2" s=
tyle=3D"padding-top:0px;background-color:transparent;border-right:0px;borde=
r-bottom:0px rgba(100,121,143,0.12);border-left:0px;border-top:none;border-=
radius:0px;margin-bottom:0px;margin-left:0px;margin-right:0px"><div><div id=
=3D"gmail-:6l"><div class=3D"gmail-adn gmail-ads" style=3D"border-left:none=
;padding:0px;display:flex"><div class=3D"gmail-gs" style=3D"margin:0px;padd=
ing:0px 0px 20px;width:799.111px"><div class=3D"gmail-"><div id=3D"gmail-:6=
i" class=3D"gmail-ii gmail-gt" style=3D"direction:ltr;margin:8px 0px 0px;pa=
dding:0px;font-size:0.875rem"><div id=3D"gmail-:6j" class=3D"gmail-a3s gmai=
l-aiL" style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:small;line-height:1.5;font-family:Arial,Helve=
tica,sans-serif;overflow:hidden"><div dir=3D"auto">SEMEN INDONESIA (PERSERO=
) TBK<br>The East Tower 18th floor<br>Jl. DR Ide Anak Agung Gde Agung<br>Ja=
karta Kav.E.3.2 1-12950<br><a href=3D"mailto:Email%3Amorganblakechurch07@gm=
ail.com" target=3D"_blank">Email:</a><span style=3D"color:rgb(95,99,104);fo=
nt-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:14px;lett=
er-spacing:0.2px;text-align:center;white-space:nowrap"><a href=3D"mailto:mo=
rganblakechurch42@gmail.com">morganblakechurch42@gmail.com</a></span><br><b=
r><br>I am Mr Morgan Blake Church , Job Instructor for PT Semen Indonesia<b=
r>(Persero) Tbk and Accountant/HR Manager here to present to you a Part<br>=
Time Job.<br><br>Work from Home/Temporarily and get paid weekly. We are gla=
d to offer<br>you a job position in our organization, We need someone to wo=
rk for<br>the company as a Representative/Bookkeeper in the USA and CANADA.=
 This<br>is in view of our not having an office presently in the USA and<br=
>CANADA. You don&#39;t need to have an office and this certainly won&#39;t<=
br>disturb any form of employment you have presently.<br><br>Our Customers =
in the USA usually make payments for our supplies in the<br>form of PayPal =
, Bank Transfer within the USA and Credit card. All<br>these are not readil=
y acceptable here in Indonesia. They can only be<br>acceptable in the USA i=
nstantly Payment/24hour Deposit. Major<br>responsibilities include:<br><br>=
-Receiving payments from existing and new customers<br>-Distributing receiv=
ed funds according to given instructions Initial<br>requirements:<br>-Abili=
ty to manage payments between the company and its clients<br>-Ability to pl=
an and organize his/her work<br>-Ability to contribute 3-4 hours daily.<br>=
-Full legal age.<br>-Authorized to work in the USA or CANADA<br><br>Advanta=
ges: You do not have to go out as you will work as an<br>independent contra=
ctor right from your home/office. Your job is<br>absolutely legal. You can =
earn up to $3000-$4000 monthly depending on<br>time you will spend for this=
 job.<br><br>You do not need any capital to start. You can do the Work easi=
ly<br>without leaving or affecting your present Job.<br><br>Pay: A commissi=
on of 10% on every transaction. The Issue of trust is<br>very Vital, howeve=
r, I believe I am protected by the Terms and<br>Conditions above as going a=
gainst the Terms and Conditions will mean a<br>breach of Contract. We do ho=
pe that you find the offer attractive.<br><br>OUR REQUIREMENTS:<br><br>*VAL=
ID FIRST NAME:<br><br>*VALID LAST NAME:<br><br>*VALID ADDRESS<br><br>* VALI=
D CITY:<br><br>* VALID STATE:<br><br>* VALID PROVINCE/TERRITORY<br><br>*VAL=
ID ZIP CODE:<br><br>* VALID COUNTRY:<br><br>*VALID PHONE NUMBER CELL:<br><b=
r>* AGE:<br><br>* GENDER :<br><br>* VALID E Mail:<br><br>*OCCUPATION {PRESE=
NT JOB}<br><br>* VALID DATE OF BIRTH :<br><br>*COPY OF YOUR IDENITITY ID OR=
 DRIVING ID {FRONT &amp; BACK}<br><br><br>ATTN :- PLEASE IF YOU ARE NOT ABL=
E TO PROVIDE THE ABOVE LISTED<br>REQUIREMENTS , KINDLY DON&#39;T RESPOND BA=
CK TO US.<br><br>Thank You<br><br>SEMEN INDONESIA (PERSERO) TBK<br>Morgan B=
lake Church=C2=A0</div><div class=3D"gmail-yj6qo"></div><div class=3D"gmail=
-adL"></div></div></div><div class=3D"gmail-hi" style=3D"border-bottom-left=
-radius:1px;border-bottom-right-radius:1px;padding:0px;width:auto;backgroun=
d:rgb(242,242,242);margin:0px"></div></div></div><div class=3D"gmail-ajx" s=
tyle=3D"clear:both"></div></div><div class=3D"gmail-gA gmail-gt gmail-acV" =
style=3D"font-size:0.875rem;padding:0px;width:auto;border-bottom-left-radiu=
s:0px;border-bottom-right-radius:0px;border-top:none;margin:0px;background:=
transparent"><div class=3D"gmail-gB gmail-xu" style=3D"border-top:0px;paddi=
ng:0px"><div class=3D"gmail-ip gmail-iq" style=3D"clear:both;margin:0px;pad=
ding:16px 0px;border-top:none"><div id=3D"gmail-:6h"><table class=3D"gmail-=
cf gmail-wS" role=3D"presentation" style=3D"border-collapse:collapse"><tbod=
y><tr><td class=3D"gmail-amq" style=3D"padding:0px 16px;vertical-align:top;=
width:44px"><img id=3D"gmail-:5w_2" name=3D":5w" src=3D"https://lh3.googleu=
sercontent.com/a-/AOh14GjLJ5j8rUvnIEJ-gx5pggZOejPjON39TG_sGnu_nQ=3Ds40" cla=
ss=3D"gmail-ajn gmail-bofPge" style=3D"display: block; width: 40px; height:=
 40px; border-radius: 50%;"></td><td class=3D"gmail-amr" style=3D"padding:0=
px;width:799.111px"><div class=3D"gmail-nr gmail-wR" style=3D"box-sizing:bo=
rder-box;border-radius:1px;padding:0px;border:none;margin:0px"><div class=
=3D"gmail-amn" style=3D"color:inherit;height:auto;padding:0px;display:flex;=
line-height:20px"><span id=3D"gmail-:6n" role=3D"link" tabindex=3D"0" class=
=3D"gmail-ams gmail-bkH" style=3D"border:none;display:inline-flex;font-fami=
ly:&quot;Google Sans&quot;,Roboto,RobotoDraft,Helvetica,Arial,sans-serif;fo=
nt-size:0.875rem;letter-spacing:0.25px;background:none;border-radius:4px;bo=
x-sizing:border-box;color:rgb(95,99,104);height:36px;outline:none;padding:0=
px 16px 0px 12px;min-width:104px;margin-right:12px">Reply</span><span id=3D=
"gmail-:9k" role=3D"link" tabindex=3D"0" class=3D"gmail-ams gmail-bkG" styl=
e=3D"border:none;display:inline-flex;font-family:&quot;Google Sans&quot;,Ro=
boto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:0.875rem;letter-spaci=
ng:0.25px;background:none;border-radius:4px;box-sizing:border-box;color:rgb=
(95,99,104);height:36px;outline:none;padding:0px 16px 0px 12px;min-width:10=
4px;margin-right:12px">Forward</span></div></div></td></tr></tbody></table>=
</div></div></div></div></div></div></div></div></div></div><div class=3D"g=
mail-nH"></div><div class=3D"gmail-nH"></div></div></div><div class=3D"gmai=
l-nH"><div class=3D"gmail-l2 gmail-pfiaof" role=3D"contentinfo" style=3D"ma=
rgin:0px 0px 16px;padding:0px 16px 0px 72px;text-align:center"><div id=3D"g=
mail-:73" class=3D"gmail-aeV" style=3D"float:left;width:260.764px;text-alig=
n:left"><div><div class=3D"gmail-ajd" style=3D"display:flex"><a target=3D"_=
blank" href=3D"https://drive.google.com/u/0/settings/storage?hl=3Den&amp;ut=
m_medium=3Dweb&amp;utm_source=3Dgmail&amp;utm_campaign=3Dstorage_meter&amp;=
utm_content=3Dstorage_normal" class=3D"gmail-aiF" style=3D"text-decoration-=
line:none;width:220px"><div class=3D"gmail-aiC" style=3D"background-color:r=
gb(218,220,224);border-radius:8px;height:6px;margin:7px 0px"><div class=3D"=
gmail-aiA" style=3D"background-color:rgb(95,99,104);border-radius:8px;heigh=
t:6px;width:30.7917px"></div></div><div class=3D"gmail-aiG" style=3D"displa=
y:flex"><div class=3D"gmail-aiD" style=3D"font-size:0.75rem;letter-spacing:=
0.3px;color:rgb(95,99,104)"><span dir=3D"ltr"></span><span dir=3D"ltr"></sp=
an></div><div class=3D"gmail-aiz" role=3D"img" aria-label=3D"Follow link to=
 manage storage" style=3D"background-image:url(&quot;https://www.gstatic.co=
m/images/icons/material/system_gm/1x/launch_gm_grey_18dp.png&quot;);backgro=
und-size:18px;height:20px;width:20px;margin:0px 8px;opacity:1"></div></div>=
</a></div></div></div><div class=3D"gmail-aeU" style=3D"float:left;width:26=
0.764px"><div id=3D"gmail-:6w"><div><div class=3D"gmail-ma" style=3D"font-s=
ize:0.75rem;color:rgb(95,99,104);padding-top:0px;letter-spacing:0.3px;line-=
height:20px"><a href=3D"https://www.google.com/intl/en/policies/terms/" tar=
get=3D"_blank" class=3D"gmail-l9" style=3D"color:rgb(34,34,34);text-decorat=
ion-line:none"></a><a href=3D"https://www.google.com/intl/en/policies/priva=
cy/" target=3D"_blank" class=3D"gmail-l9" style=3D"color:rgb(34,34,34);text=
-decoration-line:none"></a><a href=3D"https://www.google.com/gmail/about/po=
licy/" target=3D"_blank" class=3D"gmail-l9" style=3D"color:rgb(34,34,34);te=
xt-decoration-line:none"></a></div></div></div></div><div id=3D"gmail-:6y" =
class=3D"gmail-ae3" style=3D"float:left;width:260.764px;text-align:right"><=
div><div class=3D"gmail-l6" style=3D"padding-top:0px;font-size:0.75rem;colo=
r:rgb(95,99,104);letter-spacing:0.3px;line-height:20px"><div></div><span id=
=3D"gmail-:6o" class=3D"gmail-l8 gmail-LJOhwe" tabindex=3D"0" role=3D"link"=
 style=3D"color:rgb(34,34,34)"></span></div></div></div><div style=3D"clear=
:both"></div></div></div></div></td><td class=3D"gmail-Bu gmail-yM" style=
=3D"vertical-align:top;padding:0px;width:0px;background-image:initial;backg=
round-position:initial;background-size:initial;background-repeat:initial;ba=
ckground-origin:initial;background-clip:initial"><div class=3D"gmail-Bt" st=
yle=3D"height:0px;overflow:hidden;width:0px"></div><div class=3D"gmail-nH" =
style=3D"width:0px"><div class=3D"gmail-no" style=3D"float:left"><div class=
=3D"gmail-nH gmail-nn" style=3D"min-height:1px;float:left;width:0px"></div>=
</div></div></td></tr></tbody></table><br class=3D"gmail-Apple-interchange-=
newline"></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAO-qwSYA-Dnu17ti%2Bw8BwA%2BXHC0pgjxv9AnL5py%3DnB2HGtV=
iUA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAO-qwSYA-Dnu17ti%2Bw8BwA%2BXHC0pgjxv9AnL5py%=
3DnB2HGtViUA%40mail.gmail.com</a>.<br />

--000000000000f745fd05d7c43f8c--
