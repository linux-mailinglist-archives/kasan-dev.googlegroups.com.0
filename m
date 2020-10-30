Return-Path: <kasan-dev+bncBCEOFDUJ3EKRBQXL6D6AKGQEYBOCJHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 033542A0A36
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:48:20 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id c16sf4939538pgn.3
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:48:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604072898; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkDjR8m5teOkNIyIsHfEzTtzBKKetwSU9NcpeLj2/UVrgpdvFiD79Rb/EZGPaoFWnv
         h3QHq5nTpRRogWwPaVEikNqYrIYq6D3WJ9FgKzczsc26BJuRQA/2h16B3s7LHIS9X/+9
         0+uKPG+NYr9sow+H2caMrf9fUAFAfGZQLFM4Z/BOv4mjTCH/LqOxQeyKz9zJHXzFSuB0
         Tlq1zl8E8nx9SbovGQyELZWmqfTLVuFVTMDNzFZoyicG+NnPan+4A9Xfw8wp+pAl1xcQ
         DNSRrOFY10wx0DHtisjkQmruRi3L953k3Rj57w8wHo6/oIw89+dPr66Z+33oT9dyxONN
         qZZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:date:message-id
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=iD7FEJfGID4yvzD+7mNVgFWi+AHlVvd2FsgPv60C4EQ=;
        b=w7IPQ5bD2rZbB6Xkoynoao1iPhm4DTeSGiFakQqRdROAi1TMeU7jjczDZrPduKknSa
         Scp+Zwb1aTRNjijkP5746Q2bqN+ACTsX3Cg0N7IO5re8RswClo4c79vr1Lj0ZUg5Sw9B
         uwtyILYGY6TQ/OiL0EngesjnZk+rr046lJC5Zfj5xugyd5IZiOVq4nqTph/9K5LomegB
         mBwz+ufg8nDYPP++UkqiUL5H/lt7arnxyS6Gr109+etsrKVwpc/lzrdaju7wYLY90Qa7
         gw9kuZcN7XXIlmhRuKUIL+6ukRerE3Yb40MEBI6cllDO+oY3EUvLxri1Wd5T89fRNzry
         zWcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QSDhVxVz;
       spf=pass (google.com: domain of 3wtwcxxejcaagabrielthomasjabagmail.comkasan-devgooglegroups.com@trix.bounces.google.com designates 2607:f8b0:4864:20::846 as permitted sender) smtp.mailfrom=3wTWcXxEJCaAGABRIELTHOMASjabaGMAIL.COMKASAN-DEVGOOGLEGROUPS.COM@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iD7FEJfGID4yvzD+7mNVgFWi+AHlVvd2FsgPv60C4EQ=;
        b=CuEZT9+5YuF7pcXyYdotI61LCYhjt52/UAXER2+Y6v5JGWaMf9c63PAFnrpH/z8wIZ
         Cbq5L7EMfNQDYkgECPeBWDxH01i3beJDu9eGQXGvTPRMmNC+40hKYsqNws21DbT9w7Fq
         CyajqFv/SU/dff2oz5fXiMJkarKnxIxmxLGPT0HQyu7M6lS+lspcePixeX4RPBTr9FhB
         vAq9N1uWbfk33jATBY/nHn+RZCVzjVHhmgVCTZ15SiAGpr77pf4f+NtlmzThcsCZb3nf
         BNR166ErfvfIu39OEcOAXY9ErDnz9xULY/Yre4nXQS0ur2+a83Zr0Vqa+fnb4OjNUn1S
         RXpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iD7FEJfGID4yvzD+7mNVgFWi+AHlVvd2FsgPv60C4EQ=;
        b=G8p4FuLMc6rGIsQmIxaC9rIN5ZQr+e5tBZNoAQ8cc3dYGr0HjtRQmoJGtRWEZT1QRs
         NU8a8biolDlFuEpXKfJubcTn3NmipTLGSSbVCh9f/TUn4sBi9w5xd+2SBbmvsVMoQ1R+
         l8ZMmarsCI72hnrzSUB2+IzV5w1Wvq5anRPGo0M13nbDn/R4RhDJcxlz3Wto1+HHmqiK
         MAQckcfwfRqYclm0xF2KPK1sS0tWQViznVcjqf8cibm3YNljDstcRmpcjSCTTObXB6i1
         VzqWjxe6DJOMlEOB6wBsbsLv0thsfraoxdne40jqX/s43uVsnnu5f8JjlPhym22GC7J5
         K+Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:message-id:date
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iD7FEJfGID4yvzD+7mNVgFWi+AHlVvd2FsgPv60C4EQ=;
        b=GeTzbuczvdt/68YK9KxHC8kLvtKMPD649K5fLvLx/0yOh/sRpqjOYTVV7PYBx0OSbf
         G1pQicm4jztxoi9IoKGna3w1DFOg4qoLJHBpguErPjorENItKH693T9nA2ALvAt6E4/Q
         eVAwpYElTD/IatBy+gL23UX3TaXqlIHwubuV6G+yOv8h8944XMnBWKWiFR6cZCoRMf0P
         iBql5ZExS3LM2yLLwF+lS3dsAmenTkutrG9XObjXLZ98P09qELEWShU2v2eo0kFGsTNr
         uKqVlaNKRzADfcFhaJrJzHXt9/1+SwLhcd1g7O4hK2izrqhYotOm0DTUpW7brSXQ/miN
         gXVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EE9Lq8kQco8qP1mX4X5lQ3nyY4Q9Mtc2vUUbp/qle2OVp76qD
	/8dbrj+4YRUKwWKziuKvFFI=
X-Google-Smtp-Source: ABdhPJzsWVPgnTAAbCVpQ6OB+3lf+E7OzaMhovaVFxEFwKPm/WOv3EB1VE2VVCfwT0X1Jxm6/MxLqA==
X-Received: by 2002:a17:902:ed09:b029:d3:cbc3:8da8 with SMTP id b9-20020a170902ed09b02900d3cbc38da8mr9537621pld.33.1604072898590;
        Fri, 30 Oct 2020 08:48:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d03:: with SMTP id s3ls1468804pji.1.gmail; Fri, 30
 Oct 2020 08:48:18 -0700 (PDT)
X-Received: by 2002:a17:902:7606:b029:d3:d2dd:2b3b with SMTP id k6-20020a1709027606b02900d3d2dd2b3bmr9533721pll.67.1604072898014;
        Fri, 30 Oct 2020 08:48:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604072898; cv=none;
        d=google.com; s=arc-20160816;
        b=y40B4t3NrgsNe3iszDiAPLTG6AaUouEgOATRuEWyLSTszCAdAjhKtKsLfom6liajHr
         KZT28e9xv1Gl8PmK/3VVn1C721cIV6ah5xmHwQSgmmamWfGdldYAM6znR5zeV1Tt2XZ/
         KXgEOx9RZonMYI9AVSlj6Bx8myWY9bU4PxdYTFbfqnHShgH/yZJd+uUQ2QTlGBGwC4Q6
         7SZQTK98WPWNB1EjrRUBJ/1hojpXJ5QQpQ1vRxcvjejNRihHQ4MLj20UITVcziQn1WXY
         uJDrYEWmuhhngSd59O4+W7mWKxXAEB82RZHk5qrPotDsiTzL3cdqcvs9H4j6GVYdMPkj
         xD4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:date:message-id:reply-to:mime-version
         :dkim-signature;
        bh=yglUuHV2AUUJ2fm9wItl5ONjogpf9InC3emOxIAuHS0=;
        b=qU4d97hMliE5bZ6gbE5wbDgaawdFwZB4x5cVAuYDKpMzRMi82UHeDtE03pyL+87kgP
         fsGiUJKg6JO8xSkRZaHk1KxkzWt8NbBf/GK906eYa/iEslq8XUJZNwKEroHOtysqazMM
         FK8vR56Xlq7bJqkZunf9dfqFLxRxEF6KQzDaneoWCzpllG8bJ6pBT19ZoGUqR1yXCFnW
         7ftmrBUbI3gA5guyAHTBC556N4XlK3X5hVT4IbBm9TxD3w/y5+X89ci7cuo5qmZ8AlVv
         HYu/RM1UswjApKFY3kjlCpFdaGZdBVfUL2uaTh5FcajIZXUpWwonxfeepcvrp7IfSLY6
         7lWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QSDhVxVz;
       spf=pass (google.com: domain of 3wtwcxxejcaagabrielthomasjabagmail.comkasan-devgooglegroups.com@trix.bounces.google.com designates 2607:f8b0:4864:20::846 as permitted sender) smtp.mailfrom=3wTWcXxEJCaAGABRIELTHOMASjabaGMAIL.COMKASAN-DEVGOOGLEGROUPS.COM@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x846.google.com (mail-qt1-x846.google.com. [2607:f8b0:4864:20::846])
        by gmr-mx.google.com with ESMTPS id t13si420321ply.2.2020.10.30.08.48.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:48:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wtwcxxejcaagabrielthomasjabagmail.comkasan-devgooglegroups.com@trix.bounces.google.com designates 2607:f8b0:4864:20::846 as permitted sender) client-ip=2607:f8b0:4864:20::846;
Received: by mail-qt1-x846.google.com with SMTP id f10so4216337qtv.6
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:48:17 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a05:6214:308:: with SMTP id i8mt9480331qvu.46.1604072897779;
 Fri, 30 Oct 2020 08:48:17 -0700 (PDT)
Reply-To: gabrielthomas9010@gmail.com
X-No-Auto-Attachment: 1
Message-ID: <000000000000441f1505b2e553c0@google.com>
Date: Fri, 30 Oct 2020 15:48:17 +0000
Subject: Hi,
From: gabrielthomas9010@gmail.com
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="00000000000045291c05b2e5533c"
X-Original-Sender: gabrielthomas9010@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=QSDhVxVz;       spf=pass
 (google.com: domain of 3wtwcxxejcaagabrielthomasjabagmail.comkasan-devgooglegroups.com@trix.bounces.google.com
 designates 2607:f8b0:4864:20::846 as permitted sender) smtp.mailfrom=3wTWcXxEJCaAGABRIELTHOMASjabaGMAIL.COMKASAN-DEVGOOGLEGROUPS.COM@trix.bounces.google.com;
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

--00000000000045291c05b2e5533c
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes

I've invited you to fill out the following form:
Untitled form

To fill it out, visit:
https://docs.google.com/forms/d/e/1FAIpQLScuNN46De4NTNDuI_3Rm2L6CNABd5Ra0TyGG6ZxgVbAw2h7Ug/viewform?vc=0&amp;c=0&amp;w=1&amp;flr=0&amp;usp=mail_form_link

  Hi,
Hope I am not intruding on your space here.
If you are interested in equity or loan financing,
I would be glad to assist.
We are a private financial firm that acquires well established small and  
lower
middle market businesses with predictable revenue and cash flow;
typically partnering with industry professionals
to operate them.
We also have a Capital Formation Division that assists companies at
all levels of development raise
capital through hedge funds. We charge %1 commission at the successful
closing of any deal.
Additionally, we also fund
secured as well as unsecured lines of credit and term loans.
Would that be something of interest to you and your group?
Please let me know your thoughts.
Sorry if you get this message in your spam box, poor network
connection may be responsible for such.
Best regards...... Gennadiy Medovoy.

Google Forms: Create and analyze surveys.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000441f1505b2e553c0%40google.com.

--00000000000045291c05b2e5533c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body style=3D"font-family: Roboto,Helvetica,Arial,sans-serif; margin=
: 0; padding: 0; height: 100%; width: 100%;"><table border=3D"0" cellpaddin=
g=3D"0" cellspacing=3D"0" style=3D"background-color:rgb(103,58,183);" width=
=3D"100%" role=3D"presentation"><tbody><tr height=3D"64px"><td style=3D"pad=
ding: 0 24px;"><img alt=3D"Google Forms" height=3D"26px" style=3D"display: =
inline-block; margin: 0; vertical-align: middle;" width=3D"143px" src=3D"ht=
tps://www.gstatic.com/docs/forms/google_forms_logo_lockup_white_2x.png"></t=
d></tr></tbody></table><div style=3D"padding: 24px; background-color:rgb(23=
7,231,246)"><div align=3D"center" style=3D"background-color: #fff; border-b=
ottom: 1px solid #e0e0e0;margin: 0 auto; max-width: 624px; min-width: 154px=
;padding: 0 24px;"><table align=3D"center" cellpadding=3D"0" cellspacing=3D=
"0" style=3D"background-color: #fff;" width=3D"100%" role=3D"presentation">=
<tbody><tr height=3D"24px"><td></td></tr><tr><td><span style=3D"display: ta=
ble-cell; vertical-align: top; font-size: 13px; line-height: 18px; color: #=
424242;" dir=3D"auto"> Hi,<br>Hope I am not intruding on your space here.<b=
r>If you are interested in equity or loan financing,<br>I would be glad to =
assist.<br>We are a private financial firm that acquires well established s=
mall and lower<br>middle market businesses with predictable revenue and cas=
h flow;<br>typically partnering with industry professionals<br>to operate t=
hem.<br>We also have a Capital Formation Division that assists companies at=
<br>all levels of development raise<br>capital through hedge funds. We char=
ge %1 commission at the successful<br>closing of any deal.<br>Additionally,=
 we also fund<br>secured as well as unsecured lines of credit and term loan=
s.<br>Would that be something of interest to you and your group?<br>Please =
let me know your thoughts.<br>Sorry if you get this message in your spam bo=
x, poor network<br>connection may be responsible for such.<br>Best regards.=
..... Gennadiy Medovoy.</span></td></tr><tr height=3D"20px"><td></tr><tr st=
yle=3D"font-size: 20px; line-height: 24px;"><td dir=3D"auto"><a href=3D"htt=
ps://docs.google.com/forms/d/e/1FAIpQLScuNN46De4NTNDuI_3Rm2L6CNABd5Ra0TyGG6=
ZxgVbAw2h7Ug/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;flr=3D0&amp;usp=3Dmail=
_form_link" style=3D"color: rgb(103,58,183); text-decoration: none; vertica=
l-align: middle; font-weight: 500">Untitled form</a><div itemprop=3D"action=
" itemscope itemtype=3D"http://schema.org/ViewAction"><meta itemprop=3D"url=
" content=3D"https://docs.google.com/forms/d/e/1FAIpQLScuNN46De4NTNDuI_3Rm2=
L6CNABd5Ra0TyGG6ZxgVbAw2h7Ug/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;flr=3D=
0&amp;usp=3Dmail_goto_form"><meta itemprop=3D"name" content=3D"Fill out for=
m"></div></td></tr><tr height=3D"24px"></tr><tr><td><table border=3D"0" cel=
lpadding=3D"0" cellspacing=3D"0" width=3D"100%"><tbody><tr><td><a href=3D"h=
ttps://docs.google.com/forms/d/e/1FAIpQLScuNN46De4NTNDuI_3Rm2L6CNABd5Ra0TyG=
G6ZxgVbAw2h7Ug/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;flr=3D0&amp;usp=3Dma=
il_form_link" style=3D"border-radius: 3px; box-sizing: border-box; display:=
 inline-block; font-size: 13px; font-weight: 700; height: 40px; line-height=
: 40px; padding: 0 24px; text-align: center; text-decoration: none; text-tr=
ansform: uppercase; vertical-align: middle; color: #fff; background-color: =
rgb(103,58,183);" target=3D"_blank" rel=3D"noopener">Fill out form</a></td>=
</tr></tbody></table></td></tr><tr height=3D"24px"></tr></tbody></table></d=
iv><table align=3D"center" cellpadding=3D"0" cellspacing=3D"0" style=3D"max=
-width: 672px; min-width: 154px;" width=3D"100%" role=3D"presentation"><tbo=
dy><tr height=3D"24px"><td></td></tr><tr><td><a href=3D"https://docs.google=
.com/forms?usp=3Dmail_form_link" style=3D"color: #424242; font-size: 13px;"=
>Create your own Google Form</a></td></tr></tbody></table></div></body></ht=
ml>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/000000000000441f1505b2e553c0%40google.com?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/0=
00000000000441f1505b2e553c0%40google.com</a>.<br />

--00000000000045291c05b2e5533c--
