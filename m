Return-Path: <kasan-dev+bncBAABBZFY7TWQKGQEQ7JVBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D0F0ED42D
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Nov 2019 19:28:54 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id j14sf3985034oie.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Nov 2019 10:28:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572805732; cv=pass;
        d=google.com; s=arc-20160816;
        b=fx+Xc1ErCEbM7aC2P9k7OQ053qzDKr4nHLlu9XJ9h/tIz5KBJy/M3haq+UMz8e1+IY
         6ejYz6t1oYCOq8ZUE1jt7BMIK8BLkIAD28/r7+6uskx4QWpVhXsuHdyJcOfCeOtDTR4C
         aItG1Y6XE6ucITlMU31ZbtKb2dx6EaIyqKD/rNknYZichrDljel2kVj+JeveIWqhT1Zi
         wvyGmR306pAoyKOmcDrhMW010y1M8q2IRRClXwaklQ5/rYM+m7+8rOLHGqw1jpc+8sNm
         eUCAgCl9h0qAPMA6GL3UKMGX3Nb8y/l56ZhZzdXOoeODNx7xLrHVcY+h4BAwKxjcYX6Q
         Gefg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:subject:message-id:to:from:date:sender:dkim-signature;
        bh=msBLJBEcASTZw/dSdfbdSjD8vCtmZ8GMPqH3Rp9aKwE=;
        b=NqeF14aSLI4ievocVx9ksj53C+LLZAeeuU3WFA1c6+bv1/+W+KkK+JNqe70Ic1kMwL
         KXyFkmgeqjCtk7XPwNs9RMV3kdg6PdXX+99kZUNycDuDEJqEjYih2brnzmmlM9wbgFD1
         ZQGP2dGz6yZwoHhZjY00IBLB+3nBcQ7vw0qHR5QFu3/RqR53EFgU0HBeWwEdT1pooISj
         G/l4y4rSwrZi8ezMKhZUxfihVRZszjACGGyhZLboTNr9ZaarXDsnmx1fO4aZdoI39nZn
         AQ7QG+nc+Hh70++RRAkPfJyHpkTLU8nRCyez+NR7xgnljZoevh+Y9zjdXvVX+gIU+oq/
         zujQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of manami1234@daum.net designates 203.133.181.12 as permitted sender) smtp.mailfrom=manami1234@daum.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=daum.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=msBLJBEcASTZw/dSdfbdSjD8vCtmZ8GMPqH3Rp9aKwE=;
        b=Emr6tN31d500QcR85zPKymcrJgRneWgTXgzx+NnfhFaSw1aALeQj1ziYA9OJMdd9yj
         bNlFEWe0E6tdTOUoq8US7yMIVN6uvPp2SW883U9s8BV5Fs7mIL81jUW/pxD4vtVo+Ku7
         ePBTZWo/q6Ek0+qnB66TQUhfOJ1wEElkL8T2GA9LakKM8c5ejigFSglkBN5FTFXKdoNc
         JwwqztoP8UyV8adpQ8CJL93JLFJaL0lYnHFOnMibwdEJXa9JK429vOC2f+GNHT3maiMT
         ATHqQPKArxbpDZqbSJOZAlxKYHJgDWpHyZxzh8/p49AftN16ZVb7bb0JAR2NxAnIhl0m
         rZrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=msBLJBEcASTZw/dSdfbdSjD8vCtmZ8GMPqH3Rp9aKwE=;
        b=RA4vUa5VTbLxRtw2kM/xKZOLP2SoVTxb+K4udFhjqAM4Ec7TwCeoP/O8ep8smyBkOW
         MGUpii6ovydCfUn6CS3+qC1etC56QFt3iF3lYu6NKg2vJOrGtxXs9hM0S/kmQoAgtrsR
         +/msRel+2MdPWgeRmILQlYKSmvkiMu64b3l2wgeJahuAcyjqmJ5IqsMKaldkkQRRR7hq
         QkI6ymIJOer6lwytcoMlC9tRq3J7yUKk8aH3p2NpxFPLzAznU2qfA6qNhvBEg8K0edi9
         sVrQAX7LmZPfrUFJI0ywjIYzrCJeYuMYlb+9Ty9BUi+oiQLBOMa2umvuDsaa6FN1eVKH
         RaLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWkeCihTb3EUi32EaXQXoRiDyRQ2JJbI6aMBTvu8cSIcSX0rdyi
	1QDV0C8VMcMIwAGrwbpzNn0=
X-Google-Smtp-Source: APXvYqyy65olXIXRO3BXlhgECOCJI7G6rinLAYoikD0dTi9Oiq6Lim48EOikxiWoJ9nEoFJtr8a1ug==
X-Received: by 2002:a05:6830:11d6:: with SMTP id v22mr16292747otq.142.1572805732550;
        Sun, 03 Nov 2019 10:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c42:: with SMTP id f60ls2334790otb.8.gmail; Sun, 03 Nov
 2019 10:28:52 -0800 (PST)
X-Received: by 2002:a9d:6c01:: with SMTP id f1mr6284582otq.216.1572805732252;
        Sun, 03 Nov 2019 10:28:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572805732; cv=none;
        d=google.com; s=arc-20160816;
        b=HYmU9CzP0xHipFYiuZ395IgB6qI38bVXgRfQ8WgGdjI3i1j+mJM+RMkUdaRRaLQIvQ
         H0xYSr2wZ2+aISnlQodO/gjCqq9VYHUJ/4/vtKgvY4jk7Xlzshf8OYQ66Ut6MRb+e1AJ
         W+0kKy3TrvJrimfGOUb6biq1Ujvn/hq+r2xcFJrT6ycf7bcUVHsbt78t/oPBZx2Ks/7S
         b+GHYuxXe6sB79eS6jWj8jiBlrDIUqHTaerM09P0ZD/JUFwagE0D1WCbnM32Nt0mJ2cJ
         DNnBrMIFk09xwfo2d9o3lEsrRDXtJW4Uo0til2h/fATGHsvgPUK0YWgDrpAqk9LaxsGE
         hLfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:subject:message-id:to:from
         :date;
        bh=AMCr7ilOZfKp6v8j4o5rvFqjIq9EJj5bKY2bc27L9Ys=;
        b=bHwhfzNXvSjlUCwWgXMP+M2HCnQ3kCGBEjpz7PzCkruv4i3PmspYOIc14znsr+eac/
         rKkVQHI17q7eNP7HH75C677My63cN75nR0y0nk2UmQta8ooU9/p4fUZQb8UbEzkEpfmE
         g8GHKpBgMx30JdtzOWDm669zI0JfYHeQQIwht/avdCYLCXwNX+mOeNATR9zx3mUk018M
         Sy0sz68GIHwTgkTXoKgdjXCt9u6n8pxJCvXGRt7ieTvEXFFx1JGE8rtgQze6rjQ9hikX
         6i380h2NozgE6mqHDkdiILsJ+7d7EfIoFZd55SqbblBi/W4PDqYPtbm0zA6Z30dAP7c4
         AFmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of manami1234@daum.net designates 203.133.181.12 as permitted sender) smtp.mailfrom=manami1234@daum.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=daum.net
Received: from mail-smail-vm54.hanmail.net (mail-smail-vm54.daum.net. [203.133.181.12])
        by gmr-mx.google.com with ESMTPS id l141si784211oib.4.2019.11.03.10.28.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 03 Nov 2019 10:28:52 -0800 (PST)
Received-SPF: pass (google.com: domain of manami1234@daum.net designates 203.133.181.12 as permitted sender) client-ip=203.133.181.12;
Received: from mail-hmail-was1 ([10.197.6.172])
        by mail-smail-vm54.hanmail.net (8.13.8/8.9.1) with SMTP id xA3ISN1r004729
        for <kasan-dev@googlegroups.com>; Mon, 4 Nov 2019 03:28:23 +0900
X-Hermes-Message-Id: nA43PoMDE1113668684
Date: Mon, 4 Nov 2019 03:25:50 +0900 (KST)
From: ACCOUNTING OFFICER <manami1234@daum.net>
To: info.20187777777@gmail.com
Message-ID: <20191104032550.rsjc5fSBSA67LUjz9JO7OA@manami1234.hanmail.net>
Subject: FROM THE ATTORNEY GENERAL FEDERAL REPUBLIC OF NIGERIA.
 E-mail:info.20187777777@gmail.com
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Mailer: Daum Mint Web 1.0
X-Originating-IP: [197.210.44.21]
X-HM-UT: F2wJHMKgMswEvVPGmBsJa+OyvwRqoW6DrgWMVLVAkXo=
Received: from mail-hammer-was6.s2.krane.9rum.cc ([10.197.10.39]) by hermes of mail-hmail-was2 (10.197.6.205) with ESMTP id nA43PoMDE1113668684 for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 03:25:50 +0900 (KST)
X-Original-Sender: manami1234@daum.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of manami1234@daum.net designates 203.133.181.12 as
 permitted sender) smtp.mailfrom=manami1234@daum.net;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=daum.net
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

<html>
<head>
    <style>
        p{margin-top:0;margin-bottom:0}
    </style>
</head>
<body>
    <table class=3D"txc-wrapper" border=3D"0" cellspacing=3D"0" cellpadding=
=3D"0" width=3D"100%"><tr><td class=3D"txc-wrapper-td"><div class=3D"txc-co=
ntent-wrapper" style=3D"color:#111;font-family:Apple SD Gothic Neo,Malgun G=
othic,'=EB=A7=91=EC=9D=80 =EA=B3=A0=EB=94=95',sans-serif;font-size:10pt;lin=
e-height:1.5;"><p><b>FROM THE ATTORNEY GENERAL FEDERAL REPUBLIC OF NIGERIA.=
 <b>E-mail:</b>info.20187777777@gmail.com<br><br>Supreme Court of Nigeria<b=
r>Address: Federal Ministry of Justice HQ<br>Plot 71B Shehu Shagari Way,Mai=
tama Abuja,<br>E-mail: abubakarmanami@rediffmail.com<br>info.20187777777@gm=
ail.com<br>Dear: Unpaid Beneficiary,<br><br>This
 is to inform you that in the course of my investigation as director of=20
payment verification / implementation committee I came across&nbsp; your na=
me
 as unpaid fund beneficiary in the record of the central bank of Nigeria
 and other banks that are suppose to get your funds&nbsp; released to you. =
My
 committee was set up by the payment reconciliation committee to verify=20
and scrutinize all&nbsp;&nbsp;&nbsp; outstanding debts owed to&nbsp;&nbsp; =
our foreign=20
beneficiaries in accordance to the information received from the United=20
States government and other countries over unpaid &nbsp;<br>huge debts owed=
 to Foreigners.<br><br>Having
 seen your file and my further questioning to the officials of the=20
central of Nigeria bank and ministry of finance as to why your&nbsp;&nbsp; =
payment
 is still pending reveals the rot and corruption in the&nbsp;&nbsp; system.=
 The=20
bank officials told me that the reason why you haven't&nbsp;&nbsp; received=
 your=20
payment is due to your inability to pay for the required charges for=20
transfer of funds to your account. When I asked them&nbsp;&nbsp; why they d=
idn't=20
deduct the said charges from your principal sum, I was given the flimsy=20
excuse that you never authorized them to do so.&nbsp;&nbsp; When I put the=
=20
question across to them if they ever advised you that such charges could
 be deducted from your principal fund,the answer I&nbsp; got was no. Now, i=
f=20
you do not tell this beneficiary that&nbsp;&nbsp;&nbsp; such charges could =
be deducted=20
from his or her principal fund, how will he or&nbsp;&nbsp; she know that su=
ch=20
options are available for such beneficiaries. From my investigation I=20
discovered that these bank&nbsp;&nbsp;&nbsp; officials&nbsp; deliberately r=
efused to let the
 charges be deducted from your principal fund&nbsp; because they want your=
=20
fund to remain trapped in the bank, <br><br>while they continue to=20
extort money from beneficiaries under some flimsy&nbsp; excuse. You do not=
=20
need to pay any money to any official, all&nbsp; you are required to do is=
=20
swear to an affidavit at the federal&nbsp;&nbsp; high court&nbsp; of Nigeri=
a,=20
authorizing the bank to deduct all charges from&nbsp; your principal fund a=
nd
 transfer the balance of funds after deduction to your&nbsp; bank account. =
If
 you have spent any money in&nbsp;&nbsp; the past in your quest for payment=
,=20
kindly let me know so that I can follow this up. You can&nbsp;&nbsp; reach =
me on=20
my phone or email for directive on how you&nbsp; can get the deduction done=
=20
as soon as possible&nbsp; and get your payment also.<br><br>Yours sincerely=
,<br><br>Barr. Abubakar Malami (SAN)<br>E-mail: abubakarmanami@rediffmail.c=
om<br>ATTORNEY GENERAL FEDERAL<br>REPUBLIC OF NIGERIA.</b></p>
<p><b><br></b></p></div></td></tr></table>
</body>
</html>
<img src=3D"https://confirm.mail.daum.net/confirmapi/v1/users/manami1234%40=
hanmail%2Enet/cmails/20191104032550%2Ersjc5fSBSA67LUjz9JO7OA%40manami1234%2=
Ehanmail%2Enet/recipients/kasan-dev%40googlegroups%2Ecom">

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/20191104032550.rsjc5fSBSA67LUjz9JO7OA%40manami1234.han=
mail.net?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/=
d/msgid/kasan-dev/20191104032550.rsjc5fSBSA67LUjz9JO7OA%40manami1234.hanmai=
l.net</a>.<br />
