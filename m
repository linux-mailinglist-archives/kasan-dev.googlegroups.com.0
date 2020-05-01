Return-Path: <kasan-dev+bncBC66TOP4SALRBBXQVX2QKGQE3VQOQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id A66DA1C0B8A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 May 2020 03:14:47 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id 11sf8524941qkh.7
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Apr 2020 18:14:47 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qNhrKUcCfF+Z2kb8adqMc0TDoWVNzI9qX5EKB5O+EJ4=;
        b=tFF/rZiaGAIalphtqj9A03Jz3Rujd5BNiaVbZeVaa04GeO2gDhgOTvFA1kN8ASu4UI
         MGmavmk3ZGWeLfMcBcwFlESAdoeVNitNGHBZeNpweP7B6hKpws1cITH/qW58mwOXNq4c
         7wTk2i1X3kpEEutJcqkE3ylx6kpsXLmYNv6DuuhHE3UJ4/5tle7icq52lwkuwCfZhTFV
         8W9IpU/9nlDgt0ebIdR5t9IMeBe+4ofKL4PlaBYQMVa576/5K2HDAhyw66Qjl0FAp+65
         St/3amiHnvSpsTVI9k1CtElSGyFb68zn4stzoYjJfNmWtWLNL4yry6EPkuXTnIsW1TzH
         FlMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNhrKUcCfF+Z2kb8adqMc0TDoWVNzI9qX5EKB5O+EJ4=;
        b=G8NR4OU1oldB7XXDly7Mb0divLuQiEQ+ifwH0HloPv1JrmEIhoahQ8c5L9hEx6cs5w
         NXQVpHiuYSC+GxM0Dh+MICuu0scPDmCz3sPYVFeziXbhlIPPSwZ+qPwvWvQGXtDZY62O
         QQxjrzT9AKSiYPE0Tj1uzki7FCi6QzQut2qMeu8n6gIE6WTlvzEWHTNNL+WmkSjUmrVl
         A5GnV/x14HSJ3IMRRzCpW4NagOeJF6HDp1xvUFvO3fHTCbmmysbN+jfL9gGxiGwmA2g4
         YqnUbLZ9MYngHdthAdhdMbtJJiKMpehNkefuux4HnD4ipYJA/p+qxWzr5VDC9NEPXcNF
         tT+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNhrKUcCfF+Z2kb8adqMc0TDoWVNzI9qX5EKB5O+EJ4=;
        b=Qok3fP69dxz75n1pivyvi2ZD9pgVucJxF0LgH42Lbg0uDXpHMN274xEqeeLrcrT2Lm
         5x46VDycFN7TQZlquRy8bHkjDHrGZIgJbRTTBzpVrWbxj+fxlBwJrZyg0KP+9Fb/i0av
         sH2xwcyQK/PJi2cBcACBf1owdshpJUnCc3f7MjYEm0Tg4QpCWfqmOleDTChy8ffbgtlm
         UQ7CPPSQV75IJM613u0tow0ZIhRku/BBG/5unVLDUCTlsCDRoyyWqeOAAOhEN4EE3MWb
         bnLvPK5g9n117ZiAH5zT2IXr6DfRg0J0zb82mFSV9BrsYhlQjG0Xn1mL+m5KlHJN2Ybc
         nfAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pua5S+/dNE3j+lbr7ykqaHcF8VcpyN/zNvj3dYTDrER/p5W1y68t
	8RAwskAOTR5YUSrUBnX+Klc=
X-Google-Smtp-Source: APiQypI2n0vKr/Q9A/ta4NzzVouF4h3ROaRFff2mVumCN+1VgdA+FjBUJlIe3GNvqYUMWnadlCs6mw==
X-Received: by 2002:a05:6214:593:: with SMTP id bx19mr1886194qvb.2.1588295686764;
        Thu, 30 Apr 2020 18:14:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4a74:: with SMTP id cn20ls1516293qvb.0.gmail; Thu, 30
 Apr 2020 18:14:46 -0700 (PDT)
X-Received: by 2002:a0c:9e6d:: with SMTP id z45mr1838671qve.206.1588295686416;
        Thu, 30 Apr 2020 18:14:46 -0700 (PDT)
Date: Thu, 30 Apr 2020 18:14:45 -0700 (PDT)
From: robert mathews <mathewsrobert54@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <232d3f65-07d2-41ea-9de7-cbc90916cbb7@googlegroups.com>
Subject: BUY TRAMADOL,XANAX,DIAZEPAM,ETC
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3962_1395707609.1588295685959"
X-Original-Sender: mathewsrobert54@gmail.com
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

------=_Part_3962_1395707609.1588295685959
Content-Type: multipart/alternative; 
	boundary="----=_Part_3963_16567206.1588295685959"

------=_Part_3963_16567206.1588295685959
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

FOR BULK\SMALL BUYERS ONLY. DO NOT MISS OUT BUT CONTACT AND GET SORTED ASAP=
=20
*ENQUIRIES:
-Email..... mathewsrobert54@gmail.com

Diaz 5mgs 1000pills 100=C2=A3
Diaz 5mgs 2000pills 200=C2=A3
Diaz 5mgs 5000pills 480=C2=A3

Diaz 10mgs 1000pills 130=C2=A3
Diaz 10mgs 2000pills 210=C2=A3
Diaz 10mgs 5000pills 300=C2=A3
Diaz 10mgs 10000pills 600=C2=A3

Ket 5vials 100=C2=A3
Ket 10vials 180=C2=A3
Ket 25vials 320=C2=A3

FOR TRAMADOL SMALLER ORDER

tramadol 100mg 300pills =C2=A380
tramadol 200mg 300pills =C2=A3100
tramadol 100mg 500pills =C2=A3130
tramadol 200mg 500pills =C2=A3140
tramadol 100mg 1000pills =C2=A3220
tramadol 200mg 1000pills =C2=A3230
tramadol 225mg 1000pills =C2=A3250

FOR TRAMADOL BULK ORDER

tramadol 100mg 5000pills =C2=A3600
tramadol 200mg 5000pills =C2=A3700
tramadol 225mg 5000pills =C2=A3800

Viagra 100mg 1000pills 350=C2=A3
Viagra 100mg 2000pills 600=C2=A3
Viagra 100mg 5000pills 1000=C2=A3

Xanax 0.5mg 1000pills 270=C2=A3
Xanax 0.5mg 2000pills 500=C2=A3
Xanax 0.5mg 5000pills 900=C2=A3

other products available for sale

alpha testo boast ..60 pills - =C2=A3100
zopiclone 7.5mg,
oxycodone 5mg & 10mg,


*CONTACT:
-Email...... mathewsrobert54@gmail.com
Wickr=E2=80=A6..dinalarry
WhatsApp=E2=80=A6.+237672864865
Telegram=E2=80=A6..@l_oarry

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/232d3f65-07d2-41ea-9de7-cbc90916cbb7%40googlegroups.com.

------=_Part_3963_16567206.1588295685959
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>FOR BULK\SMALL BUYERS ONLY. DO NOT MISS OUT BUT CONTA=
CT AND GET SORTED ASAP=C2=A0</div><div><span style=3D"white-space:pre">	</s=
pan></div><div>*ENQUIRIES:</div><div>-Email..... mathewsrobert54@gmail.com<=
/div><div><br></div><div>Diaz 5mgs 1000pills 100=C2=A3</div><div>Diaz 5mgs =
2000pills 200=C2=A3</div><div>Diaz 5mgs 5000pills 480=C2=A3</div><div><br><=
/div><div>Diaz 10mgs 1000pills 130=C2=A3</div><div>Diaz 10mgs 2000pills 210=
=C2=A3</div><div>Diaz 10mgs 5000pills 300=C2=A3</div><div>Diaz 10mgs 10000p=
ills 600=C2=A3</div><div><br></div><div>Ket 5vials 100=C2=A3</div><div>Ket =
10vials 180=C2=A3</div><div>Ket 25vials 320=C2=A3</div><div><br></div><div>=
FOR TRAMADOL SMALLER ORDER</div><div><br></div><div>tramadol 100mg 300pills=
 =C2=A380</div><div>tramadol 200mg 300pills =C2=A3100</div><div>tramadol 10=
0mg 500pills =C2=A3130</div><div>tramadol 200mg 500pills =C2=A3140</div><di=
v>tramadol 100mg 1000pills =C2=A3220</div><div>tramadol 200mg 1000pills =C2=
=A3230</div><div>tramadol 225mg 1000pills =C2=A3250</div><div><br></div><di=
v>FOR TRAMADOL BULK ORDER</div><div><br></div><div>tramadol 100mg 5000pills=
 =C2=A3600</div><div>tramadol 200mg 5000pills =C2=A3700</div><div>tramadol =
225mg 5000pills =C2=A3800</div><div><br></div><div>Viagra 100mg 1000pills 3=
50=C2=A3</div><div>Viagra 100mg 2000pills 600=C2=A3</div><div>Viagra 100mg =
5000pills 1000=C2=A3</div><div><br></div><div>Xanax 0.5mg 1000pills 270=C2=
=A3</div><div>Xanax 0.5mg 2000pills 500=C2=A3</div><div>Xanax 0.5mg 5000pil=
ls 900=C2=A3</div><div><br></div><div>other products available for sale</di=
v><div><br></div><div>alpha testo boast ..60 pills - =C2=A3100</div><div>zo=
piclone 7.5mg,</div><div>oxycodone 5mg &amp; 10mg,</div><div><br></div><div=
><br></div><div>*CONTACT:</div><div>-Email...... mathewsrobert54@gmail.com<=
/div><div>Wickr=E2=80=A6..dinalarry</div><div>WhatsApp=E2=80=A6.+2376728648=
65</div><div>Telegram=E2=80=A6..@l_oarry</div><div><br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/232d3f65-07d2-41ea-9de7-cbc90916cbb7%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/232d3f65-07d2-41ea-9de7-cbc90916cbb7%40googlegroups.com</a>.<br =
/>

------=_Part_3963_16567206.1588295685959--

------=_Part_3962_1395707609.1588295685959--
