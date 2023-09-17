Return-Path: <kasan-dev+bncBDWP3YH254GRBUFBTGUAMGQEEONOR6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A5927A3388
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Sep 2023 03:05:22 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-655d89a574esf41884726d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 18:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694912721; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kro4gsG6/xxZ9cPiQtC3Dzne8x8dHkC5rDhnZdzkZujN0rv7l9UM2Yu+DuZVy/+TUH
         ALqoh/VVKJeFobYh2AZD5jjZrEZzRvTs70BPxPldWUGrmwbrfXEswZsV8dVqs7+209wA
         /Y9NKkQgRzVpdQiF4lYAmzKuB591nokaYqS6XFonyy2GFkwSAoqcIqW4TPDmKJ4lJhry
         A19Xn/XthKMdjg0nS2OenpQdpod322luVM1jAIpS07KgSXzrSiF4SHMTVl6Y6s+D55IB
         /USulJ/O7s1p90W4jFyFBdESVX+XUvrjHhX3qKzV6d6aAqTX/fFoP5Os+T1hxE/oDT7g
         LnOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=BPyRsVTo8/pQaBTo99ZSW1v6kyQbQMeeJnQCQ2BUvqA=;
        fh=Pr2plYkJn0ovdHybgHvE53243CPsqSX0NRPDPDnAMwQ=;
        b=R9IyBE3IBWPH57kGAG9+/CajQDhFHT8r2Hzf9kGbCPzV73NV3tWqF1QdP6zE8x29b6
         iugK3C0QgQdnT14R7fJyrxGtRde8GvPjKZeHkLGIzBpCnBwc8YXFwtaFAyDxmUEA+cqZ
         tvtk2gg4dmcuN9u2a5o8KbPY4n8FPuWgSjwHnutFblONyrNVBedEftgZICoFoVhR/Lg+
         kQ+4/DoRZ9B8iOjf97s9/PJSAafEXKB14JHIvLyyzJQLxN7KIy08ujrW+t1GbO0JaWE9
         P+vMAqP7ldlSPe9R1Dg0SxTpyXyzXE9sPWzimSzwFkxX3K+0f7upBRfzj4XbSW9mtkG6
         2a9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ygoxln9w;
       spf=pass (google.com: domain of jdown714@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=jdown714@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694912721; x=1695517521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BPyRsVTo8/pQaBTo99ZSW1v6kyQbQMeeJnQCQ2BUvqA=;
        b=xYpUa06rjyWiwualTMi2ciW2h9zQA1F/rn+t0R2aU4f5OSLJX74V5mXncsmJMer1Nk
         +Z4SduDhULIU3CDOLy/zqqP5R/vSIiwSag1nLvfvgozp5br+sZRz2+Y3C8rY+56Tq5sG
         U+h2kn+DFkkzuheS/HldOaq+OlFoBXYHXPPPFSxHLgo3Xu5Kn7SGaH4AoP+FKmUg+HUV
         SPRto3XGqfSI5kMmtk6X0SNrpzQa30dZyXgaM26g+e/wb8S1QMPRQvcLbZ8gEdCU5sGD
         YYqyOtNBSGsQ7nKWxjmpvkhRdUGu5VKR6RNzBAZYERhkdamhR9eXPkAgYwAlluy0ebQy
         wOdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694912721; x=1695517521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=BPyRsVTo8/pQaBTo99ZSW1v6kyQbQMeeJnQCQ2BUvqA=;
        b=mX0Dv3VRqrWrU6rX08SMDbeyre3Uw+Y1YNr+E24HXh85jKv9Gg2EhsJT7imhAdCDpR
         ghAySNs/H4VFchqyX2OKsdWQRY3zYuDR1/nG1cRPVFn8k/Dh4SwyNxh7WFs9bJP/UoLO
         6RyvLtmejPW4QAGj+2t1ayk8UpPMSqE3LM5HoJqejHYT8cZnMUKctaaEleQzi+XcQZnJ
         K6YxUh2g2WYVBF+knWVoKLHlVjq1Y4L8oGd9YV0867bQyS2WAjeHtzMZZIX7WkjPKNlM
         UJfPxRnN2jyd5NQGHKBGY0293Dst3OjhcT9Z0NLkJHe67ZRJnzPG6u7sFpOMpXZw03Ke
         Lj6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694912721; x=1695517521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BPyRsVTo8/pQaBTo99ZSW1v6kyQbQMeeJnQCQ2BUvqA=;
        b=Bf9t44xqIqoY/hK3S+GDNlAST5Azr0mHl+7E+cvDVeFSDjhHKtvNk9gzkCH8u5Dw2e
         HD7s/sgc43sNjqahHdRL9wNEGAIDEfvYRt28EWTqFp67skiVhe9LDLyaJtvCKWbYGrDf
         qup7P6uoXlxy23k/MUc6pTHwTt7YUpHj23hS/0qbJ70Lw7ED1OwIagkiz3m8SQXZBUk6
         ZMapVbYBNGHIeoosyniYyaEOpw8h9tuIRU/UBx43lurZImNyKkBGCBq/cYZ5j3ZpAduh
         2mlWo16RVHmFDccsLNPJ2quHBcWD6kjzLvcMJHE8Xzy/Nz7j7AqmgFblcmkgOa2wV+dr
         uVwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YygU9ZeJYlN91MKpfc9ud//6FVwRIV5yTPZBVo1Tj47yGFeziEA
	n71O7KNRG9zlrfa5beQJM4s=
X-Google-Smtp-Source: AGHT+IHD0X8l/FMcXm/RwtVLVTv/6/Wg6kUUzA9wYQpw3Aop5fIiETNlqjFyxoOKHT3CjrAvg6UxRA==
X-Received: by 2002:a0c:fb10:0:b0:649:914:6495 with SMTP id c16-20020a0cfb10000000b0064909146495mr4876712qvp.62.1694912720925;
        Sat, 16 Sep 2023 18:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f389:0:b0:62f:fb47:5672 with SMTP id i9-20020a0cf389000000b0062ffb475672ls3119719qvk.1.-pod-prod-07-us;
 Sat, 16 Sep 2023 18:05:20 -0700 (PDT)
X-Received: by 2002:a1f:ca03:0:b0:495:de8a:dfad with SMTP id a3-20020a1fca03000000b00495de8adfadmr4421621vkg.1.1694912719964;
        Sat, 16 Sep 2023 18:05:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694912719; cv=none;
        d=google.com; s=arc-20160816;
        b=u/204fI9ZLIVJeg10rvjSyIh38terdrvcMQfjPCF67m5oq3fZrlKR5PZuTnd8hCQS9
         irI3OPlpGEwUoCyf2rMVl/2w0TShMn/Bsbmhj5IAujJnraafF06cvaowif82tYxxvAJT
         KLLsGVFUTBwBuFJrf8I9of18vbcQDCxXZsfNmdSSCINLRpQdztLndBTG9FB9n/alUYEl
         dfu87pCQgRD7Q26o2Hy8B10v6Otel8FR7OdhE68rC3Fv0rIflZz29rdyvwOtMv+Gwunk
         SuvG2IXfStuZq3VO1Tit/IRC4aJswwT8vaP6mQjYwekOzC+TXMZCB2Yh1GaDmpFbBeIn
         9RhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=817iz7Nd+F9nWbPUey2nsT0RH7HGTC4km/x6KSQ5no4=;
        fh=Pr2plYkJn0ovdHybgHvE53243CPsqSX0NRPDPDnAMwQ=;
        b=xlFZ/sPzDvQkBnOaekAX8cK+enWN/K7TKxSa58KAu2gYlhRlmu2m6LsxT83uN6SerK
         VRjSVpR5k9gwxHeDKxf0DrIqneN3IsVEM/d18ag+14fjRbBgsQeRGD57SZcbiW0kVgQH
         cjtLhBVv77cU8P15+4efrLlx0KZ3DXxbOLzpsRhve/CporoE9/Olab3NnmIV+o5d13QO
         n4lnvbn7dd22GJCeE9qsH/L42HyIj1RtIiOEpRsP5Np7p7s2Pmk5RsPrXW5fDAuc4JGP
         JJj9YfcuhsIJ6iJ3hA87YH1tg5VyOlOPfn8oRt9FjAryymhQBeOpE+WU9Xg0Ja0/Ur9s
         HY7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ygoxln9w;
       spf=pass (google.com: domain of jdown714@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=jdown714@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id ci38-20020a056122322600b004936ba690ffsi756675vkb.2.2023.09.16.18.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Sep 2023 18:05:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of jdown714@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id 5614622812f47-3ab3aa9ae33so2292233b6e.2
        for <kasan-dev@googlegroups.com>; Sat, 16 Sep 2023 18:05:19 -0700 (PDT)
X-Received: by 2002:a05:6870:468a:b0:1b0:80d0:b895 with SMTP id
 a10-20020a056870468a00b001b080d0b895mr6367410oap.12.1694912718687; Sat, 16
 Sep 2023 18:05:18 -0700 (PDT)
MIME-Version: 1.0
From: "MRS. MARIA  EDSON" <edsonmaria1981@gmail.com>
Date: Sat, 16 Sep 2023 13:05:01 -1200
Message-ID: <CAOYhVia8T_6tTU-GsCPzxj1zcuPYbatOme6sJe9wmLoHmLeo1g@mail.gmail.com>
Subject: Hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000085d49a0605839e8b"
X-Original-Sender: edsonmaria1981@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ygoxln9w;       spf=pass
 (google.com: domain of jdown714@gmail.com designates 2607:f8b0:4864:20::22d
 as permitted sender) smtp.mailfrom=jdown714@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000085d49a0605839e8b
Content-Type: text/plain; charset="UTF-8"

  Hello my beloved,

 It's my pleasure to contact you to seek for your urgent assistance in this
humanitarian social investment project to be establish in your country for
the mutual benefit of the orphans and the less privileged ones, haven't
known each other or meet before, I know that everything is controlled by
God as there is nothing impossible to him. I believe that you and I can
cooperate together in the service of the Lord, please open your heart to
assist me in carrying out this benevolently
project in your country. I am Mrs. MARIA EDSON. A dying widow hospitalized
undergoing treatment for brain tumor disease, I believe that you will not
expose or betray this trust and confidence that I am about to entrust on
you for the mutual benefit of the orphans and the less privileged ones. My
late husband made a substantial deposit with the Bank which I have decided
to hand over and entrust the sum of ($11,500,000.00 Dollars) in the account
under your custody for you to invest it into any social charitable project
in your location or your country. Based on my present health status I am
permanently indisposed to handle finances or any financial related
project.This is the reason why I decided to contact you for your support
and help to stand as my rightful beneficiary and claim the money for
humanitarian purposes for the mutual benefits of the less privileged ones.
Because If the money remains unclaimed with the bank after my death, those
greedy bank executives will place the money as an unclaimed Fund and share
it for their selfish and worthless ventures. However I need your sincerity
and ability to carry out this transaction and fulfill my final wish in
implementing the charitable investment project in your country as it
requires absolute trust and devotion without any failure. Meanwhile It will
be my pleasure to compensate you with part of the total money as my
Investment manager/partner for your effort in handling the transaction,
while the remaining amount shall be invested into any charity project of
your choice there in your country.

Please I'm waiting for your prompt response if only you are interested. I
will send you further details and the bank contact
details where the fund has been deposited for you to contact the Bank for
immediate release and transfer of the fund into your bank account as my
rightful beneficiary.
Regards
God bless you and your family
Mrs. MARIA EDSON.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOYhVia8T_6tTU-GsCPzxj1zcuPYbatOme6sJe9wmLoHmLeo1g%40mail.gmail.com.

--00000000000085d49a0605839e8b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">=C2=A0 Hello my beloved,<br>=C2=A0<br>=C2=A0It&#39;s my pl=
easure to contact you to seek for your urgent assistance in this humanitari=
an social investment project to be establish in your country for the mutual=
 benefit of the orphans and the less privileged ones, haven&#39;t known eac=
h other or meet before, I know that everything is controlled by God as ther=
e is nothing impossible to him. I believe that you and I can cooperate toge=
ther in the service of the Lord, please open your heart to assist me in car=
rying out this benevolently<br>project in your country. I am Mrs. MARIA EDS=
ON. A dying widow hospitalized undergoing treatment for brain tumor disease=
, I believe that you will not expose or betray this trust and confidence th=
at I am about to entrust on you for the mutual benefit of the orphans and t=
he less privileged ones. My late husband made a substantial deposit with th=
e Bank which I have decided to hand over and entrust the sum of ($11,500,00=
0.00 Dollars) in the account under your custody for you to invest it into a=
ny social charitable project in your location or your country. Based on my =
present health status I am permanently indisposed to handle finances or any=
 financial related project.This is the reason why I decided to contact you =
for your support and help to stand as my rightful beneficiary and claim the=
 money for humanitarian purposes for the mutual benefits of the less privil=
eged ones. Because If the money remains unclaimed with the bank after my de=
ath, those greedy bank executives will place the money as an unclaimed Fund=
 and share it for their selfish and worthless ventures. However I need your=
 sincerity and ability to carry out this transaction and fulfill my final w=
ish in implementing the charitable investment project in your country as it=
 requires absolute trust and devotion without any failure. Meanwhile It wil=
l be my pleasure to compensate you with part of the total money as my Inves=
tment manager/partner for your effort in handling the transaction, while th=
e remaining amount shall be invested into any charity project of your choic=
e there in your country.<br>=C2=A0<br>Please I&#39;m waiting for your promp=
t response if only you are interested. I will send you further details and =
the bank contact<br>details where the fund has been deposited for you to co=
ntact the Bank for immediate release and transfer of the fund into your ban=
k account as my rightful beneficiary.<br>Regards<br>God bless you and your =
family<br>Mrs. MARIA EDSON.<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOYhVia8T_6tTU-GsCPzxj1zcuPYbatOme6sJe9wmLoHmLeo1g%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAOYhVia8T_6tTU-GsCPzxj1zcuPYbatOme6sJe9wmLoHmLeo1g=
%40mail.gmail.com</a>.<br />

--00000000000085d49a0605839e8b--
