Return-Path: <kasan-dev+bncBCHNBUWUSAORB2OZSXFAMGQE6ANNXBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8894CCD079D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:19:07 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-450c16f2bc1sf2284768b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:19:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766157546; cv=pass;
        d=google.com; s=arc-20240605;
        b=BIMeACjjdhLFgAr01VysHzPkwl6S0uZQgoMoxh9gVhSsuoBmdmUqjDYB9Ut3T3g+og
         INyGJxtYEuVLE5vkqs7/tEqhBEVIz1JoJbgB/XW/sKqZiLaIfsheFyBos4B10ui/gUvj
         EVpjsAzaWnjY2AiUMY433oXnYCjTIzbIVz4GpQj6PNgm5DBSS5K7GePhWI21DtRsuvnK
         f2KxZ8QxCu4bpiQt2Mik23hKoHQXqAUcC0xLFgEdpAjqXeMEoYGrC6MQEFFTX+ZnWAOT
         usi/dGt0J0fNa1hlkb44D2LC6G4QBM6km4w71DJHfhvTsTW128nx6Kdh1BBaI2wEKtLG
         c6xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=2Kt0us9P4xKoesrU4Bg1y2HiqZVtcWoz6DLoTn0bWAA=;
        fh=FXtYX/ZADY1bY9Rs/ZDCLwm+ByOIrTKhK8t7hToQFcs=;
        b=kZ2rQXxjfkBuun+78nKmSHcIRF/pVZtLX0a/iqcayqZmhBFimcBezm7ftmrNuNr6Kr
         XVpvXYkQv1syjCEdQIZZ0Yg7RsOLM8kINxMc0gME2u3vyTiJnhMKtAfZ/pQ3n/kNnTqC
         ZPmM3EyahUVisRWCqGml3aR+aqcGKvVn+hl5HB0eZzvVSP5UT3ouCxj8lhox8VVcK8go
         FVPtOUJsoFmxyBBUrk4t0PhXkpsiEwkLmMNYhdVu7AzCo+qSp45GvkKdOInDxnYkJ1Xt
         f/Xum/M02Boc394BMybwU8FdpqfBIXtG2UR1Djco3iTv6rjdiYog26SFughNmJGyopQN
         vxtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MLuXZRWi;
       spf=pass (google.com: domain of mr.kweku.eghanabankplc@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=mr.kweku.eghanabankplc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766157546; x=1766762346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2Kt0us9P4xKoesrU4Bg1y2HiqZVtcWoz6DLoTn0bWAA=;
        b=oE/fJfAlR9+DlBKxxo9A8ZiqVzjN9aXUpGONAVx5nSeXAnNChsPoLEJMU8xqy5L1/4
         QNWMQjXSTBTTWiLdnCXRw3qOOnfLt2N+ou8RRrusiE0J8vHKdFovF6plu6ZD/xzJudUW
         AaZSqypuTOeRAu6/Zm2/WU3BFFjS1iQf9Z41twtrTJhnMhoJdT5J4wfoYN9dBtsel+9a
         FCWz6qMQYoKUVtgy4c1RzjdICxtyr1w0tCGr7sa+GnLcdWuRT1Pf428pQzId4aMdpjaN
         Q89MsGkJRSqemWvh+uke51w5fK0JbsbF47MQQEqrMz3ZGJJQIMO2qTwSRTdUMbeVoFoY
         07sg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766157546; x=1766762346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=2Kt0us9P4xKoesrU4Bg1y2HiqZVtcWoz6DLoTn0bWAA=;
        b=UUzR+Ch4ElfFJiik1D3SzE/dGWErTUUOePERlkTGa0f26cyGvUr0+JKofg9y6VwKK9
         AdH753ZV0Yejl6kYeqJa4LP0NwH3725UjTDnsIxyBZu9OyEDQvMe8LICEi9apj134KJs
         cTG/kvInqTdHBmkg1aOtUEET+ppVM6yOe5sk3OaJpEvMboMbCXUgGSLYia9r3SRiOfKL
         YgqvT4no78mmzpR9wt/XQXAFezgOZjxCOabrf3zS1v5wI1nstBkPacRzjyRt4OsJD4qv
         PUuXm+vzyuxtBhuNq11x7UUdy4GM57FbEgr8OOB/07jUxqOloormWO2Lp+/TZHgSe4gH
         RXTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766157546; x=1766762346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2Kt0us9P4xKoesrU4Bg1y2HiqZVtcWoz6DLoTn0bWAA=;
        b=SatyMAXNqJAnL4cPajJiOVWPKXZtYGvZxMj/Itsn5XmbiSE7E37Qb1uH9edU1knMTw
         9Rz59se/zbKyGb3xEoMqdG8vsi+q2+vf21IQaYAu4CrNw5CZFCPUl2ylw6PYEmnK33FQ
         dX4hroMJLRSqEwpTLoX/xwkjmuYZOFESlubY11yBXJ15j91BWnz99DfMJoeZT/E9U8OY
         MnILhP4pebGcatoTZh/ZEDGjVA8V336OuSVQVX58ZbJ8FCcaUViOA70haxCAvLaaEALE
         OlHt9Wl9C757rlAn5NMWMBmoqoEACJZcx+vj1d67B11vKSZUKYkrpTwecz1WyputADot
         goJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXTHbr+t20Bpms6yOaFbl9iRunCARf1HNzIo59oG9mg5WWvRQgEOYBzXW4dutDhW9UtGT5LYQ==@lfdr.de
X-Gm-Message-State: AOJu0YxzjUJZu7llpWpU1CvU/1nTZcdLlNyxqDxdOkXYnjChBIGh3Czj
	Q+VTvC/QFyNGKzbBiuVZGjm14JslSc3HKwpNIHkcYFs5YIcyDd60Ll4R
X-Google-Smtp-Source: AGHT+IEggSNiwA7Y7enjw21Cgo/kP/iQHOtoKKTv+WrRCSl9J72m8FSlhJxfUiLjGOKwHYVRlOHrWw==
X-Received: by 2002:a05:6870:224f:b0:3e8:98e4:56d with SMTP id 586e51a60fabf-3fda56c850cmr1787113fac.41.1766157545681;
        Fri, 19 Dec 2025 07:19:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaFs0Cs10yrXiw2XU5eOY1E6gXTyYDoaioTsvpf2aKYmw=="
Received: by 2002:a05:6870:e11:b0:3e8:9f07:3b9 with SMTP id
 586e51a60fabf-3f5f83ed669ls2816947fac.0.-pod-prod-03-us; Fri, 19 Dec 2025
 07:19:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJrN+7mqD3OiKUBM07/qTLx+oNPuudA5RkyYzdDhLeymByTYPVB+FB/XjANQ5bU/iZRmAMlT2DJw4=@googlegroups.com
X-Received: by 2002:a05:6870:4584:b0:3e8:8e56:671a with SMTP id 586e51a60fabf-3fda572671emr1821810fac.54.1766157544632;
        Fri, 19 Dec 2025 07:19:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766157544; cv=none;
        d=google.com; s=arc-20240605;
        b=LnIPZ2BDFsXzwfg0Iwr9cnIFqtoZWf29HCYuU6gvnL1ITuznRH3HNU2ZVWWmYHDW/7
         agZfaIsL4jDc94ePPwFjHVpAVL2LK2++wBTZJnBmrbXiMTcRdbDrTbq476d2RM7axq5j
         D9e4f683qzNzZn7qEqvEGDOnhS+rBMkcjNbHGArMkHlO0sVKn00lV7G4NDNqZNj55G6S
         j50O99SeRMDCYRIaJNl0I8w24+MSS8bl9lF3H6aApamxcN5NIxaF5hnARkKR7VnxgyHB
         MORhM2oGA38SquOZVGvtvOIWhK/qWCAfpwmqL/GOL07Zlj999MRKz6CoKQNFm0Du5b1D
         /pCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=tLGLxkUnXJs8eJjEKZTGTmjYApH6fGaq6FWwtsvp1bI=;
        fh=6Q9vEq2DiZHWxkZLwHjmymThz3FXXyBPQj3KA4/uKC0=;
        b=A+M25dnYyHT0J6Bmi22dDtDU56y7u9mZ0FFE19yUzmWJsDF9s6xatEQtC13/PEjb56
         QW0A/sD2wUkTia5YYY1wvvVEsUrbNHLifYR/F1TEJzM3e77gLaNryexFewt5IIznrLt1
         7xEVJjSlhs7cz1ZGRCumMi1sBSLdGtyC47AsDGi65sC6r+ysYzLO0wGUk1syM1nTCcmn
         bnLjwVUbbmImcSkcpvF5hzIc2ArTm6OjFJRLTGKyLw2wg1XgbKQQuw92HsGSB2gnPz2k
         VcaB5KrDdqID7M04AjGk6jS0m8ExwmOB2Bj7sVROP497c6+33PZ0+0DhkgLqtDUStBGK
         o9Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MLuXZRWi;
       spf=pass (google.com: domain of mr.kweku.eghanabankplc@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=mr.kweku.eghanabankplc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3fdaa4f1f45si91755fac.0.2025.12.19.07.19.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:19:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mr.kweku.eghanabankplc@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-2a09757004cso22011205ad.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:19:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXKO43KOfawWUI0HPRE9wIprBIcFztJ8I07HZ1YmyUJ4wltDNsn87QTUVbkSikDnXh85a9FRTYkJGw=@googlegroups.com
X-Gm-Gg: AY/fxX7msnXm7N4B/yLTYU3cT0dOB4fvbxjeCaPL7u27hsDDAY5P3+ubcH3pB6g8qQV
	CJeYG1EXAv+gbqjY/YZXS5xs4PpmkieLXtITURLaJHLp8VhQtux2oIBKTDZahbQXVG7e/jrQhKR
	rDg++Yf0+59GeFigVnkkLqBDv92F9mL0PFc1enl81Ot2kihBiLfFWr0J3zeemOOuVSEkDsKG1P4
	b9VSxdbxqCyujOps959ZCW3vN0qfWRDfgF07VWm51c+M8t0rOmFuaqBc73KhUS9Vv+EN5Us
X-Received: by 2002:a05:7022:f409:b0:119:e56c:18a6 with SMTP id
 a92af1059eb24-121722b4e85mr2933430c88.14.1766157543560; Fri, 19 Dec 2025
 07:19:03 -0800 (PST)
MIME-Version: 1.0
From: Bank Of Ghana <mr.kweku.eghanabankplc@gmail.com>
Date: Fri, 19 Dec 2025 22:18:52 +0700
X-Gm-Features: AQt7F2r4NvH8MoxNn5nWC75d-ffslvsPlvG4wXBvlVpl_E1_F6_FcpJndBJyE74
Message-ID: <CANK+PMnATe4jea3HoeURJiP5SDPnbNfcNMLkf8B=TNPm6DRnEA@mail.gmail.com>
Subject: CONFIRMATION OF PAYMENT BANK OF GHANA
To: karen.kraus@jetmidwest.com
Content-Type: multipart/alternative; boundary="0000000000000058da06464f9921"
X-Original-Sender: mr.kweku.eghanabankplc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MLuXZRWi;       spf=pass
 (google.com: domain of mr.kweku.eghanabankplc@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=mr.kweku.eghanabankplc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--0000000000000058da06464f9921
Content-Type: text/plain; charset="UTF-8"

Dear Sir/Madam,
kindly be informed that your payment/transfer of 52 million United States
dollars($52m)approved overtime through our corresponding bank in New York
has been repatriated to the Bank of Ghana .
The international monetary Agency in the United States directed that,
inline with money laundering act, an account should have been established
in your name with Bank of Ghana for direct onward transfer to your
designated account in your country through a corresponding bank in same
country of the recipient
Consequently, we have concluded an arrangement to have you open an online
account with us urgently for immediate deposit of your fund to enable you
to execute your transactions/transfers online personally.
Details of your online account and operational codes will be provided
including an ATM master card you can also use for withdrawals from any ATM
point globally.
Sequel to this and to enable us to finalize your transaction, you're hereby
required to send your receiving address for the ATM master card and please
provide us with your valid ID to open your online account.
For further directives/Correspondence contact us.

Anticipating your urgent response.
Regards,
Mr. Eric Kweku H.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANK%2BPMnATe4jea3HoeURJiP5SDPnbNfcNMLkf8B%3DTNPm6DRnEA%40mail.gmail.com.

--0000000000000058da06464f9921
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Dear Sir/Madam,<br>kindly be informed that your payment/tr=
ansfer of 52 million United States dollars($52m)approved overtime through o=
ur corresponding bank in New York has been repatriated to the Bank of Ghana=
 .<br>The international monetary Agency in the United States directed that,=
 inline with money laundering act, an account should have been established =
in your name with Bank of Ghana for direct onward transfer to your designat=
ed account in your country through a corresponding bank in same country of =
the recipient<br>Consequently, we have concluded an arrangement to have you=
 open an online account with us urgently for immediate deposit of your fund=
 to enable you to execute your transactions/transfers online personally.<br=
>Details of your online account and operational codes will be provided incl=
uding an ATM master card you can also use for withdrawals from any ATM poin=
t globally.<br>Sequel to this and to enable us to finalize your transaction=
, you&#39;re hereby required to send your receiving address for the ATM mas=
ter card and please provide us with your valid ID to open your online accou=
nt.<br>For further directives/Correspondence contact us.<br><br>Anticipatin=
g your urgent response.<br>Regards,<br>Mr. Eric Kweku H.<br><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CANK%2BPMnATe4jea3HoeURJiP5SDPnbNfcNMLkf8B%3DTNPm6DRnEA%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CANK%2BPMnATe4jea3HoeURJiP5SDPnbNfcNMLkf8B%3DTNPm6DRnEA%40=
mail.gmail.com</a>.<br />

--0000000000000058da06464f9921--
