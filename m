Return-Path: <kasan-dev+bncBDSNT4HYQUIRBJXRYWJAMGQEGAH5UBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A7CF4FA78D
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Apr 2022 14:14:31 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 10-20020a1c020a000000b0038eb5cb35ecsf205432wmc.9
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Apr 2022 05:14:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649506471; cv=pass;
        d=google.com; s=arc-20160816;
        b=qO6+um4jB7anEuJZGi7KG6A2Hu1/kb5Z7Lbahd4NBboSRXa+F3vJFWKHHO4Wjlm8ED
         KUIeSeBWjxIa3uxmLCPdT3K/z8QMCGN4HrTsmSe+1q6z+wjKZ0J6BNQL1nTYRYPrQgbX
         nmOeQ91sQyenrfsBfnVC+1aemTxZMdTce8NPTd1qt8M9qu32UUY0kiVl4d/DYEdwceOa
         NNOIAb17CPY41vA/+8lRfOynO1hEPg181xK3i5B2p0yFi8PJBxEcRTrsbc5Eh/QWj61k
         aRl3fJdaJ7VDvps+K3lEANt6Rz0LUE9SOynOYM8isMnevLm4Q0+xHbGVKb7G3smY+F10
         RFCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=BXjwjeViWsS5lpV3fOdQ7c9k1AlhJ1u4571yLKKQ+gM=;
        b=PpqrTGuEAPQJkEvBE6T2byMNG2mZB6VXvz8oWCRRK31htRx6Kgu3/ydeN2jMIsgn+k
         SoRGKh/3Pole+9q4nUGNUJSc5KTH4Ywp2rA6qac2apv/SW1V8XAy97LQ2taXmEIWfrBQ
         kbYZqR0a2IJ6sLZGuljheiAwV4klHJsoIA+Vutw4CxEKB+DV9pS3tjGANPBH+0/Z4EUm
         UbIUZUkPFDUGNETdk5sjJIhv3RHfS2K19sKqhPHjn8lTNNQNUF2j3y2pXL7wPg8TdS9f
         U0sHLT6syBA1DJUkTAlvTbCDlrppDGcVt3zFCk5mvaB+A/Tblm300BPVEJU/t3blsdIL
         ZDJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dIaK5YMC;
       spf=pass (google.com: domain of chibuikejoe429@gmail.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=chibuikejoe429@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXjwjeViWsS5lpV3fOdQ7c9k1AlhJ1u4571yLKKQ+gM=;
        b=VxXMtOi9A5dfxWTDg748/BhbaJZaxtxNx9tRuB0QbY0DfSCEqYzyymJL2SAjgf3HeG
         pmTqRq0RSkMIdCDgQGjAbWKAfAqxatuoU23HbrS7z8c3yePf4eGF5h2keFtUuujHF8KK
         fibL8t8Xz8ZSLpzuAIhXdc95xlEx/HCqZDm/97sBM52m+/4WBh3Rls0vRmLd+9gaa9WX
         zQgnbh0oKxWOv8vRrJ7rfdD4qyaVK2DYf5q1h6IcvCKP72P/+S2BshbVgjV4samVk7iY
         XMJZ71/QNclOSW/Q5QwFErz99QA4aLCUehnt47lll3jegQ+vWLwnupvPH9YJmwZsPo1A
         CLbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXjwjeViWsS5lpV3fOdQ7c9k1AlhJ1u4571yLKKQ+gM=;
        b=PXKWjZ4macJboPAuRwQnTy7NsJs4F9sRaWpNB2Xj85VlrL09jsjHJ5ESImpxrzzG0Z
         GJ9n07jo/mVddKXx834dcZS6sVSdNmr9cwvNLFnl+yfU+8OYlcvuZtv+sTjw1Lu2IYdA
         QTNXjgOM71fw/R2BFMyxEeae98HtdCeu52a0GJCsxVEwVTI8bZxm59aQmlJQRPP1CUKK
         Iqdd4SYxzSr2A8iGTNO4BkPAcn3586W9GWH1iOvkD+jk9HI0uckBCc1bV8pIF0RITof9
         jcikQoXFwkQWbHC0qz68xCzLJfLuM7Uz+D3nUzzQFoPv4ouGgQ+m95vJbaGvgCJxN4Px
         8Dcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXjwjeViWsS5lpV3fOdQ7c9k1AlhJ1u4571yLKKQ+gM=;
        b=WgVI2ws1UtpzKar9dUVrtoJeYKNKGTeEfwHNdRxRtw6+r9r7sALlRL4dfv1SDMtmZf
         PaX/c5+lYx4ZTeFNGpFcGPTK++MNeWZu4YaUg7xnY6Ri7jCWDRuJskXZY0zfcSmsmH2z
         Djv51dDHfna+WgNiZUcsVf+ktmrPCNmCMT8O1R6NeTLn7TpTVJ6EzYgsGQ6hEEwNWL+i
         fG3v7icb6S0F49HBTa9AHs22lValsCE84+LI7HSa0fkicFyyssWnz6rWre7Z44yhIoHS
         jKcfJVT88ewPo1NB2KibYEA0dbSGTcciq1yXIXXZywzRsW7qA/nqUD0UZGmUm7yP9UN4
         C+gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WPOBc8q/xLQeeBAFhI4TundFD2kG/oAfKjtNY7CZ6/t81mftd
	24787gxkK/z09wEww6kC83M=
X-Google-Smtp-Source: ABdhPJwtmArH1Z2nRiSElv7yuj1LPKMxfJDaxwVeB/19TdK/x3jcJJiUCpC1vfFmB2L2Wwm3RSGq1Q==
X-Received: by 2002:a05:600c:1c10:b0:38c:c0fc:d5d5 with SMTP id j16-20020a05600c1c1000b0038cc0fcd5d5mr21166334wms.142.1649506470991;
        Sat, 09 Apr 2022 05:14:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls1083546wrr.0.gmail;
 Sat, 09 Apr 2022 05:14:30 -0700 (PDT)
X-Received: by 2002:adf:82ee:0:b0:207:9bec:ee5d with SMTP id 101-20020adf82ee000000b002079becee5dmr3299404wrc.634.1649506470065;
        Sat, 09 Apr 2022 05:14:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649506470; cv=none;
        d=google.com; s=arc-20160816;
        b=qEOIKnqAKNbS/s2p6gLeY0XK4Jvef0QcLZtZfuE6waZ84hjlNGZURNelYyMIXdeiFI
         Q36xTa6cRR8SgTHj+ww5Hj1lGWsQHS1g4yOTgo4GUl+767pu2jIh023/Pw3v1p9GEAC7
         2yQvY9baZZXDWf8emEgqBQQAHbW7PzazhD+ypAgnXjrWZ5ZY1Ac3Jtcmp8eaq8/A2pBL
         Fhpib/Qm+Vr99nvlw+mhgu/eZvlExqu09t1UWvr8VBhA5zTbtd6n9WShPVFz1lyzv8Ox
         Hru6jnf92vGlGE7YMRXrGn4NBqeGNfoaNhXw5N2CJsPCOB4p5V0/uGQ3w+FHSpsc/Zsv
         K9Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=KD+7LUh13xay2TU7PrGW0N3xGt/fvIfFeTpBoeANRG8=;
        b=V9L65CMg3i41oSa97eklFu38sCHte8qPBrMWDSHv8CrfqmglOhKS4RlZN5WZdM0v7i
         1h7UvuOFX71VKipmscZTmkrC3oYDwec9PtekJrFxfvHOsVCoqA/Hv/ikVW8YvCkCO5GL
         JTkxLwudqQdBkK9VHj9qJv86yb6DhfZe2m9oFhJ+IrA4ONzMKYfQPOopA+0GgEr9a9Uu
         RPqcTCWWzmd6mMj/WPrGNHO90egfWHvUOiHEIhD6vHNGVd1XVJuaFJsOwk/HizoPSx8h
         L5pPpef6PD2TEBFodOfO8bbNZFYkSvCR9Ut4To8B7ECK30M+iCxkF80/92Fr8nWNgNfz
         AbWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dIaK5YMC;
       spf=pass (google.com: domain of chibuikejoe429@gmail.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=chibuikejoe429@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id v13-20020a5d4b0d000000b002078c87e21bsi174296wrq.6.2022.04.09.05.14.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Apr 2022 05:14:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of chibuikejoe429@gmail.com designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id z99so4220310ede.5
        for <kasan-dev@googlegroups.com>; Sat, 09 Apr 2022 05:14:30 -0700 (PDT)
X-Received: by 2002:aa7:ce11:0:b0:41d:5b84:eecd with SMTP id
 d17-20020aa7ce11000000b0041d5b84eecdmr5015058edv.15.1649506469514; Sat, 09
 Apr 2022 05:14:29 -0700 (PDT)
MIME-Version: 1.0
Reply-To: anhthuong554@gmail.com
From: Joe Chibuike <chibuikejoe429@gmail.com>
Date: Sat, 9 Apr 2022 16:14:17 +0400
Message-ID: <CANP9YKPCQU-nAHRSaq1Fmh7z1cqsjenXtCNnOG=iJM7MnADiLA@mail.gmail.com>
Subject: contact me
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000002b95b605dc37a719"
X-Original-Sender: chibuikejoe429@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dIaK5YMC;       spf=pass
 (google.com: domain of chibuikejoe429@gmail.com designates
 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=chibuikejoe429@gmail.com;
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

--0000000000002b95b605dc37a719
Content-Type: text/plain; charset="UTF-8"

There's something important I would like us to discuss, if you don't mind
reply

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANP9YKPCQU-nAHRSaq1Fmh7z1cqsjenXtCNnOG%3DiJM7MnADiLA%40mail.gmail.com.

--0000000000002b95b605dc37a719
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div>There&#39;=
s something important I would like us to discuss, if you don&#39;t mind rep=
ly</div><div><br></div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANP9YKPCQU-nAHRSaq1Fmh7z1cqsjenXtCNnOG%3DiJM7MnADiLA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CANP9YKPCQU-nAHRSaq1Fmh7z1cqsjenXtCNnOG%3DiJM7MnA=
DiLA%40mail.gmail.com</a>.<br />

--0000000000002b95b605dc37a719--
