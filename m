Return-Path: <kasan-dev+bncBDCL5IEVVUMBBF4KZOGQMGQE626BWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FD6B46F97D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 04:10:16 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id j194-20020a1f6ecb000000b002f4c0eb8185sf5407248vkc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 19:10:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639105815; cv=pass;
        d=google.com; s=arc-20160816;
        b=jMsEl8SRGZloTADP6HDkLmRIhyIAQLhQLr9ToUA2czQ9ATdVYWgubmwa/+7QmkFP4g
         bZoVf37EbRovuc29oEkqE1pE0Xj2QDCw5GGsRJk0wFUXjRVCwg3dEPiSDZSupUgo6mTU
         f25BrZXPYcKu/j56WWs2SB4uIN0PG5NuSdOt2D2KOYsP4Ms/nVfrwQ7d1zZbRdsfmFLy
         1diBtLZ2HHtn/hh9NMl2WXOlqcATo5DvYpkrUM7HeCCmmEvMQRmITePAD57JEYI7Jwtx
         CDhYqt5KObv65jCgE2QOMVHA8deHvxNKBcnvw31JzZ/dSrP2WiVI8JIaD8ETLi7rbLFH
         dIPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=GxyPvfLH3XMKRWPq7jXLdoJc4doGfzAn38N5lvw2spE=;
        b=cR25KoXnRJ16FoX9Jh8QQdRM4ViEjHbEZnBd9LFU2ySMUqdF9I953Y+Gdl/R/bB6Xm
         HOaW3+iwHoBrP90olCAou4ptYs9H30YRRWHeXIIZZD+Yti0hiSx0nrNc63GQABkEEEqk
         vfBEdp8ZzMp0Rym3MIpx9uKWJyzbl+6m4GRIRFJ1ozzhkasmwNy24OXS0r9bKzmjNI+t
         PJJUdAbYoOHBcHy/nnGh2J7gG1AM/CG3C9B8pgbaMEnEPbrxC/oNqRPT3ddrUrEKNLMT
         EhkYJySezilBYR+CKrp/qqa1V6loKt1ycMy8WmKqQMk9t/WCSz/sDqIqH0dvLN/98TfX
         ZjNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=in+iQFni;
       spf=pass (google.com: domain of joshuamaxwell2001@gmail.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=joshuamaxwell2001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GxyPvfLH3XMKRWPq7jXLdoJc4doGfzAn38N5lvw2spE=;
        b=CldE2teT6jj8DSmzFK1EjOadKH0x/qbNX7webhMRd49Dj5N9kLEw1DcxXtL1OyaDCK
         KkLG+gBZJKGE6PYRf4srRlPvMf+Ke674Ue+VZPnXMzq9p22Z+q15jSOHzeM3Y7I5dSZc
         h5JI1siTm3379l6e2G7sNO9MrH/tyVIc7Tv2Fsdb0HoRr0f2AAxHtR6Or2sL9zIJL3v1
         Nxsg65G4E3pR26GNMwMsO1vCir2J6Q16oSTOPcTUm/eRx4WQZp7hVYIYoH5aSltcd6dR
         tFHf4AYBDUwJfPog2IdSItmJ9+XLFerCPk9wtpRjCTiY7QOKExFTG+m3stU441SA9Nom
         lSLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GxyPvfLH3XMKRWPq7jXLdoJc4doGfzAn38N5lvw2spE=;
        b=eQBYUMZu6mQjsG8D36uzGgxtmJeYGLk4ECcq2RgSIG+v6HbWcr6sUOLLjzSQQW0Q6v
         Gm3N6W5YL0fIB7VNs7O07RnGnlG5EA4tWae0fhPIERMBA3R+gHb7mWwBiCyHHbmyvbTC
         7EwaHOI95IY4CF1h4uCw8DBFXoXEQqggA1t/4jDPGTTeIM2iHi/ymQ6RDpG8vmk3gNJc
         P6TnJpdqdHof2pFOmkgWJOOCFUjWSttlY3mQbEAf4lU3tdanmA1Lo7N+nECQYmmGWxX8
         EgTCvWqqhU8z85WOa2VUSPP7AIc9tEQZiWxr1NF1Pxfuu1uouNHUt711i+tATuafb6GT
         INDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GxyPvfLH3XMKRWPq7jXLdoJc4doGfzAn38N5lvw2spE=;
        b=t9BKqUtgZZfVJCtTr+45Rj5xFaMYi9FWaSvDWuICkohnqfkIhRiRAioG429T4RJ7A5
         BqCZGBnL/H4MTtU5XMxcN0Jj+ftezP+cXyDrOGVmpc6PITd1+3PegyBgQmxsxu+NEUIb
         2pNNW/BlO0NV4ObheoEG6HrpiR6h6B7aYNL3TptPg9dZqsT2OiYLgqmazzot2WO8VvL8
         QipSnb3QG14qOa7Juif2vd+6pxtjrXF6wbMujsEKRhtG6ny3jyZ1hwvuaNXk98ReftgW
         cfIN/+SLnGeOLbUCaIjwhfopnY/32nw6ul+jzDAXh7aqJCAmqZHzX9pmx83cjtK1tQdX
         Xfgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328Q6H/EWdBw/vtCKHkO+ETI0GNn7pAnKrhQ8NcSbK/oAY7dUIj
	I0NLOXfaQVc86ifNl3MzRsI=
X-Google-Smtp-Source: ABdhPJwBVduoEEJyOzy/bp6a9oehWeaBs5gwxItAvM+bOpraHc/kpKFBdaW+Qt2SDT8Lo67wC6XLgQ==
X-Received: by 2002:ab0:72c8:: with SMTP id g8mr25418005uap.86.1639105815405;
        Thu, 09 Dec 2021 19:10:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b009:: with SMTP id z9ls2692191vse.10.gmail; Thu, 09 Dec
 2021 19:10:15 -0800 (PST)
X-Received: by 2002:a05:6102:389:: with SMTP id m9mr14304183vsq.43.1639105814925;
        Thu, 09 Dec 2021 19:10:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639105814; cv=none;
        d=google.com; s=arc-20160816;
        b=dj8rzVePz/CCN4D5sJUvD/Lrhf8RpUFRk7JmwoLYJfvcatYX30lq9qCXP9ftGrthNQ
         dXyWAd6vmrnGUOHMRz89H8/UkRSoy9SCHix6CeuLIKafXtiuyY+Zcues2ORsn+xM1ZFQ
         8W90OOXfFgJkCggiGFc5em32RaXdd5lcd23gFWU+/GKjYAoiURbbVKGI6ZWd+IEy460n
         AUuw2uviu8oKHfOqIeQaQEs9nwElwSL8huh55movfCVpnNQSLIPUqNsV0iGQEjuDEgs2
         lp+IXwvxllCQlQBl5y6zgkYJrwqQ+PwmJyKVJY+GKX1/LkdmKYzca7NonGKbP0lX2Cxr
         J5dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=X+MxcvH5jnrNnd1/DGPOKTxk8GmF2vtQCy+aVfBvtDY=;
        b=h7+sbVpj60E5cuT4L2g9OoLrILYO020ukwMRtKpoKHiEs7yFm6k+kEV508PkndHIXE
         AzQI5lajNZ2Aql4AgSJ/ax3rQiDOwrN1Kn/MgGNf1T6M/GbU8LcvZLEYC4kewhsT1dDy
         hfxLSwDeOXSm0MNZzkv+PLKToeC0wyPEckqDY3b0awkX0+nKCkAQmh/5KS+14nnDRjF7
         m+qEmfLL7Li38TQys992TzJeSdWJ8+HINzfBsROAg+pmK71wIHeGIVVeH+enyOWgZX6u
         ohiJErM5HZqzlwwxxaz/y76o1i+0qU5MAcv33UEINXNyJZgBgZxZw2QWQGe7LCywt3FB
         cOOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=in+iQFni;
       spf=pass (google.com: domain of joshuamaxwell2001@gmail.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=joshuamaxwell2001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id q25si185637vko.0.2021.12.09.19.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 19:10:14 -0800 (PST)
Received-SPF: pass (google.com: domain of joshuamaxwell2001@gmail.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id x19-20020a9d7053000000b0055c8b39420bso8358657otj.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 19:10:14 -0800 (PST)
X-Received: by 2002:a9d:6c18:: with SMTP id f24mr9229108otq.250.1639105814506;
 Thu, 09 Dec 2021 19:10:14 -0800 (PST)
MIME-Version: 1.0
From: massimiliano brevini <joshuamaxwell2001@gmail.com>
Date: Fri, 10 Dec 2021 03:07:54 -0800
Message-ID: <CACtWDT-6tqUiXHC-bpqYRuwDN-VUD5=Wq7PYrXXLtz3kdexTYw@mail.gmail.com>
Subject: RFQ
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000d2b20e05d2c20f6c"
X-Original-Sender: joshuamaxwell2001@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=in+iQFni;       spf=pass
 (google.com: domain of joshuamaxwell2001@gmail.com designates
 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=joshuamaxwell2001@gmail.com;
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

--000000000000d2b20e05d2c20f6c
Content-Type: text/plain; charset="UTF-8"

Hi,

We wish to place a new Order against our 2022 order forecast.

Can you have someone in sales contact me On My Personal Email Directly On

E-mail: massimiliano.brevini@glovaopp.com

We await your soonest reply to send order.

Kind regards

Massimiliano Brevini
Global SC & Procurement
692 566 120
Barcelona, Spain

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACtWDT-6tqUiXHC-bpqYRuwDN-VUD5%3DWq7PYrXXLtz3kdexTYw%40mail.gmail.com.

--000000000000d2b20e05d2c20f6c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><br></div><div dir=3D"ltr" class=3D=
"gmail_signature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div =
style=3D"color:rgb(34,34,34)"><div>Hi,</div><div><br></div><div>We wish to =
place a new Order against our 2022 order forecast.</div><div><br></div><div=
>Can you have someone in sales contact me On My Personal Email Directly On<=
/div><div><br></div><div>E-mail:=C2=A0<a href=3D"mailto:massimiliano.brevin=
i@glovaopp.com" style=3D"color:rgb(17,85,204)" target=3D"_blank">massimilia=
no.brevini@glovaopp.com</a></div><div><br></div><div>We await your soonest =
reply to send order.</div><div><br></div><div>Kind regards<br></div><div><b=
r></div><div><div>Massimiliano Brevini=C2=A0</div><div>Global SC &amp; Proc=
urement</div><div>692 566 120=C2=A0</div><div>Barcelona, Spain</div></div><=
/div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACtWDT-6tqUiXHC-bpqYRuwDN-VUD5%3DWq7PYrXXLtz3kdexTYw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CACtWDT-6tqUiXHC-bpqYRuwDN-VUD5%3DWq7PYrXXLtz3kde=
xTYw%40mail.gmail.com</a>.<br />

--000000000000d2b20e05d2c20f6c--
