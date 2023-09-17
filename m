Return-Path: <kasan-dev+bncBDWP3YH254GRBI5DTGUAMGQEYCNL55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id AB6267A338B
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Sep 2023 03:08:52 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-655c0260ed2sf42314486d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 18:08:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694912931; cv=pass;
        d=google.com; s=arc-20160816;
        b=AN1tkS218FlMrt0GBt9bJT1IedgL4JoZIdC+yOgKVaDe87j/FcMqemle0sHpH+fzfd
         C0P+Gp4fu5vDMrHLwXF7SUiRSuuhCiPR2/1GPoCTw++e/P2TPfgv3119xk5krcB4FLxN
         wWTO5D/6p/rnQkZTqm6q9VcGQ4Zle5gO9idjQeu/EmsimFxSOVEzjZ3tRKrJJ3JasrZn
         KZ8Q4J7WN3NenEYKgJlp4wZc67tNjtEeLD7giobK/BsfpTh2qjYDl3eTklfGl6I2b9tb
         8rrIPhT5naSSXvhHDAyTCMFHAd0/5jEGg12W5yQBkl6OfGIZSRCkniDinKL4PJyvhdgc
         f/CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=9WSf6d4Bc6SkfqlbyTM6JdDVrWuBLOdsPuTHtqZf3zw=;
        fh=Pr2plYkJn0ovdHybgHvE53243CPsqSX0NRPDPDnAMwQ=;
        b=rmn1MJyvIEsg4Tk3AGb4yo6utS9QLXscW+qBKDi1hn75bsb16d25u8ZJby3GPXVFk5
         XsXMiVfc5Il2VTnCM1N1IIPxwcIhVhKjCHb1OGzSCG3ftWTyg22/+w9Kn/6sGu0ljsQQ
         hQRZIY46CDNBQFR3uSBQQ99+uMDWB6y+YLBUipcDhRT1DfzTqgI2vdYCyp8+NQ/J5dl/
         L0code2LQQE5hPzNj10XtN9ClX0a515EiUtEyByHXxmXN4eYNOHldR2tOxJ7taVTjFgO
         +waExj5TmJ5rcN4feWaPMnGLxEoqjqkXfh+oXheUqurGf6FeOrzx8+hl/vfS0dDQQ7s8
         RTIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hSm9W7TC;
       spf=pass (google.com: domain of gragvictor@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=gragvictor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694912931; x=1695517731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9WSf6d4Bc6SkfqlbyTM6JdDVrWuBLOdsPuTHtqZf3zw=;
        b=ZPjHnoBKWHCBZW2uuxpu2b1hetdeEpWtr+E2ICe210L6F1+Wf6oyrt5d1GszxmptcG
         7IBrYbSVd1kAVhYd65iVNlB8qJFft/z1TMr+VrxA3T1Gn4cTHcs6hWaCI7KfexVs8MWT
         FhZi6oKQBEF2k6b5dvbKM+PKCY0E+Ak68DlZx+r68Qn6ZWN+PUqY8pZLxnO7s9MumiTo
         x1dGmpGWnfqBp6HD6UuAGziMFSdTkBohrzRKfapSi0ikj7CD+K6j3cPy7YQBLUdHf+ZJ
         9sJvK9WyHELjVGIL9JT368tlvkCuGbwA0fOubXC3Pc/ghLv+BHGGSjqAjkX0R1aL+5Xn
         l1MQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694912931; x=1695517731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9WSf6d4Bc6SkfqlbyTM6JdDVrWuBLOdsPuTHtqZf3zw=;
        b=ljXwHuQadHDHQ7mS1nl+UQDlWCnn6a7D1L/YrfAYZR4H1YwZIwKB61WRy4IHSXwTUl
         yvp+ebCUPrdRSw/QTXRltEdMhAsuKwKWYHsADSSOgy6rCdunL6VRewVjx9PUwwuOqkUj
         q92dFnw5OhA9FQyX826Z3jj6l6ZU57MaXZd10IJMCQnqVoGF5178SoeUwuS1V2CFmbmQ
         LRUnkHd5/VnZFLT4EPJzTtIcjO1xc1ntgK8OLD8IpUts7+/OXudYJvNtIgu7R79WEMtr
         fsdZ/3R/IylyHYodf1LdYezO3QDPmmQapXfy6a//FNwRd7jWjSFgmRt4sPxVBiv5NpQd
         lG4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694912931; x=1695517731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9WSf6d4Bc6SkfqlbyTM6JdDVrWuBLOdsPuTHtqZf3zw=;
        b=GL4BnVtzUslwwS7cFssKY85niKs87EBSsNT0cv8Se/zpMfozVDkpNYJybzDFHYy8En
         GZcH9EqrNu97+zqcwDqM1yILrL/kq1SOBvS3qlE6C7rWNhPuNv8hcTwvrp/t4nmbqOXc
         aGhDi6UMqaCF+ePHpIhv1UrSpR5Yh9b27EiubRrmvqv2EY6GsP5wvFWUSRnNx256p/R6
         Ol7QJ6GJN7E7hdGquHL9PQaxnYV9xUwsX3jHceZvAmk4j7bn2pVbGPDR0fdZo0Ubef/Z
         OgWvYJBfxFUbjT19yM22gQJO4iTrJz3C0O0SD7W8Nj50FR4eo78O1XyMeNneodHfum9R
         UwUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxiPgGkwzKF42vQcJeG+njgxWfFDjdj7dW9dqcQIA/04YqIoZr4
	2O2J40Z6SUhSyuly1Rh+Vt0=
X-Google-Smtp-Source: AGHT+IGbzVteSTPL5R8MDjo2lGfICn1ryIiSsPnRRsAZf261owKgYCT9GrbHnBTcsRIkvM4YwZmgiw==
X-Received: by 2002:a0c:cdc2:0:b0:64c:8b79:5b24 with SMTP id a2-20020a0ccdc2000000b0064c8b795b24mr5426403qvn.35.1694912931456;
        Sat, 16 Sep 2023 18:08:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b54a:0:b0:649:bc7:cfe4 with SMTP id w10-20020a0cb54a000000b006490bc7cfe4ls1667320qvd.0.-pod-prod-04-us;
 Sat, 16 Sep 2023 18:08:50 -0700 (PDT)
X-Received: by 2002:a67:f983:0:b0:451:60:2022 with SMTP id b3-20020a67f983000000b0045100602022mr4826747vsq.28.1694912930571;
        Sat, 16 Sep 2023 18:08:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694912930; cv=none;
        d=google.com; s=arc-20160816;
        b=J1XIEIRg4Rt3kDIwK/FATag85tAoW76lIY70AACJgTfAm0F9YcX5UJlj44URZeljfC
         URjlMVNl6DyUnvzbmG+n2mOFCl5xJT2M6X7JtP0yCeolsQRc3bcgNzyckntwbCTDcqsH
         p1orUOlrrYWB+Pu6S3xazAhfdL3//W7LqmlEDOpIX5TR3U9sSiBz6Oes283mt69HUfr5
         Rg2KZBobnkWkdTG+jhAaeTC7ZhEuMEsA50jnB7TWtIWyXhpwCe7/1kSCY2ykg/oOby1g
         0heXHMFKVrH5GWv3KYJ2boIFwiXYi/CSYfwKXyfnXfV+pmLaSQltcOFHTQhr0trLtosY
         ObNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=gO+xJM0hGY8qkl5Hr88JSY4Xsf2Yc/aNtnUmbV3ekgI=;
        fh=Pr2plYkJn0ovdHybgHvE53243CPsqSX0NRPDPDnAMwQ=;
        b=cHkZPhbPaGk3zRc0Dg2PI4BEk//ocKiEWUdP8uhZDMbvs/s5q69dsOqEAmfWolgdoQ
         O4fNLik3PNERcH6CXn6kwJeBayHMcLtGCq3adS/DugmueoR33RY80UhGe/jQXT5YpSft
         P0gBwPT+yznbIckZjagLGYTUkw/iUYLMxjzZPRed2ouH5ae2I7V7D2TpHL4Mx2zfebhj
         IwMUKmXD3Ei1dz7Uhy3QM9gorXt08LJ7fQR2Cav2OKih12bVk32pNSMRoxGAJS2dAzCW
         4suFBgRiziOdvKV6NClAqwAbr+qoLJsHCFtI2w4INIcbJYh+RckklqQ3fWoQD/19LzT6
         DuCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hSm9W7TC;
       spf=pass (google.com: domain of gragvictor@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=gragvictor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc30.google.com (mail-oo1-xc30.google.com. [2607:f8b0:4864:20::c30])
        by gmr-mx.google.com with ESMTPS id 139-20020a1f1791000000b0048d29aa0861si1578692vkx.1.2023.09.16.18.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Sep 2023 18:08:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of gragvictor@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) client-ip=2607:f8b0:4864:20::c30;
Received: by mail-oo1-xc30.google.com with SMTP id 006d021491bc7-570e005c480so1951046eaf.0
        for <kasan-dev@googlegroups.com>; Sat, 16 Sep 2023 18:08:50 -0700 (PDT)
X-Received: by 2002:a4a:dfc8:0:b0:573:3c39:2bd9 with SMTP id
 p8-20020a4adfc8000000b005733c392bd9mr6094820ood.6.1694912929552; Sat, 16 Sep
 2023 18:08:49 -0700 (PDT)
MIME-Version: 1.0
From: "MRS. MARIA  EDSON" <edsonmaria1981@gmail.com>
Date: Sat, 16 Sep 2023 13:08:31 -1200
Message-ID: <CAOtFXXj3v9B2RscxkAMSJ=S7Y74v+0JowHCv2FdFv0aYYa2HSA@mail.gmail.com>
Subject: Hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001761ce060583ab12"
X-Original-Sender: edsonmaria1981@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hSm9W7TC;       spf=pass
 (google.com: domain of gragvictor@gmail.com designates 2607:f8b0:4864:20::c30
 as permitted sender) smtp.mailfrom=gragvictor@gmail.com;       dmarc=pass
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

--0000000000001761ce060583ab12
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOtFXXj3v9B2RscxkAMSJ%3DS7Y74v%2B0JowHCv2FdFv0aYYa2HSA%40mail.gmail.com.

--0000000000001761ce060583ab12
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
om/d/msgid/kasan-dev/CAOtFXXj3v9B2RscxkAMSJ%3DS7Y74v%2B0JowHCv2FdFv0aYYa2HS=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAOtFXXj3v9B2RscxkAMSJ%3DS7Y74v%2B0JowHCv2FdFv0=
aYYa2HSA%40mail.gmail.com</a>.<br />

--0000000000001761ce060583ab12--
