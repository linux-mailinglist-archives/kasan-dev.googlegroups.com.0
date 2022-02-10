Return-Path: <kasan-dev+bncBDMZPPHJX4HBBK5DSWIAMGQEPW4NTPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 003D04B14AB
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Feb 2022 18:55:55 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id 13-20020a170906328d00b006982d0888a4sf3066583ejw.9
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Feb 2022 09:55:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644515755; cv=pass;
        d=google.com; s=arc-20160816;
        b=dYn9f3svNGVf1Dod88uKeUwC7N2mPBlK8OkjVNZEK17ZmZ9quC3aDG/HYeLMIG0qCm
         M44JQdr1hVgQRpcWYrx8MIXK4B+0nUQYsSR3EAUdZ1XEhAGezY1FGbV6itM79kDoN1nQ
         J2yzB8J9YwStb2knSxyumYyV+d5q7Gq8d3v2fsdwCGM3ItF4G9m4uQ/hdDbM3YyPMFes
         8lNkoY9nevbnRnJCLV/pcBPnFp526Mw9L3o/q4lcyspJnyV40QAkF0zwU2+XElDAZsos
         lZbPSSNgMuy+yUpv0h/OvxvL/DePA7xXyXskZPmOYFAO9jkiVJdOfJbhOCjoVBZ0K8h+
         CveQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Q5vdZmZ4SLMfBPD8HJfZOZ8mojjLMgb3UtJ7iZl8Wpo=;
        b=AnD329YLs1YjAvByXh/4Zi5LkQiPO946jqVib/PLGuTtRiPilo6c9Sz0EoJbNtHYNE
         gxxNd7h0tB5y5GPTmfnMZ9E9N7bw9f4tB2THAkRsvNP+ChafB/BeEM9XI9MMx9WLJK5M
         i+PpDw+2boH1N7ZFTvZQdQ4kvu/nZDm7+oqqQH5l7cZktFdHH56myEzm651WOKGHUeEd
         o2IgxfdCTz0jboV3y7Rk0qrkIZ5JmWv6+EVMyADcx+msY222nDJrlOE4iLSmii4i0P2H
         eS0e5tsnMfE/JrOzb61b79ug8Sm6GGCCnNzT7Rw/lbLXJGCZXfCdsxG+tbLnvKHsvRqu
         jJIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jW9tt+6e;
       spf=pass (google.com: domain of timothymack332@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=timothymack332@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q5vdZmZ4SLMfBPD8HJfZOZ8mojjLMgb3UtJ7iZl8Wpo=;
        b=sGsNxJddFM1hVuvXEFb30KyJ+pG+d2HURqrWTTbsYusCDthFRowcX9pcuFg0e46qDe
         oDdPJWFh2M+iTQw2nVzLIG4rVk3PgKYJs2wfRfsfTXtSo7UM4gRaPgtsQb0GTgFbUZE0
         /Tj6X0UFkSKq96Lr9mJtTjiUXUWgoZ0xLFMxSAYCDbWWwTV4H/o6DwmiEgGF/lRXXxV1
         uh+6zP4fb3tGrlqoF3qdK31BTS2Tc9GXqIU6tyYlUOjt/Q6onGi9PcRcBPcetybXCLwq
         8AQWl8aVfQ7qGZ51ZEqcVXzM0ar0mtxwNIFvzIxEu0em3b3wo4owhUywtLqlVox6qiJu
         UZxw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q5vdZmZ4SLMfBPD8HJfZOZ8mojjLMgb3UtJ7iZl8Wpo=;
        b=oawzUGafz8cF1d/B30O7/obD9omh6Jvp9FKa/58EtP4NUetSih1OQyzGfNH9OvgaHV
         c4VbpFMOYS5hoVbwI0DZqjLSPju95BA5zRhtXrRKwvCUiBzOBO8X6A0mz2DAJJhscKMT
         Or3/h7ETMcKv+sbHkO5fco+xzZG4t09MIaTPi/XKH+ewMhbiFTzlPinxP3rasoOwqA12
         /C/YiV/HioYSh8mFmKyJjcXZcF8a+qBmT++Ul9Fis9fhdahi65zEZd1K5qFJ4eKR94Zp
         tjfSooMXIp0KM4kcbvmvZyNRxn1+/IKMFM2T93pqbYCttKukjWy21rP3o4G/G7zRY0Yn
         SmmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q5vdZmZ4SLMfBPD8HJfZOZ8mojjLMgb3UtJ7iZl8Wpo=;
        b=488wX046lsGuCdJUkI7UP7jjVZcbcNlG3xRYuXcZcaAuMeFvk/PI2ExqDgZw1HtX6O
         bP7JjKWwwws9ON0BI5aSRe6ngkGJptYYaag4Qa0GbF6CZihNuyx6sLRVX+w2ENOcOniG
         OAKLN5jQqiNR+u+A0dhaxkAGnl0QA8GyfnVB1OQcXgtckfr60ArqPSUQSz6aZCh2O7s1
         /ZqJvlrSJ19wLq5pPXccqIZRi2f+bF43KtrcndWNhQsMSimCOgzA4He9LUdlwWkf+nqu
         mudLDuhVy29X6mDfzRrrRF/0O07yWSxU7xSzEyPBPrAopm//aEY2H0rlr/CRmSLNMaQM
         JANA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531q5gU3c3Us9pC39b3vdsCXpVc4yLTR/asMtdVKJ+46JwA49BiL
	e/Y7/GKm7ekNAxQPdRb5R6Q=
X-Google-Smtp-Source: ABdhPJy3C3sp64+v1PyL4k1liKp3ZHp81fCa6xtGD0S22NtUcY1HpHBlMtwY305HwYjkhk04NXHM4A==
X-Received: by 2002:a17:907:a426:: with SMTP id sg38mr7592924ejc.108.1644515755642;
        Thu, 10 Feb 2022 09:55:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5246:: with SMTP id t6ls1455607edd.3.gmail; Thu, 10
 Feb 2022 09:55:54 -0800 (PST)
X-Received: by 2002:a50:d70e:: with SMTP id t14mr9676591edi.19.1644515754689;
        Thu, 10 Feb 2022 09:55:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644515754; cv=none;
        d=google.com; s=arc-20160816;
        b=mQsdsu59nnhR4TTmB+Hr2fS8qL5RIPBgh9uy3KfQItabIKeG0nfuhe/zgqEHR5dC1h
         mLWXUueUE1b0fMSPH6M2N88r3/bRBReni7mTliyiqZ3AECFfnIr0Uok1aLzOMZfB8Mhl
         K4DKuFw8WQvPtJ5ydQX5/wEPaws5ETNRyRN+g8ngZyQMYaXK2w2BsOgWlxdO1YzefDfB
         3Ye4VkXdnHjwZVLm31RRaRumIhBHSS4CERNyymZBN3hhXZKB9RXlpxB40ZxyAxXI/EJQ
         voqdNzEUogam/b9KxqummwnuMw+mqrAPuadneYzHVA42Ew5eo+BKj0mrRtOWKjLfoEjN
         22Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=qKjNpoh1DG7dpSG7QxsZzMQm795umqJUMUqKJW//aCo=;
        b=l8ZRbDgUeM2mp5AdTemBwV3ehpFh5P1lwJR+F2Uil2r+nz9XjKONDQK+1ba50lND81
         HLYgW52/ZW8h1WtygcNl2t7agK9CFFqMF/KcVk2kJUm4TSqt5ObK5kk+uPEyaKXOsq8u
         g1j1glLanWrc//YGfLqXs4IqID8o/qtz/uWCS17sbkA8DR5kLK9s1gd2DxrVE1af9IdR
         nhSqGjG+kmbW1IdK3sr8DLQ2Qrj7gGGb/LrJ1JQdIcTd4t21hVd1uz5fPacAd3Ugm19N
         ciDePWTwvPolRbw1wv/5IUPhno3qjGesi37gfGnZMAZBE/PAw+h8K2Au+TIizLr/QOAl
         25ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jW9tt+6e;
       spf=pass (google.com: domain of timothymack332@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=timothymack332@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id s26si484663edr.0.2022.02.10.09.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Feb 2022 09:55:54 -0800 (PST)
Received-SPF: pass (google.com: domain of timothymack332@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id i14so10924994wrc.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Feb 2022 09:55:54 -0800 (PST)
X-Received: by 2002:adf:ee46:: with SMTP id w6mr7137561wro.451.1644515754223;
 Thu, 10 Feb 2022 09:55:54 -0800 (PST)
MIME-Version: 1.0
From: Nathan Caleb <nathancalebnathan@gmail.com>
Date: Thu, 10 Feb 2022 05:55:37 -1200
Message-ID: <CAMuE1iFPywt9nNVmxnKCLTPmC+=qyhJAC7WxpQ2vbX2qZLkPoQ@mail.gmail.com>
Subject: From Karen Smith Trust
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000005baf7005d7ada93f"
X-Original-Sender: nathancalebnathan@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jW9tt+6e;       spf=pass
 (google.com: domain of timothymack332@gmail.com designates
 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=timothymack332@gmail.com;
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

--0000000000005baf7005d7ada93f
Content-Type: text/plain; charset="UTF-8"

I wrote a previous message which was not answered, hope all is well with
you?

Sincerely yours
Nathan Caleb
For Karen Smith Trust

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuE1iFPywt9nNVmxnKCLTPmC%2B%3DqyhJAC7WxpQ2vbX2qZLkPoQ%40mail.gmail.com.

--0000000000005baf7005d7ada93f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">I wrote a previous message which was not answered, hope al=
l is well with you?<br><br>Sincerely yours<br>Nathan Caleb<br>For Karen Smi=
th Trust<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAMuE1iFPywt9nNVmxnKCLTPmC%2B%3DqyhJAC7WxpQ2vbX2qZLkPo=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAMuE1iFPywt9nNVmxnKCLTPmC%2B%3DqyhJAC7WxpQ2vbX=
2qZLkPoQ%40mail.gmail.com</a>.<br />

--0000000000005baf7005d7ada93f--
