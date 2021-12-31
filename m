Return-Path: <kasan-dev+bncBCKIFMXYYYOBBFHTXSHAMGQERICQ4SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F133482546
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Dec 2021 18:10:46 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id kd7-20020a056214400700b0041195fd2977sf18624342qvb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Dec 2021 09:10:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640970645; cv=pass;
        d=google.com; s=arc-20160816;
        b=EAx0tLl/I4FVn5ASyO0TfseMhOyzEVM1Z2AnS04Q3NCogGg4wuJY+48Ic/6Rjd3SPb
         +/LAhuTc/tXaixIKtz6ow7Lz0PQwc4COHtVRSD8Xz7p+Q5WY8Gfo1mXMZNMVLv0AIun3
         8TgUhhhlkappf6aUeYLMsGyBr8tA6C281sZU5lJVULBeeL0THWZtLx7yVVXu6aQ+6ibZ
         gAFE6QmufVbXGfIyQ254+i/hYlude0ugEysHGgre2CRy6M5FIr0s12ccTEeAk/hP+51E
         p1cBgBHTk6pvh90ToJGgM87O7d3JVzfvijhinKlEJjSVWTLxFhySxxgOXca0JEZ63JN9
         q/tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=J7lM8EYd8GXDCFWZXL4HAZwf0tbtZpUER1MsWkkd8Go=;
        b=fneRAFZ8cCj7DGjhYPrUs8UnouZGgdQuaXm5+7GMbmG0sIuJOaRI5fWEKXfy7GGLeh
         YPqWrocTO+wT0Cl/HhYrhNHheTiYsCMA5eGIi04PZ8g/LNAmBWkiLoFI67GfBZemiPHg
         EGTPjOhpFlt/nHu+kdqVBcNbdnEE3fzcRVh5pDHNNBLOVOFRBtncoMe7Gz3c2TXnmTG3
         P/qyOol3KrTWjjqrADZ9b7/+0eDxW2gl9UUhISgil2mNLkQivKxIhsz6qoHyu5sRJBpO
         tDhy324grZ0xbD/dcSV/Gu3jmLt11R4Ls+v9JNAPBjDS7IIGbtj8Wz/PsT727wgSp8dJ
         pbPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ar3ZZz2f;
       spf=pass (google.com: domain of maguiekonare@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=maguiekonare@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J7lM8EYd8GXDCFWZXL4HAZwf0tbtZpUER1MsWkkd8Go=;
        b=Zpt3mqn+BRbEQB+lJpG/ubYNy5AjbVIWtp400E1NBX0tzW13iksKFsP53XLGR9f7+z
         Uwg4FSXUtRyg/1q78+dKc48TzYiPImoodUmrhZE83rmhg3jqnwMNifzsQNYJYy7Q8/YY
         wBb903WkrgwPtXDkwnh8jPnU94fXhIDerRmo3NrEZLO7v9uGcATdxW+IN7CErK8yz96d
         ZunmH5YIDWXVWn4vhAlfs2/YKoX0HFTsKTbXbEd9EGbP4OOp1hSVbRRdRCWouabg0Y3r
         PWw6fcuxecn4xymH+ONuKhbHmMl4epTNUQFrNvADd3vTwz3JAzC+sUu4OPzUtN5gfxhs
         68uQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J7lM8EYd8GXDCFWZXL4HAZwf0tbtZpUER1MsWkkd8Go=;
        b=hZnLlK2rfkzXDsPCx8x8AjtbCYiLrdBwTm1ciEhfveoTVsGMDDGrx/vq5akLHYewHI
         bHsfyGDEfPt8zUEq94H5eN1KrlcYNEOKKWFUwouVGPYxDjVgW/75AMuTEFyrvpr5BExM
         /kXee/xnN7AXczc0KXyV4JuiBAI3YLta7YIBRl99uRdWAcycR0euEqsD31HK8n4PfOuq
         +eHIToF5bd+FxZRuGx2y/yPqTeBKRrACtL01WW+PbEhaoDwGmOik3h3Au7T80MsD2HjK
         J0RA9QE26L9SwsjsrMCtu/14K/WfZA6DfCeZwy4yicmdn/2YEi5CqVQQ5lV7jb7KooQI
         mGFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J7lM8EYd8GXDCFWZXL4HAZwf0tbtZpUER1MsWkkd8Go=;
        b=wkDlk9dIoncm9DN3X0EWB5llG/qXWZS51V9smD1BpgwnsSAbJSOj98kdGhEwdCIbA3
         b/WXFaC7vCeitxE91Lc8ANPWGQY0bu5L/2k6taZ236+N10Z9OQGgJued1qXwruyPdLAV
         pTNCgBTh8PgPJyQFpgDQA7iowTTer9a7FyM+trIpbU8GDfs1Jnyw+sW1NDkJqb7T6Xkw
         upI2PGLsgbUdJ9OklCUTqC+q6iG+EtynQMtbgBCQdZAaL/ZjhoDsYpo8mk52mnWKhV59
         FFChFdwtHzm9hmvnEt6SwiIHhGvtuFl6FBYAHuP55kcZhg3/xGafcarqnwB8Rj4Zp4ud
         Otyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iCaX3kkOjNrsubRWynQ3BY8oQ8niHJFui+G8EiKRnWhebKMuC
	/dtItIEcyvPGImTm9w1AGx4=
X-Google-Smtp-Source: ABdhPJzciwZMkdjL5y2HNphYp7tacZ0cz6jXc7j0vm5zLvCDRhd9zxpWLo0auUivNY2ILRB1hcuzbQ==
X-Received: by 2002:a05:620a:2414:: with SMTP id d20mr25252955qkn.594.1640970644872;
        Fri, 31 Dec 2021 09:10:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e88:: with SMTP id w8ls14672194qtj.3.gmail; Fri, 31 Dec
 2021 09:10:44 -0800 (PST)
X-Received: by 2002:a05:622a:394:: with SMTP id j20mr31056744qtx.562.1640970644469;
        Fri, 31 Dec 2021 09:10:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640970644; cv=none;
        d=google.com; s=arc-20160816;
        b=ONPVGJUAVxVX+a48uafwqLaHH/0WP3d2qDZm4eiRfESA6uW1UNbdPRhbKAuQ6uF8oJ
         6iEUZT3GKreeWHsPf9RwageQ3T4/NHVl/IXo7zpq7u5/lwfzMLvmO1QOm/WUEq3iypby
         o5av8K82e4pyq0ZCvLkYKalXdfkHrvWqQ5xorrUdaktXROH/1eD9zfEDiAbzZGytumE4
         7gjp9MCQCs2p1NY7gHOS6zKel2b/WxPuKOULGE5JENcmxhuHyXKhz9rcW7ILhF9Fn68O
         YfIDMSnLnp3RiSvyHMSgCRpMg3QYivoPGjonZdVVe76WC3WPlxIZT+FmYBCgAQeh9UaU
         UAwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=HVtOulvHds4i7kMHEoFMPpPgHEN5yvLDOUxM8dzjKVA=;
        b=jE995Dgh8f3152ZRKKcHbCFBiInGOlmUuIJLLQ0wl323OkoI80R4yW3hJ7aR6bNSrH
         ydJZZWZlnmrXwhOFgPxYIZBauSGE3Wyua/k+PyGKhW97ZBZplJHkWkohPVLldqb0kALY
         SHvYKlFKof1tgw969foyLhzujsh4/r3weJCi28UA5OeiVh8QUm+q8XZe1rbTIdf/krya
         EB/LiahIRp9ZSHAuNvZV869MHycf+TGuz7nYju3u16taKloIdGnjBsJqJcImK/ktogx7
         0ZE6g6P0UpPqIGqsy4/+9TYD6w+adjsWSF+++EuGRfbJPSUmtGcqkX6/793v/7HV+KIB
         DPVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ar3ZZz2f;
       spf=pass (google.com: domain of maguiekonare@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=maguiekonare@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id l20si3671759qtk.2.2021.12.31.09.10.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Dec 2021 09:10:44 -0800 (PST)
Received-SPF: pass (google.com: domain of maguiekonare@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id v13so23980265pfi.3
        for <kasan-dev@googlegroups.com>; Fri, 31 Dec 2021 09:10:44 -0800 (PST)
X-Received: by 2002:aa7:8018:0:b0:4bb:361b:b378 with SMTP id
 j24-20020aa78018000000b004bb361bb378mr36395058pfi.79.1640970644145; Fri, 31
 Dec 2021 09:10:44 -0800 (PST)
MIME-Version: 1.0
From: Karen Owen <maguiekonare@gmail.com>
Date: Fri, 31 Dec 2021 17:10:33 +0000
Message-ID: <CAJfB1p2VgoaGkOO2rraXyg3t3oGAigF64SDpUARQAj8VdGOP-g@mail.gmail.com>
Subject: hi
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000054c88705d474401c"
X-Original-Sender: maguiekonare@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ar3ZZz2f;       spf=pass
 (google.com: domain of maguiekonare@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=maguiekonare@gmail.com;       dmarc=pass
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

--00000000000054c88705d474401c
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfB1p2VgoaGkOO2rraXyg3t3oGAigF64SDpUARQAj8VdGOP-g%40mail.gmail.com.

--00000000000054c88705d474401c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJfB1p2VgoaGkOO2rraXyg3t3oGAigF64SDpUARQAj8VdGOP-g%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAJfB1p2VgoaGkOO2rraXyg3t3oGAigF64SDpUARQAj8VdGOP-g=
%40mail.gmail.com</a>.<br />

--00000000000054c88705d474401c--
