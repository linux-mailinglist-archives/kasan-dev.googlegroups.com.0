Return-Path: <kasan-dev+bncBCCYNIMESUCRBNP4Y6KQMGQE7UWOWKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 4996A5538CD
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 19:21:59 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id jg5-20020a17090326c500b0016a020648bcsf7678033plb.19
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 10:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655832118; cv=pass;
        d=google.com; s=arc-20160816;
        b=iI5Zb0d74bOtSZVPdVNTOJmF+U52c8HdsDez8SHnTLaw5oFeKbT02KR21A0kICqBjC
         DmeZKiE3HnZZNS39dmhDlkI+IYH0py2kzWi04K/s6g4BgcDAJYmnHdxf7i2jS4asT0rR
         2DhYo7qf3RFnpdCIzrvr1QevT3pku+nZmHxNyD6XdB8EuviFyKLF6pO173PyiGx+W8X1
         vM6z4Sj/n7ahGtOoRh2fqdDzt2pjeFUkEAoW28XVvB2vp3DBomkxOCwkDb5Oo01BULKv
         xo9fSojwo4hpYU44H0gnquZxe7PVet6mldqCH9CgYHVSoz9uHTrI3sAOuDVD+csStu/1
         Nawg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=mb8NBpngmapUGeVe3cooSUqkvQB4W7obvZWXlLHRJL8=;
        b=pxZTjNz0X7TTmYqm+fkrwrS3noBgiIhfCnzm/nz03BhU3Ye9dsJZ4OUlEOqYd9MHRy
         KXfU023TFqeEtyZTM/7WuIT3HdWBsuUIjqV0x3dwmkLBai7oA+bw2gM3l8PHcaz2ty1x
         2w6qSeL2T6lNpzfXHvBeYn3tO+dHySw0/Ap2fpfdVHhQKFZdJO3GyJP4aGelRuIA7gwC
         +suLZImqDHsu22LVixWRjVYWS8QiC5n149eJ4IKnsx8ElwzQNIucDXoJkDO2JqP7eRwN
         b5+UYgcrRNeORBp5VHajaK4TxoigUt3JeNMWxCVJigq0r+ThwfFetyu6Jpi6uXWMKiKX
         9lIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LQj2936G;
       spf=pass (google.com: domain of maurislare2@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=maurislare2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mb8NBpngmapUGeVe3cooSUqkvQB4W7obvZWXlLHRJL8=;
        b=OL1VkCbdIQ1HBMoZ1PNmDtpD3zoArs0RCIjwSiTE6AzlZM/SRPYGpRTqhq7UlxZRKA
         4lJUlxum7R3Cnayfjs7OUip0jpo4QnoLKqaIlYWCvhu4DLN0VBQCr82sewGXw9M6AVya
         1CT/NkzuMU06bdzjpYQexGaEDiSh7I3I7HtOTq17CAn6KUD1cxvL2ZOUjoRmNJ6Y6oys
         PW7tzl/AiWLJpOuqdiYNsmf8vrK8IO/Gi6S81vnSBTmrHTsXo9naK5J+hvIBRVyVaZea
         PzPhOJuZunvGMxZCjYghLPeqZHTtEP7e7HyKRptgSoRfx+IXLg7B4aGWonGc5ccWG6lO
         3Q+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mb8NBpngmapUGeVe3cooSUqkvQB4W7obvZWXlLHRJL8=;
        b=k8phPyO4kjvjcwJstnPPsbVHWtqRO/mZwQ8DSlDE19nEomcgVJLcAQJENuqIYLHlwh
         NJqnUU+O0z5qMiFnZbltxU/rv8vvYBZObabd/xYX/afK7mfEdTDp5UGHx38Ma6ZtDFs5
         sohUp9M7SvRj1bI7M7FT2D0Midg35Ke0Yw1yQVO/xwNch+ztqJ14jCzwMPSEceML5/KY
         o2ZE3Xbo4siEKdDOmqq+0tK3U3J48fuHCujJtJCRTN06av0ALAGwv1BKjAOle6D4vFMp
         XT2EL/l4M+S2V7iCVPsSYrIO4VWWHWDDkGPrtUFZiF1TZfzIoUp4JJpo5QdW7tlzTbu2
         xJTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mb8NBpngmapUGeVe3cooSUqkvQB4W7obvZWXlLHRJL8=;
        b=YTNz3VZZZiVRdIf6dQoZ/BjPlu6//Tl0dfOL1V0khUeAJJhl3mOskQ1BHvPhJx1oRz
         /TCI32VyVTpRqX72g+SdY5VJ2HYqxqD3qN0l5g3//1cXd5dL1UhCS4+YUd/a7jxQIgCW
         ICbIsT9bEE85ETiX1sCfK2QOlT+9NoenZQuL8sMdt11/NjmlzBOSM9YkZfshaEH4wY95
         qq/wSF+2MZXLJ0AQGrbz1qZZmWlVUEqJGzaPmGdXRgxUf+x0zUNnZoZQTRshBKZqjh2e
         kiO0ygbtKyiaoV7yHum/M9NkUlJWqFwiBTqQ9JR2HwZn0STYbcfFo+V3uAG3OXAPbm0o
         mG9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+2Y1QyQ0RwBFneW/jdNsFUWyCDpOWO+7XY65kBk7GHWHsoURRr
	o+QmT29LY/8R0kG+ddnGm2U=
X-Google-Smtp-Source: AGRyM1s+eSbbgPS3cd+VBKjFjS2+irgNheHzNm5EtTfhSOEfTmH+RGjk8DDp2YDrSnIahNQqDxXRvw==
X-Received: by 2002:a17:903:2345:b0:16a:28ac:1c1b with SMTP id c5-20020a170903234500b0016a28ac1c1bmr10236170plh.106.1655832117632;
        Tue, 21 Jun 2022 10:21:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3ec3:b0:1e8:844a:5f1b with SMTP id
 rm3-20020a17090b3ec300b001e8844a5f1bls9844304pjb.2.canary-gmail; Tue, 21 Jun
 2022 10:21:56 -0700 (PDT)
X-Received: by 2002:a17:902:f602:b0:16a:178a:7b0b with SMTP id n2-20020a170902f60200b0016a178a7b0bmr15645772plg.20.1655832116788;
        Tue, 21 Jun 2022 10:21:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655832116; cv=none;
        d=google.com; s=arc-20160816;
        b=ceGIHtkWvA60q5QB7PsL6BFJlQLlW7suaeXGVbPMXrtnHvgt+//LPx3o9ulizZTh1k
         0AJfjph1JU03rOG0Fx5LcNlvf9aZGWDbA9wYm4A+kovlN3mSt/e27P1JarDZPu0p+x9X
         OD6m5i5jXvIf63gRLanRJz3XNkV0aPoBSSFlKD2LbxKrOkkIH6hWQ1c/4tobjn4dHHlB
         hGLOGwBx+Kv6Z9oBQf4Bc24z8WpHEk68xMCX3kkzpEaiqAC3pZ6jeoCyCYF4Bw9Ur8Qi
         RfE8nnGcscmZn4kBuEpIolxOJ7lyAPWX2OUAhksBIh2cX+YVQajVb8xFbYjzNBVZtXbR
         R/xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=0jfUZDFldpkNtNpLG2k0TUsjCA5dXMxYV2VBaimEzUw=;
        b=KkFfGE31vlcSO41U3FZR/zjLsTBWSp3ZzYwZQBgfu+5J1bByUhP008PTl3qps6eu16
         SDy648M9ONz9QV1ofdmmgAfnL00vr4ys1+uLH9R3qzh1vLTVIXtLG2U7b7KWVBb3p8jM
         zsDGTDUasNVZUl6CSBqlzfQDAXUZ8OVTBUEl/IV7phph3ddInQooAmkLuQUsWiGT7+L2
         H2DaqsXqxCrvi9xAbC3eVO6WlxSmAYIy7Xskq+3YHjsHhHQiZVZ2HJ4ba/nNwlLUsiw8
         1ajYpjXullAtYU5vCtf+BVTepZAlDX2ZCaUEBWU87FlGQmTBUYgFZWPWJydrYgUhjpjT
         izpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LQj2936G;
       spf=pass (google.com: domain of maurislare2@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=maurislare2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id b3-20020a656683000000b0040d1b0de0d1si7705pgw.2.2022.06.21.10.21.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jun 2022 10:21:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of maurislare2@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d5so13101750plo.12
        for <kasan-dev@googlegroups.com>; Tue, 21 Jun 2022 10:21:56 -0700 (PDT)
X-Received: by 2002:a17:90a:b797:b0:1e0:ad13:ef39 with SMTP id
 m23-20020a17090ab79700b001e0ad13ef39mr34204723pjr.8.1655832116484; Tue, 21
 Jun 2022 10:21:56 -0700 (PDT)
MIME-Version: 1.0
From: Sarah Ritterhouse <sarahritterhouse986@gmail.com>
Date: Tue, 21 Jun 2022 17:21:43 +0000
Message-ID: <CAJ1oPZ+V3aOUSoiuzvk454UGn8iBgLQNWmhm36gYTsk4hJJZ8A@mail.gmail.com>
Subject: HIIIIIIIIIIIIIIIIIIIIIIIII
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001c5f2d05e1f87578"
X-Original-Sender: sarahritterhouse986@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=LQj2936G;       spf=pass
 (google.com: domain of maurislare2@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=maurislare2@gmail.com;       dmarc=pass
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

--0000000000001c5f2d05e1f87578
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ciao, per favore confermami se questa mail =C3=A8 attiva.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJ1oPZ%2BV3aOUSoiuzvk454UGn8iBgLQNWmhm36gYTsk4hJJZ8A%40mail.gmai=
l.com.

--0000000000001c5f2d05e1f87578
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr">Ciao, per favor=
e confermami se questa mail =C3=A8 attiva.<br></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJ1oPZ%2BV3aOUSoiuzvk454UGn8iBgLQNWmhm36gYTsk4hJJZ8A%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAJ1oPZ%2BV3aOUSoiuzvk454UGn8iBgLQNWmhm36gYTsk4hJ=
JZ8A%40mail.gmail.com</a>.<br />

--0000000000001c5f2d05e1f87578--
