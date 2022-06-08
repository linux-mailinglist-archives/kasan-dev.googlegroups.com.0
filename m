Return-Path: <kasan-dev+bncBD53JQNMZICBBUXCQKKQMGQEGKUCWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9BD543277
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jun 2022 16:25:24 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id 128-20020a621786000000b0051b8426c375sf10956116pfx.15
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jun 2022 07:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654698323; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGOs2bCERTHofltKGts1aqns/fOZTCN+3FdhUklLBfQ2M6uHD3H4bdYLUPhqmqlGfv
         LNP8xeSsq40KVys3EVNwmm6jnt0g2PQh5HcAMfrRX7xMRMaf9VoF0f701D9Tp2SDawZl
         z2+ecnj7H+71vtEGtH4eN31JCk9IIjn2YBxQuz9QOVHC5q6cLNU+PvWs8/kL4q0aOUcg
         uYuye/qhpehrg+r/DrFeTKfh5kLDDoDG/JYbpmIeibhTjpx7s8lZnMEHGeKJKc7ZZEbD
         dAWUKS6NYS3GsSEWBkoM0zS/IKot0NGlBianMPqR8vonlpIh1LcU5E7feXSwcYxMSjAY
         qtRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:to:from:reply-to
         :dkim-signature;
        bh=fMgqYSy52Et/f0+ZZeVPhzjh8867LaBgkYZho+y6vJI=;
        b=JEsUnxIaIHWO8wdKKPOYyldVV2VUcOJuRh1m6wQZyfyt+UfzV/mp5qqX/lk9Hn877B
         MJmjgTr/hpP8z190JYIICbbRc9yYOxNUc5d/EbcNW08fsVUX9FPSSxkt8V+Ddk1T9Lnu
         mlqXYwX1q1vzCwbspxy1z+T1RRfoe+gXcXML/u2aUnjc2spIJJ7q9Q26YZaKH3OPBz8k
         ORUcpQS7ysOExRr5+B/MSio7IvSdtI6LjoBMeGsvlTtmsD29r0l4E9tUMG1EuE+pTlNp
         ee939W5W7urPip99ISyvDi0e+3a207g0g/zuqaC0aG/0BttXRRYsFzqNBGZOpeR2j7Gu
         gaVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@officeportal-centers.ga header.s=default header.b=t+lzv7XI;
       spf=pass (google.com: domain of mail-center@officeportal-centers.ga designates 23.254.144.11 as permitted sender) smtp.mailfrom=mail-center@officeportal-centers.ga;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=officeportal-centers.ga
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=reply-to:from:to:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fMgqYSy52Et/f0+ZZeVPhzjh8867LaBgkYZho+y6vJI=;
        b=f3vlYurJRbmQkzKWO7GkCKg7PUIK3Ix5whxCR+pb2XZ2NvythPGrrP7N3xE5iaghld
         TlN7OMtG4C83fWFcmlXSjwazH6BgBocA1/2/2JSG1kILlwg2Q/dE9g+7byldKWRtaZYv
         AnVJOnG1E91PLCiXjI3kLwVXl8xrN+Jo39kc4h+6PWY6r+7hte8Z0sZK79OD5wdMzx/A
         /Pdc+ODa1z1bo8AZMm7NBRbIoS5GZXMYvLOnDVJmN7ATLCCxWbIRnTNuaLUXFn6B5hYy
         uto3mq4Y+C2mKhFQeZlxy6plkwPRbDIp/zCENL6S7MlQw3gvGCNN0S1j8YZN/MF1/fBo
         3sLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:reply-to:from:to:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fMgqYSy52Et/f0+ZZeVPhzjh8867LaBgkYZho+y6vJI=;
        b=KaHU0nkBJlIqsESYipzeX40Ras2TxKIjzDQ6C4QNxksEwMM1+rFop4SQFyNpebvf1p
         PWxBPRpBi+bxD/6M2wSvMglyXULHFH3aWk21DXlsaSplbSReN1kOmeWVVpFipInrjkQ/
         o4mHdYRmxVWNoeK6rMQV+yoHiBr0DrLAICyXzdyesqZVcXlA89XsU6SjFLIXV1CVIoXF
         2TEO/c13Vvaa32ctxCf+x+kzJBOeHslAkp8SCB1gV3I0SLbPk2ti/0dUBndf1h/pLfGT
         /wALHUKhBP9R94RLOm4t60XerveoIcWPABVcdE3TkVvbYiFbbva5DI8pmZ3h3AowF+YQ
         xCrg==
X-Gm-Message-State: AOAM5328bfChP5P0lC3iTVQtYTnKl0sMFSVE2L1eFY/MkAr8qpWfQNer
	VJOemyciZBjnVjYmzvyLWcA=
X-Google-Smtp-Source: ABdhPJx9Wm9SqkFdXjvbdMnLqQQQ4TTu9LVC0nofJZ92jRTbgKF0LeFmLJQDLDvj5JfQE2sYziHqzA==
X-Received: by 2002:a63:cc53:0:b0:372:7d69:49fb with SMTP id q19-20020a63cc53000000b003727d6949fbmr30365665pgi.21.1654698322882;
        Wed, 08 Jun 2022 07:25:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:cf05:b0:162:1098:f1cb with SMTP id
 i5-20020a170902cf0500b001621098f1cbls11125370plg.11.gmail; Wed, 08 Jun 2022
 07:25:22 -0700 (PDT)
X-Received: by 2002:a17:902:a413:b0:156:15b:524a with SMTP id p19-20020a170902a41300b00156015b524amr34265537plq.106.1654698322127;
        Wed, 08 Jun 2022 07:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654698322; cv=none;
        d=google.com; s=arc-20160816;
        b=y9vTqTVtlpo3kq6oucYdR2PnNhkm1cPjwGW3nPMJjdn7VSgK9/nIaAXrv4ZTxjxdIX
         xNEqkdKyXiQxlNfaDX7jp2NnroRhhsxgnHHEIpLVCwYZXqrZNSpTq5+kac5ATp1w6NQY
         QTw6qadLrGsB12DD0rtYIinVHuAlgK+upD8HoC+2nz65EOODtke6NB5WUf2glIoKOtd+
         R1UcxFIe0aBBudAPq8+/OoT1tJCljEN+5vv6OIPU592E7DiwzG+iIUB6r+8ltFIL5voW
         Lp2o+tnbEU/ebPkMWVpcwSSbNwwapx8gYFg4cjhh3REq93qfbB4jPdrAs3z7EuVQyLd5
         V5+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:reply-to:dkim-signature;
        bh=4E46+1kDettbChBUKSTE9PUh+52RpWYA1/Hgtt41d5c=;
        b=DcHULcQCXX06o3LmU15BL1isJcBHTHKaWtaiPQ3709kdTWmGYiERxtcUcB5mR11qRf
         a6UvOL/yiQtkxrgmf4FdmvvBunWxNTHwG5HjN17ufh0+qVW7v2wpurIPReTIQxy3j4R6
         qoAPr+zGAiHy6PXfgSs+PYfV2is9zRiH5G5TpSy7G1IXtg6JXsXGo3Rry1RWaqM+/9uP
         Fn4dO/M0H0KfyH1mgc/AoeacWCKNMx4PrOljs0ofosqZtmQQ2LEL5MyJqFA5GfXkOH2h
         4OWtZUqvU7r69rrH4yF03V4f2l/D5uxrUKwlN5mNzJ6Kjyk7orhX8gfCkTBKbdLOi2cV
         FTog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@officeportal-centers.ga header.s=default header.b=t+lzv7XI;
       spf=pass (google.com: domain of mail-center@officeportal-centers.ga designates 23.254.144.11 as permitted sender) smtp.mailfrom=mail-center@officeportal-centers.ga;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=officeportal-centers.ga
Received: from mta0.officeportal-centers.ga (mta0.officeportal-centers.ga. [23.254.144.11])
        by gmr-mx.google.com with ESMTPS id o13-20020a170902d4cd00b001640818d121si559685plg.5.2022.06.08.07.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 08 Jun 2022 07:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of mail-center@officeportal-centers.ga designates 23.254.144.11 as permitted sender) client-ip=23.254.144.11;
Reply-To: sherrycrawford@nationalmeritonline.net
From: mail-center via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: kasan-dev
Date: 8 Jun 2022 14:25:21 +0000
Message-ID: <20220608142521.95991FC443DB28A4@officeportal-centers.ga>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mail-center@officeportal-centers.ga
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@officeportal-centers.ga header.s=default header.b=t+lzv7XI;
       spf=pass (google.com: domain of mail-center@officeportal-centers.ga
 designates 23.254.144.11 as permitted sender) smtp.mailfrom=mail-center@officeportal-centers.ga;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=officeportal-centers.ga
X-Original-From: mail-center@officeportal-centers.ga
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

Dear kasan-dev=20
I sent a message to you yesterday and i am yet to get a reply from you. Is =
your email kasan-dev@googlegroups.com still active?

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/20220608142521.95991FC443DB28A4%40officeportal-centers=
.ga?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msg=
id/kasan-dev/20220608142521.95991FC443DB28A4%40officeportal-centers.ga</a>.=
<br />
