Return-Path: <kasan-dev+bncBDM7RQV2QAERBA7XUKJAMGQEQHZ5B6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A8C74F065D
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Apr 2022 23:09:24 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id k16-20020a7bc310000000b0038e6cf00439sf507087wmj.0
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Apr 2022 14:09:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648933764; cv=pass;
        d=google.com; s=arc-20160816;
        b=flg50Fri4Ae75Zy5Bcwyq6GZFxDeoBSlW5/8L6lgrDJ7yA7GRrAcU4bU4kQjMpMIBB
         W3WeeeQGP1Y+l++vbvmIVhEdlQtxHay9RNS7j64YSTxW1qRL4idCt9/2q7a4H92K+ZFx
         mAVQ6WOpr0TQW7dPdk8GCXWGOa0hE2lm6tRmy7xF0zkx2K0/IB4fsTyJ5BW1fR92X9vV
         TAfFTXjdoDPCW9CNw3GqYTcIaE8f6hTX3eQEPYO1zlgqyrw71u3g0cbN9+BBYUqfbD70
         tUCB9YvILgQ4cesID07EjFVFPpk5I7QkMgUkN/feM3ZAFeHXFPCFPbw5UZY5pccstN+L
         vV9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=rWShNVq+VnrM1M1ytbVDUJ+T6a+/9uDHwg54ML+oauU=;
        b=Y6RuPSD+fMQYT1PEfoKBPK9Jrh1PypGskD0u69FGe4oqKVSxphy5vu7xK6CKv5wPKP
         C+SROibvPW4GhPd+0fiVonInOyJcdJVu13yis6M4iKS7nFXcmd1Tszsn6ACNaOJBJZMb
         newX76Z9SaH3UX2yreX5ejHGcc58mkulzpfokAiBvddDwv8nagRlDcj42fbAybCOZVIG
         kKT48IwCBoqcRtWbnEmpcuSmH38mjjDax6qvcHCL8tujhL3n670eVBpT3vVP15iUegg6
         G8Cx2Pl/XDXtvJmeuASXgnomwOYbC5OxZLmXD2sem7pQifNsoEfWor6f5UKBu2ixGBzn
         n3lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=j+cRxCJo;
       spf=pass (google.com: domain of papouti1994@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=papouti1994@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rWShNVq+VnrM1M1ytbVDUJ+T6a+/9uDHwg54ML+oauU=;
        b=KJj6uAU+1uPMb1InzgnsWjMLFu6FE7sIQaY7xMBaNUfcCYCO58xk9LVlqICL1ZZude
         PN7stZ3dnGEvBzR0x/hYuYdnIssZnS+E/L8TK657qmHlOFUx0HfeES296U+GqpQSu7xC
         RIWhRrNHbJ471tTLeEnu5tTetUQcWUHprt5wl9WSvydNOJvtEyu4JYcLkkl5AlLFc7hC
         vFa3HVomW02XAwLcMia3xzCQiucDbbWWy0bLc5pfNdgprcQO1FfNquUbnbA35VLXe3tq
         rBKDYCXlTI3V9qU0j6un27Bjnuj6K3SnPo/dKrpA9OtyKIkDhQIuxmAN8ZK0Ni6xhCoy
         TPLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rWShNVq+VnrM1M1ytbVDUJ+T6a+/9uDHwg54ML+oauU=;
        b=NrUnrdzaDrHgzlV1jV1jekP11BKtE8Q16zeQn5YuUCScgLIzx8Ci4qnLOctNH3nkuT
         yibNWM5KN6+sUU2MWjSm0Bbc7rcCZx1dWWXOUr5YFAr6mRpdKhbnDdmiDkfgNX+Xmu3s
         StVhwkSfk2x7kIGjkOMVe5TK0z96trmYInMLkkI0UYSvM6SmYKwnjqrJB3BXRZ4VzZsm
         ln0XhY7DBmaKjQ7l4jfUkZCJCoNELRPsn9EwG/C7Gae8pdlCG47FAPszhubgkEZuzs8T
         MLCP2KGrg1XuHcOceuzMymdhCvfmX8wAiYC/mlCqTBd6vzNdId0F4misjQBjrrfqdvXG
         xTzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rWShNVq+VnrM1M1ytbVDUJ+T6a+/9uDHwg54ML+oauU=;
        b=yDbfWssF89Y+vpezoPk9nUY5eiWJjWDEaFpcTBMlw4psLTfztXpQukbzj6yZTl4HWS
         n9nUMK898b5w8yZOqjpbwkfsVpF6G8eTsmdVE3IDQ9lLTGJfGyE4UzFO6GBIZfd1U3wp
         fyHUb0QeBZNjWUUHvA1aSO4VsmdYXmRNlvcSy/XS52rWymqfE89M0jLkNwG7FKqFCTrQ
         n4BG56TX7+0er75DTJ8kVAg5+Ju/Nugcc/ggVEvhtmaKRb3vQTLZ2XNuJhCaovKuliEQ
         4/DOROb+3Cpd1Ba7T9H8xE2x0NcDSOoHa8UaOmmHea8Fs3LQYiOQ12bLzOEP2mqVXsgW
         cmBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ltg+vY3ydbeTcyRX9dAugNSgyZUBoaFKlgUwSOSJdk0z2ggev
	vtoydlWlfYKSgNMkrgGFArg=
X-Google-Smtp-Source: ABdhPJxKp6fQT47vSEiTdE9MGk6UzwCij8twb9NxNZcCPbiJ4af0CmW7VZu2jXnbomjCb1LVDMUAdQ==
X-Received: by 2002:a5d:4b4a:0:b0:206:bcc:83e3 with SMTP id w10-20020a5d4b4a000000b002060bcc83e3mr1271962wrs.350.1648933763949;
        Sat, 02 Apr 2022 14:09:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f98d:0:b0:206:40a:a792 with SMTP id f13-20020adff98d000000b00206040aa792ls76340wrr.2.gmail;
 Sat, 02 Apr 2022 14:09:22 -0700 (PDT)
X-Received: by 2002:a5d:558f:0:b0:206:c79:8d46 with SMTP id i15-20020a5d558f000000b002060c798d46mr899178wrv.628.1648933762871;
        Sat, 02 Apr 2022 14:09:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648933762; cv=none;
        d=google.com; s=arc-20160816;
        b=h+vSjQzCneCT0Z0iMvgQcC3aypyX9DYG3QNBo5N7bcBe/QG8l9xyZaRKyTi0hcDZU6
         AzBsbRK7KqIfPyi9KKX5YMueDptd8iKABQ5mH+8G812clCWH+YxQo9+juQCDWlPprQSp
         nUDeLX58KOaCSXN/Ezf2DfY2WniaivwUOYWyffv6QuiQFsVkA1fcP6pRczLIfGQnWShM
         Lhpw+8uhOl4i8Ff2pxg7tN6BKHn5Y+MvCyjdEUN8lZnf9fmfu7iFVNlGBYWdtaRfdL19
         IYlMuEy0i9PxcDBB1PhSWJp6mEka0U/e++nL81FiSQzUTOErJQ1cp+pUNnJktNK49d1s
         XtcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=0dtsu9yDNogaysHJNhqrFO09dVqVpQPPjWp/gjvZ4e4=;
        b=J0DaHco0Xm1qPTjcKDYeeQe0kxvdOCJ47WbqwJYpfqpeFhatKbCtzA2/6OBiZTb8Ro
         c0QojvV8GUWNchnnvfVHn6R771NUi5QzQBTFwvl61SwWkAg7PTOGijun4JB/bnH3whQU
         6ABU4C8QYftf7eyPg5SVdUulUgarUd/lc9mACKoV1yYm3KBRWaaqmVlliRHZh/o3voNk
         MqfxIMHRtUjWywVaDzQHtsDHjy8MNVAelENrWLGaOKU1iICDCAb0FVFqrALS/Zeg3zh8
         IzQTNbN01k/TG1F4qKl0pf0Oyzl0WCIxAFRqMhcEMG88FybAUHh2ffsGu94T9hA7efyL
         AEkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=j+cRxCJo;
       spf=pass (google.com: domain of papouti1994@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=papouti1994@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id a13-20020a056000188d00b001f1f8f0f76csi206322wri.3.2022.04.02.14.09.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Apr 2022 14:09:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of papouti1994@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id bn33so8246136ljb.6
        for <kasan-dev@googlegroups.com>; Sat, 02 Apr 2022 14:09:22 -0700 (PDT)
X-Received: by 2002:a2e:84ce:0:b0:24b:23e:9928 with SMTP id
 q14-20020a2e84ce000000b0024b023e9928mr5840996ljh.475.1648933762352; Sat, 02
 Apr 2022 14:09:22 -0700 (PDT)
MIME-Version: 1.0
From: Sarah Riterhouse <sarahriterhouse89@gmail.com>
Date: Sat, 2 Apr 2022 21:09:07 +0000
Message-ID: <CA+BT2oX-4gnWW77uKe3Le1aV6D-1T0RDTBujxnHxd0U_EQvEgg@mail.gmail.com>
Subject: HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000029ca4105dbb24f32"
X-Original-Sender: sarahriterhouse89@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=j+cRxCJo;       spf=pass
 (google.com: domain of papouti1994@gmail.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=papouti1994@gmail.com;       dmarc=pass
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

--00000000000029ca4105dbb24f32
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

--=20
=E6=82=A8=E5=A5=BD=EF=BC=8C=E8=AF=B7=E7=A1=AE=E8=AE=A4=E6=AD=A4=E9=82=AE=E4=
=BB=B6=E6=98=AF=E5=90=A6=E5=A4=84=E4=BA=8E=E6=B4=BB=E5=8A=A8=E7=8A=B6=E6=80=
=81=E3=80=82

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BBT2oX-4gnWW77uKe3Le1aV6D-1T0RDTBujxnHxd0U_EQvEgg%40mail.gmai=
l.com.

--00000000000029ca4105dbb24f32
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><br>-- <br><div dir=3D"ltr" class=3D"gma=
il_signature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr">=E6=82=A8=
=E5=A5=BD=EF=BC=8C=E8=AF=B7=E7=A1=AE=E8=AE=A4=E6=AD=A4=E9=82=AE=E4=BB=B6=E6=
=98=AF=E5=90=A6=E5=A4=84=E4=BA=8E=E6=B4=BB=E5=8A=A8=E7=8A=B6=E6=80=81=E3=80=
=82<br></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BBT2oX-4gnWW77uKe3Le1aV6D-1T0RDTBujxnHxd0U_EQvEgg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BBT2oX-4gnWW77uKe3Le1aV6D-1T0RDTBujxnHxd0U_EQ=
vEgg%40mail.gmail.com</a>.<br />

--00000000000029ca4105dbb24f32--
