Return-Path: <kasan-dev+bncBCI7LDNNRUPBBAMUVXZAKGQENXMKGIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A96161EE6
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2020 03:20:49 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 7sf393709wmf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2020 18:20:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581992449; cv=pass;
        d=google.com; s=arc-20160816;
        b=jJoGGmcok+YRQYOSto+ZxyDL75s60O4r2xF7oaEZ0nIB2oH4QQRR8Za9DjUK/FqxeF
         zlDq6FwCXZQpwxYXTuGaRTKFM5BEVw3ezeLJIWvnbFr9a0OWArjFkgB7yJnJ7yIdo54X
         pgnc8hYpsAMXxMFjLL5nfUJNvfOh5bsN2So3/Wy5EvQKJsSyhKe09z4gfkzsutR1v7qI
         ZJ0XH46HLPEa72kGC2SA/gN8bgRTvXI5jisUDkjZQ+4r6fidCnbrfIedGxQUbG22qQQC
         ZSiiq3W3m/ds81KKJDoZzDQaXH6fZ8dCZHm4SLxST2G9eXPRGfsnvHgo6GzneLPKEIYT
         nwVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=n4PyjtgRZwge3NBEylM/gm7opPP3B+QdQRuBACiltaQ=;
        b=M1Y1MSkUilX/J/9lC9Qe90luTsgwQzrxJvvrlWJX2ta6sP6rYMAYYwCohTdAbD6fV/
         /l5zXfreMU0ZmPrH4FjuDVtFf1mVyk7Q5RDSQgHRiwP+bHLqpz15f4A5QTDuVg7Yksdb
         daYtL4NDftLQ74pUg0E2HbrWRyJkt2AOScVse6bbYRmIOnWKHsX9D8PEBvD52kau/3RW
         82oGyZbGcTvyb1KiMsfkVIvZY17Db1VdGXI4HtUkX74fjdPAj3U180Cf1djgKXzuNFek
         V2gPsftMxri8C7ObaLkLLasa5pLasQuiNs+RhctpOEqHIsec8L2+oPxq2cHEvCZvYyqy
         Fc3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=G76WfcSo;
       spf=pass (google.com: domain of mamys745@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mamys745@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n4PyjtgRZwge3NBEylM/gm7opPP3B+QdQRuBACiltaQ=;
        b=kWDMK9NyakEY8LOW6qTFqVPW1p4A2W9Nvqmdco1g4Pbz9fLXYclnXKQrvxZ/9AuCfZ
         woSjpiLWNRBbcQ8z/HZqZWFr+jSxyhn+7+FjtHS5Rgdc2nzdiXaHexAtfB4m+sVk4NR8
         YbDyqz/9a9E4Oif9fb7f8QIcv9Ai576Zbq3DZokZlHzLaP0nMu++IeDqXrUzYuRCthVi
         xVMYTB3CFRvQ3XWbByV/DeEh9HpmFq2tXJilj1AfL3TYA2mz0OVntLiQHT4C02YZ/uR/
         ZH8bavx876PN6kRhSlE9ACpdlgN5SgNCg0QlLnoknA6dZO7tRly27yyFrlpW2inHE+A8
         sbtA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n4PyjtgRZwge3NBEylM/gm7opPP3B+QdQRuBACiltaQ=;
        b=bxW02bYEUvD/v36CDIRc3bMQQICs0MbYAIyHini5A5EwwEhMwJ+bKAKm+u3d2DGrSt
         2Ftdh+YO8ET5sIISqDf032WA8FsHuERBeKpLsIyDRnN1PU8H4Ss/1A1UIYiD8jpH8+RH
         ER0v0wjn8lXG6zwzyr4cV4sl7bGhW6gOGHbYOaUHcvcotRfB3fwzrtbTT4XEwDN50fFs
         lLLo3UbLI3/8QQH601SsEXOW6wSuyUF1QTXTOj/V7xRs3NA1tT9EfSdRjvRLhRUO3VpN
         PvBOxqqXAx2+N4e6VGv0YkUH8iDQ6jLWICtn3S68qeQTShFe+rfNsEHmyxYLZTwk6IpX
         Uwow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=n4PyjtgRZwge3NBEylM/gm7opPP3B+QdQRuBACiltaQ=;
        b=NHy/HOUFJMYvmAtWMF/qdu28BmkwC4Ev0sDde7wjIc050w/08cD8DRc9ORReSwUJth
         hmKTvj2qrfEX8TyASaQA1VyzT79+eqSwvxD3n1Yg/d0JY2HmUMLyatBiW1ja7i4JpdNB
         9cleT/fxEV1Eji+QugG7gosoN86zW5kYhofVlkoSBL+cDcIhG7pEqdpap2KH5hraF9r4
         7A2OZZ/PZqhFeawOc/fdzEZBsO3O5NGwMOJ+9agtiynBUrjbZ4OL71U5Hk7LpX06v7KF
         klbhLHoau0H+lagx0EqIf6QMj4FYDnTMrWW7v/9v5w5RN8X6lP0Ow9JoGOkbT9b8wMaa
         6LPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnttqrv0UQSbK6ClMEscxPr92gWDAJzYcZd3ruoWTAcqSfhfTj
	wSIJWipXI5vpQiuGsKVJ4FU=
X-Google-Smtp-Source: APXvYqzg75VGTt50uXq+80euk79FHbabfSekuKIqp0OdFhuPylurCjcNGYNtH73F2zid9ovkLubQkQ==
X-Received: by 2002:a05:6000:108b:: with SMTP id y11mr26019932wrw.187.1581992449541;
        Mon, 17 Feb 2020 18:20:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c452:: with SMTP id l18ls786455wmi.1.canary-gmail; Mon,
 17 Feb 2020 18:20:49 -0800 (PST)
X-Received: by 2002:a7b:c19a:: with SMTP id y26mr2244881wmi.152.1581992448680;
        Mon, 17 Feb 2020 18:20:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581992448; cv=none;
        d=google.com; s=arc-20160816;
        b=xeR6fUB9wrkcMtmzUjvheogV6MhaUar0ByVkkvTzya1vce1VyAIsjhkupbd/xZ7omh
         51B31pfZo08YeX0vqcMPazldLfFpZi0OI28xF7AtFG/CsLXTOdm5WN6tPnh+JjfBZyRe
         RfLrFFyQiHN1MfoMUvvv6mohYNwJNpZlQNfcSSpWdmroaVwFapuUIjXO2ewNO3+u7TJs
         ZGcjwhR5h87DWDLFdwAPB5DhiGvqMWlL9c+Lx7wOvgiMAZcdjOC9iGvRlN/+5FAV9qAC
         nH9wJy6IE3Bc6sW5tHMtnUhKi0HyhzPwBKokqt3zk+PPCJ5zbHNoQHH4/v3Nur1SnPpY
         ICMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=on+xf5431FpdykHeJrjURlAXjPIgWf+Va2djwfIb+L4=;
        b=uNgRl6TQHX1XXm/3Z8fN2+U5KAx4kf2NwzCIORiURZrKEhtID+IPJu0hP4Bk/JQpXa
         waPzuLq4OUWGTjVPET7HZ4SymIV8f7BjSTIeRtGB0YCZh0IzguuUdVLffIK8L+UFwM8W
         zKOmzh3GE7jtH2k2BVi9sgrifbPRMoPGJjrdMJzlTOrGgA0H0KMt3vBUBN+Hld0T6t3L
         4WvjnpAp5Wgli66hHAocvNNKJAyl/9+GXjLf3P7BEbPGxwDrIeYxy3X+jxxerL65+nQ6
         CQ++0c9WnQ9E1jBTAqbkjcM+oFD2OdhdPPzt74RlRmSjIt8HdoIuvm0nc12WAxMegoal
         Ep7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=G76WfcSo;
       spf=pass (google.com: domain of mamys745@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mamys745@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id p23si67486wma.1.2020.02.17.18.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2020 18:20:48 -0800 (PST)
Received-SPF: pass (google.com: domain of mamys745@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id y11so21992208wrt.6
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2020 18:20:48 -0800 (PST)
X-Received: by 2002:a5d:6646:: with SMTP id f6mr27043494wrw.276.1581992448517;
 Mon, 17 Feb 2020 18:20:48 -0800 (PST)
MIME-Version: 1.0
From: Marvella Patrick <marvellapatrick1@gmail.com>
Date: Tue, 18 Feb 2020 03:20:36 +0100
Message-ID: <CALCFPMXtyR1QsT17jMVqS5D4m1673rNvOiXpunxGxdO6bVG_uQ@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000ee71e4059ed05189"
X-Original-Sender: marvellapatrick1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=G76WfcSo;       spf=pass
 (google.com: domain of mamys745@gmail.com designates 2a00:1450:4864:20::444
 as permitted sender) smtp.mailfrom=mamys745@gmail.com;       dmarc=pass
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

--000000000000ee71e4059ed05189
Content-Type: text/plain; charset="UTF-8"

How are you doing today

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCFPMXtyR1QsT17jMVqS5D4m1673rNvOiXpunxGxdO6bVG_uQ%40mail.gmail.com.

--000000000000ee71e4059ed05189
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><span style=3D"=
color:rgb(32,33,36);font-family:Helvetica,sans-serif;font-size:22px;font-st=
yle:normal;font-weight:400;letter-spacing:normal;text-align:start;text-inde=
nt:0px;text-transform:none;white-space:normal;word-spacing:0px;background-c=
olor:rgb(255,255,255);display:inline;float:none">How are you doing today</s=
pan></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CALCFPMXtyR1QsT17jMVqS5D4m1673rNvOiXpunxGxdO6bVG_uQ%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CALCFPMXtyR1QsT17jMVqS5D4m1673rNvOiXpunxGxdO6bVG_uQ=
%40mail.gmail.com</a>.<br />

--000000000000ee71e4059ed05189--
