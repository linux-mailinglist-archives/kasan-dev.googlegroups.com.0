Return-Path: <kasan-dev+bncBDM3P4G7YIARBJ7C6CJQMGQEBIPWPGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ED2A523FC5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 May 2022 23:56:56 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id v13-20020a056512096d00b004487e1503d0sf1313671lft.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 May 2022 14:56:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652306216; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tmf1nPZzYuqgiNqdkohBRWbJoRR5tQhRqT3ofoopRDnsnflesjPAZ9hVHO31MWmwEJ
         InUK3CJrjN7pxfAmMZzJKs7HhvsjZ6phu62jKOHR1T1VmW12lbp3syKaK8QKiu7k5oO2
         5gEtJ/KmqyxExXMzbSMmYtFAzjh5nw6ccWy2h02YTjF8ynlOsn9rP2KvBMKexnh7OdWs
         ywA7MWrxeN0ISZOZHlFGu8glZxVoh2c0lebisp0aIZBSFQSH2UrcnICtnJXeT8cS1jqB
         3VxhrMosHZME0vHGTfODR4Qm3zFswLNtvVx/ygSJ/RJ8sau9qbKnK/L0LgpSJk2lUFgK
         aCEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:reply-to:date
         :mime-version:to:from:sender:dkim-signature:dkim-signature;
        bh=TNxxN4rJr4FilAKx1x+GbmmezivZx6bbNd2q6sIlGAY=;
        b=fnBawGXQ92i7TBc0vu35pAS9Hk/43mpCu+k9lVkJKn1DX3BxCKtNo6aHmhsyY9TKmi
         z1TkbYtHkKJL9V+DJPVbFsq8FRfPkj7EDZd1I/zB+GmUUhyr5eYumDlcX7fw4hgdh+HI
         bdGOnI15W7Kys3H0oW2Kb+ebDk2RUmJDFsIMpDAM7xcdIZvNuC7oCP581Zff2ggTcQqv
         hOlQnpMyMsX1vH1ZHc6b4l66MnfJi9T0DM0dXGr32e4bcv5fbz2UelZzJMakOki7Rr9r
         H3nosrvFZOcdxgEwHx9HVg9c6BiD9B2bwSOSC2Udej8uIBs+Ucn3I7jmlGBbLJfWaH/1
         z+UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=f8W5UgfE;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:mime-version:date:reply-to:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TNxxN4rJr4FilAKx1x+GbmmezivZx6bbNd2q6sIlGAY=;
        b=e84nSgvITRoE+2LN2tqhP0JUim+fYO30bx4u6pZvZg+3vgS5OWBq6rp62fSwQF1WSq
         gD/3i0el4zBt0xfXDMivWeOqliy5qEfUg/VrkWx/QSYPJQvx+XCPbfcQJLXIhaVpLkIG
         ldKn/S1w/ZXIc/7v6339qvLHXAebNqTEthjx8rFjhw9T5FepMKCEq74jDLGHGVWGLJJ+
         0onQO2AwYCThEcA0njzt0Verj6W73U9qXzC6UHBXCVdn07LaBIepU98eS8piEMF7JWaC
         L8OH2+kjdOT9xVPc/qmBdnNLD6+mC8dEhcTLK0rEIsKB2/Nh450MJjv0sQ6g8iUzzzEL
         rZ2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=from:to:mime-version:date:reply-to:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TNxxN4rJr4FilAKx1x+GbmmezivZx6bbNd2q6sIlGAY=;
        b=PIuakXCDvDkZNrs+2TIPQ0mbVaeAw5aLXdYJ7mBBnBcGD54MNeiJqP5AW011BC08HA
         m3bDOTGD8Tte4dKR8QsmYm9jj72ytHUDwBlaq5MFGXBuc14jQCgT8F8+zWt1auOVjfyq
         LKOwJf/0x+gzjhIP3pNtpY9jGJ/ZRMBTs+wOi2TjcduIbG8z6THmQh5fgPct/YncFhdx
         eK8Pc0y+t1akJsES2q5RpEJh9yhI9UOdzlIM2VHWEWACQVY7WFaeM7Mvn4yhDP8X4FqC
         mIW54ONd0D+X2h8Otnz/iLvxD0xkMe8DB1neLu9SOVqElaXJvMScuUvB/3ssHQIaF7G5
         4jFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:mime-version:date:reply-to
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TNxxN4rJr4FilAKx1x+GbmmezivZx6bbNd2q6sIlGAY=;
        b=MGNr+6wCOXdN82RfLdCQuohnGYO68EKPGwTuVyFQweDyLeM/WabNjGu2HZPDKPyy3N
         UDCfKBV8mMFoYkvboKJWWZqecgGzUnasAYdms7wZMcyaObhRHnaDXhSrFuhXa6Y7AqEq
         B96ZtktUx4g2jxytLdJx+KRihnVBpJ/2wOVmTdEyPu/yTEVB+otf+ubJhp92bxJXaAIb
         Y6kWngRDFzHazIJa9m/jFK30FDOHfi10sjm5NmrPXjt6nFWKZq+mpCrWvM4HOUShNLfu
         TYdXZPpB+FbYr2xPlYyaw3AwjNUHHmy+YLAITmthY4sASs+NfRusPpO+9ShHswShd4m1
         3/uQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530urUd5qbYPwz5Fk0JLJivbR1yHTd2wkDGCCP139rNb/3C8Dj3c
	x1XRbKoq0OHLtscdpYRoawc=
X-Google-Smtp-Source: ABdhPJyHY4oRsp3biAtnvYPsEfSQfqu7h3z929A8jltuUqhBQdkbLGwTNyuY25SETrzlxmeb7lmAOA==
X-Received: by 2002:ac2:4e0f:0:b0:473:a375:9d25 with SMTP id e15-20020ac24e0f000000b00473a3759d25mr21671264lfr.104.1652306215515;
        Wed, 11 May 2022 14:56:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls469663lfu.0.gmail; Wed, 11 May 2022
 14:56:54 -0700 (PDT)
X-Received: by 2002:a05:6512:2244:b0:473:aa9d:8ae1 with SMTP id i4-20020a056512224400b00473aa9d8ae1mr21995179lfu.317.1652306214332;
        Wed, 11 May 2022 14:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652306214; cv=none;
        d=google.com; s=arc-20160816;
        b=l5T+Y2gXmxex4+tmkVj+nYW9xerEV+yiz5fzJZlmpXsdGYe4ILo6l48SFcfW7E7AoU
         s+E/DfMeqWwoQ34rSabBeOdZD3hZ/G+ZEAtnQ8cLPXBAQYmeVTj4dwAN+Ows6wF9tnmm
         4ZVMwYrJ5YJQwe95KSAveUTACdgL+z7if6tI3kVQfhFMKu2mObKI3xXIx6ST8HgID/zx
         5PckC5F/bHYkUsTbQ9YHHuV6hxAGtwyWgLLL/CUt3y45NYHhMBz4oPoy9m2lBAhwT18d
         UO6lG0Csmdb3hP+odsdJzVZkpbWaeQea+QB4LhzYCZOItq6AECAyaCdSZq8b9KxLcbiZ
         hGMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:reply-to:date:mime-version:to:from:dkim-signature;
        bh=3EyCJnkc9WEjpXzG6/DGY5ykTi7wlcqKHF0Kxgvfj3U=;
        b=z9dhTuB9EvPO1PQXgT7v8x3lA3XU9TKLe8sI9nQHfZCsfVS8oxG6KhVXHGIKTF9gbH
         fduGuBfBZ0dXBVwuRqvrYPTWhQnwbVp83zgSVQVoVjWLaZZvfdL/eWdsq+TOhAJ9EDhi
         aZSBz+6OPnHqi23Yh4m1Tcm4TZZRSMij3rJoAAuv8BVEn+KWrtfTXu/Nl1QVgJ1pCDIX
         KLS/V5eKyuM7m3wJb/DiWoxWAedNvNlfCd3fGTozH7v86qX3prAUQQk14W9S3kEbPRMG
         gcn+75p5dVWH7oTld4SdDKwTdCmSvf+SajVPAA4ateVp7GGYDXtYanUw4Rlw45ERjEyv
         eiAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=f8W5UgfE;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id k3-20020ac257c3000000b004720a623d80si162163lfo.7.2022.05.11.14.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 May 2022 14:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samclaughlin2323@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id ks9so6669562ejb.2
        for <kasan-dev@googlegroups.com>; Wed, 11 May 2022 14:56:54 -0700 (PDT)
X-Received: by 2002:a17:906:a5b:b0:6f4:55f6:78af with SMTP id x27-20020a1709060a5b00b006f455f678afmr26881421ejf.238.1652306213596;
        Wed, 11 May 2022 14:56:53 -0700 (PDT)
Received: from f23.my.com (f23.my.com. [185.30.177.50])
        by smtp.gmail.com with ESMTPSA id i3-20020aa7c703000000b0042617ba638esm1729881edq.24.2022.05.11.14.56.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 May 2022 14:56:53 -0700 (PDT)
X-Mailru-Internal-From: samclaughlin2323@gmail.com
From: samclaughlin2323@gmail.com
To: =?UTF-8?B?a2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
MIME-Version: 1.0
X-Mailer: My.com Mailer 1.0
Date: Thu, 12 May 2022 00:56:52 +0300
X-Letter-Fingerprint: tsXn0BTtHRodcRyIRZcdYIvEiPPVxhXG
X-Priority: 3 (Normal)
X-Mailru-Compose-Stats: =?UTF-8?B?eyJVc2VyU2Vzc2lvblRpbWUiOjE3MDc0MCwiaXNfaW5fYWIiOiIwIiwiSG9z?=
 =?UTF-8?B?dCI6ImUtYWoubXkuY29tIiwiYWJfc2l6ZSI6MTE4fQ==?=
Reply-To: samclaughlin2323@gmail.com
Message-ID: <1652306212.252056020@f23.my.com>
Content-Type: multipart/alternative;
	boundary="--ALT--lWsSNlako0dSczl89M3MOpGGsKGRLL5M1652306212"
X-7564579A: EEAE043A70213CC8
X-77F55803: 68A6F98766B02875A0F21CC061F2095323D2FBEB2644075C126315D0AB1400100F7A170ED033A6E76ADD8015B5D986ECAD793E7D81E03748
X-8FC586DF: 7088FE8F28191859
X-C8649E89: 4E36BF7865823D7055A7F0CF078B5EC49A30900B95165D34C974B02B4EA30DFBA9B1D8EFD0F56D25FE7368AECE9A9E0895C55ABA00718791F798C294D7B94EA81D7E09C32AA3244CDADC981D8CCD7629259F58E763BCF62B5595C85A795C7BAE3EB3F6AD6EA9203E
X-D57D3AED: 3ZO7eAau8CL7WIMRKs4sN3D3tLDjz0dLbV79QFUyzQ2Ujvy7cMT6pYYqY16iZVKkSc3dCLJ7zSJH7+u4VD18S7Vl4ZUrpaVfd2+vE6kuoey4m4VkSEu530nj6fImhcD4MUrOEAnl0W826KZ9Q+tr5+wYjsrrSY/u8Y3PrTqANeitKFiSd6Yd7yPpbiiZ/d5BsxIjK0jGQgCHUM3Ry2Lt2G3MDkMauH3h0dBdQGj+BB/iPzQYh7XS329fgu+/vnDh7NWhME7XCV0+zXxPdMI9jg==
X-Mailru-MI: 10000000000000000
X-Mailru-Sender: DB11DFCB786AA44AD11578332F1651EC7505436D7ECB7184EDE77E80CD21D48973D5A176AF0171469C604E278E7FBC5B0C7C32C9699C446910CA66422320541103AB1AEBEC7359A6C77752E0C033A69EB4A721A3011E896F
X-Mras: Ok
X-Spam: undefined
X-Original-Sender: samclaughlin2323@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=f8W5UgfE;       spf=pass
 (google.com: domain of samclaughlin2323@gmail.com designates
 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
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


----ALT--lWsSNlako0dSczl89M3MOpGGsKGRLL5M1652306212
Content-Type: text/plain; charset="UTF-8"



fdvsfdsbf dsb fdsa d fafdfdfds j fds fd f dfds
hs fda fds dsf ds fds nfd sf ds fdsb fds fds fsd fdsfdsnj
--
Sent from Ook E
\mail App for Android

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1652306212.252056020%40f23.my.com.

----ALT--lWsSNlako0dSczl89M3MOpGGsKGRLL5M1652306212
Content-Type: text/html; charset="UTF-8"


<HTML><BODY><p style='margin-top: 0px;' dir="ltr"><br>
fdvsfdsbf dsb fdsa d fafdfdfds j fds fd f dfds<br>
hs fda fds dsf ds fds nfd sf ds fdsb fds fds fsd fdsfdsnj<br>
--<br>
Sent from Ook E<br>
\mail App for Android</p>
</BODY></HTML>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an email to <a href="mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href="https://groups.google.com/d/msgid/kasan-dev/1652306212.252056020%40f23.my.com?utm_medium=email&utm_source=footer">https://groups.google.com/d/msgid/kasan-dev/1652306212.252056020%40f23.my.com</a>.<br />

----ALT--lWsSNlako0dSczl89M3MOpGGsKGRLL5M1652306212--
