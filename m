Return-Path: <kasan-dev+bncBDQO764DWECRB64UTK4AMGQE5Z7LQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 17388996CB7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 15:51:57 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-37d43e7acd9sf284707f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 06:51:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728481916; cv=pass;
        d=google.com; s=arc-20240605;
        b=fHHAMqMu/gsLv6s5k5jRRwq7CLKJ4HC3stb2wzBHP6xZTplNjIczrfPSXVlwtM1aJH
         3yscpbI6Ifgpo9Z55YT1eED0oxTYZ1sqUHaF5vVklFagDwGS8/g94uCUsbqdUfP6gGzY
         4H3WkmC4SxfZIQg5xDeEuhE147Ur5+U4Bs2vcp+eDQQHJ7KaWb3f7N96HuYpGoCiSz7f
         bITpcE8RrSDvMn6QvCkW3oMK04WJWZTs5yTX0QcHoN+ehBudS0BGF7+slPT1uEc55Y22
         fOvBSh5wNQJhMcUXs+q/ZtuN9ZEQKkTekKqz2TQElZCeW5IaoLgKCvXsJPWd+6W8jDiZ
         i+QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=9/M7dIQeST5lqNhQyqGaTDLQ3kJpaIU4gcndXTUG4Ik=;
        fh=4n+u4/83aVnNHZ2kqqCD0lMbNy1BTMy0QsItJrimlyY=;
        b=SIBomAD9YYNdB+DDGZwMby/J0yAdCcsl0k+QQoUqE4GQeLQ907P9DyDGR6LQXWP2s4
         k1loG1qYgxco/O36e7VZCUJGwbB5DzpY15suoDPteLatecbxLCOs2/RSm4XELfXRzjJb
         AN0uQmE68zRFUSjvZNooOlMQ6E7nn8hO6JFYZWuG+T2CTGY0ITsaXOtiKD2pRKZF3dF2
         n/TzgytpngyXp/gyV1ocVPoiRZqLNNKeki425I6rvtdLZScNFIF7YCXOIKCRf15TQ4AW
         bRyYvvMZDK8oAnOcvEjyG1GtvAmSCrq81gW5nRoMcDKZYZXKZf/4g0E+eK/2SwTrwf/+
         kcOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LsKxg3+a;
       spf=pass (google.com: domain of sales.malcolninvestmentltd@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=sales.malcolninvestmentltd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728481916; x=1729086716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9/M7dIQeST5lqNhQyqGaTDLQ3kJpaIU4gcndXTUG4Ik=;
        b=ORVQk1WPgxIvbah343+4cJ3zXWBVsnVKcvk3P+HzH1zR+uWaMHjSNn2+628+38NWFK
         L7z/T0VepmwxwtazQZ0HcVXR3I+mYAEAqMPMTpQ5ALWMv9Oivk3OHp10eehW2a8ICjUP
         KXcTHaH9Y0LHle8IqVsmvwb7d/l4vPx22TUNF3UyqdYskIIWvDJwuFybzR+2S0b8DviX
         hYi1ENzlUCjq4lpakcyGnyEZply9XZlomImx3I+Z9a/28Tu5bPks2qDbOm8lHXoi1Osm
         /24b7Wot53hk2FRQdfnFF9zknOWuN80Fzo5H8Rebmf6PEolQ7Hmb40iajBXiuS+tgUpv
         iGSA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728481916; x=1729086716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=9/M7dIQeST5lqNhQyqGaTDLQ3kJpaIU4gcndXTUG4Ik=;
        b=aMGb+ExPE5IkOWV2VPhh5Z9WYwjxO1iQ64wJK8ZdDSEE3Ee9iuasiv9gd0Ph+jyU29
         4qVWPAOTL64m1kJqjzSJ1lZtsCbSvaz+mvYOnuDe78kK/tKcWOLpdnpKMNJv6ppeJw3+
         7V14eZtdLJqHadbOgFNbD9RV66s56cYX7U2PMV02kO5BeSKPLlR9j6qDrrdc3wRqmYyR
         bCoPKpbx81IVlimMR1V2Jgdk+4AnwCiLVnriYPjXOAygj0xpummIn+NatiDljPfFcgt4
         +wXQMSXIlUpeC/XsAcmYhcTsxByqT37emaczieaW6OlUROLvf/Oy08NeJlTZZ0Qa73WT
         NI2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728481916; x=1729086716;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9/M7dIQeST5lqNhQyqGaTDLQ3kJpaIU4gcndXTUG4Ik=;
        b=X/ZVa+/pekdKIidlZ2JbLHA8aZbMzD7gzscJU2JGrCFFBWq/Ol2Pj6yXe/DC1P61mB
         g+uC7WNnjdIpSNnIU3p0juX6oOTvghOmQGnUBoUJ1CMBwBs3nKBcfjLB+9gpm9vujYwU
         adsGBUSJw8Tdj+zUxtj8mMCfTDQ0o5jxtR+TZEmT7HWekc8Q4Wx+vNV0/9jDPOg0zAqQ
         DvdHzEL8zSzazAyjrHnotkPZK/3DFFMgJMs79VVBOnnZmPbfcabqt4kFPg99CfYAbWe7
         FkG9d10u40vO7jtesr9YvC3WOmZRPYsLa9HCSXfCxsOvqAWiOwR48g41zYVy4XoEC9N7
         rNQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8YHNINkG7bDv0od/PIVelXNbB51oFc7a9iqBHBDo6OvzUU6snxVZnBvtvWT20Fij/O3x6lw==@lfdr.de
X-Gm-Message-State: AOJu0Yxjj9lCOSZYVVMSyF5YZ8z8aENC228Ph9dPiZELHsUet0763CVO
	+HL4feYoMEoS2hMFuooqeM9XT2sF89uw4TjJhIyRlwhV0LCcQYje
X-Google-Smtp-Source: AGHT+IG8v5wBi0aoZZvBkSyEviBjUd2iE8vtYbf1q7+4cDGsb7FrOh+WwKHAAGxN9YkKwfVTm/1Bzw==
X-Received: by 2002:a5d:6452:0:b0:37d:38b2:14c2 with SMTP id ffacd0b85a97d-37d3aa70856mr1740091f8f.40.1728481915806;
        Wed, 09 Oct 2024 06:51:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c99:b0:42f:75e0:781e with SMTP id
 5b1f17b1804b1-42f7df67a4fls13740435e9.1.-pod-prod-09-eu; Wed, 09 Oct 2024
 06:51:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZckIFbMouyiS3sse/H9Y92op0BmSMkzMOBwZMIrxRwKc+92BKt1daFe0u+9m6rEMv5sypOwkZ+nI=@googlegroups.com
X-Received: by 2002:a05:600c:138b:b0:42c:acb0:ddb6 with SMTP id 5b1f17b1804b1-430ccf1ba1fmr22332335e9.9.1728481913635;
        Wed, 09 Oct 2024 06:51:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728481913; cv=none;
        d=google.com; s=arc-20240605;
        b=dxl2+yRdd8QDXT9OE2R07iBLJAAIIi9H++pxj5YNxeLSkmGp2fEFl0cRPdk7R26Ybm
         npxR7kcj4l3+UrbYpSI+3JKMWRqEgWJmVzBMa838LY5/Dj3BTjPMo5aBcGg4GidwWiln
         LxMRumOp4V7jKs6SDL+W2vgrdjHuBuNWSK9fTcWQ/gA5R371ZUbj3NxEpdNtvYOFXc3U
         fnyWqz3w6x59VMmUHtQFG080Er4x1/eZ24AexEz9xlC+of1FNKI1cxXA5f7VKo4nHyYN
         0MsWQ7lBJ8fJW9iGJZ21aqIZoa+hG8wQevDNVSdDmVIQVKryZwzlyqItGVI9BzXfxFLL
         /IYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=SX6UjdjHyYddAB7lWpclmjrqFoX28tX83XV5RsvcrXY=;
        fh=C/CTpkXl8h9kUK+E5Y7s9C89nLV306fmXhTmU44aOgE=;
        b=TM1xiGXC5ON3Oy6tXp9EeS2A9TO5shr7akP0YQCq5y3CxCFtmfKcwo+HQDyZI3rziD
         cCA0Tx+djw5w/pnNaJZLx1aFlwr7iDcnKfwp5uJAS+IH3HdNNTjFecs6ipf/7T0BHhfO
         7gP2FC9eJJxqHhI24/BMcTMi4OhLbZTsIB+w7Ny0EK4rT35sJEmzOFS5AHzKC4yQp4Qr
         4OKXdxGgC7tVFwDjxORZU/cDP9ulmlsQwjCvWJz443cDeLRmYVa7M+HK752MD1OUzim7
         3vrpDYqkzT9BAA8lF5Jywyv2Nl2z5LqStyZAUEbHgzCmj7B9T6AMKLHHSjZErO7zRU0D
         l+2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LsKxg3+a;
       spf=pass (google.com: domain of sales.malcolninvestmentltd@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=sales.malcolninvestmentltd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-430d70b47a8si388215e9.2.2024.10.09.06.51.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2024 06:51:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of sales.malcolninvestmentltd@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id a640c23a62f3a-a993f6916daso588834666b.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2024 06:51:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAgnsDxhjdStGbsW7tA0IVP2HYpPsTNYxtStUn1n0yNqcolWq5PtpHbwdKYHb43cyUI+nYSfcZ1bY=@googlegroups.com
X-Received: by 2002:a17:907:3e0a:b0:a99:4025:82e1 with SMTP id
 a640c23a62f3a-a998d3279f4mr242212466b.41.1728481912780; Wed, 09 Oct 2024
 06:51:52 -0700 (PDT)
MIME-Version: 1.0
Reply-To: nicolatyers1@gmail.com
From: "Mrs. Nicola Tyers" <nicolatyers1@gmail.com>
Date: Wed, 9 Oct 2024 14:51:38 +0100
Message-ID: <CAOHLOFxEGj9aBXkY03kZ_SSZw0E_QOiU6hT2M_djSQ3HtE6oRg@mail.gmail.com>
Subject: GREETINGS
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000697fa406240b8ed4"
X-Original-Sender: nicolatyers1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LsKxg3+a;       spf=pass
 (google.com: domain of sales.malcolninvestmentltd@gmail.com designates
 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=sales.malcolninvestmentltd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--000000000000697fa406240b8ed4
Content-Type: text/plain; charset="UTF-8"

Greetings,

I am reaching out to you with a heavy heart due to the ongoing war crisis in
Ukraine, which has tragically claimed the lives of numerous individuals and
families, including one of our clients. In light of these devastating events,
I would like to discuss a proposal with you that could enable us to extend
a helping hand to the victims.

Warm regards,
Mrs. Nicola Tyers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOHLOFxEGj9aBXkY03kZ_SSZw0E_QOiU6hT2M_djSQ3HtE6oRg%40mail.gmail.com.

--000000000000697fa406240b8ed4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><span style=3D"color:rgb(0,0,0);font-fami=
ly:-webkit-standard;font-size:medium">Greetings,</span><br></div><div><div =
dir=3D"ltr" class=3D"gmail_signature" data-smartmail=3D"gmail_signature"><d=
iv dir=3D"ltr"><br style=3D"font-family:&quot;Helvetica Neue&quot;,Helvetic=
a,Arial,sans-serif;font-size:13px;color:rgb(0,0,0);outline:currentcolor!imp=
ortant"><span style=3D"color:rgb(0,0,0);font-family:-webkit-standard;font-s=
ize:medium;outline:currentcolor!important">I am reaching out to you with a =
heavy heart due to the ongoing war crisis</span><span style=3D"font-family:=
&quot;Helvetica Neue&quot;,Helvetica,Arial,sans-serif;font-size:13px;color:=
rgb(0,0,0);outline:currentcolor!important">=C2=A0</span><span style=3D"colo=
r:rgb(0,0,0);font-family:-webkit-standard;font-size:medium;outline:currentc=
olor!important">in Ukraine, which has tragically claimed the lives of numer=
ous individuals</span><span style=3D"font-family:&quot;Helvetica Neue&quot;=
,Helvetica,Arial,sans-serif;font-size:13px;color:rgb(0,0,0);outline:current=
color!important">=C2=A0</span><span style=3D"color:rgb(0,0,0);font-family:-=
webkit-standard;font-size:medium;outline:currentcolor!important">and famili=
es, including one of our clients. In light of these devastating</span><span=
 style=3D"font-family:&quot;Helvetica Neue&quot;,Helvetica,Arial,sans-serif=
;font-size:13px;color:rgb(0,0,0);outline:currentcolor!important">=C2=A0</sp=
an><span style=3D"color:rgb(0,0,0);font-family:-webkit-standard;font-size:m=
edium;outline:currentcolor!important">events, I would like to discuss a pro=
posal with you that could enable us</span><span style=3D"font-family:&quot;=
Helvetica Neue&quot;,Helvetica,Arial,sans-serif;font-size:13px;color:rgb(0,=
0,0);outline:currentcolor!important">=C2=A0</span><span style=3D"color:rgb(=
0,0,0);font-family:-webkit-standard;font-size:medium;outline:currentcolor!i=
mportant">to extend a helping hand to the victims.</span><br style=3D"font-=
family:&quot;Helvetica Neue&quot;,Helvetica,Arial,sans-serif;font-size:13px=
;color:rgb(0,0,0);outline:currentcolor!important"><br style=3D"font-family:=
&quot;Helvetica Neue&quot;,Helvetica,Arial,sans-serif;font-size:13px;color:=
rgb(0,0,0);outline:currentcolor!important"><span style=3D"color:rgb(0,0,0);=
font-family:-webkit-standard;font-size:medium;outline:currentcolor!importan=
t">Warm regards,</span><br style=3D"font-family:&quot;Helvetica Neue&quot;,=
Helvetica,Arial,sans-serif;font-size:13px;color:rgb(0,0,0);outline:currentc=
olor!important"><span style=3D"color:rgb(0,0,0);font-family:-webkit-standar=
d;font-size:medium;outline:currentcolor!important">Mrs. Nicola Tyers.</span=
><br></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOHLOFxEGj9aBXkY03kZ_SSZw0E_QOiU6hT2M_djSQ3HtE6oRg%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAOHLOFxEGj9aBXkY03kZ_SSZw0E_QOiU6hT2M_djSQ3HtE6oRg=
%40mail.gmail.com</a>.<br />

--000000000000697fa406240b8ed4--
