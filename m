Return-Path: <kasan-dev+bncBDBKPW6SQIPBBTHJZTBAMGQEXH7FUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B491ADF8EF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 23:51:11 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-3141f9ce4e2sf92004a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 14:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750283469; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ih67GJN7tzxs/mFp1xv/huCp/R3JHNQoaqFG7GTHKGNcKp8EZRfYNmsK0QQOFaddsY
         sNlIwpzuumCCoGZp+oKCVQ2dskUZVPf/58a6FcBcw8u0mshv9AJGm7YYoqkvnSSB+ISt
         UfjG7ZBrzsDiN0Ht+d057mBVtDBKx300cDv22Orbjdc47YAGzrRE+ZiRzvV3xwIzht8+
         x5yefkIhRfiyXhuN6KU7ZvXoNoXDN/8l1KcjNlh91wyTsukOoWgE1pgxPGpN+clkOEax
         U07OlXerbRohUpVgJjDmcVpmVJM36DFcOudp04DxOEdAi1TpJAvDA9toqSazCgwUz/PB
         xT7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:to:list-unsubscribe-post:list-unsubscribe
         :reply-to:subject:message-id:mime-version:from:date:dkim-signature;
        bh=6cuvX6avSXZnM39Vkh1E1P1wo1LwGPIMEvIO9T3HbJE=;
        fh=V6B2SPJnKIECwjVwp8OCG59xwoEXg5HfROSuSUvM6ds=;
        b=WHVZp1kRu85HuCTiv52a9MWr9MNivX7UhBB9fFTTjnrTGbYFPL6N12TyvS+Jk4AgXS
         DLs9TbqPRO4eiMbS62d+SnsekIoVAMKSgSpSOEtquWA2StAL69WQWblaLi4wwVengo3X
         vlz5rT5Rm9GuLZqpc9dg+LfqSniOv1yAqAHufNwKpgi390UQ+vizsuYHltSYftTg/9L1
         +FvPiJZWMteOqaQmhheQaG54kpvrnKQs49Q2WS3nI8YRW1dHFyNtjC5G6NmUgflHYwMC
         rsMOki0PwVbEwgjA2GgzmQSCpHBTIw9ciCnEmhLCjC726Ev3KD+y6pA+0df7Sa3AwCOW
         Z7pw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@medium.com header.s=m1 header.b=Aj+c4OrR;
       spf=pass (google.com: domain of bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com designates 167.89.65.228 as permitted sender) smtp.mailfrom="bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=medium.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750283469; x=1750888269; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:list-unsubscribe-post:list-unsubscribe
         :reply-to:subject:message-id:mime-version:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6cuvX6avSXZnM39Vkh1E1P1wo1LwGPIMEvIO9T3HbJE=;
        b=bELKwOaG5rR1BLu0wnQP0RwrfJHp9JqeVosBER5BzDc0BZKJsjeEdqPpdAEHvK7ig8
         mC+uB78U2bx03nn6QGwbS9sK//vTFqbKE23v8hsxKPcMAVG8fECFks1ef/0Igrj4escH
         fQepANB+rlqa5AJcbhLr/9tJkGEywo6vzF4pA9EZs68qQwqOYBPev8BDsOMDKzA3iKy0
         fAsl92TAx3TzBRSvuLQhYw5G11CyFT+vq6DXp3WSFDvFi9vcRdknnDfet7x6q37JMDAP
         aCGJcofwQMtfQPLSxAs95gxcOxb7IzHReYeroylEF77iqAoHn/KgAV5INzoWvAhzoBEp
         sCQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750283469; x=1750888269;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to
         :list-unsubscribe-post:list-unsubscribe:reply-to:subject:message-id
         :mime-version:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6cuvX6avSXZnM39Vkh1E1P1wo1LwGPIMEvIO9T3HbJE=;
        b=PJ27irZt/j2rqpPX/31e2K8qqt0yGbfscEAM4qH5DNNlOpO6O+9b8eJX6Opef/pW4E
         uyIpbawVrJHDjIZ3cpjgprRCAbKoA8h4ttVKUkIFHduCBGbrUhCoWJN7DPQ4V1XcX380
         u6uk/LfXGvIdXiMtfGLOgXNZBAu2+PHyyOkB+BKstZ9FYRmkrySJOZuj+7hldSq66frb
         cvaSE6RXo9FdJwNGUkfsgCoZNIa4jY4xxenmjLX8l7gOIDg675aXnbD6ofAQ1PEvXmqK
         x/PnpcxSsZEFzgA7igbVR4C+KDv65UHk3pkuH4TvRnqhDN5TgIg7NozU+XySWkWkGQSy
         qLsA==
X-Forwarded-Encrypted: i=2; AJvYcCW9Hwosu6pmeXXkXPbeBaLZyu62c/WGgFGenwUYz3blvIuh59I7/cO5hPbVAArE+4eO5xjDkg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4YlCpcKym8vS5jLzvm9KBzI4iqKQiq8lMFSJh1ih5+RYmexf0
	qa4TbET4R/fc6S64Qfb1zTLKAA1SZiagVEJx5pvuHXq3RsZDV9rzwZfB
X-Google-Smtp-Source: AGHT+IFy9DUX6vW0d4ntUHIOYx3OchCqiOqhko4LuFRXmMKSnEhx9SVLK4PW0m7gN9Ct1//lzG2ZXA==
X-Received: by 2002:a17:90b:2f4e:b0:312:e731:5a66 with SMTP id 98e67ed59e1d1-313f1ca786dmr26225714a91.3.1750283469172;
        Wed, 18 Jun 2025 14:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeJKTJWvJ5+/lt3LPcUiNqqrqCEd+FzTQQsAjqqfyvFoQ==
Received: by 2002:a17:90a:1181:b0:311:daac:1a54 with SMTP id
 98e67ed59e1d1-3158e227e84ls95747a91.0.-pod-prod-08-us; Wed, 18 Jun 2025
 14:51:07 -0700 (PDT)
X-Received: by 2002:a17:90b:528d:b0:314:2a2e:9da9 with SMTP id 98e67ed59e1d1-3142a2e9e1cmr10005478a91.25.1750283467688;
        Wed, 18 Jun 2025 14:51:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750283467; cv=none;
        d=google.com; s=arc-20240605;
        b=FzUT0hg0NHq+hUv+XU65FhX2GrJuBJUTCvb9RXrtEh04UnmFAx6NZIXB5WxyjOmtp/
         de414Zd28voji5j0q9XWgsjcQGTpK8ZmShW+JLU/CigDIfVJiMiHGERdew0u6zCKotzm
         DTVJQW8tIVXDB8w48AtCDYrPgI6kUtonuw9boUWv0LeHQr7C4gbKS+wvXy3C5OB/vBjm
         tm9zMpXKh4sKQAERWgowAUREj268aBhtjgozFlq1c/zpnJkcuU01YW/PxcFBMummTcjb
         T5JRWrx5TpadZN67wPWbN+HTfbthgVN/uJ6V/yns/M02m3GE/bcbecyZ6eVxVW0Hjn30
         EXBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:list-unsubscribe-post:list-unsubscribe:reply-to:subject
         :message-id:mime-version:from:date:dkim-signature;
        bh=ydUM70QHjn4+Swl4rhWRq66hKImAyJ9YemZjgL9E4sI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=gJsQs2Q+Wgpt63p0sAFMUSXsCy66KKcgFMZ63o9e9VcHqkhL82OC3zYROTRS2PkttM
         oy7TbWGxWbXCBaaI+HYmV4dsvJVSEHhj9uLG9j8u9ohOSoAme1r3yQzPcRtNEVA7iGlX
         E5PH6t0aMr/dyYjUrRwo/8GqW0WPhpG66Sv1QEULMnDYaP7td5CpwgtY/lBDKnQXAvk3
         HnA1pUl4fET8FcjbVFbx35+oK6CLYwG660lbE6b/k9Rgm6we3yTSHWYvhgBRnnJRazXY
         0RYWO8FLcbOws+Sxpha8ZhHUqhWuJMkn50VYP45TKnquD35mlKVKxf076ncCCuqdR3YJ
         2N+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@medium.com header.s=m1 header.b=Aj+c4OrR;
       spf=pass (google.com: domain of bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com designates 167.89.65.228 as permitted sender) smtp.mailfrom="bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=medium.com
Received: from o3.email.medium.com (o3.email.medium.com. [167.89.65.228])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3157c9da648si119146a91.1.2025.06.18.14.51.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jun 2025 14:51:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com designates 167.89.65.228 as permitted sender) client-ip=167.89.65.228;
Received: by recvd-6bf44c8976-j7gzf with SMTP id recvd-6bf44c8976-j7gzf-1-685334CA-15
	2025-06-18 21:51:06.22532124 +0000 UTC m=+1228838.051447266
Received: from MTg3MTE3OQ (unknown)
	by geopod-ismtpd-24 (SG) with HTTP
	id XqNBHXHnRK2dwuH_C8QUHg
	Wed, 18 Jun 2025 21:51:06.203 +0000 (UTC)
Content-Type: multipart/alternative; boundary=e7b9834c473ec5d1501706976e0c838dc713f6088d3962c73dda1acc3de9
Date: Wed, 18 Jun 2025 21:51:06 +0000 (UTC)
From: "'Medium' via kasan-dev" <kasan-dev@googlegroups.com>
Mime-Version: 1.0
Message-ID: <XqNBHXHnRK2dwuH_C8QUHg@geopod-ismtpd-24>
Subject: Foolky has added you to their email list on Medium
Reply-To: noreply@medium.com
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
X-SG-EID: =?us-ascii?Q?u001=2E55w7ZmMf2EEl2GsC3Do5zOXm2Jr8NaTnQhYP6Ps0MXrFfhuNch5vRQ3Sg?=
 =?us-ascii?Q?TVwb8GHSxGvdh0c2pVUTmxP9c20Q=2FhoLMAUFbja?=
 =?us-ascii?Q?z1FF4SSzLuSK6wAqemyHSQBAv15X4W6lF5J4lOX?=
 =?us-ascii?Q?pasbR3dXLDVfX2m4r639AWxnY8BRZJ4L+=2FFGOty?=
 =?us-ascii?Q?p5LQOZADU8nCM1wxOzwCcqOzZh0RjNN40lckq9I?=
 =?us-ascii?Q?HazN6jeR2BdOJe33MXHr5jeu2Yxe8D4aU8dVjUP?= =?us-ascii?Q?nCgA?=
X-SG-ID: =?us-ascii?Q?u001=2ESdBcvi+Evd=2FbQef8eZF3BgoA4hOSswzUj31zD1PkZewI1bMhFo1Y=2FJU0N?=
 =?us-ascii?Q?aUkhhEjNdP6MNw8cmEdDOaZFm5curW7X6GAF1G7?=
 =?us-ascii?Q?jxsetDJWkAvtoH9eBm3rSoqeuLasUNBOSMfH1kg?=
 =?us-ascii?Q?GEkSoZMfHLV8wBr8OhwRV0U3NtsPGZuJ5ezIEi+?=
 =?us-ascii?Q?Hv1rrEepqAWy2+cuhp?=
To: kasan-dev@googlegroups.com
X-Entity-ID: u001.1fw7e6DunOGO8rot/mNj1Q==
X-Original-Sender: noreply@medium.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@medium.com header.s=m1 header.b=Aj+c4OrR;       spf=pass
 (google.com: domain of bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com
 designates 167.89.65.228 as permitted sender) smtp.mailfrom="bounces+1871179-e6e6-kasan-dev=googlegroups.com@email.medium.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=medium.com
X-Original-From: Medium <noreply@medium.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>

--e7b9834c473ec5d1501706976e0c838dc713f6088d3962c73dda1acc3de9
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0

Hello,

Foolky (https://medium.com/@withflooky?source=3Demail-3c1c5393f9a3-17502834=
66078-subscriber.importedWelcome-------------------------a18b1099_b41b_4dba=
_9fd6_e6a50204e447)
 has imported your email address to their email list on Medium. You will re=
ceive their Medium stories via email when they are published on Medium.

If you do not wish to receive emails from this account, please click the "U=
nsubscribe" button below. This will immediately remove you from this mailin=
g list, and Foolky will not be able to import your email address to Medium =
again.

No Medium account has been created on your behalf.

You can learn more about Medium here (https://medium.com/about?source=3Dema=
il-3c1c5393f9a3-1750283466078-subscriber.importedWelcome-------------------=
------a18b1099_b41b_4dba_9fd6_e6a50204e447)
.

Unsubscribe (https://medium.com/me/email-settings/3c1c5393f9a3/6c76252efd22=
?type=3DnoSetting&newsletterV3Id=3D683e07cd9a53&source=3Demail-3c1c5393f9a3=
-1750283466078-subscriber.importedWelcome-------------------------a18b1099_=
b41b_4dba_9fd6_e6a50204e447)

Per the Terms of Use (https://help.medium.com/hc/en-us/articles/44125853134=
31-Email-Import-Terms-of-Use?source=3Demail-3c1c5393f9a3-1750283466078-subs=
criber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a5=
0204e447)
, Medium accounts must have permission to import the email addresses they h=
ave collected off Medium.

Sent by Medium (https://medium.com/?source=3Demail-3c1c5393f9a3-17502834660=
78-subscriber.importedWelcome-------------------------a18b1099_b41b_4dba_9f=
d6_e6a50204e447)
=C2=B73500 South DuPont Highway, Suite IQ-101, Dover,=C2=A0DE=C2=A019901
Unsubscribe (https://medium.com/me/email-settings/3c1c5393f9a3/6c76252efd22=
?type=3DnoSetting&source=3Demail-3c1c5393f9a3-1750283466078-subscriber.impo=
rtedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a50204e447)
 from this type of email=C2=B7Careers (https://medium.com/jobs-at-medium/wo=
rk-at-medium-959d1a85284e?source=3Demail-3c1c5393f9a3-1750283466078-subscri=
ber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a5020=
4e447)
=C2=B7Help Center (https://help.medium.com/hc/en-us?source=3Demail-3c1c5393=
f9a3-1750283466078-subscriber.importedWelcome-------------------------a18b1=
099_b41b_4dba_9fd6_e6a50204e447)
=C2=B7Privacy Policy (https://policy.medium.com/medium-privacy-policy-f03bf=
92035c9?source=3Demail-3c1c5393f9a3-1750283466078-subscriber.importedWelcom=
e-------------------------a18b1099_b41b_4dba_9fd6_e6a50204e447)
=C2=B7Terms of service (https://policy.medium.com/medium-terms-of-service-9=
db0094a1e0f?source=3Demail-3c1c5393f9a3-1750283466078-subscriber.importedWe=
lcome-------------------------a18b1099_b41b_4dba_9fd6_e6a50204e447)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/X=
qNBHXHnRK2dwuH_C8QUHg%40geopod-ismtpd-24.

--e7b9834c473ec5d1501706976e0c838dc713f6088d3962c73dda1acc3de9
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="UTF-8"
Mime-Version: 1.0

<html lang=3D"en" style=3D"box-sizing: border-box;"><head><meta http-equiv=
=3D"Content-Type" content=3D"text/html; charset=3Dutf-8"><meta name=3D"view=
port" content=3D"width=3Ddevice-width, initial-scale=3D1, maximum-scale=3D5=
"><meta name=3D"robots" content=3D"none"><style>
.hljs-link,
.hljs-regexp {
  color: #0e0eff;
}
</style><style>
.am:hover {
  background: rgba(8, 8, 8, 1);
}
.an:hover {
  border-color: rgba(41, 41, 41, 1);
}
</style><style>
@media all and (min-width: 728px) and (max-width: 903.98px) {
  .d {
    background-color: rgba(242, 242, 242, 1) !important;
  }

  .e {
    padding: 6px 0 40px 0;
  }
}
</style><style>
@media all and (min-width: 904px) and (max-width: 1079.98px) {
  .f {
    background-color: rgba(242, 242, 242, 1) !important;
  }

  .g {
    padding: 6px 0 40px 0;
  }
}
</style><style>
@media all and (min-width: 1080px) {
  .h {
    background-color: rgba(242, 242, 242, 1) !important;
  }

  .i {
    padding: 6px 0 40px 0;
  }
}
</style><link id=3D"glyph_preload_link" rel=3D"preload" as=3D"style" type=
=3D"text/css" href=3D"https://glyph.medium.com/css/unbound.css"><link id=3D=
"glyph_link" rel=3D"stylesheet" type=3D"text/css" href=3D"https://glyph.med=
ium.com/css/unbound.css"></head><body style=3D"margin: 0; padding: 0;"><div=
 class=3D"c d e f g h i" style=3D"background-color: rgba(255, 255, 255, 1);=
"><table class=3D"j k l m" role=3D"presentation" cellpadding=3D"0" cellspac=
ing=3D"0" style=3D"margin-left: auto; margin-right: auto; width: 100%; max-=
width: 600px;" width=3D"100%"><tbody><tr><td class=3D"l n" style=3D"width: =
100%; min-width: 100%;" width=3D"100%"><img src=3D"https://medium.com/_/sta=
t?event=3Demail.opened&amp;emailId=3Da18b1099-b41b-4dba-9fd6-e6a50204e447&a=
mp;source=3Demail-3c1c5393f9a3-1750283466078-subscriber.importedWelcome----=
---------------------a18b1099_b41b_4dba_9fd6_e6a50204e447" width=3D"1" heig=
ht=3D"1" alt><div class=3D"a b" style=3D"font-family: sohne, 'Helvetica Neu=
e', Helvetica, Arial, sans-serif; color: rgba(25, 25, 25, 1);"><table class=
=3D"l o" cellpadding=3D"0" cellspacing=3D"0" style=3D"width: 100%; height: =
91px;" width=3D"100%" height=3D"91"><tbody class=3D"p o" style=3D"height: 9=
1px; display: block;"><tr class=3D"p o" style=3D"height: 91px; display: blo=
ck;"><td class=3D"q o" style=3D"height: 91px; width: 24px;" width=3D"24" he=
ight=3D"91"><img alt src=3D"https://miro.medium.com/max/2000/1*4mk6onwBrIb9=
FSOQ6zMv9A.jpeg" width=3D"24px" height=3D"91"></td><td class=3D"r o" style=
=3D"height: 91px; width: 121px;" width=3D"121" height=3D"91"><a class=3D"p"=
 href=3D"https://medium.com/?source=3Demail-3c1c5393f9a3-1750283466078-subs=
criber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a5=
0204e447" aria-label=3D"Medium homepage link" style=3D"color: inherit; text=
-decoration: none; display: block;"><img alt class src=3D"https://miro.medi=
um.com/proxy/1*1p2ITOyu0USn8aiamoqKJA@2x.jpeg" width=3D"121" height=3D"91">=
</a></td><td class=3D"l o" style=3D"width: 100%; height: 91px;" width=3D"10=
0%" height=3D"91"><img alt src=3D"https://miro.medium.com/max/2000/1*4mk6on=
wBrIb9FSOQ6zMv9A.jpeg" width=3D"100%" height=3D"91"></td></tr></tbody></tab=
le><div class=3D"c s" style=3D"background-color: rgba(255, 255, 255, 1); pa=
dding: 32px 24px 48px;"><div class><div class=3D"t" style=3D"margin-bottom:=
 24px;"><div class=3D"u v w x" style=3D"font-weight: 400; font-size: 16px; =
line-height: 24px; color: rgba(41, 41, 41, 1);">Hello,</div></div><div clas=
s=3D"t" style=3D"margin-bottom: 24px;"><div class=3D"u v w x" style=3D"font=
-weight: 400; font-size: 16px; line-height: 24px; color: rgba(41, 41, 41, 1=
);"><a class=3D"y" href=3D"https://medium.com/@withflooky?source=3Demail-3c=
1c5393f9a3-1750283466078-subscriber.importedWelcome------------------------=
-a18b1099_b41b_4dba_9fd6_e6a50204e447" style=3D"color: inherit; text-decora=
tion: underline;">Foolky</a> has imported your email address to their email=
 list on Medium. You will receive their Medium stories via email when they =
are published on Medium.</div></div><div class=3D"t" style=3D"margin-bottom=
: 24px;"><div class=3D"u v w x" style=3D"font-weight: 400; font-size: 16px;=
 line-height: 24px; color: rgba(41, 41, 41, 1);">If you do not wish to rece=
ive emails from this account, please click the =E2=80=9CUnsubscribe=E2=80=
=9D button below. This will immediately remove you from this mailing list, =
and Foolky will not be able to import your email address to Medium again.</=
div></div><div class=3D"t" style=3D"margin-bottom: 24px;"><div class=3D"u v=
 w x" style=3D"font-weight: 400; font-size: 16px; line-height: 24px; color:=
 rgba(41, 41, 41, 1);">No Medium account has been created on your behalf.</=
div></div><div class=3D"t" style=3D"margin-bottom: 24px;"><div class=3D"u v=
 w x" style=3D"font-weight: 400; font-size: 16px; line-height: 24px; color:=
 rgba(41, 41, 41, 1);">You can learn more about Medium <a class=3D"y" href=
=3D"https://medium.com/about?source=3Demail-3c1c5393f9a3-1750283466078-subs=
criber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a5=
0204e447" aria-label=3D"Medium&#x27;s about page" style=3D"color: inherit; =
text-decoration: underline;">here</a>.</div></div><div class=3D"t" style=3D=
"margin-bottom: 24px;"><a class=3D"z ab ac ae af ag ah ai aj ak al am an ao=
 u ap aq" href=3D"https://medium.com/me/email-settings/3c1c5393f9a3/6c76252=
efd22?type=3DnoSetting&amp;newsletterV3Id=3D683e07cd9a53&amp;source=3Demail=
-3c1c5393f9a3-1750283466078-subscriber.importedWelcome---------------------=
----a18b1099_b41b_4dba_9fd6_e6a50204e447" style=3D"font-weight: 400; border=
-width: 1px; border-style: solid; box-sizing: border-box; display: inline-b=
lock; text-decoration: none; text-align: center; padding: 9px 16px; backgro=
und: rgba(25, 25, 25, 1); border-color: rgba(25, 25, 25, 1); color: rgba(25=
5, 255, 255, 1); fill: rgba(255, 255, 255, 1); border-radius: 99em; font-si=
ze: 14px; line-height: 20px;">Unsubscribe</a></div><div class=3D"t" style=
=3D"margin-bottom: 24px;"><div class=3D"u v w x" style=3D"font-weight: 400;=
 font-size: 16px; line-height: 24px; color: rgba(41, 41, 41, 1);">Per the <=
a class=3D"y" href=3D"https://help.medium.com/hc/en-us/articles/44125853134=
31-Email-Import-Terms-of-Use?source=3Demail-3c1c5393f9a3-1750283466078-subs=
criber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a5=
0204e447" aria-label=3D"Email import Terms of Use" style=3D"color: inherit;=
 text-decoration: underline;">Terms of Use</a>, Medium accounts must have p=
ermission to import the email addresses they have collected off Medium.</di=
v></div></div><div class=3D"ar as at" style=3D"border-top: 1px solid rgba(0=
, 0, 0, 1); margin-top: 50px; padding: 26px 0 0;"><div class=3D"ag" style=
=3D"text-align: center;"><div class=3D"u au aq x" style=3D"font-weight: 400=
; color: rgba(41, 41, 41, 1); line-height: 20px; font-size: 13px;"><div cla=
ss>Sent by <a href=3D"https://medium.com/?source=3Demail-3c1c5393f9a3-17502=
83466078-subscriber.importedWelcome-------------------------a18b1099_b41b_4=
dba_9fd6_e6a50204e447" style=3D"color: inherit; text-decoration: none;">Med=
ium</a><span class=3D"av aw" style=3D"padding-left: 4px; padding-right: 4px=
;">=C2=B7</span>3500 South DuPont Highway, Suite IQ-101, Dover,=C2=A0DE=C2=
=A019901</div><a class=3D"y" href=3D"https://medium.com/me/email-settings/3=
c1c5393f9a3/6c76252efd22?type=3DnoSetting&amp;source=3Demail-3c1c5393f9a3-1=
750283466078-subscriber.importedWelcome-------------------------a18b1099_b4=
1b_4dba_9fd6_e6a50204e447" style=3D"color: inherit; text-decoration: underl=
ine;">Unsubscribe</a> from this type of email<span class=3D"av aw" style=3D=
"padding-left: 4px; padding-right: 4px;">=C2=B7</span><a class=3D"y" href=
=3D"https://medium.com/jobs-at-medium/work-at-medium-959d1a85284e?source=3D=
email-3c1c5393f9a3-1750283466078-subscriber.importedWelcome----------------=
---------a18b1099_b41b_4dba_9fd6_e6a50204e447" style=3D"color: inherit; tex=
t-decoration: underline;">Careers</a><span class=3D"av aw" style=3D"padding=
-left: 4px; padding-right: 4px;">=C2=B7</span><a class=3D"y" href=3D"https:=
//help.medium.com/hc/en-us?source=3Demail-3c1c5393f9a3-1750283466078-subscr=
iber.importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a502=
04e447" style=3D"color: inherit; text-decoration: underline;">Help Center</=
a><span class=3D"av aw" style=3D"padding-left: 4px; padding-right: 4px;">=
=C2=B7</span><a class=3D"y" href=3D"https://policy.medium.com/medium-privac=
y-policy-f03bf92035c9?source=3Demail-3c1c5393f9a3-1750283466078-subscriber.=
importedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a50204e44=
7" style=3D"color: inherit; text-decoration: underline;">Privacy Policy</a>=
<span class=3D"av aw" style=3D"padding-left: 4px; padding-right: 4px;">=C2=
=B7</span><a class=3D"y" href=3D"https://policy.medium.com/medium-terms-of-=
service-9db0094a1e0f?source=3Demail-3c1c5393f9a3-1750283466078-subscriber.i=
mportedWelcome-------------------------a18b1099_b41b_4dba_9fd6_e6a50204e447=
" style=3D"color: inherit; text-decoration: underline;">Terms of service</a=
></div></div></div></div></div></td></tr></tbody></table></div><img src=3D"=
https://u1871179.ct.sendgrid.net/wf/open?upn=3Du001.04z0otjhsYypuIX-2Bcebwj=
IkcsAFkyl7AgBiKU0-2BjRCTBGrEcA1GiYru-2Bbr4ixEMRakc4NzSc3vjaE1bRFBwX4n-2BB-2=
FNOCtHLZUmw7Cv2oY6LpgRUvVojFONQO-2BoaSZvl-2FWXRIlJ97VWYt6PIKuAgUD4ZDVpDHfE8=
63fGqkIwWGx28DqYf-2BcAKSkbvR-2FNCbZ60VvhuedrQ4m5Af85He6PXAqOE8Mux8o4zCj8CUF=
ak9kWg9bcmXRYN7dkmZoPrnbe-2BiUrZ9agmbU-2FeuhcB3dZSxBA1Ycpv7jUA4fHhy6puxXVIc=
Dpap4OhbSXJ-2BJeg-2BFepEvuZHHL8S1C0TPVV13zVAlVzkHEwh-2F9JY87K31MbjJ9hpn7CrR=
OsEpMkBXuiWEV8cCst-2F4MrfvsKrpmt001QyQ-3D-3D" alt=3D"" width=3D"1" height=
=3D"1" border=3D"0" style=3D"height:1px !important;width:1px !important;bor=
der-width:0 !important;margin-top:0 !important;margin-bottom:0 !important;m=
argin-right:0 !important;margin-left:0 !important;padding-top:0 !important;=
padding-bottom:0 !important;padding-right:0 !important;padding-left:0 !impo=
rtant;"/></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/XqNBHXHnRK2dwuH_C8QUHg%40geopod-ismtpd-24?utm_medium=3Demail&utm_=
source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/XqNBHXHnRK2dwu=
H_C8QUHg%40geopod-ismtpd-24</a>.<br />

--e7b9834c473ec5d1501706976e0c838dc713f6088d3962c73dda1acc3de9--
