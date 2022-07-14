Return-Path: <kasan-dev+bncBDOM3E4KSMIBBFHRYGLAMGQEJ5MRB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98108575633
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 22:12:06 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id o21-20020a17090a9f9500b001f0574225fasf4131858pjp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 13:12:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657829525; cv=pass;
        d=google.com; s=arc-20160816;
        b=UUrgJKAY6YoTLpX46eCJELzDd9O2xCJMn5xSO2Kk81925/g25i+hKT+mxWudbrucAW
         zFLcnp79FjXF4Hya/oRKEU5i1gvsKyWBYiMJhfnDEvQ82UQy8X/zf8ahnVpQTPzTKxCF
         lhyQ1UyZdczRaaiutRFSLwYU31BOWCPU1lAY6hCsyKNFPVQp9gUh819Fb545R0jsFkWe
         dD11nDj4WANc6qBuetoWaTz89IP4BZdriYrS3gGmqu2+zS8kVh0kN6XbJCJ5JE5cHRSw
         QEnwbsWFbGb3IIXSYIDPMuiRduBwuyCW3EsxJzjoCjusn0weBqKr9poikqEPOuhJoM2R
         tMBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=rRdM6wKEuT/QImKox3oFt+iy9kZes3PTTrLT9BGj+dM=;
        b=a/n+UhvSDqk6wi0gnNrBJ1vdEW5K4gJg45db6m+DVOqrbSd6VkhfNcNw/A4sXhLxzU
         MJtCVbGuXoM+7bGHmu1y0fl9FOSg2PZb2pWGCU2H4ozoK9N5srw/bcf3TkI0Q3u/TdVJ
         vSwn0cShazIa6Q+p6NPF1tn1rr+7Z7u+ktpM0rr4/ZLW5HELAnOK4IS0atuW3VsgH2OF
         K1wNohM9KN8xuu/kImy3aG+J3u+958Zs7FYxKV1yiQ/QX/nWU6HFMbg73px/jdyKrP0y
         LBeg64E/F5xvQA9WgGQJduVjIUQ4rXqjOGK6teiHMPPw4T61E8zhjwGv9LQI86iivDy9
         /K/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=L4r0vzLC;
       spf=pass (google.com: domain of melisssabrowny@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=melisssabrowny@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rRdM6wKEuT/QImKox3oFt+iy9kZes3PTTrLT9BGj+dM=;
        b=eGDrsT9CuMSTCCU+hPlsn89ABiFqHXkif1M3pQC5sobTFMnzZdG81qwwpcSrFqCK65
         tFT7chmge8cO8g76dK2I7TU9DvGv1ZXWVlV/wmbZf0XlPHbkP8vDleMAABz15n9aKRus
         lAw9riycTUZXeqO/RsPuLjhhdLS9Vfx9YN7KNdhp67Vfz0tSOg37q7lQFLVXB9Pt9E2F
         FejR5wgOS0ds5ZVMiBy+Q2YHU9MS1nJvwlyYU1EpgysWF+lDC6aom2umofOaDpDfmJV9
         SPcx9TKgGJNvmLlwpoAXeyMjHh8wtcREUL2LpUrF8dg0zDwumFf9Dq7OFsNF2OZtUA6+
         kqBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rRdM6wKEuT/QImKox3oFt+iy9kZes3PTTrLT9BGj+dM=;
        b=BoL13KD2QH7odTGk1L+I7uRF3q13Be4O8a8huACSomcizYCfobg1/GyhTG0XtNNlFu
         utT/dYEyodSl54SNf18qQK5XXWLEN+rh0e21/gHin4oSlu2wn9ssfV0FDaTvytW0vYfH
         JyQkhSds5USnxjZDMNSiq59ZHZ7L9XMsmqHoz5qfjpBtkgQ3I1W5D41tshiaMa3Vmsx2
         Ima7yCBh9MmxX9iRq5B7y5226M9ohKOi/Bz2tcxE+y7cTfWtlEwjH/Lz+V+AYrraDJK2
         LJvRkWYdSKC9FM1B6L/PvRtksNF49WJcd0i+r2msY/6sqwAZGtIsPHm2INKIpnRp+6zH
         uMhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rRdM6wKEuT/QImKox3oFt+iy9kZes3PTTrLT9BGj+dM=;
        b=aKL5pFqrZweR5SLulNAJmtUrG790qbJyAO+n87s2aioIOG3/LSGC8B87m26Pc1k4Ag
         53XToW9QUDMBs9In7YxkiykhOYbg3ulmeYJ1TVSCWP67swEVvMPfarcyiIQ/s1gtsF4U
         l2C3KbMLcUfu7Dz/HgPIQ1TddxLw4Ox6zr22W9rKs6dhDWmiEavs0j4TEqPEEfRSJabF
         Ka0aaR0opUirB4G31WsfH2D0ncOpxeOvoiLIqiJxRIRNlk/jXpaJ2WWxtOaQ44B43fZE
         ORVZ+8+IsMx4OJx1b+ez3YrNnWQhslGCscJwODybmOygFFyUa3HqmR+OdMSs+Lvtiy7h
         NZ4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9LUh2G8pJskli7IR2lCGn55xtVSgfhtBjGpg5/Ng9p8aGsG6rm
	TgX+YlIuYjBCQAfoxVkXqEI=
X-Google-Smtp-Source: AGRyM1ummGdeZ0WTffIpyhDVyWLfPLIwD4tSw+psDeQgcWtiKXv1f06+fXmmAgvkjeLXXMcYQRWKMw==
X-Received: by 2002:a17:90a:a384:b0:1ef:da60:9577 with SMTP id x4-20020a17090aa38400b001efda609577mr18149822pjp.36.1657829524763;
        Thu, 14 Jul 2022 13:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c86:b0:52a:bf45:ce41 with SMTP id
 a6-20020a056a000c8600b0052abf45ce41ls4789098pfv.1.gmail; Thu, 14 Jul 2022
 13:12:04 -0700 (PDT)
X-Received: by 2002:a63:cb:0:b0:40c:a2b4:4890 with SMTP id 194-20020a6300cb000000b0040ca2b44890mr8913251pga.304.1657829524029;
        Thu, 14 Jul 2022 13:12:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657829524; cv=none;
        d=google.com; s=arc-20160816;
        b=mEjdjgepDc5c0bJjhQjuYcuzXq3CoSF7S5OxeakOndb8pdNRge+gq88aOBDaJ74Tkb
         flpVIWy4DpMfOUp8LV/WQFigC0bFYaGqp1JxMtLGN37WMj5bKonO/k1h/dLWVypeiEyB
         ysM2t00TiUdroF1DffARS5RKYp2JbwEOOt3E8oJqTPhtzRqqheE4Cdez/fEsfb6wTFzO
         etopsD1zu48ZOEmO+UgehaB2/aeQcPjzJurlqfQMyjsuPuBXzd4Bi63qJu+Pji5z605f
         C72pPDhjz1bEdB453d57UFupYMUpC4o5N/OUO78yoHJ1tXnclYWPrXTiokSQ+mQ3HJsz
         +J6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Q/pknAYqgeJAo7cs3CnrcoQZ8XKD17mjj0nnNdrX3us=;
        b=gxr0qAned1GzcWvtZuB33iWLgup76G3H8nyhtfhB7UbQW37Pzoh3nizbv8nZEqH+7h
         7dCrhA7f22sVLqetIIdsPUT5P7wpl6I2a7mBtfpCa8mELKGwlN1lu2ZaPfwKqjEH7Etn
         4xikJiVNHb5gZeTp4masCGs6Tm+KBORC1+f+KRiCIlOjX03AsE4QHm1ftaEhNrNCvvY1
         huRAIDhpm26DYj2Bjhyu+hy3I7hcs0yY0YHa+Ekj3wt0wCylrtakHaTwbwZIVtRyHkmm
         lgg9xqlVbIBaRaQmpbzWfjsWzeAou6cgKBf11rgFzCGb9u3IYJ6A4v7YZlxqbDSJfS+9
         QxOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=L4r0vzLC;
       spf=pass (google.com: domain of melisssabrowny@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=melisssabrowny@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id mq9-20020a17090b380900b001efe7b9d808si110379pjb.0.2022.07.14.13.12.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 13:12:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of melisssabrowny@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id r1so1394372plo.10
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 13:12:04 -0700 (PDT)
X-Received: by 2002:a17:90b:3506:b0:1f0:81a:6477 with SMTP id
 ls6-20020a17090b350600b001f0081a6477mr17998986pjb.46.1657829523407; Thu, 14
 Jul 2022 13:12:03 -0700 (PDT)
MIME-Version: 1.0
From: Melissa Brown <melisssabrowny@gmail.com>
Date: Thu, 14 Jul 2022 13:11:23 -0700
Message-ID: <CAO5ge_WDpBj3-W8T+jUXgydhu_Qk+xufCteYht+_YGGsrHKZnA@mail.gmail.com>
Subject: hi
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000d7496305e3c98371"
X-Original-Sender: melisssabrowny@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=L4r0vzLC;       spf=pass
 (google.com: domain of melisssabrowny@gmail.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=melisssabrowny@gmail.com;
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

--000000000000d7496305e3c98371
Content-Type: text/plain; charset="UTF-8"

Did you receive my message to you today? Please let me know.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAO5ge_WDpBj3-W8T%2BjUXgydhu_Qk%2BxufCteYht%2B_YGGsrHKZnA%40mail.gmail.com.

--000000000000d7496305e3c98371
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Did you receive my message to you today? Please let me kno=
w.<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAO5ge_WDpBj3-W8T%2BjUXgydhu_Qk%2BxufCteYht%2B_YGGsrHK=
ZnA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAO5ge_WDpBj3-W8T%2BjUXgydhu_Qk%2BxufCteYht%2=
B_YGGsrHKZnA%40mail.gmail.com</a>.<br />

--000000000000d7496305e3c98371--
