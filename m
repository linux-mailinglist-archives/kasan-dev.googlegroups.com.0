Return-Path: <kasan-dev+bncBDT5DNMSQELBBDVIYKEAMGQEFXSYOYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D84793E3DF1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 04:33:50 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id o4-20020a5d47c40000b0290154ad228388sf4830886wrc.9
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Aug 2021 19:33:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628476430; cv=pass;
        d=google.com; s=arc-20160816;
        b=jUuB8WCpA48xfzj19FygRdQVfm4tuNKHJ24cyQVdMXZvIHR16oGU37h/DfkDLID45z
         ohnNPMzAvPCaBrwk2A3id3LFJY8w4hCrIrimukzrsRjdqWWPvY1uK9yDOJlzNBycYQ5n
         x5+1/CD4JYmtUTt+WxRjJLQyi0O6rk7lbbQwSxuceOXRlKIcRhe2PmQ8yYU9/yINT7JX
         ShiheCPKVQ35/pj+9RDVawB60Uxrem+FM15Yqj3Xi+RS48Ha3PFZ1Q19USbw7rZe8ZG6
         jrpmQx2QesZZicC+M4rd8YaFmaLacZ8MYwCcie5lj3kdUEZfhmTDDPS09J5uI91iB6iw
         PBIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=mRPSw2igCiQsEauhQGOVke8/doWlJhWbXA8FVqrEfS4=;
        b=0EA2Ew6zbZRI8Yf4bcm8sdUQoMg/KUdVwxLSAlhMsSBCbLSU7lUEonf9YpneHgeVwP
         Gr1ypp/9Ws4AazJIA2LJfyGq2jbZpiPv1nPb1egtDcbdgIzPpo8kFFuBhUGoiyR/CFzn
         XWV1TZDwBB440zD+02gYGWSFnLLykmTzW7Hv2/jsY60k/hWq++yBoAiy9t0yLO640lwa
         J8XLY93TV+aF+QYKtLhQx1wf51TXgwlTtBLquGDxbJaaWo7S/93zfV2A3d/Xg/AlZYKT
         q9PgR+cnt+VYs1Ev/wyP3w8Ie76jAHJhC6eyhmL2zS0OMaY43UJXFns1H4QOjp4TVAPZ
         +Pow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VV01BZej;
       spf=pass (google.com: domain of edwar22032@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=edwar22032@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mRPSw2igCiQsEauhQGOVke8/doWlJhWbXA8FVqrEfS4=;
        b=ZlHb4I+oTPLoMMxALmPS2KCEhG1T46zx2HngPL67rNEgkSA2aTRy3Q0JLX+rDs/dWM
         Se5Yx3/qebwuzfkkV20gMznPvwo1Cy3ENwfcvQtc677lmaOFGpW3p2LpAAp2rguNqqS8
         04AVo/jGgyXfBzM2yuQAth5jkpuvmH/CsAVv9qFe/4f3p8mjavMJIItIQvoTYqWXPgwZ
         RJuAzKa+YTGejfjL7PrlCS+TMH7xHuQDMFY8rOp/YP3NvLZsMpvQdvHfoiLGAXFtLjir
         VBESn+T0F+arETGl0Ykp3pa4dNUxOuLhL8bmtEBOB/AHdd3Ea68ILtNXzQTRmgs+2QzE
         H1Rg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mRPSw2igCiQsEauhQGOVke8/doWlJhWbXA8FVqrEfS4=;
        b=mcU+vA2gNfx/otJjQOF70HyI2AQJc6ezLfQN3nHDuzheSeINcJW/xShVFeFFT1Y/qw
         Hq27L5Twa+iffPbD9+/7xaIphZUOBjh4A8k7VnpODqctKyb6GfPFrkHEo/mVxgJCSikZ
         tkm3UjlPoxM4Y5S3LhVr/oVhHVL/BCdo3EclXrm++crA4DbQbbTjoKuD1pZ5a/pGExWW
         IbXXmcFXNmFA78tazFZh7Ju17SWs9eAQ6zTxu4C+5eB13mv6oaPpGqtQdRBBgYaha2Ok
         R91vXZv4AkHx+fzVlFty9ygpykKpXyKXMFArjBj7VaNbF8n6djLj6QJhV9NYpICgXfUO
         qgdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mRPSw2igCiQsEauhQGOVke8/doWlJhWbXA8FVqrEfS4=;
        b=BDiaZAsr6FG3Iqp8e509fQ5HUZ7YGCXTwMI86qRGrmHaGDBnmGG3Jjyx2Rg4sz+Mar
         c7gUczcTsrh7YdplzH0cMVR0/8oqY494EUh3UOt//OfHp9Jz/QjjxYa5WgMbjc3sinkY
         AdHfcDfMtY+qR0a9DCnx2Awnp94r767tt6uhwgwGV9anxA3vIx6/3x2GrbTJCBIJxMra
         gjgxcxZWMsQFqtAxFT5tJeot3DamcOmyPnZ88C/1y5lzfDbuWfsmE2HppCR9ziXwqtmG
         YOYn3d0gzPl1qPrQifRViQ8GWXbsD480qysgQY+p6Bd4SMfKGYWB+4Lh0/oR+SMxwIZ5
         kEyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mGni6haAhEFSJHNm/jpktZPnQNmAf/jf3A1kREa9/bfLPSgiC
	taQnoET3DT7Akl3znPNLUk8=
X-Google-Smtp-Source: ABdhPJzJDY4R0OpgK1JnuC1de93yNnxc65J4iltxObeLmSSimKEjP8aPnSYgI/yCvz4O6vx0xEX4JA==
X-Received: by 2002:a7b:cf13:: with SMTP id l19mr32238233wmg.134.1628476430552;
        Sun, 08 Aug 2021 19:33:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c8:: with SMTP id 191ls9397312wma.0.canary-gmail; Sun,
 08 Aug 2021 19:33:49 -0700 (PDT)
X-Received: by 2002:a7b:c106:: with SMTP id w6mr1074898wmi.152.1628476429704;
        Sun, 08 Aug 2021 19:33:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628476429; cv=none;
        d=google.com; s=arc-20160816;
        b=n4h7gX+G0qcjslW41JMvU0Z5dF8hs+bJkbtuvcQZ0KfjIhbTxpDjzrnIFhzH/GAshB
         0Dm835ouSyavOGKDCVzoGjbPZXcJbOtZ2dIPt5IZxUkCMNbpBVuxjNYtBzAItbtyScjK
         5eWKWJwjOLLsju1PwW1fMthsCJW9YT/6aro3NpH0MrrNw8R0M5GyxIK1ebmbIFFFpZuj
         obnHaRe86lpNZF0kUpEn8RTmrG6F5+zj1LX/jwpkhbi0l/v33852i6++dnrVPv1ocipV
         /82LERtnI5TPhkMAyjAwS/froXCvV1K1nYbZ5e9/dZuPjdLintMKxdN/cwMT3sFMvaWQ
         aNog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=Mi/biOcCcrRDGimhAa+hwKsahhgZjGMOt2r2KVQR9d8=;
        b=vPN4pJnt1LWotMF3FMLI8G5CVyEHm8wa18ZYegtsnXO8Jej/eRiq0R/4/W9TLWB7Xy
         pF9FI+i+EDDxxqKsYYNauyl/apuo4111F3Le3e02N0/0xNWOkRiaD+fTmDzVcB2xdysN
         TtK/psvh9we0bEUoBAReU5ymf53rnijLUune9ZcRfUn9T066nzzKrieQi5bxgHLDOvwq
         PvIKuWNM9AQoSMo39zyE0xrhZtmz9wCwdnSJ62a96KUGNDFIDxf+93Bce1DYMOtUGp3v
         l+UG8ZXLmy0wDllWN62CCMK6hhUasAKFVSJpXNXsJlzAFAKowQknzDpW0HM3mf4/PAy4
         PbrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VV01BZej;
       spf=pass (google.com: domain of edwar22032@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=edwar22032@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id c26si858464wml.0.2021.08.08.19.33.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Aug 2021 19:33:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of edwar22032@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id d11so1912746eja.8
        for <kasan-dev@googlegroups.com>; Sun, 08 Aug 2021 19:33:49 -0700 (PDT)
X-Received: by 2002:a17:906:4156:: with SMTP id l22mr4893668ejk.75.1628476429315;
 Sun, 08 Aug 2021 19:33:49 -0700 (PDT)
MIME-Version: 1.0
Reply-To: chusakjaidee2020@gmail.com
From: "Mr. Chusak Jaidee" <edwar22032@gmail.com>
Date: Sun, 8 Aug 2021 19:33:24 -0700
Message-ID: <CAPnzuTrxdtb5uPfcxuu0W_wd1RRJQ=-DJ3EWrosSUHvq+XzOfg@mail.gmail.com>
Subject: Hi.
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000018394205c917374e"
X-Original-Sender: edwar22032@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VV01BZej;       spf=pass
 (google.com: domain of edwar22032@gmail.com designates 2a00:1450:4864:20::62b
 as permitted sender) smtp.mailfrom=edwar22032@gmail.com;       dmarc=pass
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

--00000000000018394205c917374e
Content-Type: text/plain; charset="UTF-8"

Hello,
How are you doing today?
I sent you an email yesterday, did you receive it? It is a very
important message, anyway reply back to confirm that you already got
my message to enable me to give you more details..

Best Regards.
Mr. Chusak Jaidee.

Sent from my iPhone

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPnzuTrxdtb5uPfcxuu0W_wd1RRJQ%3D-DJ3EWrosSUHvq%2BXzOfg%40mail.gmail.com.

--00000000000018394205c917374e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div>Hello,<br>=
</div><div>How are you doing today? </div>
I sent you an email yesterday, did you receive it? It is a very <br>
important message, anyway reply back to confirm that you already got <br>
my message to enable me to give you more details..<br>
<br><div>Best Regards.<br>
</div><div>Mr. Chusak Jaidee.</div>
<br>
Sent from my iPhone<div><br></div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAPnzuTrxdtb5uPfcxuu0W_wd1RRJQ%3D-DJ3EWrosSUHvq%2BXzOf=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAPnzuTrxdtb5uPfcxuu0W_wd1RRJQ%3D-DJ3EWrosSUHvq=
%2BXzOfg%40mail.gmail.com</a>.<br />

--00000000000018394205c917374e--
