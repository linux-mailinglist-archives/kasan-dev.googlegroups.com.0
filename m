Return-Path: <kasan-dev+bncBCNYJDE55YMBBCHD3SHAMGQERIOJRWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 525DE486986
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jan 2022 19:14:33 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id m9-20020a05600c4f4900b0034644da3525sf429226wmq.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Jan 2022 10:14:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641492873; cv=pass;
        d=google.com; s=arc-20160816;
        b=SJvu1Yn2S8aITn5m3o0kcPYqdELPlL1TbHGvC753StQiq6OfTNETu2niiXoNYlcEg0
         X670B4w9GIEMiI41qI44936XdO80o6mkRLU74HqzGklB08VOoVef+68tcHPaj3AUiz9N
         ApxxpdjPKjXlutft8ggqR9xLirPYFfA1INI/KL4qeIduSFkyUEpsa5LnTQkNpPeX4Bpd
         s8Lfem09PHVuilE4o3u6SwQSihGerf7NBns9RxVkJFVf8PU2qApyTYJmFXvB87OP3sxH
         2CYVbkuSqcMKC5eziNZfN6xQP55ntC4Bl0Knqg9f0SwN+KTKmbAEsl/84xX1Ze6Nvq9M
         hVtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=9ISGFjVVkjcmn4pOucqPkujL5wKT/i2+x6borXiPkeY=;
        b=zmZdCUQ5xziTXuJqNl6QT13ZyduhrqjHagE9gfZabjP0Q+y88G+Ofpat/K2sTrdBTW
         AmFAB3cM99iyRwWRkQzmY7XLgK05AhKPT6ukNsCUGEG4ZSLvGG9HiLp6CuUFm7i3RFd4
         kNJ0dtObTlAfBSUGj/F7c2NBWvfQ7vWlnCOCZ+rtZAPWO17wbY50xwPmiAVbH7CYyC53
         Fi8Y/lH3IUEdnIVlXqW5S0p1q0Ej+S3i6cm8yqHCOuI+w0xcSElXHxoW2ZpGrjNMc9g7
         0+ybZNiUZbL/hqoe2g1DGS1eoXy1BhncvUh/wgKQFU2zO2/6AjSx1OoRBefv9aCuUec9
         3pkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PjppqNcD;
       spf=pass (google.com: domain of j06217505@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=j06217505@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ISGFjVVkjcmn4pOucqPkujL5wKT/i2+x6borXiPkeY=;
        b=FJefIkNcTMOdk1+ylm9LNAiE13PrzU6EHqxgsdjW7vIjSUDQIo8jJ06drV1HjLZ7+n
         nD527/JvRSbnhrn1aLoRzqjApC+8rWCOn8aMIbI4QACOAfTYes6st/LffithMqjzliKm
         u1YkCKWaZNhhXO0qUz3EQhYlgy1TaVzL+cV+54+mIsgxFdkI2vSWLTkwIwhKIxkAzcGC
         X9v+8u+uzwsbocuvo9fyqNdapNZmVXUzRoY4R6tDEnKBxBDB/TuF4C+GSpIpHSsqeH4o
         hRvQ/TbiFLacSZYNwD/0tEqQIcGku6wMp8DWKyLmtbbu38QB34aJTQAWgcWefRvPUUkr
         ekQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9ISGFjVVkjcmn4pOucqPkujL5wKT/i2+x6borXiPkeY=;
        b=UxhXm9izf4tUK0CiNi3TZLAf5FxkIwHB8hH2lRuqD5KZQKAOl8Ln8tLoRyXG9EtYdG
         swkj9gRmOu8egRQdTIyLwANuJKkpqpKSQua+82/YgyIVkz8HULocS0wZBT5DRNMOZGZQ
         YYM6/DtPFYj/H7B3PJt8lhhMAbcNTjT56WcIgqlBylu8ThKhBU4alUMm6UxekFgq7Fno
         lND/H/o6l6h8kFcbKmJw3gRDnFjPQPMwgSV0/hUIyD4TlA3s7llGgLaORDg7vbD2tgL7
         Ls1p5s6mDlPh5mu8HUuNT+Y/ETIQdYfqQVC6EtkTAjkbOiIhcYj1z2WpTTje/iuKPOMC
         rMHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9ISGFjVVkjcmn4pOucqPkujL5wKT/i2+x6borXiPkeY=;
        b=Fkdx37m531V5LHalZe5r+DJCeCFOa1D6Oy91lKYEEB7fuv/g32ooh2BwufoBfgLaFn
         KehGE401xnnBSx4Fo1QQZCzUpGr+gsmcF0cYp+mPwXAK4eqt0lBzOZtp1YsZaaQigb0Y
         czqC4rFnQ64uH6ru2PjPcNs9DXA1jPiLHuxqtYGzlzPzbJciDP292sR2ZWKDEVzD5R5w
         OAiNP6vYNlRMrByXnI0s+vcEjMztffOnq9WuxjMgQ4R4zTm7r0ENE0ZiLSMfdYXFIEJH
         wQYwRiAe73iCiHycbwlZhPqp2WU3zLrW0gZ2iKMH5t4NQyFqQoI7E4dqwRwyaD2wKd86
         Syfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532absNmp7bwdL1ZAm080tF4PqQ9GF85z0agU+6OgsqAH+2HWcr8
	dITQ+P+zsZP96KNx5fRrnT8=
X-Google-Smtp-Source: ABdhPJxQhrRTaNW9xSbmXMt5VTSbed0204u2nri6JF8c1V/jgJ/4RkNIo8/y+maSFXVsbdVshekUbg==
X-Received: by 2002:a05:600c:2f97:: with SMTP id t23mr7010113wmn.85.1641492872982;
        Thu, 06 Jan 2022 10:14:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca7:: with SMTP id k39ls1100378wms.1.gmail; Thu,
 06 Jan 2022 10:14:32 -0800 (PST)
X-Received: by 2002:a05:600c:204d:: with SMTP id p13mr8282261wmg.102.1641492872049;
        Thu, 06 Jan 2022 10:14:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641492872; cv=none;
        d=google.com; s=arc-20160816;
        b=fc+I7XZhMuWcnirYMo9jXnXnHhiHg1WC9VNeGSrH3dD8wnieicwHznABBBxP7WsJ/x
         ylV0NunVkezPlRV7CWivh1Sz58SJUo/6cvC8wUzq25ykJNpWPUEV3Ua6Tt6dNd/YAe+d
         EBCuVfihmHEUYtpzXhO2Ea2y6R3qWOmHQNfkwSuGktFVjha5FZ+qPutjG3YNi7OCptaT
         axtZ883K85lkj5VfWnHfszOP8oPh9l1TXeUGHC+2E1atK6yRMxll/tvz5tlWmkERHdRz
         ChqoHG8WdgVdPrOAWVQ5h1CPZ0oMxbDgXc5q3C3Hgi7ngcXy7rx0L0/rzYi5rhnbHev8
         Dmrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=mlQyVMgqKnYnqXoH/L9izR6919IV2jHwSd0sK4wxqrg=;
        b=V1Wi+79Odh/IubEssEa87QLUjpMGo/VWsgKvUxUpRyQAjs6HbeK5ieJPwwe4zoZnUg
         j/fJMunB8PxG5HYHN1fQuYx84V6s8ygzPUtCGYzmv2AKorML9rxMhCU2DIdxZ0nMzJDd
         bXWUXJ2nNMKFg7VyBPLD7+vMizhD5wAr14nMwmzV4wIc1IAjvo50g73rIEdI1DviVqAS
         LmLqweRqr7iYbQU+H8eg5in42CHaXXCugM66S51nlTXQ6k9gIrH7QCw08Recp09/izv1
         sfSSkVCxomV71vLKlIB869T9m3P/uTCQ6sYdoq4eNaGSbgCNuyIX8Jmxc0Ako4I5naOh
         2qdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PjppqNcD;
       spf=pass (google.com: domain of j06217505@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=j06217505@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id o29si298665wms.1.2022.01.06.10.14.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Jan 2022 10:14:32 -0800 (PST)
Received-SPF: pass (google.com: domain of j06217505@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id h2so6678381lfv.9
        for <kasan-dev@googlegroups.com>; Thu, 06 Jan 2022 10:14:32 -0800 (PST)
X-Received: by 2002:ac2:46d1:: with SMTP id p17mr55166187lfo.578.1641492871847;
 Thu, 06 Jan 2022 10:14:31 -0800 (PST)
MIME-Version: 1.0
From: yacine  8447904 <yacinebeker88@gmail.com>
Date: Thu, 6 Jan 2022 19:14:19 +0100
Message-ID: <CA+QAkA9PTpRded-PXhpwFihdq196Zk1Xbz5wqFEezNq871VApw@mail.gmail.com>
Subject: hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000087230c05d4edd79e"
X-Original-Sender: yacinebeker88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=PjppqNcD;       spf=pass
 (google.com: domain of j06217505@gmail.com designates 2a00:1450:4864:20::12c
 as permitted sender) smtp.mailfrom=j06217505@gmail.com;       dmarc=pass
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

--00000000000087230c05d4edd79e
Content-Type: text/plain; charset="UTF-8"

My name is yacine can i talk to you

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BQAkA9PTpRded-PXhpwFihdq196Zk1Xbz5wqFEezNq871VApw%40mail.gmail.com.

--00000000000087230c05d4edd79e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr">My name is yaci=
ne can i talk to you<br></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BQAkA9PTpRded-PXhpwFihdq196Zk1Xbz5wqFEezNq871VApw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BQAkA9PTpRded-PXhpwFihdq196Zk1Xbz5wqFEezNq871=
VApw%40mail.gmail.com</a>.<br />

--00000000000087230c05d4edd79e--
