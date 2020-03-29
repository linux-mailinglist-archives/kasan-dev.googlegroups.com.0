Return-Path: <kasan-dev+bncBCS4V27AVMBBBIPDQP2AKGQEZTAKHEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F79B196F9C
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Mar 2020 21:06:09 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id e10sf9117397wru.6
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Mar 2020 12:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585508769; cv=pass;
        d=google.com; s=arc-20160816;
        b=D/itjjfVoRk2EgTCdJZPT3LerK0B01hKTPg+iU21mq2wrg7wff3V9xtVxOXQmnzOyy
         1emLlhTYw9maP6nyPv3GBBpLPGAznb1DtM6Cr+ooFGTh5HYUGZGMxkM0eOw8dnqnqc3N
         6mxd+HgZVBqAqCPhEJH8OOS/CiDy9jzpTUnhk9zHMj94YgztEESeMJKH5lU5uFqTA1zy
         mqYvN7syhFnMlnAIrxBnStZTDM4io8Y3ESqRxp3BYTJXPNmDtO5RD7AxwFj/6UB0Z/8g
         UgLdT5BwT7F1NDOxWCaSlbXNFkcJ69PWVrO99//NSnccyV9t/c2U4l+3Cr1YQB9cO1EB
         abmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:thread-index:thread-topic
         :content-transfer-encoding:mime-version:subject:references
         :in-reply-to:message-id:cc:to:from:date:sender:dkim-signature;
        bh=ALy3aaHnP6Wm2IMkgfvNIvM1h+s3y9OKEVCsYMx2M28=;
        b=owWPmvzIz78rngEueK+GoYpTrOquEB5BQ7tDTVRgtbHPcuH/h2/VeBk/eIJPkOwMpN
         nqv9VQ78v0YNWQxgyny02toCZ9ZkjRRvcf8zRfZkYUK6GOwkwK8W1emf0yiOEjJwm5He
         srGLeXM7fLprnxTlStJzTk2lKnDKiM7Ndc2GAFMqyJJVUgqwz9RTXXo/xa+Euuaq0p3x
         l560CWGs4PYsxE3BWOVU/AJG69lKc8Nx6BNt/C7BRtLZIhyDuNnS4DDzf04VXapXjhZl
         Q8qZsJ94EAWOgD3iGMzFpl8ug07ltFF1oOyMd8w5N2vdufPtS0YzDpKHaE0vagkfotbi
         63bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:message-id:in-reply-to:references:subject
         :mime-version:content-transfer-encoding:thread-topic:thread-index
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ALy3aaHnP6Wm2IMkgfvNIvM1h+s3y9OKEVCsYMx2M28=;
        b=YTiG4/Lf1CLIO7oZPeLWwW67OlxFBTu5bwPA1AtBPdffCgZI2EYF+0xFCG/hzz0YhY
         8SEOR33wwbYL4VFuPnzllOIlwtQKgP5BxhmWWcxBDJhZfMOfxLw+9lW9MHWPHNencrfU
         CVSgK5MhdEJ9XwYVzpJWHgZ2o2UdDUfRednzQMDCb7sBRfAIJZmbrMOiEjklQaxxxiac
         aC+PrlRglNqYKBqkE8sZXH+ZLSudjBQoL4lRc8DpNNRgtKZMDIq4aW4J7vbIphVYlz9x
         lXh5DdWupjAXTnB2CczETbZ1JQsiX9nAVvEE3SpeHelZ+4y7nFUe1uJI15xSVDtri/ZA
         Xs/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:message-id:in-reply-to
         :references:subject:mime-version:content-transfer-encoding
         :thread-topic:thread-index:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ALy3aaHnP6Wm2IMkgfvNIvM1h+s3y9OKEVCsYMx2M28=;
        b=VQ6Xr41ZxOAF3G64V2Mj4KuXQc7FkA5W3YCPwUSJCblxxG4BCLaexxWVyboiFeJk4B
         PfT2W0yJK72zk5BFVEdWuHLhiD06X0RV0thRT51iiLCbHZjs12BQYK5CvpiM7ZaFf0Vj
         DAnEnrzCNPB8/lnk4Y0f994v71DI8lQUW9NZVapybNDcd1ZTW8/s2ujIxfv5zfByWl2Y
         Bn44P5ja73GomEIBYpAfZ/GI6X04siPheHDsZmX5vJaT3bFtjYMYK3ru710D7tvjsAex
         do04IStosAWK66ALyvqd97fm4yffYSggYXL7uwOcU2S4bv+YkbaVJZqYgsOexqRhnC+w
         /6iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ030ZKR76Op51CA0nqtLfOA4MN7iKvUOTaDyChVHz3n6rlUfQkU
	nunJIUOkngrapzD7id7ZFJo=
X-Google-Smtp-Source: ADFU+vu494x9vBCcSomyvDSlB2JJk7Te9SYHtlvm65RRatbymA/RHCR9PHzy3A9jzSgMWa0NQnUvqw==
X-Received: by 2002:a5d:45d1:: with SMTP id b17mr10467675wrs.111.1585508769152;
        Sun, 29 Mar 2020 12:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f5cc:: with SMTP id k12ls7236399wrp.6.gmail; Sun, 29 Mar
 2020 12:06:08 -0700 (PDT)
X-Received: by 2002:adf:ef08:: with SMTP id e8mr11574253wro.66.1585508768558;
        Sun, 29 Mar 2020 12:06:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585508768; cv=none;
        d=google.com; s=arc-20160816;
        b=acc8ioMBLhfjBATrWbgYkAcPSgVyU7ddYcG1Y0/aai2S5CucNwZ/BBCRnJ9e9TNk3C
         Ho562qpojU1xQO2UtnxdCm6JZmSvtSM993myMfs3bkrY8jcIDtL/c1CFwZHa/kuisyDg
         7vfa1PvWuuVZy6izeJgHzxoEegYYKbokhR5IU7st2zsupd20Au0N4cLBMeD/9G5rOZBI
         cR/wPwKKLmepY0m3+aDQShRRcJ5036xreMskrZtO+BGa3uYHFChCgoSucjhIIDqt3sEI
         dcCiSAvSmwplgKkKvK12owGXqJT9qZd70kkwduZLzHqevfZi1hs4x09kBd90Jo4GH0Im
         zlaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=thread-index:thread-topic:content-transfer-encoding:mime-version
         :subject:references:in-reply-to:message-id:cc:to:from:date;
        bh=fhDCoxdC+5sp1/p9OuSG6lB+Nx1u5aU6bXUm+odV2TQ=;
        b=Z8uuuOg0yeGNbqdhkl4KPzJHY0HsMUC13GYRw9CC+0L1+OdUhFmccGsr6bMZxttdLD
         VqSVAwSlXPhvnJdZi4HC/CLodW/zFipl1d17n97oglCpNMiyFaCR2AuwZTw/mOHrAf1+
         kyK6Y3ql6mD4FMP38i7xg8uxdSkFxFjh9k2DHQ4g5X+4y6Z2YQOU7gEtJzrNf5Quufx2
         3H5exj9BAOIdYze220ubpqP/vFVPHrU7kRSJdlSgTOgaEmf0XjGr6QRQRTIlQ2/TkZYl
         QjsBN+mA1a149Xz8yk5Cdm6Ewge4cffzU8MIpGCt9W2iX80l7xfG+gwZPQjHNFvQ5+Cx
         uCDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
Received: from lithops.sigma-star.at (lithops.sigma-star.at. [195.201.40.130])
        by gmr-mx.google.com with ESMTPS id y83si406964wmb.1.2020.03.29.12.06.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 29 Mar 2020 12:06:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) client-ip=195.201.40.130;
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 251696094C4B;
	Sun, 29 Mar 2020 21:06:08 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10032)
	with ESMTP id QJ2GV9CvNgMe; Sun, 29 Mar 2020 21:06:06 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id D9B5560D0873;
	Sun, 29 Mar 2020 21:06:05 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id y4bO9EX9EtU0; Sun, 29 Mar 2020 21:06:05 +0200 (CEST)
Received: from lithops.sigma-star.at (lithops.sigma-star.at [195.201.40.130])
	by lithops.sigma-star.at (Postfix) with ESMTP id 8D17C6089320;
	Sun, 29 Mar 2020 21:06:05 +0200 (CEST)
Date: Sun, 29 Mar 2020 21:06:05 +0200 (CEST)
From: Richard Weinberger <richard@nod.at>
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	anton ivanov <anton.ivanov@cambridgegreys.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, 
	davidgow <davidgow@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	linux-kernel <linux-kernel@vger.kernel.org>, 
	linux-um <linux-um@lists.infradead.org>
Message-ID: <1606942453.56384.1585508765254.JavaMail.zimbra@nod.at>
In-Reply-To: <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
References: <20200226004608.8128-1-trishalfonso@google.com> <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com> <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [195.201.40.130]
X-Mailer: Zimbra 8.8.12_GA_3807 (ZimbraWebClient - FF68 (Linux)/8.8.12_GA_3809)
Thread-Topic: add support for KASAN under x86_64
Thread-Index: efampVW5tmWSwSdm2ja8syshwdMa9w==
X-Original-Sender: richard@nod.at
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted
 sender) smtp.mailfrom=richard@nod.at
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

----- Urspr=C3=BCngliche Mail -----
> Von: "Johannes Berg" <johannes@sipsolutions.net>
> An: "Patricia Alfonso" <trishalfonso@google.com>, "Jeff Dike" <jdike@addt=
oit.com>, "richard" <richard@nod.at>, "anton
> ivanov" <anton.ivanov@cambridgegreys.com>, "Andrey Ryabinin" <aryabinin@v=
irtuozzo.com>, "Dmitry Vyukov"
> <dvyukov@google.com>, "Brendan Higgins" <brendanhiggins@google.com>, "dav=
idgow" <davidgow@google.com>
> CC: "kasan-dev" <kasan-dev@googlegroups.com>, "linux-kernel" <linux-kerne=
l@vger.kernel.org>, "linux-um"
> <linux-um@lists.infradead.org>
> Gesendet: Mittwoch, 11. M=C3=A4rz 2020 11:32:00
> Betreff: Re: [PATCH] UML: add support for KASAN under x86_64

> Hi,
>=20
>> Hi all, I just want to bump this so we can get all the comments while
>> this is still fresh in everyone's minds. I would love if some UML
>> maintainers could give their thoughts!
>=20
> I'm not the maintainer, and I don't know where Richard is, but I just
> tried with the test_kasan.ko module, and that seems to work. Did you
> test that too? I was surprised to see this because you said you didn't
> test modules, but surely this would've been the easiest way?

Sorry for vanishing.

I read thought the discussion and it seems like the patch is not ready,
right?

Johannes, thanks a lot for pointing out all these issues.

Thanks,
//richard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1606942453.56384.1585508765254.JavaMail.zimbra%40nod.at.
