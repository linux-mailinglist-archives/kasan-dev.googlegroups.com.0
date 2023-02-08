Return-Path: <kasan-dev+bncBDEKVJM7XAHRBQXRR6PQMGQEK3OKYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id AB60D68F819
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 20:32:18 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id i24-20020a0564020f1800b004ab15d934adsf1146610eda.23
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 11:32:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675884738; cv=pass;
        d=google.com; s=arc-20160816;
        b=aTul5K2RSmE/wGKywGBYpybp3vFHrOGIAxa6D/ZG3Eb8jL9mpV8HkNW994fjQwmqm8
         ANB0O8NDNxAFvnBePQpAAzVt8K3cBOFoo3K/uSpHGYQaZQi3wct0m2jc5ogoVMQezGU3
         fxeIvF+rMNT68bTAkbLG4srRen5g5GwVMt8a/0FXsfxOTphr6hyEwbip5GupNPGcIq0G
         V/7ICgQkvDKwYIG01iIx1tF2xDxlcfGEKPUzaO7dvtyTK9OPVuUNg+erFIFqcWpeOeO3
         EvyZx4SPJZUIo7rmtNmH27HN/apwEDcCONfbYxs036NOdM1DiBy2xkrl0F7JXizHHcWS
         KrcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=SWTae0rVDlv6dVZr5GHJxPosLKbqq0nDrk6T6iIsNag=;
        b=yuYJ0wX3enI4LEnbPjFssJgsH+8NGkpKN9mPEvg4KJ5Bayxz1P+o/gEAbPwAnDflHu
         uP0/+RRAMMpKG4fTpPaKTtzbX1MoQ460H+ZGwv2vOdbW8EIqM/eg4w5CO/HtjjUI51kz
         GsEKmCcU3liioHfeuVXlCk1Y2/Mvuf+9Q8jbJh73nXYgZ1OWXkcVyrMMF64GqOiDWK67
         P6UWnA40YxDYxjTsZoxHJNhiZRIHNCxJMV/lb8pyGekh2MwPMtut0A5rv0nGJ+cPbDsn
         V5sMh87nDYs6X6/aIJidgMzhXcabyu1KSv86CHMAS4ix20tWE0FBDHq7bh2ygeMM01HO
         70Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=gKMIAaKc;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=XLiYR35H;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SWTae0rVDlv6dVZr5GHJxPosLKbqq0nDrk6T6iIsNag=;
        b=UHohB8oAzAxgrQT8U3PnfjFgauU6v16QUZZZIeKmGxwCExOuJxSGVr4Xippl1k1ips
         i+T/BJNq/c1FpJQfqNXwCqOr9MKKg1ibDYZf+JsWdzW5A+b5dtusuayxBy4zR6yJSAa9
         tPteDFZW5ISBxdp+oYBwWJQcr4paAWqKs1IWeEgCxOztcUntdEI9zU99v+PJ/GDh5eJy
         7wV2wb0ZRR72stzg2SHY4SDOeYXmJCUQUyFGUcBMNGB79E4U5rVcDFCNFx9QVnsCDU+s
         /AyFdHF8Zb/Gohr8Te8I9SuwuAvX4TYllE6uzcphUWxjBsL7/Lo2wTA79WgACFl3CE8l
         v0mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SWTae0rVDlv6dVZr5GHJxPosLKbqq0nDrk6T6iIsNag=;
        b=woBmdKFiswaARPl4GWY7muA4mNSNds0neE6iqVmMjxmCpJ8428/OSdTmawPAzejxMf
         pJNTUbVIWM18lzaUvI8V9SqUARFBfAp9yfr0+gneo6fZ7idbtxmxtToc2h+cvqRQNM41
         IsZTcjKOKMh2c0UMdOvSF/dTC516crh3DeWTfeJRcyWH8uekEs6MPhDCbmwPCBVmvels
         pcDwbKKECMiSqdBK3CYM+6GCpR59f3AZEYrCUQDLYRyreJYZ8mhXLzQa/pbOisR7wu4L
         tp6L50cb76WktxIL7nrVbIpb+shNowhhBpp+jKx/T4yQVPcDY+ysu25AYGNKe4Cl653h
         iMAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUNUFJIpuYrvcY7lNesOYBbtj3c2ZOjIuPDrezYlneMxgmgKehh
	LNLmMjcsC+FI7NJ3+PgHwDs=
X-Google-Smtp-Source: AK7set8yzDBFpefPITq+osJTUAu25zTQDIq34j/iYNlFv1z7DNZ0Sskv0Qzr0jkCEHPPRL0jDHnhrg==
X-Received: by 2002:a17:906:1f46:b0:886:520f:15c7 with SMTP id d6-20020a1709061f4600b00886520f15c7mr1930140ejk.208.1675884738201;
        Wed, 08 Feb 2023 11:32:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:e707:0:b0:4a1:ec52:2ed5 with SMTP id a7-20020a50e707000000b004a1ec522ed5ls20572971edn.1.-pod-prod-gmail;
 Wed, 08 Feb 2023 11:32:16 -0800 (PST)
X-Received: by 2002:a50:9e62:0:b0:4ab:1736:5e03 with SMTP id z89-20020a509e62000000b004ab17365e03mr485078ede.19.1675884736749;
        Wed, 08 Feb 2023 11:32:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675884736; cv=none;
        d=google.com; s=arc-20160816;
        b=dzUpUvD43851eS0+kHoPpR6gknwXDaoyauPZ2Zmq7wGe/r2MJSVSj6nwjG/reG/nAg
         bhhqQv3LiWQCH2Hl1fYpwixTnwk3xDXkcJNbeeLeijxXzPA7u9qmsLspQg20rKXhwtSB
         lQBfNV/MkbKpeg4twBpTYfZVLJ7iVQc6TZ/37VqC4UsQenGxkiAMnWAr4UcMRpMuau5T
         zOChrZlYC/+dPzR4UkeLVoSaCfimL6cjVaGzf2WbbXMYuFw3F9uXhUDXF+zCghmiFXby
         R4/a/aQL6Yv6YrhsckxIZZybqVWZHt6ztTuJIKv+KuqOwiMahvM5nwXCW9AYmRGxix3H
         Fbtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=0Ww7YIi+8SzE/Xk29Ed4NjK6FpaU8TbVKXVoUGQbitM=;
        b=UU/qcCXU/laxd+Bf39vO5U2U2jKHSXSkLG8+buYFJ4XG943aSqKjDfXB3soE5QC7t8
         Jk3I06ONyjvP3wh9KA7OO2B6IrIil53CLrQ03dmHZL5mCyYe/SfXAniedCBDLteqMDvB
         552apCctwHy7qRkOnV//1wQT82lAVSUb6MMZJQKZAf3VEGZgijSRJ3vaDzFn71Pxw7E3
         DJQ2P572VsJy16N4RGoYg230rGQR/paGfPk5nx+bZYFK63hpw2KK/gcnN2JfdBpz38RZ
         qF9fDLyaK+Q7eatX3UOiJw/rp0Nx2iCTh2rfL4UVv3t2AgvFfoROuIhjCdLBUQGxZ3sW
         76RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=gKMIAaKc;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=XLiYR35H;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout4-smtp.messagingengine.com (wout4-smtp.messagingengine.com. [64.147.123.20])
        by gmr-mx.google.com with ESMTPS id q14-20020a056402248e00b0046c3ce626bdsi882563eda.2.2023.02.08.11.32.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 11:32:16 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) client-ip=64.147.123.20;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id 2FFDC32004AE;
	Wed,  8 Feb 2023 14:32:14 -0500 (EST)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Wed, 08 Feb 2023 14:32:15 -0500
X-ME-Sender: <xms:vfjjY5Eg1hdqVcmvOVVeGWlCVY8z2Q53HC_owr8EGqh8tzMtK3Y1YA>
    <xme:vfjjY-U_EJPYwu6baP2Cnso94SV8adNDuNvpEqWDeK3dTTIA47vMQ8GXNEhG6GLcA
    _N6yYVSxDTB8EohZNg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrudehuddgieefucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepffehueegteeihfegtefhjefgtdeugfegjeelheejueethfefgeeghfektdek
    teffnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprg
    hrnhgusegrrhhnuggsrdguvg
X-ME-Proxy: <xmx:vfjjY7JKz6uULfTO4hAbSXHDHiGB_sE9l7NEKpuC6F1p4KV0_qd7MA>
    <xmx:vfjjY_ElWuERIAJPPWJxfCS0qvE-RJx23SEdrUuCWrfc-XOYyr2TSg>
    <xmx:vfjjY_Vx6CW4igWk2c6vconYp9IobXIF27hn52FaeXxswCF9blsZWA>
    <xmx:vfjjY4NrU4T61TPaCOAyigKl_HZdKvyhX_JSmlOG4XEeDT4iLL0F4g>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 8B860B60086; Wed,  8 Feb 2023 14:32:13 -0500 (EST)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-156-g081acc5ed5-fm-20230206.001-g081acc5e
Mime-Version: 1.0
Message-Id: <7a62bc92-e062-4d33-9c3f-894b49452f1c@app.fastmail.com>
In-Reply-To: <CANpmjNNYcVJxeuJPFknf=wCaapgYSn0+as4+iseJGpeBZdi4tw@mail.gmail.com>
References: <20230208164011.2287122-1-arnd@kernel.org>
 <20230208164011.2287122-2-arnd@kernel.org>
 <CANpmjNNYcVJxeuJPFknf=wCaapgYSn0+as4+iseJGpeBZdi4tw@mail.gmail.com>
Date: Wed, 08 Feb 2023 20:31:54 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Marco Elver" <elver@google.com>, "Arnd Bergmann" <arnd@kernel.org>
Cc: "Josh Poimboeuf" <jpoimboe@kernel.org>,
 "Peter Zijlstra" <peterz@infradead.org>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrew Morton" <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/4] kmsan: disable ftrace in kmsan core code
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=gKMIAaKc;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=XLiYR35H;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Wed, Feb 8, 2023, at 18:00, Marco Elver wrote:

>>  CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
>
> That means this CFLAGS_REMOVE.o didn't work, right? Can it be removed?
>

Ah, I missed this. Adjusted the patch and description accordingly.

    Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7a62bc92-e062-4d33-9c3f-894b49452f1c%40app.fastmail.com.
