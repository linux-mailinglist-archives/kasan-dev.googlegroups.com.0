Return-Path: <kasan-dev+bncBDE6RCFOWIARBMWGYSAAMGQEUW7TQWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 980F730558D
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 09:24:18 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id x12sf517916wmk.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 00:24:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611735858; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0osOLVXTv8bcuySM4O+pQGDxJpP8USWkCH2thBl2fqdL5MTgTUJodPgPgZVsf45GY
         XX4ygkbxLL3ho7WEuuNEAFqsOObsFYTnKcCcHgxPPb/h7L3zjw7ygY6XcG9AtSSVofzS
         A+VBO3S4O1IQbXMuErCWPun/K+Wcv1tfpIYe+TjdolOWdALtvfHdTpHXv8zLgKl2KeXk
         VVfqDFax5rQ1zgcbltQDl4uIFwoi75Fqn0Z8AjH4Mm8lPIWV5qEkuRfb6Yt6xKJvS/TX
         liHesUZYCfkMKo4ITY9EVz9XXg2ees4560UC8WqmtC0NjjU/e6c0Ab3txuCB0PbItFDV
         TIOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=UbrcR4cIyYUpOCKB7ZSUVDuaRF3u7xXxPAcWVZyL6zk=;
        b=EDrSMtpnJnsxF2Hl1xABLHrrOXyR9eJM+IeuYke5UA/l9X2qSgPGW40uVUd63QO2RW
         gazolD/tPgrMGIl838N6j0SOieYLjIuB1vORc3U8zyT0OKUzDiXWh9y54ZDL1ixkN3u5
         IVLqprv5b43FqACG3l7cDQvDqFJZECID90ra3tmGNlHew1qO7GSN5A2+8Hnk8vOGhloh
         /aEzQLTbnUFnFLYPLeSS6feaJ3mWmebZmBii6uLzg9s6rKUjAwx4iQ5nBB17OspvOCmg
         K1TsGCZtcC+nbZ4N8SLwOu3DjpO9GWeYnN0Lsjt1h4EwVI1+E1JJfATU/rKqwdt1LLOj
         oqKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=FA1oujPK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbrcR4cIyYUpOCKB7ZSUVDuaRF3u7xXxPAcWVZyL6zk=;
        b=sUhs8aigzFnQeAx+7EF+sHXPOYonmP5opwdWl56ANzPHrBoOy3cPvi+I+Ss4QRU4dI
         hJuA85fLqf7hxFxV1Bf+Ec4n+lTAgRUorSKGsUpesOYVbQ7x2jRvu3gibHxozlsGle4o
         E4rOzL/pZ9P+DQ2M4U5wixOAC1hSECINlI1jrkJacjqIWgKfbPXK3XY9u33eA7UJ+nZP
         4HI5k4FLNGLWe4cmpvYGTxFusY+hZwhFucuK4uEHVTt5fhgWibAA7nQCrUQNVL63XfeO
         yFyVVPKu0guVXJiWqI8kBhyms8WKxj1v21qnq1bNebdZKkt1J68/lVc0iD2RWFbILLXt
         0fPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbrcR4cIyYUpOCKB7ZSUVDuaRF3u7xXxPAcWVZyL6zk=;
        b=aBTlHt8KAphJnGkHfZfgbI8SnnzEMNfto/bdu7rS7PTRg3UrRhBa7NGjKzYwNuvYIM
         Ou9pXY9faK5SLIKTYL1brh5wTo7cbUWADb3IuQTbZFa1w7+t6QDZK7rUoPZf/ipLULXj
         9Q0J4v+VoI1VyfkeKOLpHxxCXbjSN788M+jEp/qYSdmGtSbeftEt5LJQKmkThPsHALJT
         Jh0J88NlHVs1vEtDNfc6CfMkudEBXMlIsTPrw8QgBBAtZ5FcjzRcpDfUUl1d7dKLp6ky
         epNJ42u8Vbdl8TqM0uN/lWbDwIR9mqcnC/p+WuxtajqvamSfrrO7UXOeA1nzcIV74bkM
         Fjcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533f+KH0h3Z3Q7rPkxvhzoSRp1OyWdPzS+PfGG8z4hSLSy3Msb1q
	C0ThJrzIPc68zLydaLrE96A=
X-Google-Smtp-Source: ABdhPJxbFWY3MCOeli0IXMGVg8xHG7B6c+JH5mwVJbuViY1yCdKAtPgSDWdXwJJ945cpInFiX2kSHw==
X-Received: by 2002:a5d:6511:: with SMTP id x17mr10125034wru.313.1611735858439;
        Wed, 27 Jan 2021 00:24:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4482:: with SMTP id r124ls515391wma.1.canary-gmail; Wed,
 27 Jan 2021 00:24:17 -0800 (PST)
X-Received: by 2002:a1c:6744:: with SMTP id b65mr3133485wmc.60.1611735857609;
        Wed, 27 Jan 2021 00:24:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611735857; cv=none;
        d=google.com; s=arc-20160816;
        b=fZR2HE2wSNPTer4TbR9AUGtPiGglNcRryXWmUEV7GaFQWBJqzZKO1fAC7aC5azR6c0
         UssdYrTkK9mr0RBcxpz9WtJ8V57lz1Wbimje9zLXegGPGxgvqb8JlUlItACck1kHGgZa
         mh1IyDbGXX2XeDKgmxfheVX1/O5ANLRKECMTCP2TLSBl7YMolVbacCaWaMea5gd+Pzna
         mmsexeRJymYzjEB75a6eBwXH+631wzk6A9xwVSM5X7qc0GuChN54eiisseKrJwIwmITF
         EVF+ytBghgsyb6ki7RYsypbZW9dps5wnv+0ndxOqLcbtWR1pm/4Jer2hFG8BPOE2trib
         Is+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M+fox9EIbHT1bM+NWJSO3LQ1cTkJqG7je2ZLDuI8gc8=;
        b=yjby56KnmSUv5nZLDXNJFAmofkRT7EC/aF5Ylx6rloQnkQ1UYDDU5T9yNqtSBwjfXf
         SqXsGzxsa1Iw51CZ9X6SJlPtahccgFNY6BUXdXuzw0aPgBx19MPvbWQy+qHy6USl+4aA
         ETqp1p9X4hyMPzSDFIDXhEigqDi9gsy6TuvS+1KB9Z/UaCdkdna3qxdm8e8IhVN5kfq1
         GLe6CU7eHl/CdAAyNcBJ2H/EdeYF1Enzwl1aH/d4qhpJjh/zYaSDATPldHqI5cnmxbL/
         wYE4FESq7Mo2M7HuO2flwzpLJKuax3ik01EchuK9f2PsQ6t5bSuznwoDTljMMcE6kg7d
         lJcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=FA1oujPK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id s74si81905wme.0.2021.01.27.00.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 00:24:17 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id f19so1071069ljn.5
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 00:24:17 -0800 (PST)
X-Received: by 2002:a2e:88c1:: with SMTP id a1mr5345669ljk.74.1611735857339;
 Wed, 27 Jan 2021 00:24:17 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com> <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
In-Reply-To: <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Wed, 27 Jan 2021 09:24:06 +0100
Message-ID: <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=FA1oujPK;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, Jan 26, 2021 at 10:24 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> I've set up an arm32 instance (w/o KASAN for now), but kernel fails during boot:
> https://groups.google.com/g/syzkaller-bugs/c/omh0Em-CPq0
> So far arm32 testing does not progress beyond attempts to boot.

It is booting all right it seems.

Today it looks like Hillf Danton found the problem: if I understand correctly
the code is executing arm32-on-arm64 (virtualized QEMU for ARM32
on ARM64?) and that was not working with the vexpress QEMU model
because not properly tested.

I don't know if I understand the problem right though :/

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew%3DHQdzHkw%40mail.gmail.com.
