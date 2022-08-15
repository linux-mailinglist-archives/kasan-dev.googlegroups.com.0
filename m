Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6W5GLQMGQEGK3K6BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7189C593277
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 17:50:56 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id q184-20020acaf2c1000000b003432f020449sf1818947oih.15
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 08:50:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660578655; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7uSihRjk2XN0sifcNEYWsfyhxqIq5aMPN+SdVLYdZTQEb/0qmpcsZDSunvPuKoDNY
         roeueo7vz4H56KM3gnLhKFgOJ8fnvloBiEIkUBBWaIRpMrbgVm1KVpqik3df6UrQomKt
         y8W9xDt5Z2MiYRHMfrLrnMKHpiXEnuTpwqM47tUIxOEOa0pJ6VyCr/+UyiTDfEadaqrz
         pY5NE7SjEKy3FqiznxdxnoCBVj7VvhdtNAdTjObmlmpPP2dQZbT0++0+YFjhWRExXyX4
         J7bhsd7iEH4ZJUBAx8dAzKNKv3ZiAa9vcUZ9ruusNHUtBGH8G+GHLkD/Bv9UyX0r6PDU
         lNOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KkfbxBdaW6f2P0e3QDI3ELPG0nei5LvWIZlqdk41O9Q=;
        b=GgHLZMEdrwVz5YgbxNssz9/tjb8zCmvQkq+vTyxVONFtB9Fu3+jQcdtSx8e4xYEPEd
         oQ2+FrLLvzOnqRR58IzYgLR8sTZDyyYcQ+0ouvHfKmJoV2uPQ/UxoNZpfh4mAJjk7XHr
         tA/0Y63tqgIZfsmBo4kxRlPYR42XyK2KFYOXaSVAhC4NUi0D8LdEzdari1LoIKkCf2IQ
         KVq0/t9gN6nDYHgBxSCN1B7TtVaRghP2AOmCo1HQlS+MNijmLK2U3+t/2+jw4C3paPtb
         qzzEQyEYRtTdozAEvoggI40KMOBcT6XKSUVcVoZ8OkzfeoPotxqxgZUcAMYZAaNmByjG
         mo3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SYh7xksn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=KkfbxBdaW6f2P0e3QDI3ELPG0nei5LvWIZlqdk41O9Q=;
        b=IjM0a2Dn+/pHTQSAfEWZxtxKzUa6sEDwNHC+Vl2Y4HYcWmmt9AyrL9vjNMYQXkE69p
         L/kedR+0DFeEfYJRVLlUVYz/qKb7M8wnfq/R8zt3eW93/mH26uWzJxUU3QeUggc23mhr
         O6ICVWbaW7e4R3L4sqHgpO7ED2AUsd5S5m58Mt19rGdJXG8PU/4tJzrcNYoqyV/3Lq4+
         eKwz4qGH3deoC1byZRME+AL9L6einYmxXbNipyz7agiOVLS2F4dy4kJ8Y+nkP0Ooo6M6
         CvHaiaryZ5v8g/DQMlgryDD0XXIY55UJB7r8N7BdlWI5B9sjbhKjt5ndjaOSXLGxWJOu
         0jsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=KkfbxBdaW6f2P0e3QDI3ELPG0nei5LvWIZlqdk41O9Q=;
        b=nG4ebLrhC5DPY07IZ7Z72FN1K9AAEpgoC0n5iwYvePhjh+Y02G6p6czzvABd0IzA0k
         6pRQdv6anIuSMK3QJ33Epdi98lnC9IyoXv5gKufMBLW78BLcEYgxHTm03V6nGMfdvKt9
         Cyf0Gm7lflmoOjUqiwNsfidEehTxVhQbpxS61SImipU6bqZh+GAHk49DpPhuVoGJp88o
         2giS+DIucIoR98wPWtsN55rWxHgMJmzk+ItZGrsudu6bOG5T7g0VJ/JULxj4IPay0HjH
         xcVr2IrutbyfAZDV9UmTYmNlq8tjrneEsGbJbVxAfLuu7Vkarsx/ZdAJMORbier74pms
         sfEg==
X-Gm-Message-State: ACgBeo2FGNGMCGpRvKDz8o866+No2JSLCxq/goj89mron97hW2BUkSzY
	Iiay1uumNjcMHGYrPHZY2ug=
X-Google-Smtp-Source: AA6agR4RQCB1OWmhIolYaDwPQlHutpnTX0Almh0sDjAMFyXp7zN262RAKqoe6/GI6Ce2TDYVWRra1A==
X-Received: by 2002:a05:6808:2383:b0:344:99d1:1568 with SMTP id bp3-20020a056808238300b0034499d11568mr2769934oib.167.1660578655286;
        Mon, 15 Aug 2022 08:50:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1c03:b0:343:2cbe:ad5c with SMTP id
 ch3-20020a0568081c0300b003432cbead5cls2781546oib.1.-pod-prod-gmail; Mon, 15
 Aug 2022 08:50:54 -0700 (PDT)
X-Received: by 2002:aca:da54:0:b0:342:f011:554 with SMTP id r81-20020acada54000000b00342f0110554mr6920076oig.82.1660578654833;
        Mon, 15 Aug 2022 08:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660578654; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9vIQo2nAICOa2HcJ9qcV7oZiAUD4LO9WlIUMo+zi4EVAGKN1+WC5H9MxCFKiutlFA
         kGtdSGOVJlp6wgsTl9xjEdlaL6jAuCLOx6nyuBpUIupCVDTFNnY0FQPPbwnBEsFkxof6
         uGBDUZkU/Wjbgc35aCQcnSTGOXsUBldeCUnSTd+Ww5mcgPSecnHN1AmHZzpvx7slf9on
         AePJBAtP8Yy1cbSi/ZBaYrqNe1hh6Gwx8oqLurz23RlSlaZXli+QPtwN2+Nf699Q3VjG
         To5PCVeBnJlGy/q5zpM0gv9nnOLFqe8l0yUhxbZFc8NKfxRtRABY+EJlNsvuJ4OyV8SZ
         FQWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BA5JxEWaiggh7rcVutkFHgo7MO5B5CEC9Bv0Dc8xyu8=;
        b=T7cX/LGqmiGDD7K2nV2tKjAcVkS7W61HEMLhKl99Fjr9w+6rOl37YMTQccJyvDQMv8
         QqsXjGeqi4z8+Ru5auX4t1dtuphOCwUwFHtLhMHgiBki2uZAt/a8MsYOx6QJR9O3swTI
         ny8M8JjhiV42ITIfxmIxHJnub2lVTLl6/awjc2uj8++upLgj6uDRFvZ3pxX5Ntleunkd
         B897NjP2HTR3SVz1qpf3PAgcSnTFl0ls3ZgOaA7Iav0nCt7Mn+Q8lsasnnYegQOKghqm
         98RmIiXMJEPRYpuT4R+2fLHXJLIp6VihS8vxW1EMtoQ71DIrhFnvegIxY4yDkqMiPWCO
         XMxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SYh7xksn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id a17-20020a056870e0d100b0010c5005e1c8si856212oab.3.2022.08.15.08.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Aug 2022 08:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-32194238c77so82892597b3.4
        for <kasan-dev@googlegroups.com>; Mon, 15 Aug 2022 08:50:54 -0700 (PDT)
X-Received: by 2002:a81:bb41:0:b0:328:fd1b:5713 with SMTP id
 a1-20020a81bb41000000b00328fd1b5713mr13705494ywl.238.1660578654409; Mon, 15
 Aug 2022 08:50:54 -0700 (PDT)
MIME-Version: 1.0
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de> <20220815124705.GA9950@willie-the-truck>
In-Reply-To: <20220815124705.GA9950@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Aug 2022 17:50:18 +0200
Message-ID: <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object search
 tree (overlaps existing) [RPi CM4]
To: Will Deacon <will@kernel.org>, Yee Lee <yee.lee@mediatek.com>
Cc: Max Schulze <max.schulze@online.de>, linux-arm-kernel@lists.infradead.org, 
	catalin.marinas@arm.com, naush@raspberrypi.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SYh7xksn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 15 Aug 2022 at 14:47, Will Deacon <will@kernel.org> wrote:
>
> [+kfence folks as kfence_alloc_pool() is starting the stacktrace]
>
> On Mon, Aug 15, 2022 at 11:52:05AM +0200, Max Schulze wrote:
> > Hello,
> >
> > I get these messages when booting 5.19.0 on RaspberryPi CM4.
> >
> > Full boot log is at https://pastebin.ubuntu.com/p/mVhgBwxqPj/
> >
> > Anyone seen this? What can I do ?

I think the kmemleak_ignore_phys() in [1] is wrong. It probably wants
to be a kmemleak_free_part_phys().

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/mm/kfence?h=v5.19&id=07313a2b29ed1079eaa7722624544b97b3ead84b

+Cc Yee

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0%3De732fEUf4FTmQ%40mail.gmail.com.
