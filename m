Return-Path: <kasan-dev+bncBAABBQPXZLWAKGQE4V6TKVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A99BCC2BF2
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 04:36:50 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id w14sf8407693oih.19
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 19:36:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569897409; cv=pass;
        d=google.com; s=arc-20160816;
        b=n7mxUfa6fNhW2YrW860GhtUBbzCthPa6p9n4ugk7ZjbbdpbeI0hRHfqCgN8ux0rm+o
         mrRkhO3+ajRyLCvL4TOoS9fBg8u6JpayxFKJVS0dM0p/6xit3Nb41wUwU0TuOWY65cPh
         /mDW6j72QLIE0opOAkAkA3kH++gSQm7URTbWuVr+x2Eap1Hz0QIc4YGZChjvG1vHTcvB
         uciQnmb2w1G/DSuk/mM8eTkho02cL/OpwGF+6khXmfHu+tvqiRybkFldU4SZC1NHkGK3
         k9dYd84EFsMT7btRifVQUbNmjfIgenlkOIJIhYesto/JPatGw2Ton94bC6SNKuIpaqd9
         VSYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=t5RPl0F+WBVK0JIdXX1QE1g+oBKXY4IeKkXM/ysBSBQ=;
        b=XzMSqRCyA9+vT5Uuq+JSsc9KQQIil3aX7G99zLO4XiKY+rjjTSARj0Wcx9ijsDP/lI
         2moXJVf8G86IzOY807cRdr9gOiZ6RMvNjGrBzpSKpuahAEraVsbMtuZjZMU846PAcp5b
         XlrPVdu3gSLMvHiUm9pLKpf/p6esn4KueOEg47lxW9Eq3353qaOsVrapQEe7LYTlO1nS
         aiJGwN9pny83XmYtrNM0NxTUwPuD/r5QddDUrKaSrxA0XHeQdQpCnSJgyrCLyybzPBuD
         b0lPGXU8wVzbM+Ur6dOGgx0gWI+gQgV+xBQ+1fhLL4ZGnhEWngyXEgBxruEnEA6f3ggT
         TN/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5RPl0F+WBVK0JIdXX1QE1g+oBKXY4IeKkXM/ysBSBQ=;
        b=eQlDE01Hz79MHEk06Ig2nUB3AdgpxODVkf00avkGpHKaeix4nAeO5oESEUe6q+gP7s
         iNO2Zdh0tpj//Ke21wQVVUeEgqs0iGN7t8QSrNc4NpzEzWFmy9WiP+HtlSbNuGRp/OAC
         DmicuIIRy/MvP/kiRiNkLjo6LJKlgH5iUZpQHu+B/of5wLbs8j2xKQotdq7cXZ9jTD/s
         G8D9mgYytnf3md4vZ0gDxL3usZr8rmfZrrW/yLogURnmNZyMw3iIa7nSNuDxy2CBtE13
         ZFoZzCXGUd6DAfpa0vLua5hBVxFWrPYPt6g+0xrPt+mfzjezuhp2GWRxnPandzzBh6nC
         xmsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5RPl0F+WBVK0JIdXX1QE1g+oBKXY4IeKkXM/ysBSBQ=;
        b=j0YYdwgFh+FpMn4uMESgFMrsPYpuBl0zp8ejpZpKQvNBKduJSF9GtSAFY1rOfSF5HV
         BIT5MhRrdndXKY5J+sH5Y6LYSAiukmRFvz8KE1WSkuVQ0XtetCNUfjOaV4yyElMdWW9B
         yxubqtBNnFm8XFtvFrTmqpZhEZnCgP1BT0QWcy1wHhopS8O+8GdzaYez7tKP+qCQaMI6
         sC8Pv+QcM8tkX6aq7w3ydSR5urmIxpZZeTKfdQVzbZpfKO3x6Crja7PIJNgJazdYKBHD
         v1FBTKCyzBhYEzNDuykD69WxJ1pA8yp7r3EFi8YFKt431RCZz1lLWvV9d28MupXQ79Xi
         Ertg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUs/Ru9p+BLE2cat1bwFW/fU2Kks7vGhIuZRLcHhgT2ae2d1FSD
	wIDcaxVg845XkqleGu0x8po=
X-Google-Smtp-Source: APXvYqwn8nRTeIcKA7qwqB8BJ1qSH+opxcXVnIjZoqzpFmU1qbYxuBmVkeeg9mdMWupN9M4dYUwaOA==
X-Received: by 2002:a05:6830:18cb:: with SMTP id v11mr2808784ote.364.1569897409364;
        Mon, 30 Sep 2019 19:36:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ed43:: with SMTP id l64ls2882948oih.3.gmail; Mon, 30 Sep
 2019 19:36:49 -0700 (PDT)
X-Received: by 2002:a54:4f8a:: with SMTP id g10mr1865009oiy.147.1569897409107;
        Mon, 30 Sep 2019 19:36:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569897409; cv=none;
        d=google.com; s=arc-20160816;
        b=lICSOQm/OP3IhzyrL1t/ZbkJUi2zHIKAYNkPMokET45WijcnP8fRpaXISht5BzTTEy
         cFEdOw4ztcSOY7OeK4PSuVSb7pQnzbgYlxJFxP8X8Sn++qpTQnAlFHVsGEwSeULK24yk
         kiIILu0TQ0Ggz3TVLCo/WTGBL2pdHVa25vQglLbMMLfpyODavi3tpCz0uokhl+gGbo0Q
         dsT4W6UZmpDTiGd5bawbfXrMZ+ZpOPPUgyyN0ac8OC3jLX3OPS45M02/YfunM2MWfizJ
         9j8sBqgTohzHU7eqLyqCzIDSin3TJ9lreV7JxEkvZHT6QRhQg8BUF+fQ9Ay9fe61ozSv
         3Hqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=+tKCGMMnGbfCJEgvBSgNc5tNekozb+vQ4ndzEOsuXBg=;
        b=eHMwQ9MIraCu7aPKb51QXJX6prM6HKQwiD+efza48uco3eWmnjU1ytPebpsCfOlR2g
         aRR7TJ5cpUKNDYikME+woQfZe7UX+owtUbboVYYdIl+h33fHlg3H5KbOY+RR7bx77Vmz
         ODRFaxdva5cRXtaQ5DWU5QWDxOX7QN756UzHYlaMLZmLZuCPPtt521xs7tyvrMZvd52j
         sZM9YQ3lW//dL8POTT+//aeawwDUfnOZWVNwFGxN8vA2i2mcsnqjHytBwURSKt+ttpW8
         YOVYZOSTfIdOx3SGVznn5WQDnanowxZwh+Xx3/faEY86MWnF91HXLuMHJnuSmZbySRss
         IBqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c67si713192oig.1.2019.09.30.19.36.48
        for <kasan-dev@googlegroups.com>;
        Mon, 30 Sep 2019 19:36:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0f9e666b914a42c581ca67844efd6fc6-20191001
X-UUID: 0f9e666b914a42c581ca67844efd6fc6-20191001
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1273433479; Tue, 01 Oct 2019 10:36:42 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 1 Oct 2019 10:36:39 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 1 Oct 2019 10:36:39 +0800
Message-ID: <1569897400.17361.27.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marc Gonzalez <marc.w.gonzalez@free.fr>
CC: Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrey
 Ryabinin" <aryabinin@virtuozzo.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>
Date: Tue, 1 Oct 2019 10:36:40 +0800
In-Reply-To: <a3a5e118-e6da-8d6d-5073-931653fa2808@free.fr>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <a3a5e118-e6da-8d6d-5073-931653fa2808@free.fr>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 30DA4FADFE5493A2DA7970C7B5D1BB63117B8C3E403BB8DB2EA5B42E8CA9F7522000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2019-09-30 at 10:57 +0200, Marc Gonzalez wrote:
> On 30/09/2019 06:36, Walter Wu wrote:
> 
> >  bool check_memory_region(unsigned long addr, size_t size, bool write,
> >                                 unsigned long ret_ip)
> >  {
> > +       if (long(size) < 0) {
> > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > +               return false;
> > +       }
> > +
> >         return check_memory_region_inline(addr, size, write, ret_ip);
> >  }
> 
> Is it expected that memcpy/memmove may sometimes (incorrectly) be passed
> a negative value? (It would indeed turn up as a "large" size_t)
> 
> IMO, casting to long is suspicious.
> 
> There seem to be some two implicit assumptions.
> 
> 1) size >= ULONG_MAX/2 is invalid input
> 2) casting a size >= ULONG_MAX/2 to long yields a negative value
> 
> 1) seems reasonable because we can't copy more than half of memory to
> the other half of memory. I suppose the constraint could be even tighter,
> but it's not clear where to draw the line, especially when considering
> 32b vs 64b arches.
> 
> 2) is implementation-defined, and gcc works "as expected" (clang too
> probably) https://gcc.gnu.org/onlinedocs/gcc/Integers-implementation.html
> 
> A comment might be warranted to explain the rationale.
> Regards.

Thanks for your suggestion.
Yes, It is passed a negative value issue in memcpy/memmove/memset.
Our current idea should be assumption 1 and only consider 64b arch,
because KASAN only supports 64b. In fact, we really can't use so much
memory in 64b arch. so assumption 1 make sense.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1569897400.17361.27.camel%40mtksdccf07.
