Return-Path: <kasan-dev+bncBCT4XGV33UIBBA4V2CKAMGQEUSOGAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDA3B53730A
	for <lists+kasan-dev@lfdr.de>; Mon, 30 May 2022 02:06:28 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id a12-20020a92c54c000000b002d2f39932e8sf6410387ilj.19
        for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 17:06:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653869187; cv=pass;
        d=google.com; s=arc-20160816;
        b=V8MoOoNo0PJo6uIhpa3JpMoODRWnso2IaLlE2Hwz49msAujXjQ3ZS3v1YoTLCzo6ZB
         TZHzaIERNOj/e/BoQ3yEuy0K7VnLhmLvJRcbkyIjkN8bRsocN6K5ZUJF1VE3k89XvwWJ
         In/Fij3/InPdaSOfxaF57kesiGea8maZ2SRp5+XK3BHz1oBGdwhieXYcKG1LzXBtapc2
         9607odgBhjyPCiZHApDDl9FDVZB60TRvJieNNmCuSBoJ0MUP8v4isvV7flp6KbDlSc1+
         kiluzfsKLh3UAq+LO1uODgNw+Bzxix1ts/Rti0Ne8WcVWmWWlsk+jaklQFL8D1qDaAYB
         KZWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UP55tc/98rxg/KvWteVVPFJIxIw5ys+mBohsDKy2eP0=;
        b=uGsgYygzVBeVBRS0TpJhHbY73DT5ju4YJpVZ6SSwCci4o8qPUqkJn4I/AoP2hG4zJZ
         RD7vQefVUKR4IzRdQR+XUhGCe4oE3MGvzGtu9O8faBA9bxloOJtiJfYVmcYu7x6raBfi
         s6+Lc4n9uUKYUaHax1NyMYJcwKy/jM+r0Jf/dQobCB5yRPTb7mjrPmwDCfd7RawGZeu1
         4+pa5o8qwBWj6h3O3TpObKj7KsMBlWoD6dUJ5EWkbOgQJQ9yi2NhXnfsVQpj3YhRzEiR
         0WQ7BlLAyZCB19y+hiLUIsWxwakFfbp8OVG6/s5DsphCgScDxOVM6Gg69BWyvQMWeM9g
         G/Sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Pd7wVlI6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UP55tc/98rxg/KvWteVVPFJIxIw5ys+mBohsDKy2eP0=;
        b=JQALScJ10gkzkwERKWf5qQuZGniQ7M0mR5R7gXJZKziBCTgRBDkAz0fQbH1P0CmIn0
         4vXeNFWPBlEDM/UhnbOJR3S5eaUdtzrdipsKTwKmzyhf3reyVwJrLw7fzXrIzNeNvtj9
         RoADsWt/iPa6rdI65jPuZZ/lDA0naYC3PUj7N2O4/W3TqY7g2HVJ/AsmKbAhrKjK86An
         F0tSxcRUVgS7jch8QezZ3shFatoXfurN9c7f+f//eCFKbc69F4CuHR1D9FJMPzzGlhm1
         nIuKIPxdho7W/SS2WndGVDbR6jLuVuRyxL8GYHT3cWv8TQQcrEhDPe/jnFnkXNGrqzYy
         eJGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UP55tc/98rxg/KvWteVVPFJIxIw5ys+mBohsDKy2eP0=;
        b=TD1MjOdEACmbHBbdIO/syJVqxccFZYuApOcklSnyeYAXLZ17kYFTwZP2xKs57MB00Q
         Z08x4fwhEaAQklWDb20Et37oZI2Z2QJRMhogrZ7eHtPjXAib4/DDX3qhkN8insso+WJw
         5eew5/z4L49klQ6LTQD6fdBRBnyhtFfHpFy01Gzv/IrIoqYsJQJi6pZqvvLBIYw4DMYK
         ADXrKszrpUfoxreJkOUcVQWTiSf2NHjWikrK0tAiEk6KdLVLDVd/ceDcW7v2JF3M7Fag
         Q2naHeb/jjrV0UCdG00dV5fWs20vIZEbd/DSTbF0Uie578MhzOlcY6i51AHxwiwzq5Xd
         UCzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gZvZLB0VG8jeTkR58WRIy9UC68+2JnjQMsQCOfzG2QEJaKcf7
	N+0ds5+VOaIdVGa8VDwVWNY=
X-Google-Smtp-Source: ABdhPJy3KcnR0497KFO+ApgSDqE36CvmoizKSaQ2rVyv1Qs5VpeZ5o7vu3jVRyr21vA3xRcxrO9yyg==
X-Received: by 2002:a6b:c810:0:b0:668:5b08:4e43 with SMTP id y16-20020a6bc810000000b006685b084e43mr4823244iof.94.1653869187643;
        Sun, 29 May 2022 17:06:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:14c2:b0:330:a6c2:be6 with SMTP id
 l2-20020a05663814c200b00330a6c20be6ls2179873jak.10.gmail; Sun, 29 May 2022
 17:06:27 -0700 (PDT)
X-Received: by 2002:a05:6638:210e:b0:32e:b8e5:6a95 with SMTP id n14-20020a056638210e00b0032eb8e56a95mr20480829jaj.81.1653869187086;
        Sun, 29 May 2022 17:06:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653869187; cv=none;
        d=google.com; s=arc-20160816;
        b=CkXydKNHFShxltqP1TSIAyfGSyGKgOOXR7y8NgJ3s6aj0Pic4Mlusk/GNgNTXI5Mng
         owbIaebUjgHN/ZxzdOKhRMTEjV70Zs7dr3F4lydkwscI+v5TbCK1fxB7LNdoaBR53S+C
         CbUj/xJXXUuy9UdVXBBa4XV/1dM+TCV4EPa7R1AXmCi5RhTbOg+RSdNIbzb/lWc2J2ci
         KhhY8xFNlDfXzKfkrOBsi3yO1VFs8kLP/POAykNVg2IPe97smqL1LI4aUjALiSMxP2az
         xyIodg7MFRq/sPTbinF3/PcHAqEyttgNUUOo3HCoeXFdLDhnvj4E9cSFGYMpnLVh9tyr
         2T4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mT1I3Fl37Fkszm5PlYwey/4KQg+RDSh/eN7Z/0JYqjA=;
        b=RzA/9R0YiKEGakDxgZI5DdgdLe0Aoo2Ti0duZh/yLjHEvm/jPGyjr4wcNQWIQlKReu
         2vdNWqkEh0EcIKc0ZwGVxqZTRqI/0tBku1S4Qp17CwP0btGzyEpToWCQC4+jT0VSwAVK
         38nWoCPsL/kIiVyGx8tgv5KmCJrFgcHV74d8lXCZ3Ybn9A9tAVOYkKXN5wIzw3mxeXni
         XJnkpm8jI5gxmqC3QyfY8/q3eJwZTqmNQFw6kQZK2lCFw32VjfJsud77zyXuKxXDDluL
         dXCEuY+AIKb8K+xbzbye+bN/IvMSY7vD/hzJnzoEvQEouZfOF4SoaCOX7rsvxyCz2g64
         hy9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Pd7wVlI6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a16-20020a92a310000000b002d0f42d33c4si537436ili.1.2022.05.29.17.06.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 29 May 2022 17:06:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 92C3F60FCD;
	Mon, 30 May 2022 00:06:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 60065C385A9;
	Mon, 30 May 2022 00:06:25 +0000 (UTC)
Date: Sun, 29 May 2022 17:06:24 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg
 <johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>,
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, LKML
 <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>,
 linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] mm: Add PAGE_ALIGN_DOWN macro
Message-Id: <20220529170624.0ceefb52ffd2c4496cbe696d@linux-foundation.org>
In-Reply-To: <20220527185600.1236769-1-davidgow@google.com>
References: <20220527185600.1236769-1-davidgow@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Pd7wVlI6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 27 May 2022 11:55:59 -0700 David Gow <davidgow@google.com> wrote:

> This is just the same as PAGE_ALIGN(), but rounds the address down, not
> up.

Acked-by: Andrew Morton <akpm@linux-foundation.org>

Please include this in the UML tree alongside [2/2].

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220529170624.0ceefb52ffd2c4496cbe696d%40linux-foundation.org.
