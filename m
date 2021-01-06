Return-Path: <kasan-dev+bncBCMIZB7QWENRBC67237QKGQEQZIW3GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 3393E2EBDCD
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 13:39:41 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id w4sf1794129pgc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 04:39:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609936779; cv=pass;
        d=google.com; s=arc-20160816;
        b=hEzU6h4K80DSj4qIccAS6TM6U8q1/xC2RmdcSsbTcruW5/su6hDYNU/EjFwzAaWRPZ
         tOMgufBC+eBPUhLdJzrMEc+aO/beq2C5UYVuy6JxEEuxtekYS/4av/vg2ZpYkiu7E6bt
         L8FkJ24HwYNqNlDEAwXaUO6Zpz4pnrn7r/7NYRA2/4O3n2k3OAYfIU6QygoYZxwQqZEn
         Qx/f5UXlE30FXWyFkqlCvROlKK0dkEy+FxgDER/drSFL7DarNoaiTAqqupPc7KvUMJlx
         I2vXu+UB+IwCyz+c0W6mY0TV6RSWxOxj42qwZxzBnqEcNT73wrsWiQuVQMZGtIB30IKb
         VkGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4NVMW5h/Go95SMUiY3/ohrG3rNFRAT1eaIZ85ftySJA=;
        b=pV8LJN9nuVt9QnRe1oUZPIFuXFNpYtVbib3/MN9DUG2KQq8BTSiP1mrmU83JOMTfj+
         mHnhOLiJSLLNepDkm1fmXbYpbmbIePo3huY4Ai7+uqVQbQRk+WJasxf+jF3Ik3R2pm81
         0Q5uD6BOowGn3kClfNotuidYfLWFcHaKMKK1yFD9gXnV9KsdHFkpxIg1sO0/Gdey0NGS
         A4UMHM4bndvOBjpXpZboXv5m2BgKsi+Wywnz7fD+isoVFXzRNWCCS2tjvcfSoe2GU4P+
         +qNg3p+fyax8MP/01ZRfoTPqHO+6gp2wZM9FW2yoPSoUwzTVtANFB/0EdSe46Cq1P+FO
         VUqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rWvdH5qN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=4NVMW5h/Go95SMUiY3/ohrG3rNFRAT1eaIZ85ftySJA=;
        b=MCsAEFV/IqsF8ENxfKleM5xQAvaQgy2OFKcNHSXE4vxlJTtvQvq9jAsyv8glW5CsvX
         X/NSpGF4rLzcgMwZFdX4UOgnkbnYMFpI5FwM+Vu0HfZsBeuQgUGuvLFLroxTUeAjfRI0
         f1+IPlFGQEqAseogisrU2gGKlbkibDVKA5fgycQZqCU4iP+WYHmIDCHkFAAoQ1Ged57U
         Qrnbh5ibirVTfmmCb0szIU4AcXps4rxPC1UEsJeMgYNt9mTnfUeVhs5d9K/a3m7mp6AJ
         HnOBmajq7YMfPHKMq9UoU614r2+Ac3outuuqOZGTyWhSTv8EHnwQ2rVgn1NWH4NTb3Cf
         nohQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4NVMW5h/Go95SMUiY3/ohrG3rNFRAT1eaIZ85ftySJA=;
        b=K4dPGR1i3RCzDyfM0EBGV92uug6WdVvJm5jvbWYAd9D/2ee+ANLvWEV5Yw0wxS8NaV
         Yhl56d1dMshY0lWdSx6gEI0vLZLAt8IoUY+bU0XgmKAEC3FnVFNUyQ72G1ndIyS3vg9B
         QQca/9uPR8fgkjxR+NlScl5VLmx5qqVgZQq+ss/F7RN9mP6JBECNGdh+rpv7zXnLBhz1
         iyKJIE1b3RM69LXJRST/2E9+jyjK7RCtj185U99kGQx7ECFN5ib/QmjrUD5RjFQnlDag
         YIlknZfNiV4uo+mziwrVzDjSdKBUxqA0IRk4uPw3wH81N5/YhJq7DUm+SLoL7EIH9AZx
         08zg==
X-Gm-Message-State: AOAM532hI4eGUdaApxnGjMrlqFLR2OABuy787W9jlibb8EaBObE0Pyjn
	IEFZl93YFnFER17HSN0K6V0=
X-Google-Smtp-Source: ABdhPJzEEUQYW9SK+NDvUBTzT7/wjFzCko2JzwisvkOhIlgSuUyVmlDDQTmkjJjb1gUYuue2fmOGxQ==
X-Received: by 2002:a17:90b:1811:: with SMTP id lw17mr4164910pjb.105.1609936779488;
        Wed, 06 Jan 2021 04:39:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9155:: with SMTP id 21ls1107046pfi.3.gmail; Wed, 06 Jan
 2021 04:39:39 -0800 (PST)
X-Received: by 2002:a63:5642:: with SMTP id g2mr4357619pgm.434.1609936778916;
        Wed, 06 Jan 2021 04:39:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609936778; cv=none;
        d=google.com; s=arc-20160816;
        b=wcNm77XAiDRn8koWqo5ZPDbpSRtal/NKEJEgWR+uV2l50AQPvfj2hlzoXe/ENUnbrQ
         +U/DsBag9L+9vQNeaJHQmaLk/Tzej2LuVkH4FKkQOtlkQuGvyp9LTDwm6uINw2dNEGpj
         ECSIjZKbQ174zmeDCs5xurg+HYJxD8T44tc9Bmf5pXO1SZgPbRv5tgcmvAZrnEfD79Oh
         LVSfEIMDIu866hROufWuv8YLrFfr/LUHKn61EK6goky8rrr/t2XIod1TlMp+RcNqw6cO
         GtNXPVfrdAdRJjT++8aF7peehzwmEDmKsPS1b0dcsnvJKavIKTZ3aRUaPqN0F6jDfYFJ
         LArQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QNyfZBknDK0tJZw5z2xlghVq7+//yDSquF+oYZKyhPI=;
        b=E7wtqWroVj35Y+uYRQ+ZA7FV/lZtjPJtOYJRUyFL6ZxpZQdAcXZ77M1NWjNErJ9RkI
         o5IYN8hwu/Zv1/gibHe9GjS/0XkddndAo/czusRET3xWhuInwIac+1oBIRwnbXmHOUYv
         QbjLqVQDEeQgzYDwGBNNjhweLmMRueTCCEWkzywURL6OzH0D0vIcomAHTdhBHUPJdlC8
         VvoXf/sE3vApHCNsRtisao633p1XkEz1/2Z82uj36w8Ijl3s/BW/rxXjsWYMWZ3qUHrN
         m4FUifhgWYRK0BqK+tD0a8fF7EJFlaMwFPubsGQiu4oTJqdWLuc0uaeUd5wYNMrPPpdQ
         Eblw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rWvdH5qN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id b18si157109pls.1.2021.01.06.04.39.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jan 2021 04:39:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id d14so2216535qkc.13
        for <kasan-dev@googlegroups.com>; Wed, 06 Jan 2021 04:39:38 -0800 (PST)
X-Received: by 2002:a37:9a97:: with SMTP id c145mr4016102qke.350.1609936777919;
 Wed, 06 Jan 2021 04:39:37 -0800 (PST)
MIME-Version: 1.0
References: <20201206164145.GH1228220@cork> <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork> <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork> <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
 <20201209204233.GD2526461@cork> <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
 <20201229174720.GB3961007@cork> <CACT4Y+aAuJexS9o0Vct--v5WX-a123OfcuKmYKgAEUWxSbzd5w@mail.gmail.com>
 <20210105174810.GD287109@cork>
In-Reply-To: <20210105174810.GD287109@cork>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jan 2021 13:39:26 +0100
Message-ID: <CACT4Y+YNA1V11fUeEODv-Wye8V--f0+Gi3D72D7qnD1NptwN6Q@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rWvdH5qN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jan 5, 2021 at 6:48 PM 'J=C3=B6rn Engel' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Jan 05, 2021 at 01:57:58PM +0100, Dmitry Vyukov wrote:
> >
> > This is awesome!
> > Are these bugs public? Or do you mind sharing at least some details on
> > these bugs? E.g. type of bug, affects production, would be easy/hard
> > to find/debug otherwise.
>
> Not public, we have out-of-tree drivers from vendors.  One was a
> use-after-free (write) and would have been exceedingly hard to find
> otherwise.  The second was sscanf reading one byte beyond the end of
> buffer.  I think the buffer was smaller than the kmalloc bin size, so it
> couldn't even result in a page fault.

Thanks for sharing. That's interesting.

> I suppose coverity would have found the use-after-free.  We just gave up
> on it because it took too much effort to work with the vendor and deal
> with their copy-protection scheme.
>
> In case any vendors are reading:
> Don't try to sell us gamification.  Sell us something that finds bugs
> and is easy to use and we will pay money.  And to most developers, easy
> to use means something we can invoke on the command line that generates
> plain-text output.
> Also, everyone is incredibly busy.  The time we spend dealing with
> vendors is time we don't spend fixing bugs.  So if you cost us more time
> than your tool saves us, you lose a customer.

Well, first and foremost, we implement these tools to use them
ourselves rather than sell :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYNA1V11fUeEODv-Wye8V--f0%2BGi3D72D7qnD1NptwN6Q%40mail.gm=
ail.com.
