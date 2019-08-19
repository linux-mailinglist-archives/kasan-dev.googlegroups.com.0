Return-Path: <kasan-dev+bncBDEPT3NHSUCBBTWB5TVAKGQE7YSDR6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id BC6F2950A5
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 00:21:03 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id v134sf3337005pfc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 15:21:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566253262; cv=pass;
        d=google.com; s=arc-20160816;
        b=KqzY1jRVoaFqKcUXPcSg4R6Nv5Y89rSsppjbw73sIZboS6Q6xWF3ee7MjoTZFF+O7B
         0D1pEoUmENaWl48Zjfg5FyRSaqbEnql6X3yWtkiV31XwwUxKgmLBp4e/mCXf5qSRg/ua
         8ogg5lAn3tf9/+s6JzycLuujH4ZTFnsHPdnNMtHn0MWt1DZsTNM9M/zQE+Pm2Or28Yn+
         UhKYxOIzsvBDeOcNKIFeS6I85ByNX4lo5oRhJc7hs1qTkHQqxQZ3I2ULIBwVe1+nWMXH
         CEJztjGncC67oxPSpIwgChPbjxnhUJr0zbzQpkbU92Jqzwsz60GjHCGczkdUWQqdoaIr
         0i+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=k8DMD/TZVqibYjP6+tfCb/UOWk/nK1XGniYIb8Z2y+g=;
        b=CHuoPpTD8CmOes/cB+H43ZHoTUQ9JuyUWdJTV3Y7cJWiTJ8cq1b7RagWn+ok93Zcz0
         qnoBIJHkTsVDpmDv6vF3K+4+wMUuKNApv/5i636DSWfad2D0oVc711OAPYefGjS+USuN
         qwjwJvP5uDFNZlIH0zi6x0vKvwxO5eEpJbb8rZX4aV2341ne5aKubuLj0XZzmhObmlp4
         b0V/nkYmhw3zVtDOmDrW4fINUzZaKUl2W3eRRa6X35fZVLS1ynjaCqzWP3aiotRg7VRD
         l/1uNj8FwUZuq1TVkrpF0E6b9cEq+fJUbJ9z3fs+jxR5PCLlV9dt1l/nhuVgrPyDT4lR
         96dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="XGcvD/0M";
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k8DMD/TZVqibYjP6+tfCb/UOWk/nK1XGniYIb8Z2y+g=;
        b=B6ajxbNzyHoShmYUbKnsigu9WFesa+L0dUM2vkfhetEvAMBaE5X9u5R9WUI9T4KiWy
         8meOhKmbOyWf5eetXnO6zFejzWkFrBhFZw4XHmJy59nKuWt0idvcY1TbyEKRdWuGKCdB
         cptp+Na1Ie2x6O0eRc2o/0WpHjme8pWXf0frpOSU6UAmZ6BTCrES1CoHipT+DyqQD4kC
         J8fJiYgdBHaOK5Sdq4bjhdyGrhBWx7MBQ/Dryia+aKBcrIRB+n9zcT+SXvEpJTIxd7+J
         MbPFk34VLiEGfUY+YzLfY5mgyH955q/nkSAz99bAzo3XHhwIE9lPq3FNym7wQgoTln4f
         8mAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k8DMD/TZVqibYjP6+tfCb/UOWk/nK1XGniYIb8Z2y+g=;
        b=Y0nbhN0Ax/Im4N9Mruuv3zH+vOv0bJghsR9SKhWQMbg+ZttPyFQhfU5P6FBeaJqnMT
         YU1F5mP6xVv3mslBQppdk1MYeoWKkMHZVBu5wYXtnVBpjz4hWZR0347m17OqDUQbY+L0
         jzXLYacL/iEDgBZUIQvOZ+auLHwph2ZFusX3lEaA/1NoyzsM9zmtuiS/XVAxLh81pp2I
         Pef/zKC3xk73h/d8Vi6OUfiBG4xBb7LBWDo2arDQ/XNNeA4JcVbdozfKFqUre6bRO0DT
         OTbbnUiF8QnKcBkUXpTXQVCoPzm1cZjEfjRUfQGYFpjr6NZ5fghuS6ll4JgKST8eOLD9
         ONGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV421dAU8Rp1sg8/k3N7P5cRmYXo0xWHNpxN30fn9vwsDQGyGvL
	ezVHZtuiAC17NKINU2DoMPw=
X-Google-Smtp-Source: APXvYqz+dntkiuGg6SlaoKnTf2X/RTaudoiyaFULog2PjyVpocH64ccXUZ+GGnecvzwrbrkcr+C0jg==
X-Received: by 2002:aa7:9483:: with SMTP id z3mr26730306pfk.104.1566253262222;
        Mon, 19 Aug 2019 15:21:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9e81:: with SMTP id p1ls4298129pfq.2.gmail; Mon, 19 Aug
 2019 15:21:01 -0700 (PDT)
X-Received: by 2002:a62:8344:: with SMTP id h65mr26636008pfe.85.1566253261930;
        Mon, 19 Aug 2019 15:21:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566253261; cv=none;
        d=google.com; s=arc-20160816;
        b=VhVYbxYRgNwWO/FUji/ROfnsZV3xg42vV6jtZvQT+tPx63zX84WW77s0HnBfktObAO
         vJymNC9u8XHk7VB/0cYqX1QvVyZHLAHKTCtHBUQxDKKZpRR/7g9rqaW76+vB5UtkzKDS
         qi9LeXT5CEaZEUEkS7J7ZzAg48gGpODnz5XhW78NrGInjE7UtnP8OsltrMsem3BQ4N6e
         A79atAdUeY+11aPfKP8XF2ld3kMmGACfG5DL9yvXjrK8fCIsuqg9necCzPqL1uE7Ujci
         Cc2VRzyBqil+j1oF93Qcg7Bp0ZcYniZb6LInGooMEOjP36M5lV3wGygFuMToBnkKQ+5l
         GzVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KR93Nh2pEVTQXskRCcRNJG5EoMuJxb1LL9zdGmo9ev8=;
        b=P1ntQRvh00sZJQ5SX7apKm9pi25ONTwxoCsWXZgT5GCmn7zn+1nyoRZq4vpCzzmBmq
         Xm8wqoubDBPo0GBy+BvsmxZMqxqXq1UwkvSWzs0OYqx/b3hvmka9FbfC56/+OdGeTUxH
         aKPKoyJ7F5CEyR2EwdFQ5GXZnZ40IgDl+5fNtUmGYQz8ErzfSY5j2xC968LXYVik8icI
         Y62gngQRvNh5ZPx0eaQAm4EKT2VT/p781F2EbLHLwDvyInCywMeddNuuf7eJKt9izTQN
         902FGzAVJPanv8v2OqemlFqHk4F6wYXxZ4yuMBpyCJS2lG6IzwJLMv2h0TbfKqF4x3Ye
         bWfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="XGcvD/0M";
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 85si717595pgb.2.2019.08.19.15.21.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 15:21:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f50.google.com (mail-wr1-f50.google.com [209.85.221.50])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 51EE122D37
	for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 22:21:01 +0000 (UTC)
Received: by mail-wr1-f50.google.com with SMTP id g17so10305952wrr.5
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 15:21:01 -0700 (PDT)
X-Received: by 2002:adf:eec5:: with SMTP id a5mr29877043wrp.352.1566253259728;
 Mon, 19 Aug 2019 15:20:59 -0700 (PDT)
MIME-Version: 1.0
References: <20190815001636.12235-1-dja@axtens.net> <20190815001636.12235-2-dja@axtens.net>
 <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr> <20190816170813.GA7417@lakrids.cambridge.arm.com>
 <87imqtu7pc.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87imqtu7pc.fsf@dja-thinkpad.axtens.net>
From: Andy Lutomirski <luto@kernel.org>
Date: Mon, 19 Aug 2019 15:20:47 -0700
X-Gmail-Original-Message-ID: <CALCETrXnvofB_2KciRL6gZBemtjwTVg4-EKSJx-nz-BULF5aMg@mail.gmail.com>
Message-ID: <CALCETrXnvofB_2KciRL6gZBemtjwTVg4-EKSJx-nz-BULF5aMg@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>
Cc: Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="XGcvD/0M";       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

> On Aug 18, 2019, at 8:58 PM, Daniel Axtens <dja@axtens.net> wrote:
>

>>> Each page of shadow memory represent 8 pages of real memory. Could we use
>>> page_ref to count how many pieces of a shadow page are used so that we can
>>> free it when the ref count decreases to 0.
>
> I'm not sure how much of a difference it will make, but I'll have a look.
>

There are a grand total of eight possible pages that could require a
given shadow page. I would suggest that, instead of reference
counting, you just check all eight pages.

Or, better yet, look at the actual vm_area_struct and are where prev
and next point. That should tell you exactly which range can be freed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrXnvofB_2KciRL6gZBemtjwTVg4-EKSJx-nz-BULF5aMg%40mail.gmail.com.
