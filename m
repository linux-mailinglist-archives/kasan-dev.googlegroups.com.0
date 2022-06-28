Return-Path: <kasan-dev+bncBDW2JDUY5AORBPH55OKQMGQEK6T4J2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D7C9B55D4E6
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:14:37 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id b7-20020a251b07000000b0066c8f97b0f9sf7285152ybb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:14:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656422076; cv=pass;
        d=google.com; s=arc-20160816;
        b=n2sAxxBmkpLoI55yVGo8+em0lX9ZEGNDcaJj82nGbR6W3inFGo7u4nJn3YSr5moKmE
         FUQq1I/o+8mC7scLZTxh6WDt7OK6U2eG9OPXgNhHVEkrvi2UrYQMXHa+FaXHCbpDgTmy
         t9Agj6BP8PtSW0EJifqJVaJD3iEgAtui8ChMZ5rBHUl6YN+7W+WSyn3KsoO9ySouMJ8k
         gYeODQ/XKEmi4oZVIV0a6pAEzTHbVOAT5uIQe+m79Lc80buNUbaqXUcXmqYvfKy/gnOF
         3WiEji1f64PCADUW9U5jOTqC1mIaHmvIt61xZUPCx2K/wRJWVwkBy6iRNoVA0a4P+MMP
         lRuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0mSvGJZ+PvGbGSyoPYTkAla05Pt9QgJKZD5F0Jz8jAA=;
        b=pk34oiWU4K54B22NpzaTVBymocT6dERf6WjJLiAgrtyF+lpAqVz9NLT5qqrK+KDi6I
         kMvSeE+NNcTrJ4a/Onrql7ls6xUmJHvJMlGZr11zFjOqL2WcXiU0OKe5mZHy0AOGrwSG
         TOCMB2OQCJ/LFVArshK2W6v5ChMMpVpCo3AYXcLV9OY+U/0OnELFvIGSC8Xz9ieei8ex
         9yQJ2P5eJjOjfK71ckB0mTfuuK7AnAPz8eUnu2JuyGzDhzR9EIyJrTuMUGbut3dLrS3U
         NrtWhYstI5xkQU23BGVtHtc/KrxsGGbCAlADdFxhcBvAgRY9DP65HAD77l8pVXpa0foX
         GCDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=e3IN4akW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0mSvGJZ+PvGbGSyoPYTkAla05Pt9QgJKZD5F0Jz8jAA=;
        b=HNQhCwONkp6mpbZpCMVQJuulsesMgUoaYiE6B7bw0RfJEMsjjVg27aC2XLD5l296S7
         GW8b5pu1xz98Xkjk3RsV44JqcEOBrt2UHcART+JAWC2YqP9vqR6Mopmgm6ttXIKZzsZ9
         sMv2Mvtu0Lw1VlfhkIo/jzoRIMr5Xce0FMj8RB7obmQA8iI24NvcM+u2Sp9eCr1SinoA
         biHZIsiJXg+a7LzPKHaAulKi8jaOvKZ9E7QMjtnSsGY79zytuMkPzkqh4o5PILFSdRq1
         PJ+hLw5nvwTdCNz4bIklukBpSh4YhMmOyB4DgBlJDUcXeCu6s0Txcos6a+8yfjC3V7IR
         RqtQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0mSvGJZ+PvGbGSyoPYTkAla05Pt9QgJKZD5F0Jz8jAA=;
        b=pwazvG872TC8t0HCAi5/imKxrsJASTKaVcWeYQfDhkfQDDEN9RAxgHXUcvQmLFp4cT
         AE8qhDKpLF5yZ1nw4m0PUSVCJ8UYTBWuTjuhAsJMAHsVaSEljAPljTB6fYrkyv16hnhP
         qIT/cwFPQR5pph1QodoO66Z3p4JpS6AtJDD3jWNP1XVmszy8ZiBYTPiFw+sineToN9rd
         RR1xNw8mlYTS8Onfm6Umm/fxyqhbXSHJzHyDlugAYSMfidKtTj/gtHY5FKOokAAolHXP
         GkS+X9KRS7ICIqxv5aRllea1qhhxxwnJU2ZE7tY97wVjmwRell1mRc1kBkzBfQ73AcX5
         mb8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0mSvGJZ+PvGbGSyoPYTkAla05Pt9QgJKZD5F0Jz8jAA=;
        b=pwBfj5UziWZjzlxRwBRpqA1zIrYEuE1T3f+vENrgejwERo8dAD2FPKxfif2OzAO5ot
         PmO/6Cf9qkOQzy+JdBpED1kuGFNpZq4yzUiLoWqXAVMGVv+JxyrHLrv97aXgdL1JQy/P
         n84KrjSBGwIyp+5AM/s/HDvMSqh8Sn0PVd6wbzqtxiod11PqDtOeVvpxAnwOplHZnOaI
         Dpx+4s2gAn//a+wNXecp8VD/AOfaQAaNBpPH2ZuaenlV7vIFGGc8flQ1T3u0aUxbdKLE
         17N3ID9biIt82Fz0Mekc2a91rMxGOvhDj8SR3mXc//sI7s66e4wONO1hFuOG7MOUau6a
         WwvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8nhSmICTqpLYjiaVQrca3VIeZQZ6Bocz0elwAbd7/pccPuUKWD
	oeKOPHBLFII4Wo/sQibQW/4=
X-Google-Smtp-Source: AGRyM1vVrDvEkU3z0lan2HgfHCw+gcL5UYU/kIy/XMd+BXie8iRZp3JLbwlNPMPJ75Un81I48LD7gw==
X-Received: by 2002:a81:ac17:0:b0:317:6e98:1f63 with SMTP id k23-20020a81ac17000000b003176e981f63mr21203045ywh.303.1656422076656;
        Tue, 28 Jun 2022 06:14:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a488:0:b0:66d:24b5:fd75 with SMTP id g8-20020a25a488000000b0066d24b5fd75ls1347373ybi.10.gmail;
 Tue, 28 Jun 2022 06:14:36 -0700 (PDT)
X-Received: by 2002:a25:5092:0:b0:66c:810c:e520 with SMTP id e140-20020a255092000000b0066c810ce520mr19213804ybb.649.1656422076083;
        Tue, 28 Jun 2022 06:14:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656422076; cv=none;
        d=google.com; s=arc-20160816;
        b=hA24at1hd0g7HBn+YfmW4CDynvGdR72J9UsWejh+8/jiTSKO2J7tUWkca1HBc9gyXs
         6o1gvtxdC4khP4VAeW6kSfpwfAOM0sMnQ6yYBI2QiK5qsrBYhzet1g0hMEv1UAat5Gkc
         YVLZRmEL3oHf8KU2TtA8M+3n6aKqUzuWHAbcZrTktRIWxpIfATOkboNP+W3BJxe8NkVU
         Q47sVr2msImzVQVab7YvYIzHqXGjyvdAPcNWz2dgv7KA/2u8Y/sAYdOxA9HzDTMQVAdy
         lsgJVef/yxXOBlisC8fiYgU15URQMYuNkcIzQPzMtctRZlZcQImZBiYgb0n942VjJTrH
         hXTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DsbdvFQeUqASiOkCBKpg+u5M35Pu57mB+0bBgUEwlQ0=;
        b=WDVdmyq2Rmq9NqGZ/2GZ5hXwo5DlBbVSovy5pVibDLgeGbxapO9eK9SPRV3YrIFjOs
         mOlt6RKe4Jz91v5oqUsFgQcQkVx5n+mSsUbm6L7lA/6YN/wHw14LtWfHnOQoztvbLi3l
         t6qiw7HrJE/91R/VjoxeZGzFzMBmTjy33nsVggwTA052xw+6MgN6r0LkO1+2okF+1Ey0
         LLlei5RCid8hDipZA75852b2aV6E1Un3lvr/9a/GG4pHyXSkDDvvmh1nU07OYRSdDSeY
         8CV3ieE8dLmJjX3kfGQDlDECeCknv5ldNYGyVbFhUl7+89rLHTX9bq8yfpn2/+vIhqHo
         xhlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=e3IN4akW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id r9-20020a819a09000000b0031332987bdasi577213ywg.3.2022.06.28.06.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:14:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id n14so8102322ilt.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:14:36 -0700 (PDT)
X-Received: by 2002:a92:b10e:0:b0:2d8:d8a7:8b29 with SMTP id
 t14-20020a92b10e000000b002d8d8a78b29mr10510693ilh.233.1656422075643; Tue, 28
 Jun 2022 06:14:35 -0700 (PDT)
MIME-Version: 1.0
References: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
 <165599625020.2988777.9370908523559678089.b4-ty@kernel.org>
In-Reply-To: <165599625020.2988777.9370908523559678089.b4-ty@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 28 Jun 2022 15:14:24 +0200
Message-ID: <CA+fCnZcLsGVpP_bJ=OLkPe=DXwAzyzv2eS2jsMv9RZV58sjGZA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] arm64: kasan: do not instrument stacktrace.c
To: Will Deacon <will@kernel.org>
Cc: andrey.konovalov@linux.dev, Catalin Marinas <catalin.marinas@arm.com>, 
	kernel-team@android.com, Alexander Potapenko <glider@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=e3IN4akW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Jun 23, 2022 at 9:31 PM Will Deacon <will@kernel.org> wrote:
>
> On Mon, 23 May 2022 16:51:51 +0200, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.
> >
> > This speeds up Generic KASAN by 5-20%.
> >
> > As a side-effect, KASAN is now unable to detect bugs in the stack trace
> > collection code. This is taken as an acceptable downside.
> >
> > [...]
>
> Applied to arm64 (for-next/stacktrace), thanks! I had to fix conflicts
> in both of the patches, so please can you take a quick look at the result?
>
> [1/2] arm64: kasan: do not instrument stacktrace.c
>       https://git.kernel.org/arm64/c/802b91118d11
> [2/2] arm64: stacktrace: use non-atomic __set_bit
>       https://git.kernel.org/arm64/c/446297b28a21

Hi Will,

The updated patches look good.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcLsGVpP_bJ%3DOLkPe%3DDXwAzyzv2eS2jsMv9RZV58sjGZA%40mail.gmail.com.
