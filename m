Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJVDQKFAMGQELST2DOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 053DB40AD29
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 14:12:24 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id b25-20020a9d60d9000000b00519be3bdc04sf10874398otk.7
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 05:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631621543; cv=pass;
        d=google.com; s=arc-20160816;
        b=cX+b+PBMdd/to/Ndo3x9IgqH594gMUb0/W2tqBQxiNwsEnVJaJ+JHI3Tb2j32WNtl9
         eYziIk6vtbV+nta/2/lfNKjboDzhQaq/JoP5qZrtFdinlWhbnx7VMJTmJoe3jiqJWU80
         0ZocW2Xq9CybcEaofo8RCLOKtQnT+DWiaiKSsJZjTu9CyMthC3txNxkXsE0ZGmTRqPHj
         oMsvuTr8VFdvY1PRU1X+1yR4MRQyyU52jsvWYo9KcW12xZK1snJeXVRqLnGSPX2ilghC
         +WvPjOEm3lc4pr0Cp43xSrBH+y6oEL7R73mkN0j8G3pgOnCABZT52nwQQlNNn1LUP5IL
         3cjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IB/n2uIVX1ECq1isPp8uVKWA78g9fODD8LpNZe0w6CY=;
        b=j1/udfGdKJoaWT/r0INsfxmc//BZFzlQyHhpO49NdXieZD144G1T8ILiUP4kTmQu0M
         1NjYx7cqf/DUJW+tTrj8x3xSs1HMhRLCEm+sqSspOZlzfyPQvCTqtiYPzJ7PUXO30Ecn
         WpenBY2xTuyeOo26weKwaOnzeff8XeUwPrentYt0zpCn8R5QkMJSbtJ8Q0mBMisGvdWH
         jvwiXdQ7RpNpoBon6GUb6OXNpclqXJ9iDiC+vI2fFTTTHVsQloENv6F4r/tKPW2/KhoA
         Oe2B8jHFBnYWnU63X7EXlizxcSifYndAt8BujUTQs37BbeYI2D5NaXCIoy4LH0YDQtJ+
         BUHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MlX97dF4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IB/n2uIVX1ECq1isPp8uVKWA78g9fODD8LpNZe0w6CY=;
        b=rOLI0zjpXylcq5tgydaO//Bpdm0QjJGnGzld21wNsibNnCJqAXQGeNu7hzjPrAuQ7O
         PyjnrIP/9JijAGqbts/Ijjwk/m6dP3AFXLF3rT5g5Gc2DOSvs6dRB3kM0pYwJAbk+PbR
         W8jfpWjEAceXuqQ82tbaHD3J4ntILbPwg4JNp39DxZMRIUuFvWYZTXx9aXC1Fjojs96f
         at8viMeHoUL+qnY001M8z+JIaPslpcKpuysQuOLPcHCIoD9FdqaMzuGqWQTrwUe3fteh
         f0BmIpDoP20C9Y6C1PP9r0QYVFlGfEi4WHvEr3AY5BJCVsjaLI0xyDuuFbyv4gt2TN4e
         Vhwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IB/n2uIVX1ECq1isPp8uVKWA78g9fODD8LpNZe0w6CY=;
        b=RUiG9Gg3zPT7OCzNjStwULCPPh6cnf0vPCMKkBwrt0adBsVAttHfoZkAuiMzFe+BfV
         Juw4quM6jCpY3RMzXhyv/P/UIjS3emJci8T3Ct5GZcNd0/OwsZcdZlN30HHZXBlLuA4K
         4YOiA5MCOS9KKGiTojsIHZeOPOi+QpTM33Wu8MFQWDU2N82gdjtC/W5kA5TAEInRJXwP
         M6E9a38VvDeB2FRaDy2YqLyiqhgBBCzz9MAGJgUhKNIwZJY/PdODn9LTH6oY4Mflkjpp
         YxMWrcNBXDm5nTup0MBx71aDVT3YJRg3O04QvnnYjwEVecjKcV6EjGTqwzwcBAgR8G1z
         NPZQ==
X-Gm-Message-State: AOAM530H+hXx7ofqcDVofptMejHMFOAi/cTXIYfImpXkouAaL0j35CpH
	vjFgXNaNT/CcW9mwwQE0gS0=
X-Google-Smtp-Source: ABdhPJzt/CTmMg9BSYbY49SV0mS4qmfbq7uG6SyOG6okbYzkUQkorcQjxhyj9OLvvzM/3Izj5MBtSw==
X-Received: by 2002:a9d:6e91:: with SMTP id a17mr14354755otr.372.1631621542801;
        Tue, 14 Sep 2021 05:12:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4408:: with SMTP id q8ls2992488otv.7.gmail; Tue, 14
 Sep 2021 05:12:22 -0700 (PDT)
X-Received: by 2002:a9d:6a4b:: with SMTP id h11mr14531453otn.5.1631621542079;
        Tue, 14 Sep 2021 05:12:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631621542; cv=none;
        d=google.com; s=arc-20160816;
        b=re17Wsv/IvR0GV1Lthiltf3SMR4q4IKqf0qJP+S7p4mRmfQgvRx4xXtMJ1bnuu915u
         MmlSSARdCP7DxFkpIJdECamxlcJe/Zwr3nzBvdieA5b6M1577cWh5E7jaAfm5vIjm4Bq
         tgvyLFfz2/djZDx0rM6BWqRnkLN9QbDc4Xz7y8SmFqH5KGC33Lft0+pNss3NLj48u3rr
         AdHe5Ohg0VCLE81qY546l5WbrhI47ImPVY1iWwgQ3pdx8hWl6B134pHAeU3IkQ9IWXhV
         Lwytg+UbyN6TSZfr9R7mDy/sIw5ieSMt+k5A9ZJxsp3Syq+ziXgpiNQPN9SEWtw9Cv5e
         KL+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0m8YoXMgG1crnCPt/39VMUSJpuHCvLuD4Bq99ZM/h/o=;
        b=jPSOr7BIHKWwQLf4VUfwr1BEmIsHvNBaE3gAMkEiTovzq0yhYj0bdI8awSSBNf0+Dz
         JgtEXrIOH8vxdu0wv9Mjz6PLOPkqCT2x2MIVV5kpKJpOM7lUZkQTc1xVDVZlxO3QRliu
         UWglGvG3JxSk4Y9lMLdg9YLVRTjSC8f6lNl40WAIO6Gk7kKa4Sip4T712zyzia50m33S
         Knrcvt4hwI+KzudelXJwG34FjrdH3BNsfdGOFr3VYTrMQyRmA2AQqMznusBL48fSnryV
         tpM5jNaPU7S7Jt5rsGu8rsExgNZSzT4oy2tSe5M5bABu6DehUMJk3eWziS1ijAhU//MW
         +e2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MlX97dF4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id b1si1270082ooe.0.2021.09.14.05.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Sep 2021 05:12:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id g11so11156912qtk.5
        for <kasan-dev@googlegroups.com>; Tue, 14 Sep 2021 05:12:22 -0700 (PDT)
X-Received: by 2002:ac8:7482:: with SMTP id v2mr4321263qtq.235.1631621541584;
 Tue, 14 Sep 2021 05:12:21 -0700 (PDT)
MIME-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com> <20210907141307.1437816-2-elver@google.com>
In-Reply-To: <20210907141307.1437816-2-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Sep 2021 14:11:45 +0200
Message-ID: <CAG_fn=WEZ=W0DzLqbpmG3kgL4QjvBr7OfnPKN_peeti2GYB5Pg@mail.gmail.com>
Subject: Re: [PATCH 1/6] lib/stackdepot: include gfp.h
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MlX97dF4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 7, 2021 at 4:14 PM Marco Elver <elver@google.com> wrote:
>
> <linux/stackdepot.h> refers to gfp_t, but doesn't include gfp.h.
>
> Fix it by including <linux/gfp.h>.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  include/linux/stackdepot.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index 6bb4bc1a5f54..97b36dc53301 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -11,6 +11,8 @@
>  #ifndef _LINUX_STACKDEPOT_H
>  #define _LINUX_STACKDEPOT_H
>
> +#include <linux/gfp.h>
> +
>  typedef u32 depot_stack_handle_t;
>
>  depot_stack_handle_t stack_depot_save(unsigned long *entries,
> --
> 2.33.0.153.gba50c8fa24-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWEZ%3DW0DzLqbpmG3kgL4QjvBr7OfnPKN_peeti2GYB5Pg%40mail.gm=
ail.com.
