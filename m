Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOM35WOAMGQE6SW32VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D6764DEC7
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 17:39:22 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id d20-20020a05680808f400b0035e4213541csf2135623oic.7
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 08:39:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671122361; cv=pass;
        d=google.com; s=arc-20160816;
        b=JQgxX63GxQLJyO5BEuhf6g7Z4bh9/+KAVO2ml2YZNpGPB9b/L1WgV51z0Jed77y9J/
         2doQ8+BFPBP2TYcxkSv/CHL5e/y5n7A9C1q+iHfh/Qw0+3VWSwFv8NOH+/I+jvn2srWE
         vNqbyiJ08xKA9c9MUFK+N7lQeZ0vE1Ry+CxVHlSrYsGtu+hHOePvCCotIXfzcsAUDgw9
         8qgow7XXjbNjo8mFY3euBgL0NHURAJQzjGCHcjYUpsEH6G+YlVoD9wMJHA21j8cbfuvY
         2tbzG5qRpLRQTYpby4vrhy1oAzd1D2UCqWjqMZqyl9Jjo28iBLUwtcdwRVkKiEy3pC/z
         bA8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CTwRN/YWUzO/SiJgM4M5eQiW1HcQIsvtwqBA4W9R9S0=;
        b=bWbi3+DhjHqhQhcVkG4fiEBZew7icwfXkpImpQ3h3Ew8rWFDwmER75fol6ODt9RjHr
         4woVgSmIokEWCzaBtLtxN6rEnYAwNu/12iZgE/Ea8auL1hA2FvcobkHfO0/vprj0M5rv
         U5cCQ2CEXqZV70pEGxpAGhO7Tmd+N3gSNDtq8bpfgbIt3Q4MPjUjTKRio08vmG/KpaBB
         YJCYRYgs59m/urOrEd6eXk+9qbcqgnRAWmNrgTUQ3N7TK2/xxZp/WAD+J/dWG2CgmXei
         IBVbjYhHJfSv1BrMTndg2KjNOQRoSM21zc57Jl6tz+hGkSWO/LanuEvgxb9ajSWKUrI9
         wE7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L8PwH57K;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CTwRN/YWUzO/SiJgM4M5eQiW1HcQIsvtwqBA4W9R9S0=;
        b=qEZ53mEhIss8SPfp8htvkjcZ8yYnk4PpxUt5wOahBvv1Rxr2Aihw5eh4Vy3q99NPWa
         /QwKlMEYeUyqZEXUCp3f/ff3JzgynD+a6ffaAxcXIWR7KHxcmjDePlpUCAq/3F7nZvFy
         VsfI9oDtETM2UMdvj62Q3IPeAI8RVmnAbtmw9ihRQ8LgpFsF7uH/2zS4mNLVMI3EX8UA
         YUWv8WZYZvAsBxUKQ8hvovt8RgrRXrKV24F2RwUlV2h5nMIG2TRUS80O+oK9Pi7UQEmY
         79/hqOAe4RXE+9Oh5FpzKL3qprHgchtmEYhn2kgY42Y/r8ETAaON3R3nlpHY1DlgBemQ
         /T2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CTwRN/YWUzO/SiJgM4M5eQiW1HcQIsvtwqBA4W9R9S0=;
        b=ExMuTNIcS6YUPDBS6NgaLyQhF0Gi4c2GugZ7zMk8JTq+u6zBixBsGt2DdXkF5UF/RX
         AnEfalTZcS9aDRZLkmS+ejn/f7fl6r+dWFhW0I9x74R6Ki+Ksb81SgdLk8FlN9wzL9Up
         9VbvtuVR8XyvDKWT1J/t6KD8wdYriaoO/WSsFcmsDzwur9wrqXOLw0VsOyqyWUnKCznx
         xWa9rBZ6iyolyYVsKD9SGJxxs+6dSTehPXGB8UZABNL7V0sPRumUXYaSF1/qMliTOCxE
         2X41MitUB4+C0rvZtT4JGaZU/jY4hbUQ6aQJgWnRWTYoECWQ52qA8+f8LrhGrG1cbkMJ
         AxDw==
X-Gm-Message-State: ANoB5pmiQ9z6aizlMSjtE6tHRNibp6ph6cKfXYqCRei7JmRah83NcRkl
	3F9smR5vDdONPjll6o6z3rM=
X-Google-Smtp-Source: AA0mqf4UTrB6u9o/BVXIr6q8Uddru8Sd3JXnFgWKz3OAeghfe7ayYNsLm/PwnTQAbn1jjiwhCgt+1g==
X-Received: by 2002:a9d:4813:0:b0:670:9e71:6948 with SMTP id c19-20020a9d4813000000b006709e716948mr1039905otf.109.1671122361118;
        Thu, 15 Dec 2022 08:39:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3a2a:b0:143:408e:349 with SMTP id
 du42-20020a0568703a2a00b00143408e0349ls6736024oab.6.-pod-prod-gmail; Thu, 15
 Dec 2022 08:39:20 -0800 (PST)
X-Received: by 2002:a05:6870:589c:b0:13b:765f:ffc4 with SMTP id be28-20020a056870589c00b0013b765fffc4mr15215456oab.1.1671122360724;
        Thu, 15 Dec 2022 08:39:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671122360; cv=none;
        d=google.com; s=arc-20160816;
        b=TCqy0gGjF3uP0dGvern99C/6VAgiCsYb2EsaLuZSp83cZMJ2Vv+G1aNVWD+sXTvE9W
         sIOZGGz8c/78BV0zCgadTJEVAJYd+uiU/IIfD+Lisk1wLext5m9DVHP8W1gU/dlPWMww
         qapTe9shHdyEdVNSQL6qIUinnjQb2Q5RCcyfWDL8p25t9gdzMZHFQ8Wj52n305rPga/7
         kQn16yGgJt3G5acQ7o2mJ4C1RYEPGdhRIjA5Kn2Ktsac0vj81WHH2IvEDv25wQ72zpiE
         etNJkFdIiT4s7O3ugPr2GJ3xvbhqH+qVBay5lOcm9i/9IHi7wxIweXIF6E22FVQY3efi
         tf4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ReHOnZb4ThrmNXkDfGJFFUAl9tq1r2FhymWmrkBvIJs=;
        b=PtBpcmrcobPmrSJpxohZ8Fj168rxqtEB9sHiab8/ReZth3WF7xGzw5O4jJhww8RO6d
         QzhfSoNKhpoG4a/LRXjn0SAgHy1IqLzNPwCOKqT/A/A51NIU74KaHMuNa6HXKYCqwXh8
         jpphni+ac4DU8h/V9nR9ekH8LpZRqm+m/FdeE4n7xCAyjPoQvTaJbubScDUEB/kMUuME
         K9nbJMvlbg84XJgylVSixwoYn2janEsoTKztXlFQzvFjjc8KZzpUS77CdIy+HYYJnYA4
         sbWN5N8o/OBBfFIzNR4dvQVm4hRN1cHawl9GiOeu9Gk5SkvtC1Y954yOhyGgfIEsxD/y
         D8LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L8PwH57K;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id v6-20020a056870310600b00141f024fbbdsi1355524oaa.5.2022.12.15.08.39.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Dec 2022 08:39:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id i186so4162408ybc.9
        for <kasan-dev@googlegroups.com>; Thu, 15 Dec 2022 08:39:20 -0800 (PST)
X-Received: by 2002:a25:d9d5:0:b0:6fd:ef90:2ae5 with SMTP id
 q204-20020a25d9d5000000b006fdef902ae5mr25586080ybg.376.1671122360068; Thu, 15
 Dec 2022 08:39:20 -0800 (PST)
MIME-Version: 1.0
References: <20221215162710.3802378-1-arnd@kernel.org>
In-Reply-To: <20221215162710.3802378-1-arnd@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Dec 2022 17:38:43 +0100
Message-ID: <CAG_fn=UcY0qE8OXRui1-du3TnMA06TZh0ANpDj9pqoUT4aqknQ@mail.gmail.com>
Subject: Re: [PATCH] kmsan: export kmsan_handle_urb
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=L8PwH57K;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as
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

On Thu, Dec 15, 2022 at 5:27 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> USB support can be in a loadable module, and this causes a link
> failure with KMSAN:
>
> ERROR: modpost: "kmsan_handle_urb" [drivers/usb/core/usbcore.ko] undefine=
d!
>
> Export the symbol so it can be used by this module.
>
> Fixes: 553a80188a5d ("kmsan: handle memory sent to/from USB")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kmsan/hooks.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 35f6b6e6a908..3807502766a3 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -260,6 +260,7 @@ void kmsan_handle_urb(const struct urb *urb, bool is_=
out)
>                                                urb->transfer_buffer_lengt=
h,
>                                                /*checked*/ false);
>  }
> +EXPORT_SYMBOL_GPL(kmsan_handle_urb);
>
>  static void kmsan_handle_dma_page(const void *addr, size_t size,
>                                   enum dma_data_direction dir)
> --
> 2.35.1
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUcY0qE8OXRui1-du3TnMA06TZh0ANpDj9pqoUT4aqknQ%40mail.gmai=
l.com.
