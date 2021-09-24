Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL52W6FAMGQEZYCOH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B9CA4176AB
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 16:14:09 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id x23-20020a4a3957000000b0029aff3ae536sf7489736oog.0
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 07:14:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632492848; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ma/Q+6g6Wu9wqTRYfMIXmA0Xck6cp2vaUFafInmuFwu37w52dD1HNiUo8/+Ozp6TfA
         HmDJnQ3E5neW31U7mBGmPzCWf7qtkIAxmoJh5qI3JPT6k4XKH2u+xGImEqxfDBBkQEmi
         IfPJfk1GZqjCyJBydNqduCMlYpG9yIcAUbnNXuz/tLY4lFK4ZAlQHmai3ItTdmhfgI9N
         ZzcwcmAptPzWzJiV1WEXBcI3U99REyWxAhMZcoxy3HF2dN6PZFV+3qPVxvSDNhGVE2dI
         +9uDZRshIs713m9cYicCY7W6Wx1Y33sGZh5lkgBf/sOD0mj7IQOIdo8TKo4lLasKaL8d
         ID5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Gnxq09xaiey4ZA4+BP26T4Pg6dDmdVzq/vzPnHadOfw=;
        b=C940pxmk8ZUpa3tJUCk/EW3Z83ckNJQHNkYrJAkptDzIu9y8ilWC6Bi2KWBdIxRVhR
         kJZ8/6r327QREDlagnZGahmhmgE5ffzLdHTKzh8m9VVNuJSuDtV+ByGxn+C6MX+s/JOY
         QHWQg1kDppet4EVNkDCM1eNK7jY3Oivg77W0W+q1iCQ0tY+wY+KZ477jwS+DPU4DvrML
         6HB5bIJ9VgBSkjxCW2Oy0YuJxH4KqSrzZSZFINz7isA8wKPKTr+fRLDlj1gpvSCoJfpk
         PZs4DLOwmThdvHzyhKu/HNvkrCNJ+UAU5Lm+gsGSP4RPmKdq3edAeiLbBiIdSZG/4oqE
         Yg9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xi0Xuiva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gnxq09xaiey4ZA4+BP26T4Pg6dDmdVzq/vzPnHadOfw=;
        b=jbLrpn2lTtLrxW9zkiV6h5oos9vn0kcDajGfv3SfGTcglr7TBfS7Z249WUxcjV1h5B
         wBP8/JlgRZFFJE+82Me77+7v7Iji+S7L24kBg1iQVwfys7SezUKUDAi4y5AZn0v8g+y1
         2wlR9q16Dj3hH8qbMeOeNPYG7JeMpfYo9CdvZd4sd8+hoC5e+OSnLq3IWahFk1tZ0SdO
         XEY6b5V/7chh951fCfGdHutjZcOW20kA/AdyPtnIRiXV7sc9BsBdDCy8vuBEA5JzMVc/
         I7yegAwW7vFeguycr3xAYh5Bcv+py0UmpYhadcvBL8sFanuXpgGe0DFXTR6AUwTVxT0P
         oXAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gnxq09xaiey4ZA4+BP26T4Pg6dDmdVzq/vzPnHadOfw=;
        b=jzbZiroQ9nIEukHFEeeKLGRo3r7j8du+37ja/qLydW4QtgFqg4Ze+woQ4zJhLbJwPg
         s6bgrqrp0PFLXArYlnXBvGa36Dz+dGQ5i24d0YTK0TDrz9hxBDbLv86O++DWQjIMOg/F
         Twp3yDW+NC+5QbHnsjpc9InM5CRMipJ4D8FXm6AwZeuxXiKjjEuStRkDKwlRI/N4Fe31
         0QNAbn3MSRrmRlT96YrRtc4G/8ePkLMRuBX58pvGEAKzUdadMGhtABtNsFZ1T0Xam7rK
         VuxA+oku3dy8uM9zal3GkdaGAHgaoa6Ppl360QoawkiIkVQMUaeHCgqzwYK0JJHouZ4t
         cKjQ==
X-Gm-Message-State: AOAM532B4tgUu3FMsx1zCErA4Yzf4XrH+Bcb35NzJcffffV85Gfyjz7s
	UZhCwLwRJq4QuO0iaup8eMQ=
X-Google-Smtp-Source: ABdhPJylBM++pNbaJsaBOL0cO1cIzad3IPJ0PWswGKuf/09M8Oc5fqze0do30iTFP6jd7AROEoj0FQ==
X-Received: by 2002:a05:6830:25d6:: with SMTP id d22mr4270158otu.50.1632492847894;
        Fri, 24 Sep 2021 07:14:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:114:: with SMTP id b20ls2831667oie.10.gmail; Fri,
 24 Sep 2021 07:14:07 -0700 (PDT)
X-Received: by 2002:a05:6808:1912:: with SMTP id bf18mr1597861oib.118.1632492847221;
        Fri, 24 Sep 2021 07:14:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632492847; cv=none;
        d=google.com; s=arc-20160816;
        b=HyohRJkX07DPym7POBqXUCXi+lAK7PfjLHTXhUoe0DIJgPMmno1NKhUXPgbZVHz3kV
         KUCGY1g5K4R7qnSztBW9v4qwyd70iObnR6GTqlbaw/3F93FtYkPzkS0ErGFWEZxNENLf
         zyLlMzZkOJ8b0fKxOTgGS7oMsYPZmfxQClXN4pHym/59SaaSyMHSb1l7WGlqXKeYHjQ8
         uY6Xh9Metb/rIp5g/IktmisEyjGbJ1qiI7wedvyTbciePamh4o/hGbrvJ6Iog7QtQeNF
         pbpWjzPBpRyrOWmF0wVvULbxkGFPzs9XnYmPBWrToJTn56NZFdhsKtl7n398TU03gMHF
         9Hig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8K4PrtN7OiONQx5lRLM4t8rDUMaxWp8v0q/xipOZJhQ=;
        b=L81IPZR7EQopa5aY6vjOO7k/SAeh/o77VnY13TuZyiUYSZQJYi/xphcVYkTzfMfR5E
         Ox2HogKXXgrDGnN13sELm5asgxpXzJZ3aPIvJrEfHdiTtNZtSWoHf6kX7//2/NPmInWY
         iEN0sNbz+vMTGhuxoWZY2ZC+1J39/kOXNHXsE5vLFFV3F7m8QXDyhOOlVLeYERuo8epY
         7Kyz7IBW4jfoTZ+uw/UsYIcQU566emn5oZUNDAA4vm+6ZzBxjzarV7I6or2iJAGfHSbE
         auQUYayh5tgT2YO0uDrG+y5Vuejxga4WKxmx6D3k8NeaIY/a+/mIAVqll9rzMdtBnrOH
         /hqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xi0Xuiva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id w3si113213ots.2.2021.09.24.07.14.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Sep 2021 07:14:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id l16-20020a9d6a90000000b0053b71f7dc83so13288510otq.7
        for <kasan-dev@googlegroups.com>; Fri, 24 Sep 2021 07:14:07 -0700 (PDT)
X-Received: by 2002:a05:6830:791:: with SMTP id w17mr4311950ots.108.1632492846701;
 Fri, 24 Sep 2021 07:14:06 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210924121457epcas5p39266266f9cef79177f2301a6a4f7d79a@epcas5p3.samsung.com>
 <1632485642-20625-1-git-send-email-manjeet.p@samsung.com>
In-Reply-To: <1632485642-20625-1-git-send-email-manjeet.p@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Sep 2021 16:13:55 +0200
Message-ID: <CANpmjNMcgUsdvXrvQHn+-y1w-z-6QAS+WJ27RB2DCnVxORRcuw@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: Null check is added for return value of addr_to_metadata
To: Manjeet Pawar <manjeet.p@samsung.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	r.thapliyal@samsung.com, a.sahrawat@samsung.com, v.narang@samsung.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xi0Xuiva;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Fri, 24 Sept 2021 at 15:55, Manjeet Pawar <manjeet.p@samsung.com> wrote:
> This patch add null check for return value of addr_to_metadata().
> currently 'meta' is geting accessed without any NULL check but it is
> usually checked for this function.
>
> Signed-off-by: Manjeet Pawar <manjeet.p@samsung.com>

Your commit message does not make sense -- what bug did you encounter?

"usually checked for this function" is not a reason to add the check.
Adding a check like this could also hide genuine bugs, as meta should
never be NULL in __kfence_free(). If it is, we'd like to see a crash.

Did you read kfence_free() in include/linux/kfence.h? It already
prevents __kfence_free() being called with a non-KFENCE address.

Without a more thorough explanation, Nack.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMcgUsdvXrvQHn%2B-y1w-z-6QAS%2BWJ27RB2DCnVxORRcuw%40mail.gmail.com.
