Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVHZWIAMGQEWN2GB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8954BD862
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 09:55:43 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id n99-20020a9d206c000000b00590dde2cca8sf7003574ota.9
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 00:55:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645433742; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLnPxORzDr8HT9UlGJrQfTrRN4nUO0yZei9gYbteAsEUsdo+m7wnmjEs3FowQLIRrG
         flSzIdNMlkrEVQIQ9/1Btfz1TverSQc+EK+vY8fndyZusBXCgr7YjdbxeKs8xoe9ThqD
         dG7T3k/w/336tV5daf3F2DrBM8Iuvrh89rwmqxSvOAKiLYvFzQyieG2i0dTdT8wBPEy+
         Bbwd1yjvTopBMkmZ1r/bZL4atoZeUqYUDbsMYz4Y5bWp44u/wzDCkCYa1RbAme691efB
         zywlhu9tqeqQIQoA8gKNpCihXjhqYtEA7E5R/5exrMrCcxVfx2TJxT3uXUJIJ6amsfB3
         4BRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UCVgLnqz4zVPYKf4T/XGQOCBuM6bSXy8B/NdVK9wXpA=;
        b=yUu3SGvIbgw+s4r7Q4c3aQSc/A8NEmklfPy1bax4/Q7jjMkLbIUgAHmCZLciwBeLSA
         OwHzuHze5LVYjzt51PaG8fsECWkBRW9KPbCJtUdFTOYSar7E3dNbBQpHGZFjbcAcFhPU
         AVpsP5a9ocf7ER2q1ZH7B6J+lXoK3dJUkI3BF5WakqULhiyVNm4Ux7SpvjddV7g0N/c1
         Bjq/+DlOlwTg6LPjYnXhTkmVPWqny47iIpNQVjkzvm3SPLqYUb0REqHYVt8W0S1AcuS7
         ukcMmU3FGNzDhnYveex0JwNgTFZCyz1V2drmn8uAGC2qgIOCX5OXC9BY4Mincm/jJqTH
         btGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ca2BM6g6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UCVgLnqz4zVPYKf4T/XGQOCBuM6bSXy8B/NdVK9wXpA=;
        b=RQ7O7c58A79G3S5Mo4RESLpkSauCh71ClHyosH3HgnFEIQK5bMCS0Pg453bMgnlvgX
         uniSgLJ7//ruJR0aIEUbT4zjkeRmglN8DUz1AWxUAbPttxY6xYkRhbLwnU9fJ1hyNoNB
         8hOOrm4cP0+6EwOUqIOWpx7O+nYSpGeOWpN/ixntwTb6POl+62AFHHcz+7KxHpFCq9Da
         2QxBn2OqFoYdd8A2pZ9keF4hrL483IcHK83Sf2bBhVS47yzpAkUMBrc0caBPsllpZF3x
         2+kWiN4zJ/67JeB5SVsjoC6DKJi2c3OVOwb+E1JXXicEv0ireEuwUzFlINIFqilLHIWo
         8v+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UCVgLnqz4zVPYKf4T/XGQOCBuM6bSXy8B/NdVK9wXpA=;
        b=uo8OP9E8230dtAA0PfFjZngdav7OzLmwi1eNKoaJviI8wgOwt0q4s+IkVpCaIXD90C
         /uK4/E/l67Lca+AL5fNBgS8KWqThkGQXV3aEjf4sxNmZBCIaFr6Jx3ZsAuSRdh4jlXTB
         6skv2UCNtD8BDgypc7vQ3QEqCL4k96u5jJ1cByLYPBzKyTfcK0I0EUqRxtjZouEdwlJ5
         fqW6Ca3YgwT2yjQcsfS3PLFoIw3BDkZdgZaiJVi5N5BQakvS3k+HL5yXlnqusYVNf09i
         GFOBkb7O7zFzgjEtYcq+y6FAC4RT/3L75qp5QJTJgfBaKqApv+vHqp2UffkT4997tPjZ
         lICw==
X-Gm-Message-State: AOAM533DrYXqw5MQJ6qG2UbegrIkoVEmDCPhY6qp9bmsDVSEn8lyYwnv
	idd8qc0MhmrIYQLMtpJ5qJA=
X-Google-Smtp-Source: ABdhPJyQjCD+t1bGz8IG6yTxZzFe/vldpQPUUX6n2i8H4rDfeDr3QI6/yaDM5G5QEytA3PyesPPSbw==
X-Received: by 2002:a05:6808:114c:b0:2d4:64:92ee with SMTP id u12-20020a056808114c00b002d4006492eemr9622291oiu.195.1645433742215;
        Mon, 21 Feb 2022 00:55:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1a18:b0:2ce:5441:56cc with SMTP id
 bk24-20020a0568081a1800b002ce544156ccls3630467oib.6.gmail; Mon, 21 Feb 2022
 00:55:41 -0800 (PST)
X-Received: by 2002:aca:bb88:0:b0:2d4:eb52:4513 with SMTP id l130-20020acabb88000000b002d4eb524513mr3354477oif.163.1645433741874;
        Mon, 21 Feb 2022 00:55:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645433741; cv=none;
        d=google.com; s=arc-20160816;
        b=ZtMrWG2q31ZPVPGtaA0EUi6xsW7osBejswdknMPL+nPTV8Mhe46sl/xwJhJEpq/4rK
         Q9dMD7tCzdBQL1APMqQ2GKlPF3/S5b0CwOoDAwDHAbIv1cPiAjpTe/GKXGkYx6huLmbh
         XHilqaeCHblFH1DCjrYoY3MinL5uL2wJ+eK1rD9Yr5+msS3kVW0RihQxsHnVni/3cTB+
         z8i/jR5SvLDtH/NJ/sHJ1LwDUFpzqFdz9jCfTFuko62MJeOev0mg2wDhqr7DR6bndSJa
         P6Y4JN5WHOuCHBrv6lEPu/UyDz2iiB1LnuARne/rj/7zAXsDY6+RGiudoIb7RWPshOZ1
         yG5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=khIa/7OGm0LBxAJ/g0p2l7rc9Ll0z+rpERju9Mdr/S4=;
        b=o5oe1TqA70bOrAJvOdFb3Ijdnr9QMozGm+3SUOZLNbXM0TE7wBS1uhLjrC5dUNFYDc
         +vT+z6P/Jlq+gDFJS1XpyLTq26JiLNFP2VJMwIU6az7ngq5rMsk/Xzt0JB4hB2KGGXch
         fUd1hv+ZkaOHLWVfj01CWQf7ei6elKyoAv+WJA3rh/+haUH7t9d2f9XXxSuI+6FiM5cy
         p9JYC2407smGyzhZc2HB09QdkW1T4Zo9j3TaGSlkO7MKQZxdzrjDlE6WXG1PhfH1DNvj
         krE+Adjskc5cUdNbEcDs7CesUzhy7D36yBc8/CQsAoP2iMFj3iAWWWEpDQ30EJdaCC/r
         CrOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ca2BM6g6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id t25si4406610oao.1.2022.02.21.00.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Feb 2022 00:55:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-2d07ae0b1bfso129955377b3.6
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 00:55:41 -0800 (PST)
X-Received: by 2002:a0d:fb07:0:b0:2ca:287c:6c97 with SMTP id
 l7-20020a0dfb07000000b002ca287c6c97mr18233281ywf.316.1645433741222; Mon, 21
 Feb 2022 00:55:41 -0800 (PST)
MIME-Version: 1.0
References: <20220221065421.20689-1-tangmeng@uniontech.com>
In-Reply-To: <20220221065421.20689-1-tangmeng@uniontech.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Feb 2022 09:55:29 +0100
Message-ID: <CANpmjNMyb5RyfQG4S=TEBJEY4RDsG8u+D3X=Ate3avL18XLonA@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: remove unnecessary CONFIG_KASAN option
To: tangmeng <tangmeng@uniontech.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ca2BM6g6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Mon, 21 Feb 2022 at 07:54, tangmeng <tangmeng@uniontech.com> wrote:
>
> In mm/Makefile has:
> obj-$(CONFIG_KASAN)     += kasan/
>
> So that we don't need 'obj-$(CONFIG_KASAN) :=' in mm/kasan/Makefile,
> delete it from mm/kasan/Makefile.
>
> Signed-off-by: tangmeng <tangmeng@uniontech.com>

Looks reasonable, thanks.

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/Makefile | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index adcd9acaef61..1f84df9c302e 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -35,7 +35,7 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
> -obj-$(CONFIG_KASAN) := common.o report.o
> +obj-y := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
>  obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
> --
> 2.20.1
>
>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221065421.20689-1-tangmeng%40uniontech.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMyb5RyfQG4S%3DTEBJEY4RDsG8u%2BD3X%3DAte3avL18XLonA%40mail.gmail.com.
