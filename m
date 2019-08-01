Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBVVCRTVAKGQEPBRSOAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id BE8EE7DFF8
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2019 18:20:39 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 145sf46072716pfv.18
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2019 09:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564676438; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOmWzTC3HZffa6eP9mTUOIjZEJYbfKwNKAMAdeYl7mxa1EfeWIsM1Mpudb2U/jONym
         NCNP6QQOSzehA1PZoBGbqYu1kxorDvHcyfyBB8/BqN78ScBi/lHXIHc2nHZOTu1l/WE/
         N0f0vqgnn8HqnYzI7NnYtN0NJAKQOfuDlRRH1EmIDB+yPqoZfaVNEe+2GziPLwbHhDzN
         Wdx2eK5jlC9G7myGJVe6BaN1vYVaZm3klI6ZDMDiGjdHgUa80gpdK4DKggPxl329191V
         M2Reprz5dOLuvQ64kf3GxlmWbWPgU2JWUJhbbwHjzW0K3NS/4XB0I2VbRs8HUfWDJ4Cm
         dztQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=L2DzT89Ib+Olk04k6X8vpIxKm6vP/6bJSu8Mg+UrrC4=;
        b=YLuB+lfRz20iDHF1IE7rBjxJRH/kU8FNddH7z6gTSt6AJflbBLgMN+w9L20JPon40M
         lsS4y8MCP9EVNC2lM6mULYaKcJyTC4oAeWKx4XAhg9l3t8oh0eNOt2pLB4I87ditpFTy
         jXWKATvNc0NNtkaAG7tHTrZH/f7ZJCssSJCcz0x+0IOupJm+9iGvheATrEnQQXaAF+dK
         FJCzILZ85/U2VYIzWILZQZZeHTc8vkXXj7K+cznU2UEyR7+74kyOXrLB7TmloiMNQs5S
         E9CVa/a1Y3sdyBCYO9a/Iia0rfl6D+iuK8T1bXa83qxsCwnnvmsQL5gS5m9PR5gMte4D
         MNDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Mvpx3v8T;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L2DzT89Ib+Olk04k6X8vpIxKm6vP/6bJSu8Mg+UrrC4=;
        b=tPPai0zMNFdTAargC7WthT08uNVvWb0QCVAYOcU9BEP6R9NuVwlCaH1FPHVqhW7Mtq
         EYrV3iRz8/+GSggS7f4M2+lrBBYkE1wc8RVaLWHUgVlNdaInkbXCThs+8X0u/1iEj/F8
         /iXTmF6pgZFfGFGvfTaUEO9FJv2iqLTAJ7fq94cCCR6osDh8I+/JMe0/Eb9uAPAj9KAz
         /sRHM50ctpG10ikoFV8yRQd2up5CKaWtZ8D4/VrvCFCRkRiD6/V7YpzTGbroGIBk5eJE
         ufFe5G+RCYEx7JPGjkfwb9WaYc2JDZxt2XAJ/Q5+qTAcNVhWo7lXxQg4YvfhblA9Zy58
         /3+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L2DzT89Ib+Olk04k6X8vpIxKm6vP/6bJSu8Mg+UrrC4=;
        b=W+1mKm9je5fUJxrdmIQV7yPrknQGrPOcHSgTnVNtZq80LI+AerlZkDKAehVLv/GEbO
         UhcoS+0Koz46u8/49jaIkHSES4hsLocLceJ7pN43PaIuwO+FFMdjye8v4AQPIept6CMc
         b75DcVS7gGfLs77SLND2GUJ6OUiF8pRFydja9mGXUnbO6DMrZYA1F6ejq75z7u6hFXrr
         YEfKHhHdjepIGHOitq1eBtkFh/xw1Zxpy3u55kaGZjiUoxvcc7eVNwz32XlKOqxL3GUi
         pK7UcoSOTKbRMkDdWl9avxRR3qmzezdOCf5IbUKu6bBeJsNQWXsloT9eLCK588sX9CyU
         gkZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWCZVzg+k9W+2zf6u+lnIN98B1KPYayUi6EZ2EFZhD9jKEoAOvn
	/fkzUVM6hh5WYwAW9mEOG04=
X-Google-Smtp-Source: APXvYqzPCQxTqgaYzPpvBXrOYfEi/9m0vKvLxkkO+xTwQgiG1HdBOmMD8qCyHNsGwoahbpJ65J5YLw==
X-Received: by 2002:a63:2ec9:: with SMTP id u192mr117325881pgu.16.1564676438112;
        Thu, 01 Aug 2019 09:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ce4e:: with SMTP id y75ls15951336pfg.11.gmail; Thu, 01
 Aug 2019 09:20:37 -0700 (PDT)
X-Received: by 2002:a63:1341:: with SMTP id 1mr12440646pgt.48.1564676437743;
        Thu, 01 Aug 2019 09:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564676437; cv=none;
        d=google.com; s=arc-20160816;
        b=FPoSMLCXJEUZML3nH40xWpmDv66cBa4N2W9kVTs+a3nRV31q3zZngA1r5tYfxBXi9y
         26G8uJcz//6F8OetvLA0ERb3E2J0jmjOy5Et7fnPQR+Q0cMMG7FuYic+vDIst9wSTCqu
         6EuHLcJ25DcgVWLPHhe6u31BuCukl7rgWmm32MZzx9mXTnduJS3pwXI6UbiZjR3u6sIn
         kiIkvwJwNsneep+6ced32v2kseHtyVWE4mk9bQ+DegjiZ1l9wNWAL/SY1rjwJoDdJPGb
         FoDb7WGNTWlrCiIMIE6/NyKiZG+KZdvUMEDnzwgkQGt5Uu8yvRZ8gV1g8xaoVOR3SnYV
         glew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=D5T2Uxf2pvzlQgNSYEF3ht0LNwLAYlgpi5hrr37GkRA=;
        b=VrnRFHEjCWpwA0PtvRblVAsiBHr6RxEFW68dhRyFSPUY0pnSLxW0uWsnxP9j5KNQyA
         4zv2qT1hQZ7RCininz4bXKHBoGPk3UfB447LJqg/9EBKQw7B4So3O15wvuLWbGxu53d4
         I6KcYSybYAYoLTrwb9mtQy9vbCJR32GpeV3yTHcptTwOpq+IEeYGJ+2mE1MSS+ZSZQDk
         aE0StwjfjxvvmFINsf7ufFdA71H1ICsqNwzyr4wtGkUfA1yGeuBZTjIxSCafttugvcUW
         Nu46sLUAQaJF9XdHwpHG7vtonIbQBQh6oGIqCIRbhYc6tukVi7Ff/e9T6FWOz8221746
         42rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Mvpx3v8T;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id b12si142152pjn.2.2019.08.01.09.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Aug 2019 09:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id k10so1669438qtq.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Aug 2019 09:20:37 -0700 (PDT)
X-Received: by 2002:ac8:2a99:: with SMTP id b25mr91869588qta.223.1564676437174;
        Thu, 01 Aug 2019 09:20:37 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id 47sm41640083qtw.90.2019.08.01.09.20.35
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Aug 2019 09:20:36 -0700 (PDT)
Message-ID: <1564676434.11067.46.camel@lca.pw>
Subject: Re: [PATCH v2] arm64/mm: fix variable 'tag' set but not used
From: Qian Cai <cai@lca.pw>
To: Matthew Wilcox <willy@infradead.org>
Cc: catalin.marinas@arm.com, will@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Date: Thu, 01 Aug 2019 12:20:34 -0400
In-Reply-To: <20190801160013.GK4700@bombadil.infradead.org>
References: <1564670825-4050-1-git-send-email-cai@lca.pw>
	 <20190801160013.GK4700@bombadil.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=Mvpx3v8T;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, 2019-08-01 at 09:00 -0700, Matthew Wilcox wrote:
> On Thu, Aug 01, 2019 at 10:47:05AM -0400, Qian Cai wrote:
>=20
> Given this:
>=20
> > -#define __tag_set(addr, tag)	(addr)
> > +static inline const void *__tag_set(const void *addr, u8 tag)
> > +{
> > +	return addr;
> > +}
> > +
> > =C2=A0#define __tag_reset(addr)	(addr)
> > =C2=A0#define __tag_get(addr)		0
> > =C2=A0#endif
> > @@ -301,8 +305,8 @@ static inline void *phys_to_virt(phys_addr_t x)
> > =C2=A0#define page_to_virt(page)	({				=09
> > \
> > =C2=A0	unsigned long __addr =3D					=09
> > \
> > =C2=A0		((__page_to_voff(page)) | PAGE_OFFSET);		=09
> > \
> > -	unsigned long __addr_tag =3D					\
> > -		=C2=A0__tag_set(__addr, page_kasan_tag(page));		\
> > +	const void *__addr_tag =3D					\
> > +		__tag_set((void *)__addr, page_kasan_tag(page));	\
> > =C2=A0	((void *)__addr_tag);					=09
> > \
> > =C2=A0})
>=20
> Can't you simplify that macro to:
>=20
> =C2=A0#define page_to_virt(page)	({					\
> =C2=A0	unsigned long __addr =3D					=09
> \
> =C2=A0		((__page_to_voff(page)) | PAGE_OFFSET);		=09
> \
> -	unsigned long __addr_tag =3D					\
> -		=C2=A0__tag_set(__addr, page_kasan_tag(page));		\
> -	((void *)__addr_tag);					=09
> \
> +	__tag_set((void *)__addr, page_kasan_tag(page));		\
> =C2=A0})

It still need a cast or lowmem_page_address() will complain of a discarded
"const". It might be a bit harder to read when adding a cast as in,

((void *)__tag_set((void *)__addr, page_kasan_tag(page)));

But, that feel like more of a followup patch for me if ever needed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1564676434.11067.46.camel%40lca.pw.
