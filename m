Return-Path: <kasan-dev+bncBDY7XDHKR4OBBSMT76DQMGQEWLLTFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80A7D3D7193
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 10:54:34 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id s29-20020a056808209db0290240ce72dd5esf8541789oiw.4
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 01:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627376073; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQUyxGlZGfhM1JNIoXfKPsgUymg0z8vKCmaFSISdBuFJVRMg5Gl1sscrOnqvbIRJJd
         kxSO7SPT83PGlZ0KThwsyYzoKVePySLp/wLr1ILgS42Rva2MGyLY5MtL8jvnq5GQZcYF
         vaA7wJWr6vCtbBWp7YKMmWnunXlBYLU5Bo5MKGQBz1hsPPjHoLAAo+vPZkGIGcDU70fY
         1kB6Qznq4E0+w/QmSZFJ1Yk1TbzAtBa2Nls6PHcCxvKPFuOz83MZDw9BStVCTd2w+RkB
         2AL1wlcU99rkryDs2qOrLtooqx3IcpBYd8ejVOOAhiMFQrXaWwqBtD9G6pVk/KIgyUzk
         m/rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=FZQYNJ+ObgXnuzkpz3URFxV6CFqXBKO6xhQkBV362oo=;
        b=Jt0Pel6kKe8WikOcBI3mqxiEtcAlIeDuKqy6tdwPBRPsxHKd7QBSsl0KsasS79X3vM
         YXRSwM20+lNdWFKgzL3ZxvmC/JjgcBZ1Qc5aV5eV+nM3RCIIoJiEZ2+AZjSFfaJ1Ap/J
         OZ0e/ws0PHAN/XKb4zC989gc5gBomAQjllq4lwkc4WRo8EqTErKKyD5UHFMmtj8TtUb5
         GEWHO2vKAmCKNwYHRaFB9lsRMPs13XO3KwI4NIxLg0PEH8X/0H8EWqFKEnWKRTXtH2BV
         8F0eNYkV1wPvzzwj+m3Xsm7QXivg5K9bnsGyQXUbR1Y+GTvwcqbUlQ8Qr+a6w68/0iZV
         GI4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Sbgx3enf;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FZQYNJ+ObgXnuzkpz3URFxV6CFqXBKO6xhQkBV362oo=;
        b=Tn7n2QCbuQmaaa1MJ09+TeGxNuR2SYYDtOmSGkZCZY6z1/CR1+4vW9chWCCeAkq1Yr
         C46qfWH2dJNaPluFf1EzZtbewxKDZj+QiHqY1gNEi1GkYQ2RV8wrq97Tq1e6c0xfUIyO
         sfX0H/Uo85TYGYkuCxSDDKXH8m7owxxs3UB9UxrIap/OLyEoqE8fokSx5BE/8vy15hyA
         RMy6knzuRprLT4mETRWk+6dgknjU3rKkISyEkSZyulbEf/fmqVSSmhoc9WgZfDVEeUUQ
         9iNkPfP/v0XfLGM31y/VmGVSLpy+OamfeVeXgp1cOEAeIElPaR7FedR8Aw5zev4kXoED
         4Tsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FZQYNJ+ObgXnuzkpz3URFxV6CFqXBKO6xhQkBV362oo=;
        b=QQ00IhrPQNyLnKgERH34r2ZhCYVdvjTxPO8QCOYlO44LjwNZVEurYZ8GaFCzqwRS01
         Ej1B+zQUUYCiZa0WoekhNcf+JnDeHPl+C5t2uDv9XlAZO+mEPONRXZqXimvD/kJX0fua
         pZwV0AYO8xr6UD70BAJQ02SHhxd0gjrSa/RCRim1orvgRBnB1BlDu8+rmCX5g2GlyRh9
         mW8qEkcfFEnIL2EuUQkfxKr6I2Mg6TYgkh4g1MXouePAHY8ah20cJJBhc/BJk+plDQYX
         crbuu1nUlqWAJpa7AWb4nEIsEI6oVQdwgTpdcSggXelOqk0QjNK6WxkXlTkGyOYGB2w9
         i9ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iQuNXJ8CpktQjhc5LBHK/3zMxuYFmbmfbKYPJIdOFJp92H1gC
	BsfvQ0OxU+lkT6BAa6FdUuo=
X-Google-Smtp-Source: ABdhPJxYjN1xUNb7sBMJm/wzv3KPEzyvCgGRIw5J2S6o+7caJFFpfxbNnEebU+R+X8h7OQOT7zI6vw==
X-Received: by 2002:a4a:da0f:: with SMTP id e15mr10399691oou.53.1627376073209;
        Tue, 27 Jul 2021 01:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:352:: with SMTP id 76ls6576507otv.0.gmail; Tue, 27 Jul
 2021 01:54:32 -0700 (PDT)
X-Received: by 2002:a05:6830:10e:: with SMTP id i14mr14444281otp.242.1627376072766;
        Tue, 27 Jul 2021 01:54:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627376072; cv=none;
        d=google.com; s=arc-20160816;
        b=fnIlLFQ3oT0U5RNpXB7lNdNsdFb55POQO1jINkoEkKYCVZQHZuZdQjnUIW/Oahbrxa
         wu7ewy+8FWRzj8RwLZVRens9ufSgOilkA5AigiYh6eNxjU2V6ittmCjP5aJaSgS82m+9
         cahmElsQqgzV8iXAz/BEvv9+2RFzzMSAUr3ZearexdR02yCv0DgZlrJtDJutSnZDj4C6
         HiQMJ23ruYwL1NwHh6AcFvfy+GCadS+v4yIPvROG9y540YCiQy19wJxUiR0UUbZw3GP2
         xEuFjk5L2Q2pYLamGzAxKGcGrypK6BxELm256CTOZVerC00eRjAB0s48SBxgxuwUKuth
         h1ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=pHkaLI0XXjme0KOzVJgZfcROjWi4O4Qvm9FSQ9EMZ7I=;
        b=WzmTQ7nv5hTtNkXerUj77KKn3+/RKH9P2v+idVnXbJ1mi2kR3WfM+A0u9W9MPN5ILN
         hglrnou5Fe9bDfPqT55BOGWrSdlas83FCGwHnBVrm6rtvd76Lqs2UJKKdVVVyfod9hk2
         dIBjmRpvv3QXC/eR6RFhohDdylNupcmSyN8JYyLLgszxEWBl+Kg6jzTTXBkxUyJh+7Go
         ZKi4zOKMxSDxuReLGhecuByThFYfcLmCWytaMlqj8nKuTJNwP2YodztfJNRXofguHI/C
         7b6oSdjFwlz2WOqO97WH9yg5PjRpOJOdaXsgwDF0PFMmPLMiJFC6yBgujm12U+syWIOc
         B2lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Sbgx3enf;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id b9si274501ooq.1.2021.07.27.01.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Jul 2021 01:54:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 907db055f5bf458bace5cfe9da424ea1-20210727
X-UUID: 907db055f5bf458bace5cfe9da424ea1-20210727
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 687126901; Tue, 27 Jul 2021 16:54:28 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 27 Jul 2021 16:54:27 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 27 Jul 2021 16:54:27 +0800
Message-ID: <77ecf897408ab1022bd7fd879b8708e99c479cd9.camel@mediatek.com>
Subject: Re: [PATCH 2/2] kasan, mm: reset tag for hex dump address
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<Kuan-Ying.Lee@mediatek.com>
Date: Tue, 27 Jul 2021 16:54:26 +0800
In-Reply-To: <CANpmjNNOkCspsf4=gPLLw=29vtv4qEDaErB1i1sz-p+bzLxNKg@mail.gmail.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
	 <20210727040021.21371-3-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNNOkCspsf4=gPLLw=29vtv4qEDaErB1i1sz-p+bzLxNKg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Sbgx3enf;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

On Tue, 2021-07-27 at 09:20 +0200, Marco Elver wrote:
> On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > Text is a string. We need to move this kasan_reset_tag()
> > to address but text.
> > 
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> 
> This patch also makes sense (I think), thanks for sending. But it's
> unclear what the problem is. The fact that when the address is
> printed
> it still includes the tag? Or a false positive?
> It'd be good to clarify in the commit message.

Yes, printed address includes the tag, so when we access the
metadata, we will encounter tag mismatch with HW tag-based kasan
enabled.

> 
> Here I'd also use a more descriptive patch title, something like
> "kasan, slub: reset tag when printing address".
> 
> Also, I think this patch requires a:
> 
>   Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing
> metadata")
> 
> So that stable kernels can pick this up if appropriate.

Thank you, Marco.
I will refine commit message in the v2.

> 
> > ---
> >  mm/slub.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 6dad2b6fda6f..d20674f839ba 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -576,8 +576,8 @@ static void print_section(char *level, char
> > *text, u8 *addr,
> >                           unsigned int length)
> >  {
> >         metadata_access_enable();
> > -       print_hex_dump(level, kasan_reset_tag(text),
> > DUMP_PREFIX_ADDRESS,
> > -                       16, 1, addr, length, 1);
> > +       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
> > +                       16, 1, kasan_reset_tag((void *)addr),
> > length, 1);
> >         metadata_access_disable();
> >  }
> > 
> > --
> > 2.18.0
> > 
> > --
> > You received this message because you are subscribed to the Google
> > Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it,
> > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit 
> > https://urldefense.com/v3/__https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-3-Kuan-Ying.Lee*40mediatek.com__;JQ!!CTRNKA9wMg0ARbw!13XOuYbzPQrBvIDMNbrT7vm8RGc56Oqr402PDfQRDmHrrBsujrZUr7O9q24JeDJ_3NlWSQ$
> >  .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77ecf897408ab1022bd7fd879b8708e99c479cd9.camel%40mediatek.com.
