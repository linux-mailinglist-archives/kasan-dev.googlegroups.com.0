Return-Path: <kasan-dev+bncBCG7JSW44ABRBPPAYWFQMGQEMOHZZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 36906436369
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 15:50:57 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id i14-20020a4a928e000000b0029acf18dcffsf259352ooh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 06:50:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634824253; cv=pass;
        d=google.com; s=arc-20160816;
        b=gcvTUXvAwyNXEYNTiW6ywIuYIq9jd0qDs07qHWzTQrQIfgPfV5ZO8ylZ1IVjVJ88oa
         svs6tNuw+JA8JAs5+NJE1yr0riQ3hMy64jEFuTitqTaMCHXEZVonx3+OLXho+KanBo10
         CyfsrTnqkmiRBGivS8Bicgy4gje4odBels7ehAAlgPYIA3EDKnoXN3CjErkE0Xw/8sdy
         p44dmuuWzjILiB0kJVdtwTfJDPO4JwWzTHTzl223TJshsoCRaTw74Rub6LUgYIoEp6Q6
         ywL/U8glUylvGxXruIZ1QViksmTkjNH7vivhJJxbPUwqOh07gYF0Pho29ugBYnn5jbCD
         ahfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=q+8Aw9X2TgxXOKi/HJ/qeoemjKRH2Lv3NbL5hie7kxg=;
        b=hAjcGUF2BUBsN/PA4NgsKKfh55F4IzejFSppijcbIQYAmdmkZv0PPsSmRVDpLb4K6G
         UWbbcPJZPM7Wyzn1JuZQyrAQBtgKJp3lFxINRXJOIJVa9QupPcVx9LzrF4C93em75HQJ
         xL00H5b9giVbeNIgndh+3nmNQJEfRG40jSBHtM3rr6dBQ7SHp9GabRib3com0ibGw6DT
         cG4ErcFO5XTxgn4AmcZkmcQYUqZ/dzyqIRxrLXUasDK3GOqJjkLaJ7RLCTowqOCAPFFO
         w/7hQfNTZqqUzmDkcObmLjHbwzEPoRXtPDD6ntDKKanzRR4w9nM4kte9hEXWnFokcoIK
         prkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b="Z+oMjis/";
       spf=pass (google.com: domain of konstantin@linuxfoundation.org designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=konstantin@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q+8Aw9X2TgxXOKi/HJ/qeoemjKRH2Lv3NbL5hie7kxg=;
        b=LyADWM0X27RYnhdTnbfng1gwEoWye81UpDxjU6TRNAPjmzlHoBbqR2NqEEotEI2rzg
         6bkdEiYvPVSiImSssOR1Orpq7Y6UVB+TT9C4HjqgGVmpsu3FvSv9cw0AXyx0jft4wn13
         +5Tr/f1bthA3PU2KbD/JO4mnunge2oCmzGRihzPK4ooKyNQx3HEaSGJMnSOCkD/qF0j5
         E+BHzBvNI5Bo+t2yegcNtHf4znaP2t59/pPTc2gus0v5J+35QQ2CpwELkBBn7IFpcIj4
         qkfApj1Cl+JZAi1e9mEoRWSLQ/C9BmlZG6PVbYjRpW0lkXF1rFZ+ccqeQb+xc4e7D//S
         1QsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q+8Aw9X2TgxXOKi/HJ/qeoemjKRH2Lv3NbL5hie7kxg=;
        b=O6OeIOE+0RPeW5z/W6Z3b4LX/wYNnnKANQSVDTEY7jygZ+WvmPwSGKyEPAQDcpUXr7
         VRRc0OKv01/pPVq0e0wTErTuU72crP3+PATmhfGuWxjvTpNnJ3MPm+4+PCRn10fcLS2g
         6KMx9ZdvpxtnLfr06z84O32Atv4JWqNDC3qq+gM//RZRDT4Xya1ctqW9p+aRRwkr8/It
         HcilD1DELy9aAXgHt27eoxkSMNjt+LV4YcBI1Fk2inEqIFhswBxkEb/xFKJU0q9HaoBY
         juwtvr3Xm4Vao2gwa033CoDH9CEXr+p52L8/fRZcTBfcwonuoZ4xT4Is1p4lqNPJGyXh
         7PNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532yTOmaNLgRklTvV9zC6/1k8WlJEEHqv3VW/EVxmc7TEC8uFkGw
	3qZiMnawCCK3cm9Q7fshAkI=
X-Google-Smtp-Source: ABdhPJwiBSP/AWpakrGaKswZPL0c/ANR8U9SUiTN1RkQczGqLXJ5Dst8L66B9lcOrntsOaQVnPs7Pw==
X-Received: by 2002:a05:6808:1383:: with SMTP id c3mr2161010oiw.80.1634824253510;
        Thu, 21 Oct 2021 06:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b60a:: with SMTP id g10ls83853oif.5.gmail; Thu, 21 Oct
 2021 06:50:53 -0700 (PDT)
X-Received: by 2002:a05:6808:110:: with SMTP id b16mr4388327oie.7.1634824253225;
        Thu, 21 Oct 2021 06:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634824253; cv=none;
        d=google.com; s=arc-20160816;
        b=DbGr4NgOcQuai0iq7l8nHuwPcdBw38JgT0XQFhtZpBJDkQmyM+9ciAas5dooU6znM7
         M2e5ZT6U510VZM2Fg7p98MRva8cu9sZ0tY92lsmCvFezc3iVLD0XIJ3KY932dPlaJ9E5
         7HKI6Q7EysAhdfMENCX65WR27OsgDBLKpPKQuDypBi3CchENFWpJLNjG3ed8QDdbi29x
         AejUIdp5UPbEnhgP2zSoXKeZBaaEYFB+PPjZ2JXBHJqhRbBoOpjQGbthqrAnoF44S7+a
         iD4ww0SUWUZAcLUOUms/lrJ0nVb4LF6drUtb5w64JGKJLVIOt06YtSHZ1Vn8ZhFup1WS
         7gJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=X627hdV4ApujpQUUoEd4GytdquRpFSDxi4GbRHWgN6w=;
        b=DXpTb/kqiXOgYrHYq6EGkxd9abCbhDfI4kX+qASW6xMcvwkkHWdx+8tsAO4dz36kSP
         RdF82hH59ryPBW2i247JPT2+vxe1r6eCGjLqRKbVmVJpDsS9SWb+GqBzkJkBc7SyLgBv
         oHqifi0sYxJe1hlUPiaa/L7laGEhF5YjL/O2k0m2HFvoMpiq745rlktU1h/nJohZb5FH
         /tLIX4j3bWo+e2Qw/VcItt0A1qmML45u477f20aNBrtAp11ezrK79mLyUXmszNGY4L4Y
         hdqCuKVD4AWgGMlxLEJ6tmcrSiaG0lPMkVnSSmplVuiR3kUhis2AfXpVyWiu3oIdUwI/
         6lRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b="Z+oMjis/";
       spf=pass (google.com: domain of konstantin@linuxfoundation.org designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=konstantin@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id y201si385965oie.4.2021.10.21.06.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Oct 2021 06:50:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of konstantin@linuxfoundation.org designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id r15so1426671qkp.8
        for <kasan-dev@googlegroups.com>; Thu, 21 Oct 2021 06:50:53 -0700 (PDT)
X-Received: by 2002:a05:620a:1a28:: with SMTP id bk40mr4577765qkb.224.1634824252613;
        Thu, 21 Oct 2021 06:50:52 -0700 (PDT)
Received: from meerkat.local (bras-base-mtrlpq5031w-grc-32-216-209-220-181.dsl.bell.ca. [216.209.220.181])
        by smtp.gmail.com with ESMTPSA id 12sm2656131qty.9.2021.10.21.06.50.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Oct 2021 06:50:52 -0700 (PDT)
Date: Thu, 21 Oct 2021 09:50:50 -0400
From: Konstantin Ryabitsev <konstantin@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Miguel Ojeda <ojeda@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>,
	Arvind Sankar <nivedita@alum.mit.edu>,
	Masahiro Yamada <masahiroy@kernel.org>, llvm@lists.linux.dev,
	Ard Biesheuvel <ardb@kernel.org>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] compiler-gcc.h: Define __SANITIZE_ADDRESS__ under
 hwaddress sanitizer
Message-ID: <20211021135050.vmangeqpl7ahidus@meerkat.local>
References: <20211020200039.170424-1-keescook@chromium.org>
 <CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001=4Q@mail.gmail.com>
 <202110210141.18C98C4@keescook>
 <CANpmjNNwEXH2=mp4RS6UUU7U9az7_zgVM223w-NJgqw1Zp-4xQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNwEXH2=mp4RS6UUU7U9az7_zgVM223w-NJgqw1Zp-4xQ@mail.gmail.com>
X-Original-Sender: konstantin@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b="Z+oMjis/";
       spf=pass (google.com: domain of konstantin@linuxfoundation.org
 designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=konstantin@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Thu, Oct 21, 2021 at 10:46:39AM +0200, Marco Elver wrote:
> > >   Reviewed-by: Marco Elver <elver@google.com>
> >
> > Thanks! (Oh, BTW, it seems "b4" won't include your Reviewed-by: tag if
> > it is indented like this.)
> 
> Ah, I'll stop doing that then -- or can we make b4 play along?

I'd rather not allow for that, as this can lead to increased false-positive
rates. It's already a bit too much of a cross-your-fingers kind of thing.

-K

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211021135050.vmangeqpl7ahidus%40meerkat.local.
