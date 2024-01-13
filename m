Return-Path: <kasan-dev+bncBCV4DBW44YLRBLNLRGWQMGQEFS4UJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8103F82CABD
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 10:19:47 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35ff5a2f9c0sf61356815ab.3
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 01:19:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705137581; cv=pass;
        d=google.com; s=arc-20160816;
        b=dCrdDNp9ybbDHgKZE4pcCtoUuvkNQBZj1DnZJdf0L+76blI+wB9LlFLo5zCh+cgTOb
         52PjdfCPZ/DRJM074a2BSKzSPMH6rYnjt1ac9aVC8l5Grwq+zeFsiRLzDHbhvTQP7VNj
         XjRNq/9D0jkGBpndWVGNxgUiNa3vx6qYLx8wlJAUmGyjphXGE1C14R77iiNOCkAnICsS
         nAIJD8WvzuYgKZYKy9j1lWgErt8tIkqkibr3qQqE9FbhPzOP2U76W1bA5FJA/bXdgKU5
         9fkThtPh6z2UQFv5NZHA2IqMw4n3kZM3wZ0WgoF1RivYBtHvfuIcxx2uJuQJdxvDo9gw
         ZqHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iHRAV/7O79Xft8+03Sc0VdX+ppfiaFFK4ZI3Df4GFns=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=Vv3oK1ZGBG6h91hvSXbC249hZUGB6aJSCXiqmAf+an7v0DFWm3xgBQMjXPPGhfQ9wn
         7D+DF0t1ulY37AgRaDYXD76gczFnt3TfGmCRttO4hQdaCrPY5orq2/HszjXB1p/JtABM
         8NCdf4rWHyDTEClj7n4GjutNkVnVi93NbAfdo8WBV1x7qzBBSzYNz0u5INXplaqTDKlR
         Whu/uKUfJFPDJnEwSH6Y66P3irUmETV6ql5dLVKDli5HIx/4//HxoKz1xqzLcK5Bj3om
         KJ+1r/9tqDJiMPIMW9LOmt6Kf7zaJhhNwmVcV/JyFhDXcpsBe2KfigfMsVq0WSfw4Bjt
         kF1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hEgAQF72;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705137581; x=1705742381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iHRAV/7O79Xft8+03Sc0VdX+ppfiaFFK4ZI3Df4GFns=;
        b=HFBB4UZR6ZHOlZFBNhM689eoaUiZRe1MuI5mpOSgKGMznfoV/b+BwgOp6iTZArvJFw
         2r0BhBxR1zqmZ1k9Mh9dtTbXWLZVvKDGsysqSqyo+vCVU/vYPk6GZQBCOZzgyZ4Y/Nu5
         Tf+nuPRb7CZvBTJ+1oO2cdn2rSs9NSh+Wrc1YrdLM82OJibx7JfdCcm6AIIeeuqeGF6b
         /FsCvfqL+9qmHIS2Qb6g1OsJEkiBjAhDOft5K2xf3ShToqfvZJ3bxOY/yJ4nFKkhExRr
         yfxbXnhKevGNrFk1G7L0KifC6+ziOjK7Z6XfhW6Vh3sPNhHUB9ve4Fh8ay4cy/O9Xe+l
         ewdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705137581; x=1705742381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iHRAV/7O79Xft8+03Sc0VdX+ppfiaFFK4ZI3Df4GFns=;
        b=rTsC6G4R49+a6bsa0OQyKP+9f52Pf2EsufAOuzVvKkC0FwOehZZ4Qu7sXOrMgBBj7w
         7CjsKOVOUDLyJcJe0wm9FTP41cqgy/aeslWCcA5gY+HRImJzcFvPiflkOueedd5DuzAV
         O+ioRV/uMvzm4GPBrcM4lYY8X8eYnUdcU9hioPB8VKoytr/2/YEOuGgFIRuI7kq0Eg4U
         BTjrpNoj2DnTYrF5FQlqbUf/Wwx9woU9/kFy+CerfRyGizV/fX/Jj92N9gVR9JiL5gS+
         fA5GoVHjLZyKe+KJPPNGfqlVsjuf+mnS0sfQGx6+657ZhJ602R2lsowWhbkSJxRTT2DL
         n9Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz5KzF/ds3Yc2Uf1DUBiPzQry+TmDBwfvR7MKBunU/KVRz458fA
	bCOkiixk2v8aIQ5kJwV1wnw=
X-Google-Smtp-Source: AGHT+IHRR2LO+WkkPXvGc+GCPFvNP/FEWGx1o8jh0IjJHiKozHSAFFyZdFiWIirbz0JsS1fjQCcv7g==
X-Received: by 2002:a92:c885:0:b0:35f:ac40:4ec8 with SMTP id w5-20020a92c885000000b0035fac404ec8mr2797041ilo.13.1705137581280;
        Sat, 13 Jan 2024 01:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:308d:b0:35f:c1a2:1d90 with SMTP id
 bf13-20020a056e02308d00b0035fc1a21d90ls3723248ilb.2.-pod-prod-07-us; Sat, 13
 Jan 2024 01:19:40 -0800 (PST)
X-Received: by 2002:a92:c5aa:0:b0:360:8033:e943 with SMTP id r10-20020a92c5aa000000b003608033e943mr2779822ilt.38.1705137580605;
        Sat, 13 Jan 2024 01:19:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705137580; cv=none;
        d=google.com; s=arc-20160816;
        b=TEHxX+Gu1gXYWu4xdpF5YWoleSKkLr5M/vlUowVED3m+Y/yWeDnQerZRegw18imJ3C
         2F+ISoTR/97+n6nSOLKvM9E7NmC/lHwf5dchYai5Eiiy9Mhj8icJzX+xt+zQCEfK7OGg
         ahlXyI7UljTTuUj9ezU658iyvVTQKJcMwCswdzO71idipbzW3h2Zr/cphiVqglPiuaM7
         4jXAAZyTsIu1XjjMXBpE9xapF/8t+qlpKOSuRg90CVJGPTvXyqlmnotsGlrAc/4rJHzL
         LB05DG4MEO0J0S2v1Hw1hCJt2WkOPUyQc1+wKfQOA9fAfYldgoA1mf2STOEpUOYXpOeZ
         vEGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9lYQKT++pGy+ATA5JMUYS6sYp9tJrbUHXHjxYVq1w4w=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=LeSnhhI2WWOdj8/58G85zOL7zxKz0ELhnZO+A8CH7GN2t/IHpU4vQInZgVDYvR0YBs
         u8k1BWVdF3IHs7FEtwp31REn37D1VkRJb/VKeCQYkmuMxR2gk5h7iUoHTOjaXOqrpI3f
         9fAdauuNhD7ylnyW1NArxTrhGMufwHetPhD3zcOAXgAPGehed2tHgYH6aK3VHURvsftR
         892qQ13KzBmOTP/CwPtm3EBMG8p+7QS39jyGQRr+a7vRCxNZUNJW2LXaPMu+6CZj7wGU
         IX5a/ECwauOk46xSp1Nnf+/5D4SQKmC7GNLeveWUTLECwuqc6QA1jJEAe80iZvckbO3q
         GxwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hEgAQF72;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id jc14-20020a17090325ce00b001d4b03b7914si342920plb.2.2024.01.13.01.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 13 Jan 2024 01:19:40 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="403130393"
X-IronPort-AV: E=Sophos;i="6.04,192,1695711600"; 
   d="scan'208";a="403130393"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jan 2024 01:19:38 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="853513285"
X-IronPort-AV: E=Sophos;i="6.04,192,1695711600"; 
   d="scan'208";a="853513285"
Received: from tassilo.jf.intel.com (HELO tassilo) ([10.54.38.190])
  by fmsmga004-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jan 2024 01:19:37 -0800
Date: Sat, 13 Jan 2024 01:19:36 -0800
From: Andi Kleen <ak@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZaJVqF-_fJ_O3pJK@tassilo>
References: <ZZUlgs69iTTlG8Lh@localhost.localdomain>
 <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo>
 <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com>
 <ZaHmQU5DouedI9kS@tassilo>
 <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com>
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=hEgAQF72;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=ak@linux.intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Sat, Jan 13, 2024 at 10:12:21AM +0100, Marco Elver wrote:
> On Sat, 13 Jan 2024 at 02:24, Andi Kleen <ak@linux.intel.com> wrote:
> >
> > On Fri, Jan 12, 2024 at 11:15:05PM +0100, Marco Elver wrote:
> > > +             /*
> > > +              * Stack traces of size 0 are never saved, and we can simply use
> > > +              * the size field as an indicator if this is a new unused stack
> > > +              * record in the freelist.
> > > +              */
> > > +             stack->size = 0;
> >
> > I would use WRITE_ONCE here too, at least for TSan.
> 
> This is written with the pool_lock held.

...which doesn't help because the readers don't take it?

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZaJVqF-_fJ_O3pJK%40tassilo.
