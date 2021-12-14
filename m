Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH4N4SGQMGQEOAJ4GJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 20227474CEE
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 22:03:29 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id j9-20020a05651231c900b004037efe9fddsf9201129lfe.18
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 13:03:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639515808; cv=pass;
        d=google.com; s=arc-20160816;
        b=hGtdM/RMQxw36wblrPKnr0EeOS09UIGr34Z01iiCwUSZUl8BYzR8h0IKYrVhGRpPmo
         1MuiYns1AoesoQbeZlygvbG3ksdwg8cfxfIk2LWv9PN4874yJH+o5C9XkwWfDIc7/Vir
         o3ToNo/lqv5kIl7mjjo4KJ1CdClqn9RJl8dSqeO6ecQsyACt2RYK9lGWGzj89S/lJ1ew
         NpzStZuVZkN2z/k3Pq6G8WgMkHCy3P9qW6SeRobZry3CjIe4HmD+oeSM+0XQR2hAZ3xW
         GSPBMVx4heFm6JEVHv/8Ln83hxA0ZSlbvmOmlkGmbWihUho9PByUlhaRI29A+JGEHB8i
         wC4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LLDcKNvjDqqJQodPrIi5seFL+v7oSI55fgwXwUC+ouU=;
        b=PLZgEOu2+LvUwqOXPYhjAuriBeRdtSbmMg665UV7fYv0xRzOo18TKDd+ztECiv5x1O
         C5lxB8t0dHJaYPGi3/PAkrsxBbmpCOCHQnjU2wO9hsVxXXZP/SYvJ95L06gC4+ReF5tg
         yxxOxezZ/OsGDx4WaAaMPHBXemYWbzfwuFJXKpcTF8VAWoLoiYBgDTAqavyDElLXg6pW
         jsXOjeKaC4Vq3ZB44R8HLweUyW8z00PM89Hb61dX/95/cgXLgwRW4xb3JdlHbQocDfbU
         djyHqBnKzqVAaOVbXNWMLWVfM4sP11WEeOPBpr2znj8bgsvYj55+IEG3kqiXmHtx5i2G
         V4OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PE8uPggn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LLDcKNvjDqqJQodPrIi5seFL+v7oSI55fgwXwUC+ouU=;
        b=ObWmvb8ciLNBfH6lt63sWXFm+bRSG4lxfGRMBeTRMA7I0F7v4hSLAcTLF1fmnTm8b3
         BtLtXQwrNT9/VJeOXSr7JwAmj/vSUe3zkr5jxNTGgJAkSezD8+KT+jlpKz2SDoaBnA6i
         8DG9obCRGvVAoQafKw1yAye4K+xBH524i7MbBPG+XzErUCXkiO9W1mDoOZ7Sb8keRjEP
         sdJ/f2D5xKC8jb+tv3LfRziKJI2z4mtwc7YPWBDh6hWYm2lApBL8fPn7BmlJMis9fwbL
         fGFmLvP0SAaDD3z7JQQDoo06sKsn0qu8ZkjB/aPcZkBhljWHb2Ff1bpvzZsnmuIR1Gwj
         l7Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LLDcKNvjDqqJQodPrIi5seFL+v7oSI55fgwXwUC+ouU=;
        b=NGOCOEyyXv7F1LzwixjbPBO7iqKUbw16qyJGw0WO1BmsB9nqjNI9cNweU9WdTuGV0y
         PufLI6wS/oq/OJjoxTv4jsmWdj33/dhByLBlpCtyms0kWzlOSSAbvqBrOWfWlsPfvRqi
         ysIFtxb8o1QX6kp2ORTO+uY+6RwBLirC7tB+DGgUSyoo4nbLIb/3eG3f2AuNuSc8005S
         xHbu7KwDmiJjPJwoE+iLLpTHCBcV5/3MVH8jB+52HHR2LOxTLHLi/DAC8xrPmD5+X+hW
         aGE0jHojxD7wN4TGozH2aT0pHmbvB08NmZX1TYLlrOcxIrFUhDbaWSCtNVdPxekmkwcg
         DA8A==
X-Gm-Message-State: AOAM533PyxQIGZ2QwB9/GNNLq+pvDoJmt/LcYjmc/YyxWJWjWC5OnLyZ
	gmJBqpM/Q1phOcxi/xoMpo0=
X-Google-Smtp-Source: ABdhPJyDC5iG1Xs0ADdqSQ+DgRRzlQT24rCgZmJJwA9BZnwO4UCRf3WFqAYpsxA7Ee6kYBJLd9FuSA==
X-Received: by 2002:a05:6512:322f:: with SMTP id f15mr6552866lfe.476.1639515808210;
        Tue, 14 Dec 2021 13:03:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b9c:: with SMTP id g28ls20022lfv.3.gmail; Tue, 14
 Dec 2021 13:03:27 -0800 (PST)
X-Received: by 2002:ac2:4c4e:: with SMTP id o14mr7093557lfk.148.1639515807025;
        Tue, 14 Dec 2021 13:03:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639515807; cv=none;
        d=google.com; s=arc-20160816;
        b=a3ALphy0IQZ61/tYI7oM/bmO6Jju6nkb0kGLnAnmI1nyvWcKj5xHBMq3PGNZDZive6
         m7VjDPdjQPDmwrlovmhip+ZnRb3RFNH9popDgxQohYRME9jTJYaqJ9OjKpt+JEvLm2Bg
         su6gZxHpbQB1102nycwvoy7YmdhnB/UwiupCD0ssAQ+OlY3WmPRuz0Rn7b4tvvMzw0bO
         JmmNyppdM4EZ6bmRB8uyWzHB7HposZEvGnvd18hgrMqS67U8tFWM4x5nin8Mjap/v5JP
         p8GDReWYY/B504oqcxaArJPyTT+HysnwJkLiX1W2GqFPex1mxIgRWKDcq/AMV32wjtOG
         E0kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aset2ikDotS3hcbpPPk7kj6RXe+C5lMKImjQj7BFUoI=;
        b=kAQCiY+2FU4RcqWdOC1E7EzSmMIJJ5hXrF67LYzlo/S0f1cbFWGi1m9PoS6bto9gqq
         yMvcgQwTzWisJAMSSmlIn6N7A34GUXe6f/KbHkpDPlySYODyg4gPyROh0YnLa0O3q2/t
         Z9K0hxAzh3s191q8hAVYDKH1tWBToF9rm84VpXxRZ7dVhBAsxEeB6ihxiX0WL9uanTva
         OwQRwef1xDVBuhIejPhrmf78c063PeARiMGTe3OmILm1/z59P25WjWhhPkLt2C8zweYj
         npDkHo2LLyYVVUbav3WvC62dBgtgz4j2iJkDsqorxvPZwZ3bOMAKoqXcpEvxkm9ARBk3
         A/Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PE8uPggn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id i12si100lfr.7.2021.12.14.13.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 13:03:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id k9so16801269wrd.2
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 13:03:26 -0800 (PST)
X-Received: by 2002:a05:6000:1688:: with SMTP id y8mr1517654wrd.420.1639515806600;
        Tue, 14 Dec 2021 13:03:26 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f9c2:fca2:6c2e:7e9f])
        by smtp.gmail.com with ESMTPSA id f18sm20520wre.7.2021.12.14.13.03.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 13:03:25 -0800 (PST)
Date: Tue, 14 Dec 2021 22:03:19 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 29/38] kasan, vmalloc: add vmalloc tagging for
 HW_TAGS
Message-ID: <YbkGl/tmvEczufrk@elver.google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PE8uPggn;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
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

On Mon, Dec 13, 2021 at 10:54PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
[...]
> +
> +	/* Skip unpoisoning and assigning a pointer tag for non-VM_ALLOC
> +	 * mappings as:

This is networking comment style, probably unintended here.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbkGl/tmvEczufrk%40elver.google.com.
