Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHFTQ2AAMGQEXZJQF2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8549C2F7CB3
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:33:18 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id g20sf711202pfo.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:33:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610717597; cv=pass;
        d=google.com; s=arc-20160816;
        b=lcamePLs7MRW/+ZUDw6mkxPNzBw7iKsZU0PwJRD3Fha1T7ZoLZ4xkJcLobdxQHSV+A
         vzxbBWZN6AdzMSBFR1ZsIZnA3HVCNTcZtQa4kLQdDK3hACC/xR5u2EUKZ+CqvKzd9CQq
         TY+Aif+8Kvl2KpAnoCNd4grQ7JPMHjn9n9A1EMasPQf7nABmYry5xQ1loM7uVqQ1RmOT
         L9teHVw4QrnVLKeE70c/R4oSd3nv0x0tOeVSV+mAc7YfO92bhJAB3+FLMPYFHTjGMrPK
         0YN7PyZeh7xNKDOBtUqHy4aM9dov9Suucudg/HFnvYNKPaQ2AZpmytkol/FO7Vs3rt0H
         1U2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uxolJnJ3GcVnBscVIRWxJld+OFiKevi0wvbOZbwKSYA=;
        b=jLjbW9lw7pd+aGFxYZTzByaoppcmryPlhVesmj1OIeVlXd6ngePS/FWFfnkzr9K2Tf
         eVshFNHOYvi9tLhwmJFwizd0dNEdq6HwdMIjCWxOrg8Yzq463lj/Hh2FprA/uPAcbfiQ
         tg+qWaBd6JB572SZaDtbrzYqHwoGatkUAsgUrzeNHvfSgAFr9Gwmz0vQTHb1tTbwdOl+
         jifkNyA5BfXyvVNAfULHBFJDy4BkM3FfpwJ7XHrAy4sKO8LaaLxH9KQBxJY/pjOAzPwy
         MuH/1buJQygBFj12ogymikLOKLk1K5roUyj8+ya7o7euHu4AnMDvYTNJoJ9iV1BPacJU
         R49Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpFhrwzG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uxolJnJ3GcVnBscVIRWxJld+OFiKevi0wvbOZbwKSYA=;
        b=Vf/mZzTuWTz+4COf4wP7MejUEZBmlqy/eU9XjA5l7rv4uKNwAW594Bjh0qlf8smYPk
         gTlmBmmg4kd/pNlkgDO+JLENqBvy4eB216IrUqH6wrEEaMtz5n8R/4Ms4zKgbsqB6KX+
         hRstuy+s3nULC5ktRKy/03GsWBMSmOfGneGkg+7ouwaLxlbvEVSCnhyz3A3yyW6XCxLh
         DZWb28r3If3VR6+gxcGLmOS4pxYx0qFEa3Aw8272qzNp9b1oJuvi6V7ECIsFAKiNV1SB
         po1KGX0dRNTOMYfq9uk3yJoEWb/Tw2jU5HPkBR3tmoDt1/j75Bk5mfLZF3xhxMYraJ5g
         MllQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uxolJnJ3GcVnBscVIRWxJld+OFiKevi0wvbOZbwKSYA=;
        b=TF2hKCL1dFUTSwDY9BS63GcTIsif9avBr5V6LjnnLqxRPqE73GU9ufoobLRxApwzpS
         bu0oig55uuRcTkDjfQ5jULTwgDlLxYo2WHSkjOYlO6Tg7EtqIQ57eNjuU3XScxHFw083
         c9D+o/Vh0amc+fBMSnmpX+InmIcT74M55UPTbA+L0mQiBjeAoaTvwtjM8DvrGFz2Wha5
         zol7kbg+t9HS4tgNBg5DZJdW1let8p24A0sTXgivoNc0TcEtt70YG+M+kyXelaaNo/gM
         qC37lv3A1n6EO6xNRsAazTnNJD0H91VMlfumAy5favP3H5cfBbwchcVUZbIpAuRL1EQo
         NGGQ==
X-Gm-Message-State: AOAM531LhmyWWdQxYNWnRWHDGHKR6E6SMG64i55hI3hgUXmq6Xuofzdo
	bM8NIz0xP3lpPdlqI9hlPaE=
X-Google-Smtp-Source: ABdhPJwUbErnPPqHWomUyjuoqWVVbfBLCUwYX/tVI+gv9CYPqmoq7GSUIZTSoLXXCjyA0tUtCCvh2Q==
X-Received: by 2002:aa7:9046:0:b029:1a4:aa3b:1f31 with SMTP id n6-20020aa790460000b02901a4aa3b1f31mr12443576pfo.77.1610717597005;
        Fri, 15 Jan 2021 05:33:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls3566449pgj.1.gmail; Fri, 15 Jan
 2021 05:33:16 -0800 (PST)
X-Received: by 2002:a63:d814:: with SMTP id b20mr12587301pgh.202.1610717596457;
        Fri, 15 Jan 2021 05:33:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610717596; cv=none;
        d=google.com; s=arc-20160816;
        b=p6WUZLjxml5prnb1ltOVXzQrO9vOM6yEmNln9hfZxsXmM8h/S8lqgHzLlDTRn62p9D
         ca7c0MUEGEQxPICy76TVZvX9cBX492Hon4G6YGOSHNcZHIRFOCutOR+CnSHe3GQbfPhw
         Ze7iXxTQ6SWvNQiBDJgBFm1Be8H26YIdnV/JjSEDaP66u4tfsYLoKkDPAaU5vs/vUlXG
         wZARq2ssuwd7QTNBYv0kBtXb7+XjRDN6vKNkL9A9tbpS2PeywKVw3zsn/jRDP3RJE+E3
         RewZk3pSd/srYFeyf9nvNDyKtwfz0ZNSoIcLIHhD7+4DNtYNF5wVVKCpcuaSACrqAUBG
         7s1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K0aoGg0wPuE1hYe4sqWhHeR+8ZOS1Jh5Y7WE82oHlpQ=;
        b=jrOR3oGiIpZvnleEpQ+cDsX+WD9cGtYQxKubAm7i/ntz/yi1/zAJfVITia87rV5kMs
         pes+7R0/JHopEf/cHNEXsv6kONTva9ioN1D34l8V8MFucFiKvZhDqbOQXBQJmtLh59Y0
         im5cGtjFroLKbwFK9YLhN8UCxoQvKCS9gDTVM88hNbkA70DVFjm21zmhxDrgU7SxQBTg
         UJfMaTufKE87Z08afAwtEx5pwGQkSeDgfP8qJZVYpAahOTz5JtNqf66EF20i+XiT4FMx
         6kDLwpWZdA7rB7uHij7jqYwkLuSrU2aPsYT0xJvV7QSqIxP9B6PA+HmBtaFx5B3pEBRf
         qezg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpFhrwzG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id d22si641358pgb.1.2021.01.15.05.33.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:33:16 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id h4so11605212qkk.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:33:16 -0800 (PST)
X-Received: by 2002:a05:620a:2051:: with SMTP id d17mr12177058qka.403.1610717595909;
 Fri, 15 Jan 2021 05:33:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <5153dafd6498a9183cfedaf267a2953defb6578e.1610652890.git.andreyknvl@google.com>
In-Reply-To: <5153dafd6498a9183cfedaf267a2953defb6578e.1610652890.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:33:04 +0100
Message-ID: <CAG_fn=WcrOHH0eoG=R9-6w3pqs2ig-weowWFG78r-s0whDqj=A@mail.gmail.com>
Subject: Re: [PATCH v3 05/15] kasan: add match-all tag tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LpFhrwzG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
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

On Thu, Jan 14, 2021 at 8:36 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add 3 new tests for tag-based KASAN modes:
>
> 1. Check that match-all pointer tag is not assigned randomly.
> 2. Check that 0xff works as a match-all pointer tag.
> 3. Check that there are no match-all memory tags.
>
> Note, that test #3 causes a significant number (255) of KASAN reports
> to be printed during execution for the SW_TAGS mode.
>
> Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWcrOHH0eoG%3DR9-6w3pqs2ig-weowWFG78r-s0whDqj%3DA%40mail.gmail.com.
