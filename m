Return-Path: <kasan-dev+bncBD52JJ7JXILRB5ELRORAMGQEMKUOA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 628C66EB077
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 19:20:53 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3f175a24fd1sf11635375e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 10:20:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682097653; cv=pass;
        d=google.com; s=arc-20160816;
        b=ddbtYdilxQHgu40ORlcmynLUlk4cEO90KOpmOtOTGZXEc5L1cFPAS2RXRjveYT7ET2
         z+bSGCGjEIzt1xIgsyg8tRgOGoRqmGksWReEz8YNzvyvuJ0kMGpP56CVILj+4y+VlAQB
         uoJ/RLIMBx1e/DqEopsOcQzgqEx4jsVP5kMeSSUZutcS/R51+vawD/VJUg1Uset0zt48
         sleMv6DKmrbsPmv2u75vwgatT01kPAB6GO6pLkT3IYZXSXkXj5TnVMQlhJzZS29u73Kr
         8U0p3QzSEFnRLlKYSctBooJ2k/GHe8b41cT0wQztr42YWI7gzSYcycIt7jOBdv4YaVap
         pTzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LEoNT5DRHEh3sZPbHmFeU2dY/bptGo2kJMsivbedY3I=;
        b=BMtwzYTecQoY9TdUxwLgT84eHz1U6Q4oSQJqUUqTgVUyKpnux28/oiSdR/2yB1n4ia
         bbX6Zdfq+QNOSNtk6X+0m8V0qm3uF9YlNR+COfwRvngPq81AsUJN4qd22DXKrD8Uq0Wk
         7ThgmhWJjl0y12jfaU1/qAuy2Bt2BlVeoqcYM+wCrSb5/i4zSa9Cbej6gYzChP3Mcmqp
         Jom5lK8ChybZoBPIiid1c7sHYnt+CTEvcA0xRWUjEsn60iArpgr/27X/PdWqzK6HfBk3
         gC/MIuQM4HOJHOzUb+Nw9o7pC2m2pBxrLRRW6U0VKet2cMIjqYqfVXrwORTWM23BFMIC
         ZLMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ErAUgtcE;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682097653; x=1684689653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LEoNT5DRHEh3sZPbHmFeU2dY/bptGo2kJMsivbedY3I=;
        b=ehN5Q/YfAzq3Y7iVunzOSJrR4naPPjOtTrbi80Xegzq7iY7X6zGktSz2JlEk2+GW3e
         D7xCmhXT7p3JVr6y5TDG+gSAZDZwHdy+FvWSaLwvA10THhHtl3uYbhl9sEYqAY2AIv9e
         qZq2Tj4rVjbBdoL+umW2M0K/T9v4zjeBzPDJQcMxZFtv6JQZihqC4lSG7FV0if/yFEOl
         qJYf/4jY2vXo+cZb1kUFeci9VQMx5WM0vf/QeglEuWdqKck+4aPl1gGi1JjdjfG8FxQf
         MDe6FdoMkKkyeCrCW0UvZ/8QZ2+AacJl1w9HIPIrgoBeLXTuQGpdGzE9cJh1yVZKB+/4
         M2KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682097653; x=1684689653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LEoNT5DRHEh3sZPbHmFeU2dY/bptGo2kJMsivbedY3I=;
        b=EH6640cIVHMqb/CEo0Ggi/KGyJrXrpBHtdHAJRw9oyONoIYm2bhmQEsy2D3Oe8Y+TH
         bJB1ZViYYsjdb8lrVnxFOUyRDAtBIF3w+MEF/iZgS563gikFIJ9/kycHXwQGhCHrQqBU
         x9Wj3ltpXADLNAnClvMUrIbHujufranJz/0UJN6cb8MNVim2xUU42ZmmnqfL5nSNT/IT
         10N9izYQOD1ESUFnQMxBVZB/CZtUlq9+TMd4ssROJp2Qh+aY67HIWoBlQ96Dv9IEVnZL
         P1f0lGj+gMNy6qwtMBV73f8MPcaCyg8yodXcWfnDtdZQzVMDKaAQCGNjOQgysQ8WL7eB
         clRA==
X-Gm-Message-State: AAQBX9epQ93oDXbIx5v2U5YD7hHDfDA0mjygfLtSTxI1pVNSG0ErMc2U
	VYjltFg6ovliWpiiDEzi85MEIA==
X-Google-Smtp-Source: AKy350ZX82s4XVdZoYPp2dXmVwnIfBuqwYwJrWxSoCr91hsy4NkG/sJ/GqkAi5pC14c75vuyCEjyQw==
X-Received: by 2002:a05:600c:221a:b0:3f1:91ba:feb6 with SMTP id z26-20020a05600c221a00b003f191bafeb6mr518143wml.1.1682097652498;
        Fri, 21 Apr 2023 10:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca2:b0:3f1:68f0:7451 with SMTP id
 bg34-20020a05600c3ca200b003f168f07451ls4432871wmb.3.-pod-canary-gmail; Fri,
 21 Apr 2023 10:20:51 -0700 (PDT)
X-Received: by 2002:a7b:ce87:0:b0:3f1:7277:eaa with SMTP id q7-20020a7bce87000000b003f172770eaamr2535027wmj.31.1682097651091;
        Fri, 21 Apr 2023 10:20:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682097651; cv=none;
        d=google.com; s=arc-20160816;
        b=jgzI/fqJ0WeRKUjrnKK9OzXufHOqWlmpat4SU2jLD8DOW9uPwDFbU2yTxT04XgFjsi
         DvidikjIAFnzwuVZ60ZYbnLx9AlxBu3MqOf66vETkwEZefwxDf788Fxxva51bjHgy6TI
         xasxys88FcgK170hE/1/xmjkSn6H2s47yaue8LL4lGSQJtYdcTk/G4P5ycs/wJIdzCKe
         up9+jgrAFEBO4paWzKDHPhOGhs6xd1vls5e3Pi7h65Y7ErBSlktZd+5ak/O/we5kVeNE
         Wxeb/G2+TkWyVV9uiqwxpHunU0qgR1+y3kf161BPfSjyM9D7edAK5D6X1n21N7K5QUBS
         4pwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eoANvRP3wG421x09FuFePYSeF3qyxJZTGGqj7xA90Ec=;
        b=rwdpE/jUCKDUPDY5W1XAcYFQyRLiWI99Y7VFJOlUOmb6LWRYDvmzCZKnVqv9D1LPfL
         tnuhI2zOZJtLiQb/jtdkhwrtYmGCgzGKwzCk76FriaCaEr4TsCP3Q5vLpLlj0WKYMVkg
         YjeJ8qydzsr9HpX2r9EdWUOSiWtWjgH49RN8VyHEw8OYYssUHcJJeNaghSwp8jDhcCGV
         FDWXNTRsbnZ1Hhd7XXp31VkmjkW4aSInyqHR1pGWXora/49WXIgIHnh02mpH4PnNMZAv
         MkBNxpakx4Oo5RztLAqemnILbsEF17X+1bbjNWwhNnYNc0H2qwBEnBhfOfBgAH2RK0XD
         GwEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ErAUgtcE;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id p12-20020a05600c1d8c00b003f17514c7b3si102213wms.1.2023.04.21.10.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Apr 2023 10:20:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-3f182f35930so193245e9.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Apr 2023 10:20:51 -0700 (PDT)
X-Received: by 2002:a05:600c:4f42:b0:3f1:6839:74a1 with SMTP id
 m2-20020a05600c4f4200b003f1683974a1mr1119wmq.6.1682097650270; Fri, 21 Apr
 2023 10:20:50 -0700 (PDT)
MIME-Version: 1.0
References: <20230420210945.2313627-1-pcc@google.com> <ZEKAZZLeqY/Vvu+z@arm.com>
In-Reply-To: <ZEKAZZLeqY/Vvu+z@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Apr 2023 10:20:38 -0700
Message-ID: <CAMn1gO7Kf39nTjrggPmk+biUa9A7sQ7JG8ZNfeH5yQzmQA=+rw@mail.gmail.com>
Subject: Re: [PATCH] arm64: Also reset KASAN tag if page is not PG_mte_tagged
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: andreyknvl@gmail.com, =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	linux-mm@kvack.org, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com, 
	will@kernel.org, eugenis@google.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ErAUgtcE;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::333 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Fri, Apr 21, 2023 at 5:24=E2=80=AFAM Catalin Marinas <catalin.marinas@ar=
m.com> wrote:
>
> On Thu, Apr 20, 2023 at 02:09:45PM -0700, Peter Collingbourne wrote:
> > Consider the following sequence of events:
> >
> > 1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
> > 2) Page migration allocates a page with the KASAN allocator,
> >    causing it to receive a non-match-all tag, and uses it
> >    to replace the page faulted in 1.
> > 3) The program uses mprotect() to enable PROT_MTE on the page faulted i=
n 1.
>
> Ah, so there is no race here, it's simply because the page allocation
> for migration has a non-match-all kasan tag in page->flags.
>
> How do we handle the non-migration case with mprotect()? IIRC
> post_alloc_hook() always resets the page->flags since
> GFP_HIGHUSER_MOVABLE has the __GFP_SKIP_KASAN_UNPOISON flag.

Yes, that's how it normally works.

> > As a result of step 3, we are left with a non-match-all tag for a page
> > with tags accessible to userspace, which can lead to the same kind of
> > tag check faults that commit e74a68468062 ("arm64: Reset KASAN tag in
> > copy_highpage with HW tags only") intended to fix.
> >
> > The general invariant that we have for pages in a VMA with VM_MTE_ALLOW=
ED
> > is that they cannot have a non-match-all tag. As a result of step 2, th=
e
> > invariant is broken. This means that the fix in the referenced commit
> > was incomplete and we also need to reset the tag for pages without
> > PG_mte_tagged.
> >
> > Fixes: e5b8d9218951 ("arm64: mte: reset the page tag in page->flags")
>
> This commit was reverted in 20794545c146 (arm64: kasan: Revert "arm64:
> mte: reset the page tag in page->flags"). It looks a bit strange to fix
> it up.

It does seem strange but I think it is correct because that is when
the bug (resetting tag only if PG_mte_tagged) was introduced. The
revert preserved the bug because it did not account for the migration
case, which means that it didn't account for migration+mprotect
either.

> > diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> > index 4aadcfb01754..a7bb20055ce0 100644
> > --- a/arch/arm64/mm/copypage.c
> > +++ b/arch/arm64/mm/copypage.c
> > @@ -21,9 +21,10 @@ void copy_highpage(struct page *to, struct page *fro=
m)
> >
> >       copy_page(kto, kfrom);
> >
> > +     if (kasan_hw_tags_enabled())
> > +             page_kasan_tag_reset(to);
> > +
> >       if (system_supports_mte() && page_mte_tagged(from)) {
> > -             if (kasan_hw_tags_enabled())
> > -                     page_kasan_tag_reset(to);
>
> This should work but can we not do this at allocation time like we do
> for the source page and remove any page_kasan_tag_reset() here
> altogether?

That would be difficult because of the number of different ways that
the page can be allocated. That's why we also decided to reset it here
in commit e74a68468062.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO7Kf39nTjrggPmk%2BbiUa9A7sQ7JG8ZNfeH5yQzmQA%3D%2Brw%40mail.=
gmail.com.
