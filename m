Return-Path: <kasan-dev+bncBD52JJ7JXILRBRVLV6RAMGQECUMJP4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BC1416F1A5B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 16:18:47 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-32f23e2018fsf78508605ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 07:18:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682691526; cv=pass;
        d=google.com; s=arc-20160816;
        b=BiIdkTnO+4VzUFUyQg0PA5AOudSyCRdXGJXGccabjXdV1W1oEDsyJziC7Z0sZg7ZLT
         surmrCsZWz17PvVGCKUzBipcyuLXv1Fhe2P14MSh6s7tezhNr2z+ZXmQPJSQLGuFgGJE
         duAZhg7HLgxyPNHxWjo4Dy0QY16IaJX3aXMqIlXSpaLlBV6cR9wy2t7J+jzhFBCPq58K
         0kte2GyakA3ysavH8Rwb3/qeSAkgDGurUdCp7GTEIR/WnC+SI1oWAukUWkTCpOV1zhrX
         66WN5wKjBMhS6cdtiXGvKRd7hmQd6xsrpwx6SKP0XsXU8cI6268B5bLVDdRMBFKyYLlO
         QqnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mvOVzsieUqTujP8LnvdNiz9yR5rlZm8uqyk03Rb19Ak=;
        b=LELfNhnb8UDsqG/YU1ssROAyAP37ZqbplfxA78xeXHcYrq+EuwvxtlTXgeCeqDMTJS
         BXMc+yXNwtGJ2ujQNX2BWfYsfpxgEsXOsuzCfVu0FiM7rqDpBUPdhiDOLrpGcRWvMk3u
         /WK2gtbElc4TtIYxeO8wGqr3rx9vZQq7yyAZdTLaACoDcZsKYOgmoZ1/byvXSPu028Nj
         cLpATOEoqXbslUtVaDjtbwgzlbGpwjjo7A1rK0WVQZqkkHLjyQXwtHber2GWGO15eLZC
         Tkc0OnQtOc0QkafJQp2CQT+MnRt3G8b5gGPVnkSTEuSTAFY5kG5uPfoIIrwy3a8WJMq0
         ybNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=P5QH0dNv;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682691526; x=1685283526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mvOVzsieUqTujP8LnvdNiz9yR5rlZm8uqyk03Rb19Ak=;
        b=ZoHemdKw2qBft0GJZnx+7s3pd3zTTHUcjckIc1JCehWq1Tuww6gATU9Fb1BZfvH1i7
         YVWZ6EvZjPEMYbzNI7ynWtA1TPIFDBwniioBNBESa5vPazDw58GCtQ7r07AOlBUZ8xFa
         ZgBLvocDmcBZ6moJ1zklYOVLo1fE0d+r2vcG15gV//7QiPp0Rs9BasfsIZQTosXXouKn
         NPs8OYhBeqjPP0zl8OwJodEGaUL4qPwDaPI/K6cyAdAQaTb6I3AYhUbasjp9fYpqfrr0
         DB/Mek5Wg9JLEPDAxs+C/ctbLG7wmXI5krcrlsr7cu0ctpCpQTbACLmmqUErd7CMisy9
         XCQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682691526; x=1685283526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mvOVzsieUqTujP8LnvdNiz9yR5rlZm8uqyk03Rb19Ak=;
        b=IZ7L9U6cQ2HrSin8CLxxLhN9kvLroojff4DtybuA7kGzJBtdwpd9NHQVtFxuh9u7tz
         ol2hz+79DFyBpJHf9c1tgN+p93T6hHAx3uF5wUxH4DGQFLi6zbiALFkesc4RXIFuquS3
         9qR0rDAwE9HqpWT97rdgWCo1ANH5THF3ahZnwQdAa2CgOAVZE7NXKKuJeG4rZGHp4/1i
         gh42qfbbSwB5X9R6HaKu+zV8fGO7i+OsYVichP3ruwVxzn1Nf8v8bstAG0cTsIQQoG8w
         V5KArAG+43Rnj4AJ7IVJgEQRKa4n3Vr3RD8RNHXqKvVziyiBkYEzThM1y4WRrLbnWu8+
         Pmkw==
X-Gm-Message-State: AC+VfDxT7irW/IfYT5T/uBzW6F6is9ZcZNGjcb394iuSUoLUlU3uHzTO
	NABym7PICL1KYGBLZObHwW4=
X-Google-Smtp-Source: ACHHUZ4H+sjZRgceYc/N2vurTKC5fgj7UjlBEdD6PHzrDojsJJF2FUvEea8LX37Hh8KXi3LQEIOj1Q==
X-Received: by 2002:a92:b743:0:b0:32f:4e0e:f052 with SMTP id c3-20020a92b743000000b0032f4e0ef052mr2238465ilm.2.1682691526448;
        Fri, 28 Apr 2023 07:18:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:907:0:b0:763:ade0:a7ad with SMTP id t7-20020a6b0907000000b00763ade0a7adls859824ioi.3.-pod-prod-gmail;
 Fri, 28 Apr 2023 07:18:45 -0700 (PDT)
X-Received: by 2002:a5e:dd0b:0:b0:760:effd:c899 with SMTP id t11-20020a5edd0b000000b00760effdc899mr3462522iop.5.1682691525873;
        Fri, 28 Apr 2023 07:18:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682691525; cv=none;
        d=google.com; s=arc-20160816;
        b=nYSXOohiemcBz92Mna0WtCDB+pfE6YT7F/N5fRAm0S8zZaPItQIkQjXlyque1QU6TR
         PN6vVzwz57gAuTx9cP4qRuF10lKPxo3Q5k80I6MI6lQmAO6EOHuCNMTBlPAUpCFsWoBf
         zRRDvuzaO3bhmUXZdklZCQHOVuz7bmiC7HvGeDHY+j9zanK9qf4QcxBULnHsrIsJjkY6
         qTaRNx3v1lqfRMm/u5v29Wp+K8gv/KTzN/EzWHSPfEniIbj/0jncfqiAFzfepCIOpPn1
         R7d3CFLf5jaW9mBPnCTWIAfcd+7lY65z1c4APCfDASS1PZMklJ4VcZGx5oF9/LcieQdW
         rk0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Pu6CluFUTtRnaBZwnaoLdbpyoIqPOJ+pqKyFgwstymY=;
        b=BLEKIud89P2/ir1CCfYXAH0bbzUvO3F1K7TbGqj2z90EsQY2wa4Wr5M878esQF2sx6
         5BR96nLYr/H/tPXoa5mD1p27Acec/3pauG4FJtxcckWYICruNXDfZYdmXA+XvkYvOJ9C
         NdmIgVeYBAmfVx0g60Kr8XQqUCkRDSVDh2Gcbi6iXkW++bbxoUEiZvJFdltOcIuJBus4
         0TvduK0EDD+GkUbgbnbWwFpBHw2SVH1ivVc2080bSnJeIk9aoHi+HqTgPjC2z9vdJbuf
         dp5uAljLmHlxQ+XKdZ/DrT29H3NAj6z7ZN4lISwPQn5baPmwx75GPNMGPMFdQpeXZ7GQ
         ACeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=P5QH0dNv;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id t21-20020a056602141500b00763b993e80esi929730iov.4.2023.04.28.07.18.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Apr 2023 07:18:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-3ef34c49cb9so1011391cf.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Apr 2023 07:18:45 -0700 (PDT)
X-Received: by 2002:a05:622a:1ba3:b0:3ef:330c:8f9e with SMTP id
 bp35-20020a05622a1ba300b003ef330c8f9emr396343qtb.10.1682691525255; Fri, 28
 Apr 2023 07:18:45 -0700 (PDT)
MIME-Version: 1.0
References: <20230420210945.2313627-1-pcc@google.com> <ZEKAZZLeqY/Vvu+z@arm.com>
 <CAMn1gO7Kf39nTjrggPmk+biUa9A7sQ7JG8ZNfeH5yQzmQA=+rw@mail.gmail.com>
In-Reply-To: <CAMn1gO7Kf39nTjrggPmk+biUa9A7sQ7JG8ZNfeH5yQzmQA=+rw@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Apr 2023 07:18:34 -0700
Message-ID: <CAMn1gO4n=d_cCjq851oy0G6r_sog6_aQsmPJ0hJTBeE5r40LqA@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b=P5QH0dNv;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::835 as
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

On Fri, Apr 21, 2023 at 10:20=E2=80=AFAM Peter Collingbourne <pcc@google.co=
m> wrote:
>
> On Fri, Apr 21, 2023 at 5:24=E2=80=AFAM Catalin Marinas <catalin.marinas@=
arm.com> wrote:
> >
> > On Thu, Apr 20, 2023 at 02:09:45PM -0700, Peter Collingbourne wrote:
> > > Consider the following sequence of events:
> > >
> > > 1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
> > > 2) Page migration allocates a page with the KASAN allocator,
> > >    causing it to receive a non-match-all tag, and uses it
> > >    to replace the page faulted in 1.
> > > 3) The program uses mprotect() to enable PROT_MTE on the page faulted=
 in 1.
> >
> > Ah, so there is no race here, it's simply because the page allocation
> > for migration has a non-match-all kasan tag in page->flags.
> >
> > How do we handle the non-migration case with mprotect()? IIRC
> > post_alloc_hook() always resets the page->flags since
> > GFP_HIGHUSER_MOVABLE has the __GFP_SKIP_KASAN_UNPOISON flag.
>
> Yes, that's how it normally works.
>
> > > As a result of step 3, we are left with a non-match-all tag for a pag=
e
> > > with tags accessible to userspace, which can lead to the same kind of
> > > tag check faults that commit e74a68468062 ("arm64: Reset KASAN tag in
> > > copy_highpage with HW tags only") intended to fix.
> > >
> > > The general invariant that we have for pages in a VMA with VM_MTE_ALL=
OWED
> > > is that they cannot have a non-match-all tag. As a result of step 2, =
the
> > > invariant is broken. This means that the fix in the referenced commit
> > > was incomplete and we also need to reset the tag for pages without
> > > PG_mte_tagged.
> > >
> > > Fixes: e5b8d9218951 ("arm64: mte: reset the page tag in page->flags")
> >
> > This commit was reverted in 20794545c146 (arm64: kasan: Revert "arm64:
> > mte: reset the page tag in page->flags"). It looks a bit strange to fix
> > it up.
>
> It does seem strange but I think it is correct because that is when
> the bug (resetting tag only if PG_mte_tagged) was introduced. The
> revert preserved the bug because it did not account for the migration
> case, which means that it didn't account for migration+mprotect
> either.
>
> > > diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> > > index 4aadcfb01754..a7bb20055ce0 100644
> > > --- a/arch/arm64/mm/copypage.c
> > > +++ b/arch/arm64/mm/copypage.c
> > > @@ -21,9 +21,10 @@ void copy_highpage(struct page *to, struct page *f=
rom)
> > >
> > >       copy_page(kto, kfrom);
> > >
> > > +     if (kasan_hw_tags_enabled())
> > > +             page_kasan_tag_reset(to);
> > > +
> > >       if (system_supports_mte() && page_mte_tagged(from)) {
> > > -             if (kasan_hw_tags_enabled())
> > > -                     page_kasan_tag_reset(to);
> >
> > This should work but can we not do this at allocation time like we do
> > for the source page and remove any page_kasan_tag_reset() here
> > altogether?
>
> That would be difficult because of the number of different ways that
> the page can be allocated. That's why we also decided to reset it here
> in commit e74a68468062.

Ping.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4n%3Dd_cCjq851oy0G6r_sog6_aQsmPJ0hJTBeE5r40LqA%40mail.gmai=
l.com.
