Return-Path: <kasan-dev+bncBAABBD7Y36SQMGQETLALL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8558275991E
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 17:06:57 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6b9ca98ff25sf6922420a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 08:06:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689779216; cv=pass;
        d=google.com; s=arc-20160816;
        b=uvUwaFOryqkTmejRoOfI4/YkKwt8kP1IYaDqFre/7qDUE7FxzeNvDgoIC3rE7gypAf
         AAZaraADd1G9bV1DFvFyHYh4PxIeUsxDSp0/gzqGyc2qHwWwYeqKk8jcLNC2Hc2PWqZ6
         b9Y08zxk3iEkbjl1ZDp9ipPwwLfZVqRmwKuVDSahbkUlsC/72s+Q8MRBsQ+jDi43UvT2
         yS7jP8n8d8BZsM71C1ZlVU4tHf4EhmUXLXJvl5TE6VN7EIY2TDjg+Tzd8yYr9LQ6WR4j
         hio43LrEm8mWzCwSo2Vx8wvbEIt0y4iIr9jsRP4QFMPbctYjBd3cFvNwfmkU20se4Mlj
         FD1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=NZBvg52NVazNInvY3xx9pUixVLhOd7DUOW5OJZ/Yqzo=;
        fh=jLRHw9q5W91fgyusEsUHP+3JApaDCYkeL6+K+0RaqHU=;
        b=X0NnbdRT5s/DHJGlQjmNpL7+vtVwtcyazR/s3PkKaE0LvamQKkAtMh98zQzMGkBPiW
         IAHhFdThefdBRuOGxAm3iLZbvXkJfu11m70aDmjy2IIs1VBU2oqhwao7lDodJqM61hBc
         b3yIfouD54o3mlhN1cn56TOGzMJ28e4NdwMfoqv5O54Mb33JNPUkCuLpguYea+4uLGAy
         9S8LZXYUJXAUvK0O8ECPo3nd0AX1k1l5jydyXihMEmTq+DJa54T4Zp7VcfZBfneJPurl
         3/HjPo9j/TUS5oMp//qP9t+VPld5I5HkxKmjsOo2Hmz+wNejviTH47jM0lIdAgzfmY3T
         YzyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qqgFzyb1;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689779216; x=1692371216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NZBvg52NVazNInvY3xx9pUixVLhOd7DUOW5OJZ/Yqzo=;
        b=nOfZRdWctkjQJJu3bmKUXPkKA2Kt0y2Cf/mUpg3MePMYN/vOavBzHxEsnXnYpJI91U
         VCd3QNMc+uCd+TQ0qpZXiomE8LfpWbNL6d4tR9SNeEb/DZJVMctHAOKsy+1WuIL0Yixk
         L0Ttja3CvCbwdIoAsf6NpAgRINC/pZ7PX5GbAvp+Y6YU/zaoB/3wEF/9ZEnA9bFIGmQv
         Vw9OXytW1jYNQFOL7EFRIFWRdjp+W2HnjauVnJcXCAyCplsJwkIBN0iY3HRWUlzsnMxz
         9rEmCwOQaqOu8WnkhpMp7YRm38UvBWJu/v+B14ReVzJXoCTQyWi4QuL/gGFNOiCXDsIi
         c5RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689779216; x=1692371216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NZBvg52NVazNInvY3xx9pUixVLhOd7DUOW5OJZ/Yqzo=;
        b=HqRrysbi8pdjc+2jk92FG4+SE7HP4aDJAfEtkH7DDuvpqyIgb6ie/1Ut9g7Ukt+4gI
         iYm8cF9NADX9bjVX1K4DMM15ezGDTn6ftJYtxQXQU+b7VJPcxYqjyZ72/yqof0y4MUq9
         6X2H9lKbO54oSbBxKkcSLoV31gdBy86yI7FwCt3vbS6ICe+wfMsYFvRbqgCZm8BLX0EE
         GSIcD7zViAoNbbn9OeA5LlfzxNkgRsgYOC2iqfiSXoC/tKPzkObHGcxSzP6Nnl5Xy82o
         tkay74Q5qwNLDrxABgbPGAjM4kzLr8k8XkglBGL3CaOQtCZLY9W/ZgBIXgk9V7hbSxMT
         bOGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaRZn3pKcTfrcU6Vk2gw4blo/Ji5k6ccboalxvq87deY/8x/rDA
	o9qIleRr+suUG3v01OoH/Ew=
X-Google-Smtp-Source: APBJJlEIFd1qOmyu8G3tPVp617HkJIDBFKS84il+s0VYOEzzx3bwt9EeODZl20G+e5DVgQ/Z9JZddw==
X-Received: by 2002:a05:6870:d599:b0:1b3:5667:5e44 with SMTP id u25-20020a056870d59900b001b356675e44mr19856803oao.28.1689779215990;
        Wed, 19 Jul 2023 08:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:33c8:0:b0:566:3d2c:576c with SMTP id q191-20020a4a33c8000000b005663d2c576cls573137ooq.0.-pod-prod-07-us;
 Wed, 19 Jul 2023 08:06:55 -0700 (PDT)
X-Received: by 2002:a9d:73cc:0:b0:6b7:56f6:f846 with SMTP id m12-20020a9d73cc000000b006b756f6f846mr62771otk.5.1689779215493;
        Wed, 19 Jul 2023 08:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689779215; cv=none;
        d=google.com; s=arc-20160816;
        b=hMZKRhSfeaTU0w3XSpCP2h7pL2bwwqVkQwQG8ZyUvDgvBaAPbQuyXVdJjll1VBrA5b
         Jv17uZ0j8ESD8dTyK5t/ghv54AW9SEi+SumykJ1uztpUoWve0xcCG0kFIUC//dlXe/hU
         g+hmS+AbRLPJERIaxP9hRE2NIfxctuughcWeWAMG+ywXsrXpglBI1ZEBtaU3P4N2ptua
         i7gHU2wMtbP9lJo32BT0vCkFlvoVFqHYOAoq7dvxC34W5kqYK26/lJJTjH46OelbDdni
         6946h0drgW0s0LF7L5ehKcF0IpIHMP9782nKmx47goxvhHFSDRZ+4O2grJERdWQ8bXZL
         zQ7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jx3BVc4/Aba42tkB++z3xWt67laer3kQ9sjvtzX6hiI=;
        fh=jLRHw9q5W91fgyusEsUHP+3JApaDCYkeL6+K+0RaqHU=;
        b=c1ppmKdq3p45GZ/Y7rwm+fNfQA/q54AO+Tw3RjS5WnkToPVs2K5mJz0cimI0uuaTHm
         qKSJ4944Wcatcb5JmrMlBSGlAfzeQAgIO5zkmKzX3baVarD/DnoyX7gAKxdi4HHmK23s
         LpjrSWiRUbC0xIfkw7pqVf+rv5ff3Y4hz+EHhmAAYYGwIaeTYXFT235uBDi+9/nUb2qc
         peuQWfjSFyNaJGBJswb7Rek+gKuyjpToOemKLvpYoHD6PoXNcdmFljHt9pIqG+XZiULI
         lI5XONV5IFqoGPC7ghTSJlrYMUsLxrFAFYaq4mqBpxLm56zn9tBtld8MOzrY7UdPgRqd
         dJMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qqgFzyb1;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id w30-20020a9d5a9e000000b006b9f166fa6asi122046oth.4.2023.07.19.08.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jul 2023 08:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 41D936173B
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:06:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91FF9C433CB
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:06:54 +0000 (UTC)
Received: by mail-ed1-f54.google.com with SMTP id 4fb4d7f45d1cf-51e429e1eabso9871447a12.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 08:06:54 -0700 (PDT)
X-Received: by 2002:aa7:c1cc:0:b0:51e:ca0:8a2e with SMTP id
 d12-20020aa7c1cc000000b0051e0ca08a2emr2687589edp.36.1689779212858; Wed, 19
 Jul 2023 08:06:52 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-4-lienze@kylinos.cn>
 <CANpmjNOHL8EMP+E9w5wxMJ+PUbxYZh2DMaEocfHP1ATQn64+ng@mail.gmail.com>
In-Reply-To: <CANpmjNOHL8EMP+E9w5wxMJ+PUbxYZh2DMaEocfHP1ATQn64+ng@mail.gmail.com>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 19 Jul 2023 23:06:42 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7Ca08Aj1y5HHUsUreOdBTQwVu=H+3nFOUjiUiq5aR76g@mail.gmail.com>
Message-ID: <CAAhV-H7Ca08Aj1y5HHUsUreOdBTQwVu=H+3nFOUjiUiq5aR76g@mail.gmail.com>
Subject: Re: [PATCH 3/4] KFENCE: Deferring the assignment of the local
 variable addr
To: Marco Elver <elver@google.com>
Cc: Enze Li <lienze@kylinos.cn>, kernel@xen0n.name, loongarch@lists.linux.dev, 
	glider@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qqgFzyb1;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Marco,

On Wed, Jul 19, 2023 at 6:55=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 19 Jul 2023 at 10:28, Enze Li <lienze@kylinos.cn> wrote:
> >
> > The LoongArch architecture is different from other architectures.
> > It needs to update __kfence_pool during arch_kfence_init_pool.
> >
> > This patch modifies the assignment location of the local variable addr
> > in the kfence_init_pool function to support the case of updating
> > __kfence_pool in arch_kfence_init_pool.
> >
> > Signed-off-by: Enze Li <lienze@kylinos.cn>
>
> I think it's fair to allow this use case.
>
> However, please make sure that when your arch_kfence_init_pool()
> fails, it is still possible to free the memblock allocated memory
> properly.
>
> Acked-by: Marco Elver <elver@google.com>
Does Acked-by means this patch can go through loongarch tree together
with other patches? If this patch should go through kfence tree, then
the others should wait for some time.

Huacai
>
> > ---
> >  mm/kfence/core.c | 5 +++--
> >  1 file changed, 3 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index dad3c0eb70a0..e124ffff489f 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -566,13 +566,14 @@ static void rcu_guarded_free(struct rcu_head *h)
> >   */
> >  static unsigned long kfence_init_pool(void)
> >  {
> > -       unsigned long addr =3D (unsigned long)__kfence_pool;
> > +       unsigned long addr;
> >         struct page *pages;
> >         int i;
> >
> >         if (!arch_kfence_init_pool())
> > -               return addr;
> > +               return (unsigned long)__kfence_pool;
> >
> > +       addr =3D (unsigned long)__kfence_pool;
> >         pages =3D virt_to_page(__kfence_pool);
> >
> >         /*
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7Ca08Aj1y5HHUsUreOdBTQwVu%3DH%2B3nFOUjiUiq5aR76g%40mail.gm=
ail.com.
