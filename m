Return-Path: <kasan-dev+bncBAABBNX37WSQMGQEDMP3ACI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 68293760C43
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 09:46:00 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-55c475c6da6sf2377923a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 00:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690271158; cv=pass;
        d=google.com; s=arc-20160816;
        b=s2M59xikr82aSwNCOWbyOLi0RBrMPPnmCgs4ZyXB+x4ZkUQ4ChowEA6UZIYIHsIqHj
         kWMVOQCc3Bba93MT3xfwLSgN4W4e6OHCJQ5ZsybkB9fHPehJyrfQE63KdWEeFWa1Yh0J
         xP9poWWE9IIKbBgp95v8QhAR6jK12D6f8T9OIrCH3+x9nFoulw5hrRFsPKsPMlGDwHOY
         k44rxdMEiUSrpczWkxmZcDSfQr0W1LRRqS7J95LdG7L6SFODfI31wVwV1AXplAv703Eo
         ohsAumm16rBOy3qcSUj9QYd0CI/Zc1kAJx95A9xx/PYubE9Mdyb5XT8s5WMKeCMi8mSn
         sBmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=pg+pKNeKFO0noR81HDrZH5nN/Uk6xNbm69G+myTWjJY=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=iK0MIjL/l7b4WbMguUGY/9BzlsqqjleNJs5HhslQeCQ0lGzWuAsV+ydmb6sQ8WKlN+
         yAUofblG0YLBOeYgVvGaXavjR1+WvREm8Dgdz3qcRhRVGPlYwNz4oMfQccXnFy+CpOZm
         HHdPi7UqOBfX9FV+YhtYcz27EwP7phpqPk0N2MuUshoFEWT6otmyyygNXER+UVi4Kodn
         f4tJeG9y5M3ZZvhkWEN6VEEQqlBxBP2Q3uHkFXJf4ecKz2/dVAV9lBARF5Lb5MYbSlFl
         1mwr0zPjg8giQ7HMIbviQ4ysgg+ANC1YVb2vSeMs6yPPD+MG2bpRVOC6YrCVq1a9SARV
         FjPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JIOOxeLK;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690271158; x=1690875958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pg+pKNeKFO0noR81HDrZH5nN/Uk6xNbm69G+myTWjJY=;
        b=pMm3C/UQgFAtVYjf8572gqF0zi4g5MPQE8LYplr0L6u8SMUu00MCjo0YLj/ze2Q3cJ
         y0IfUywsMFw/o0jgEq1CwT0VYBWXArpxHNLFJRDeaS0nwMGfJn3qEg0fvC5kfZpgNAVf
         muQFBJ6aixhMr9FGmy2WfSTmHF5EnOWohahO/MFJc3FmSnDBn9WTyCz3vxNEjRpCNXO0
         8ZLUy5H8ShAnKCuM+3mQvFx7FnCEpwcdZgzR+LwPKUmLOpJYNEPJ55pSpHrzG3+1eO46
         okFGoDbf34zS9GqMPbDkhKmKzgJJLxZbREf/b0Wxn8T3HlepbvaA2DIiSiT6WMZejkjr
         xSHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690271158; x=1690875958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pg+pKNeKFO0noR81HDrZH5nN/Uk6xNbm69G+myTWjJY=;
        b=X/KKU9KKj+9rEuqRTL+RcYJm8oI/Xx9g4Ly0PW/H1iQW98/qmYKDzUP+wcWP2PEzno
         +U00d2c5P9PSshryc8mJMaD6r4Rn1HhLj/ZPSSe19xNsBAh0lZAyQJCgP+/yXaiM1TKE
         OaL4ClGgUPRjWLA10BAPcXyYhVcQjsDh27ldhRJe0F1yrQ8Mhzi2Q6cjbY5IIX2cP48f
         sfrgrzhNL2uNL4JRKV8hTYjxD6WO//p0HIqPvMoJCndyNvXEgxhg46auDd0jrkHwzPy3
         wqoxiY0tAlMUuZ6zSJaHkes+8xWUHNn1EDsyvzMwHfDL1Rm5TJGaA9w2APgDqytSbqDs
         Hcxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLa619LAWEKi7YWeFnmnOxRmR6gAs7lx6w0XGvBUelFCXjx9KafK
	/to9d1HNDRDd5UKSZKDTYoE=
X-Google-Smtp-Source: APBJJlGv3q6GA7jTenRuV2fhBsCfKMZjFhp1UWR7+RCL9KbwJlJIOyWzRyLn4WZVL8tWdYLPDc9/rA==
X-Received: by 2002:a17:902:bf02:b0:1b8:5bcc:2ffc with SMTP id bi2-20020a170902bf0200b001b85bcc2ffcmr8447148plb.45.1690271158409;
        Tue, 25 Jul 2023 00:45:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6e10:b0:1b8:9bba:77a7 with SMTP id
 u16-20020a1709026e1000b001b89bba77a7ls511293plk.2.-pod-prod-02-us; Tue, 25
 Jul 2023 00:45:57 -0700 (PDT)
X-Received: by 2002:a17:903:41cb:b0:1b3:d6c8:7008 with SMTP id u11-20020a17090341cb00b001b3d6c87008mr11839724ple.57.1690271157661;
        Tue, 25 Jul 2023 00:45:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690271157; cv=none;
        d=google.com; s=arc-20160816;
        b=If+SpO1RHYeCCwPDz4K6RVyy+ZeUYqf0dwCzeon1dFaTycthLKP++J0/rEtvC0qW1r
         wt/IwQOpJLaL/fng3DBQD2suBlKNfn7eK7/abseqF9s3GoQZjk3qpKL2O0XvHiHRp3FY
         gddvmffoSzCVpvrwwk+E+TLwj2Jj/DuweNY+HglrLrX6ttiJn+y0+HbSGAgcKbA6blPn
         IJgt3TVhHj9yK1UmMsbDYq41u/DFG8NUZjnsHww/AWJvdINl1RpDhU3Lzwnexlh/jfpO
         loG+i5hmnKQDhkAYtXMvq4JUXOD9AkxwPR7Sjqw08EjeA6+ALfsEKEXWRAZCRDY7A48O
         ctsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HXyJI6vPSlUN/DrKOtEDI9CVxKqG5iQYUqOSzPkyMug=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=s0iRk2dk7FDyBVw/k5hYDWSK6+J2sVJZurxYIUskqlscf5qSy3oZGoVy5n0Y2jIGLw
         HtM5JT+aM3jltXyVO2x6BF/YX/WRmnreGfqf73BzheywIAQB6oORlqHYoW/gOE2kciNJ
         ftfhZY6Qo/8lM/fuGFVjGZUUcEtOBtJN1NLJ9Kq7tR3zR0CygkVNxGzvAANytR9C+/KF
         hwG9HbE+7dvT67KM0ARL/nDgtNpBfWwBDoJZjUVDo/rcK+L7ZodZErhuDmAzuuOrIUnV
         IW3ncwJGdh7QKb7exzJzwZXuCLghAy9y35+DmLuS1SRpxfx7cYK8Zo0T5Sc11x9XrISU
         1zPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JIOOxeLK;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id n16-20020a170902f61000b001b8b3657d9dsi611285plg.7.2023.07.25.00.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jul 2023 00:45:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EB7476120F
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:45:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF4CDC43391
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:45:55 +0000 (UTC)
Received: by mail-ed1-f45.google.com with SMTP id 4fb4d7f45d1cf-52256241c50so175059a12.3
        for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 00:45:55 -0700 (PDT)
X-Received: by 2002:a17:906:76d8:b0:99b:8c6f:f3ab with SMTP id
 q24-20020a17090676d800b0099b8c6ff3abmr6993697ejn.13.1690271153978; Tue, 25
 Jul 2023 00:45:53 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-4-lienze@kylinos.cn>
In-Reply-To: <20230725061451.1231480-4-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Tue, 25 Jul 2023 15:45:43 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6HzN63ccAR0mYpmJ4kV81REO+yk2h56Psic0==iMuMZg@mail.gmail.com>
Message-ID: <CAAhV-H6HzN63ccAR0mYpmJ4kV81REO+yk2h56Psic0==iMuMZg@mail.gmail.com>
Subject: Re: [PATCH 3/4 v2] KFENCE: Defer the assignment of the local variable addr
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JIOOxeLK;       spf=pass
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

Hi, Enze,

This patch is a preparation for LoongArch KFENCE support, so it is
better to move to the first patch.

Huacai

On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> The LoongArch architecture is different from other architectures.
> It needs to update __kfence_pool during arch_kfence_init_pool().
>
> This patch modifies the assignment location of the local variable addr
> in the kfence_init_pool function to support the case of updating
> __kfence_pool in arch_kfence_init_pool().
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> Acked-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/core.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index dad3c0eb70a0..e124ffff489f 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -566,13 +566,14 @@ static void rcu_guarded_free(struct rcu_head *h)
>   */
>  static unsigned long kfence_init_pool(void)
>  {
> -       unsigned long addr =3D (unsigned long)__kfence_pool;
> +       unsigned long addr;
>         struct page *pages;
>         int i;
>
>         if (!arch_kfence_init_pool())
> -               return addr;
> +               return (unsigned long)__kfence_pool;
>
> +       addr =3D (unsigned long)__kfence_pool;
>         pages =3D virt_to_page(__kfence_pool);
>
>         /*
> --
> 2.34.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6HzN63ccAR0mYpmJ4kV81REO%2Byk2h56Psic0%3D%3DiMuMZg%40mail.=
gmail.com.
