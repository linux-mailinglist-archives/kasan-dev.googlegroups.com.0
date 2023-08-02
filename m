Return-Path: <kasan-dev+bncBAABBZXEVGTAMGQEXNU5B3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BBB576D128
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 17:12:40 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1bb809b748csf563085ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 08:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690989159; cv=pass;
        d=google.com; s=arc-20160816;
        b=ae2yhoKZWCDJ681I6n/stLx3xNq0zC80W9P/NL4tmEO0CAYRheSepQunVT3/qQhZ52
         sWsReTp89kOfI0A5o+yo+CZgtsXaX0R5KHzVkwn0OFfzH54+ZTWpnAGAh1jdzuQydbkc
         Xd1lbGuVuubgGIws1b2P2FiDusWF9cmnYb0NdmvQpitFJvPd4HMOfaGFAFghFY2XuTtE
         A9uhEjh6Frz5IS9KVVImCaBXlL93bVC1tMEXLwcPR9sbVFn20Lm7j8pPHN/p+AEhQpKR
         eiwimx0tRcRawUS+JmkBxl/0wuRzS55dGUoLzS72EpGrD1g+AFVU65ycznbgDWmA+zTa
         9c3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=eOdVjuTWYNg3+CPPui3vWrqOsqTF8ebruxqulhIxeSI=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=q8JErpKqNx8nAgDY25FdNmAsaR8A3qF7TuFmV8rZ4KzqIBqc3T40mVUJee0LxJo9UO
         IcWNhLgLabos5nEzhmADeJ9L2WP1eiqitSmXZxUY3fN3lRq+IoUP/e/ReEetxqEAjMwo
         yLihIDpnQXxbQ8BQ1NdOLjc9r4tXwg4SHCRiea/jHDuscSdXhhyheHnh9ZR2Ov2x6jrK
         d1wHC6/mi3SQblQGVKCpN72xj3ChiYsMFxgQsC5RbWs7w+A4veo+CptMAXFTDysRjU/H
         x6iDMdF18EN0GxpEHWd55pPODINsF3t5E2z+bDzeqPmdEFt4yeGLo1LAweaTiLfXvo0a
         rEbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KTXzkScC;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690989159; x=1691593959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eOdVjuTWYNg3+CPPui3vWrqOsqTF8ebruxqulhIxeSI=;
        b=aVpUkwYlsDyWvOFTeOlnDNE776N+wbk+AAEahpaovoY1CMPpjmrbLPzIfWVBrhmPCM
         WvVr+Qt4uTzJTc3u+e/WwXEu7EcKKcYBr0O+vF8uDPzKnLfhFilts3+DboFH+XDH44LM
         zzFxdcgqJDlSw2dw0Hug4ROfzLSLYZpbpfXGTyZ+hBl+hLg61VSauT66v8FhXnQnySo0
         TFrNSgxMuOv2yLPXa3781k0DUKQfw/5rqK4cNnav2HtVxQ4I7oHDrx+knfhzRVFricIQ
         bkw6uXgjJbQ3gplvrmpguOnL5RjJZc+DQrDSI37Uzbwz+jV49MBD0XL+yYoOQKjaTjyB
         MfRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690989159; x=1691593959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eOdVjuTWYNg3+CPPui3vWrqOsqTF8ebruxqulhIxeSI=;
        b=Y3AGr3SK5RWD8odlHVWfCdEtylMrZdhyRv2nNx8dZUl8V6B0e9iQTTh0L+WaMnrM5u
         FLB1a58rmH+u5B7vNT0DQtkvKR6mt8vcmCt3mPakH0VpbgyenKc2Wju5r8G7THRv33gQ
         7pEr92BBFnKe+66VyWO6nVFcZ3vfnihf1d/kWeD1YgeiIvy4rj/ammX3Ru1tioPwr2fm
         aYfqGABv5UomFx9P6dYiVarlwhCADokbC5giwyUZoSHrxKQMGSdd9hAKnyy3EjA5qGve
         LovBrSEZEYmHRF8GO2ZYXKv/gWWvzOwc7E1TGVuD4Tt1eZTrzRLAgIhl9CUpmzICIt4y
         WwgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbvzfOTABRZ/hlN41ExggRk9UwZbuywhKKA7EwkVr52ZBtddJnA
	j2/5RhkfNU/7ULrB70YSklg=
X-Google-Smtp-Source: APBJJlEjGuCw1Zbne1fzpshTunma7bG833XZv1oBW3bj4816Fx9uZWjh8FhbpfChSFBCPVZFJjApnw==
X-Received: by 2002:a17:902:ce90:b0:1bb:ad19:6b78 with SMTP id f16-20020a170902ce9000b001bbad196b78mr846105plg.0.1690989158923;
        Wed, 02 Aug 2023 08:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4592:0:b0:56c:7bbc:374e with SMTP id y140-20020a4a4592000000b0056c7bbc374els6272614ooa.0.-pod-prod-05-us;
 Wed, 02 Aug 2023 08:12:38 -0700 (PDT)
X-Received: by 2002:a05:6358:880e:b0:134:ec9d:ef18 with SMTP id hv14-20020a056358880e00b00134ec9def18mr6250370rwb.28.1690989158341;
        Wed, 02 Aug 2023 08:12:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690989158; cv=none;
        d=google.com; s=arc-20160816;
        b=LPx4MCL8lttwi9S7diwOsDMpJGPxMEmEDVdwtLQl7nyeDR2ForHiHHLFxvis6u5ibF
         ZjdOj4yqKNQflLNWhGY8l0U9idgXHCK5oiC1AZreRx2uHqUof1AM+Fe+eiUepshVVFDK
         Yk4sHq5G7ZY8mmjwbaQgyIQ20MyH2jCw4EvniGBxI4KYgL5U4ncI1Qe2nWd3Af7Ktggq
         iPDoKYmRWkV7bQzPNhHWzSKUCMxw0zcE3XaI5mYaPgq2ErNiXjT7S5wEmNaMHh9AfP9G
         EDEeMNE2otbOhdXM0YXwTjloqQg9CV9/XDjvV7nDBu1SCSkCFcD3mno3yK/umbJrxH/d
         3VMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mfYiR2Xby+itEFPf3/ZL0bWmx5pPHmkxC5yq48DJu/k=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=bv3LUc51Jkj8kq7vrDkUNL0rvC+ElqOI+8g8fE6dp/ARqn5ytEzKcKs7hb0FqSGrYV
         L7IAbwizFpBkjeww9k+KgyM+BmrqFap/aYqdGPgcyswVe5fSqLQ0gE8s1wIX2rStClzf
         XDyxVilczB/EYa1Ju7f0K1NwqB0w29CrQ3JWSRiGnw/1S6G98/GLeQ46yWFEQy6rV6g1
         fUWhpBWanBNDzvxzmDsGhZppYlUc3EFVGJH0URf7/ZCJRwf7By21fSmwqsUzSX5Su/xE
         1bBeuPlwWVub9q+NsUQ/Edd3aldIOIl+2jeIHtDH6v9irvoeLYlf1K01RlJtU3GhrdU1
         oUnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KTXzkScC;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id m17-20020a0cbf11000000b006363f2c380bsi1068244qvi.7.2023.08.02.08.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Aug 2023 08:12:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CD319619E9
	for <kasan-dev@googlegroups.com>; Wed,  2 Aug 2023 15:12:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3FBE2C43391
	for <kasan-dev@googlegroups.com>; Wed,  2 Aug 2023 15:12:37 +0000 (UTC)
Received: by mail-ed1-f53.google.com with SMTP id 4fb4d7f45d1cf-522ab301692so7485740a12.2
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 08:12:37 -0700 (PDT)
X-Received: by 2002:aa7:dcc3:0:b0:522:31d5:ee8e with SMTP id
 w3-20020aa7dcc3000000b0052231d5ee8emr5771244edu.8.1690989155487; Wed, 02 Aug
 2023 08:12:35 -0700 (PDT)
MIME-Version: 1.0
References: <20230801025815.2436293-1-lienze@kylinos.cn>
In-Reply-To: <20230801025815.2436293-1-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 2 Aug 2023 23:12:23 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6FqreZtuOXYayhu=bLZeij+fxygbK5Mpw_kVuPTvdbWw@mail.gmail.com>
Message-ID: <CAAhV-H6FqreZtuOXYayhu=bLZeij+fxygbK5Mpw_kVuPTvdbWw@mail.gmail.com>
Subject: Re: [PATCH 0/4 v3] Add KFENCE support for LoongArch
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KTXzkScC;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

I applied this series (with some small modifications) together with KASAN a=
t:
https://github.com/chenhuacai/linux/commits/loongarch-next

Please confirm everything works well for you.

Huacai

On Tue, Aug 1, 2023 at 10:59=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote:
>
> Hi all,
>
> This patchset adds KFENCE support on LoongArch.
>
> To run the testcases, you will need to enable the following options,
>
> -> Kernel hacking
>    [*] Tracers
>        [*] Support for tracing block IO actions (NEW)
>    -> Kernel Testing and Coverage
>       <*> KUnit - Enable support for unit tests
>
> and then,
>
> -> Kernel hacking
>    -> Memory Debugging
>       [*] KFENCE: low-overhead sampling-based memory safety error detecto=
r (NEW)
>           <*> KFENCE integration test suite (NEW)
>
> With these options enabled, KFENCE will be tested during kernel startup.
> And normally, you might get the following feedback,
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
> [   35.326363 ] # kfence: pass:23 fail:0 skip:2 total:25
> [   35.326486 ] # Totals: pass:23 fail:0 skip:2 total:25
> [   35.326621 ] ok 1 kfence
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>
> you might notice that 2 testcases have been skipped.  If you tend to run
> all testcases, please enable CONFIG_INIT_ON_FREE_DEFAULT_ON, you can
> find it here,
>
> -> Security options
>    -> Kernel hardening options
>       -> Memory initialization
>          [*] Enable heap memory zeroing on free by default
>
> and you might get all testcases passed.
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
> [   35.531860 ] # kfence: pass:25 fail:0 skip:0 total:25
> [   35.531999 ] # Totals: pass:25 fail:0 skip:0 total:25
> [   35.532135 ] ok 1 kfence
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>
> v3:
>    * Address Huacai's comments.
>    * Fix a bug that Jackie Liu pointed out.
>    * Rewrite arch_stack_walk() with the suggestion of Jinyang He.
>
> v2:
>    * Address Huacai's comments.
>    * Fix typos in commit message.
>
> Thanks,
> Enze
>
> Enze Li (4):
>   KFENCE: Defer the assignment of the local variable addr
>   LoongArch: mm: Add page table mapped mode support
>   LoongArch: Get stack without NMI when providing regs parameter
>   LoongArch: Add KFENCE support
>
>  arch/loongarch/Kconfig               |  1 +
>  arch/loongarch/include/asm/kfence.h  | 66 ++++++++++++++++++++++++++++
>  arch/loongarch/include/asm/page.h    |  8 +++-
>  arch/loongarch/include/asm/pgtable.h | 16 ++++++-
>  arch/loongarch/kernel/stacktrace.c   | 18 ++++----
>  arch/loongarch/mm/fault.c            | 22 ++++++----
>  arch/loongarch/mm/pgtable.c          |  7 +++
>  mm/kfence/core.c                     |  5 ++-
>  8 files changed, 123 insertions(+), 20 deletions(-)
>  create mode 100644 arch/loongarch/include/asm/kfence.h
>
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6FqreZtuOXYayhu%3DbLZeij%2BfxygbK5Mpw_kVuPTvdbWw%40mail.gm=
ail.com.
