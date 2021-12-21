Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGWQQ6HAMGQEZCSH7EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0670247C1C3
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 15:43:40 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id c24-20020a4a3818000000b002c9ba7f00e7sf7577080ooa.18
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 06:43:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640097818; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwwhQOfO3c9XFdJrZIARrbgV9UqPBpirHZvuVfdeumPXtFGeN7BaEPs+zeuc2Qipa8
         MoPYrjCP1PFeM26NXPWbLJw5/Or2Mzc804S10gD+Y0O6Tkwmb+J4yF6odJr7gL8StbHm
         oZg2yPfUsyAoc1coTJk1HHTzNvaXO3iRp0o/GLkUEcJvyaOXx5yGPSssoo+fWseyGTj4
         NW1UW0Ffo+WNYzgoia5dYZb3q/UJu6LPEtmSdOtHF7lPBc96/m3XO6sY1QfD20p1UxbD
         QS42Azgvxx7bLCtt/aDB65j/3bGarUtesV7VRvwR5b/zCBfkjJVJnk+VrphXZ+tq5608
         QQ5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DhXn3gYiNJdBSjYG0/xvR2ADSo6A2WagTSaczCOgULA=;
        b=027nMATW6Rv0iCFEVZ8dJIsFavoBjxTHe22pMete75iC+1o/TCvrz+LLIe7nSgdW96
         YvQ2wzpa1PPk6hiG0bNzXdvIHs0LUAYCBWo11ysOqk3BtS3O35mxKh0CKuKu2bPNx8Iz
         EG0vwGoyxkLDTYU/F2eAWlGG5xYoRtfb9m0VmmflbD7wY8Z9K3W7sZUY5j+WabD1NBaE
         XqubWs1p30BEiACJRGi6AZGAI2srOAduA48OubLH6UvPfi8FmtdhC7qo/VkW+vlk4hY1
         4JZh/IlpqLQSOVTgsXnTVpoqEdpB1eY2SEpVKE4Krki37c53nHyBkf7NWxNQeysjviwT
         vi1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=luP0qgoH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DhXn3gYiNJdBSjYG0/xvR2ADSo6A2WagTSaczCOgULA=;
        b=dsX8Q8XcKkn3FWSmBJEdt0wnnGwXBn253NaaDQ4eq9yah/J7GA5XWSigd/ozzHHOpx
         FKsuN0TNA1wiDN3K+qsF6Q+i4T/XWzkKYMLleJqnb3gx2byNQWUBp4FSzOf5K5Deexj6
         Kzh8o3eU1YsMi/+mq43+3vYmOU39aqVPY6bxd8ItFUJsoB31q30Agz6U6tOr74DfZus4
         oucmIOJs2DUDEYnMmqj0SzB6wIesfTAZTFPyZLZwLCN0kqGkoI+xMjFAt8+ZumgchnPP
         AsDH+7Wp1RM9Au6TIZA8kkDyANsclXf70oNmy00djX+4ctBcHC6RDI8IaS3SVrO/GC/K
         BpVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DhXn3gYiNJdBSjYG0/xvR2ADSo6A2WagTSaczCOgULA=;
        b=1NfuwBoFqvacJy4QEo8XEz1EGFLXdfCOvqo+0yLPjKJFGdlkk3ZTlhZ8qIR2gaL09t
         a5SZer2vp5nzxpQusHMhHebBitw59CTe4cTiYL8O5ZkVLzBQaL2dbegnlcFLXdTL7W5A
         lRi8gk/l1c/tzZsrip2KDGU9RPjLXKcIj4KeG8VJqgG6hRjgF98akzyU0KmVHsDNJ578
         EUGgOFmoXeyL4Ct1r2hZ7Fr9Rw8Fq/68MEpsbs+AMuL7EEJLdW/UL8jTYuYYleKaMAiP
         7zfVjnuBqN3wWQmDdmoD6A2SbgVGCNLjrmEB+6sTrwVpE7nNrvmlFwsys1IKv23hFd+B
         K2ZQ==
X-Gm-Message-State: AOAM5306MXYrU99rxvX61ONCDd8fGtTQmIOXKjqOHNiCBHh3xg5neDKe
	ciMNt8wwbVQTOiyCdF5Ao84=
X-Google-Smtp-Source: ABdhPJyuOW0FM2jYvB6wSiYDvz6EqAS8DUnXrZt1gnVjCEEKWyaIuGq4Pib0ZjqEHgqbQzplFMheXQ==
X-Received: by 2002:a05:6830:44ab:: with SMTP id r43mr2400445otv.251.1640097818780;
        Tue, 21 Dec 2021 06:43:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:219c:: with SMTP id be28ls4913763oib.1.gmail; Tue,
 21 Dec 2021 06:43:38 -0800 (PST)
X-Received: by 2002:aca:ea55:: with SMTP id i82mr2714912oih.96.1640097818444;
        Tue, 21 Dec 2021 06:43:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640097818; cv=none;
        d=google.com; s=arc-20160816;
        b=wgVC8OlphfXAW26mww5MQGM51V5wBZKcphQtmevm3jWha1H4oEBWujI0aXuBH/DA/t
         GZfWpM2RpYBUhlfldqSTcZOTv8xrGGtrNfEAb9WCzjo3yWnnoRa3K9GEpvARL6GNlCjP
         Ukg3J3JD2uAWI1VAEhy38g9cltB+639AdhnywRbvlPonO4uY6qCNuoKI3409g6DBo2Wn
         EjvZjU30Z3acp8XrPhtsP+S4QGk0dIsx3VhABVnQV4ykuuFb1AoMoVnj0c5FIjs5e0bn
         IqpS5T/ARYTgQxVr3WGhL7lJ5N4M4+pjOMiegC7CMiHpsUZUypbYl2YIx0vXEl18UMYH
         mPwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=epf+WjKxZfy4MqSd+K2oWsIRS0SOqREyZW9UCHGm1zE=;
        b=kd6VKjZ50OXF3b73pWoVNr7xJS5OUkanpAT7KHV1xH/PluES9bMfDAuNsCZxIuLPIp
         U9G/1eua/CJlTlGX4kmWTnxUi+Gnw7twfMRB5nX8ulCCVPIWF9YXI+XotSJGP0E16rpI
         slix/8VNac9dCIoZbeR2nVqH21Rfvi2rw9QHaB4RhN6rjH5Sz2MgV1GNgZec8VfikVJG
         L2u3n4tbFWHIIRqR23iLlIY6h2cQQncIz1WAhEBL143OK1iBhChfzjj2VwWutxn5JNBj
         gOMn2ml/CDHbaJP1YfljzDV507nFLmlZV3lF4OVpSjTPYasvI2A7OKldF0PqINirBj2b
         8Vug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=luP0qgoH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id h14si1580890otk.4.2021.12.21.06.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 06:43:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id v22so12980880qtx.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 06:43:38 -0800 (PST)
X-Received: by 2002:ac8:7fc5:: with SMTP id b5mr2467950qtk.492.1640097817903;
 Tue, 21 Dec 2021 06:43:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <f7e26047d2fb7b963aebb894a23989cd830265bd.1640036051.git.andreyknvl@google.com>
In-Reply-To: <f7e26047d2fb7b963aebb894a23989cd830265bd.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 15:43:01 +0100
Message-ID: <CAG_fn=VUBm7Q74u=U29zn3Ba75PsQNsObqjcH_=14cosGU8bug@mail.gmail.com>
Subject: Re: [PATCH mm v4 35/39] kasan: add kasan.vmalloc command line flag
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=luP0qgoH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
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

On Mon, Dec 20, 2021 at 11:02 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Allow disabling vmalloc() tagging for HW_TAGS KASAN via a kasan.vmalloc
> command line switch.
>
> This is a fail-safe switch intended for production systems that enable
> HW_TAGS KASAN. In case vmalloc() tagging ends up having an issue not
> detected during testing but that manifests in production, kasan.vmalloc
> allows to turn vmalloc() tagging off while leaving page_alloc/slab
> tagging on.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v1->v2:
> - Mark kasan_arg_stacktrace as __initdata instead of __ro_after_init.
> - Combine KASAN_ARG_VMALLOC_DEFAULT and KASAN_ARG_VMALLOC_ON switch
>   cases.
> ---
>  mm/kasan/hw_tags.c | 45 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h   |  6 ++++++
>  2 files changed, 50 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 99230e666c1b..657b23cebe28 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -32,6 +32,12 @@ enum kasan_arg_mode {
>         KASAN_ARG_MODE_ASYMM,
>  };
>
> +enum kasan_arg_vmalloc {
> +       KASAN_ARG_VMALLOC_DEFAULT,
> +       KASAN_ARG_VMALLOC_OFF,
> +       KASAN_ARG_VMALLOC_ON,
> +};
> +
>  enum kasan_arg_stacktrace {
>         KASAN_ARG_STACKTRACE_DEFAULT,
>         KASAN_ARG_STACKTRACE_OFF,
> @@ -40,6 +46,7 @@ enum kasan_arg_stacktrace {
>
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> +static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
>
>  /* Whether KASAN is enabled at all. */
> @@ -50,6 +57,9 @@ EXPORT_SYMBOL(kasan_flag_enabled);
>  enum kasan_mode kasan_mode __ro_after_init;
>  EXPORT_SYMBOL_GPL(kasan_mode);
>
> +/* Whether to enable vmalloc tagging. */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
> +
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>
> @@ -89,6 +99,23 @@ static int __init early_kasan_mode(char *arg)
>  }
>  early_param("kasan.mode", early_kasan_mode);
>
> +/* kasan.vmalloc=off/on */
> +static int __init early_kasan_flag_vmalloc(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_vmalloc = KASAN_ARG_VMALLOC_OFF;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_vmalloc = KASAN_ARG_VMALLOC_ON;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
> +
>  /* kasan.stacktrace=off/on */
>  static int __init early_kasan_flag_stacktrace(char *arg)
>  {
> @@ -172,6 +199,18 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> +       switch (kasan_arg_vmalloc) {
> +       case KASAN_ARG_VMALLOC_DEFAULT:
> +               /* Default to enabling vmalloc tagging. */
> +               fallthrough;
> +       case KASAN_ARG_VMALLOC_ON:
> +               static_branch_enable(&kasan_flag_vmalloc);
> +               break;
> +       case KASAN_ARG_VMALLOC_OFF:
> +               /* Do nothing, kasan_flag_vmalloc keeps its default value. */
> +               break;
> +       }

I think we should be setting the default when defining the static key
(e.g. in this case it should be DEFINE_STATIC_KEY_TRUE), so that:
 - the _DEFAULT case is always empty;
 - the _ON case explicitly enables the static branch
 - the _OFF case explicitly disables the branch
This way we'll only need to change DEFINE_STATIC_KEY_TRUE to
DEFINE_STATIC_KEY_FALSE if we want to change the default, but we don't
have to mess up with the rest of the code.
Right now the switch statement is confusing, because the _OFF case
refers to some "default" value, whereas the _DEFAULT one actively
changes the state.

I see that this code is copied from kasan_flag_stacktrace
implementation, and my comment also applies there (but I don't insist
on fixing that one right now).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVUBm7Q74u%3DU29zn3Ba75PsQNsObqjcH_%3D14cosGU8bug%40mail.gmail.com.
