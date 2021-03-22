Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5F4GBAMGQEKTYSTOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53F84343B81
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 09:18:09 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 131sf59850012ybp.16
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 01:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616401088; cv=pass;
        d=google.com; s=arc-20160816;
        b=kNYHR9ibZIz7v1BnEQv4PRRWcgVFG022T+MN5UWl0YnxQ96SULchCuuelDp1kW4ZNx
         RODsu5FJlTilTmy4RP88T0LG5BgCMmRb1KddqHEb1tp9ALjf0E6n6Iw263jnWRP2fBMn
         vA1bL9VqTpQWXle1mJqEomG65bUI+tuPFaNlVf01+0z8zDkdG8Qbdw44HLAiqeq0h43+
         I4MQANz+CxD9VgmVZhovYL9/EkFbm6J+5A4SejarDKr+xVI1SMAp0cTOYNbfRsrla8M5
         qR1sEZqXZRERGM/UvzcJAhZh6Z2YwXOJ7YeQILlH3iPpMy2+bFqdeL16juB7Pa3pCrK7
         ylng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YWKW2kCGFrB2+wd9wUqmdDtfAyMj9iXCQC1hr/Si6BI=;
        b=BDFVpiJUWHR4ia9OYWeeiaTFOEbXA6iTGUgyN5Hr3XeFtjQ0Ew8wsmcSMRnoJEJTTp
         Nfwc2eJQ8Q8/c7uulrAR8Y4Z3gOcyuS+lHXeOXUvBFTUbPr3Pr6kOWEZjXBVnqQWjvX+
         gTOL5xqc3/3aMr2SaPDk1PVYaHMa/xRLsa+8gijwxBOxEevIAHp4/i/YXfhCYyQedobR
         XnUMSsEArSPCVS0ReMJ7XMUOqvCYRodeNpqO6h92Y/Lzg43My1Ql1vDgytqSPBlOTAx5
         w74cXLsYNDTcl1283De/P4Iu5g4kTL9IVPS2wyu/sgql4nPlqg+zrj2kcLYSm4EguEj7
         5UYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UsoPckqy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YWKW2kCGFrB2+wd9wUqmdDtfAyMj9iXCQC1hr/Si6BI=;
        b=aEYy6DFepSWykGe/OoLR10QPqAqaFMexHRcXtB/8SK5Jpm3y9lCa6aIRbCNFY+gCFF
         KDVcHQwz8yInx07VilJOFBNNveO0Ast353bc6x7+sDxrxLFpNIDRa1hjGS+MP8aoUqQW
         5lkQKVBOy0nIKZ9ymIAv2xuyoI1jPAupQ7vGBmYA6fFpAe56wCL5xNXbb3cq9C8C5+7A
         BjgqJ88WCqRKoJTKjVsWHKHfm2EktCweg4zi5vd/vcKd48axl99T6UqL2Foa0yA9WNeF
         9nyE6RLmgiENgcYyr8K5y+2lV7KjiM7f7DaXmjSKF4ByEFq2T6qUo3Ym2zNvtABgbuu3
         aeTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YWKW2kCGFrB2+wd9wUqmdDtfAyMj9iXCQC1hr/Si6BI=;
        b=gI6dIlEAVcbHfr0pL8GotnnPh5iac3JKV9p3zOBo35G+SMWUw+wYxPDjYH+PSAh8Bn
         iyMLUg8C5NooEr2pZPeRwfRaM+0tr1I88cT6EF0qGlme2RdXdKg9IYwKs3eUfpfda8A0
         oUqtLLekU7NfzONrR9CvI88refAujAHvAUyr/BKsBVPqDTW+UOMvtPZ0Q66bMvBDiKno
         TrFBETgfIgp5W9oS2m/aYx8uDK70FEGIigQCNHfWSs0R7PpKHXnvOkJ/Yv540rtbeVhH
         xE1W4NBZGVmutQDybZzzMkj32GNnqMSyUtw5o8AyPtDM1HSO/kzXFGziRfncL6JN3F2+
         ufxw==
X-Gm-Message-State: AOAM531qeVkXKI7lgdDIpCjO801S12sT3kSqmJwA9R4yTDrzNhIQ14YG
	rhgSkgk5TOm1rAYmyqnnpos=
X-Google-Smtp-Source: ABdhPJzYue9yGHZVfgWx6MUQP9CiHyF7Evo3KCcBDzOrECr334CfvFVAGLOvIcwpvIPMIxZQN+i81w==
X-Received: by 2002:a25:df8b:: with SMTP id w133mr7353859ybg.140.1616401088144;
        Mon, 22 Mar 2021 01:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6603:: with SMTP id a3ls4614164ybc.5.gmail; Mon, 22 Mar
 2021 01:18:07 -0700 (PDT)
X-Received: by 2002:a25:868c:: with SMTP id z12mr2030664ybk.389.1616401087626;
        Mon, 22 Mar 2021 01:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616401087; cv=none;
        d=google.com; s=arc-20160816;
        b=FkwgTGpAzjW1Za5eG/DWza1Gflh03TdtMwQZxkH6jkM/ig0YrA4MYqlmudi8cMLg+d
         3JtsJu6OZo2rmQXP1ytR/DWejSOsMDTcrSeNphwxlAqSY+Hw31Xhe8/SeIPCzniQq/nl
         mXm3+/BJewN7qFntPb52QNiULWfuAArwYjT4NIHvsX+dbaAUR1kQUkhbTzHwlb6XKZd/
         CySsidlDSbZs3xCCy9BEGk2+i74j0jmgJsbMx92lTYG7W9qBMQZaXVbKGY304PnzVNwX
         s7nJ7EUjbO5QTZ63LtvtARU8IhNv89i0qlB9vQaKJz1dvL/Cp8VfdoCf/vWBV6SnOY3F
         T1EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sk5nXZmNrPBhnu290SRFE/AaX0zXvxqhg24fy7HJRik=;
        b=dNS5XvPKUJ0BXkFAhIDN1Flfls46W+4Polk+yuWNQzNL8fyhGyuZuGbVzjvGZde3Pn
         WI1kUPtXEFAUaolpWH0ynx3KNlAtxNt8+OQPx3HagvhLt5gTlOARbAfQHG4V9WXD0/ux
         AlkK5z37f6LASuTMnYLvFt3e88jQdIuR2XBk8djvS2dza8RVBbqp0k13V9F0wQFhm84+
         N71LsQ6TyqjpSGNlJNvWkP6L8zzZj8Jbqq5E+BqALLm7wqTqbLtu6vBNeqBV1RlvmAPL
         lLsu5EXytOt75Zu6R8hbw3lk8ZNmw1Igyy3pKcfqDjSB84SEs2EwhNwlRoqR3WNCbo19
         BPmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UsoPckqy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id t17si833538ybl.2.2021.03.22.01.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 01:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id l23-20020a05683004b7b02901b529d1a2fdso15083691otd.8
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 01:18:07 -0700 (PDT)
X-Received: by 2002:a05:6830:1c6e:: with SMTP id s14mr10905818otg.17.1616401087131;
 Mon, 22 Mar 2021 01:18:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210319144058.772525-1-dja@axtens.net> <20210319144058.772525-3-dja@axtens.net>
In-Reply-To: <20210319144058.772525-3-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Mar 2021 09:17:55 +0100
Message-ID: <CANpmjNOGp0DLn8sMwvm5SQo4cqJDogtrEPGFhawRPd3Amr3D=w@mail.gmail.com>
Subject: Re: [PATCH v11 2/6] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>, 
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UsoPckqy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Fri, 19 Mar 2021 at 15:41, Daniel Axtens <dja@axtens.net> wrote:
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>
> This will only work in outline mode, so an arch must specify
> ARCH_DISABLE_KASAN_INLINE if it requires this.
>
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> --
>
> I discuss the justfication for this later in the series. Also,
> both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
> ---
>  include/linux/kasan.h | 4 ++++
>  mm/kasan/common.c     | 4 ++++
>  mm/kasan/generic.c    | 3 +++
>  mm/kasan/shadow.c     | 4 ++++
>  4 files changed, 15 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 8b3b99d659b7..6bd8343f0033 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h

Does kasan_arch_is_ready() need to be defined in the public interface
of KASAN? Could it instead be moved to mm/kasan/kasan.h?

> @@ -23,6 +23,10 @@ struct kunit_kasan_expectation {
>
>  #endif
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#endif
> +
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  #include <linux/pgtable.h>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6bb87f2acd4e..f23a9e2dce9f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -345,6 +345,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>                 return false;
>
> +       /* We can't read the shadow byte if the arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return false;
> +

While it probably doesn't matter much, it seems this check could be
moved up, rather than having it in the middle here.


>         if (!kasan_byte_accessible(tagged_object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
>                 return true;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 53cbf28859b5..c3f5ba7a294a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
>                                                 size_t size, bool write,
>                                                 unsigned long ret_ip)
>  {
> +       if (!kasan_arch_is_ready())
> +               return true;
> +
>         if (unlikely(size == 0))
>                 return true;
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 727ad4629173..1f650c521037 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -80,6 +80,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>          */
>         addr = kasan_reset_tag(addr);
>
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         /* Skip KFENCE memory if called explicitly outside of sl*b. */
>         if (is_kfence_address(addr))
>                 return;
> --
> 2.27.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-3-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOGp0DLn8sMwvm5SQo4cqJDogtrEPGFhawRPd3Amr3D%3Dw%40mail.gmail.com.
