Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTWCXGHQMGQEOIMILJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 78A9A497A22
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 09:20:31 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id q7-20020a056808200700b002cccac7f381sf2574898oiw.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 00:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643012430; cv=pass;
        d=google.com; s=arc-20160816;
        b=niPp6kDiflVIHgIQy9JnwKkgOAqPqW+wr4lfotAztcg8Q6YwVF47OJbuLLDNNK33Bc
         y7hHD2sJk8o0c3lAz+qlVudV5gfw3PJBv2DsWkaEuorDp+C4+ByL9PpdgdBNxZJerpjY
         ckBv1cUEEGowdG9/Cq4K6Q9Oa962xheq1t/Tr6CSC4nKs9zYotzEY0PlkuwBm85MkjhA
         tDNdyynu1dVz7LwoWY6yky4Zo/6ardryeYgsFNbr6JPFma2Xd60+s2tkEwLJFICVBAVS
         cdW9RgOq+R8QXxwIeDa7hOEols/VpRfccGtnj1quoh4JfxE5hJVKHar8NJWNctv+kifh
         i5FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Jk/DGcZmwQAnJ2qVfCiChrg8K387eDk5/Q0TvvMvd4M=;
        b=Y57GtQZM+VLwSrQolPd7RRk9FWWja3x022yhmoSmWPmXp5cRHiyew8gOCwPHyGUqJJ
         TPeGENzq4nxhQH8afAyBPmQyIttABF65RxvMaCDtWfnlTBboQYV4STPS0BpfzPo1BGxv
         wM5YpIOm954mFiTz9lhSf+zIAowfdtMxoLykWUTxdOotxv2ndZPjyrbqGMGdswKu0LgP
         mhwhoqJCNE2HfL04T70WV9fB1xrfcRic/Zvj+/H4KrZs5VA6HSOlMAuukS/uOK5qa3LT
         bKfkEKiogOFJSliWD8v+otTyXTei+BkV+yAa3g/E1zFi3oMP8GhGLae5QXP+h+FNa0a6
         jS2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hbC0p1Hg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jk/DGcZmwQAnJ2qVfCiChrg8K387eDk5/Q0TvvMvd4M=;
        b=TbtYXn11WVZQHgNvr9MXyLFzuwu2Kz+gxnYnOmFu/UamIUstBBhoxf9Xhhgknz/dTe
         CpXZHdiEQYHdhbptb3Tl8cK+XwQEnU+rkrHmCLIOVxKR0QkXEqPjiEv99fINVJmA7gZ9
         I1bzxdrKe2xXUjzfmqWqCwFgdHyJ/MHFyw6XsiGA9OMhGTXIMNzlsr28dIfcz+vf3KOg
         NWrfuZYuDXzFICv7lZ0g/a5aokKQ8a8syWe3Z8VxmnN6Un3Bth8iKdzbUOitOKMoxP3d
         KyY8e335i8RXGijA+z0ifA/MwgrIHog/dViSJAit1WFqvDQfvcrBDGKkAVcPoder8RCe
         XIuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jk/DGcZmwQAnJ2qVfCiChrg8K387eDk5/Q0TvvMvd4M=;
        b=LGfeoAzjL22/6QPRIAgoH7lJ79IYWwy6XMxTFkeDgCSlLnBqULCaOeH5vO/ASMzTFe
         VIdxYoOU50J6DDepJRrcaahmB9gjSgn5Z0w6FznnwnCzzj8Q6DBm93OUguH9Kc9Qge7z
         By8sIIk51yY0qIJaQhBriOu0druHm+OOKMRvsXg8Rf5rqXxicPv4h2i5qxFnSSgS3yBM
         liJIqLOk2tGs4q0k1MXk8Lg9Yt0MmToSRBr+ryDlps6DaRbXfmGuFxvZ01HQh1jcacyT
         Oo6Vohi4FLvE/AvPGOJBOhvkxEPGPUS7/eoDo3J52FxHRXIp5hLre6Ju6Oz13VU58PAS
         aaJg==
X-Gm-Message-State: AOAM532mCL4VYOyvhKCCv21e6VyQWoNPqeXzk2ql/rTc1hHHIIN1JV6U
	j1cbgBwP+eEImvWet9XSOzg=
X-Google-Smtp-Source: ABdhPJy3bpD1UxJYOhAuOdhdghZiwaWeo7sesWmNwU8v558YEbE7d9xJLme09+0neOkjQYiW2L3INQ==
X-Received: by 2002:a4a:e704:: with SMTP id y4mr4465814oou.2.1643012430121;
        Mon, 24 Jan 2022 00:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:17a2:: with SMTP id bg34ls5057747oib.6.gmail; Mon,
 24 Jan 2022 00:20:29 -0800 (PST)
X-Received: by 2002:aca:ba85:: with SMTP id k127mr546455oif.169.1643012429389;
        Mon, 24 Jan 2022 00:20:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643012429; cv=none;
        d=google.com; s=arc-20160816;
        b=YctHqrMUFpOlNJnP3owM8foa/RD1De7rjtsPCqo+8iyBSgQIPzlj4uy9EsI6Y9ISvu
         tAkcUj1aHhUn+CYwf8mnfAMkFV9n0/upve5odVQk0oxD+rzwDFq73ZA8UoDCQaHzOETV
         RhqKAGgtoGauFDgpwKhZW6TN8PnX6NXgk6PXJswFyq8Kdg2kjTv0wqbDzvqTaJvNcQUY
         eGvFUQPHnnX/XpMu3uakpOleULtZWea2qN5kVpOKXVcWpmSd8sIFJtG8+AFkRN6PuYa/
         d5aREumIYLqleriyYePkpQF+90JR+qP+yvDpVp57u8dND33eMD2BdT0GPNUH1RPD8Yhh
         LJlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fe4pubot63aeTTcTlbwPRtQDcLp34onKse+sfKBfh3g=;
        b=JrEZS8Nf0uFSsnsJKtFC4YBdMpK+S4UEoCsINqqGQBrtZVnxefsU2v7/JCaaiv76/Q
         Hu0L5HwyrTIIyMO0HTds9zbTCRRyHI4KyZj+N/PJj3LZO9OdYiUwaCrZtIkDD2VbklOy
         bUE+gHKuJUZEhb+r351SOwMdF8EJiXZiQhTsG+fAjVJOs7+dE/1WPv2hJDqy58AmM9aa
         1Ng5Q5AsTa+ij9sJp64jtuPAnVubGt4sBFEF98wxOmZccBSu6ED5xqSyJ2wnhv/Eu4+V
         1KEFqpPeQf5w9Duh231SqHu2/CKN5e8CBFqL1mqQN1g23/TucvmuMtQfMsLni5V9idh8
         JjwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hbC0p1Hg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id w25si89216oop.2.2022.01.24.00.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 00:20:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id c3-20020a9d6c83000000b00590b9c8819aso21199083otr.6
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 00:20:29 -0800 (PST)
X-Received: by 2002:a9d:7053:: with SMTP id x19mr10625205otj.196.1643012428642;
 Mon, 24 Jan 2022 00:20:28 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com> <20220124025205.329752-3-liupeng256@huawei.com>
In-Reply-To: <20220124025205.329752-3-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 09:20:17 +0100
Message-ID: <CANpmjNNBt8LazZMLH2_6rFc8u3bVpPNNyetV0fqmanwB5DLZPQ@mail.gmail.com>
Subject: Re: [PATCH RFC 2/3] kfence: Optimize branches prediction when sample
 interval is zero
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hbC0p1Hg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Mon, 24 Jan 2022 at 03:37, Peng Liu <liupeng256@huawei.com> wrote:
>
> In order to release a uniform kernel with KFENCE, it is good to
> compile it with CONFIG_KFENCE_SAMPLE_INTERVAL = 0. For a group of
> produtions who don't want to use KFENCE, they can use kernel just
> as original vesion without KFENCE. For KFENCE users, they can open
> it by setting the kernel boot parameter kfence.sample_interval.
> Hence, set KFENCE sample interval default to zero is convenient.
>
> The current KFENCE is supportted to adjust sample interval via the
> kernel boot parameter. However, branches prediction in kfence_alloc
> is not good for situation with CONFIG_KFENCE_SAMPLE_INTERVAL = 0
> and boot parameter kfence.sample_interval != 0, which is because
> the current kfence_alloc is likely to return NULL when
> CONFIG_KFENCE_SAMPLE_INTERVAL = 0. To optimize branches prediction
> in this situation, kfence_enabled will check firstly.

This patch doesn't make any sense. You're adding an unconditional LOAD
to the fast path.

And the choice of static_branch_unlikely() if
CONFIG_KFENCE_SAMPLE_INTERVAL == 0 is very much deliberate, as it
generates code that is preferable in the common case (KFENCE is
disabled).

Please see include/linux/jump_label.h:430. But even then, CPUs are
very good at dealing with unconditional branches, so the difference
really is a wash.

But that new LOAD is not acceptable.

Sorry, but Nack.

> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> ---
>  include/linux/kfence.h | 5 ++++-
>  mm/kfence/core.c       | 2 +-
>  2 files changed, 5 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index aec4f6b247b5..bf91b76b87ee 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -17,6 +17,7 @@
>  #include <linux/atomic.h>
>  #include <linux/static_key.h>
>
> +extern bool kfence_enabled;
>  extern unsigned long kfence_num_objects;
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
> @@ -115,7 +116,9 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
>   */
>  static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
> -#if defined(CONFIG_KFENCE_STATIC_KEYS) || CONFIG_KFENCE_SAMPLE_INTERVAL == 0
> +       if (!kfence_enabled)
> +               return NULL;
> +#if defined(CONFIG_KFENCE_STATIC_KEYS)
>         if (!static_branch_unlikely(&kfence_allocation_key))
>                 return NULL;
>  #else
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4655bcc0306e..2301923182b8 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -48,7 +48,7 @@
>
>  /* === Data ================================================================= */
>
> -static bool kfence_enabled __read_mostly;
> +bool kfence_enabled __read_mostly;
>
>  static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>
> --
> 2.18.0.huawei.25
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBt8LazZMLH2_6rFc8u3bVpPNNyetV0fqmanwB5DLZPQ%40mail.gmail.com.
