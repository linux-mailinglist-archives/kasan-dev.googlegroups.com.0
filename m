Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBXESY2HQMGQEHMRXBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 04A8749D11F
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 18:48:13 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id c5-20020ac244a5000000b00437739a41a0sf53211lfm.10
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 09:48:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643219292; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUP44908jKFcXzzhseF4E9WrhPQVen+W68CCrgKfL9W5zD6fZwaJb3mOE5o+8daQS1
         mR+FsEJR2/suAusNoI9GMBlj457KnXH0ybxcZReQd+rTwMSvm0FZ7MN8Lv10ezIE7NLJ
         tNl49b8/bjKyNS2Ec5rhtKjSFQLKP+Cfv7xyGG5J60fl9R2UFYGKu9q/PPDWsUafXh0x
         fQS9mpPh7OsgpQ73iUrHRRX3Ob9cLLWK+mH6tIkO4gvVVVngGgEi4Q/xnbOXG9gRbi/c
         N3ESUe/zhv0QLmZ/i7j8dSzRipG9SX4CcP1t8cImWNPHcqemxU38IqfgQAhBhXRHPtNj
         LTXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VPcFY39Fsmcu3Cbz/E4IdvN4U3tNf88HQkbIXvWD7OU=;
        b=dl/PXMULX903euKHpQvJrvEVVeN08QZbxrWsTa4/Xw+0/y7pszR4Gn0Icfwf6H5LW5
         4oSOjdSoQf8Lw9ei8+z8cvq2T2ZG2ECzA9kq5MrlJWHs0pEJsqq2swpqkbIyWTKBvX94
         XjXV5Lu9mcUa3sZyGb+vrBdYvy16Vuu3AQlq5CDGs8i/yEIQzOZshxiG5Y6M4Zb2lx+h
         NQTbtVu0qlhnN74KYb1iEyfORA9dRsU3Q9X0ezniv1Kh9ldeZxxIVP/iv2b/p/en25G9
         3nJqhzbFbYiLlOXsB3v9QecFY/wIhQ8lE+y6fgpbS+l3W69SznO3m+MJQdRYWLtdJsMw
         9SqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X7xFhQb0;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VPcFY39Fsmcu3Cbz/E4IdvN4U3tNf88HQkbIXvWD7OU=;
        b=eI8meeVQDKcvl7nWE4wJV/4ZJy/n5ela6/rA8rMdSSsSSR2cCKNdT8gh+2Q4P97HMT
         BqwIs1edyD5Psddbj3M5/x+lAI8/mr0uuaIaJ0nj6H+XrN8iXGHjNEPl6+VKbB18g7rJ
         ZGZY0NAFSf4bDUFYi8SmPaDtJBUVrv09nsNWDSabRkGQy2f8pAOib4aQnUKfzp4UgBZT
         ajgpNllikDq3CZ5C64HURI+4b11q1sqLdZo3DNRqUuUn/Qn9hZkA8P+5WQy1l2xtFjQz
         +V/y009NHR15+NiIgfrYSA7NAu47w1Pgfq6QYc90UABDZMc1Esfn6pxmAJN9n0YoI4mU
         /yIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VPcFY39Fsmcu3Cbz/E4IdvN4U3tNf88HQkbIXvWD7OU=;
        b=pwJsi6IgkcB8UgdqN4C3Je8aKKLONohP3qUkygIGrdErzEy3zsrd/w+Ex/bXvYyH19
         VNK3XmU9jsdLgO19oF9Ou4iB/N8kQcqL3aIjj9SJhr5MH/t/Ue5JhfZscVdZPPremnbj
         j2JG1pB4/3TlZL8B5cBzX7qvrM21d34/Y7T4a/+nmRLgQWVR5o/ctpavCknk7kXEHv83
         0U4gbeoY1mG07d6Ds2r4FtsziMnb33f26Q/5KvXOVXbjg3ykU7f21feZIX+D6u9Ft1Rl
         aqMB/AKQsoe1I+VGPkwEzLvXgWMLN0ukA7cJVegVubbz15OtNLY0RlOrI34anVO9YQIg
         UiuA==
X-Gm-Message-State: AOAM533XD/mdyFI7/HBdbWROjcIQIfJysFjAcUvjiFH0j2al6p8yoVZm
	z9QPYe51eKy0dTS7+811TbY=
X-Google-Smtp-Source: ABdhPJx+ItY2fEgOi355CbqSXjMdo7Q6+ituo6H8/g6F/AY0+joE0Fms31hdlQ/0apTUC8ZvTtE38Q==
X-Received: by 2002:ac2:491c:: with SMTP id n28mr12576lfi.486.1643219292588;
        Wed, 26 Jan 2022 09:48:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b1f:: with SMTP id f31ls1408631lfv.3.gmail; Wed,
 26 Jan 2022 09:48:11 -0800 (PST)
X-Received: by 2002:a05:6512:2506:: with SMTP id be6mr57740lfb.48.1643219291609;
        Wed, 26 Jan 2022 09:48:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643219291; cv=none;
        d=google.com; s=arc-20160816;
        b=dPR7dW++DuZSUTofqRD+y/QhhxdwaJDS3HQbsT48ShzPJh9Bz4m4qc7k6ECaYCodr6
         mnOnGJDOrGw4k9AIrMKGRGVLUq9sqkGtvQN7gt0eNI+FV+GrH+kudGgY1GV7eNzjk45r
         AigJnxL/LWlI1wvSk9W5OTgQ1W7ji+MExOx/HnmSSexY25Z6vWFEp/fVXNb7zYr2h8VG
         SYsaWTDIrhjvKO/zFYNVaeqwTtAxeb3iIa7DVfh1MNL7LKCSYZg4icIKHoCDdaq294rI
         V76naDD43SvMtuIuPJc4WHId+W0h22UKF0UwgXyZFvWfXjxiW7O8Ix2rT1XdtarMfBtV
         qQ7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xLIqTYmkTKOqFZ7wfTxJc0kW+NLs1daqfDz4QtnxNOE=;
        b=AI3p/AUS1nxceO4DukiRPVurte2Tx1NI3wmQLgLO4Ta2bmxES08C85mkUrT1YrpW1R
         WjncyzETlr0xBYNIVvH4Svmif+XAxjo2jyOJmhlXmVsdwVRrqgtVAZoPptAY4xEk/kDf
         0vCi5u14g6dSMSwVknOId3h+ETdsaZwWPIuGb0AdZtxQHy2NzDaDIa942aza3+Ecaacw
         AFeWUqj/Dto+tGO1YYmT2Hab+Ebxk88rNT6bhYkzDH1Kz7JbzeyT6TsRZusuzi8gr3Qh
         oHJh76wNI7KjD9IXuAHPfAzNHm6ggYIotQsLjMgYm7DMUWcgjKmfCY3f1N8Onafjouz1
         hYjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X7xFhQb0;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id u17si2649lfo.13.2022.01.26.09.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jan 2022 09:48:11 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id u6so373241lfm.10
        for <kasan-dev@googlegroups.com>; Wed, 26 Jan 2022 09:48:11 -0800 (PST)
X-Received: by 2002:a19:ee13:: with SMTP id g19mr32931lfb.288.1643219291219;
 Wed, 26 Jan 2022 09:48:11 -0800 (PST)
MIME-Version: 1.0
References: <20220126171232.2599547-1-jannh@google.com> <CACT4Y+b8ty07hAANzktksbbe5HdDM=jm6TSYLKawctpBmPfatw@mail.gmail.com>
In-Reply-To: <CACT4Y+b8ty07hAANzktksbbe5HdDM=jm6TSYLKawctpBmPfatw@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Jan 2022 18:47:45 +0100
Message-ID: <CAG48ez3mfAwgkJp+GKLnbtgQoQVT78U+voRN09H5S=7Ewf+DgQ@mail.gmail.com>
Subject: Re: [PATCH] x86/csum: Add KASAN/KCSAN instrumentation
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	Eric Dumazet <edumazet@google.com>, Christoph Hellwig <hch@lst.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=X7xFhQb0;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::134 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Jan 26, 2022 at 6:38 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Wed, 26 Jan 2022 at 18:13, Jann Horn <jannh@google.com> wrote:
> >
> > In the optimized X86 version of the copy-with-checksum helpers, use
> > instrument_*() before accessing buffers from assembly code so that KASAN
> > and KCSAN don't have blind spots there.
[...]
> Can these potentially be called with KERNEL_DS as in some compat
> syscalls? If so it's better to use instrument_copy_to/from_user.
> Or probably it's better to use them anyway b/c we also want to know
> about user accesses for uaccess logging and maybe other things.

Christoph Hellwig has basically eradicated KERNEL_DS. :)

In particular, on X86, set_fs(KERNEL_DS) doesn't really do anything
anymore since commit 47058bb54b579 ("x86: remove address space
overrides using set_fs()").

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3mfAwgkJp%2BGKLnbtgQoQVT78U%2BvoRN09H5S%3D7Ewf%2BDgQ%40mail.gmail.com.
