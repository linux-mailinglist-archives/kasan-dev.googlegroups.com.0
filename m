Return-Path: <kasan-dev+bncBDW2JDUY5AORBGFQ32IQMGQE2T2QHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id BA2784E1DDB
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 22:09:45 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id x9-20020a5b0809000000b00631d9edfb96sf10683390ybp.22
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 14:09:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647810584; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrjxe1VR9ZGPo7WgvXakTvwOogbl2sRyaUnCQro+ltT8pF3dfEu7k9BylI/jDGjM+I
         KC+UlwUsSciiVkyfes4AqIRULiIhSee3jkzspiT4y6WIypfjm08UM2ihHIIlv9c4wMeF
         1TAEf8VR4FQlWdMZ0qTpBl3wdpRb8BAHSGqQNOSiykIcv2P7XWnrFhGZwDaAhj7FHPpm
         bpkRlYtp18w8vZn5dLKzG/Vmgt2civSVpYZ4xj7O9dp75e5vNwwavftRpAC3J7fmTdLk
         Ili0KWAAxr7eSplqn/Cuo0M75EWafnsAzUjgJfrYnMY4rvKomRWDsVTePXhd4gi/zkjd
         zJCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TQqG80kteT4vphOLV2qAIJYjrMeRe85LLlBpllizfY4=;
        b=vT3wQbGOYFe2ocRwcXCdmY409vTUgo9w3YW6mXvhRQF+mE4NYPdxBJVWfVNksabHV2
         +VDvIeV1MVSBzaitaX/OODUjlsZaKvzdxddOQXMoEHd8/DqMHtfHLDuT+YEa0+4qQ3eg
         o3NTjEbI1ysf/+f6MGmAEWONTg30kzVKRdMwUwbjbONRmJiyxume1mHmxm/SG4xdvUz/
         LIGPzK0N+H7c/my/WW5E9tkrqOqmi340wG4tVttBUUTK5Rka2Sp9pqRi7RzsQFKSEUfp
         1gH+b6REEd30uMqPWeKqTD7AVxj0vN9X9iWeyJ5po0VlxDzd15HG2zaA5dxLKEjokPR9
         1wCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=peCpeuak;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TQqG80kteT4vphOLV2qAIJYjrMeRe85LLlBpllizfY4=;
        b=phqhxb1Iav0N3Qtu9D1UoR0mb57uoDKai/pfdjMHdvFd0RlfNUpG4Vf9ihaOCxuWHu
         h3zBPznpSk0iJFmCFOMPS9TfUThV7vkLKGlcxfe2TAXRZ5eULdUihyLoTe9O8K6RM/t/
         SDybaBb+z0bZ+4ZkuSsyCCtSACzLLrLgM8iZsDSsP7GOr9hTpUNlSquqqxBMz944Ip1m
         aUY9VE4luAKx7A/nt43sAqA91nzb5gy546fqerpWeu34CCf5LpyaOgqHYQxwyyh8lS7L
         k2ps9r96jxte6kL97J64H0nr0eucQg7xkSFsF5J9OzrV6A34k3VGeaSU1y3adiB1r/iw
         VtFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TQqG80kteT4vphOLV2qAIJYjrMeRe85LLlBpllizfY4=;
        b=AFnr6cLDudJLmIaDXBcTe+jkW/TDbgZ9OZC5LhW7eyw9UAfmz6XI6raxc0h1280HVq
         a04MDn2Q3rUcN9v9ffd6q7ORUit9W+2oIQBTqd+l6OFm0afhZxlZPjXDU7X2OafP2PnR
         YvQtoJtmJJ0xFXM8PPBWLVsuXFFlbHxxbJZXnqvdhPesxBL93uWRzbi0XzGqiSU74deN
         h11B5/v17OgICMLHXxvdLIrD3VmR0DP7mO6FDDgmxyq80c6SjKBK2lf9NwP4I00d1hXr
         UiHaTBWRCL5E/n/QiM3fjEYg5FoUH+SkSKITJY0HXhmsyqRY3JTlxPF2ObvGe09pNzZf
         kzpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TQqG80kteT4vphOLV2qAIJYjrMeRe85LLlBpllizfY4=;
        b=JxaJHlNOxak4B5oSdEx/w42wmbRJofd/EuP3GD5TM6g4thGPD0EBI9C8JEeRdXjmFu
         wd+Y/n2jtTn/gzgYg5WEeWyIYNNvSFSCpSYNH1fN2WryADddT+1HJdNB2ylhJ0dLuC5T
         BN6aWoiC2B9R2VzVlIGa9nnG2S2SiUSWXGKHpPJ0X+HyBr1Zq4YsCriL33TMauITpXD1
         VchaD/f9+B/JY4nISzJWCbZ+0WnXUZ60eKbLkKmolQQ0iAHUgyIJSEmI1M+q7DD0qHbL
         7NaFqMF7wWu1cciGp7i9Z3SRoWB5N+wfIi7a6WwtXmLZQ9M/wILH4NpqgJqq8TO3CaVN
         gqDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hy+gbk46ZB0iZfhyYpIY4hs/A4yvEkTfy7IAy8nc26mS/Mkrg
	UF5hXbNjpAq4FJLN1/2AFSM=
X-Google-Smtp-Source: ABdhPJy7MS8omuUa4RuWeGXuHnARwgW234P21Ao8YZ2rR6B4hxLsAKeCJCw9wS6C+GUGDgLGBwjKzA==
X-Received: by 2002:a81:7c88:0:b0:2e5:8fa2:29d with SMTP id x130-20020a817c88000000b002e58fa2029dmr21199114ywc.346.1647810584659;
        Sun, 20 Mar 2022 14:09:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:1ace:0:b0:2d7:9723:3e85 with SMTP id a197-20020a811ace000000b002d797233e85ls7695693ywa.8.gmail;
 Sun, 20 Mar 2022 14:09:44 -0700 (PDT)
X-Received: by 2002:a0d:e904:0:b0:2e5:80bb:90a6 with SMTP id s4-20020a0de904000000b002e580bb90a6mr20824587ywe.515.1647810584206;
        Sun, 20 Mar 2022 14:09:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647810584; cv=none;
        d=google.com; s=arc-20160816;
        b=CGtkW0yxz84E2CCJxkb/HbAlh349C2TE8j1D2BtuzTbsasvAXoTGWVva2jJ08C60VI
         ydZMhtJq3GeA/xn+K0IE8jnLoeSDbLbpm1R/O1pnGD3iglJLawBhdEsIzejp3sk9Qie6
         Q78bLK1/M89F2byDeeeJawqqgePqpIk0MpJf7nBccTrjYgfW19KUsACEOiibGQorIJ1w
         umf6FTcv2cj1BMTXoCy0SNSnDZdxh5Duo+ieC6f+sdPXPgqxuPEL4O6vmX1C/l79lvc6
         MKdLA8+agiJfiuz8RBuvaOronPtC1jZSMDzkHUJUKGdlVwNHc+4weUbaA2OcFaBc0gaO
         gXCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uu3NPXS3YIK/joqnoO2dCxxZrdruyUVh70Rwb4NqWi8=;
        b=FdfZo/VcPCapI3TqQIoaB3FyrwAArWtgSW9pf9tSHnSUxds6nZqKiIqVcqaGzeRuBt
         mJ2oIizEsGPo2CMiLtRBDcEaOZUc/8wAJZCNEohr/6AXB/3oipmPbmURecbC5m5lMwFD
         ti2aLcZ8DbLX1OvC+hmz61mklqpe6r2Llv7+NjQ1U6Z1mODchng33SYMSaC6HfDx7M9t
         SbYCZ9/KyUbOhn+0grQtsQJUZ8ormYQBSV3o+07bHgyp/tvKr9Jz2yjoE9uLuE/wTnNZ
         VteX5ucjc9dCPtKMI21c1KTkJO684roGxMcu0VnXS6lgGx7kgYQyanWZiUh76oGnnQ6F
         CFNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=peCpeuak;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id i7-20020a056902068700b006294894fe01si921297ybt.2.2022.03.20.14.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Mar 2022 14:09:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id b16so14882321ioz.3
        for <kasan-dev@googlegroups.com>; Sun, 20 Mar 2022 14:09:44 -0700 (PDT)
X-Received: by 2002:a05:6638:210a:b0:31a:536e:4714 with SMTP id
 n10-20020a056638210a00b0031a536e4714mr10058666jaj.71.1647810583809; Sun, 20
 Mar 2022 14:09:43 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
 <CANpmjNNBzVovK=N9b2Lv0VUqpE_4nU+6gqO91_ojVoEbR0C5hA@mail.gmail.com>
In-Reply-To: <CANpmjNNBzVovK=N9b2Lv0VUqpE_4nU+6gqO91_ojVoEbR0C5hA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Mar 2022 22:09:33 +0100
Message-ID: <CA+fCnZfYLZhjijPjp3Wd3ZeBQnKNiQCLNn7uuF=cpQi9wU50xA@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=peCpeuak;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 14, 2022 at 8:01 AM Marco Elver <elver@google.com> wrote:
>
> > Instead of invoking the unwinder, collect the stack trace by copying
> > frames from the Shadow Call Stack whenever it is enabled. This reduces
> > boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.
>
> This is impressive.

I was surprised too.

> > We could integrate shadow stack trace collection into kernel/stacktrace.c
> > as e.g. stack_trace_save_shadow(). However, using stack_trace_consume_fn
> > leads to invoking a callback on each saved from, which is undesirable.
> > The plain copy loop is faster.
>
> Why is stack_trace_consume_fn required? This is an internal detail of
> arch_stack_walk(), but to implement stack_trace_save_shadow() that's
> not used at all.
>
> I think having stack_trace_save_shadow() as you have implemented in
> kernel/stacktrace.c or simply in kernel/scs.c itself would be
> appropriate.

The other stack trace routines consistently use on
stack_trace_consume_fn. But I think you're right, we don't need it.
Will do in v2.

> > We could add a command line flag to switch between stack trace collection
> > modes. I noticed that Shadow Call Stack might be missing certain frames
> > in stacks originating from a fault that happens in the middle of a
> > function. I am not sure if this case is important to handle though.
>
> I think SCS should just work - and if it doesn't, can we fix it? It is
> unclear to me what would be a deciding factor to choose between stack
> trace collection modes, since it is hard to quantify when and if SCS
> doesn't work as intended. So I fear it'd just be an option that's
> never used because we don't understand when it's required to be used.

Let's just rely on SCS for now and reconsider in case any significant
limitations are discovered.

> > +#ifdef CONFIG_SHADOW_CALL_STACK
> > +
> > +#ifdef CONFIG_ARM64_PTR_AUTH
> > +#define PAC_TAG_RESET(x) (x | GENMASK(63, CONFIG_ARM64_VA_BITS))
>
> This should go into arch/arm64/include/asm/kasan.h, and here it should
> then just do
>
> #ifndef PAC_TAG_RESET
> #define ...
>
>
> > +#else
> > +#define PAC_TAG_RESET(x) (x)
> > +#endif
>
> But perhaps there's a better, more generic location for this macro?

Will move in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfYLZhjijPjp3Wd3ZeBQnKNiQCLNn7uuF%3DcpQi9wU50xA%40mail.gmail.com.
