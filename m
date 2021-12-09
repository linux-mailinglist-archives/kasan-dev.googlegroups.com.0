Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5VHY6GQMGQEU6OLJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1661D46E618
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 11:01:30 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id a207-20020a621ad8000000b004aed6f7ec3fsf3311985pfa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 02:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639044087; cv=pass;
        d=google.com; s=arc-20160816;
        b=rW7ngxdOsFRAAo5KPjhScRZUMsk/E5x/QyQPhH4orJtzRSKM4h9CvSw/fUxvi2kZV/
         7e4ULGjyhopmqY3NjlqNG88yCnDtNSqzGOkHSSvG4ScNqeeMY6nIHGJdI433emUow04t
         QXKPZ9YGCjck740XVqD6e0GJWw/RkIs8x2MlHpwHit8IPKikhavyIlaA8sZ2RDFZHqAg
         wUJ+SIO6kyBX+6xiP5vprCGU927336NXb8ynFa/lDlx4kWekjQ7BUhuldwPy1TgFQmUO
         aKS6w0RsuxlJBB3gakwz9/zRDqvY3c5npaMqM+E1zhJyCqDR/PLOxrEEVuiWIA1Xdkh/
         9OsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kAf+XMFFjiYwbGkiCjiKBOT6McsYXuc8SQoYkBtkt/w=;
        b=ydnqGj0jKVWjw+CoC3/+EtR+iQID0HYVMmHfanJholPTaqxHmoc/HJ3blp5ePauHt8
         PYKtlUS3IxtkUvM0zBlKHYeIx00khqh0vHjdVSh9Kc2UZpjxW0BWRAYJNd28EK92kuYS
         ed/SPv9ETlKZq8jjfQQpK4LVtXK4xALX6o73OwKv4IflWAm7pyN5nJxcEe++o8vNIyP+
         wrVGO0cbSY5KwsXl07ft/bxASrU1ypd9f1aj4UU24HFmH4pc5HhFi/wuJh8s/tL8X3Ic
         YA4b8o2pHcX8SQ+LQZcCf0ox7CbH0d+Q9BuPLUsouQD3prPgHt/zJAFYN0W7oJfqGLED
         2mNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Ky/1aN74";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kAf+XMFFjiYwbGkiCjiKBOT6McsYXuc8SQoYkBtkt/w=;
        b=I+rGXZw/THUtwZ0HGxFNy0UBlowrd0gADaAzLN/lGMU6JVQ/HY9r/H7Lq2JSxXP3Fl
         Z2jM5XPVyHINiK+G+Kykq2d8au6chQZrozlAIb8Z3WcoPcnG3CEne+2TjHQCxFXqe9nP
         hfHIXITnUps0UR9jLZwvDq8bZxVwpjZM7cloJyv3Lk45qpofGDdRaIpjYo6ufO5zge/w
         mnmtxNZfW50ftkSYXIVzAr2UjrbHfU1AeQhxN+MOUp5e1nwXXnQvliaXXgvo4sHQjeni
         amN9cvAoTZJQmN6dCiksjeZXFciI8uEwiFr+0+oSZPQJrYi3QpL9W78FUjHFDVmThcwz
         eiDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kAf+XMFFjiYwbGkiCjiKBOT6McsYXuc8SQoYkBtkt/w=;
        b=DKrsH3RluDscp3UIXDfrJy+jTBHvM2iKn9I8cVQGJzFTnoWTLrc73fvGCaWWkVwTlv
         hcUUwgzcDad97VASr5900EZzS/V4hphWIYY2ZBs6kWAJzJcQf+RWos9Wzq8/0AmDsDat
         LvcUyvfiU8jxKeMf9pXjfm3KnQcJgSDWGx9RUON/DPebOgj++2ylKW74YF2jQ+gTp9gH
         ItY28x3xbvq9WAWW0jlFsF8ZQoM5/pGwbYAUooy61Bphs2xDr2yzaMmROe3LtXd2rnai
         AveIaGSaus7w+6GnPyMbUGsU4Ii7WfsWBJVSGM4N8TfU5iJCpirfxA8sXhp0eY44hdAN
         U4Tg==
X-Gm-Message-State: AOAM532l1HytHoKMN69YSufuYzjwv8HFpORdTgCO2HiLSJb4695tvCa7
	GPBlNncu/hng/vBZQTjULZY=
X-Google-Smtp-Source: ABdhPJxLX7weRmBuyRyD1ObyEbj6ADBZbBoD8nmAVFIX8S6Zd5+4zoGutc8cvlKCpva4P53DKSBf8g==
X-Received: by 2002:a05:6a00:22d1:b0:494:72c5:803b with SMTP id f17-20020a056a0022d100b0049472c5803bmr10703765pfj.84.1639044086401;
        Thu, 09 Dec 2021 02:01:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:18a9:: with SMTP id x41ls1919355pfh.0.gmail; Thu,
 09 Dec 2021 02:01:25 -0800 (PST)
X-Received: by 2002:a05:6a00:84d:b0:4ae:da2:9ce7 with SMTP id q13-20020a056a00084d00b004ae0da29ce7mr10694368pfk.16.1639044085710;
        Thu, 09 Dec 2021 02:01:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639044085; cv=none;
        d=google.com; s=arc-20160816;
        b=P6X5FHjAnncsws5Oc/nVV6f+jhtb5gxAdlIwyI8bLGMbL35uy4zEV4LNQJDpt3Y4y4
         ZYOx+1iCvccUsiAbBysvVT6dfc8Vh1IuTQmp/3UcNQ31BEhq77JgJpZwihIwovecOBXB
         qCiKVuuNguG/ICKlHCegqjLLESpRkzn6Yq4lIozMUTuxT7dnlL5Evwyb+cG8bdx4Rao3
         7KqU0B6tQraHmErxVtn25zNISxwCMLyVmxQFHDaZFMc5yZ8ASgSB4D7jZWhIQlc+yUKn
         MQTXzv17EKgWMNopN1Wcf2WgFB1LThZ/jTZOfj7TjR5n/6eZUDO6gcIPAoIFQ9l8TVnI
         uBPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AwZ2q+ht+X4UdZ54dnQJfViFXAccYyFB0RjG6X/nT4g=;
        b=BxhzouipuCrKM3s+ff8lvXIg8+e8ZEriJ3aeWQHRaMARj0Msk5NCNDXOCzicD9moNL
         LeYB8FyMmGqw87GJinHL+5V7qlpfpA07H+6cVDlhx9vj82mrRNCLnSZahfv0YhkgN2Q/
         un8fzXjijQXzizyzvJdxnFQYEeCDRoZYAW0fS8VLrlOsDiXtXxk9HlZhMGPdOb+0gTph
         i5IW55AamQY5yGy6MsJ9EO8cYN9ZtNIAIcSmMiS1dNGRs6y9NNg2i4SgpLptaHx+mCyl
         7wtM8Ul/EfrYeSbZMUQjrFivGjJSvctb4t5yfqd1wksGmrbcRS2LRj+7uV5FCJilbyt+
         fchA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Ky/1aN74";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id q19si508885pfj.0.2021.12.09.02.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 02:01:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id v15-20020a9d604f000000b0056cdb373b82so5593255otj.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 02:01:25 -0800 (PST)
X-Received: by 2002:a9d:2ae1:: with SMTP id e88mr4211892otb.157.1639044084792;
 Thu, 09 Dec 2021 02:01:24 -0800 (PST)
MIME-Version: 1.0
References: <20211201152604.3984495-1-elver@google.com>
In-Reply-To: <20211201152604.3984495-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 11:00:00 +0100
Message-ID: <CANpmjNPaKMsgfDo5PE_dX794otFXbJvGubxG44C8-QL66UVaUw@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if ARCH_WANTS_NO_INSTR
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Ky/1aN74";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 1 Dec 2021 at 16:26, Marco Elver <elver@google.com> wrote:
[...]
> At the time of 0f1441b44e823, we didn't yet have ARCH_WANTS_NO_INSTR,
> but now we can move the Kconfig dependency checks to the generic KCOV
> option. KCOV will be available if:
>
>         - architecture does not care about noinstr, OR
>         - we have objtool support (like on x86), OR
>         - GCC is 12.0 or newer, OR
>         - Clang is 13.0 or newer.
>
> Signed-off-by: Marco Elver <elver@google.com>

I think this is good to pick up. Even though it has an x86 change in
it, I think kcov changes go through -mm. Andrew, x86 maintainers, any
preference?

With the conclusion from [1], I think we decided it's better to take
this now, given we discovered KCOV already appears broken on arm64
(likely due to noinstr) and e.g. syzbot disables it on arm64.

[1] https://lkml.kernel.org/r/Yae+6clmwHox7CHN@FVFF77S0Q05N

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPaKMsgfDo5PE_dX794otFXbJvGubxG44C8-QL66UVaUw%40mail.gmail.com.
