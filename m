Return-Path: <kasan-dev+bncBCMIZB7QWENRBNFYZH6QKGQE4QNFRFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EEE12B41F5
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 12:02:13 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id u25sf7254607otq.19
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 03:02:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605524532; cv=pass;
        d=google.com; s=arc-20160816;
        b=eLVY/v+xcs9cv+a5KvAPT2NR/Qqs6O6W5q0ZvT+YZLLpx9822vDdQ+UWWVl4eEMWmk
         ZDG1vSnfwFNdDAISpYqXUf/TLfvSdiJDYgNGywbj4kdEjqoJ7P5L3mm42ctAcRoNJBaG
         tYS+PDLr+DtJFiPgx1qKu5Vqn5vK03mzu3AR+TqECttw+2ZzeXCK5T+1CHhnXbDIYX3w
         6JmieFXPJGvINMYlZ+zsj9OlTzQEmXHKa4Pt/W6bjatwrvgBWl1DaPj035t1lmUjMWt5
         PxEVVK7ro6ML5Kh+rfVCK8vIMRJFmKu5Zpsec+/qZfxSFr5cbqKwKHcZrtAY+fWQFL9t
         JMQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OoEPGxrEU37u7AaoHfnid9V/9dbFEs2iRaIxeLuz8l0=;
        b=TxtTHuy/j3g0+qhEAETWSjxKHgWNvr/s5EMPfewpCE6+ia1YFxoysYrXqDTXe9zCMj
         vhCGPmoY0pUivNBJJFXI5BO4h6etJ4cQaHAFznXrDMjcgJnHPiIv/X/bQnxIxIP1z6iK
         iS2M/DzkW4j9NJU0s8ckid71mFRF8J51aG/ReEv4sjWwT8DCrQqsiU0QknDmvPpktfKW
         dcNevN5q1ns0d68bc3UhK03DfSgwhvt48g+0puj5b8DdK9j9zgO/0sWzClfWImimXLHk
         y7y85PRh8nZeITnsyCFgPf3PMT01MIAbVdt5liV4/h1qIbeTzdsusYGwyk9hED89ngum
         C0QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lNCRW+LN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OoEPGxrEU37u7AaoHfnid9V/9dbFEs2iRaIxeLuz8l0=;
        b=OmLubpRks4bqroLtxbsTtlUuN+/RrNmJxDmZiPL6EkyGTtveC6030wI5DbcyGYPP4C
         h1oq10WkP4tXbJDdJ38YSSvVaZSoMOjys8qGG/A6ksIEluSbKttj0WZg3v8dtSZMbXLr
         t8QXyFRTgT/QMyfsWsxRz0JFGWBRPVVL5bBws+TuPtsUMV64dsRRHEWN5HUHroodfn/Z
         CenD9wZAUfWbzJSg0t6fPGLaCESwzqo97uCXoMZOUnihHSjjlyzk6oc8Tk5WXtySmd5C
         OMDj+WJfGeeIDNQz0qW7isbArVxILLp4uJcp9HHShN62WqBFAT0yq2T9X+JNPDAzfXPt
         60rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OoEPGxrEU37u7AaoHfnid9V/9dbFEs2iRaIxeLuz8l0=;
        b=GnctPR2FONM1A3rp4OYCK5GIiQObpG8rHD24uzYt4AECzxDd00Z+glsLFFn3YRi4g2
         iUNoeHRshDV5WNH8KeqFhVQuXhTrp9ihKiEj7kCttNp0FhsuXJoGlVMhEiXimLkviyII
         t3TE7tOcM1sHz3iGfS/afAbN6WnPMtPl9tOGm4/92QL7W3WbfDas9fxffoxpEQ1N6Pg7
         +PlcywfFHXbhngpCqQANrgsCkfhvkDHZMKr+61ePcyocqT/LEZWpf+fM7k9kquzI2Hq9
         0tUUjF8ILhhhGlqiPGJT76qJ4nD8SvlH3THzo/Qm75I6DIfNMenIXVqbVJIVXmDA1Rma
         n0QQ==
X-Gm-Message-State: AOAM533wwTCYgwSmv+r7KVqKwc/PBOALQhCkmB1E8VBZ5Lh4v6/J7OFX
	JkaFepQp1zDTPt9rwnrh0FM=
X-Google-Smtp-Source: ABdhPJwKEHTlHim/O+XlYF8M7GVH2GRZ3kI0TraZXZ01bXAqXpJqf31yPLnq20LgE9qFgvCNa9bSCg==
X-Received: by 2002:a9d:8ea:: with SMTP id 97mr10414051otf.310.1605524532253;
        Mon, 16 Nov 2020 03:02:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls3069763oib.5.gmail; Mon, 16
 Nov 2020 03:02:11 -0800 (PST)
X-Received: by 2002:aca:cf0c:: with SMTP id f12mr9630157oig.139.1605524531911;
        Mon, 16 Nov 2020 03:02:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605524531; cv=none;
        d=google.com; s=arc-20160816;
        b=TEt7Xtav25IKo9ffcDiSG6K9dSwCYiU2VK2zwIAzYXhNDxz7qq29vN9kX7KWXRV/zd
         nxEsZAayUqhhRB/zL8nAnDRNMSO5FyZCPfNkSoK54VXslJVYfUKaEGyMb+UbqO77rrxx
         sfwoHmkpKxRLI77W+PMuUMlKWhDwk5Ti3K/QTuYpghLYgWaIjomqIkxcpS2827pniwNL
         RhpXdpKgS5k3i/elxhFNbqEEFXv6s5BEdx35fq0EaxEN9BcUeGUiVBQqLG52S5JfSGXU
         i9aYYGHpjgrRSR+TaQ5vZHdNFjxX8E26SMofusCCc1918vqnODxKD13t6XVCbiTr4193
         69ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WCo6s0/nkYmCiNM2lfhtKvRgQtlMOZhZ3Qm9cvd64Ns=;
        b=S8FVeDTXD+QmJ8rqEuWHjdiyJWiGsISJ8GZNJ7ZCjGfpgA5BIZWGoCgTxgLyf5ZaIy
         +ebsRn9PItkv2viJ6q3oIcvAZC3SeRclQVpauj8S4uSGz6zMaCLxJ8PnTEbcxr5vE308
         Ud0Xe6XhIHW7HFK45Z3flU7QeOEAFyf5RZ5eyDDciDSndNjLu/zbGhrdazdioGZFM+PF
         QFi1HoR01klY/V2Z4Mb/Tuuuvl0PMn92xWRoLJAt/Gk1BFfwm75YQyRAZCWTUN77PBbW
         Nv8KY3CFipNarCacXCIC5XQ4yKCEbdhBAl082vM5ZmXAQgAI5mUFCXqSvSXLqxfje6Vn
         u5Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lNCRW+LN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id t11si379790oig.0.2020.11.16.03.02.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 03:02:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id f93so12487548qtb.10
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 03:02:11 -0800 (PST)
X-Received: by 2002:aed:2744:: with SMTP id n62mr13892523qtd.67.1605524531286;
 Mon, 16 Nov 2020 03:02:11 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <89bf275f233121fc0ad695693a072872d4deda5d.1605305978.git.andreyknvl@google.com>
In-Reply-To: <89bf275f233121fc0ad695693a072872d4deda5d.1605305978.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 12:01:59 +0100
Message-ID: <CACT4Y+Y+5g24oAMDL7SKESXO6p6tW=OrC9Y8S1=Lhs6DwAkuUA@mail.gmail.com>
Subject: Re: [PATCH mm v3 05/19] kasan: allow VMAP_STACK for HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lNCRW+LN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Nov 13, 2020 at 11:20 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Even though hardware tag-based mode currently doesn't support checking
> vmalloc allocations, it doesn't use shadow memory and works with
> VMAP_STACK as is. Change VMAP_STACK definition accordingly.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> ---
>  arch/Kconfig | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 9ebdab3d0ca2..546869c3269d 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -921,16 +921,16 @@ config VMAP_STACK
>         default y
>         bool "Use a virtually-mapped stack"
>         depends on HAVE_ARCH_VMAP_STACK
> -       depends on !KASAN || KASAN_VMALLOC
> +       depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
>         help
>           Enable this if you want the use virtually-mapped kernel stacks
>           with guard pages.  This causes kernel stack overflows to be
>           caught immediately rather than causing difficult-to-diagnose
>           corruption.
>
> -         To use this with KASAN, the architecture must support backing
> -         virtual mappings with real shadow memory, and KASAN_VMALLOC must
> -         be enabled.
> +         To use this with software KASAN modes, the architecture must support
> +         backing virtual mappings with real shadow memory, and KASAN_VMALLOC
> +         must be enabled.
>
>  config ARCH_OPTIONAL_KERNEL_RWX
>         def_bool n
> --
> 2.29.2.299.gdc1121823c-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89bf275f233121fc0ad695693a072872d4deda5d.1605305978.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY%2B5g24oAMDL7SKESXO6p6tW%3DOrC9Y8S1%3DLhs6DwAkuUA%40mail.gmail.com.
