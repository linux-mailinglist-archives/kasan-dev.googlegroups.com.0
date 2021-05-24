Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP4DV2CQMGQEQEWRBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 86DD938E427
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 12:36:48 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id d63-20020a254f420000b02904f91ef33453sf37213535ybb.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 03:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621852607; cv=pass;
        d=google.com; s=arc-20160816;
        b=VMamxK7OJM6LllRQUI6sC3HFSymIvFdR62EX5etXTmZuQ1AknsRLlRoXYZFpR/OqJI
         e+cEs0w8ihKKF9BMpspQ4v4k8+Mp2LcICBZ54UlSS0frGjdR4NXGJhWFlNqKf0RvEALt
         PAJ36fT/eBT509IyW9l1pYxjvzmPjAa/qatowC8U+szNvZSloZ21Q89UDn8LAov24DyF
         BsmrOqHjCX9T9XKVwYohdHuKZXPy1qbJvcJyxzXNyBnPNpXbkHsjWUXkVqUb4Ml4yaMP
         6KpdqCEc+h/vTlIOEjjKI+0WsK+bxmVm22wjTKnWmjvUQh7Rc85rVPxriZcX0o3GKYLd
         Zedg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ow2CEmHM7+467fyf5GKNpSf9RRlcHrVgI9JmIK2HWP8=;
        b=Z+tn68HLBVzUqAJLvP5fe5EbKhz3wtJezW0yNN/ERgy6usktX3M2oEcFNPJDCAM6SN
         YFhk+LJgkoiIhX5ntB8cjez3NUq1yoVpW/4Czhmkh9/cUkKEdP6ROANgE62AFwX6onuZ
         oSAXtAErtvNj9x4RO6Q7anYHPqjopiqJjb0qILIIUyaBoGjKGwJB8bxEXZjJmT1NEgEt
         B3Xv50f7n8o3WR6t2uh9rtp2bF13BcPylM1cBIuuofTbzVzhie8gSs7O+9WFrWs1abdm
         EtvBVW/CApBftvg2tLzn93ziuCQppB0PvJblNYesCp8V1nOPvl07+mtByOCWEZGYySxn
         2P6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vO8TRdch;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ow2CEmHM7+467fyf5GKNpSf9RRlcHrVgI9JmIK2HWP8=;
        b=EqOBuASj4tPJNznZKKjiZBp97qe5rHcvoXIMKSgAsR+V+tMtQp/iqrzFhMHo+sMhvI
         unkUmiZQoZjpF7zNVnQ8B8Nb1wMOEuhaxfaGUTle18YxspiCJS5Vsb9EpY3++SMhtjJ0
         +7GknM3JlF9JeyZEjyd4ntMRPFbcfKy+A35bzwx2E9aIFl4bTJCG/gVFQpbx7TEdJt9Y
         6xnNDGzeZSh76z6m+5TbS9ct8cej0oMuOkTI3oR/cyWoSVttOwcBKfSi5RW8DsoXH0sg
         vJkkLDxoujxAzrewkY3i9iJClOZTrFPlULCjCqE/7dQPiz3idhoIXgZAA5Lmwd9Y44wi
         q0Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ow2CEmHM7+467fyf5GKNpSf9RRlcHrVgI9JmIK2HWP8=;
        b=gBs+q7jY81F6zVabPAWohk49KsgY59U5MJU04CZPXIGrIWB6KR9SPDMHOxOj3Hy/uP
         bmsk3vMev4FtJw/GqcllB0KwdNfyw1lzrtwM3Mbdnas8aJPKp/Cz+3E8RB5Ug8WKz5oR
         CXxdxLTwBL2DQA7XEAFCsqcltfsS+ps3XnJt1O+Q+y/lcBpKu4T5zIEO99HUKGy9t+nb
         DiyFAsN0Sb9L/xwxRKbGvmUWEvlCJJqRq4Tl1YKuDJT5VaAcajno99VMkgFlIpiIzhXc
         2TQCVXwFo4m9jaK5qjkROVRVEOC0i04vzphee7e4R1NKAHsDdPgTqV9MyBa0WC0Smqis
         4Hrg==
X-Gm-Message-State: AOAM531tDplOp1CoIq1C1wNRYTQ64SePLdZ/B9DfwgNt4Dhxo8fcJIO7
	UoY0iAjQPC4rdlUFvEk4pAM=
X-Google-Smtp-Source: ABdhPJy4XK+qN+pmYZvsYWdhmonlRAh7E3pCUsuuDhkFXmM12s1v6z4PcFAXhHT9SRohYKUR+36lLQ==
X-Received: by 2002:a25:cad8:: with SMTP id a207mr36260843ybg.288.1621852607388;
        Mon, 24 May 2021 03:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2787:: with SMTP id n129ls6938368ybn.6.gmail; Mon, 24
 May 2021 03:36:46 -0700 (PDT)
X-Received: by 2002:a25:3453:: with SMTP id b80mr8882586yba.271.1621852606901;
        Mon, 24 May 2021 03:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621852606; cv=none;
        d=google.com; s=arc-20160816;
        b=VA8yBnlmkV2sT4UCIatzlwjFzQh4rFfY0TH47NkidgmNbHy10SsiojfzO7wOqQvqtt
         hKL3rSvABKBHgZWCXKLMHmheTMYqmOwKlhsywNU8L0IX6CfEDBAXLzaUB9lq5dx7VF/a
         6OeDXlbGa6CNJ1HZ5Yrqe5V1AVoau0CFpo0ydPejjhjNo2gRd0ZUjAi7sMi/QecmNySt
         JMLYvfy0LT1upjG+kvj6vGZnsRRBuiNo7glBkNcFggR2rUNWm8+lCQ1lP4mEiRq9qDbb
         FYJDZWAAVKgDbdgiet9II8cGejeO9TSg0nAeQ8z3ZEXyNMJ93chfaK/ei+bMyF9F1rVJ
         q+Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OyogGDxMaGSBrj2rkEP+jK8JOL+4OXbDVcsd7RbbjgQ=;
        b=JZuGc5h0SNFIW5ICJDjfeAw6CwAzEN/iuX6VBtdB4F0Wv2pFFHZnDJH3JGHM5dzz1B
         0nR3L+K/YJ2Luy9JcbGSY8IGfLe3lNI0OW4cxlkpVN2971FzKoco969iboL9yGtVkv7z
         7YmXyUNxv2+DVOPaoS0+G7SvJwCDxS1wgqSdu8oDtaK8sLkzQyaFRte0GUZm/4RoamLE
         DuWKcS6CZkRCo/CMDshmPJxzP7a2Qy9tHt0rkXE43b0hes6m2aT7csiWU/6ydOxr8vHa
         ZKORNIcY+ArfZ1OHZliz/uDtawWc9HEbawYYkW+dDOH3Fnc2cNF26HjFhJUEP7PUm6QN
         BWtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vO8TRdch;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id z5si1349187ybo.3.2021.05.24.03.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 May 2021 03:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id w127so22822096oig.12
        for <kasan-dev@googlegroups.com>; Mon, 24 May 2021 03:36:46 -0700 (PDT)
X-Received: by 2002:a05:6808:10d4:: with SMTP id s20mr10530580ois.70.1621852606335;
 Mon, 24 May 2021 03:36:46 -0700 (PDT)
MIME-Version: 1.0
References: <20210524172433.015b3b6b@xhacker.debian> <20210524172529.3d23c3e7@xhacker.debian>
In-Reply-To: <20210524172529.3d23c3e7@xhacker.debian>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 May 2021 12:36:34 +0200
Message-ID: <CANpmjNOVikz=u90-xQKzWGxbH_ov5R_EkuG6ZLqVAkjkgw8Z2Q@mail.gmail.com>
Subject: Re: [PATCH 1/2] kfence: allow providing __kfence_pool in arch
 specific way
To: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vO8TRdch;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.com> wrote:
> Some architectures may want to allocate the __kfence_pool differently
> for example, allocate the __kfence_pool earlier before paging_init().
> We also delay the memset() to kfence_init_pool().
>
> Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
> ---
>  mm/kfence/core.c | 6 ++++--
>  1 file changed, 4 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index e18fbbd5d9b4..65f0210edb65 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -430,6 +430,8 @@ static bool __init kfence_init_pool(void)
>         if (!__kfence_pool)
>                 return false;
>
> +       memset(__kfence_pool, 0, KFENCE_POOL_SIZE);
> +

Use memzero_explicit().

Also, for the arm64 case, is delaying the zeroing relevant? You still
call kfence_alloc_pool() in patch 2/2, and zeroing it on
memblock_alloc() is not wrong, correct?

Essentially if there's not going to be any benefit to us doing the
zeroing ourselves, I'd simply leave it as-is and keep using
memblock_alloc(). And if there's some odd architecture that doesn't
even want to use kfence_alloc_pool(), they could just zero the memory
themselves. But we really should use kfence_alloc_pool(), because
otherwise it'll just become unmaintainable if on changes to
kfence_alloc_pool() we have to go and find other special architectures
that don't use it and adjust them, too.

Thanks,
-- Marco

>         if (!arch_kfence_init_pool())
>                 goto err;
>
> @@ -645,10 +647,10 @@ static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
>
>  void __init kfence_alloc_pool(void)
>  {
> -       if (!kfence_sample_interval)
> +       if (!kfence_sample_interval || __kfence_pool)
>                 return;
>
> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +       __kfence_pool = memblock_alloc_raw(KFENCE_POOL_SIZE, PAGE_SIZE);
>
>         if (!__kfence_pool)
>                 pr_err("failed to allocate pool\n");
> --
> 2.31.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOVikz%3Du90-xQKzWGxbH_ov5R_EkuG6ZLqVAkjkgw8Z2Q%40mail.gmail.com.
