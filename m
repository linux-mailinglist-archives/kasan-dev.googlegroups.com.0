Return-Path: <kasan-dev+bncBCMIZB7QWENRB6OCXHZAKGQEJK6QK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id D580C165BAE
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 11:37:46 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id w17sf1958945plq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 02:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582195065; cv=pass;
        d=google.com; s=arc-20160816;
        b=qiBHmqvqHJkb1wcgJN4UOUYUyxvDcPN4wa/+VxI2npBsG50hKx7xLyZdjcX+9UNJrC
         PEIXAA6M/Y2aNU7PWpQAsA9zs0wV/IPj5mDdS/Ctuy8yKI+4pqLJVD8uFKQIR9iKK/cm
         L2cQqs2ZxTSLc4R1WB6iE3EKJkhy7LKfW8MQPWPT6PaVwcriyBGvBARTolZXMATeXxQq
         Do08+2kA18uaBEk89tEdhkn+ViZyR1qIwe13aenpGHG3NecW6aLOolhGon6Lg4zQ8bge
         tBn5djHTIDCVEN74FbtHZ9E7u4F46nYNFRUQ/WcOBgs/xMPOUv182/tHbmar03N2OjIx
         sgvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZDxS9Kv395sgy0op6+tqmltAdaimGwfILe7IttkXARU=;
        b=abR9Akgd7JqeBntNp/zNcKUP4DoWYHzryS0PrCtrb8t7GUkRjHAy3T6sIPuMDcwcPv
         Kj1HpgKV3Z0aAc3Q26BcsVLm4A+x5ZtxwRmmYQi9FdrAN2XvxHJrixVXc4ZA29mY8bPM
         bufU2UAmUV/8OVX0xeSY+uv1GuNcZBQiyPBh7cSKYxbEpujyquDSqZYpTjjqqb9P4Inu
         OKojnpjdKdKCsw8pWIQSWP6rbgWlP3ExKSWAiZF8ID9dq64wJLObPqwgWoVwOepm/DJu
         ZzDF+KkSHWsbxnuMgeZUbKw5Uoii7iiX+nrLTyYEFH4c9zKeSaiAtjHSFoIHkm3xjf8k
         I5JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jA55lcjy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZDxS9Kv395sgy0op6+tqmltAdaimGwfILe7IttkXARU=;
        b=re0Bl7X5/dKwEMKmTCoRPqQ3RMkPZFLLHXy2j9BWjJFZesxWLitfC2ydFwBE8AhEYn
         DQcFcgjJ/FM5QfrTgdwGaqLQpmlDy/GXFpRbfifZmWVwQfIVkN0IRO+BVq6KFTo7SvHy
         TI3Lb1lOFK4/yEaf1nR94/Uv8nrCXV97ztZ8MbLjW+XZfhKlPuoFy7m/+DIhR6oQwgEL
         ldheoiVSKrkP/fn2qtNXXjTCL50GJNk+/PdKKsAur1HBEmcg0DV0jXRIihnf3G+qbdSo
         vp0u8GRKlGKP74Z9m4VBQqFxIPgnyDzzDC9nPkvLeKif/vJoJv5y75BkKnH5+pWOyLvw
         suzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZDxS9Kv395sgy0op6+tqmltAdaimGwfILe7IttkXARU=;
        b=dwmi0HCA017hcXQ60SfMVnW5yMPdiPBqacUv2ZJe2hGedl4kFT0bJUMACfSJ2O/Zpe
         BBrnykmwlmajtdUej4PdCLRsWXY+p4L8duMyMp/og84fub1hQmJM8Q6rUCdZhIRmtYXH
         +D7ai/hLUz/zAUS0ICmZqg+NSqNV8pUdY7L+zkZATLkGaxxSwlHI+nVbtrdjuqY9Z5HL
         9/tVou7LdDhT/TfxI+HPtB0QEl4g9FI6pXQ4RsvNmw1MLcSW4U5PUdb2fhrbOegjtjvD
         HGbdclTKgKdPUtRxdIqMZ9c+jDr3qIDWXpx1y4Pzy7vvXZqHjc0FJckgeq5ZWA4L2SgJ
         EE2A==
X-Gm-Message-State: APjAAAU7BqKYBOQMTils49blyZ2YXh0PTtjLE/cpwMji6Fowtb3bVkFm
	uLoIiFYnbMRgmREUuT/K+LM=
X-Google-Smtp-Source: APXvYqzZ4+PaDkCQlaKH+AyaHofJBpEXzUwW0L6f6Hrj9NTsohkAR3YQe+LDi530vLwMlfAKXy624Q==
X-Received: by 2002:a63:921a:: with SMTP id o26mr33052880pgd.246.1582195065588;
        Thu, 20 Feb 2020 02:37:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6644:: with SMTP id f4ls776874pjm.2.gmail; Thu, 20
 Feb 2020 02:37:45 -0800 (PST)
X-Received: by 2002:a17:90a:5289:: with SMTP id w9mr2806906pjh.95.1582195064976;
        Thu, 20 Feb 2020 02:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582195064; cv=none;
        d=google.com; s=arc-20160816;
        b=dtPBQYb0k9yzVTSzSV9BtrMe4aEqPr8XssB7VWsBNw8wfro+9wJEdbHYO62geQvaX8
         B3jj3Q3HzV4lIIOQ5yrd+n1PfWuWHVFKRAet5fYxdxHNHwRmqpTPFojT02vBBCf1vk+j
         MEczMi/5qUrfWTXM6zpg4MXHQiZ3FTTe4LVpJ1EiOg3nLx7++3lIe+BDh1vckqbLn3p5
         9RBJqFAO46CJjrJgk+9eUJVfKAUUsnFp2GfqwqkUMPLKilUMd21tln0A93eIJ/N0hcSV
         nzJ4zLs+kMppdXJ+WUtjgNBD40L6PyD1k1bsGsxYxWzuN6SwIHaNsC2Q/SWUYL/LeBsq
         Z8NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+L7+FQcGBr8q70euhVbn25PNyS+UmjbMnhO14ByiE0w=;
        b=S5i252TprIWGK7ImkBkO6KhrRpTv3Mh/D95uohIvMn9bweC8R7pUbFcLcErgtcKdbF
         Hs2vqlSJvWroroPd16UhWQK1COeoQZ+tOSZ4gDVWPbBIOBYq9ViU2/RwF4P06f9ZvMbg
         enDQuhx7FkVYU6Ibtqn+9ICJr8/QnPFnq8K7aWxWjJxIIz4tlQ6q9Sa1aLdWkcE8Mz3s
         HMM8nutTuDizjArOWw3dtlvJ4/ZwpF48oTNqbi5Kj5f/Kts9KJ4UapmxY+lKH/H3noFH
         YVaSsE86wzjs9tyhm3bbp/8fBLJoqMHRsJRz9LPTZ7B6EY334CnXMiLqXfQo4iVI2bKb
         Yakg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jA55lcjy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id n20si135906pgl.1.2020.02.20.02.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2020 02:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id t13so2505244qto.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2020 02:37:44 -0800 (PST)
X-Received: by 2002:ac8:340c:: with SMTP id u12mr25564787qtb.257.1582195063751;
 Thu, 20 Feb 2020 02:37:43 -0800 (PST)
MIME-Version: 1.0
References: <20200219144724.800607165@infradead.org> <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
 <20200219163025.GH18400@hirez.programming.kicks-ass.net> <20200219172014.GI14946@hirez.programming.kicks-ass.net>
In-Reply-To: <20200219172014.GI14946@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Feb 2020 11:37:32 +0100
Message-ID: <CACT4Y+ZfxqMuiL_UF+rCku628hirJwp3t3vW5WGM8DWG6OaCeg@mail.gmail.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is not sanitized
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com, 
	Frederic Weisbecker <frederic@kernel.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jA55lcjy;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Wed, Feb 19, 2020 at 6:20 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Feb 19, 2020 at 05:30:25PM +0100, Peter Zijlstra wrote:
>
> > By inlining everything in poke_int3_handler() (except bsearch :/) we can
> > mark the whole function off limits to everything and call it a day. That
> > simplicity has been the guiding principle so far.
> >
> > Alternatively we can provide an __always_inline variant of bsearch().
>
> This reduces the __no_sanitize usage to just the exception entry
> (do_int3) and the critical function: poke_int3_handler().
>
> Is this more acceptible?

Let's say it's more acceptable.

Acked-by: Dmitry Vyukov <dvyukov@google.com>

I guess there is no ideal solution here.

Just a straw man proposal: expected number of elements is large enough
to make bsearch profitable, right? I see 1 is a common case, but the
other case has multiple entries.

> --- a/arch/x86/kernel/alternative.c
> +++ b/arch/x86/kernel/alternative.c
> @@ -979,7 +979,7 @@ static __always_inline void *text_poke_a
>         return _stext + tp->rel_addr;
>  }
>
> -static int notrace __no_sanitize patch_cmp(const void *key, const void *elt)
> +static __always_inline int patch_cmp(const void *key, const void *elt)
>  {
>         struct text_poke_loc *tp = (struct text_poke_loc *) elt;
>
> @@ -989,7 +989,6 @@ static int notrace __no_sanitize patch_c
>                 return 1;
>         return 0;
>  }
> -NOKPROBE_SYMBOL(patch_cmp);
>
>  int notrace __no_sanitize poke_int3_handler(struct pt_regs *regs)
>  {
> @@ -1024,9 +1023,9 @@ int notrace __no_sanitize poke_int3_hand
>          * Skip the binary search if there is a single member in the vector.
>          */
>         if (unlikely(desc->nr_entries > 1)) {
> -               tp = bsearch(ip, desc->vec, desc->nr_entries,
> -                            sizeof(struct text_poke_loc),
> -                            patch_cmp);
> +               tp = __bsearch(ip, desc->vec, desc->nr_entries,
> +                              sizeof(struct text_poke_loc),
> +                              patch_cmp);
>                 if (!tp)
>                         goto out_put;
>         } else {
> --- a/include/linux/bsearch.h
> +++ b/include/linux/bsearch.h
> @@ -4,7 +4,29 @@
>
>  #include <linux/types.h>
>
> -void *bsearch(const void *key, const void *base, size_t num, size_t size,
> -             cmp_func_t cmp);
> +static __always_inline
> +void *__bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
> +{
> +       const char *pivot;
> +       int result;
> +
> +       while (num > 0) {
> +               pivot = base + (num >> 1) * size;
> +               result = cmp(key, pivot);
> +
> +               if (result == 0)
> +                       return (void *)pivot;
> +
> +               if (result > 0) {
> +                       base = pivot + size;
> +                       num--;
> +               }
> +               num >>= 1;
> +       }
> +
> +       return NULL;
> +}
> +
> +extern void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp);
>
>  #endif /* _LINUX_BSEARCH_H */
> --- a/lib/bsearch.c
> +++ b/lib/bsearch.c
> @@ -28,27 +28,9 @@
>   * the key and elements in the array are of the same type, you can use
>   * the same comparison function for both sort() and bsearch().
>   */
> -void __no_sanitize *bsearch(const void *key, const void *base, size_t num, size_t size,
> -             cmp_func_t cmp)
> +void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
>  {
> -       const char *pivot;
> -       int result;
> -
> -       while (num > 0) {
> -               pivot = base + (num >> 1) * size;
> -               result = cmp(key, pivot);
> -
> -               if (result == 0)
> -                       return (void *)pivot;
> -
> -               if (result > 0) {
> -                       base = pivot + size;
> -                       num--;
> -               }
> -               num >>= 1;
> -       }
> -
> -       return NULL;
> +       __bsearch(key, base, num, size, cmp);
>  }
>  EXPORT_SYMBOL(bsearch);
>  NOKPROBE_SYMBOL(bsearch);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZfxqMuiL_UF%2BrCku628hirJwp3t3vW5WGM8DWG6OaCeg%40mail.gmail.com.
