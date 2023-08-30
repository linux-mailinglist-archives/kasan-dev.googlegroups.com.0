Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4TXSTQMGQER7UBZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A0B878D48A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 11:20:13 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4005f0a53c5sf40469175e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 02:20:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693387213; cv=pass;
        d=google.com; s=arc-20160816;
        b=HIB4rDwqyva+jjAk9H4REW8iWNWwlpszfUyXIS6/S/XTdxz7j9VY1Sl7RyIja2Jupz
         PRks8KJn/ZAJPFS/CXQX+N4H1ikSUpZuACehXhH7qiYmes//jTiVfbABlJrf5StwHSYc
         eXx9f3TXA3hs4Aq3DMqeoX0w0WQafjawai8VaPdgr9NevBr5d2LN6Ag0Us2Gq3BnUpIk
         dcOZNXyXOdujtC9cwg+0Fd7bkVgcc97eYc3hTYKifTiCq87g5L8luGGJKFWnLNsvPp6D
         8On8M8HoRzQx4R8NM/Pb3p0flO1ruOSpkcumKAzS0aLpKiOsOQ1k5UJwPZvFkivUpFG5
         3Ysw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yXgReiNiRXQvOKQ1o3IsiLhGuQLdJJuGn3e+zbNTK0Q=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=BD3nhFHowBhWvZXqO/r3q+szLPYjX54wFDFSpHFYKCFTQRVODnh1AlAFfc97zQRjwa
         wv2JnWseWytijVdfQ5pksIOvOsOuKwHl5kqbbodyuybokvwiBWn2HWfsiwfZTj8/JiSu
         rFXzfmdPdpUyqpWdq97EO6Zd8Io3JjpvMMQEoJYXv5p9ljCxI5DXHXjKm9Grsc8uSc+v
         wjiY6e/I1sJcDkuFu6P1Ph+mfrdATXcgUcdoxBqo3Nk6I4KqUpgQ97S5VWbVsWs2kNP9
         5NJ7X+1OONxf6dwZkz0RPC9jK89Lv5KLajzhTzEpq/aG+5jF1Z7uRZIj/9dzQjlrWGot
         nU/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="CkasLzN/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693387213; x=1693992013; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yXgReiNiRXQvOKQ1o3IsiLhGuQLdJJuGn3e+zbNTK0Q=;
        b=SjwZZzph0v3kP2S01KmfHAafRBdd8KeAUaORj4oP5K6B+7HuMeZXe519PCJ5IvFhdW
         6eAJa1bLwLwrztqHFkQ4ixCQmyoe58D9+QATm+cqVoZ7ZydixMmrcLF3xi6DN+HJfoLo
         qc30Dgs78Xa058Hjd+DfahH9QcMfYgFagGx4oxlMUf6sacjMDNN/JVnevYab5Iod/SuH
         B0/ZIMRDMCQUWtY60q2YMyGsbeeJvk8EGfCTVV7AC5RoGFXMzIza2imQn5lIiotgeL9Q
         fyH8HxipISy6XwkX5eaAm7ZhTvMTmIFAIYBhmBEG4M0+Zos/OqHhp1X11jFE7Wokj99w
         zJcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693387213; x=1693992013;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yXgReiNiRXQvOKQ1o3IsiLhGuQLdJJuGn3e+zbNTK0Q=;
        b=fwA/JH6VQObh0DEKfyVhgHNXz+VZjwo1DbIcuxZPI+50evdNGQNuQOIPX3sY2r0UWn
         gCu8+cwf2lfGwrbWnkKo9Hf4Rgv6KkGIyIHQvqLn0VABHLTMtW12qLB9Y51ep02SFFey
         DlLK+/kT94pKaGyEvkhOmpwDryenAmO0eSHSGkZ9myw0LHgXXtPb2Qg6ZuRBJvP5/nja
         LG3ph/cFHUvXKaiLmJrkvsYK9nnPAz6JKFPiHshY3RsyMDgXPJhHfZvifibb+x7gB1pb
         a44DlzSWrNfF/HXWdqttYA6ThtiIraxvO7V5p1zp0qZPMqU7V8P+pLeLgug++kw+rIpn
         OlfA==
X-Gm-Message-State: AOJu0YxcEoIssxM6CGfDa9UTOsZcuvUoNbKtiLq+w9059hAkYLhsnD4L
	kQFfxu9LLWReDEbUid4a8ok=
X-Google-Smtp-Source: AGHT+IFHZPIw0P31DamoXFcZyfJtPVU2ngbw0regpkvo4FT+/gFPZNoRBSPHPIKG5En/uzo0DIdwZg==
X-Received: by 2002:a7b:ca47:0:b0:3fb:c9f4:1506 with SMTP id m7-20020a7bca47000000b003fbc9f41506mr1515412wml.1.1693387212190;
        Wed, 30 Aug 2023 02:20:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9c:b0:400:5097:70b4 with SMTP id
 k28-20020a05600c1c9c00b00400509770b4ls429070wms.1.-pod-prod-02-eu; Wed, 30
 Aug 2023 02:20:10 -0700 (PDT)
X-Received: by 2002:a5d:4586:0:b0:319:6e43:7f6a with SMTP id p6-20020a5d4586000000b003196e437f6amr1316741wrq.30.1693387210360;
        Wed, 30 Aug 2023 02:20:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693387210; cv=none;
        d=google.com; s=arc-20160816;
        b=HhsP3whjVBRrACbeDbxZYmnVbSm3YcSamBLEa0pbI+Pt+aYutVTmkoZkCPfhuRLJbo
         ZWDQNCygPz+nTgN8hJGh+0kA5DE2kFyVMDvofhxvKbUVZdvPgZ8fZzZIC1IOEzxzzl4H
         NHxshWF+tC1tAthbFCQWuP23oV6phRaNC86vq4paRIzodXOZH4EWdHxwXkKUnE2gvkFj
         5UjURodKaZ+3pTgBlYYSteMLtTGskTdYfoV/ibFGUaDNH5aQTWdrTq5HHRDoJuO3zLS/
         eHgdB4yXUtHOgu+dM9B13yBzHa/ZioXwX/9Etbq6zkpkhkX5s4lENydK7X6cfKdIpg1K
         +Qsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=b3mfR1VNhnX8t7/rO2iFNZaVWO0Cq4zowvDh6il0OaE=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=Q0s7wdDCtxb259YY2GY/Qg2b83GPOwq8R6zJyy3V3Ap7JyKdJ4wiPHYF89a8UrFB3P
         9Ed6DQOEcnWnfXom2G1aJJVjMUBS5IX2ulqVaaTVNb0Ng6kdBh0Z9TqfHwPCOVRMipdq
         5OYHSv447goRpMzhNJAzmIjp6epp4mpaiU+vDbbLrqn+hMrRILgZ0xjbhd6Tp0lm/s/y
         UIFXq2A3ENu/xnFN2tXMIYNhDSM4ImzuqXRpt6cAkRIbvNG6SEz3O25hCZwI0MdBmTqE
         hpvhKP0u4cNjMUKnINUA8fw6tn4u2v4AzHRGazXGv+xRykr4Pn4DepzpwS9CoLxf6mHl
         5YIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="CkasLzN/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id j22-20020adfd216000000b0031ac9fda4c5si1063127wrh.8.2023.08.30.02.20.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 02:20:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-400a087b0bfso49951265e9.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 02:20:10 -0700 (PDT)
X-Received: by 2002:a5d:4049:0:b0:313:f45f:74a1 with SMTP id w9-20020a5d4049000000b00313f45f74a1mr1221197wrp.51.1693387209795;
        Wed, 30 Aug 2023 02:20:09 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id w12-20020a5d4b4c000000b0031416362e23sm16155248wrs.3.2023.08.30.02.20.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 02:20:09 -0700 (PDT)
Date: Wed, 30 Aug 2023 11:20:03 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 14/15] stackdepot: allow users to evict stack traces
Message-ID: <ZO8Jwy5SAgkrQ5Qz@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <99cd7ac4a312e86c768b933332364272b9e3fb40.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <99cd7ac4a312e86c768b933332364272b9e3fb40.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="CkasLzN/";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as
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

On Tue, Aug 29, 2023 at 07:11PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add stack_depot_evict, a function that decrements a reference counter
> on a stack record and removes it from the stack depot once the counter
> reaches 0.
> 
> Internally, when removing a stack record, the function unlinks it from
> the hash table bucket and returns to the freelist.
> 
> With this change, the users of stack depot can call stack_depot_evict
> when keeping a stack trace in the stack depot is not needed anymore.
> This allows avoiding polluting the stack depot with irrelevant stack
> traces and thus have more space to store the relevant ones before the
> stack depot reaches its capacity.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/stackdepot.h | 11 ++++++++++
>  lib/stackdepot.c           | 43 ++++++++++++++++++++++++++++++++++++++
>  2 files changed, 54 insertions(+)
> 
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index e58306783d8e..b14da6797714 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -121,6 +121,17 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  			       unsigned long **entries);
>  
> +/**
> + * stack_depot_evict - Drop a reference to a stack trace from stack depot
> + *
> + * @handle:	Stack depot handle returned from stack_depot_save()
> + *
> + * The stack trace gets fully removed from stack depot once all references

"gets fully removed" -> "is evicted" ?

> + * to it has been dropped (once the number of stack_depot_evict calls matches

"has been" -> "have been"

> + * the number of stack_depot_save calls for this stack trace).
> + */
> +void stack_depot_evict(depot_stack_handle_t handle);
> +
>  /**
>   * stack_depot_print - Print a stack trace from stack depot
>   *
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 641db97d8c7c..cf28720b842d 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -384,6 +384,13 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
>  	return stack;
>  }
>  
> +/* Frees stack into the freelist. */
> +static void depot_free_stack(struct stack_record *stack)
> +{
> +	stack->next = next_stack;
> +	next_stack = stack;
> +}
> +
>  /* Calculates the hash for a stack. */
>  static inline u32 hash_stack(unsigned long *entries, unsigned int size)
>  {
> @@ -555,6 +562,42 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_fetch);
>  
> +void stack_depot_evict(depot_stack_handle_t handle)
> +{
> +	struct stack_record *stack, **bucket;
> +	unsigned long flags;
> +
> +	if (!handle || stack_depot_disabled)
> +		return;
> +
> +	write_lock_irqsave(&pool_rwlock, flags);
> +
> +	stack = depot_fetch_stack(handle);
> +	if (WARN_ON(!stack))
> +		goto out;
> +
> +	if (refcount_dec_and_test(&stack->count)) {
> +		/* Drop stack from the hash table. */
> +		if (stack->next)
> +			stack->next->prev = stack->prev;
> +		if (stack->prev)
> +			stack->prev->next = stack->next;
> +		else {
> +			bucket = &stack_table[stack->hash & stack_hash_mask];
> +			*bucket = stack->next;
> +		}
> +		stack->next = NULL;
> +		stack->prev = NULL;
> +
> +		/* Free stack. */
> +		depot_free_stack(stack);
> +	}
> +
> +out:
> +	write_unlock_irqrestore(&pool_rwlock, flags);
> +}
> +EXPORT_SYMBOL_GPL(stack_depot_evict);
> +
>  void stack_depot_print(depot_stack_handle_t stack)
>  {
>  	unsigned long *entries;
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO8Jwy5SAgkrQ5Qz%40elver.google.com.
