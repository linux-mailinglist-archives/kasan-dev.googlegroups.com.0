Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCE4XSTQMGQEKF5YE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AB3678D499
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 11:38:18 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2bcec24e8f8sf59017301fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 02:38:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693388297; cv=pass;
        d=google.com; s=arc-20160816;
        b=yTSEiLgeV/azDAmzHklQbARGkZEwtmpvbMZ9lanrVegZHgcpg9EIgzODOkN0uhlyKU
         4luRQT0YoHpdCBf0U8fLO42vrVN4ScXCn9cKayn0DfmqRFlIljRWLYJxDT2CFd8oAHtn
         7Q/tMw3afn6GPyLKjtAG/afREPkXj1jvKXd2NWIhRGCsFpMoC3Ow+gUiJKuPHwvMEIOJ
         yywsi9ZtUsHl57/Zswl8V+alp3FcrSvdAbEKxAoSte4LnD6ywfOMCd+QP7IlBwfHYhfO
         k9ZjpyvK8vg+ek3/TAeGmDPzLc2Hg2cO0OcNbAALbdGr/zvLqueQN+lH5511NqqyBO4G
         C5mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ugCv4jMpmCcjMwPaV7pTJL7wsopn7/dttucW3mLZwtw=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=JEdqcOVxEhxN5L7aFcl70ZOBuORPSev/KNuvMTVVJ6tQ4GjPAIuiLoYUunSh1gLnK+
         drbhJy8kH2ETWjvk+6tNS89dCQhL5Smm+TehmkUiHxlfwdigLwq+y6RW85auqlMc6ukX
         +5uehu/SnjTpk2X1x3jeEpwwJEJ6KnQ3k6htzAO9Xun4191MJLJAgL07aNM7Zdfe0J9K
         vYr4EYzxIrji+CiDn+gmYpb8BEUFGaaX52p1jq10uSXKmn+PJY6Ghwq+qD8n2G35G0lv
         xhpLGjZ2nzlL4P5jqAphWG2JyUL8S5T2uwP0uoKeZf4vpXVAFQQoj6i73p6jx4povFgW
         /VSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Hwza5xv1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693388297; x=1693993097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ugCv4jMpmCcjMwPaV7pTJL7wsopn7/dttucW3mLZwtw=;
        b=DpptWiVUWEW2e4MDhj0Xir8jQC9TJz9WFOh30q1s/GGDYBLcKGd0fYHmX30n7d7uh2
         0Uuykz/JoPjpNR5g0PuCOnT0nAm8ogGWCdhI/3rOaSX+ZQarDvz1v1q+4JZj8SdE3k87
         A2IMaztq1nGMnOSipl94DaAzNh1bdFQz9QfOd6tSuFN+Dd9bPwBGSZmvDJz1lBNl8xvV
         MZx68e//cBPA1CAmKX1QLjbjwihaxGFYZfTe/yi3+bTr8bdAQM5dRMLFZ6cvY4tlyK2K
         akEYOXldowqKCY7RonM0Bw9henahxUmpWJ8059i3ITAzD3Zp43I2wJQR+i2tQOVujVeP
         OcUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693388297; x=1693993097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ugCv4jMpmCcjMwPaV7pTJL7wsopn7/dttucW3mLZwtw=;
        b=AMn0ki3ubvJePQMlVCLXBKIEJG/n9FljmuxWxxxc0omfcg7ZyIFEIT9tTgN0m/BZ0B
         IVve4Fe/ugXRi96u05ES+35ofEOj8twWhoOKZvFsE8NTBNhhEJhru4y4aLluX1qrjwol
         4VaH8T/6L3NdCYalJgQMEqMqiTCy+sslRJ5w1GsqKMsXREF+9leABKiK/RuqSJNdGIU6
         m9/+yNTJnEcGEntJ4WA9Bhlux+/Uuf6jLk37pCO6BKHQIEp2sPtwjF+ZSGompb7MTCuL
         ORZp8uTdwYeU3xfkpBXOO4pdsfwTIIsCorp/YvgM0iYcXltqeqzUkYz5JcCLA67WZVfX
         Umlw==
X-Gm-Message-State: AOJu0YxNhi963sXxDPb5fmudt48owpve+plpu85dFQhYAE/eLxtEjb83
	cz+xuAVqIRcnJ7DHdIOxXKs=
X-Google-Smtp-Source: AGHT+IHbbB07lnJdgPwB1HUr/iYXvl1NCfP2MNnD5q5SzW6jrO8E/ONE3Hs+bFHFVTTOMERrspFsaA==
X-Received: by 2002:a2e:b05a:0:b0:2bc:c3ad:f418 with SMTP id d26-20020a2eb05a000000b002bcc3adf418mr1628749ljl.20.1693388296591;
        Wed, 30 Aug 2023 02:38:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:22c4:0:b0:2b9:47f5:1aba with SMTP id i187-20020a2e22c4000000b002b947f51abals6480lji.1.-pod-prod-06-eu;
 Wed, 30 Aug 2023 02:38:14 -0700 (PDT)
X-Received: by 2002:a2e:240c:0:b0:2b7:2066:10e1 with SMTP id k12-20020a2e240c000000b002b7206610e1mr1416609ljk.0.1693388294513;
        Wed, 30 Aug 2023 02:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693388294; cv=none;
        d=google.com; s=arc-20160816;
        b=xIMY3DoF+ckvWUqR5r4XlzAsdblbC05Li6rMczFppHM6AkzsgiEOqMr8LyEGNS1EHX
         9RWOH83/6ITGz2Z8HHDYDgaOsW6/I5d/EYtfXGiKQlFF98MjxsRi5fzULfZV/dAqyE+1
         IznsXgsojJgrm5GuUmXrONKLVeOLlODS1TNee+sUMi7U+b259xq5W31ysQWNxlhFTmBp
         EW/DkJX7RkxIQ1na6hfpijfHUqY4YIQ5F/cYHcV5iJBOC1vZoOi8IqhQTuADw/4LCBkP
         hohm4YDbJ1+MBknuXB9IVilJIB01Na8M6OGA+zou0Ejv5gmmIG3HR/mj13HNjG/WTkmp
         o+qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=V7w982v/e1jzg2/UemZ2RnWkspcdmAHHRTHnHv5ffU8=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=hRdeaLKYDW1Pw7bmBJbd28dnAjXmECM6fyYngKus2Zpb+dVaLcBv6NPPoywDmC+lel
         8cG/vBPZ+N1MwWtaThqB5ftRu4DOLSOh9xf7wKW/vhZ8sk7VbMUN/dEXw+PkLp73h39/
         a79M1m9eSGGrsGulWp2TuICI91GLnGIPqu20c/b9ZRuaUfHuy8VVCaIStITCptycW+3p
         7NRCkC+FJhupmDvTlxd3OezCQiYPNOa6xZhIIN+Op4GUIfmIfmbqyHPTm2DyJ+Osce7K
         TPgYK3rc9GJSfLGZ/IsBMGKC+b71dGUglvfHbR9sXjkw4o666AYZMI9Tnw9+zo+OevnU
         EffA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Hwza5xv1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e5418000000b002b9e701adbfsi1269813ljb.1.2023.08.30.02.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 02:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-401c90ed2ecso31059945e9.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 02:38:14 -0700 (PDT)
X-Received: by 2002:a7b:c8c3:0:b0:3fe:d71a:d84e with SMTP id f3-20020a7bc8c3000000b003fed71ad84emr1520377wml.1.1693388293802;
        Wed, 30 Aug 2023 02:38:13 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id g15-20020a5d46cf000000b0031762e89f94sm16003691wrs.117.2023.08.30.02.38.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 02:38:13 -0700 (PDT)
Date: Wed, 30 Aug 2023 11:38:08 +0200
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
Subject: Re: [PATCH 15/15] kasan: use stack_depot_evict for tag-based modes
Message-ID: <ZO8OACjoGtRuy1Rm@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Hwza5xv1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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
> Evict stack traces from the stack depot for the tag-based KASAN modes
> once they are evicted from the stack ring.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/tags.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 7dcfe341d48e..fa6b0f77a7dd 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -96,7 +96,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>  			gfp_t gfp_flags, bool is_free)
>  {
>  	unsigned long flags;
> -	depot_stack_handle_t stack;
> +	depot_stack_handle_t stack, old_stack;
>  	u64 pos;
>  	struct kasan_stack_ring_entry *entry;
>  	void *old_ptr;
> @@ -120,6 +120,8 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>  	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
>  		goto next; /* Busy slot. */
>  
> +	old_stack = READ_ONCE(entry->stack);

Why READ_ONCE? Is it possible that there is a concurrent writer once the
slot has been "locked" with STACK_RING_BUSY_PTR?

If there is no concurrency, it would be clearer to leave it unmarked and
add a comment to that effect. (I also think a comment would be good to
say what the WRITE_ONCE below pair with, because at this point I've
forgotten.)

>  	WRITE_ONCE(entry->size, cache->object_size);
>  	WRITE_ONCE(entry->pid, current->pid);
>  	WRITE_ONCE(entry->stack, stack);
> @@ -131,6 +133,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>  	smp_store_release(&entry->ptr, (s64)object);
>  
>  	read_unlock_irqrestore(&stack_ring.lock, flags);
> +
> +	if (old_stack)
> +		stack_depot_evict(old_stack);
>  }
>  
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO8OACjoGtRuy1Rm%40elver.google.com.
