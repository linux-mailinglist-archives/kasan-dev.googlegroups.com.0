Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBVE436NAMGQE7OOB36I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 034E460CB4B
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 13:53:58 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id w2-20020ac24422000000b004a299d12364sf3692554lfl.13
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 04:53:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666698837; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCWRPQElRZbkwCq1k8Lfa+8TVM329c75E5tjgSOVedjp+ZkE39lIKEFumhimdVfBX+
         Nr6+vlSp8R2VTwPyTjw5mhOQHiOkkJiMiq5IlYmTK3QwPVWerTGbgR5/GmUgLUo7YlmQ
         pMHq9kCzwzWL/S7ZbhDmBL5epgAbbtQ7Q5DCJQjovu0CoYzWhCR1+WTOvFxHQ2Z9qrqn
         0g2snHOj+TAlZego0e7cRqFLizpUDVIsNdPvWhG5ptlbFGpOS+JPKgJeuaydFeF/0e8k
         OZxz3Woj9MLQXI53IWgxYQXUsenDigNBZJHapOp6JoKvoiXcj5odDTMcJZrho875Gpa6
         LPjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=fUsypjcfc8mwHfldnYCr69bPJvubnG8siwe2Ys3/EN4=;
        b=KR1QEgetgWbUyl2THiRsiTzO38ntcT/pHPQOq4vSOQTzoRYxTSD4sPt0Yts4ktK6M2
         f63HAEV9NZlv27LCe2xHNqppZ4BYGOv/2nr3L0FOxMrCdrSZnFDUfNcxvAMaJPUdXGd4
         13WlBHMeIVWnQ0+CvRT1RMtexrkw8lB4Xr24ZB+uEEDjLp/5BSZcvFWAu8zvosZ6lzcT
         eMWnGf4KjUZkVDQD5XU0RES1kMs1yOrKSFNznOt0Q+MMCOMRiwy1aBipIDC6Q4WielSB
         e/X6GtrIx5Qc7apQVZrQUu4ij0YdW8yQpaWwuHbKKJBFu8oZm7PUlmFxXOP0xd09dcmP
         mZGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kPGJPSHP;
       dkim=neutral (no key) header.i=@suse.cz header.b=tq6qoYZa;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fUsypjcfc8mwHfldnYCr69bPJvubnG8siwe2Ys3/EN4=;
        b=er8h8ISN9hqXPzWSqQ6aT2P38UcEOk26+Zmjx2q42SKHXzA6oZ2zpV7bYmwAEJC2x6
         zCkkSCQ2KQFhgdfx3p/hkNHuC3m4a3FtMFdA7NoPCGN6A1RTUuisf+pLbkYlvKfGH+cW
         kCAauXIP/LJTF9ZLsiWD2jUEX85KEU/mp1UV4m9qMEo00/qI156fm2u5MfXYCALe68fE
         18038o4crytdQ3ToagHytE81nDu5qqL9GTdxBE6D/2Qyqd3jE0fPRzvZjvZGdg7eqN43
         8+dDOKyMEBFV+V+9IJEzaU0GjOnllxM2HgRpW6UvYXjWLzlR/kPS+Lj2PCnIqew6aaZz
         zmCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fUsypjcfc8mwHfldnYCr69bPJvubnG8siwe2Ys3/EN4=;
        b=HvlbRwOk36lEIgwpBLQKXb/SRAy8PHzTUX+6Mj/Qq54hf81GJ881OBB6VgUlxnZLbL
         t6Nmx/v84Wu+VVVJLkG1jrDSYhujFS14lu1Ix/fupDNtsUac8ri7BSoWNEKzXrdX025j
         DMhRCn1bIAMcBEK0sEjAJSuazdJ4JYC1TQZYYurSCkxtyNxEDukZoDAF6JchrOEM82Lh
         /Wm8dc1kFBI4dbJNMdVRBhTj9nZGFSv4t3LqdhRrXX+W8k4zRML6DAtxb+bgieKYbHQV
         Xv2PL7vY2mZCY0NEL8REtiz147B/OWh6L42173GyJ3w/P0Xm0JxEA0JI2mlnYtSPUMkq
         uF8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2QAJr7aJMq1lXv0BEybg0GB5AbkcDyZQ/fz1ulFHQWoBSrfYr/
	Jz687FPW5vMLjvvbkZ5lTD0=
X-Google-Smtp-Source: AMsMyM7xeEhLkm5UxDSlMAgIO9GHSaJtcs52qO4ptvfjCQ3hPBNS+qlja9MF5fv/44bUxZCcDeWxCQ==
X-Received: by 2002:a2e:bf0f:0:b0:26d:e258:9ff6 with SMTP id c15-20020a2ebf0f000000b0026de2589ff6mr15171564ljr.356.1666698837128;
        Tue, 25 Oct 2022 04:53:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9684:0:b0:277:1d5b:1cc7 with SMTP id q4-20020a2e9684000000b002771d5b1cc7ls62340lji.3.-pod-prod-gmail;
 Tue, 25 Oct 2022 04:53:55 -0700 (PDT)
X-Received: by 2002:a2e:a7cc:0:b0:26f:cb7a:f375 with SMTP id x12-20020a2ea7cc000000b0026fcb7af375mr14975697ljp.392.1666698835582;
        Tue, 25 Oct 2022 04:53:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666698835; cv=none;
        d=google.com; s=arc-20160816;
        b=us544OWGCNOvC9e9DYPsN6g6f1t1z3K/KuoPbyBGePhn6RMpTAiD11JrH5ql2FCyCg
         I4/TShVkSTn6e4IR1mDWDkXymgcgtworj7mnsGIWethQN5cC+MD5CuS0SulQvl4XotTw
         DvvMN3Y8I7TtHUgkzFJoPFDgxMvmeZPgEwVeDdgc1wde9qO8oeorUmtTqQAYvae3vOnS
         gxI1zUaxFKj3c+EAnd4GZCxpSP3Tm4h+/JFd1GY8Xavy4ZQl2tmrAb+AKwlikwZIC1rh
         NtZRzdlhi6+aO+hWwrzR5CW3IxOaEoUYN5Owzan5uS9UWIPVY2pKOPd+Z29v4Rt7ixhx
         vdgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=lRKktY4aU99itUG0r84bU0CD/8p8OYqUqOyB0oh37xY=;
        b=psZvwWGlmdpb79xV3wVJNBDirQfq62bS551tLhIuxeIehd+s8hBywuA1Pn5bSe87Lv
         5WRi7vn7sGP+55Jo1gD6ryXBQ8j6o67HR5Bob/H1nK7I1LLvoHbwc8G76zH5SplHtNB3
         rY5eB8V9SEYzw6dVGV6EgDKY0YPMnEnlORcecaGWrDN46RqlU2h4sURhIFeoDMUkZS85
         2ScQkYY0hlem72et6s5X1r/qCEybuxzztCIo4gqdVTKdHhSnAOdDzl4WawZFVjsIEY4x
         MC3/+LMDw5imgNfkqqSxriXmg5mybDo0VbhkChFXggbeOd1pizso5ZoE3BRH15KoOzHK
         pyjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kPGJPSHP;
       dkim=neutral (no key) header.i=@suse.cz header.b=tq6qoYZa;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id a17-20020ac25e71000000b0048b38f379d7si84463lfr.0.2022.10.25.04.53.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Oct 2022 04:53:55 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B6FB51F898;
	Tue, 25 Oct 2022 11:53:54 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 7056A134CA;
	Tue, 25 Oct 2022 11:53:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ynO5GlLOV2OJBwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 25 Oct 2022 11:53:54 +0000
Message-ID: <fabffcfd-4e7f-a4b8-69ac-2865ead36598@suse.cz>
Date: Tue, 25 Oct 2022 13:53:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.3
Subject: Re: [PATCH] mm: Make ksize() a reporting-only function
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>, Christoph Lameter <cl@linux.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
References: <20221022180455.never.023-kees@kernel.org>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221022180455.never.023-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=kPGJPSHP;       dkim=neutral
 (no key) header.i=@suse.cz header.b=tq6qoYZa;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/22/22 20:08, Kees Cook wrote:
> With all "silently resizing" callers of ksize() refactored, remove the
> logic in ksize() that would allow it to be used to effectively change
> the size of an allocation (bypassing __alloc_size hints, etc). Users
> wanting this feature need to either use kmalloc_size_roundup() before an
> allocation, or use krealloc() directly.
> 
> For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> some of the partially open-coded ksize() in __do_krealloc with ksize()
> now that it doesn't perform unpoisoning.
> 
> Adjust the KUnit tests to match the new ksize() behavior.
> 
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Jakub Kicinski <kuba@kernel.org>
> Cc: Paolo Abeni <pabeni@redhat.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Vlastimil Babka <vbabka@suse.cz>
> Cc: Roman Gushchin <roman.gushchin@linux.dev>
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: linux-mm@kvack.org
> Cc: kasan-dev@googlegroups.com
> Cc: netdev@vger.kernel.org
> Signed-off-by: Kees Cook <keescook@chromium.org>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
> This requires at least this be landed first:
> https://lore.kernel.org/lkml/20221021234713.you.031-kees@kernel.org/

Don't we need all parts to have landed first, even if the skbuff one is the
most prominent?

> I suspect given that is the most central ksize() user, this ksize()
> fix might be best to land through the netdev tree...
> ---
>  mm/kasan/kasan_test.c |  8 +++++---
>  mm/slab_common.c      | 33 ++++++++++++++-------------------
>  2 files changed, 19 insertions(+), 22 deletions(-)
> 
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 0d59098f0876..cb5c54adb503 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -783,7 +783,7 @@ static void kasan_global_oob_left(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>  
> -/* Check that ksize() makes the whole object accessible. */
> +/* Check that ksize() does NOT unpoison whole object. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
>  	char *ptr;
> @@ -791,15 +791,17 @@ static void ksize_unpoisons_memory(struct kunit *test)
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
>  	real_size = ksize(ptr);
> +	KUNIT_EXPECT_GT(test, real_size, size);
>  
>  	OPTIMIZER_HIDE_VAR(ptr);
>  
>  	/* This access shouldn't trigger a KASAN report. */
> -	ptr[size] = 'x';
> +	ptr[size - 1] = 'x';
>  
>  	/* This one must. */
> -	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> +	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
>  
>  	kfree(ptr);
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 33b1886b06eb..eabd66fcabd0 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1333,11 +1333,11 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>  	void *ret;
>  	size_t ks;
>  
> -	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
> +	/* Check for double-free before calling ksize. */
>  	if (likely(!ZERO_OR_NULL_PTR(p))) {
>  		if (!kasan_check_byte(p))
>  			return NULL;
> -		ks = kfence_ksize(p) ?: __ksize(p);
> +		ks = ksize(p);
>  	} else
>  		ks = 0;
>  
> @@ -1405,8 +1405,10 @@ void kfree_sensitive(const void *p)
>  	void *mem = (void *)p;
>  
>  	ks = ksize(mem);
> -	if (ks)
> +	if (ks) {
> +		kasan_unpoison_range(mem, ks);
>  		memzero_explicit(mem, ks);
> +	}
>  	kfree(mem);
>  }
>  EXPORT_SYMBOL(kfree_sensitive);
> @@ -1415,10 +1417,11 @@ EXPORT_SYMBOL(kfree_sensitive);
>   * ksize - get the actual amount of memory allocated for a given object
>   * @objp: Pointer to the object
>   *
> - * kmalloc may internally round up allocations and return more memory
> + * kmalloc() may internally round up allocations and return more memory
>   * than requested. ksize() can be used to determine the actual amount of
> - * memory allocated. The caller may use this additional memory, even though
> - * a smaller amount of memory was initially specified with the kmalloc call.
> + * allocated memory. The caller may NOT use this additional memory, unless
> + * it calls krealloc(). To avoid an alloc/realloc cycle, callers can use
> + * kmalloc_size_roundup() to find the size of the associated kmalloc bucket.
>   * The caller must guarantee that objp points to a valid object previously
>   * allocated with either kmalloc() or kmem_cache_alloc(). The object
>   * must not be freed during the duration of the call.
> @@ -1427,13 +1430,11 @@ EXPORT_SYMBOL(kfree_sensitive);
>   */
>  size_t ksize(const void *objp)
>  {
> -	size_t size;
> -
>  	/*
> -	 * We need to first check that the pointer to the object is valid, and
> -	 * only then unpoison the memory. The report printed from ksize() is
> -	 * more useful, then when it's printed later when the behaviour could
> -	 * be undefined due to a potential use-after-free or double-free.
> +	 * We need to first check that the pointer to the object is valid.
> +	 * The KASAN report printed from ksize() is more useful, then when
> +	 * it's printed later when the behaviour could be undefined due to
> +	 * a potential use-after-free or double-free.
>  	 *
>  	 * We use kasan_check_byte(), which is supported for the hardware
>  	 * tag-based KASAN mode, unlike kasan_check_read/write().
> @@ -1447,13 +1448,7 @@ size_t ksize(const void *objp)
>  	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
>  		return 0;
>  
> -	size = kfence_ksize(objp) ?: __ksize(objp);
> -	/*
> -	 * We assume that ksize callers could use whole allocated area,
> -	 * so we need to unpoison this area.
> -	 */
> -	kasan_unpoison_range(objp, size);
> -	return size;
> +	return kfence_ksize(objp) ?: __ksize(objp);
>  }
>  EXPORT_SYMBOL(ksize);
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fabffcfd-4e7f-a4b8-69ac-2865ead36598%40suse.cz.
