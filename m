Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYMDR7FAMGQEDY7QJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D85CCCB07F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 09:57:07 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-477cabba65dsf2380615e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 00:57:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766048226; cv=pass;
        d=google.com; s=arc-20240605;
        b=ORcXI4P7BouwZ6JbD8NJhZN+nctVkTdVsXtu7ut0jMdIvRDNg7vg9LneA0viC2IZlN
         w2LBDTBFm236dBLKucgvw78FcP2ED/ksC+vV+KN+YfzDN8xe1cs5Vk4GQpVMOgrpaL9F
         vQEAGeoCbYqwoHnriEMQUFp633aGITdFxJtU/rmBAWiFuoLKUE3bvocRLTSAlxzh6hgI
         NZTP28I1/Xa9+sAttX3JzMxzjAyF4NhCeeO50fYy759SFKKh/ilis4kX4CE/oYnJRC5c
         bJUJYrBdS5juRpi5kYRlV924ODHAJRGk2JrJIRzYd5kSS5iIF5UCAd4A3dmyKuZhQz9O
         cq8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GZik2kvas1+UMOUcRjm4OGhrN76cYJUo6G5T+aCvYnQ=;
        fh=VSRKxeBK5umn2x9NLszfz90F852qD24dBP/ZLkq7gv8=;
        b=IF1r05MieEOVXHDZsDLpPXovgYJjPjlc9RB4xe/b5yTm+3P9yK61pmq5S/rrTSp+n5
         PDspaYxZzQlgeTSW4zYfW6yv91O4uerNj0ZDtxTfYq0dbAPNOGvwVoWN4WR2a2O7XZ5o
         tphvOHcHfgmbYzctota36f+KBYlTCDaPqGwtZUX2OcK0Rx1orVsDyrOXL+imxZr/Hv0Y
         42DXiBOBJ4I+3QkBPcfj9pUHP8eZbUEzZUJYP97oCbXYqTJm5/h3WsOcwNGTOEjeadCp
         kqd1XNIx8jIf2b4jSW+aY0X5MOG8x2N3Ae7/igRfJ63VEiKFNMVHM/NAGdk98rEYGwKL
         dr/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fQeabV4u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766048226; x=1766653026; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GZik2kvas1+UMOUcRjm4OGhrN76cYJUo6G5T+aCvYnQ=;
        b=t6xCTZZMRMXhC4kD1fU96TtMu1xguXStrBo9R+WfJbMHaV/Pz4j6z3uEs2ZjSoHybX
         Y432LeimLu84HpYAgwZbth+IlXQ+aNU2FjkW8nNurJCMxPBov45ST9hzSszB8F/aKSiL
         3pyT8phceUj1GxXkn6AGTUggcWfYFrnZn5bn6K9r8lzV/oN5nMyeBqwLwmk5YGz9rwL8
         rZOCOo8UQsjfVPrBTBAm91RP1JLDSZzKUTyZkwnEyo/rzenzfMObh9eCme6Mn/xq6STA
         D/nchjNCuJiZZ1woWhx6TKptbQS/wOKcSi9HSKyUKqqS/8kVN+6hy3XUEvZx5LWZwMD6
         NkWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766048226; x=1766653026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GZik2kvas1+UMOUcRjm4OGhrN76cYJUo6G5T+aCvYnQ=;
        b=FpNUhpUZDW9MT6ddiggitUoQIbhmx5STcs83ndbXuZlmmx3wR669ywoPNkQupCuD82
         qdVaN52t7Y8G8j7c4Sfi8J9h6oi6huB6NnsbtnpUhlkrbHvIGmwuTxjhAOfzWLq8t3Ch
         rVGHRavLDSn7xaErzRtdo1HKaTnQ3aJIKAM5biv+LxBJh6g03VJypRJlOpwy+nG5TZ5Q
         HEqSS+Tt33qlnpjflsO45JbVpOYX6HBfAVAaYMVg+xElhNKkL8PVFZiaSsttwtNgf3om
         VCzte9AInqArZOAh8AaapFkpGMMv7FI68AFud08vM5juS2WwhztHfz3y7vL4wJgPOgku
         v1QQ==
X-Forwarded-Encrypted: i=2; AJvYcCXZmUDmCfzMmaVhyjPnuy8sxAvV+jXnoVMTr/lrQDm4ShIJ34L5ullw9lGtIxPU70T8bqLtxA==@lfdr.de
X-Gm-Message-State: AOJu0YyJs4OSMiCI6Zw52CfQkcY9QTHBRKEqTw+qWGD/rC4jDSZQYc/5
	EujgIWXzl6ltv9veYQnVkgxRi5kltI6p0J1yfP6JGbAW1sZLS8Uy015W
X-Google-Smtp-Source: AGHT+IGRsX1bZKxuCPWa0wlazfIboqp9jgTt5ip+txUd9RfocpsKOICAvN4GSi+nqlr3XJEit9SM6A==
X-Received: by 2002:a05:600c:45ca:b0:477:9f34:17b8 with SMTP id 5b1f17b1804b1-47a8f8a80bemr200450665e9.1.1766048226419;
        Thu, 18 Dec 2025 00:57:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZx1EOSjmgpv0YAeZbOaBqdC+vi2nH7ea4iZdZjvzPn/g=="
Received: by 2002:a05:600c:3596:b0:475:c559:4e89 with SMTP id
 5b1f17b1804b1-47a8ec6a769ls59442285e9.2.-pod-prod-03-eu; Thu, 18 Dec 2025
 00:57:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVBOEQy5I19e2ZrQ0CRq3Gd1SgLbNut1rYIPol1HiWPEQVgb4cm9mpi6qwm/X4U+blLmOT8QJlOWaQ=@googlegroups.com
X-Received: by 2002:a05:600c:5252:b0:477:76cb:4812 with SMTP id 5b1f17b1804b1-47a8f708ebamr207522555e9.0.1766048223532;
        Thu, 18 Dec 2025 00:57:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766048223; cv=none;
        d=google.com; s=arc-20240605;
        b=fAys2ukkiK3pWK/ChxYwl58ok6MUlTTwn+g6GohtijilAXkssXiyNrNn56wsFqz0au
         s/9VNC25fbH8XqNxrC0/tI8JwuwH13ukmU7hwbA0NC42XxtB7o6s9K0KGdiFZpvhRPRU
         g64Qo0tuMkqoJFEHZG6NUhUSH0qRElqwO/DvoSEBXD5WY7W4fcA78qestXb25Kbx3/cb
         aQgva0RniQ8r6fUKzMCOs+RJ+f9mpiagxqBYN84Tx4/T3Ulg4vxMfydw3nngpguQl51S
         mFeNuLv3UH5enf4obD1RwjWl6pGj5VnE8yY88iSPlNvglPUs1LXk9bRAA1ZXbe3wniav
         BaCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GQSScrHGocujKud+xiMEi7IrZhWMIzDGmWhBlDWcW1w=;
        fh=1FHR2yLdof6p4ELdW8AssMEEVI3H/65bBY8fBzts/l4=;
        b=j+rEEpeByMC4L0gUqe5uxhmU9B1CH3txaKGiJxwQiZh9HXSpUqL1bw9wBGY+fQhyHC
         sGktGDeOaJaPfGV2e1FsKaAtcI5861urGzyI7CUh/qVFkFeogiytdO7d/sWzu2ubqHno
         7BnvXMburDXvcGmcjObdyw5bogww9aojJha2Qw0/b8Jmn9h5Ik1LoeGRA6vwMor95nw0
         LUq6Qcv7ztTyHARV7muxMGGV6jKvNmWlqp2dTs5eGCws9643TVWAwU9zWsAnST0qIGpm
         Sf/jXEuPXmfgptZjF5VFGMTaLJXA9FLA/OaEeXwz5vYjZq6DkKbYomebcYnCERz5fwrI
         f8rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fQeabV4u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47be3a5b84csi252575e9.2.2025.12.18.00.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Dec 2025 00:57:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-477b198f4bcso2601935e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Dec 2025 00:57:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXlJjecxFYyq2+HCacXHe9K2Dm47d8+yXZ8b270d5cP3Kusi9N/INfUtzT6RsCE0KCEHufJiR7C5kE=@googlegroups.com
X-Gm-Gg: AY/fxX7WCn14j7A094scMjb0oC7IZix+YysZr9h8ZxzX8ptqhfxHW+KjLAX9nopYP1p
	vWGt3c/7I7kH1+ThFUJrI435j1nPb/cw23uCatQjhXcUW0vWfVM/1D7umMyGR+at7TFOpcuIBxh
	4sSYbriLs49yy5lDIOrlrSSolJ/KEglxen3kqWXwPitfKdNyzF2nZW1Q4qgGmaBiefmzhWLxVAX
	81e216H0b/yMYhL9FTLTyvzs5vuRILQ8Vw8576kqOpVLLDjvyIGOwdJ1UfKYcN8GCeAIbkNcSZ7
	pHfFXpb2StdBCNBdWvIzAE0z3KsAbAjy/euYwuUDVv3zUatg+4k6HAVwyrfyqvy3LC6PfwV3I5U
	L2ObxAz6vwv3HUw+SXb9s0I9/NJKcFjndz/dyUvtCufiFYSyudsNEDGBtqYyt7W9AQy8N28IVso
	rJxbMNbt4rthHT5O6FjDiWOzwg5WVJtzuSZOeQXaIREPq8e7CF
X-Received: by 2002:a05:600c:45ca:b0:477:9f34:17b8 with SMTP id 5b1f17b1804b1-47a8f8a80bemr200448785e9.1.1766048222784;
        Thu, 18 Dec 2025 00:57:02 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:fea4:c93d:2b17:7eac])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47be3af6dbdsm9753695e9.19.2025.12.18.00.57.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 00:57:01 -0800 (PST)
Date: Thu, 18 Dec 2025 09:56:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: yuan linyu <yuanlinyu@honor.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Message-ID: <aUPB18Xeh1BhF9GS@elver.google.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-3-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251218063916.1433615-3-yuanlinyu@honor.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fQeabV4u;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Dec 18, 2025 at 02:39PM +0800, yuan linyu wrote:
> when want to change the kfence pool size, currently it is not easy and
> need to compile kernel.
> 
> Add an early boot parameter kfence.num_objects to allow change kfence
> objects number and allow increate total pool to provide high failure
> rate.
> 
> Signed-off-by: yuan linyu <yuanlinyu@honor.com>
> ---
>  include/linux/kfence.h  |   5 +-
>  mm/kfence/core.c        | 122 +++++++++++++++++++++++++++++-----------
>  mm/kfence/kfence.h      |   4 +-
>  mm/kfence/kfence_test.c |   2 +-
>  4 files changed, 96 insertions(+), 37 deletions(-)
> 
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 0ad1ddbb8b99..920bcd5649fa 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -24,7 +24,10 @@ extern unsigned long kfence_sample_interval;
>   * address to metadata indices; effectively, the very first page serves as an
>   * extended guard page, but otherwise has no special purpose.
>   */
> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> +extern unsigned int __kfence_pool_size;
> +#define KFENCE_POOL_SIZE (__kfence_pool_size)
> +extern unsigned int __kfence_num_objects;
> +#define KFENCE_NUM_OBJECTS (__kfence_num_objects)
>  extern char *__kfence_pool;
>  

You have ignored the comment below in this file:

	/**
	 * is_kfence_address() - check if an address belongs to KFENCE pool
	 * @addr: address to check
	 *
	[...]
	 * Note: This function may be used in fast-paths, and is performance critical.
	 * Future changes should take this into account; for instance, we want to avoid
   >>	 * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
   >>	 * constant (until immediate patching support is added to the kernel).
	 */
	static __always_inline bool is_kfence_address(const void *addr)
	{
		/*
		 * The __kfence_pool != NULL check is required to deal with the case
		 * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
		 * the slow-path after the range-check!
		 */
		return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
	}

While I think the change itself would be useful to have eventually, a
better design might be needed. It's unclear to me what the perf impact
is these days (a lot has changed since that comment was written). Could
you run some benchmarks to analyze if the fast path is affected by the
additional load (please do this for whichever arch you care about, but
also arm64 and x86)?

If performance is affected, all this could be guarded behind another
Kconfig option, but it's not great either.

>  DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 577a1699c553..5d5cea59c7b6 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -132,6 +132,31 @@ struct kfence_metadata *kfence_metadata __read_mostly;
>   */
>  static struct kfence_metadata *kfence_metadata_init __read_mostly;
>  
> +/* allow change number of objects from cmdline */
> +#define KFENCE_MIN_NUM_OBJECTS 1
> +#define KFENCE_MAX_NUM_OBJECTS 65535
> +unsigned int __kfence_num_objects __read_mostly = CONFIG_KFENCE_NUM_OBJECTS;
> +EXPORT_SYMBOL(__kfence_num_objects); /* Export for test modules. */
> +static unsigned int __kfence_pool_pages __read_mostly = (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2;
> +unsigned int __kfence_pool_size __read_mostly = (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE;
> +EXPORT_SYMBOL(__kfence_pool_size); /* Export for lkdtm module. */
> +
> +static int __init early_parse_kfence_num_objects(char *buf)
> +{
> +	unsigned int num;
> +	int ret = kstrtouint(buf, 10, &num);
> +
> +	if (ret < 0)
> +		return ret;
> +
> +	__kfence_num_objects = clamp(num, KFENCE_MIN_NUM_OBJECTS, KFENCE_MAX_NUM_OBJECTS);
> +	__kfence_pool_pages = (__kfence_num_objects + 1) * 2;
> +	__kfence_pool_size = __kfence_pool_pages * PAGE_SIZE;
> +
> +	return 0;
> +}
> +early_param("kfence.num_objects", early_parse_kfence_num_objects);
> +
>  /* Freelist with available objects. */
>  static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
>  static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
> @@ -155,12 +180,13 @@ atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
>   *
>   *	P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
>   */
> +static unsigned int kfence_alloc_covered_order __read_mostly;
> +static unsigned int kfence_alloc_covered_mask __read_mostly;
> +static atomic_t *alloc_covered __read_mostly;
>  #define ALLOC_COVERED_HNUM	2
> -#define ALLOC_COVERED_ORDER	(const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2)
> -#define ALLOC_COVERED_SIZE	(1 << ALLOC_COVERED_ORDER)
> -#define ALLOC_COVERED_HNEXT(h)	hash_32(h, ALLOC_COVERED_ORDER)
> -#define ALLOC_COVERED_MASK	(ALLOC_COVERED_SIZE - 1)
> -static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
> +#define ALLOC_COVERED_HNEXT(h)	hash_32(h, kfence_alloc_covered_order)
> +#define ALLOC_COVERED_MASK		(kfence_alloc_covered_mask)
> +#define KFENCE_COVERED_SIZE		(sizeof(atomic_t) * (1 << kfence_alloc_covered_order))
>  
>  /* Stack depth used to determine uniqueness of an allocation. */
>  #define UNIQUE_ALLOC_STACK_DEPTH ((size_t)8)
> @@ -200,7 +226,7 @@ static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
>  
>  static inline bool should_skip_covered(void)
>  {
> -	unsigned long thresh = (CONFIG_KFENCE_NUM_OBJECTS * kfence_skip_covered_thresh) / 100;
> +	unsigned long thresh = (__kfence_num_objects * kfence_skip_covered_thresh) / 100;
>  
>  	return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > thresh;
>  }
> @@ -262,7 +288,7 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
>  
>  	/* Only call with a pointer into kfence_metadata. */
>  	if (KFENCE_WARN_ON(meta < kfence_metadata ||
> -			   meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
> +			   meta >= kfence_metadata + __kfence_num_objects))
>  		return 0;
>  
>  	/*
> @@ -612,7 +638,7 @@ static unsigned long kfence_init_pool(void)
>  	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
>  	 * enters __slab_free() slow-path.
>  	 */
> -	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +	for (i = 0; i < __kfence_pool_pages; i++) {
>  		struct page *page;
>  
>  		if (!i || (i % 2))
> @@ -640,7 +666,7 @@ static unsigned long kfence_init_pool(void)
>  		addr += PAGE_SIZE;
>  	}
>  
> -	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +	for (i = 0; i < __kfence_num_objects; i++) {
>  		struct kfence_metadata *meta = &kfence_metadata_init[i];
>  
>  		/* Initialize metadata. */
> @@ -666,7 +692,7 @@ static unsigned long kfence_init_pool(void)
>  	return 0;
>  
>  reset_slab:
> -	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +	for (i = 0; i < __kfence_pool_pages; i++) {
>  		struct page *page;
>  
>  		if (!i || (i % 2))
> @@ -710,7 +736,7 @@ static bool __init kfence_init_pool_early(void)
>  	 * fails for the first page, and therefore expect addr==__kfence_pool in
>  	 * most failure cases.
>  	 */
> -	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
> +	memblock_free_late(__pa(addr), __kfence_pool_size - (addr - (unsigned long)__kfence_pool));
>  	__kfence_pool = NULL;
>  
>  	memblock_free_late(__pa(kfence_metadata_init), KFENCE_METADATA_SIZE);
> @@ -740,7 +766,7 @@ DEFINE_SHOW_ATTRIBUTE(stats);
>   */
>  static void *start_object(struct seq_file *seq, loff_t *pos)
>  {
> -	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
> +	if (*pos < __kfence_num_objects)
>  		return (void *)((long)*pos + 1);
>  	return NULL;
>  }
> @@ -752,7 +778,7 @@ static void stop_object(struct seq_file *seq, void *v)
>  static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
>  {
>  	++*pos;
> -	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
> +	if (*pos < __kfence_num_objects)
>  		return (void *)((long)*pos + 1);
>  	return NULL;
>  }
> @@ -799,7 +825,7 @@ static void kfence_check_all_canary(void)
>  {
>  	int i;
>  
> -	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +	for (i = 0; i < __kfence_num_objects; i++) {
>  		struct kfence_metadata *meta = &kfence_metadata[i];
>  
>  		if (kfence_obj_allocated(meta))
> @@ -894,7 +920,7 @@ void __init kfence_alloc_pool_and_metadata(void)
>  	 * re-allocate the memory pool.
>  	 */
>  	if (!__kfence_pool)
> -		__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +		__kfence_pool = memblock_alloc(__kfence_pool_size, PAGE_SIZE);
>  
>  	if (!__kfence_pool) {
>  		pr_err("failed to allocate pool\n");
> @@ -903,11 +929,23 @@ void __init kfence_alloc_pool_and_metadata(void)
>  
>  	/* The memory allocated by memblock has been zeroed out. */
>  	kfence_metadata_init = memblock_alloc(KFENCE_METADATA_SIZE, PAGE_SIZE);
> -	if (!kfence_metadata_init) {
> -		pr_err("failed to allocate metadata\n");
> -		memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
> -		__kfence_pool = NULL;
> -	}
> +	if (!kfence_metadata_init)
> +		goto fail_pool;
> +
> +	kfence_alloc_covered_order = ilog2(__kfence_num_objects) + 2;
> +	kfence_alloc_covered_mask = (1 << kfence_alloc_covered_order) - 1;
> +	alloc_covered = memblock_alloc(KFENCE_COVERED_SIZE, PAGE_SIZE);
> +	if (alloc_covered)
> +		return;
> +
> +	pr_err("failed to allocate covered\n");
> +	memblock_free(kfence_metadata_init, KFENCE_METADATA_SIZE);
> +	kfence_metadata_init = NULL;
> +
> +fail_pool:
> +	pr_err("failed to allocate metadata\n");
> +	memblock_free(__kfence_pool, __kfence_pool_size);
> +	__kfence_pool = NULL;
>  }
>  
>  static void kfence_init_enable(void)
> @@ -930,9 +968,9 @@ static void kfence_init_enable(void)
>  	WRITE_ONCE(kfence_enabled, true);
>  	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>  
> -	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
> -		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> -		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
> +	pr_info("initialized - using %u bytes for %d objects at 0x%p-0x%p\n", __kfence_pool_size,
> +		__kfence_num_objects, (void *)__kfence_pool,
> +		(void *)(__kfence_pool + __kfence_pool_size));
>  }
>  
>  void __init kfence_init(void)
> @@ -953,41 +991,53 @@ void __init kfence_init(void)
>  
>  static int kfence_init_late(void)
>  {
> -	const unsigned long nr_pages_pool = KFENCE_POOL_SIZE / PAGE_SIZE;
> -	const unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
> +	unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
>  	unsigned long addr = (unsigned long)__kfence_pool;
> -	unsigned long free_size = KFENCE_POOL_SIZE;
> +	unsigned long free_size = __kfence_pool_size;
> +	unsigned long nr_pages_covered, covered_size;
>  	int err = -ENOMEM;
>  
> +	kfence_alloc_covered_order = ilog2(__kfence_num_objects) + 2;
> +	kfence_alloc_covered_mask = (1 << kfence_alloc_covered_order) - 1;
> +	covered_size =  PAGE_ALIGN(KFENCE_COVERED_SIZE);
> +	nr_pages_covered = (covered_size / PAGE_SIZE);
>  #ifdef CONFIG_CONTIG_ALLOC
>  	struct page *pages;
>  
> -	pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_online_node,
> +	pages = alloc_contig_pages(__kfence_pool_pages, GFP_KERNEL, first_online_node,
>  				   NULL);
>  	if (!pages)
>  		return -ENOMEM;
>  
>  	__kfence_pool = page_to_virt(pages);
> +	pages = alloc_contig_pages(nr_pages_covered, GFP_KERNEL, first_online_node,
> +				   NULL);
> +	if (!pages)
> +		goto free_pool;
> +	alloc_covered = page_to_virt(pages);
>  	pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
>  				   NULL);
>  	if (pages)
>  		kfence_metadata_init = page_to_virt(pages);
>  #else
> -	if (nr_pages_pool > MAX_ORDER_NR_PAGES ||
> +	if (__kfence_pool_pages > MAX_ORDER_NR_PAGES ||
>  	    nr_pages_meta > MAX_ORDER_NR_PAGES) {
>  		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
>  		return -EINVAL;
>  	}
>  
> -	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
> +	__kfence_pool = alloc_pages_exact(__kfence_pool_size, GFP_KERNEL);
>  	if (!__kfence_pool)
>  		return -ENOMEM;
>  
> +	alloc_covered = alloc_pages_exact(covered_size, GFP_KERNEL);
> +	if (!alloc_covered)
> +		goto free_pool;
>  	kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
>  #endif
>  
>  	if (!kfence_metadata_init)
> -		goto free_pool;
> +		goto free_cover;
>  
>  	memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
>  	addr = kfence_init_pool();
> @@ -998,22 +1048,28 @@ static int kfence_init_late(void)
>  	}
>  
>  	pr_err("%s failed\n", __func__);
> -	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> +	free_size = __kfence_pool_size - (addr - (unsigned long)__kfence_pool);
>  	err = -EBUSY;
>  
>  #ifdef CONFIG_CONTIG_ALLOC
>  	free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata_init)),
>  			  nr_pages_meta);
> +free_cover:
> +	free_contig_range(page_to_pfn(virt_to_page((void *)alloc_covered)),
> +			  nr_pages_covered);
>  free_pool:
>  	free_contig_range(page_to_pfn(virt_to_page((void *)addr)),
>  			  free_size / PAGE_SIZE);
>  #else
>  	free_pages_exact((void *)kfence_metadata_init, KFENCE_METADATA_SIZE);
> +free_cover:
> +	free_pages_exact((void *)alloc_covered, covered_size);
>  free_pool:
>  	free_pages_exact((void *)addr, free_size);
>  #endif
>  
>  	kfence_metadata_init = NULL;
> +	alloc_covered = NULL;
>  	__kfence_pool = NULL;
>  	return err;
>  }
> @@ -1039,7 +1095,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>  	if (!smp_load_acquire(&kfence_metadata))
>  		return;
>  
> -	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +	for (i = 0; i < __kfence_num_objects; i++) {
>  		bool in_use;
>  
>  		meta = &kfence_metadata[i];
> @@ -1077,7 +1133,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>  		}
>  	}
>  
> -	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +	for (i = 0; i < __kfence_num_objects; i++) {
>  		meta = &kfence_metadata[i];
>  
>  		/* See above. */
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index dfba5ea06b01..dc3abb27c632 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -104,7 +104,7 @@ struct kfence_metadata {
>  };
>  
>  #define KFENCE_METADATA_SIZE PAGE_ALIGN(sizeof(struct kfence_metadata) * \
> -					CONFIG_KFENCE_NUM_OBJECTS)
> +					__kfence_num_objects)
>  
>  extern struct kfence_metadata *kfence_metadata;
>  
> @@ -123,7 +123,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
>  	 * error.
>  	 */
>  	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> -	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
> +	if (index < 0 || index >= __kfence_num_objects)
>  		return NULL;
>  
>  	return &kfence_metadata[index];
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00034e37bc9f..00a51aa4bad9 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -641,7 +641,7 @@ static void test_gfpzero(struct kunit *test)
>  			break;
>  		test_free(buf2);
>  
> -		if (kthread_should_stop() || (i == CONFIG_KFENCE_NUM_OBJECTS)) {
> +		if (kthread_should_stop() || (i == __kfence_num_objects)) {
>  			kunit_warn(test, "giving up ... cannot get same object back\n");
>  			return;
>  		}
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUPB18Xeh1BhF9GS%40elver.google.com.
