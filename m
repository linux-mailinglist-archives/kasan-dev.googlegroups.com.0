Return-Path: <kasan-dev+bncBCM2HQW3QYHRBFEZRTVAKGQETW3NEEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4C4E7DF99
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2019 18:00:21 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id v1sf11720360qkf.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2019 09:00:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564675220; cv=pass;
        d=google.com; s=arc-20160816;
        b=eV4xzqBvLSMNVLHjsLVY9OCixDFskhuQlSlb1R3NKbXzCohgdWRJ35L2lKqVfkmcKb
         CroIc0Yp4dOlZwoMzduaY/rUjmj3WHe4lkdzcx3S97chgZ02YLkU5OUUJ+W+5p9yfjvO
         xsWTgVzyBWRBFqMo77tuqv15O4XJqXzx9BYdhcQjWdmOcx77eGbwY4XN5nnz2q+VAGMF
         /NoayNQyjEnBrX0rTgvhXa1ySYnpRajY4YMR+sO/zPfRUF6x7PQe2+0IyU5J0p4rHAfN
         zj/gfFEzdCyKfJ6PGG9KDzOE5r5hm8QkhN7G/tNRyr5Cv81odjSTM7oyO3GX4aDekepk
         ytZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=omVsmNUyDPNEObnQthtsXANk9oev2a8cu3viqGXpbQY=;
        b=I7mcTThqt7fjSGzM8JJbwQ698NtzaRNLkCToU02ZE2cMN3clzn6vnGFJ+7bSgFfAfe
         EBbhevb3wl6O6XZh/3unT7FQWHyjen8rjo5onJh54cmHg6jcuvhEtUkDMe7/grIuHxkN
         VeV/gRcj2S3VZmUSeh6WghT6TeyLg1P48xwIRG+28YBMnkRWt+vvvUl3zqT68wWGED/3
         vW9htM2131glcQOjENfmjwzayuwPj+tv3Q44cGTgv0T1Qa71YR9PZTGiDgkgH15RnJL9
         7vmP6ky7f+QFm1P8pLP8i4odiwwF0V4F8/d97LH6bNMfB1toOmhQRPNPB7XrjbW5TkFN
         mkIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=bt6gngaa;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=omVsmNUyDPNEObnQthtsXANk9oev2a8cu3viqGXpbQY=;
        b=N9jUwWNw+nFkocjdPyVakIaQPsMLT4+V3evcN15KBHVgaRvms/2am2ac9kT8tDpXwh
         8FxtxgOyVbDWOr+KW29y/I/hdjYSc761afTmvLM+HxZmnCewxYnH0g/IUgafH7SAvL1D
         EbQOhlnw0FyfyaSBIO1p2c/gas64wtGApFTNJztfh3e5YacCr74VwPEHWBmsBT5OuTgv
         CCjjzeJHZRMakv8SOf7uisihde8hRIjK88zFfzYktUaPRZnmr/kDzM1PFhsp1yZRMXXb
         R8VTi7IEc9PSyJrE+cZVUbyGO1vVNh+w+4lxeDH6FB4/k88c1vduXtULd5paUQBPN742
         IhpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=omVsmNUyDPNEObnQthtsXANk9oev2a8cu3viqGXpbQY=;
        b=g3g+RyfVBXm3olBK65WfrHSGKPnhWWvClq7iWURViIrwRX+9/su2cijNwjUVVhgAQ5
         gUf/QHm+TmDy+FfGKd3dbHJDGc/NDVhWg99ff6hxwlmX5ntoUCk03Tm+ucZ4Z3dUSRT3
         Epp+8Z5Gc7ikayBdg8UYK/KkBNN3PQBbBmW9RZbXmP/H3EjdndDRRsn8bmn12UL/gOp7
         QwcHhYa/xLV8TepT7izqc9CQOrxafO+W81AR38T+TYpgvxKNzBf0kbdMOCg8B1xFjqL6
         8Ej/XurAXGUrcetVw1AywIve6gOaWRFGT1zeukv+QNXbUihPwQWRFVodcmuJgzq01SUv
         +bDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGmvdIx8e47O7h2URiD/XLoScn4Azg09NxCjlSA2QfmZoJxCC2
	nF0rGQpBGbayzfbvc1iB9tk=
X-Google-Smtp-Source: APXvYqz0rB5YE9r6kxiLNO7DZsvRzcYuACtzzDqy2fTitWZ8W3q96dso6w3dY6C24LnJmiecduBKiw==
X-Received: by 2002:ac8:140a:: with SMTP id k10mr71769431qtj.175.1564675220377;
        Thu, 01 Aug 2019 09:00:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7804:: with SMTP id t4ls565926qkc.16.gmail; Thu, 01 Aug
 2019 09:00:20 -0700 (PDT)
X-Received: by 2002:a05:620a:16a6:: with SMTP id s6mr2223189qkj.39.1564675220086;
        Thu, 01 Aug 2019 09:00:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564675220; cv=none;
        d=google.com; s=arc-20160816;
        b=gFrYItX/KuE10FdLxzfwYRJErFFOgnvV6shGNIpRj819v3U+awFSoVXYZpLSbAG/5g
         OzVISfU+zVWilfTLlwTIFUrxRRiJmsa4Nl3IqQRm8mTkmkuplpXiIanocJJHHXhGZxJZ
         op7fPawG+QtUymQ3rGIM+zMURqVj36JCZ1bKkzJy+sMEbHNSU+3SsaOhLutbyAlV/CNc
         jqsPWUxaWJio6+iTVhsCugHXf8beOYfau3+qh0fLmvxmBlGPKVdY44Fzz44n4JXX5Hqw
         +F7D9bclylTqgestUZOtMdclwKs4Qu4BJJyASM0UVfw9YjJisQD/3pdFu4dYCQBAocKz
         XPhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=V+mqoypCyVp89zi7d87lU2RRcj8SerxFad94nqYfDDE=;
        b=irgiPoq1dhGWjU6zLZ8/W4oeRBoEotCdxIMLPy6Pb+A5gXnP07cs6tuV6MIVoU6ckL
         Gpd/aiZk3LOdzt77K9xBkwu72elV5o2pCQeMSGTvDE4RJtP1FYl/izc/wxllXbaM8cNs
         1alrFpQFivmsLAigk3Z28bPHTMkI73IqUKHBKjJNDIhhJwcfxTFv0ycHGgSo3Y4LIryK
         ZTVwe7rbvwGJUTjtw+INajTDhYWWnNnEE9EgrTXwwr6Wkqm7KyleyVNgiDHdwC02mfqC
         d52GZNq1TgUHFEpvY0RAzs2TOlmavy0O1qYj5C6CzJsS3eYGtl7BGeixJFYkyChqBT28
         SFCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=bt6gngaa;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id o56si363195qtf.0.2019.08.01.09.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Thu, 01 Aug 2019 09:00:19 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92 #3 (Red Hat Linux))
	id 1htDUz-00024S-4b; Thu, 01 Aug 2019 16:00:13 +0000
Date: Thu, 1 Aug 2019 09:00:13 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Qian Cai <cai@lca.pw>
Cc: catalin.marinas@arm.com, will@kernel.org, andreyknvl@google.com,
	aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] arm64/mm: fix variable 'tag' set but not used
Message-ID: <20190801160013.GK4700@bombadil.infradead.org>
References: <1564670825-4050-1-git-send-email-cai@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1564670825-4050-1-git-send-email-cai@lca.pw>
User-Agent: Mutt/1.11.4 (2019-03-13)
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=bt6gngaa;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Thu, Aug 01, 2019 at 10:47:05AM -0400, Qian Cai wrote:

Given this:

> -#define __tag_set(addr, tag)	(addr)
> +static inline const void *__tag_set(const void *addr, u8 tag)
> +{
> +	return addr;
> +}
> +
>  #define __tag_reset(addr)	(addr)
>  #define __tag_get(addr)		0
>  #endif
> @@ -301,8 +305,8 @@ static inline void *phys_to_virt(phys_addr_t x)
>  #define page_to_virt(page)	({					\
>  	unsigned long __addr =						\
>  		((__page_to_voff(page)) | PAGE_OFFSET);			\
> -	unsigned long __addr_tag =					\
> -		 __tag_set(__addr, page_kasan_tag(page));		\
> +	const void *__addr_tag =					\
> +		__tag_set((void *)__addr, page_kasan_tag(page));	\
>  	((void *)__addr_tag);						\
>  })

Can't you simplify that macro to:

 #define page_to_virt(page)	({					\
 	unsigned long __addr =						\
 		((__page_to_voff(page)) | PAGE_OFFSET);			\
-	unsigned long __addr_tag =					\
-		 __tag_set(__addr, page_kasan_tag(page));		\
-	((void *)__addr_tag);						\
+	__tag_set((void *)__addr, page_kasan_tag(page));		\
 })

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190801160013.GK4700%40bombadil.infradead.org.
