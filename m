Return-Path: <kasan-dev+bncBCT4XGV33UIBB2UVUT3QKGQEZIWSWBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA8EE1FBD94
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 20:09:47 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id m11sf16368686pfh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 11:09:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592330986; cv=pass;
        d=google.com; s=arc-20160816;
        b=jyKC3Hk0pwigtKzKuYe7wBLEHeIDyYa6/QxtOQyR8TNLsFhRAltJH5pz8Byn3+REA3
         XEk/8drgdI0Dh4aSiRJMjD76zyLfnJeJgkRNQW3py26mDQxvc/9/maTmYc9xSCMMqAry
         GWl4ezgQtJ/I5szevtZXSt437rmmrjFWiWsYVdsukmCVKV3Jd89AmKVQlqgtkizxL9nj
         k1sgfsXtIr7ZODvdFnKQj79zE4HkFHG/ObIM6xYk4juQhXI7yRyi+EPa2TVQyoaiS7G7
         pxLUuKJDuwKSktD0w/Ky9ewHwXJlN3Teq+h9FLUvbr3+WWrtblBv3wsghU3k4wS8bEor
         7k5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=U7x/RKi4AaXnX+ZNnzWy+EFneXe85ZaTtApSqqL+dyM=;
        b=UBnTPY2B3O4jZFz9QGHV/Xo6nY+FdC1aBA2srXgXfjTct5f5K9FOigEf/lF/6l6kjA
         hW/SGLnLkH7t+xgZMIG6s/A6pFPJgU4qvPBSO5uNRfsCZvonWnd0QUiHyajGjJlk+Q8Z
         Wxmd8jQByhMZo9cHv7kQB1If33ZxBNAt8Bu/J3eAzKexyv/pQutYWr8jAcpr4u+Kg49P
         eOT8Vv1jH45kZKuMU7nRF1xe7lZmPrXodDGFmvzWsDLpgz+0KEYivNoAmpb3zYVdFfe+
         fyjUrnuEcZo37xUhLLQUcBsvaprGUsax3q/W8yBRxcdYHnS9KkTGoDxiFCm/VkxM+oMP
         mswg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=IhpS1taE;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7x/RKi4AaXnX+ZNnzWy+EFneXe85ZaTtApSqqL+dyM=;
        b=H9UAIZQtn+0J+LcdsSnxWGHtWkAKuZXollKwMmQOecIXv8qgaeOQFAMlg/BvczVx9t
         6msOCCBsSjBt1mp59KQodkchX0rB68xiOS5fOUR7OihosdfWXuCvQHHQub02NZi7+uAk
         nr9eL4+9vBZh4zOD47mO66YgfGFpfSx0oZUrMfbrbiVMzEfX5OSgQK6Vb9d9wmhQyHKH
         1eKzMlR/K17duozXZFHjzQ0DjZBkfeykfiUcjOZ/YlMzy3EmpCC2OEI3APWiiN0tCy50
         QKP46fGzOuVrZ7fm0wSMz4J6UIPHyxDNmlcU4sRtsCpielrS/hxbI6AgX0XQ9qRlO38e
         pu/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7x/RKi4AaXnX+ZNnzWy+EFneXe85ZaTtApSqqL+dyM=;
        b=JptQiic4RAbEDELIbbfHZGF+kkb7+SVjlxNedRDPOUB6/dlw39jMk6pKlNUX68bhEm
         9cdnYMcfqOBDVFNjOPZxx+JQgPkeWX+ggXb6UjcxxmAr1iVVLty0S+oEzLRIvVegD+pI
         5u8or84c/ZUFZ7X7ffdB1ehWxRJbnM8RkiqhG5fqtVO1KBAElO9F6AGJaU/RoVwXk/Ya
         EtoVq57cW1MGyapD7LsRfs2myI8RAR42MjJpk280Nhu4sqbs8WYxFnokPoOvSR0n+rDy
         p6GgPisGXNkJwPOi7jcp48ntwaqQOH3Hh+EHTyxdNzkgH/oQyx8G3fl9rd+QGHKUbeBK
         8QYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530snEkFV/8EvGnFlaXWfftQuGJ0fRDAPEso1mJ2qNfHPjT/1eco
	sh1M93YIHs7lVsONVV2ymT0=
X-Google-Smtp-Source: ABdhPJxnjGRLR5XtOv8Wj4qkio6dd3CgCIKJ6+WEmq7YZ7AkRgedIxlWj9ziOcgm9WtLU5Hlt7NKmg==
X-Received: by 2002:a63:3c16:: with SMTP id j22mr3087544pga.335.1592330986538;
        Tue, 16 Jun 2020 11:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c910:: with SMTP id o16ls4500240pgg.4.gmail; Tue, 16 Jun
 2020 11:09:46 -0700 (PDT)
X-Received: by 2002:a63:be02:: with SMTP id l2mr3016969pgf.347.1592330986029;
        Tue, 16 Jun 2020 11:09:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592330986; cv=none;
        d=google.com; s=arc-20160816;
        b=kK4aSO9TIpct8ScYKf6QX8B3au670Ce5rdU6mmAj0Q36JZ9W3MkkHEoFDX1XTwTGTp
         +A1TpQUqlrf6IB/9+k6/5NGPSm5GwGURlcYKP3BNvv1+Y0tpRnYYcMBgh4qgEbaqedi4
         ZdPJxJqxlvHW81LGbJ6c6mPKzng8QblmYqHmmhH0PfzzNpzSmWwJTxXpx1J3slK5OwJv
         blpsyjq95tUYkGgBYXq3E/WRe9nDjxlKMdXT61bt0nd56QImfBQQU7DLVkHvA6keGGyO
         8PHddiukzn97fk8oYZIauwptPOOW8FlsgE6ha5HzbIKFNOLr3qColeOPGL9S7rK6u1oB
         CtkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=s75njGX2YaiOsTlxOv0IfOYWxujKyfcAfEYj5ymw8gQ=;
        b=GgL1nmykl0MfqUTFSD1Ir043E7zFs9gB7D5N+U4bmNDl+9H83RHavEjmr+Ky14C15A
         VKeXIPKjSCNeV2sr7/wa60s5b3hnKHZzLS9CkA8V60H9QoIH0s7YSR34tp27jRKS1kjF
         eI5ky08LdLhusY9wFUKft2RD+OLTf9PCfzQX7qG4DF1xGXgivC/BCwc3FY5O3dYVoWGF
         6QWewbYhZnP9SWmiqfM5K5GuwQEWpm9suRM540d4Dt6coiLUyg6puFVcjAyBrmnBqPek
         eFAqLRscLUNYyOUhGlXmsscORKyMAEGC7lsxoOokQCaZlVTLA4Cno2NCK9bjq6S4yqL6
         /mcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=IhpS1taE;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l9si105958pjw.2.2020.06.16.11.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 11:09:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from X1 (nat-ab2241.sltdut.senawave.net [162.218.216.4])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B1C752082F;
	Tue, 16 Jun 2020 18:09:44 +0000 (UTC)
Date: Tue, 16 Jun 2020 11:09:44 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Waiman Long <longman@redhat.com>
Cc: David Howells <dhowells@redhat.com>, Jarkko Sakkinen
 <jarkko.sakkinen@linux.intel.com>, James Morris <jmorris@namei.org>,
 "Serge E. Hallyn" <serge@hallyn.com>, Linus Torvalds
 <torvalds@linux-foundation.org>, Joe Perches <joe@perches.com>, Matthew
 Wilcox <willy@infradead.org>, David Rientjes <rientjes@google.com>, Michal
 Hocko <mhocko@suse.com>, Johannes Weiner <hannes@cmpxchg.org>, Dan
 Carpenter <dan.carpenter@oracle.com>, "Jason A . Donenfeld"
 <Jason@zx2c4.com>, linux-mm@kvack.org, keyrings@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-crypto@vger.kernel.org,
 linux-pm@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com,
 linux-amlogic@lists.infradead.org, linux-mediatek@lists.infradead.org,
 linuxppc-dev@lists.ozlabs.org, virtualization@lists.linux-foundation.org,
 netdev@vger.kernel.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org, linux-cifs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
Subject: Re: [PATCH v5 2/2] mm, treewide: Rename kzfree() to
 kfree_sensitive()
Message-Id: <20200616110944.c13f221e5c3f54e775190afe@linux-foundation.org>
In-Reply-To: <20200616154311.12314-3-longman@redhat.com>
References: <20200616154311.12314-1-longman@redhat.com>
	<20200616154311.12314-3-longman@redhat.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=IhpS1taE;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 16 Jun 2020 11:43:11 -0400 Waiman Long <longman@redhat.com> wrote:

> As said by Linus:
> 
>   A symmetric naming is only helpful if it implies symmetries in use.
>   Otherwise it's actively misleading.
> 
>   In "kzalloc()", the z is meaningful and an important part of what the
>   caller wants.
> 
>   In "kzfree()", the z is actively detrimental, because maybe in the
>   future we really _might_ want to use that "memfill(0xdeadbeef)" or
>   something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. In addition, memzero_explicit() is used to clear the
> memory to make sure that it won't get optimized away by the compiler.
> 
> The renaming is done by using the command sequence:
> 
>   git grep -w --name-only kzfree |\
>   xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
> 
> followed by some editing of the kfree_sensitive() kerneldoc and adding
> a kzfree backward compatibility macro in slab.h.
> 
> ...
>
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -186,10 +186,12 @@ void memcg_deactivate_kmem_caches(struct mem_cgroup *, struct mem_cgroup *);
>   */
>  void * __must_check krealloc(const void *, size_t, gfp_t);
>  void kfree(const void *);
> -void kzfree(const void *);
> +void kfree_sensitive(const void *);
>  size_t __ksize(const void *);
>  size_t ksize(const void *);
>  
> +#define kzfree(x)	kfree_sensitive(x)	/* For backward compatibility */
> +

What was the thinking here?  Is this really necessary?

I suppose we could keep this around for a while to ease migration.  But
not for too long, please.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616110944.c13f221e5c3f54e775190afe%40linux-foundation.org.
