Return-Path: <kasan-dev+bncBCT4XGV33UIBBWXMUXZQKGQEQZQSBAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 232891825EF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 00:38:04 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id s13sf2194975plr.21
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 16:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583969882; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWepdI2vnfrXULUBLb65mBt3Xv+FnwUbe7vNsnXC56f3gN2koEOkY0g6BUVdcrrVEM
         HRR6dWsDvDHoqmEVWizmB3brv2WimMi8kN+2iPjKT8o5YfUxnsTgBKEuJ04XR5C1SdEA
         XN26KKUb6QHHotdMaSaKuLClKieezDQcLRMHc7cSo5sihWaNd+n1KukCHCjVVl83LqNf
         3wPoVuiU2gjz/fXb6OYmud+aeavbGR6FHP1FrxDJ+KDNdxWAdmJVPyYZbY8mjwLzFEjv
         n2oXt+qur5P/d0g72Cgwu1i2dKiwbGWxTHNBDz3+yzqgp1H0nzr4DRPhHcIYtf7oaZat
         efFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xoaGUrE6dwtVXGWqSu9Z9+c/DXJsL+W+ifyfqnVZWyw=;
        b=PVSEfpP8sTTwf6XCCtOXqxdYUP0qyh5EeCy/Wzz1OhwJUmdV9WL3ZK7WKYr2OwrE4i
         tHNWDFP382wWGnCPduPGGw8w2g7RAdN9jyOwVUC7EgHL4sOgfJlRn9/W8OR3We8I0xJy
         QxCcgNO5gszYn06WFZnKAhPwUrntGleDAO2xh+QLruA0Z28HOSa+mvSOG5AF5O7sV+KC
         tPtpHdSdzxe4LoTBM4BWHTUNIJaYVEpT3mnotOd+CAmjEBOsb6U0Gvoe+HJKs5FVaLKG
         hXK/eCTPs7WFmgi1Zho/rALthw4t7FL8puMX+IVfs4THzvHDLq6bHIpa12s4fD7n8kWf
         6F4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fRsZjvD6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoaGUrE6dwtVXGWqSu9Z9+c/DXJsL+W+ifyfqnVZWyw=;
        b=dcOv7N9VIe0s3Pj4rZXWES4xtjZV2QCUO9mQL22+VSoNDH08bLdLeunuvRm/BXsFAr
         u9vyXZ0IRVK1Ofthfi05CKlrYYlKaBlwZuA4TDb/8reelt1v48vuoW+uim7Uz4GTCKm7
         koNjPHQgj4RJrdLK7lKUKqB059MGQKm1u2EtfezDMApNgVg31s+L6GxkFreW+NNP7+3L
         C3tzp4A+LH7DoyspuV4whRpe92KmcmKvshzbLkiB5h7FYEi6+YpTzlcSSYUnrMzFVn58
         OFQZLcSkpINiTgZvVHad9Kqd0lc32SJSNNeiZ+weRh6rcSdi31upQHNdQaM1gluMAyd1
         xCng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoaGUrE6dwtVXGWqSu9Z9+c/DXJsL+W+ifyfqnVZWyw=;
        b=GXXDkIkZ0beU/I9frUMMaajhpoqB24RRW2HH8+OU1EzqiB+Qv1NhenPjPQvvkDZnfy
         XjSJFp9hnRWd5/kCt+ZYSCT6xIZ8zjYyD0sWiSRIY4NEMfWM+l6uzBAGpk5U7rmJWAtC
         vikpJ9tT0y8asmxdbmnH8h+A4iTYaO/KG+YRgMna1Uvsm9m6q+7k9wE5Yx3Cf2Kt09Ij
         c7BsM93TeQyvK2bIP58vd848s0sk5DeubvoliWzA1CecDJcr9AwHHdJFdJWU+gxSlKfg
         /aHzsLYC3PIM+Ak2aCIQF6G4c+4B8HnDAbf8MPUmPRkdsVho8/3eUJ9RWXuM4uUXA1ko
         rsIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ108jOmK/BqfYCF9kw4A8KhNlF1Gad0C8WLLhzAxIrhcgDjesGK
	JtCxcZE2+mc8FvsAndlCQ3c=
X-Google-Smtp-Source: ADFU+vvQ/p708vgKTc5XdctmdCgeZ8cLdxuAT8VFOD9nHGpD5820w6rhV0vTQtU48vhVb1351uD7XQ==
X-Received: by 2002:a63:7f1d:: with SMTP id a29mr5110683pgd.123.1583969882457;
        Wed, 11 Mar 2020 16:38:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:868f:: with SMTP id d15ls1619438pfo.5.gmail; Wed, 11 Mar
 2020 16:38:02 -0700 (PDT)
X-Received: by 2002:a65:6843:: with SMTP id q3mr5055748pgt.269.1583969881952;
        Wed, 11 Mar 2020 16:38:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583969881; cv=none;
        d=google.com; s=arc-20160816;
        b=GkKll4bQLbcdNPlVeB6fWOpZsKrU3zB3mCdotpfOIuTNHFS0zxI6VjYqmWXeJMdUsM
         vB9mOoKC4w+THILh7iR1liNde9/HnsfRwLnyjGsA02/VQj9dSBudRvM/jMeB8Na3GCo1
         DMsMitY+p1ZYmPwWZUobfU0iBSarcjTLDHD7qMZBQaXyYMsjpVDzbFZ8Ni1b8+OJZLCv
         u2GYTD+Gf46mAeJcYaMPCye3jL3AclycI2SDJac+NIp0HMWgF1A5dSwTwWg8R2uNT+62
         YPZpNkT+Bv+a35Iiuda/S1Uva7/nGlzEZhViqoEZ0HPdC/Nldkex/f8nP0lnAgluINgB
         YR7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9CBLe6sHcUgeeYntR7oN91GJg4OzoiFrSoZ5delPU9o=;
        b=Hw4JNWDGK7g3tCDd0Fo1qd6I1Ya3gd/N7hloqM+fT7qk2F8AhtTfEmIJTfGVEbGy1R
         u2Gv/ualtY63StzlAAMMBpwbvMtnTM2nHcRdf1gTGOBdR/bHPPDuP6/1LK0b1E+6czPA
         FAAMBZTLd/B6Xg/Fq1LG2N/Asf9vD4yIYzm9ZGCFZ9fRziijtulACHOUP6zZOKkE9wRn
         8NZaHaqVA/fe4VOR79JH/kwaoooHzCIEPF9k3viESnEnEa1l2BlSOkEruCt2bltPDvwA
         /3N9xGPfHqCHFHGh3KZ2s4CNTa4hRPW0C+8CmlpkSZzPBqLB/pHz0cA25aS/Zezl6hvE
         rSGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fRsZjvD6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l6si125326pgb.3.2020.03.11.16.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Mar 2020 16:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 61D4A20754;
	Wed, 11 Mar 2020 23:38:01 +0000 (UTC)
Date: Wed, 11 Mar 2020 16:38:00 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai
 <cai@lca.pw>, Stephen Rothwell <sfr@canb.auug.org.au>,
 <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
 <linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
 wsd_upstream <wsd_upstream@mediatek.com>
Subject: Re: [PATCH -next] kasan: fix -Wstringop-overflow warning
Message-Id: <20200311163800.a264d4ec8f26cca7bb5046fb@linux-foundation.org>
In-Reply-To: <20200311134244.13016-1-walter-zh.wu@mediatek.com>
References: <20200311134244.13016-1-walter-zh.wu@mediatek.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fRsZjvD6;       spf=pass
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

On Wed, 11 Mar 2020 21:42:44 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:

> Compiling with gcc-9.2.1 points out below warnings.
> 
> In function 'memmove',
>     inlined from 'kmalloc_memmove_invalid_size' at lib/test_kasan.c:301:2:
> include/linux/string.h:441:9: warning: '__builtin_memmove' specified
> bound 18446744073709551614 exceeds maximum object size
> 9223372036854775807 [-Wstringop-overflow=]
> 
> Why generate this warnings?
> Because our test function deliberately pass a negative number in memmove(),
> so we need to make it "volatile" so that compiler doesn't see it.
> 
> ...
>
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -289,6 +289,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
>  {
>  	char *ptr;
>  	size_t size = 64;
> +	volatile size_t invalid_size = -2;
>  
>  	pr_info("invalid size in memmove\n");
>  	ptr = kmalloc(size, GFP_KERNEL);
> @@ -298,7 +299,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
>  	}
>  
>  	memset((char *)ptr, 0, 64);
> -	memmove((char *)ptr, (char *)ptr + 4, -2);
> +	memmove((char *)ptr, (char *)ptr + 4, invalid_size);
>  	kfree(ptr);
>  }

Huh.  Why does this trick suppress the warning?

Do we have any guarantee that this it will contiue to work in future
gcc's?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200311163800.a264d4ec8f26cca7bb5046fb%40linux-foundation.org.
