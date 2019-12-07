Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2EWVTXQKGQEY5VOXMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F167115AB5
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Dec 2019 03:16:10 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id l4sf6403094qte.18
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 18:16:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575684969; cv=pass;
        d=google.com; s=arc-20160816;
        b=b2Ex8+w0MfvpV11V0c/LPrUPLIrjrGtVZ97XrZOFysJLKeN2vhEd+6D1LL6ECnPFNF
         lRdOkSiS9Nt+gSa3oWA/IHj4NNpZi5eCk5yU7kV2XExtxAX9hLzd1IzPiRks3v116uj0
         ElcNxbRca0MtTUX5RkO3wyypOTDYvicp0dTwvzOW5JO1PP6e4mS/6uuCjmHno5b0ubYG
         Yi4z5Kt+C9rmq6YpxFVXiMd3763byctJjtf9UILYeErSqN/ADIFPP2IRDbSeRelTInLQ
         ZB6OadKfQRHdkYkOqfGAJz5bCQE0611U6o5ce4j8/QD4CgiODj6Iis0xRCJFKXwVgZSx
         9TQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=udZ6UIMsUMfIS8r2fmse3la3P7fXIlqZu2heDwyDoVY=;
        b=tcsQ3KNFx7DhcS6z69AvUKVBjRykR7ZbPwydJ4Q1wBWd0rDSRKA5681HCqNSUnVgdo
         RMXXKKZ3SEgWivXJxuOEAJOEO222gX+u4dIFoXW65vOvvd7gJjiNSZDyBPSwd/68/cB4
         D6Rb1+nHEKmGYtAcoqqljGUc3eEOIptYWSrB4IPJhY8I4ew0BS7l/vhheq9vYol9YPwi
         /xQVijZGwnTdkP16QtkI95NHvbdYB+fncctH/LZNJF+rMZ5tzSDYhGEWox1dqM/8QRyW
         znXaPdOFEVJQgSBQ/XztrxezV7wioz6R09Qujg5DP2tJDE/+c/leotQG9Av9+uGRdCoZ
         vQrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="L4n3r/SK";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=udZ6UIMsUMfIS8r2fmse3la3P7fXIlqZu2heDwyDoVY=;
        b=MYK1qwFwAViMx6s84qS+5jVBJwIKhSTbFrAZ084rrrFY3ABrYDUqHo/yGaB1faccD/
         7v098faZA1AkR+K5CTV56IZIM70Dj0usRXcQo1/BqqKTHy+l57ae2V3R4tkICWFXenZb
         ckf1R7dOgqrqSv6BvcJOYVFpNEYMuhQozxpvDAMwSSUq/tPmHHOGyR5HNogayv2BacFe
         n7zLtMIMmB+9EmjxKE0TGPObWcdyX7dlwLRstoq00rAKUuJZu4KCN3TFfNdkv5es3aRa
         i9jcKTRC/4amqc0Bjrr8PVL7/SddthvvyCMKyUc1K0ZUU0xNBlbxHFph2GcHHek58Jqq
         ekTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=udZ6UIMsUMfIS8r2fmse3la3P7fXIlqZu2heDwyDoVY=;
        b=Yjxf0gbOCCf4PTxXlCVBEIdkd7lRBSV9sB8E03eRBdoGbpFGxQQJ65U5xD3szyxffr
         2aGLH+WJF+XSqmYDAAvdWiIZsh0zKG/h/FsrrsCo1PjtNZ0Ndm3LDUGFwpr6OqTlpE7y
         2wbh//GqrQeTmD2AymeE6PT5pc03UW0pSK27GTONfZpzG4VzeXqlxBsDPD/VCH5jMrvZ
         x2vTLvl9479rhST9yrOVygQsA/4PUknhge5ShpbscJ6PMohXUhAk3myV1peAAbA15an7
         h1f/nYcPZpJy95UrdrNIgioNo5Pq/d7nn9LQ6Bo1+rZwAOFqyl+38Mz7SB3gL/KTyV3W
         iGFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVXVATgYLVHOGHHigL82yYy7oOpw/yloZxHrDgzLhqriJkd+31
	wdik56+vjpjJJQvV23CIhII=
X-Google-Smtp-Source: APXvYqzo8sncol7/GpyHaLVNz5na8lj0oxChArQqpAU8YMGUgylzciYXyO88c0gF+Ce00VEzrCesTw==
X-Received: by 2002:a0c:9476:: with SMTP id i51mr15439552qvi.75.1575684968814;
        Fri, 06 Dec 2019 18:16:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3443:: with SMTP id w61ls2428536qtd.11.gmail; Fri, 06
 Dec 2019 18:16:08 -0800 (PST)
X-Received: by 2002:ac8:2391:: with SMTP id q17mr15860010qtq.122.1575684968496;
        Fri, 06 Dec 2019 18:16:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575684968; cv=none;
        d=google.com; s=arc-20160816;
        b=v4vdtvdLUaAVMYt3NYuaMpRZ6D6gW7dE3EAFwANvw7/+Ewo2+Y1JvB5uL3bJFgXna8
         g22vo0uLJAyAFKN89OajfkqWUWCIsbgvV+jd+13elxNWVAPOLkvjrj2BzFzzh/g+bTt4
         bMjjY13xfcvGCSlekAdaKSALVVshRQZZLhCx3dsOfk9ELG4+ohvwwd7P2yCxGB0aY9QV
         JFnD2VqCjojYNxBHIlwawRLWHkP/6ngWjSty7WOzrUr/hzCLXBo57gxNoIyysSs2U9m9
         ZBVYs8lYeqE7UuWnR4FGA+Ujw6DRN6gI+aSNTieDwpwlyegxDxDT6gmJ2O+KrqxyWMwS
         4+FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=RvSWSXXOJHTsbagyrlqXQzUh6ihQzraXoeMeWUbMh9I=;
        b=eXLc5/pYaCFC16JWgNYVpMZh7k2JTzK6R1SgyDY5d8MRXLemNViC97sgPM/DsG3J4G
         YVgB1KcxkOZpfoLwLUTOOHK9prws/g1QjoTscfgnj1iBD/etL3jQyzOotMt/RJ4cK+yD
         Bw+lJqfVuWknWKRggcHkMoInDM+l09fW0pe1NhLCdYBpHDPCw8lWv8XcahN81oL05khg
         bOwDJrWEuDtIUC+EJlH959x1HyXwdj5fwQVX9IeVT052XGASxS1rAyu0cLQRANWr0sNx
         uKv4kHnXoNK6L/xQ1SCRdn0N4H0oYikHXwu0GF1tVXBE4LQy4jUuKkRDe5R3bzvGsFx1
         /Seg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="L4n3r/SK";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id b11si867225qtq.4.2019.12.06.18.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Dec 2019 18:16:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id g4so3496452pjs.10
        for <kasan-dev@googlegroups.com>; Fri, 06 Dec 2019 18:16:08 -0800 (PST)
X-Received: by 2002:a17:902:d915:: with SMTP id c21mr4588859plz.295.1575684967444;
        Fri, 06 Dec 2019 18:16:07 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-ac4e-75f4-122e-fbe0.static.ipv6.internode.on.net. [2001:44b8:1113:6700:ac4e:75f4:122e:fbe0])
        by smtp.gmail.com with ESMTPSA id r68sm18641871pfr.78.2019.12.06.18.16.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2019 18:16:06 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, aryabinin@virtuozzo.com, glider@google.com, linux-kernel@vger.kernel.org, dvyukov@google.com, daniel@iogearbox.net, cai@lca.pw
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
In-Reply-To: <20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
References: <20191205140407.1874-1-dja@axtens.net> <20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
Date: Sat, 07 Dec 2019 13:16:02 +1100
Message-ID: <87r21gdgnx.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="L4n3r/SK";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

>
> Wouldn't apply_to_existing_page_range() be a better name?

I agree with both of those fixups, thanks!

Regards,
Daniel

>
> --- a/include/linux/mm.h~mm-add-apply_to_existing_pages-helper-fix-fix
> +++ a/include/linux/mm.h
> @@ -2621,9 +2621,9 @@ static inline int vm_fault_to_errno(vm_f
>  typedef int (*pte_fn_t)(pte_t *pte, unsigned long addr, void *data);
>  extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
>  			       unsigned long size, pte_fn_t fn, void *data);
> -extern int apply_to_existing_pages(struct mm_struct *mm, unsigned long address,
> -				   unsigned long size, pte_fn_t fn,
> -				   void *data);
> +extern int apply_to_existing_page_range(struct mm_struct *mm,
> +				   unsigned long address, unsigned long size,
> +				   pte_fn_t fn, void *data);
>  
>  #ifdef CONFIG_PAGE_POISONING
>  extern bool page_poisoning_enabled(void);
> --- a/mm/memory.c~mm-add-apply_to_existing_pages-helper-fix-fix
> +++ a/mm/memory.c
> @@ -2184,12 +2184,12 @@ EXPORT_SYMBOL_GPL(apply_to_page_range);
>   * Unlike apply_to_page_range, this does _not_ fill in page tables
>   * where they are absent.
>   */
> -int apply_to_existing_pages(struct mm_struct *mm, unsigned long addr,
> -			    unsigned long size, pte_fn_t fn, void *data)
> +int apply_to_existing_page_range(struct mm_struct *mm, unsigned long addr,
> +				 unsigned long size, pte_fn_t fn, void *data)
>  {
>  	return __apply_to_page_range(mm, addr, size, fn, data, false);
>  }
> -EXPORT_SYMBOL_GPL(apply_to_existing_pages);
> +EXPORT_SYMBOL_GPL(apply_to_existing_page_range);
>  
>  /*
>   * handle_pte_fault chooses page fault handler according to an entry which was
> _

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r21gdgnx.fsf%40dja-thinkpad.axtens.net.
