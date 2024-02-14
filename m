Return-Path: <kasan-dev+bncBCT4XGV33UIBB4MVWSXAMGQEKL2KUYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD919855297
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 19:48:18 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-68c4f4dea85sf1469336d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 10:48:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707936497; cv=pass;
        d=google.com; s=arc-20160816;
        b=qn2vAVuBSyq8oTDCLjpzkHV73plqz37fRBkbr14xTvIBFKHte7yCsQMZNsYkMBx9EE
         YBH/RuRQilt1EGkXRpuxKX8d9YXfPWoAPx3BxYTeHaYRbEvFnAxPQjuFhbxQK8nbXMt7
         QQdRI5I1X3bWwUbdhQeHhoUK7Zm8iNUokWwk9nhPr6psLjSr7lEYdaaqW9IYQImV4fF0
         r3el9gAfTKz144MfMt9YRQC9ThQ34ehBMCRo4TMzSt9eMR9d/pO5pCPLpcgflJuiDr+5
         IZSSw18uhKr4Se8vmmOAM/ElwfX/t6MdWU+Fy2fkvAaGx0WnZPaj8UEyQ6pRo+pPutLa
         DhAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=NgLcS84mvY8wimC9K7udnUI6vRjpLnVKKOt60VIzZ0g=;
        fh=2zv7CG8+zIVR61wV5HcqOE+BGP9dDQPJR8qcm9NDYrY=;
        b=opz/Ovgecqh9gedY5GZXKgtml7c9y++OFMlN5oHykGDixssT230y6HfptrliSKJKD8
         13QwNWT58hHeXukgyJpTqq4thfDL0hNLS0VONFG3IQCclaIM0Uc2wWLU/X/d9SlXRD7T
         Bdj4GqbBzqznrDEs/X+IesSyl+kkmqQzT2+63lHOLNGv8BLFsAClNWMOju5dacgwu/m8
         JpU+xb9Vupkht6AeK4b6DaSgFJ5giFVEHL3QCDeGBfJUi0IIzJ4RMVNrSFDOx7swQtjy
         cyIZDaAVU9ktVMuLzbQRZCg9Yil5OmqatRbHm3bqn/yVnvhukl7uU+mVyymPbh926pcR
         3E1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IC6QhSTF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707936497; x=1708541297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NgLcS84mvY8wimC9K7udnUI6vRjpLnVKKOt60VIzZ0g=;
        b=SZ8jYslci7LoBoan9xiIjRUBdh8Vq33RifVrM563b1SRU0G9inDpnmmI5VwzVXfjFE
         XZmsR+4FZZDPuHqERsU6D+LGFEwzLKajIz9NxfOd0OUIn1d0Ce71M/K/aomFTWE/Hwhp
         /b7UEc7pDet7/8ssB7e0D3FJg77rwvZdi/7oazo0bb5O4rtkCdIICMxi9xOm/whbuaX4
         kHxmXj52n5xhJIDtbesK8Z9KHWMYqJBZQmiAnZR4ZIyC1W5yb+pdp+fYfk/x3wiipCus
         EsdYCjvnpMfeZ0ARjC4k6Lrcdl4oNhzxgglCZzhfUBfe/crUtwBF0rxocB46Hu1zLCAT
         DO/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707936497; x=1708541297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NgLcS84mvY8wimC9K7udnUI6vRjpLnVKKOt60VIzZ0g=;
        b=pxWhN9W9fRKSLw5NkTmvIUmP5k+yiPQTYItjn2p048fUJxBSrzgHqFmfah4OTSCRGW
         rYa9cD+w0Ajk07PCtQZI5P1s3cJYPsGlSfxwK0aqMtb2s46CrPVga+h3YiM5Qh03qX4K
         gXpDu8kk5mYQufWF1ygJBSNsBFxx4SYPPSnSIsSRRTSbSvUiFPBz7XcdPmDGyPZyNT9/
         trlmzS5vNvIF7gc7Vi0xjT0DndHnRTFeiu/0uLJEDVuGvgvtEZm+CC5voStBp9lXxWUQ
         uOpnebYSi50r4+B4zxjQpl6kagPNVJvkc+SUxRk7Fi2VTAtftr7k2H5fb64HCEcMfvYN
         WSHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIQAg6MXVQdVLrOXKtm0vpYs6tfAkE/ct4sOl9inM4BPHqJ7wRGaskrEue6AQvBFQGeByaRV7arnC7qF/eSrWZ5LKpwF63bw==
X-Gm-Message-State: AOJu0YyjzqGX848lniQ50QHCdO0BP/pZzsTY9QfOaphbgICyuPBser2w
	JrrUSJfkqY4UdFNrJ4zvr0PW8sWAAE95vCsazJw1XT8aSdiTeBQE
X-Google-Smtp-Source: AGHT+IGlrAvSRsxRpsseaXLD5pq9DP3vy25b21e8UaK22jvwLiyaHqClKkFA10Cwu5DnCxNwJgHmKQ==
X-Received: by 2002:a05:6214:224c:b0:68c:9ed6:5b87 with SMTP id c12-20020a056214224c00b0068c9ed65b87mr4509924qvc.12.1707936497427;
        Wed, 14 Feb 2024 10:48:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2481:b0:68c:c65a:40a4 with SMTP id
 gi1-20020a056214248100b0068cc65a40a4ls1048098qvb.1.-pod-prod-05-us; Wed, 14
 Feb 2024 10:48:16 -0800 (PST)
X-Received: by 2002:a1f:ea04:0:b0:4c0:2d9c:820a with SMTP id i4-20020a1fea04000000b004c02d9c820amr3686595vkh.14.1707936496467;
        Wed, 14 Feb 2024 10:48:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707936496; cv=none;
        d=google.com; s=arc-20160816;
        b=AvacNYiufwCbLJfQkUlsPpV1oSafBcUEgv12fU+Py+n9i1zhJUbVTnHIJxx0RYK54R
         RDAbR43+zNLVpdt64RPjqdMxyURQbewPnir6oPBrXbP7aH7umFZehqvq1rcXUmfBxBkr
         1qLV1cE9kMlWGKB99caOmHSitN/dsZCPEawJg4zT9ax9aJPeNNbW+Zl/VnCAjUWsp8mh
         txgBSjCpdZe4SgZqGdeYxLJaTcVwCTPMOaTN/2Lg/XvkvP86oHxZsbsOKSd6IJMNigtv
         Xxzxu9PnAKfjdvgklX0kq+L4TXh7HscUbu1Z4g82pvRCSSmYoRT8pue1SUiaHaySV85f
         pHmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=M/s3FaDG4gZhQ2lrG6CVUKCCfwEU9giQ+dHTS6jQYos=;
        fh=cuUqV10z4+fTkswtA3Bp42mnryCU24Kr752dJeKE/4A=;
        b=RDfhWsHq2wJ4FTNCe8HstiTSDO06tW4vGRVYEgZkoP6HEAAsDUuC/Ij5no+lkQ+c/F
         rI5sjDGQthHUoHJsvsgXJ+TbitYi2pGo8NDaOYtpbMwVxLDx8QtnDbs8rr8rmk3QW4Vs
         uX+a0FH2ieHwHnkwBf7eXKDipESE9rOFoK2xYa4uTwk7Y9NP21x9O/LAyrjEscOgnMqJ
         tnAgFNq+7v+3qOwOjkenBq1kQiOmtl745SHsQHT8jWb2XHMXLKJzxpH1vIEfHWO5G2zO
         ESDbTjJG0ZOHuYUiIrFQz5vBsBGESnEmjUKqIoyICO7iO9I7yxKxtCV2q/TWM0pvD92G
         smtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IC6QhSTF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i16-20020ad44110000000b0068ed0794675si386798qvp.5.2024.02.14.10.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 10:48:16 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E02D66069F;
	Wed, 14 Feb 2024 18:48:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 47A91C433C7;
	Wed, 14 Feb 2024 18:48:15 +0000 (UTC)
Date: Wed, 14 Feb 2024 10:48:13 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Benjamin Gray <bgray@linux.ibm.com>
Cc: kasan-dev@googlegroups.com, mpe@ellerman.id.au, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, linux-mm@kvack.org
Subject: Re: [PATCH] kasan: guard release_free_meta() shadow access with
 kasan_arch_is_ready()
Message-Id: <20240214104813.be849bf79b26b2bb70108311@linux-foundation.org>
In-Reply-To: <20240213033958.139383-1-bgray@linux.ibm.com>
References: <20240213033958.139383-1-bgray@linux.ibm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=IC6QhSTF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 13 Feb 2024 14:39:58 +1100 Benjamin Gray <bgray@linux.ibm.com> wrote:

> release_free_meta() accesses the shadow directly through the path
> 
>   kasan_slab_free
>     __kasan_slab_free
>       kasan_release_object_meta
>         release_free_meta
>           kasan_mem_to_shadow
> 
> There are no kasan_arch_is_ready() guards here, allowing an oops when
> the shadow is not initialized. The oops can be seen on a Power8 KVM
> guest.
> 
> This patch adds the guard to release_free_meta(), as it's the first
> level that specifically requires the shadow.
> 
> It is safe to put the guard at the start of this function, before the
> stack put: only kasan_save_free_info() can initialize the saved stack,
> which itself is guarded with kasan_arch_is_ready() by its caller
> poison_slab_object(). If the arch becomes ready before
> release_free_meta() then we will not observe KASAN_SLAB_FREE_META in the
> object's shadow, so we will not put an uninitialized stack either.
> 
> ...
>
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -522,6 +522,9 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
>  
>  static void release_free_meta(const void *object, struct kasan_free_meta *meta)
>  {
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>  	/* Check if free meta is valid. */
>  	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
>  		return;

I'll add
Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240214104813.be849bf79b26b2bb70108311%40linux-foundation.org.
