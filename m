Return-Path: <kasan-dev+bncBDDL3KWR4EBRB2P2XCPQMGQEHLCO6EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E52E699762
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:27:55 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id g6-20020a6b7606000000b007297c4996c7sf966353iom.13
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 06:27:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676557673; cv=pass;
        d=google.com; s=arc-20160816;
        b=UM/qlP/9CRzFp6FGzdj9/8rpJvGlHFyCsjda4atBiVl9lpQFCl8Roh10PX40oUjIf9
         2KkaiQWqqFPONg7IrSE/1ImrYmxNupLLYWGZkkhNJdln8jZMz1Q9cAuhwcxNcSk7WBMs
         Q60HSHI3DyrYhZjsdWFNBLN0mUb6ZM0P+WIw5PkU5RvGjdNyqv884P73MjOLUyanJg+M
         veJ2VMBB4eJ0THSrnBXAr9lbJeEQAtJtHaxHA+lRHq/1GnmE7YNQHy5FumdUg28jmkco
         i3g0g1hlpfVp/LpsMpdcIfMB3B7zxDMhYo22pCaQPc6I1pXcvMGfovK6IBcx9AykXR+p
         04hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Uv6UKhpmTNf84kF4FsGcEAqEof0f8Zx393CGEeyyyvU=;
        b=0nvhcl2KJeRu6VbOOtWtlk23Z9BngqjjGIwYOP49X0cnmnjOpm1LUCBnRcu759cJlS
         aYsktJU4VDyJQ4mN+elZYxPfMMaKx6YpZvA5UvBxa8Zx57PFqE764PsRs6jGw5UUZgR6
         1h9m5lSUaOFBYtZgs+v7Ylioqy0VqkA+EFYF+qdN+bAJT0448iYMdFb8oIRTI0iWhtjl
         YOcRoEnjjLoSURtkxmCcBOtGB8vI46LI86YP38HacIpbuXPZza3C8kCEOfHe5Ta8CWKK
         Jysfdtv9sIdfFEqI1wYUxdENhOvlXKMo53QbjOwEkSHihhm7cnLZpdQWSGVumJT1J6LS
         x4fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Uv6UKhpmTNf84kF4FsGcEAqEof0f8Zx393CGEeyyyvU=;
        b=cO4hRZufm6BCClyVoRkUFA1dQjHLJ5Jy8Wp1kPrrpqQfesyZzdsjPHe1disJ/vD7PT
         CcK0CQb+pcmFbRmKRzfSQkuGHmHDNC2tvO3fDAPk3j1/yCGmKLjmVyUl4DmxiB/uTm65
         T1DnrhbfDLh/8CaBaBmtrcMIggrRoIFBz2DeEqTePc++MXo+Iklt0Dbwiyg+vdgZ/0D5
         V0sDhobuWJI1wa2rmYijZpZ+WDefbn23XhdHAImIQkeB2y+hFaTZFiY/AlrvykTg6scJ
         rDGuK+zp7/xgPARJdmICFcG56Blbu41dk+NcJL+xRzj17Cp+IiPsTd/ZhRgF51+Pvg7n
         c4Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Uv6UKhpmTNf84kF4FsGcEAqEof0f8Zx393CGEeyyyvU=;
        b=mYcTftl31S70I0m/h6RKGOTXw+t0ONQIuUODFslDai+sBsAa66Ho2cZWD/O0WPW5oJ
         XkL3hMXL5aZnjCe+e5Uvl1mexJXL/fG8fAh+xBgpSVKx0fQQbUt8LT4/kLrwR1FP/LTy
         vLy38UWRPy+q5Yh3xnfQhFqhD/Uw4NQC3ONK0UuvhdIDSVW/Zsukn2KAuc84Qz9Evznu
         foe4OYPiiOpzlCtSHIm5UZ4ekQ24FhXzfrdbJ/X8370ELgMRoVw4ySdIl4qi3J3V9zZg
         QRoXsHvTA+fARZrwodpJMP6BJlreNos1nxxi+7igkbzUqUIVpABqAbRWoBYT1Lu/ngw9
         LqPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW84x8KAfMhxGy0j4QcFLux7XuwCvhqjbghVymSmB4OyzXoDEqR
	3FeUXG9vTIPj24t74tR5htM=
X-Google-Smtp-Source: AK7set+010sLl0aLD+OvsVal4+FL2EaJ+VOFo1BS73joADr6uQdw5ktSf5BFqJGmcCwj63ALKSJoFQ==
X-Received: by 2002:a92:7a04:0:b0:310:a381:d0a2 with SMTP id v4-20020a927a04000000b00310a381d0a2mr1690098ilc.0.1676557673537;
        Thu, 16 Feb 2023 06:27:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a24:b0:30f:4f58:8670 with SMTP id
 g4-20020a056e021a2400b0030f4f588670ls736131ile.10.-pod-prod-gmail; Thu, 16
 Feb 2023 06:27:52 -0800 (PST)
X-Received: by 2002:a05:6e02:1546:b0:315:51c3:2ad9 with SMTP id j6-20020a056e02154600b0031551c32ad9mr6339321ilu.21.1676557672894;
        Thu, 16 Feb 2023 06:27:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676557672; cv=none;
        d=google.com; s=arc-20160816;
        b=ZOucSKIGphh0QK5SnJZLiqxoB2dS8/n5Xy0gkvaXUWPDFMJIwV6J8egTE4IPZVO3XV
         7ds6PZYWEwh+u7dyFuzQdqkQGWcBfDSMH/DaYGnW8fzy1yOWuorVecpYss0PfK+Ab/4N
         JADVzfEGqHo351YprLqjurChEUg/6PWT8/TLmf3odS5y6xOoFXFryor8hZ+0EFjOUSkw
         WjCXQxagbn9EXwOGE4Q6lMf/DYn8URdqXv0U8DzdMQlya71ug3ia24KTV+LLozJGoZBe
         sAMp3icD4W3DQL4vW7lJfteUWIBBKS3+1AHb7hBcdejmof3/qGILJmFOVFHFOoYR9yRw
         SSpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=48fO3JbsEc3aZalpD8wObnGiS7gasR3PAA5gkMgL9tA=;
        b=a/trDgAUT/tTrfeiMiitL7teyT1Q2o8LlowfZ/EK01Ds+SmYmCnsx4Y7V/NgqJ+D9Q
         alHBh96KddQcPX9sa2OYF97uRYb/BzX3Rmu9WMFyWXv5DhZt+dpTAJURs15bodg2+K2v
         bmwyrab0yLHw3EHoRqOObKaGjEUE75gq7duGuoSiT04DxaO4vUrFeJZApGZHPueG4+wF
         BhOy24PYVXbOLSvnR3wT9huAjC0mia6yoVIWSSpXQN1gPpOpJ52oGdhlgRM/W7t64tK/
         LZv2DwfYHJ82I9gYXc9xmSTy4n8jXQuD26tIyfgqxAUzeSuNeAvTvObZ1uqLrS+WPTzF
         JayA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id j21-20020a056e02219500b0031580b246e4si107920ila.2.2023.02.16.06.27.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Feb 2023 06:27:52 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7DAE160EC0;
	Thu, 16 Feb 2023 14:27:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D8B5C433D2;
	Thu, 16 Feb 2023 14:27:50 +0000 (UTC)
Date: Thu, 16 Feb 2023 14:27:47 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com, linux-mm@kvack.org, kasan-dev@googlegroups.com,
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org,
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Subject: Re: [PATCH] kasan: call clear_page with a match-all tag instead of
 changing page tag
Message-ID: <Y+49Y4lD4GmDP8fc@arm.com>
References: <20230216064726.2724268-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230216064726.2724268-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Feb 15, 2023 at 10:47:26PM -0800, Peter Collingbourne wrote:
> Instead of changing the page's tag solely in order to obtain a pointer
> with a match-all tag and then changing it back again, just convert the
> pointer that we get from kmap_atomic() into one with a match-all tag
> before passing it to clear_page().
> 
> On a certain microarchitecture, this has been observed to cause a
> measurable improvement in microbenchmark performance, presumably as a
> result of being able to avoid the atomic operations on the page tag.

Yeah, this would likely break the write streaming mode on some ARM CPUs.

> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711
> ---
>  include/linux/highmem.h | 8 +++-----
>  1 file changed, 3 insertions(+), 5 deletions(-)
> 
> diff --git a/include/linux/highmem.h b/include/linux/highmem.h
> index 44242268f53b..bbfa546dd602 100644
> --- a/include/linux/highmem.h
> +++ b/include/linux/highmem.h
> @@ -245,12 +245,10 @@ static inline void clear_highpage(struct page *page)
>  
>  static inline void clear_highpage_kasan_tagged(struct page *page)
>  {
> -	u8 tag;
> +	void *kaddr = kmap_atomic(page);
>  
> -	tag = page_kasan_tag(page);
> -	page_kasan_tag_reset(page);
> -	clear_highpage(page);
> -	page_kasan_tag_set(page, tag);
> +	clear_page(kasan_reset_tag(kaddr));
> +	kunmap_atomic(kaddr);
>  }

Please don't add kmap_atomic() back. See commit d2c20e51e396
("mm/highmem: remove deprecated kmap_atomic"). I'd duplicate the
clear_highpage() logic in here and call clear_page() directly on the
address with the kasan tag reset.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2B49Y4lD4GmDP8fc%40arm.com.
