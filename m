Return-Path: <kasan-dev+bncBDV37XP3XYDRBRFPSLWQKGQEEYVANDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA09D6655
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:44:05 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id m6sf4465675wmf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571067845; cv=pass;
        d=google.com; s=arc-20160816;
        b=GF6MD1qlSUl0ca5TFZo5nicg8DufCaEp7EVIR9hn6Mtpbz9V4gtQKcMwfAEwTB9LzF
         GUXSYyexzgqBmf4iax1PFeLG5c942B4ukyLBJMvifkCTb7qwZNB8MvkzfQ+ZXcHrN2+D
         ORdbhxeSdFVnaOBaLTEF7UBAExg9SmAfZltojKrrnETR+WTgFiKBoSrutrNgZ9tpEVKj
         SG5hgMRH3BACJNtpZqfCC54VwHus/a5MGKOqLXmNtYUmkNbu+EYo+lDvRUoigATrqHhK
         KKXKGMhN/w0rAIct88SU7Tjz0ebmZRl7JcAtJl2McoVoaffJXElO4wqNoz278G7OsqKA
         Q9mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=UIZPmaJxnr2IWsorcqzd8kIYy68eONRsbWFJLlPuB0I=;
        b=wOvgdE9olIJBJDXafOtXxgZyuR25mGMzu5XCtpcdZiwAYIsJilEKCrfFswrf0Pfb35
         mqQf9B8M9KJSnK37FKvBaAFV8HuVVd7yoz7iP7WgRHkNEBv0jmkUpJ5uRrucx6Cgg1ED
         1WjtkVRCLaqJZ81P8UGCiR2A4G4x+ncuS80nK56E6L58pR/Hhl21nav3iCTVxECYbe5f
         Tq1ytj7FOZfi43PNbkl0la0DJHhDhtAmHjuSHXEQ2Ot96C6Ms94N0VEcrl1ENZU8IC6N
         aYBFzcVZk1lDtHnBhFmNI0o5NiGlNOaPO/uWxZ0Nz6H7NxvMZQRIaxIsM6Wh0T89w9WU
         vR7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UIZPmaJxnr2IWsorcqzd8kIYy68eONRsbWFJLlPuB0I=;
        b=AMfkwJh3+2IGbdunlSie1i4EoRW6PwbOxOvqs9+HclTTUfSpMcDN7Eds/NEviAQpXb
         hQQ0mNmLixkVRHFyPZ+z1/hPEtPMuwn96mdwaR5aXAOW1ufEj18vYKm8PTa6wgd+ZUNE
         8Gmvil4U/hPZ0AtygaXpDCtAG674MMp4uCZWX3/gzVCptxE1yU6kGPIk31Bloxt8Dra9
         +ebuiC6VTj/iNXWAicnI97F19qs3nbydc2B3vZXsuVgBzfkG1sVgeQdZQsea2VGpSSkU
         hVvx/+1VG6CZgcjwJpmuQc1oGBrR3IuE166bZEk2Qijg8K+ueNV+4WBQeBl9JCPc2i+T
         A00w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UIZPmaJxnr2IWsorcqzd8kIYy68eONRsbWFJLlPuB0I=;
        b=MICTZSIsAAXjouiDWB6dNlwUXd6WQBaE0mxAQFAJuaCQS+4CoSDgICBwqKGdOpxsid
         vGY9ZlkCsH01EWWFw30snQ7oc74yAhuyUge7XHGWoEGy+np6JYGcXdMEa75nLA6uVqJn
         EhAMwptbW9REaHjHw65gsfl3J6j7HgMw8+LA99rqZ1PES6nUu1BRs0ePKH/3AcZB18u6
         71o/QJu95ovgWfUaiLLaBvMhzrEI5oHlA5UpMMpYuEmAFHkpvP2mC6e4hDPeUFAPHpUk
         nKEhC2+VsI7T5C55zZ8Pc9Ple4BptaZe5P5ajUwfqCyGHbikp4GgJXYvK5503LsNf9uF
         DNkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV2prjbPJuEhw4fD2rMMpEPSTy4nP1qYDHDc+g9lPSR6Bq/mMiB
	4hIzDl0CwnkAjgKCazyP7Dg=
X-Google-Smtp-Source: APXvYqy5BLNN7H6ytvOxbfD0tafhb+IVdtXbpebNwFATDiJ1es3cpVHX8XvTHch1yT7d4p+azKMNqg==
X-Received: by 2002:a5d:56c4:: with SMTP id m4mr25413207wrw.195.1571067844836;
        Mon, 14 Oct 2019 08:44:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a391:: with SMTP id l17ls5601821wrb.11.gmail; Mon, 14
 Oct 2019 08:44:04 -0700 (PDT)
X-Received: by 2002:a5d:6651:: with SMTP id f17mr8182316wrw.175.1571067844098;
        Mon, 14 Oct 2019 08:44:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571067844; cv=none;
        d=google.com; s=arc-20160816;
        b=bKljNbyzkB9gpi75vGD/Ri+70W/RthXImU9MwVUKF8ZMgTI0pwYAiKidyD/xRW2IQX
         ky5oS3KY1W0+tgG2h3CanuFotH2GLW4tsLmHliAfTOulUqAs8kkavcue0sm4WIOSBkp1
         rbKdHXJZcFT7LvLsrY556mx8e0ZIV68ibSy68DkywBVfFxd1RkyVo9LCjT1WiTc0hx4j
         XY9A3Fod9ii/CMbptv3cacbfH9azgoCeKM2xHEO5zH7/TwCe60aMBkQRMOB3kwjjYT+V
         Uthz3sDdhh2iJqwNO4gAK9WzJJ1mkREYKaDpKvwVbrYLPUB8+VHLVZ9wHPgxjNPZuzCX
         GaOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=UoT2pOzkJy+Uc8c+b4u1ar1CCmQVsfRZ2xR5y+1AnWQ=;
        b=iLt6g8J+SItJNpVTNYyDoolM3PktQhnUTRkFJRvJa2XV4n6cD0fUptGf4/4yhmPjX7
         dVWruWyeA9MkIpLzyp+HvtAmvxx4h+PqRSu02//0pTEim7Xy0/6qYbkF99+uvuzz29q8
         4ilxSRCEhET8ydVsASKxd1ef+N4BS3F+x1lfiRQCo1RgyLSHu5XWzBtzOf1h6YsIYhEu
         3UbIO5vgiKVwMjZe1ph94KiBbijQZCWSMzGuCT+i6jojbGVnpeouG8Lege6lAphD1FtY
         3IPfkgb8a5m9UTVdvjo8/f3sz0jth7ypKE/roWm8L2yF9x9H7YKu9q5yLSX0S0I6fA9B
         K/1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l3si23367wmg.0.2019.10.14.08.44.03
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 08:44:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 60DE228;
	Mon, 14 Oct 2019 08:44:03 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C9CCC3F718;
	Mon, 14 Oct 2019 08:44:01 -0700 (PDT)
Date: Mon, 14 Oct 2019 16:43:59 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191014154359.GC20438@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191001065834.8880-2-dja@axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, Oct 01, 2019 at 04:58:30PM +1000, Daniel Axtens wrote:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate a
> backing page when a mapping in vmalloc space uses a particular page of
> the shadow region. This page can be shared by other vmalloc mappings
> later on.
> 
> We hook in to the vmap infrastructure to lazily clean up unused shadow
> memory.
> 
> To avoid the difficulties around swapping mappings around, this code
> expects that the part of the shadow region that covers the vmalloc
> space will not be covered by the early shadow page, but will be left
> unmapped. This will require changes in arch-specific code.
> 
> This allows KASAN with VMAP_STACK, and may be helpful for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on). It also allows relaxing the module alignment
> back to PAGE_SIZE.
> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> [Mark: rework shadow allocation]
> Signed-off-by: Mark Rutland <mark.rutland@arm.com>

Sorry to point this out so late, but your S-o-B should come last in the
chain per Documentation/process/submitting-patches.rst. Judging by the
rest of that, I think you want something like:

Co-developed-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Mark Rutland <mark.rutland@arm.com> [shadow rework]
Signed-off-by: Daniel Axtens <dja@axtens.net>

... leaving yourself as the Author in the headers.

Sorry to have made that more complicated!

[...]

> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +					void *unused)
> +{
> +	unsigned long page;
> +
> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +
> +	spin_lock(&init_mm.page_table_lock);
> +
> +	if (likely(!pte_none(*ptep))) {
> +		pte_clear(&init_mm, addr, ptep);
> +		free_page(page);
> +	}

There should be TLB maintenance between clearing the PTE and freeing the
page here.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014154359.GC20438%40lakrids.cambridge.arm.com.
