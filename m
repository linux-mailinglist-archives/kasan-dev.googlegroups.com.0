Return-Path: <kasan-dev+bncBDK7LR5URMGRB37LUDXQKGQELXWA3AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E69FC1137AF
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 23:40:47 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id z17sf362460ljz.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 14:40:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575499247; cv=pass;
        d=google.com; s=arc-20160816;
        b=fW9aCpB/xQdfsxZydjrSS1IX/JTokPkvpJ011doOou/802YP6B3DGsdkGFCQFh2zFp
         gQHYrWG+qk2W6wHwO9h9kw/9rLfl+D+AmkvXIvzAnYirwEZXqksE61Kvw/2xmGTcpIV5
         p6XHAg8owFcQZ1dOKuU16syZK3abtXgX19TKDDM0vTOhMLVwhRMxJOP597lQ9id6qTab
         RZ42/YPTvscEZPIK9sFpe3qNUHPu1X2Ok3wYzzIcNDZBZ1k1RUHM5D1fuDtT2ZccCa7w
         ImtGJ7uappxxlK2IgGzKAV6qOQVTOOUnesedA7IXykWOHF8GST/t4h5ErzFNX3H7fFqk
         qYkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=9eyl4QVQpg940Fv+hrDN8f+IP37ZEhX0ncVL3JUWa0g=;
        b=sYMv/Mo6IFrRVw617Jx6WMvROitZ/g1NDpTeuyo7F5IeX9iW6iWPsGhM+/M3+TgbK1
         fdHqlEZoN5dnx4P87XOc/QkyLcPGEgxlni0UVRBNhRwxjEEkL+UNz2uOBPW+1PO9JAxT
         45lvZb8td6s3iAXze3uZXuboL/ca2PHx3r8EKUy619w90r7aMkeAYhi4ugY5DbI6W1GK
         GuQ7nigqN6J60fyST0pvVGz1W82ZCIg3i92p1YY7Ds4yeZhn/DgOBwsCnLnYKiYxCdET
         T2TzOdlrns66MCYq1RBajbXh2qiwfBryaFOGLN/DzLK5F1YC+46yA9SnrTfNNoflGncM
         4WnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=F96XFSXR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9eyl4QVQpg940Fv+hrDN8f+IP37ZEhX0ncVL3JUWa0g=;
        b=UpbnG+2XDwclVU0BZsDb5OFId0Y0P81FYdK1u7m+8jP8/rUHzX60HgTd58y9jcDJf4
         +6F6qiYGgknJwzbFuvjcxWqmkDHFLq4RUeuvgJiPbZvL/bFArD+StEBQZD1WT278rWck
         yJh0ZjPHuNc3MZL2Eoten0VgeV8wxNXQp3OAt4e6Rw4VMBgecmnaxkv5KF0d7Yen1w74
         dAR5elR7iX9KZ9GAUaIcYGXgUItWGyX9BM0wpCS13YU997AWfgrKUYiTMM8luH+gEKY3
         p+cBAraB0p9yJn9gbPDAqzMD0OucqeSUhSk6CWmXu8nMTz7Ccy56l+d//Rk6QpoAv5yO
         IPRw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9eyl4QVQpg940Fv+hrDN8f+IP37ZEhX0ncVL3JUWa0g=;
        b=YlGma3ayftotnXGWODhxtTl0Z6UTJyeb8HzwcT0/iqX32GXbzcAt1eg3sAiZ7VYY6L
         HiRVa5GPPQ53NxAlPWXV9xZkveWnhdg1MCPp+Uj1sxEzesRknUuD3kTlCN5eHSInQ89v
         mI32PI7MulLaIfRbFKa3uU2yq6ZG5PF2EUeGh5ln/yE2w+Wu5qhNm8CodipqxYgnWBvU
         az10gulM99hcbcTF2n7KYHlnGiZ9DxHlsAHzx1wXjedRW78l7WOUIp+G4Pcm/lqIYtgx
         CT17jZy3tr48GWIoQBXFvAjtVOe9Y7hw0CmtzL3Mo+WbA8GfJ873gDrwarakDwIz5JFg
         ME7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9eyl4QVQpg940Fv+hrDN8f+IP37ZEhX0ncVL3JUWa0g=;
        b=TS7YHZnk5Ott2v9skicaJvp9MRz87/Oh6iFRzkTHZfjsXqSCljMfMn2+K3YiXn5UEg
         bEYO/jUF8fPzwXvQbzzx0m45KrRwWgzgWGtM5pHY45GX5cQPBe/ZRQcQCUccX7Uxib99
         tcGuE/5nVaV+1FWTUHEmcMcnTsMJXUhdF6Yc3/yHqUAE8Dsv5tHnp5V2DrFOiW+NOjf7
         4TCP05IXgr4FdrtuGwx3f7aE5j6U31uf9zphNtTp4vV4TN1ylDsxt7sIjdfzb/pHXHeX
         0KA5l1cwgk2OUGRDyFGoKqlq++9kIsab1uxHt/jC+iRGtCXrOId6z0hLDeH0zfFTtaAV
         6F6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZQFXz0mkZENjLCcefJ/MxtA1kUFlI9heDCjuUp2SQwgrg5R/4
	hA06b5VU5bi2ROFyZNxB/hA=
X-Google-Smtp-Source: APXvYqzCPxU7JgKtvMz0mxGF14DQm5wj/6InO71uy8Sheb9GMlLCqZUmxjBaSLydh15Ln/w8j7foRA==
X-Received: by 2002:a19:6108:: with SMTP id v8mr3365780lfb.119.1575499247457;
        Wed, 04 Dec 2019 14:40:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4182:: with SMTP id z2ls89232lfh.9.gmail; Wed, 04 Dec
 2019 14:40:46 -0800 (PST)
X-Received: by 2002:a19:ef10:: with SMTP id n16mr3474755lfh.187.1575499246963;
        Wed, 04 Dec 2019 14:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575499246; cv=none;
        d=google.com; s=arc-20160816;
        b=tARHBM7S9xXHzBbvyf5CgEKK2upqHlhkUe2iqU5kNcrd13SVodzP3kGavwy/ivNBsD
         CvhHpagVE2iH5hg0CKP8d5pgED8ObHLhkeb8kvEcPQcUOwQPoY8Xr/HF883f+CvzOErt
         G9eis+qMivHV2Jq6bW2tl18KqV1t/nMiZPANEzhaOjXXDF6OD0aAu4YEW+ua8xFAJ/l6
         fBEr6Hyo1IRr8T0lBuarHrmtUQfkdZXGm8yg5+y2vl9hW51CTeKbxQR1AE/yS9UTyWdc
         uIQf8AeVJ9pQqCmM6mp8EGPu2Wem8coQjtdjMbu25Gs+dTi09tkQqSsaHnkGN06bPrfE
         fYtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=PXU0l6hsLNwOEAachYcf3O/SAhU82EqIUjlmH0om7uk=;
        b=oNsda5zI1Za9V3n80IqzSMSERFnxcVBtvW2jdh8crP/dpvOrRmIuIugBbrPbMOx7zt
         qordcYHpZQrwOBExGg2yB95pZkNON/HeQJrOkubDl6+8jdOxZ1hhgUhU1aojEs5Qw0Tv
         BBYfDMkFDdViP0kh8sfDJVPJ4x/B2pQPTWsrMm/dlMhtf4/TBHQWmjIP8/w4sB1ysKVd
         ORN3ydfgT1TS4Exe/lfwXkjUNFewUwwajpCt2yO+LcDzOeQea+ZaaF7Nao8OHxzrNgPD
         KdhCoP8GcI5wg9gUlqoxXq2hQGsCus03Oqnd5m/th06AONKJ4jQdNV/pj7my9WPetVD6
         1tVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=F96XFSXR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id b5si555835ljo.0.2019.12.04.14.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 14:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id y19so841477lfl.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 14:40:46 -0800 (PST)
X-Received: by 2002:a19:4f46:: with SMTP id a6mr3490704lfk.143.1575499246564;
        Wed, 04 Dec 2019 14:40:46 -0800 (PST)
Received: from pc636 (h5ef52e31.seluork.dyn.perspektivbredband.net. [94.245.46.49])
        by smtp.gmail.com with ESMTPSA id m16sm3932304ljb.47.2019.12.04.14.40.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Dec 2019 14:40:45 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 4 Dec 2019 23:40:37 +0100
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
Subject: Re: [PATCH 1/2] kasan: fix crashes on access to memory mapped by
 vm_map_ram()
Message-ID: <20191204224037.GA12896@pc636>
References: <20191204204534.32202-1-aryabinin@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191204204534.32202-1-aryabinin@virtuozzo.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=F96XFSXR;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 4d3b3d60d893..a5412f14f57f 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1073,6 +1073,7 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  	struct vmap_area *va, *pva;
>  	unsigned long addr;
>  	int purged = 0;
> +	int ret = -EBUSY;
>  
>  	BUG_ON(!size);
>  	BUG_ON(offset_in_page(size));
> @@ -1139,6 +1140,10 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  	va->va_end = addr + size;
>  	va->vm = NULL;
>  
> +	ret = kasan_populate_vmalloc(addr, size);
> +	if (ret)
> +		goto out;
> +
But it introduces another issues when is CONFIG_KASAN_VMALLOC=y. If
the kasan_populate_vmalloc() gets failed for some reason it just
leaves the function, that will lead to waste of vmap space.

>  	spin_lock(&vmap_area_lock);
>  	insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
>  	spin_unlock(&vmap_area_lock);
>
     ret = kasan_populate_vmalloc(addr, size);
     if (ret) {
         free_vmap_area(va);
         return ERR_PTR(-EBUSY);;
     }

> @@ -1169,8 +1174,9 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>  		pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
>  			size);
>  
> +out:
>  	kmem_cache_free(vmap_area_cachep, va);
> -	return ERR_PTR(-EBUSY);
> +	return ERR_PTR(ret);
>  }
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191204224037.GA12896%40pc636.
