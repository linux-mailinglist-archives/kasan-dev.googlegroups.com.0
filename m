Return-Path: <kasan-dev+bncBCCJX7VWUANBB6UT6CAAMGQEVVYPOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D330630F564
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 15:51:39 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id c69sf991300vke.14
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 06:51:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612450298; cv=pass;
        d=google.com; s=arc-20160816;
        b=alA0hZnIOauY35WA/qpje5JbY39W2TSSZz86wEMgcH0bHnecdwX6aYGqqZ7TgS5xgI
         8P8r00j08LToSkF1mXMi4CzKHoMS4wx558VoqSm+ezVmxD7UqbNxKbG8uq8drtpXcnP8
         JQ+HHu4h7aZxzRhe0AkTaqPjHThXrTSrqm+SvY4uZGjAu5z6mUOuc/fZsjlHl+01vfHW
         EtJfOuiaWut5/ZTwLyD0drzBUB6vhZz5jsyjDz5QVctxK26EzejxwY73WQnmroKsa4zx
         3pWnBMfD7YPwjNgSFcCzsW5vUt4nBO/XKB/NCK1r5L84khqT0WMk0Uu9ptsR8YJ5pjp2
         quSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PF0eQqe5X/wRhOKoFG9dEPDKtZ1SBcfeEA1Rp5FWP2o=;
        b=YV4rfKpn7BsZPD/eYO43UksCnqeBAIKxVEnH89hnYPxQ2KC4WsH0OvqhyoYaYMK4iM
         +MIi4QKQG8y7PUM2OkKU0FtNXDwkgdvbeVZ8X3SXoBTgEK2sPjsPXk2L5hoPbB12L+Ex
         VhVUuls3Hw3vcdSqvNYwxUECQ+L+Pm1HwIlAn+kMA5jB9QvS32KgZNJARpJWdXg1eZI5
         ZX+W8yTQp1e3OxAxBgueXQhfifwhV19HbPhvMVTHsduF9ECIibSCDEAyAD/b9chmj4iL
         jOY5NvZehqp8GO7ojcbZJwIPGMnHtBaxD13IZjZvJ3CWdRpKbc3cwA1ySI+JdjySfo8u
         MwVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=soWUtNJ9;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PF0eQqe5X/wRhOKoFG9dEPDKtZ1SBcfeEA1Rp5FWP2o=;
        b=d2pcxFOgQ01AxF+iLK2AgUQXkF3091teSb5iUXJWTUjICGmN/tkiv7zciCgUVay/3c
         Iqdh06If2dmODgOrN0sAwZpWPfh5B6EMKHAcKmolFzaRU5jf9XEi1rTLBfM9NGPlsEOP
         opsa9DuXv27uBB6A6Zc6l8oaQwRyS3gsdBynHLlTVQhMMvadwZcxneMfi7BRd5UtVVNP
         ZovWwRhW+fTgncPuKY/M70UgVP3wkkNjRVFsBY5W/ujJwLgwRY1iIY6bIP/+pePh+b+x
         ANY1lyCK9BP6S1P5o4TXid5yRIiKkzpiA9h2jl8KBd9JCuavEXzgCLmPQfUg2VXIsRUr
         F+Ig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PF0eQqe5X/wRhOKoFG9dEPDKtZ1SBcfeEA1Rp5FWP2o=;
        b=B2vyMQbJbEOwdPfTRmL6/Q1CIWLlWYMIojKnqrdA+ajOL+bYTAvPzKRKU80bgzkyg1
         9exlak+kSjoX26ij6sm0/O6XhjpGDO1zh8UKWpzNTymf0SoAR5jvzbl8nfE6aH4CsFAw
         7DAJyRQxI9R7uGvKqPyCi2EhvH1Sf7Usp/MVsbDBhyga9U6aTkeVSBHLzcj658HAqdrO
         9VOizFT7zcAQaT2F+WWkI/8R3sx7RuZk8KzemxlveG8e99V+zgK8N20xzhxNtRnQoBLl
         +6nFilG4iRFAHM6jxMWH2NJGdmEc+ZmdBTv6NZm659MdiBStswV+Bo4ftK5FKlwx9Jo2
         G3eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PF0eQqe5X/wRhOKoFG9dEPDKtZ1SBcfeEA1Rp5FWP2o=;
        b=HDmBJzmCturb2NJeM07ewMqPJqnsFTK8XYaq0V6VHhbf6ayOlIdaufdkrW/Ic8sMhO
         yMqY7oPceIFHskUU6sQY9rJJbj7CrQlhzVhkClhwq0sttPdBdBpurbeW8A91GB7CVoPp
         WmgOl9Q0ksH+FinTQq77GD6ZdF1228EknGETDh0ci41mL5bokO3crhdlFsyx+hJEE5gG
         G+QKNKuCUVAR0lTISbb5sXSlu9PiOzsVURdamgwCreISx6wtYqwLK5KCPN3LG4YVZzej
         9/kDZwzvDC7eeTpojrywIFe1RrjVWgQChKyALLgO516JXqC7ReYLT+u5ZTISiS/OPCTF
         hEnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zrWF0dcpVn1q9HWz/wKJBuVfF/4n9jVtuAmf2FSuI6mdi4Hnl
	MlPgY3sX9zXiOh4MQbiPzFc=
X-Google-Smtp-Source: ABdhPJw/myAFA16Ec3sMxeQz6iLmndrTvNJBZAMAYFhmYlRadpqGgWncKq26bZ/814C/EKmwd7mwEw==
X-Received: by 2002:a05:6122:1213:: with SMTP id v19mr5484090vkc.9.1612450298821;
        Thu, 04 Feb 2021 06:51:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2106:: with SMTP id 6ls466318uab.2.gmail; Thu, 04 Feb
 2021 06:51:38 -0800 (PST)
X-Received: by 2002:ab0:7848:: with SMTP id y8mr5520786uaq.143.1612450298463;
        Thu, 04 Feb 2021 06:51:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612450298; cv=none;
        d=google.com; s=arc-20160816;
        b=LE0ynJAhM8hLoRcugTvivz0YoN/QzSnKgSnr7xB0FvAtWXfCm0xw+j2fyzG5g1OZz2
         kfudAzhfsFMzkeIqeWDQgLCb87x3IWlbbUn3SBaB2Qj0miHVOxQJHu4nkq0dSRiUKJge
         UzcAqOZC2SAA08B+7P2eiE+rhoiXj4nBwRsP3PRKGMj9cu7JLwNCUiOVkfAGjMXhCAsP
         PLioOwvon+4zG1PXhx8y7sTjhDFIVj9Q/bbdvYayoosXah/i/ADjuwYURUSyirBkJ5PA
         vPML6w34VFpCM9ZAPwGqseR57ijeYX31PxwI3LX40QpunST3n5l9TyGxO0TL8KWG3ySy
         nzfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j2b0oOc+rzmzi38W+sTrovSj5jDaFAC2TznS4DZxElU=;
        b=jF4TxoqanePuLCzirXstBZ5tDc+25AyXv2khDt/4fNppxOy4xcjRi9OiBeqwv38wdv
         MvrDLO1pgq/ELWDRX2nPnCsUQMB+hU6Dr7/fRnALflWXwhLK4TEvN9a49Hg81FaO7PKQ
         9LYurGXv9quWgH/bCWQbPfs/WcJgtRLjfN93fcu+OAlDbK+jxnU9AV7zmCakVGpYFy9t
         H6ZspG/vrlVqN/tsoHK3S6054yScRD03GaS7KJtzb6BcqnM7Rkhbh8/3LHCK/ytNNkf7
         PCKEXatolxgB7GawvBk/zrkY8f/RTE9/evK8N+BnflqXKwpPwGRnR6eBYpns5Fs4D0b9
         clVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=soWUtNJ9;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id c4si314423vkh.1.2021.02.04.06.51.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 06:51:38 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id s24so1829522pjp.5
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 06:51:38 -0800 (PST)
X-Received: by 2002:a17:90a:6a43:: with SMTP id d3mr9043689pjm.224.1612450297639;
        Thu, 04 Feb 2021 06:51:37 -0800 (PST)
Received: from localhost.localdomain (61-230-45-44.dynamic-ip.hinet.net. [61.230.45.44])
        by smtp.gmail.com with ESMTPSA id u3sm6866224pfm.144.2021.02.04.06.51.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Feb 2021 06:51:36 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: will@kernel.org
Cc: akpm@linux-foundation.org,
	andreyknvl@google.com,
	ardb@kernel.org,
	aryabinin@virtuozzo.com,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	dan.j.williams@intel.com,
	dvyukov@google.com,
	glider@google.com,
	gustavoars@kernel.org,
	kasan-dev@googlegroups.com,
	lecopzer.chen@mediatek.com,
	lecopzer@gmail.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org,
	linux-mm@kvack.org,
	linux@roeck-us.net,
	robin.murphy@arm.com,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to KERNEL_START/END
Date: Thu,  4 Feb 2021 22:51:27 +0800
Message-Id: <20210204145127.75856-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210204124658.GB20468@willie-the-truck>
References: <20210204124658.GB20468@willie-the-truck>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=soWUtNJ9;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

> On Sat, Jan 09, 2021 at 06:32:50PM +0800, Lecopzer Chen wrote:
> > Arm64 provide defined macro for KERNEL_START and KERNEL_END,
> > thus replace them by the abstration instead of using _text and _end.
> > 
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm64/mm/kasan_init.c | 6 +++---
> >  1 file changed, 3 insertions(+), 3 deletions(-)
> > 
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index 39b218a64279..fa8d7ece895d 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
> >  	phys_addr_t pa_start, pa_end;
> >  	u64 i;
> >  
> > -	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
> > -	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
> > +	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
> > +	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
> >  
> >  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> >  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > @@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
> >  	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> >  
> >  	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
> > -			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
> > +			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));
> 
> To be honest, I think this whole line is pointless. We should be able to
> pass NUMA_NO_NODE now that we're not abusing the vmemmap() allocator to
> populate the shadow.

Do we need to fix this in this series? it seems another topic.
If not, should this patch be removed in this series?

Thanks,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204145127.75856-1-lecopzer%40gmail.com.
