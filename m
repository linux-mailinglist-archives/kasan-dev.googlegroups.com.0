Return-Path: <kasan-dev+bncBCT4XGV33UIBBNNLQ6JQMGQE7L3Q4LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 849E050AB2F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 00:07:50 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id x10-20020ab0380a000000b0035d5853f6b9sf2431131uav.11
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 15:07:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650578869; cv=pass;
        d=google.com; s=arc-20160816;
        b=XYYSkXh/QSDh5esBpGbfzrPj1/LEVWfaI3+skpqMhQLQSjOYaaPE/+pLhNk6Fg9yv3
         S8xzD/fopxJZZVP3s2c9DWFqfaIkJyvXKrlIYw0J1UtUCqeCw68Pn4iJRfQ+U4ZMELIz
         wZz6M+yckq2TQ0L88PlgekPOi5izMV16PrB6JY+HWLCANX8FvzKLLFTG5yzl2Q/0qTHb
         ROXnYrTxM+Xn0VSwf3wZr9XPZzwIV2c4/LjtA+926a8NRWhCs0H6Vy+ox9aXTQWkjJF1
         mQw42/yxtBlXhN4KWyU2WBMzSqwjhcE3pUuxnHVO+5ZXaAfTmdDRtqQFhMRFNmW8MQzE
         J7Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DMWY+eIHhsk+FzGdlJ/xpqE0aqpKdnMnZ9voeEghm3g=;
        b=DNGemLMxV9SmQOdGH/uJvMrRvKnjyCX1uvLSV4orJF2EE9H5+DAT4kSIviwS/gMCoO
         8lZJGQfglr0AfGT7eVKmBV+reEMdjophGf8bUCDkh8zc0CEEoagq0HclIaDMH5ciOX+8
         FtqzphApT3xmXteriV0RRd3E4X/QekfwoOUG8NA186np0v0lEvxx6RDVFBbWZdNhl36S
         5RTPjsVK1RdhfaN6zVFcMoXJ9yYfIqVzp+J3ANY+02egR6pW4q+iNW8E8eFXAKfVMime
         ArO23Oykt5zv7tZDTedRSJNmNQXt5hsY3ZgZ5t2ySAUnrUMF1cqasN2gUAsaFSabJOCE
         6Rqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fAHKB5NS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMWY+eIHhsk+FzGdlJ/xpqE0aqpKdnMnZ9voeEghm3g=;
        b=cT+jHpYHRGRy8lIdUFCUCD5un8zP+EnHyztc57YcroD7OglptflEVeLb0lwsv271C+
         Q4qQ4Sow6lH2OzI1ZWqwpTnY99DQr8uOLHFxGikpld9/hGFiEGDQHBO3ZLNJm7F4fncb
         S3iVQ36HcRvqjRmauRX73QztToEcpUDVDvRVdXD1/qZKu5tP91PAc8htx9vWMu1bQ7JX
         M9A0QhESjhSq8X+xD0nmO7l/Tn6wvbCa4Dr3+5B3o9et7eTRzSh+k0Y8k9oWzHNJ72I8
         tDFQIQ6m8HZC1svex8hYRESPvIaTRPbFaVEKxt+7sSQiA6yj5xs+W7Pd9R7W83BSJq/d
         Pesg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMWY+eIHhsk+FzGdlJ/xpqE0aqpKdnMnZ9voeEghm3g=;
        b=eonByOYfRnOp1xBX4qBYk9jtNVplWqktaA/2RYuWaMAIzROKE7UvVHdsw5XnavLliV
         3WJYjMoyrNF1WWV/LI+LVuunuyX1FnwUUt5tgYMZK5bTYBNVqBkdn0fgwT4BaSPM/UpG
         L/i4K+Z/J6BOBoUICNJWG51VEPMVlceoTdT49cAFw9iLIazL8W680qKd+G9R5E+V/z5/
         lEi+WfXSEUDuNBTX1RUsvYzGFrtTsJ42P140cALrfHBla07xtck0FSoP9pDI9niZKri9
         vQtL9wQhdCZXJfZQ2vbKl8On7C+mLCdroJgE1lGrHj7yzZCWQ/3aSnsm4iPaOoMPDfa/
         /LZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uln1d2Wk06JtKb7vm8Tg9IEpWDlBftHjqwZQDCNUZbR2vqd9R
	Tny3XX2EVSztJJ7xB9kQt3k=
X-Google-Smtp-Source: ABdhPJxuX/FBSadjl3MifPUlMmzS810qsHUXdqBC6SS4MxiTJbO5ZpR6nrE7X6sgou+50Szf2SsiAQ==
X-Received: by 2002:a05:6122:b70:b0:349:5366:becb with SMTP id h16-20020a0561220b7000b003495366becbmr676871vkf.21.1650578869435;
        Thu, 21 Apr 2022 15:07:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:b0:32a:4ac5:3c7f with SMTP id
 j6-20020a05610202e600b0032a4ac53c7fls1884040vsj.2.gmail; Thu, 21 Apr 2022
 15:07:48 -0700 (PDT)
X-Received: by 2002:a05:6102:4b8:b0:32a:4a0e:6270 with SMTP id r24-20020a05610204b800b0032a4a0e6270mr480772vsa.58.1650578868741;
        Thu, 21 Apr 2022 15:07:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650578868; cv=none;
        d=google.com; s=arc-20160816;
        b=iOt72g04zGABGxtnZjojIZx6czAAP2ng15aG6fXU6wsv5p5ZL4xkVTOr0LJW1ljS2T
         4MfPSrmsCcK15cHLjzOQf7w45r1l/TbNEYuUWaEraN/t/8NbY94ZjTIvEZASTbieDDjY
         SmqFXvSv8jaJI7+7La60ydWqaUd06ZGC4yOa/fjHJTOw88Ppl0LBrcoOcbhJVCFK9l27
         EwaxXlENww1TL9NelgPSADlR9g3p2s+YXz3E983Onr0GbFU69izfdBwmGJF9Xwl41slp
         rP2puCvo9QOcL90Cduh/83O7qusmxt79maZPnZuCYTFQxfTqG8i1fkgii05WI2rCAWBh
         OLKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9PTUHp3ha/u1SZ/ogRhtmV5nZ5ipDzuxSu1S8cX/k50=;
        b=oVnHlQ7gfcu3FrBTsmlYm7FUJV8aUF9ompmG6+7+Xq0j2v0i3kZAiDf3vy2JNJitWM
         0nvlwDL/LC/kQgeTwMMOcM42eQ2nSkQFRs1TPssq8t3kbvapvLG01RFwqh+BKv5nk3MP
         YjWqQsaN/XLGRrWpo1wbZEdExVL7hHPkusMH3trOxSj+WYgq3i8Lw0kU4ELC2Wu03UJd
         HLsHWwoiO7TLqCuY6RvtSyWciOOTRWQi1gmVNyLH6k7zfRpGqeq07LqLbLHBkW6aAyon
         kgUfk0zC8Q+gxW/IfyNI45nZlrdK/i4+pHoQRfXrfO2IghITtDjY50mIoYURnXc/pNo7
         7pkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fAHKB5NS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id j13-20020ac5c64d000000b0034911e6ef9fsi608909vkl.4.2022.04.21.15.07.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 15:07:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3E40461E2F;
	Thu, 21 Apr 2022 22:07:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 61277C385A7;
	Thu, 21 Apr 2022 22:07:47 +0000 (UTC)
Date: Thu, 21 Apr 2022 15:07:46 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Zqiang <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] kasan: Prevent cpu_quarantine corruption when CPU
 offline and cache shrink occur at same time
Message-Id: <20220421150746.627e0f62363485d65c857010@linux-foundation.org>
In-Reply-To: <20220414025925.2423818-1-qiang1.zhang@intel.com>
References: <20220414025925.2423818-1-qiang1.zhang@intel.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fAHKB5NS;
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

On Thu, 14 Apr 2022 10:59:25 +0800 Zqiang <qiang1.zhang@intel.com> wrote:

> The kasan_quarantine_remove_cache() is called in kmem_cache_shrink()/
> destroy(), the kasan_quarantine_remove_cache() call is protected by
> cpuslock in kmem_cache_destroy(), can ensure serialization with
> kasan_cpu_offline(). however the kasan_quarantine_remove_cache() call
> is not protected by cpuslock in kmem_cache_shrink(), when CPU going
> offline and cache shrink occur at same time, the cpu_quarantine may be
> corrupted by interrupt(per_cpu_remove_cache operation). so add
> cpu_quarantine offline flags check in per_cpu_remove_cache().
> 
> ...
>

Could we please have some reviewer input here?

> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -330,6 +330,8 @@ static void per_cpu_remove_cache(void *arg)
>  	struct cpu_shrink_qlist *sq;
>  #endif
>  	q = this_cpu_ptr(&cpu_quarantine);
> +	if (READ_ONCE(q->offline))
> +		return;
>  #ifndef CONFIG_PREEMPT_RT
>  	qlist_move_cache(q, &to_free, cache);
>  	qlist_free_all(&to_free, cache);

It might be helpful to have a little comment which explains why we're
doing this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421150746.627e0f62363485d65c857010%40linux-foundation.org.
