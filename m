Return-Path: <kasan-dev+bncBCT4XGV33UIBBQG7VWJAMGQEHNBFYLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 134684F1E00
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 00:22:57 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u29-20020ac251dd000000b0044a245bcc1asf4287104lfm.7
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Apr 2022 15:22:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649110976; cv=pass;
        d=google.com; s=arc-20160816;
        b=yhwybI7AiTiF8OH8qucDFfppcgJnSxj4A6RmCqwICgtSfcnpfHFyO/P4K9nixeXUKJ
         9SUg6cccFL2DP5jNvm762swjdxHvCPyzsJHS8sIYQi8tBcSkYpUkfEhW/1RzGetnpbNV
         F9n+/DEvTQD3hcxYqZOynspBBoF8oSYhAuclOIJtTrhJtDUyIT5TeI+vqTTyBi26SnYt
         YkDcbz83H5F8oJhNIFUFlKTmJada5TatsHiher78+n31joX9HgBIqXOK418m+FJq4/Cv
         UDgQZ8aw4pMAqGB6dvDUVerQSGGWeXTXUf7l2kmNLT7hke5JvfzGDnBT9PnTtwVFvxBe
         k0DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=p2OULspfFW2OM5aRYVWdjWlDaLyQeEijl8sl7/AjawU=;
        b=FYsXjN5/Dq7wzAYybwFMR2lAQ70+QwP7NbMRbQ3vtv8vW3J7pRNSwMIBTpf9aRek7f
         Pn0I2NG4Hp/ONpCR9eeRtK6sL2Uduq75eyzgyod307JAiJ35ZZvDE3XzbhAepKdp3o8m
         GYHUc7nKeoGJP/PpIwnh0/fJuppIvF/2d0bSTC7MvHOlt3Yyye9fki7M33M+/kttFcAe
         X063XzwFkU1Jx+ZsV91jS4ygovj87WK4o6Ch5eK2ymm3vtqR3eIkiN6dVY8P/HPWNGSF
         YP82Gw/WPz0U/4kAaSQT1pGwQUhB12Ut2AcbZdUE+0+mtRNdwTG+o9AJI34l2bw8TGUh
         EzYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dI9HQbt8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p2OULspfFW2OM5aRYVWdjWlDaLyQeEijl8sl7/AjawU=;
        b=cffysybATW2+10YMNuWaK3GMlR+cBTRiDSGTK2pPqWhn8TnD6Wte6/FGGrubfEcs+w
         s98ipyBidkOx7WGJcqvEa0K/dRLoNwX83DdoOT3rpYHdJF7FXLU3jC1zVf3lyGRiuwQp
         BI+YZKSqQqaXQAwPYvAjr/B/lS2yxeQ0t0RR7kWKigcR9P81+cqSi7kR4VPBdVbivExC
         qxW3dE9VScl0/N/ijB2tqbEoJEsQiHL8ZrH1giau33u2fUE6p+ytFEY1ANrtgbNYdiAr
         zQlzwriqfVJzTt5GDfXG4DyeZh02orv7VR4m7CVWLYBEvAjtHdsCdYQZhD5LG7PkM+gw
         ZKxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p2OULspfFW2OM5aRYVWdjWlDaLyQeEijl8sl7/AjawU=;
        b=qB9RIcrcNSIQ5V6wb7umeEHfX5dxkYYx8FYPCUg5s/FrcLB3AxG1xbOzcObuYaz1AM
         qs57Enu09uDA1d6h/gGDwvtQp/Px0+eIkBCRZRn4Y9lJleDlOiF0B5d36ypZoL2BVDyK
         Nk7xEdt97Mm+fTn/ajIxGXJHdGhPeYx12lyh5WFslO7V+B9kljIFiOe9tvNMo5oipBjt
         nUviWroaLSezI2MwAFH7AnHpPJcRwnmdQCQy5HJJm5dQI9RKGtpQb1WKNdpdbkuT1sSg
         CO7RCotIWOdJXCPGIMd5myiDi7DzgEyTsvR5bJQBMCQTpYTAkCfI2zkPmxiwYFeqf3d+
         j7bA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531b+Ri3lnamSXHyZTzZBkl4/ebH5wbwensj0S9P/t6lXNxREOFX
	5OpNHW3sUdOTlGj3j6F7sVI=
X-Google-Smtp-Source: ABdhPJwruMsESXuBxi4eEk6rIM7H0qnNg7uUYA2Ird+LOiAPbYvvuDRlPY2orhbRifqsKnJvrItczQ==
X-Received: by 2002:a2e:90ca:0:b0:246:48ce:ba0e with SMTP id o10-20020a2e90ca000000b0024648ceba0emr172996ljg.401.1649110976443;
        Mon, 04 Apr 2022 15:22:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls714998lfb.1.gmail; Mon, 04 Apr 2022
 15:22:55 -0700 (PDT)
X-Received: by 2002:a05:6512:3b0a:b0:44a:2e21:ef25 with SMTP id f10-20020a0565123b0a00b0044a2e21ef25mr359464lfv.333.1649110975282;
        Mon, 04 Apr 2022 15:22:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649110975; cv=none;
        d=google.com; s=arc-20160816;
        b=beTyosfX5Ae8z8T+5uvNR9DMIkh7iguFgxqChtrOSjsef429XeKBbIKwlNeWsnosiR
         wf2MyRBhtZq4/V3ptz9NVTtXV/WjQZKBqpO1tWDlSB+FcAlEHQzNomrNw/0qUjY2DpPL
         Ijt+kfK9oykT4uRo5TpKwNVux4Gt3sdQaq1HEhKBb0ppxIYucdX35OkOPzKXwK5ZVVLa
         CFgdj5LOrlysLIsbY6TYfzD4+7F4HZw2b9AjlzzJxkEysTJ8DNeOQPRvDLAHs6pd2Qtz
         MYMCDtsoT7nf6/Houw/sB61bpomGc/y/Lye4rsD6LoZmfQuX9XEqnXHQOkReEEdccqyf
         qE6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Fsuul6HKe73SdgWfx5cs9D2im7lcVxtKDQkhb0o7Hmo=;
        b=sJ22cBzVLK8pAuYD1bR4qMpC6MwSbWfn+vdIV4sFQotgVA5k5JY9HGiYWFKAuQwaqe
         YiCM6qsNPIVthSJiz+rI54MC6ALS7EoTESYtx6BiFhnMyG34AXNDivMSSnbMTObI8KA5
         wFdLLTa+YzFmaaAmkIatDxknJKEAeFJI2NYnwWrwGwNSYLNegDi3dLd76k9YojwMhP+G
         PIlYUVpGP3u0dC2ntZBwkuISKyH6ZvzkEEr3RnV+E9s4Js+wjMNqpe5pe0Vv78n3BTX2
         +F97I1dFWuaoq/pSKM+LCzJD/F0h6USrC2b2ueDpuc3MW82e1FAZIxXAtZiLe4CszexO
         L+BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dI9HQbt8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c16-20020a2ebf10000000b0024aff6ac16esi578988ljr.0.2022.04.04.15.22.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Apr 2022 15:22:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id BC1B0B81A22;
	Mon,  4 Apr 2022 22:22:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 37DEBC2BBE4;
	Mon,  4 Apr 2022 22:22:53 +0000 (UTC)
Date: Mon, 4 Apr 2022 15:22:52 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 dvyukov@google.com, andreyknvl@gmail.com, elver@google.com,
 glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Subject: Re: [PATCH v3] kcov: don't generate a warning on vm_insert_page()'s
 failure
Message-Id: <20220404152252.af0c9c9127455e9cf5e632fb@linux-foundation.org>
In-Reply-To: <20220401182512.249282-1-nogikh@google.com>
References: <20220401182512.249282-1-nogikh@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=dI9HQbt8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri,  1 Apr 2022 18:25:12 +0000 Aleksandr Nogikh <nogikh@google.com> wrote:

> vm_insert_page()'s failure is not an unexpected condition, so don't do
> WARN_ONCE() in such a case.
> 
> Instead, print a kernel message and just return an error code.
> 
> ...
>
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>  	vma->vm_flags |= VM_DONTEXPAND;
>  	for (off = 0; off < size; off += PAGE_SIZE) {
>  		page = vmalloc_to_page(kcov->area + off);
> -		if (vm_insert_page(vma, vma->vm_start + off, page))
> -			WARN_ONCE(1, "vm_insert_page() failed");
> +		res = vm_insert_page(vma, vma->vm_start + off, page);
> +		if (res) {
> +			pr_warn_once("kcov: vm_insert_page() failed\n");
> +			return res;
> +		}
>  	}
>  	return 0;
>  exit:

Can you explain the rationale here?  If vm_insert_page() failure is an
expected condition, why warn at all?

I'm struggling to understand why a condition is worth a printk, but not
a WARN.

Some explanation of what leads to the vm_insert_page() failure would
have been helpful.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220404152252.af0c9c9127455e9cf5e632fb%40linux-foundation.org.
