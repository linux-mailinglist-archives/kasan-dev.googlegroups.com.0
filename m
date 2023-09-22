Return-Path: <kasan-dev+bncBCS5D2F7IUIJTDNVVADBUBA7PR4LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 84AD97AAAAD
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:47:39 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-502fff967ccsf2172027e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695368859; cv=pass;
        d=google.com; s=arc-20160816;
        b=wylu2f3NItAN5laVlybj3pjnKC1kqeYsCfnNZ8XxqifZ+1XpB6uYzGk+ty7K9LoRHj
         +CsC0kdUg14J+NGUy2RlAb8iBJlxohbYtOQ2dU0LMlp9AkyzJbKCyzQUCcNFEqBefvPe
         WcbDoXUgZ9TE25rOqY+ATs/qKHu1MVkbST0+QL4VrorFiJse8N9XLTL6llz5WkE//Awb
         W/HWnaSgy1hZyR2xp2y3wyT+ia5AZDUV4Iu3SpFibHUKgnEX2iF6UR8xeK42n4g/Dxdb
         4oZML0Gnfd2HgJrOnKFMnJeNLj6Ubpb+85UeVpBoDEuSkSo84gjvBpExGmyLtBDwYoW6
         vFFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TiSbcyeJNfO7jMCpz/fK03nEro37B4Y9GWkvF4fAd2A=;
        fh=trpnYWfTNd13yDurm36qzuGYoHnnP1N+m/SMOchAaMI=;
        b=Fk+OFl1WhuDVr4ZkhPg/1tj4VIC1gWtmAM4F8y5q8m/9jWlD8ompBBvfNet8m7FjmX
         ZDwciZ4ezuk0MvxuGituB5XgJEWJfW/qQw38QbVnVbRmEle0rAUEcztJ6n9zOs4Y5U5R
         PPzZka6aUpPaBpkpU0tfZheowL1/eE2s/payPUF9R/2/7VPREtYB+oDstmzPvDQU8OIF
         mC6Q485cZW1KQD64v2kWjfB0VCvxQ8hKtfQVKs4shsQikVN512xl3J48SCtuT4bys0sV
         Lt5HvXl+kjZUiNQz3dNMjd/ecahAzGGnRUqKU++jRmibRvLajH1OMQlWJrxpuTJj9hhw
         a/EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cxr2t9Sc;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695368859; x=1695973659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TiSbcyeJNfO7jMCpz/fK03nEro37B4Y9GWkvF4fAd2A=;
        b=kJ2+4l9ax89pTRRShfre6LD0ta40bCQyEGLLEGedJrytsp3S3E/hZUgeOns31Qv2n4
         6gyGQN43Mua43W4WZW2GxFyqS+S46huGAOVYajphEf+mRcJN0EXe0aOdcVos+rH7lplO
         9qx/hAR1KGlnggbpXXFF9m3UN5WIgE6jfFS4cz2gjilqVk/tRjukb8G7AjFihGEbJaLn
         Kast3CCdH9k7f9TZHPS9cMQxdMPPezJqEJynWF3jcztiYs1TCER8RmVLYG9pARbIU7Jl
         v6eQ0O7q/q0jzj9zpHX6FLjrJEKhChanpgWtkkjoxsPQzJ0Nv0fJXz9EQqa0qA5CkNtB
         bdaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695368859; x=1695973659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TiSbcyeJNfO7jMCpz/fK03nEro37B4Y9GWkvF4fAd2A=;
        b=fpfMXPcuWPONVr6z1w8PbP5DcR6iKoGydjBHNEmVBXiUXqB4QwyUFEjTUg5pGPzMxR
         L10zp3tXj85X+8kVTLbQMACxVjotFXdG555EIQjibUU+HzdQG3MfK5XR7OEhVr3dXU4k
         mgx/4lmHF50TUPvjBGLKlpYHBjvzPriOL1m4E6FKAszE4gKTBkAoCNPVzLRzsiRHimaE
         xvs0rTDW4PNl5pMv0iXhVoqrZD2eif0jYmdIlGzjjZPC3OXLfcZvusaS9R0mVpeNHIjV
         BB0VfE5odOOaSsv5HO3iFiSKmMyLXVjy/FNdqSdh1DAttQnka9VtBoPoAIP26BmHEaCk
         i46g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzMfgW12KZka9GZwk1+3hWrprSA6SXwxEEXAwSdsWqwJvbXLsYj
	D5D8ziNupblZLMe+4CUbA6Y=
X-Google-Smtp-Source: AGHT+IHYswHB84+IBeTfi0lRug5hXeaFmDjZZ5DHGr/N1au8xWFs77fwu5ebDfgZbRH+4NtcD3mTZA==
X-Received: by 2002:a19:5f58:0:b0:503:3753:9db9 with SMTP id a24-20020a195f58000000b0050337539db9mr6626870lfj.35.1695368857985;
        Fri, 22 Sep 2023 00:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5b87:0:b0:500:9b76:ced2 with SMTP id o7-20020ac25b87000000b005009b76ced2ls495127lfn.2.-pod-prod-03-eu;
 Fri, 22 Sep 2023 00:47:35 -0700 (PDT)
X-Received: by 2002:a05:6512:281b:b0:503:256a:80cc with SMTP id cf27-20020a056512281b00b00503256a80ccmr8808994lfb.42.1695368855761;
        Fri, 22 Sep 2023 00:47:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695368855; cv=none;
        d=google.com; s=arc-20160816;
        b=WQUJ4JwKdQYu7UsRFxYcb2ZUUEAtKRe0mxudL38yNCgoqTMnkKdgNqErS+TcAvO1Ap
         NUG0E8ME2UXFsEJpbs0rAz4Vwl5zDgPidrrRV+q9Y2VJuoFil9vWa7E3k/IFt2divRhw
         ib5npO/+gHHg3oM34N5lZXsrkk3/Fb5IpJzO2hsgiWcqm10BGmJP3hvUVEKhe5A0Znx5
         63/zDI1nYSJoyHopPMU29amI17uBE7A7AvkYL40Kl5jsSBqiKZI0dPTRE4aVCp8XD95J
         MHdDYuYjfULHZU5b6CRg65ogP/uN8rkTnVU4L8YcJfIgvV47u4UtNlJr7fdfhlArH4XH
         g+5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=67+5P8IA4r3ycxzRXf9uS+CTU1WKObU4FRulN1vPJqY=;
        fh=trpnYWfTNd13yDurm36qzuGYoHnnP1N+m/SMOchAaMI=;
        b=IVtTMR7Rn74oZjqLcDgyWSFwTf1I1jY3PaE7xAecEqeen14aFxpa6d7QtnxaXt5PuA
         ErpJjDOVRLgigzsvQqSm8k+pbdoRyzam4R6XrRbEEyeC+FW21pby+aPPHTDlNo30SPt0
         HbrOyMbGXia9PlXb/AtCwhxclrN/C+F/92rji7qyqQ+c58dHlYQ0tB35Xjt4xAXxj5hs
         pMyDXZQxo8imQ0EDQOmPRmiMvLCs5TTNqp3C7QBKIakNicdorC24x51kXY0FCeI0eO/L
         lrkqgVAnXRzhKPl5y49p4Uxm0Ss8I01M63cy4Rwjh6EaYSZUITX8zLgcBL3PhNdETEG6
         KU0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cxr2t9Sc;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s8-20020a056512314800b005032919f892si243597lfi.6.2023.09.22.00.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:47:35 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qjasd-00H0QI-U7; Fri, 22 Sep 2023 07:47:15 +0000
Date: Fri, 22 Sep 2023 08:47:15 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Yajun Deng <yajun.deng@linux.dev>
Cc: akpm@linux-foundation.org, mike.kravetz@oracle.com,
	muchun.song@linux.dev, glider@google.com, elver@google.com,
	dvyukov@google.com, rppt@kernel.org, david@redhat.com,
	osalvador@suse.de, linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/4] mm: pass set_count and set_reserved to
 __init_single_page
Message-ID: <ZQ1Gg533lODfqvWd@casper.infradead.org>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
 <20230922070923.355656-2-yajun.deng@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230922070923.355656-2-yajun.deng@linux.dev>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=cxr2t9Sc;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Fri, Sep 22, 2023 at 03:09:20PM +0800, Yajun Deng wrote:
> -		__init_single_page(page, pfn, zone, nid);
> +		__init_single_page(page, pfn, zone, nid, true, false);

So Linus has just had a big rant about not doing bool flags to
functions.  And in particular _multiple_ bool flags to functions.

ie this should be:

#define INIT_PAGE_COUNT		(1 << 0)
#define INIT_PAGE_RESERVED	(1 << 1)

		__init_single_page(page, pfn, zone, nid, INIT_PAGE_COUNT);

or something similar.

I have no judgement on the merits of this patch so far.  Do you have
performance numbers for each of these patches?  Some of them seem quite
unlikely to actually help, at least on a machine which is constrained
by cacheline fetches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZQ1Gg533lODfqvWd%40casper.infradead.org.
