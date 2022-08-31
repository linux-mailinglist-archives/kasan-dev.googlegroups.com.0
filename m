Return-Path: <kasan-dev+bncBDV2D5O34IDRBNH6XKMAMGQEAOQQQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E0385A7395
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:53:57 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id x9-20020a056602210900b006897b3869e4sf7843703iox.16
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 18:53:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661910836; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSdP4RyqPFEiO5MvGjxTTbE4bGCJA6APpmfcgj3JinYeqfNXJO4e7OzzWCFWKZf8Mw
         CTeJCQwUqQRPJ3KWl3O6oHLexo3gl+qRnKLtBU8nNEyovZcyigp299CXAQku0mf+eH9a
         Akz0IjuagVqkbFceHVKQm0DINV9pjdedcEpeOGf/sdjF377VqCWKwN8w33Y5KlGjyeDl
         8DqnBK5r0jUQS3H7LRJhyFyMTh7VDBfyTgrrGL0eoV2rm/8znKthQfnHqU2wEIGykLEW
         UfHn6YzikMa9e1QwwTzCb0DmfEI2J6zctIoSlq3IzeFrPNX8uU6I9kJPAyc7ndy1yW0i
         c/jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=n7a7cVoNllTr1Zre4ztJsckJg/mKDDUjl0vrOPd+Eek=;
        b=v+HzekzemBFRcl2YzcNyDXaEqSMcsRcgt7ZxUFABzf0N8S6tU2fCEzasUkVA/SGlpv
         VCksx+1LAgg1e2G0wWicDew4zNRIHnXZGI3Wr76TcQAWEgye5KeZRUlFJipDNkJMJykh
         F2Ab4XPJCO30u9vZ/ly4G7b/3hAlr9Y6iWLblQqtCFT4KUc+wPBL0NvT8g269PbCCNeG
         3MdXzgH+2aFulefVuAncpdzFRfiSUEfJML5vXFnoE3RZNIwhTzXRCI6fuF4vLPRyZ4X7
         Syn6ztDRCccIOAykCohv7G6bxoBN7gBpl/gaKFaJwkpOiRicpb8hkPQyN5+ZA0gA2Gc+
         ukpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=QysnhHPV;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc;
        bh=n7a7cVoNllTr1Zre4ztJsckJg/mKDDUjl0vrOPd+Eek=;
        b=g79fCGrPpOfhMuX4iWVDiaKa/CfNaZjEXsh6ibXmtNdpqBTVPnfdpROord46+CWN12
         ok8QYPxTS+UPCDRE77ylyM8visQj3n4wKLb9DUn76SRm+y8W0h0Z0He739TTRJLOIOll
         aw+2rAjiTjwF99pd0UnLZlur1RbpvBwfPSUREMDBWxK2zub8odKFmXRBIYpVmhwxMRPc
         IlACarwdAl1tSbFsqt9vXEZjYF5UKjobGtePI0qlH6Io0VQWfyDvYUqEnTHCWZa0Cvr2
         0xcA0reuE646RiPIIm7PYl3ipx5w7xC96Lzqcah/XFVyqSOkdpeu6FjgFsg+cwOMpOEt
         uOtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=n7a7cVoNllTr1Zre4ztJsckJg/mKDDUjl0vrOPd+Eek=;
        b=h7x8PPpDSyc9Q4ppPfCpKyhpeCtrmWl+14WSisE4ZumwGrOeKRO7xZX8bEekve7E1U
         8GsIDQ+SphZZ1PTiAPeyYIWk4NTwQO8RqxYUpaQ1RTDTG3rMjjskw2d9tgyxyTn/ekPm
         ExogTmWksQYD/y2LCIPQ6oi9y5qqZGHdArTxWFCsMq/oNs5MvdpJoy97RI11ukxUPnMS
         8+ybhylvqm2192anA7kRl+k94kul+E6ybqRQwS4oc6Z1UtMwT2uQuIJjsvdLdZSohP1c
         rysu3IJTsbmt3GNE86HsAmhV/vuImH0DOzg/m05+ZHkwkiTjCJjR4CnKVz+JZqxIrjHM
         uGvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo06/6LvkmUifsl3tKfP8oCQEFY2+wdNGbmx1bui1+4PemAaWetn
	0fxm3SWS3xT2wO/Tq3tQIpc=
X-Google-Smtp-Source: AA6agR4H5k2Gr1sgkK/ZYp6Vno/Wg0YxoB/Yi2cvHdjcG4Am7gLmxylgyQ3ydrSiqcoxgXYsNcc7MA==
X-Received: by 2002:a92:d12:0:b0:2eb:5775:79a9 with SMTP id 18-20020a920d12000000b002eb577579a9mr2683516iln.25.1661910836278;
        Tue, 30 Aug 2022 18:53:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12a6:b0:2ea:c20b:a232 with SMTP id
 f6-20020a056e0212a600b002eac20ba232ls2169856ilr.9.-pod-prod-gmail; Tue, 30
 Aug 2022 18:53:55 -0700 (PDT)
X-Received: by 2002:a05:6e02:b4c:b0:2ea:83a7:bd29 with SMTP id f12-20020a056e020b4c00b002ea83a7bd29mr11299939ilu.55.1661910835866;
        Tue, 30 Aug 2022 18:53:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661910835; cv=none;
        d=google.com; s=arc-20160816;
        b=WA3X7+5flGuqD9Q1pkW5jPAimax7QNRDpLYC4fF7fddnujotvz3JB9vv5AaCt+W/eb
         cL+UrZUkuDq2dKik5TOHBfuBx3VdR3nire9GhS7WSRJc/+XbqOpT/8d17rdtBnLnwZec
         omJE6jzoKDm5jTv77mXV72gMMlYx4m98yItWPgLFlfbLymIJiy6McZu7q1B7xI2t7AR5
         geNBA2bwrCqSLa2sx8K/0LlwntckDV3fxW0EugHbcB64OxkAkFeOc6eVj0TgKzioYGPe
         ffNCXeabXirhic0tfFKp+Q7R0onUO+Pq8DxPEH0egFatSe+Gr4FUlsGuy4uEFmFSYFfx
         7Rkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=RhkN3pjenFJ3Z4sU+BUfbopmS9x7erS/IYHXt0Yrgys=;
        b=bNI2c7UyEBVRYHvHUDm/hUHhIdbu8xO6ewPhcgPYC4lFrk9+vkLLHcirOVGAazeI7v
         A4kDR8y55tEuwM+d7zwpNtP34crTYxnMhfkCrGwi9T1F/j8bjiaVA3WvJI3zkl43VnFQ
         mthocK0qT2bfv+c3wSJ0JDlsnIBnv2ndinFclwmIoNedSI9zxoUGDZ4yZ9ErG2BUIRo+
         bzvx6hWf9qGVcwjeniuDfc78M4Z0sYpv1hvXQR/bfaAZxgeKPhoJfqise+zdlN9DYR9V
         6gxu5QzgKGp/g3PN/lqqHwPrXWYbMfkNlhzMZPW536y2HCSIf/esb+hPY92NIzA9L2A2
         M4lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=QysnhHPV;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id s8-20020a056e0210c800b002eb7fbf5c8esi56854ilj.2.2022.08.30.18.53.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Aug 2022 18:53:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c0:6280:3f0::a6b3]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTCv3-0036yC-Ja; Wed, 31 Aug 2022 01:53:29 +0000
Message-ID: <241c05a3-52a2-d49f-6962-3af5a94bc3fc@infradead.org>
Date: Tue, 30 Aug 2022 18:53:26 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.2
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20220830214919.53220-28-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=QysnhHPV;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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



On 8/30/22 14:49, Suren Baghdasaryan wrote:
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index b7d03afbc808..b0f86643b8f0 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1728,6 +1728,14 @@ config LATENCYTOP
>  	  Enable this option if you want to use the LatencyTOP tool
>  	  to find out which userspace is blocking on what kernel operations.
>  
> +config CODETAG_TIME_STATS
> +	bool "Code tagging based latency measuring"
> +	depends on DEBUG_FS
> +	select TIME_STATS
> +	select CODE_TAGGING
> +	help
> +	  Enabling this option makes latency statistics available in debugfs

Missing period at the end of the sentence.

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/241c05a3-52a2-d49f-6962-3af5a94bc3fc%40infradead.org.
