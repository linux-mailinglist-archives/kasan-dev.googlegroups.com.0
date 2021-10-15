Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZ7WUSFQMGQESWXHMUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6383842EC41
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 10:27:20 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bt36-20020a056512262400b003fd7e6a96e8sf6099868lfb.19
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 01:27:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634286440; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZfV7suSJyiWdE6mWhX3qX4pW/NzeTS/sq/2hPkStgJdt2Y3e9R0hIu69yXmX+8bQO
         Ct6YLQoCq487cRmNkPwIRe0srAklmakRc4LEgd7S9TBVrMBAh6F+cjlJYb8gix7xaZXk
         B6AFr5wBzKmFEXNR/pVOhv3d7wpVsUhgJAerokvwygro4pzWT3lxxho+ObFYDH6sDYEW
         noEspCOZVzJdskOUt6kvHae1H4k/v102qjK1BTQ7h+9YeCsmEukX0IVrQ9AxWLQ4rLYW
         E7PZYXvTQf/qBp4C6eJst0R3OGRvp2DCCMpF9bFbrTzowXmojbIWyRrrjVw/4Jc0mxmI
         1s2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cN+ynA1I19ja2uVaFnoQOQGV9cZF2yEakZbpnZO3I20=;
        b=cxzI2ryOnEnKOB7pyhQ6nw9cqfjZXBi/wwOj2hRNRGm8IL/qPmutDEnbl3uaPZVWQw
         KvNYIHSrMg5A4S0GQN9WqfxrH7SJJnH4hMoiBpJRSbEo3OmruGISomBOjhDHRowQfU7r
         GEGrDH/eQm/s3wbUQzNwjZ0lat65nmMbL3J2qdk2sxX2q64YsLFMZ2cK/YLDiXcqMMTn
         GCdkj7QrznezVrY4xnTiTVrBqT/I+l1ejHCuFaoa+6H4zbsHwfs48xsivIxxBLxg4Iv2
         8+T30NcSwJV37eD7y/JeV4BjPD8ORHldk7rTG1YmibxsrQjlvDlhXWk0cC6gXs/pD+Vh
         Fjpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jTXff+NM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cN+ynA1I19ja2uVaFnoQOQGV9cZF2yEakZbpnZO3I20=;
        b=blAnq9FFDO3nr+ou++nW3IV/AxMjM6sN3Tw28R8g9YIAjfInW6UC5NM0m3BLfEvCCO
         GdmdGmkxq5ruAfI7EFwwq7xmkUoXITjxb/N7D/hJEe3z927tDOMfYw/NpwbxdgI+rL1a
         ncCzYJMIbim4Cj3wklaDG8f5c6vrWgyHPneUZ2KGDgIq+16TipUyRDAwMta03nSXX+bP
         lWUR+Tce5VmtboPpWg/7oE8M9+xpyKNTMvQTHdCKXzOkVdlAE7oEW/146dkAv3YHpIdS
         OiRqtZdWoQZVo+3iZtbVcuTtHgoZ6ijDsrlQPaARkzJ7ckFY7qRHNIn1DrhfzsjxgNAo
         cU1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cN+ynA1I19ja2uVaFnoQOQGV9cZF2yEakZbpnZO3I20=;
        b=o6FVbs9Of9AwemNygMp2IkS+plL81fEBBntpTX0PTjn8ngMoOTZW7Q86sCcZmnR6jP
         pJ3562WDHZMswsJLjcJRlrU9QbIY60uC0h7TxMt5hZ2KmPfqgZLltIxVmqVMLLRrhY+p
         XU0hv9otST4/qI+0wqemDhOljjno5P8mr8086o+fkh0ZrwKrCbvgsRZhiIm6VfnRDCZo
         dHyKaPOTbs4X+ns1g1qIkq944NquFLRrGltRoHVDuFUMOTxHWdCCpiZrRMgZhu5CSIyJ
         JovQspSUysHQojRvV1DAJpSg+Cl00MZ4hZYxxGBgpg58bDWTWHcPFn1ETpFcK3PC7oLx
         +04Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kfIN4rrhT4+7TOpB8+BeoVPEga/P6JnYnBegR4kblPP+69UNV
	IcUlMHz4QI1aemtyl8ZGBw4=
X-Google-Smtp-Source: ABdhPJyvtOZ/dyZGo/6i63lLWLuvtBher055B0Qw9Q6Y2YTK+0lH1bj7wXlna3R79fYyITZuJD3fxQ==
X-Received: by 2002:a05:6512:3da6:: with SMTP id k38mr10178787lfv.545.1634286439925;
        Fri, 15 Oct 2021 01:27:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls1720900lfa.1.gmail; Fri,
 15 Oct 2021 01:27:18 -0700 (PDT)
X-Received: by 2002:a05:6512:1054:: with SMTP id c20mr10285335lfb.59.1634286438727;
        Fri, 15 Oct 2021 01:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634286438; cv=none;
        d=google.com; s=arc-20160816;
        b=bPLpkHPf6bHAKqVH/H5Z3FuCQYOzqPANt07s8awX/OQzj5cUx8p3U4N75zkUxTSvdc
         xehsAQOfa7GStoeU/n1LQAL2BozE713TkFhYfXdNiCZNZmT/oP898WIYJlTVjMHMGAdX
         GF0me5pbTXSi58B9pb4jtkMhvkJT/YCe8QRfaKal3zicc0e4A6ciNRMtJ8i8I52T1Vwx
         4o5hiwfw1roKWwM8Iif7f/SDNTyVaX308Lv9ZJsG42ceIpuRepahD5+EQrod/HTYa92r
         nsfJCyTGMGyctGm+TARnAwC+Mt7+oP8wyG4aPXOAZ3PVWhhmEw0O5ci1w7FJiwejgfWX
         ytSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=XH1hXLqLnxkTOtk+fqniTFsoIzBDMQNj7gJXWTZhb68=;
        b=r9BG6RPfwmrIHfURETbW+40LloL9gdRGE/2l9LmcwVkH+PvT+9najUp+aF/iy1o6Ay
         Xz06dzsf9RIm5Iv2QZjJAbRI+tb1jM6q+UfF/f9NmsM97dChb0QRD+wNihlFU6KD2pPw
         ZbpSGpeogb+asIRcXcRw0a9KmZmi6EdK9I1bt3iiSYQooa8CJw0hITUZgWmolpWutipV
         4O5y4q9aR8AtHNqlyKaxr9q4L01tIaEBy7PcHLqBy7SVHJy5mlMrk7xOupRTAIZRNu5W
         AQ0t7Lg4hKnbRmATsu6ufpfKzPFAXENl3Uxbm845h7WgjaIX8xmJ71+uxJsn9MaLIXsm
         XeVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jTXff+NM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id t12si309348ljh.0.2021.10.15.01.27.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Oct 2021 01:27:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id DA3BC2196D;
	Fri, 15 Oct 2021 08:27:17 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 838AE13B87;
	Fri, 15 Oct 2021 08:27:17 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id DTlAH2U7aWHKCQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 15 Oct 2021 08:27:17 +0000
Message-ID: <137e4211-266f-bdb3-6830-e101c27c3be4@suse.cz>
Date: Fri, 15 Oct 2021 10:27:17 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [lib/stackdepot] 1cd8ce52c5:
 BUG:unable_to_handle_page_fault_for_address
Content-Language: en-US
To: Mike Rapoport <rppt@kernel.org>
Cc: kernel test robot <oliver.sang@intel.com>, 0day robot <lkp@intel.com>,
 Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta
 <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>,
 LKML <linux-kernel@vger.kernel.org>, lkp@lists.01.org,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 kasan-dev@googlegroups.com
References: <20211014085450.GC18719@xsang-OptiPlex-9020>
 <4d99add1-5cf7-c608-a131-18959b85e5dc@suse.cz> <YWgDkjqtJO4e3DM6@kernel.org>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <YWgDkjqtJO4e3DM6@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jTXff+NM;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/14/21 12:16, Mike Rapoport wrote:
> On Thu, Oct 14, 2021 at 11:33:03AM +0200, Vlastimil Babka wrote:
>> On 10/14/21 10:54, kernel test robot wrote:
>> 
>> In my local testing of the patch, when stackdepot was initialized through
>> page owner init, it was using kvmalloc() so slab_is_available() was true.
>> Looks like the exact order of slab vs page_owner alloc is non-deterministic,
>> could be arch-dependent or just random ordering of init calls. A wrong order
>> will exploit the apparent fact that slab_is_available() is not a good
>> indicator of using memblock vs page allocator, and we would need a better one.
>> Thoughts?
> 
> The order of slab vs page_owner is deterministic, but it is different for
> FLATMEM and SPARSEMEM. And page_ext_init_flatmem_late() that initializes
> page_ext for FLATMEM is called exactly between buddy and slab setup:

Oh, so it was due to FLATMEM, thanks for figuring that out!

> static void __init mm_init(void)
> {
> 	...
> 
> 	mem_init();
> 	mem_init_print_info();
> 	/* page_owner must be initialized after buddy is ready */
> 	page_ext_init_flatmem_late();
> 	kmem_cache_init();
> 
> 	...
> }
> 
> I've stared for a while at page_ext init and it seems that the
> page_ext_init_flatmem_late() can be simply dropped because there is anyway
> a call to invoke_init_callbacks() in page_ext_init() that is called much
> later in the boot process.

Yeah, but page_ext_init() only does something for SPARSEMEM, and is empty on
FLATMEM. Otherwise it would be duplicating all the work. So I'll just move
page_ext_init_flatmem_late() below kmem_cache_init() in mm_init(). Thanks
again!


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/137e4211-266f-bdb3-6830-e101c27c3be4%40suse.cz.
