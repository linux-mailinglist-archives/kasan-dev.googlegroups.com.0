Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAW7V3DAMGQEQZN4YZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id A36B2B8342A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 09:06:44 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45de13167aasf5881345e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 00:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758179204; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sx+cQh01OIt4NMe/BTLJPbjONtGyqu576tT4CEQfmzg7fvbTJJggvxUw5WATPQ3Jbw
         2Fp8HYn+KMnLULkv0RsC3z/gsl4batuuAXw91KcvOFeomQyg1bU1zQKZjkShWTRKGsmI
         zpMcGfJUHkY7VVvfgLlrw6Y6uX4WXEwuWdDY85ZsYFt8rUUsP7tNg1ixVMmS1o3PziYC
         bz9fM4ciINfg6rkbPu8AFUS6h8slvV0IAg5KtsMUp4i2SOV8yCaf9syIb8XIXrXHojZf
         dw+m0+/QcGdU6hVDmj2XS1HtOezi7VGIrrAtIWy1ucVl7oqXbJQQGnAtNKvsOB/8AIXH
         16Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=bQGpnhRqjX+mbssC0xv9EPooxdbAOJjU+U6muvAWBkQ=;
        fh=sObE6rMw7bsT1KDUgQfw5AtDxcOjYCU1T3nE3Nbk+D8=;
        b=Z7hwzeIaAat8sESlkcfgB1kwDp3pGB0buO/vS5kClTWCCMYpYcC27OmqBcgsU9YvP+
         knZZ9mJCKiFeuBRXeutbQ5W8jh5iXCBgotM9OojP1+Dkh5JYNuCVuwUKeOYiQotAhS2y
         x0hVVteNGoV29XT9B/TWhgN8v8SgbwS7W2ZzF8vHgwNPC6Q3H9FlMwlgpPtKW54Yi56w
         ye4403GYN5+5fJw+oDqg58GEQ1thwThZXxJnF6U5xOX1uJDpALes9mB0Ssh8xme8Yq1l
         KWkU980X1VwlBbpYwDhwlYG9mKM/lE7VuGG8fTxYY2zG+D9NbyWkH4hMMk3NLYaptEp2
         d1dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kA27hBwA;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kA27hBwA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758179204; x=1758784004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bQGpnhRqjX+mbssC0xv9EPooxdbAOJjU+U6muvAWBkQ=;
        b=E2pjMqXv8StET8tO0mXm3J0WJAnSRfztCet0n5gOwHOT7izbA/HT9Su4NYXdNPMHB8
         zU4L/JzqjfGGvCoo1KPyF8Cv0BZPi4orXRJR3uupKXz59RMkKnYZqdoYmGDPD0GSCUY8
         lO342NBbqkXtIfDI8d4FPEfWC/jKRDsZ9POtnnaMZqARXL8NGhPrmmTZxB2rEBi3n3sx
         C/LZBWS0xRoSYZ2MGEayUifWW25OIyGA4WqjeGfVKaQtE3XOEwHrGCgjZnvb5qyw498a
         CZ3Bh9S/RilJYH30yCSIo0DSpS/EhRFtANv7o59Daa7fcFqu8iS7XqSY1VByQrwPcmMx
         m8IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758179204; x=1758784004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bQGpnhRqjX+mbssC0xv9EPooxdbAOJjU+U6muvAWBkQ=;
        b=HCkkwvFaFm10quJQ3PeON4CxJiwbCC/8baNW/5RG1mhkGVKqNktUCv5Djjq4VJA3qX
         RMtrblyQXx/0sRq91BNWXHPfB0dJ/BClCJBTeJqfcanJW7BA6zcQdF7ej4yx5Q8H3OGO
         RwGrnU6FZasha2NrsR6PsC2Gq4pr1+iQA6e7K/RYDISbSvZ6FYA+G1L0u9zk3y4Ls9sA
         WExtRuFlFZkJw3B4Qcibl/as8rIn//eMyGkbgN7esW+V67Kq9vl1g27IamKHaDpOafKV
         MT6qm81hECWgXv7wQ7v3MUV9x9Pt+89qnxMXy2HGD1PBMilJBd7LFdVga7M9UKHoXDt6
         OgBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEQQ/1HvY3YP3LwOvLr0s9tVlrOVjRWMyQW/8IktF7xcEFmGUbt64mCcIOa0e9M3RRwCCYTg==@lfdr.de
X-Gm-Message-State: AOJu0YzUoltMVb44/Ztv0u853+4filRqSpEwX6CZ7ARPsJQ+pkvsrd80
	O8ZZx/4VOdGZ9KhOa4lbTqOCwW4ayMjGgjQJb/0xhjsfQslC8eTYFx+i
X-Google-Smtp-Source: AGHT+IG3mNxKUUwre623jSRworL1+6ANMlLMOGeeSe1Wyx3P5QsupK3YNjvIqwqAkj8i4V8Q0pKFWQ==
X-Received: by 2002:a05:600c:350d:b0:45d:f7f9:9ac7 with SMTP id 5b1f17b1804b1-462021753a3mr44663255e9.6.1758179203641;
        Thu, 18 Sep 2025 00:06:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7dJiPvwx/6IgbZNCiq+XEQonI4sBxTBGGKHFxoliK2aw==
Received: by 2002:a05:600c:4690:b0:45b:bd1e:2b0f with SMTP id
 5b1f17b1804b1-4653f168968ls5229835e9.0.-pod-prod-05-eu; Thu, 18 Sep 2025
 00:06:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0mCXnGGnOu7YIW6tkTd1Aq8mxJyNSmHBtQm4G2fU2oupXmzNiPkN02KlqT5VoVBan4sFCtKBvCjs=@googlegroups.com
X-Received: by 2002:a05:600c:c4b8:b0:45f:2bc5:41c3 with SMTP id 5b1f17b1804b1-46202174cb4mr46608155e9.8.1758179200858;
        Thu, 18 Sep 2025 00:06:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758179200; cv=none;
        d=google.com; s=arc-20240605;
        b=MexDhqPkXspbKUCqx5SF0L1r3jJT5H79/WpWHf10sXl9tFAzLgS+YHs7/1OzHQEAQI
         BzBt4aIEhJFYen0+U9aNExhq6jm08mJMuLuXLYQiEtZSfzWm8jjQbL8aJwupRNWaUcAA
         Xj8KwwnFcct1iOviwM/n8vTHoZd71bpxhfYt1r3Snr1dzWr8iBI4e6lLtsyC3HxsqViQ
         kl0pqimPHTqj9dgVreGcsE3ZSyZCc9bcjlR5MRVzAiRHsIIRgZM8mD3X/6pSKTbURTOU
         AT2uWePpTYmLG4YCEEF9r4FryjKdiOdqYM5DaXVSiJlmgzxnH1z7Vf3vnex5kJhLrOiK
         Znqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=JZoEadOth9tqAYHaBTKYwWwdApoK/1xkW2bLM7y3+n4=;
        fh=ZD0z7iMH/xB62oVR5ITCA7p9VVbZgt8sp9izOh5MaFg=;
        b=WCL0U72ekv0Sjj2ZAISBuZJKblN2DUKZjpbTNlEb30zah1VPKeqN95ps4YeuBX28Kf
         oHAjO7QLjlkUP6Ah7UCAuT20WjsGMIP7OXlBrNnjPG5mm7iPE8dJlWCNoilCSVJ5ZIMB
         LNOK8NNJA63tMZ6qwy8U6ljeGiqxjnyThoPTC8+8ZGaukvHNwPPlFjG1yN/0Z3GrZGry
         9nNRke/ulsbPq3kQOJ/khQvTw0hY3zKB59uxFoyIhz6jUIBJfnwmImHMUJ/Bg1qFfWTr
         9DOfVNPOMEN174QfmSXxgGp00rpqHStlRU04EyldGC+3RpCcgx0r1OvYyVOh8F5R7l0B
         nT5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kA27hBwA;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kA27hBwA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-464f04eef1csi305175e9.2.2025.09.18.00.06.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 00:06:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2482D1F793;
	Thu, 18 Sep 2025 07:06:40 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0743413A39;
	Thu, 18 Sep 2025 07:06:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id NWI5AICvy2hLKAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 18 Sep 2025 07:06:40 +0000
Message-ID: <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz>
Date: Thu, 18 Sep 2025 09:06:39 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slab] db93cdd664:
 BUG:kernel_NULL_pointer_dereference,address
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: kernel test robot <oliver.sang@intel.com>,
 Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>, oe-lkp@lists.linux.dev,
 kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>,
 "open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>,
 linux-mm <linux-mm@kvack.org>
References: <202509171214.912d5ac-lkp@intel.com>
 <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz>
 <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 2482D1F793
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_SEVEN(0.00)[10];
	DWL_DNSWL_BLOCKED(0.00)[suse.cz:dkim];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:dkim,suse.cz:mid,suse.cz:email]
X-Spam-Score: -3.01
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=kA27hBwA;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=kA27hBwA;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/17/25 20:38, Alexei Starovoitov wrote:
> On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> Also I was curious to find out which path is triggered so I've put a
>> dump_stack() before the kmalloc_nolock call:
>>
>> [    0.731812][    T0] Call Trace:
>> [    0.732406][    T0]  __dump_stack+0x18/0x30
>> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
>> [    0.734037][    T0]  dump_stack+0xd/0x20
>> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
>> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
>> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
>> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
>> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
>> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
>> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
>> [    0.741604][    T0]  __set_page_owner+0x167/0x280
>> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
>> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
>> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
>> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
>> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
>> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
>> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
>> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
>> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
>> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
>> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
>> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
>> [    0.753879][    T0]  new_slab+0xe1/0x500
>> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
>> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
>> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
>> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
>> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
>> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
>> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
>> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
>> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
>> [    0.762506][    T0]  mm_alloc+0x38/0x80
>> [    0.763260][    T0]  poking_init+0xe/0x80
>> [    0.764032][    T0]  start_kernel+0x16b/0x470
>> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
>> [    0.765723][    T0]  startup_32_smp+0x151/0x160
>>
>> And the reason is we still have restricted gfp_allowed_mask at this poin=
t:
>> /* The GFP flags allowed during early boot */
>> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GFP_=
FS))
>>
>> It's only lifted to a full allowed mask later in the boot.
>=20
> Ohh. That's interesting.
>=20
>> That means due to "kmalloc_nolock() is not supported on architectures th=
at
>> don't implement cmpxchg16b" such architectures will no longer get objext=
s
>> allocated in early boot. I guess that's not a big deal.
>>
>> Also any later allocation having its flags screwed for some reason to no=
t
>> have __GFP_RECLAIM will also lose its objexts. Hope that's also acceptab=
le.
>> I don't know if we can distinguish a real kmalloc_nolock() scope in
>> alloc_slab_obj_exts() without inventing new gfp flags or passing an extr=
a
>> argument through several layers of functions.
>=20
> I think it's ok-ish.
> Can we add a check to alloc_slab_obj_exts() that sets allow_spin=3Dtrue
> if we're in the boot phase? Like:
> if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
>    allow_spin =3D true;
> or some cleaner way to detect boot time by checking slab_state ?
> bpf is not active during the boot and nothing should be
> calling kmalloc_nolock.

Checking the gfp_allowed_mask should work. Slab state is already UP so won'=
t
help, and this is not really about slab state anyway.
But whether worth it... Suren what do you think?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
e3be467-4ff3-4165-a024-d6a3ed33ad0e%40suse.cz.
