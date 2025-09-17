Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWXZVHDAMGQEO2OXF5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id CC3E8B7C52A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 13:57:03 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b0bb71dead2sf410086066b.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 04:57:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110223; cv=pass;
        d=google.com; s=arc-20240605;
        b=ecq7rDvzLsyetm8b82j9JqBBCBrZNrlE6RQzbkRjY/Yk+jx/aYZ7r/FuEj9ncyn1+0
         H49+1sPR6nyUQon/OXnHc4V2QzZ5uhCNa4x8PqnjIlAZTGr0dvSGIRjBFQ/tQxHvWZ0s
         UlBeUei4ZYREaQ8jY4LV7W2r11cxJvGByRVK+zBC1573LrJlG+NvTDE2VY3rtXaE8Eot
         Rgbg+5fuG8lUZPRmO8dBoaE8BF9LFFUM2zVrdvI5Bc5ishoVWF771P3nQK/Afic1Is0B
         JL3MjrIkOg5YSQUsyaOSl9eWdBFsKFSFQq39ZQR4QMQwuIvZ3W4YfeIp/DWXFuS5xSi5
         j7UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=KR2GVbYXFCwQJ7hH3wgwj9ccS0rUVxFw0LdrrOhcDX8=;
        fh=PSzLfo1zEOq/8bLLbjTMAFG8FuTd3VI1WG7LYEFi9fk=;
        b=bW0dsFJgz6DNxeC17C3wAfjfWU6j62XcxLJ0ACqsqgwc6DEIGX5S26WSy8Q8ukAdIL
         SmMDLTX35U+idoUua2MFEwNvLgrRv5+w2imhnoqCdj9VHdlYhF52XqN2sDuCdPm3VqJK
         Om3g/ZvZH8B1B1iUynAseFNHHxOYNFKoZWy0Iis0f+RtgcEDQmNRQBe+e17emcUO8Uuc
         DeFWSm9Acd/56dxywm5oRb1hnnLWEq8gT/LgKSWWYq7vTMYbcjOwVwScvohNCTGhg6hb
         h1Z4S0N/5srv0D8P8BUueSSEHr0nN8Q3yd10zy0AI75m29XOaBg36Uvi28n9htnv3ybf
         oWnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110223; x=1758715023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KR2GVbYXFCwQJ7hH3wgwj9ccS0rUVxFw0LdrrOhcDX8=;
        b=QLfVNOTjfvkuaD6yCn18rWNUxVzz9ZSXDRwrI9717je4ozCErzvIr1lhyxGZ3Ohp+a
         sGhZ4HFEjJmYufZvQWhRsNn9I/YPG2PyPUjNRo7WYzOvECxXQ+Tec6LOoQxTHr5Kz4bK
         sKjlWy9erYa6g/D6Rusy6dxMaHQtuCBt3rpNW+3YiSKYtXC9iyBijerNATXETQkwAfA6
         N+c5wE5S/gvEHOPnch83BwEZkmwaXk78iGQV7ILz2v/TfbJHLuSv0zkfEgr/UQ95khzu
         rhvFOMhRBVNa7lYYdXk10Me5mgjaGMrwmeC39o0RU64uzj/sHD9Ye2KKix526dwAhCpD
         cztA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110223; x=1758715023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KR2GVbYXFCwQJ7hH3wgwj9ccS0rUVxFw0LdrrOhcDX8=;
        b=KdHyUYCI1gUNHHum4Olr0I2LorlbxriBAYKwgoSboxFfGlT0Ptr6fDLSmQjH4YS7Y5
         q1s2JxxHvcOtf7Z8drqGU61AHtmKH9Us2ZPhyy8hDXcC5JGOQ3buMq57Lc+sa7ZJ+eb+
         UZoKZLEaQd/PikoMbqtVIGo08sKbhA9xWuszLzyMZhZ/RH6EUkkGWGCL0JPnyWASGvR6
         Y4RtEcJaYZVFtVbS79CoVj7V9Qzrnu/r6i38LjLvExHeI7hTRpJv5gz17HoLnJSY7div
         xtRm0OrrMP/orKrl52vEUMzMFV4E3Be0utTYQA6cGEY3VvW55GCglCD+51G76GpkrBSz
         9NVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpxo02SxBXOUjiw82MFsO2ZD5xUC7Iy9krEpUSqkGx7I/5Z6J27SuBdJNBiqmkNny4jU0hbg==@lfdr.de
X-Gm-Message-State: AOJu0Yw+re44tcxr62/FedAZFsFhmwkhxI3X+2CYxG/V0ysU1VD1UUxN
	oxTJznRdzQPCGsljXXF+5CpGuNKnlTlSON2ZEYYNtT/PQviTHgi7HcN7
X-Google-Smtp-Source: AGHT+IFRNORwYpCDcjeQq3vG42VlFMzr2tT1/3EkepHGeof6JcudR87qADeJ6FkYn+kcQ05Dhn/jDg==
X-Received: by 2002:a5d:64e5:0:b0:3b8:d360:336f with SMTP id ffacd0b85a97d-3ecdf9cf5cfmr1241214f8f.28.1758100698876;
        Wed, 17 Sep 2025 02:18:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6M+yrffrD50DEO0x5UzcyL9wsUNucqS1W84VB20qHzjg==
Received: by 2002:a05:600c:46d1:b0:458:bc96:3b4d with SMTP id
 5b1f17b1804b1-45e0618382bls34702145e9.0.-pod-prod-01-eu; Wed, 17 Sep 2025
 02:18:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVc0aRA9xE9rHZH28keJGK0d10nPWf+YbOoreaRagxS81woU8ZSvtDtCCR0ExQ64CkU84iPsWTVY8=@googlegroups.com
X-Received: by 2002:a05:600c:198f:b0:45c:b601:660a with SMTP id 5b1f17b1804b1-46205cc8658mr14197185e9.23.1758100696119;
        Wed, 17 Sep 2025 02:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758100696; cv=none;
        d=google.com; s=arc-20240605;
        b=ROd9xZ9fK5ba9JXE8uh9nXeUp2z0GcbtKHLOYcyCB6qF56OrJsEf+5mDVMGdGfxkyB
         XwBKxDXi5Hxk6vQ+FemNoGF/MGpzcscQwygTy2aJK9ES8o4xcz80WleogJOAY4Cjspux
         SK62dOLCLpUDbhEV4WD+IbAu1WkY4RwfdbL+7sKCZLSbjcCE3OKCIBYJ8CqWlnPHEKYY
         NpJVfX7we+dsil9Dqn8f5zc6b/xH6Ngces439OQ5Q137PhQTAX1luBTxtSwxHolIrEbU
         5uBJl7RFXqYXlO3vyS8C9hnSs7D3D9aopVDW+JgbyJfodTzrVlkRWzcxmqjp7HCQp+Sb
         5VdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=/HdoRh34zKgekx7h76Ak8Vo2WP4hVIe9wi/o5NYVnBo=;
        fh=dSLNoNRODuHfrINR08MynOeFNp1Z/HXwcrjRxeBZyBQ=;
        b=UvNIVdNlKRMNWUkTxLxs5yaqE4xL4HDZ4BOMhz+KIaxOrEMpwGtBx3kCWyNX5Urg0F
         iq3ES6Vo5k1EHfVZlrvwdxURfef/vkDm2u0deWw6vBIEtGCvU6CcpYREkp0yyEWeu7xK
         MaJg270EtPkEYfkLiq0s2+loNCeKbzJwjlpqkoCls7EN6+5gTtNsFhozMeWVmzpjX0m/
         SkNvA+eGaoPlxD6+fLdRReXPAHB62yQelObiyo2/Hy7HNTeDedVGo6ztYrU4miJuj2Xc
         tIGuLFlvZPoeToAZCRKwC4ba/6ufPn0Mpb43w2kf8zQ+Itw/0O6F0LzuGTHHKbzW8pNL
         RO3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-462d5169602si52725e9.1.2025.09.17.02.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 02:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 95AEB21DA6;
	Wed, 17 Sep 2025 09:18:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 73F26137C3;
	Wed, 17 Sep 2025 09:18:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id D3umG9d8ymhqHAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 17 Sep 2025 09:18:15 +0000
Message-ID: <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz>
Date: Wed, 17 Sep 2025 11:18:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slab] db93cdd664:
 BUG:kernel_NULL_pointer_dereference,address
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: kernel test robot <oliver.sang@intel.com>,
 Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, linux-mm@kvack.org
References: <202509171214.912d5ac-lkp@intel.com>
 <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.998];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_SEVEN(0.00)[9];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Level: 
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="TBSD/CJ7";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/17/25 10:03, Vlastimil Babka wrote:
> On 9/17/25 07:01, kernel test robot wrote:
>> 
>> 
>> Hello,
>> 
>> kernel test robot noticed "BUG:kernel_NULL_pointer_dereference,address" on:
>> 
>> commit: db93cdd664fa02de9be883dd29343b21d8fc790f ("slab: Introduce kmalloc_nolock() and kfree_nolock().")
>> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>> 
>> in testcase: boot
>> 
>> config: i386-randconfig-062-20250913
>> compiler: clang-20
>> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>> 
>> (please refer to attached dmesg/kmsg for entire log/backtrace)

Managed to reproduce locally and my suggested fix works so I'm going to fold
it unless there's objections or better suggestions.

Also I was curious to find out which path is triggered so I've put a
dump_stack() before the kmalloc_nolock call:

[    0.731812][    T0] Call Trace:
[    0.732406][    T0]  __dump_stack+0x18/0x30
[    0.733200][    T0]  dump_stack_lvl+0x32/0x90
[    0.734037][    T0]  dump_stack+0xd/0x20
[    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
[    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
[    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
[    0.737858][    T0]  ? __set_page_owner+0x167/0x280
[    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
[    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
[    0.740687][    T0]  ? __set_page_owner+0x167/0x280
[    0.741604][    T0]  __set_page_owner+0x167/0x280
[    0.742503][    T0]  post_alloc_hook+0x17a/0x200
[    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
[    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
[    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
[    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
[    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
[    0.748358][    T0]  ? lock_acquire+0x8b/0x180
[    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
[    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
[    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
[    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
[    0.753023][    T0]  alloc_slab_page+0xda/0x150
[    0.753879][    T0]  new_slab+0xe1/0x500
[    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
[    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
[    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
[    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
[    0.758446][    T0]  __slab_alloc+0x4e/0x70
[    0.759237][    T0]  ? mm_alloc+0x38/0x80
[    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
[    0.760993][    T0]  ? mm_alloc+0x38/0x80
[    0.761745][    T0]  ? mm_alloc+0x38/0x80
[    0.762506][    T0]  mm_alloc+0x38/0x80
[    0.763260][    T0]  poking_init+0xe/0x80
[    0.764032][    T0]  start_kernel+0x16b/0x470
[    0.764858][    T0]  i386_start_kernel+0xce/0xf0
[    0.765723][    T0]  startup_32_smp+0x151/0x160

And the reason is we still have restricted gfp_allowed_mask at this point:
/* The GFP flags allowed during early boot */
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GFP_FS))

It's only lifted to a full allowed mask later in the boot.

That means due to "kmalloc_nolock() is not supported on architectures that
don't implement cmpxchg16b" such architectures will no longer get objexts
allocated in early boot. I guess that's not a big deal.

Also any later allocation having its flags screwed for some reason to not
have __GFP_RECLAIM will also lose its objexts. Hope that's also acceptable.
I don't know if we can distinguish a real kmalloc_nolock() scope in
alloc_slab_obj_exts() without inventing new gfp flags or passing an extra
argument through several layers of functions.

>> 
>> 
>> If you fix the issue in a separate patch/commit (i.e. not just a new version of
>> the same patch/commit), kindly add following tags
>> | Reported-by: kernel test robot <oliver.sang@intel.com>
>> | Closes: https://lore.kernel.org/oe-lkp/202509171214.912d5ac-lkp@intel.com
>> 
>> 
>> [    7.101117][    T0] BUG: kernel NULL pointer dereference, address: 00000010
>> [    7.102290][    T0] #PF: supervisor read access in kernel mode
>> [    7.103219][    T0] #PF: error_code(0x0000) - not-present page
>> [    7.104161][    T0] *pde = 00000000
>> [    7.104762][    T0] Thread overran stack, or stack corrupted
> 
> Note this.
> 
>> [    7.105726][    T0] Oops: Oops: 0000 [#1]
>> [    7.106410][    T0] CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G                T   6.17.0-rc3-00014-gdb93cdd664fa #1 NONE  40eff3b43e4f0000b061f2e660abd0b2911f31b1
>> [    7.108712][    T0] Tainted: [T]=RANDSTRUCT
>> [    7.109368][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
>> [ 7.110952][ T0] EIP: kmalloc_nolock_noprof (mm/slub.c:5607) 
> 
> That's here.
> if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
> 
> dmesg already contains line "SLUB: HWalign=64, Order=0-3, MinObjects=0,
> CPUs=1, Nodes=1" so all kmem caches are fully initialized, so doesn't look
> like a bootstrap issue. Probably it's due to the stack overflow and not
> actual bug on this line.
> 
> Because of that it's also unable to print the backtrace. But the only
> kmallock_nolock usage for now is in slub itself, alloc_slab_obj_exts():
> 
>         /* Prevent recursive extension vector allocation */
>         gfp |= __GFP_NO_OBJ_EXT;
>         if (unlikely(!allow_spin)) {
>                 size_t sz = objects * sizeof(struct slabobj_ext);
> 
>                 vec = kmalloc_nolock(sz, __GFP_ZERO, slab_nid(slab));
>         } else {
>                 vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
>                                    slab_nid(slab));
>         }
> 
> Prevent recursive... hm? And we had stack overflow?
> Also .config has CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y
> 
> So, this?
> diff --git a/mm/slub.c b/mm/slub.c
> index 837ee037abb5..c4f17ac6e4b6 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2092,7 +2092,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  	if (unlikely(!allow_spin)) {
>  		size_t sz = objects * sizeof(struct slabobj_ext);
>  
> -		vec = kmalloc_nolock(sz, __GFP_ZERO, slab_nid(slab));
> +		vec = kmalloc_nolock(sz, __GFP_ZERO | __GFP_NO_OBJ_EXT,
> +				     slab_nid(slab));
>  	} else {
>  		vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
>  				   slab_nid(slab));
> @@ -5591,7 +5592,8 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	bool can_retry = true;
>  	void *ret = ERR_PTR(-EBUSY);
>  
> -	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO));
> +	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
> +				      __GFP_NO_OBJ_EXT));
>  
>  	if (unlikely(!size))
>  		return ZERO_SIZE_PTR;
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ead41e07-c476-4769-aeb6-5a9950737b98%40suse.cz.
