Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFGFWO3AMGQEURVFJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BF77B95FA74
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 22:16:21 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4280645e3e0sf42478105e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 13:16:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724703381; cv=pass;
        d=google.com; s=arc-20240605;
        b=iSLgpzlr3Y0w76PxoAkMLUgkjuyL5iJEZaJkk+GqjMx0ZKApr7XGbCdNX8lpzZ/ePR
         kDj4aBIaBhlD+Lj0ss41MVkYJezzn1wFQ28Qp/40JtW0KiJRjf9F22xIK4YMAEX8tpir
         JSP7GZoiKlTBeVIxr0eu27e9dOvVZzjhVp3fLe7iUBxtB6+KP3uRbki2ZGemu+b2XgyR
         /P7ZtoORp3TZLydloj6HK1F51Ds7ANW3Dwv/BmMLu0NU0uFv27NVRi6EcMqDuYA9Q4hP
         0oI8pc7TQdh+ODL0oU33EZdJuljp0268KGIooqDD4qYnMGBVGZhS8II2VX4h2R0oL/Sj
         yRzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=YK2JQppRlsnc1yQuLSKQU5TUNO0XPzU+qAiwWYe2JVA=;
        fh=wW8HnTkOcbogeJa5qcJfe0hJ6u/4pb4d4y9eJujFxFg=;
        b=W9LyFZDTJXLyUx+cK+HXtyaJJ1SedaH8r5pZ8FmOu1VSdANKe7zrbfE3lbArvFq95E
         Srp+ZUK/WLvO4XSX0P6t9Dj5roCNaG6eDtVfUy8Rp9x+mjZbYCGke0c5CsCT5/pHSKDQ
         u7d86HZHEpqGnHeGYu9sS7sLN0RpXuA6rMKP68Ti1B4rbezYfl84EfMotKPEGfcqZZg7
         52EKskfwAFpvVS5sVjLgJFZehV48dJQj4Nk78FXlMGIlpEfrSzp7xQVqeT300ldUr4Qg
         wmk3fUyQg7vRnR9+m3B3YTCgzQDWjYQP1byEbeTkEychOWWnYyGw1r1ZwKOXTjZRKi1N
         AAWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpfPXADs;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4WdmPyJG;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wt7TmSm+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724703381; x=1725308181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YK2JQppRlsnc1yQuLSKQU5TUNO0XPzU+qAiwWYe2JVA=;
        b=O+TDFf+wrgdUJkHUbDAgEM4qIMVUkgCCVsFHgAUHpssTvEoPFnZNChDxIhkz8Q8128
         lk3cm4EZraVL1Pa9rsJQ0ak4Gq/0zp9GZZW0SaR2KyxUO3zjPDvM42snp/+tQVmtDVdP
         hYXhmj+VBcPHt1SzAIHiv8sEdc2KB/QE+csrA1a8ZTwxitEAeF0AO1iUSglLHJb4FBsK
         DZ3J6LfKn2pxLwBJi75JcRBI7ccqHTnS5WjVFnOI7HNb8bUeP7hQGnuls2XyLLyz9Hai
         gqQ99VONuulQh5LEQhgq3kD4s1crr8iHNKXlkPiDSwAVzh8HqKC0KEQ/EqQHio/Wfamk
         b6pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724703381; x=1725308181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YK2JQppRlsnc1yQuLSKQU5TUNO0XPzU+qAiwWYe2JVA=;
        b=Kfwn4H4XiAp9P6GnycvFrQwNUdKbyMXcrf6nI85KfZDjS0jMmWfIrJh+KfqOXU0ZAn
         GnoivV22+jqba7cX5F5oSdTxDsOy0vv/PUnuMC/oU3UzaVgHXJuKsAkVNihebj6xqQCS
         QpY3bBDiDWyZxKJMOsksHQ/lXyRUAAgx4gFsZm27JqDoVp5fbWe0DKV6uNAoebblYAst
         J1eTMjFXlT549AcV11B+XJLjjDwOCcakUzeM+hKWbmW3bD9sIKQwoi8o4L2n5lEf57E/
         upHkjezDtxckPxUmxpEx8PSMdll8QuzVAWr6ThIVBfut656/2sGecmzLLEJrbm5CzNcZ
         joBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUm3ASZTD0B7iOISKMH0I61dYU5WqY2o/Rkqhz16J07zoTGgnUA/7y5YFzGFS0nD6py4ELwxA==@lfdr.de
X-Gm-Message-State: AOJu0YyW73F5TDKiiAPSY/6z3DsPaXkR+U21Gs4q+jIUXHIwFmNjd0L1
	/QFFHmS0jbm+Fp+2h/oUhFWAnLKr9V5R6fpEUVtDwhbckbxFnA/r
X-Google-Smtp-Source: AGHT+IEq0NWZJ5+Xo7DHu0EAlOjOsaKz0ulASi544P1zOO4CHjcQleD9kC2B+YMS7Igsuh3YgYKyrA==
X-Received: by 2002:a05:600c:6d0:b0:428:2e9:65a9 with SMTP id 5b1f17b1804b1-42acc8ff921mr75386505e9.28.1724703380408;
        Mon, 26 Aug 2024 13:16:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1396:b0:426:68ce:c965 with SMTP id
 5b1f17b1804b1-42ac3de4e80ls1506885e9.1.-pod-prod-01-eu; Mon, 26 Aug 2024
 13:16:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDpAGbh88ULfwQwI+wx942TEqTGcDw0ZTwDmoqVhKbmmND3AM1RyGzYX9MZKh/v6fQB3L7G3ytU6Q=@googlegroups.com
X-Received: by 2002:a5d:47c2:0:b0:369:b7e3:497c with SMTP id ffacd0b85a97d-37311840089mr7366565f8f.1.1724703378436;
        Mon, 26 Aug 2024 13:16:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724703378; cv=none;
        d=google.com; s=arc-20240605;
        b=F51+YxCIGw8LEWHGDNJoh3wwdlFR0olibsxUUugv0uFCKdSHmWmrMwk0qHR7p1TRb1
         Ju2gvDFzv5PvTKlhJnwP0DewJltueezClb5U9mlcWEYIljQkD+vbchKFcHyXI/y+cH6m
         omX5Xq7z/PVVMeiTzWBQNINWfqh0cOur9JtECQRuZeMmMxEnxUlpewAAHP4ujH4YEO9n
         VSP5hlvfDxTjCRdN0Qs+GhAZ2ovB7vnfyeardMEpW3ny1TmgLllDbPlBseQfgrzLAILr
         IjTqHN0AVDvd7BJP0pqBtV1q4B8JNeShvk513ZLOPP5F8fx1tYfrtaYpzu2jCbFqwAZZ
         Qwcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=pI/jyIrtPaEmbStKVtuunJ5n4+ozSzU6r3tapoA0Qrg=;
        fh=+CFYnpG5UPMw4HJ+LlqsgDXE6JGCgOxZeRexDSVHwaY=;
        b=dYUJlm2kChmyHU2Uxf0anmMYjHt1p8pQB1iisKu/zZ5TSPJFD0DQLO4oB6xHVg1e2d
         tsb66WNcQR0NAntRIYaiq2kLX6tBhJUzCtHoVCV5o0tfrCGOSxDSrcKR/QjQ7YsoCQ3t
         UZjSYYlmaZAM5aId/zORbK7auN0GuTR5cqepHQP9VRJshY3C/73qoB8tXy/pfHUNgeB4
         LOBm6MazvdvKJ0P/vdm0PLrIZdA7szWwUkNwB+/QYFYTYM18WoCGFhPfP3Sz0efeOLOM
         VXpNK9LUPxsJlTpoNl2V7heKUTV8cmaii6WrpklhyxJqG8tQyiYMeadjysfH5l/UHD1C
         AEJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cpfPXADs;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4WdmPyJG;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wt7TmSm+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42ac517b34csi1674735e9.2.2024.08.26.13.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Aug 2024 13:16:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A5EF51F8AE;
	Mon, 26 Aug 2024 20:16:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 906AD13724;
	Mon, 26 Aug 2024 20:16:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 4xziIpDizGZTRAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Aug 2024 20:16:16 +0000
Message-ID: <2386c86f-d356-4782-b091-4007ee684e19@suse.cz>
Date: Mon, 26 Aug 2024 22:16:16 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slub] 3a34e8ea62:
 BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>, Jann Horn <jannh@google.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
 Linux Memory Management List <linux-mm@kvack.org>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 kasan-dev@googlegroups.com
References: <202408251741.4ce3b34e-oliver.sang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <202408251741.4ce3b34e-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: A5EF51F8AE
X-Spam-Score: -4.51
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[lists.linux.dev,intel.com,kvack.org,gmail.com,google.com,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MID_RHS_MATCH_FROM(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCPT_COUNT_SEVEN(0.00)[8];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DWL_DNSWL_BLOCKED(0.00)[suse.cz:dkim];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:dkim,intel.com:email,01.org:url,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cpfPXADs;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4WdmPyJG;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wt7TmSm+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/25/24 11:45, kernel test robot wrote:
> Hello,
> 
> kernel test robot noticed "BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf" on:
> 
> commit: 3a34e8ea62cdeba64a66fa4489059c59ba4ec285 ("slub: Introduce CONFIG_SLUB_RCU_DEBUG")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
> 
> [test failed on linux-next/master c79c85875f1af04040fe4492ed94ce37ad729c4d]
> 
> in testcase: kunit
> version: 
> with following parameters:
> 
> 	group: group-00
> 
> 
> 
> compiler: gcc-12
> test machine: 36 threads 1 sockets Intel(R) Core(TM) i9-10980XE CPU @ 3.00GHz (Cascade Lake) with 128G memory
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)

It seems to me the kunit test produces the expected output and kasan doesn't
suppress dmesg output in kunit test context? So lkp probably already has all
the other kasan tests in some kind of allow filter, and this one would need
to be added as well?

> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202408251741.4ce3b34e-oliver.sang@intel.com
> 
> 
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240825/202408251741.4ce3b34e-oliver.sang@intel.com
> 
> 
> kern  :err   : [  359.476745] ==================================================================
> kern  :err   : [  359.479027] BUG: KASAN: slab-use-after-free in kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
> kern  :err   : [  359.480349] Read of size 1 at addr ffff888361948840 by task kunit_try_catch/4608
> 
> kern  :err   : [  359.482361] CPU: 29 UID: 0 PID: 4608 Comm: kunit_try_catch Tainted: G    B            N 6.11.0-rc2-00010-g3a34e8ea62cd #1
> kern  :err   : [  359.484487] Tainted: [B]=BAD_PAGE, [N]=TEST
> kern  :err   : [  359.485478] Hardware name: Gigabyte Technology Co., Ltd. X299 UD4 Pro/X299 UD4 Pro-CF, BIOS F8a 04/27/2021
> kern  :err   : [  359.486969] Call Trace:
> kern  :err   : [  359.487837]  <TASK>
> kern  :err   : [  359.488673]  dump_stack_lvl+0x53/0x70
> kern  :err   : [  359.489634]  print_address_description+0x2c/0x3a0
> kern  :err   : [  359.490788]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
> kern  :err   : [  359.491900]  print_report+0xb9/0x2b0
> kern  :err   : [  359.492830]  ? kasan_addr_to_slab+0xd/0xb0
> kern  :err   : [  359.493806]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
> kern  :err   : [  359.494882]  kasan_report+0xe8/0x120
> kern  :err   : [  359.495797]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
> kern  :err   : [  359.496862]  kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
> kern  :err   : [  359.497927]  ? __pfx_kmem_cache_rcu_uaf+0x10/0x10 [kasan_test]
> kern  :err   : [  359.499020]  ? __schedule+0x7ec/0x1950
> kern  :err   : [  359.499929]  ? ktime_get_ts64+0x7f/0x230
> kern  :err   : [  359.500843]  kunit_try_run_case+0x1b0/0x490
> kern  :err   : [  359.501772]  ? __pfx_kunit_try_run_case+0x10/0x10
> kern  :err   : [  359.502735]  ? set_cpus_allowed_ptr+0x85/0xc0
> kern  :err   : [  359.503662]  ? __pfx_set_cpus_allowed_ptr+0x10/0x10
> kern  :err   : [  359.504629]  ? __pfx_kunit_try_run_case+0x10/0x10
> kern  :err   : [  359.505579]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
> kern  :err   : [  359.506640]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
> kern  :err   : [  359.507642]  kthread+0x2d8/0x3c0
> kern  :err   : [  359.508468]  ? __pfx_kthread+0x10/0x10
> kern  :err   : [  359.509337]  ret_from_fork+0x31/0x70
> kern  :err   : [  359.510185]  ? __pfx_kthread+0x10/0x10
> kern  :err   : [  359.511042]  ret_from_fork_asm+0x1a/0x30
> kern  :err   : [  359.511912]  </TASK>
> 
> kern  :err   : [  359.513276] Allocated by task 4608:
> kern  :warn  : [  359.514082]  kasan_save_stack+0x33/0x60
> kern  :warn  : [  359.514917]  kasan_save_track+0x14/0x30
> kern  :warn  : [  359.515748]  __kasan_slab_alloc+0x89/0x90
> kern  :warn  : [  359.516595]  kmem_cache_alloc_noprof+0x10e/0x380
> kern  :warn  : [  359.517499]  kmem_cache_rcu_uaf+0x10d/0x490 [kasan_test]
> kern  :warn  : [  359.518464]  kunit_try_run_case+0x1b0/0x490
> kern  :warn  : [  359.519323]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
> kern  :warn  : [  359.520274]  kthread+0x2d8/0x3c0
> kern  :warn  : [  359.521040]  ret_from_fork+0x31/0x70
> kern  :warn  : [  359.521825]  ret_from_fork_asm+0x1a/0x30
> 
> kern  :err   : [  359.523201] Freed by task 0:
> kern  :warn  : [  359.523891]  kasan_save_stack+0x33/0x60
> kern  :warn  : [  359.524646]  kasan_save_track+0x14/0x30
> kern  :warn  : [  359.525384]  kasan_save_free_info+0x3b/0x60
> kern  :warn  : [  359.526154]  __kasan_slab_free+0x51/0x70
> kern  :warn  : [  359.526901]  slab_free_after_rcu_debug+0xf8/0x2a0
> kern  :warn  : [  359.527711]  rcu_do_batch+0x388/0xde0
> kern  :warn  : [  359.528433]  rcu_core+0x419/0xea0
> kern  :warn  : [  359.529120]  handle_softirqs+0x1d3/0x630
> kern  :warn  : [  359.529858]  __irq_exit_rcu+0x125/0x170
> kern  :warn  : [  359.530584]  sysvec_apic_timer_interrupt+0x6f/0x90
> kern  :warn  : [  359.531389]  asm_sysvec_apic_timer_interrupt+0x1a/0x20
> 
> kern  :err   : [  359.532754] Last potentially related work creation:
> kern  :warn  : [  359.533562]  kasan_save_stack+0x33/0x60
> kern  :warn  : [  359.534283]  __kasan_record_aux_stack+0xad/0xc0
> kern  :warn  : [  359.535063]  kmem_cache_free+0x337/0x4c0
> kern  :warn  : [  359.535794]  kmem_cache_rcu_uaf+0x14b/0x490 [kasan_test]
> kern  :warn  : [  359.536644]  kunit_try_run_case+0x1b0/0x490
> kern  :warn  : [  359.537394]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
> kern  :warn  : [  359.538244]  kthread+0x2d8/0x3c0
> kern  :warn  : [  359.538917]  ret_from_fork+0x31/0x70
> kern  :warn  : [  359.539616]  ret_from_fork_asm+0x1a/0x30
> 
> kern  :err   : [  359.540850] The buggy address belongs to the object at ffff888361948840
>                                which belongs to the cache test_cache of size 200
> kern  :err   : [  359.542668] The buggy address is located 0 bytes inside of
>                                freed 200-byte region [ffff888361948840, ffff888361948908)
> 
> kern  :err   : [  359.545021] The buggy address belongs to the physical page:
> kern  :warn  : [  359.545911] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x361948
> kern  :warn  : [  359.547012] head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
> kern  :warn  : [  359.548094] flags: 0x17ffffc0000040(head|node=0|zone=2|lastcpupid=0x1fffff)
> kern  :warn  : [  359.549131] page_type: 0xfdffffff(slab)
> kern  :warn  : [  359.549918] raw: 0017ffffc0000040 ffff88821419ca00 dead000000000122 0000000000000000
> kern  :warn  : [  359.551034] raw: 0000000000000000 00000000801f001f 00000001fdffffff 0000000000000000
> kern  :warn  : [  359.552151] head: 0017ffffc0000040 ffff88821419ca00 dead000000000122 0000000000000000
> kern  :warn  : [  359.553278] head: 0000000000000000 00000000801f001f 00000001fdffffff 0000000000000000
> kern  :warn  : [  359.554406] head: 0017ffffc0000001 ffffea000d865201 ffffffffffffffff 0000000000000000
> kern  :warn  : [  359.555532] head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
> kern  :warn  : [  359.556660] page dumped because: kasan: bad access detected
> 
> kern  :err   : [  359.558233] Memory state around the buggy address:
> kern  :err   : [  359.559130]  ffff888361948700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> kern  :err   : [  359.560238]  ffff888361948780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> kern  :err   : [  359.561344] >ffff888361948800: fc fc fc fc fc fc fc fc fa fb fb fb fb fb fb fb
> kern  :err   : [  359.562451]                                            ^
> kern  :err   : [  359.563410]  ffff888361948880: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> kern  :err   : [  359.564535]  ffff888361948900: fb fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> kern  :err   : [  359.565661] ==================================================================
> kern  :info  : [  359.982162]     ok 38 kmem_cache_rcu_uaf
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2386c86f-d356-4782-b091-4007ee684e19%40suse.cz.
