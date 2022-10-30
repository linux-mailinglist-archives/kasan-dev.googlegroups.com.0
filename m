Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB5OZ7ONAMGQELTGABUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21B50612CFA
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 22:30:31 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id s7-20020a2eb8c7000000b0026fdd80df37sf4087852ljp.23
        for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 14:30:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667165430; cv=pass;
        d=google.com; s=arc-20160816;
        b=gBMaKvaGe0PftdugC1zzNwKIHJfsqUpoQjcS+Avuf6RerLSrecbmR06Yc7nXGRndO8
         oMoQzZodwVviyVBv4za/RlQUsHC5j2qCi/rMYwGggQi+L64BZQ9bJAnvucH//Bjk/Kbb
         l1cjx1KGDlKQ0eOANCn8bkVgNa2GSZzFNsiZQoycVx9uJcjDB7l+wHS5Agx5GomdT8Ug
         fGWzPKzZW1Lp+STUbp6DLgAofc5tOcVTurVyc9o5QISLbC1PPAgAgApbBiplpDkFK2I0
         hGJFvgvgaUNzu0dbqAW5V8rcQ1sGKQkNSmdBPn4UZEpkpCNJIeNqstxYTvcdsw7FTZwh
         +f4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xbYZ6oupBsUsU86gwX88eDxP2+069QKVWJKnpTef3uo=;
        b=zaB8kna6dnJWYPAWLQpsHDffeSeFq0ljcNB586j3wxkJRQnm/EyfARa0Hx8vjR5eB7
         SFQWNE3xHUGmc/jTrJaM9iU29xBZZeVhnvdwOzetwn5XB/1Aj6CWKVOOg+kP9Quke+0o
         eo/gfuehHH+oR5Z63pI0hzMJ8TxmMCR5SjU55ZtYDHYaw/ItCqWdxTC6yZMYC0GTH6pj
         SwMNOM6v9E/w3Tq0FWpiKCkZ53HjMyTRzypId8yUMcEXtFUbuCFCXc56BQbms2iOezmC
         54RpVNZBOspepyzjPfAT9Pbn+ozRk0jGDWK5A7YXuNh65mLqsh0JHgzrQ5YhFg17j7wO
         Yg8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj0DUIpN;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=n4W7wmdY;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xbYZ6oupBsUsU86gwX88eDxP2+069QKVWJKnpTef3uo=;
        b=eWZfOl5PsoKB/Xc1c7JKOFXTgWrrcYM+qCpFmvm2EXNNJbLczuB/cvC0AFunmoZOgh
         0+DPRs1NDQQ2cAGtMr+VJqzYduh0W5beQTNshmAA+eKxB+6LRtL3gNfJmXM5r7fi3733
         hB86e76P0SBkkRZ3cRlJ44+EzNMeMhWrayOsRq9bUELHppD/caRrInLb9swTteo8LLQB
         QjfA8ajttFGojnlf6Wda3lbQvUrj90atdeC3zpE/RFWj/gNCavrfYzPadenY2oRCg5rJ
         fOpfeliKb8/A/hw4HDuQaICOxx2ZbCOI62p60qE7lIVkclWXvw1pjnVC040W2tlIlCkc
         jqEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xbYZ6oupBsUsU86gwX88eDxP2+069QKVWJKnpTef3uo=;
        b=jbXJRr+GROxP0typdaF6BD8rMnTFaDHryzk0fvJkWiCYh6UO1xc8aC04BBT4+9dfjT
         Frdd3vCdW6hZJ6urG17GQbZJv/O/gNC43DnKmAPeyhc0mIiew8Y6WXMxcLReW8EqJSJU
         GS+7PVBw2naHFwLAGLG9ZJ7dQCcBAtwl4h65kcl3yw1ciw3qOQCxmKZittVPPb3yGSIL
         TfA6zqCUzOijTWaB8wSIHtwCCxQroGsXgOThVGO3NqRWKv2BlN1XOpX+ej/UEL8XumNf
         AI50kqvWW3k992nQIkbPXdD0tZpPvpRvqRF4yCg+6wbza2bLtZL1vpx18S//YxDw2je2
         49Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1Ddy/T9GaUpJURZ3Hio7r4sUO0rJJ/pwfrAj1J3xBE6nrxZjcd
	2aT7NVgd4nkv1W+SYO5QgK0=
X-Google-Smtp-Source: AMsMyM7WIzaNoo+ZUOVp7jNNShAgkS552U3jJQyu4djqpRui+86mB1Sg3VJI1ThdqSzAbKPkYup0Hw==
X-Received: by 2002:a05:6512:75:b0:4a4:6c3e:a75d with SMTP id i21-20020a056512007500b004a46c3ea75dmr3848702lfo.408.1667165430199;
        Sun, 30 Oct 2022 14:30:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f3:0:b0:49a:b814:856d with SMTP id v19-20020ac258f3000000b0049ab814856dls4697344lfo.1.-pod-prod-gmail;
 Sun, 30 Oct 2022 14:30:28 -0700 (PDT)
X-Received: by 2002:a05:6512:3e13:b0:499:1829:5181 with SMTP id i19-20020a0565123e1300b0049918295181mr4215570lfv.71.1667165428633;
        Sun, 30 Oct 2022 14:30:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667165428; cv=none;
        d=google.com; s=arc-20160816;
        b=OVvJXcbQOF6/jHwjjZziCQGmfs9jJ5RHhu18Q31ayuzACNd34MVNBXTmIMLLFj5LhH
         YYpru/ng+jLDKeg4DlyCGynagCfXrhFJj0J4Ae5rbyrTuoAf995r7/B58t9Hq3Hkstb1
         Cvel7IaOnpAxbMEgGulZx1/pKfjU8ifJA4I2IqG7sakUTPY9fstLhjmqjvckkMjRzMFa
         jdiOIZyNrroXpTLgaO6UAhslhiUWfCvBlsgp179ivTrk5Dl0sDVhyI8CsOXTXF/IwaKu
         gAr5EVydF/XW6BOgtToVTjMmdXLCNqGIWOPjxNYtj72YjUNGF9XKvTLCBlavLl7MIdne
         apIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=/NY1rcDEamX9FhWGip4UCMQebRBOgw945um303QnZ04=;
        b=a1mhgOz3h/FCIKL3KEuw+s8oKZlQSrkBFYdwXEph9sOZISwWUZbt0ULFKevedUVj33
         JeBdkXOE1sChCicZM+HjkOM1HlPIM5ASCuL2jlAhYwh6TdG5JaV4LAhlQ2KF5rWzD2Iv
         Ba9DPNEqcJtvTO3rx5Mjy73RqrlD+zeCnUIAjLRIf5wvaCFW+HjNrtpyRjvVMWXbJ0YE
         WqHSA4JxRgqqaAVI0Smpqbp6rIhGdGw2R8TVp/zrehS5uLobyJr/O84F9zt8MbvRk1FW
         qjyw2hGuK5yWFd+a44o5TuiiwKswBS8JaTXGMRgINVcE2U/cQB+YLYhepZFstgYiDh/h
         fpsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj0DUIpN;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=n4W7wmdY;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id x14-20020a056512078e00b0049c8ac119casi124285lfr.5.2022.10.30.14.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 30 Oct 2022 14:30:28 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CCE9B20C00;
	Sun, 30 Oct 2022 21:30:27 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2AE5913A37;
	Sun, 30 Oct 2022 21:30:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id uYpNCfPsXmOTOAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Sun, 30 Oct 2022 21:30:27 +0000
Message-ID: <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
Date: Sun, 30 Oct 2022 22:30:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.0
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Content-Language: en-US
To: John Thomson <lists@johnthomson.fastmail.com.au>,
 Feng Tang <feng.tang@intel.com>, Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Uj0DUIpN;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=n4W7wmdY;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/30/22 20:23, John Thomson wrote:
> On Tue, 13 Sep 2022, at 06:54, Feng Tang wrote:
>> kmalloc's API family is critical for mm, with one nature that it will
>> round up the request size to a fixed one (mostly power of 2). Say
>> when user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
>> could be allocated, so in worst case, there is around 50% memory
>> space waste.
> 
> 
> I have a ralink mt7621 router running Openwrt, using the mips ZBOOT kernel, and appear to have bisected
> a very-nearly-clean kernel v6.1rc-2 boot issue to this commit.
> I have 3 commits atop 6.1-rc2: fix a ZBOOT compile error, use the Openwrt LZMA options,
> and enable DEBUG_ZBOOT for my platform. I am compiling my kernel within the Openwrt build system.
> No guarantees this is not due to something I am doing wrong, but any insight would be greatly appreciated.
> 
> 
> On UART, No indication of the (once extracted) kernel booting:
> 
> transfer started ......................................... transfer ok, time=2.01s
> setting up elf image... OK
> jumping to kernel code
> zimage at:     80BA4100 810D4720
> Uncompressing Linux at load address 80001000
> Copy device tree to address  80B96EE0
> Now, booting the kernel...

It's weird that the commit would cause no output so early, SLUB code is 
run only later.

> Nothing follows
> 
> 6edf2576a6cc  ("mm/slub: enable debugging memory wasting of kmalloc") reverted, normal boot:
> transfer started ......................................... transfer ok, time=2.01s
> setting up elf image... OK
> jumping to kernel code
> zimage at:     80BA4100 810D47A4
> Uncompressing Linux at load address 80001000
> Copy device tree to address  80B96EE0
> Now, booting the kernel...
> 
> [    0.000000] Linux version 6.1.0-rc2 (john@john) (mipsel-openwrt-linux-musl-gcc (OpenWrt GCC 11.3.0 r19724+16-1521d5f453) 11.3.0, GNU ld (GNU Binutils) 2.37) #0 SMP Fri Oct 28 03:48:10 2022
> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> [    0.000000] printk: bootconsole [early0] enabled
> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
> [    0.000000] Initrd not found or empty - disabling initrd
> [    0.000000] VPE topology {2,2} total 4
> [    0.000000] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
> [    0.000000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
> [    0.000000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
> [    0.000000] Zone ranges:
> [    0.000000]   Normal   [mem 0x0000000000000000-0x000000000fffffff]
> [    0.000000]   HighMem  empty
> [    0.000000] Movable zone start for each node
> [    0.000000] Early memory node ranges
> [    0.000000]   node   0: [mem 0x0000000000000000-0x000000000fffffff]
> [    0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x000000000fffffff]
> [    0.000000] percpu: Embedded 11 pages/cpu s16064 r8192 d20800 u45056
> [    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 64960
> [    0.000000] Kernel command line: console=ttyS0,115200 rootfstype=squashfs,jffs2
> [    0.000000] Dentry cache hash table entries: 32768 (order: 5, 131072 bytes, linear)
> [    0.000000] Inode-cache hash table entries: 16384 (order: 4, 65536 bytes, linear)
> [    0.000000] Writing ErrCtl register=00019146
> [    0.000000] Readback ErrCtl register=00019146
> [    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
> [    0.000000] Memory: 246220K/262144K available (7455K kernel code, 628K rwdata, 1308K rodata, 3524K init, 245K bss, 15924K reserved, 0K cma-reserved, 0K highmem)
> [    0.000000] SLUB: HWalign=32, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
> [    0.000000] rcu: Hierarchical RCU implementation.
> 
> 
> boot continues as expected
> 
> 
> possibly relevant config options:
> grep -E '(SLUB|SLAB)' .config
> # SLAB allocator options
> # CONFIG_SLAB is not set
> CONFIG_SLUB=y
> CONFIG_SLAB_MERGE_DEFAULT=y
> # CONFIG_SLAB_FREELIST_RANDOM is not set
> # CONFIG_SLAB_FREELIST_HARDENED is not set
> # CONFIG_SLUB_STATS is not set
> CONFIG_SLUB_CPU_PARTIAL=y
> # end of SLAB allocator options
> # CONFIG_SLUB_DEBUG is not set

Also not having CONFIG_SLUB_DEBUG enabled means most of the code the 
patch/commit touches is not even active.
Could this be some miscompile or code layout change exposing some 
different bug, hmm.
Is it any different if you do enable CONFIG_SLUB_DEBUG ?
Or change to CONFIG_SLAB? (that would be really weird if not)

> 
> With this commit reverted: cpuinfo and meminfo
> 
> system type		: MediaTek MT7621 ver:1 eco:3
> machine			: MikroTik RouterBOARD 760iGS
> processor		: 0
> cpu model		: MIPS 1004Kc V2.15
> BogoMIPS		: 586.13
> wait instruction	: yes
> microsecond timers	: yes
> tlb_entries		: 32
> extra interrupt vector	: yes
> hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
> isa			: mips1 mips2 mips32r1 mips32r2
> ASEs implemented	: mips16 dsp mt
> Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
> shadow register sets	: 1
> kscratch registers	: 0
> package			: 0
> core			: 0
> VPE			: 0
> VCED exceptions		: not available
> VCEI exceptions		: not available
> 
> processor		: 1
> cpu model		: MIPS 1004Kc V2.15
> BogoMIPS		: 586.13
> wait instruction	: yes
> microsecond timers	: yes
> tlb_entries		: 32
> extra interrupt vector	: yes
> hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
> isa			: mips1 mips2 mips32r1 mips32r2
> ASEs implemented	: mips16 dsp mt
> Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
> shadow register sets	: 1
> kscratch registers	: 0
> package			: 0
> core			: 0
> VPE			: 1
> VCED exceptions		: not available
> VCEI exceptions		: not available
> 
> processor		: 2
> cpu model		: MIPS 1004Kc V2.15
> BogoMIPS		: 586.13
> wait instruction	: yes
> microsecond timers	: yes
> tlb_entries		: 32
> extra interrupt vector	: yes
> hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
> isa			: mips1 mips2 mips32r1 mips32r2
> ASEs implemented	: mips16 dsp mt
> Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
> shadow register sets	: 1
> kscratch registers	: 0
> package			: 0
> core			: 1
> VPE			: 0
> VCED exceptions		: not available
> VCEI exceptions		: not available
> 
> processor		: 3
> cpu model		: MIPS 1004Kc V2.15
> BogoMIPS		: 586.13
> wait instruction	: yes
> microsecond timers	: yes
> tlb_entries		: 32
> extra interrupt vector	: yes
> hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
> isa			: mips1 mips2 mips32r1 mips32r2
> ASEs implemented	: mips16 dsp mt
> Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
> shadow register sets	: 1
> kscratch registers	: 0
> package			: 0
> core			: 1
> VPE			: 1
> VCED exceptions		: not available
> VCEI exceptions		: not available
> 
> MemTotal:         249744 kB
> MemFree:          211088 kB
> MemAvailable:     187364 kB
> Buffers:               0 kB
> Cached:             8824 kB
> SwapCached:            0 kB
> Active:             1104 kB
> Inactive:           8860 kB
> Active(anon):       1104 kB
> Inactive(anon):     8860 kB
> Active(file):          0 kB
> Inactive(file):        0 kB
> Unevictable:           0 kB
> Mlocked:               0 kB
> HighTotal:             0 kB
> HighFree:              0 kB
> LowTotal:         249744 kB
> LowFree:          211088 kB
> SwapTotal:             0 kB
> SwapFree:              0 kB
> Dirty:                 0 kB
> Writeback:             0 kB
> AnonPages:          1192 kB
> Mapped:             2092 kB
> Shmem:              8824 kB
> KReclaimable:       1704 kB
> Slab:               9372 kB
> SReclaimable:       1704 kB
> SUnreclaim:         7668 kB
> KernelStack:         592 kB
> PageTables:          264 kB
> SecPageTables:	       0 kB
> NFS_Unstable:          0 kB
> Bounce:                0 kB
> WritebackTmp:          0 kB
> CommitLimit:      124872 kB
> Committed_AS:      14676 kB
> VmallocTotal:    1040376 kB
> VmallocUsed:        2652 kB
> VmallocChunk:          0 kB
> Percpu:              272 kB
> 
> 
> Cheers,
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af2ba83d-c3f4-c6fb-794e-c2c7c0892c44%40suse.cz.
