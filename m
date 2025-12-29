Return-Path: <kasan-dev+bncBD5ILSM62IPBB555ZHFAMGQEETCD77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FA41CE66A3
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Dec 2025 11:59:05 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-656bc3a7ab3sf16005113eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Dec 2025 02:59:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767005944; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vm9b7FWTYOWweoWE+u5bAoymsjUtMjhjfUXzr5QJXLrNQI3qROKGDE592Q5qe4VMEO
         IwGGImsxgRwPidfHp7AcPCCkbp93CMWJwaZAT+sGHi6Rb9unNYb6uC8lDcgYTmRbUkKM
         ge/7KQx4dCLtoY3X7fER+WWECv45octFPm4TIPCfe6UtZjFVlxN48DzLILdlcqCRzD20
         mNDbR8y0O26bW+4GxhhIqLPABE1PSH5Tfp0jB2XHEU0dOdJLWwFqWMeRJxcYgf3ErmIk
         vJBfWHm5UIpCQ3zf5QTKYbKPTdJMC6Thv+Kn0mKzocc/u0jpRE5rS0EdPMHb6ZiR3taZ
         i2YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cpgspolicy:cms-type
         :mime-version:message-id:subject:cc:to:from:date:dkim-filter:sender
         :dkim-signature;
        bh=RpxP0G2VxtiTJWARrJ63u40C9h+1DpVkEJcQG70y7Ps=;
        fh=9dBDwDwYheSIzcUyJN2PU7E3Esg7o30QbP74Ev6MdYI=;
        b=A3SlZobQ0V/Zmk8FuHbt1raSps3qXQSVu3WAOWndYqpEM8n27jEjR8TtMfHFWqcDwK
         /WJOft096R6OXoJo9gB5qV77huIcj2nAisz2W8JS4z2enEatdvSIHhV9IWZka1+j3++2
         sFDCKrn8iHmFa7alceEAx8guRcZJrKkueW9fUfk0qvFsXASYYplLsXHi/2ZecHBx6g6v
         1qEk/VEc+OHhdsBVp9OuIN1p4depmonzXQMylclEzRAw8eHtfugOWgGC4fwOPR8p3ro8
         n37JYU+CnQnnxOyPSsEW+/x8zqmLgif3LQDT2o/TGuEDjy6Y3uKh0MAMgOnIn63HdC8J
         S2Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=SdE274Y5;
       spf=pass (google.com: domain of jh1012.choi@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=jh1012.choi@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767005944; x=1767610744; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:cpgspolicy:cms-type:mime-version
         :message-id:subject:cc:to:from:date:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RpxP0G2VxtiTJWARrJ63u40C9h+1DpVkEJcQG70y7Ps=;
        b=xu+fO8oUMheSmWnR21yjVGOyWkuvh+0a4tct3q1ZKVZ2CV7yKsz/KY4utq5XA4Uuz1
         cW4GZIm6HOpWpzlGtDWPWQ07OUUv7NOe7yCEXXnNQgW7sEVSl4DTeCUBrRkr2TIU/PBb
         KuiE8lMpOzzsOM9nE/RktCqs0FcN9rWGbLXAL74RfpO7wrciAEjHsFA92GR+8EW3Kqo5
         FAJ9oFjCI5X/7XCnc9MOmjbpA3TTIB7SNhTf3gzo2+kHYQw9mlJsGI8DByHIyQ6G2MCn
         6/WNaqPiCOMVXdGfJiaGaabuMgUeFPjFaod6YPKg6bL5tjknT2rM+zfRd55KtKPsAJda
         4ltQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767005944; x=1767610744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :cpgspolicy:cms-type:mime-version:message-id:subject:cc:to:from:date
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RpxP0G2VxtiTJWARrJ63u40C9h+1DpVkEJcQG70y7Ps=;
        b=lWmLvK2DzL1W6I82gw3GBMCCQfPHoD4Ux04rX8/Kt0sE8nLn3UTsx8YOhxkDnwgjyE
         RlwFgwSIkGx4EDzj7DuVDyUNupOPtqXTf9ZcjBjxDho69hgJlBhflrc+LhD/Dn7E0cS2
         8nwVnFuaYQUKiM5+hQ1ax2zIJzR7raE/RMvm/AXsGp4Ibb/B+UGnEqTL/QjBtTU7X8lc
         FRuUxfj5BiltOyde+13X4C0WWXmbW8prm3/zzKE4HCugYL5FToIc+5BxcDLv/nX+qubB
         kLkysUTvdL2Izqhf8E5uHuLOcSikKBaIga7Ld7hjdSsu4hEOJNM9iJArI6xOSf5YdqRZ
         TnFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGha1TdgNMJQIgtc3k7HJR4d88/o8g0yHT0JQWRPGuCJryTL/G9dgonlVVAypPbDYj90dyYg==@lfdr.de
X-Gm-Message-State: AOJu0YwnA0AQrej+ESq6mInvTOQBEow/LhQhIA0znGK9IneBBtc6lHdO
	xUebsJuFCeFjTwoZMC/8YbZT/F7JCSgSOD1eudHhh+79yR8cowReGwP4
X-Google-Smtp-Source: AGHT+IE6yPY31cUfmvm10nTRi0U0OvoYQVDr89CKcOBSKuQ/dQopvo3uBC/fC1zHZ7ajsBhER177Gg==
X-Received: by 2002:a05:6820:1c9d:b0:659:9a49:8fb9 with SMTP id 006d021491bc7-65d0eb2ff4amr12954365eaf.50.1767005943795;
        Mon, 29 Dec 2025 02:59:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa4ZI129KdkV6D858oSvrD3ha9omy+hzUp9+IwJyobStQ=="
Received: by 2002:a05:6871:4e97:b0:3ec:4eb6:abba with SMTP id
 586e51a60fabf-3fe94e399ecls934596fac.1.-pod-prod-05-us; Mon, 29 Dec 2025
 02:59:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUV4DA9taa22iQDVVs61D2CFZJ3OPGzKZHIJzpWK8r62V3x8Eiea0F7coGWlxnOhQoErWlXX6Li3Rg=@googlegroups.com
X-Received: by 2002:a05:6830:6586:b0:7c6:8bfe:f5e with SMTP id 46e09a7af769-7cc66a18443mr17021626a34.32.1767005943003;
        Mon, 29 Dec 2025 02:59:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767005942; cv=none;
        d=google.com; s=arc-20240605;
        b=CsVHVICjXtubLefQ0u/MAXp0E61eQhd19GFOhvolynP2779bxjPovjtL8LCIr8LXgN
         XIbICsQvHSU4oTrpuMIyFDh+nlpD2ME+r1Sw7Fkv2pNtskOJ2XnIUvs7F3tUmH8hnqex
         VXWPbXSoAStjI2eQDAO/k1K1iVa3elkonLrXmKoHy8tJREjU6u08TXPwU8QkANOxGZ4N
         VHvH1JxLXjWMGM1j0pGlFDzmaEP+XoOXzVVaedwkboC4ghhrxjIvmbsSTUE2WP3olmxM
         1pc5V7NOm7m7NDabxQwS3MoNRblR5h4+evkXK/J10bryO3rpKuKK7m+ULe+b5UwCFDoN
         VlUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:cpgspolicy:cms-type:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature:dkim-filter;
        bh=359yQ6XbAw6WRUjKppsMEJqR1osu72NIkC7C9Pwse1A=;
        fh=w+caShTYRZBt1hfuBEpDoUFEI9yE0l5OKwFJ7MeePB4=;
        b=NTi4qB4aoZ2kawnC6h4P0ofc6CFPkb2VcGRonIiJp5ZSQhL7ndIPyDMX7wOfvs6KiC
         BC0aQhAPo921NkdxpZGIrTxf26GNXuebhBcVQkzp3Z2a1NSQPgLriRvOF176QCcA81pj
         7lHCBOfbVBHK8flEjVxiYWk/L0ak9RZ0my64dO6Ni0lLLdeR1W884ATphWvtM8Hkagj9
         Yv8M4aQOx1cT8+0S1Ev07RQ4rJLX9e/vmQNq9/JEj76O1ei/8bQasZEpiJw6uwfu62J4
         UZXUX1e/saSopsGEVbrvKAlla1I3UL+FEs3OpsSLztOevG/uqt3SMQm4kU471a+e86uW
         MjTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=SdE274Y5;
       spf=pass (google.com: domain of jh1012.choi@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=jh1012.choi@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667ca0a2si1922370a34.6.2025.12.29.02.59.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Dec 2025 02:59:02 -0800 (PST)
Received-SPF: pass (google.com: domain of jh1012.choi@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas2p2.samsung.com (unknown [182.195.41.54])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20251229105900epoutp0192f7d17aa9888983d843827d7e831030~Fqop1bw5b2808228082epoutp01B
	for <kasan-dev@googlegroups.com>; Mon, 29 Dec 2025 10:59:00 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20251229105900epoutp0192f7d17aa9888983d843827d7e831030~Fqop1bw5b2808228082epoutp01B
Received: from epsnrtp04.localdomain (unknown [182.195.42.156]) by
	epcas2p4.samsung.com (KnoxPortal) with ESMTPS id
	20251229105900epcas2p4c2ff5e3733867193a7bfca2b2e8876ee~Fqoplg3l50418004180epcas2p46;
	Mon, 29 Dec 2025 10:59:00 +0000 (GMT)
Received: from epcas2p1.samsung.com (unknown [182.195.38.212]) by
	epsnrtp04.localdomain (Postfix) with ESMTP id 4dftWR6C4vz6B9m5; Mon, 29 Dec
	2025 10:58:59 +0000 (GMT)
Received: from epsmtip2.samsung.com (unknown [182.195.34.31]) by
	epcas2p2.samsung.com (KnoxPortal) with ESMTPA id
	20251229105858epcas2p26c433715e7955d20072e72964e83c3e7~FqooRMj7h2169121691epcas2p23;
	Mon, 29 Dec 2025 10:58:58 +0000 (GMT)
Received: from tiffany (unknown [10.229.95.142]) by epsmtip2.samsung.com
	(KnoxPortal) with ESMTPA id
	20251229105858epsmtip2fefb80a8148940daf5672c3bd8f32845~FqooOs5XO2776727767epsmtip2h;
	Mon, 29 Dec 2025 10:58:58 +0000 (GMT)
Date: Mon, 29 Dec 2025 20:05:47 +0900
From: Jeongho Choi <jh1012.choi@samsung.com>
To: bpf@vger.kernel.org, kasan-dev@googlegroups.com
Cc: jh1012.choi@samsung.com, joonki.min@samsung.com, hajun.sung@samsung.com
Subject: [QUESTION] KASAN: invalid-access in bpf_patch_insn_data+0x22c/0x2f0
Message-ID: <20251229110431.GA2243991@tiffany>
MIME-Version: 1.0
X-CMS-MailID: 20251229105858epcas2p26c433715e7955d20072e72964e83c3e7
X-Msg-Generator: CA
Content-Type: multipart/mixed;
	boundary="----V_Ee6mLygYIcFboi0QdK.jy0CXpDH3EB3hR9DzJVup49CurE=_1d105d_"
X-Sendblock-Type: AUTO_CONFIDENTIAL
CMS-TYPE: 102P
cpgsPolicy: CPGSC10-234,Y
X-CFilter-Loop: Reflected
X-CMS-RootMailID: 20251229105858epcas2p26c433715e7955d20072e72964e83c3e7
References: <CGME20251229105858epcas2p26c433715e7955d20072e72964e83c3e7@epcas2p2.samsung.com>
X-Original-Sender: jh1012.choi@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=SdE274Y5;       spf=pass
 (google.com: domain of jh1012.choi@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=jh1012.choi@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

------V_Ee6mLygYIcFboi0QdK.jy0CXpDH3EB3hR9DzJVup49CurE=_1d105d_
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hello
I'm jeongho Choi from samsung System LSI.
I'm developing kernel BSP for exynos SoC.

I'm asking a question because I've recently been experiencing 
issues after enable SW KASAN in Android17 kernel 6.18 environment.

Context:
 - Kernel version: v6.18
 - Architecture: ARM64

Question:
When SW tag KASAN is enabled, we got kernel crash from bpf/verifier.
I found that it occurred only from 6.18, not 6.12 LTS we're working on.

After some tests, I found that the device is booted when 2 commits are reverted.

bpf: potential double-free of env->insn_aux_data
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b13448dd64e27752fad252cec7da1a50ab9f0b6f

bpf: use realloc in bpf_patch_insn_data
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=77620d1267392b1a34bfc437d2adea3006f95865

==================================================================
[   79.419177] [4:     netbpfload:  825] BUG: KASAN: invalid-access in bpf_patch_insn_data+0x22c/0x2f0
[   79.419415] [4:     netbpfload:  825] Write of size 27896 at addr 25ffffc08e6314d0 by task netbpfload/825
[   79.419984] [4:     netbpfload:  825] Pointer tag: [25], memory tag: [fa]
[   79.425193] [4:     netbpfload:  825] 
[   79.427365] [4:     netbpfload:  825] CPU: 4 UID: 0 PID: 825 Comm: netbpfload Tainted: G           OE       6.18.0-rc6-android17-0-gd28deb424356-4k #1 PREEMPT  92293e52a7788dc6ec1b9dff6625aaee925f3475
[   79.427374] [4:     netbpfload:  825] Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE
[   79.427378] [4:     netbpfload:  825] Hardware name: Samsung ERD9965 board based on S5E9965 (DT)
[   79.427382] [4:     netbpfload:  825] Call trace:
[   79.427385] [4:     netbpfload:  825]  show_stack+0x18/0x28 (C)
[   79.427394] [4:     netbpfload:  825]  __dump_stack+0x28/0x3c
[   79.427401] [4:     netbpfload:  825]  dump_stack_lvl+0x7c/0xa8
[   79.427407] [4:     netbpfload:  825]  print_address_description+0x7c/0x20c
[   79.427414] [4:     netbpfload:  825]  print_report+0x70/0x8c
[   79.427421] [4:     netbpfload:  825]  kasan_report+0xb4/0x114
[   79.427427] [4:     netbpfload:  825]  kasan_check_range+0x94/0xa0
[   79.427432] [4:     netbpfload:  825]  __asan_memmove+0x54/0x88
[   79.427437] [4:     netbpfload:  825]  bpf_patch_insn_data+0x22c/0x2f0
[   79.427442] [4:     netbpfload:  825]  bpf_check+0x2b44/0x8c34
[   79.427449] [4:     netbpfload:  825]  bpf_prog_load+0x8dc/0x990
[   79.427453] [4:     netbpfload:  825]  __sys_bpf+0x300/0x4c8
[   79.427458] [4:     netbpfload:  825]  __arm64_sys_bpf+0x48/0x64
[   79.427465] [4:     netbpfload:  825]  invoke_syscall+0x6c/0x13c
[   79.427471] [4:     netbpfload:  825]  el0_svc_common+0xf8/0x138
[   79.427478] [4:     netbpfload:  825]  do_el0_svc+0x30/0x40
[   79.427484] [4:     netbpfload:  825]  el0_svc+0x38/0x8c
[   79.427491] [4:     netbpfload:  825]  el0t_64_sync_handler+0x68/0xdc
[   79.427497] [4:     netbpfload:  825]  el0t_64_sync+0x1b8/0x1bc
[   79.427502] [4:     netbpfload:  825] 
[   79.545586] [4:     netbpfload:  825] The buggy address belongs to a 8-page vmalloc region starting at 0x25ffffc08e631000 allocated at bpf_patch_insn_data+0x8c/0x2f0
[   79.558777] [4:     netbpfload:  825] The buggy address belongs to the physical page:
[   79.565029] [4:     netbpfload:  825] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x8b308b
[   79.573710] [4:     netbpfload:  825] memcg:c6ffff882d1d6402
[   79.577791] [4:     netbpfload:  825] flags: 0x6f80000000000000(zone=1|kasantag=0xbe)
[   79.584042] [4:     netbpfload:  825] raw: 6f80000000000000 0000000000000000 dead000000000122 0000000000000000
[   79.592460] [4:     netbpfload:  825] raw: 0000000000000000 0000000000000000 00000001ffffffff c6ffff882d1d6402
[   79.600877] [4:     netbpfload:  825] page dumped because: kasan: bad access detected
[   79.607126] [4:     netbpfload:  825] 
[   79.609296] [4:     netbpfload:  825] Memory state around the buggy address:
[   79.614766] [4:     netbpfload:  825]  ffffffc08e637f00: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
[   79.622665] [4:     netbpfload:  825]  ffffffc08e638000: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
[   79.630562] [4:     netbpfload:  825] >ffffffc08e638100: 25 25 25 25 25 25 25 fa fa fa fa fa fa fe fe fe
[   79.638463] [4:     netbpfload:  825]                                         ^
[   79.644190] [4:     netbpfload:  825]  ffffffc08e638200: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
[   79.652089] [4:     netbpfload:  825]  ffffffc08e638300: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
[   79.659987] [4:     netbpfload:  825] ==================================================================

I have a question about the above phenomenon.
Thanks,
Jeongho Choi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251229110431.GA2243991%40tiffany.

------V_Ee6mLygYIcFboi0QdK.jy0CXpDH3EB3hR9DzJVup49CurE=_1d105d_
Content-Type: text/plain; charset="UTF-8"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251229110431.GA2243991%40tiffany.

------V_Ee6mLygYIcFboi0QdK.jy0CXpDH3EB3hR9DzJVup49CurE=_1d105d_--
