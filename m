Return-Path: <kasan-dev+bncBAABBVEUUTXAKGQEAC3VNSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 37191F6EED
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 08:14:31 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id h2sf11933452pfr.20
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Nov 2019 23:14:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573456469; cv=pass;
        d=google.com; s=arc-20160816;
        b=dm4wpid1S7nkM4KUN8M5cMhzTg1zpiBlMM9iv7qIW3IDkGlHe6uC9m+rl9wGTNCzme
         RHmTxyB3WJIozEzGpxvRjqxIW5PiH7r3TNx/ywVPPc/X1DNKmTCWIc4AJdIV3vRo1Jvk
         RuhOEYXdVsDpVwBeEP88AxQV2cPy6x7ixxOxqDHtcUJGGtJqUZeKkQp7Yj6siztwmhnI
         hlhfutYOcoGZiEkZTwjQJ1TH3nZtzinfX0XXY7ISqDAFkhysPKZvm2lCghDbJRP0BwGY
         hPoJGRGJed3KkKnRiifdDKL0HfZF7JEqLO4ZVhG3vJ5h5vDtVuvKnqGkiaM9ihkB9QCz
         cOgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=4rvLV4PKIxxdpTog4awwfmaoy3ERgw6sUmpFV0N7Rkw=;
        b=SlasGe9yt2vfTDQwMFYuU+enuekzHHrdvrypiQ+2IjABC7JRmt9Nx5ZY8EdulvGMqT
         38eY0WW1c4fs0hq/I7LVpI2XjzraTEHgvToMUly1m8KPX7veVbqL/5XbuNMILJh7OBxh
         Cs5Th9COlSGY6C3kDGgfwYf/7UiwHZL/Jrfw/mJEof52O1pnQdVwUrk21ujWsNMvyZMc
         1dwLldHLuieSUPN2eyVexfFi6+TISF+f+TT9OHTosKHYAO8InUR7DlLbPOHG4h9piF46
         /4IrYDscKOLOlESwhqsjYfZ9Lf5QaVw+g1BkzsL/zWFVJWnMG9Pa7RSBOE0qfjyK8NRB
         zVkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aPVHgi82;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4rvLV4PKIxxdpTog4awwfmaoy3ERgw6sUmpFV0N7Rkw=;
        b=eTYxMePInPvAnXWObyynxShjEoICWjg5+2mfbO5euwT2AR676m1fm8p1dS6vJiuayg
         xWXADlaHb8Xxpm4Lcf78GZHr0PPcPhGmUxCc1RM/ymDP/MocxIDON8pi4SLK8TX3njSy
         NTTdLC8wXw/D7t917zF4Fr4oLzCHeIQFC1woCAC6vlybB6si00CotNhmxKibL2J4C/yu
         ozqa5JFu+jKsm48wJ1NJ8Og8eok/Z9C8nXPXSzZVrbmYfjSo5PKGZrQm01ONkF2ErG1C
         c3hYiUsxGfoz65LFFQUN9CT9YsDMKEfeFIW2SQVwiJ4VsH7pX1CLXnbwNg/pmV3TSsnL
         Bktg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4rvLV4PKIxxdpTog4awwfmaoy3ERgw6sUmpFV0N7Rkw=;
        b=SpOT2YtRRpRbb/jYHNMwa+Hcjo3tl0Xhty8vYlsF/KmlGCmdDaHVTEVkmyxCngKyBd
         8qZsgfJIhkedVF5PpLQADnj8XryBtAHln2Z0eDAKcCEvjicuOmZvzxM/zpIRWg95ZIoE
         8k3XpglEBzRdoLpT51RmtfH6DznPfSu3tW7ormp6Inrp3QLEvJec/ZHZiniXcWpfqs3Y
         scx9m9YmMr9Wg92WeLbf1U5DjoU1HKfemFs+ShAAXrn4126vzxfpmZbyZ7mUGA3ecXgK
         FKeLGdTxsnvtKD/r0KFVJ/cP4HkoGiEeZdx1FOPOpN/rFFHNepSGp85wpumtMSchruw+
         uTkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWjfGtAsBlJaEi/aJ7cSDAQQj9rOVAnsm8RD47jAA7qtEVWoS/W
	CSbp6EKeMpfIs0lnis3JxJQ=
X-Google-Smtp-Source: APXvYqyAWDB7CZnqhFOiv2dxGQZD2WUnPGBHrXp67FQKj6lMbscPDEa6cwCRKJjGPYYRzvbv6o2ixw==
X-Received: by 2002:a17:90a:33ce:: with SMTP id n72mr32739880pjb.17.1573456469173;
        Sun, 10 Nov 2019 23:14:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c10:: with SMTP id x16ls1700977pll.0.gmail; Sun, 10
 Nov 2019 23:14:28 -0800 (PST)
X-Received: by 2002:a17:90b:30d7:: with SMTP id hi23mr5389680pjb.10.1573456468689;
        Sun, 10 Nov 2019 23:14:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573456468; cv=none;
        d=google.com; s=arc-20160816;
        b=EJMycSQHgNHXo8+dUoKvPgdw+5Z8x3psSgOf/cBEismBZKr25eacKnbwxnuZC0fEJZ
         2qt/LsLtctYixB2DqYrAETeRGWzAB6U99Cg+Gm+UPXfbwwjsAx8r2/EO5UmZtb3/3VAe
         S0S2SnQYCk3Yk6Tx71tewTsdV8U/3gANCj9Ak5EexjshFVqIR14vsA3DUJYsz5LUXdzL
         FifDBDCVRxs2fHql7a+jNuYsir2d8SUHPxXova7RHvj6RGlsxpExhmW/yetKY/NZGQ/9
         xpPjUloOcf6dzH/JE2N7YQPXVX86q2IsdTvbcqslY7f6jLkDqQXYwbb308uZQOQ3KKsH
         POng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ZET29UGGhorDG5MNMT5K7ddGjyv/P0hiwCQLJxUqtP4=;
        b=0l24BOzy/diktXsOmJ/0BAXakQC8ELcIO+lOPk1Jvcud78qZ7eFIGE19XLLr+8VQf7
         eJKPlAxaAGNN40r7nVjjZf/mwzUSKvbcT11UiWaQA8mQWgyu2DW2wSZSB8HD7dFRnSvt
         kRpKNXyB6fYp0nrSRUWvLp9GE8wWlPUmTxSTdkkcI4rJxYYjf4mhZnRyyRdF/cmhth/3
         gxKJvb3/9jwz+cQ51Fuj6Cd/Au1zy/nCJpA7dZr/7/qGwA/4iroHk6my/mtmcmSfgWrc
         0ogCGnSYu06EGTwzBQxOzST9i82eO579hxpJ0fABZmj0se5BuXq6xcEmn0hKkFN3UMnF
         kVyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aPVHgi82;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u10si545979pge.4.2019.11.10.23.14.28
        for <kasan-dev@googlegroups.com>;
        Sun, 10 Nov 2019 23:14:28 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 53c84c1b40474be08d6072da63118f33-20191111
X-UUID: 53c84c1b40474be08d6072da63118f33-20191111
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1852812815; Mon, 11 Nov 2019 15:14:26 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 11 Nov 2019 15:14:23 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 11 Nov 2019 15:14:22 +0800
Message-ID: <1573456464.20611.45.camel@mtksdccf07>
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Mon, 11 Nov 2019 15:14:24 +0800
In-Reply-To: <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
	 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=aPVHgi82;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Sat, 2019-11-09 at 01:31 +0300, Andrey Ryabinin wrote:
> 
> On 11/4/19 5:05 AM, Walter Wu wrote:
> 
> > 
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..4ff67e2fd2db 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
> >  }
> >  EXPORT_SYMBOL(__kasan_check_write);
> >  
> > +extern bool report_enabled(void);
> > +
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +	if (report_enabled() &&
> > +	    !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +		return NULL;
> >  
> >  	return __memset(addr, c, len);
> >  }
> > @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +	if (report_enabled() &&
> > +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > +		return NULL;
> >  
> >  	return __memmove(dest, src, len);
> >  }
> > @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +	if (report_enabled() &&
> 
>             report_enabled() checks seems to be useless.
> 

Hi Andrey,

If it doesn't have report_enable(), then it will have below the error.
We think it should be x86 shadow memory is invalid value before KASAN
initialized, it will have some misjudgments to do directly return when
it detects invalid shadow value in memset()/memcpy()/memmove(). So we
add report_enable() to avoid this happening. but we should only use the
condition "current->kasan_depth == 0" to determine if KASAN is
initialized. And we try it is pass at x86.


>> [    0.029609] RIP: 0010:clear_page_orig+0x12/0x40
>> [    0.030247] Code: 90 90 90 90 90 90 90 90 b9 00 02 00 00 31 c0 f3
48 ab c3 0f 1f 44 00 00 31 c0 b9 40 00 00 00 66 0f 1f 84 00 00 00 00 00
ff c9 <48> 89 07 48 89 47 08 48 89 47 10 48 89 47 18 48 89 47 20 48 89
47
>> [    0.032943] RSP: 0000:ffffffffb1e07c48 EFLAGS: 00010016 ORIG_RAX:
0000000000000002
>> [    0.034010] RAX: 0000000000000000 RBX: 0000000778000000 RCX:
000000000000003f
>> [    0.035056] RDX: 000000000000002c RSI: 2000040000000000 RDI:
0000000000000000
>> [    0.036068] RBP: ffffffffb1e07c78 R08: 0000000000000003 R09:
0000000000000007
>> [    0.037066] R10: ffffffffb1e07d48 R11: fffffbfff689abdc R12:
ffffffffb1c3c6d0
>> [    0.038057] R13: 0000000000000000 R14: 0000000000000001 R15:
0000000000000001
>> [    0.039049] FS:  0000000000000000(0000) GS:ffffffffb1f32000(0000)
knlGS:0000000000000000
>> [    0.040290] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> [    0.041134] CR2: 0000000000000000 CR3: 000000003adba000 CR4:
00000000000606b0
>> [    0.042128] Call Trace:
>> [    0.042482]  ? alloc_low_pages+0x1b1/0x1d6
>> [    0.043062]  alloc_low_page+0x15/0x1e
>> [    0.043619]  __kernel_physical_mapping_init+0x121/0x2f9
>> [    0.044354]  kernel_physical_mapping_init+0x15/0x1e
>> [    0.045081]  init_memory_mapping+0x357/0x465
>> [    0.045684]  ? alloc_low_pages+0x1d6/0x1d6
>> [    0.046314]  ? __kasan_check_read+0x2b/0x36
>> [    0.046914]  init_mem_mapping+0x26d/0x4f2
>> [    0.047524]  ? 0xffffffffaf400000
>> [    0.047994]  setup_arch+0xa6f/0xf9d
>> [    0.048490]  start_kernel+0xdb/0x9ce
>> [    0.049001]  ? mem_encrypt_init+0x12/0x12
>> [    0.049567]  ? x86_early_init_platform_quirks+0x8f/0x124
>> [    0.050314]  ? __asan_loadN+0x31/0x3a
>> [    0.050878]  x86_64_start_reservations+0x40/0x49
>> [    0.051614]  x86_64_start_kernel+0xfb/0x105
>> [    0.052212]  secondary_startup_64+0xb6/0xc0



> > +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > +		return NULL;
> >  
> >  	return __memcpy(dest, src, len);
> >  }
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 616f9dd82d12..02148a317d27 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
> >  	if (unlikely(size == 0))
> >  		return true;
> >  
> > +	if (unlikely((long)size < 0)) {
> 
>         if (unlikely(addr + size < addr)) {
> 
> > +		kasan_report(addr, size, write, ret_ip);
> > +		return false;
> > +	}
> > +
> >  	if (unlikely((void *)addr <
> >  		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> >  		kasan_report(addr, size, write, ret_ip);
> > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > index 36c645939bc9..52a92c7db697 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
> >  
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +	/*
> > +	 * If access_size is negative numbers, then it has three reasons
> > +	 * to be defined as heap-out-of-bounds bug type.
> > +	 * 1) Casting negative numbers to size_t would indeed turn up as
> > +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
> > +	 *    so that this can qualify as out-of-bounds.
> > +	 * 2) If KASAN has new bug type and user-space passes negative size,
> > +	 *    then there are duplicate reports. So don't produce new bug type
> > +	 *    in order to prevent duplicate reports by some systems
> > +	 *    (e.g. syzbot) to report the same bug twice.
> > +	 * 3) When size is negative numbers, it may be passed from user-space.
> > +	 *    So we always print heap-out-of-bounds in order to prevent that
> > +	 *    kernel-space and user-space have the same bug but have duplicate
> > +	 *    reports.
> > +	 */
>  
> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
> type, but at the same time you code actually does that.
> 3) says something about user-space which have nothing to do with kasan.
> 
about 2)
We originally think the heap-out-of-bounds is similar to
heap-buffer-overflow, maybe we should change the bug type to
heap-buffer-overflow.

about 3)
Our idea is just to always print "heap-out-of-bounds" and don't
differentiate if the size come from user-space or not.


> > +	if ((long)info->access_size < 0)
> 
>         if (info->access_addr + info->access_size < info->access_addr)
> 
> > +		return "heap-out-of-bounds";
> > +
> >  	if (addr_has_shadow(info->access_addr))
> >  		return get_shadow_bug_type(info);
> >  	return get_wild_bug_type(info);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 621782100eaa..c79e28814e8f 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -446,7 +446,7 @@ static void print_shadow_for_address(const void *addr)
> >  	}
> >  }
> >  
> > -static bool report_enabled(void)
> > +bool report_enabled(void)
> >  {
> >  	if (current->kasan_depth)
> >  		return false;
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 0e987c9ca052..b829535a3ad7 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
> >  	if (unlikely(size == 0))
> >  		return true;
> >  
> > +	if (unlikely((long)size < 0)) {
> 
>         if (unlikely(addr + size < addr)) {
> 
Thanks. We will change it in v4.

> > +		kasan_report(addr, size, write, ret_ip);
> > +		return false;
> > +	}
> > +
> >  	tag = get_tag((const void *)addr);
> >  
> >  	/*
> > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > index 969ae08f59d7..f7ae474aef3a 100644
> > --- a/mm/kasan/tags_report.c
> > +++ b/mm/kasan/tags_report.c
> > @@ -36,6 +36,24 @@
> >  
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +	/*
> > +	 * If access_size is negative numbers, then it has three reasons
> > +	 * to be defined as heap-out-of-bounds bug type.
> > +	 * 1) Casting negative numbers to size_t would indeed turn up as
> > +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
> > +	 *    so that this can qualify as out-of-bounds.
> > +	 * 2) If KASAN has new bug type and user-space passes negative size,
> > +	 *    then there are duplicate reports. So don't produce new bug type
> > +	 *    in order to prevent duplicate reports by some systems
> > +	 *    (e.g. syzbot) to report the same bug twice.
> > +	 * 3) When size is negative numbers, it may be passed from user-space.
> > +	 *    So we always print heap-out-of-bounds in order to prevent that
> > +	 *    kernel-space and user-space have the same bug but have duplicate
> > +	 *    reports.
> > +	 */
> > +	if ((long)info->access_size < 0)
> 
>         if (info->access_addr + info->access_size < info->access_addr)
> 
Thanks. We will change it in v4.

> > +		return "heap-out-of-bounds";
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  	struct kasan_alloc_meta *alloc_meta;
> >  	struct kmem_cache *cache;
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1573456464.20611.45.camel%40mtksdccf07.
