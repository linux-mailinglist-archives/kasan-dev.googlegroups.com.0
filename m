Return-Path: <kasan-dev+bncBAABBQO6USQAMGQE4TE6KNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AA6206B1851
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 01:58:42 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 23-20020a250b17000000b00a1f7de39bf5sf511472ybl.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Mar 2023 16:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678323521; cv=pass;
        d=google.com; s=arc-20160816;
        b=0CIFsqai0ypjY88E4FU/KIM2pW4rlzwc9b/ZLB7ozu7AfoVM/RoWtQjXFzoFd1tFs4
         4mSjFbeo60JncvbGwxwgOPutcnvLPWx3K9d+CqQw055A5M0nLfJqZH1TKCQj0j/7GNOc
         NnugkYIKJydi0adDB1xGO3EcohpGPXI8iffiACxCDsrwW/AdI2kvAidShYOTm5RXcaRt
         /zV7vS6/XpuqAgoNIr+kgjL4QTxDhQJBnoHqKD2DmMPDtSdSHg6YdsnGF4NwHwGuLKAI
         NRJ8ultA1MXtjkVV1U/G8Dvaub2P8vfGe2pB9baAk6Ad6WXhMwBOiTrhxVWoon6C/biZ
         4gtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=krRHMPDb+1R2MybrA87LPi6LT7Y+Y5mJNJsRSScgdBQ=;
        b=CzJqrme8J9EWShOlM8ERGlTpouMJBbONHjpuc5bSUu0OuofuZVf2Au+2+6Fd3rrrYo
         whcGQ3u+GZX7hTUI8PxaTRAAMaBOREI+Nlinh5H45Xse+UvAgiF8GReAR+xUL8fdggXN
         mskIk/Yq4Yu/pf1W6hKQAzVmpNmrDvj6rhhj9U75/+TtiziFaiaLFmTj6d7SJHlKRcsJ
         3vshGaPIWnzPWeIa/6lqZpdVyrzwuMnGtOyS+p+OA9ifeonUmpMh0Bd8tTkMRmBblpOS
         caXgU5geQkubG8QrZbRtpEo92RFLonB2IHscxJ0gHmSfomoM+NwhMQOH8qWo2fqMvV/D
         Dotw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=WWlMqsMQ;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678323521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=krRHMPDb+1R2MybrA87LPi6LT7Y+Y5mJNJsRSScgdBQ=;
        b=QNjwvoVqlSlo0lrGrmDtk2N6xEZHA31okn7ifDV96Q2U4RGO3XRpNQunKIJJS/utlj
         ttLIqVLXiYWoJKPU1JMDzDCUYqyU+xv1qXENJLT02MwvC7Is9Y7FVxFGnryWSL7xTNrM
         ee6iP7VnhC0KVn+bQ1aiY+Oc54TjLcvKeT2epcKnvgrTOUAkuNMorxKNMhCk8fFquUk6
         VxnNp5l82C5f74zzlh/iw941O7/nvR7lHcaP5l/PbQdssNvM0FT7JviYQwX7vvBBGTG3
         vNGn38EmmladVZuaChF4sIKwmlqDMBW9RqFjMHNlDBBuc0Y1H3Lt9s1JMO6bh3G66JM7
         RdrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678323521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=krRHMPDb+1R2MybrA87LPi6LT7Y+Y5mJNJsRSScgdBQ=;
        b=yaYpzGuxMphQbZ+yxDovajxyR897sQrnXkObKr4XLhs7whp1wX7FVGV35ts8eSw2A6
         xjPcZJC4IvTUGqvd/zWa74+qC65rVNQKAbbwdnte2RbD1yetxq7JQ8KUda8FKf73T8Ic
         ig8cz+XkR0niPwf2RqQlksdg48am3VneThGfs6jPutWn28nCXWksEESJ40FRAyhGtSHA
         VRYoWzHsy73yDXk9Ib7H5Mie7J6s0c2sudL2G7YoJL74qlvFK4CA72FmsYiAMIWedS1n
         No/CKsIN0T9g0F06UJ9vJCDN08LW+oSkBcDT53uL1GBy1NvOu4p6edpsjM1nTtLKEM89
         1IUg==
X-Gm-Message-State: AO0yUKXjrLFKl9hVV8A9wYiPwHq4y61Ju0B/pUEjwoHezzE5k7v1gADF
	Tpa19SWonhnO0MmHEaTIM3U=
X-Google-Smtp-Source: AK7set8lF6Js0i2Eix/sGYOagjjAYVRp2FxpP794fxI4iGWooqmY3YYTGRp7Cwa7RZISE1RixJEYxw==
X-Received: by 2002:a81:b243:0:b0:52e:d380:ab14 with SMTP id q64-20020a81b243000000b0052ed380ab14mr11525925ywh.3.1678323521372;
        Wed, 08 Mar 2023 16:58:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9b50:0:b0:53e:849b:650 with SMTP id s77-20020a819b50000000b0053e849b0650ls268662ywg.7.-pod-prod-gmail;
 Wed, 08 Mar 2023 16:58:40 -0800 (PST)
X-Received: by 2002:a81:91d1:0:b0:538:7722:da79 with SMTP id i200-20020a8191d1000000b005387722da79mr21235007ywg.30.1678323520803;
        Wed, 08 Mar 2023 16:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678323520; cv=none;
        d=google.com; s=arc-20160816;
        b=n8yGxLyCdNdENN6YINZixtuFzNSgrXy2fwZWLfL6aUAFFJ0QlVRbmHG72JOeZNWh+m
         peH5MUoES6OIcLbNVRlCg83mdgwcagiX7rtmmhxfkp5cGH7K+J7wNdtpgm1Iek9p+Wke
         7/Rvm+xcnLAmh0lxZa/tiWSURBL7VmnJuxIRA2pPDGtKyGpM0/Hhk0mtsRNZp6w7vTPQ
         bGfrAvlV8Yu1RiQ21VVVkvyDDqHQbYwRvCvM6Ak8Z9EbLIHHdFHpwIOM9U1NOBuq19PI
         D3tmgQ2psgMm6u15Li/8T4ZtM8k2/gKQRgRKSwrKNvk/EomXRDrIWwIcNe+Dy2MA28Zb
         GX3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EqhDZzrss8FZauHLdy3yGltu/TNnywGdNfFHVyXVdaY=;
        b=NeUdSTJ6MKxUz+KHkZvLblHubr4Du1P732fnLs2aTxgNLRGAkTw0LdOuHlfdsdPs3K
         MtyTe2W4PbxbgqBPKzp1TqEa5z3AzdluLq6sQ4NFgZTj9k7J3F+2o5LOelJ2uKycrE7S
         5ScSyIJoS6yqnx+zDH5v1WgrW7aoHuO/FBKWdwkYhgj1G5htmohKEKezzFc1ictw7DXB
         Li0tzROSSrH462eMj8Wlz827VFEN/gpCSNPoTYLD8Li57O7sBvyW3ekO8paZa8zzqQo9
         V5Ni2e9fSJzdPXESvkP1hcbfPJdl6fYGb3sQO5V3Tw7elhsZmzNCHlRT2qjSk1McVRJx
         sSsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=WWlMqsMQ;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id k18-20020a81ff12000000b0053cba27e38dsi1029835ywn.1.2023.03.08.16.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Mar 2023 16:58:40 -0800 (PST)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 83bcd93cbe1511eda06fc9ecc4dadd91-20230309
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.20,REQID:da883947-a5c8-4ae6-8b68-b83b2d9efe05,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:25b5999,CLOUDID:ba6fa6b2-beed-4dfc-bd9c-e1b22fa6ccc4,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0
X-CID-BVR: 1,FCT|NGT
X-UUID: 83bcd93cbe1511eda06fc9ecc4dadd91-20230309
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1867993968; Thu, 09 Mar 2023 08:58:33 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.25; Thu, 9 Mar 2023 08:58:32 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.25 via Frontend Transport; Thu, 9 Mar 2023 08:58:31 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <angelogioacchino.delregno@collabora.com>, <dvyukov@google.com>,
	<haibo.li@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <mark.rutland@arm.com>,
	<matthias.bgg@gmail.com>, <will@kernel.org>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kcsan:fix alignment_fault when read unaligned instrumented memory
Date: Thu, 9 Mar 2023 08:58:31 +0800
Message-ID: <20230309005831.52154-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <ZAhkQUmvf1U3H4nR@elver.google.com>
References: <ZAhkQUmvf1U3H4nR@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=WWlMqsMQ;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

> On Wed, Mar 08, 2023 at 05:41PM +0800, Haibo Li wrote:

> [...]

> > > > x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000

> Call

> > > > trace:

> > > >  kcsan_setup_watchpoint+0x26c/0x6bc

> > > >  __tsan_read2+0x1f0/0x234

> > > >  inflate_fast+0x498/0x750

> > >

> > > ^^ is it possible that an access in "inflate_fast" is unaligned?

> > Here is the instruction for inflate_fast+0x498:

> > ffffffc008948980 <inflate_fast>:

> > ...

> > 	ffffffc008948e10: e0 03 1c aa   mov     x0, x28

> > 	ffffffc008948e14: 06 3a e9 97   bl      0xffffffc00839762c

> <__tsan_unaligned_read2>

> > 	ffffffc008948e18: e0 03 17 aa   mov     x0, x23

> > 	>ffffffc008948e1c: 9a 27 40 78   ldrh    w26, [x28], #2

> >

> > And the instruction for kcsan_setup_watchpoint+0x26c:

> > 	ffffffc00839ab90 <kcsan_setup_watchpoint>:

> > 	...

> > 	>ffffffc00839adfc: a8 fe df 48   ldarh   w8, [x21]

> >

> > The instruction is different.READ_ONCE uses ldarh,which requires the access

> address is aligned.

> > As ARM v8 arm said:

> > "

> > Load-Acquire, Load-AcquirePC and Store-Release, other than Load-Acquire

> Exclusive Pair and

> > Store-Release-Exclusive Pair, access only a single data element. This access is

> single-copy atomic. The address of the data object must be aligned to the size

> of the data element being accessed, otherwise the access generates an

> > Alignment fault."

> >

> > while ldrh accepts unaligned address.

> > That's why it is ok while disable KCSAN.

> 

> I understand now what's going on, thanks for the analysis.

> 

> Can you test the below patch, I think it is the correct solution for

> this - compared to your approach of opting out unaligned accesses, with

> the below there is no loss of functionality.

> 

> Thanks,

> -- Marco

> 

The below patch works well on linux-5.15+arm64.

> ------ >8 ------

> 

> 

> From 889e9d5ce61592a18c90a9c57495337d5827bbc2 Mon Sep 17 00:00:00

> 2001

> From: Marco Elver <elver@google.com>

> Date: Wed, 8 Mar 2023 11:21:06 +0100

> Subject: [PATCH] kcsan: Avoid READ_ONCE() in read_instrumented_memory()

> 

> Haibo Li reported:

> 

>  | Unable to handle kernel paging request at virtual address

>  |   ffffff802a0d8d7171

>  | Mem abort info:o:

>  |   ESR = 0x9600002121

>  |   EC = 0x25: DABT (current EL), IL = 32 bitsts

>  |   SET = 0, FnV = 0 0

>  |   EA = 0, S1PTW = 0 0

>  |   FSC = 0x21: alignment fault

>  | Data abort info:o:

>  |   ISV = 0, ISS = 0x0000002121

>  |   CM = 0, WnR = 0 0

>  | swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000

>  | [ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,

>  | pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707

>  | Internal error: Oops: 96000021 [#1] PREEMPT SMP

>  | Modules linked in:

>  | CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted

>  |   5.15.78-android13-8-g63561175bbda-dirty #1

>  | ...

>  | pc : kcsan_setup_watchpoint+0x26c/0x6bc

>  | lr : kcsan_setup_watchpoint+0x88/0x6bc

>  | sp : ffffffc00ab4b7f0

>  | x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001

>  | x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80

>  | x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71

>  | x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060

>  | x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000

>  | x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0

>  | x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8

>  | x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007

>  | x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70

>  | x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000

>  | Call trace:

>  |  kcsan_setup_watchpoint+0x26c/0x6bc

>  |  __tsan_read2+0x1f0/0x234

>  |  inflate_fast+0x498/0x750

>  |  zlib_inflate+0x1304/0x2384

>  |  __gunzip+0x3a0/0x45c

>  |  gunzip+0x20/0x30

>  |  unpack_to_rootfs+0x2a8/0x3fc

>  |  do_populate_rootfs+0xe8/0x11c

>  |  async_run_entry_fn+0x58/0x1bc

>  |  process_one_work+0x3ec/0x738

>  |  worker_thread+0x4c4/0x838

>  |  kthread+0x20c/0x258

>  |  ret_from_fork+0x10/0x20

>  | Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )

>  | ---[ end trace 613a943cb0a572b6 ]-----

> 

> The reason for this is that on certain arm64 configuration since

> e35123d83ee3 ("arm64: lto: Strengthen READ_ONCE() to acquire when

> CONFIG_LTO=y"), READ_ONCE() may be promoted to a full atomic acquire

> instruction which cannot be used on unaligned addresses.

> 

> Fix it by avoiding READ_ONCE() in read_instrumented_memory(), and simply

> forcing the compiler to do the required access by casting to the

> appropriate volatile type. In terms of generated code this currently

> only affects architectures that do not use the default READ_ONCE()

> implementation.

> 

> The only downside is that we are not guaranteed atomicity of the access

> itself, although on most architectures a plain load up to machine word

> size should still be atomic (a fact the default READ_ONCE() still relies

> on itself).

> 



> Reported-by: Haibo Li <haibo.li@mediatek.com>

> Cc: <stable@vger.kernel.org>

> Signed-off-by: Marco Elver <elver@google.com>

> ---

>  kernel/kcsan/core.c | 17 +++++++++++++----

>  1 file changed, 13 insertions(+), 4 deletions(-)

> 

> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c

> index 54d077e1a2dc..5a60cc52adc0 100644

> --- a/kernel/kcsan/core.c

> +++ b/kernel/kcsan/core.c

> @@ -337,11 +337,20 @@ static void delay_access(int type)

>   */

>  static __always_inline u64 read_instrumented_memory(const volatile void

> *ptr, size_t size)

>  {

> +	/*

> +	 * In the below we don't necessarily need the read of the location to

> +	 * be atomic, and we don't use READ_ONCE(), since all we need for race

> +	 * detection is to observe 2 different values.

> +	 *

> +	 * Furthermore, on certain architectures (such as arm64), READ_ONCE()

> +	 * may turn into more complex instructions than a plain load that cannot

> +	 * do unaligned accesses.

> +	 */

>  	switch (size) {

> -	case 1:  return READ_ONCE(*(const u8 *)ptr);

> -	case 2:  return READ_ONCE(*(const u16 *)ptr);

> -	case 4:  return READ_ONCE(*(const u32 *)ptr);

> -	case 8:  return READ_ONCE(*(const u64 *)ptr);

> +	case 1:  return *(const volatile u8 *)ptr;

> +	case 2:  return *(const volatile u16 *)ptr;

> +	case 4:  return *(const volatile u32 *)ptr;

> +	case 8:  return *(const volatile u64 *)ptr;

>  	default: return 0; /* Ignore; we do not diff the values. */

>  	}

>  }

> --

> 2.40.0.rc0.216.gc4246ad0f0-goog



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230309005831.52154-1-haibo.li%40mediatek.com.
