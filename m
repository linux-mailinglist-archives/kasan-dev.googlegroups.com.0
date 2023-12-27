Return-Path: <kasan-dev+bncBCT4XGV33UIBBQVLWKWAMGQEKQAXKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E32B181F232
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 22:23:16 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6da18672335sf80576b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 13:23:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703712195; cv=pass;
        d=google.com; s=arc-20160816;
        b=JKmB7BPX2+qcy1qcihe07yr9M4dpxyGh+yIpC8Wp/uD7vjleXkCgSNx1ViQsv0ivyH
         8TMBQX/kF0f41xI28LlpNua+P/AAZkTGg2Wmma7kzhNz++/fnpdN9lgmz/Tw24DCl56x
         Eq/xoLlCs6WLfYE235qzFK8fEIITMuHpvidqE9r8JQt0EnOfPEEbdkh5u09aeiuLVedX
         cRh3XTO17Sd5dgw1LKygKd20kTkhan6aHdpi+F3QHsazA0miRkUw8QMgnvXhY2COPhI8
         zPWhe82B3PRVlq2KPEsw8Epw4lR9GnWYF5NNp2j+L6x8Iaqe1hFr7N9hXhwJl2GA9Ujj
         K9Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=XrfMLQ4ZA5XIdfFbwR75TEQQmbIJ3kFCFxAh2A1cBt4=;
        fh=+ln+r0y0j6tFa9IoWpX8cwKXwelbkVR5/nwhYyfXjEo=;
        b=eqeIS8wNVd71YrLeBdG3dINC7aPs7kpAmzXQWkL6v955WrxlZ6yjHDqScnNNyKnE/B
         Zvw7bhzF8aPsmOci3d9i69vxZZpfc81tEszzX6/v3fwqJL7yePZftlXxuj6+g+Mo5C57
         AKGl7nNYjXk4X7apaAgkFc+3ZGHgLZiyeS1kJRdP+xT4MzbKk99gJDoFToluhgx2+2vf
         n+DoVo0sxJikHRxG9qpF/NycS3OfwHbScRjc1ghvHoobxN7RoGvmj055XfdtuVLhHt6s
         2AVhhLcPwk48ZusBTJc9oN3FzITMxgGa0jsLXabP+KTTdvx8komJBX8wEF2x558zkJ7O
         +zWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lFZ9Bdtz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703712195; x=1704316995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XrfMLQ4ZA5XIdfFbwR75TEQQmbIJ3kFCFxAh2A1cBt4=;
        b=EuchcpTWMOHdVEbwJi+YU2VT4kVTJVEynuhXjharuK9ojRgy+uE+lI7r+xow//IHo5
         5jhW7whN+7DG0n5kM6z1rLYn8kHgbTmlXOnSTynZV1GkiKMnypoXgyF7NciLvbAGNNDc
         Xikv9FniOKSDk79SnXsztINLkjHdLhnfC5owo35T3jcO3AykkF/DWYaFf3ZZ+de0Bu5Y
         lt+gt53HtLg77ffkyJMB3DclvuHpc7Nblnr9KEy2t2DkHIWEmFLMG073z4cRUFJCgLSC
         JcjI3HZ+x7jq1QAYborGEqFWxZVgnswNgo6nPHY3syYS8W68q6mSUtzW8+ejknMsL+WK
         ++/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703712195; x=1704316995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XrfMLQ4ZA5XIdfFbwR75TEQQmbIJ3kFCFxAh2A1cBt4=;
        b=MhtNHqVIF89GPDYERNowa5SbDBZUDn9kUlE5MICWb/0SjgOrKJ45BqmN84JJ7vhNti
         PCLlpXEt96kw74i0mE3nKHRXn80+fs5qVj0OOfElBtSz6ta2jaRPoxJjvXWmaLy7GEEO
         InBXvjZ1GLm527hR4+LfzXY3i5AIB/5M+WD3gWFKt5A3tfXBbU9LMoLd19hJ1VHXJF7o
         90coMnG0vCeUVzHSc4c3mvAf68CtsfxfeZ0Mt8l5rTLepxBfMGmxEV58xM0xr5tUhXuz
         qDqpjA7XU9j0GvxRyfqMxzfasuPe+71RQUdwu8nKWTcYEBCGDkJlOhceCzA0GFyL2MyT
         Jprg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyRMdfjqB0nUASEZ5oxz3P7dSM4QnJYp/O1PTkmf7YtqshmwUqY
	93yEtXF8gIT0957h77CQn6g=
X-Google-Smtp-Source: AGHT+IFuHRqsaatP/R/ZKjyR9peGqZQi8mHtP2yV2159XLy8lTvn8LnhmycnhJpO+1a+0oCjTbfcKw==
X-Received: by 2002:a05:6a00:706:b0:6d9:b95c:65fa with SMTP id 6-20020a056a00070600b006d9b95c65famr2130412pfl.36.1703712195105;
        Wed, 27 Dec 2023 13:23:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8782:b0:6d9:b38c:4f64 with SMTP id
 hk2-20020a056a00878200b006d9b38c4f64ls697189pfb.1.-pod-prod-01-us; Wed, 27
 Dec 2023 13:23:14 -0800 (PST)
X-Received: by 2002:a17:902:c408:b0:1d0:bba7:4f95 with SMTP id k8-20020a170902c40800b001d0bba74f95mr6552814plk.51.1703712193882;
        Wed, 27 Dec 2023 13:23:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703712193; cv=none;
        d=google.com; s=arc-20160816;
        b=HxI+4dL0SxJtCvsCFVtH5Ir7QK3P/z89Yezuawme/ruiZG1hR12Q5trTkj9ZgfQcBo
         SnHrYCYmT0uY1Pydn1ZhY2YjVYHb+IR3XBVbxdiHHFysq8mxdvsYLUjc+dJy0Q8SFWdj
         BNqEDAM4UIcafKCTgKxqFuGEQf24L6UtHeYTXt1JF465yFNqx62ngkS9r3L2Rmi79xYT
         nSqfEpLEkkoCGFFn1LTnX4KLBlEyDjVJaAINXmSg8hAUiMfTILWBy23GwlBJtuSQQIZN
         NH6q2tUgdb7/ChQdwfZq3fWJ5yKg6O8rAfR3nrmdoU91XgfdCEjF9Kc4ZQ5V/PLj8qcF
         eHRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lH+yqWGjh2MCQCB0UFXTbcgoswKLu3j5XuXUnRonSG0=;
        fh=+ln+r0y0j6tFa9IoWpX8cwKXwelbkVR5/nwhYyfXjEo=;
        b=NGU5c6rhYT80kV3N+2rp5jg5CfruZS+Zut5YlwU8IIoMisSNDpGAVoQFWOuyURZdst
         B743vqisAm82n7mIbbf+QF4/nrTHRtOMWGWTF45xgxIRTG2LpnHCkbDo9IoRREsRHRBr
         t9lel71sfhdoko3sNZYQYaYXismp/r6tPFJWnhHddGtG9KeMilZiQWTB1T7pS2iiVwCC
         cmGutffp8MOUnD/Ew4WlrrOeDyckr1EFYk75q40C9n8I5u+KIre3JxhiGjSzHRor5Kj7
         vzOIbZe8wX2YjkU7VyLHFjcqmmjBz8RyKs/gufZe7WpXtOQtkRHJ70iqAnK/fb9cXINV
         mfhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lFZ9Bdtz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id jb21-20020a170903259500b001d3f8dbcf5fsi827494plb.2.2023.12.27.13.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Dec 2023 13:23:13 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1358B60F8D;
	Wed, 27 Dec 2023 21:23:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6691CC433C8;
	Wed, 27 Dec 2023 21:23:12 +0000 (UTC)
Date: Wed, 27 Dec 2023 13:23:11 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: kernel test robot <lkp@intel.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 oe-kbuild-all@lists.linux.dev, Linux Memory Management List
 <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@gmail.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] kasan: stop leaking stack trace handles
Message-Id: <20231227132311.557c302e92bdc9ffb88b42d5@linux-foundation.org>
In-Reply-To: <202312280213.6j147JJb-lkp@intel.com>
References: <20231226225121.235865-1-andrey.konovalov@linux.dev>
	<202312280213.6j147JJb-lkp@intel.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=lFZ9Bdtz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 28 Dec 2023 02:19:51 +0800 kernel test robot <lkp@intel.com> wrote:

> Hi,
> 
> kernel test robot noticed the following build warnings:
> 
> [auto build test WARNING on akpm-mm/mm-everything]
> [cannot apply to linus/master v6.7-rc7 next-20231222]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
> 
> url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kasan-stop-leaking-stack-trace-handles/20231227-065314
> base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
> patch link:    https://lore.kernel.org/r/20231226225121.235865-1-andrey.konovalov%40linux.dev
> patch subject: [PATCH mm] kasan: stop leaking stack trace handles
> config: x86_64-randconfig-123-20231227 (https://download.01.org/0day-ci/archive/20231228/202312280213.6j147JJb-lkp@intel.com/config)
> compiler: gcc-12 (Debian 12.2.0-14) 12.2.0
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231228/202312280213.6j147JJb-lkp@intel.com/reproduce)
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202312280213.6j147JJb-lkp@intel.com/
> 
> All warnings (new ones prefixed by >>):
> 
> >> mm/kasan/generic.c:506:6: warning: no previous prototype for 'release_alloc_meta' [-Wmissing-prototypes]
>      506 | void release_alloc_meta(struct kasan_alloc_meta *meta)
>          |      ^~~~~~~~~~~~~~~~~~
> >> mm/kasan/generic.c:517:6: warning: no previous prototype for 'release_free_meta' [-Wmissing-prototypes]
>      517 | void release_free_meta(const void *object, struct kasan_free_meta *meta)
>          |      ^~~~~~~~~~~~~~~~~

Thanks, I added this fix:

--- a/mm/kasan/generic.c~kasan-stop-leaking-stack-trace-handles-fix
+++ a/mm/kasan/generic.c
@@ -503,7 +503,7 @@ void kasan_init_object_meta(struct kmem_
 	 */
 }
 
-void release_alloc_meta(struct kasan_alloc_meta *meta)
+static void release_alloc_meta(struct kasan_alloc_meta *meta)
 {
 	/* Evict the stack traces from stack depot. */
 	stack_depot_put(meta->alloc_track.stack);
@@ -514,7 +514,7 @@ void release_alloc_meta(struct kasan_all
 	__memset(meta, 0, sizeof(*meta));
 }
 
-void release_free_meta(const void *object, struct kasan_free_meta *meta)
+static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231227132311.557c302e92bdc9ffb88b42d5%40linux-foundation.org.
