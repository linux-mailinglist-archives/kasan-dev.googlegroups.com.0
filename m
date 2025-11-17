Return-Path: <kasan-dev+bncBAABBAWW5XEAMGQEUTUM3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58F46C65BC8
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:35:48 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-65703b66ebfsf7260792eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:35:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763404547; cv=pass;
        d=google.com; s=arc-20240605;
        b=S5J8jvLd+fGdhPqf2MBDwWRq3otuk4BXDiP4KPjDAwUcVkti/1yLfQc5LB0CPOP+PA
         MQ2qi9pczCuLT92nQQHAh8gGR5Bstn6eMwpLJciY5cYkrNfmkJaRuXRUTJFnr1nzstXO
         H17likDXleF13m7Q623tUOwrcuEJKeeJuGtsTEaPE1jM5z5zko6iiuamWrl0U0YeDC/Q
         ugGCvbw7/nf6lLE3DaPV5rsQH8L3bA+g5Qy6h6GUde4hix0SZnAN2v8uxNd2qqU8EXSX
         J4EfGtW1vVnsaYhNLY4/P2ERsUUgGxjLbeJdE6Gf/Lgs8oA5tVS+AWeQX5btpCBpvPkR
         59ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=orPYhVszVNp5AabJiY44QHFK7h/vGiJaI11X5tV5tiY=;
        fh=QJemhrKyUkE/rfWqmcKhYURX8/F5P2q8vC6eiAZgUak=;
        b=CpV1eCJyFxXUJsMsmxjJHzEh6oVxZk4SMXXRpP9e5NlwRM3OSn+NuqmN7jkUcG3xOA
         hPrEaW7sHS50D20nDvIfHCJin4nwRdB0U5+xZbu2JUSKKrZWwgfAK5H4kOXUg28O9EC5
         9LQCJIDWOALrYWyPyAF0ltHr31QH72hAZDyXe0XiCLhBxSwIdV1xkU351dyXWn7PH8sG
         KBimuJzYMzPxCVRC5yNiA6bkY4Mnim0q8Svgo2/M8CkAR765WrAAFUSrRU1/NYAbrYru
         7CyiX+OyfeV1MJ5wjumZVlTS5a14S1C5zC9B1su4t/T3HOMXXRrChUwmyVz+Z20tfpMp
         5HFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Ow9517Gl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763404547; x=1764009347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=orPYhVszVNp5AabJiY44QHFK7h/vGiJaI11X5tV5tiY=;
        b=TZP2+xfyYvG2e8CnQFvBauTyXDpewisqtGzJ4C4WbVCwfdZ58NFbeULBrQg+cfDWq1
         dt6IP0IT8CWKzch8FBXTsKl082j9P+GO5XUOdeEkJ4NPoS2MHcE5UATuvXYiq1avOwdp
         vuPhWQ/oOJC9rL939MzUwrhf1CzS33zjAvPIw/4LRWt0EEInMfhKQ+WY41MTNwLC8BYu
         a8h+jQk5b09UuUiTx3ZzHQF3jyR8SoQJsTiE6S9A4kkBPDkwdfrxN2srxe4MhJKjVnre
         gcN1FgrRGsdUeK6Ravm0DZNKaNl3TK8lxPVxA2+gwL4a6hBZxUG713JKK5Z6HXtZ732m
         zIeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763404547; x=1764009347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=orPYhVszVNp5AabJiY44QHFK7h/vGiJaI11X5tV5tiY=;
        b=atfWLYoSUeVjXJ56brjnufXOOSGNr2tmIXBaj6MRuGWUrYUlYD2a3Qu/j8echxLFvz
         NJMj6z67HjE0L1NkPo6bT5uvb3p/nJbNXPpAMkJ0m9yRwh3qtS3aH8gNBRufT9usssis
         CAupIDRyuh9EJMSeoHci1Zw4bVbjw0a4QEtmYChkUqG31rXlAU3xvSVvJ2aAsr/zZShA
         ImIZrLL3QeiDQceaBESzHgk2tOI5fdNL5WRu3qNc/imwSne6Du7mAMyrj+CfyzlKRNC9
         fAhAxJj/iGuA5Qqu+uu/UiewrSBE04b0fjdojPZiOHZVKdKXut68ucQagMdi2poI8uMJ
         38Gg==
X-Forwarded-Encrypted: i=2; AJvYcCW+68jbjQq8uvPoTPOpV23GDJCRr0+EQl2H9jpSqz3SpC1thVdhrz+mp36x+BbbeTIoXwOvnw==@lfdr.de
X-Gm-Message-State: AOJu0YxmUAxunXukNqMT8NfE75usDchH2UKBuvcwzqS9ZIiwbxtQrQgU
	qCFkJnNSxeqNvUmAiNRaHWFKn/2z5MaDbb3kXHLoyMVJv7ZpBnVHNc9R
X-Google-Smtp-Source: AGHT+IEtzFpA6oIkuyPF2OHs1cLNXkMQxn/BA84B6pPw7J4iMemCJlNsCh3HSJ+SFblXV1g5rQBCPQ==
X-Received: by 2002:a05:6870:2492:b0:3d1:a15c:f06a with SMTP id 586e51a60fabf-3ec60916b21mr280564fac.0.1763404546975;
        Mon, 17 Nov 2025 10:35:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZxSvRtoCDPC2dy53zZRyiFJjSSW91zu1K5HKDKLlXAVA=="
Received: by 2002:a05:6870:d404:b0:3db:9ad3:39cc with SMTP id
 586e51a60fabf-3e84b3458cfls2077215fac.0.-pod-prod-00-us; Mon, 17 Nov 2025
 10:35:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUUwX3sXLNAocFE2DIbjmtgyeAS/CuVCa4uBOHN5/pNCClW6nEKH6V0km3PmklLlZqGPYzqHcPmrK4=@googlegroups.com
X-Received: by 2002:a05:6870:1d07:b0:33d:c5bc:1a05 with SMTP id 586e51a60fabf-3ec60cab353mr253909fac.10.1763404545905;
        Mon, 17 Nov 2025 10:35:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763404545; cv=none;
        d=google.com; s=arc-20240605;
        b=CMuk7zg9ET6f5/IyAEDfoaV1opKD+dT6MATNkvv0JyNZ+AjkEiCa1YBZeEvN49UXUM
         JW26ODEUe/8Ngkn4P4qjAySaFEa+25kr/GSV+NgNf8ZTjctVvDHh0eTaD+subC7dlN98
         AhFJjLLL32hCFY+2DfZrWQpb4D5NOzpM150UZsmwm13PPxYO1SK9vh+GwWlvszztUXvB
         HoUqyCZJDTbVv+NFPgc7u/05gFf4wOdO7KOeIKZzO3nNSAFdIs2gEMTbt+LAl1Pi25SQ
         j/3KrisGSue7/0zYbvv6Sd6Cc5/3DOl7MK48K2IqTVB/WfDq+mXg72BtXqLJocSaiR8P
         wTjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=zH5WVIO3cxOwoV7JqKcP1ToXH/X437vo+cbBXaQZW1Q=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=L0z2OwUw6ku+944lMCZTC9pzXRBGnwunzHKf9bhxNjDrx6HJbPN4GFX+3d0J6MkgQl
         VRUqW+6WQcJHpFjc41wgbhm0b7xKrTg50jYWgoketUWi28o7Tc26G1OTSaXIr6KjXVgi
         G6lhkEPdkf9rF4KjPTzUyQ/1tAkhdCs3nyvio/7+q0s4L4EhKUksYwzNgnGj5wVtEO2I
         KsG1H7XVooo/YzAmNHL60bxaIZRUjF1XEfp9Vq+iLMl5sTIY5H10lIFDBZmobNvm5+xa
         rmAI4Ku4gBA5rVLw05la1nYHi7ZFIjSn27rmtMR3kcdFhH2iQwk1XPUsB6WRmy+hhOU0
         XdrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Ow9517Gl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3ea15cf1abesi215347fac.3.2025.11.17.10.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:35:45 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Mon, 17 Nov 2025 18:35:38 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 04/18] kasan: sw_tags: Support tag widths less than 8 bits
Message-ID: <6rh6ynwrmh7afqkfyfphiy6rv2xjpdpcotzooqfye6lg7rddhe@betrc4geghsk>
In-Reply-To: <CAG_fn=VUx7GkcjuYO3oRH7ptgKVtzQNChW1xKL+1SPfJ=XvWwQ@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <8319582016f3e433bf7cd1c88ce7858c4a3c60fa.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=VUx7GkcjuYO3oRH7ptgKVtzQNChW1xKL+1SPfJ=XvWwQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 89bdc726c809a41792e2e4dd98d31d2c2e8b87c5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Ow9517Gl;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-10 at 18:37:59 +0100, Alexander Potapenko wrote:
>> +++ b/include/linux/kasan-tags.h
>> @@ -2,13 +2,16 @@
>>  #ifndef _LINUX_KASAN_TAGS_H
>>  #define _LINUX_KASAN_TAGS_H
>>
>> +#include <asm/kasan.h>
>
>In Patch 07, this is changed to `#include <asm/kasan-tags.h>` what is
>the point of doing that?
>Wouldn't it be better to move the addition of kasan-tags.h for
>different arches to this patch from Patch 07?

I wanted to keep the split between adding the generalized definitions
that Samuel did here, and my arch specific changes. Thought it'd be
easier to review for people if it was kept this way. But maybe it's a
good idea to just move the asm/kasan-tags changes here too, I'll
rearange the code a bit between these two patches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6rh6ynwrmh7afqkfyfphiy6rv2xjpdpcotzooqfye6lg7rddhe%40betrc4geghsk.
