Return-Path: <kasan-dev+bncBDGPTM5BQUDRBGPRY33QKGQEPBKAJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D1E57204BF1
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 10:08:58 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id ge4sf1627236pjb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 01:08:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592899737; cv=pass;
        d=google.com; s=arc-20160816;
        b=OlSe201+KN/gHwiwfbSEENGsf+sRw3B4WecO9rIlkm7baa7fJ7w/4LaXftGLNvVjNi
         7xu9/+odbE+AOyB/ZJP3qHQRcrF/iGWreitpP+OHbbMU7XjiL2cv08i4shSBuh4ul3m+
         ZY0pUKtNTfnW/vmWLh8foLxDXhD9eQajVIQOtllfbaBsWCSf5rIsJijUgh/WMHowUekx
         RTDUDwOzGRx/T+VqxYvn0FyhdnQgkePHNdsdBXV1w4pvTZOpuc6xeiDSksacBRHjGPYw
         lUfEFZRrppq71/eQI++fPM1u1C96Knz6kJqUtISBjBxawAcS5xof0hIEJPaHE/g47fFz
         gRqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=UX19BQOxkbyvndA4dbAg3c9gCF/3N7+usguWMtKPf1o=;
        b=Yrzncn2A6EK8V1DoLfLGIZUf4u3UzOpm//1QSbIeNNdBCQIpO3jJZqORfgbdaqAZCz
         SwapulJbXukv4EnFMB/13drC7ijrnLEgfJCDl3NCNHMcgSMTlCCJxQxT68Aop2vEJdVN
         fnqzzBsFAkIPAneDR/sossXXrzu6WP7mJIgjKsqZ3K4JEO/8WjKdp/3e7NQdo2xhuqMy
         99FwKBatl+gSoYLNlZg2wt8gZeviwiCDoKdfLsIp2S7B4lb5PK0lUZ1qRK7xW/rR34LB
         I8+gnGR6yFrdVCApuWN3JUVT7uPeimi0OfXLJQp4jzoYh0x0tRFUy4mjPb5qxHtaSEIC
         OKeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tbtPgDHs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UX19BQOxkbyvndA4dbAg3c9gCF/3N7+usguWMtKPf1o=;
        b=JkbzlFxkIszYT7C7hRyofHpclyewplhVxfhQ2YHb1/DQbaKZvh70CU73ZbMUXlcM++
         dJfshFOYafttZebs9ic3/l6GHc4vq9Nx/hEfkxx3jWjCjoNRAVoT7nLaHsh2vbyKbB/f
         eAq2auioWZOq8Muwdjerv9Xeufj0AMajhVxQfGqC3m7bc1dUNhHBPPfqlXZvl1UZYTRC
         HggkX/4SWSxM6kBy39CyudTekgbfT0iMn50JBO85Clg9e6wnGqziB8aAXqDeT3iG0zbq
         F/SuHwsImETRyL9QSsQZ6/f/aTlJ9zhbt8Iz8vDnFAqyImTRxv2n0tjrl76Y47fhqfw3
         m99g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UX19BQOxkbyvndA4dbAg3c9gCF/3N7+usguWMtKPf1o=;
        b=OzoaNAU1PMfqpmol2Hqhou+O/1JjvsXxs5I+DENoIF5Atsb2lz6YKqVAzUzJ+DLvKG
         qPQqZBM5B1CJOl6iG7/rmtxjCk8WzWpTSe85KXtG8GnBLQqMcrF04cjqxuKw00ydeA5G
         kAd3kqFpoZKsHxdMNFwIKQqcBiUsi9NiA9BB6JOEcUdb/jr/lbCaYmYFPhtf8mH2W0Pq
         lhquuLbyTGsCkeA8oMG7zyuTOezKPGIL4B4AjAioO22x5hgkOMPVk6cF7hfeyHBiqq23
         wL7gYiILsY6Zm9OPhKG5W/41mxTQft66y4bRmPNP8p6iIa6aOeU5Dh3IVKhfPfYuFIBr
         OFVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PIyg1dBX88Fq4LP3THd//Pj0CiH0xH/Y88UX5S/aL/iOPyLsL
	IvfnnfHVaMfJT3YtHBgmPdo=
X-Google-Smtp-Source: ABdhPJzP8z/8xUMArhXhU80wjgd/ybE5DzEnW24V27W0DWdoJJaRY6QlDGzi41WHg/EYFU32HYmJ7w==
X-Received: by 2002:a17:90a:1781:: with SMTP id q1mr23188997pja.8.1592899737484;
        Tue, 23 Jun 2020 01:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:104a:: with SMTP id gq10ls1027019pjb.0.canary-gmail;
 Tue, 23 Jun 2020 01:08:57 -0700 (PDT)
X-Received: by 2002:a17:90a:7403:: with SMTP id a3mr21226616pjg.222.1592899737006;
        Tue, 23 Jun 2020 01:08:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592899737; cv=none;
        d=google.com; s=arc-20160816;
        b=PZKXA5KgJPwzvERY5SQbaE8QG/VQAclpKMOCXXQeRiCV32Iu2Ap92GzSl6hTYJEskE
         vxQ5P/C0thLTCVYn2Z4sPaiy0+SZfOo8lGPE6Wxb888FhQEVg5dgMiogMg8VBtHo3kwR
         BW11eCa4xjvWNS7MxkFUFnM13gN5FSn5snzn3gd+daamFT5Z7P9oNYCOQigAPtfxc8Gm
         fkgEVEBKqeS4qD7aaCwdAn7kEGoc4JIjGgPKbuiZaI+IQomnfeoOgSXr/fgniPTaxkGA
         Ym2Q5Esrqp5QMK/a34yaGYkcUHkHKNCS0+haB8BLr9qZx+jDSsit8pyLxQ/hQDZmlkl9
         D2FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=2JUe8k4H2JAIMhaQ+KEJKU5IVfrqr7nlfFcnjCydfXU=;
        b=roYq/MD4AgD+f4mF1I02dBGGVKdLGJQBoJ9f77b+PoTQN8QcNe/cVtd1zuXWp+UpDC
         G8t/LwcgDRjAyIDLb3/oB78AhgxWbU8w7us+Rj9Vxgix3OAo3Be11jv1KfrZOEw551jU
         eGd49r2V9MyfwTZXt43y5ky8jvhluxUsdWE9fa7gc3B+Ir9lGXbSr/iwV9B3eZeG4t6t
         PWNEHHdAoHYTtIgXa/0Pe/Hb3yDjTPv1jrhtXDbHTiMP7d6dETzrJh4EqVJszwR0cm7i
         u/dyn5BnIJkOxX75oWpMRP+/UHVAYKJKgwb3RVw5kRsSYTcQWi1KVkXaLDqM9ePwOACw
         7tAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tbtPgDHs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id w13si96281pll.2.2020.06.23.01.08.56
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Jun 2020 01:08:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0ebb0f637b2f453fb30c8e70f9946db1-20200623
X-UUID: 0ebb0f637b2f453fb30c8e70f9946db1-20200623
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1981792401; Tue, 23 Jun 2020 16:08:53 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 23 Jun 2020 16:08:45 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 23 Jun 2020 16:08:45 +0800
Message-ID: <1592899732.13735.8.camel@mtksdccf07>
Subject: Re: [PATCH v7 0/4] kasan: memorize and print call_rcu stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrey
 Konovalov" <andreyknvl@google.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>, "Andrey
 Ryabinin" <aryabinin@virtuozzo.com>
Date: Tue, 23 Jun 2020 16:08:52 +0800
In-Reply-To: <20200601050847.1096-1-walter-zh.wu@mediatek.com>
References: <20200601050847.1096-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=tbtPgDHs;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Mon, 2020-06-01 at 13:08 +0800, Walter Wu wrote:
> This patchset improves KASAN reports by making them to have
> call_rcu() call stack information. It is useful for programmers
> to solve use-after-free or double-free memory issue.
> 
> The KASAN report was as follows(cleaned up slightly):
> 
> BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> 
> Freed by task 0:
>  kasan_save_stack+0x24/0x50
>  kasan_set_track+0x24/0x38
>  kasan_set_free_info+0x18/0x20
>  __kasan_slab_free+0x10c/0x170
>  kasan_slab_free+0x10/0x18
>  kfree+0x98/0x270
>  kasan_rcu_reclaim+0x1c/0x60
> 
> Last call_rcu():
>  kasan_save_stack+0x24/0x50
>  kasan_record_aux_stack+0xbc/0xd0
>  call_rcu+0x8c/0x580
>  kasan_rcu_uaf+0xf4/0xf8
> 
> Generic KASAN will record the last two call_rcu() call stacks and
> print up to 2 call_rcu() call stacks in KASAN report. it is only
> suitable for generic KASAN.
> 
> This feature considers the size of struct kasan_alloc_meta and
> kasan_free_meta, we try to optimize the structure layout and size
> , lets it get better memory consumption.
> 
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> 
> Changes since v1:
> - remove new config option, default enable it in generic KASAN
> - test this feature in SLAB/SLUB, it is pass.
> - modify macro to be more clearly
> - modify documentation
> 
> Changes since v2:
> - change recording from first/last to the last two call stacks
> - move free track into kasan free meta
> - init slab_free_meta on object slot creation
> - modify documentation
> 
> Changes since v3:
> - change variable name to be more clearly
> - remove the redundant condition
> - remove init free meta-data and increasing object condition
> 
> Changes since v4:
> - add a macro KASAN_KMALLOC_FREETRACK in order to check whether
>   print free stack
> - change printing message
> - remove descriptions in Kocong.kasan
> 
> Changes since v5:
> - reuse print_stack() in print_track()
> 
> Changes since v6:
> - fix typo
> - renamed the variable name in testcase
> 
> Walter Wu (4):
> rcu: kasan: record and print call_rcu() call stack
> kasan: record and print the free track
> kasan: add tests for call_rcu stack recording
> kasan: update documentation for generic kasan
> 

Hi Andrew,

Would you tell me why don't pick up this patches?
Do I miss something?

I will want to implement another new patches, but it need to depend on
this patches.


Thanks for your helps.

Walter

> Documentation/dev-tools/kasan.rst |  3 +++
> include/linux/kasan.h             |  2 ++
> kernel/rcu/tree.c                 |  2 ++
> lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
> mm/kasan/common.c                 | 26 ++++----------------------
> mm/kasan/generic.c                | 43 +++++++++++++++++++++++++++++++++++++++++++
> mm/kasan/generic_report.c         |  1 +
> mm/kasan/kasan.h                  | 23 +++++++++++++++++++++--
> mm/kasan/quarantine.c             |  1 +
> mm/kasan/report.c                 | 54 +++++++++++++++++++++++++++---------------------------
> mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> 11 files changed, 171 insertions(+), 51 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1592899732.13735.8.camel%40mtksdccf07.
