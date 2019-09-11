Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB6VA4TVQKGQERQX4I5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EC2DAFFC5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 17:19:23 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id b143sf25390586qkg.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 08:19:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568215162; cv=pass;
        d=google.com; s=arc-20160816;
        b=wrxU8UWgde8WlWp+Hr7oWAqImxqhIA3Z7d31P/98Kxa6lEcSFEWjVNYFJGchNEmZWF
         yi7Y+Au6NXImiBPFl+DJVxjH9xyTEAO0GWEvdUDeBBmb3yH/7et7BnN+k9/pUMjG2I1y
         jB2K6o2Qxk8ffq5tZhkMfe3XL4KZClg7rn1jIhEG8WY90AemIkO+UIcA1ztQphTTGr9L
         visvnwieZdeA2E1n6+vGeTMqcP/M8JZVDhQyf+uOxumYUmk4R0jHDwV1ZOd93FQzAfoC
         EMtxByBXKNjqazzuVwXANEmFewUmgwUi9OJH/jMGsJtkqEaQFQOR8hSzsJOGHw0gofYc
         uwwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=OYbZXE2efPMH2tYXbtHRJoswUAka4RpEvO+rpjbQ3lA=;
        b=EMzuiLPFRMiAqm7IgqwcBlcJUqfBR+Wo/Zyg9N6z/JLY93XPJA1JkTrXyeuiKe6jjs
         boLSF1+dcyrzPq6JqhRqNdeBs4pGlJ+3BikJ+0QQ8cl1jIvUmqsKZH6ryiyBpXf9thfo
         z0VDbcEcUaALUEj6LaJyiABBurOZyC9SYjOZ+IFaA1XQQ7kTE0CqLfOfcpHehjSv9q74
         VE9An6GaEMC4Zs/kHcfyQoTnLsH1+KcEaHukYrb+SjkkX4MwJdAXhpsy9JGpMLfmgeCS
         Q9pjfPqUj07BzRydle9l3E3U/TLTdw2SEFThxaxUukwJk1yLt8UB8uZRhmWwUzcWJarN
         uPqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=P+MDd2FC;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OYbZXE2efPMH2tYXbtHRJoswUAka4RpEvO+rpjbQ3lA=;
        b=EWdV1dM1KPMjIRL9EPPcjBx+UUqLAkFQXn4WyU/n4+Mp9Xigre8hcPWKXzxyGt0Ikw
         2OaGLlyt5wZMbNAh4IvCOeobmOCzLWyyMw1cq5zcwze9nJKj1XZBNagd5gvIo5rk/UqF
         pASQw/fmzEiUtp1WT4mVizZoNJUj8ockQABXYnSfavVGa9aN8MpN4+w+/W9Orx2I2Bt7
         J6TUq22PS4kaPI8UJAdEa5Vmp2uWlbYQm8WfqeZ5PycAe/+KZMQUrMi+lJcd0Du8N+Qx
         DEZyPPPDI+3LAjei15Fq/R0cE3npbSCSsEwVHd13mVYOKKUtfw2XhBPx13giuEDuFD+U
         EwoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OYbZXE2efPMH2tYXbtHRJoswUAka4RpEvO+rpjbQ3lA=;
        b=jcErBE72W3Y/W+u7XXQBGYrKYCw1QdYoCr3j5tNUID2ZV8ow/yeD3wg7tw61/12Nuy
         I/ka/dfXOR/7umGRI8hddB8fulsB9+/aAUWR3vT+ZaFWAvV1x5RvvxRKZZdy2XiViuV2
         M5CbvgFfbGnyX0KADZkV3D+lenflq0SOnETpGi4NoTCfqdfp/gAZzHjOOS4Ke/HDY01S
         IGvVyptrAsWPQo5hIzIdUORoeKvZPduh5bcatbqbD/s1cBjXFtPYFj5TscjlEucvoiTV
         DWcpP0Spd/ooFjskhUQ9CXkbB/gJ/BxB9J/H2A1cTKrGdz581GoySZxQHPaNn8jGOnTK
         tBZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW0rJQRxCTZhVg43at2+3NDY645qZMJ1lIMBMmlSEa8PVFepN3M
	hKInuc9O1ck7KwfSJ6vDj3o=
X-Google-Smtp-Source: APXvYqzJQzGEroh8BKJNQWU0w+2wAtjeT9S9ahpCsboO0vEi7eRKeWYBFuSGUUhaZzSQZWn40CxFJQ==
X-Received: by 2002:a37:660c:: with SMTP id a12mr35710250qkc.70.1568215162367;
        Wed, 11 Sep 2019 08:19:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4896:: with SMTP id i22ls879752qtq.9.gmail; Wed, 11 Sep
 2019 08:19:22 -0700 (PDT)
X-Received: by 2002:ac8:3525:: with SMTP id y34mr36398264qtb.140.1568215162088;
        Wed, 11 Sep 2019 08:19:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568215162; cv=none;
        d=google.com; s=arc-20160816;
        b=iks+l/oN3h4Vli94pGFwYoOg2tDdK7sT2n/ybqVxcdLumk2XYly7C0NvFmQz8BaER4
         hU0WEDWNDaqfCowWaFJfMOPwojH5emKLkANs/BnbOGsTM2fX/UwTICI20pbu8gpE/I1F
         cIH+UHvg9eRQy3E/CGW1zrTzcx9RtYa8u6UrDsglTX638o36hevTR3T+O69ktZ6OvJ0E
         Ej8d4hcaUooR55s6Gpu8lj5+5adUKq6wngKdmOAXSlhiZW/jtRqLcxFE6SLAMX+npJz2
         toqGNIONbExT3LZo0LONqS1FxiIt3iTH0NlbeUdOhOWaQUyoV7Ne14ejghLkFbJkGz78
         IqrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=ZU9ZAjmx+sYl629AtpqCVueI4p9/wYdOG6Cg3kJEbbA=;
        b=tO4uKnONKj7P6Z5u50o9pFntW69v4ftHPoSBUEBHewE2r36Z6+4wyxN2oEYjlcBIQS
         pF3QDlkrORLizMaTdMq+YrEAYsXYnhjIfcasLEdLspFxkbI+lLY1J4qRCUMdnQEe/+tv
         lJLsS9KnCoHpK66klfzZ2ob0TZjNU+ds8Qjow+igiP2C2HclqiB4fXvgn9CsrCZdGkcb
         E/ajZWZ9D9Ny56qcgfjek9NiiT3RjfpatkL9Ob6KOlK95qb9ndNzXdka0q7AfWa1sAPH
         6CKCQK4FF4QHvI6ZIcN+PFy8j3GGC8PuH+5b54KOaQ9nETzYIzDQnztWftm+rA8LHpXw
         x/Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=P+MDd2FC;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id w41si1362547qtb.4.2019.09.11.08.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Sep 2019 08:19:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 201so21130185qkd.13
        for <kasan-dev@googlegroups.com>; Wed, 11 Sep 2019 08:19:22 -0700 (PDT)
X-Received: by 2002:a37:49d6:: with SMTP id w205mr35829035qka.191.1568215161746;
        Wed, 11 Sep 2019 08:19:21 -0700 (PDT)
Received: from qians-mbp.fios-router.home (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id g194sm11256279qke.46.2019.09.11.08.19.20
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Sep 2019 08:19:20 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
Date: Wed, 11 Sep 2019 11:19:19 -0400
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Vlastimil Babka <vbabka@suse.cz>,
 Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 linux-mm@kvack.org,
 linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org,
 wsd_upstream@mediatek.com
Content-Transfer-Encoding: quoted-printable
Message-Id: <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
To: Walter Wu <walter-zh.wu@mediatek.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=P+MDd2FC;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Sep 11, 2019, at 4:39 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>=20
> This patch is KASAN's report adds the alloc/free stack for page allocator
> in order to help programmer to see memory corruption caused by the page.
>=20
> By default, KASAN doesn't record alloc or free stack for page allocator.
> It is difficult to fix up the page use-after-free or double-free issue.
>=20
> We add the following changing:
> 1) KASAN enable PAGE_OWNER by default to get the alloc stack of the page.
> 2) Add new feature option to get the free stack of the page.
>=20
> The new feature KASAN_DUMP_PAGE depends on DEBUG_PAGEALLOC, it will help
> to record free stack of the page, it is very helpful for solving the page
> use-after-free or double-free issue.
>=20
> When KASAN_DUMP_PAGE is enabled then KASAN's report will show the last
> alloc and free stack of the page, it should be:
>=20
> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
> Write of size 1 at addr ffffffc0d60e4000 by task cat/115
> ...
> prep_new_page+0x1c8/0x218
> get_page_from_freelist+0x1ba0/0x28d0
> __alloc_pages_nodemask+0x1d4/0x1978
> kmalloc_order+0x28/0x58
> kmalloc_order_trace+0x28/0xe0
> kmalloc_pagealloc_uaf+0x2c/0x80
> page last free stack trace:
> __free_pages_ok+0x116c/0x1630
> __free_pages+0x50/0x78
> kfree+0x1c4/0x250
> kmalloc_pagealloc_uaf+0x38/0x80
>=20
> Changes since v1:
> - slim page_owner and move it into kasan
> - enable the feature by default
>=20
> Changes since v2:
> - enable PAGE_OWNER by default
> - use DEBUG_PAGEALLOC to get page information
>=20
> cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> cc: Vlastimil Babka <vbabka@suse.cz>
> cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
> lib/Kconfig.kasan | 15 +++++++++++++++
> 1 file changed, 15 insertions(+)
>=20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 4fafba1a923b..4d59458c0c5a 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -41,6 +41,7 @@ config KASAN_GENERIC
> 	select SLUB_DEBUG if SLUB
> 	select CONSTRUCTORS
> 	select STACKDEPOT
> +	select PAGER_OWNER
> 	help
> 	  Enables generic KASAN mode.
> 	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
> @@ -63,6 +64,7 @@ config KASAN_SW_TAGS
> 	select SLUB_DEBUG if SLUB
> 	select CONSTRUCTORS
> 	select STACKDEPOT
> +	select PAGER_OWNER
> 	help
> 	  Enables software tag-based KASAN mode.
> 	  This mode requires Top Byte Ignore support by the CPU and therefore
> @@ -135,6 +137,19 @@ config KASAN_S390_4_LEVEL_PAGING
> 	  to 3TB of RAM with KASan enabled). This options allows to force
> 	  4-level paging instead.
>=20
> +config KASAN_DUMP_PAGE
> +	bool "Dump the last allocation and freeing stack of the page"
> +	depends on KASAN
> +	select DEBUG_PAGEALLOC
> +	help
> +	  By default, KASAN enable PAGE_OWNER only to record alloc stack
> +	  for page allocator. It is difficult to fix up page use-after-free
> +	  or double-free issue.
> +	  This feature depends on DEBUG_PAGEALLOC, it will extra record
> +	  free stack of page. It is very helpful for solving the page
> +	  use-after-free or double-free issue.
> +	  This option will have a small memory overhead.
> +
> config TEST_KASAN
> 	tristate "Module for testing KASAN for bug detection"
> 	depends on m && KASAN
> =E2=80=94=20

The new config looks redundant and confusing. It looks to me more of a docu=
ment update
in Documentation/dev-tools/kasan.txt to educate developers to select PAGE_O=
WNER and
DEBUG_PAGEALLOC if needed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5E358F4B-552C-4542-9655-E01C7B754F14%40lca.pw.
