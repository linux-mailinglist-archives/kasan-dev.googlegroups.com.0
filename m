Return-Path: <kasan-dev+bncBDAZZCVNSYPBBYO777FAMGQEIRMYONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D629D05403
	for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 18:56:51 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4f1d2aa793fsf105685181cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 09:56:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767895010; cv=pass;
        d=google.com; s=arc-20240605;
        b=iChHA+Wl4h2iZaE3cHW2FrKi/Ym3+wGzJMwW9LKOPOC+/6Z3JhLFYHZPFBI0apmCmN
         s0qJ7BkOlBrq17jeiP8mY8VQCUZpExW//zW9dnCJ89oTww4P7vI12kquL5Lgd3DUJZDA
         R0KNVBCzB5sIBwf45quL0y5q8pRrs/tsgq5SYF0W2XgZNXtlh87G7xd9+6t+DTDK29EF
         jOUDgUcWPqTC8cULbHM18NlgrdnmEzeGfwCVDs0ojBPQ4AHceCyahDhsNndWxoqgeeiK
         lbyT6Xnml9HATxngYB7oe/GEUJ9QcBb2E3x3Pp6rGzJJa3mRaBVD4oFhqIjkUadYSJBx
         jh6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tOIjs9L8taq5+WCZmq0ixOvYgB1OYImcdoOuYWf68I0=;
        fh=Ve53TUUXdDA4PR+jPR3VllMYfgmJKVp7ip2PzmfTRDo=;
        b=eA2Q4RQNo1smIe8fBqb/igqf+ojizDA0eWYvUiqLFaldfQJEkBy5it4rScyz0TmSlv
         mNaCVqOHYA+uN5q2h2dcqkVGGHZhOphRRfzpCMKa3Ybj1IURHP0yz/htQvA9RbnzZGKj
         1kSwEOeA1GwJBvUUgg4kicM974cX9GjscLQK7jJswHSLYYMyb+PrmAAotICTTF09Mowr
         y+dN8u4mizD4/7ib+ONTNvBYb8D1iy4XtZlLNOE6YLqoNwuEBpLaC6tl+RWYkIl9l7Ja
         27SAH3AB84ravfdj0bbimDQeyurrWOUUWSTKhJVS/UVyD/Lz+rT+432IyG6wzgA63UoN
         o0Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a+78jq3R;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767895010; x=1768499810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tOIjs9L8taq5+WCZmq0ixOvYgB1OYImcdoOuYWf68I0=;
        b=otuC8QhtLWuPn+FtBWPNjpzxPM1p3/nm/xVpObpKcAtLqDBL5WU+uXkJTacYw75iqx
         lywOUW8IUa0RhfVYd9AyFq2c2xqjN0xgs7qK6Cre6Go1vVh7CaIduqhDcYy/0qTQzFaZ
         e9Urt2v7LiJJSl/9shYFPxEtmL4aOt78o0nRKz4WjEz47lHFseIlatcD8Iz14ZClzSoZ
         wBMMoA2iWMSlAD6YGX6eGIU6jJ5QWVB3U7nU85NdnqE3r06LzpvBVVUy3gPueWDgeb3L
         qFR0r8z9MEw/+N/blla75E9TggGD+UekO8+ZlfP5cn2lpOf8ZvSuJpRrUt29XrMibmK8
         DVeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767895010; x=1768499810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tOIjs9L8taq5+WCZmq0ixOvYgB1OYImcdoOuYWf68I0=;
        b=mnfKRWrVWxc1o3eO140KtQ+uFoBqpz7zWpmmA8wzbAcn9wCPhf5YiV4JYi4V4e7A/0
         yKWeopImrAq6S1cfLog3Un9V+e2+XXeq05XYmAxJaBCOEu4dIMIzREVbCfV0TB37Fpbb
         3KkPZX9N54tD5o/G2NJmarKPf26ZpxliobuxClnMPM2bK3VbV8c6jjPU+4NmoxE/AF/e
         dDwNN9+LrkAX/45gKAbWxG/q+wM/VWTBp6IYjJjYZh7ZiMURmoUYZ2oDmKo7j+Bqi8wW
         Ie2rEV44Jl4nxzdcKJFX+lhJyj22u7J2YRoYYKt5k0DWIoThHOGJO9aJytbYVsQO4epl
         gxsA==
X-Forwarded-Encrypted: i=2; AJvYcCUE5t4Cb9ZfJh3hA0HJiBsvnNyHXMX8rJ410zk7HsHtrZzjLTDZopIPbf/KJgv6Ucb6NtTtXA==@lfdr.de
X-Gm-Message-State: AOJu0Yy6rBkFJBEF6OMqQ8rSYxZcAuOEKaxzCuWmHOkgdmTl51MEJIGT
	R+mZvZrRSsbuQNyvTns1KPzNZOOzIoFtexV1C7E/vhB7q7clhZRufjzR
X-Google-Smtp-Source: AGHT+IE2TB6sIZLEkkHi7mEVQpVSvtsFzxSyTOyzkODlj3SMv+owQGIcMQlLrfGMIG1b8aazcOQ5jQ==
X-Received: by 2002:a05:622a:16:b0:4ee:2423:d538 with SMTP id d75a77b69052e-4ffb4825cc6mr90054401cf.18.1767895009493;
        Thu, 08 Jan 2026 09:56:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ5wgmHmrw50Q41ei+NaLhRYsBXhRVImBzi6p75VK3FBw=="
Received: by 2002:ac8:5e4a:0:b0:4b0:8b27:4e49 with SMTP id d75a77b69052e-4ffa70f1872ls72099761cf.0.-pod-prod-02-us;
 Thu, 08 Jan 2026 09:56:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDtqPXw11vyi38UV/B2krETAFTZZFzM1osoBlXT/lRNON639m4cfySZz/deaNitI1Bs4K1Q3ycjO0=@googlegroups.com
X-Received: by 2002:a05:620a:1791:b0:8b1:7c0c:e27f with SMTP id af79cd13be357-8c389434aa3mr765435885a.82.1767895008357;
        Thu, 08 Jan 2026 09:56:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767895008; cv=none;
        d=google.com; s=arc-20240605;
        b=TnpMRCp1Is5EBsxfG1/vyRd+sDzQQ5nT0++X0ztGSgLoEoESUW4wf275lsjUbzbtef
         9SHETusjXSubgIl1XZosDflA8H5zk5ygi2rLlFMFFLsO2ioRhekqEWQt9aGvfAx2dj30
         mrKexXqOK4dKrbQfkvq1RGLT2YLdEKR7hatZCQ1S45a/rfdjg180hShhsvNxz4vszF4F
         nf0lfBbAYgr/odVJrRYldZDpDyxLfGUPYaCTpkAY3+ABEU7tBv+A9YfRV+ZLDzrHMf3f
         v+ilKtchYZr5KOG6Hc3el/8lAiTg0CgQJFHa/bLbsv7N1aU19vNSWDw+Rd4fYVdY7k5N
         Qvew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OODmGsMJR8KkWVIwL3oduI42mZW6JkdE7mQV95TGWGk=;
        fh=0klHsykIlYA0L02PWevGOvSi1jbl2pNEFV7/5iwQ0Zw=;
        b=ibNAGIS/OGuMDLv4tCGXXe7r5HKmOt1c19d3LZwI26RTTHAaE3EIcwlYcO+YWnmLPB
         /as0VAlgPtfV0Syv0/LQzcTdXyeOFluz8lpvt3pWJWcWMY/tm8bgQDbSagMSxpwbrldn
         DLB8ClI+e0dYkKdOIuUn4wcC44fSbAU8BRRcHOm9Z2i/pYdTpLhZG5tsDyYpWo5g1xCp
         1MypMeRx0S1vNd+5JUCzlLcJ5MoKtjFpmk7PlUc7FXFScl2kQ18qRT8vfL93i+vwYs+J
         6hhhVALZUApvB9DCIZI1PgPzeU3wvg6Vo6vXiibUE5nE3Sh1r/OD0ccOsRny8Wah8pKK
         qirA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a+78jq3R;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c387c51770si14209985a.2.2026.01.08.09.56.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Jan 2026 09:56:48 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 82EAF60132;
	Thu,  8 Jan 2026 17:56:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5BEA0C116C6;
	Thu,  8 Jan 2026 17:56:42 +0000 (UTC)
Date: Thu, 8 Jan 2026 17:56:39 +0000
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Samuel Holland <samuel.holland@sifive.com>,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v7 02/15] kasan: arm64: x86: Make special tags arch
 specific
Message-ID: <aV_v18YWCHXMETVK@willie-the-truck>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
 <0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman@pm.me>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a+78jq3R;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Wed, Dec 10, 2025 at 05:28:43PM +0000, Maciej Wieczor-Retman wrote:
> From: Samuel Holland <samuel.holland@sifive.com>
> 
> KASAN's tag-based mode defines multiple special tag values. They're
> reserved for:
> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>   in the tag checking function.
> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>   the value that is used to initialize regions of shadow memory.
> - Min and max values. 0xFD is the highest value that can be randomly
>   generated for a new tag. 0 is the minimal value with the exception of
>   arm64's hardware mode where it is equal to 0xF0.
> 
> Metadata macro is also defined:
> - Tag width equal to 8.
> 
> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
> values need to be changed accordingly.
> 
> Make tag width and native kernel tag arch specific for x86 and arm64.
> 
> Base the invalid tag value and the max value on the native kernel tag
> since they follow the same pattern on both mentioned architectures.
> 
> Also generalize KASAN_SHADOW_INIT and 0xff used in various
> page_kasan_tag* helpers.
> 
> Give KASAN_TAG_MIN the default value of zero, and move the special value
> for hw_tags arm64 to its arch specific kasan-tags.h.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v7:
> - Reorder defines of arm64 tag width to prevent redefinition warnings.
> - Remove KASAN_TAG_MASK so it's only defined in mmzone.h (Andrey
>   Konovalov)
> - Merge the 'support tag widths less than 8 bits' with this patch since
>   they do similar things and overwrite each other. (Alexander)
> 
> Changelog v6:
> - Add hardware tags KASAN_TAG_WIDTH value to the arm64 arch file.
> - Keep KASAN_TAG_MASK in the mmzone.h.
> - Remove ifndef from KASAN_SHADOW_INIT.
> 
> Changelog v5:
> - Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
>   mode case.
> 
> Changelog v4:
> - Move KASAN_TAG_MASK to kasan-tags.h.
> 
> Changelog v2:
> - Remove risc-v from the patch.
> 
>  MAINTAINERS                         |  2 +-
>  arch/arm64/include/asm/kasan-tags.h | 14 ++++++++++++++
>  arch/arm64/include/asm/kasan.h      |  2 --
>  arch/arm64/include/asm/uaccess.h    |  1 +
>  arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
>  include/linux/kasan-tags.h          | 19 ++++++++++++++-----
>  include/linux/kasan.h               |  3 +--
>  include/linux/mm.h                  |  6 +++---
>  include/linux/page-flags-layout.h   |  9 +--------
>  9 files changed, 44 insertions(+), 21 deletions(-)
>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>  create mode 100644 arch/x86/include/asm/kasan-tags.h
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 7bf6385efe04..a591598cc4b5 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13420,7 +13420,7 @@ L:	kasan-dev@googlegroups.com
>  S:	Maintained
>  B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
>  F:	Documentation/dev-tools/kasan.rst
> -F:	arch/*/include/asm/*kasan.h
> +F:	arch/*/include/asm/*kasan*.h
>  F:	arch/*/mm/kasan_init*
>  F:	include/linux/kasan*.h
>  F:	lib/Kconfig.kasan
> diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm/kasan-tags.h
> new file mode 100644
> index 000000000000..259952677443
> --- /dev/null
> +++ b/arch/arm64/include/asm/kasan-tags.h
> @@ -0,0 +1,14 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
> +#define KASAN_TAG_WIDTH		4
> +#else
> +#define KASAN_TAG_WIDTH		8
> +#endif

Shouldn't this be 0 when KASAN is not in use at all?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aV_v18YWCHXMETVK%40willie-the-truck.
