Return-Path: <kasan-dev+bncBCKPFB7SXUERBEMI5XCAMGQE7RVTB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 407BBB228C3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:39:31 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-240908dd108sf39729585ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005969; cv=pass;
        d=google.com; s=arc-20240605;
        b=GUdpkNiWgkd6t77zWdnftXHSbThVCTnLhkiFwO3X/+oy7X8JhkAMeXmtZjG+HF1KsI
         diRaswwFUSwPz2qR72zCq32dZ1a1LVMMOXnDKME/AtTi4MU7cX8d6oZ2hVfQYtpoNVZm
         RrlqeUGBWm/nyhugOaPUjiT2xi35fquC36R6TYq8WTeYsRQ9hIlE6fr/u27Ki3adtTEq
         Go/6aiiFzeZmaUFeG7I5kaT7BYyPnoFp84yKpmndQNuJPb3OB5z3OhQWFlgl9mRCjGhK
         /3Qq3L27X4MxO/I9/d9u3mHyLUJKqSNW1Ghf7YlIohJc7sdYMYfr0yEUI7pekhj12F4g
         Wybw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3SgsKKp9Xy5dg58EvKx3CzzMQT/rUTGePk+EsqhwIeI=;
        fh=Qy4eXkG6fg09Ptm2vSzWy14R6GuAIZENulRE6bMq38w=;
        b=T+2v9Rp3NS5nBu4k0SGSb42qiI8c6ZzwF3NK2ZxWGqku4TVaWGoLi9XINAd42J6DeK
         tciRHRhLJzbSxszJW0ohWMosqb+s8IPTxQXOctYxbDN/wPRnjOFGeW22yjPJ65emOE6H
         d/xUghQN/EpGK4BN8ZFRTdxerRai2rFIHiqJ0I+YHa/UW07tn05AN44cFWFuR8ud/raP
         DmMWRW6EAmE/mjqKHby5I8HNQ7jNgbKMKNg6JDiAGU7rJtZjJ0Q8UiCB+EkEdHTg1di9
         611ZvfRSmzxfzp2fdHpM1BohXwc85kWEPxbYkOb/oIKSt5mD5F41TAeB/cqtVkC5HZo8
         VboQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DFGdEDIH;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005969; x=1755610769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3SgsKKp9Xy5dg58EvKx3CzzMQT/rUTGePk+EsqhwIeI=;
        b=WYSMcEYAf0oXPmvF4iO44dLFNltQC79D9HPFNnSKSojXIKVs/h4QKIVrYy8kXHP5WD
         Ob5+YMaweUODTrkw7YSzcz6Y1x5XJcYfzqpUa9WZrgt/eIJEg4pe1ygzStE0eEGVfoIG
         NM0JL9Argznuq7+0+4vHlRzuYexNCM7rmS/i4li42cn1Eykir5JiShK+q6lsXuFjkcxJ
         Bf2iaLYVcbV62cy0Yo1GpIdYrItTbmVyN46vW3k4+pySkoZWMLhYhJrEdS3m6g5Np2ab
         x+061EYb1g9zI05qIWQZ/SCtJFTGexXxqIkpaeacmPMVdd6nI9KGXZv21zQLIfry4dc6
         +vAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005969; x=1755610769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3SgsKKp9Xy5dg58EvKx3CzzMQT/rUTGePk+EsqhwIeI=;
        b=JwR0vX1yh/XSPgrmt5PpjS6q3jy7eveHjxyPPjQnLiZnU3iqsd/MMgg3BlLSLBKKZ5
         9nLObBB6HcfAeVRlX1pWs31pIAEumX/oPFkiBQLHGe0bJIyWH0DbgPmJeyaT9xc6FJjd
         gsBZRDEAofqnFwqFIzM/m3/Ajoza3+IhS3oyKBkISkMdsUXdybuQ/d1Or4saF93mVrRe
         F/odJ4psXge1P/i1dRYN4E8vpqrVyXtXqmMslVy0SOlkDOC7FEekWp/j5YLZmq45k32U
         Gv2zS00fJi5Sjs2UbFor4ODeKOFsC7wt4GXNRcrsJAuozxKqrhVjypauYybyACYkTtW+
         Sleg==
X-Forwarded-Encrypted: i=2; AJvYcCVzLqE8R41FdE0ey906ocoWP1XnNQfzW8Z0+YFnS5xNYw6MnXapw6JwCQIKTC3J8pS376D1zA==@lfdr.de
X-Gm-Message-State: AOJu0YwZ7Pu6jx3B4hGEAa5nm0RQ/FizUklj3IjF+G+jLrS1pege1bw7
	JcSvMhlXcUBYasP3CdtrZpjOT5Am92apjEO+XwvoQle1m6FKZBBbE9Ew
X-Google-Smtp-Source: AGHT+IFrr265ZRCpAk5b2zrDc16yDtmOx4tPillfXmrVj/F75D2Uy9SxQLgm8I09LKnU8fbsHq6gGw==
X-Received: by 2002:a17:902:cec1:b0:23f:f39b:eae4 with SMTP id d9443c01a7336-242fc32a4b4mr52812235ad.9.1755005969471;
        Tue, 12 Aug 2025 06:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCi4hB8Xv5NBQ6lVhOpIJMQuje42r25Piv/p+CQL7TLw==
Received: by 2002:a17:902:db0e:b0:23f:8c3c:e26e with SMTP id
 d9443c01a7336-242afb5f20dls31382615ad.0.-pod-prod-00-us; Tue, 12 Aug 2025
 06:39:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9lVeC4mht1vUT5fcpWQUz3UNaQJJ8rU7Ts3/+FHjgz7bbNAfbZp2n0ajLQHM32+68wQegY1NN/B0=@googlegroups.com
X-Received: by 2002:a17:903:22c1:b0:240:4683:90a0 with SMTP id d9443c01a7336-242fc2d2186mr44706275ad.6.1755005967536;
        Tue, 12 Aug 2025 06:39:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005967; cv=none;
        d=google.com; s=arc-20240605;
        b=c8T/d07+1NK/RhNzmcxstN0p0HbZP0stzw+JYNd3cZE9mcYlJIsOLDGNYQSLkIS0pw
         tuSKnQAwbtprft6xxsuoEV/6csf0CkiSZnGjscg0/E/kqZnZJiJZfK14N1I5SNyhBzH0
         u/qgGhLwb9bpC9Uul7VW8Y+Wo0L1Zew9ONaxOm2wYx7VXVNVGKlLnbOFsKJC7JDrHYi3
         SDEx3jK+Cob2NLZVPF4cnmSVFetFHREK1m2um+v0Wv6fww47xHy9velbveiEwpAwzUse
         6aDwfo+a3cbj8mQj1hHFot/4dtXP0e9ReYehb1NPxRlsYvWEgRdGLi06A2ILG7a2tnLS
         mh5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DxjcecEI7phcRYjWyLkZSnGEJwCBjNTRZZccT/msDU8=;
        fh=p7lznpqflXjLIdAZSvPWYLvV/JqoNdwwtATJ07xJp2s=;
        b=UGb41eWXVdiObr/Fy3HKvQ2qjtcWdMI9DVpM/0J5PejMusOIMU+F8/oDcNoIKboO0y
         VydvTXlinUZwzyThzmgoLJRVlDckxJ6a8pTsK/rO+HodLw6coLGdO5X5E6SmqkCP9hJM
         uiLns9uQZ/4rbKqba3kx2hTXhydmEaBPGUIh1Y/+1M/J0QtVSJ6ROlM3yS6KCskBgOuc
         u4EDQbNOO7gqWjz9h+c2nh6wxUPZieQqbUGeD4nyKUlsVuEwsfGJciYgXfwpKV7K9/9K
         NJAdNZrHX9sCNL8uWfNrfcIqZGr1cW6fh38bUKtfHoXeH21tXvdFmFgubT6qcNNVP6hH
         QWOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DFGdEDIH;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1f92d58si9446635ad.4.2025.08.12.06.39.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:39:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-553-FY5fxrhNOyqPzbOI5L33kw-1; Tue,
 12 Aug 2025 09:39:22 -0400
X-MC-Unique: FY5fxrhNOyqPzbOI5L33kw-1
X-Mimecast-MFC-AGG-ID: FY5fxrhNOyqPzbOI5L33kw_1755005958
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5149919560B3;
	Tue, 12 Aug 2025 13:39:17 +0000 (UTC)
Received: from localhost (unknown [10.72.112.156])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7F8A819560AB;
	Tue, 12 Aug 2025 13:39:15 +0000 (UTC)
Date: Tue, 12 Aug 2025 21:39:11 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, alexghiti@rivosinc.com, agordeev@linux.ibm.com,
	linux@armlinux.org.uk, linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org, christophe.leroy@csgroup.eu,
	x86@kernel.org, chris@zankel.net, jcmvbkbc@gmail.com,
	linux-um@lists.infradead.org
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com, elver@google.com,
	snovitoll@gmail.com
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aJtD/8beAEHtm2/6@MiWiFi-R3L-srv>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DFGdEDIH;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Forgot adding related ARCH mailing list or people to CC, add them.

On 08/12/25 at 08:49pm, Baoquan He wrote:
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=on|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.
> 
> So this patchset moves the kasan=on|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> kasan.
> 
> Changelog:
> ====
> v1->v2:
> - Add __ro_after_init for __ro_after_init, and remove redundant blank
>   lines in mm/kasan/common.c. Thanks to Marco.
> - Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
>   this is found out by SeongJae and Lorenzo, and also reported by LKP
>   report, thanks to them.
> - Add a missing kasan_enabled() checking in kasan_report(). This will
>   cause below KASAN report info even though kasan=off is set:
>      ==================================================================
>      BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
>      Read of size 4 at addr ffff00005f747778 by task swapper/0/1
>      
>      CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMPT(voluntary) 
>      Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2.10.20220810) 09/30/2022
>      Call trace:
>       show_stack+0x30/0x90 (C)
>       dump_stack_lvl+0x7c/0xa0
>       print_address_description.constprop.0+0x90/0x310
>       print_report+0x104/0x1f0
>       kasan_report+0xc8/0x110
>       __asan_report_load4_noabort+0x20/0x30
>       tick_program_event+0x130/0x150
>       ......snip...
>      ==================================================================
> 
> - Add jump_label_init() calling before kasan_init() in setup_arch() in these
>   architectures: xtensa, arm. Because they currenly rely on
>   jump_label_init() in main() which is a little late. Then the early static
>   key kasan_flag_enabled in kasan_init() won't work.
> 
> - In UML architecture, change to enable kasan_flag_enabled in arch_mm_preinit()
>   because kasan_init() is enabled before main(), there's no chance to operate
>   on static key in kasan_init().
> 
> Test:
> =====
> In v1, I took test on x86_64 for generic mode, and on arm64 for
> generic, sw_tags and hw_tags mode. All of them works well.
> 
> In v2, I only tested on arm64 for generic, sw_tags and hw_tags mode, it
> works. For powerpc, I got a BOOK3S/64 machine, while it says
> 'KASAN not enabled as it requires radix' and KASAN is disabled. Will
> look for other POWER machine to test this.
> ====
> 
> Baoquan He (12):
>   mm/kasan: add conditional checks in functions to return directly if
>     kasan is disabled
>   mm/kasan: move kasan= code to common place
>   mm/kasan/sw_tags: don't initialize kasan if it's disabled
>   arch/arm: don't initialize kasan if it's disabled
>   arch/arm64: don't initialize kasan if it's disabled
>   arch/loongarch: don't initialize kasan if it's disabled
>   arch/powerpc: don't initialize kasan if it's disabled
>   arch/riscv: don't initialize kasan if it's disabled
>   arch/x86: don't initialize kasan if it's disabled
>   arch/xtensa: don't initialize kasan if it's disabled
>   arch/um: don't initialize kasan if it's disabled
>   mm/kasan: make kasan=on|off take effect for all three modes
> 
>  arch/arm/kernel/setup.c                |  6 +++++
>  arch/arm/mm/kasan_init.c               |  6 +++++
>  arch/arm64/mm/kasan_init.c             |  7 ++++++
>  arch/loongarch/mm/kasan_init.c         |  5 ++++
>  arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
>  arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
>  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
>  arch/riscv/mm/kasan_init.c             |  6 +++++
>  arch/um/kernel/mem.c                   |  6 +++++
>  arch/x86/mm/kasan_init_64.c            |  6 +++++
>  arch/xtensa/kernel/setup.c             |  1 +
>  arch/xtensa/mm/kasan_init.c            |  6 +++++
>  include/linux/kasan-enabled.h          | 18 ++++++-------
>  mm/kasan/common.c                      | 25 ++++++++++++++++++
>  mm/kasan/generic.c                     | 20 +++++++++++++--
>  mm/kasan/hw_tags.c                     | 35 ++------------------------
>  mm/kasan/init.c                        |  6 +++++
>  mm/kasan/quarantine.c                  |  3 +++
>  mm/kasan/report.c                      |  4 ++-
>  mm/kasan/shadow.c                      | 23 ++++++++++++++++-
>  mm/kasan/sw_tags.c                     |  9 +++++++
>  21 files changed, 165 insertions(+), 47 deletions(-)
> 
> -- 
> 2.41.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJtD/8beAEHtm2/6%40MiWiFi-R3L-srv.
