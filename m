Return-Path: <kasan-dev+bncBCKPFB7SXUERBF5QUTEQMGQEMJEXOWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D336C90C1E
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:33:45 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-3e1383751f1sf2734004fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:33:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300824; cv=pass;
        d=google.com; s=arc-20240605;
        b=CJcXkQSohU06Anb4wHaB176F8ff/4cGKb/MJgIGg4MdOg491YgRq/FYUP1Cl2zwfnx
         6pu2zad8wCMlAMZQfnq2MTOTg7ss27dtsV4d/jV+BB7eGah86l/tC67yC25Dtfntz5qz
         yc0QFJNCiWvYtugN3qFRmtoXAa148tOA6AkKlrg5Bq/M5MvCxm88yPlP6czVaO330WGr
         WdV+4TjpMhAPDh/XgM+JZMS9G70JC0M2YqYyYu33UaR47riCCPAyZPAgtyGrSweajKu4
         jz/NI/MeK//9fig2MBPzqSdh3ki4uHkMvMLQI1BDRraSMBFBLB+UiMUo5CHNrx0BZhTz
         BMGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=vn3P3QMoncBt4LuQpMUCY7SOFueFZNVGBHMsCZBFQyY=;
        fh=uA+5ZSqncP1ODrwv1EE/UjTOUK7OLYkZ5RV7CFu4W1g=;
        b=d3NG/g7lu+oJpgozB2dDifcH4fIuqRsuFj8RXx+8/0cMAEBdWiY27Q5AHYrknGd4xT
         kRWR7j3T5YsvOUwteHOluiIxcCx9NJnB6c+cTJRyoYS5YgTuYfShp8Qt99Dz07FT/Xp7
         TnTo3v4zhdUZpmF1xkyhd/0QBnY6jLiXW/MCSt5zlV3ypNyT2YqKNfBxBBgSpagtTElp
         4E+19FHrhgEFjZZjjQXF07tPXO2h2nXCAQQ4MidYFrwaj9C6bQy23WjZtf4X+9h2Se41
         PDagGul/tHCjUvvGGpn+MAb5EpU8b+gIwrXuKc8igmYTdd/QAxjfECkBhkXVX3qDhifA
         DPFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PDMufAVL;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300824; x=1764905624; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vn3P3QMoncBt4LuQpMUCY7SOFueFZNVGBHMsCZBFQyY=;
        b=G0zI2deDDVEjPwNt8TUBLqO+NeHGAtXQmxZ3k2cq+XVBZxCQk2ixcbLoWjaKbkIIxq
         CvUoMS6BLkpaXuizablbn6gP3M5b55hWmn6wkY3Rle4hy1jJf+4AyuDzbvpMtJgAII/n
         JexZQ8Zca3/ayWOgv/i5qczxx69ACrvD3p2OKjregD/ByggKFcREHivBE+BLycouCeoL
         leY88GSHVpj47f+wy6hRGCuAB2yt5iWkBa+1xhDMqH80AA+FnMCYdZ3YYXGFEvSmEy/e
         Z23N0Uyb8pPCuJuy5jgPe0Y2yXaitpvTQpxSY74vPKd1Gct+RvPYkCX+bKslh0611bDD
         BV9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300824; x=1764905624;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vn3P3QMoncBt4LuQpMUCY7SOFueFZNVGBHMsCZBFQyY=;
        b=cPsETOYCxaPMbLyxbU7L/tn3VqAqeB2Hd5YNLJ1rQdURC1GGSY3uhLLKgbeOByAvyl
         ZIX4yXqJsbePlauL9jizOKkbHRF3vskVK0yJ77GNlhzN9nOStTsNFssVyrEj+1XLNj4n
         46GtX3UDDKLr2griR87fYVtyhIXogNfmyhJHjBWX7oLLYocIN8qd/wHpSqk8k9mMCXSW
         RKFX6SOdGPR4bbqg5Tp0hdyCexT2BtPC50lZLx5vfPvjfKaLeRApHahlPY1JFLt8ZNo/
         v7vM/n0iYJzRidrFlTM5KYUbnaf9GK6Vh42jhWO0zk7pocEGTMmYxsK4H/BamSpflk+z
         IH9Q==
X-Forwarded-Encrypted: i=2; AJvYcCUpz6h7xvZBzgcDX8csRGUQCt1kxD8KdzG1gES1M/Li2IB2JomQQXoeTikEXSnYsgyx3LrEvw==@lfdr.de
X-Gm-Message-State: AOJu0YyFewyMI0cpmU7dKgZ9hTRKjszqsBXTgevJLhYxCAOy33f4WBBD
	PU9U124F8tUbW4vbYbQsMuSWVDTrcyldE83JUSiCc++hrJybB+I3v2Cf
X-Google-Smtp-Source: AGHT+IHRUSMfsxDV/QJ/viaAvQA2wCAUjeFN5BwIfFW/p1upBfOCYlTYVcRBYudZ3lPnkc00k20wyA==
X-Received: by 2002:a05:6870:9110:b0:3e8:9bc9:f74 with SMTP id 586e51a60fabf-3eca16480c2mr14161357fac.9.1764300823662;
        Thu, 27 Nov 2025 19:33:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aw8wpFFJ2jZgUuWKWq5c+6BNdaLTPYEf2enJOj3q4QNg=="
Received: by 2002:a05:6871:2b15:b0:3ec:31da:bbc4 with SMTP id
 586e51a60fabf-3f0b9e9ef02ls676651fac.0.-pod-prod-00-us-canary; Thu, 27 Nov
 2025 19:33:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUjvLHMnkBqOnV8Am+O4P6B8rgnfmNQyB9E11sAUaKVKLJLcpZv01wITJutDgB8xBfOSQ0v52SERSg=@googlegroups.com
X-Received: by 2002:a05:6808:4fce:b0:450:f45e:f4a7 with SMTP id 5614622812f47-45101cf9922mr12573459b6e.8.1764300822684;
        Thu, 27 Nov 2025 19:33:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300822; cv=none;
        d=google.com; s=arc-20240605;
        b=MyxYMlVlWsl2Cpvf08P4WZDBeofgseYrHbEj8H2/K0/Gjf8UbNBCIJQoveaEHo78Er
         CV8DpD9vcJRi2h7A2LKHO4HVDdQMzRJIP3TmSEwpYTYDgjcLaerJR+l1ykyYtSxn9hgM
         +sFK1C1khOf9IM5GrpO+Xiv5fz/foNBjXgLePlWftHuHdPMVzGHjIJ6MDrZiDw8CytcR
         m2ZY2AqDXpt3Vc/Qb9hPCYqWXqUboXkhCYyy39eBrP4opIkdgHbwTSKuwlhAV6ehqoGk
         diDbgxVC18t25U3Qro28yaNUzvDsGvWWdzenNNVLkOvovWqygxtO4r1WSB9J0sCWFq1z
         +3pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Qr0zpQpajQCRbG+sF+yGezyQgSmvvZvdStpi3agx6mY=;
        fh=5SDByJ3Hs0yfOCoQGEuG1sRE6NAvqIWBUeJICelOz9U=;
        b=k11qI+mTBvY42BDzSkcqg3G+0vqm7goaZiRfh9tAagsLVYv8etig/xQ9dgDzJjLNcg
         7jyHUXlhiwryCWCy2C/8c+Tcvb6KQLYLgr8/RgaerB6xSZ6BUlH6vlXqnEayoK+8Ei6s
         cI3dtACzDVqcsfMGKNKqUwJd0HUNfv4FM3L5wS1jkphD9mKdw/QrmqMHnGtiRZUZPb8Y
         KIlENrGC4tXmsg+qjrvuZ5L+MCzfK3uwQOiZJovH7Kf9MXtm9xWbES/3XewX2TjEVQ2W
         EjZ2STrvTZUA7KDq2XearKrLBBzX84ermCHwv6fgsArf2ZJM8zjOS2uCUG/1b01xlOs6
         kc/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PDMufAVL;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-659332d1e70si52869eaf.1.2025.11.27.19.33.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:33:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-441-sE3kvIDuP_qIGMkVoeXVOw-1; Thu,
 27 Nov 2025 22:33:37 -0500
X-MC-Unique: sE3kvIDuP_qIGMkVoeXVOw-1
X-Mimecast-MFC-AGG-ID: sE3kvIDuP_qIGMkVoeXVOw_1764300815
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 42F9F1956095;
	Fri, 28 Nov 2025 03:33:34 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1735A19560B0;
	Fri, 28 Nov 2025 03:33:23 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three modes
Date: Fri, 28 Nov 2025 11:33:08 +0800
Message-ID: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PDMufAVL;
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

Currently only hw_tags mode of kasan can be enabled or disabled with
kernel parameter kasan=on|off for built kernel. For kasan generic and
sw_tags mode, there's no way to disable them once kernel is built.

This is not convenient sometime, e.g in system kdump is configured.
When the 1st kernel has KASAN enabled and crash triggered to switch to
kdump kernel, the generic or sw_tags mode will cost much extra memory
while in fact it's meaningless to have kasan in kdump kernel

There are two parts of big amount of memory requiring for kasan enabed
kernel. One is the direct memory mapping shadow of kasan, which is 1/8
of system RAM in generic mode and 1/16 of system RAM in sw_tags mode;
the other is the shadow meomry for vmalloc which causes big meomry
usage in kdump kernel because of lazy vmap freeing. By introducing
"kasan=off|on", if we specify 'kasan=off', the former is avoided by skipping
the kasan_init(), and the latter is avoided by not building the vmalloc
shadow for vmalloc.

So this patchset moves the kasan=on|off out of hw_tags scope and into
common code to make it visible in generic and sw_tags mode too. Then we
can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
kasan.

Testing:
========
- Testing on x86_64 and arm64 for generic mode passed when kasan=on or
  kasan=off.

- Testing on arm64 with sw_tags mode passed when kasan=off is set. But
  when I tried to test sw_tags on arm64, the system bootup failed. It's
  not introduced by my patchset, the original code has the bug. I have
  reported it to upstream.
  - System is broken in KASAN sw_tags mode during bootup
    - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#u

- Haven't found hardware to test hw_tags. If anybody has the system,
  please help take a test.

Changelog:
====
v3->v4:
- Rebase code to the latest linux-next/master to make the whole patchset
  set on top of 
  [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
  [PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific implementations

v2->v3:
- Fix a building error on UML ARCH when CONFIG_KASAN is not set. The
  change of fixing is appended into patch patch 11. This is reported
  by LKP, thanks to them.

v1->v2:
- Add __ro_after_init for kasan_arg_disabled, and remove redundant blank
  lines in mm/kasan/common.c. Thanks to Marco.
- Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
  this is found out by SeongJae and Lorenzo, and also reported by LKP
  report, thanks to them.
- Add a missing kasan_enabled() checking in kasan_report(). This will
  cause below KASAN report info even though kasan=off is set:
     ==================================================================
     BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
     Read of size 4 at addr ffff00005f747778 by task swapper/0/1

     CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMPT(voluntary)
     Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2.10.20220810) 09/30/2022
     Call trace:
      show_stack+0x30/0x90 (C)
      dump_stack_lvl+0x7c/0xa0
      print_address_description.constprop.0+0x90/0x310
      print_report+0x104/0x1f0
      kasan_report+0xc8/0x110
      __asan_report_load4_noabort+0x20/0x30
      tick_program_event+0x130/0x150
      ......snip...
     ==================================================================

- Add jump_label_init() calling before kasan_init() in setup_arch() in these
  architectures: xtensa, arm. Because they currenly rely on
  jump_label_init() in main() which is a little late. Then the early static
  key kasan_flag_enabled in kasan_init() won't work.

- In UML architecture, change to enable kasan_flag_enabled in arch_mm_preinit()
  because kasan_init() is enabled before main(), there's no chance to operate
  on static key in kasan_init().

Baoquan He (12):
  mm/kasan: add conditional checks in functions to return directly if
    kasan is disabled
  mm/kasan: move kasan= code to common place
  mm/kasan/sw_tags: don't initialize kasan if it's disabled
  arch/arm: don't initialize kasan if it's disabled
  arch/arm64: don't initialize kasan if it's disabled
  arch/loongarch: don't initialize kasan if it's disabled
  arch/powerpc: don't initialize kasan if it's disabled
  arch/riscv: don't initialize kasan if it's disabled
  arch/x86: don't initialize kasan if it's disabled
  arch/xtensa: don't initialize kasan if it's disabled
  arch/um: don't initialize kasan if it's disabled
  mm/kasan: make kasan=on|off take effect for all three modes

 arch/arm/kernel/setup.c                |  6 ++++++
 arch/arm/mm/kasan_init.c               |  2 ++
 arch/arm64/mm/kasan_init.c             |  6 ++++++
 arch/loongarch/mm/kasan_init.c         |  2 ++
 arch/powerpc/mm/kasan/init_32.c        |  5 ++++-
 arch/powerpc/mm/kasan/init_book3e_64.c |  3 +++
 arch/powerpc/mm/kasan/init_book3s_64.c |  3 +++
 arch/riscv/mm/kasan_init.c             |  3 +++
 arch/um/kernel/mem.c                   |  5 ++++-
 arch/x86/mm/kasan_init_64.c            |  3 +++
 arch/xtensa/kernel/setup.c             |  1 +
 arch/xtensa/mm/kasan_init.c            |  3 +++
 include/linux/kasan-enabled.h          |  6 ++++--
 mm/kasan/common.c                      | 20 ++++++++++++++++--
 mm/kasan/generic.c                     | 17 ++++++++++++++--
 mm/kasan/hw_tags.c                     | 28 ++------------------------
 mm/kasan/init.c                        |  6 ++++++
 mm/kasan/quarantine.c                  |  3 +++
 mm/kasan/report.c                      |  4 +++-
 mm/kasan/shadow.c                      | 11 +++++++++-
 mm/kasan/sw_tags.c                     |  6 ++++++
 21 files changed, 107 insertions(+), 36 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-1-bhe%40redhat.com.
