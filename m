Return-Path: <kasan-dev+bncBC24VNFHTMIBBGNPVD3QKGQEF43YRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 31F9C1FCE31
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 15:16:11 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id d197sf1771853iog.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 06:16:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592399770; cv=pass;
        d=google.com; s=arc-20160816;
        b=rsX26f0FN/M5myPk1h7/2P76k+XlsUyS61JI5NbmOebeqMp5YWR9AHH3MSCgodIvpL
         M5OqeBdAK3kxXKKq/gZj/T2Ht2cBozOhgzBdrrz2l0bzT2IAg1FsglgASF6Fpka4QLXd
         8s6u5j/1+P67sDzhoSMCHB4VdKO6BCqjvpm9Y0e8XrbJY0qRHk+RHD3mRTmmv43J82M2
         aZXVEt7ZTOe7CfEx8rYqECtnZwUKvpDZYvrAJzCUrC2FooF8hsd4CrXROoC1jy9+GEBz
         OEdT43ndAqckARtMD4DoQ7rKuH7xjiYFZcLghcVIhoIMBWyyPwlP2zrbqA89IrX0FnE1
         T76w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=VhZOfv0RaMsD7rJXSdIvxWYFLXOCrjPzYTyXMKjbK94=;
        b=tZlsu46cUZY74zlXV6NI4SgRgk8Q3T6ysuzUph8a9no7IaiZExnaet7c9lZYKCa1kc
         9ReC0hDNBW07uZsYX59UarvtReYztxMnmAauK4Gn/asmSH9HbR+dTIrHPRbNBDwyk+pc
         vx4zw55+ITCE8SvUe9JMWxjl8z7I8BWsaZNKS0LiyOGjEuF0Qcg0x9nh6IhduVANqh+t
         rkvcgMO8M1CrDUjSzwf4mltu4vkzq9mgu1jg3caEZ81prkHQTpwG2TllTQJe1P9fXAZk
         2dAbXJ0IO0NDG31v2oCTHKb0UkYWi1hTmBp+U5Kdz/b5IpBgknUDwb+ZMWUPN2XxzTDB
         Mz4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VhZOfv0RaMsD7rJXSdIvxWYFLXOCrjPzYTyXMKjbK94=;
        b=GuBK72Hk42HT99MsD5gdalKubrbkIuuzT659BSiPrrQHwNI696O3rolk1ZAYn1arvc
         3E227Jxhtx3FsQeh5KZgXGPjsXC19bkvEVxmLHClAdYLJdCy+kPCLNEeBcXY+hsyGCtZ
         O4crbEaR5vZm2IBosSNqNhIGWwZzOqqu5H71+yoAslkV7iNfShXjVFYa0ZKphpn+jt73
         zd8ebEP7v81uSdxMYOKpOB1wTimVh+vk6hk7mKqJh7kIeplD6UftoNZoo+KrJ3LNP3UJ
         phl5DbrRX6Lxh0wnpqzw3Jxh3W9lxhsFItKyMVxZFbTn2L0W81gxiyB+rsIM9O0WwjdM
         WI4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VhZOfv0RaMsD7rJXSdIvxWYFLXOCrjPzYTyXMKjbK94=;
        b=cW734pBo5oRpVYXWSP/d766gEGd+a6xBBEeepXkJyvD/g1dq7ZGFmqMJrABjwZtK2T
         XgacRNWkAjcsrMsCxnf4rd9ozNtMrwY5GulJB8bRB1EqiPYnDfk9DIyPCYhNfCkRFq1F
         SCmdkf2XUaFeW0FxV85XavJ9Tb9fmgBzyfHiPRrP1Qo6FvxgpfdB9SFi1cFPHeRjRl+W
         FiR9lM9bJhsgDlbXxbRoUrmONZmOLwpfGO7X2mZrFxJburNmqunSJAbV3a0jtWkNYEas
         SJxXQnx4PegALvNAmIhYj3OQ0Ba/D1j9vmAEp2ouzQrcne8tW/JB4L0OIq/axEw2y1JN
         8dWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+WFhrFbP+qyqFU5yiWrEgOenomhefCpG8HuasoqJ335w+Ls3t
	s3t3d3/CKO/7KOfcG+j2rEA=
X-Google-Smtp-Source: ABdhPJxdXoaC4dPa77pWRTH7f9sI6NjJL7oryr1bfX+sMbiC/sysgQmfk1Net+dUCxyqtdNSwA9tug==
X-Received: by 2002:a05:6602:2c8f:: with SMTP id i15mr8052857iow.45.1592399770015;
        Wed, 17 Jun 2020 06:16:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3b07:: with SMTP id c7ls266398jaa.9.gmail; Wed, 17 Jun
 2020 06:16:09 -0700 (PDT)
X-Received: by 2002:a02:95a6:: with SMTP id b35mr30561523jai.40.1592399769727;
        Wed, 17 Jun 2020 06:16:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592399769; cv=none;
        d=google.com; s=arc-20160816;
        b=l960DSBl5pjtYQ5vXrOgCUete4snBqjkhuYwYwkco8AEHcgOnpsrxfEIuKHnUDNhCl
         /0cdMlT4nJP6EhKf2ITmFniFAvKj4ZdfWP43J9y9q7x2Gm6y+fyMaMjGs6Nt6kcJRhDS
         VjpgqhI+ZgQhY6DTc2T7ccQ1w02odn4gVdOwxrb9BRieWkQ5lsu0UiGjTT9StaS7dtDx
         GMRZ0ZHeeA3PCVYSrgyQzN0EZ2EtZ6fahxkRDSWfrpJlhmQiqJu9IDB7Nnrx+qtrCPfy
         tnNZuC4IgjFJoA7aBb5pDwLZr0uyBMfznBih+DjOSWdh9vrDX2Wo/rKr9ObVq9ORKFL3
         R2TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=27rWr4kJpMH5rb9uMoheDKvuw3Q7OJzYuFqjR+Ghdaw=;
        b=Y67cZHMO8KFp11xDw61NNwufr67BJPOFnxBaR1cc1S230sYtj4p5ZPPkX4dLEJyq5b
         YKaCnPbs28tbys8PPgcEyTtNPXfHM35PDXzPU5MdQR4dt0m2rtzOzs4+ZJB7FsVC/dsh
         3Bn2EpqF8cCqCJydlinCnwZk4aWoZbH6/2OOtramqZrbzMNF6cqkmJpzcxAMS0f9E4HU
         JCw0opMRleDzLSh82nyn/Px6/KHBB0Va1flWTJbuV3ZzCF6RCz2gSVb01wvuBZPzB98z
         7XKdWXhDZWMJVzb4qTOtT2e2OP5kJ2q3WR6WGVuXtrNIb6JZW2eus5uh6eVqA/Iqhbu+
         DpJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v16si1294540ilj.1.2020.06.17.06.16.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jun 2020 06:16:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 17 Jun 2020 13:16:08 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-b4o6NwKJd6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #8 from Walter Wu (walter-zh.wu@mediatek.com) ---
I always see below the report on qemu, the stack variable is 'spec', but it
should not have corruption.

==================================================================
[    0.002089] BUG: KASAN: invalid-access in format_decode+0x90/0x10fc
[    0.002110] Read of size 8 at addr 74ff900015447a00 by task swapper/0
[    0.002127] Pointer tag: [74], memory tag: [08]
[    0.002148]
[    0.002175] CPU: 0 PID: 0 Comm: swapper Not tainted
5.6.0-next-20200408-dirty #23
[    0.002193] Hardware name: linux,dummy-virt (DT)
[    0.002209] Call trace:
[    0.002225]  dump_backtrace+0x0/0x578
[    0.002242]  show_stack+0x14/0x1c
[    0.002258]  dump_stack+0x188/0x260
[    0.002274]  print_address_description+0x8c/0x398
[    0.002291]  __kasan_report+0x14c/0x1dc
[    0.002307]  kasan_report+0x3c/0x58
[    0.002323]  check_memory_region+0x98/0xa0
[    0.002339]  __hwasan_loadN_noabort+0x14/0x1c
[    0.002356]  format_decode+0x90/0x10fc
[    0.002372]  vsnprintf+0x184/0x31e4
[    0.002388]  vscnprintf+0x80/0xd4
[    0.002404]  vprintk_store+0x98/0x93c
[    0.002420]  vprintk_emit+0x168/0x79c
[    0.002436]  vprintk_default+0x78/0xa8
[    0.002452]  vprintk_func+0x918/0x9a0
[    0.002468]  printk+0xb8/0xf0
[    0.002484]  kasan_init+0x2b8/0x2d8
[    0.002500]  setup_arch+0x460/0xbc8
[    0.002517]  start_kernel+0xe4/0xb88
[    0.002532]
[    0.002548]
[    0.002564] Memory state around the buggy address:
[    0.002582]  ffff900015447800: 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.002599]  ffff900015447900: ff ff ff ff ff 08 ff ff ff ff ff ff ff ff ff
ff
[    0.002617] >ffff900015447a00: 08 ff ff ff ff ff ff ff e4 e4 ff ff ff ff ff
ff
[    0.002633]                    ^
[    0.002650]  ffff900015447b00: ff 14 14 ff ff ff ff ff ff ff ff ff a4 a4 ff
ff
[    0.002668]  ffff900015447c00: ff ff ff ff ff d4 d4 ff ff ff ff ff ff 94 94
d4
[    0.002685]
==================================================================

I try to add below patch then I see that "BUG: KASAN: invalid-access in
start_kernel". I am not sure whether you need this information.

--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -2278,7 +2278,7 @@ char *pointer(const char *fmt, char *buf, char *end, void
*ptr,
  * @precision: precision of a number
  * @qualifier: qualifier of a number (long, size_t, ...)
  */
-static noinline_for_stack
+static
 int format_decode(const char *fmt, struct printf_spec *spec)
 {
        const char *start = fmt;


My environment:
- clang-r377782d
- linux-next-20200408

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-b4o6NwKJd6%40https.bugzilla.kernel.org/.
