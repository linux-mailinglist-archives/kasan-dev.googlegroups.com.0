Return-Path: <kasan-dev+bncBDBIVGHA6UJBBIN7YOBAMGQEU77NRZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 06FF033D9A2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 17:41:06 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 74sf13691202ljj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 09:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615912865; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGOJ2qTVhHDueb0lDWJWwZ1JMkZhroykfoz3pP8en+B0M/InZ+Am9HB2kYTUv3ep/F
         FUrCgYdhHUL1Foatlk1vzVZbGBizb9M2XYjXGcAlIbtiKNBFDyBFJ4S+NAsmZOeMivOg
         5e4sp8Ef/T8mAUBI/5nnk0Rmdx+iWeOW2biq1AgcgiKnqvw9Sv0KRZOJZA11rU/C5poD
         og9OXJ7r3Mbsy+E/9pSWCU0Y+H/IlyuR3ryBK2wDYev2dCBMFaXZcpJ6yaobTRyZZDfx
         IyKxzrMZ7Yu0SdpMaxjqHVYFxJZyI23gbWKXBm+GhMWtyyl1i8TLt6RZpBis/1kS1w8W
         gBNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=yUs/4e170xe/LqAaGjtQTVhQDHFUggToAu0P8xo9oPE=;
        b=IdTMWIk83NMMxd0+wyDTKC6BOq6EPr0OrJ53dcLnWF5y9jLyZ2wjM5Zt3Gw798ry95
         JY1SZ2KcgPY3CzxrcoFFLMHeyUVxBLa71RsgnrqhzTjFOTHwxkRjKsjoYG2bF4CIud7T
         qUcAlBt+Ph43So/pAVIh5O5HoaipzEpBGeWa0FcmbDk9iE96uPJrUwUgMp/RCe5XJHmE
         jfmqNVKHgB1CVmgXZRBdOo95YT6ZWOw2i8clWuDZkfhyQp9VCpbTUI9IFJQkKiT0ysHk
         GJDkRiI1FLUei6M9RlzRvLh4w/Xb3ihHq/U34gE0Q61WxSzfYR28sX51szPsFePuZzt+
         LDAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yUs/4e170xe/LqAaGjtQTVhQDHFUggToAu0P8xo9oPE=;
        b=Hm01WSzgadm3KF94gn8HC/BYVJXtYf/+XVufNE+FhTzqTKbP4zTYV36XxdqgdLstsN
         7ZX2OvXJ3NeAYABDxSpyKmVugvQ0vq38HI8Y90WSU/qbttVL0YDyRnrRkfvyPscYCFby
         f7y4oExXui+jf+DFKxxIEGCeXisdwjyDZn8RlILoB4cbxiux1yhvWgtqd2mqQxYom+I3
         aMvcXey6glsZGNeTdROxq/TufynuVBft9+9vAeJQI1lRDCoYAfg3kSm8Qz2IjCMv3W2a
         QYIXia2fgHnuLgG3mkOiNyhXJMg8Zm3VudsFdSlBfXFPLpIwp4zizKWz9x/MCTQnhWSR
         //hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yUs/4e170xe/LqAaGjtQTVhQDHFUggToAu0P8xo9oPE=;
        b=HnFNGgvkU0nucT81l4ikKmiMlNbN0zY9rAW1yPQijOcXRAR7rF+dlW59bfkq4Rm6hI
         a4keFuArkoNpSvgXS0QAyhx4nlsVQH3nBr9DqdexJj7cs2OkRg10tD9b6GLPAuXTp/p2
         lVv+TxSTBxrMFuybMoPf9JOaceA1asMKXY7JnGsBjqnJEJ4TG46Qo4PgMGfjz5CYb5t0
         Po/+K7iBQ/tKf/L84Iq5zIx/8eQ7dniIB3YHY5IpjnjwOu8zUlp86Jvwqvlj4VSY4dB4
         7N/PX+36DtWayYcJu6MrscN5HdvUuR/i+0iAecZFrQ2JWopIneyuHwbaJDUyrH3wJuQv
         MBZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EGYzDrW5VgA0FScI66mkFEc6QqLIhZz+TE5U5Z/WDNTRB49IG
	5UxvR2G1Dy1hxnu8CqwALoY=
X-Google-Smtp-Source: ABdhPJytK1sFwUP88dm4WnJ+vl3z+3VES8yiBIfpJp8wVFcMvJ0Ate+SiBSDBa6MZx6DOSjSnU6qpQ==
X-Received: by 2002:a05:6512:3618:: with SMTP id f24mr12009069lfs.34.1615912865603;
        Tue, 16 Mar 2021 09:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls4562164lfo.0.gmail; Tue, 16 Mar
 2021 09:41:04 -0700 (PDT)
X-Received: by 2002:a19:ed0e:: with SMTP id y14mr12248267lfy.440.1615912864541;
        Tue, 16 Mar 2021 09:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615912864; cv=none;
        d=google.com; s=arc-20160816;
        b=pltrHq8PN6GUs0kh/MRNOPrKp/nmKLnGvi/cZGs2MEGbbpspS8bCnu3Q97XaVAHUfl
         d1gm5kKupP5ZzJNNQKCHyY9S9ERyTS/t2nrxoCfz++2Egn1F5w+7c9J2yzOW7rVAqvOT
         j+iSL9gEzudbxH2JbFNuIBWoVotFCY8cXBHFyM6DRbBCGc3g1V9i3tVmsMGR1189awiz
         T4432NVCfZHZooTQcZSKmtA/IHcFo+ILgwqPAbADbg5GKOsKq745GiivwO0U87+cgMnW
         8dzhrCqW/VZMfg+AHnu3SFpLmsMzgVHsh/tQ6R184GcREiUAqVMrayEFssS0NESasqxk
         ed4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date;
        bh=MQhQQvwuVxxsBcpaG84D8YS9Um672cR4KxL3McSaVWA=;
        b=MKKDJ3PSFrpNBh6YvNhZcbVAWv7W5wIKb4xPnvUpwy8Apqd1ndgkHNplGJCJJwbcPQ
         hzHNqQ8gh8zCNKt9yMAxGTp9fzMCyRDTmVuwFnUU9hkb1LsJxyRFWRvdLaOmG7WrTGlg
         9HHlYVa5jkwYRX9gh3zqCYfbLf0Z/L1UrdOBOWTJ3/aChanaDYU76A5E7vNLJaXs2aq6
         CPc0jmK/WtfYACPmyKCCHqgr++8Eik1MGT5DjbNyLMWKwaiPWipQi+yUF2wwWDOSRvjL
         0rT+w22N9KO0Z5EOZ4BXTPqywYfFz0P/LCzRnuEkNUUJ87sAB4GwFj72z1TCQD//GuzO
         dpwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z2si653929ljm.0.2021.03.16.09.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 09:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id BAAF8AC24;
	Tue, 16 Mar 2021 16:41:03 +0000 (UTC)
Received: from localhost (brahms [local])
	by brahms (OpenSMTPD) with ESMTPA id 924d4c15;
	Tue, 16 Mar 2021 16:42:18 +0000 (UTC)
Date: Tue, 16 Mar 2021 16:42:18 +0000
From: Luis Henriques <lhenriques@suse.de>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Issue with kfence and kmemleak
Message-ID: <YFDf6iKH1p/jGnM0@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lhenriques@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=lhenriques@suse.de
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

Hi!

This is probably a known issue, but just in case: looks like it's not
possible to use kmemleak when kfence is enabled:

[    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the object s=
earch tree (overlaps existing)
[    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
[    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
[    0.272136] Call Trace:
[    0.272136]  dump_stack+0x6d/0x89
[    0.272136]  create_object.isra.0.cold+0x40/0x62
[    0.272136]  ? process_one_work+0x5a0/0x5a0
[    0.272136]  ? process_one_work+0x5a0/0x5a0
[    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
[    0.272136]  ? process_one_work+0x5a0/0x5a0
[    0.272136]  kthread+0x3f/0x150
[    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
[    0.272136]  ? __kthread_bind_mask+0x60/0x60
[    0.272136]  ret_from_fork+0x22/0x30
[    0.272136] kmemleak: Kernel memory leak detector disabled
[    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
[    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
[    0.272136] kmemleak:   min_count =3D 0
[    0.272136] kmemleak:   count =3D 0
[    0.272136] kmemleak:   flags =3D 0x1
[    0.272136] kmemleak:   checksum =3D 0
[    0.272136] kmemleak:   backtrace:
[    0.272136]      memblock_alloc_internal+0x6d/0xb0
[    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
[    0.272136]      kfence_alloc_pool+0x26/0x3f
[    0.272136]      start_kernel+0x242/0x548
[    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb

I've tried the hack below but it didn't really helped.  Obviously I don't
really understand what's going on ;-)  But I think the reason for this
patch not working as (I) expected is because kfence is initialised
*before* kmemleak.

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3b8ec938470a..b4ffd7695268 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
=20
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
+	kmemleak_no_scan(__kfence_pool);
 }


Cheers,
--
Lu=C3=ADs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YFDf6iKH1p/jGnM0%40suse.de.
