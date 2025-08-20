Return-Path: <kasan-dev+bncBCKPFB7SXUERBTV5SXCQMGQECLUSETQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 67025B2D38E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:36:15 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e94f7232b6esf681998276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668174; cv=pass;
        d=google.com; s=arc-20240605;
        b=TewuKT7aZPBCBu2Ln+1Hq4AXPjFnQT4ZQJI38kAe3/JGvIfOnAnZKzjgHezyxKlMnA
         bICVB0G7aLF90y4e9LBWJuSTnEUkk8XnQaZRLoEaWDikhEywhgUi8zLITV3RLUxXtG8q
         db9yj9F5knCjxnjbtKJ7FbaehAzhZ0UWenaAdwDLJzLJMESMcDOz3HNxDy0Meb5C7mJQ
         MMKhO9RxiUa9bbYlOVmLDHezHObqW7Xo7F3bx2Ekl50FHX63dIuBc6ykW7cjbv5o3WhV
         KRAxIxB23C7xB30LwalR03C6XPuBqu1ONheKaW8ThS+Tmq3RerPrioSzqB3c0+Ii/c9U
         9KMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=OMs2kaukGXuWg/mZI327rpWTn4sInpze+RC76rkXIzA=;
        fh=lajdO68hi9PpBJCTDTRYt4THUdRduY7MQSbdcWk3sJs=;
        b=MohAFfO2stKrxMleL7zMfFbxWlelytubB5ynn4n4J/X4TPTjxKaCZzF03nkXJZyLSm
         gVW/cxxzOoMsZYDvHbNZWrrjW5a1P6YHjTJsEtoG0wq/EDDXD/FHQes4QSaGgZVwnI60
         fQ0c0PzEhrSCcadIYF3KtxBW6R0W9wd7dl+E0T5j6BEpeVilrtKbzA6FIr1gLeCp+eK8
         aWJ7pB9O3SpFq++7upDg88oaKBWwchL98a+vQFNZUyCeN5Mb0OQlylQtkeUVmNq4wSR7
         sLD5Iz+UQeFrmtaTTV/5X3F2QAZLWUdKWEZCpmktqM2+ztPjeE2X/i9PhNXv1bUTR1qk
         8GOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GI5o7mlK;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668174; x=1756272974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OMs2kaukGXuWg/mZI327rpWTn4sInpze+RC76rkXIzA=;
        b=n3I/V8sgJ2Wnln25tHamLyjW0HRhRp9y000sSDRcv81EZHtvy9fHEWmjEA5SnB6IqR
         uZ8r/IdwmJLyVgZ1g9OlsCpdjv1tFOXJyqcP1Xx5goy0/TkOM1Y/HLnAz6Tnt0GkuPLE
         //27UBz1+jKBQEnYvoYqjU7rgsYi49jwKmFzp/Jf72D0n3QPF8ryaCYSzfwZ1SV0cExJ
         pSpsFtPk4h1yV07Oc3H+yzHBw1Za23BkDJzjX7Bu1yPee9NpaBJs8fmzNHoqJsQo8f11
         qcs8Oj1KBSbwig8EuIPFh6PqGx5xZBj3dDKXC4zOes5GDQ514jOOuuM/fHBSHBb6l8Dh
         IzUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668174; x=1756272974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OMs2kaukGXuWg/mZI327rpWTn4sInpze+RC76rkXIzA=;
        b=DM7a6RjUbui2f1dRWEauNyJ+dlZV14r+r8i00Hz4ytTyz4xw85McniN5xz5YhZUKbV
         QXVpr0R7yS6aHGbIOSSQrbKNjpq/+mQx0XhWd9sHApoeNww31Vpv/ObmD+rnjD4kWNsv
         AO3uY+QMjQP7yt6THSmHxJ4rPVo6CnKQ/pgeRQSfi4LW0qyQHxitMt5FnoANEAfXXJ8Y
         U6pXulgxLi4Ct4jujTQkAYCve32Dn5Yj+RRgnr2d2IE1I+VJLRp5X6XkF7p7b3U2LOab
         U4g16TrOZ+n5g5s01xkyIW1ZFJlx6P71OPObysu04q4S5cBkUYZVxDTcxOAvRhlSRRCf
         eanQ==
X-Forwarded-Encrypted: i=2; AJvYcCUG/G8HC6hF/f1eXXK3aQYPvDtM4BZChkg3NZSAGwTwhxWh/aGMx6u8PRGyp2rKkOrrAEG8NA==@lfdr.de
X-Gm-Message-State: AOJu0YwRwMHrhaK1/HlmIAVUGiUWx91h3dlKBH4sUb51VKWHtTUjayIr
	8G2pTmRj+ox6iE8DTv8kO6EwefrmjFK7nGAbGagRpisYfbSBvOUX0tey
X-Google-Smtp-Source: AGHT+IH5H2TJiUfxSrLwE2Hvh5LkncC7iYzjkzIzbqrLUY2V4xqUbp1HXWTOBOtAeWkF+Z3eB6ZGqQ==
X-Received: by 2002:a05:6902:158f:b0:e8f:dbd4:45e3 with SMTP id 3f1490d57ef6-e94f64c82ddmr2031693276.4.1755668174179;
        Tue, 19 Aug 2025 22:36:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf5eKMCBbhJbmlAOkaVaDe/GH+jybS4e/mCgCP9owHX4A==
Received: by 2002:a25:ae9a:0:b0:e94:e82f:67ac with SMTP id 3f1490d57ef6-e94e82f6842ls1399545276.0.-pod-prod-04-us;
 Tue, 19 Aug 2025 22:36:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7MRPmH3xWpoiqdAcHdXwojR411vn+v4fM79CAXuuMuF4fnUpth/dFzWqVnbghrn3/13TCZSgh9VQ=@googlegroups.com
X-Received: by 2002:a05:690c:6902:b0:71a:35e1:e1d5 with SMTP id 00721157ae682-71fb30ed69amr23939667b3.17.1755668173323;
        Tue, 19 Aug 2025 22:36:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668173; cv=none;
        d=google.com; s=arc-20240605;
        b=lyXxS5eD1cA7wgJ/eNdffsL7pXzEN8S/E3Por6byHpIlChuYO93GsjUjSUcveSR2RE
         kfdxz2aDTePIjM5UoWsbcGzoXCe0iZQWklJ5df+eGOGvtvdwWj2vL39IUpzpIaguHxx+
         DrZ0Qc0UtFCnwdiaoG0XelJtr79jvlRoZjORXaC4WxyyeVQ/QiY/LGZE5Xwri2nM69H+
         olPTqVMzcIjUxLyrKkJGE0A6+rOAok1/EjwSBEIlEFt2HMTS8QyEs3sFzJcPuRWrIrqh
         wZypAzRqK7UHlk4LgoiFDEeIaJiFnBNPcArzql6zEfkCIBtgD68hUeHcuGbTzjMTfBvF
         o8EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HIvq87a0AAq2d23Q/rNsSw9xnqrtCb4IHcYwpyhrt5Y=;
        fh=sLSiTBUqtWQjWgHkI7YtQlNHjLETl13CqbbSLrDbiMg=;
        b=STuSz0TcmZDqeqj/W7kZ/kj7VU+qH1dNG6bLEQ9f/R9upBU5f3KHNvtL2CK/bh0Lfy
         QBtyLtdeBVqtctVi7jK7iUkGJCWk6tsgvBwhndlnT4FgyujXJrQi89To8accg3yKafkM
         wKN3Elp3fYmB6FzTXPP9sx/umVs0b1z2I/kbWj+ybt7JIesYLVTYB6TIO3pitCDcSNc9
         b3dim/sUaMKGGgYgAhX6FjHVYVLfjptrVaYDb63lvxi18Q5LhtGGT7n95Kmt3S3nquxm
         XMZ+CuF1wEtGHyiIuSSm0mxcqV+dN4CbDOWxvKm26hErpkUZ8A5/+wFcogRNgSX8iDuA
         LgiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GI5o7mlK;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71fa513c048si1066877b3.0.2025.08.19.22.36.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-661-P3sGgTDEOVKL3Cw8VTzXMw-1; Wed,
 20 Aug 2025 01:36:09 -0400
X-MC-Unique: P3sGgTDEOVKL3Cw8VTzXMw-1
X-Mimecast-MFC-AGG-ID: P3sGgTDEOVKL3Cw8VTzXMw_1755668167
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5E17F195605A;
	Wed, 20 Aug 2025 05:36:07 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 661C219560B0;
	Wed, 20 Aug 2025 05:35:58 +0000 (UTC)
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
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	loongarch@lists.linux.dev
Subject: [PATCH v3 06/12] arch/loongarch: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:53 +0800
Message-ID: <20250820053459.164825-7-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GI5o7mlK;
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: loongarch@lists.linux.dev
---
 arch/loongarch/mm/kasan_init.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index d2681272d8f0..0c32eee6910f 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -267,6 +267,8 @@ void __init kasan_init(void)
 	u64 i;
 	phys_addr_t pa_start, pa_end;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * If PGDIR_SIZE is too large for cpu_vabits, KASAN_SHADOW_END will
 	 * overflow UINTPTR_MAX and then looks like a user space address.
@@ -327,6 +329,9 @@ void __init kasan_init(void)
 	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
 	local_flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized.\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-7-bhe%40redhat.com.
