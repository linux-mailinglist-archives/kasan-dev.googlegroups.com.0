Return-Path: <kasan-dev+bncBCKPFB7SXUERBF7R5TCAMGQE5ISPZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BE040B22759
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:33 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e54feea321sf43842025ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003032; cv=pass;
        d=google.com; s=arc-20240605;
        b=evE3uPA1koau3Yf32ZDfDiWis/WWb3st6FTxFrCgNoSODJMO9u/RDU08HbrX7k3AQM
         jJ23gjT4+gvRcw6hNCZW2Gfx0fHvAAA6KkKbTgnsr1aZ012SJOGFeoTEwTaa81/HP40F
         HLOeX0hgiFxfDav5p88D8Q7A3wshQUyU/GlN+V79pW+onuoH37K1RnT9gc3VaK/zmqSv
         ANCvqxlmG/UvgSpc1+urusAanl+4kM9LiTysuZusPRPQws3YMf4SodEqBV4HCrrf+TYX
         g4OzyWWTnV5G+ctlYXqCKCbMQVa60Ff1cj/ykt+00DmsdWZS0bhNx8r9g6PsIB+LoIZM
         jXZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DDU6HCdTm57HUrlM3UImxEN4zKQOFArcfSGk82l3m8Y=;
        fh=yr3cUwDD4oO69v9undDahE4Q0txJm2Wl6OzVqUpTgs8=;
        b=EkaYzw4z4B//JMoP6hL03xVVDOOThpYhIn/dIgABbK5jd3miJfaehiqS67BclYul+H
         mhxIwZy5eMx9ibjW5BxPDrPY6O25eafB3hjprWClxdeEYKtRYULZLLX8sNQKt3n/0wTX
         GsnZSaxbNtPBqXODksjoniGQ8WFJV2nvNzmwDFbw/crbPWagDePNH83thmA+cdeC84X5
         frWq51PqW4Jp8b7rmugwAQ2OqPLgE0nHwflen6IIBfi71lENxZkzIR7qBY/mFs7SJfHg
         kvVY/BYc/qoawD8BgveiDe1xtBLVwipG53bysCrTVQmo4vWcG9mXDIzHUD38xz7PZMV6
         ypgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XY9uIOfq;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003032; x=1755607832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DDU6HCdTm57HUrlM3UImxEN4zKQOFArcfSGk82l3m8Y=;
        b=K2TuTOV1wCvxKbMjJrv+TlRaoPs9CFbhC6a0mlaLF2A3RVMUb8OQg5A+dp//RVWhBL
         Huzp6j8zDW2BYNVi/68eSGTlTv8gX/FNEzw8n7TsYgenggbh1lfIz5I8rYQwxAGf1gpw
         DITe2zmtFjU5CwgFh1E3UzXDV/E9+66ucySWV1IhrgiqEx7dnDpPQsNd/Sd6EC5SbcEI
         tIZbJGbJjeMd8/93qe2V2gDhsFN0GtFh3ANyfpX2bek4deD3PAItZ0R2j/WGMEwo4bch
         8r7V1C0NKsvRKriv0it9bV2LXrud1Y5AdeIMJv110tVTvUBNDbUiNq2eqSpEhrPD7od0
         kOYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003032; x=1755607832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DDU6HCdTm57HUrlM3UImxEN4zKQOFArcfSGk82l3m8Y=;
        b=eM4QTt6Y77ZMUx49YXHLsYdnYs7EmLJ80nyEXLNmRUeQ1tTSu6GKUrlrrv4S/pxm9D
         RNS+Gm9fpkZBLs3BUBqetC2SVp4KpQnj9UXHlq0X29WPllijVT4WAWgpu+VmtDG4eTOH
         AWGABXSx6XFS2wcpIreg80AthUDPhBHKUenFlqMMjSRhVNbmUHkHTYEjPuLchBA+t0Vu
         8Ff1PwtOBHmBxsBsrXPZJFl44Cqpg7NgoFySSuXuQ/9us+7rpMups7UI5ss47PhT+/XP
         9pVF+ayxQWrBBAtOW90j2NAowQGAwgnWaqahV9r3e2Bi00qBYYilRIsBDd/P3ZFg1hwX
         p2/Q==
X-Forwarded-Encrypted: i=2; AJvYcCVtAsAwZ2uoxq1OOwABjKidRe4lccXg+kFzg0eIFcDF+DPIU6hNgGy/J5JaIE5SCoFGeOYG4Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw4ehsJfNE2z8ivTOO6QJjXGrMym1wrTH4IN9tzTRdO6FnsiWyZ
	/doNmgBmPg5mAJX/oSp/zOP9Nr3kP1V/48FOfGi1ieuvyP5mDbMQxUKm
X-Google-Smtp-Source: AGHT+IF8oWM88Bcn4iVM6H1vOwklm2UH3o59kLDbphqYkQ9v3xqwiS8qB6CEip21j1sb7Htp8YG2nw==
X-Received: by 2002:a05:6e02:b4b:b0:3e5:262b:8303 with SMTP id e9e14a558f8ab-3e55b055c5cmr58009235ab.20.1755003031994;
        Tue, 12 Aug 2025 05:50:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe08lem/Ug/s2dVtjIRaJXgLJjLk8tJVUVtXAB3Eb6/BQ==
Received: by 2002:a05:6e02:4815:b0:3de:143a:a012 with SMTP id
 e9e14a558f8ab-3e524941c0bls59465975ab.0.-pod-prod-01-us; Tue, 12 Aug 2025
 05:50:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjkfSliIqN9aWR8RShikr+prt7ujYJqqU51VvJWC4aHRP4AZF1EZmuUEJNYNPD7eOeAGaZs9/mBJU=@googlegroups.com
X-Received: by 2002:a05:6602:7187:b0:881:9412:c917 with SMTP id ca18e2360f4ac-8841bcc009bmr653833839f.0.1755003031214;
        Tue, 12 Aug 2025 05:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003031; cv=none;
        d=google.com; s=arc-20240605;
        b=Cnd8EH7J2RIgu/6M/ol1lquZfy+QV5gosSImGja6j0rk8YBeDG7OX6exy7x1LNoy6K
         50PnX/cK3Jv880dAJnur8Jr+Geg0n/Y7nZSnKvxqkJNg4CBzif+I5oFP5XKPQzvW20vS
         elMkZlbd1n5lFIFKkqEiAn8z4Ozu4/UzoLbFMZ9XIePvKL9dqTbzaE5pw2QgEN+mqk7Q
         quTv8efKaaMCMerEVo4kjCQvO1ll6IMO+qu0T4bnMqOCgp8nQvNYKLYSuTdN0DWksxZ5
         og24fCPEnEN0bfK2R1oEN39xXa1B/j2fbzimID43MuojTlk1Oe2mxGCEV5YWUKoyXst0
         YOYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xr/w2mK6l802lCxz4VjyI0YPeCChzTlSQ7qvXcEbkU8=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=fHBU4f+9PawtMT3nV6TsE3GQeP9sCiDJ+uNKCAT3coENS88IQ4kSoCutdhvxVCAKqV
         g3oAC2Vrx0tqefFSBG2ht02wDBIetGA6zcn5MCIiqcJceqpbU7C+H6LmNOo03iWNlYbr
         v+fw7hjvO6gLQuPZFIUDCP2S0f8WhAlyhGKA/Gl0vYWm+2Rk44BbM4A+tY+dyUsWFLaP
         Loz65cKt+hJC/k7qyGW6SEu/+6ebIwjhXpcyhTkFdKLYdwz5QdIOzkaIGXDKpciVih9H
         n67EUSa3SF8byy1NrBlMIHKEjMW4hvFpbIYrAbYptjo+tMr+xzaVsC3PJp2X89O5OBmF
         Odcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XY9uIOfq;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f1999f30si40264839f.2.2025.08.12.05.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-10-XufWQzS-Paee81uzo9E_Ew-1; Tue,
 12 Aug 2025 08:50:24 -0400
X-MC-Unique: XufWQzS-Paee81uzo9E_Ew-1
X-Mimecast-MFC-AGG-ID: XufWQzS-Paee81uzo9E_Ew_1755003022
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 24E73195608D;
	Tue, 12 Aug 2025 12:50:22 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7BD173001458;
	Tue, 12 Aug 2025 12:50:15 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 04/12] arch/arm: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:33 +0800
Message-ID: <20250812124941.69508-5-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=XY9uIOfq;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

Here call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/arm/kernel/setup.c  | 6 ++++++
 arch/arm/mm/kasan_init.c | 6 ++++++
 2 files changed, 12 insertions(+)

diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
index 0bfd66c7ada0..453a47a4c715 100644
--- a/arch/arm/kernel/setup.c
+++ b/arch/arm/kernel/setup.c
@@ -1135,6 +1135,12 @@ void __init setup_arch(char **cmdline_p)
 	early_fixmap_init();
 	early_ioremap_init();
 
+	/*
+	 * Initialise the static keys early as they may be enabled by the
+	 * kasan_init() or early parameters.
+	 */
+	jump_label_init();
+
 	parse_early_param();
 
 #ifdef CONFIG_MMU
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f703136..c764e1b9c9c5 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -212,6 +212,8 @@ void __init kasan_init(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 *
@@ -300,6 +302,10 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-5-bhe%40redhat.com.
