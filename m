Return-Path: <kasan-dev+bncBCKPFB7SXUERBS7R5TCAMGQEAVEC2YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 68DBFB22764
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:51:25 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-742bcd34a93sf5918938a34.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:51:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003084; cv=pass;
        d=google.com; s=arc-20240605;
        b=BDWAAPz/xkwPVHogj7uacwM9RrmHbrsCFGufQWD+wDnSkWfa2LVhqgOJNEVG3NQn6k
         elm8Ju1VXHROzkEakDPMzQWnQ2w7LGWubuhcohTiZODPflRLEPz+1uaTptGLQpopoRzH
         ErztCH6835iAws0FFdFkj40TprCXgtps817OkL6LWBs8d5bCtTR7DF1Qr4152CwO0TIC
         30JzJt+bmG8yPvnX8MRRVi5pjOFiHQhytGbueWPtUrR/OwYTzeUGvMB4h2ZgWlRKul5D
         AT5Qorkj3ef+2vGWj0N1rIqWjYdRlhK1zmZUZeFvgZcFGHnfmsRdvj9/8YUhC95im8uc
         ++fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qCoklu+YSA1M5L/BELwNYtnrZKcifTtrkrSeWze9bc8=;
        fh=DtOFHEJkWngNLOOm5KNOMF9mh90lUj7fp+uJ+jRDfO4=;
        b=HZpNxBTzLenYRZrVWUmBb0IJilefEqFhUOLyFcun/IYRzQ+mVK+1uQZDgw4P2iSVUq
         zgIpnN6ryskDjnnrgxBKCkF1vPYaa21ubhWcBEcc4C7lxe6JPjKWaEA2ZC6rBc/elu0h
         teglgQrqWOYPpKuvkkfTxB1+pOINvrftAXSUbvd5/UjrqM3EGMyzWf2j5MpxISVwM4Dn
         pl7oBsOzLYb93GckaGb+nQSbcIjT5SkYb+B9U5/yC/HLws39Ay8H3qTAddHEVfS41+q/
         b2ikVsIJTnJAW6aYCqsi6n535KrRvlZUKdEWjKO+1+i3eVeNpzoJvMBuAdfdESnWpkEf
         KYWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G71EocB+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003084; x=1755607884; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qCoklu+YSA1M5L/BELwNYtnrZKcifTtrkrSeWze9bc8=;
        b=pCK2YTlFtyqmOKgmpS7s0FCFZgxpzddAjg988ko7cFvt36wdKI0VxFaTTqkH3jrd6J
         4sjZQZtJvZKm5jXV3eaArieDRw0LIK0vTWfkH3F9L4NNFwmVeZB3lbNu7Hqloa09Og5y
         tAQQ5aw3UHe0aelBBXGyLfCgNhiBOJUyWNKQEDze9ayDbUV8O+irNb3u3e1naOcHVbaC
         9WXdzyOyWYlYpAwJOUb8EV7sFodRVJlUzglbiAToSc7fioK1rbR0ZFGQ7PluuZPw6buD
         JNVuG5DOSUBRanTmxBwVvzAYZ/nh2WfYJGZiN1gZeFvaTIpf5SfiTk0NUNyrc74j9wO9
         r2og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003084; x=1755607884;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qCoklu+YSA1M5L/BELwNYtnrZKcifTtrkrSeWze9bc8=;
        b=bX2UhjTlUzQuy//HpF6xpggXXk6/edxoPO1+rUQVZhCSTxO01gY+sG4UkdjotfmCk+
         1gLCqM4qvY0ISQODmIuD9oNGIhekCEDl2fZBD0Zt5Ez4QZW/K11Bk7J5x1foXHVVf5aF
         TIQ8BanSsypCOPlP62pQ9uxbMMCkzLB6YAOJh7PFrv768G0IxYYvx3OekeRtJsYIsMt1
         7bPimEKpeDPgSZmYNFUi+ob/E8n1MAX1H7C+O9ATQHSTODd7o+mIv6wWjCLXvc0ew0QN
         ZXfnKJS7YBt2Jze/abI1VnBLFypPxTh7stPAdZIOlBHb3N8nj8tdqIMdNUfvDODGykkl
         M36A==
X-Forwarded-Encrypted: i=2; AJvYcCWRVPe3p2CXSLQ0V4M2lP6fVHVmwe8+54Jg4DK3Q9eTysICkt41xczX5mDZN2ur3UfuLoKFmg==@lfdr.de
X-Gm-Message-State: AOJu0Yw0N4MnPmDI+FdgB7IQ/kg9LnSr5gQh1EzmyU++EaGRuQbnooQe
	TJcH8dwQy/bzDdsLvJk02662IcjNRvGGMyqp6R4768APLzae0wR8nkVY
X-Google-Smtp-Source: AGHT+IGOfCeZBoom4khKPMWohMat+aWgUCbHSxYiwrV+/k0FZ6SuJ4m1oaUrDQ5uxuU8MIESJyQzFw==
X-Received: by 2002:a05:6808:f0a:b0:406:697f:a62f with SMTP id 5614622812f47-435c90e0ae0mr2022447b6e.10.1755003083927;
        Tue, 12 Aug 2025 05:51:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcS6TqWE9Y6DjjLLH4jmKiI6W3du4FjlKcQna59S4Frpg==
Received: by 2002:a05:6871:88f:b0:2e9:9a5a:7609 with SMTP id
 586e51a60fabf-30bfe70c21fls3458243fac.1.-pod-prod-01-us; Tue, 12 Aug 2025
 05:51:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUphvc632xbmfGWNIDLC+HQkRDPKMB5fGcRwlGts0CCS8M5JxmFu/nMCKOD3KibES0qQ7OnAsMwXmI=@googlegroups.com
X-Received: by 2002:a05:6808:221e:b0:434:b43:652d with SMTP id 5614622812f47-435c90b4a1dmr1620964b6e.4.1755003083171;
        Tue, 12 Aug 2025 05:51:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003083; cv=none;
        d=google.com; s=arc-20240605;
        b=irzLQBL0EP4ZiLkgJQBwtCIZLKu9a5LsqtQJbORalATnw7P90T0wLPkqg3IOI9HQUG
         iHoqFSEVb747ctnhznLowpmZOeKRlnk9vAgh7gDeXZMGApMEPCZxg046c6WZlUk3XZh5
         Vj3yXRIH1Ty+6cGRidDIu+VPKSjwfKdlEHSAV/o+jWosSHybU3rpI+UujL3p0BSOZISZ
         OGdtCj0cO/khdh0cha8oEbZMvdIgV7tb+F04OsN1irFzRF6TJ0lOiQoVH2rm1dHFBPkf
         KHW4HY6uZ/jpPGyS8eg+iDhsZe47FhlsJyWDlD9YT7fk+uNgwB03S9tJsjdV7xlVpvcm
         xC/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UNvwjh3bkLYd7LcWTIY96phbAPIdD7DxmW/f2AxTNdM=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=PnuA394rspgtxweVSEH8bQqIehEotPslMD+15IP33M+s2WEYTcUYfoZtVOsde8tuDZ
         5qf0q8DRwECnZkxek0Ki5inTHGStKW35ZLFcRSRczQt2AXNI3V0jXdZTWpRljIDxS8Oi
         qpvm9wVJrX9UpmwO62eC2tuXRVMKD7/DGQphVni0avOyJfayHZPZe4dqkBrwApV3NOXB
         kw+zl7Fi3s/qhiS4+Ncgn0LdTP1dm/SXZ5aAcYCpGCBNtkvHxDBKJRNhw+RTSt+VsPwY
         CBkR9xGlDukYHSahZzPqfaRBhAZfEgmjQmrMU5rVQgo/GjHP2jOQXG9slNExofEvUnWs
         +ySA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G71EocB+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bd07efb28si501778fac.1.2025.08.12.05.51.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:51:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-515-BarAkwZZPNi3t3OI2JjPPg-1; Tue,
 12 Aug 2025 08:51:17 -0400
X-MC-Unique: BarAkwZZPNi3t3OI2JjPPg-1
X-Mimecast-MFC-AGG-ID: BarAkwZZPNi3t3OI2JjPPg_1755003075
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0A2E81800352;
	Tue, 12 Aug 2025 12:51:15 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8EAE530001A1;
	Tue, 12 Aug 2025 12:51:08 +0000 (UTC)
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
Subject: [PATCH v2 11/12] arch/um: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:40 +0800
Message-ID: <20250812124941.69508-12-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=G71EocB+;
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
usage. Since kasan_init() is called before main(), enabling
kasan_flag_enabled is done in arch_mm_preinit() which is after
jump_label_init() invocation.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/um/kernel/mem.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b5..392a23d4ef96 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -26,6 +26,9 @@
 int kasan_um_is_ready;
 void kasan_init(void)
 {
+
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * kasan_map_memory will map all of the required address space and
 	 * the host machine will allocate physical memory as necessary.
@@ -58,6 +61,9 @@ static unsigned long brk_end;
 
 void __init arch_mm_preinit(void)
 {
+	/* Safe to call after jump_label_init(). Enables KASAN. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* clear the zero-page */
 	memset(empty_zero_page, 0, PAGE_SIZE);
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-12-bhe%40redhat.com.
