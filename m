Return-Path: <kasan-dev+bncBCKPFB7SXUERB2N5SXCQMGQEQZZHQHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B41D6B2D395
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:36:42 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e56ff1127csf76872215ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668201; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wo2dgggBFHXlZi3sL0knunHaCx8gjVh6o+m3pRjr4zsTS4wEB9o0pq48hRTZs6H0mv
         A4ZhGeE2HuQ6tyxfIEdShK0GmEh6hMaS8lQtV84TAKNFwqD4Ilh7ycGtQH1rO0jHURnv
         Wen/A8mTGuMtngUkiWysPylNfInbFdwQWilwV3KiWTSZs/jleVVkxfxPWEedN28ixrQ7
         5AgSSQCJ+ohiqZUzU9qciplYlOiQhsmoRQCrBRPs4Dwatlpq2b2K0eEK5ZlIjJaC7w0H
         jJAuwMaowGqIhejBUek4btolaBpY+XqB8LgJm4M5sFNJSWf27T1FlMgPpyWK2hqC2V0s
         sCEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AFcHOAajcepIZloXvJQX9TI1nykGR9G6/YtoaiNI2Rw=;
        fh=nAXxcMtS8/iNjF8eLbHr2Zk1ax/J8HGy180qZ/GpE74=;
        b=gPubzdg4JwqUN8aIQjnRerhvh6yjzfbcLR4Rdlt71NwODmevxhoH3PaBo6hVL38lm8
         kOsPJUtMS30jSzbYJhtXxlILFJDA2FGSwRKXAqTESPGWe9ZgpVvy0z1WZ9ANU5AzDmY4
         XTOd0e2Yr2n2rOuHyZ0oGChId2v37fIOBZCF0f3xoquy73poT+SLZeG1voDqJXdpwiEI
         AstKrEwUtOOPoQGOcNhBQyEEMoI5QUsG+5PMYL+iO4LzDgI33/WhUHkmhZU1kyVKlkoF
         aNmRYyWWAkfO+1sb0DUvaJRw1NKk3BlrQWY+aqOQI7norri11SV7pehr/U/3fs8vu7tv
         hgtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gPdTm5lz;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668201; x=1756273001; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AFcHOAajcepIZloXvJQX9TI1nykGR9G6/YtoaiNI2Rw=;
        b=W8viQLEqjydk2ROSmHkUDl7BYFZKtW/f4kFpdR4VQ7yuOWLty6FtGy2n2MKigzWs2M
         /nOALG6Jl7Mca+RPXbzWhYoM02uJ/aKDqA3+yK+yu687vIxfnyLI6EhUXDwshpC7e99b
         a50h+VoLRzB+5fJ+p4V0b1G/U4DuNnvYa40omcgsOavKsHtopqNaNMnFhtsiw90Le5tm
         elPUVvGoW2etw1l7AznmMiWUJ5bJmu5kqbcn/APZ4IQccFULWeXlCPNjbOVLA5oGFCQc
         oCj+3glFhfmV+a5yezdnz5H0XCOvsOOf4+USHLioVL6SEqF2yJBkxgGM/abC3HTdPA77
         Llsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668201; x=1756273001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AFcHOAajcepIZloXvJQX9TI1nykGR9G6/YtoaiNI2Rw=;
        b=hsl1f6CfBZOTa50pcoSrqlz8I7f+lxiXjgOSKYQcIBQglJ8KfFLeDQp1JI9n2bJHcd
         XsqNrcl/4ZQtpmb9nehAUjUt7V6DXaEDeArOtGmtL+JmsdJUt+f0TuqzE4wPU4tFdayX
         msprowjFNiLUv/rvRUg55ggvYWSHVvpcREcCvY4KP+mgkXBOk2v+zOqHb14pnddBhIqz
         fnPmgZ0lyE+7PmTxtazxbtvg1ghC9EUGz6lNZkQcIzaw/YNofGYQtrZ6ePwcsARpzVaI
         Sb9sxz0eY+TBVhVULXdlDNEegV6uuyKCX57NdLhpBVyjwpMYZPmAswirQXLbVM7uXdSs
         AzDA==
X-Forwarded-Encrypted: i=2; AJvYcCUp2UzyHcq9g84Nr9jlBqr8bZ1jsLx+cVwHOlq9DWqWyTflENMAekWq8YxlzP7G2NLDQ7HTHQ==@lfdr.de
X-Gm-Message-State: AOJu0YwIU/Phtbb0asI+tz23M4ij/mqt4QuCR/FlF2BPPzI7fDXvXOua
	nCWv8PH0gI0wLHI6SZIYIlgmgw2Crvb2DHvgTuCLAUsOqUzu2j5CtyNY
X-Google-Smtp-Source: AGHT+IGp5UCeSWAvEDKQZIm3OA2u0GJGdnkYzTd6OWGIMcMfgLtmKdp2qYULBV/vXzYuzWfXsV5nxQ==
X-Received: by 2002:a05:6e02:2147:b0:3e5:83c5:fe10 with SMTP id e9e14a558f8ab-3e67c976d8emr30947945ab.0.1755668201430;
        Tue, 19 Aug 2025 22:36:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcDnpOGldKcOfvy6231YMW9o5viFUTH5fyI/hJkU8mxBQ==
Received: by 2002:a05:6e02:1fcf:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3e56f9278ecls57463605ab.2.-pod-prod-04-us; Tue, 19 Aug 2025
 22:36:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1N4PODcSCeRjiPgkE+kZSsacREKbl59LqNBmJNq+MSLEp527IaBfQ4U9RKQcm+odBQFvyJJ+X4mk=@googlegroups.com
X-Received: by 2002:a05:6e02:1c0a:b0:3e5:4332:91bf with SMTP id e9e14a558f8ab-3e67ca1db3emr28246295ab.2.1755668200317;
        Tue, 19 Aug 2025 22:36:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668200; cv=none;
        d=google.com; s=arc-20240605;
        b=RCmgyKUNTSealhP2lpRypb1SBNXhTswmmuwo3JTNn9cjGHr/FiSt3iXtRJsNUEzpoE
         zcYCImLvYhgAV0FFX3IOO1p5Q2Um0rFe5OTVMcnZHVF47DHPwjMaLD3N7dbJ4r+d6eXR
         Gm4ojJ3RBrvo9Egvtfl8VzWv213CT6WaUIQ2tneOR71fZR904qVlkiLYbkybRdKu2AWF
         9iHvp5e4B1MUJoO84DjpBaDotEO48zN4majJYDtkelW5HzJnGDnkZdR4DnlybMdqNIiG
         i22AHqELlyvTCVepf9jrq2QeGCa5X3+m4VFVMNltQYzL0Vth088DZ8dDi7WnEZk98xhV
         TbBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iAEMFQ7UJQsp/YRWJnDzAESQXUNpKqSpnHshmUmLX+c=;
        fh=yBOvpl5Zrjdnr6qGCfpgKC5AtoOI1zBZxb3NiMj6RCQ=;
        b=WDm3e+sn+AQKMwG/rBvom093adn3skGe8TeWxSXu7CbQZrX3qpRMny7I/9dOpNHsyo
         1BVkYkErIDAnOwVa50ThB+Oc8SoOpx4wsev53L/+R03J5FK9x2mxAv8dqkzYxjDOAT01
         eF8EYFweLWJecNpLJlFgz0zZ+p2eRw9VWwKh3WeXCth+YqamaO+OfKW1dBZOoGaIxSIx
         BeHonr+zX7zgoq7vy0GKpfArdkKgQ0gJ0cOp5Hj2FerbyFn5tC9ETC9sk4L1IzbDi3Oj
         kPed297BdeijNLz1TclRtYI03brYMGBTUeVM+9YasgYtZqZVfeHkeZF6bI80FJC2TvSL
         qsGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gPdTm5lz;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e664d656easi2615895ab.0.2025.08.19.22.36.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-488-ua7zccu4OLWU2rQ3gWmgQw-1; Wed,
 20 Aug 2025 01:36:36 -0400
X-MC-Unique: ua7zccu4OLWU2rQ3gWmgQw-1
X-Mimecast-MFC-AGG-ID: ua7zccu4OLWU2rQ3gWmgQw_1755668194
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E7C12180034B;
	Wed, 20 Aug 2025 05:36:33 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 712EF19560B0;
	Wed, 20 Aug 2025 05:36:25 +0000 (UTC)
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
	x86@kernel.org
Subject: [PATCH v3 09/12] arch/x86: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:56 +0800
Message-ID: <20250820053459.164825-10-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gPdTm5lz;
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

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: x86@kernel.org
---
 arch/x86/mm/kasan_init_64.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d216..0f2f9311e9df 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -343,6 +343,9 @@ void __init kasan_init(void)
 	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
@@ -450,6 +453,9 @@ void __init kasan_init(void)
 	/* Flush TLBs again to be sure that write protection applied. */
 	__flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-10-bhe%40redhat.com.
