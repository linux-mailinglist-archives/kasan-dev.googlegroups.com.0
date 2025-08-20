Return-Path: <kasan-dev+bncBCKPFB7SXUERBYN5SXCQMGQE7BNFKJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 75673B2D393
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:36:35 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e671c9e964sf26520195ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:36:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668194; cv=pass;
        d=google.com; s=arc-20240605;
        b=BgTTsXkzlyU5vmqtjLB04LNpNJX+1mJFFYyLSEhN4DxK9ZoA4jXCUGxi6GfiZehmfl
         XQ2/qBFgjgsAfS47ZOjMyKFqsk1beJiUDYEgC7W1+LDmL2+Tzc0YAA4ZggP8N44VsHCt
         b2fDWjb6N/1p1yL9JWEti4tRuAKBSBHFD/Yv9/OfDo0uVXjekkyvnXFi5Xiu17XxOMel
         aXUnEyWqbt/kIRBwcXu0qDphIupOdqvx854AiUEm4Gu8yw4Ds2JZ+O1ytfyKXk0mv7Hm
         G38TVUZxsuk6K/cvKQl1F4leGrSBFO7vfgmo83mD9E2667L71pZKqQEiSFHz/ztLKfQ6
         BwWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YIs8CNuHV6Aa4AFdsHrNvBnq4T1fNTjm6XnyVbxVvlE=;
        fh=gZKsTkYnNHPLvBN4OyWdSNxFJuwVVR50S0IRDu8ttBQ=;
        b=bpzCIfBO04kx9eYcCBaAoPM4J1+4yLU3/AjLXLdwCtB2/Tss/e8xhU9yWPQVhehjSg
         I5yxoqHCVRox/xiOOcleZs+JYI9x/0oY2RxTU2Xij7oIZ9PXN8IIjsCTvs0yXhC6mpEX
         UHaFeFtlGIZCe+RERSTthfoI7e7IC7fklUwcenag40JKaRkhlNsdcyBCpsOMUCe5xsHi
         UE+tm/+iLnD9CKqh4JIy2CWlFLCP2S1Ug68IVzhmso2GgR+EgbX80zrgESRWGcmi6B58
         KcxxNPV1uj+/kjrNg583Zm+fK9vmguJDn+RJ95GWdmEz58VndL7ruLdDQJ/PoEMyKXcS
         bNEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tdsr2JNp;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668194; x=1756272994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YIs8CNuHV6Aa4AFdsHrNvBnq4T1fNTjm6XnyVbxVvlE=;
        b=TdopQSoC6GmA98RlCE9BHCjJ5rSMGNBGP7BKzce/4eJzmbZK4pPg5g88ZbSVcc47TI
         y3jyU3oUUVxKKPaRSLf0AXBRuVF/uXlriimsNi0eOSnuczUnwVU0sqXOvd/THb2NhipS
         F8YnmdbJGJ5flckxFlQhsJk5gCMH9xcYEy9cp3dxypa22MaiH4yT0znZQtHHQ/FZHkkO
         yIpu0fttJMqNsR5JUC0IOuZR57UzT7iqhRzHsDgtnQowzO5soU72RHTYP/O7t4LpQcuE
         OY2C8AwyTqDq9lI0mIhCNt3hug4VVHAzS4cvjyXKx1JjIh1uCoQI7hIdEyUiosu12J9p
         v4Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668194; x=1756272994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YIs8CNuHV6Aa4AFdsHrNvBnq4T1fNTjm6XnyVbxVvlE=;
        b=SBYRSQn6CdZD3fXLts47UC68Fj3qb7hJ9QmJGRnHXPwKTjAQztT1x6Sz/96+UaMs26
         dkfn9Cl9T24UK4EznckQavuhSvAIywdaArBwZpsyYJdLa/Ew5ehKoEzvehnSE/3y4XFz
         ySlDO+srObxUGbG7wFCxzTrDVwCO/vokKqABMGUD8tvVBjAS4pRGXo4eCjARMXcb6BXq
         760u7KADQygovY3+CHGUyPqLASe/T5uwbbcDfLKmAdcS6YsgmmsZRIDTRT6FPqrdbO5t
         Xm31iXmiK3s7UqubkWjG0Tuc4csucxHCJT5z+7HCgIAHBeNAcZ1Dg3p5i6nIDDhwygHK
         F6MQ==
X-Forwarded-Encrypted: i=2; AJvYcCVqxSH1cQKTkPbfNLHEYmmdJI1FVf7VGg9IetEf7p9zjbRSFiztye3cy0cSOL14ekAAcdoWUQ==@lfdr.de
X-Gm-Message-State: AOJu0YzpWOXJjIooDcbUwzZ7MsMeakSsrjlttPOmW9O8UsW29pj9sFgc
	VFu+fvjresAwhqTZCNwDv9C1ltbV1Z6kc6JTNKxOKwkJl/ZbKWav2aPb
X-Google-Smtp-Source: AGHT+IGrX8x/1B060IJX97jKTfcaufyeNu/yuzVfJVV5Iw5oNaMe2pGc8+eUXOJ+l+se9k7zSznXJQ==
X-Received: by 2002:a05:6e02:1c0a:b0:3e5:5bc0:21d5 with SMTP id e9e14a558f8ab-3e67cab1130mr30033895ab.21.1755668194077;
        Tue, 19 Aug 2025 22:36:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2EAiqROSKwcVQfpyrTUtS6q+ueR0kAn+30y9GO6w7XQ==
Received: by 2002:a05:6e02:2198:b0:3e6:6577:1881 with SMTP id
 e9e14a558f8ab-3e66577194dls28224285ab.0.-pod-prod-09-us; Tue, 19 Aug 2025
 22:36:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcbsJ3+ez4o2ubDDkmiXqsUB8UbFbKpY6Li5bs2xLeKIgZ8s48GKZYtoGbalJtPxrx2nRMzzdrtgE=@googlegroups.com
X-Received: by 2002:a05:6e02:2141:b0:3e5:4b2e:3b00 with SMTP id e9e14a558f8ab-3e67c9e6dbdmr29464505ab.4.1755668193250;
        Tue, 19 Aug 2025 22:36:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668193; cv=none;
        d=google.com; s=arc-20240605;
        b=VN3mSTsIlvrOkqZqeqZ9dIuEOWiCkYe75fVqHckWcbHiZN9NgzTYLkdcE45siL8SIf
         +tibzJZ1Lv0yorhql6nxmiN46OJftqgvCMEV3/2QE2iWbbSwKIeetQPRH+a8zoel6LAt
         sQ1KU6webmpX86P9l1Lw1Nq2zwlko1vxxSTvmLg11WnEsFMIh7CM/PDzi/kMUrUZ1xtV
         NZ2HyEBUm5ZBVbUuK0ZVp8v7kSBUPqzPGiKlrl2jbH3Z/Lf3t35rGu/Rj/uKcyzGmRKB
         YUysZS+DE/jdLEEiDXJLVNI1MJXutTuvBX/L6zprWwt23Mq+rbMNNH9e3Lg9gNeSFhkC
         dk3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tSX6B0M/ECg+25VESJMFTz+rvOMGoiNHgeaxc9XIWxk=;
        fh=ycJwri3+npIqQ6/4WF4aq1fihy4Jw3YilAE7bQJHhrA=;
        b=b4TpTa0iTfVtHI0h3ay90XEavky2HiZy9sgjsgLGjMayG5oXwV4k9xM3R7jcODndwn
         J9Ll2e5Il7IwsaSpAYF07T8YfYuGQEluJABIlaISt347AsilTYEzzku4KRUtYjI0PhJj
         oiNDPAFrEmSrFzQQ1ErmfKQi0oPh5ofH+3TKUShyeOPKj7xVFMfZVwpAW9M5rBfRlfQ0
         sthlh4cF/werRdhOrBZ6I8rKt9C5zEP4vXbgsifZ2LDG1g7go35gF+XBTVfzwz10rk55
         RdkZm+zruvf/hTWX1vevAb0gjYWXGqW7Y3+F3/FjnEl3GXoSmyS92huTVu+Pp2zin2UN
         vZeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tdsr2JNp;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e66ba5ef4asi3987195ab.5.2025.08.19.22.36.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-92-GaD0GWmKPR2v39dZ-bWOUA-1; Wed,
 20 Aug 2025 01:36:27 -0400
X-MC-Unique: GaD0GWmKPR2v39dZ-bWOUA-1
X-Mimecast-MFC-AGG-ID: GaD0GWmKPR2v39dZ-bWOUA_1755668184
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A6107180047F;
	Wed, 20 Aug 2025 05:36:24 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BF69119560B0;
	Wed, 20 Aug 2025 05:36:16 +0000 (UTC)
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
	linux-riscv@lists.infradead.org
Subject: [PATCH v3 08/12] arch/riscv: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:55 +0800
Message-ID: <20250820053459.164825-9-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Tdsr2JNp;
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
Cc: linux-riscv@lists.infradead.org
---
 arch/riscv/mm/kasan_init.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca4..ac3ac227c765 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -485,6 +485,9 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	create_tmp_mapping();
 	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);
 
@@ -531,6 +534,9 @@ void __init kasan_init(void)
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-9-bhe%40redhat.com.
