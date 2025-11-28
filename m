Return-Path: <kasan-dev+bncBCKPFB7SXUERBWVQUTEQMGQEM7GDRDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id B37B6C90C4B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:52 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-297dabf9fd0sf19068715ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300891; cv=pass;
        d=google.com; s=arc-20240605;
        b=f/dibUfxnpEjdO7jMRc1UD0rbzXGVR0e+7bU+ZfwHsCHFyPE5OiwTlr3ptDFIC10KL
         V/x/zXymYGC8XCfbgLs/XpkY8GIC3ml7jQjoqJktalbeY/xBYa3vc1igcgSeRPqKzwec
         vfZUrrGqBvKjjUQTQ2bpmUCej4zcHefm0A233bg2gSUTDwDAo1zdXrhcKrVlCq788BL/
         iE2nhrT4lC/oolXMz/aOS+V8Fv5dzw4bKOcmtWVSd5qvrd3YyBK/x+di6uSOcGnQMFhE
         LIs2LCQnsA+M0bXNyHa7adY6L0BpMf9hn1Fp1YLx0KeUqPUN2+jWd+p6I5vMBb46TJ0/
         9e0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T+Rt8BZputwAgI6RWPmTwiMWlQ7ywlDrWSG9KPrUpzs=;
        fh=d6rdlUGeoV15tJaMujCpLgbA25QIwmC1J1tU4TP2xn4=;
        b=RYMK9ApDh5JhzxpD84ujETijt+cnLXCd8hYnuRyfNuSHRKtPsb7JkYBUIKOQV9fdm7
         XogwzHP+TzNBaTsDJQw0clWSjxFNOsTvJxiKqdLMiZjCcVkv6mNsRWsdjH+VjgD6VKCj
         IPMekxKHOs+Rg+vFO+g8CdYXXPTR5qxZ8X+YveBK1QTfgGWvouUuJaJDFFRzu1F1B1pM
         FQQhQyjh3Ihb/ecDmPRVhsbsn0IzNUTTdtn1HsFRzh/g73GPR8ogodjZOxCO0GrcXwKT
         Q8w4Rz8SG1KQS6Bj4qrLcBMeN6+oOwhD1W/FSBafMxBDRCnSdg3xmid8FeOlz1OIwMMy
         dE6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OiMllP03;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300891; x=1764905691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T+Rt8BZputwAgI6RWPmTwiMWlQ7ywlDrWSG9KPrUpzs=;
        b=EjeiwEpBZRn2/ONsILN5OwzQJHOZVwRMtdMjNdPsc+iS3gh93veaesYZ/4OZCUf+cj
         oj9eBIoirHrLacWqm+YcACaaf9pfP+RHUsaa4I2KpbfDDGanvm3PQdes7oc+24qi3S/1
         0U69Aot/sGRnvfkKY3YROgM1j13r+YtCIBS0ywsUJLy8VunuOUY3yKNwc6VueplssvWP
         BdYuHDvhiQN1jheo3EZBVYPeO5+6HGCaPeBodInSvjenzSwoDRHxtQmc2BSZ/k5JDqZK
         wDkFcZAr/16h1rG+BtKF2ewC5EW/lGHOADxPZWln64urz1G4e0uQWMQ0U5PTEEPAT8gP
         a+LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300891; x=1764905691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T+Rt8BZputwAgI6RWPmTwiMWlQ7ywlDrWSG9KPrUpzs=;
        b=xQJyPJvPthYig40aWSeq42jFHZ6wSCesyxxnf0e095ISJ2B4shKAGeVG8yYDeraEbM
         i59R/PWD8+E4PODAYU7ANb8s4paqRRfKGmuBdh0NfBArPPa7TJ1dXCSmVmw+KA/WBME9
         cwdzTatKSlrSTislzdqEN6xlTgGgnb8ofjcYCTo9HeTR6y0BnhBItLUIM5Lp0mTux2YI
         LIljgbx+taSVwCAZjhfeFRCCgLtnKvdOfWrxEfgN5ualXQV6zVJ9rsKgj0homqJT/Eu0
         L4sFlEMlLbRjAPMWOgvQlH6zAH4xpCKcbvGNK1BXRtrTkgTeJ0M9crRL01E0zHgK3QiS
         aK2A==
X-Forwarded-Encrypted: i=2; AJvYcCVpwGvKZHKfXC8Q4qh07d01uj+AQMyG+7tVycnenkADY6k+Dapsrslmk/tjk9WW8G0HGmJu2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz67DgSdNTj7PDhJe6v5EJUiAJ+DsELPv5kEznrXb9e29MfqCwn
	cVv4F2SWAjX1yjGV1ub+kLWlPVjRz9h3skWWHlAf/xKXU3HYK7kJlKMi
X-Google-Smtp-Source: AGHT+IE7NJkYc2TP5y73voRpcRmxqrEE74RcdcSMcz3vLzKpwJHxZ//vULMzptQjrgL3ijlllo9THg==
X-Received: by 2002:a17:903:3d0b:b0:290:91d2:9304 with SMTP id d9443c01a7336-29b6c3c2864mr278214975ad.4.1764300891030;
        Thu, 27 Nov 2025 19:34:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y8RZsflAQOFsNVuFVr9eCIzl+r4u9t+3xsZ2gVLSdf/w=="
Received: by 2002:a17:902:e346:b0:295:ed3d:16da with SMTP id
 d9443c01a7336-29bc93e6215ls12749365ad.2.-pod-prod-04-us; Thu, 27 Nov 2025
 19:34:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDa5/3PbOY4qHtnJVr6hc173zgiRgDWdrGSLpO52waICO9pEElRcU5kl6AJ/UfDtZu89fo390BiTI=@googlegroups.com
X-Received: by 2002:a17:902:f691:b0:295:68dd:4ebf with SMTP id d9443c01a7336-29b6c3e3c48mr311221005ad.16.1764300889636;
        Thu, 27 Nov 2025 19:34:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300889; cv=none;
        d=google.com; s=arc-20240605;
        b=STnscDRg+x8QqgUc41xqL2VHEPOth9+bzP7lSv9rb9wBxVE9xC1S+snZeKNuIhlDeK
         udx+lrbiv1v21VUOsGJLPL4Owm+bms2KFFiZ1Tb4x5FhsLDNN2J7SRsluz15bWkv8fMV
         FByxhJOml0nShVa+qgiYRcWhEUhX2AR6xa4HztCDTNtD3OrLEU4vfOb8PKxAAObpbq3h
         EPiIkkR9RhtXYb/uTV6GhF41ddMxRFcW4ap2piE6BajzRtQViu+1ciChIkp+B7MTcgxb
         0hE/0aZkdeJUd4kRj0wiIeNn9U5tGE8cZLuTKqmJHrlfW9l5vjAfCEn64fURI3WOiB/m
         AI7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=r92fL9oKQlRTavP6tbfc36+c9pPVRtr0L8H+RYQ9Yos=;
        fh=XbGuLv1UKY9322YcpA1HoxO8xGpy8xrSTS+o2XYS9Io=;
        b=So+kVGhn/Pb8d+F+Mcde6XVFhOjKKOovnQH8MymcTJr39Zy1QGTTqigq4Vm2YQT65V
         /y+Lz9b90Ew248tYjjRH70XyTSpMcVxUzdFj2Jm0YriDB5EgWhr/FMsV5c4DU9Qz4WiY
         JyQ2gq/OT46lF/R3ACu1hCZiJL1ejel+rdH+H+W3ccGSFW7EJ453PVGz4H1dJq4d2TBj
         ZdZ9KUHZTkLQDgWQrVPXW1/Z1C+sQKM/IC6nszB34oc7mvJFamFnr1fIhasorZCdaKxF
         MoAQFt4OgIyH7H3JeJIkyvFgCbt9HmsWJMrQc899llmn48TiGUI26GLoliadjlGBdr1y
         2S2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OiMllP03;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29bceabf099si1101335ad.7.2025.11.27.19.34.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-119-wgaq95i9OjubHDsKvyV9Bw-1; Thu,
 27 Nov 2025 22:34:45 -0500
X-MC-Unique: wgaq95i9OjubHDsKvyV9Bw-1
X-Mimecast-MFC-AGG-ID: wgaq95i9OjubHDsKvyV9Bw_1764300883
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id EFFC8180009D;
	Fri, 28 Nov 2025 03:34:42 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 46F4D19560B0;
	Fri, 28 Nov 2025 03:34:34 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>,
	linux-riscv@lists.infradead.org
Subject: [PATCH v4 08/12] arch/riscv: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:16 +0800
Message-ID: <20251128033320.1349620-9-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=OiMllP03;
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

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-riscv@lists.infradead.org
---
 arch/riscv/mm/kasan_init.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index c4a2a9e5586e..aa464466e482 100644
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
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-9-bhe%40redhat.com.
