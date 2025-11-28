Return-Path: <kasan-dev+bncBCKPFB7SXUERBRFQUTEQMGQEV5DUANI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 60E46C90C36
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:30 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-297e1cf9aedsf23834405ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300869; cv=pass;
        d=google.com; s=arc-20240605;
        b=GsNNViPNyH+N09hA8i1fMUU/K4Tz31C3ZKVX4dBbTabLLBPYz1/+CXXBSdWx1JxAp7
         puEY4w//CRJYfp1JvUa831msNdkzHKWx2oaRXk1k99j2UX1LpaAbM4WpzT71af6TW9IY
         7+3DajmWAHXvDvrBueqgQ6e0RvvE9hGaDR3X1K5obPkYT7NxcraK6wbKdSot0GKxlNeX
         dd2EwskxvVB3oS//cztReoAi9AWYBe8kzAlMFZ/eJ35PAFi6AFlFasCwm7vH0ElDXJZX
         AGsQpD847zr+B3vW8aHGUgDZ1VO/4HBejT1tl0lPoQGXemGYSYUCjlyXsLORykUWhWrS
         A7fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=J4DnMyO3OHhgWw6wYmkkKUbtF2En7urplMxeFeDUhWc=;
        fh=5SQ+tFvS3EPAdul6IVHBjGRbsyoXkRLmW/OI0MuFgF8=;
        b=Fq7gThVa1hlufKj5U8y3dC8762Rx/XnAKRKP0hBgUVMvf9GjPr1DyMkMmEl40SeZng
         X7oaSobop1YwEtD8PI5VCBG4UdjfVBIA7UB7CHA7vrcAUXkKan6b+7MjKg3nd3BuUuiV
         yjsZyGGA29gMwaGonTU1sDyCEhirRIgXcZuK9efdaVLzokqI6/2qw2Brw82YFyv51bjZ
         xC4bhufN6Zyth+R+DgTSFIlgkkOcl7R9HgtmZWmJVUzVI9YmwOdHG6ljNNxcHhPY3duN
         erHwll7fgM1bbSDagMz7q6B0d/7jQ40vp+4aP/ZNPWYpO5e4pMQAjCbQOlS9d3q73Apc
         LBLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KHDnTcCd;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300868; x=1764905668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J4DnMyO3OHhgWw6wYmkkKUbtF2En7urplMxeFeDUhWc=;
        b=shHXaiwdVcxBKTWBxnp7ieiuv3gxD0quOFmtqQnV6/Ddzfanqrl/pV9PgRpROsmYJA
         fHt2H/llcd5LtQ5NiuSLRRbm9wGbmIn53MJizqwax1Dpj7l1nd4Yqf6X9mYuJddERpXt
         Vq3oL0Bh8ctz5GwJ9GCBuXUKXehM9ohL9dEAWHIWEbCU7kImpWS59yX59rEzHSIdKcHf
         HQD37UfsiQ5fLfxZG+6v8baK6BT5bgF2hRZg26JRs817fOA2H0z4ijr7ZSFlJCwYbESk
         VaUsCzWhAi1PufkNFFZfH6oINtdj084ibEGDJzSRfKViEN6Kn4NZpXWYV0bsyczDwX//
         aIWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300868; x=1764905668;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J4DnMyO3OHhgWw6wYmkkKUbtF2En7urplMxeFeDUhWc=;
        b=vkvh52VBB9199eB6QHaWUIb1f6aEakkKiiRK2EnskkGY3628eE1+ep4jHl7S/dvM3z
         Eq0kRACgUkMLsN8QQHcmG1igjDevx8iq6f1cQDBoCnNfjtZmfY6sU252kQn2ymrzA+ls
         EMng4F5gTdEuBt0neRhj64pvDmV+eHVag5D56T+PhHjiZbL9lyxTbTnWqTGJFaApUoBo
         YH3eb4FnBInO93DEial4m0846rnZlyfbiBqBymRHuObiry40y2y28oxCpnRvHpcEJGSZ
         q+ZshbzYk2ZgXL0gybPUjIq4k3nyru+UOtMiKi+k3slIHo+ySMZkiaNoseDDx/S44xML
         aICQ==
X-Forwarded-Encrypted: i=2; AJvYcCW8GqBl30flMzkIJHNj9eajEYzALjoz/MVN8DTbLdt7jWvSfDrc+67T3Nrdqn32DkGXk4i6gQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy0RHG41S9fiqk3eeQTJH35XdhfxKfXfdGeRIAcJTSzQH656mGo
	LTyBeHALqpI9MxBXC6Amvpy6UqJQtr6ZWyvaRBELMIqVlYGp+5Jhgb57
X-Google-Smtp-Source: AGHT+IFBeHj+W4bO/ZatrYofHi80lHbeg5eCsaDEnYbVTAXAfpv1NnfI8n+i+7+Z82x748hV9G1beA==
X-Received: by 2002:a17:902:ce89:b0:298:485d:556b with SMTP id d9443c01a7336-29b6be8c617mr293711975ad.5.1764300868608;
        Thu, 27 Nov 2025 19:34:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aSAbUz91TOH8AMQ5iZnZZNcpkb73cqE7qU7W1Ra5DDfQ=="
Received: by 2002:a17:902:cf03:b0:295:68e4:74d5 with SMTP id
 d9443c01a7336-29bc93ca9fels19746395ad.1.-pod-prod-01-us; Thu, 27 Nov 2025
 19:34:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV3VLK14gewFTE3UVv0Rqbt8xGUGbhbSftOGW+GllpEvFR+5AOrBXehNWtHFaZ5DnuG/XeAKXYSSMM=@googlegroups.com
X-Received: by 2002:a17:902:ccc9:b0:295:596f:84ef with SMTP id d9443c01a7336-29b6bf3b5dfmr329255695ad.31.1764300866998;
        Thu, 27 Nov 2025 19:34:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300866; cv=none;
        d=google.com; s=arc-20240605;
        b=fxY+ogEP6hG4ELxzFTh/ISWbNRt2ZRYV3sOJ3s5VzpBEo3jU7l13O+CjJDLg2Lr0x2
         ZjjevZqg9il1N1/1ukMLF1VQ51iLQp3Mkc2W2b9DzIZZ3qcFywGftDvQPfHKVpbPMsBB
         sOrm5wX/Vo9GHgDRVKp3yZiT7ZqRjp4lWBvQQkfO4E6AT6FE1qBiMz6la66K/2GC26++
         E+qzcYt3wpDzQkXWYaX5AY/FJmjuXT03ntr+9WUjhbhhKQDNRWcGujBzHbsNIzXTS8Y3
         KCJZxQEFIcLErwizZep1goicclCi7kPej/4jz7UeRNdWl0biSCUu8evxFOlR0sfxlseF
         Zv8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6bb3Fj+IEu5TgR6FamitgP4LC7HB+ODz43uA7YZcX7g=;
        fh=RdIeUGhv593+6LddHcScKkXcdLmFfNfDa+JBvBQDRdk=;
        b=YPr/NPz5S4KZy8LN3lqkKB3imfkfP30alOeuPeUa5l24pN4XFiNeFAjSdXPVytjsQv
         knVT0YZ2YRJIfNnBJr7SiHM0p7mINXhpggn9dspCtXS0rmqEhE1EdbRpjV17vB9jdfFr
         JENEgilmRBTzuqnc52432k1pglj2vZlsyDWPgFTfYR4CiEPktF/R+XLVq5q960kss95y
         rB+JtlH4S7jiUKJImA8LUQ/2jp5nFCfc/OxtfwT0AzBa8n0ABMrVvBF1Em2RRbeUFJ2D
         GLSOU4wvJmAYe4B7sHT3+IpSCC2Z6xwDvjL5sc4E92rBwlVzxYwxzEHsFBMLo8zgQpGZ
         FO0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KHDnTcCd;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29bce40b0absi1180155ad.2.2025.11.27.19.34.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-639-sr4zb15qN6-IOLblGY_jsQ-1; Thu,
 27 Nov 2025 22:34:20 -0500
X-MC-Unique: sr4zb15qN6-IOLblGY_jsQ-1
X-Mimecast-MFC-AGG-ID: sr4zb15qN6-IOLblGY_jsQ_1764300858
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E2EA5180057A;
	Fri, 28 Nov 2025 03:34:17 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8142319560B0;
	Fri, 28 Nov 2025 03:34:10 +0000 (UTC)
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
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v4 05/12] arch/arm64: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:13 +0800
Message-ID: <20251128033320.1349620-6-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KHDnTcCd;
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

And also need skip kasan_populate_early_vm_area_shadow() if kasan
is disabled.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm64/mm/kasan_init.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index abeb81bf6ebd..eb49fdad4ef1 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -384,6 +384,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
@@ -397,6 +400,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 
 void __init kasan_init(void)
 {
+	if (kasan_arg_disabled)
+		return;
+
 	kasan_init_shadow();
 	kasan_init_depth();
 	kasan_init_generic();
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-6-bhe%40redhat.com.
