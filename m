Return-Path: <kasan-dev+bncBCKPFB7SXUERBR5QUTEQMGQEUJFP2RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id D4FC0C90C3C
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:32 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-7865de53d43sf16502697b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300871; cv=pass;
        d=google.com; s=arc-20240605;
        b=lRt46JpYZJNmRvTkom6/F9eMtpZfGWWsDVETvTsf6rtsi3JIqQGLGFlxBxdzj6XYBe
         21huwMKFqwD0EOHi6ml8xKdX+MACk04/aYNhOFjOeLNQwnauSQhz56YOxLy3RBTij3xD
         lIVAoyOyyVWyykDhyNC/AwaidEP0vc89Dq9hpNcT/HjVdo7is8JaW/wFij0jYAX3wV5F
         pY6Vt7SbHKCFLJYMLhTfbcwZBKtY1I8gBT79aqle+LccAAL1ek6cq54T1Zd2hikh267q
         bgJGWSOmPWq/6Myf1SyAWVgTHmitE7FOC6WSG7kprVOFdVYkT9iRWRKcf2jPtHU8u+vS
         cWEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4h3gnbeKGhbwgzHvI1RwgxDUa9n5TYn6RgnCLBrZ6RE=;
        fh=pdVaUTe50Mq/CVfU6E/7JmKNa5EIwEhHD4SrIbnQ03Q=;
        b=QZe4O87JvIGRtbNIvsKoH2cXmd6OYqRzGQH0itTA5LvxQyhAFktC9LpEDzCl1HYmG+
         aPVouygRrK0ige8tfyXHBvsZh+75s984FQ7AytGT3BzSqtj5cV98C+UH//yDIl6CBEgc
         D5z6XQ2yqhINJjPX76rX5hDpIY9ARDAEsAWDnXokzFaoudLrNn1VlyFhIIhc06MEAdh2
         U1x2mpLqtiCte8IwT3vtDeafkuLKAMXJppjjtYRSPkXajIgCqSdd+XtZgW7c08TLOdIW
         Ug5SJulbbORVVwQFEaS1RqkRJTZwxJ7P49zu/rqWaV4eAKipwmLMzTS+DyE7HQDIC5L+
         JHZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=i5dD5mEs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300871; x=1764905671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4h3gnbeKGhbwgzHvI1RwgxDUa9n5TYn6RgnCLBrZ6RE=;
        b=Vm1iDaMcU4ybO4+M57Pwb+xZ9y1JhWnDKZ48b3aD/L2Frkey4vxEtI3QmNZM4kazIL
         oarRoSnZlWVpqtIBk3weE0PrnKLbVYssivVwKxyTDCmJ9sk0J13616ch3Ww+2Nq5a5JY
         gKzanNwmZWEQVE4ENb4mxR5T+L4330ZxncYkjJ5RSqmkmJRzJBz72DzWBUguVAhLQ8x9
         D+TznK0Ex15CCVkD15Eo1Op49TtZxicCuZddWRw/pwGST/oU/EIlGB1bHEB2ZVvSqbyF
         1EiGHnZRkkA2nKSRgF2CVRhyAyE/T9C23n3vHiVRDdsW1bu6ycs7FO0p8vjzuC6POtVK
         iC6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300871; x=1764905671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4h3gnbeKGhbwgzHvI1RwgxDUa9n5TYn6RgnCLBrZ6RE=;
        b=wsoKF1PXkukREZ8wvOCI6tiUG4flZCvnbb0sB4+WCWV0N0hEzwD28PhXT8Pz6B5abq
         aalyUeByNz+oGXRhWo1nuUzMAjcEO71QlzS5b7ureGCG+4Sbdg8McslEkVxmT3tioHXk
         xyldQcLHWj5BbH9JVYI+OZEStVwxg9hSZRZynD7tQZiCZwhhZcUf+P2BZPa4TxoBRhn0
         KvxCZKwswKsWspe6gCM931zc34rP+rhinPLqFHHZjoXMjUgX9ZNEHmuapUJJwLdRKfxq
         gvxEgW+VkiDJnQOt4WrhKZuvqkZhdzOZciDlxvqAgiHXg/M+vVCbxrFIzlPCIFIHPn6i
         wvLQ==
X-Forwarded-Encrypted: i=2; AJvYcCXBqocDHr72Ekrc5bhC+PlZMQN6eYY/AFy72l9RB267Fy2veezpz+iUVJIqwkqPNLdXiaivsw==@lfdr.de
X-Gm-Message-State: AOJu0YyHci+qhm0zdsaCos4CMPJi6+Fo49AcWC5oeUquXNqBv5K4j1bn
	2dNS6Kf0qycaC8fkDGtnfxXfU4v+XrybdwERzSGnBdaWph4P2Lpp0++V
X-Google-Smtp-Source: AGHT+IF7M1UmPq85l8lxBBBcywh3gazUryTT10uK3P5GadWdnBDTFQGYZ5mHdUY4PRYmtfcW93LFQQ==
X-Received: by 2002:a05:690c:9c0c:b0:787:c998:c7a2 with SMTP id 00721157ae682-78ab6dbceb3mr214881087b3.15.1764300871366;
        Thu, 27 Nov 2025 19:34:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZgmMrsCZdFjbKPt7cYKI+//ZMPOYihggh9dCxkTZq7fQ=="
Received: by 2002:a05:690e:2009:b0:63d:e4d:ce01 with SMTP id
 956f58d0204a3-64339352107ls1102106d50.0.-pod-prod-08-us; Thu, 27 Nov 2025
 19:34:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWRI+7eh2rHvxjAwQUQmqkY2Edv6bNCyQNZKg86k2Hkvv4r+o971iKMZ4rI0dGeUP3EpPFfAecc84=@googlegroups.com
X-Received: by 2002:a05:690c:f94:b0:788:161c:7117 with SMTP id 00721157ae682-78ab6d6d138mr204469157b3.8.1764300870293;
        Thu, 27 Nov 2025 19:34:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300870; cv=none;
        d=google.com; s=arc-20240605;
        b=loNsYyp8ygCFRs3C73oB1FYCtifXFgO+Pvm/pUCJToi9ABBeITEfvgSznGTPpGQo8s
         AcEizV/O3CyoNY1WlKfG0IF7KDqaqW0uuzPsECIUr1LzKMYOd0m5XaGDqjzJz4NpwTQO
         dgEnT/U6v+6kgH4StXjyGotZ/cBFEuxpf9mxbC+pnCB/lo3cymqhjshan2ibFczLcNXG
         1QtfIo5+2aS7n+/TD+4It0PBKbZ1AMVlspkPAOSleSU2sMIlFCMgCFlYxHk3aFqAjyt7
         LcswLIjfw5Vg0ABHcEQuy4VLd2SUrmB+TPo7Z8rXRLlClK7y4rB2VssCT/d5KDz8ZJ4D
         dblQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lfKMAPgOw/dmuGwbVXfO4D5MkyZDnIUQ+/VwPEWi/wc=;
        fh=ASlSMvNKbHPU8f8mAvYRAeOstukoU9hyhvJlrOBTKHk=;
        b=WR105j5Jy/nnfTNSbggZuILHX0J8a7cuVXhKlUy4iPspQcvrZpjzNfBpltgJX4zfVT
         zPkpQ2xEEyEVozCTh1HnWDrR3fAKT6uXTNFURg4dcFES+3mS9VfM5ium0B3ve3msLoJO
         xxrlqXS+THBij1ZDQYHpBCHHMUA6KbzHaAWi0IP+FqW3FvjkBABAsqcoiRMqbOHj21qH
         dbnFF1875IlDu6Eh0swf4ma3xmAQ5zntIG8ZNcTHNpHZ0loQPjh1Y6BCmG+uea2UVvEr
         fH8wK2beTmafVrGFKsCHwVPHXlr2/Hzn2tC9k3qj79qt4lkbV/D06aYruG5nE3s/t4Sn
         u8CA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=i5dD5mEs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6433bf6457csi102776d50.0.2025.11.27.19.34.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-115-zjYbfpDXMs6rEpZfQ8z1Kw-1; Thu,
 27 Nov 2025 22:34:28 -0500
X-MC-Unique: zjYbfpDXMs6rEpZfQ8z1Kw-1
X-Mimecast-MFC-AGG-ID: zjYbfpDXMs6rEpZfQ8z1Kw_1764300866
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 256E11800473;
	Fri, 28 Nov 2025 03:34:26 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A827D19560B0;
	Fri, 28 Nov 2025 03:34:18 +0000 (UTC)
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
	loongarch@lists.linux.dev
Subject: [PATCH v4 06/12] arch/loongarch: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:14 +0800
Message-ID: <20251128033320.1349620-7-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=i5dD5mEs;
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
Cc: loongarch@lists.linux.dev
---
 arch/loongarch/mm/kasan_init.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index 170da98ad4f5..61bce6a4b4bb 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -265,6 +265,8 @@ void __init kasan_init(void)
 	u64 i;
 	phys_addr_t pa_start, pa_end;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * If PGDIR_SIZE is too large for cpu_vabits, KASAN_SHADOW_END will
 	 * overflow UINTPTR_MAX and then looks like a user space address.
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-7-bhe%40redhat.com.
