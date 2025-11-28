Return-Path: <kasan-dev+bncBCKPFB7SXUERBONQUTEQMGQEJPCCS6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id A5F01C90C30
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:19 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-34378c914b4sf2604821a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300858; cv=pass;
        d=google.com; s=arc-20240605;
        b=MiOX/cwkyAOmPNQBAhivYUrYj0rCxTz5x1Vrlj8Cu7m+8QRyOZyrgEDQqpBiI2gaLW
         i/ltRjkFGW3bBeXXD8mHezScP4RupNt4ZYxlo11WtUGzu2mirTRvpiBhAZ2mZFk8v2Ii
         A1SLniWZUniD69TvwpT7MHTxfvUQnWHQudAfsIRwsIUCXVxeedxg9aw41iXEkrDwz2ke
         T9vMFfnsOE51YZNxgrhPSSCmrczCvlUWTt+gH9iO4HJQYMX2y03Dsx9W2MmB8tNKMUVL
         f6kiiRzklqZw62JUvKdyhAe9LmW0BwU+YaSIQAz095lLpAJXzCZJNUdKtonqYYjputJU
         SVvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=aXboIIwyx1EfBkqFpbIcqGQQBFMYszDPcQyCm+2pMt4=;
        fh=5a4pIxOGQkq9E7szFW02f3U5j4iZWexMpjATNjIGwaI=;
        b=Nr5Z7jYIq7c/XvjRCZJ4WzsLQKdeBICv3744ZlWNjtk1f3tn2K4HCew9gxjjjedKOE
         nMFm6vtGpC+hH7P3kecK2u6SsNhzWVGGYcHdR6embdMQf3z2VSgr0g6EmyT2lMC1kXXk
         CR80Gw+gGgD7Xv5DflRScwzO1E1Hddun2NnPjPYFrl+T/PfeTs28e+YSHaL2Jv8v4zu8
         K3QZM4cQ/SWNR+TrvQdWj/5ghWfssSWsPNdQjzuV6KBm4yumT7PmM/GDntoFzKXOmTUx
         q0emvp4hwOew9tbsAcfA5do+C4oSyUIP37+oaspRqqd0fq9njut3F7i61rDJgAvmrOOa
         AiXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=T9XT1fjo;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300858; x=1764905658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aXboIIwyx1EfBkqFpbIcqGQQBFMYszDPcQyCm+2pMt4=;
        b=L7pwQNWHx0wGqS11aK8uPTNMl1wlVAVvOV5XHaZBNrpJj9h1sMGn67m1/HT3cpgqxh
         VrQ4yJBaLIEdtcLdh3KZqz8IKuo7OEqviuoKLTXYSV1as74d0Shk4uf8+1VfUpcVbSaf
         0L99gsN1ZQcgqZV5uXbyAWPUX5dUaorOdIVbvu+hRekhXI3tcF+FAnKaobNTj8W2K684
         37vjv7JVvrUc9AkZvfQHvw63z58CbTWwQmWDiziLVUxmUSIUQS/tW7i6qX4YDAsSBlcU
         Zdf4+D6Llh+GxMMeGW1RbJg30wJyYml5jcHrmGO5guWOJ6WyUwEw7VHJaom1aY+6798F
         iOQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300858; x=1764905658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aXboIIwyx1EfBkqFpbIcqGQQBFMYszDPcQyCm+2pMt4=;
        b=YJNMeJHdnY+8RQ5diGeZyiEa3SisjsU9taV+xvPp1/6EMzN9iuNHeh4D75aVbWd3Xr
         dONQXon5dD7gtQF2jHq666MbIeLNqJxrONVCOnB9zFcNyLFv1rYbiY43q9kHf/0hHc36
         btMPncvFDRvt2pqpJyO408baZH8BhmsaNU3SyPtVbA/nT+0mhLnuxIC3plIIB5kQZxDM
         yXYgHg6SwwFlhWPS6YI/izwDMX71wq9Hcru27ODWZbWqBxiG1KwuzYqO+cTjSMMj4OZh
         t+nwH0Ol8vZqP9GZi+Wk161/kcSbN1tQhBX6KHXZ5Mi+D8Pfz9ygkvXe/0tEKpl2DrXF
         wmWg==
X-Forwarded-Encrypted: i=2; AJvYcCUepU//KYaodihLJNlvnKiiZdOtqG5BychpIlnq6pYXf5MGwRmbMiOjp0qjUjopHYplHkGZDg==@lfdr.de
X-Gm-Message-State: AOJu0YxLALGN4bLkyTYbPKmJ7dadB9Q2P62b61yQY2JdduQaiHspd/+t
	7HNpKa9EZdBpvZgO40DJ0VuSKKp4fhwinfMFDUG01T+KXiv0O7eQo3Yh
X-Google-Smtp-Source: AGHT+IHGA2prr8dB4lh147KWTyZN8VbLIpuF5osKVlNTxNMtgdqWtVk0nSD+yOVMza7szDiNt6ouww==
X-Received: by 2002:a17:90a:d40d:b0:343:66e2:5fa8 with SMTP id 98e67ed59e1d1-34733ef6e2dmr26047911a91.21.1764300857971;
        Thu, 27 Nov 2025 19:34:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aN8q/Co1ppTSxa4NTQzLQciOEA8yMkn8mVoquHY2iZ8Q=="
Received: by 2002:a17:90b:e17:b0:33b:529a:13ed with SMTP id
 98e67ed59e1d1-34776fbedfdls1024392a91.0.-pod-prod-05-us; Thu, 27 Nov 2025
 19:34:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXcnD+X7oIISR1W9acOaqx3VeJSdvyq+oPiICOVoLyLkjD++NL7sECDgy1QPd4Sz0xKuULSWAKcXn0=@googlegroups.com
X-Received: by 2002:a17:90b:384f:b0:340:ac7c:6387 with SMTP id 98e67ed59e1d1-34733e2d4a5mr29068997a91.7.1764300856574;
        Thu, 27 Nov 2025 19:34:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300856; cv=none;
        d=google.com; s=arc-20240605;
        b=iCW2XA7aDobw5g5r3/twmM46/BS282Q+Zsqon8ZAmK8r559/XyM8LxO8wnUIanpO+B
         Z4gIF19rzy6TILCIXBbzr/omWGCBx6b5mzBCTqlr7qH1Q5FJ8O6OrUlF8ENIlnhnerbZ
         R8jrO+pEfSMshRCthcAAE9YzR+Y4m86X+iFWZ+ENg4pjN//dnYoOC0QX1Oer8Nuq7R6F
         pZD1UR+1ETWzGwyZC2yDyCH9SCDRc+owoxpCAuawbMtNg6tFnn2Sf/iguZ/X+2VVvtUK
         dA8z1amCBQ+RgDtrkxu7rG/Cl9SrT3zeBNBMsB48iNpDt5r6Huqi9PgxvVOQqSQD0UGo
         cfhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=z6ce0A26qYWTGzgTeV3YqEFLmRYbdSXU7xKZaZXOpMI=;
        fh=RdIeUGhv593+6LddHcScKkXcdLmFfNfDa+JBvBQDRdk=;
        b=NRqqzjsk/Z0eEj9iawWMFhb4W/cq7msqy7ugWApJ/gXxc+2IGsCmG1YOcvRb+i3tLM
         mEardZvpNxBc2jLyPdN8rray2OdKPh4THiYFCQP+nO88GijLi9jlvDOORl+XNXomdBPM
         eVToBffdD5IE3ZvreEd7Az2ql0rITkfWFpCKf/AH/4dXhlOQjfYStkuzH39ztkHszLkz
         sK6+R/6H39tzXxjySXpmBVT6wgJjL5lZildUhiaughFEKmJUWRsRLK1gmyrcRCo5VESx
         O2MJVJwgHuqDACsW7KTFU0TLEpwPciv9vXf+eAV1rqluBL/p6Gc5BFYAdvLm1S9yy2zj
         CatQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=T9XT1fjo;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3475e8797aasi61867a91.0.2025.11.27.19.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-607-hxO-P8tUMzmgqFinLUZQLA-1; Thu,
 27 Nov 2025 22:34:11 -0500
X-MC-Unique: hxO-P8tUMzmgqFinLUZQLA-1
X-Mimecast-MFC-AGG-ID: hxO-P8tUMzmgqFinLUZQLA_1764300849
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A4303180045C;
	Fri, 28 Nov 2025 03:34:09 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A7CDD19560B0;
	Fri, 28 Nov 2025 03:34:01 +0000 (UTC)
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
Subject: [PATCH v4 04/12] arch/arm: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:12 +0800
Message-ID: <20251128033320.1349620-5-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=T9XT1fjo;
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

Here call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm/kernel/setup.c  | 6 ++++++
 arch/arm/mm/kasan_init.c | 2 ++
 2 files changed, 8 insertions(+)

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
index c6625e808bf8..488916c7d29e 100644
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
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-5-bhe%40redhat.com.
