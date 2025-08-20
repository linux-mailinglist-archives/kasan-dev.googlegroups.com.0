Return-Path: <kasan-dev+bncBCKPFB7SXUERBM55SXCQMGQEKWEWVDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4A1AB2D389
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:35:49 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-88432d877bfsf1515542239f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668148; cv=pass;
        d=google.com; s=arc-20240605;
        b=PmwFjwkpEX0HYik+deoAcVYPl4kT9QVtPDwNyl8GdahhHZ7iapXQYVn2Ph97rocuVe
         5UwOe+YLHzUqNWOA/S5IeXmmssrgn6HYx1+0K2KbCysex0OntYTwPfofWyyzcWh8JnXK
         CksKv1wBc7qBnpTmx9QttvvD4QEw/4GErt7NR4gpVwu5hEZM4IZdH2oYLPwdVz51f0lK
         FPSvBvlE8Mhfww5MTdvHcwODf5ZQ56H9/m1fSv6VGSg1IDQAVNtMxh2ftYGP6dfm7c6v
         psCvNKrQYyKZeHeAkOiSCdJM8R6BJQpFxgYbcQJyr8YvcjVCZ5ZZwPqDfXsSH6eb1L1l
         pX6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qFOMZuH+erSvJk36e0uKjqizazCcVrtO6bkB3uFGW+A=;
        fh=zq7igUYdn4NZNB9YpmopW4OUNkCPAiFuZ5DSvFSERUw=;
        b=RRj4p7AaPAszsa6q2f4BHAmlaya+1en8190U7RabmUn8s7OiXpQSOhhtdfYyMWwczy
         pPd7Q9ywvHtvD15B3IeNiGeZxbqhV4l5sStQOD77Kb1meC6aYYdX9mL37p2yr6HYXQ6N
         M1SWU0SN8U+UAK8h04M80NPacan4fKxVFnloT13CYCRiHpwxbtVLrcpxn3JASGgZnG/7
         ipIj7qk0vrXX+bCasjADL2RNc3xt9OpT/PlK2ZcLahtHKGsmxDHLlzpHpTePQSdnqYYk
         04fb15wsqbZu8fTCxC+8ShKU7i0CUtmS+C4I4Bi8+l3ft0AjVL+7e5yuvTXvpYhIeyD4
         8hvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="MzDPNw4/";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668148; x=1756272948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qFOMZuH+erSvJk36e0uKjqizazCcVrtO6bkB3uFGW+A=;
        b=s6/hhun6wWj/pBvzkfL/4KmBR2keozVYvVqwCsp/hVY8hoIAxZT+VskMG+UIDDDc7v
         WyNSnGtloNajMs8VIVa3hrwXnHqzfm8/8oeHk/kj9O7n+B9mzg9Ok4m8jA0E9sGTkINB
         THHlnG/yeMqlUVXwC9o/qZKogQAtdn+z5eoinzl/EWSy4UNMHn0ElK9JNwEFYon555ir
         lVcscb7PMJaLVxWVsdvRzUHAfuVSeX19OyskPNHyR47Ej3LkPdvnpJBRZCvCjiLQo8xM
         U0g+Y9avAK/Cjy293Q4+uwCYaxYa6NE5/vJmY9lU0+Cj5fYqSPQAG0x5lGR6pPyj56Jb
         MJpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668148; x=1756272948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qFOMZuH+erSvJk36e0uKjqizazCcVrtO6bkB3uFGW+A=;
        b=CdnubgYSP3rJ+NakP1Q8jpfUxPIYMm7aKNrLOQ4QbiaAD8NJ2+8EfsbFwYRepUzUaF
         3QRz/037n6AtH3kG11JwgTMntoI4sM5gXtiHE7dz3IY9QC9f/wohMoGphHbxtsF5hlUi
         tUBqhpVfXhQKyHKZrBWnWjeVO5JLABzj1BU37JKbn+vZliVIfyO4k/W0xhKImmoJnEm2
         JHUbUGYnl3Sg4rQy5ARt0NH/DP45ZF0HU/qfVn5TDhoZlEpfYYt8LQfdg+BYCasJ0u+W
         9jaE98SpIJuW1wR3qQgm8axcjpxI/ef8NVAChMu46R8lTYsihR9P2lJHXMinX6o6pWv2
         VDTg==
X-Forwarded-Encrypted: i=2; AJvYcCXIg+TKDv1N2QJMQwkcHUMNcxol/uG2ojDs/Ez9+I9NoBhLYmkM5eFOzjeocfkCIwYd7+WGIA==@lfdr.de
X-Gm-Message-State: AOJu0Yzc7QfFhZ2zsQcxwXzYETOIqwCl8B6C5Uf44ZWnqmTZuuSKFv+c
	hHH+O4yiDcxg2T9taU0OmrbhqioSZs+nBePsiUEIRqflgMJ0YWmFvUvN
X-Google-Smtp-Source: AGHT+IHxuIYeS5jWWI/Fuv+VfUyMY7aknDWVFh+gppx9MUd7rLtQGJ75Fl8/SewdMltPv9i+E8oQzQ==
X-Received: by 2002:a05:6e02:170b:b0:3e5:6999:3278 with SMTP id e9e14a558f8ab-3e67ca5ec59mr23533695ab.22.1755668148056;
        Tue, 19 Aug 2025 22:35:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFIfrvrU1EwC2sGuGxivlvir8ZA91cnncrzVABaxiseQ==
Received: by 2002:a05:6e02:4914:b0:3e5:1b1e:ec7c with SMTP id
 e9e14a558f8ab-3e56f8d9328ls62318335ab.1.-pod-prod-01-us; Tue, 19 Aug 2025
 22:35:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXB4h5FYTGmb8Osh8+xD+XwOViVGSK3qrO096iNEI8OGjD0VcxILOHb4lLll7EF3KPwfGLqh+sVrh4=@googlegroups.com
X-Received: by 2002:a05:6602:487:b0:881:9412:c917 with SMTP id ca18e2360f4ac-8847163ae3bmr352436839f.0.1755668147208;
        Tue, 19 Aug 2025 22:35:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668147; cv=none;
        d=google.com; s=arc-20240605;
        b=fYOnZqFVQuseswnsSdPigU8Tg7hnnM+SrSY0Oq+MEB6t3jUfpwwnfQhjHgr4ihNESh
         v8OvK2qp/vezmTQMJpUmlYeB5XbsXorqTxoQSOV+YuRtUSFzWpELCQH60AHDqZARvvqa
         BIhvmMmpMCsNuCsBlBaOrscR/Zzg1cg2DDFVaDe4KxQD8Me4F83hDo+B6GfPfXQ1nP+5
         bACgrY0bU0ha6ZUPIy5o5Zbc6WeULrM/zNJiz84XHlWU8/v/x54BvzuujfA54GS4UprK
         xBwA6vuuuUryhvCwhq/X/dRtZWOGtZHhKaqexhbL0mkUxbwVCyhYspqpEPzaPDv4eBoI
         YobA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lC7gxKLfCffY1/zE+RJo3yBumyZwu5V9Ft7avRiVVTY=;
        fh=yx2TOEA8OAv6JgprDRqBo1i40dkdP17DWUnpFH3PSuc=;
        b=AsBXQVE7eL6ak3WuxPo5x4mQ1CU6dH9FbSNIdKpRRGQgjOC2m4+jG16nzYAflCs/gW
         qdAUV7opI1vx5V3VGg1Y8V2KxqvSuXtSiMWFIJhmiTDPvg9WhuLRd2ZtzXgpV6ojCtPu
         PuCIzFG1UQBbQf9avjOdmMiOG+kE7GRnkaOUWmVbjrXI5AlhPKMc/JiOYy0geWyuoItK
         M49IEAP/QMbX9IHcILqmkq7GuZDyVZ6UhLVG27sh5nDYjh3unN8VjqzCCZii6ujWIQk3
         xBC9BfzPPXHt+s1O09ko6JqlwMPJ/dhMfDWDyDD6nIRUSQsOEXUtjDeIDay8EpLiXgsL
         U89Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="MzDPNw4/";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c948f5320si575945173.1.2025.08.19.22.35.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:35:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-265-6LzTzuBZPxSmLJLuVYPWIw-1; Wed,
 20 Aug 2025 01:35:41 -0400
X-MC-Unique: 6LzTzuBZPxSmLJLuVYPWIw-1
X-Mimecast-MFC-AGG-ID: 6LzTzuBZPxSmLJLuVYPWIw_1755668139
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4AE39195422A;
	Wed, 20 Aug 2025 05:35:39 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9FD9E19560B0;
	Wed, 20 Aug 2025 05:35:29 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v3 03/12] mm/kasan/sw_tags: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:50 +0800
Message-ID: <20250820053459.164825-4-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="MzDPNw4/";
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
---
 mm/kasan/sw_tags.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 01f19bc4a326..dd963ba4d143 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -40,11 +40,17 @@ void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
 	kasan_init_tags();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
 		str_on_off(kasan_stack_collection_enabled()));
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-4-bhe%40redhat.com.
