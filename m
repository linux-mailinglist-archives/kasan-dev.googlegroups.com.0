Return-Path: <kasan-dev+bncBCKPFB7SXUERBZW77LGAMGQE7OVSQ2A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wOdSLeivnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBZW77LGAMGQE7OVSQ2A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55D891940A1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:40 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3870bfaee4dsf33336441fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007399; cv=pass;
        d=google.com; s=arc-20240605;
        b=J/gYBYab2vwsrP5Diqp3yduOn/kCMeLBoXYRna22sHtEYy1m+J1ErwbvPldbB9bwvy
         npeJHsyefFBeyvzlOtcHg1bQPJsAYA/q02lTUctEjZoKrL11k5TghnwNUl5XNu/QFbnI
         Z6Xu4WDUldP03gazIAFcjor0aOVMjuWxGCiQqsmnVSaPfoaJxhShlmZIOtBVBR3hBCsc
         rq8hCEvEFg4xYZ3QKW6a0l4v23vU3PB3pmlpRM/FHuaQHZgOzG0NLi52N3Nt+vIzi4Eo
         EWI73j1KYpg86XYABGHIcfJUBqPjZDHdziQ7I4YYnW9KvJ285BPwr/GJ5S9TvpCYjFMU
         bU7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Xj/fh8ZONI3L1Nn/zGD+1sgUm9FKWj3s2T0xois5ViA=;
        fh=svZfExK+f+QKU9cJDtE9uLz8lSnjOWG/+4QF7gsTIVc=;
        b=joA0P5hthdzftoWquox63cxxAUqjg7O8GeW7pzbA4bMmgbtJ9EvtplzZ/lI2ZJASIG
         1Sy6dWSmy49wNS0B60FHigQ8kL/NeN5caKe6Cyty/I2BUYRgusXTp8rPBhn5mf5gu169
         nAKyOjesRFyDfTA+Wngr1AdWo8gP6B118Olj4aqfYcavRa19hpNY6dGIR0dXBBxo/NyY
         cQODDvSws31lsLgkchRFXuHqJeEs/KfebIpe0VVCwAbhdWMuYlbOS4/0ocNFTusXVA3J
         JcFGYN0Qj4dGViIGIF3F9wSIxAUF4cRrOB/WAAEXQi4rfcfEHNN4gzWIDhiu7DRGUkmV
         oCdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DzcSWzsl;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007399; x=1772612199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Xj/fh8ZONI3L1Nn/zGD+1sgUm9FKWj3s2T0xois5ViA=;
        b=r+a4p0zrPefCsFplI9i4SsUquspzEG4xopaBLwwP902Cf+tZ8OGhxqDUo4lBudZC+W
         LEBxZtLCbo0LkVbtWVFXkaFfzYXQpUYjKXjJ/PQVaEM8SIhfiaMntL4usKUQ1nnT9j8b
         W72qhx6oSURr3/eeEbi6hqDC1id9tfNuK7hAX/tVBpBKKd6VzEa5JJWpDJ7iYRkuwVom
         hCJ1CRxxUbLXtc++3SDJaIbBbcOzRAxl0flRsnZdLROCWRKJHMjVp9rCd3S4+IOR1fk9
         +laIn7qeH8uDlsRQG2wLorZP2k+9Ag9YLQYapwjat6lGFZWuvPJYHYLYgj9cpmVymMh5
         VKrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007399; x=1772612199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xj/fh8ZONI3L1Nn/zGD+1sgUm9FKWj3s2T0xois5ViA=;
        b=b8lQoZ1dkcQJ8T4wZFrjzaRQVxCxMHCjEEDL8Cm/lHjhqSVQTUVBn8/tN6CWTnUDHs
         2F4Yjpxi77ojG3LgGaaO5qV9znEhUHAbmw7QYZ+AxFxeqySqQgqvgARb7SI5wQjlbuN0
         xHkogchxXVE7nAVVwUluoE07NDkGGn6bp+YGrzX8/M9la9BQrpTe3yBQzLYsershFU2d
         4eTOae/GGo8ObywaI/5ihVpMhORhV3/ICyiIYkFWvtiv9PzFbvo9lOrb4rBeY/C/LTEB
         SngCIibUQ7AOfEsNhyo5uim3N/1x3ZsoLylI+txkXp2nJtiMIwsMf2ZZqjvIsm/Hscq7
         dbaw==
X-Forwarded-Encrypted: i=2; AJvYcCUuJHc0rfxtKdHueNJe/IGdjlWtq0C7af2HWtY6P8OStFXtLtdwfCSUKNnff1yFUrmo9lBPVw==@lfdr.de
X-Gm-Message-State: AOJu0YyM1jmtvdcEi9a5MEtQk8s44km0qE6D69BtPAQP5/dYSWRBktPm
	v38/2B4JfxYzKDoD0Q3wwh1ImZFLBLIBAFGLWacrXcRGXpbxHdhqWLsb
X-Received: by 2002:a05:651c:4189:b0:385:f235:51bd with SMTP id 38308e7fff4ca-389a5d49090mr38300111fa.14.1772007399194;
        Wed, 25 Feb 2026 00:16:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EMFckrYAVkVeOW1LW5ugp+FhT2TcvjqQOX5Squl2OW5A=="
Received: by 2002:a2e:95d6:0:b0:385:b70b:dae7 with SMTP id 38308e7fff4ca-389e3a1594cls393541fa.1.-pod-prod-08-eu;
 Wed, 25 Feb 2026 00:16:36 -0800 (PST)
X-Received: by 2002:a05:651c:54c:b0:37a:2dca:cfaf with SMTP id 38308e7fff4ca-389a5de778emr42857921fa.20.1772007396592;
        Wed, 25 Feb 2026 00:16:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007396; cv=none;
        d=google.com; s=arc-20240605;
        b=N842b9ztUnK2KFe7aKuUJyy3Bw5zin/XxFVGIR+w4MYv2DRoGa2X839KE7LFFeFe06
         CYJ/hdtK/PK+L/G0BRkMxh9ZZum8szwqTpUmz0DkK2XI6qljeLbn0CHtqhQ5t4Tc5CFS
         jn4wxYsuLPAXTKwS0DbuWYq4gXhBOJS1GvrIGsWCe+CtrRJj15xE+FQjfwK4VhPTIUYl
         dEn6jYiRBqtrcDOJIdHPGw58EyAKqR4ToTY53Pv2CahJbSfyCUyBayjOv8hcUfGriWJo
         41BhFCrxQEMLzeZcdOyKpkdIvKpv0MHQjzLPQACq7MPar6WKEU+eNUhDjCFI2qLQnxzc
         KIcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ufH5nmkXpWJzJI9ksuEPClUSVztzr8yoo3w4HNv6hNs=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=ktqOSXrx58gaj8xBQ8/zPHh02jz0AfbYfZUcoyS5UtYLrP+keC02bwfVcWHhwQlNRK
         1mXwp25gzIA23GhIo6LNXwV7QIprLPHdZOUxNSXmiHPxpgZZoFkJMaT0w/raXqPVjiqR
         1cQq/OmPSLXZ8yFo6ocReSNudMgZJoaDJEMmZH/XsVtz5xw0QBZXxtxQ/tTB9dY7zKFj
         Gbv29vhVjuoM0O8ijJHoAZKBcX3TDaOT0YOX8VHsPrgEBlNkGeIxw7cuMYOvGwifgXlH
         umg4BDxldevgc644t0RdmVMwQMvYs3iQynYeUpDx3iu6RnIj43Sdft4jxbPcWR++eSe0
         VPkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DzcSWzsl;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-389a79cc37fsi2657641fa.6.2026.02.25.00.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:16:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-648-Jj4asdUeMuyAfccAe_OsEQ-1; Wed,
 25 Feb 2026 03:16:33 -0500
X-MC-Unique: Jj4asdUeMuyAfccAe_OsEQ-1
X-Mimecast-MFC-AGG-ID: Jj4asdUeMuyAfccAe_OsEQ_1772007391
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B293618005BC;
	Wed, 25 Feb 2026 08:16:31 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 5C45A1800465;
	Wed, 25 Feb 2026 08:16:20 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 11/15] arch/x86: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:08 +0800
Message-ID: <20260225081412.76502-12-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: fE_2ZDDCNg8eg2l1413Jei9J6RWvRD9qgAD0lAirWWs_1772007391
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DzcSWzsl;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBZW77LGAMGQE7OVSQ2A];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.981];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 55D891940A1
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: x86@kernel.org
---
 arch/x86/mm/kasan_init_64.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 998b6010d6d3..5ebf2850c77d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -343,6 +343,10 @@ void __init kasan_init(void)
 	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-12-bhe%40redhat.com.
