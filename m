Return-Path: <kasan-dev+bncBCKPFB7SXUERBKW77LGAMGQESFPOLRI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KCNfBa2vnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBKW77LGAMGQESFPOLRI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:41 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A4719400E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:40 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-679dda090fbsf25392923eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007339; cv=pass;
        d=google.com; s=arc-20240605;
        b=UWII7GcB8q3FYH9w5AkzrLPbeIPsgnXsxj8iyhkgBv84lzFlkcY/7OqYqnK1uyi22J
         xP0PJenUsYBJ3A6CpfW6ZrYCRJ2wTAxSuR0qtz6e0/UCvMWBoTjf+Hvxw+UZkTq3gbLg
         Uz0qVfQAhsDvcTfH1b+I6JCzMSNel67Tcg4NMDHyAuhYf1Chay1lhf4lwsm/hEoEMPZF
         v6fi/GwLG2OGLf8nxUNKw7h8ZXDSCkm0UGdSI03VJ1VV9POBD0Dj+VGM/5WzFVE/ZdmY
         GnNN0KWC5sDmNIgCW8Af8icUPYVPkG9vrZzDKCiS4RQgULxd4N1MLNORd3Ml/kQZv9nI
         iyNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=RuK9HenpN5AtUF+ut86+aoaEomhV5MabNwxM1VN5RQs=;
        fh=Z7Ry8hrmM++LXUoDnGeCBNLyWgbtTiJ7YYLf/0a5wOs=;
        b=gF1wYV1GUF0XLfReMMh3s9mTF4PaDQ/equ+h+yVhzN38QVg4EGLg7rgf4MlzCVbAce
         kL8NZePnxC3pym2x5pcCP1Ht0gYrHgcq24tT/ZaJsiLNHok4tUmJ709Ss08K+IUZxC3a
         XL0SpGTnKRBNMM64MN6LdqXj9PjqV1Y09me9N0Bm5v0hzi+Ou63y65MYcaFcMy3ol5I2
         +rNLLJ8bw5XyT7juVqXj+aOvHsXuOAGsvsmujBBlci1lo3SAGTUHYzFEWK6l/IgjxGkm
         5GGMz2bGHQ1gxXHJ0WWqF2QZqDodwAGNVB2yQaxl/Tg2t3VR82qFq3kH/61Pui4sQQv/
         0ggg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=guRSlNdb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007339; x=1772612139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RuK9HenpN5AtUF+ut86+aoaEomhV5MabNwxM1VN5RQs=;
        b=E1exRDmulIpcR0ztH8Awl6BwKjW+ThS0NDMz7tV68JeBYgPqCSdYN8jAcF1lKrr8R3
         eHWwby3+OtJ9/Lm7p22V9LNiG5op4xdfRDzaUs+fa8L5Gzl6Jr2tKDHFG1h0maLDMlWU
         xL0U0WGjbk47uaaz5gv92JF6DYx3pz2ubQETxFdoEzv9xnXrt27MUPsD6wWnO5uyabBj
         Sqw4j9qNvPpEoAci93aqj6kBStpsqWflWGMu89qxBZ8A6om6mBFiPcDz2q0dZSqwX9sw
         5dGwXO2m2eHndUQv5u/63xg5xD9iJ9RsJlIvjv0XmheFJQIXxW0PSrm1SR9L+Dj4Ymqc
         zt+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007339; x=1772612139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RuK9HenpN5AtUF+ut86+aoaEomhV5MabNwxM1VN5RQs=;
        b=Xld0ZsFRVCgPsTpZBFj8NVrBrOrKEzKiNZuHbgy8RN3hNDGtuCut/+oLXP8taN6K0a
         2JBqg0HbJ/ELRWKxXtw9JNkryIhOULuATIwGC2hUvssh924mCdnk3OraCF4plX2q63ic
         qgX6mqyp49MlGdKC5SaY3Je2QBT16Wp4ONX5H3m2z5U9RuOIJauAJ9UMK7SOMrlUBYWt
         tXGJhk6CzcoGjXhNdkDVPEdfsUh1XhINH1Hku+kMP6PeuEJerdnNh/AsTy4wM+TiK+Wc
         9+R1mqCm07aejzZkA1romLll8vy9naOR12VseWGUD8pKobn1g8VWun7DWPCfHYc6ukI4
         XdKw==
X-Forwarded-Encrypted: i=2; AJvYcCU0zMHNZAVqsr062+6GeUczZFpoQ5H/sbPhlxV3Knu/yqSEaMO4qaSTV6i5ddCd0Hff1zKIJA==@lfdr.de
X-Gm-Message-State: AOJu0YyY/Bm6u7W7sUzUp1FgrfH2Yb0xGw23uU/M+QbKJNEOxnxb9TBX
	mxBmHChZxvMlIQx5R0ioELaqZXirTIQfLmLXgs6kWX/TBmBUaKAwK6Go
X-Received: by 2002:a05:6820:169f:b0:679:a560:cac7 with SMTP id 006d021491bc7-679e9b93621mr746043eaf.7.1772007338684;
        Wed, 25 Feb 2026 00:15:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fa72OyoeHUcATETbhzsNCdXb59P7DsssEXCaf+K9Kdww=="
Received: by 2002:a05:6870:1755:b0:40e:fc09:2e2e with SMTP id
 586e51a60fabf-415f0bb89fels185042fac.1.-pod-prod-05-us; Wed, 25 Feb 2026
 00:15:37 -0800 (PST)
X-Received: by 2002:a05:6808:13d2:b0:459:9961:5114 with SMTP id 5614622812f47-4649133aec9mr700559b6e.16.1772007337813;
        Wed, 25 Feb 2026 00:15:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007337; cv=none;
        d=google.com; s=arc-20240605;
        b=ZIEkQJDYQYQav/Egzzx+qhUNYVW89x2CozA3Ca7SB8h91fSgesth+gUUt26VKvWlS4
         bjpnPcat/uHG9HOqKWyhxAACRefuoFVCSRXntSih27+KN9bnonOjY7H38IyDeJxIOpZS
         5bZUZ1R/JjpSEw4M8zFYLL6j5EZ6yOM7QmZjbqfXUufkF/2K3RwiYM+Y+ZZRbs9TBDEO
         3bmg0YCIwDGv3AIZwleOwxFJLVD+KE6VDpl25U9zXjl5XggWROi/oj27KBvgoLN//dms
         F9lWgByNyb5r5yReYKtJ8LPs7o05l69fA9V/lJLL+GtVihaebB33Duz173wktIGGgJn7
         0MCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iXwY0Q2SJZmWL1WR2SYctHtbhbAGYnU1QS3gfwuZnJo=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=Zw6dmGIEHW88MsIH3tvi1P/8bFDwAEshyiS+CvIOoyWgneveZj0FucbRShuMA2BOD1
         TFQuEd6yhT2vg66+e3BzKok4m5lYpY7+3FuiwK/C9P4SHsA6iVkrNs7JiooGwWYdmx0X
         WWPYzSrKeRmMBjvWpFNdKMdvCWKZrF1+GGo4AE3f5+axTQdnggjDD14/xQXfXHfPrAzM
         /9Vfw5FZhhNUnoymtOwjksLip0JJ8+cIRMe4aqdhRGFrNBNn/tAsqxgKah5uS7eI5wPo
         8kcsYLHRd1c9F2RLAd4zsHmwDGIoL5yVAsEpXQLMgExCTk8P8ogdqIugv2MB4djDACy0
         XezQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=guRSlNdb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-464755f83e2si192960b6e.8.2026.02.25.00.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:37 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-338-W_q9ig0KNGOLXjAkoHCtsg-1; Wed,
 25 Feb 2026 03:15:31 -0500
X-MC-Unique: W_q9ig0KNGOLXjAkoHCtsg-1
X-Mimecast-MFC-AGG-ID: W_q9ig0KNGOLXjAkoHCtsg_1772007329
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 989F01956068;
	Wed, 25 Feb 2026 08:15:28 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 03B561800351;
	Wed, 25 Feb 2026 08:15:19 +0000 (UTC)
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
Subject: [PATCH v5 05/15] mm/kasan/sw_tags: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:02 +0800
Message-ID: <20260225081412.76502-6-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: 1YRjPbp7DR9vBBaaVdwaAXvx8hdYBV0KLe5Obs808bw_1772007329
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=guRSlNdb;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBKW77LGAMGQESFPOLRI];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.980];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-oo1-xc40.google.com:helo,mail-oo1-xc40.google.com:rdns]
X-Rspamd-Queue-Id: A7A4719400E
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/sw_tags.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 6c1caec4261a..7757b69b1c86 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -40,6 +40,10 @@ void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-6-bhe%40redhat.com.
