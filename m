Return-Path: <kasan-dev+bncBCKPFB7SXUERBRW77LGAMGQEMWYKTKA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YHfgC8ivnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBRW77LGAMGQEMWYKTKA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7E7194042
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:07 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-679e82ff925sf827462eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:16:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007366; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qq32ZzWepXEY3whuXF8JaytAwSwgnkkLm84vibnEeYDN9VvVez7Oi/TBtRFa2m92Nb
         P8NYJo1EcViE7aEGw/LO/JuNwxMas9Wjw/EVnbu3Cu4cYnx6VDiUw46cBHtyJmQ4iXOX
         IuMF5YlhJG7gwxVPRnpseeTph9uHkp7J0wnP7T158AT8rTNp+s1s1WkmBHSOgzVf7Dhe
         yRKV7Bm1zagfpzq03tufkW6mMsT0EQBMiiE9TgFr12S8jc7YENH+ynPmBcU0//jvPKVq
         TqZBAGKgy95XFTmQVvD2G7V0RMmfFrdYtHXpaMtmYGrOB+K3+hV0+d2ICGvhbd+9oit0
         YI5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1BOn0nmZaC0Fc8iW1bqPLnugqaf5UtbRNJQhN2YgkC8=;
        fh=BG8sY4f7ti7HuZNCRT5pCJGkGao5PBIeYnLeohKPX1Q=;
        b=QyNFASyTMLWq7vWTtoirRJ0fJO9M5KMeBjyd3uxNfQEG7vrYqtJsp37sOD/CgYB1GJ
         xap56TyebFTduIoPkJ/wykbS9XpFw7HdDuri+dO7oRAyUnR/sxwsusnO+OhTSMKb630G
         LAUvd50g2V2ENvJfATit6mRTy21lvWeA8NzhUQSldMq+wGo1hzmpVKJIMhvXJ9uNmGvr
         ZTNFRMR9xB8RkBuZd9H35OPsVPMiMQV//PH1yCNwjMCils8TiLMSgq5/dBt8t+xYoG2T
         o/AK+8JthjaOtn0jtal/CbwHw9aBmLfs7ud1yhEMlktzECcg0WsssYdxoViMHqPeU+Qa
         W1Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FGqHqNhv;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007366; x=1772612166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1BOn0nmZaC0Fc8iW1bqPLnugqaf5UtbRNJQhN2YgkC8=;
        b=brA96g7zuEhGN+DQFi6MQzPAJjT6uB1eWvO3Pcg1cXdTESeHBJwRy/Izi7cwKIlD01
         4+0A30RdfVn3MP6GfeBYKFgzLkVQr0FYrcEaHbaBVPiyUodcH/JqGpwC0O5tPJ7wRG5E
         lTgmlJi7ZG54kog5Jng+X5zsSZchEDW+0/R8PkCWx69f5Bm9INJjrmHYKVxXIbmIYVyW
         CQNL9BQ6bRv2nQa9cVJOU4qi6u0hLMWSPrWNlpF8AAw9ifSd2dWIa+darnetQ75r9rs2
         Q6HeLCBawZfM4fYtH1wR3QzpCmAEiLX7zr6gCZXj+ghK7k+lTNsBVxtOIMAy0qULw0IL
         gYRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007366; x=1772612166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1BOn0nmZaC0Fc8iW1bqPLnugqaf5UtbRNJQhN2YgkC8=;
        b=p2Sc89htU+WuaI/gu09q3bbvIv6To49ZoT+G0zL+KOyWJHHTwjNYmmdfpBpRsotuR2
         soHRUa+dOaZnYba5egkk9H76GCLBHbNSyT4wMZIcUBlahxrN9Saw0gzY3tHMlk/Y3Zl1
         LVjn37yQPnZeZESa0Ow9g05smVwe0TA6pyouIIs+y7R+zlCTCy+FLfOZ/bh8eSuYPlP5
         UNiIA0FAyYxTAdMjrHvYGU+LYa9sjORTqN8U0t4OIAnYzAGdED7QhGDHpgHNYb3Dvnwx
         VJpHxlpJjIuX8/7YntQN6cvNBeNSe+48bQyTwPG+Nf45nXd/4DxKDkYv7hWWkySx2Xgp
         TCsA==
X-Forwarded-Encrypted: i=2; AJvYcCW9CntLVJleR1yPNIIcvYcMnx8lItcOSQqntDm9c+Rq//DH26RRInJQGzDgbHMR2xhlyIfw1g==@lfdr.de
X-Gm-Message-State: AOJu0YzTjyshE/mcNiGYSkp69ZTuP0kwqfHdD1nFVgHjUTZXRjKDhhpf
	XcL7Us0eGBIcpcW+3dIyhwEG2JpE8SeXiFUTh3KYo2yAhewvQc43FFkj
X-Received: by 2002:a05:6870:4784:b0:358:ecec:9b with SMTP id 586e51a60fabf-4157ac11c88mr7444988fac.1.1772007366296;
        Wed, 25 Feb 2026 00:16:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FMlGVxsLguDf8cJPRFbFA/PM6BwGdFAedF1AHTOcrtkw=="
Received: by 2002:a05:6870:818c:b0:3ff:9e43:57c5 with SMTP id
 586e51a60fabf-415ee294c32ls231514fac.1.-pod-prod-01-us; Wed, 25 Feb 2026
 00:16:05 -0800 (PST)
X-Received: by 2002:a05:6870:238a:b0:409:732e:4f9e with SMTP id 586e51a60fabf-4157b15d40dmr8950038fac.46.1772007365304;
        Wed, 25 Feb 2026 00:16:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007365; cv=none;
        d=google.com; s=arc-20240605;
        b=SMFsdkTXFX4jLh8Y4q6XSzl8aorBKUMFR4BWndgeHx7tavHTLycQ7t4LnNyhLBMAXd
         UkoHSpbokwa4liSVOqieT5jSK5E7isaVd+vBkthmBo18uoF69J6yPXO1aa0eTXi6eTLq
         AE/aYcFaSAdvpcWQPIdE0dlCxNhhwBlLOpwx9WZnnR2RA/exAGA67IBx3EG8/k1Uq2P0
         /p4wBjJ2QUw4zSiXYoFP5NR84khg3BSJIsJijsiArHyHft/DCPgdAGj3HMIU5gqXMamD
         ooX73LQXALK6yr+0A5nq1J6+qIWysSGkpvGh1roYdYCSgqYjy21RCyBApmW+cR+TM7cL
         +Lcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=19vaP3y5lR+93yTFpmYDfoD2vHNlJZSHy6oOHn35u4M=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=PsSNODKcUHNd7fL/VeyMiw0C9DUtyT0dD+ZpKp8LA+0L9op1lJ133ZHN5M1b3+qlkJ
         XFSHqR3ehQcdHlebc8jUUloO+FtGQM3/II7T9zjstX6RkPV9d43RcoZ8Tp/m+3D/wx8B
         t1fmC0B+6g3B6edzE0LeiqMzzNxPESonN5vAy5f5iZrZlJACN/P+CR9FUujrSxRSnAAp
         dtzQMrhqZQsEMJQUU/40Z9QG3oZ/dzWNdss8jvRn/GOdah+C98kndBqPNqC8Ybu2le+M
         aRRd4YTcogp0afNx+1HtpDFboFYWcae64WILrKvmn51DXQPCetqDQKO+0EPN58tDE19U
         Tdvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FGqHqNhv;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4157d2b5dcasi427949fac.8.2026.02.25.00.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:16:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-659-fNbyuKNINK6CJvlLPKrBfw-1; Wed,
 25 Feb 2026 03:16:00 -0500
X-MC-Unique: fNbyuKNINK6CJvlLPKrBfw-1
X-Mimecast-MFC-AGG-ID: fNbyuKNINK6CJvlLPKrBfw_1772007358
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 83A1E18004BB;
	Wed, 25 Feb 2026 08:15:58 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D0B361800465;
	Wed, 25 Feb 2026 08:15:48 +0000 (UTC)
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
Subject: [PATCH v5 08/15] arch/loongarch: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:05 +0800
Message-ID: <20260225081412.76502-9-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: ksHb1MXCUBEdZyiHR-p9s0tLSlJ-oHauvs9sSOxqMOQ_1772007358
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FGqHqNhv;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBRW77LGAMGQEMWYKTKA];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,mail-oo1-xc3a.google.com:helo,mail-oo1-xc3a.google.com:rdns]
X-Rspamd-Queue-Id: BF7E7194042
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: loongarch@lists.linux.dev
---
 arch/loongarch/mm/kasan_init.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index 0fc02ca06457..047a059544e1 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -269,6 +269,9 @@ void __init kasan_init(void)
 	u64 i;
 	phys_addr_t pa_start, pa_end;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * If PGDIR_SIZE is too large for cpu_vabits, KASAN_SHADOW_END will
 	 * overflow UINTPTR_MAX and then looks like a user space address.
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-9-bhe%40redhat.com.
