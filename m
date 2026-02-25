Return-Path: <kasan-dev+bncBCKPFB7SXUERBB7A7LGAMGQEKMR6X4I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YPXEIQmwnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBB7A7LGAMGQEKMR6X4I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A10C5194105
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:12 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4806b12ad3fsf48456995e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007432; cv=pass;
        d=google.com; s=arc-20240605;
        b=EJRtBJ5FAVopFvnNFUqCeWOnmgY+EmY3JE+iivMwWHqdf7m6QeFyvsbdZt7xalWayV
         AUIi6ZcLCN24pGGAxLqat7zAEBXKzNebkiH5DjhyJZmme8QtMtJtvGLcBhwvzK1gn47H
         cf1YsX6gCO0lZI4C/xGUYEtebyNMyVd0lvkWZ0Z1213POsdaCczydEeLXhfnyV9T2+MF
         G3nWfX6z/wfpffIPSTzqApjIuWbD94SybfmTL24er+LACNmi7svgXdV9Kggy6d9SxCU0
         bMcNYlmJbZYuc+FCwLz4B9001+M2aZzvj7rzCimzN6SJrlXBgcEo3vs05xg8NKhsGfog
         SgmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=iSWhlMRBf1jFkSpj4FqHLv8feM5EAUEDnhv7q9wseWw=;
        fh=T4YeguqPfZtXz5jkG0OnzmroJ97IQycrlU7MguifbiI=;
        b=YJptzqLS9FUfAp43HFfc/5qcoi+II81rItiHONZROkF8XvJ9gGtN81hDnBaEKwlaZF
         eulqX3At/yR0iUbP2P17y3cpBqNNaUvGKmShBjaoFTMhVNKlfEcStdUwIcnBpUp1cZv7
         kg7mT+rXbgvpqbQbSfS7zwaKab2WQM9w4kbPHXH2VeLUg72esDQOG75gT14KqKb84yF1
         4S/mGHxkJ0xJzLdkkvbgk7Yd6GixsB1npiXhyyAQ2TeWHXphvENUwgMVY9DhwUdVjXoN
         ZC//iQ2jgrnWPsE/L3PHIFIeC5fLSvIO9nciZaK1SlonS9greAS0pw+1bcm1baoyP1Re
         YiXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hW4vql0v;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007432; x=1772612232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iSWhlMRBf1jFkSpj4FqHLv8feM5EAUEDnhv7q9wseWw=;
        b=o1v7q/tUwdurhaD4igqE3uTgpCnDuQU+qotvbz03AYnw3gWU1q+WK56CJNvNi8lz0z
         0sp4eQr2ecA11YaU0tbtB1e6xdIMFlbf+jCwpSz7wQhPuj4zW1iRcVhvbbgm19wfvwXV
         Do4QMX3rG7kv7polGy3LX83v5px92p04N5HseI+NRoUUJ5BUP0fb7FHoM5sKDsTj1Eq1
         CE7+S+f0ZYZYTzi2dO1MunktXiFMAWEgIYa/tBqAOM/bcw6saW7n6cighLjt2Wu1ZtrV
         WeupycU/axlDftXLlG5nDfvsc5Pi1xWdtSE88bw5AoS939de/2dJg0hMGShvbYVTSS6A
         SdUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007432; x=1772612232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iSWhlMRBf1jFkSpj4FqHLv8feM5EAUEDnhv7q9wseWw=;
        b=YzQz6UOA52q62YyG9tj5LMP3atMKQKls2WQ+Mz7JOemWidF1e4/051QYN1hGHeynOR
         dnpfpo1266ByuAegOUG2YLHDXjy/3r7UuvtLZlTgn2t27lEdsyj85t803RJpKqY0V41d
         cDq8eQ76rljJmtT20gkMSs4ze73fVEDHpbrJxafsWkVG9qJgsqcDFHbJYqkxCICPpWMJ
         poBVDUW4dN6FfBtR2XkIoa4pHjmH33yKsb52moysr4M/c+ZPfp+ENEFAWBokJbsUgGT3
         FUGnTDiczY6y9//PSBpZBVV6RXgWpS0WtZ38UZHfeV7SNZk6gcGASvsX/Y4o5YZ3GdaV
         ydyA==
X-Forwarded-Encrypted: i=2; AJvYcCW9nyCrHcZ2k12DXi6tJnYcJedg8IbbMZz2x7hQG2xGQUGMXiDPHHDz9UhNwFCgICXQbPiUrg==@lfdr.de
X-Gm-Message-State: AOJu0YyWHX1msYvXkVlVKkPGyU1/d+Q5rc8O9cZ1gbDnKva3wCdhKQLj
	SBSeFiCfHJdJEv6GBXIR0sUawFgMq7MaOKV6QRawlTk8PKj25xEB0V9n
X-Received: by 2002:a05:600c:8183:b0:477:9dc1:b706 with SMTP id 5b1f17b1804b1-483a962e3d4mr208020235e9.19.1772007431541;
        Wed, 25 Feb 2026 00:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GT95mEhkrHM0b4+AsyNuXe2BSMMD3zZxnumofdyTIEtw=="
Received: by 2002:a05:600c:8b4c:b0:483:a26d:128c with SMTP id
 5b1f17b1804b1-483bf031af5ls2754805e9.0.-pod-prod-03-eu; Wed, 25 Feb 2026
 00:17:09 -0800 (PST)
X-Received: by 2002:a05:600c:154b:b0:483:7ae2:1737 with SMTP id 5b1f17b1804b1-483a962e486mr223631295e9.17.1772007429094;
        Wed, 25 Feb 2026 00:17:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007429; cv=none;
        d=google.com; s=arc-20240605;
        b=JtjAIWknbez+y8T+wzA81unGWwLBFWqQkrSjnhlHuCz/SmRSsmYf0KfUNLsJ1QQz+E
         zCbfyec7bUD8kWBnDGV6r6s9SihsgTdh9hjnDPvlo43Fsgb9S4EhZhVFW53epWldA8Lv
         czZWwKs7Ri5Cum+MTgpEcfPt5yuXyRtdpuHu8H/Ag4fbfPR9toE0yuXP9RcKTbcphkny
         eJNtZ2HNmUF6PUs8GeRBHs56/RP33rW4TAewb2bHqKpbOU3psjfU0/X9zmsy0Ax1yInh
         TEAiboCM9FsSPhaMsxC0hiI3XWtq6YOAn8WOVGMXVkDfCnNlm8HttJpJTFjkQU3N7sBR
         fNkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oT83zYbQb0MMseAk5Xm5Eaz7XNiK7MPHbcs4LQizA5Y=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=NWtDQLW7j7ENGm/XDJgCEo91PzWvXLZIocAnwVUuUxyY8banINMMoNsX/8yh9I3COE
         Vi99V5/DvVUEBP9omQgQBht56eXwXXCBKu9SrHCxBxQrHfUg06ZxeFKevbX8W8LOLBRv
         338+7haFFjfm2aHFwzdUtBIzUC7eO1SNsitWzxR2zfZXW1be+GSUhpuEdFx3EhlkAUhN
         +2LkKk81ubbZXvnxb2Nah6Nm+ju27vQn89/PXDjgWxXJ3JI1E64bwCKElWQxOlVEGbw1
         R6prKQQT9pdYjOBQUc9gSYjFXl4c3cGEPmEEhoUg45iCmJSRStgZWfwCE4rFssKkTlmv
         p7nA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hW4vql0v;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-483bd687affsi502255e9.0.2026.02.25.00.17.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:17:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-68--PGROTGBN1uM5wyFliyqng-1; Wed,
 25 Feb 2026 03:17:06 -0500
X-MC-Unique: -PGROTGBN1uM5wyFliyqng-1
X-Mimecast-MFC-AGG-ID: -PGROTGBN1uM5wyFliyqng_1772007423
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AA092195609D;
	Wed, 25 Feb 2026 08:17:03 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 2EF4E1800465;
	Wed, 25 Feb 2026 08:16:52 +0000 (UTC)
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
Subject: [PATCH v5 14/15] mm/kasan: add document into kernel-parameters.txt
Date: Wed, 25 Feb 2026 16:14:11 +0800
Message-ID: <20260225081412.76502-15-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: IIRnt3GND9eFIjhIBYojrt21M369Pk7MonnWqUp4W5w_1772007423
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hW4vql0v;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBB7A7LGAMGQEKMR6X4I];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.978];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: A10C5194105
X-Rspamd-Action: no action

And also remove the relevant description in dev-tools/kasan.rst
which is hw_tags specificially.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 Documentation/admin-guide/kernel-parameters.txt | 4 ++++
 Documentation/dev-tools/kasan.rst               | 2 --
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index cb850e5290c2..e0115fad9e60 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -2899,6 +2899,10 @@ Kernel parameters
 	js=		[HW,JOY] Analog joystick
 			See Documentation/input/joydev/joystick.rst.
 
+	kasan=		[KNL] controls whether KASAN is enabled.
+			Format: off | on
+			default: on
+
 	kasan_multi_shot
 			[KNL] Enforce KASAN (Kernel Address Sanitizer) to print
 			report on every invalid memory access. Without this
diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a034700da7c4..eaae83fcb5e4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -129,8 +129,6 @@ Hardware Tag-Based KASAN mode is intended for use in production as a security
 mitigation. Therefore, it supports additional boot parameters that allow
 disabling KASAN altogether or controlling its features:
 
-- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
-
 - ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
   is configured in synchronous, asynchronous or asymmetric mode of
   execution (default: ``sync``).
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-15-bhe%40redhat.com.
