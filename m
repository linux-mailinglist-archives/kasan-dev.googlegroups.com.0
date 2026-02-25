Return-Path: <kasan-dev+bncBCKPFB7SXUERBCW77LGAMGQET7OZWGI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +FlsBY2vnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBCW77LGAMGQET7OZWGI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:09 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id A2FF2193FCB
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:08 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-79868381229sf8852717b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007307; cv=pass;
        d=google.com; s=arc-20240605;
        b=NhypBRPgjzpoOwVLhlOhIN+U+05Jvjm76I1QrXixkO0mzecRRLse0Dg3LDg0Ypqzj9
         MEfHvvoTOZbgnjoynyCOEYTTUrHI7vJ/n3WAn1xQlGrctZVZvyINXw2zH3aMwBZxDEfb
         cGwxD6LTW8Z1RTk6QQuc6mBc85Lw6TPIn897puwAbSloyKAHNhT7+/n+v25cRErD3TEW
         hCVlkVReC0bAAzQ72SyUiAtH8l0vo6x4DZeMwQHFkrT9KGQW4tNOv/bnknkFlQBoEgJj
         lYMVEHjubUtZXDfWbZaL/Ktb2XDNyiKkaawi/crLdIDF9d+bMfdNpskLf1gBiAY1D2mH
         cjcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=y7Fg6wQaqi1YPZN7+JNRQHaFF0Fg/euzm7wvCP5iTVg=;
        fh=4iJVt9hpJf6kXaWog5nMX0HdFw/A4sO+DES0U/Nj8CA=;
        b=ZLG0Qr0F8gBTjvf1ywH0QcYpw3y/2nTzrsQGU1doVZDJl4XXBNpM7qc9wPbl353XkO
         vQgYCrZDdTR6EegcnaygRMEaN2SBIugYIywt/9W8/BRhxiI3RYygS0LwEkwySKrCIbrc
         waEj0Pbf+Z3g2BcvEtYepiCYKuBqW6CXeM9hdvv+nVND+V1cZ+xrJBOg3/Vyv7tYgLnC
         hetkKR6x/6ucui33BF/hZ0qCcJuFkOHzOph3AxCc45vGWKIm1QHsZtBJqsEtSQiLsZ10
         GVD94B02iVXJl7K2FQhANeLBocqguH+PzrU+HmB2snfjNCn1FZmaMcDbo1/mn7o+srVz
         SObA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gChPkYou;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007307; x=1772612107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=y7Fg6wQaqi1YPZN7+JNRQHaFF0Fg/euzm7wvCP5iTVg=;
        b=GfTqH/AWPhdh/YJ1JqNJksQLBzy/R3U00+KL0j+5nI8U53KWcxfo9LdDJGRen7ZFWi
         08cfok8BetQRzBC9CB009ymeAbjNTsZikvdwBriawxYKlyfVjdA2qW4YnIpcgelzUW05
         K0WiI9UghWFnBdLX1yhK/tVjIjIcSGz2fn0XAAso7yQpX4b+ssYjrZx4UVnG2mCYhFu2
         D8GLKZDlRVaJVs9VCkYR+jirYf8b8fLZ1no63Rf1jw0G6o4cgO+rF6m8U6Tf56b8r7lv
         jMBJZGO0WUywfzFLU13xj5JBjuctqU4KhMOSxscqb+FougR8uqZQeOzjomN2GQEKnXOL
         sQCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007307; x=1772612107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y7Fg6wQaqi1YPZN7+JNRQHaFF0Fg/euzm7wvCP5iTVg=;
        b=BwLOCcGEpd+OZ1iJHurTfjyViCYi8ZHNDqG/+iNMuDatJmYlDnpjynmg+GihHfvhp3
         zeGXvvNRKeakySl2hIF7tXep4oSVbOdsgo21VHhUzY83pAmsPbqi5r64WwK+BUC/A0QG
         GjzScsiQrn0Y6EqnJvsbeSEjhhHxTFLLMBjMEV6fvgwiwXLq0wBflW7gk5ZWuu5s5Obr
         BQKKYgMhI8afzP0Rs/wGCYrISaeeGf7M2TGsLjgmmwR0++bu+AfLQhSllZUUxr0B4a5U
         EdRuDizJbWXMLTExuMOr7ULwg5HTidhzuZCdNmGyb6NCsDvdREy4zcn95hCwalfwT0Bl
         c6JQ==
X-Forwarded-Encrypted: i=2; AJvYcCV+M/dycRYFGGKsP2q3M6z9WZ1Y2Gtisr94xf2MBxm1b6TuCgc88w+octciidjJXDBmZlACIg==@lfdr.de
X-Gm-Message-State: AOJu0YyRjclrEzjl2fpbmCIkXZKX6dtGOwV3UH5OKy+omq/1jAMf+i7R
	RGEG4rCcUS1lWyMXsrRUaj0z2WFIiLH49lb9GuNKzWwwMepfOyBKdezP
X-Received: by 2002:a05:690e:b8e:b0:64a:db63:99e9 with SMTP id 956f58d0204a3-64ca61a2a2dmr2178761d50.23.1772007307070;
        Wed, 25 Feb 2026 00:15:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FLrCpbTkVOZs0liIXUBtQGK6K30MKkhB0cy5KS/qwBlQ=="
Received: by 2002:a53:e1ee:0:b0:63f:b944:666 with SMTP id 956f58d0204a3-64c9db6452als809612d50.0.-pod-prod-00-us-canary;
 Wed, 25 Feb 2026 00:15:06 -0800 (PST)
X-Received: by 2002:a05:690c:9691:b0:797:a162:f7d8 with SMTP id 00721157ae682-798650369acmr25197657b3.27.1772007306063;
        Wed, 25 Feb 2026 00:15:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007306; cv=none;
        d=google.com; s=arc-20240605;
        b=jA0r75V4FTXB7YWEcTXW3sCS5fViPMcg+p7U/CQ2W0FoAWcOwsAjmM0Sew4ma6KhhG
         7y9SfXBcXYPV/qfvjy4A7F6Adx24oanFbW1gotTueFb8lkne8+NtxvllFLuA4pwnmuDY
         WwtCn8kGK0JFktEyzqKVGDDy8cPRqQFM+2SA/7GvkATqjMAk1xFSHHSub4ZuEFwvzu2x
         Mit5Mz+cEaqeVf5tWfW+VcW5QPsAktJEfKx4ZkSQTN2gEPtqlQ7e8iB3YUjyQAoa6y7B
         FloeMNQNoTs6DdbwFtha6M3NvylWFJ+qyNTAZnAAlg70/yMfG3kjnny2eTvMy6TPWQ+5
         Rttw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=m4icHQGTRNbNNPTctslHsQ21pBhC6HpCZWDHuC81RQQ=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=HaYl++f00y1ckvpdniYNkt1KYoMNXWzchZMg+wGr32wY+SSnQIiBLdHsdo982oyies
         MCtv70OEZ5vxg3A6C+/avKr5bq4FZzoU7jF6XOxrPLnZnA4z8gAGRurM/K4ihRCFDers
         6TfQnQi4/DM3QEG88e592GPPOlM2n9fGGtFXRWsvk2f1sQwW4g1N8O+B2vfDPehUV6Wt
         Qko1V0wpYNKfM9QLJsKalBaOSk4hRiJofPdyNIGDfhx3G7COXzvBrhd3Gqsnj3qhH4l7
         pi0B2FR65to4N12ZoZJpvf88HEhqYm3TIX8OZMsR8brE/wt9+ldk3UNsFkMgGFWvumDq
         0p/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gChPkYou;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7982de56130si4625897b3.6.2026.02.25.00.15.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:06 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-647-dIDhZlzRPtCltfWDvHZypQ-1; Wed,
 25 Feb 2026 03:15:00 -0500
X-MC-Unique: dIDhZlzRPtCltfWDvHZypQ-1
X-Mimecast-MFC-AGG-ID: dIDhZlzRPtCltfWDvHZypQ_1772007298
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A1EFF180025C;
	Wed, 25 Feb 2026 08:14:57 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6EC9E1800465;
	Wed, 25 Feb 2026 08:14:49 +0000 (UTC)
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
Subject: [PATCH v5 02/15] mm/kasan: rename 'kasan_arg' to 'kasan_arg_disabled'
Date: Wed, 25 Feb 2026 16:13:59 +0800
Message-ID: <20260225081412.76502-3-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: DCh3-xLlx5rIxLivrt9cxddXZmUnFtlYStXBOQhTpKk_1772007298
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gChPkYou;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBCW77LGAMGQET7OZWGI];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.980];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TO_DN_SOME(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com]
X-Rspamd-Queue-Id: A2FF2193FCB
X-Rspamd-Action: no action

And change it to be a bool variable. This is prepared for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/hw_tags.c | 16 +++++-----------
 1 file changed, 5 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index cbef5e450954..26a69f0d822c 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -22,12 +22,6 @@
 
 #include "kasan.h"
 
-enum kasan_arg {
-	KASAN_ARG_DEFAULT,
-	KASAN_ARG_OFF,
-	KASAN_ARG_ON,
-};
-
 enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_SYNC,
@@ -41,7 +35,7 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
-static enum kasan_arg kasan_arg __ro_after_init;
+bool kasan_arg_disabled __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
@@ -88,9 +82,9 @@ static int __init early_kasan_flag(char *arg)
 		return -EINVAL;
 
 	if (!strcmp(arg, "off"))
-		kasan_arg = KASAN_ARG_OFF;
+		kasan_arg_disabled = true;
 	else if (!strcmp(arg, "on"))
-		kasan_arg = KASAN_ARG_ON;
+		kasan_arg_disabled = false;
 	else
 		return -EINVAL;
 
@@ -222,7 +216,7 @@ void kasan_init_hw_tags_cpu(void)
 	 * When this function is called, kasan_flag_enabled is not yet
 	 * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
 	 */
-	if (kasan_arg == KASAN_ARG_OFF)
+	if (kasan_arg_disabled)
 		return;
 
 	/*
@@ -240,7 +234,7 @@ void __init kasan_init_hw_tags(void)
 		return;
 
 	/* If KASAN is disabled via command line, don't initialize it. */
-	if (kasan_arg == KASAN_ARG_OFF)
+	if (kasan_arg_disabled)
 		return;
 
 	switch (kasan_arg_mode) {
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-3-bhe%40redhat.com.
