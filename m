Return-Path: <kasan-dev+bncBCKPFB7SXUERBR55SXCQMGQEHZVZAOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 97C39B2D38C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:36:08 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e934c8f973esf4829390276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:36:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668167; cv=pass;
        d=google.com; s=arc-20240605;
        b=bx1dhqJj1Z1nJJRzhR7pv6KcnvFO9PRaeSvAG1qyx9/QvzkOPswqxoy/yxLKdLKWtE
         Wf1BgeCs7XD7Dh672gJ0JCDFrB1Z7Kuv0JfFyqBGeEKelK4nD3oJgHLLZtn2H2oN7Tif
         S37YIIg6Gb/g3eSji/z4CuB58CTd8w9N5vE8D5Qey/BDBSA+1rROFyyRzywU25MVHo5W
         8uuznbb3n1vhaYKnB+wql+UEj5L2AIgR8PvxBCsLWLvANhqW/t3IrSGalG5qeQhmpE0M
         dto7LCWZAd4TFpFeSavPlhNFrYx6trg42fuJjJaQzT1xMjdx34o7RGNcfM3V2FE0dfv5
         yaHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yBrvF1WxlALA2z9nC9o3wUVHnmGydlVGSy9hfUQgTZc=;
        fh=UDCKN7yTr0/ZMR98r0VvVcWuloTEMqBCvgDhrxOkBkE=;
        b=C3DUyIO4wj9ROR7SZGP34t8RTokTAevA133K+t8XAelul0rBfMKLSWi0isfv4zPfQr
         bzWb6YiCCh/Fgoecw/aP4ry9d4WqIlZ9iiGQk9g490Rj78TQsaHYp48Mgc2LZyRC0hlV
         aU9jyBfAmLxd2HrONaWxmea3VBrOmPa3yiu/XhxxVKoSm3MQ+TMSPi3X9YJJuSuq8RFZ
         I5gCSynZel3uG0CUNQ/paqpkd8cs9+DM0A9VKK/7TyohYCQP6dfI7zhr/CkAC/bbaGVg
         p8CxyoxMFIGPTQVg3mFP17o900zu9PR0xalxEDhInqtPRVksXBh0oHpl0wTTYHdIuNB3
         AvWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TcLbrShx;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668167; x=1756272967; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yBrvF1WxlALA2z9nC9o3wUVHnmGydlVGSy9hfUQgTZc=;
        b=WBkfirSb7qdZ03JK1gr2DhjW8Ky7d7gQXu3gVTUoqjU2IL4aw78vrPxCAH+fXhTaP2
         tJBC2tYGRkPSzVzQc+xIjwDtL6OrRQbxPeI2ivtzVAzlaz/581W2QG2QQVondMjuds7u
         2Ynf5UV9jFQriUPbebnFcYIa73pM3IgYBz2Xfxcy+jXPZtSMAXNKBJQquhrUpun2BrYf
         VO+WWz8tLUqKCwK6XOHqsMgnINvQ841EXb12WsDmlabCDM3myDGbvLG8MHZBqMueGuNU
         kGVpQA4kvIYtTvjlXZENd1v9YKs9lt0skplt0vZbcTzEN+/3C3KP4JTb/xTUsMt5fkH5
         05Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668167; x=1756272967;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yBrvF1WxlALA2z9nC9o3wUVHnmGydlVGSy9hfUQgTZc=;
        b=bR/DT8IAOqhp85/gDXSS06gCBZ46yS2Kq4WYhb+oxQOXTkZY/+pDRSRxjvMUL21Y/V
         +E8jhpDe+IPdphraaBZOEz2ACuKmed5mCN1Fv3gQ2Mk6bMVpHYx18/r3uIPtcOoL0V0Y
         UoJkG/Hce1FBVZjg0pAvG9Ju9tYJ2OnEUt5CHaWacwX0oCC1CQnqiPyA5PU+d+nbd4bW
         DxAwHUPZnSS3h3GkPG3FcOsdYCW2PIRRqQ68v7VDb5VgfsLaHXwYi3kX9gtxet4uWT4n
         iJdRWoNmmpm3Vtl6OZ+Bk/csvwozRHVoa2tXdHmbPiCMGWL7dVPUuZZRNKPp0Iu5CMDT
         A22A==
X-Forwarded-Encrypted: i=2; AJvYcCVCt+7zwRfE8N51DMmSxUX8mnH17d7SSAi/Rgckr1PfQP+KAmLEq55xlGoLKACcUKCoU9vDKA==@lfdr.de
X-Gm-Message-State: AOJu0YwahYCxA8HgWTnkwnO9lB2XAj/Sf0m8JdrSB4M2u2txOqJxzKvs
	IkIwHvBX2OQhljs3xT/UFdWCvEECTVSIgiV57ttak9JkxxHGOJsSsPya
X-Google-Smtp-Source: AGHT+IGWBNUJzz1RUJNPcr3bd/B1RNurTQv655W3EJxcbvwGC0Ijsk6bD86TyeDyY0OCQsTaZ2UoVQ==
X-Received: by 2002:a05:6902:1083:b0:e8d:72d0:9733 with SMTP id 3f1490d57ef6-e94f660df97mr1907311276.32.1755668167299;
        Tue, 19 Aug 2025 22:36:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZenppaffCLkMnOlA6xCU+XskkjPy/qm8ZNXitfLpGKGUQ==
Received: by 2002:a05:6902:1788:b0:e94:e5b4:b866 with SMTP id
 3f1490d57ef6-e94e5b4bbd5ls1429168276.1.-pod-prod-06-us; Tue, 19 Aug 2025
 22:36:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWk5lDE7AGHsJUVt5oedEp41nKzP6cOl55ECs+/1Y+zaoxtXZ3GhDKHVwWdZ6QfJCAZ9rjygpeplU0=@googlegroups.com
X-Received: by 2002:a05:6902:230d:b0:e93:36f3:5717 with SMTP id 3f1490d57ef6-e94f64c1d51mr1745669276.8.1755668166507;
        Tue, 19 Aug 2025 22:36:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668166; cv=none;
        d=google.com; s=arc-20240605;
        b=NYjGO4PN6okovNxQaaHUJIzPGAizD5mTc9R5RhKR7ypQiX1cRgr/b1QYLO0Jral+KY
         v7CjZuil1HwFK9MURtdM74B089BMUZgKarghwCOM0CL8vNXbovai2YrcxBLoedX3zkO3
         GFaa3NSJCzCQ5TKRPJqH6sgeshnabJokrfMvOFQl/H5hbpIOVwtQUEZ6NZ4F/4864T02
         wO/uQvBpaOKB7AS3FCP0FJKxmOI7th5n7yaEaxPfP8KnaLPyBLttGEe86W9R8P25YdDv
         wq87BQceHO7zIxTpWxU54eSOzY0y63o1kWn31h4CylXirJ3aHNjqa9pIsBoZiLIbo+HN
         LX2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oS87V1n70KnlvoMP4fCQ/ERdyh1R0fC3CtG4IQhVRyE=;
        fh=NXbV5ohCfOyHdEWSL7FOtNKIczhwSC3wS44hia1kWhY=;
        b=BVeUGR4nrYonPwRd3uRJuRAlhBJ1JvTF/FIE7GgrGurdMG5Dza0TWjp0wpm994/pqv
         z30MCti98Eyz6f3qhytbGAfHZdlWi0WagpR4YsWRFO/7k22Ra7nIpL3Uf/6DV6VmlO8J
         CC/3jwQePOaZV7tmXy9zFEU1c2VLJdO0eNV58A2R+Po0lb5vn8ewjLUM7VLJuIbtqiUa
         eLuIXvgQ2oAz5DMJVcDS1UP9IfoMxeLDECm5qEeBlAzmBOToMIODF0CPEx72zAvJEXCy
         bh9fcRmltOPmUFW1My+bYuWw5h2bSPPOuBw2ehK4xNRI2QBLg7Tn1VomUEAI4TaOp9Jz
         WTUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TcLbrShx;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e94f4a965f6si73147276.2.2025.08.19.22.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-547-NwZMdlajPhyC9_mbi6VafA-1; Wed,
 20 Aug 2025 01:36:00 -0400
X-MC-Unique: NwZMdlajPhyC9_mbi6VafA-1
X-Mimecast-MFC-AGG-ID: NwZMdlajPhyC9_mbi6VafA_1755668158
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 84A5019775AF;
	Wed, 20 Aug 2025 05:35:58 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 2B42719560B2;
	Wed, 20 Aug 2025 05:35:49 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v3 05/12] arch/arm64: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:52 +0800
Message-ID: <20250820053459.164825-6-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TcLbrShx;
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

And also need skip kasan_populate_early_vm_area_shadow() if kasan
is disabled.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm64/mm/kasan_init.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45daeb..0e4ffe3f5d0e 100644
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
 #if defined(CONFIG_KASAN_GENERIC)
@@ -405,6 +411,7 @@ void __init kasan_init(void)
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
+	static_branch_enable(&kasan_flag_enabled);
 	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-6-bhe%40redhat.com.
