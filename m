Return-Path: <kasan-dev+bncBCKPFB7SXUERBAF6SXCQMGQEB24GUOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B7ABB2D398
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:37:06 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-76e2e614c60sf5380428b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:37:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668225; cv=pass;
        d=google.com; s=arc-20240605;
        b=NzvB6Uuit82/T8J3O/7MfhTI1MmhIoNsfxFY0CqCCOKrcvmk0J1s/ylzZ4EQIPCBYS
         h9VCVM+Z5Tl0cAM/MwqhMFy/SO2MCEEQPpmKf4inUHY4/51RudvlnCNR+HEacABfRxS5
         NMzAIOl44J6jDUSxv7L5PwYR5PeJr95onr+z4Nb+Qh8tHm/RXe2eyDJTzZfutcLLVGaD
         zyJTobbGQeAQbzZNf6IlYHsOdVrd9Z3+/hWT3AsKwEkbhVyDZ2FM3+U9xNnRqAKJBJXv
         2WLqYwenkQxBTvAYNtgOXmofPf9zdO4Z+ehaql/9fdFkogaB6hGA599i4fIbScEUNS5G
         aouQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=uJwXIIAVACgXWxeOwRjIvKa6kpldLbeHhvGv/XyQ8Ps=;
        fh=Dwt2Tzy+Z9tIf8Tz9SRXoCXE0b3/b75jwttKWiFePTs=;
        b=j9eDS1Bxvw+kD+p4bN2ggl/P7jf9d1a4r8OKXKcZtepn4Cy/f6R9I7j31xYLB0+CKg
         C6NGsXjp9+pFntFnKSwKC7dYA8EWTWWCH6d9ix3T7/BxkOgXR+9qgMCwuaPGUnApakjx
         xXwo+Iuc48DHrJh2KjJqVFd7NiFXXKpjPLbCW9pTBJmukMyXMN0IapQnhGoqyguxWum4
         E5NphzsXLAShXspa8hO0abo7Hs4WcK48rHthgT+SlJeOkDt6h93Ky7Jb0vDvdtwQrgd4
         yeAYYfEkNznxkrxItJe+jPiy5Xh14iL1zFJqY2YoFsh5aS7/hxCbRg7gNl5jTOt21a1s
         KLOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HpK785ZZ;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668225; x=1756273025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uJwXIIAVACgXWxeOwRjIvKa6kpldLbeHhvGv/XyQ8Ps=;
        b=k8A2ehRjbx3CaWVRM4YGhSsD59KwGXY0h9bhQ9F/FKgTHa8f+7r7n5MqKM1KEJfwsX
         M3YM9hFsBP1S6xaEfmQIH5InNxm2Gm70Ms4j+nS9yDIdAGowoo3UP41H4zaiqEl2x39C
         EhUJxS1O8Bdby3KupUPAuF373XHMM5Kb0sOfYXiVUKeL9PHoYfTZAiCCJeLdvzoa1Mt+
         u8KdIiTyqdCeoirOPTyLrelMbEQS622uKRZkMBFoq+M1eeqNA+ttWANGf0I623P5LH29
         jmLvGs3Bt1HruNMkHT33GPOKc922XHhnaSrg90VWkzTJAcCCBHEwmAY1SJy04uosmYJY
         nPBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668225; x=1756273025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uJwXIIAVACgXWxeOwRjIvKa6kpldLbeHhvGv/XyQ8Ps=;
        b=O7ZmSEB/LMJrMraUwr1t6OEX81K9lel5iTGhAXOdKJiyZpoeBspYwyi24yPrb1w5mC
         ADW+lM+obKdo7KwW7IHESaiTVuY7+wygmVEVsspPolkqUBfYldrgQyIYyaX90GLnZHJ7
         qh9dv2Wb8SJn3sOTPwnE84ffvNr6X0szOLdLvwBsfHSb20UYeC7vFq+tsFZE8Jskfvii
         IubBWkJLnZi2ffWTPjGonR61FxXz9buIiemwjTsI90McBq8Y76ft27wZKKPaIjUsrFL1
         FZNvlb8jxkNSwHfHY8BfHFTGCxFqriPk122zV7HX+auto0l/jaA7dwieo9WMPhdDnHn8
         duvw==
X-Forwarded-Encrypted: i=2; AJvYcCV0r3MP2zld8+AQZ0sNN3SZd0imavnrdb214xTXwskZUQYXwYHBUcrsIO5N5eBrslkV+ALm0w==@lfdr.de
X-Gm-Message-State: AOJu0Yy+NqGWPLYvBhFjv3qjGFhjQepDHKVT5vD6BlKQGsE30vzfuEQi
	KQ1eTwPsNoxiVksMYt54/thPS6xZOEqq6v0tWNSlSz2GXbCBUEHz2IFj
X-Google-Smtp-Source: AGHT+IEWy4jmvGJvXUCuajFGtRiQV5mQTudtaCjtkK+LnJcKchppk8CB84kN+zZ7kATrzat6RxaErg==
X-Received: by 2002:a05:6a00:2da8:b0:76b:ffd1:7728 with SMTP id d2e1a72fcca58-76e8dceee5cmr2524473b3a.17.1755668224459;
        Tue, 19 Aug 2025 22:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3tJqGgkkhAleMBZS0ZJHi1q0E5xokygvWRm46OGAhBg==
Received: by 2002:a05:6a00:1490:b0:725:e3f6:b149 with SMTP id
 d2e1a72fcca58-76e2e5278f8ls6649328b3a.1.-pod-prod-02-us; Tue, 19 Aug 2025
 22:37:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvTyqr8DRYgGJiQ7BF+YH42aX38UT17lajKmOi5xbgMFjYkN0TowCTcenBbNT4wcsIV2g1Lu4MQ3w=@googlegroups.com
X-Received: by 2002:a05:6a00:4b07:b0:749:93d:b098 with SMTP id d2e1a72fcca58-76e8dd24b34mr1956185b3a.22.1755668223116;
        Tue, 19 Aug 2025 22:37:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668223; cv=none;
        d=google.com; s=arc-20240605;
        b=fcu5s318YPWr2he4mAEKFlNct6a57gK9cQhMyvZmyDrKv+0mxcMUBRinznh47DKX3L
         oDVfO0ZxdV4EGF2aZ1h+U+v31+7LRUiO4mGY+ouJM7r3jocd6+bOxKjHIB/1jQWuDIOz
         DX/40/zqaAlfm4bsaQnIHo+UQVzsUq0Ab8g7h8HxDRWYdqRQlLmWJqQhizaPSCeRebxN
         mRjLeQujIPZ+/MXNwIZfowF5LM2N9hVaD+rQzKbyPHkEtR5D5giVr7aYCqy4GVU/b3Bh
         NnZdSccZ+KbvzXmRfsBVVMLVMYBBJEeI77dkV4+i+X6LRSzuCZMEVNdeq+WYzEh9DnzN
         Sbag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z1K+NrhffiuczGQxxvXLPTT8safjMr4ane+44BSMgbw=;
        fh=hJ/qyxR18tidBeEMpaQhfcPMsvmKPXJDvZgVUkr0Cxo=;
        b=dRDk62ur2wmgRUpzYCwZrVPx+xsWE2S5cGCEWzAAM07nJHC3U7rfqIc5Axvo8Pi3EF
         gS/A1eRZOBB/86VVZ3kQBzexCP3pzxQa7ybeJ4AXGvbVbeU8VHAgJ5lDE2U6ch5V1Shl
         EXZpvsOrlxjFha/djadBShgvngInS+5ffOgRehOf4oSVl/HH9cYu6uACDIKTdvnPu378
         9MH9us+uqmxPnZXHCyiOIRqAW8tv9rQ3gvfZ0OoFZ2bl4aqjzD5tWBdIa7wntd4hgfbY
         5GtzYElwS4z4FBZK2SFzFM5w9oNK8lz19K6nccVdv4kD4WW5nz/hfUP9hsfk3Iiy3gZW
         Z7EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HpK785ZZ;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7d52a576si155219b3a.4.2025.08.19.22.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:37:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-679-FM4T_kMAMBejUgJcViqkcg-1; Wed,
 20 Aug 2025 01:36:56 -0400
X-MC-Unique: FM4T_kMAMBejUgJcViqkcg-1
X-Mimecast-MFC-AGG-ID: FM4T_kMAMBejUgJcViqkcg_1755668214
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 62A951800366;
	Wed, 20 Aug 2025 05:36:54 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1826D19560B0;
	Wed, 20 Aug 2025 05:36:45 +0000 (UTC)
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
	linux-um@lists.infradead.org
Subject: [PATCH v3 11/12] arch/um: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:58 +0800
Message-ID: <20250820053459.164825-12-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HpK785ZZ;
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
usage. Since kasan_init() is called before main(), enabling
kasan_flag_enabled is done in arch_mm_preinit() which is after
jump_label_init() invocation.

And also do the kasan_arg_disabled chekcing before kasan_flag_enabled
enabling to make sure kernel parameter kasan=on|off has been parsed.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-um@lists.infradead.org
---
 arch/um/kernel/mem.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b5..7b7f838274b5 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -58,6 +58,13 @@ static unsigned long brk_end;
 
 void __init arch_mm_preinit(void)
 {
+
+#ifdef CONFIG_KASAN
+	/* Safe to call after jump_label_init(). Enables KASAN. */
+	if (!kasan_arg_disabled)
+		static_branch_enable(&kasan_flag_enabled);
+#endif
+
 	/* clear the zero-page */
 	memset(empty_zero_page, 0, PAGE_SIZE);
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-12-bhe%40redhat.com.
