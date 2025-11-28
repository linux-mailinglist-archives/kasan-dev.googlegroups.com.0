Return-Path: <kasan-dev+bncBCKPFB7SXUERB7FQUTEQMGQEFKQDQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE49C90C63
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:35:25 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-8804b991976sf28545596d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:35:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300924; cv=pass;
        d=google.com; s=arc-20240605;
        b=CiweESclslKtzVlqkDazC4/rKfXDHb0E6CJ8NHva+1KJQt0h4CCOGCPM1cn7hvrRQZ
         uXJ3MWbWkDwSaTYrvXMF4strBZVoNUl4MUqJyOOP6RL6tgHbB61oPRPVTh8ZzpnGCv8e
         wGhkp5J2oEfLMolZ6Msqdb1T8iGDEUPAz4rUNRJmGS6K9sGOk8kAEpnhqx2bpSOTUveB
         vmq+DPogtyQAnSvYnb+WO5FgsNqViaIvLGSd9tC5YFkXwQkwmjBMfdrRyn/a5qGOQ+2A
         8mc/pH+e4z8FibjElDNjd0dpLmM0mBkcU65c5THJvrte5IcDzEKc/ERqItF5GSg2e5Ye
         1gUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=e5g7zCCQ6PrPzizFq+lF7Rxigt5r9PFT5DNDN/tEHig=;
        fh=Qpf8TLBIeP+/yEc2x+Dosyrug+5WDAwemfBKYfAt2YU=;
        b=PP9eH+w3jniff0AIF3T2vzOloe0lgVtg2k3ByT1QChIAANDOW38eLD5QlrxgP49NCk
         0dMzdx5+2BaS4aUKXlMcHcaq+dEzV8LLgx8jhRbMdweyd2B/4BKh1mifbupYeXht5fKo
         pQmaBmMSOy0ls3q225coMgmbc1t/8mTMsWaHxTONuS6ZjCTJfzC3LIkgNoQ48cwMFqbh
         dU17e11oTBcMfUEV8iSTpnd+Y0mOJjr6eMx55sOLfZahvBzquu0pBnzG94352jhRVJ8C
         tm+O/3TI0QtlpPR19tZb78IuFwFfF9GyakKT78+m3rkqnm6vDa7BBgw5sWI6COoYRzhI
         WjHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TyGbnDTk;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300924; x=1764905724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=e5g7zCCQ6PrPzizFq+lF7Rxigt5r9PFT5DNDN/tEHig=;
        b=WZXxKONA1/uxtLn4/zyiAVkzZviXd1kzYfxnVIa65KQXq34J+9gMXRq9UAjWHlNh9Y
         XCEez/WwKOIdxzqzQJrzdSSvAFzeKe08u/iKG4n/p03CE3/R42IAYuudFdxSboXVOQjA
         9sIaqTk0QsnjBe6HusU93KBorK7tbFcgPjlVIfMTl54EzvZuHOrvdxs9mz0PWQP59J/F
         oMYiNIruLE4K3BvHhM4ZPo11RaivczhdyI5x5Ms7uhFeIGQX46Jq8IbBGk9iuriOwYEP
         LGNGzHbkyq8ZjrD2mG2x8VOR1iGMROdfrMPTzj6h6wcjw2CijEw/Nr2b1Ip8+xaW9+AU
         HBmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300924; x=1764905724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e5g7zCCQ6PrPzizFq+lF7Rxigt5r9PFT5DNDN/tEHig=;
        b=BfsPwZFb0pkApF/myLYDG5Xnb0IBzHt6HjMkIIULlt/HfXZwu7Y7U52itCwUwReb6R
         aGgCzV+sJjFD5I0irVVJY7DVm3lIiRbmbJYLcwDZSXWF1nKy/JFCUSDS7JpxLwnzcsAY
         qXsjFDSLmGlCm9FfPiKIzQd6QCkdk8kJKUiSffaHX/ng80/xzTaquo2/BL/kxhrn/ZOR
         CmDV0Km9DhyXi94n2rFkAAXLzZW/XYOGsTKpDgLUZ+LCG96KQnZw2bMpJsowF+U86QNm
         PyuWtgv6kd7ILOUrlKgmSXS10g68N38GL22SzNrg50A+WntVD5DFfTMT+vGMsZ2fjmSL
         aoNQ==
X-Forwarded-Encrypted: i=2; AJvYcCV71hto42QCPr79G3or5JNh9eIXEhdr+kjjfpm7okR/hMKHwoP++7VuXsxCW/YAQjpZwblCMg==@lfdr.de
X-Gm-Message-State: AOJu0YzS8/7P9l458AQa8PigRkseAFnYon+S7fkc0TGQdJ69iRjPjljr
	VZ2XmOT0OVjFQX5IkSQkWxk7Ic9CeGbPia9cTnXuR+sJTt0DrLu+SXmp
X-Google-Smtp-Source: AGHT+IHjJGmbLpfB24j3Xqd6Pr1u0Pmn6cBr2VnsgANPmH8RwsVgYnRwH0aie0dOVrP5eyp9j9r9cg==
X-Received: by 2002:a05:6214:20cc:b0:882:3f45:c811 with SMTP id 6a1803df08f44-8847c546509mr383964276d6.61.1764300924581;
        Thu, 27 Nov 2025 19:35:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YAk5039OYwYo1tncI32gwvp2EQxyPn4l+hkl2kfenLnw=="
Received: by 2002:ad4:444e:0:b0:882:3ab0:1d82 with SMTP id 6a1803df08f44-8864f7a1340ls14754106d6.0.-pod-prod-03-us;
 Thu, 27 Nov 2025 19:35:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXiFGRt/MKnNMvLBbuDo89DgHy3RlrNUugPp13B8/WV3DI3VpZ7FG4EidQLEZmafXRh/W3PJhXpt5c=@googlegroups.com
X-Received: by 2002:a05:6122:3c47:b0:559:65d6:1666 with SMTP id 71dfb90a1353d-55b8d6bba4amr8328903e0c.1.1764300923580;
        Thu, 27 Nov 2025 19:35:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300923; cv=none;
        d=google.com; s=arc-20240605;
        b=lXjuQdX0vGhL7L1YsZmtoZCYUzOMYZqXdnspHRGYwVB3cWFmizZEFELmUujCEtyXPx
         4XwplrmkYipU8WibRiNIfOoOWIw+X9gHsFM2imSuKL/Le1A102Xgtk012CXjtTh4AehF
         IqPANUJy/KPrp//12GhBUUsgWaZxXBFGZQqFsMjiPpvNyTNGkwbzKK4kNGoo3kLosc20
         v5QbzsnhO4GTJE9sJ1sXjjrc3UaoPvn037jcogjGS6ThvMCsPS/iqB/heHIrIbC8t8fO
         ibkVLYkLXVWJVM1QiGpL9GtRpVE2ouCQdwBc4GzzaOsVNgBU6xOwQ9Qmwe7NsITNd1AU
         bsGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2zYq5Xg8QPu70UaOO3h6mVKhUd8xeQ64UlU5KTsxCNk=;
        fh=5SDByJ3Hs0yfOCoQGEuG1sRE6NAvqIWBUeJICelOz9U=;
        b=BLVKwN5wtqQYc/Q3cGzckQ576CHQkR+f6ffqfnGHMnl3WVfLW1UiOzz4A4ChVszzYQ
         jfO1x6+uufGYUA8B5s8GCtp1ayFXrYAF70yg1ZyFYUcq4glZTaig6aS/Bw0+wIb6gPN7
         yH7ZK6ayyM1KLYlowV8bi5S81u/7HreevV2tWr2R18ig/USYLPCU9Hik+AlfBDUx3NVf
         1CKj0qHViTPQ+KPWNTtIw5e68NlEdQjbDh2UKFLWH/PaF6e1LHe7OUjLnr4y+mhyFsUB
         4Je/QdRb7r7QgfAwjG8QZm6W/YQA10zWergXGfFce3QV4LKOJwFOfvzTHGQWON/2TOcG
         QpWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TyGbnDTk;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55cf4b0ab49si99876e0c.0.2025.11.27.19.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:35:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-677-PSk638q6NMCqBHAkPGt0ZA-1; Thu,
 27 Nov 2025 22:35:19 -0500
X-MC-Unique: PSk638q6NMCqBHAkPGt0ZA-1
X-Mimecast-MFC-AGG-ID: PSk638q6NMCqBHAkPGt0ZA_1764300917
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E833A195606F;
	Fri, 28 Nov 2025 03:35:16 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3A4DE19560B0;
	Fri, 28 Nov 2025 03:35:08 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v4 12/12] mm/kasan: make kasan=on|off take effect for all three modes
Date: Fri, 28 Nov 2025 11:33:20 +0800
Message-ID: <20251128033320.1349620-13-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TyGbnDTk;
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

Now everything is ready, set kasan=off can disable kasan for all
three modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index b05ec6329fbe..b33c92cc6bd8 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,6 +4,7 @@
 
 #include <linux/static_key.h>
 
+#ifdef CONFIG_KASAN
 extern bool kasan_arg_disabled;
 
 /*
@@ -12,7 +13,6 @@ extern bool kasan_arg_disabled;
  */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
 /*
  * Runtime control for shadow memory initialization or HW_TAGS mode.
  * Uses static key for architectures that need deferred KASAN or HW_TAGS.
@@ -30,7 +30,7 @@ static inline void kasan_enable(void)
 /* For architectures that can enable KASAN early, use compile-time check. */
 static __always_inline bool kasan_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return false;
 }
 
 static inline void kasan_enable(void) {}
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-13-bhe%40redhat.com.
