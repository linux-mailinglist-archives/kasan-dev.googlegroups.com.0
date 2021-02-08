Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBS62QWAQMGQESCNVUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id CC176313A31
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:44 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id o20sf11199462pgu.16
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803403; cv=pass;
        d=google.com; s=arc-20160816;
        b=gi+5DZiE0KpHeYIHk8vqD6eOIIVo7AWnfLB+IRdxDBp1yD0u0z1BZH+akeOj7Nas9G
         U6+OzntRbyQ9UCOdFRtgQ9TQcTR39NNWl4krKsPZccub0RTQ62enUIkZBlABruD/U9d0
         GVtB97QsajxwXqwx7ZS/om6U8/suxpHfQI/ph7xX26axfE3ZykXb2JCVi6CUlcbGKGif
         +x815Aas6DRUdxHDrsGZzLvwsBHOx91jpka7e9SSsr8eN8e5NU1D/NySYHzeX29+IVpP
         DYEd/JpDEMmx7gLiK/UKA9mM+C5mnaLdN2LRlqMOKR5tfHJUnQIjom34Nxn1cmKMjcsR
         jdSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j2jRU+KA90EL0b4NDeE3zf2qPcjQhPk8E9q9O51GMbE=;
        b=LN1UKWyGVKPqORaLosTAtcsofmecdvE+lZWfSDqvSd7LL6gBTWvYkIu2KIZu227pKR
         0ziZMoohU+JhbbHDY3h0gkSLZh4FImEfPlkC/zS09jJE3oOzjqqVZVSyrquo3l61RYPT
         0p9+BpC74z6rCYTTJbOAJr+8GgZ/BzBeGw/YHW7LNMkybPvuptYd359/hbVzsXirAZko
         xa3VMBfwEXj5E6p/Ly+1A2tMtX6IQC3n+PR/pkAdIahk2nAbjiUkvoAnkuKwwcjMgRye
         8259AHvsJzD9NnjIrnsfLDTvVECmVqY5Sc5QR9mD4wetDburVPsVZikflz96AuT+zuSN
         rFJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j2jRU+KA90EL0b4NDeE3zf2qPcjQhPk8E9q9O51GMbE=;
        b=J0ilau/61lrlRCln8SQx/RNO9hCLEgrJ4HzfbdasAPsE7fjETmjAM6hCbF0z13g0+F
         yvt4JwErwr8ScW8R+fWM9xTtndYQBE7Q+bZ2H0K4Y5aFeI1SL4x6+1dKYGA25N6p3is/
         KMiF3xBcRqGGtZyxbxsk5BnWzQMEdmNYbMhlhewlffomOMH33D3bwtdFlWr4z1yrkxTx
         j1xn29a5gOvIisPKQdfePHl/ynKc5tX8QibAAbvpiMFpAMN/S1ILwXji1m3BYyf4yK8y
         WBD8Qmjmn7qoeXaCeN6QaEx4iLwk7vrQpF5HygGqUX/o7Bi7eL3hY9E6J2xoZKMVt1dM
         e4Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j2jRU+KA90EL0b4NDeE3zf2qPcjQhPk8E9q9O51GMbE=;
        b=iX33gqbbScy4kTFyoYf/ertTuYnhESJuy2dV8ed8R14xn456cllb7qgvv0iMZnO1AA
         xoUsr3wnXPIQfn6UAPTFR8BvCet8oa2vzlkpLmSCDDARLeK1J8a8DecFgc+ji6tGHB7D
         PO5g9IdwABPoiQjcuPkKpCCh5+G1ZWKBRAcsxQcf0BkwmSwjTzRFW3BICG1MTEieOwlY
         HbAql8G6idbogs2oelOOJY4ZYYt8xkK9ONSXS4+DaUyZ1CUAr6eZ5L837U2186rD+9Uu
         ghbrpFZyQ1sOZjp1XXPVeUqKxCea5kna8GGpQB3GuEGaUHyGyyfCeMNbwhVVnXOZc7Pi
         Iiyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532N6iyM3avxWrdE0NySI+5n4slZQgPtMF/eg6kjqBoc7UuEqDAT
	Iqg1OaSxhuyItkV70AhipUQ=
X-Google-Smtp-Source: ABdhPJz5K3mpANMQ204pSm8bvI8kcj1qADG4ERMRYsBEy1ehm+4ZlScVxKrV1kTDRMqHLPPtOfWBWw==
X-Received: by 2002:a17:90b:110c:: with SMTP id gi12mr5916335pjb.48.1612803403603;
        Mon, 08 Feb 2021 08:56:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c1:: with SMTP id e1ls8110605plh.10.gmail; Mon, 08
 Feb 2021 08:56:43 -0800 (PST)
X-Received: by 2002:a17:902:c242:b029:e1:8332:f14e with SMTP id 2-20020a170902c242b02900e18332f14emr17184484plg.41.1612803402963;
        Mon, 08 Feb 2021 08:56:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803402; cv=none;
        d=google.com; s=arc-20160816;
        b=aA+m8OB2v33nkZIN87HfQGIrNvt4j0PAfBzxMLmATLqx6Xko4uxzhXxdPLpoGTZOEi
         jMSlpjteqBznVDIwnY4qoGdZESIy0D47RzbQfKuBMumvP9erW8YDhBIaD6hzq6UBapCI
         QNFqX0IkA9037sbrqnpWdtBToqR1IwLZEJmcI7aCh+VbJUVW4QZ157hwsGOQE4cl0lBR
         BKQNPSilqrS2212mhqTGo5xCkOCy30ACCvIqVlJ0raM/BrW7Fgj9GRvPsjd4GUfbwQNX
         JZJJlVETWM0USZkjjxq+oBush8jfdQmwsT/tz6Y7Qef4jdbu+/UqVGSAqvDoon3a4LnJ
         daWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=66NUF2svl3NXghVPiBBpnsWX+ldmFm+jrfwDBc8eS1o=;
        b=JQLZRusFHgGw+2NANcVBLpl9aJn8nJVQOkkwj2y7O8deJ/pAo1vUXbEc0x8HkULada
         s6dHdBebGSbynR84PFm89Oy7AGl28sm17LGSf+GMk+yg2YwOn5HVPae7Zeiiv7H4rT1f
         UGwuIBkOSej2KVJrqaxU/xzN/pxHK3KetVhX5+v8Mfet2lzGi5cEL5BSrYcwakpgP1MH
         bnjIs1cYw3Fu841iEPRaBzmZBQQV5s9am6Bu6ICgosNilQMxJTUn5PKTrYn/U5T8bGSt
         kT3egMkcwVoM9+uFJEbt036BgtcqVy4jwrl4mIQU+rlZTKZGIkvKg2mu2R0w/oxZ+4l0
         nPXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id kk5si408601pjb.1.2021.02.08.08.56.42
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2E53F142F;
	Mon,  8 Feb 2021 08:56:42 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4D12A3F719;
	Mon,  8 Feb 2021 08:56:40 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v12 7/7] kasan: don't run tests in async mode
Date: Mon,  8 Feb 2021 16:56:17 +0000
Message-Id: <20210208165617.9977-8-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Asynchronous KASAN mode doesn't guarantee that a tag fault will be
detected immediately and causes tests to fail. Forbid running them
in asynchronous mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7285dcf9fcc1..f82d9630cae1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
 		kunit_err(test, "can't run KASAN tests with KASAN disabled");
 		return -1;
 	}
+	if (kasan_flag_async) {
+		kunit_err(test, "can't run KASAN tests in async mode");
+		return -1;
+	}
 
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-8-vincenzo.frascino%40arm.com.
