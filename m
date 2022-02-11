Return-Path: <kasan-dev+bncBDHK3V5WYIERBC5ETKIAMGQEGONAEIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D79654B2AAC
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:42:51 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id v1-20020a2e9601000000b002446a7310a1sf4214489ljh.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:42:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597771; cv=pass;
        d=google.com; s=arc-20160816;
        b=OSaib14M6ngf8RDah4R2P1UuX07S/aja5rsGpPGbPrtICG8ATgOpa31JJ/Zz7Ydxtt
         6vKu2JL3w9zdhTIwkzR0IuZ3TSOFWToVFyVlKabOfAD1AOhDIkoooa3MsNlGNFdwvtth
         l6SvKZ4KBRgN6ve104gWY1H/6D6pY2gq4gesQVW0Ys6QSaHQVDig7vLWFXDAOBxVCVGE
         Tn6A5SH+3Wm23jhGmmpRtJUZKNKs76HilDvg1Ki3QEycnSeCMZyIw/U90APlMaoNJv60
         mpTD38GcBfN7pEVGHWbq0GqbgAFKPqCKU+Sr3LCJkjNEaTxFPVVWrNQ71uUim+GbKSEi
         oSmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yHK6DZTtEqlaHds2zwlpozcgR1QD9Exk/dGKfqqLjUo=;
        b=K51kkDtbgOoQsAWgv0ezv32KXoGEHwUSLCoxJJoAe1D/2yuY9EwG7u71EGAXGWMRL4
         k67+OsRx6P8h6mVLztyCccCxjIi/1yEN2SnWjnfodmhEm65PaRO6xvYdjelySEBqkTco
         PYPdfE5GeAc1Yy+u0AQw3vhDGGuoSVe+4Wt66DOepjAoT69Fp4JWyo5Pv8OwX8hPKE7j
         DZEMU5+PYiZqYM6qPZviC+s0ard5HgtzFCcwTxDMxA3T8wI1Ef054hRruYqP4ak40RuJ
         PRv94lPlHJmBOzB0oTcmXDXRqFXnI0ZRj7BkQdhKY09EfL+XqBJaJZ3UucHnYfj5hbYZ
         wSJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lzPfOcHo;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHK6DZTtEqlaHds2zwlpozcgR1QD9Exk/dGKfqqLjUo=;
        b=MbMyVcvBOepWGC7a+uMM0zu6W/SRPe3UPk39YrasYktvm7lqdlL7S3AHRmTuUiSOcy
         EpYA2r8hLNvOMWz1DFCGnTLbqrG3HNGHD+fx/BvFnGG3FzB04x5Sp7ANtnYg8u+MeOc3
         fJuJ1xnQMdDj3kBB1kQKjQHW+j0v1GG96Swp4O3R250INvAppb/hGqmqf9RIzazj9ofB
         KsFX+g9GdQHEofyvStVFqJa5pbWJRJ3z4HQm7hQHnsLtZ9p0ThqCmZKAVK7j3J3njS4U
         tB/DeWzDOWiUeH70VIAuzSriZtBso/OGcDpQSB70CSLk3cgRfLIS30rLFugNojjJdINi
         WSeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHK6DZTtEqlaHds2zwlpozcgR1QD9Exk/dGKfqqLjUo=;
        b=SeyKc0NAjyQXyTYmKEp7R8GAPnfdEhb3AdZE3FuN20KnJxrMtCLd8e8zy5G+wEti/m
         GP9jhn3M4RSnmUi/4U33iJucjbdPfh/Na4VpQZJ2QsEpvQjN2zVm3ntQZ9pg0Md18TZH
         VNjlKT1Erq2cJiheArmoJ66gnBVUBqzzYi9GSfwLrJANIlbpc0Tv9W9Xm71JfLqkHTxw
         4+bvv5vd4tlvGqhxISHgcecL9l1X02QoTgfKPWF7lgxEwHSbKbZCCMqncWq02P24wK5J
         RMN4nnraD+A6ISka22zVuOKnaf/0I1Chlo8QpU5YCi13eIZv0cnMXnLX2V0FflBbvM0N
         6JQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xZfBfvrxrdSNbwrcVAzUyy8qpJmtSJi8MepTEBsUmVVsSxWtd
	msC5tKIXyLgxGm9J426x+mY=
X-Google-Smtp-Source: ABdhPJyhDS6F2ACrvaLJwpvCvyUp0xvtZG7iSGCqyp/8MK6xvYh6wsKTjMLHEEMR6cc7OylgWNuDcA==
X-Received: by 2002:a2e:b891:: with SMTP id r17mr1556852ljp.306.1644597771441;
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls305477lfr.1.gmail; Fri, 11 Feb
 2022 08:42:50 -0800 (PST)
X-Received: by 2002:a05:6512:ea6:: with SMTP id bi38mr1712512lfb.377.1644597770468;
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597770; cv=none;
        d=google.com; s=arc-20160816;
        b=e4SibeatRyRiShUMg7AQ034HothEeSqFYQuUOLVaWvKZuF9Ik662LmbCbEUy7o2aqV
         LuracuC9hkOrMsqAzRMEspPgj4VPGbUmbZ0FllGJ9cxnKHfF1ruFGm7Uhtdr7v8YjSyG
         mGyO/s+u0W7LShVFHQwwtYs5AKSy2JTykRrCCyRzLtR+PRRnCevXqJpBPz7zPoYImMBZ
         nGBCWeBiEhisbq7Joh0i2pPyOVnNX4iR/LVKxLa2pwVuV/IxwE1I3lhLZlWyeD0jRS7e
         MTMnYSVvmOyBxN0PPhGKyhhdnzfP5hGdyfcplX0wyTrOI9hOgQx7msDxuVT+dfgCMjZ1
         W8xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yxy7zthPRWHub+MPiGJfuPkSoZH4U5JEJa8lsfSBR/o=;
        b=h7pblFaZe9tWeiXy6iA146YFomQh6jn1eX7jb1MV/UBZ50OhO1ZWZM7Lf51+hVhJtG
         gLHed+L8MaCoHqQFSDfrLuOmYfau0Sd6HpxfXKubB4HLo74gyLj/61/JEEXx6scvpVpH
         afls2YnEieRR5QVHdl31VcY/xoGKC6DmL05Mi55fN3upBFf5QYWIXjwhioYkPz+D5tFM
         4wfX/BnPAROUJ2/zXbLknLFuZ1X88LrHh3nm8oZ4tBHVVYpVaOQY29VGaXDbyb7hYzbP
         o05ghcx4b4Pm80t3j7DARkV4VkWAQm59z9VweuMHBcldj7kTp+vfL/fd9/0EAQpu0CG8
         HP8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lzPfOcHo;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id z2si910827ljh.2.2022.02.11.08.42.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id b13so17513362edn.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:42:50 -0800 (PST)
X-Received: by 2002:a05:6402:27c9:: with SMTP id c9mr2876049ede.178.1644597770279;
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id i24sm4981233edt.86.2022.02.11.08.42.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v6 4/6] kasan: test: Use NULL macros
Date: Fri, 11 Feb 2022 17:42:44 +0100
Message-Id: <20220211164246.410079-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211164246.410079-1-ribalda@chromium.org>
References: <20220211164246.410079-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lzPfOcHo;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace PTR_EQ checks with the more idiomatic and specific NULL macros.

Acked-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 847cdbefab46..d680f46740b8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -385,7 +385,7 @@ static void krealloc_uaf(struct kunit *test)
 	kfree(ptr1);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
-	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
+	KUNIT_ASSERT_NULL(test, ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
 }
 
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211164246.410079-4-ribalda%40chromium.org.
