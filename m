Return-Path: <kasan-dev+bncBAABB5NK3HWQKGQEX4NBTXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 07298E6AE1
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 03:41:59 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id n17sf3132316ybm.19
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Oct 2019 19:41:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572230518; cv=pass;
        d=google.com; s=arc-20160816;
        b=p8d7QeRhCITCvFOnVZCWYpjehj47ZDrK3pDXk0vkTQOOhTLflqnTT2Y2BuePKE8sro
         FP1H9vwbJ+ZJo+YZAYOGdzggwJwibb3ZcJIvdAI0hTTY5FjD005MkofqgiL0r5P/Bcbx
         UH5FcP/nFRApFNbIBsKjZXQ+Zage9zhfhEpe3FEt0jGBk+/k54M2wM6xxuY29bbcU9n9
         ZGMblPOfgRvijqhLI6YLyRQlnBwhBBkCPjs4dKSUuPX0wvFNht4fYWssOXOZErNyqzxq
         0HxpJ+smPCREFVWry1gl/uy2dDMuZ2XeNOhS9GXCQ7zWJRp+FwjHQAA57xz2mVr8HCRq
         TkXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ggUtGVjmyfKmhtzECf7tbuJ1Y0DN37AqK59efcrCguQ=;
        b=gXShb73fTdd3XZVMEp8Z6NDnlIfyJ9n2mQXbtg5ymNenR1VWMJqlU0I2d2PODY4mEa
         woKiRvgn3Cv0d0PkAixtS0B2If8WHH7lcpK7R1plcyGlkrO9KdLpCCuYmFLTLBAjuEM/
         iHu5CCbjGGlI5XD9T5CVxmTH7ejUME3r3m1SPEoy9kwrGfdBzUgPqd5NoJMjO6nBSPfk
         kd3HJybd85GtVqlQ6gUjNPMnfLUg9pTcD3ZZ0zgSpj3YRRB/DoFApZI9iRMOXuE2/Gau
         iyW/vF2zIfrC6MlYDDq3yAmtwwYzfiVrbDHN3vUhHWc2TwQwv8rI6h5euzQSuTCSXBhg
         wedQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ggUtGVjmyfKmhtzECf7tbuJ1Y0DN37AqK59efcrCguQ=;
        b=HHhla0XOtYenyxl/RTdbtKyTPmro7/bWtUHued2UJLABOp5znHQ6HiRCMiMMIuEEQb
         ZeDOuwLjxJggb6WwhIl4K9P/EkobAl4lXztCE5xXiQXfWBmy5mq+tqYaElm6sn+LJH+9
         j1ccJp5lYVUO8E1ItNVTRQo8iwjHw5PZbbIWavK90+m9xzGj06PCAl7yB8oNpK3qg1U2
         GVZ4cBccF62SA06VSMmPN3ED7ZAU5GBOGui5HJyhJF3B1VLKcx/R+vxQGDZ6/1Ls1osC
         fVUASsDdAPQL2hd+NIx75WpucJjrClPGkbSg+PovNOLRPSbKh14O9eH8IQq3D8bHkVrO
         fkSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ggUtGVjmyfKmhtzECf7tbuJ1Y0DN37AqK59efcrCguQ=;
        b=My6d2Y5yb4m7YsYLI1iqnRE73rVeZfg46ng06ya5UtxLdPR+rpmVmOHfs9VqXgfQ4E
         6P/GNNfVLd4Tc41GqbL4LvUmrwEg3BtICzEJtQBaRkkHGjj5oPUwzkvqZxJyidOmztd9
         b6fKkshcCpJgao0jyPwl3QW0pTgiyjy+RB4Q9oVH8VxerbHGO59DZrEwx/OwEJ3Tlwir
         tQw00Tp2uNznpszVAK5wveWkqOmMi3Hggpi8mSq8g1JflhHKvc4qjw6RV3i/8yLNvuxY
         zqViGeuxOdqUDyH13CAT8+Cr0MYi0cqp+Z83nZCCbNG6tTi+4Va92d+vVQ1YCO2Jdot8
         jOgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUlY4fhskYa7c3M98bGcnStZkf6I/wS3lvogMVFiIXZWjdYIcZv
	U1OfsHap1Uaw0LUPj3MqGn0=
X-Google-Smtp-Source: APXvYqy58yahEqbS0992mJ1iFAVOUU9QZHvvWn0isUTHETceL6/TCE4GtpZtIIy1rxT4Efjkypp21w==
X-Received: by 2002:a25:af4c:: with SMTP id c12mr6076337ybj.303.1572230517772;
        Sun, 27 Oct 2019 19:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5748:: with SMTP id l69ls2322347ywb.11.gmail; Sun, 27
 Oct 2019 19:41:57 -0700 (PDT)
X-Received: by 2002:a81:a885:: with SMTP id f127mr11079963ywh.93.1572230517089;
        Sun, 27 Oct 2019 19:41:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572230517; cv=none;
        d=google.com; s=arc-20160816;
        b=YBvlCsTJX2PPWtWehsqRfO2cSUt/ua73wD4h4RkOkCi26m5hIThYPKjFeuVPlzSMQD
         nd+6Xa8yq67GyMS58ZovxCcy3pzuTuqWDS/6MnloqKLRK8tBno9BmASCUUM+YxyVQ7IV
         jt2f65HiHElA78WxSTJuLFurHwCtD9mvIshQov+HeWn7tJtLlpBeg48LM/JC94nHET6k
         QrnAkUwRKFk1EEoogDdCG7A0ijRORskcb+hPM0pLlECPcNXJNMlgsWnGFhgcGcnMcRcl
         vnJlfY+86rBNqJbp0Db6vgP6EwapUW//F7ZBTnn7g7U4D/jwkWOdpNyXR/5j0IVEFxWy
         mC9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=iYYolFveJ8Akyde49pJssUyPk948d0RgcLFdsLc7XdQ=;
        b=WTiEqjcxRLI+glciYE1MS+HjqW/aLXTpkRh1ANVCNRI8EmdKpxWOeh3Khr0lVvZ2D7
         xclbV2s1aBJ6i/iBARxPHkVjOIbH7Lg2x6FvBtCVh6PFqSWSi9uumNKpRDRosOIKpGAd
         oNP+TgYAlRTTMggQ7vqKIO+Yph8q8JVLTLSyXJzvrGt64pvJSvxO0uOgSikbjcwxnP2p
         qF/fxWrW3FHmO3t8kxgaQhdUfnWMSRyV9c4oPTQW9lSQ7o8y2gBqi1V1n5v2X+OJM0sQ
         YlNWXSb+NOZ6jgGJB0Cvh2VjbcM1kMY6G8OThsMikaqdj1Q/G0O/PwIlmOpT9EgG5VVG
         J4DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id r9si557831ybc.0.2019.10.27.19.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Oct 2019 19:41:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9S2O9tf087229;
	Mon, 28 Oct 2019 10:24:09 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Mon, 28 Oct 2019
 10:41:38 +0800
From: Nick Hu <nickhu@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <corbet@lwn.net>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <alankao@andestech.com>,
        <Anup.Patel@wdc.com>, <atish.patra@wdc.com>,
        <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <linux-mm@kvack.org>, <green.hu@gmail.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v4 1/3] kasan: No KASAN's memmove check if archs don't have it.
Date: Mon, 28 Oct 2019 10:40:59 +0800
Message-ID: <20191028024101.26655-2-nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <20191028024101.26655-1-nickhu@andestech.com>
References: <20191028024101.26655-1-nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9S2O9tf087229
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

If archs don't have memmove then the C implementation from lib/string.c is used,
and then it's instrumented by compiler. So there is no need to add KASAN's
memmove to manual checks.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 mm/kasan/common.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..897f9520bab3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
 	return __memset(addr, c, len);
 }
 
+#ifdef __HAVE_ARCH_MEMMOVE
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
@@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
 
 	return __memmove(dest, src, len);
 }
+#endif
 
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191028024101.26655-2-nickhu%40andestech.com.
