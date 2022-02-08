Return-Path: <kasan-dev+bncBDHK3V5WYIERB35PRGIAMGQEGUUSYOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E8194AD7BD
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 12:45:52 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id bd23-20020a05651c169700b0023bc6f845besf5997378ljb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 03:45:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644320752; cv=pass;
        d=google.com; s=arc-20160816;
        b=uB8nmyHtyaTgGi83FpsZuqZi8nHbwL3KsmnHRnKdzGbk8512CmmuoBUEos3q5J45P0
         inbEX43DOZSgzeBWCBhmlH2sgbAh9v2SOVAZO/giCTMDc3OzlckkJhcfwsYhdmoBIODv
         iSVeI+XJ1zbLFMZBZ4IYC54PX4USYG/9/gxLZUJWSUCL61Xmj7OOEPDbDjzLGAPzF1NT
         Vo/nR74Zht4KaMW+siUMaleyEXLQVKLJxkS59jkQZ0NmF/4/3QVjS1lhxldicr9T/0jY
         mpqg0/2P+nk0eNM3VtRfs6k0ym8+Cq21YCN37ahRPowEi/Z+HJUANvL55zUdcZHh1Gzx
         lcwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KEeFTsdnC2BZ67h/7xv4QxXmA8MFal1Hi8Dcnobg510=;
        b=nkzmpfOVqGN0nVTJ6PSmA7BHdZLu27cbBhBzHeMERDK1oJcOJGacb5b6dDinf4oNwN
         8snFd9W+CsdFV/pbd2HY6WXhJIHXlvWULQM6Hk7Rrebei30j0UgdBdz3c/XCbQ0gYd0V
         mA8hjx2qQRwGLOuVjXnSpbYbZKQARwygIAK+NPdPoJWbtgr+DM4TZkVzaUzE/jtXyqTB
         dYp9LE+WSj+ei4cIiY/mc0ziFGfPuWt0AP/T3K52VtbudJWpjKs6uBWKR+as2yuuFjaw
         Tkgj8rj2yGOTn7KYjBI64KW41r+qTy+oORSSYrg0j8qEoQmShyWG0471IoZCNPweHPKc
         u3oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dIU94/X3";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KEeFTsdnC2BZ67h/7xv4QxXmA8MFal1Hi8Dcnobg510=;
        b=i2xODaMHio7WviDly1844SRjWeZG2yiJcPT7s6sMXfBNaOdU2o29hA4oIIbizkCy7V
         lZa36rsTEgUS0Qfb+PHmgNvmhHCkCqFZBRol08UJyS91HxJq63RuKSaHdLpSkL0o/RYT
         5eRPpBy/OvuQRjg2dJmSBhneANv2sZ8DDdrFlREfryICAB3BnrLYOksDz1Uf7r7A53cH
         dJS91Oqqfw+5OCOJH4eFz6pAUQk4df20DEDASsxYJEGxFn6py1jzA3OgwnD6zmRziVrJ
         WqCg6/XI6R9PVYhWoaTJ/w3/A62E3rTTy3TsWfDrlZh8tlnOISG44HnNbNXfNOjvMsLM
         WgPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KEeFTsdnC2BZ67h/7xv4QxXmA8MFal1Hi8Dcnobg510=;
        b=RWq6skB7PPWH0LQYlXZg1Dw8cz2RBOExz9MJ93NMz5ndX4OMwrbk4PuNL7138wmJlV
         /Hz05KlmjUY3pPbin06bbX249IBwJRPKpNlG7Rjy1xDT47R7cN1JJ8MTQG4+pma+1Dnz
         XTV3ccLFhISnLox3zFQrUzOWzZW0T6Z89XQNkl7xCacQ/hHNFcFeLP0qvm7R5gjzeFTO
         M0i4WFzIJ042rCtO6YO+Y7VXnoLOZDKH4O6HCozQrbp0tYLy4hAF4NjUaUKIdtlfQ/Zn
         wAXlozHQq3DSRmRlvdGAK5DCB8TNXTIVPEWLh65WXzFzowd8FB8B01M5fncgrhcyH1Po
         4NxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tVSR1MsCWOcuCBh2LdCRkEXpWLafCSF2+byi0atWu+YPHdlTL
	v3Ag6VZ6Aooe24n296DxEQg=
X-Google-Smtp-Source: ABdhPJzoRBiV0H3/WXu3ReKXUfGbql5KJiuwk+L9EatrVTzU8RrB5KlwNnDdp/gkSDx2qZ6ZjqlFjw==
X-Received: by 2002:a05:6512:159e:: with SMTP id bp30mr2802063lfb.324.1644320751801;
        Tue, 08 Feb 2022 03:45:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls7704766lfr.1.gmail; Tue, 08 Feb
 2022 03:45:50 -0800 (PST)
X-Received: by 2002:a05:6512:1382:: with SMTP id p2mr2805777lfa.0.1644320750849;
        Tue, 08 Feb 2022 03:45:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644320750; cv=none;
        d=google.com; s=arc-20160816;
        b=WathZJhHuMCOYb5yZY5+o/5qANSfgBxZQbTyqT+uiJF1k4An9qtrYp64J5cs8VESML
         hWdWC2S5Ms86EYcQ8xVdsdK9ryaHH+V9o8kSVC/TAFz42AOinJ2cK7vx8hGoU+rCvO/0
         ILrGAHCQcra6TrdoD/ptGmZYaFpbkuaCNY3Vd2NNtW8Khsc7vpilqxaJMNsijwK0FMI7
         nOZIxyEvS87LxCI3rkauvwQXZMbtSvhCwyDY9A5fPD/iIEUQcoPftS7D7zb8bHK6F4z/
         C/VsLayEjszIj4krVUrVW0LsVvp4W7ZdFV/FF/+jSSl7v654hZ9/4SnRYMKHQ/7FeOMb
         MyZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HihT2WHm5CL9KTfiGWQaowQJbGra0dr2IasABIBxyUw=;
        b=LncarGm4YAXZHzltTYnI4jdGeyBjF60x1Ar9Fk7a8NHV7pE+DbJuf9nzv+SKIo/pVg
         MgECLljL1jkr72G1PeCof+0zGqVKHVWrF2v5nxQn2ZIUoT8DNLowAQXoQZdDHZpsjOp6
         AKjcoKikQa+AVKDNGUDVNVzriuxVUbMt4XxFcXfjBiMXEtgqL+M5/YipYpAQ2n1xegPD
         aCnAmvR+2Tzelm/UaUWAPA7BL6J9HVtPd5loB7ZKlBSddkdp0d5FePPP80xcHLOGA1G9
         pv/BoT2xzmVresWGI8nWDuQ39V/RLfq5CuCIcbS96tJFwlHVWoc03N+QA9ohwb9Z3vK3
         X3zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dIU94/X3";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id o24si760519lfb.1.2022.02.08.03.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 03:45:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id y3so30630761ejf.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 03:45:50 -0800 (PST)
X-Received: by 2002:a17:907:c27:: with SMTP id ga39mr3323524ejc.626.1644320749345;
        Tue, 08 Feb 2022 03:45:49 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:5d0f:d242:ddbf:a8a6])
        by smtp.gmail.com with ESMTPSA id y2sm4151902edt.54.2022.02.08.03.45.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Feb 2022 03:45:49 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v4 6/6] apparmor: test: Use NULL macros
Date: Tue,  8 Feb 2022 12:45:41 +0100
Message-Id: <20220208114541.2046909-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220208114541.2046909-1-ribalda@chromium.org>
References: <20220208114541.2046909-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="dIU94/X3";       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630
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

Replace the PTR_EQ NULL checks with the more idiomatic and specific NULL
macros.

Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 security/apparmor/policy_unpack_test.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/security/apparmor/policy_unpack_test.c b/security/apparmor/policy_unpack_test.c
index 533137f45361..5c18d2f19862 100644
--- a/security/apparmor/policy_unpack_test.c
+++ b/security/apparmor/policy_unpack_test.c
@@ -313,7 +313,7 @@ static void policy_unpack_test_unpack_strdup_out_of_bounds(struct kunit *test)
 	size = unpack_strdup(puf->e, &string, TEST_STRING_NAME);
 
 	KUNIT_EXPECT_EQ(test, size, 0);
-	KUNIT_EXPECT_PTR_EQ(test, string, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, string);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
 }
 
@@ -409,7 +409,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_1(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->end - 1);
 }
 
@@ -431,7 +431,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_2(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->start + TEST_U16_OFFSET);
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220208114541.2046909-6-ribalda%40chromium.org.
