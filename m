Return-Path: <kasan-dev+bncBDHK3V5WYIERBFUWQ2IAMGQED74SJCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 898644ACAF9
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:11:51 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id m13-20020a2e97cd000000b0023e09d49ce4sf5010133ljj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:11:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644268311; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGzXlzweewGY0CKyFOP1l34XXR+ySGxKCtf1bG82AILsiZTdjeDnQP1yHTBTCLxrbO
         f3U1ryKAixivSVSpeMDbuLPFxdohlYc8Lr5cIbSIlK3xjxvLIII+ye5JN4KUe67SLTwT
         Gy3XE3D2QQyf25BaC7ZknmOUdTxd6NTYtQ2/+xap4d9oHLKaYybGYY4ACb01oV1+LJPT
         0WiNWrcpY0M6tyQTTdg2hZO/7GQvApzo680JVVfbIyhS0yNooFgQVgI2MXkFtKAOInRg
         qkmJEJ0/AjESoUerDRqFqbMAD+nLV0X0HR9mloJ3QOQ+H1QqSTQjwrFKs5bq33yMTHl2
         crEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JgG9TJ55dFym+o3Pu0BFsSCRWydDRINBeiWuxGFFBE0=;
        b=Sv2geXDE5+ZoiuLJyK478Gb0mVcClTbe5ead3tGrf3YVBm6IQmxEdBjMwEc8am5rGy
         oCdGUcXt+uyW99piBuwszGwwdmHXoDAYReTeyaikRVUf+GApEKWWrcnld5KOvwHDcVIv
         5xKCScFnkYg1QXIA7IrVq1DtzKWfZ46VJcrosanFlL2H7OrRgtEGyMLybmAJX1SBrsiP
         /6C7c02vFd6+LS/BeyrFyu7zMmhPq6ZtSkRSHrRaWmRgOHM+7dNYVB3rpWbsYcXnr9D3
         BAqiTT1myKN6iJJmMMoNx+xRk3FOFzmzving608von15Ems6nW0AUglBF/+iP3L8XIOP
         gMag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=alaweuer;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgG9TJ55dFym+o3Pu0BFsSCRWydDRINBeiWuxGFFBE0=;
        b=fkqacVBa+iHs8Uge7ac7okd8PcSikWj3VqNoJOP7RgLfaYb3CSLqYb7zupiVsP0wXZ
         gVLbcd8MAmnYrYcKK5PVHTyqJnfMRVuTUiHZRqVFUEMUnQ0oNVGPxecYqbjvgkL6oHUN
         YL9ZG4jRhj+DQcddLgC+9boS6fHim91VR3rJNps3aytQeKPC1RJw+cVJYh163Ya7X8y0
         sJVwEyGeN5h8LQ1jf0daTMmFTJt8LcmSOsTDusAbrceklHSqF2PixUyiL3nroZzhxZpT
         5Dofctb9uHb9z6MFxW2NewZaPkwQJjzJgc+QeIo9PHqfOPxhdgm7PiJkxyRCGgobY+Jz
         qXVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgG9TJ55dFym+o3Pu0BFsSCRWydDRINBeiWuxGFFBE0=;
        b=uNGdoc0uZG/JfPahYXoOddLVlb5UroWDxtgmqTg6imwUtDq1WXydShycvs2LAQIxRV
         EW0LC9Eacs1ApQvcVVD2nE47YztrOl3rCHM6jnhjru7WDk+qZEbTJLWls2MaEBpAc65H
         OIWQFH34xMhqsGiVF0dDhIKOMpRFbP5MAW7dGJvLEv0YMlrEV/OiTukZiZNPG9ahW6dp
         jkdxZ5oFD9SgmvJfrK4IfQQg/lPzdA/wTZGjFKWPnbIkqcLKyellW5ER1QN+OK+09yt4
         n9CmYN7GaSmw4oxW6NpP3Xf7D/L2PYNRe4/kK64aGTw3kwKhAkKMAcCS4CTSSiN+RWJK
         /ulA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ycL+AyNOotK7yy4bg6xDEK1c8OYtupck7khmo9WduWURaBClg
	DWAyhR3nlx5i7D7sU1oxO2A=
X-Google-Smtp-Source: ABdhPJzPdlXsjJnICM7M7LX2jPGc0c+Z/5EUuYd92GndN4TyeQQadtWKjTpvRF63Lxj9IuRszcHvdA==
X-Received: by 2002:a2e:86d8:: with SMTP id n24mr851724ljj.344.1644268311126;
        Mon, 07 Feb 2022 13:11:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ba6:: with SMTP id g38ls6465179lfv.3.gmail; Mon,
 07 Feb 2022 13:11:50 -0800 (PST)
X-Received: by 2002:a05:6512:1088:: with SMTP id j8mr911649lfg.350.1644268310319;
        Mon, 07 Feb 2022 13:11:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644268310; cv=none;
        d=google.com; s=arc-20160816;
        b=s5HBgiOvuUxQvFFsLlk59VONgjYPAOk1wD+TjOYmMaWMkNa/XeJbVQd0Ar/MdCneg8
         /BfLv8FmBCLm/pl+wCpKqQUxdq3y5yF1zdi4porh0uqkpvmOwALu4OeBMIs2tWVQDseW
         Lrka4a2FGq7dEQ9il1hoNr/Moz63KigBMpqEkNU/VOfbwmBZA6lAyqbJde5I7xRd/wGc
         4A17BD0wceUY8NKNLjlz7ETMBixaQgwNUaaJiuchiSPoH8JPq+psgasl1rYosdrH1Fiw
         Cv5eTsW0Sn/29BZ7aBNYlSXGeaTylj8vJx4z/kTI4p9hP/kv8QAAt1anI3zigCOmT3DQ
         BQoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sQV3FF5mFgBVe7Tg/aDZitfy1ByGgWInZOonbxaNvNg=;
        b=onjFG5QqO2doIkxZu/7xZaf2F0VF6xX6Y4Q4oOn9n43+TpMJ2TG59IkY8SUq71Zpqm
         HYj/G1xvzddS36Kcp6CLe8Ty/rwOOJzhCQM8UsSqcaeZnwEASwTwRN/L9x1Kb6Pndydw
         H4ntD3G3t+H/7RHi79kpfsEcn9tJrasg5v0yhO+lEVZRAc5g8nr/Ct9tR6ielIHfM1v5
         FAzlsQ7ySilkc36UjdkDSMsIrvrGJzkWtGv5YXd6Ek3Ghrdl/XzuMmeDbYLwvPK5wQ+z
         sd5r0H5ACiNis6Ux1hIHBmoielv+0cGGuY/AF4RnvuQ9FpY3GgesfnPmXy+wBbtzZcsw
         BMsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=alaweuer;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id p12si533249lji.3.2022.02.07.13.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:11:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id u18so32607454edt.6
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:11:50 -0800 (PST)
X-Received: by 2002:a05:6402:4256:: with SMTP id g22mr1394967edb.78.1644268310129;
        Mon, 07 Feb 2022 13:11:50 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id z4sm4047239ejd.39.2022.02.07.13.11.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v3 6/6] apparmor: test: Use NULL macros
Date: Mon,  7 Feb 2022 22:11:44 +0100
Message-Id: <20220207211144.1948690-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207211144.1948690-1-ribalda@chromium.org>
References: <20220207211144.1948690-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=alaweuer;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::535
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207211144.1948690-6-ribalda%40chromium.org.
