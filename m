Return-Path: <kasan-dev+bncBDHK3V5WYIERBDFETKIAMGQEYZTKYPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0104B2AAE
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:42:52 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id w26-20020adf8bda000000b001e33dbc525csf4023769wra.18
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:42:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597772; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6ej+WLrXRqwVEQxZKrFTwuiTSM7OBGx6hJzZzDC6zyPFytZIQ8VBHoR4kP/ppKiEZ
         7zARpIMPQPMCZXP/bQCutc4er4jE/3MfcUvJL0cnZ1p+EyMnCB5M1uwYLOeDGews0y/F
         tbvJDGhsKjI0get6RRNBGylPv9mxg3jNj397VauW/QW+pOufYbZ3cAyUL05evuxv1YG2
         gq40j0ga4grV6QUw2N1QanEjE9OCF6YHrRJbPsQHxlngH/QSzSGtdT2x/zyTKVc5VDnT
         X3T7i7sczodXuJuZQ1MEnykfV3zHCm0fWBbwxG13Y4sNtnJbgwTRTbH0LmOb2YXDASA4
         uLtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tPDfFgYMd8+9aQJT2i1nhW1Pxze/X/GQFsABTX0AchQ=;
        b=jk7X6CKOA4xPpZJcYIKqrki3Z974UlsVDoN7mrk8vdO8TuVNyOZP07m5KiSKYxt9xd
         xCt5zkwmTv6wcHEfC0DdCJicrxu8tKX97a2Zx8HYSb2RpAr5rl980gVDa4qD89AowgjA
         tdN1sSxt9iiNB0HJvjZ8+BouSLRAdl2uC7zvtPS0cry4VBQy7msdwVAvlozxkcULAAja
         0brpMZYLibuzh+uztuqxVmOPlZFqokuGu8c7/Yjgx5Oy3guEpOTU03XUqjfqxF2PFld/
         MpKyStOxjvjf19eVldrpFcY5oH5ov+2Q7cuLB6teGtnLa95jQotGI/U/yjizPhSRNScv
         Dkmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CL6Jlbne;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tPDfFgYMd8+9aQJT2i1nhW1Pxze/X/GQFsABTX0AchQ=;
        b=DnkPDOTWlRY3A/xS83nijg2ePqcxNYfGuI5/PqgpAHkhESYHUhq0UwEVF1Tq1J9EMK
         lJEAicNS8TRnx4FU78oeIhWJ8YBiiFBWZSOVHRY3HF0AwyhoGsQSQroE12VHWpwGsq3k
         EG54PDsT4w7vqJS6NakpxeCXiy5aAMCbJgjgHfdooyaAQp0ewQAIPGecsWn0eevq93/B
         HL0EW6ZacXJw4M3wnJaVlg+XxRMeW8UI6TwVW5JYXnOgVueaCX9vXa/38UDTHrtl5Vi4
         JAk6cDz7VDJUs2fRkKp63YKD9xGRzfstXSMVHiJ/dm0Z9IuDcRbkf+8IsHsQesn1Dhjl
         mlSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tPDfFgYMd8+9aQJT2i1nhW1Pxze/X/GQFsABTX0AchQ=;
        b=EKRSKMKlTRhwbdUsT++E1eHg2b17O/ZWvT/8HJiuFnd2fCyc9I1QkjfqSVCr043Fls
         X/uvpvU16orHXmUovxU2vg0XBxK1KEa0ad/grydsvMX8xxOzHkhcgpuWMRMh9wCTzo83
         mCJDt6u+30wdUdU/oEOa2k1qcyCYhP/V6Kiwb9oREAjSE3bkbH4V2HSzJN9aJR4dFNfI
         361V/SjuFrig9j0cHWM6XGYiBQrMETxLL8OrMDIs3QXSdc1HRc0vaVO2XjpVjwJaC4Yt
         /+Xwu8wyK4z7RjsVTwAk80Qt1QfrNIeXgxshZs9zIl9DH9x1z46mSC4BmNsOlJ7DqXVm
         A5dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309uQWH3KUJHJ2Ya6MuDd7KNkL6BGCPxiOZ1VAaPoDPwo4OCCG5
	QnfiQHwvQIB2uTbtzdGXWRs=
X-Google-Smtp-Source: ABdhPJzehwvBGRj4m4eHyZmGd/V5al7K3ctb2tmEqMDEjWd06f/uQ0JL3vbUBmOkqoEnnUeaBMBuTA==
X-Received: by 2002:adf:d230:: with SMTP id k16mr2023580wrh.196.1644597772466;
        Fri, 11 Feb 2022 08:42:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3596:: with SMTP id p22ls2853003wmq.3.canary-gmail;
 Fri, 11 Feb 2022 08:42:51 -0800 (PST)
X-Received: by 2002:a5d:514d:: with SMTP id u13mr2005065wrt.352.1644597771654;
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597771; cv=none;
        d=google.com; s=arc-20160816;
        b=cjx2cVLhh1PqbxpPpI7LoP3AfLme0l6+E2lCON8V7UxvRcbnVL6BCbfxDqZfp8Zfv2
         ZdBNAYMnA3kza7MJGtI3hiqS/mZMSWKaNWRWmGPReeHVGDy2iGo9npM9yUdrV7EpwEbg
         4qkzdgYktoShN7YDPkzx0ss//cUdsJvskmvBD3hMyRtOGTJ9WZFiWSOOXxO7uNjTLRez
         KeN9YkO5Cvv9kd2iVugRDie7S11rX70npkUMhwL9CQ6aLYdv5NsBbIb7uZD+zwmPXDnA
         0hTwnckmpTNYtuLtZVCr+DA7xWAbtl+evQ9q03U9AfduIumVKplzULHSOT1geWaCpWoh
         2Qcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rYp/F1vbxbLivUF65w2maaWuA20v5CCQAIJDPT6o8JY=;
        b=lyGvO/XIuYhCIm27wgiv4uWshmEFaxme7j0FKXzPGQtyk7GmbCFNF38g+9il6q1y57
         K0WcHF3IE0YCBU53QUnP1LyDfSAWnFAZwJ46x2YOwAJaTsw3QlGwJj/1ziTk4WGC8JHr
         x+2uOdMMJCyIThgU1C+D12H816F7sJWr/J7ByIzdVemhepQk+lRgPs4je3IHPtYMS6mn
         aaWIGsiLNgTcVQf2S9QRiSBo1vHJOt6dg1suuShId+bT8lPjdZ7Ch/ipy4/Es0F0uKB9
         Oz1t2wMuf00Istb6HkG3arHQwW0DzhEHdWnRMms+iOcwd6G8xn//lzm3YfnM/+To9Zct
         HqGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CL6Jlbne;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id o19si459730wme.1.2022.02.11.08.42.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id u20so19805589ejx.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:42:51 -0800 (PST)
X-Received: by 2002:a17:907:6d1b:: with SMTP id sa27mr2076137ejc.166.1644597771403;
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id i24sm4981233edt.86.2022.02.11.08.42.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v6 6/6] apparmor: test: Use NULL macros
Date: Fri, 11 Feb 2022 17:42:46 +0100
Message-Id: <20220211164246.410079-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211164246.410079-1-ribalda@chromium.org>
References: <20220211164246.410079-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=CL6Jlbne;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d
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

Acked-by: Daniel Latypov <dlatypov@google.com>
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
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211164246.410079-6-ribalda%40chromium.org.
