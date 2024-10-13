Return-Path: <kasan-dev+bncBDAOJ6534YNBBRMJV64AMGQE7BD2JLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B9E9C99B975
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 15:01:59 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-539ea0fcd4bsf513608e87.2
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 06:01:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728824519; cv=pass;
        d=google.com; s=arc-20240605;
        b=HuJYLtaqKXw4eUvHyvN6ky+f4gGwKx03sktAvsaZvFBS0kIlJTgDrhCG0Kk0jPsKQv
         lbiXGXPHs+scYjw5GsrDn61OKWI4A7HmU6m1j5Ue9CeeOobPNkdLOEorTK9U4BQczfMQ
         Hzce4dhRw633z9EmPX6Qhz//Tp9u4/L230W2Xg0DAhxx0op7xvE9pzEQYuUvK/a9cHs9
         d0q7gEcjmUW6N6kPqeAWiJLSstPSALXNTFAQbU1dwsmP2S2ltdDPbso6HtRkjnxGGr7E
         D52Fc0cjKckOJpzZqn7atPKlKvsGwF9bqJomKhV2Bs3ALk3bhfw8EhdJ3oeVj0ncKynP
         exSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=fnsqO3DFnaPXNVt4qzVQqHIiAaOU+OCxXV5ekZWe2fg=;
        fh=HJZ5p+vrMdOPOeaKfp3bdg62G1bYBf7WkDdHEpRRnNw=;
        b=gXtqu1H6+siqBjVMyquS6CkZTfQZJuv/T5QBwxKvh30N+wLXajD2bRyCnnPcpQIcmC
         Y+WaKZqqkfZ8jwack6FfJZIqm+8BAKqipvBQwRSKk0YfGdulN4XmooY/7jxJlaNSVzy4
         IGEFUo7cRsia80I0oAnuJxzK2OEgXNfiyRC5TMukZ+gKrEPLuTMSU289NJlYmi4Ut7Rw
         LKKccbXMF052jhMS8ZUbmeUOCkGU4SD1IbV99etsplr6egPVpTO/JuTtILyflVVcWZJV
         DoAAztH5RJEE3CHLpSmbouvoQuMwVSg4liCDm+jm9benwFScwOk8149UDYkEgV7ZUVa1
         +JNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jhsz8uHx;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728824519; x=1729429319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fnsqO3DFnaPXNVt4qzVQqHIiAaOU+OCxXV5ekZWe2fg=;
        b=S0HZBQMLziOpOhalCbiSGGrMkJoRG9m4xe9C/JBukwx0ItNtOSLZpVRdTgH4Pu5eSD
         523od+x4VnJ2LJ0Yfd1tokYtgaViYfnVxEuQzDVz0UoL38xgsXcfMAPEcJLzeKRZ+E77
         TBDFZ2k/ynE1F/lbjQmAfF3y1r2T1OryXRlQfQRZl3HDrq4+BR+3+SsQNsCmP46MfApu
         p+J0WixkTPs6aim33ywhnfH56Buzrids2ofwX5zC52OYbR0FzjKyjhRoEKE3Ln1Rn5l/
         K4/iC8dkxobxBmB5S9UVncGfTs+c4S1wkvc7GFWZ1cQrwhX1z2U5btr7BINtKJXzOTyc
         Grog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728824519; x=1729429319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=fnsqO3DFnaPXNVt4qzVQqHIiAaOU+OCxXV5ekZWe2fg=;
        b=VlnXL+gOhHjWfbIfTpgbUhOfnlIRFaEyVYu7YEoXEfIv6olItjI49VXPxrNJEpPKdN
         KbTuYhjL/i24K0BLHt5sjxCsNZZHgi5cS/m+/NMmCDq2PRHUVIxqYsFaCCbbf0i3msJw
         H6g9YD5d8TD0DxuZVtxo4cJrTO2HV0h9rh2fkSMb+IWgW4NROoy4nLg3WHuOErf5zImw
         lw8/EvC2u91def/2t5WLFyPQw/zcALF1VxRj/96ziLeXftet9tMNQ81AvxMkuknDG/WY
         PoHbRV8O0VSNFEOx4w6EzegBItUfk6CQPNy5eZRKPw6Cysr/jjjd/mGuZDZPwgbzdUss
         GMjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728824519; x=1729429319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fnsqO3DFnaPXNVt4qzVQqHIiAaOU+OCxXV5ekZWe2fg=;
        b=OpiCBSyXzE4Hay98yfCpwxUmBNs1TwXxvIpAy/siK1B4CwFqz55vU/jsW76mbvx65O
         iYY4QsWkl7paG2vJn1rxmrHI6lFjVOrlPIdyhFfJXGH9wMUMK7x7E5ygJVpwI5l9hMqn
         Vdnt/t1Npr2Ennq/LQtoCtk5p+Fzo9ZtW0f2KqfWsiojp6UuhwXItAw1x2cjibJsZKZZ
         eNEDDPrqvAp+N+r1rOQMvd5UdV4IK46BtSk4CrYiOdOnqjKnuqUv4Z5PXHi5vyauY4SF
         l6S7Tz69LiH1Ah5hSUXlnxlABMD5h+gbm1lySiUeo4NVlqb12PmfseFigoWBu1JskSiu
         XpJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUT/XNJUUwFT99zMfpb3ku+gJTNjvWLc/oF8dCL1hwo0z7H8ogf2HKwVbTnH0bHv07kc7WJKw==@lfdr.de
X-Gm-Message-State: AOJu0YzIePBIXcxxZC3KNUONw8oD8Ct+oLvhU9Pf+AKlvQiiFmzq4tFN
	yzoz2cPP/K+Y4wVFyKRLAVaf6CANZuTkSo92+Ccebi8CdoPd6sUe
X-Google-Smtp-Source: AGHT+IFQ5p0UgKNy8BpP+PKNpCS+HnPY/evma7DgtpzAVvamzT9VOAcgm988HugcRzW+Dch3B5k72w==
X-Received: by 2002:a05:651c:210f:b0:2fa:edb8:3d5e with SMTP id 38308e7fff4ca-2fb32b4174amr36228951fa.40.1728824517635;
        Sun, 13 Oct 2024 06:01:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7809:0:b0:2fb:41e8:dbc6 with SMTP id 38308e7fff4ca-2fb41e8dda9ls1704381fa.0.-pod-prod-03-eu;
 Sun, 13 Oct 2024 06:01:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJIqOAd2m+d31V+mAuFHvxczeC4ffgELyXA6tvQCtgaHMYcPzpIGjVZB2rQZS9GwseGVMJcKestsc=@googlegroups.com
X-Received: by 2002:a2e:a9a4:0:b0:2fb:2fbd:3c54 with SMTP id 38308e7fff4ca-2fb32740379mr27309451fa.2.1728824515552;
        Sun, 13 Oct 2024 06:01:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728824515; cv=none;
        d=google.com; s=arc-20240605;
        b=XATdeaKzbZDwcVOSUGccw+vfH1uJWFz0wPklPKtTYF9frQsR2C0JTYxf3r+mHL9RYU
         g7WKprW5M+shxnS/0oPu/nIW9DT/PKmGqnq7KhjHvZQdbNoAaP9eEvJ3iAxRjrIIVm5D
         xQbRtM/wq9LUXlvdJDQQF8VAwgT79FTUurI5OemcQqv/Qjbz0rsW5ec09gNWH45NtyIe
         0XlJOz13W7GDAT3YLyyXeyyabR04zVi2lD3ZMl24/FJlrqccm+MySqkj88w/iBn8m+cL
         y3YgL3y6U1l8U/ob86ifr7eL+F4gynH81JUi3/OSLXmyl6NTMY9UMLGk3KQNb+6aIcmF
         3EUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YUH0O52iG9NocMBQX2ifD6HnZr5R8mVmxmATQ3anrSs=;
        fh=rYAKI5VbVSLtgjb7GxVDugDop2lsJS9/R74WcWZudno=;
        b=VkQUPWbmrG3yVsUfNeAIdeVAYnQYWZLRDmGCK5YM94LvVtjl6Jcwk+Vc8OXxAKgyOH
         m6g/GhXEm5GCTLvrLPYPYp3GfIr9Tf4hGF4vL/IWAEN4AqGlRLqfT5A5oT7wSe+7O1X7
         iJ5YOrb2qlDyaVfc5heq0U/2vxSEmob4Z9sQXCYXpYjgqzueh8Bg4g3ydSNDd0yzU1iy
         FQaQAGLXTBRm6wdUY/M1UU6BasemdSgx0r7kRDnyU/MktSdnPNiTO3CDZyilQcMxGDcx
         jNixWFADlKRSL5R9NgJgQ7ZPZUDzqKj49zQQSVKWi2lRS6UX3mphTwaLmPEBLxocM7F7
         Vn6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jhsz8uHx;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb31c21beesi1048961fa.8.2024.10.13.06.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 06:01:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-a86e9db75b9so515934566b.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 06:01:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWQJ2azK2+kxrvLvoXVPW7GanPAxLH2h+MnTEFXVNaYVLsjritNRZyLHxkVxw1tDShblj3wC1GbmGw=@googlegroups.com
X-Received: by 2002:a17:907:2d8b:b0:a99:399f:cf2b with SMTP id a640c23a62f3a-a99b93ae7c8mr624523566b.12.1728824514634;
        Sun, 13 Oct 2024 06:01:54 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a9a0d9de967sm19209666b.139.2024.10.13.06.01.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 06:01:54 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	corbet@lwn.net,
	alexs@kernel.org,
	siyanteng@loongson.cn,
	2023002089@link.tyut.edu.cn,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Subject: [PATCH v2 1/3] kasan: move checks to do_strncpy_from_user
Date: Sun, 13 Oct 2024 18:02:09 +0500
Message-Id: <20241013130211.3067196-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241013130211.3067196-1-snovitoll@gmail.com>
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jhsz8uHx;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Since in the commit 2865baf54077("x86: support user address masking instead
of non-speculative conditional") do_strncpy_from_user() is called from
multiple places, we should sanitize the kernel *dst memory and size
which were done in strncpy_from_user() previously.

Fixes: 2865baf54077 ("x86: support user address masking instead of non-speculative conditional")
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 lib/strncpy_from_user.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
index 989a12a6787..f36ad821176 100644
--- a/lib/strncpy_from_user.c
+++ b/lib/strncpy_from_user.c
@@ -31,6 +31,9 @@ static __always_inline long do_strncpy_from_user(char *dst, const char __user *s
 	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
 	unsigned long res = 0;
 
+	kasan_check_write(dst, count);
+	check_object_size(dst, count, false);
+
 	if (IS_UNALIGNED(src, dst))
 		goto byte_at_a_time;
 
@@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 		if (max > count)
 			max = count;
 
-		kasan_check_write(dst, count);
-		check_object_size(dst, count, false);
 		if (user_read_access_begin(src, max)) {
 			retval = do_strncpy_from_user(dst, src, count, max);
 			user_read_access_end();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241013130211.3067196-2-snovitoll%40gmail.com.
