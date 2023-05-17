Return-Path: <kasan-dev+bncBCXO5E6EQQFBBPM3SORQMGQERJJF4ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C8057068A1
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 14:51:11 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-76efc7fc502sf48411439f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 05:51:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684327870; cv=pass;
        d=google.com; s=arc-20160816;
        b=HN7I0GwEQj7842CCnpvO342WrN3Xpt2zEXkxQ+/LcgOlohPm33/TfI0oy19NSTi5vm
         77Nsgi1wCa1P6ItAL/IBGeJ4VRH7Tw8ATrP7AsivUO68RqTymU1qisY+7S3ustED/YXy
         OycIucXZlg01Ik8L9rqbiz7DJcstN53jvLZnf2xNA1aLiWg/mvxxdU+G9da89flt/E8n
         SPtmF5KZwslL12QsdNJm5Ff6LFGZRX2qFwZQ5EUZAqXle0HL3y62xPSveMb5DCXXZNZ/
         XR91GyfPr4D3OWCmANrE4anghG1AlxZE/HzqtR5P/4nrgKP4987liuIEZC6V6PkAdPFI
         kruQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=R58wj1rwmNltU4pyUH1fZXsyaWRCk1ZtL9OhRxCfHIE=;
        b=RapIM9xgm5+T29ZrOixuFV7+3mhG3FW/+yZW//UnlY3ouoy5ntPLm0cPrS02XXVdAR
         vQOEmoqOrVP4SYk+3SyDhBbRZLZ/N6iTc2UjneoATQiHqkA0sDpJJqywG1PmLe2hb1/E
         4/iogO7K2oWp2ysQC+UBM4+FvKSC2dWiSRvVdvpvKvBdTW4jsqopAlxR+A1Ktbambn6o
         Agl15xp1/e3fcVzR9M1cNbr+1BeuuUP+ElaaAz/qTKJb6pU/yXdn+zbui6DjYEgjjyE3
         1YRmshckvVi4oQmPOVWRKVbE9QdiJ5NUAiTFecxH1/XLWPPo9wearsEPCR2xUivNLnkZ
         havA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YNmsxNL4;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684327870; x=1686919870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R58wj1rwmNltU4pyUH1fZXsyaWRCk1ZtL9OhRxCfHIE=;
        b=SIShhIFf+Ba6bwu1HXHnLXJrBcoIW1RENgCwx1YUcPvfyVUimmgVWD2MOb6uiWygJI
         1IBUzss7MEPoYyDVNCzA5HqJuJqePJUw+Hm09I9hikWQXgM5mzcQ2uD/I/zhkul5uM3C
         8kOfDX1swOUw7BqnVfPbsvV2hGEXfnOAIS6LhVjjH6dRScsWC8ivLMFqWYpKlY2HHhla
         XMAaDy6VK+LS7yOOtMCxU6epHtPkFHEyIcIm3gOTMJts+5BbEIqLBVdbq+FvwV1wCiLk
         Zqp8ofBI8jemnI9NnUHy3Sv+TjKnDwNWkwciCjpIbW9QYxxE/S+lZ8T5bJXV0W5Nqxow
         t3FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684327870; x=1686919870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R58wj1rwmNltU4pyUH1fZXsyaWRCk1ZtL9OhRxCfHIE=;
        b=Rv4H/SUdGRxZ7HhTbNM3fkwzAEbHCfJnHVQWL5yW62i3KkGW47BnNcD/eFrNz9kcOA
         +jYYYtsYJUGCadI7Fp/Y1Se8bOm8yvdQ5V8+W54Q7L8PTvUzg7lLE5zRqgp/coleWfr4
         yanSlOp2MW1z+D5GB034Zem0Vllf81bwEdsNV0jzknlT/kUa9fCiDjmvpvHCGj2kZAbU
         SuKylIK5YrzDnVNdNxzOwQI9TlfF7ELy+JwQ8uBakaXEs95Bmt/sQ5ohlvuD+URO8CTW
         zOCbT4KH+dGUsPdcnZPVYaKBQoeyFNR7EJ245d/zSoX0qt3mJVIapSenYdkSEq1cg6YJ
         5JeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxhzj5kJk5rnufL2kFkt1kH5btcyRMAoPWGZPutR7pCVrxyGLjT
	QGsMXHv3o3WiiZuD0NIsXLg=
X-Google-Smtp-Source: ACHHUZ77jVa9IMoDiYu8caGTwyBYh5PML1WyrtGJ2pTR5LeUe3ixRY2Tw6+PTqxrIjBeezrsxodpxA==
X-Received: by 2002:a92:d402:0:b0:331:1846:6064 with SMTP id q2-20020a92d402000000b0033118466064mr1329593ilm.5.1684327870021;
        Wed, 17 May 2023 05:51:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a8b:b0:331:1905:987d with SMTP id
 k11-20020a056e021a8b00b003311905987dls1533024ilv.0.-pod-prod-01-us; Wed, 17
 May 2023 05:51:09 -0700 (PDT)
X-Received: by 2002:a92:dd01:0:b0:335:5628:9270 with SMTP id n1-20020a92dd01000000b0033556289270mr2012998ilm.9.1684327869499;
        Wed, 17 May 2023 05:51:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684327869; cv=none;
        d=google.com; s=arc-20160816;
        b=F3mFJ1SdY+Zqwb1VPNlEdTqWEEzocv0ypCZkE1K0rOe1lLf5IR8GEzQEDXmssyJWCv
         Iga12VrDSFBGH3FG/MhMgYgFJcn/5f4BtIrG8hBbJLEepSFSNKBZ8vRD+G0W3c9Xug9w
         0EofgPQHn55NdoHI516F1voANmW//NbQgVhPMESoB1J2PIPGCBQCm8ETgOafsRUxgUj+
         3dDSpm2mhO+lBdGIoy2TM2mibeDM9LqNoDnljzP4DePmv/hBts9jKDaJSK+4Rt2siNCi
         tuMnrQ0TJnNrA4bWaTbADZeZ1aCnTbz3WOKLHt8EEAoTHLBPIg5ngfR/SQ3aHa1FxNRb
         4y0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=0EotLhn+hG0ldGo90gH+aUEvqzvk6YJ3FtG4wppM6gw=;
        b=C+eXlIhryjxYlGDGvUNLITcV/Y0ULVw/iTSkp1wcBBJ2tGEDcBvdxQjzlYDWBVRWrF
         WCrBATGYKFvkvbm2SL3p5wLb8ZxLugDMY625bouoF9QLa0/48Y6YXMOMZTeM0/S0N7Xd
         i1DiDm/irZUsJ/woDwW9gerRi+ZvvU0pJd8Y9vkgBIkFgHGD98cNRpSknHVN/v5fjbgi
         NY0C/1AsnIctKGZgw23PH1tAV7ThI15JHoEUU5rXcS8CUJlqayQ++EO5d+GRrGXsKhD4
         +4oqyTK6dOQYrQxOKwRwqjJKXsgGCMBpUWva+50MJKo4XBxPoiNPr8tBR5pi9+Dq28xO
         eZFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YNmsxNL4;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id m10-20020a056e02158a00b003312406cad0si1934170ilu.0.2023.05.17.05.51.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 May 2023 05:51:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2BDAA63BFE;
	Wed, 17 May 2023 12:51:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30382C4339B;
	Wed, 17 May 2023 12:51:06 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: kasan-dev@googlegroups.com
Cc: Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Mukesh Ojha <quic_mojha@quicinc.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Ingo Molnar <mingo@kernel.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Fangrui Song <maskray@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ubsan: add prototypes for internal functions
Date: Wed, 17 May 2023 14:50:34 +0200
Message-Id: <20230517125102.930491-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YNmsxNL4;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

Most of the functions in ubsan that are only called from generated
code don't have a prototype, which W=1 builds warn about:

lib/ubsan.c:226:6: error: no previous prototype for '__ubsan_handle_divrem_overflow' [-Werror=missing-prototypes]
lib/ubsan.c:307:6: error: no previous prototype for '__ubsan_handle_type_mismatch' [-Werror=missing-prototypes]
lib/ubsan.c:321:6: error: no previous prototype for '__ubsan_handle_type_mismatch_v1' [-Werror=missing-prototypes]
lib/ubsan.c:335:6: error: no previous prototype for '__ubsan_handle_out_of_bounds' [-Werror=missing-prototypes]
lib/ubsan.c:352:6: error: no previous prototype for '__ubsan_handle_shift_out_of_bounds' [-Werror=missing-prototypes]
lib/ubsan.c:394:6: error: no previous prototype for '__ubsan_handle_builtin_unreachable' [-Werror=missing-prototypes]
lib/ubsan.c:404:6: error: no previous prototype for '__ubsan_handle_load_invalid_value' [-Werror=missing-prototypes]

Add prototypes for all of these to lib/ubsan.h, and remove the
one that was already present in ubsan.c.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/ubsan.c |  3 ---
 lib/ubsan.h | 11 +++++++++++
 2 files changed, 11 insertions(+), 3 deletions(-)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index e2cc4a799312..3f90810f9f42 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -423,9 +423,6 @@ void __ubsan_handle_load_invalid_value(void *_data, void *val)
 }
 EXPORT_SYMBOL(__ubsan_handle_load_invalid_value);
 
-void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
-					 unsigned long align,
-					 unsigned long offset);
 void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
 					 unsigned long align,
 					 unsigned long offset)
diff --git a/lib/ubsan.h b/lib/ubsan.h
index cc5cb94895a6..5d99ab81913b 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,4 +124,15 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
+void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
+void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
+void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
+void __ubsan_handle_out_of_bounds(void *_data, void *index);
+void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
+void __ubsan_handle_builtin_unreachable(void *_data);
+void __ubsan_handle_load_invalid_value(void *_data, void *val);
+void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
+					 unsigned long align,
+					 unsigned long offset);
+
 #endif
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517125102.930491-1-arnd%40kernel.org.
