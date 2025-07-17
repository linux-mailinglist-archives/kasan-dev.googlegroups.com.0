Return-Path: <kasan-dev+bncBDAOJ6534YNBB3EQ4TBQMGQEFRT7P2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F822B08F3B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:27:58 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-612a799a7f0sf887229a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:27:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762477; cv=pass;
        d=google.com; s=arc-20240605;
        b=QahiJMXz++Mp2Q/RoUeBQ43qG0RumrwtJ28TUKJddTLShTt5B3pnIzNm2cg+kwApHC
         CV0otiQjHZL8JTp+RM6CwpS/CX8PJp53vPWyGEvgpuLd3K7EUCdZQSeKlO9YoiCGnr+X
         NiecT0azsTvu0TOk9QSXVzdks7+UY/Cf8Nlny9LtirJWG+SovkeeLUVscQ562bIRjD+k
         Rg3j8W44/bmPYL2xL5xDkcT+cJAtWd/3ARDqYj2J3fRIxDus8THxs4fHChiIuT6YpzCK
         +LxQvYx9AsirN/v+FaQd5u6a5R0iehIsROoLDY+daTd3Dmrof+3cIXXVsyrZpeG99vVd
         4O8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=xIx81AFhp9ygaZFpijbFGvkdxE8eqdaeZs3U4TrWcCs=;
        fh=azO+6sLxtLKGaMrFhUDuuFHhEhR6FQnY8LI7dKrmB0o=;
        b=DJqEgSxR2VDXffSy2Eo7pZEX7aA6vTj4GgWvVKBHiInClBiqdERwZ1V0BrFcO3WBik
         g0tYzStPX+Qiv39utTYCSG2wQ1YQqlSaQ4IUjsRlmhXlrYW+jI9d4F5iVHdv89HyemAW
         g0tCSpXaMuAcMnxSj2KIdJ3JiFoye3XnNJIz08C3KnRM43Oqg0z6ATMn5u+3qMYMsfvr
         kzRRhHgFD4VOL54HKdBsR1iOF59zt1LhD9VbThGkOkvVOH+0gQPQjV5YIIjlQ2f8MTdG
         2jGLcrCf65NWWUxeVVy62YqL1Nc/h617gJrkLjlW7QXK3dhjhvlM27lV93iydxcFfNkt
         +4hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OJPiXvB9;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762477; x=1753367277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xIx81AFhp9ygaZFpijbFGvkdxE8eqdaeZs3U4TrWcCs=;
        b=JSiPBRpYeV93LJpVrKWROZlSlLHZUMKvhSZqXSsHIRAVwgrxSa1hh4eonoKtzecuOj
         HsKnQM0JqwN0BnXW8C9n/B0H7YFdMiQPQv/fqWe0rE+BOuNu0bx9BtIleFs7MpEmtXKi
         hSPoIZ8vgiKAD1KaIloiQN/gMP+Ep9ejWRif6hXTt52CYzJNCWlPDZ7fKSsujcLgwccn
         Cbpb3oKmslDztEiUnp7KE9VYk3oHPuoXRoTiajm6CvHEPEMq/x38hJX8Wv8q5GtzK+NZ
         zpEQ61HiP+twK0Ls8BKk8PGnIYMEPZd5A/xFlpjA2XSCoq/+MfIYdl+cMfVccvaiyVib
         4vmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762477; x=1753367277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xIx81AFhp9ygaZFpijbFGvkdxE8eqdaeZs3U4TrWcCs=;
        b=X/9a09NnlbiiDK03tMLm3K34bQK2nBfAH+/wOVVfwcsb7shpc+ArmELcgHvvTt/Sbb
         G5KdHM+NR5d98t5L4/dDENMAgdvyCURhXoZVGQR8dWLtXyw0rdnD6y/POS7kw/hUwIKw
         yceFv6k8pcjo0QSbu2uhZN+DW2DTt+FjDfb+NpYU9/b2qOBsgPJq5H/ggR0s4R2TukCV
         B8tC/QCsiIehvNWrHw5r39l7RS9N2M0yV4Womcs/jP+/loY/BdFL2ssFkKAmNQ7OJfBs
         nPYHLViCcDU449M5fIg0va4g3Z2GhI+00SXc/mSNVuU64ygW5YAMJsrJ3sv74cPR8QKS
         77qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762477; x=1753367277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xIx81AFhp9ygaZFpijbFGvkdxE8eqdaeZs3U4TrWcCs=;
        b=XqQXcHHRomJ1wsYdOoCSLmEVimQd9hcVymT4ODLcY48EO4Tqw1fEVCZyS+fOZqWujk
         Y7gwG1Nr8zti/pmosSE/hD0LRk4IAz1IsF8g6m1aL1tEBFWR3nNP92EuYEwgTTr/2mwQ
         7cPqOJqh2w3KcnTqPZf2JnpqZ3iHXldbVb6iqH+wSaZhiZ6fVzdKkGdZZ6oafxcmpkY6
         JiGYxd0bsBJxW0K0gGCKXUj6tvFb0kIA6jP4RXnYKjd0eFXjCilgL3sSq1YKPLImfygu
         OzuJlHFuxeNJ5bX9K3+1GNmVe5b38ZtmBFi79aL7KykBALeMFaYMgbpLAu+ilXX+YhEs
         yI0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVafpeP/HN6XjadZv6+SeC0ALVDw6Hi1dyydXJqgomajWl05dojiTuz3OWA0HSiwXkzsIW1uw==@lfdr.de
X-Gm-Message-State: AOJu0YyF8lfIwB38WbjeNwx/6hlRfil0k7rbOlP6wmPdZrR9NLsvTI8C
	EvChl5g1h6lLjwyNsqGwDOrj3v09F2rQuLkF5cNEhscJ8KklL10sLoZC
X-Google-Smtp-Source: AGHT+IHLOTd92XT1ojZNFseuBuZlHirB1QOuneUHKkFkNOeR9s5oVDIC5pWR0JqeEFHWJSeEzgCTtg==
X-Received: by 2002:a05:6402:2755:b0:607:ec18:9410 with SMTP id 4fb4d7f45d1cf-61281e9adbdmr7330120a12.3.1752762477592;
        Thu, 17 Jul 2025 07:27:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZea7F3EviMGdbPyB5OanOgjphT5q68vt8I0PrwmA83QSQ==
Received: by 2002:a05:6402:1eca:b0:605:d962:5e1c with SMTP id
 4fb4d7f45d1cf-6129fe89af3ls996617a12.0.-pod-prod-02-eu; Thu, 17 Jul 2025
 07:27:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWiitwBf/2yUvp9aBZVYlqGAMDbsc+4DiioUgZvq10pLe9gbD+zeYaseXcg/WSKN2EJDPCA7pkIemU=@googlegroups.com
X-Received: by 2002:a50:954b:0:b0:60c:52aa:d685 with SMTP id 4fb4d7f45d1cf-612824ee8c4mr5078488a12.28.1752762474926;
        Thu, 17 Jul 2025 07:27:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762474; cv=none;
        d=google.com; s=arc-20240605;
        b=WlIS509N38E3F5bUKp8L2Xk/SxfOSS0vK5kHwKUOBouyu/hgdTmARLTVH68aSdyG5j
         Gd5UosZbCmeTSw4JQmtzMaq5K4kaUxS1fMBFq/lUTWlkl8rLUefmYCbWKIUZSBrtS4B3
         rct31G1iJQ5JLTYw50V8cEQrrLV9Sl+piYOh1U5bPuXkAfENcG8WgjfT3zWkvW7B/GwR
         GA/oQXGZotIbJ5QV33t61b+C6F8ui5mqe6J2VIJrX1CPirg9ox7LT6Mzqh/eLMZvIF9b
         ApXR/dBzzOihOSbi8271Cwiw+3g/muHDK5Iww+9zudQwSGKFsFFolvLrsPvTV4lCTaLM
         Fxow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Bku05+DNIlaPeHqRJ4y/c3E9v08tlUqoZ6kZCd1AC2c=;
        fh=XBw0sEOa/FKb3r4CEsb9xSgdi3PgYUVExFTHEl5YNng=;
        b=hdLw1siTqRk6dWj1E4YxdrcytWrZC/GPn+xsP7PmfTYOmxL2JixmbpO6EX3ksyeqLq
         EXDP7Y9y+GtRSuHwPgwVJw9gC0VwYElHGRgE/Wo8NxSis8rG1miw+jDOvD8/ouLPVAim
         WYJq0Ol3w5Q52+bXEClrRBdvRO0f/595z5Al+NJ6fWn0juOggZlc5LziZePtjgmPmt5r
         52krlFV88Egw5PVJ75lywUXnpah70wcmRyViHxgiFLsnMap19La0eRuPSAER820JSfNY
         A9grrD16BUKosdI8tOwMhOLLkieOry9gCwWqPxiqYInRIkBqnQlWVZHjMmu3mB294vBX
         16RA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OJPiXvB9;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6120b2a54fbsi250382a12.5.2025.07.17.07.27.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-55a25635385so1157246e87.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXrUFoaAYlsL49AmtC6r98hEOivnq5AEpwgLzhajohikbbJb3J3Y8/SjiRm+Gu6cR4w7f7nunw0igI=@googlegroups.com
X-Gm-Gg: ASbGncuRomRj3nYotnLpf/Yg4iK1YCyQRW4zpnRK9INFaS3T39Xp8shG0+uSV9UuH9f
	FkS4vDQK4Rvl5gIkt+blYeJPicEWvLQ3yYur/RonL1ZNRnphtJgHRG5Sdkdu78vPRzSpa/bXRRw
	tCV+QL3uvtOv3VcpRQ0qob026nguLR60Nxmf7u8AHi08jRoRhafmVVjmohZciR8gON4jAgDa0S4
	kExt1uW3kpnj8JgNXBjwK1MkzXFIjaMrVdJDRq/u7OqSxRFGrcP2GBNieYCOBOvaIymFYX7hDiP
	4P68nLkVYUBc1btaqQUA032Q46irgh8FbvxLBRZfJLRIDqdiGO1IXMUad6MPq5/cPKiwr+NKEXv
	aJkO+zqJHzuDKwQMZ/qKUN9pEJmVwKqRDdktn/0itRtjSGpvcjHpDlCwV/2TR2jk0J140zgtDGI
	8kMIg=
X-Received: by 2002:a05:6512:1452:20b0:553:af30:1e8b with SMTP id 2adb3069b0e04-55a233affa7mr1874039e87.38.1752762473999;
        Thu, 17 Jul 2025 07:27:53 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:53 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 04/12] kasan/arm64: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:24 +0500
Message-Id: <20250717142732.292822-5-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OJPiXvB9;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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

Call kasan_init_generic() which handles Generic KASAN initialization.
Since arm64 doesn't select ARCH_DEFER_KASAN, this will be a no-op for
the runtime flag but will print the initialization banner.

For SW_TAGS and HW_TAGS modes, their respective init functions will
handle the flag enabling.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm64/mm/kasan_init.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45dae..abeb81bf6eb 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -399,14 +399,12 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
-#if defined(CONFIG_KASAN_GENERIC)
+	kasan_init_generic();
 	/*
 	 * Generic KASAN is now fully initialized.
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
-	pr_info("KernelAddressSanitizer initialized (generic)\n");
-#endif
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-5-snovitoll%40gmail.com.
