Return-Path: <kasan-dev+bncBCWJVL6L2QLBBON2VSKAMGQEZZ2Z7SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D635308D8
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 07:35:55 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id k2-20020a0566022d8200b0065ad142f8c1sf7591326iow.12
        for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 22:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653284153; cv=pass;
        d=google.com; s=arc-20160816;
        b=R81/FDLzRxj453JLGl7zJvLFDgM8lynmBMV5nDVQFrxhsEUus1PPl0okM8qytKjv59
         o6JYOZxviYlo94gXDBLv5velRUXsmi4A3ep61MbNI98SkKADZTHk9KUXNhr0KcaX6r6M
         3JqjaMkSTPZ+yC38diWTkHpzQPzIjdsmND64/3q3pyLbLCfTOREVC8i+hTR+ikpf9S0j
         fc7yrq9c4BfIl4QzKF1ToORSmitmkXmvwZx6JmTWLXlcC3m3I8Z4LhsVwe2EdeRMfoHr
         OoKs3mBd4lEKfkQQbC8I0Kke2+bQGivpgVEMfWMc7E+qvfc8t8VKTJVGVE1VhNlGqX7O
         H2kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-hdrordr:ironport-data:ironport-sdr
         :sender:dkim-signature;
        bh=oyfutomqZAltBmg+OLrEilCwLCt0eB0KSz8nI5GR9ww=;
        b=W3/nnOKlZ5squBVQyx9RGP6JXzkMZncYyvnM69olCSqStfuuxGsY8N8iQ5Xcyp65IB
         TzDVL5uIt57jsMBibw6QsoOdsETOH7zW3BreealokO34hG3noISM83O5mPyxyqF4IfeD
         qViU9gOmV0jIo+wHt3zhNpzMHSx83M7lpwmQoWrXfSdoN5jRvBnEdDUarq/6GIHBBdVM
         9jJwuA0DoHqMYnhZG/tpzgpOUHOOYwAWqBbfGJRw8LiZm1ep0QA/h7EFsnpUdl5UvGbn
         SbZO9m0AqIDYFMXbGfE5qWxdys+wnuqMVT2KEM0sv5su4D3U4ee9raRgObPGymLdnpjT
         x8UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.5.15 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:ironport-sdr:ironport-data:ironport-hdrordr:from:to:cc
         :subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oyfutomqZAltBmg+OLrEilCwLCt0eB0KSz8nI5GR9ww=;
        b=qF8pjeHVU3vF6v9VigyLukY+Y9QHAJodBcajoBdnBMylU7Nfx5YTUE4gonU5VPXZ7W
         qnfPtfzaxrrAqa/iTZ3AB1OOeVYZCaC8LZ5N0G7jNPYd5AId1fvkQWFAIwkrBAognQNs
         GyvwYi6t8pHMdYvvIa/15hhEdc2f+YuJ+49RGkzCSNRM+fPFEC4d+Djm5j4yIpz6T9Vx
         yPEs3uwLcEeXQcDFqpVZxYJJV8G5r3gq0V6/XAbr54qRpK36eUFVWXv1WKBbsEH3u3Lp
         o9Am/U/RiRd77n8g05xFKOlqSEmltFkbZZMajXcb8+Ifkn6+XqRP7LxL7B+2pY+6z23S
         WVPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:ironport-sdr:ironport-data
         :ironport-hdrordr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oyfutomqZAltBmg+OLrEilCwLCt0eB0KSz8nI5GR9ww=;
        b=GRHy4AHNLOnhAaoEH2UVlB2fWdWRueQFs2k9ahOFLaYEWLfgh2BOfEX4t6z5D3lsoD
         lm8voJ97S9tGwq+bNwhK0IsLXs7HdE0u5QnduUzqPYCkltn3blPuVCgwmrR1uMjajO5Y
         IYQyP3PkTK514WK4UJzS6sgEFTH6dIwMHyF/oIhV4qQqiPJIKpT768BU3PwWuQD5XRQx
         B3OyEVlKNLpUDCe4KE+cpJxdhHLLyVJKEI71ch9mReMHFuSG0mesm0VxADuSaxlknMvp
         M/cVrxhKHomOxN3Bf+mf+Wio2wKzg0bMxnTB9JYWTpWShQtiU9Mo4Xa0R/OdET/L5WOR
         YU+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QseFxjVHzAW0EMBQBEFOyLmHNXavIE4XMq+EfCDjAyaI8QO/b
	jRe2gLr7P0K+jBJEogilBBg=
X-Google-Smtp-Source: ABdhPJw5mX3RPMzY/66QIVq/bZzuifOIkmvGK7pwIzGLdZhDkm6kEI30o5xyOn81unPqMrnpXSdP4Q==
X-Received: by 2002:a92:d346:0:b0:2d1:aa4f:8d1e with SMTP id a6-20020a92d346000000b002d1aa4f8d1emr1906265ilh.152.1653284153709;
        Sun, 22 May 2022 22:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1355:b0:60a:9e26:930a with SMTP id
 i21-20020a056602135500b0060a9e26930als1017510iov.7.gmail; Sun, 22 May 2022
 22:35:53 -0700 (PDT)
X-Received: by 2002:a6b:ed06:0:b0:649:d35f:852c with SMTP id n6-20020a6bed06000000b00649d35f852cmr9362867iog.186.1653284153287;
        Sun, 22 May 2022 22:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653284153; cv=none;
        d=google.com; s=arc-20160816;
        b=HAxqQHERvQEncCvOVY2MODhlcw6eTEXNmsGk/LYDNcwDL5b3dHX8ZlAL63ozI5mnFY
         gstnJOVehczXWDElc8vv9Jvd38WtqJt3vZYF9DUdXRzwTcd1NSvNPnrRn0fr914Ftdix
         oQ9hlWvMiqWL5cQVObAY1Rtay/UWxYbKK/j17VNWzcyvyoT6OVAJ7k6pVhUuxFryTeNa
         /D0xNkgmZX2TA/AS4MplTJOAApXi963DJJOUa8E9ME/CNoxhYhGBlUx6703i21ZrDhho
         HEOW5vIgt0WSwlmJ2XT2GkB3aY9O6JY4wviQnZEhIpX+4DaIsRb4OtFco8mJgi2SQPvW
         0p6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:ironport-hdrordr:ironport-data:ironport-sdr;
        bh=EAIsD2GTS3XDG+buHkLtWnipY1LNgqGZnwCsD6SWf2c=;
        b=kvHRrgsOC1F78zKsPOFDjOCUVJ2Ah5IRqkxGkOb9CLUl05IVVw4KZJeTb26UGVjodf
         8sXMpI0QLCo6ZhAeJGiGX7X+THEZacmL+MoNgPaEUNT6PPakMx9gSZegNEaZbE5F+R8s
         g6HQ0C14xNFM4UsjzQkiBc+B+Nt1zgzaFsj0iXFcoEyhfzUP/567dfp4jjCY6XkkIL/n
         fYsixFOEqFtZ53uMfPlYh58Kt9ht3I9qUwvBnrMfm5AKgN2dvnfbyh1NN1nK837tjPyo
         IgqBeHBzk79AR0X3ucoePGJ1k+x8PbfmElgRSvOszswZeAfK4rqb1HMU06GQFdvfNBUV
         nvJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.5.15 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from xppmailspam04.itap.purdue.edu (xppmailspam04.itap.purdue.edu. [128.210.5.15])
        by gmr-mx.google.com with ESMTPS id v3-20020a02b903000000b0032b22cd5f74si631730jan.0.2022.05.22.22.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 May 2022 22:35:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 128.210.5.15 as permitted sender) client-ip=128.210.5.15;
IronPort-SDR: 7S1kxYPAs/kDDMfSrsekWdS8eTswCq5YAtn2a0PAzktF6gr5pbKmBkw+jRW+JyYYbpfluM2fym
 aFu5gfbGSnmwZ8uzXljHcl5ucaI6ehbgg=
X-Ironport-AuthID: liu3101@purdue.edu
IronPort-Data: =?us-ascii?q?A9a23=3ApY2qUqPJMarjxOrvrR2ml8FynXyQoLVcMsEvi?=
 =?us-ascii?q?/4bfWQNrUpx1DxWxmcYCmuBOq2IM2T3c95xPYi2px5QsMXRzNI2HXM5pCpnJ?=
 =?us-ascii?q?55oRWspJjg7wn8dt0p+F+WbJK6+x8lBONTGMu4uSXrQ+kWkPrT79CEuzbySS?=
 =?us-ascii?q?qfxTuPIJ3kpFwNjTS4gjzNlmvI43t4z2ITpU1vVtIOgudDbNX+kxyVwbjAe5?=
 =?us-ascii?q?ZWFpU49p//1oj4Z4gEzaKkT7l/TnnUYFrwFIqS1IyeqS4VYBLfiFf7e1r2k8?=
 =?us-ascii?q?yXU8wp0UoGplbPyc0srRL/OPFTe0SMKC/j62hUb/348yKc2MvYYeHx7sTTRk?=
 =?us-ascii?q?oAj0shJuLyxVRwtYv/GltMbXkQKCCp5J6BHpOLKLHXj48yey0rKLynlz/l0V?=
 =?us-ascii?q?hlkPIsU674qR2pVs+QFMjwQY1aOi//vmOC3Texlh8ICKsj3Pd9P4Sg8nWGBV?=
 =?us-ascii?q?ft2E4reR6jq5MND2GtijM55G/uDNdESbiBibUidbhATaE0bDokywLWhinXlK?=
 =?us-ascii?q?WUKqVSZtPJqpWPIihRsyrTwPZzYdsHTHZdZmUORp2Tn+WXlA01Kb4XDmWrdq?=
 =?us-ascii?q?n/81PXSmS7bWZ4JEOHq/PBdhlDOlHcYDwcbVAfmrPS04qJktwmzEGRJvHt3x?=
 =?us-ascii?q?UQO3BbzFIOlAkfi+CTsUiM0ArK8LcVrsGlh9YKLu251NkBcJtJwQIROWP0eH?=
 =?us-ascii?q?FTG5XfV9z/dPgGDhZXOIZ6r3urO8WniaXB9wVgqPkfoRSNdizXqTRpaYhjnF?=
 =?us-ascii?q?r6PG4bt5jH59K2ZL5lncUEDa7svYc4jj81X/HjGhT69/sWPRRVz/hjNUn+oq?=
 =?us-ascii?q?A51eeZJZaTxswidtK4Gdd3BCADf4xDomODHhAwKJZWMiXfUGLwlBKyz6+uId?=
 =?us-ascii?q?jDQnDaDGrF9qGr1qi/zId04DDZWYR0B3tw/UTP3cVLQvh1565hUM3+nK6RwZ?=
 =?us-ascii?q?uqZAsIm16XxFtL7Utjba9NPZt56cwrv1CJnfkeWmmzgjmAjlqYwPZqUa8GxF?=
 =?us-ascii?q?W1cAqNipBKyRuEAwfooyzo4yGf7W5/21VKk3KCYaXrTTq0KWHOKb/1itfvdi?=
 =?us-ascii?q?B3I6dpCOo2Hxwg3bQFUSkE76qYSK1wbdSV9Douws9FNevOOZAdqBQkc5zbq6?=
 =?us-ascii?q?etJU+RYc259z48kJk2AZ3I=3D?=
IronPort-HdrOrdr: =?us-ascii?q?A9a23=3A/RJRpattgGOoH7bfmqG0oNxA7skDb9V00z?=
 =?us-ascii?q?EX/kB9WHVpmwKj+vxG+85rtiMc5wx/ZJhNo7u90cq7IU80i6Qa3WB5B97LYO?=
 =?us-ascii?q?CMggeVxe9Zh7cKuweAJxHD?=
X-IronPort-Anti-Spam-Filtered: true
X-IronPort-AV: E=Sophos;i="5.91,245,1647316800"; 
   d="scan'208";a="476099845"
Received: from indy05.cs.purdue.edu ([128.10.130.167])
  by xppmailspam04.itap.purdue.edu with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 23 May 2022 01:35:51 -0400
From: Congyu Liu <liu3101@purdue.edu>
To: dvyukov@google.com,
	andreyknvl@gmail.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Congyu Liu <liu3101@purdue.edu>
Subject: [PATCH v2] kcov: update pos before writing pc in trace function
Date: Mon, 23 May 2022 05:35:31 +0000
Message-Id: <20220523053531.1572793-1-liu3101@purdue.edu>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liu3101@purdue.edu designates 128.210.5.15 as
 permitted sender) smtp.mailfrom=liu3101@purdue.edu;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=purdue.edu
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

In __sanitizer_cov_trace_pc(), previously we write pc before updating pos.
However, some early interrupt code could bypass check_kcov_mode()
check and invoke __sanitizer_cov_trace_pc(). If such interrupt is raised
between writing pc and updating pos, the pc could be overitten by the
recursive __sanitizer_cov_trace_pc().

As suggested by Dmitry, we cold update pos before writing pc to avoid
such interleaving.

Apply the same change to write_comp_data().

Signed-off-by: Congyu Liu <liu3101@purdue.edu>
---
PATCH v2:
* Update pos before writing pc as suggested by Dmitry.

PATCH v1:
https://lore.kernel.org/lkml/20220517210532.1506591-1-liu3101@purdue.edu/
---
 kernel/kcov.c | 14 ++++++++++++--
 1 file changed, 12 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index b3732b210593..e19c84b02452 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -204,8 +204,16 @@ void notrace __sanitizer_cov_trace_pc(void)
 	/* The first 64-bit word is the number of subsequent PCs. */
 	pos = READ_ONCE(area[0]) + 1;
 	if (likely(pos < t->kcov_size)) {
-		area[pos] = ip;
+		/* Previously we write pc before updating pos. However, some
+		 * early interrupt code could bypass check_kcov_mode() check
+		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
+		 * raised between writing pc and updating pos, the pc could be
+		 * overitten by the recursive __sanitizer_cov_trace_pc().
+		 * Update pos before writing pc to avoid such interleaving.
+		 */
 		WRITE_ONCE(area[0], pos);
+		barrier();
+		area[pos] = ip;
 	}
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -236,11 +244,13 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
+		/* See comment in __sanitizer_cov_trace_pc(). */
+		WRITE_ONCE(area[0], count + 1);
+		barrier();
 		area[start_index] = type;
 		area[start_index + 1] = arg1;
 		area[start_index + 2] = arg2;
 		area[start_index + 3] = ip;
-		WRITE_ONCE(area[0], count + 1);
 	}
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220523053531.1572793-1-liu3101%40purdue.edu.
