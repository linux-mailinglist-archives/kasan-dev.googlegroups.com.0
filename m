Return-Path: <kasan-dev+bncBCWJVL6L2QLBBI6UVSKAMGQEKQ7T4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 194A9530990
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 08:31:01 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 65-20020a4a1d44000000b0040e8fbc7720sf715908oog.4
        for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 23:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653287459; cv=pass;
        d=google.com; s=arc-20160816;
        b=ncD5pVpodEJuHWKYXUZ6oe4zlU9I9kA9d1ZpOrGAoiHHj2NFD3JA1dMan44WT9lekk
         PdxkvHX2WFdGkpLFN40GEiDyGrqLsHeigrhf0CcBBv3M04eGgQ/54AW+Zn6ZjQaVKDai
         10ZjJA0v6IzQ32BqxMoCVidrRSYZxelVXaDvVrLjbh+ZImbIdeigtaK4Zxdf2py4LOLQ
         gNa63mB3vyHY6d4/AXfhm9gQpuVOlpjrcfSczdlRnyQZwbMHCGOXbKE6UfQ330lQO9MW
         U9r6e/fmKonuNNNapfkhm06qfbAqBTIbahymBj2id7LTSchgmUrrGjaXJuxbPKapS3i0
         jbNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-hdrordr:ironport-data:ironport-sdr
         :sender:dkim-signature;
        bh=spZYs6S7G7mF/VcQPxolfExIUOgH/UyAPxcjU1nZ+SU=;
        b=Lbn2MaB5oeOjXF/KBQ1u+bB2fmfzt5rmkER1h77YccfcHTgm5B3vX4fr2EntvbhnLm
         85DsWDL9WU3Ch7YBe1NjQESMBWELm91oMhQULxUm6SwFYrjETtjI84VeZ73x7NQ+8wPW
         NkKXhsr/rYF65/qtt5/anzIljiIAGs97sf5Bp2C5rMc/erDCmMLghJGOTXcavMlPEIJF
         svn1phb8loAvGSxhHkpIsHZw+7K8MSv2760cjnmq6AOiYbjP/oenZPoj7h8qgUIVvCK8
         dpb4D8mCUyR88cqGceXqidn2ODSxlm23Bu80a4YgFyRkqor53GJufJJXCJGc6CVDm9v1
         dBaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.215 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:ironport-sdr:ironport-data:ironport-hdrordr:from:to:cc
         :subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=spZYs6S7G7mF/VcQPxolfExIUOgH/UyAPxcjU1nZ+SU=;
        b=FdvgiUATtSERfzcemV2OW3i4U7NeiDV3LX/kd8avPqhgOQc32vMlcyhsXMeqJH2IGY
         16KECfu3bUQB3fwHL65bCL5n5R67ZUI9LZGAvYTsoi9O8SWmWlOFrCoH3js2QKNV1rem
         OIjZ66i/qjl0/fb3WV59flditEA3PymtgcP9K+ODH+Cx/B7NpDYqwurON+bnr9aFjCFw
         a0y/8URVtkbWgYBuwnr0MgEDQbPwOtJl5DIhrrCA4KBc6u+sITm/Pps6dqGa7cCbGQRq
         /7bZfz205kAiv87892ykWctbzBSDD36R1ND5/2Jvkv9oqYEaUYeMGdJueWq2fnzdwU3b
         cAGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:ironport-sdr:ironport-data
         :ironport-hdrordr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=spZYs6S7G7mF/VcQPxolfExIUOgH/UyAPxcjU1nZ+SU=;
        b=Uax2vMAuFYomNDWHq2ueFDUeIDCe5HlAqaRjA3yX4jqKz6aMOGwtdi+RZJDz9IDggR
         14BFTwMYqndwJhZNkBMKV6yenc3x9KaZeKIEjc8Cy0t1GsciFvmjw1GtQVVzpIdIQh4D
         OQkX4MSC+EnqqQy8NRNoU5Kzp1dWC8iOzjdbTO90ot8+XyepKqmv5Gy044Pw0MaQ7jeK
         /4E//c0GuC9USOKg9YZQ7kq4wmFived8NOF+v8yBD3cYu7V0Ef/zquWNw7mKACTL0/AM
         j83XkZawctziE9RuTsXiB4ecc8hU6wYN8SRM820u7hrHD8E+MY5sgGgQ9zZaDuDpRv8Q
         1QxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HuqJNT50QUo7sxtXwIO7aA6MX3mGhysSqrLdewhdh4UStmJdo
	cBRLyb8oy/oopn32sxLAL2k=
X-Google-Smtp-Source: ABdhPJxkA8hfUDS2Qn7KhBtB7Jkx6/tK3So5Jjg10eEQC4lEsO/zBK6n5QGBBqZ/KIdnkc8tUIP73w==
X-Received: by 2002:a05:6870:4288:b0:f1:b413:8ca9 with SMTP id y8-20020a056870428800b000f1b4138ca9mr12105463oah.197.1653287459770;
        Sun, 22 May 2022 23:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4e1b:0:b0:5c9:3fe6:39de with SMTP id p27-20020a9d4e1b000000b005c93fe639dels2466959otf.4.gmail;
 Sun, 22 May 2022 23:30:59 -0700 (PDT)
X-Received: by 2002:a05:6830:25cd:b0:605:c92c:967a with SMTP id d13-20020a05683025cd00b00605c92c967amr8018048otu.306.1653287459421;
        Sun, 22 May 2022 23:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653287459; cv=none;
        d=google.com; s=arc-20160816;
        b=dt1xg5KXq+cmf7PFG/isBEGYFlLFqYKLn5OvOIQyMSr9/vCUBRUhtlurdo1/JypeE4
         L517opG8naifW/augjWkepw7SK3LkGlW9k1131pNjq6Sj0kKd5IP7V24er9qNTmYRFvu
         zcnH9zhkUIHLyir+y0n4OpDKMrQo11Xu2ce3keMmHbJs4lz+vbJ7V/ZQVVbW98/FBQGQ
         2gdgWZ57RwP93ZLIBsMe74JyRG2HnS3UU2pPL7khzZfGa9b72HMggUV4lveaGUfJD8ID
         tVAMCDOs+EF+/221v0OsxUs879XfCfC1QDwY1AtWbZaKCshRWJt5zvCUVbHq0n4YxFLo
         uJcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:ironport-hdrordr:ironport-data:ironport-sdr;
        bh=U2T5JCpt22wtoz/m3BNhNSi8oqLGu6brVcFGsmM9QGU=;
        b=a4UJLGZk8Yi28bqRMGW8slRtl7Kb0O6UEfXY6J3b/x3eJ4r3fmcEDXuPlKZFDiVzVM
         8G81UbB779lulPDVNTQ3t4jkPU8jrnExOjS5OX8IAB4Hya/GMRz+eNQ6ZRrL2wI0PLtW
         mrUm46Jn6sPae3L1nIBpy9YllkllwXMtI9nmqlB2daGJu358hkTY6px7xP5znAFZjg9w
         b5gJB5PSNWY2y76rYAbznowE+bnHrraOG1uJN0zHzSiWAwPhN+BoBxf0poaauUS7Oooj
         V+RaAV2wcq2Ck3pUoPFoAA33djahJYDNBvof7TcPBCvwle1QZjBrpW8kU5HHY9AmnWY2
         VDxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.215 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from xppmailspam11.itap.purdue.edu (xppmailspam11.itap.purdue.edu. [128.210.1.215])
        by gmr-mx.google.com with ESMTPS id h24-20020a9d6018000000b00605f6345a99si482464otj.3.2022.05.22.23.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 May 2022 23:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.215 as permitted sender) client-ip=128.210.1.215;
IronPort-SDR: nnbxmAp3WC2w9hxp4UzB735Hd5mv9U4/fEVDZqIBp1zykMV6eu9D2T+Z0TZmNWhqWva1O872n1
 qEDrSkFFmUof2e5AvFAqgO4Fm64vuOOOY=
X-Ironport-AuthID: liu3101@purdue.edu
IronPort-Data: =?us-ascii?q?A9a23=3ASeMQq6MmfktlJivvrR2Nl8FynXyQoLVcMsEvi?=
 =?us-ascii?q?/4bfWQNrUolhmEEyjMYWG+CaPyKN2Hwfoh+OYnlp0wBuJSExtI1QHM5pCpnJ?=
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
 =?us-ascii?q?jDQnDaDGrF9qW/2oCb/Jdk4DDZWYR0B3tw/UTP3cVLQvh1565hUM3+nK6RwZ?=
 =?us-ascii?q?uqZAsIm16XxFtL7Utjba9NPZt56cwrv1DtpflKd03zFn08rnaQ+ItGca8nEJ?=
 =?us-ascii?q?XMbD6tg5CC7S+cUzfkgwSVW7WDaXpn9ihiqz5KRY3maTboKKlyTdvt/56SBy?=
 =?us-ascii?q?C3R8tBCJ46Jxg9ZXenWfCba68gQIEoMIHx9Aor5w+RTd/PYe1I/MHk8EfPMz?=
 =?us-ascii?q?PUsd5ENokj/vo8k5Vm8XENJkAe5jmaBMRiQZm1uLr7jQP5CQbsAFXREFT6VN?=
 =?us-ascii?q?7ILOO5DNJsiSqY=3D?=
IronPort-HdrOrdr: =?us-ascii?q?A9a23=3AT6cH8q4Ny7Mp8E7PBwPXwHDXdLJyesId70?=
 =?us-ascii?q?hD6qkRc3Nom6Oj5rmTdZggpGfJYXMqNk3I+urtBED/ewK7yXcd2+B4VotKNz?=
 =?us-ascii?q?OKhILHFutfxLqn5DH8FiXi/qp00Kt6buxYANn9ZGIbse/KpC61Dtsp3dHC2q?=
 =?us-ascii?q?Ghnvq29QYPcShaL4Zt8gpwFw7eOEh/XhNHCpoyHIed4M0vnUvERV0nKuO2G3?=
 =?us-ascii?q?QMQuCGiNXOlJf3CCR2ZSIP2U2ogS6k4KPzVzmfxAp2aUIq/Z4StU/IjgHw+6?=
 =?us-ascii?q?3miPe/xnbnpgjuxqUTv9f9x9NfDIi3htcYMTXwmm+TBbhcZw=3D=3D?=
X-IronPort-Anti-Spam-Filtered: true
X-IronPort-AV: E=Sophos;i="5.91,245,1647316800"; 
   d="scan'208";a="463330401"
Received: from indy05.cs.purdue.edu ([128.10.130.167])
  by xppmailspam11.itap.purdue.edu with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 23 May 2022 02:30:58 -0400
From: Congyu Liu <liu3101@purdue.edu>
To: dvyukov@google.com,
	andreyknvl@gmail.com,
	rostedt@goodmis.org,
	mingo@redhat.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Congyu Liu <liu3101@purdue.edu>
Subject: [PATCH] tracing: disable kcov on trace_preemptirq.c
Date: Mon, 23 May 2022 06:30:33 +0000
Message-Id: <20220523063033.1778974-1-liu3101@purdue.edu>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liu3101@purdue.edu designates 128.210.1.215 as
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

Functions in trace_preemptirq.c could be invoked from early interrupt
code that bypasses kcov trace function's in_task() check. Disable kcov
on this file to reduce random code coverage.

Signed-off-by: Congyu Liu <liu3101@purdue.edu>
---
 kernel/trace/Makefile | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
index d77cd8032213..0d261774d6f3 100644
--- a/kernel/trace/Makefile
+++ b/kernel/trace/Makefile
@@ -31,6 +31,10 @@ ifdef CONFIG_GCOV_PROFILE_FTRACE
 GCOV_PROFILE := y
 endif
 
+# Functions in this file could be invoked from early interrupt
+# code and produce random code coverage.
+KCOV_INSTRUMENT_trace_preemptirq.o := n
+
 CFLAGS_bpf_trace.o := -I$(src)
 
 CFLAGS_trace_benchmark.o := -I$(src)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220523063033.1778974-1-liu3101%40purdue.edu.
