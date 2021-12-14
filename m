Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B6F8474D89
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf5220721wrh.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=RdjZhmvY4HSwScziLW/8fHnmAZtzpWftZPtFhVHA6n664tEiKGzKWrpyUxu1PUOvSM
         ZlIWN1NG14zuQ0aunzNO7kTO8YWJ69c2bstePBKMGuhzoK6zsAVcUfmDl+APqU9FPdMz
         PCIzI4/9J/UrLe+xrFB9JZt8T7MbdKm+BC7xKIcoTsFXIabVbS+beoU7SIRr++bsR5Wv
         bJ654kXGeMsaFoyvBD2iofeJ2G7kb7Lt/oACyRC+5H/c/n61nv1Qazr5W2E65VA6mdSx
         ks3HQ7pkqUGiV1iVf/4pDesovLb1OkkrK2xChNMf+d+tbRzsxsadeUz+psqrqiN/kJTk
         eBzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uXvAu2rYcijaHlZfVq6lp+20PVc1TXpipyjhXaikIUU=;
        b=SxD++bwjJU3/xS0Lm+2KryG3SWSypOaFE505gdTMN3YtiaPPz5dXYUo5eDfA4cg82Z
         r4WLt6EpvQPRjuA/+tutn5toZoA/52u0BURnuOjDWqV+2r9BKHrkfMiXlIvelyMuUU+x
         Dtc15dAem7lXbd0FPqW+Qe47ijRDcsMgfjt6nCuTPtw3uvpMehxnbKISQC/sgRI097Zm
         PmTAB560VGyo0QJVvXYAABTwKxML+11MiWgFpNtwBx0P2Qttd6EwCUHqhin65wnzS3S6
         l6id6ePfbFLDjpUxeiNxwPMHC4bDyoETu1WRJce260B3ZjG/9oka3wW5NahfyQiGF/2D
         SkSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j7AGrtf4;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uXvAu2rYcijaHlZfVq6lp+20PVc1TXpipyjhXaikIUU=;
        b=V5KeQ7/5V3OnuZie57XyTkWkMUXDu8VVnVfqjQ7uQR0Iga9xgao9tSkg03cLHHFTKO
         GpOOYhpqZn/W5UOpq9MC0XBUo5dYGFfpho/qvuv1iJnx6Y97EIZo3uIad9OlXrNiNtq8
         HNlQfosQlkWUCx2Em92E2eWJt/cIIEPewUgI76Piv3cA9B/VKRcfKKCX5FI4nfNymQOB
         I9woelgJXzQRN6U6Vi+hsdrnvpzqbwgnZ9qpms4lKz2MDKBVWz5viOwGda1dvhcsEcRt
         4hPPxSqZl0cWGI3OmD7gYkvIbz/6sOIC9mUaff4MJhZf5Kb9ipVyNN4KTLNr5DZmIo0d
         TaiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uXvAu2rYcijaHlZfVq6lp+20PVc1TXpipyjhXaikIUU=;
        b=M4lCIVRm+tZ2+6CuCeLsGQ1XYlTAp4g4e47wgBSBJj9jFzditLA1y+QexuXp1geIbu
         ybyG+k8fdwkiZar+gOUbO/PPTuscnetolC6BqvjN1U6bH5kuct4uB1Qr+VQarZwIo3O7
         8pJYNnIVNiDH/TseclriGt+SRxM9gHDU+mLAuyG3MLkJMMxE4knfzJd7YBvvttbFfbDv
         z34PZAkmCGNkokg8PzpLEilQGCjvQaBfEX8Ne7FAI9iuF11+xvj/bnsQlclxko+XRDiL
         y7bsi2xErBc98c02Cro+L4XOcJgjCa+V32NFt9I+4Jabsy5PThWnZWS6aY/2EZXlRgaf
         5Jxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533v8EzBsDI0kEW2bDaXcXJpV2WYfUkpkjRbge871KFPjYG+oYyg
	UVmlxwhc5+GsB/w+4dm2lfA=
X-Google-Smtp-Source: ABdhPJzOabaUcUDL621VOu7HDUtiLT68k0qphRVwG0cJC3uMzVSqnj5mlauZzqrSva9CWAoYsQ+5Ng==
X-Received: by 2002:a5d:5381:: with SMTP id d1mr1744598wrv.500.1639519487017;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls207373wrp.1.gmail; Tue, 14 Dec
 2021 14:04:46 -0800 (PST)
X-Received: by 2002:adf:bb8d:: with SMTP id q13mr1698768wrg.364.1639519485967;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=DrBtAfhQ/AtGCb5Ed2ha2U2p84wwI2F7263q0IhpJXRT1ymhgsilU+ULWfRX8XQBC/
         YePteQ1sw4vVlRtP9qWOjv0n/1W8vb63e6pfgJFJPfsf/F5clCdHh/E/pE6d9ueu183X
         KKD0QMS2OitbK1O/RB3p44AFOLxi77n6qco4Pu1NAJPT9nhHLB/GNCP1hCMd2NIehlgn
         RQSe0x3MDyUSLp2bdq6/mkrRw6uMRLbS4Aiqw3FfEnAUQo7mUTwN4JfOK8E5kiztkJN8
         il65d60mRW53td1XlxmSTbl5zTlNvHdNmBDuu/N0i92NfnqZyVd4cLJiI51Z/T4iWN3f
         ULzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CcKP1isdtzFfxXoTuyyQ1HPlCLTA1u448HV+yT30cBM=;
        b=nSJt5PoY2DhDZnKHsSY42vYrumYL+xo1rYqCdM0nC+478D/0j+adQ8ReTckU99Kztd
         zBu6CefVmrpJxU56r6JgtZ424SFKtISYVchIES8SnK7rwPVei/93lBtDtzh5vx4T5ehQ
         3dBBw4M895XQMubkIpKeHEUIGdVgx5YGyopCxA/5DMtCoJBcfhiXYnijXEI11F2HWYW1
         uhTxkDTAdJ8vDp1UshwuYZIUnyYsGopQtcAnOjVXCxdtBZ9c+XdAp2C7fvEvP0PRzxap
         Wy7Pc4Zt3wGEhuJyNMV0OFOjyhdZZ6Vc8UNVwI698EkhDmYlQKOM7wfQNKToS+Ehdmg3
         xssg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j7AGrtf4;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o17si298858wms.2.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3A61861758;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 306EBC34637;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8285C5C1E85; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 21/29] sched, kcsan: Enable memory barrier instrumentation
Date: Tue, 14 Dec 2021 14:04:31 -0800
Message-Id: <20211214220439.2236564-21-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=j7AGrtf4;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

There's no fundamental reason to disable KCSAN for scheduler code,
except for excessive noise and performance concerns (instrumenting
scheduler code is usually a good way to stress test KCSAN itself).

However, several core sched functions imply memory barriers that are
invisible to KCSAN without instrumentation, but are required to avoid
false positives. Therefore, unconditionally enable instrumentation of
memory barriers in scheduler code. Also update the comment to reflect
this and be a bit more brief.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/sched/Makefile | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index c7421f2d05e15..c83b37af155b1 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -11,11 +11,10 @@ ccflags-y += $(call cc-disable-warning, unused-but-set-variable)
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
-# There are numerous data races here, however, most of them are due to plain accesses.
-# This would make it even harder for syzbot to find reproducers, because these
-# bugs trigger without specific input. Disable by default, but should re-enable
-# eventually.
+# Disable KCSAN to avoid excessive noise and performance degradation. To avoid
+# false positives ensure barriers implied by sched functions are instrumented.
 KCSAN_SANITIZE := n
+KCSAN_INSTRUMENT_BARRIERS := y
 
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-21-paulmck%40kernel.org.
