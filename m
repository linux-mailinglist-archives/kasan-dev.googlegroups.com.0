Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2UEYKNAMGQEN2SGBLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 83F516053AA
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 01:04:11 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id v18-20020a2e9f52000000b0026fef129a3csf3087538ljk.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 16:04:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666220651; cv=pass;
        d=google.com; s=arc-20160816;
        b=pIzYM953NChO68Pg9td8Hcd5BJjAsTLgSIIoYRoamwDYVbUttrtuXn8dX+SZrlBIIc
         2a3CzAEnYJEWiFEjXPXUL21mlSRO4J7XxcZrXxbxYF2WUmNCJXnGp0t4VK3FoBhMwwVE
         kOLVgBcNXw2Med97GpL1qxBaD+7/1b7R/3HwNbUOq/J2RLk6hxN4Q1h8gnwQNOXEOHkx
         XKiYskAIex5PxpoJ/l2k3gTe8OwR4+ni/cF7SxB6qxrpYYr4qiamv1eRhHxZ7sk+Yz4N
         VIbv8O8b4KdHc0t49EGMVkulpJY9mwsQYlI4x22qyODNdDB4wDBwigHk5kgQ1piYqo8a
         btag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/7sp1bZg1vhtI2vciXgGaLU7W4UPYKfd6oHJmjO8jbA=;
        b=lMPwSe9W/dY6R6yt9mmgfkLthFkc4e0UAZBwVnZE9dwA4EA8dhJ59JXDyVgPqGlwE9
         idVVQLbp9EN11ddFRJLBk+KF4dfDdNIKy+rL8e+LsDTpXQUkjQxvf5capjlhR3OqFng5
         m0fmb+WLqAtpV4sIz3dV6knK4+EOJAennDeOsFs+NIdHER11PTYWp/8OKBPYsNC8BUPZ
         XbBVfbPCZZBynipMMONw/2sd/KiC2atj19NC/PacIzWA2mPADX/xLanjkvk9pII4EDm6
         2F8X/jU6lOSI4I6LD8c3I/rMABnZVupXKbg3iKZAHoo+gmjrYV4SZfHgWqxf5kBDiG0h
         +JGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YrX9Uiwq;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/7sp1bZg1vhtI2vciXgGaLU7W4UPYKfd6oHJmjO8jbA=;
        b=Y532slmvWp/Pif1ctkbMMxMARjRm/Ka/8ufG+GH0biZgl6pNxThY0m8ZjOd+IhT2yV
         6P7iS2lMGvhH24jv2HpCMANEe753SBzKpPx0ZXAXlV2S+ZHiGBff1CpyV3FhvJXDxf1k
         Lw6TjIDZ6j5qICrT7PIntJt3HMp1ZHgwaA8Zb+BDthDByZJlNnlDU7tdxr0adqBvCCM+
         o5ZTVdZe2TlaP3lY85fMfb+YO2MhJVzbEfYgRzuX+O5+1tt7mGsH4A6Idu9c2Q+jffd7
         qalmcdiGlw7W/GamZHWhHZKMzj10Snw5G6aeKTIhpVp2Ls1pMpUXLem3ii1NL/9NY9pz
         gI9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/7sp1bZg1vhtI2vciXgGaLU7W4UPYKfd6oHJmjO8jbA=;
        b=LOOfbzPhTUrUP6WkNcAROaWMcUCVGxri6iFuosI4gAYAmO0K/401aD/03AfU9nnHT2
         +xI5QTz1ZNuC/BkVUSK5ceNLvZ6+cETnzhiVr64T9jMY+Q/fkL4c3AA4ga27YslnMtyL
         Vykg8Sfehe2GFcRGl6b4l3F18BdWOd5v1HOp1qZlEYLnCGvcLAHq5RleARvPGWnXR+9B
         y2i3T5TVHRDE35jQpxD1CtLCpPHGmFgFMAu5YRURyfKK9Nab85yvnMpDb9ig50re7IRy
         Cl6kZJyNNjGkbgqjO8Qv0Sw7ZQ/AICqarmEvHnq9tAhyS/MBjFPW99O1vz90KxX1/InA
         lr7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2rp46kUiEGzYI0HkBUCOjbGhr+UdfvHb03vR9grU00YOKizfWL
	O7tLK6+LzkGyIW4j6q8XiG0=
X-Google-Smtp-Source: AMsMyM5A4TMrEl4BMRTAEdPCzx1wn8GoENNlEmpVh+Tvhv50WehU3bO6aUrFR3glZ5E7KddZCvl78Q==
X-Received: by 2002:a2e:beaa:0:b0:25e:34d0:4d57 with SMTP id a42-20020a2ebeaa000000b0025e34d04d57mr3837131ljr.329.1666220650806;
        Wed, 19 Oct 2022 16:04:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:202e:b0:49a:b814:856d with SMTP id
 s14-20020a056512202e00b0049ab814856dls4825835lfs.1.-pod-prod-gmail; Wed, 19
 Oct 2022 16:04:09 -0700 (PDT)
X-Received: by 2002:ac2:54b9:0:b0:4a2:9c69:ab51 with SMTP id w25-20020ac254b9000000b004a29c69ab51mr4069111lfk.297.1666220649304;
        Wed, 19 Oct 2022 16:04:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666220649; cv=none;
        d=google.com; s=arc-20160816;
        b=Yl4ao5apcPr0y9Tsp0ixPDllSkulX1G1KxBibVPxF3AI+7Musc3jGM+YkjiqCsHjmy
         fIj/CNH45VD0nPq320/Swmp8/A8FwCVeJFVS6NzNK2hhfoy+Yd7fj7sqb6CdBiz8GxR/
         iFmLhTt8IdnkZRqqOZSrc6/7Ph0w+dNr6bM8g9rCK65kSSmuGyntU1NaTcuIITyGNAu3
         1+uYadXfpXPWhdb7oLqBMoKvAx1gMPoKQtdQsUSpOBJFBfHi5F12YzMuq93emrZit/Bi
         eLSGCO7dNr1V0xIGQJBgZCjyfLT2lws9lEG5muEdTeOLvHMxLx+FAVGgiRUcU3yyhKVN
         gOcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fUtCU4kEsogL3th/B1bpR7s1fXeGGqX6ji/5tcjGGAk=;
        b=j7qCkYDXXtrG1MSJZl+RKpOLoL8awyRs9MDf9zv15ST/8ql4yA464Wdt2JLIjcdofK
         Gd67oPtSJZqPmsZrTqAMFT55IL0WC8zqttAH1XqKMRL0lKtX17cK+DlgQqobEFjTBxN4
         D/b0RGhWMFHvtdXUyXHdSWS8xqYyJ6narYkEi1sg2g3uahEYLnP762o4gMzzHWyzSHI9
         w69FowunfYQA5QPTBmQGA/RwCUoL0ckEyQ+m0oeeV3N8RDzd/ywTpIhp0Rqasp4WpAt8
         j5cdKi6CE2KCeTMuzHZksl2NbunOCegNZ+C6xAAOH4wCNFI/htnDftMVyeQZWQSGuD32
         /9iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YrX9Uiwq;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u22-20020ac258d6000000b004a273a44c4asi618871lfo.7.2022.10.19.16.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Oct 2022 16:04:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id AD4CEB82565;
	Wed, 19 Oct 2022 23:04:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E0A5C433C1;
	Wed, 19 Oct 2022 23:04:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 2C6CB5C0879; Wed, 19 Oct 2022 16:04:07 -0700 (PDT)
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
Subject: [PATCH kcsan 2/3] objtool, kcsan: Add volatile read/write instrumentation to whitelist
Date: Wed, 19 Oct 2022 16:04:04 -0700
Message-Id: <20221019230405.2502089-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
References: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YrX9Uiwq;       spf=pass
 (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Adds KCSAN's volatile instrumentation to objtool's uaccess whitelist.

Recent kernel change have shown that this was missing from the uaccess
whitelist (since the first upstreamed version of KCSAN):

  mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 tools/objtool/check.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 43ec14c29a60c..a7f1e6c8bb0a7 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -999,6 +999,16 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_read_write4",
 	"__tsan_read_write8",
 	"__tsan_read_write16",
+	"__tsan_volatile_read1",
+	"__tsan_volatile_read2",
+	"__tsan_volatile_read4",
+	"__tsan_volatile_read8",
+	"__tsan_volatile_read16",
+	"__tsan_volatile_write1",
+	"__tsan_volatile_write2",
+	"__tsan_volatile_write4",
+	"__tsan_volatile_write8",
+	"__tsan_volatile_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221019230405.2502089-2-paulmck%40kernel.org.
