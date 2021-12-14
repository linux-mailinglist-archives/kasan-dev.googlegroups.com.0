Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7NJ4SGQMGQELIIP4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 56B37474D7F
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id i14-20020a2e864e000000b00218a2c57df8sf5955422ljj.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hxrq3tvcQmh+qzBLCGXfLAasmzudVoxiA6AshjcqJx33xlB/tYxGfxUBi3yXcxwX+d
         kWq7zgytKVH/lDcnEgFvwiQqW+Waq5yxBvBnVdDVRmPqMedZJu3vXUkbQwRAtE+K5y6g
         WC3qmsZ9Gkbj6o1xVDdq11LQ77kB05z/lfmQcp4pPHiho5rg+/cjVXH8ngaPeA0WXVY9
         xnpd0bnq5XfIrF2Fh66oYS3LdRw6Tr0zswZM8HGUQ++Dl43TWR8tP8nKN0SAA/ttTwWl
         27Qs5Jrz9ndvsji3yaFV7/BfwUE4XVZjk89Mh6DuI1LvsstHPbro7mqVyO6paPmgRjjh
         y9bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=76M+TJDwDL3uqo1tPeuKiRo7VL3IAzuN8seqN/lHE7U=;
        b=Dei59wWDyIohhBOAWSuFUXGeAL+p/7qngmgLKGxQ5pzjdwfbH4Szx0pYrZH3caezHj
         FN6ml5RisltyMpcV61incFH8Nt63OxkRZlEROpKCPIHYA3KyrcjDo17XW2M6JJ9YlJJG
         VL99EAUr1SCjGasaCDRtURPWdBnRcytLe579pXbFyQOHzaLMCzlnS9nTVXegBzg7oQBx
         0L3AEuYq9WXtMKDDt6AGpw/T3FdNZp3EUw6KF+273E68z67wOv5efeS4l9PFJ8+7VtHY
         hYJ4c+E49qOn8VeM3KJezyY4ii9LrmVUOztyZzCUWUklwUeNau4layDz/jOaCB4gO7PU
         O94Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SlOIAtap;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76M+TJDwDL3uqo1tPeuKiRo7VL3IAzuN8seqN/lHE7U=;
        b=aQrzHkclWA3Bv9YP2ErC3rkTDrwv+lJBC6Y1d6Gn5Cwi3QomNgwN8cPka1BY/T9fPi
         9U3BPtZgAcUAMZreEwq9svm8gzev/zU74mlgnDh+LPXfgF7aN5zG2EYYZkPovpQZM6fl
         yG9BABmdtrZ737+/96Whqet8WGQJV+HWdNuldUqoMjyBlCYs2+INDiiu8MLEE4D5XTFM
         u4ZMahJ99hdDzC6zhA8Qn2fypmwzVcQ4giVjSbvX02amvxFVdKLW3Wo2RU6AF4xrTL5N
         iktzf+7DpdQhH6KJWJDUQe7LILdEbfGnMRsJZ6Oerq4w1myL8vtucK3RokViVHmn810E
         7mGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76M+TJDwDL3uqo1tPeuKiRo7VL3IAzuN8seqN/lHE7U=;
        b=GhXhKQS1UliJE4fYFKhAiM1k2FTmAucWUJw1+NDCiVTtBq1GTd7UE0+Zp7XCjPz7+d
         VvWOyaOqLg8dUWZPWoYT4cAa6CdfdF6q9xzn09dRAm7wekEAhnxzCj7bAZhJL4rVRiF4
         Vh5fOjz0JJ3/oh97mz4BRnYZzp380xMkwrAbrJ0hKDqgKNQRgXlm0aBGu4UN7Nq5YYe1
         yLJexamimhq4ePLmpkMyYPA+5T5PABbAmfZWVvtfZeE/bln/IwtMv4g7/rQmAP2+/uRm
         34RodRVDeNj1+47D0YtlCrYVErpdvLlqKfh1NGSyhIJnk/4h7xC1XTn0jR3yAL8wws68
         CA7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JZBObteoNCB77RD7abbKC/FpALnZumEigaP4REsPWim/xGLNU
	+x7bI9qZ0a9cVGOWuxI2OuE=
X-Google-Smtp-Source: ABdhPJxFEotYPfbalcOGKMQasa+f0kJT1fkuNv/grblCzhyjZ4ku2znQq+fJqCDTB1oWtp4+Oq2SEA==
X-Received: by 2002:ac2:4564:: with SMTP id k4mr7132271lfm.380.1639519485725;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls95888lfu.2.gmail; Tue, 14
 Dec 2021 14:04:44 -0800 (PST)
X-Received: by 2002:a05:6512:3b8c:: with SMTP id g12mr7249396lfv.119.1639519484523;
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519484; cv=none;
        d=google.com; s=arc-20160816;
        b=AOHg7EzBravJTAHNY9HY3pg7J3jD4RlqgI9CqKlWx+iEH2Glxpu3++ef9vUczy7zTN
         iVLtAJQ5ai51RUjHuqop0X4cCMdtg0NEDHBHNuf2Wg9nPuW/WuG0jyRDhgNF/92U7au4
         M5qZyPqmqErmIpdhutslbWI6S8Vq28e1RSW//EyeQ12UWPsBWD8uCw+9HkaGLftwpSnR
         Mfwo3J5jRo38hiaCt5Q2iNMRBpaOPrZtVRkryu/4IvrpuGPARiDRk7bzf6UlSeSQGRq0
         syIRP04sIYPEnxLuvJB41p4VN5cI/NeKZz0+xRFpwAVzqo3s7+3ogyTH5UL1ttab411G
         OUpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C5NxDxuShxZevKqrWeeo+wtYPOwlm0i9M1fLGMrtwaE=;
        b=k636n7znGc9IXTOCovEuv8+PDwwa063olmkxBr0fIxWi8Qoox+DVCSyCwe1wEgC1nR
         7KPsYKfWwrAj0/svriDswOaIIFsy/F+6MItN8TO44YO2zimmAazMeJWiB4Brxvi0eKpl
         B3w4v2dNQ78sS7Q3RDq436ZM0M+QyB+deItYBonukUxCJQVXAEiovolDugRfLMsdtbzw
         sQIR3m/rP0Y6i4+ZtU6UlY0VI1WdaQ+vI3ThUV15KvWpV+AfLgMtTtK4if3GVNaH/0at
         3/j7tGIMOn6BvRhupVOCzh5InbYKS85npn3HDFkn8tQZCRcU9ZSbtOX4WCL+jVpTg7X6
         a8eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SlOIAtap;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e18si3909lji.3.2021.12.14.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 01D5F61725;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CEA29C34614;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 64D935C134C; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
Subject: [PATCH kcsan 06/29] kcsan, kbuild: Add option for barrier instrumentation only
Date: Tue, 14 Dec 2021 14:04:16 -0800
Message-Id: <20211214220439.2236564-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SlOIAtap;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Source files that disable KCSAN via KCSAN_SANITIZE := n, remove all
instrumentation, including explicit barrier instrumentation. With
instrumentation for memory barriers, in few places it is required to
enable just the explicit instrumentation for memory barriers to avoid
false positives.

Providing the Makefile variable KCSAN_INSTRUMENT_BARRIERS_obj.o or
KCSAN_INSTRUMENT_BARRIERS (for all files) set to 'y' only enables the
explicit barrier instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 scripts/Makefile.lib | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index d1f865b8c0cba..ab17f7b2e33c4 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -182,6 +182,11 @@ ifeq ($(CONFIG_KCSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCSAN_SANITIZE_$(basetarget).o)$(KCSAN_SANITIZE)y), \
 	$(CFLAGS_KCSAN))
+# Some uninstrumented files provide implied barriers required to avoid false
+# positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
+_c_flags += $(if $(patsubst n%,, \
+	$(KCSAN_INSTRUMENT_BARRIERS_$(basetarget).o)$(KCSAN_INSTRUMENT_BARRIERS)n), \
+	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
 # $(srctree)/$(src) for including checkin headers from generated source files
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-6-paulmck%40kernel.org.
