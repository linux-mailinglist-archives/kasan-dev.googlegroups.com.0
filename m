Return-Path: <kasan-dev+bncBDHMN6PCVUIRBTN6Q65QMGQEO2GFVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA5369F57BE
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 21:30:07 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5401a41056fsf455172e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 12:30:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734467407; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wt+iKGNYHg80FRp57brExVRX14Q0RghQ9ZRt6FDus7YGpd+ClkhbKCPukBJbCLuOPN
         kxgbiIH5RIICVH/f7dSEFSsp6MxJe0him9pTfLdNdh+Ty+C013Z56Ty2LX8a47qJQEQ8
         BmjzG8Q1w4MxA3Pm3noiEjFqmueAgXDwLAibqo989oZNC9tDtJFRDGWlsEHNoufbT77Q
         2INheov/3vJmrZFdsfcsvATgSYvtpzNNf+v664/VCwZvtbEBy/PNZOqyiYjiPjOviikI
         gmNCTDzpbMfpMMmjh+jHGJ4Mz8Fl554vQBhHFH8srlezXInLPK/3EEDI/5UUJdPGhZ5I
         pEZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VXVEylPwlX+lseSl2+NyiRBussSbKdYSITQouy8iHTw=;
        fh=g3BajIRIAu4Vk8GSgZmf1r2LUXZh0bBdnU77LfCXaTk=;
        b=J3O96bTUFGMO2Q1EQ8O+QtFXKK/5SRRgzcf7+KEjJYWAN2GpiY595Bk7iif7mzl9nR
         /pKiro+jHo8dVT87ZFmfwz+pGGYjIej7BtCocQXfq6QdLz59RaIPAmviRTFTXPMjc6Pl
         qCjR9UdVoZzuW9giM8yeJSFGz4qNxXwhDDldyGTvvUKGcBQlTI9sRji6pDnx/xq9RAY+
         Vhg5tynD5Ntt1k/1Id7WKVVzi4uhSAA3IMixjCZkp2w8dA1UnuJV5jXazep99wGmj1wu
         FJgvu6FTlALhG4Y5IBxkVAITuh89PyK684ct6vdpvwZUiy8lNIUmqKmZIR/Sym76/pBg
         W3mg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=TdofIxka;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734467407; x=1735072207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VXVEylPwlX+lseSl2+NyiRBussSbKdYSITQouy8iHTw=;
        b=GhSjzHHAtBQ0VkZbWiO8auVWZVRcPIEEwa7uGBUMdon3sr//lP2OpFtEvxqDbeKikQ
         BrRUH+Os6p+wtvoQI+pbejg1i4RJuNLtss0LINusRRhxHUDcXbXGc3O2BKjQpSVQeUz0
         Qy0FGEaa01yqay/yfINzgOVwfigv3mUW6P9yTQeU26Q3b++zB6Tpd9rx7JA1JqqMMA9w
         c1JA75KVsTlM3lrSvZIMTActIjsGKTuK5y8KQEv+BzP7x4SyPWHwx29IEfgOqsH/Lqpy
         n22pACIyLsQtV5ikO4/3zf6WD98fJEKmg4BjUS2eKGt/bOlg5boeOWV9DC8vNpMw1xLm
         QZ6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734467407; x=1735072207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VXVEylPwlX+lseSl2+NyiRBussSbKdYSITQouy8iHTw=;
        b=LV/YqpRS1uXJrOXTF9aqgsCdrVJQPzMXgwTFA7pO0eFbWU5Of235cVjclJb45SKcqf
         qaDKF5FCIiENYODiB4vmC5ZsbDorDH82757G1TCCaSndDddzCg+gn+32IhXRMh5ApQJE
         s17MMGmSXAlQ79yyoVjFIkzwhrBKnJDsoJGPCi2K7JG8PXijBvuDv2IHUa9EY6xr8iZO
         ZXN+N5Tgz9aeMgaF0J5LCTGrAywspG+rUd3HJ/qzp6Z7cUauwRpolcdj81vAJzsaRnFh
         DpwYHlvf4Ofcr5IHrBLCsJLd6bpVACeYBFQhp16Aj824EkKeIrM6MXz5ij5Q/vT5yus7
         RugQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvflHWrIKWa89fLDJityqT/tq2DUIAoVZXdZ/rkCTaTXNh7fJh/IAfh3yAx18kB+nqxX9H7Q==@lfdr.de
X-Gm-Message-State: AOJu0YwvjyQDHxjMOomu4lhXCMgUCGWSzBwJ68/S99iE07UZ/4qrWhnn
	UuDqWPzawZdayOR4cXzVpNrrqKXZ+i+QOZOk2hhfEwyAP8SctpUm
X-Google-Smtp-Source: AGHT+IG0jgiy+m0sKpvBUgfQ/x1lv2DJc/dFEKr28rkzxt9ePa9aYXjsYQkgTR4yn6x8ZfpscT7y3Q==
X-Received: by 2002:a05:6512:2214:b0:540:3530:5a83 with SMTP id 2adb3069b0e04-541ed901bd4mr136981e87.36.1734467406174;
        Tue, 17 Dec 2024 12:30:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:592e:0:b0:540:216b:9667 with SMTP id 2adb3069b0e04-5409a258b5bls591113e87.2.-pod-prod-08-eu;
 Tue, 17 Dec 2024 12:30:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW48OZJalnSqKb8lARRSlfafYZ1PLGnyiIViIih0wulQ89lhYoW8+5AghApgVsWCmGEzjRC3Z6Hcmg=@googlegroups.com
X-Received: by 2002:a05:6512:3f15:b0:53e:383a:639a with SMTP id 2adb3069b0e04-541ed901b7emr135052e87.37.1734467403585;
        Tue, 17 Dec 2024 12:30:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734467403; cv=none;
        d=google.com; s=arc-20240605;
        b=XqSDqAUoRJRxYQCS1aUEeucKaLK7zIoBD7TQ3sKNV/PF9YgHAZQYJ4anPG7CeWpXCv
         0c6W0XTuvjjm9yD5aEidL43qgSUBqS7WjpUYXKb6UDq7GcT4BLqU5VXIHL8h2gX/b3Vi
         N2nitQLzZdxL4zS6kJnw7r7ekOdaqkGQLzu6w6sjN5ML9bux1shgNyc0VDXU5ppNSaXN
         TAIwWIWGtVkcRooQqDVBJQ2A5Bz4vPqFz10KjRHGhL6fBM63LSYySlO158RTRTc/Nj1q
         OMsFEUx4KjDmrUGSxQJOzIH8zQFiNJtJGkGlrLVwshFZns7sglCcSxhgrzCSJVs39CIm
         XSMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/v364bvrO8lfqCXGMi7TqSOwSVU8ULaOAM7RRdJHOaE=;
        fh=k2Z8B0SyaWkPc5Fxzj03jgfC6ikcy0wx+bFc5bYaPPs=;
        b=OOWsodBH7OTvsg5Ps4I8RBAaVJUsCeUNudrYFV71xxPJuQPLmAAltU0G2Gdk/mU9b2
         kQ0a2aDy2CdbfncopR/qC0RxXumartfykO5G83FxH6O+AprHu/Rlicy+K+pGvkvEmbcs
         viY+MXd/eoi51iDh25ViBPPmFb23r9Qi/ufGDh2MYcEdqFUZBqCqgx9SEMknSBh/6IPV
         3HCDSvpUuCaR0G4wTYDsR3fpEiWlmZWDMg1DceCA6JHudmJ7DTRGqxQUiqoa806XhVsy
         xSeQOM3mAuMOyqD5Dj/QpM2Of2lXdh3nyKA5eFkm3jeTN6ctBnjNXvqC6q4Qz5/UzV8W
         /nbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=TdofIxka;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54120bb80a2si104164e87.6.2024.12.17.12.30.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2024 12:30:03 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tNeCd-00000002NwX-26Tm;
	Tue, 17 Dec 2024 21:29:59 +0100
From: Benjamin Berg <benjamin@sipsolutions.net>
To: linux-arch@vger.kernel.org,
	linux-um@lists.infradead.org,
	x86@kernel.org,
	briannorris@chromium.org
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Benjamin Berg <benjamin.berg@intel.com>
Subject: [PATCH 0/3] KASAN fix for arch_dup_task_struct (x86, um)
Date: Tue, 17 Dec 2024 21:27:42 +0100
Message-ID: <20241217202745.1402932-1-benjamin@sipsolutions.net>
X-Mailer: git-send-email 2.47.1
MIME-Version: 1.0
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=TdofIxka;       spf=pass
 (google.com: domain of benjamin@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

From: Benjamin Berg <benjamin.berg@intel.com>

On the x86 and um architectures struct task_struct is dynamically
sized depending on the size required to store the floating point
registers. After adding this feature to UML it sometimes triggered
KASAN errors as the memcpy in arch_dup_task_struct read past
init_task.

In my own testing, the reported KASAN error was for a read into the
redzone of the next global variable (init_sighand). Due to padding,
the reported area was already far past the size of init_task.

Note that on x86 the dynamically allocated area of struct task_struct
is quite a bit smaller and may not even exist. This might explain why
this error has not been noticed before.

This problem was reported by Brian Norris <briannorris@chromium.org>.

Benjamin

Benjamin Berg (3):
  vmlinux.lds.h: remove entry to place init_task onto init_stack
  um: avoid copying FP state from init_task
  x86: avoid copying dynamic FP state from init_task

 arch/um/kernel/process.c          | 10 +++++++++-
 arch/x86/kernel/process.c         | 10 +++++++++-
 include/asm-generic/vmlinux.lds.h |  1 -
 3 files changed, 18 insertions(+), 3 deletions(-)

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241217202745.1402932-1-benjamin%40sipsolutions.net.
