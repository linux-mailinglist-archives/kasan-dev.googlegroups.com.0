Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYEBWTDAMGQEQZTE3PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DB39CB88187
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 09:06:09 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3eae869cb3fsf1204636f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 00:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758265569; cv=pass;
        d=google.com; s=arc-20240605;
        b=N7vnKKh5+mQNnnH1IhFTj6nc6/KxHrQswMrI7tQ+hjaNlGNRexeat6ziUUf6tVd/cu
         7aAQCPrWJB6JwvSxBBxt04TU+smus7oWnn0RXBwytVoqAcnAJuCOjZcypthobeM49cx+
         49vIBpYme53nfYSP5BAys8YSsni3GTs9T82LizqV+QBw5or4lHn77TOv5vDFNiG0O9v3
         cdE6XBVDt8fLaJfeY9lfhL8xOVb/gVwbiDYZOAYOg/AfBQxilO/0tT9WF51EK0vwn++m
         hDstHpFZHbmTEqbYgXOKf7YYcj1ppkequ8tFL99UKziano+YMXoFeq7Pd9Qpy/oMu25F
         izeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zCC4Ye/fWuiBHgSyVLKCMiYc2TM79hqY9UNJgb32xNQ=;
        fh=TuTpljinFiv6vGgFzcgZ5Kih94wsPA+pqdOnZvFyptk=;
        b=IkyN0mLIfKKAo0mER+6QWLEaRj1KPNIZb8JiYgn7RtHiN80LftihgRYwReiPGxC282
         zeY4r6UoroCvuE9GFX6ywSq+1Qmcf5YEETeRSMzTm8oERTgM6dhSuYd86EKFwkqrV64V
         96tOTI4PBcHvwV7gMLRzW+d+VeyGR/2+lSwQiYiqRNsagPmVK+Yvi/U8yKlXRslVVKYT
         ja2JR+7+4cT79gBbCCezy9jJTQHiJ5ysrzwQ5nWMFJWzlqX9hhCVs+dOZKT5Q1SJBGLY
         94w8H0UcdvjD/jts0dNPkA/6kxoWv8pm0zPXT8zZWKR3XTG8yPNiT25sIJFw728F6y0M
         TorA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xlW7nBXF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758265569; x=1758870369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zCC4Ye/fWuiBHgSyVLKCMiYc2TM79hqY9UNJgb32xNQ=;
        b=cWXenWhhG43htz5RV3kbf+VJRWjsh/sJBR97cwpJqA+sSjH6IXj48BK2JtCWpXsq71
         E+FZwai6maOaUNFwZXY31dfUTo7qhWL9dNh3L7w7qCMK6lEguEfCFQKpH2zCldUnZIve
         pTBUxp7ZIOfMBsqlYYKs3H3N5svjr6ZP+rmI01V11Ohzkiz4u+pSwZYYb1q16MapsaxQ
         yCy9mXnGeyHirVmcOaiwlwhQICFn+O73SDahovYZ+aLhoyLk/oJGhQixvU5BD1DKjpWC
         xSXYkZdHTImePWe5kQ8eI/4bGwyKYKaCWffnkxa6ARvSy3IGAG4SvUxHwL4Ep9L90Eys
         6bAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758265569; x=1758870369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zCC4Ye/fWuiBHgSyVLKCMiYc2TM79hqY9UNJgb32xNQ=;
        b=TYVim/8pXf/5Ud9dZb+c8yEOw9ghpDuH5TCTYfHUlhpubs3X7oAeh3XkAqTnrwof+u
         /yjuBVQkumAdfhAGQMAbnZbp+yJO0oVSCJiAYZPDUPBuBjLX5ksU8jwVwc06yhpBHX+o
         m0cZkLc1/iIg8c4JFoGK2Fpzu+0IvhJD8huKJx3X1chSPl27UPVgRXV95fnePEPCpJx1
         PTL138PEDARZTr7F1+HjfnxlmXxRctk+tKhxv6Fk7/ig6DS/9uVTGdtQy7lEZdCg3/wM
         ffC/RFxbzQCdcuxKkwwaSSkl5y6rXFNF/gcb/bkM81urbr9ljJdb750z2fN984CU83mZ
         ROKQ==
X-Forwarded-Encrypted: i=2; AJvYcCW7Y5pb2ngUu+ZNj0cVPtRqXPWzMjgqtX5IBwPsxlOsh4VdNPda6jUmKhTSjoljXKcczTIj7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy9+oAv/kEGPqsV+ztOps0C5+w9Kc9UCsE7yVLbaSGNorLhNp8J
	hTzDVVl2MEXElGmbEQRJPLF8YJuIGiv8CThUemGb34RtoocpvsDvUFh5
X-Google-Smtp-Source: AGHT+IGA2PzYs/Rt8w+2tfqW20NYz/eaponIxclj0MyUwh9qF6+rStpj6jD+4oc1Tu576KSFgq9I+g==
X-Received: by 2002:a05:6000:400c:b0:3e8:b4cb:c3dc with SMTP id ffacd0b85a97d-3ee7c925658mr1623881f8f.3.1758265569131;
        Fri, 19 Sep 2025 00:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5rrGWZuHP5Uc05VN+ORW5RQ9iiH+9lv6Ulfpx7LaxlSQ==
Received: by 2002:a05:6000:4013:b0:3ec:3280:5fc6 with SMTP id
 ffacd0b85a97d-3ee106a1289ls1135261f8f.1.-pod-prod-07-eu; Fri, 19 Sep 2025
 00:06:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPwhssa614BFXFerGiKrfUhKcWlgmNIZt37VEEOQcd809d1s/kuvEnL2rvDK8SQKC7ueRVGS1rKPs=@googlegroups.com
X-Received: by 2002:a5d:5846:0:b0:3e7:4835:8eeb with SMTP id ffacd0b85a97d-3ee86d6cfbfmr1653287f8f.53.1758265564318;
        Fri, 19 Sep 2025 00:06:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758265564; cv=none;
        d=google.com; s=arc-20240605;
        b=Q3HglKt7uRjSRwhqXfizHJMc11q8f6Wc9+P6qpuV1BJOG9Nk9PvyC0MXh3ZJgwP7Co
         k6XsR3g69FVnAbIHbEMslMSQf7/gut3A1pkW4sW7aAeDdA9Rw0im5SAjUNMuDPO+UxlD
         W6ErKBWA2AZJnn2Y6rvrWiduSeeVIN304+u+3SE6n4t5AuiCPARAGw+UH4qV5LeLaBi+
         3EsCq10Q2JSfX6RggSUhEE1ktiJYRPXFnXky8bLN99kgjIZiH2WM6wD8EYUMvCbTcGeD
         CKVX+KvVIW1KWWcmySfVy9qYFrsSDRN2yjPAZ/8errSkeX0/G0mY43aOjPRhKGCbqW/u
         FIjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/Klo+L3KBBL4ssbFZ2YOqJt7BcxJ8M+dYCfYzeUYYBY=;
        fh=l4zMzvSVhHei27JBe8zAQGEDtyblsBM89CAoUT9/XlE=;
        b=CooH8BwXiGKg6N/SsqRPUjs+bPWcF6uewpwP7bXBS0Ykr/NqZYVml1er4UNER0AKMt
         G1mzsUFSSwVG/R7pInETZlfeGQOES31i9S/GyZa0atd96mmXf/o+4qoNQWYlGP/lvSF+
         PWW+2H223CmEOrcTi0KHkdUy20oYC8LfMMyGXejLVFo5K37yj0Zh4dL544xxK+5YzB1A
         hcIj7UQYyZLkxi3PK1zLC4dUQE/wYhuF1fBqA2c6mvdx51L32teOSrutC6OmVM1xqsFJ
         pe3UQ3eoZ3nfWEMOZzRz0csUJGRjMty3LHpZTQcT7TuBm+nI54/vKljL3D6V2u670RGH
         kLjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xlW7nBXF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3edff885cf2si91255f8f.0.2025.09.19.00.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 00:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3ee12332f3dso1432889f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 00:06:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbTKVzJoSxGONLqK+hHBzxECHPyxsHpC4Ei+2S3X1TdMZa/tvfa9E0RLNrqB7pGfju0JMj+eJD1X4=@googlegroups.com
X-Gm-Gg: ASbGncuf56esjbIqVAGkZ8IXwtzEoXtHn0MuCduPExz5aQs6m5pXEazbXOTsOihelH2
	22400hpNKzEn7J2e5W3LSX9MrP+wmuvVoGpPQeSaTLBjbTFpDlHKyWjj0W/guiGeagS1q0UFM/h
	3bRy+nyGgA4MGnZYwGs6ssJyPjFpH4ueKVEO4XfFujmE8ViqU+BFxZvZL5YAQFct/AIUF17m1XR
	A28W81xpkecmG6XbbqQzRPEeR2VxxUWFtussoxODYQTi4HpjWzKlIgAvg+JPXXdr8ISKawzEVDd
	fQg6jYQrqaYxs8hykzpD0X3UotNcMFbGnWHI1lqg2kWWxH2biQGJbON5r1USdlPrsr0G8ef8oY2
	W7Z7aMGdeuANSMtr4yxZjTV3/1rd5yixzf6rF/k6K3i1KbYt0jr9IPIEQH9k=
X-Received: by 2002:a05:6000:2c0b:b0:3ea:6680:8fcd with SMTP id ffacd0b85a97d-3ee7c925245mr1570227f8f.13.1758265563176;
        Fri, 19 Sep 2025 00:06:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:1f7a:8520:7568:dac6])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbf1d35sm7200088f8f.55.2025.09.19.00.06.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 00:06:02 -0700 (PDT)
Date: Fri, 19 Sep 2025 09:05:54 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot ci <syzbot+ciac51bb7578ba7c59@syzkaller.appspotmail.com>
Cc: arnd@arndb.de, boqun.feng@gmail.com, bvanassche@acm.org, corbet@lwn.net,
	davem@davemloft.net, dvyukov@google.com, edumazet@google.com,
	frederic@kernel.org, glider@google.com, gregkh@linuxfoundation.org,
	hch@lst.de, herbert@gondor.apana.org.au, irogers@google.com,
	jannh@google.com, joelagnelf@nvidia.com, josh@joshtriplett.org,
	justinstitt@google.com, kasan-dev@googlegroups.com, kees@kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	longman@redhat.com, luc.vanoostenryck@gmail.com,
	lukas.bulwahn@gmail.com, mark.rutland@arm.com,
	mathieu.desnoyers@efficios.com, mingo@kernel.org, mingo@redhat.com,
	morbo@google.com, nathan@kernel.org, neeraj.upadhyay@kernel.org,
	nick.desaulniers@gmail.com, ojeda@kernel.org, paulmck@kernel.org,
	penguin-kernel@i-love.sakura.ne.jp, peterz@infradead.org,
	rcu@vger.kernel.org, rostedt@goodmis.org, takedakn@nttdata.co.jp,
	tglx@linutronix.de, tgraf@suug.ch, urezki@gmail.com,
	will@kernel.org, syzbot@lists.linux.dev,
	syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot ci] Re: Compiler-Based Capability- and Locking-Analysis
Message-ID: <aM0A0p4-3lwLeAWF@elver.google.com>
References: <20250918140451.1289454-1-elver@google.com>
 <68cc6067.a00a0220.37dadf.0003.GAE@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <68cc6067.a00a0220.37dadf.0003.GAE@google.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xlW7nBXF;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Sep 18, 2025 at 12:41PM -0700, syzbot ci wrote:
> syzbot ci has tested the following series
> 
> [v3] Compiler-Based Capability- and Locking-Analysis
[...]
> and found the following issue:
> general protection fault in validate_page_before_insert
> 
> Full report is available here:
> https://ci.syzbot.org/series/81182522-74c0-4494-bcf8-976133df7dc7
> 
> ***
> 
> general protection fault in validate_page_before_insert

Thanks, syzbot ci!

I messed up the type when moving kcov->area access inside the critical
section. This is the fix:


    fixup! kcov: Enable capability analysis

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 1897c8ca6209..e81e3c0d01c6 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -497,7 +497,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
-	unsigned long *area;
+	void *area;
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aM0A0p4-3lwLeAWF%40elver.google.com.
