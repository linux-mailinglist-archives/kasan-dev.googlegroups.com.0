Return-Path: <kasan-dev+bncBCF5XGNWYQBRBI43USVQMGQE5Q4WFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E9DBF7FFE7F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 23:33:08 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35d42e84e99sf105085ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 14:33:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701383587; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBZmnBipD059WYoKOJq7fbe3N09Q3fuvdgBMjbqr61Z6+dAlPg1Ig1lmNXkJc8WnXI
         jP/RFR/9XHfTJaE4VXgHG4PRezM9IKFFBgWLOh0i3Iv4WBKd4GxwMBplyvXjUq//+R+w
         m7St2/OuQr8lDkCrQGJ6csvGPsyzSgNNYzmLZfn51wraiNiZsxEiWWgoiyeFEHE5yaBN
         Om2+VMAjONxagHEfVL5HyoK6cFNmvHjegBeuICpeaJSnMZR/P2gZ8D31p5POcudO+2iJ
         4xkVBLpOuQL2f0/5mIA0v2eIxDmJ6+xKQiK6XbhfjkuHjX7kQa8X3v4yCO5jsmzStzDj
         l+3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bpMRSvwmmEsD++iblpeT+WfT725HbyyRcYnzBIGr2S4=;
        fh=4PKixRBL+vOwfJMAlG/+6vj5WGpMCaAGILnrQyWlLe4=;
        b=UfkJkxsPOR7sowJUmlWKs53I12jY545QCD1ujQdyY+vXZOVCTpp39kpuhmltRLCKIW
         ylD9YuxcyCcO44yUP9DXY2IUhuTCEOI2ST8/Soxgr18DxxeHYXegrnaoFo4MN9Q3TP7A
         yF7N0IR0m0C5MgWHxaINHLARgiIR+mPQO8v96FfqyQQnjSjoJwpOq8BGLWn5J7HWWB9v
         8g5x/t9oH6HUPEOtT/Vv2P05LikcWeoqwZE0GtuE4ckb8+B9EpcweKtUJyezK7nIHmqB
         RzXL1ls+nw57Ka6MFIYCaMG1AbHcTQHDSrVRz2MykR95+bEfEEjCjOc8EPsuC/vvBLZ+
         NqXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AZc3EoF8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701383587; x=1701988387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bpMRSvwmmEsD++iblpeT+WfT725HbyyRcYnzBIGr2S4=;
        b=D06rnA2UBPoySgLF7aZZ4ODdLno2N0BiaZwgZhrkj7nfgOXXS2dFWV6v51rn3iQyo5
         n0iWy36g3WR8mxK5lyQa4ZzPUlJgKz2h1cjEttxp2jeLj3nfiTRfvShO7hve9Z1Wts2x
         tyhn//3IUhuiRmoywAUwPfUgT4yvJmMT21qm1Ps9PkA8pLhm+YGRlysSiqDLFCdzGdp6
         t1L8L9JkCu4frE/1lWqNQr+vqXEl8580/rcW8+KmGZ3aewN1tGKa0PFf+kTMEhPOvZsH
         TchwNa93vrbU2pHdqOzlwr/Wv07ObYx7nQ2RTJwGAx0Z5rl5kF2TfQuTTjsTkq3JeXA2
         /7wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701383587; x=1701988387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bpMRSvwmmEsD++iblpeT+WfT725HbyyRcYnzBIGr2S4=;
        b=goznzkBeFPAA7QZujxLGyJm7fW2ZuOPUjeOUAn2NBmT/ErPRsTrDneUgPW76BS9O0g
         zau26ZbJsMoT04lnDaFXXzwUhERCL8NijGd9C8f/10069sbyVpnMRYO1MhrLWmfB8Xqq
         NlSNC9d6RCxQXUDAOi0Xw1PK/NMcHSssqeKsd1RAdnPBoNtKoxg+0kMEThAkPi/5bW1I
         blOFTkPVjeMpmTnBZILY1A3jMCfnfQOVvyAzNTRrfZ3P8LWDCmWEdOHAuX05JpXoKUWs
         K2SjY0l9oB9ZARqQsLtfPoIEFNpE9q23aMyLYHh/6Qyb6rFw+zeyHiEqBU6Fiadl8CJG
         zvEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy3rVyeCNjeLUOO+ebCfPfFf1tmkqOKZfLcTayZck8dnkZe9gw+
	RsyBwR4rjcnxz/FokoOM1Ts=
X-Google-Smtp-Source: AGHT+IFr7UWWxihDxaeVnw1ZA7h3g2owtndFLdTyIerR12/ujIHh+8GH3dTYYhKFPG/duN5dgs6xYg==
X-Received: by 2002:a05:6e02:1aae:b0:35c:8115:8174 with SMTP id l14-20020a056e021aae00b0035c81158174mr37269ilv.4.1701383587352;
        Thu, 30 Nov 2023 14:33:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e6cc:0:b0:58e:9c:510d with SMTP id v12-20020a4ae6cc000000b0058e009c510dls76924oot.0.-pod-prod-09-us;
 Thu, 30 Nov 2023 14:33:07 -0800 (PST)
X-Received: by 2002:a05:6830:33ef:b0:6d8:1360:7dab with SMTP id i15-20020a05683033ef00b006d813607dabmr45885otu.2.1701383586915;
        Thu, 30 Nov 2023 14:33:06 -0800 (PST)
Received: by 2002:a05:6808:2182:b0:3b2:e349:d5c2 with SMTP id 5614622812f47-3b8a8292eaamsb6e;
        Thu, 30 Nov 2023 14:05:49 -0800 (PST)
X-Received: by 2002:a05:6871:2309:b0:1f5:b1e5:76cf with SMTP id sf9-20020a056871230900b001f5b1e576cfmr28070483oab.53.1701381949180;
        Thu, 30 Nov 2023 14:05:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701381949; cv=none;
        d=google.com; s=arc-20160816;
        b=XydRIRkaeI2d90ju/PrBQYzyaQirwfl/oPMfn9avVsh7vsMdIdlXBdTtTmIm2GUsNS
         YUqYJ3EgMr65pX5pNI5m1a1pet3EgcjGv8iqXyA80dFbr01nN9MKj3pHxDHYD2PUR60D
         muqTGz4MfdHGmLf4B7fqXLwPZtN7CC3/Q0sjCJugoCPyEMVqjH2mEEyC3DzYg3Subii8
         rd5XPo/WhD9eRVcq/Gl4GUM7i+QhaRvmKYoDvsGGzvA9OrfEXcOBSsO/FsQM9jBmKO14
         16ni5F1VecjUnb8AcW/MCggYS3zelwe/AOpUtLfP/S/3096L7iAGzN9g5LtBymv3lrg8
         3LOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E+z84/9szAuZC+Uij5uL4JYHHRg/gwkkJLqAhisbf48=;
        fh=4PKixRBL+vOwfJMAlG/+6vj5WGpMCaAGILnrQyWlLe4=;
        b=iPbiGx/dKK/JpgELlk1zulu5QR+BkrvB0BVg5OsfGEygtJtGRQ8sCw/cnyL7bU/oRZ
         YuFhVbZG27rxpqYVBOuUItjhCwpwKnfByu/lrSfQjDLqEZf6u22AaR23TFhFdTw/3N+H
         KAqcZQrNSIzK+PPmOwXkF360+meXqkLEobBKramIQmvWzX7O/y9j2MoBDqgunZA9P1M+
         QXvn0Hl52O+St2skg/DJHWd4APATdEOuybMK59Y2aqs53KeCl1Gd5A2IlK+fz3ltjtv2
         J2LmRZ9/zYvRfvsRjfiBP5zPhtppUVGGCzqSfwQFVb2Wb81A0SnEFklboDlZnFMcYXXZ
         v1Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AZc3EoF8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id l2-20020a056870f14200b001fa14d23e44si502423oac.5.2023.11.30.14.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Nov 2023 14:05:49 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1cfc3f50504so13527785ad.3
        for <kasan-dev@googlegroups.com>; Thu, 30 Nov 2023 14:05:49 -0800 (PST)
X-Received: by 2002:a17:903:2345:b0:1cf:d8c5:2288 with SMTP id c5-20020a170903234500b001cfd8c52288mr15051983plh.41.1701381948433;
        Thu, 30 Nov 2023 14:05:48 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id n7-20020a170902d2c700b001cf65d03cedsm1890895plc.32.2023.11.30.14.05.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Nov 2023 14:05:47 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Stephen Boyd <swboyd@chromium.org>
Cc: Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] lkdtm: Add kfence read after free crash type
Date: Thu, 30 Nov 2023 14:05:45 -0800
Message-Id: <170138194305.3650163.16392122923355361827.b4-ty@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20231129214413.3156334-1-swboyd@chromium.org>
References: <20231129214413.3156334-1-swboyd@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=AZc3EoF8;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, 29 Nov 2023 13:44:04 -0800, Stephen Boyd wrote:
> Add the ability to allocate memory from kfence and trigger a read after
> free on that memory to validate that kfence is working properly. This is
> used by ChromeOS integration tests to validate that kfence errors can be
> collected on user devices and parsed properly.
> 
> 

Applied to for-next/hardening, thanks!

[1/1] lkdtm: Add kfence read after free crash type
      https://git.kernel.org/kees/c/0e689e666214

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/170138194305.3650163.16392122923355361827.b4-ty%40chromium.org.
