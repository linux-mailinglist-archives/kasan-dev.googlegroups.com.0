Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOF6Y6SAMGQEWCTKXYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 94918737297
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 19:17:45 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5166c6ff004sf110830a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 10:17:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687281465; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jd7xtnNm+x0LmFRMq1EFOllOsIcnZI4zqvhx5KJIw2pbgmBsE3bQMMBJ5SVPoLbxl8
         5BpmxkfedD4ojOSRBgE9eK6KAM+gV/XCSRtiLKuRKr5yVz6rMQ5qnCAPUDJ0owFCaqmf
         mVOxf5UMkHtZZzzZGG8uWM/o4m5IUZ5VrUBR3GUxrQiisfaQXsIBDbqKrev9QYDwAksg
         SflZA6VOjahqRrfSGRHSHqtd/0Lq4tPzElNSnh3NGETEnAQrQtKBkXYQjWXuimmgqr8A
         KcU/CiZsfWouBOYz6vcRMBUC243pHdPQMNVeYlwvKH2lLVAh4nWE7BXQ3dLCT2v3R1gr
         H7Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MyTuFa8e9N2pEk8PJIvN/vU1UcgsLBMjr4wUkrXJvjg=;
        b=u/8zqfQ5qqwX/xPvao/3Nx5ty2ZbMLO7yxA3soSdoFU23/Zt17swgjHo96lls8h59U
         JvjZzIz1/ZZK0x/st6MI3etJouBIqHZNMQr7pDTlJZN9bz25EYUEszVECyPv6072+LXG
         zqB97SmBCe9Rn2bLQGMXyiNGoDN1ohvwAsp1WuoSO3gS/QhftKtVtMyYitjbwXaBOGJL
         UG8FnMqH8/qs7jjmVaam0jrw8U1MlTJdJPYFQlStr1GzEGzthkHG4vPm2Gn7yFUMGrtW
         RDL8N7v7ff6WzQGq6A0UHEfRfb6DMF1rZ0ZDpUxS6kLcNxJiflyVd0ld3uM/r0swkG8r
         N1sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=BCP+qIWJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687281465; x=1689873465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MyTuFa8e9N2pEk8PJIvN/vU1UcgsLBMjr4wUkrXJvjg=;
        b=MFPi7x0JpkduRrMdINRjQlq7oST9HY6hn+l8ARKY9U28bcczkslBqosg6f3zQs9JrX
         kJ7+kk5JfG6Ho3F3CgPn4WL2AzQh5jmmYW19BDRKaJr7ubG6IMWl2Qw8nS+nKqL1xclP
         gCDSyxNIHa0wMuk9yI0mL1eQxQ1WDSVDdm3GNfuCH1xIsq7nWmEFgQYONKCZi7gRdzTf
         4xawEssngls0cVem8VrsSl6qMCocirLErMSvimwLOBN4tr2NxDhnITRU161Sw19/jdyH
         nOoRkJGLKtR9N5Fs+tR+fBrdrvbxXfI1fB79DSt8L6uN1ABku86dqN47Qdoo0rEkzHwm
         UC3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687281465; x=1689873465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MyTuFa8e9N2pEk8PJIvN/vU1UcgsLBMjr4wUkrXJvjg=;
        b=ZujSSXBsE0hEs/3ReA+7DLavBc11DX4fdk58vxr/ZL5o8+9IEJsxJpT42dwcAqKruU
         JuxIK/oVSktTsgkK1ZB1pyZhKtwz2U4AfUdagrbKY6Ra6MPg1i3Vgpmce0sJzeF9PUcL
         XkcttDWYpN6XiEaZzLwQ2OcMjIBpqtUk3yxwdsOCSaJvyfiTbVg9Dvuc6DMEfcuKiild
         MlzcaNol0fOV020h2dkpX08IRBTEdqnnp7sxaMbb9omzxqpkANrbubcI6s6lCt049l7m
         93G5g/hkKsmkK/cVwTS/g6J4whjeFPHTkbcu2L/5mG0cwFa7is+KpCpMvmnA+kIo/30B
         AEZg==
X-Gm-Message-State: AC+VfDw6DcNO24BnrD2MC6rINZToE5+JGqCIWXRqZt8QnCLPOAdqJpJB
	YFOluqWZM9X0RVBc88M4vaU=
X-Google-Smtp-Source: ACHHUZ677ylG4oAVRbhe6trzWfvOhyurGXe7OCUftQ7nZmo8JngOSyyVMNwwHCRVZdyOitTncYcYvA==
X-Received: by 2002:a50:bac3:0:b0:506:b280:4993 with SMTP id x61-20020a50bac3000000b00506b2804993mr544634ede.2.1687281464493;
        Tue, 20 Jun 2023 10:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7218:0:b0:2b4:6dc4:68cf with SMTP id n24-20020a2e7218000000b002b46dc468cfls672129ljc.1.-pod-prod-04-eu;
 Tue, 20 Jun 2023 10:17:42 -0700 (PDT)
X-Received: by 2002:a2e:8296:0:b0:2b4:76f6:63a8 with SMTP id y22-20020a2e8296000000b002b476f663a8mr4578415ljg.12.1687281462826;
        Tue, 20 Jun 2023 10:17:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687281462; cv=none;
        d=google.com; s=arc-20160816;
        b=nUcL7g+wfe1gmYN6rbXTPxFZ0ooxGro1vB0iT2xSxbG7qYGhRLl+hkjDgvnpZ6Pu2Y
         60cNpuT8K28YrOdAyhQQxZplVKIVAeDKOZc8Waf2bb7tt9zukCFq5+o5Jl5DILuZ8cov
         +bF83Q4JNeHrA7HWihY6KokI+fQb4/SfdBxFRDJ5TwUUJPXWN0L3+sKPbPL6DT0Si2vA
         lw1ev01QANNU8OL3Tt5HN/GyfH3metdc92g501OnaNIl/ZhHc7rP4k/74kvHK1sbPJ+G
         TQW/iB88Sy41meA4357FPtTUkFmCjeb4aEJZSrxAvIrx3XN/gGUA5p3zXQPqZX66L9ke
         /88g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kdF5fJc3RpQKsA1Z6nsArhtDlSIHXXx5950e0HmHoSI=;
        b=aoVZIAMF1N32ycM9QGkTcTr6y5WLk90TOHHLfJTi6QNoDP4GBW/ipxMLllglgZ5AFm
         jUX+dDFhIPmoZcA1NdpoFcu6kP6FjPSh3cyams9+7haSVt278dDQHo7upFvX8gA2VKGA
         Ema+EL3J5imZovftjiqOoytY4m3sZHaU4Sxq6XRWEc/DVFqYP+5iGahB0mvUev/r4RrN
         WAXqn31J+OvMZrj6vpTVty7QMSZcqWosEL+4H69m7nLPt5grOpKbnhlpjTCycEKw88Sc
         b4TwRYP4uX6SEHa5UxMUayp6po84T4Qi2KAZDoVoAio11boQomA5fkVl7SLDtDPQUPOh
         9PLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=BCP+qIWJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id bz10-20020a05651c0c8a00b002b1077838f5si138810ljb.2.2023.06.20.10.17.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 10:17:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-3f9b4bf99c2so17087995e9.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 10:17:42 -0700 (PDT)
X-Received: by 2002:adf:ea8d:0:b0:311:1b8d:e566 with SMTP id s13-20020adfea8d000000b003111b8de566mr10135149wrm.52.1687281462168;
        Tue, 20 Jun 2023 10:17:42 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:8530:a6a3:373f:683c])
        by smtp.gmail.com with ESMTPSA id y10-20020adfe6ca000000b0030fd23381ffsm2469591wrm.11.2023.06.20.10.17.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jun 2023 10:17:41 -0700 (PDT)
Date: Tue, 20 Jun 2023 19:17:35 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Taras Madan <tarasmadan@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Catalin Marinas <catalin.marinas@arm.com>
Subject: [PATCH] kasan, doc: note kasan.fault=panic_on_write behaviour for
 async modes
Message-ID: <ZJHfL6vavKUZ3Yd8@elver.google.com>
References: <20230614095158.1133673-1-elver@google.com>
 <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
 <ZJGSqdDQPs0sRQTb@elver.google.com>
 <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
 <ZJG8WiamZvEJJKUc@elver.google.com>
 <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=BCP+qIWJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Note the behaviour of kasan.fault=panic_on_write for async modes, since
all asynchronous faults will result in panic (even if they are reads).

Fixes: 452c03fdbed0 ("kasan: add support for kasan.fault=panic_on_write")
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kasan.rst | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 7f37a46af574..f4acf9c2e90f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -110,7 +110,9 @@ parameter can be used to control panic and reporting behaviour:
 - ``kasan.fault=report``, ``=panic``, or ``=panic_on_write`` controls whether
   to only print a KASAN report, panic the kernel, or panic the kernel on
   invalid writes only (default: ``report``). The panic happens even if
-  ``kasan_multi_shot`` is enabled.
+  ``kasan_multi_shot`` is enabled. Note that when using asynchronous mode of
+  Hardware Tag-Based KASAN, ``kasan.fault=panic_on_write`` always panics on
+  asynchronously checked accesses (including reads).
 
 Software and Hardware Tag-Based KASAN modes (see the section about various
 modes below) support altering stack trace collection behavior:
-- 
2.41.0.185.g7c58973941-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZJHfL6vavKUZ3Yd8%40elver.google.com.
