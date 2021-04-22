Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3FWQSCAMGQE57XGXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D7B1B367A17
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 08:45:00 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id r14-20020a1709062cceb0290373a80b4002sf6821168ejr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 23:45:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619073900; cv=pass;
        d=google.com; s=arc-20160816;
        b=oqtxKhS2Nrz2YBZWFsRmIFJfjPgiKXXqkNYebb2K0B9nK/tOFvWqe5Re01rBuaPaU/
         nky6R+QJ4Po8FhXZPksHy2khz70co6A2i5wtwXnMYwRuoNsK2g8MScdsk73UMImZhOGH
         Gdc4MFr9+GtbSQAZnoKFQ/qBsnZOrGqnRM9fczSmXaM58kZ1Gx3umbF2qlpB7ysP1oFH
         z4BE5bZ6RwrL76fl5MO6FM92288FjsYb7juIr5K+W4tVD4lzhRztBOTvovXyd54PyiU1
         Y3THiy0xVQoNJkoVUAqJm4LiH5xSjjX3KUxOHdOmSjeNqMFv2NQpjtHy2jxyJ/SSvauB
         YTCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3zqwKEgUuDH3OVWB/Nz/Gw2wU/RvZk9rwQbiB4zitiQ=;
        b=WlCMICxh0TYiO9Jnzj0Su06UbBa7b06IJa6PkbObaXx5P2JwV69CruEeYI1/qw5/68
         BsOKlSpRHmamNoPUXy8L3c5uWr9cmAix/ZTB/J2LBJZM/6yI4DYtk5RpkP8nUcZhwDLp
         5AVtnv0ZSDfBmxFlDor58W+MC5SN+WWtz7ayzIcwK9rPoQnnuuLrp5p8gtkaIWD/iF79
         I4yj2mTA49E0/GnZU/WapW3OIT8lcMwoZxH0RW9lEtc+RAhqIPk/CRpCU/3r6DZQnujM
         nmrtQjjhNBGbhpzNipWpR8gyGWZJITa7IDRoF2pW+ue9y+URN7+gLsrlpMyJHia/iIW6
         uiBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rlmZAOT4;
       spf=pass (google.com: domain of 3axubyaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3axuBYAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zqwKEgUuDH3OVWB/Nz/Gw2wU/RvZk9rwQbiB4zitiQ=;
        b=gVqHgX79BfhUh3+P1Fv4i0HxGWPdLuWSmlC5tbtGvwHT8M5eWOL6BiFKrwkvf3Uhyh
         ayvq8VoJpcotsQNmJAMPkP8EG8LX8PrPh3JpIDez00lzpCJS/X8HAhf+yyUe8NWFKFEP
         lYqdloVjbfXAnwtf7jvMR+t8OAVs3wrHYLbA/33JI6qKelnytl/2SxhgxE07guPqUIoi
         Ciacpd7TocyJK5fx45v8gbZJSq0E4bQ2w8pTGjDe6cyFnW2BH4EI9TFEwysO6IntAjnt
         EzSVqnGECGFMrPmTV6dkkPYlsqM7qMzWww0A+fk1A3pjrcTpfB5tYSh+XI5XPFgtiP/a
         m5Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zqwKEgUuDH3OVWB/Nz/Gw2wU/RvZk9rwQbiB4zitiQ=;
        b=c8Tl//boUzlMj2+MtDtWTs2v8fgW5W7TU291LyZSTK5VzocoMBjmWEo6R2JzFQpDZv
         SZ+wTvXmN6MRgS7DoLJnAQIcQTDGW15eI9HMKPPHSwS4xqbw/3bb2+xZEylSwEHN8kYR
         cJ9J82E04F7G9UmoqPu0ehuZ/cgMkSaxqEhgIRLkDsOIS4r7h0JeRfdKd80DZMYMESIX
         h0PBA4LFdVtYkPkNcPI79emiaceNqM+gKYEO19sjtpLT7hc8i3paqefNyFCmtqh2rNKN
         JVQZup0YKgh72TStL4XgoIeRjVMDRst5akWiBS63TgVcIqC84lJtGrbZzTv+36Gr8DFK
         n7BA==
X-Gm-Message-State: AOAM5314DsW9H16E00r/BoFr4ATF/gpaR/HHKFpjkqO6M8reAjBSgMvY
	Bsvx0o3fARVeZiXYU0cH5lU=
X-Google-Smtp-Source: ABdhPJz2db535Di8HnFYzpfjzh5wnmCAWEDNvKknJPyWjfBKN8YTCSWVYGR38CUU1fNQfe9sfg3vUQ==
X-Received: by 2002:a17:906:35ca:: with SMTP id p10mr1757338ejb.199.1619073900653;
        Wed, 21 Apr 2021 23:45:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4d10:: with SMTP id r16ls2267714eju.8.gmail; Wed, 21
 Apr 2021 23:44:59 -0700 (PDT)
X-Received: by 2002:a17:906:170f:: with SMTP id c15mr1742059eje.358.1619073899704;
        Wed, 21 Apr 2021 23:44:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619073899; cv=none;
        d=google.com; s=arc-20160816;
        b=fWT6yjS6UVBus4Xnzx0rWYO9gIQ5hazDXf4r1gurjT1CuKFjcaWUL2zHu7IC+3T2fx
         GgktAyfTS20BxmgR4UObqJdQGyR71i9pltm6/gLvfnJ82Vbmnvjj0lLdPRjpiBLq6gq4
         9MC1pa0OlHHf/xqrK+b78Vp9puNEyDNA0nb6Zp2z1rt0kQ/oPi2kM4g1Y+5vjfsbpkhA
         SXY9GA1OCBgwSP8dJBJI1OHhBC10L7wDtHWugic9QC0a5HHV2ZjBUqBoHSTrgGT5iIP6
         hqe6Oj3n52oBIZ+nVgHUKrNMp6ecZQX8KsziIhkqP3Vd7m2r7DWV6KPVrQBFOSVmk8/I
         O7pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Sugwskr8rXy42pZ1xDG6/Yn9grQzLU2kaW/tniDjvCM=;
        b=I1n/FVKmIO2DIVYxi9giOaiXJ113WS2xaATIBKVciq1XllziSlTHapVASifHElmogD
         Ep4NDX0PEQXfY8pQKTuQ+RktNp5OLLZq2B4yQmAscG8mDSSQa+QCx5YdroMQfHAJWbKZ
         u5W9MOcCGoEwL9Gy1Lhf947SOHCH5UDk+8+EwEhTcqcoinLa6qmpHwdlYzh5YpSj5CYU
         2jOpnYtjRAyc2ipNSPj/APcoD0AmXkzGN81QKPOPk7HYvpKpkf79x4DOFx6Vbkgik9SC
         Kav7HeeOHZ6IKYlQLWPBb+LTlQzwTMk75qd7yJ98Ez0V7Gxsrg2e6B1sE6oaB9mCx0j4
         OUeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rlmZAOT4;
       spf=pass (google.com: domain of 3axubyaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3axuBYAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y16si483164edq.2.2021.04.21.23.44.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 23:44:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3axubyaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v20-20020a5d59140000b02901028c7a1f7dso13346642wrd.18
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 23:44:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6273:c89a:6562:e1ba])
 (user=elver job=sendgmr) by 2002:a05:600c:35cf:: with SMTP id
 r15mr12248413wmq.183.1619073899334; Wed, 21 Apr 2021 23:44:59 -0700 (PDT)
Date: Thu, 22 Apr 2021 08:44:37 +0200
In-Reply-To: <20210422064437.3577327-1-elver@google.com>
Message-Id: <20210422064437.3577327-2-elver@google.com>
Mime-Version: 1.0
References: <20210422064437.3577327-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.498.g6c1eba8ee3d-goog
Subject: [PATCH tip 2/2] signal, perf: Add missing TRAP_PERF case in siginfo_layout()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@redhat.com, 
	tglx@linutronix.de
Cc: m.szyprowski@samsung.com, jonathanh@nvidia.com, dvyukov@google.com, 
	glider@google.com, arnd@arndb.de, christian@brauner.io, axboe@kernel.dk, 
	pcc@google.com, oleg@redhat.com, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rlmZAOT4;       spf=pass
 (google.com: domain of 3axubyaukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3axuBYAUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Add the missing TRAP_PERF case in siginfo_layout() for interpreting the
layout correctly as SIL_PERF_EVENT instead of just SIL_FAULT. This
ensures the si_perf field is copied and not just the si_addr field.

This was caught and tested by running the perf_events/sigtrap_threads
kselftest as a 32-bit binary with a 64-bit kernel.

Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/signal.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/kernel/signal.c b/kernel/signal.c
index 9ed81ee4ff17..b354655a0e57 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -3251,6 +3251,8 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 			else if ((sig == SIGSEGV) && (si_code == SEGV_PKUERR))
 				layout = SIL_FAULT_PKUERR;
 #endif
+			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
+				layout = SIL_PERF_EVENT;
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
-- 
2.31.1.498.g6c1eba8ee3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210422064437.3577327-2-elver%40google.com.
