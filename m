Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46X7CCQMGQE5BBFHYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 818E139DEA0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 16:23:48 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id t19-20020a4ae4130000b029023950cb8d35sf11176469oov.6
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 07:23:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623075827; cv=pass;
        d=google.com; s=arc-20160816;
        b=OV24/ODYuxin0Uu19Wmasj6DpmoZF2TD9kOAUd9qv53tZABa6YFdyNsOaCkyMpiIWd
         dXdRIwjoEWuiJ6pEhjEFAve1ToPfWv3jGEo30EbbLNkgx+vdBJ8wpkPMMSzrAZMA+LMO
         kBKPr90BH7W1wzNXpENVbZiY1aT7X5gqKkwBOSvarnjGUjjHZz5Zvbzptqvs5sOAl3z6
         n1TBOqpL2PR4+rfJ4dl+0Wdbo8ILY0k3os8nb40UbjC/8yQ+CPH3KWw8M+eq9yn6h92N
         jqMaVuSbLy/sXdRmFYWMudFN02CPSSUZYTWaPoQsyhr6hExvL6xL6+z9T/svlNKU2PIb
         F5gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RgW/rrLdLBiBOz8LXv6Qwrq9ljtN97S1rDbURu0QdKU=;
        b=qopjM8ld1JMegI8U3veU0JBtl45S7/imWbFuqV421QLhVV0KN+VOwa3dJyqJSY7M4O
         T9Wa0BOlFxRruSFarm6Rx7rSDQIAh4KPIG4gJCNX2DyXnbZO1GJKtJZ6BtStbFKzmjwN
         sa/0+lx9H9VW4rQDoLCawn+C9Y0dfUwVzAbht5UIQV8ofGO+bpcAm7PnAsJTDd+maA4J
         ImYGxEaiOfgjeZSVadcjySEkd5sKrkw/ZNko8Lgi38jtR1WM5EwE6VjlvhS727oRWvA8
         +ODEIZx9bK/LSKbS4xHQe8R3cU/gqwvmgYmKZNI3nyFpVM9vrF5N2Jicblw65pdrJsYb
         G5MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cnyQchdM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RgW/rrLdLBiBOz8LXv6Qwrq9ljtN97S1rDbURu0QdKU=;
        b=EuEfr2pu0HguS4X/kAn5/deuVjRF20kAL60qMH0zAO1VqpgrP8Ipqdh5n5eZVFJztT
         uqDUGZ4IKYdqrRYZl4YRiQxLFbpwkEg2+ENQsPpj6mZyoPTtJsmmi5HJ+EcIm60tVfVC
         dj7Dmq6NgcXPXXuNvSB44GDNV8gUSgLapko2UUoc5EBsxDqqxT64InvUzTuuPynnZMoC
         9XdmSDYpYM5lLrZvfN+ftO1AZZmEWGRK7bTJq4yE5SKkALjZ2gdreXV8hLe8hlYb8u6a
         QqVq8DNnWaUy+QzNo6n3x0NrEoT8D6ZA3imxJJtdKk3HiAquQg67ykCn0O+UAi+1nUFq
         BNoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RgW/rrLdLBiBOz8LXv6Qwrq9ljtN97S1rDbURu0QdKU=;
        b=W2pkKaSdVZrmcpcoBgWP+koRVQnAevgU/DqBN29qILQupE2ZTTLQeU/lTPEpc2rpsc
         1qDrNs9LycfzjORjgDo95jJkhtFnchm/bBV271ggnRlY7riGkdzBdjIXgOY+4TVG8WO9
         WBs4RB9/HvVTHTb4XrkhCZUaEeVsFxKykYza6yHTBp+0XJG+n+3DmILh4/w9RyONdrDI
         iMETujLyXAtLA6KzTHILsMCQeIvqeyU1LwXCk3xL8sbJXD/WbPY1iLIigivZkmvF4i2D
         h73Of+8+h75g7PdNPoILybAWYGSlTtT8wkWXfbr4qx/FZxsjBSBpu54lstauEEKV/tFk
         rtHg==
X-Gm-Message-State: AOAM5331MSITBrtV6jxvyG7pz95WB5fGso/B8bAmCN90KvdVS5v38WJQ
	bDH/m/jluT1kKkfSXtiptYI=
X-Google-Smtp-Source: ABdhPJzSatXwBzQ0Q+mAPUXcjSDwWU+1/M77y/zh6xTmdiw5HtKrEp+0wp0W/XmA+EKErtEiaEtsUQ==
X-Received: by 2002:a05:6830:19f4:: with SMTP id t20mr14468140ott.103.1623075827128;
        Mon, 07 Jun 2021 07:23:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a18:: with SMTP id v24ls5009890oth.1.gmail; Mon, 07 Jun
 2021 07:23:46 -0700 (PDT)
X-Received: by 2002:a9d:a13:: with SMTP id 19mr14181851otg.131.1623075826776;
        Mon, 07 Jun 2021 07:23:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623075826; cv=none;
        d=google.com; s=arc-20160816;
        b=s0FyUE+JcdcFikeOzfZEzEA1bGH8/Dm4upO0vWpyHPh8xfeeh0vJK5Yp5paHgTUWgj
         tBFNzCwq5Tk5X2B0YmIfM00OSrLVElc6hx+4Z6cazJEXtQsV1TSgWVSdJJM1HV4qB9pq
         S0bPxiX4LhguYq/tfKl/UwrgsYh8FL68xtxYGIpjS9XrThV9JtORISEVkLPeq03ROd6o
         xMJHcvly2jJbdh1q26meIPdt4WLysi6+dWMJ6KoQE9Q6Ez4bNGsVXJgBtFA07/mKf4Vl
         Ys+ZKyGK8wvLGNFp/nl3NsN9nzJb8slIY8Ub+MHpb7qLijgaHi654P85f6i56BOo5J/i
         GtcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4PwH1AXD3SllEEcEV6owIpVJRtalHEcUOPjpbDNsvcE=;
        b=ubhRbXGgLMUPB/Ed/6LOdMFG9x3E0LFyPMd1Cl86iQ2KFdMyKfSoqtX9DU/uHiggGE
         faKZs0iQKA+qE2HsJsjjUDoXnJm8I6FbsDa8KOuFhlj/CjV1FVJ2yTUoJz8eTDJmlT1N
         /ZagnsT6yYnfwbLoQQzGktkuW88UGn3ksVXRKV6i5BtdbHdr8Bw1UJX8YfrmUw/1OTnK
         wKwjXxWuYPnonZ1lWc4lhXoyn7iw7PnDJodfBtDkxDaxz2SKodepVsOm8QBtTGpOtNKU
         wdtSpnqQ+vzKaioN42kYd+Pqpguw55YitRCYWyj8AbYOdyq7RQm+cTZprz8yUtLFb0f8
         p25Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cnyQchdM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id c9si1085635ots.4.2021.06.07.07.23.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 07:23:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso16834636otu.10
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 07:23:46 -0700 (PDT)
X-Received: by 2002:a9d:7a54:: with SMTP id z20mr14261136otm.17.1623075826297;
 Mon, 07 Jun 2021 07:23:46 -0700 (PDT)
MIME-Version: 1.0
References: <20210521083209.3740269-1-elver@google.com>
In-Reply-To: <20210521083209.3740269-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jun 2021 16:23:34 +0200
Message-ID: <CANpmjNObVfB6AREacptbMTikzbFfGuuL49jZqPSOTUjAExyp+g@mail.gmail.com>
Subject: [5.12.y] kfence: use TASK_IDLE when awaiting allocation
To: stable <stable@vger.kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Sasha Levin <sashal@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cnyQchdM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

Dear stable maintainers,

The patch "kfence: use TASK_IDLE when awaiting allocation" has landed
in mainline as 8fd0e995cc7b, however, does not apply cleanly to 5.12.y
due to a prerequisite patch missing.

My recommendation is to cherry-pick the following 2 commits to 5.12.y
(rather than rebase 8fd0e995cc7b on top of 5.12.y):

  37c9284f6932 kfence: maximize allocation wait timeout duration
  8fd0e995cc7b kfence: use TASK_IDLE when awaiting allocation

Many thanks,
-- Marco

---------- Forwarded message ---------
From: Marco Elver <elver@google.com>
Date: Fri, 21 May 2021 at 10:32
Subject: [PATCH] kfence: use TASK_IDLE when awaiting allocation
To: <elver@google.com>, <akpm@linux-foundation.org>
Cc: <glider@google.com>, <dvyukov@google.com>,
<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
<kasan-dev@googlegroups.com>, Mel Gorman <mgorman@suse.de>,
<stable@vger.kernel.org>


Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
allocation counts towards load. However, for KFENCE, this does not make
any sense, since there is no busy work we're awaiting.

Instead, use TASK_IDLE via wait_event_idle() to not count towards load.

BugLink: https://bugzilla.suse.com/show_bug.cgi?id=1185565
Fixes: 407f1d8c1b5f ("kfence: await for allocation using wait_event")
Signed-off-by: Marco Elver <elver@google.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: <stable@vger.kernel.org> # v5.12+
---
 mm/kfence/core.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNObVfB6AREacptbMTikzbFfGuuL49jZqPSOTUjAExyp%2Bg%40mail.gmail.com.
