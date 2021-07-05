Return-Path: <kasan-dev+bncBCGN3SFZVUBRB5O5RODQMGQEIMRQUKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB0D3BBC4A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:37:26 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id df18-20020a05640230b2b0290397ebdc6c03sf4871168edb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:37:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625485046; cv=pass;
        d=google.com; s=arc-20160816;
        b=BvYT0YmFt0QgvDRuJKKCCv2uJ5F0kIQShV8677lUTdPrMImjVta2GZtVLbqPhZbjVt
         9v6fKsOLIoXBHzbpc+yyl2T7SjF116S0g5cSyEP6q/bwrnKvZJYCnQk1QDsLVnoObsnN
         rwMDWbPb2/keYxA+uxi+sJ+wztCzGId9IM6qVVIXyWxefElH07jO9+1qHcbwUc97R9uI
         jB5VLqOxte7ukOc5/sYBCDqKdzYOnm/5vJzppufT/Ax8CeqA/YaekyU+OfbSfSV4mQOz
         TfqYVqQhjI17oXAsWeFOpTKpmqPJAfuJUIo8a4SKsktPNSq8HDaQptQ8n71DgnCMsg+M
         A87g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lgEp7g3iHcQsTtakUdgGuSrqrYAcUkoE/JoGEqogaSI=;
        b=rKB3cNdwvxICkY6RSOTRteosOp9cLw3IUc6OJfb5Tw53C0lIrQ0OcCqjUi26O6Xl3N
         8n6ZtC9Zcbjqz1C78QP3C5Dki28qiTk/JX8CbVtFzG+N12vFMHwnmo1sZ4ZJLUOuJwdM
         vNE8Qkb34EkPOGw8Scjm/JGqhccsGjIpCyY+D1Be0h19mFAmAS1QET/UfyU6INadE1J1
         0Vj8cbF1dDz++ZkCuA7QQ1SfAb5iFn72RWLq2TdfppjRSIJC5utmXii68e91GgWn787+
         GJ9TXBLQmiuCXLR8YVArNeuZwDZ8Qv3XDX99Tg0Uc2WZDxVyQCzWT7F77jI7F+UCVTO5
         oWyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mgorman@techsingularity.net designates 46.22.136.58 as permitted sender) smtp.mailfrom=mgorman@techsingularity.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lgEp7g3iHcQsTtakUdgGuSrqrYAcUkoE/JoGEqogaSI=;
        b=BEnx0lddWqPecgu5FZPScCl3idkaQQJJnV6jPaI/lxAbQFyHbBRXn/H2etpego+2rs
         NeOoCHVLje2Pf6SXjHWl6iMgnCpJm6NrViMueP3Woxsa2hxOpdz92JwTNahysk5AfEU7
         0NW5khs/BKXOBo9+CpucWIT8AoBKSlyUQJbXKD/hmV1fNbdVD9I3F43vh/a/M237o0z1
         WsCklGYOPXM64VkCE1HbUHlAzwKTjj5XtNq/hrcATPmyjILzfZzpobLXmavkWljQvFA4
         66zuTh0skSnm1QWv8KlUDyIwTuXCZ7JSCDLOrBjUEvyRVVnTHCHzKmk3dz3lSwjUN1HU
         LUWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lgEp7g3iHcQsTtakUdgGuSrqrYAcUkoE/JoGEqogaSI=;
        b=tAQ7MdwTOag3DryVHdyUsf6EVuXj0zCQRg364kiQNj2dSXUS0MyRSEvwofvb+sP3N+
         j/0zSsWTTE6tW6DLJyY+GY5rkhOHOlOOIFuBC2Nmrbjxk4o0VhE4kNHS4lhdd2Y/popq
         pnjdNf9EyTQ5njYlaW9alJbXQDuMG9Cm9rFf8/YjU77U6k5tAxacRCFcN7O3/FWAyWCP
         U3dazfyDJgXWglq4D6XMm9Yd/xLgXClkHYDKE5Q+qoaKZWpWVnRVlPmfwAB2FTMvI0Vs
         LMALIjFZDjjG37V41TIAKmuqxqlyHL8hG4+EpO3k5totRNTDBLTVMWG4dvU4qwkdkZ08
         4lwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uv/aRN8PEVAjCCQv5CJk8DTJnnWMW62+9XQNAGeUPMIvui3ne
	WDEjK9M76lmh2jMwXA6175A=
X-Google-Smtp-Source: ABdhPJyQTuOh8wcchOxAWfGX3aQHRf6rVAJJJQZPdJXEaDKnXWUw3Km/se9VLGozb03PjfV8KRhYHQ==
X-Received: by 2002:a05:6402:524b:: with SMTP id t11mr15856517edd.129.1625485045973;
        Mon, 05 Jul 2021 04:37:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d905:: with SMTP id a5ls6250241edr.3.gmail; Mon, 05 Jul
 2021 04:37:25 -0700 (PDT)
X-Received: by 2002:a05:6402:10cc:: with SMTP id p12mr15975877edu.328.1625485045149;
        Mon, 05 Jul 2021 04:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625485045; cv=none;
        d=google.com; s=arc-20160816;
        b=bgljeYV643kAZ80NcxMQiskyb3lWVjoAdQ+54oJ7Pws4RAqwb8a/XVTAJY/ADRa5FP
         QLbQqx6RA2yiqePOu2Bv9OipBrb4SpaDXKUW150aBnI7tM6YBHi1qe+TVHyEMbEckDKV
         UR2x2RMU9e70xV6tJ9ImFGYEao4PO2HoQCdQG7YliOBT9SiByT8nqCYzLbf04OmsWMuF
         69eiM250wO3afrbKoLp0a3Wfx5NdiYoSG2gNmRT0kVzcLezMBPy885qtLUgiTUYc6Y3a
         d2zdg0m9Amy6A3Q9ziXk8wvYgY9cVEGhrP+DyAT2dVaY4sBGcaz1wlASPDmGYdPIUc9B
         +CqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=MduB2IqsWpwzkEPtGASoULjfQJnI8w+hQTuYS2S8GnM=;
        b=hlZ43tfykxvOaEvBYVPzer740Z8aeXNuMR8I7+rVr0dbKDcIHbgNkmL9HDeIr8+B1O
         +hveyaSNTWBg6t6bcoRWViVlrsF7LVXtQ25k4yeWBftNgl4otGxlIXDE7c7NM9nUo/yR
         dp6bO25RYONKwGZdr1Cw36qfTpuPm9Jw1S2S/g+LnqdC+CXEEAma2Ql8lNFv1o0VmJlL
         GUEnM2NhxBu5+D1lRI5OFg2ZoeqQe398ET0BiHpKxNbGA6hM10mOGYAibFglZT4+/D6B
         Z+5Nj3WITAvvdTs8gmx3MJyh2iame5VJemG+PbF7/hkd9qOMjOniDWR95dOS3RGljtUT
         cfNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mgorman@techsingularity.net designates 46.22.136.58 as permitted sender) smtp.mailfrom=mgorman@techsingularity.net
Received: from outbound-smtp46.blacknight.com (outbound-smtp46.blacknight.com. [46.22.136.58])
        by gmr-mx.google.com with ESMTPS id s18si418132ejo.1.2021.07.05.04.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 05 Jul 2021 04:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of mgorman@techsingularity.net designates 46.22.136.58 as permitted sender) client-ip=46.22.136.58;
Received: from mail.blacknight.com (pemlinmail05.blacknight.ie [81.17.254.26])
	by outbound-smtp46.blacknight.com (Postfix) with ESMTPS id CDE7EFA840
	for <kasan-dev@googlegroups.com>; Mon,  5 Jul 2021 12:37:24 +0100 (IST)
Received: (qmail 21946 invoked from network); 5 Jul 2021 11:37:24 -0000
Received: from unknown (HELO techsingularity.net) (mgorman@techsingularity.net@[84.203.17.255])
  by 81.17.254.9 with ESMTPSA (AES256-SHA encrypted, authenticated); 5 Jul 2021 11:37:24 -0000
Date: Mon, 5 Jul 2021 12:37:23 +0100
From: Mel Gorman <mgorman@techsingularity.net>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Andrii Nakryiko <andrii@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Vlastimil Babka <vbabka@suse.cz>, Yang Shi <shy828301@gmail.com>,
	bpf@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>
Subject: Re: [PATCH] Revert "mm/page_alloc: make should_fail_alloc_page()
 static"
Message-ID: <20210705113723.GN3840@techsingularity.net>
References: <20210705103806.2339467-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210705103806.2339467-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mgorman@techsingularity.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mgorman@techsingularity.net designates 46.22.136.58 as
 permitted sender) smtp.mailfrom=mgorman@techsingularity.net
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

On Mon, Jul 05, 2021 at 12:38:06PM +0200, Marco Elver wrote:
> This reverts commit f7173090033c70886d925995e9dfdfb76dbb2441.
> 
> Commit 76cd61739fd1 ("mm/error_inject: Fix allow_error_inject function
> signatures") explicitly made should_fail_alloc_page() non-static, due to
> worries of remaining compiler optimizations in the absence of function
> side-effects while being noinline.
> 
> Furthermore, kernel/bpf/verifier.c pushes should_fail_alloc_page onto
> the btf_non_sleepable_error_inject BTF IDs set, which when enabling
> CONFIG_DEBUG_INFO_BTF results in an error at the BTFIDS stage:
> 
>   FAILED unresolved symbol should_fail_alloc_page
> 
> To avoid the W=1 warning, add a function declaration right above the
> function itself, with a comment it is required in a BTF IDs set.
> 
> Fixes: f7173090033c ("mm/page_alloc: make should_fail_alloc_page() static")
> Cc: Mel Gorman <mgorman@techsingularity.net>
> Cc: Alexei Starovoitov <ast@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Mel Gorman <mgorman@techsingularity.net>

Out of curiousity though, why does block/blk-core.c not require
something similar for should_fail_bio?

-- 
Mel Gorman
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705113723.GN3840%40techsingularity.net.
