Return-Path: <kasan-dev+bncBD5Z5HO46YDBBQOAYOOQMGQEZPOL6ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 583E665A885
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Jan 2023 02:22:13 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id bl3-20020a05620a1a8300b0070240ff36a0sf17086417qkb.19
        for <lists+kasan-dev@lfdr.de>; Sat, 31 Dec 2022 17:22:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672536131; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pnkz91pYKjDGODLACeDNmc30b383tN8+ch3UWwYL/UV1BtM228q3NH8slR2+A20QXt
         qCXhBFEgUM6D2KrQqKvVS3Pa9tpjfSfB+7c7PIC1yajzj9/kAWjguGKybZjUKX6rLnEb
         GFCsITzshReyOkfWIavgjBLTO1wLbvgCZzmZdY2fO0YqbAIcVaa0RkmVJVy7HAI4M4Zs
         OT/kxksXjr+N1IxeS5E4Elfk2ydQSdAjCi2MX2pBq69X/WepnLGUeSy/SJoOdjnNeZzG
         5D4O3AaoHFDk3LyjnZfVBqUym3f1eOWet+MyxEFCQrtFtf0mo3hujPUH0Bog9xez1j9U
         nJxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+xLabo8njFYftn7YpvLyD2y1lbFzk0WI5UaBwET+sF4=;
        b=wzGZQsu2x183duMyCqQccWarmjdr/xJwAyzXheO0RiZpwVeuOzYl1dc38FZJu4PDLQ
         NvCqaiDolYev9bhBB1CYqTQkeRQEikLXjzmdrRX3HUmgU9qP31FU6PWW5C9EhUoDdQfO
         dvK5N/nOUGdQsv4bwjrMwEScQE/flsQPsilQ4nP2u06hHCRGyyRddxShzbpEOId6bhSV
         Ae1d7l7WYgY4xcaEqBNGP2vAJRth3JNNgM906Hx85Z2UoQi5aKqaeFjdWW9hE5LhhWuF
         TCbAwuyk8Bm0QjtXFu2eL4jVjt1lKK5F4REHBEHRoUi52uDyjkPVIV9bsfSz9y50QN8R
         yH9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@landley-net.20210112.gappssmtp.com header.s=20210112 header.b=UWnp4aAA;
       spf=neutral (google.com: 2607:f8b0:4864:20::32d is neither permitted nor denied by best guess record for domain of rob@landley.net) smtp.mailfrom=rob@landley.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+xLabo8njFYftn7YpvLyD2y1lbFzk0WI5UaBwET+sF4=;
        b=gvV8IkHcQF7CILNKpyE01uGXqWuRsJUztGtMtYlwGCnKAsn0YR/mylNtsdimN6SyG2
         Yzz7ZCOik7nzcBEUQ27cR1uvGYH73pZZQTs8EtdCCVTbQ9fR/yfr+gzdkjZaQdsvz2Kv
         7efPiTzMsOTyhGlArZ1iLrMVhDgTNd0IOhZzY8SlhUuXlTtDMdy5JSD4FG7L1Ahb4Y+Z
         4aed/i623szbZ8Mk0Qm8KFQC2Yvg/BByVT7DOqwYabYxohBR64um1tNf1UHqA+HmmJRM
         h3g1k/UCTBQoja1s6jGpiW8sSrPxHiJG2/QLUBtNm6FFGA6LKZ7Ogvi2T03gKfqLKYPO
         qlnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+xLabo8njFYftn7YpvLyD2y1lbFzk0WI5UaBwET+sF4=;
        b=GnFalFvX7LWHmfRZpRJ9VEYwklPoBaS2LS/ORpN1ECuKBkpjq4DDrOS2t7q6l7UbSH
         KotKZNrEV8EQkeglmoa47AinvtXUpo106cbnJDDJyPX6j7XcCzaaDxzX6wKi9yuISYEl
         1JHQ16q1UpkP5uKQ1j4Bp1bAxzeCzUel6N/ZlP+vOGLL5fd5GJJMuEX/EE2l4mE1b75T
         FQh2Rte/cpkGquQyNPPi+5HTW2GMZHvwVaKeUfloxJDvb44s/+4icCqi2VnC0HicbqKP
         Xs9Hwe/cFvZw5wewF1LgSItMSt4lEO22anoMP5zB7w55vjI8trwASJmyFWWI+Vzim00P
         wq/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqM8gbrJSXQQnOPdPb6A4rL7TwCMyNAah/wl6vRYnX6zy59svx5
	3VxvXq5PXyqB89Oy5koP22A=
X-Google-Smtp-Source: AMrXdXv2MMFSbekgpIBQFYVzFf3FLnMpFOmCc6MacNsrM6Nujf20V+IyLNS8mE8nOqOYBahjs65rew==
X-Received: by 2002:ac8:73cb:0:b0:3a8:11d6:a618 with SMTP id v11-20020ac873cb000000b003a811d6a618mr1694025qtp.601.1672536130018;
        Sat, 31 Dec 2022 17:22:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:58c1:0:b0:397:ab6a:3f0 with SMTP id u1-20020ac858c1000000b00397ab6a03f0ls17915984qta.0.-pod-prod-gmail;
 Sat, 31 Dec 2022 17:22:09 -0800 (PST)
X-Received: by 2002:a05:622a:5a98:b0:3ab:8c3f:328b with SMTP id fz24-20020a05622a5a9800b003ab8c3f328bmr33151850qtb.4.1672536129588;
        Sat, 31 Dec 2022 17:22:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672536129; cv=none;
        d=google.com; s=arc-20160816;
        b=tLGuiaoYlNod7Vyrf7p2LStasruCvjVn/wfzSwRLDlDX/RyqES2oYg5DpJLgc5mR5r
         iY1l4XiksqRmKgjXxF41gIlvBkoLBNB+TEGUawHPLtLbJZ0iKxrmIxBViG4NyW208tJL
         d1oc5ZFZmFr6fIfr7Son/ddZCtlosnxkc/QttYUeM2TOD3cejpOvGktj3vWSYmLAjdKJ
         qFl29Q9aUh+QQNjAL1QuTqZIkt0Mz6EvZv+u308ndtva9hBQRNEiopbAC2NJOx4ByBqD
         BNt3ZNLNzn2xs+J8e5dbL2E47j82LrQRNcbDsqGDe1AVFjv/1tOt5hacmr/Ib/yZr0iJ
         cluw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ww925qDRQMTRBp3kPOnTlPG41aVz0lVhVGJ/nRtnW2A=;
        b=lKQDAU5HXN9POKrr9lEhwjvS5XIqQ+RlEAMYauNAYVFq+sgZoPca5ZT7pp3lAcY/dk
         CVMLv5HHgAAMaG4Gf6xUBHG9wI4Wa3ftXEZYv7L/Gk2XNgrXzJ4zaCoVsHo6FkNaHi7u
         ofnGQt9JH0HPi/U9Fs+clw2Dk8yApSHR1RMPgHlftlrFZhnda7kIBGLDPxA/V7fKE9hn
         VIFhCbwNuZYKsceYPjTdm037kPPa5AMEcjF16K3HT3bRTqPuxmEnaUEPf88JdpegyZCy
         oLx6MAkkg3qKsnb+0vqDz/MlHsfAaaFsKsKwlVi4ZvXKbuJCDW41wxXjSNxCcdaUhzQr
         JTxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@landley-net.20210112.gappssmtp.com header.s=20210112 header.b=UWnp4aAA;
       spf=neutral (google.com: 2607:f8b0:4864:20::32d is neither permitted nor denied by best guess record for domain of rob@landley.net) smtp.mailfrom=rob@landley.net
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id a3-20020ac844a3000000b003a80e605d25si1675059qto.4.2022.12.31.17.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 31 Dec 2022 17:22:09 -0800 (PST)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::32d is neither permitted nor denied by best guess record for domain of rob@landley.net) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id x44-20020a05683040ac00b006707c74330eso15305674ott.10
        for <kasan-dev@googlegroups.com>; Sat, 31 Dec 2022 17:22:09 -0800 (PST)
X-Received: by 2002:a9d:7314:0:b0:673:67f8:93ae with SMTP id e20-20020a9d7314000000b0067367f893aemr21342552otk.29.1672536128939;
        Sat, 31 Dec 2022 17:22:08 -0800 (PST)
Received: from [192.168.86.224] ([136.62.38.22])
        by smtp.gmail.com with ESMTPSA id c8-20020a9d6848000000b00670461b8be4sm3150741oto.33.2022.12.31.17.22.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 31 Dec 2022 17:22:08 -0800 (PST)
Message-ID: <397291cd-4953-8b47-6021-228c9eb38361@landley.net>
Date: Sat, 31 Dec 2022 19:33:53 -0600
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: Build regressions/improvements in v6.2-rc1
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>, linux-kernel@vger.kernel.org
Cc: linux-media@vger.kernel.org, kasan-dev@googlegroups.com,
 Linux-sh list <linux-sh@vger.kernel.org>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
From: Rob Landley <rob@landley.net>
In-Reply-To: <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rob@landley.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@landley-net.20210112.gappssmtp.com header.s=20210112
 header.b=UWnp4aAA;       spf=neutral (google.com: 2607:f8b0:4864:20::32d is
 neither permitted nor denied by best guess record for domain of
 rob@landley.net) smtp.mailfrom=rob@landley.net
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

On 12/27/22 02:35, Geert Uytterhoeven wrote:
> sh4-gcc11/sh-allmodconfig (ICE = internal compiler error)

What's your actual test config here? Because when I try make ARCH=sh
allmodconfig; make ARCH=sh it dies in arch/sh/kernel/cpu/sh2/setup-sh7619.c with:

./include/linux/sh_intc.h:100:63: error: division 'sizeof (void *) / sizeof
(void)' does not compute the number of array elements [-Werror=sizeof-pointer-div]
  100 | #define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/sizeof(*a)

(Which isn't new, lots of configs won't compile off x86 and arm. I'm not sure
allmodconfig is picking a sane/actual cpu/board combo?)

What actual configuration are you trying to build?

Rob

P.S. Also my ssh cross gcc is 9.4 so I may need to build gcc-11 to see the
error, but I thought I'd try to reproduce the easy way first...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/397291cd-4953-8b47-6021-228c9eb38361%40landley.net.
