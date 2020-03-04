Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB6FV77ZAKGQEOPVLWUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6A2179595
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 17:44:42 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id w5sf444313uam.13
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 08:44:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583340281; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGkKjGkM2xkcrVWYfDAzMgO73Wlh0yX11GTXeb/8/quxVVbXcEVEysF+qn59WmfR+o
         IbAH2Z3vuY1qdn4Tc41iOTxC0aAxced61ezJMghiaMFn/OoGYNGtiyFg148lTUPO0Brl
         Gc8USO22qrWxVC4evrbcz+nglwTtLcnpW7AZdPSQRFq1t6fIYJC4OBH18GDHdJByq6VG
         6AFL7lkudQfDBjhoHWrPtuMu9tBRwSVOoHuiWSjSNo0K/gcR4/gyHIA8vVFrlSKL568/
         K8QewDC7If4OsUtJzinKSTNP2ka2JzT6hHmcxGh6yLBMaPPUOLhaH8RTs0SYwj0Cd2th
         DUyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=viCMVkb5/Lli5V/xfOAJ4SXG3k3oCwi4eSs8CvfQncU=;
        b=BlCVy84qlRBZv+jnM/Dl4VuQHOwhf+y6yDXLT2lUj7akyWhhKrmkvSj0nrTNprlzqw
         Ll0kkn+4FoXzGAVokVnGszHf5SYqiihcGhvgSs2ZZX53QamnR9/l44k9vaU/StUH3v0O
         2V5S69EFHlBQgN+FW0zjgJH1/eTI1bH3Ka25CqXc+BOtBu9vT9CjJ27NA5WNfVoA/U14
         u4s6dLE8oNW0iggN2HoeyW5STrLhHO1DQqC24fel8HSTbmZpX1qA7qVHKEdntFuda5SV
         R85ru6rP2kuY3wtfJm5+PyURCM9JL6nGyG97rDBkvcgf5tcXGYjWlVBPuyEJUTpYwDVG
         Zs4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=leSmdPEc;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=viCMVkb5/Lli5V/xfOAJ4SXG3k3oCwi4eSs8CvfQncU=;
        b=WUn21oKbaD0wRgDwpyqIK7WydcmoZ55pBQGks74tawxgKIZvSMt2GXFXvLU2/IaW1P
         r26/OlR0p0ls4Qdn53gw3MfQg5k9N8CP9tUEc1PE9fRscJCtGKSEEk7uWFsexEiFtFTK
         563up2a9ozVEspCWbpOdn2IZgHeMbFqa3SFf7kjZrJAjNpjgy5ayh1NnHVnMeSkSrp7A
         EeiZneGDMjPwCWR8toFWFvRYHeXWzXY9+tjPaqu/cqN5BJj+035exn9DrR+VQEiXXWqY
         01A2RCPZY8pqn3HqvRrNUTB/e7RBmumjILnEV/bbTysjeswTmaVblRvIMmiWc5bozEwV
         gmnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=viCMVkb5/Lli5V/xfOAJ4SXG3k3oCwi4eSs8CvfQncU=;
        b=lkUX1/60XO9ozLUkxjplrLqiSiaxGAh4A2AtAJv0eARC4sVxQ2bAW+JBZDjwZXS0bK
         30KdXaMs6gD1cIHdczHdj/4jmUH4ulkWy1TXY5biazgZSKqDXWTSbFrpWAL31Aj5n4vk
         mm1KIcgtYCnRcaA9RuVXma/QuzMRUQEXQ7Dj18BiL71xMCHTU8pYozh0viEOCmMgrNIn
         qT7iLNEIEXTse5nzKIB5GsRh2dBja+yNJwzsI/x5D2u0i+Af1v9U12k0dHtWB3Ljk2xR
         upazn11Ces16zKHxrSrqYrjTmymzRxaxNHZ5LTmpTkId/tnQqLNTrv0ENmCfnBRJp0+X
         nGUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1XfOUKe81HLySrcMb6jJR/9MHVSFeJl2ADJCvey6RgenORpoTz
	g8/u3caLoSHvTii0XtpL7j8=
X-Google-Smtp-Source: ADFU+vu99Lj6BOzWbNo1ygjZ/NUngrN/6C/doJoVE3Ry7Mg53cWdATUfmjpuKUzmT/UDj7FhA51j/A==
X-Received: by 2002:ab0:23d1:: with SMTP id c17mr1943485uan.52.1583340280907;
        Wed, 04 Mar 2020 08:44:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:41e:: with SMTP id e30ls158113vkd.5.gmail; Wed, 04
 Mar 2020 08:44:40 -0800 (PST)
X-Received: by 2002:ac5:c15a:: with SMTP id e26mr1907200vkk.62.1583340280184;
        Wed, 04 Mar 2020 08:44:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583340280; cv=none;
        d=google.com; s=arc-20160816;
        b=uC5/FUkxo132WL/h5zXWfZBY/Wo+8NRjKWUJvi+hf1EesdgklO+cqCnxIp4fRRKlRb
         bziYlKunhIFAjNiqoMahovxXZVic57CRO4PA0slRJFRvwn6uS0+TCKhTVNc5lQnFDqP8
         cSqpb1HZWJmGIQFf5RBpcL9cZEAvcZZo9Yz4k+EQbAEt6Ijmb/z7cLRvnwGTkHT7Mrzc
         l87oGa3mBbIF8OyXyezsZWixir/c98F1RTq4hwZax7LttMFd+BM8//L2TaXlwitfwU6Z
         hZmJIQ2ctPEfj9CGQmq3Lsu/2BJY0+s4aNvnjkQ5q1forflRGU8wfB27mgtS7qBq9ldu
         +3oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=sWZM/vSQvIFpCrYKTig+vbD3wjvs5x43S2+zwby2k3U=;
        b=ZR19TrRdVxTPPKuxlCg333494zMni+/OR4uctgRAHjTOaQmUb83alvvgBmxB9tFvuo
         6qP6iTApNRKHSlh5t4/N/4XRg5Lg7Zn6JYD9j8fCdQCQejSu2a9Gx015U4LIt8nf+Qnv
         Iuds8DtcXemeCcgcXL3PnTwb+KfP1i+qeTs5Cipg/s4NUoAEd0I8ouls2kRPujc3j2Ej
         CZ+0C0q+vm8dRVdpmzEZ+HPL0cIdqk4VB6Rfq60KwjPct1ybxKN04XTpfrfr1a8xiELB
         Jvtf0yvH2PdtYmd2IAoaoH1i0vkDZemPBlBv+mkN76w9IwT1ziP+HbUbVhneLP9XCqT/
         uYAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=leSmdPEc;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id o21si102523uaj.1.2020.03.04.08.44.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:44:39 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id v15so1857810qto.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 08:44:39 -0800 (PST)
X-Received: by 2002:ac8:3778:: with SMTP id p53mr3155337qtb.158.1583340279528;
        Wed, 04 Mar 2020 08:44:39 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id m26sm2024089qtf.63.2020.03.04.08.44.38
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:44:38 -0800 (PST)
Message-ID: <1583340277.7365.153.camel@lca.pw>
Subject: Re: [PATCH 2/3] kcsan: Update Documentation/dev-tools/kcsan.rst
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
 dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,  corbet@lwn.net, linux-doc@vger.kernel.org
Date: Wed, 04 Mar 2020 11:44:37 -0500
In-Reply-To: <20200304162541.46663-2-elver@google.com>
References: <20200304162541.46663-1-elver@google.com>
	 <20200304162541.46663-2-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=leSmdPEc;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Wed, 2020-03-04 at 17:25 +0100, 'Marco Elver' via kasan-dev wrote:
>  Selective analysis
>  ~~~~~~~~~~~~~~~~~~
> @@ -111,8 +107,8 @@ the below options are available:
>  
>  * Disabling data race detection for entire functions can be accomplished by
>    using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
> -  ``__always_inline`` functions). To dynamically control for which functions
> -  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
> +  ``__always_inline`` functions). To dynamically limit for which functions to
> +  generate reports, see the `DebugFS interface`_ blacklist/whitelist feature.

As mentioned in [1], do it worth mentioning "using __no_kcsan_or_inline for
inline functions as well when CONFIG_OPTIMIZE_INLINING=y" ?

[1] https://lore.kernel.org/lkml/E9162CDC-BBC5-4D69-87FB-C93AB8B3D581@lca.pw/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583340277.7365.153.camel%40lca.pw.
