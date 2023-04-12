Return-Path: <kasan-dev+bncBCT4XGV33UIBBHVL3SQQMGQEUS4HREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id C58D66DFFE8
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 22:33:35 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id d128-20020a376886000000b007468706dfb7sf6485293qkc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 13:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681331614; cv=pass;
        d=google.com; s=arc-20160816;
        b=WVxkFeZ7AlUGb3bE+1L0xeSO6w6XYq0UStUGo27FZ3drt3Qlv8W1ppM3dTmLSLXY5H
         ptb5DuGOISmuVOlexDKJtWo5wQALg8yy2CYgX/mxadEUh3A1MDa6OyJlSWd9ejRKN7qj
         QVA49j82YhnnTBvhLpyOR/IOrkg2m0zDjCRed/6SdpqUPyCSAdGgtD5Jya53bPbTQEgU
         9lRLCuvRLlpK04yxontU9f7p7dU8bFp2fUM4buIMsNRjZEipIk3IresM5oJLquLkqPMG
         aADpbSjURw3GhcGoqFSWO+msYUgkM07xpB2F+wWnd9zzln06k54db3ATBA1oGlJCeSgv
         iNFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=toTuJdoDPxIki1mZphS+2INAQrkaDB98NQkZQAP9PXw=;
        b=JdZI2ygGbnhH/f14G+FI3LSCYH6/gcQsGB3ZnR6MChxR24Ojm6FF6Ygu7bYVAoxOKj
         1kbj8ztlibJfRecRgFrM9mXF2U9/XsWzLLkleG03yMR5HEosLe6DgxlQkSHzpZIosIrM
         dZKSSpiijRcQ0v8VgEpii304PZHGsOIAlXWylY8Jzg1wT1aMGTGwnBZe11zGHlpd03tM
         1giCLH43i2482dZaJyfVX1ML0urSYc99umsYbhBPUyG6TR5Sbzg5K0qi1ovdDkRLxLUF
         gAB516ZJTdvTWmKyT2QN+Lqvc9Ta7qSv2GLQK6eW08ZcsMGKEneLH2D86N8qd1dhXdjF
         IaOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fv32pv5D;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681331614; x=1683923614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=toTuJdoDPxIki1mZphS+2INAQrkaDB98NQkZQAP9PXw=;
        b=i9NG7qDeIZrsIpEsGmiQB2VRurGRoKknad/hJPkFVJpINsyulW3dYSrg++/Rzsflet
         MHr9PiJouDIfMx6k7VyLZJCoMnLwqeGBXeJKanjKEha9SP80D/Zg4A/oYriCXP4fZ7G2
         THknPyhFZ7GUDNTjnYB/j2ACoQBbfCVmft6iiG0Zd+bmqGLseNG0DOl8/gcoUKeOWpTm
         JsJW8f53O0zPSnuZZ6AWX/3kfSFAZyCn7NOFpodfVqgTICuanoCsuZbDETX9Oxks5PwK
         6D8J3dgcdkjIfmJxGyZBfcABk6r34xwlgMIy+C2muGthlE+I6Ep345lclGk6S0VI9fUJ
         3elg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681331614; x=1683923614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=toTuJdoDPxIki1mZphS+2INAQrkaDB98NQkZQAP9PXw=;
        b=V1/apXLr/+B8PFaYgvP/lTsl6KmAuvgVRVYhpnKaaRWB31Xq12o+2ab4TALFbHk/IJ
         7He0pyYqAPNzbSjzqdkgw6EEnBXKljXhKEaf4ztL37OFVFyZu6bKiCyQ1k7f8NEWry3k
         rJcekmwRkRyQxDiDBnA+rixoXhVLkDffAZTlCwmjCHPRWO86xt9EKsiLyGwx8JCyJSsI
         cHEaWtEH3DPRRAmKqA1vd1C7B0qCbijuH/TQurnbhsK8Iv4iIKmH/6MqETqL+XMJePLy
         gqOc7MQs63vOoLMecnNT0zzFKmL3hE8gv+SOSSRNUrOEmlJJYhijHzFOit4m4M2RZrGY
         1rjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eiWo1pDIFUQnhTT1fdW6aly1UD9NHEOTpDMHkrkXGDwTvaRK1D
	NORcocdT59T7uAHgiO1Rq2E=
X-Google-Smtp-Source: AKy350aeRsfImycwDwVhd4TDRd91I69E1ZqseDn4Y3oqGQdxk01C8cpmTW/H62pOmc7A4LXnsPEUTQ==
X-Received: by 2002:ac8:580b:0:b0:3e6:2fab:675 with SMTP id g11-20020ac8580b000000b003e62fab0675mr5393987qtg.9.1681331614567;
        Wed, 12 Apr 2023 13:33:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f9d0:0:b0:56b:f6be:9a8b with SMTP id j16-20020a0cf9d0000000b0056bf6be9a8bls25985164qvo.2.-pod-prod-gmail;
 Wed, 12 Apr 2023 13:33:33 -0700 (PDT)
X-Received: by 2002:a05:6214:daa:b0:56e:9da4:82ff with SMTP id h10-20020a0562140daa00b0056e9da482ffmr26211498qvh.50.1681331613854;
        Wed, 12 Apr 2023 13:33:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681331613; cv=none;
        d=google.com; s=arc-20160816;
        b=gRpXnZ3bTaEAUdt2UyKdxraMrTbJqdu57JYnLzKrNFJ3Q/dcwqhzs7uxu945Q0lPQq
         lo34K9bXrDRXTLAth0Ro62ZGNeruzp+sAMD3157Ppvv9EbnYtU/J9uaFv114VAbcmU+2
         P/FGsmNTvFulPBUNtim+bJJS2SHM+1MolhQyvdfa+Y4Ifn32sUtwmjEJtAZxIdE9JKeI
         oiCsRNK+nVKVEiCUs/mQvMESZXF5TSu/qvD+EPpWkRhSPpxPooNf0GmPrCRd3hBff5tt
         oXeJJ/kbSirydc8rjMaBviRhEJWLWlfB8PcpjQRsylEPOVm2/Pbfu2U3m9IaTKpNw5K/
         3rNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UzH9ZZ+3Mqyki6awZHd9xaydWdAAoUbID+Rsx9iwclA=;
        b=mOYRRhHG+DyNbDrfFZJnURXDCe41a+JYDdIVFPJavkp2JvJt/+7oh5Nv4dmWgCZTgs
         wjNAxAVLwIYSY641NzhWQPcas1IFeTIVz2yPRdBzfHQf2b18O3/pdXOzStjXZE3xKyuM
         2BniOdE9dzBqk72NSxwtMmI9NdlW73h9selQZ9BdOWul+cHEQclkfD6FS1XPlXqWyUd+
         Z564Irg5ka+nmb1XoMXBlNz/VTAeL2RdcPSQM2AIVzZtXQOP2K3poEyuz0R3N/aispY9
         IwvHNWIdHJoOV/uGmGimc6A2GbwdpkfXX4hm5xjBI2wQNqN6zZ9FXvI4RJGtnUHx9DjU
         avLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fv32pv5D;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id op9-20020a056214458900b005ef465ad69asi99081qvb.0.2023.04.12.13.33.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Apr 2023 13:33:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7655862DFF;
	Wed, 12 Apr 2023 20:33:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 99E27C433EF;
	Wed, 12 Apr 2023 20:33:32 +0000 (UTC)
Date: Wed, 12 Apr 2023 13:33:31 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, elver@google.com, dvyukov@google.com,
 kasan-dev@googlegroups.com, Dipanjan Das <mail.dipanjan.das@gmail.com>
Subject: Re: [PATCH 2/2] mm: kmsan: handle alloc failures in
 kmsan_ioremap_page_range()
Message-Id: <20230412133331.e26920856ccf94edd057c1e0@linux-foundation.org>
In-Reply-To: <20230412145300.3651840-2-glider@google.com>
References: <20230412145300.3651840-1-glider@google.com>
	<20230412145300.3651840-2-glider@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fv32pv5D;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 12 Apr 2023 16:53:00 +0200 Alexander Potapenko <glider@google.com> wrote:

> Similarly to kmsan_vmap_pages_range_noflush(),
> kmsan_ioremap_page_range() must also properly handle allocation/mapping
> failures. In the case of such, it must clean up the already created
> metadata mappings and return an error code, so that the failure can be
> propagated to ioremap_page_range().

Unlike [1/2], this changelog doesn't describe the user-visible effects.
A bit of clicking takes me to

: kmsan's allocation of shadow or origin memory in
: kmsan_vmap_pages_range_noflush() fails silently due to fault injection
: (FI).  KMSAN sort of "swallows" the allocation failure, and moves on. 
: When either of them is later accessed while updating the metadata,
: there are no checks to test the validity of the respective pointers,
: which results in a page fault.

So I'll add that to the changelog and shall add cc:stable to both patches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230412133331.e26920856ccf94edd057c1e0%40linux-foundation.org.
