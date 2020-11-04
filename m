Return-Path: <kasan-dev+bncBCT4XGV33UIBBTHMQ76QKGQEI7FX24Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E33C62A5B03
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 01:31:09 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id b11sf3631648pfl.20
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 16:31:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604449868; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhgvuiULdyT15jjdrcIuiQEsiQeFxFd6Rj6C0RjVkL7YpYZXZuP6G8J6OrzcqKTpOl
         yyMI+wqdwmVxFcwbaZ63D6fofj85Ufm/Ry476Q1VW7sukF9valbAr2tMMob6O3yUyIAs
         jJALfUZxVVu+KIrX5RMBEdaJ47IlipseXVtClOg9AofSD/hX4L9Jyaag/kVkqZRE45Wr
         eKuLmTv6Y3ETLJD1ll9tn9shSCrCFzr0gs+IlDMsmXcxfzgI5TNwF8iGi3FAAEX8ZTeD
         FP3irAhco+20TPhXfs0/nCNT/y4HWeTYtScYXepkNS8NIDbkY4DlYrSRYAfUuWFF/rum
         /p4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fdHuWwhW+FgOrIX7/uxxYa5dL06I2TMkKvMhqfkYqNc=;
        b=hv+PvWrHyMkmkkXJAmlyGxzbVasPeFk1wymLVmIrmUvTZFC7SkW5Wt9sFIJA/g1thQ
         b8AbPjQTFbp6oXwJ/jeNEVnGKj9dniyYbBQL1bsZ6kD2x/4Gsqymen1CgfpDxDys1plU
         LmICVoDkQMkguaby0sJoriC5vg0VpTgGQnyh30u9s2wTADOesG5VPk0kwbs0Qk7gttLf
         dD+ELD8Kag4zyUZFx6sUenUcvY2vvhUWWgUqak8k6ucbtVg4P07RfDNgFCJ0G4N4LmHM
         OpB2GAhpZKf353HHuZJ01oR8fRXy9ZWb3dc3qmKC5AaKj+0RRNVo/6QAh4tUxg+5tx9R
         VoYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ER7zLL0f;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fdHuWwhW+FgOrIX7/uxxYa5dL06I2TMkKvMhqfkYqNc=;
        b=H8W0k2P3jcFBF+mIpuVSYtceuGDvsiuo5rMox7y/9mvtVVzE4kV4vO9alruQjDCjVo
         hdNwpdXrHXjda1g225WZWye44+oPftsQj2IzIEPHiuBzTxdnBQelbBNv+Wxu/48EnDVw
         78Uec89UNDfzOXPc5pF4aneW6/4cS4Wu9sY/tBZmzuGrk/Wr4ZWOEI0UvhsLMMdPZsmr
         mqIeLnjpuve1IHLs7RWbmYlRgbTuFzjxR9Zd49ToLntMGpmVxc/v2R7QLDhy/2UhxJ3C
         36KdKvJzWkmv/jMJNfjn5cajQ8xq0oyPkqkrk4DDL2oo5+hVycy3NjJLJs8AMM3MCK+q
         5Vsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fdHuWwhW+FgOrIX7/uxxYa5dL06I2TMkKvMhqfkYqNc=;
        b=V3A9az9CiRFrG2F2zEbI6xABPBgxDYh14CwrksDbb4+t4rJ/cP+t9Zf1buul8d86s1
         AZ4Nh4l8FhVPmgHNToTiaFwBExD35CbNYNHGrgFPuKB+fAAZCIHVZq67iGzuT5ZE+Ur6
         rUZgbXoowjkRKSmCyuH++bc1y+8mD5U9Rvf90LBd/fWx8nUF0SF0aHRebphXlS8nSX11
         /eLx/5xK9FqAgfTQDxysewcoUwiWLluospO8Lto98+ztT3MrQFyi9Ga0psEPqPRA01Ru
         lis8faJgDbB9ruImXxDFfhYhfr5u3bW0jOl3SuPPmyeFm2PoK5ZLocODDPeoxyIxvFEu
         9X3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gNftjpirmF6MkUz20BqGllRgQv8RaO3oEqHjZKavblRgFFsUY
	qV0H46YYeFMEldIduZ/MLdg=
X-Google-Smtp-Source: ABdhPJxGMbcrsT89vV2MsoCV74IrZaMVxL3SnDZoZXK5G+jKhayZU8XGkK8FBTiuYEOQJkKguVFWbg==
X-Received: by 2002:a63:210e:: with SMTP id h14mr19146740pgh.232.1604449868563;
        Tue, 03 Nov 2020 16:31:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d8d:: with SMTP id y135ls165179pfc.3.gmail; Tue, 03 Nov
 2020 16:31:08 -0800 (PST)
X-Received: by 2002:a63:e241:: with SMTP id y1mr19669285pgj.264.1604449867947;
        Tue, 03 Nov 2020 16:31:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604449867; cv=none;
        d=google.com; s=arc-20160816;
        b=FgMcLL8ktIveVUawFOos9FmUaltcOhtycDled7YOlJIvF5oVPKUqOpTbOIh4DUiuxG
         ArlIEbqro0AeERsHLuqOn6pQ73pnId/RGKAB/8Dm7fSTMf08vtxWCcPRolwC3vWN+MZM
         SdTiTDr5g+qRde2nMnj01H7OP27+YJNNMscdcwoYRKDzvuSxtxXBS7skWh7QbsAGMxcn
         0em3oEGSAH0mO8FC+BF8IqyDe3hvYUNZM2eLjtofXh9+4NYy2Gfd/3sVyRyCPDRnSN/4
         PAy+c/Fo03CDsGEHOOpUxmhN2iXSPWia4dKv3JRNtGli17itl6dyP0TJcrRfOMasdGfZ
         YhHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UdhHRU0F98jC1cBoiYUxAunB9O2RIE4/2px9pbMYCqA=;
        b=AiqpcVPs8AWO9xK2oDx7j2Z5DiMF6D62XenV7Qwt+vJonVCIF0mXm515pVyqh/HA2f
         0yhXe731IuPoAHu6bFg9jjc3wpXOMMmOTAOLX3Qt3LBf3GHEHNaT0EGo6lj5xvFQAEFg
         6XCvXe9R8JML1S44J4Fc/OdudeXOu/EGK/7lYGq21ELQCW3+pxqa0jcMq/xsQGtAKl4D
         kaakkFqT33r5/F4doXSUhej786tOYjxvaKIpMrWimn8NCe5jFn7pFYmjXLZexHxFFfDc
         zznGknOM/vSo/IoiujE9gdl7XYoGnMjmF1A/DVEudLUdXa277K81GxRf2FlRZIO8T5zi
         eUXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ER7zLL0f;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k24si14601pjq.2.2020.11.03.16.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Nov 2020 16:31:07 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from X1 (unknown [208.106.6.120])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 42824223EA;
	Wed,  4 Nov 2020 00:31:05 +0000 (UTC)
Date: Tue, 3 Nov 2020 16:31:03 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, hpa@zytor.com, paulmck@kernel.org,
 andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
 bp@alien8.de, catalin.marinas@arm.com, cl@linux.com,
 dave.hansen@linux.intel.com, rientjes@google.com, dvyukov@google.com,
 edumazet@google.com, gregkh@linuxfoundation.org, hdanton@sina.com,
 mingo@redhat.com, jannh@google.com, Jonathan.Cameron@huawei.com,
 corbet@lwn.net, iamjoonsoo.kim@lge.com, joern@purestorage.com,
 keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org,
 peterz@infradead.org, sjpark@amazon.com, tglx@linutronix.de,
 vbabka@suse.cz, will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v7 0/9] KFENCE: A low-overhead sampling-based memory
 safety error detector
Message-Id: <20201103163103.109deb9d49a140032d67434f@linux-foundation.org>
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ER7zLL0f;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue,  3 Nov 2020 18:58:32 +0100 Marco Elver <elver@google.com> wrote:

> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.

Has kfence detected any kernel bugs yet?  What is its track record?

Will a kfence merge permit us to remove some other memory debugging
subsystem?  We seem to have rather a lot of them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103163103.109deb9d49a140032d67434f%40linux-foundation.org.
