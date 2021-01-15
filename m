Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRVUQ6AAMGQELI7RRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 19C0D2F834D
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 19:09:12 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id t7sf5411412oog.7
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 10:09:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610734151; cv=pass;
        d=google.com; s=arc-20160816;
        b=ID5auJFzSP9jJ8YeoVDZN8AYmLfpRsU3/spSe+wIq5nlyAGvuRJqY6ueoYYuJREtTA
         8q/D+fd/+K0nlowEX+AQMvbHhJ/7qzJWTkQTDz+Ym5Ag9S3kSPcudvSv4hv8/Yd1h9VO
         x5CcvNGVzJJHQ2k111G04x20OYIcKGqxgCNM1FJRfcwKGoZAN0NT7IDOhNAFQdwt6CJ0
         tRhXFFGjiG4cNEMdSYKvv+so0EKI/6SBBMz9vlUpF30s5oDFYfmySnjVs9zGATxccXB0
         XXJC+MVarDvuzaOkfTXTpF/Vhr4U42Al+bIQCGHZEIOLeTnvoW3dceyrAOp82nbsuFa3
         WUgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WPk8cknpk6kV3KWsJZZJP3myKQhK7lRFG8wPAt4AlCM=;
        b=oq24oJVRTr3bxfc4sIbLo2LtI+IGkwEpwsxnWancDyoa83JDEJ9n2UUy6zyV5Fg4C6
         ts2SYPzwAMJzpzknOEiZujp4L+Dg+pMerFVlUeQHrBxm4ceG1oTtP80s5FSa8ByO8dKC
         WwtRuZ3Cq052YuROpUodSrBrc/ZWetrc1M1/v4AT3AW0qwYXj0vsZ4iUSi6peuk1aqGV
         cGgtodt2mIfRLSz3CM4E6qrX21nfNC6WkrjxGWX/27Mv5XaBJXya0AKn3abgykR3jpnP
         jdqNLqYIJMhnaCtCOG77myPZNFziPq34PX5T4OimlhtF7+q5K40OR1PZsMkchRB2dPmv
         60cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xpx51qo9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WPk8cknpk6kV3KWsJZZJP3myKQhK7lRFG8wPAt4AlCM=;
        b=P0xWZLIDE9cgQBlrnqQDEgtqof0TZktymepRYsQYwGyOiD9ZBSyR4RXZpGdM65iwW9
         rXLLCbUh7qAV+bHc5LqgVinMU2ImhF1Zxe6dahFxhV8psrIPShSuq8pGSRqb9/zEJLQZ
         fy3JbxckFAne8889JxRO/WRjyoalEu2X/6jq6OgtuP+SySXxtfDFYYCBt8JDsnD1ZK49
         IbRRwdkLMb+n7bUJ0andyFLBnXNQnnmEz4mPgzhOKmFm/5tTo6EErrrQ+jzKFIDW/qKz
         etSzUAiJjajoqvNnhPlROwZf8tlRNhnkcqNRZDYEzsJ/0PVV4n32YgSP/zptwWU3TDc3
         5j8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WPk8cknpk6kV3KWsJZZJP3myKQhK7lRFG8wPAt4AlCM=;
        b=lBX+ogivUmwgwFkibZ1R+D8JziGkYPcz4U+h9vnXBVv/EpWtICvoE44Nf2+R7ilJoc
         J6pecd+OWlx/zMZmYmRlpreyUgBkYcLMm2nFmhYJTxsMREqZjGaQBhzrXzR3+kEJCYna
         g/+67UomlF9Fv6KQnHiTDeYpXtc2/0O2iUCgTcnGt16dXQVWGiPMekeXx5lOvrFVQV4+
         iJgZ8+P2b/2oucqlCd68tvcMrt2R3iTZ1BpOdw2s9sDBMo/WxWJ35k6VgVZSykoNXgKX
         e1czrSD07Ar4ed9+drUhD9VN9nfKbOIkzyfqYJsz5Xdc4hSz2TydagvrgM5c7Ko4xw7f
         ZAZA==
X-Gm-Message-State: AOAM533wkC7Y+PhpKc/0Hn4xLHxe3TzWUdejsuV6UKb2P8YkpOQN9Rib
	JEFgAgwpOL3Tui1ygfZH1O4=
X-Google-Smtp-Source: ABdhPJxdCbGc0Bhc7Nk197ToNk86jA7jiee7bPn/uprJdxcxjc87bQ6Du3EjKflEs61fFk+MtY5eJg==
X-Received: by 2002:aca:5248:: with SMTP id g69mr6415993oib.22.1610734150900;
        Fri, 15 Jan 2021 10:09:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4694:: with SMTP id k20ls2377914oic.0.gmail; Fri, 15 Jan
 2021 10:09:10 -0800 (PST)
X-Received: by 2002:aca:3757:: with SMTP id e84mr6220741oia.5.1610734150586;
        Fri, 15 Jan 2021 10:09:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610734150; cv=none;
        d=google.com; s=arc-20160816;
        b=IzuoAN43RSUFi/YQMsFCwA+LWrGMHSvW16Ac+UFys1BmhjW4U2CQEKHO1IaVnMlUel
         DcTfev8hGoBPHuTcwXm5XKeXS9+gxxEOrD5p72rVkPNDhuKOlUaT4PzNQWHk6eb0nxW3
         TXbeW9BLJi0fNexRMbZVMzW8VbWfSjZ4JdbKrSNkVCQg7o5LYzn+fdSOTILNLuaBs/lO
         p7izrWH979iqVCw1caOnMy3z3K/4FBMs7g0iDomxhJAirN3v2R1LHY0dGVcZ+sf2eR3R
         u2KGAUuhFrFpndzc05FINVpU6whUfVkAbAt0cE82FiRlPd97m85lSxxjatZXXehiRMhX
         HOIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GeuXFTMHH/dqlLS30TqVtIZ+iZRqb8fjBFP+mG2mN+E=;
        b=QORaT/Bhr4iC+sfUaUmI5DNVpD7k/aLHISgnEyoRspwnflD7sXtc82CWf51JVNWXYv
         QrjFX/toOz6pMyHZCUj86eosGeWM5//iVciF5HWRnSgFRmAZNOpHju/JGickyFfST0Hw
         /VFTrUgtFUp6XNepu1GK2kXQHFydO1GDP1Gc1B4lNt8HlBuiiIMPQJoBQ6CkdeqF4KIu
         b/UW2xwd2JIvCQiA63D72uYqzzxzQlCazsRSf1003eYgmF71Zk81h+LSN66M3dnV5TdM
         gcNFxCHXYAupX5JPGYBQcvFMwG4uNngHuGE/KczNMzEwSdRAHd94d0+H8joVdlS7ZUui
         ci3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xpx51qo9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id c18si632194oib.5.2021.01.15.10.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 10:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id be12so5107374plb.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 10:09:10 -0800 (PST)
X-Received: by 2002:a17:902:ff06:b029:de:362c:bd0b with SMTP id
 f6-20020a170902ff06b02900de362cbd0bmr13048327plj.13.1610734149962; Fri, 15
 Jan 2021 10:09:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610731872.git.andreyknvl@google.com> <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
 <20210115175922.GI16707@gaia>
In-Reply-To: <20210115175922.GI16707@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 19:08:59 +0100
Message-ID: <CAAeHK+xGDcd1DQVGU-WX+5aM6+0dO08xp20YBLPUJj0i3RWGKQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xpx51qo9;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 15, 2021 at 6:59 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Jan 15, 2021 at 06:41:53PM +0100, Andrey Konovalov wrote:
> > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> >
> > Fix up the pointer tag for kernel pointers in do_tag_check_fault by
> > setting them to the same value as bit 55. Explicitly use __untagged_addr()
> > instead of untagged_addr(), as the latter doesn't affect TTBR1 addresses.
> >
> > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>
> Unless there are other comments, I'll queue this for -rc5 through the
> arm64 tree (I already finalised the arm64 for-next/fixes branch for this
> week).

Sounds good, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxGDcd1DQVGU-WX%2B5aM6%2B0dO08xp20YBLPUJj0i3RWGKQ%40mail.gmail.com.
