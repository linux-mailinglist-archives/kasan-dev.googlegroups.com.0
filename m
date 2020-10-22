Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX7CYX6AKGQEAXXIPMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id BB0DA295DB7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 13:47:44 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id g24sf1039640pfo.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 04:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603367263; cv=pass;
        d=google.com; s=arc-20160816;
        b=DsXkTotQg2C4dgX9hQDyoj7r0zpoPHN8z7STgbBS5pAJNb3DNc/ZAUPLEBeFMeZVJ4
         +QOjIEiiYgpYHiTfes0ztqwwZN0eYF6xSijOY8RT+RF7Eib/mkz93b5rD2+fAPmnRD1y
         L5ok22TtBMlxtLczWWY7Se11zQH5otrDAA+wm34BEI/nd7NXTedohp71GjxJZ9t9mi/n
         x13TOJ+m87J3xaNWGUe0NZ9z+pX3h97GWYkQUwA4YCM8Hht+3S0hn4v4N7M26BIAsUjC
         vh2Q2TRz4+T6uSRPc4g8rtVOtqTJ4bVOA44MjYTGPiqxp5q8sETQc9V3kmOUPuhHVzNJ
         +OBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hNnpFUnPdiEjWjQNp4OrMUOXCr1h4Cf3mBB+nKPVn7o=;
        b=I4smGYWzqGgwQkr44W3qfvkHaNeAyk8yjZ0+I87GbvSkqiWbZ09PxuoVeyS12UatZn
         qzdR+/p2pCq8bdOwbfq03ChrIi2ZIsnawpVSnfWSbXESTkCdBrS+WJ6I6Vyx3faOXbEF
         bOsI0EkfeXRFE0Huy+sgsM9XQyjRQMwhCXhZA1mpFtXe30WfXlTmSnsKCd7C3rpfecPZ
         agznfTfPS+BGXtjq0Y2t+mq3MPwzr/nGGavZ75IUSbbFZGVmHNfQEcNnaS+/cov39glA
         yO4Wz2OAhDbdaAmi7iwDuBHD6Jl1ePUkWI0i/8+3bVjfI4B8KsqgxFz3VxLvgT3I61Mu
         ZA1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IM7WAkzC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hNnpFUnPdiEjWjQNp4OrMUOXCr1h4Cf3mBB+nKPVn7o=;
        b=o8G7/Q0lEe/HTDTC3xmPK8ZVwLilNkebLymCYTKW/1t4oOT4Z91PaLqD4NmFw6Ydws
         J0KvMAJjKyVu6gpfDUc6dgmCgW2R9OQXJtxHiHZLwCSfHJooYGjcGmh7EWkbo55merBi
         s2ZVSck3RyGuc65LSfXD7XRbNTNOAC8Qcq0qCHnffVN6ka9LIPSdx/pGmSU9NuXNYmJk
         85PwGJ2VC/FdHlY3HQggw2kMYc6V20SWJ4Qht8CntHEsyNJPvu4hUaC3sSP9OKMnMy4d
         P1hrtQDYYFnBShqF8OMmhLDhQ75OvNDAT2buvwIGOj/4mTxonZQw/SyGDabI4kOsIkCt
         t8ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hNnpFUnPdiEjWjQNp4OrMUOXCr1h4Cf3mBB+nKPVn7o=;
        b=Mz4rrNemuwWa8QrYlHVGNDKUDRINMuu04yz1kLI/kDGRtMFWhrb3fLQUnpvjawS2zW
         Gn8NW+Bn1+VVWmp9hhd4HpFU6JbI7wgnQAj6jA6D5JfMmEU5dsNSTREfFkZwVbVFcMZy
         H/PgUUQcoARf5FzgXDLqo/UxJmM21kYjPwNcO0yW33nxZuSkW9WCifSVh+vEyAoWS5iQ
         4bIB8mAjJzzqjbf4Wy2aEZS4MQC0xW5YYbUZ/EY36Ckwor80bcadkiAc2rDvfMoNRTx1
         WT6TF6nJaLeNMQvkkjaDMfN7bP9PZJQ8I+O344XoP0Fk00WwiIjvm5/NhgI76icDvg64
         N8Yw==
X-Gm-Message-State: AOAM531gTAuIbpwehFPLtbxjx1vQK9rZbSFMkGVCrXXeVIVIVxKTRuc9
	ulx1jV2e1uunopt06GuA28s=
X-Google-Smtp-Source: ABdhPJzR96UzFOsfsdtWnohKZVkTDk04bLu6anqy0ryNUQty2uWtJYpAJIiNGa9Nec2Bc9feQ40g8Q==
X-Received: by 2002:a63:5d44:: with SMTP id o4mr1815795pgm.409.1603367263268;
        Thu, 22 Oct 2020 04:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b05:: with SMTP id w5ls664200pfc.11.gmail; Thu, 22 Oct
 2020 04:47:42 -0700 (PDT)
X-Received: by 2002:a63:f14:: with SMTP id e20mr2040584pgl.52.1603367262691;
        Thu, 22 Oct 2020 04:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603367262; cv=none;
        d=google.com; s=arc-20160816;
        b=DZGRhWBXOXk9LRqC4HBH+fbtPyrk2+MdQ6wMxohNjss6m8bOSV2ONPDlmz3bqJ3j5F
         mv6KgcYjXGroXPfrgoRjpIpFzqvcMlpn//qDJZZ2PPd9xdahrI84JHfOQfHn0pmmucig
         zSnDBmRqkgt+bKtvmUqicAG02+TLhmXpa/n3UZKXu+ciRloSHB2d9twiFmvdVA3hoa/c
         fDrjGhvJbS6ZN+mMmB3bB5pgf7SzjF4oGtQbY0inpPkjwTTdp7kJ2w7+CiHbeAsMzHAs
         0RPwrMyTqOmkEmEOzxW1JRvWTlVdAjP346tl2d2Bqjt9s208dhNoWSvRMtDVrFSzDgqJ
         bFtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nQ90kVlYCVdEBMkM5DxKx4SDCKnOT8r71z3S9jFcYrw=;
        b=dyWOuFOptW8zXCBq5MFioxyeHHF21LgKoVreqBvCjCR7FVbw6eXSRd6cihCLa+hWVk
         a4ecrmUFqq5MAI588Vm5vUvS7tFdbInWBmtx+cvRxDeNeiDTI9yct1xMm3CCwJZ3GYOp
         uaJiCbHRCcGm1YYc3OFndLVQbZZ1VA1B3k3Ntjp3ETuC0zb3zZtvcJhvRojDoZXShwBv
         +0LsJSE4834dFRE/HUqVzZrUHmvDoUun8FEl0DNomxaLrV9voZF66uAF8TZVmtDHoes1
         CPpnIZMTSao603NJdSrztoSizWHg41LstiGQbGJXbah37bde0QE9TxTHfdf4vPY27p0Q
         gFmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IM7WAkzC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id mu11si53784pjb.0.2020.10.22.04.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 04:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id j7so1364889oie.12
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 04:47:42 -0700 (PDT)
X-Received: by 2002:aca:6206:: with SMTP id w6mr1303294oib.121.1603367261918;
 Thu, 22 Oct 2020 04:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20201022112956.2356757-1-elver@google.com>
In-Reply-To: <20201022112956.2356757-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 13:47:30 +0200
Message-ID: <CANpmjNNyhPtb04np4bm6SgUyGfQaPt1RVb4ktjF3Uv=95NHxxg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Never set up watchpoints on NULL pointers
To: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IM7WAkzC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Thu, 22 Oct 2020 at 13:30, Marco Elver <elver@google.com> wrote:
>
> Avoid setting up watchpoints on NULL pointers, as otherwise we would
> crash inside the KCSAN runtime (when checking for value changes) instead
> of the instrumented code.
>
> Because that may be confusing, skip any address less than PAGE_SIZE.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---

Please use the series at:
https://lkml.kernel.org/r/20201022114553.2440135-1-elver@google.com
which includes a prerequisite patch that was missing.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyhPtb04np4bm6SgUyGfQaPt1RVb4ktjF3Uv%3D95NHxxg%40mail.gmail.com.
