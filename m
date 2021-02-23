Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQ772OAQMGQEBJNZIHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52C88322B47
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 14:14:44 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id l7sf4924977oos.15
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 05:14:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614086083; cv=pass;
        d=google.com; s=arc-20160816;
        b=CjwtE79NPkTJO7ThvUDtaFk9RcxVaiFvZehzB61uwl7NoXGNTBZCPVd1tp5izcBqM0
         JJ3E37nGfMfKQbXSBGKVzGRraLwpUIniXiavb4k3HpMP+FsYz7TtTwV8YaYOXhEga28B
         of+41y9g48FyB4z4GkX9cbTDE5WKywCFyLUfZmTu1/Pixd23TL9PnD1x+w+WsdVkBxN1
         63qZXdcKG8ud+Q3fQt6qpSTGcetJOlWIu1w3H/oV36HwZy533ntKKim3+cJNS4UJgQ4Z
         OpfSBByZ8CskedH2cE2abvI9/k8BfHXaHqgIfNMwU8oSE2+z588qvl9P/MMIJqFrx1F4
         NleQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=z/hi3RemePlmA1ICOvcWHdsmOv9OxOW+CpLYeFBsomE=;
        b=mlDvWrUCxAlcdD30sIPwnquuaRh6knACiggwaJIfVWsByxyohgt63VlKEywGbIRewd
         XkV0KI9TNfoXTLQ3GZiEVW5FddJ63dXUaMxQS2oDTBRpLI3n5R2nMMpAij41jfmENcaf
         M/a/NJiJ2SFokoJJ2yOt13N8X4kosks0KZ1BQP7yEJ6AJjqOUnObti4XJQlrG024zl3H
         ADDyhpi237xEPIAOXldN3EYjUgfVh5/yqVQRZdca23NmdgbsHYdf398nnlkzokyeBlCP
         HTOCdKlSHW28fcnpImvKEFZ1oNYbStzFreZoH9dWJZudZ7Zsr66VHO4j4DHSMM+tqY3m
         eRyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z/hi3RemePlmA1ICOvcWHdsmOv9OxOW+CpLYeFBsomE=;
        b=l7FGfsAcSPhTD4GP4lYUxHlyr7hYJZ4qXOz6IdzfInpnbjrQYUJFnxtJMO51GWS+zr
         rdJ95QNbOzBRtXBRBCZywTdTRkYjs6kbVPXVaMAvpnkITNEtx6sUum+UzYgQzOOGR5be
         3GiZm3Qh7pYpxqVO/WQQWdNYeCrGdarhY04Lxms3qCH/BlYEq2agzKncS+dpF/PbP9rK
         xa7a5yHRFz5F7pwv1si5wpk9Jhd/TGzSIiuj/V+0yn0/LLEvOInqJel69wCa/pu0knAt
         zL6qVDBkWlzeZ3AQtkuas+K0vvi9ACU34b0KJ+EsmHVcR4k00DWRqf+C0xTWBsUuBClD
         5CQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z/hi3RemePlmA1ICOvcWHdsmOv9OxOW+CpLYeFBsomE=;
        b=f5vNHWvdPHP2XHSmBubw5n6UQUhH+loWWIQlvgq91gXoOj9AN2ueXvOYCwir2CCunb
         8No5/k7pFDzssse/p0MhKN7WLE3IncI1trjiAPROOw0JhjRY2HsY8XvPcDubquZnGuyA
         QuP0nKac011CVAIFFAD1Wi0/xWTV0y4EGjpogW7bCCE25UBqCUiOTrabVhdqP5X/lC8w
         SXTG38SnBAWhRVqX53pVmKYQ9l0D1ldi4tuvn5qKhIiZdHHgYfzywbM8JDVlee91O2d8
         7Oe1VdAi0gSToq3q8U6DP6jpeMbjpludiJg2IJoV+JstTviB4FpjXFkVV9LpvTidpfHV
         fDrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JFOsDMx0ZUybvgrqZM8xoBFflYKTfqEP6UiMegaynjQ6trDfw
	5Su6IXlBBbHrhq+8YSnb080=
X-Google-Smtp-Source: ABdhPJzEuFMj8dhh2Cscd1lmAA6XBl7W0gBlWd3MeDLhZds/6HOzaxQ2nCo5IbU6JEfLxNLia0dI3w==
X-Received: by 2002:a9d:71c6:: with SMTP id z6mr20897313otj.276.1614086083283;
        Tue, 23 Feb 2021 05:14:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1553:: with SMTP id l19ls1123370otp.4.gmail; Tue,
 23 Feb 2021 05:14:42 -0800 (PST)
X-Received: by 2002:a05:6830:128c:: with SMTP id z12mr20353194otp.130.1614086082901;
        Tue, 23 Feb 2021 05:14:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614086082; cv=none;
        d=google.com; s=arc-20160816;
        b=xDiLPWF9kvDG5oKVcTPc3oZNVeUFa6t6Wp/PpNHOVhzM3v2uafMVnzBtqMhIOQafB6
         kj8B/BPhj1IkZJDEuw4CI8DKMIAQBxdKQajh2oCt7Ykz3IHdY7vfkx3/CB/Wv6BhVI4/
         4bgrSzMqBfyMq2BZnzUzrcDEQtz8x4EcifGV1qsTCbyuFqghOehqMUnLcHAWXlMEhY8r
         Ylvp+e60CP5fF72PhZuWRge7vgGF+sUuB7XwA4/Hn1WCCq+ngTVlBqk+JQACJ9ULJme2
         W7QMt4g5J/MyPoUmbrtO2pAc9WnPX87YovyVb3/zTC7cthVLsQaWE+bvxEEPTtpfvcB/
         cezA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=rQ7HDhVNwvJOKjrAoP5GHZtS/1FFXvk3BwA7r+ewgBA=;
        b=iQsY+kGlf+o1RB0dLAE4xcxS4wDZ4yzORyd/6EDTHnmxB7ECKkyR3U2rzalprzLwYe
         xutDD8H145pD4dbs0b0x3js6vLRyKbCOVrukUCwkYtxoOzShS4eIeq+hQSl2nk/f19PA
         1JnMizKaksP9aaHq4nSiBaUT5TQQe+9Rn532UAkfY3CngPgZjWa0QIzLpmvAP97ik6Qm
         IX83yPr7jf/0mBmXSElFwVd1s0uiYjShYlF+ZX1f8zwWCYZkuG6lfB7e42b5SgZBZp/A
         xo+6xV9+weuUnlsuw+DKBVUvTJFci84BXbfpEDRYnXvUJpCDhkrYxp3OknWC2AME6T7X
         HINw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b10si1017267ots.5.2021.02.23.05.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 05:14:42 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E57E264E2E;
	Tue, 23 Feb 2021 13:14:39 +0000 (UTC)
Date: Tue, 23 Feb 2021 13:14:37 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Will Deacon <will@kernel.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210223131435.GB20769@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
 <20210223120530.GA20769@arm.com>
 <20210223124951.GA10563@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210223124951.GA10563@willie-the-truck>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 23, 2021 at 12:49:52PM +0000, Will Deacon wrote:
> On Tue, Feb 23, 2021 at 12:05:32PM +0000, Catalin Marinas wrote:
> > On Tue, Feb 23, 2021 at 10:56:46AM +0000, Vincenzo Frascino wrote:
> > > On 2/22/21 5:58 PM, Catalin Marinas wrote:
> > > > We'll still have an issue with dynamically switching the async/sync mode
> > > > at run-time. Luckily kasan doesn't do this now. The problem is that
> > > > until the last CPU have been switched from async to sync, we can't
> > > > toggle the static label. When switching from sync to async, we need
> > > > to do it on the first CPU being switched.
> > > 
> > > I totally agree on this point. In the case of runtime switching we might need
> > > the rethink completely the strategy and depends a lot on what we want to allow
> > > and what not. For the kernel I imagine we will need to expose something in sysfs
> > > that affects all the cores and then maybe stop_machine() to propagate it to all
> > > the cores. Do you think having some of the cores running in sync mode and some
> > > in async is a viable solution?
> > 
> > stop_machine() is an option indeed. I think it's still possible to run
> > some cores in async while others in sync but the static key here would
> > only be toggled when no async CPUs are left.
> 
> Just as a general point, but if we expose stop_machine() via sysfs we
> probably want to limit that to privileged users so you can't DoS the system
> by spamming into the file.

Definitely. Anyway, that's a later kasan feature if they'd find it
useful. Currently the mode is set at boot from cmdline.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223131435.GB20769%40arm.com.
