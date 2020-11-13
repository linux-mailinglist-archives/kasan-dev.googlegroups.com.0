Return-Path: <kasan-dev+bncBDDL3KWR4EBRBR7KXH6QKGQEFUVWQYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FE7D2B1A6A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 13:00:08 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id u16sf6256873ilq.14
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 04:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605268807; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIYMwObx5or8hb/GntLAP/GHpt+EupsTu3WcVuXZCm7pd7EbjpIHqUxVAAOwGXVinI
         ovy8080xo0fMP5oP6hjEJwGVYKaWTS2JmzCDh/MUG1pOKNk1VsONF7ZbuBZJ5Lu2LrIE
         eYvHPB5muCE9nc0HDj6as0THM90t52x+Pa16YjmroozQeGvLBbidh0PgFMHLVFHfydNj
         fiPchRinr5lm9EspxuZvyv4Po+yQu4gdu8j2ga4+0B9Toizu4t4t3rEMPoicpC9pzXKy
         tgxLJGSX/045oaFa1hvg98vdZKz5Ate3tUoCdDo67RY7wfqMXU9UxRawGAt5S7M7nirP
         pPBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=SK2yX/0JPRptFAponvN6aSJyditvnIXDqhRzgUQXrnI=;
        b=XrP/BR1Qv8A+eewXoC77/2YWSGHgAJNYPINwCj3XeIFuvcyQdwgtJeGEe58GhYTp9W
         PvCLKb3o4aZT7m0oiY65JhKGmOTWBJIV5Ge5AiyTO0rM48e5IL+XReMxBFpWQJKiHnhC
         58Mhhv3nAqJium0zUyXsODILFLnKJZs5IrumL1vECfdJJsya0WfaXa91y/xrsz+Xfg5S
         CTkkuT0TvuDwMLWNXkSvJxmOE5UN2In9x7bVdAHmVkATYNxoKJQw41jxFiinNp0Dmn37
         OmbXCXIynyRFLSWrkmK1AoNTLkdo2invsH9PxY+G2wAaB0bu0bW+cisc5SpPr2B5o+z8
         IJvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SK2yX/0JPRptFAponvN6aSJyditvnIXDqhRzgUQXrnI=;
        b=dRdN1R1ETl7WvYdjrUv7DBCyUTL1CcZyuS1GdTWnWwKck4C7NHZzAnSW9fBOHeGYFD
         ouou1odUb6flc7ucc9xekIuMlSGOaknINxoX8ZRH8N/1kTJO2VeIul/DNho0x/lI9ePt
         7URkxyr5oLv4XShu0Pjea3VApLSYWGWUZf+TDYsEEI+rw3+e4w/hbhnz2QMC9C57HUj+
         GMbm5vzeCBztgzNvK04mDh+7zGPnh6JAti2RIR0sC01R1t7wMUaHtIePaq6WlBIofP7v
         Y5mMyu1uCi3UnUso/G5R7TLvB6SirTmDR9VqrBgmeHS4vYJ8pV5lgjjlTvHBZP+T5Cqd
         h57g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SK2yX/0JPRptFAponvN6aSJyditvnIXDqhRzgUQXrnI=;
        b=giN4VO2b1uAovpsYPb7hlWvj496kHYmhTFIboXKz8Za2pOG3/WoqqBrWGdItmZWV2n
         P3AGaSXlLYCTRKvfGKDy+ZDi37cXJOywKaNmx5Q9KvT1piXmeU7+QDAOYjEZ0YV8788Y
         SmfnPGokc/PPchu+/oZxnlW7BJ5oIk+tnFbODXJvb2ZjiT0uuWAHndHQqTWG6bwB/7Lz
         tcqvo1nYH9yW+9AVuPHS7IMrj5LUh4283BbBHcEmko3+OsEL0uSROjsrpfc3VjufT0/x
         2T39sz+RJxslmXK3UYSgXzpiNS+MPOWg3FCsDdV4w3iyYCSnUvY2EIQriz5a256YwqsF
         272g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Sj3qEItEdGSTjIFyyGpbQY+zhRpw0AMw19DtN6YecFD0xl2vO
	mQe9qq+XqRM7Wwksc113B2Q=
X-Google-Smtp-Source: ABdhPJx0b3W8ytPRIA+B0jQoSGvk15mEKIa77yeMQqoKIy3GxTWXZ4AY6vsvVdIzbfhcnW7tJ8b6lQ==
X-Received: by 2002:a92:6e12:: with SMTP id j18mr1153614ilc.44.1605268807365;
        Fri, 13 Nov 2020 04:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f90c:: with SMTP id j12ls932415iog.7.gmail; Fri, 13 Nov
 2020 04:00:07 -0800 (PST)
X-Received: by 2002:a6b:4401:: with SMTP id r1mr1566519ioa.78.1605268806945;
        Fri, 13 Nov 2020 04:00:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605268806; cv=none;
        d=google.com; s=arc-20160816;
        b=ev+XJDvMtmcY8KAPiQcixVIo5m29UjsFi6+Y5ZJsFn8glYiGvskaceYHnYa2I+M/0k
         gOsgYSjT77mNInxk6+IT6252fNHvuSIQV97SoQx2C6p8CqZ0kdoAPLyIuGvUh5U1CKIh
         kQZY0X7PdduHsiEyuhV7VjISuQoTGBv7CtJtg2DmIjGfX0owVE1EfEwS+JqPXVTyj7ql
         nLPHXsY/Q2sVD9MmpbncJ4DCUz9BsSAQlWAy7fqaYsAX1oG6btDp8jFc+4bLjPyu+lEr
         0O3+e3iiyntaSmdG0BSAY5cmtB81t6PhIaEq2sfBT/JW00mT05tsNDaqcEDADYZJkaSW
         4zrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=rw+ezY+sxlbNQ0ZPe6Z94qZY9Gcj4yMIYl2EziXFB5Q=;
        b=0QmPgrZ9l75onUqx1cgATxiPqv3IaEK/0S2VU0G3W6RIwXfmMGzW3qTBThkmgpynuC
         +GHYtu0F6vUc/aaIZFoibHDwh+mc+3aIraGgDGDnuEriijDuBpbGQ9ZnCcanbSu3t11H
         CU6CqmLFxyC4eDH4a7507p2F5+y3ysSnNWSW7ZpZI1Eb1uFNizyfnjDj4ttAy1PWi1/B
         SJdyHxDbEUa475GmoskxPan3UDvzO9wJ1XDixcF9FtXruzDmrYroSVOOTNINoBYEbO9Q
         4E/08J9AyRXF3MvSbtgxz0KfGjsM2FMPE9OM2sA+XvjZ9R4M6UWMBA1lzuJuaGp6AKXp
         C5rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y16si360837ilk.4.2020.11.13.04.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Nov 2020 04:00:06 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7FD642224B;
	Fri, 13 Nov 2020 12:00:03 +0000 (UTC)
Date: Fri, 13 Nov 2020 12:00:01 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
Message-ID: <20201113120000.GB3212@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
 <20201112094354.GF29613@gaia>
 <66ef4957-f399-4af1-eec5-d5782551e995@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <66ef4957-f399-4af1-eec5-d5782551e995@arm.com>
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

On Fri, Nov 13, 2020 at 11:17:15AM +0000, Vincenzo Frascino wrote:
> On 11/12/20 9:43 AM, Catalin Marinas wrote:
> > On Tue, Nov 10, 2020 at 11:10:27PM +0100, Andrey Konovalov wrote:
> >> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>
> >> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
> >> feature and requires it to be enabled. MTE supports
> >>
> >> This patch adds a new mte_init_tags() helper, that enables MTE in
> >> Synchronous mode in EL1 and is intended to be called from KASAN runtime
> >> during initialization.
> > 
> > There's no mte_init_tags() in this function.
> 
> During the rework, I realized that the description of mte_init_tags() in this
> patch refers to mte_enable_kernel(). In fact the only thing that mte_init_tags()
> does is to configure the GCR_EL1 register, hence my preference would be to keep
> all the code that deals with such a register in one patch.

Fine by me as long as the commit text is consistent with the diff.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113120000.GB3212%40gaia.
