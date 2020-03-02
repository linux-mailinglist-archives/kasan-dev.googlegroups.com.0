Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VC6XZAKGQEVI7KI2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DDACD1762C9
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 19:33:15 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id d12sf31190vsh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 10:33:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583173994; cv=pass;
        d=google.com; s=arc-20160816;
        b=ue5u+nCS4VYehlKSNUyNQ67eLIbxYb7bubXMzpKqH2CDNy63+hGsRAV0NkuiUIsqv8
         Sd7IgPQKfOQy94Wjk5E6k88l001+yx3dqzEKL888QelwOXzAYEhv0iQ3tipY3D5vucjf
         jjWh9QccF/t1QUieQHay475JZjaVp47j8JG9sqMbnrcbV+Mu2CciIbCsb9xcxvXVbqcf
         cE/ZkgACMuQ54egdCl4xQZi8tOvjoX9QFP4T4vHvzYqJlBVKGU0JvDQW72tUD0aSluSd
         6rjkD3XxaBWiDxB8oze1htXIgj08jVt1FzAF4pAb9Hs7nvVefopROVfQdniOrORtGpu/
         wHpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PMAgNwEO9l3ha9RKVfvjLNV3v8bpL/c883zYS/bF36w=;
        b=Jtd7+h9JZP7B9kymzyBE6gvN2ALU1vrWFILGXOwACsIKzfjo7SSEud/5wo6CdtCnLJ
         8T4+LofDjNh9rF36yhPIrsE3HBSbeKw1dtmXYRlXNbGpPlpj7/wiy97xlA+UgR3KpkEH
         YRZgWCgOI6Cuuh5Wy2yzU7kaBacVCJk9GIdPJcHlhuThX4IgObUYeoMMjdGLEN2CM6uT
         hNdGine/pKQWOEA6htHkMJ7OKCFDj7AHzmZfj3bY6P+u6afMAYIu2uqjDZQxuCdIqsgg
         +/AYGc19Jo4Xu9d7M9zyTIFjSJk2e16b3Dc6PQdBJQfZewZFbsiTWRmt7zlhtfD2D2ks
         /sDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fHPhUsdH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PMAgNwEO9l3ha9RKVfvjLNV3v8bpL/c883zYS/bF36w=;
        b=c9bxvmRzql/v2AZHuYWKYh3SuJd1OXtuBuE3iU5sBJG5zJwi+5yvdjIiX8mfEG4aX1
         8CmlIl6gHaxCvCsvJpFQPW/66GzEzqIQk7zoeJqPqDrRnO5MtfrrTcCDIjrF5xFtPBRD
         JtuhwQXdsQvouGhDYfFgeZmlJduKeL3xVGdRtWqHiP8RP8IkPWEE800F7JFqSyDmBx2o
         MtPdx6MS8rtYhNUS/dN9OssCKBed86/XrFbvkwtuF5RLeWEjIbQ04CE8zWk7ZLt5UNaH
         +2TVv1Uxi13ZRvar6uwL2YhuFpAvSS50QEu9pRkFJDjKdqYDlzk+NmxScfztpJLDG6jp
         JiUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PMAgNwEO9l3ha9RKVfvjLNV3v8bpL/c883zYS/bF36w=;
        b=FW4J3oPkasq1NHik01LauI76bwhPlYIAJtR5o1JD36svemTmbvdisWr1uTrZyAAIMP
         8ML0sYaRNdOgwr8Nj5zoRnvbCT/EpgmZwDqUuL7XbNXEgfmH0HjEQicQ59FG1bTnkXk8
         764cPtk9CCOubWELmfhN7pRDnvXZpiWpmxUuhtQHKJB5+khX18MOh1+DigmKxtpnq6ws
         VPOX0IettjMdb5WTfHsm6NhwERQGkeAAB1u2G1I4DJ/pB1EQeZDBZ+aYgOxKmt36C9Xi
         mvJEngb5WNRR4HRuDSfz1shyj949b5xEKWeDBkVEuzFAhofrleFU+u6pKZpIRXToLu4a
         2Mow==
X-Gm-Message-State: ANhLgQ3JDM3ec9rF3bYvlKEdHuA7F3yg09sDwvTzqfD48qnIn30W4OsG
	9Rwfb1cE2QQuImWXf1LS7Pc=
X-Google-Smtp-Source: ADFU+vvHRhNIMCzdyzwJ0DoVIjihpArUyEjwPuU/zjUyqUMdZe/x+qNNIneAEQ1pqq6DSktLCtBRBA==
X-Received: by 2002:a05:6102:749:: with SMTP id v9mr143453vsg.173.1583173994739;
        Mon, 02 Mar 2020 10:33:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:503:: with SMTP id l3ls72741vsa.10.gmail; Mon, 02
 Mar 2020 10:33:14 -0800 (PST)
X-Received: by 2002:a67:ee46:: with SMTP id g6mr142317vsp.153.1583173994344;
        Mon, 02 Mar 2020 10:33:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583173994; cv=none;
        d=google.com; s=arc-20160816;
        b=IJf2q2v1cy1zydWykfo4Nk7q7d6SthlnbnhVZtTwVSTdNDV1UVZgD03+0B6yZMOPxR
         OqsTLwcZD9BNzsKgPUUZJ1GCFVvsQlR0JZNzypZ7znXHni4qvb/ci/u6Xl05KoIKi93y
         1rOVXQDSwtb4f+4ui74SbydDPJpYYXr8qIJ6DLV/q4BtPLE4TjimjVG7XLJOB7+KU/Li
         aAV8NkccAr5jb4gJB9WdQ+F6b6yg77nS5V71iBFs3Op5tMqxOiGZtFhHDLes4sytFNNb
         Solg03JLNUTgbMyO+JAZY5Wk4VoOURK1umB/INcZyl7k5p0U2kh/tNBRjl/a5qyDe8i1
         0fdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MZbmtOiRk93OR72yt1EoTbIuU9x3jbqZX+qgicq1dyY=;
        b=x6BV5KbIg7fbp1IuG5C8ct+ZM3Cr8vQuf5F9NTjuE5eBFzruHWsG5G0ioOswH3NKo/
         oVZACyhje6pTZO7bty89LQUpJu81H/8+kaAAKyNE4mMalAy5eyxjpILmRhevtJ+eA+nw
         I//eA+13EbISFDgo0g6dMQ5NcseHsamoNH4ZSpizxLo6VF7E125L+5IcO0fZ+HGhxt+b
         vXb+BltO6MnPwjYhu8gISKUxVyFNdaDoEpAT1UAQEc+5+DRWOSr2QunekdXar9PX/NH8
         hxIyJP48IEovNZkeRHeKfb2EVwYgadUmo0sWNSNEtwfIXYnAJlAvktZZQr+hxymJ2ZhI
         hBMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fHPhUsdH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id 9si514543vkq.2.2020.03.02.10.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 10:33:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id q81so267914oig.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 10:33:14 -0800 (PST)
X-Received: by 2002:a05:6808:983:: with SMTP id a3mr317859oic.172.1583173993550;
 Mon, 02 Mar 2020 10:33:13 -0800 (PST)
MIME-Version: 1.0
References: <20200302141819.40270-1-elver@google.com> <8d5fdc95ed3847508bf0d523f41a5862@AcuMS.aculab.com>
In-Reply-To: <8d5fdc95ed3847508bf0d523f41a5862@AcuMS.aculab.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Mar 2020 19:33:02 +0100
Message-ID: <CANpmjNNbXLzrVOpLPVaCfX_f96s9kdGXUioBm8QnS8A+B_-NKg@mail.gmail.com>
Subject: Re: [PATCH v2] tools/memory-model/Documentation: Fix "conflict" definition
To: David Laight <David.Laight@aculab.com>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"stern@rowland.harvard.edu" <stern@rowland.harvard.edu>, 
	"parri.andrea@gmail.com" <parri.andrea@gmail.com>, "will@kernel.org" <will@kernel.org>, 
	"peterz@infradead.org" <peterz@infradead.org>, "boqun.feng@gmail.com" <boqun.feng@gmail.com>, 
	"npiggin@gmail.com" <npiggin@gmail.com>, "dhowells@redhat.com" <dhowells@redhat.com>, 
	"j.alglave@ucl.ac.uk" <j.alglave@ucl.ac.uk>, "luc.maranget@inria.fr" <luc.maranget@inria.fr>, 
	"paulmck@kernel.org" <paulmck@kernel.org>, "akiyks@gmail.com" <akiyks@gmail.com>, 
	"dlustig@nvidia.com" <dlustig@nvidia.com>, "joel@joelfernandes.org" <joel@joelfernandes.org>, 
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fHPhUsdH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Mon, 2 Mar 2020 at 18:44, David Laight <David.Laight@aculab.com> wrote:
>
> From: Marco Elver
> > Sent: 02 March 2020 14:18
> >
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses.
> > The definition of "data race" remains unchanged.
> >
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
>
> I'm pretty sure that Linux requires that the underlying memory
> subsystem remove any possible 'conflicts' by serialising the
> requests (in an arbitrary order).
>
> So 'conflicts' are never relevant.

A "conflict" is nothing bad per-se. A conflict is simply "two accesses
to the same location, at least one is a write". Conflicting accesses
may not even be concurrent.

> There are memory subsystems where conflicts MUST be avoided.
> For instance the fpga I use have some dual-ported memory.
> Concurrent accesses on the two ports for the same address
> must (usually) be avoided if one is a write.
> Two writes will generate corrupt memory.
> A concurrent write+read will generate a garbage read.
> In the special case where the two ports use the same clock
> it is possible to force the read to be 'old data' but that
> constrains the timings.
>
> On such systems the code must avoid conflicting cycles.

What I gather is that on this system you need to avoid "concurrent
conflicting" accesses. Note that, "conflict" does not imply
"concurrent" and vice-versa.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNbXLzrVOpLPVaCfX_f96s9kdGXUioBm8QnS8A%2BB_-NKg%40mail.gmail.com.
