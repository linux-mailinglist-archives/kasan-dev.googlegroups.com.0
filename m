Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCM72KBQMGQEBBSM4RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A195335D027
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 20:20:57 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id j187-20020a1c23c40000b0290127873d3384sf1932282wmj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 11:20:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618251657; cv=pass;
        d=google.com; s=arc-20160816;
        b=nq3UFp9ANTFKyJzbKPj/QNtJF3sSjMP8IjkVYH3LB/m9GGfyoXjsM6dIrTHWVX7alp
         OaxWeu9MAYflV6E5I7Nv3tQIp51mhwt+d4dPJl7spXp/J2KA/pEkZKe8aOT4ChKDiAIp
         Pc6ro0oGAevQfAJzKhgiG0FMYbvr25Nbtoynnb/ycestlcJjNB+RBJiGr6bsOsL7hRre
         sUYji7e8PiTAf1y1e7437vl1ZBWNU0TRBvNYKG94NC1L7gbhipymINO+Kzr4CcSyEqyT
         XMqV20k5AV0r1QWCoViGtrZzId8E87V0ND5TCoB1ZBNDaShe5I/pohot3K7ka8zQU4hL
         J9dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KHaF650q3vGLQ1uQhdEmjAHAJLQnc+nC3o5GtqDjNYY=;
        b=QIsAuu/S8MTQKfrY6arhzcyyi3nz9T0pZwkIqa3iSH8noiXMpXT3rJv6bGaOqhNG9o
         TVcnIXnIbekMYBlXgwc63Nc/Dn9/VNJQz5VjGzkO0pZqr0rs3DmIP4GYVgf3PtXzYXyU
         Ry/N44zhi6LgpX4UkO/yTns3es84aesJeltTWzK4b7xSr8UBzlic2vq6vH8ZS0Lkxvn3
         dTmRqVXd3CpG8aszZ+RUCuj3Y3aicXqUrtyYuBDxn7nCv1VYIyTxrrwyFQidoCMrO7mA
         furteT1lJwUgFylu1WWeZK+PNT0iqvbqSCAZ4BV99A/jpz+KaFUnWC6VgexbRKpr2Djr
         Pl5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Owyxnfwc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KHaF650q3vGLQ1uQhdEmjAHAJLQnc+nC3o5GtqDjNYY=;
        b=puW0YklPPp+5OE2osIjWWjeUWeASxLsYGZcTewrjVZYKdPlpCNPmtdmNkDJ2gzbtZ6
         NyHr7nIVSjB8jkSHBh/udHddQKDIPtSgENoikihCsJSAOVPWADxs6r1pZHwdEHjcTi+7
         FHIULXl7SDLlKarHeJ6yE7FndNnrtfpEqJVsLLzoPWhSs0+X7ZaIzjbP6wgd9O1nIksk
         lKslXyZFYHYH9P/ecWwmAHPd/RWAnZRSNP5MN8LdPkQpX6pwhwn32Y6bOr01UkfDIDd4
         diXOCdn5sKhLJaB3hnvfZUCk2KHLPSMROzJK/Jie7hu5hjxyDJ9d/AI4yCn+S7M84TJr
         c1zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KHaF650q3vGLQ1uQhdEmjAHAJLQnc+nC3o5GtqDjNYY=;
        b=PeE4r3vxXqOgyWikwsYzESHnBAqRwRMALNfdNma3lEzcgQ30AYwRlPNvcwUFyqtb6b
         yEh8grdo734+Bkt8kTnx7Zk2JHxWuzKrsD6gTC1/tKDlwCHCLgMKJxM/OGYNs8sdbWF1
         EJWCyo4fTWv5/PcNTAjOWwtXKB3BQzhiwkn0tBZgIIzc6E8aP/PmQKkHxK5Ai5eHYoQ6
         7ce1NSZp1fZx5kO91lOVFHLHdeRCIDHuME4hftMPtkY45cs/iqVtWUf0EAcQSugNprBw
         +G0NUfItGn543LGsJ792dsOgrPrRSrj9S5pIq4MREOfAh8e6F2bjDJcd7TCv2dzrWQMQ
         1AzA==
X-Gm-Message-State: AOAM530FsxNm0wjV6b2dkE08tX8tJxhXWxgKX0b0PrAadjT4i23TqyJu
	rRY7jH5sfEyz+VvlvDsdOCE=
X-Google-Smtp-Source: ABdhPJxJXfbq7SUBw6gaRRIa7XJbLcVDXkgbu0o7zdFqdVHvDYMRa3IxsicWnMpjeH+NkRD3oE+oNQ==
X-Received: by 2002:a05:6000:54d:: with SMTP id b13mr32225361wrf.417.1618251657404;
        Mon, 12 Apr 2021 11:20:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:9a6:: with SMTP id w38ls117406wmp.2.gmail; Mon, 12
 Apr 2021 11:20:56 -0700 (PDT)
X-Received: by 2002:a1c:5453:: with SMTP id p19mr387436wmi.166.1618251656308;
        Mon, 12 Apr 2021 11:20:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618251656; cv=none;
        d=google.com; s=arc-20160816;
        b=Z6DMWZcIuDVm0GaolRKuPyIawuA8eo9bXw8LJPm7+XoXdP4pU1+9bAsiOrJXD7vgnv
         cojGmCJhpYRVGBD8PhozwzZrtVkG4wCs2bGGVuJ9LmkjHALIqGHGdJNThoToLFfJtori
         3SSQT2lQKnn0UIsh4xegtg7R0f7NqsyjMPkJ5//ftaMDgG8gHTi0IpzlPoT4npDoM/kI
         dggEJ3PRxHM6PZ8OqCA0hkgPwtTEtxc15kox7u9UVDALJznf6+khVGjay+LiSPfjf0ns
         SAObmT3O5jorQguEeU1WBaoRXHfIX6gRZz2OIEoGWVQzDz5k0K6imX8u9PZfPW3sfsi3
         Phiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0z3XzP3OkACR5NstqNEyPn1NJX+7W0uBkbKJqycox7I=;
        b=JWt1vCpQ9Dw//y0LDXNRLYWoTVNS3OzSMRtlL3IFglofUN2t17ltaPgMhp/S8GQF0i
         62sXTobyDrQYY+V8KzRmKBaOUKn3SZLZYBPL6AuArk/6BfjuPBwdZbkhu+RTeqJbXZLB
         3PWBbPevcaGg/6MHAgy9xh9alVYRWaaTh3t5vWeXIVHWLp7F83TUJH82LtXPkU+LJH8g
         9TvZBb+bhpXxtk+dy9rZHLneKgVbNus306n1MfIGnHJF/pw1vu1YyGs07LF8laLeIsI2
         7nK/8SPKadplZxJVoCtY/l+obxHCpOyJISCnQtwpZAgGIxWLBnMi/kFvK+p8b3/AC71H
         yrmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Owyxnfwc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id w2si21550wmb.4.2021.04.12.11.20.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Apr 2021 11:20:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id u20so2825294wmj.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Apr 2021 11:20:56 -0700 (PDT)
X-Received: by 2002:a05:600c:189e:: with SMTP id x30mr415323wmp.44.1618251655804;
        Mon, 12 Apr 2021 11:20:55 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:197c:ad7a:49b7:8f5c])
        by smtp.gmail.com with ESMTPSA id g16sm18643195wrs.76.2021.04.12.11.20.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Apr 2021 11:20:55 -0700 (PDT)
Date: Mon, 12 Apr 2021 20:20:46 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Theodore Ts'o <tytso@mit.edu>
Cc: Jan Kara <jack@suse.cz>, Hao Sun <sunhao.th@gmail.com>, jack@suse.com,
	linux-ext4@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, paulmck@kernel.org, dvyukov@google.com
Subject: Re: KCSAN: data-race in __jbd2_journal_file_buffer /
 jbd2_journal_dirty_metadata
Message-ID: <YHSPfiJ/h/f3ky5n@elver.google.com>
References: <CACkBjsZW5Sp4jB51+C5mrMssgq73x8iEko_EV6CTXVvtVa7KPQ@mail.gmail.com>
 <20210406123232.GD19407@quack2.suse.cz>
 <YGx308zQXxOjmwNZ@mit.edu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YGx308zQXxOjmwNZ@mit.edu>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Owyxnfwc;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as
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

On Tue, Apr 06, 2021 at 11:01AM -0400, Theodore Ts'o wrote:
> On Tue, Apr 06, 2021 at 02:32:33PM +0200, Jan Kara wrote:
> > And the comment explains, why we do this unreliable check. Again, if we
> > wanted to silence KCSAN, we could use data_race() macro but AFAIU Ted isn't
> > very fond of that annotation.
> 
> I'm not fond of the data_race macro, but I like bogus KCSAN reports
> even less.  My main complaint is if we're going to have to put the
> data_race() macro in place, we're going to need to annotate each
> location with an explanation of why it's there (suppress a KCSAN false
> positive), and why's it's safe.  If it's only one or two places, it'll
> probably be fine.  If it's dozens, then I would say that KCSAN is
> becoming a net negative in terms of making the Linux kernel code
> maintainable.

I've just seen the latest reports on these data races [1], but it seems
the more relevant context is here.
[1] https://lore.kernel.org/linux-ext4/20210412113158.GA4679@quack2.suse.cz/

Let me try to put things in perspective.

No, we do not want maintainability to suffer. Whether or not documenting
the concurrency design via data_race() and a few comments is a negative
or positive is up to you. To me, it'd be a positive because I don't have
to guess what the code is trying to do because concurrent code rarely is
obvious. (In fairness, if you don't like to add comments, just a
data_race() without comment tells a reader more than now; perhaps they'd
then rummage in the git logs.)

Yes, there are currently lots of data-racy accesses in the kernel that
are mostly benign. Yet, they are data races in the memory model's eyes,
and every optimizing compiler is free to screw them up! For example a
lot of those plain read-modify-write bitops ("...  |= ...").

Unfortunately tooling cannot determine without hints (like data_race())
whether or not those are safe, since the programmer's intent is unclear.
Crucially, the programmer's intent is also unclear to the compiler!
Which means the compiler _is_ free to screw up those operations.

If we could somehow precisely determine which plain accesses can race,
we'd solve a decades-old problem: optimizing compilers and concurrent
code do not get along. Therefore, C needed a memory model to sort out
this mess, which we have since C11. The Linux kernel, however, doesn't
play by those rules. The Linux Kernel Memory Model (LKMM) tries to
specify the rules the kernel can safely play by.

But since we have KCSAN, which initially tried to follow the LKMM
strictly, various feedback has resulted in taming KCSAN to a subset of
the LKMM. A lot of the data races that are left, yet appear benign,
simply have no obvious rules or patterns (otherwise we wouldn't have the
problem we have with optimizing compilers). I couldn't, in good
conscience, tame KCSAN based on poorly thought-out rules. Because we
know they're data races, and the compiler _is_ free to subject them to
concurrency-unsafe optimizations.

Because we knew that different codes will want different KCSAN exposure
until there is a de-facto LKMM that is to be followed everywhere (one
can dream), KCSAN has lots of knobs. They are described in detail here:
https://lwn.net/Articles/816854/

> I'm not fond of the data_race macro, but I like bogus KCSAN reports
> even less.

While the data_race() macro was meant to be exactly for this case, to
tell tooling "this data race is fine, even if the compiler messes it
up", if there are too many data races for you right now feel free to add
'KCSAN_SANITIZE_file.o := n' to the files you don't want checked. Or
even 'KCSAN_SANITIZE := n' to ignore all files in a directory. It would
avoid the robots sending you reports. Not ideal, but it'd give some time
to see how things evolve elsewhere if you'd rather avoid all this for
now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YHSPfiJ/h/f3ky5n%40elver.google.com.
