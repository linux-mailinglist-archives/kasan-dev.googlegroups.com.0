Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTUKUL4AKGQELBDFH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E282221B920
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 17:12:15 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id o2sf3847894ilg.14
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 08:12:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594393935; cv=pass;
        d=google.com; s=arc-20160816;
        b=dcAo1T5lugBdOMy88K4xcwHEVlHymrcJIHUj/MsdNGtgif70pBX9qiMsv0dwidF5/K
         5x9HlU16CCAvsSiIxEcwUzOzsW9PzPChA3rIc2QJ4VTm7CNe1pOakQWdTArUH2Yw51M2
         3uKFCtVU+/Idn/lNpWPFnzNpzlwXa3P/jIYeZ5xxTuzQ7EIE5V/etvkprWJ5CLIiFbd5
         vF0tTDAcM4EZso8ya8ySCmFuj3Xv3oHc/g9Px6s+nlRT8efuEqlo5KOlDBsdT9oSQF/P
         hfRNGSU+syqAs/yGPItZaWwMfZHfPJOS7VOGqN7rIylIZosfDITX3UsH1p82ElI7mdmb
         PwGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Adz4BtLLaR8et9iXPpJx+jJIzMm2Dgdh5JvKrHKecRc=;
        b=gH2749UEUoYMGF1nil76FqhKlf2P8CSEhVB5hq0ZXzLPiS46LL97lhQp/hWWZTBD85
         5ePYzdF73/p5J20HxNbjIJiGUNKxIEBRMDL1O7xPNOriTCypAsuL5b1krSZ2HMiK4w+Z
         1P5boGwT8oMQqF1z+XN9a7D4cLFmQAJ65LOQhZC4Sk8b9syrr0IUXq7rXMUX/vq6meBf
         bbo18pEVwVlN1sHpUU/k32fFLokVt0TzNQSuxrvpIccBdzFoj7vkZzVOVXl5WReRPCXV
         hDE7HHka27DlsrVv0Rp3bQJfYjBq5oqAZ3xhpXCuvdIg6T6kXCa6Ag7kbL89WsmKC/SG
         3Yxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZFMZY1r6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Adz4BtLLaR8et9iXPpJx+jJIzMm2Dgdh5JvKrHKecRc=;
        b=GqGeeOB/LZe44KIXFV1WdU5awNMUYP78qb4Fvzx5vQ9PjA2d0/K87LKalxIJ2NNDwd
         jvo0zf4Y5hAw3uyL3aTWvLBLyctwZ3R31uNKOVMZP/wH4OsQsh5JrOtfN6ZZjiE08vt4
         1BBV/Gdra2ygO9JTI0uAz12uLWSc7HW5/Ri8ekseZqQIjriSjYp+OhNGs/7zd8UokaDy
         awUYhta0GzTCdgUeEShyVCyRj24qqFwL61LALu9zBbhcI3vMHLB4ubv7X3qtIYsfX8P3
         NgA1uP1dNKj52WKCONFswJCiHdlRCZdp6Jl73yhcEG/VyAAZsZ9MLmFx/3EgLISL/BhR
         ouBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Adz4BtLLaR8et9iXPpJx+jJIzMm2Dgdh5JvKrHKecRc=;
        b=L+qg9ALPoTGpZVxHMI1IirEhqgZkj2XRZVc/0wrKYCFzrOnrivlKLXvKq7FNSWOGJY
         obcva1a3Rcb0HT3MQ/WU3xYKeTrsLOOjnhj4wyVS7ibTPExBoEqQZdI3IL/etbludKPb
         6/xDk9kQ54EoXRwrcdYW8M2SBeu3ZY8CVeurLDe04K1essZMmERrcF+x+FrFT3MusU+2
         XUTZB9qKmy2orJxF/g72qB1xivZyNdAedsirXZJdqCt/8Fi39xo7o2rAdFqyZV5Cwulc
         8H65PPLS4iKH8upJTZ4GNdKnKvTIcB8/eyFL5xbu4T8RT7suJkOjOT0shdB1kbm90ILY
         JUuw==
X-Gm-Message-State: AOAM532z25s/lIYqL2+34uJ5NwgxUJ+X+K7pg9//WsyUYZp+RPaphmLq
	5Oe2F8YT+eTj0AEZ3y2uZ9Y=
X-Google-Smtp-Source: ABdhPJyUpKlP4Uwm+lXZ6mnxKUaaOZ80kcbZr+unryE2vEFbme8FSm5wWMQe9SogcZFWTyhh8SFkBA==
X-Received: by 2002:a92:a148:: with SMTP id v69mr51711514ili.7.1594393934829;
        Fri, 10 Jul 2020 08:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a89:: with SMTP id c9ls2422543ill.7.gmail; Fri, 10 Jul
 2020 08:12:14 -0700 (PDT)
X-Received: by 2002:a92:1bd5:: with SMTP id f82mr22702696ill.121.1594393934449;
        Fri, 10 Jul 2020 08:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594393934; cv=none;
        d=google.com; s=arc-20160816;
        b=T4KMUrqH2uMVO+hpSTpOlqwgafqt6MY36k7Tpy15TC9mk8CizSNOyeYiHWbnszCoa6
         URLGH3OwbnCOlRGQvikOBGKcMQSYIG8tGr9rnHif3rcAbtK5naRXbGbzU4l2vDVW01wd
         1ZpEwELUFUdrUuNgO5J0YdPWKZ9gAIV0qpVONw95kM7uHeW4jifsXKHjp9qF7f5J/pJk
         6t190pY4MKbRAntzu4L0AhxItVLUm3BtBBNCBc2iFBafjLrABUou6nBborE83SHl9QEq
         XU8mv+Cd8cDlq6ZnZO17ItzG32LWSxIesPj35lJxJizNo/zCxHVDv3B95O0zPHtVZTF7
         eAQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BT6oGbOYcorzIDNtBkfh/sJp5PTtpoYA6e9UXGRz5rY=;
        b=UXh4eU5pERFIsqxQZtZgzp/oAWI8AwBNKxlkmB/GVgKD8Xusw7xKGpwbmPBtt0SgxA
         gmptaVv29RJWniPgPVjr0uwtaOzh1UrsaAiWAIk1OKO+pXlSEI0BOpQLPGUnyLvpx0Il
         uUyf26aY1b7DlmPneaMEWpEKi0y9tHZfYTyxh8LWx4l1kUkE3VFbjhbxeXuatlhYCqZe
         KVE/Bz9PkTxb/VahoQ0pN97ejU6sW7I0QvwE/5fmg7nDctblFyyOtjlUa4uj4e/cJ6RV
         bVywmMx3Rn2sOWW3rsEAEWUHiPgr2ofSKHrWqEg3V5/dZgNwpMhm/w74d0JBiKpSdXvv
         8WLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZFMZY1r6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id p1si437891ioh.3.2020.07.10.08.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jul 2020 08:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id j11so5024163oiw.12
        for <kasan-dev@googlegroups.com>; Fri, 10 Jul 2020 08:12:14 -0700 (PDT)
X-Received: by 2002:aca:cf4f:: with SMTP id f76mr4555556oig.172.1594393933763;
 Fri, 10 Jul 2020 08:12:13 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org> <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
In-Reply-To: <20200710135747.GA29727@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jul 2020 17:12:02 +0200
Message-ID: <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZFMZY1r6;       spf=pass
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

On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Jul 10, 2020 at 03:41:03PM +0200, Marco Elver wrote:
> > [+Cc mailing list and other folks]
> >
> > Hi Sachin,
>
> Hi all,
>
> > On Fri, 10 Jul 2020 at 15:09, <sgrover@codeaurora.org> wrote:
> > > Are these all the KCSAN changes:
> > >
> > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/kernel/kcsan
> > >
> > > And the same are applicable for arm64?
> >
> > No, those aren't all KCSAN changes, those are only the core changes.
> > There are other changes, but unless they were in arch/, they will
> > apply to arm64 of course.
> >
> > The the full list of changes up to the point KCSAN was merged can be
> > obtained with
> >
> >   git log locking-urgent-2020-06-11..locking-kcsan-2020-06-11
> >
> > where both tags are on -tip
> > [https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git]. Note,
> > in case you're trying to backport this to an older kernel, I don't
> > recommend it because of all the ONCE changes that happened before the
> > merge. If you want to try and backport, we could dig out an older
> > pre-ONCE-rework version. Another reason I wouldn't recommend a
> > backport for now is because of all the unaddressed data races, and
> > KCSAN generally just throwing all kinds of (potentially already fixed
> > in mainline) reports at you.
> >
> > On mainline, you could try to just cherry-pick Mark's patch from a few
> > months ago to enable one of the earlier KCSAN versions on arm64:
> > https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=arm64/kcsan&id=ae1d089527027ce710e464105a73eb0db27d7875
>
> As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> release before sending the arm64 patch. I'd wanted to stress the result
> locally with my arm64 Syzkaller instsance etc before sending it out, and
> didn't fancy doing that from a locally-built clang on an arbitrary
> commit.
>
> If you think there'sa a sufficiently stable clang commit to test from,
> I'm happy to give that a go.

Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
(famous last words ;-)). We've been using LLVM commit
ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
(https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).

There's also https://github.com/ClangBuiltLinux/tc-build, but I think
the version that one's pointing to is slightly older (May) and doesn't
yet have all the commits we want for KCSAN.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD%2BzO_3C0P0xjYXYw%40mail.gmail.com.
