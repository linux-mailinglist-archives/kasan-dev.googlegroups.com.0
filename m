Return-Path: <kasan-dev+bncBD4NDKWHQYDRBU7MWX6QKGQEIRC6TIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D6932B0BA7
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 18:52:20 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id h19sf2664576oib.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 09:52:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605203539; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNqtRPcUdMzD1YUjIzcquB+NB5EsF4RFX+Z8RiWHikGYop+Wmtgz1qqdQOZHn0qOwQ
         K74bw0zcuAzTPv9qjBxdBGtc9QB4x/ntMH2BHFHep5BObDB+TgP+uOvQw1cF9K78A2I4
         ue7+q8MQ6ZZZiJKaI1HQaAYbD1XEqlEiEQvDlPXW4+mAJZYVHBmyliqxqVxoehZeFIoh
         sPVF+w3Hg8nLNh0ehrZDSEsYfGzdGekub9SMJR8CLu+XWRLytPJFS78IMT57kkJ5QVoD
         a54hjW6iHwMOnGRBThzhk6pdCzZeaDSw0TWinaumSJMwDA2JQtZhUBDwMlkhcHZqqup4
         yrYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=DRcPe0Lp3sWbGR4twwqLvynsr/WZML4oAPD5F9tjrsE=;
        b=Lo/Pok2AomF8Z3E1S5xxVEqCbH/1V0RIYP8uNvj/SlQIvX12ioFtPlCzGfMlaMuTxu
         9SizyWXjiXK1PiFzMtbG/wRn7ZgrPiKMCFlB0psnstDtOqBXvlWiYwmy/uSvufd9R2nn
         JyLKDGjzfWrQZ9pJxke7kwyHI6BrrR37fdys0vhuyyvzZyNkLCW5+6wynn4yrX+yo8qg
         fNu+bhDY6bI1EjqHHatQhXhTVm3xrXYlJhZfpfHDu9/9rf0RjIpr+hEZE6G5DJhL5xur
         psctoamjvYr/iyd/PduzU75tCoDxHiJL8nMUC02h/PMLmiazdtTMMN5xBZH+z6HSbJfV
         Dxyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MMfgWC4Z;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DRcPe0Lp3sWbGR4twwqLvynsr/WZML4oAPD5F9tjrsE=;
        b=KwhA5m1qDelzd3XZj7yACqipjDeqAa+t2yP3dGlhHyEyXl0L9czTGk0pwD4LVSEnoL
         JxYXLVdLvEr9KxeDIgcgZVjP7rQ8YQPAT/MYL4GFSV6RQ8P+zcrJOOtn3JfjvMs2Fiqc
         Zx4n0zYJ5mDv8//3Ni9kWAygQBZl0ONkh92HG9+c+6deCxSnqTCcrpgcNkR9uXXyBwv9
         uJXxNfIeZVl1SmKtQoCKeQZDi20Yl3QggraZ1Djucjhwv15kUaJ+CCJbWN3yyw0bqa6J
         S++595iC7rgEBgV6oE7sGw+0LNRVPf6/19j6TVP7zm2JeaH4BitAMjhgfQsO0fcLBgKs
         uN3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DRcPe0Lp3sWbGR4twwqLvynsr/WZML4oAPD5F9tjrsE=;
        b=oebXuknyQpvLNOKcKS4c9MFUo9ZiRZEduB+efDUPHuix8RjbFst/51RTIKspXV5FtG
         k1Dz6RBGq15oqf1N2ifptTrJxH7wi5LHbKWSfFAhQmTTpsA8GEVP+dlvWbemtLaV9ElU
         mJsWeSxcqeV53quz/Jek1AjazfUfWjGPIjbViZxkhgoG8pWTHuXMnrxOnHQxAgoAPIy+
         i4PgioH4cAig6y6wbXQxWUwayZPx7FRtiVYJxhsbYa5xMShQqKOSfO3tLI0U4Ty42Ah5
         N8N+saYfDilRFFx9cMfpgOMvovYvkCAUmbHBuCCyMKpAsDaYvyLirIW6Mbu5ox8B7VSm
         fs/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DRcPe0Lp3sWbGR4twwqLvynsr/WZML4oAPD5F9tjrsE=;
        b=GSGk20ad/Gq/vL5mg6AzA0V4oU7dY/vRBUnnVcncJApTapqDYw/1HhX1LaiIOi08Ki
         1Yf+0B4d9nMMFarzcyo8GBWWt1huLd5PEVTWbgp/vni7BM4bIGYyo6qAZ0dWT84M12cN
         GNRThAgmLUj5k2M/HqmIH9CWHALsiIqN5BZ7TCswvpNk4GEmu5TpAW88xtA9klaVUb1g
         nAqj+FNUsFbSkucKIZfT9jcNOwTCf8i/GFMh9aoMKKb+UAQFgmHNGxXUeJbPHasB3H+e
         UXA5SYRpiX4SolR8m/EPkSM8PiK5A4dCrBc2ryBaJU86q8sf9LXTy+QaiPHMCjy9zaku
         SJBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325QJTvyZ18AVnFtoXnTrF5HF2LQDBVL9ZZ0N5eazubIFxN76MQ
	7oC+aX51g4WfY7jh8wyYhcc=
X-Google-Smtp-Source: ABdhPJydeP+yyTdo6n98lR7sGVfdT58f6DiAVMZrua8Y7C3ERYg3jkjAdvy+3m4K9TTAOO98Pvwj/w==
X-Received: by 2002:a9d:7f15:: with SMTP id j21mr296897otq.76.1605203539221;
        Thu, 12 Nov 2020 09:52:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:51cd:: with SMTP id d13ls910436oth.11.gmail; Thu, 12 Nov
 2020 09:52:18 -0800 (PST)
X-Received: by 2002:a9d:410:: with SMTP id 16mr241849otc.315.1605203538862;
        Thu, 12 Nov 2020 09:52:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605203538; cv=none;
        d=google.com; s=arc-20160816;
        b=CvYowdBN9gJhtK/yiMl5D7gIsbki0N7IZeLfpy/HjY6E3pUriQ6Bmey2I4IReC04Dl
         ZJaFnJhbCbol2DO2/ZW+4Xc5CC19ULo2OEh/xyXtNkdV4vy5yn2vDchVlYgAKFrYGaCE
         aFDqRpTU9OY98G6wJTs5m5rE8XvaGZoF7IMvhIyuLncNmuRx81k6a678pgbh/gHwdtAA
         dPCoFGhsE1MfEYEpBEuWDx7rmtbeeleJVdTF0Hgv5Rd2F70EOH22F8uZFQB2z6VpQ9qX
         sSfHAAnzd1zexxNU3PbvUJ4bWWlrTDC2OOnAcJ4nR9n4jTDBaTC1oSHQRsgWp2HT6lFg
         QaTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=MV5o1y23M6b0t2UlHjVlNzL4uzRL01omBINxln5TdCQ=;
        b=ykVk3CwDYsSopbT+a6aRbMdhP5aPSk06cOPhNaKZ3kIZaqJztr4buxMLtnuM87QeD2
         o5mM5G2oHwADEbbNAlXBqG+oz1pvqeJQeFN2S17EhhBT6C9YVFzSOoICJXt7cCPsUAHo
         HjRuzW5B8G5fqjXcDbQzj8DiiY6swermSwW4gWR3O702y3AbXO/DkdyRE1F5vH2NmfjK
         HtvC2qKp+Iy23V/FjhTdoMpR6RCmDh9o5fEas123evmN0jhzQAm/eSb1A7MUayiMRKJq
         J2zpjMbSbHzUu1FL9rl0IWx/Au7Wx1wtnz6mKxtpmfs2E5KjYIplUNUQR8GIb8w45L+6
         8HqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MMfgWC4Z;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id f16si576350otc.0.2020.11.12.09.52.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 09:52:18 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id ec16so3202699qvb.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 09:52:18 -0800 (PST)
X-Received: by 2002:a0c:bd19:: with SMTP id m25mr831736qvg.52.1605203538329;
        Thu, 12 Nov 2020 09:52:18 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id k64sm5255179qkc.97.2020.11.12.09.52.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Nov 2020 09:52:17 -0800 (PST)
Date: Thu, 12 Nov 2020 10:52:16 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Linus Walleij <linus.walleij@linaro.org>,
	Russell King - ARM Linux admin <linux@armlinux.org.uk>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Arnd Bergmann <arnd@arndb.de>, Abbott Liu <liuwenliang@huawei.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Linux-Next Mailing List <linux-next@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
Message-ID: <20201112175216.GB934563@ubuntu-m3-large-x86>
References: <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86>
 <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk>
 <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
 <20201109160643.GY1551@shell.armlinux.org.uk>
 <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
 <CACRpkdZ1PwT13-mdPBw=ATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg@mail.gmail.com>
 <CAMj1kXGXPnC8k2MRxVzCtGu4X=nZ8yHg7F3NUM8S_9xMxreA9Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXGXPnC8k2MRxVzCtGu4X=nZ8yHg7F3NUM8S_9xMxreA9Q@mail.gmail.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=MMfgWC4Z;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 12, 2020 at 04:05:52PM +0100, Ard Biesheuvel wrote:
> On Thu, 12 Nov 2020 at 14:51, Linus Walleij <linus.walleij@linaro.org> wrote:
> >
> > On Tue, Nov 10, 2020 at 1:05 PM Ard Biesheuvel <ardb@kernel.org> wrote:
> > > On Mon, 9 Nov 2020 at 17:07, Russell King - ARM Linux admin
> > > <linux@armlinux.org.uk> wrote:
> > > >
> > > > On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> > > > > On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> > > > > <linux@armlinux.org.uk> wrote:
> > > > > > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> > > > >
> > > > > > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > > > > > build *without* the changes from mmotm?
> > > > > > >
> > > > > > > That tree isn't using git either is it?
> > > > > > >
> > > > > > > Is this one of those cases where we should ask Stephen R
> > > > > > > to carry this patch on top of -next until the merge window?
> > > > > >
> > > > > > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > > > > > until the following merge window, and queue up the non-conflicing
> > > > > > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > > > > > and the conflicting patches along with 9017/2 in the following
> > > > > > merge window.
> > > > > >
> > > > > > That means delaying KASan enablement another three months or so,
> > > > > > but should result in less headaches about how to avoid build
> > > > > > breakage with different bits going through different trees.
> > > > > >
> > > > > > Comments?
> > > > >
> > > > > I suppose I would survive deferring it. Or we could merge the
> > > > > smaller enablement patch towards the end of the merge
> > > > > window once the MM changes are in.
> > > > >
> > > > > If it is just *one* patch in the MM tree I suppose we could also
> > > > > just apply that one patch also to the ARM tree, and then this
> > > > > fixup on top. It does look a bit convoluted in the git history with
> > > > > two hashes and the same patch twice, but it's what I've done
> > > > > at times when there was no other choice that doing that or
> > > > > deferring development. It works as long as the patches are
> > > > > textually identical: git will cope.
> > > >
> > > > I thought there was a problem that if I applied the fix then my tree
> > > > no longer builds without the changes in -mm?
> > > >
> > >
> > > Indeed. Someone is changing the __alias() wrappers [for no good reason
> > > afaict] in a way that does not allow for new users of those wrappers
> > > to come in concurrently.
> > >
> > > Hency my suggestion to switch to the raw __attribute__((alias("..")))
> > > notation for the time being, and switch back to __alias() somewhere
> > > after v5.11-rc1.
> > >
> > > Or we might add this to the file in question
> > >
> > > #undef __alias
> > > #define __alias(symbol) __attribute__((__alias__(symbol)))
> > >
> > > and switch to the quoted versions of the identifier. Then we can just
> > > drop these two lines again later, after v5.11-rc1
> >
> > I was under the impression that there was some "post-next"
> > trick that mmot apply this patch after -next has been merged
> > so it's solved now?
> >
> 
> Yes, it appears that [0] has been picked up, I guess we weren't cc'ed
> on the version that was sent to akpm [which is fine btw, although a
> followup reply here that things are all good now would have been
> appreciated]
> 
> 
> https://lore.kernel.org/linux-arm-kernel/20201109001712.3384097-1-natechancellor@gmail.com/

Hi Ard,

Odd, you were on the list of people to receive that patch and you acked
it but it seems that Andrew did not CC you when he actually applied the
patch:

https://lore.kernel.org/mm-commits/20201110212436.yGYhesom8%25akpm@linux-foundation.org/

My apologies for not following up, we appear to be all good now for the
time being (aside from the futex issue that I reported earlier).

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112175216.GB934563%40ubuntu-m3-large-x86.
