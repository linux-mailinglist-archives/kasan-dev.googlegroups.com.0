Return-Path: <kasan-dev+bncBD63HSEZTUIBB6VPZL6QKGQEAEPZM4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 873F22B48F0
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:17:15 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id u37sf21271477ybi.15
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:17:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605539834; cv=pass;
        d=google.com; s=arc-20160816;
        b=wpoaEekeqbsFAiaDvqie+GWPZfsm5dfYvbOfHdcP9D0vpDRI89tyGUs2S2bxnB8hVF
         RBPiY0ndRnJ5mEpIOATMctHRwIsdYKRsjayVd0GYJEGeX7NrOik2nDcYv9w7cfME0EDy
         3q27AZXTyJl+kHox8IjbqhB3T7CK7g8ns5jftagalZvSsSUnjWxQRkuPV1tfwvrhkwbP
         YyWfL/WyddcN75t+bubCaM+y5td0q/KMttxJ0pfZHSqgjBuxwagf5cHcf3UmUo5ArSFS
         HqBgSjSsH61XVMhS1D8cIbxDQGTKs+NF570Hwa6N9FRrCMH0APVpz9rjlEQ54SwPfDdD
         ruxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=6NZ21+xxLn/pJ/x4hwtnL3rQ4zjPENnCr8CwWD0WVdQ=;
        b=c7tf1nGPD3smpZ6PEV03+J5+BP4XKTaXILCmg7KgfzDzXwcOSRJy6Xo5ioW21fEfSx
         jKJm4NKFWxa2mnoHH1JEKTTH6/Lo0eDFzcrRrYwJ2+HUGXEGZf5NlSSUw44cpS3OMxDY
         JyzFhdD/74cM1RPf7YfRl5txVTqMyf46KThXnx4g/PkLbIyr9HnHXgmoAi2xS3Zg9Q+X
         Xkmt6OTXKK1p/a2nuRxX/7xHzec5oQd/3RnSSVgIxsbG22fL2JKxmq+q8JEZfzy7u0Dm
         MYb9j84lzTt6jbvG3gj5AhJofZg7G+eae88r/8H2R7grtjzYnFpaSrkLtO9gsV4VZcA9
         VKDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DYCEsQqU;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6NZ21+xxLn/pJ/x4hwtnL3rQ4zjPENnCr8CwWD0WVdQ=;
        b=TkLg8M4Lvj0lYg68EthcEHrX7Gq+i/zBdxGk+pf10H4sILm7NIzsVjqeDYKQ/mlaoq
         bCGvp+O2nqxqzFz75gLgRFMN09oGbp/tPUYJDHAmFOf5BQ6GrLvodOpIUzX8aLWXZfYO
         cst3U0dNaWybbl/zL2lbyLrggZVKM4LEcvQJpDmOFrttNUIP5vS1Rk9oCNqCf+VOa4Dd
         9OH8lFbNplqKgzzABPoZ70FHHyzx6YI7Ar1qtb8OXy1scNwJFAWle+BaLOE2RQlvB31M
         n0JXWwnf4ns97axF5msSc+DkpVh9QpYDBQxgFgGjGUSiJuBo7sxixzYgvNsfUQoEThG6
         8Xvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6NZ21+xxLn/pJ/x4hwtnL3rQ4zjPENnCr8CwWD0WVdQ=;
        b=cd8ocEQFdVctebd2ewMdE4vDSFeACXH4+hhJtMSe8jBQHyoS0z+9wZbie5l2N/isPZ
         /uzAfBHO8a06KW6wpVlkxnHy5n7gn+2+Yt5Y0Cmvhb/0zViDAOY5X9MdNuh3xUrhr1Gb
         +AY1hZrnAYsEtqzJ/z5jqI16xxZ6t9OesEe+Kwa7X2J8fCz0Bq0k27zuX0BQXMh96FyN
         IIlZxTR63tKp6WCdZ+gaowq/MEL+kQtwXbQs8gAXyN2ahdJ8W6dZ+38AuGl441ixfOf3
         f5OEiDj8QjYbPBzZZPYpIff0KRyosZd9xamE2qpWvcpRluG2q7QLhXL46vWCdi+kCdPJ
         KQMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530x+Ow9OC9e3/VTwkeO3buGbiBaWgjsWZXMnhrl5PyuGD6qnBiU
	QWCDMf2rVcUzoHzXf3vabfo=
X-Google-Smtp-Source: ABdhPJyYkOTZ88GpSopb308zwQHcgqVD35YwDVdKNvnF1yqVhRNJOyftwGHvB/O/42uIVbEHlsaqHw==
X-Received: by 2002:a25:c946:: with SMTP id z67mr10534121ybf.56.1605539834444;
        Mon, 16 Nov 2020 07:17:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:4cd:: with SMTP id u13ls7015968ybp.9.gmail; Mon, 16 Nov
 2020 07:17:13 -0800 (PST)
X-Received: by 2002:a25:20c3:: with SMTP id g186mr9828276ybg.475.1605539833925;
        Mon, 16 Nov 2020 07:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605539833; cv=none;
        d=google.com; s=arc-20160816;
        b=UD1yIggLq2Bs/heWcZAsyCo2EHu1TWdaipLPhErGcNMrX9XgCGU6TUEwxIW5CZAT4L
         wF1iLfcmZVjNehDXU44byl96W9BkAhxUpSkhQCpUrJHkxTMgXtajlVhogoIn+K58lore
         if1WHrc11ApiQpUG40byfnURfEEh5sxV7rwzK1i9UiLRfxqyS1lC7c9NiEtl9MeAbiWp
         t/ZI7B8FYJAdut9A3gLXx9hWUmRK6Y6Q0vYgv1jItzk+UDrNck64+G6hi3keyx8KG1FW
         b2fpaNbZADzfWEKsVQS/FOLCL/RlURNFSBuxzb1QfhHPe2N94hNNsb5rs7k3tM6VmN5b
         LIQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e1HQYiwm1KTWlMXlYVtIGSInMYW1f6CbIyrdNrjQM1w=;
        b=rCS/yoUuigoZ7zEty37b83n9nN3hubruSCowZHnFspKZrIJguugsPHdjzozO4QJ9dd
         upsob/Yh06+Ydh3kWJXemWz6ZGqtA9ETQUWnDDPmfwFA2W+LytUutjrwqJ/adVCfKD5r
         sgeJU+bkNT76H8xW4GZQNLXNx3Gkziosh2X0PqW3WWBA5VojrNd7wIvict0KtYIZI80q
         uVBVTVqLEgGXmfEDhzRCdQSIPKkySsjVu62O8Bg6sppR26deLeH/pObQKihTfPikOM1E
         U2GphbKAUvUzPZQSdA4i67waaSmGfyvfnY5YvXLVOKj03ux0LAa8G3La4/5CBA/cVDWf
         Bogw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DYCEsQqU;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l7si246159ybt.4.2020.11.16.07.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f181.google.com (mail-oi1-f181.google.com [209.85.167.181])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BAEDB21527
	for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 15:17:12 +0000 (UTC)
Received: by mail-oi1-f181.google.com with SMTP id c80so19171245oib.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:17:12 -0800 (PST)
X-Received: by 2002:aca:c60c:: with SMTP id w12mr10610302oif.174.1605539832094;
 Mon, 16 Nov 2020 07:17:12 -0800 (PST)
MIME-Version: 1.0
References: <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk> <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
 <20201109160643.GY1551@shell.armlinux.org.uk> <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
 <CACRpkdZ1PwT13-mdPBw=ATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg@mail.gmail.com>
 <CAMj1kXGXPnC8k2MRxVzCtGu4X=nZ8yHg7F3NUM8S_9xMxreA9Q@mail.gmail.com> <20201112175216.GB934563@ubuntu-m3-large-x86>
In-Reply-To: <20201112175216.GB934563@ubuntu-m3-large-x86>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 16 Nov 2020 16:16:58 +0100
X-Gmail-Original-Message-ID: <CAMj1kXGjw4-a-Qsh6W8Kp8RaLGU3LXq-VU6paZ5EucJJuP0ScQ@mail.gmail.com>
Message-ID: <CAMj1kXGjw4-a-Qsh6W8Kp8RaLGU3LXq-VU6paZ5EucJJuP0ScQ@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, 
	Russell King - ARM Linux admin <linux@armlinux.org.uk>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Florian Fainelli <f.fainelli@gmail.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>, 
	Arnd Bergmann <arnd@arndb.de>, Abbott Liu <liuwenliang@huawei.com>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Linux-Next Mailing List <linux-next@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DYCEsQqU;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, 12 Nov 2020 at 18:52, Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> On Thu, Nov 12, 2020 at 04:05:52PM +0100, Ard Biesheuvel wrote:
> > On Thu, 12 Nov 2020 at 14:51, Linus Walleij <linus.walleij@linaro.org> wrote:
> > >
> > > On Tue, Nov 10, 2020 at 1:05 PM Ard Biesheuvel <ardb@kernel.org> wrote:
> > > > On Mon, 9 Nov 2020 at 17:07, Russell King - ARM Linux admin
> > > > <linux@armlinux.org.uk> wrote:
> > > > >
> > > > > On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> > > > > > On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> > > > > > <linux@armlinux.org.uk> wrote:
> > > > > > > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> > > > > >
> > > > > > > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > > > > > > build *without* the changes from mmotm?
> > > > > > > >
> > > > > > > > That tree isn't using git either is it?
> > > > > > > >
> > > > > > > > Is this one of those cases where we should ask Stephen R
> > > > > > > > to carry this patch on top of -next until the merge window?
> > > > > > >
> > > > > > > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > > > > > > until the following merge window, and queue up the non-conflicing
> > > > > > > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > > > > > > and the conflicting patches along with 9017/2 in the following
> > > > > > > merge window.
> > > > > > >
> > > > > > > That means delaying KASan enablement another three months or so,
> > > > > > > but should result in less headaches about how to avoid build
> > > > > > > breakage with different bits going through different trees.
> > > > > > >
> > > > > > > Comments?
> > > > > >
> > > > > > I suppose I would survive deferring it. Or we could merge the
> > > > > > smaller enablement patch towards the end of the merge
> > > > > > window once the MM changes are in.
> > > > > >
> > > > > > If it is just *one* patch in the MM tree I suppose we could also
> > > > > > just apply that one patch also to the ARM tree, and then this
> > > > > > fixup on top. It does look a bit convoluted in the git history with
> > > > > > two hashes and the same patch twice, but it's what I've done
> > > > > > at times when there was no other choice that doing that or
> > > > > > deferring development. It works as long as the patches are
> > > > > > textually identical: git will cope.
> > > > >
> > > > > I thought there was a problem that if I applied the fix then my tree
> > > > > no longer builds without the changes in -mm?
> > > > >
> > > >
> > > > Indeed. Someone is changing the __alias() wrappers [for no good reason
> > > > afaict] in a way that does not allow for new users of those wrappers
> > > > to come in concurrently.
> > > >
> > > > Hency my suggestion to switch to the raw __attribute__((alias("..")))
> > > > notation for the time being, and switch back to __alias() somewhere
> > > > after v5.11-rc1.
> > > >
> > > > Or we might add this to the file in question
> > > >
> > > > #undef __alias
> > > > #define __alias(symbol) __attribute__((__alias__(symbol)))
> > > >
> > > > and switch to the quoted versions of the identifier. Then we can just
> > > > drop these two lines again later, after v5.11-rc1
> > >
> > > I was under the impression that there was some "post-next"
> > > trick that mmot apply this patch after -next has been merged
> > > so it's solved now?
> > >
> >
> > Yes, it appears that [0] has been picked up, I guess we weren't cc'ed
> > on the version that was sent to akpm [which is fine btw, although a
> > followup reply here that things are all good now would have been
> > appreciated]
> >
> >
> > https://lore.kernel.org/linux-arm-kernel/20201109001712.3384097-1-natechancellor@gmail.com/
>
> Hi Ard,
>
> Odd, you were on the list of people to receive that patch and you acked
> it but it seems that Andrew did not CC you when he actually applied the
> patch:
>
> https://lore.kernel.org/mm-commits/20201110212436.yGYhesom8%25akpm@linux-foundation.org/
>
> My apologies for not following up, we appear to be all good now for the
> time being (aside from the futex issue that I reported earlier).
>

No worries - at least it is fixed now. And KASAN is already shaking
out bugs, so it is great that we finally managed to enable this for
ARM.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGjw4-a-Qsh6W8Kp8RaLGU3LXq-VU6paZ5EucJJuP0ScQ%40mail.gmail.com.
