Return-Path: <kasan-dev+bncBDYJPJO25UGBBONRYL6AKGQEA7KDZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 227D629536A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 22:23:23 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id s10sf1028829otq.4
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 13:23:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603311802; cv=pass;
        d=google.com; s=arc-20160816;
        b=AqtVEXCjmZ9Kgrsi/506xKCFp8WrE3c7g1wPdOJz9bbhYZerk5V6rnAxRrhlDZGl08
         jPjCxeRBTdd5EN5sKwyv0G51VPXw2YIqYVSl0uC3yOOSK2TTyh94JEYndkWw8Guq/ziz
         JCVpSB28tbf7gTgkk2zR73L1laY/vsBIdwS3AlhD/jZAgSgDS+rrbKLQVPPnYTPdCIJ9
         UNA51duZNYONIYlPSe9mK5U1DWfsdySeCkD/ekncp85z0PiCTMKzEZp5DPFGWEwgeBez
         WZ5YdgT7pwU6u/W8swnl/pTskIA10RIi/LAaDmfgXGWjzDIgZbULfLcS56447vxDqE64
         7C7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cfrRGVzfhJabIy+C2XEqwiB4Us35SS75VNuxH/wFz4s=;
        b=yFewVnb6jbp7MXJOkI28cj4nig7IS2WrwS/D2J/+FxM7IOfPZcnLsauvgPyC2Qwga0
         FeE0ZKtoYemQfgixOlZCYOvfG0VkleurY0tppa00hfcGTCsLadDSjoMRMU0AR7iZlces
         mFcmQ75S9hx9WUt1H2fkXbnOtcyrlxHT2VDkFWZwI3jdZKnu4qqdN0X243dNij+PUBoh
         eooDJL4trbn5DbksE/NzNU9NbJFwUrMrVJ/DjwacEecYikrKoqHIK6tp1ezH2W89vsl8
         QcXkuwKkGTXncetdKtx8HtwX0AGUVHgYhgx6CclBc618W7Fy8MS3lq22eppANi/hETtL
         wzIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u9o+ks4L;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cfrRGVzfhJabIy+C2XEqwiB4Us35SS75VNuxH/wFz4s=;
        b=io6yV5dZG1QgcHRd5mgF2DBmpL09C+JYryNdNJmdozaSFsYKff6NGrUZV2QUKkZ3QD
         F1XtudJJunq+p2dwbadkg1ggyeRsOJFwWdMgvv4gpD84KORmlE4q3FoewQZ9EskxGErx
         Q9/ssDD38XIvh63i4a+Zk+NJZj0VvYfkA2wYJkZ4otPy0EaAsmga4eHcj6i6CUmAZm/y
         h5BAdUZ5Y39Is3N3wNhHES/orc9tCikbrCZm0rpQ10wMD27eDREpa58qELdOOxJ3n0RZ
         GmpVXaJohz4Kanc2TtOKGOSIH1ehoruLLKCNNeg2mwIDCXng5JZZGDEf6jaNuokc9QxD
         +t6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cfrRGVzfhJabIy+C2XEqwiB4Us35SS75VNuxH/wFz4s=;
        b=rjCFv4477IJve8F0wGwTipilW9N2vlI1ceATBoeNr8tfYOqjw6y3M5kAU1fcS++/fL
         Y4rII6KqD7SVmjdwJv4euD4u5LQaG+pCxi54mXiqZRwFUUjEpO3xz7xjqfknkx1/i+4+
         aKNtiZSnsSJuiIkDIJxC/IBlA/Tlm3nDnmQ6SDuSHnBsbp4tAmCtfwiXn5VDmKdl84y1
         gFd/vbYiUZSXLt7UrxF0fP/UJCku6ii6MjpyxTlNZBm5g28AYLjZLwxui42SWFtwMWXf
         9+21+puCcQIlj/wPLcKyLW50UiHO665TVEzMnzCkxSd9xZThZNYs+wb1Sljc+UgRaWke
         YFyQ==
X-Gm-Message-State: AOAM533ERiFfOMzdUWwixnKBsgg8r7RBNoWNiaxnW8MJhvAqa66xYawZ
	O3TgMpxaXzswT9oDMn9xrCk=
X-Google-Smtp-Source: ABdhPJyuP1DZ9HYf6/6nTiWyjv9Bw+vVudD9Zl5xYF5Hz3+cpMXp5EksGulM7Lkeert4DqXEFTCthw==
X-Received: by 2002:a05:6830:2153:: with SMTP id r19mr3700719otd.207.1603311802051;
        Wed, 21 Oct 2020 13:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:310b:: with SMTP id b11ls308720ots.10.gmail; Wed,
 21 Oct 2020 13:23:21 -0700 (PDT)
X-Received: by 2002:a05:6830:2425:: with SMTP id k5mr3879936ots.86.1603311801573;
        Wed, 21 Oct 2020 13:23:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603311801; cv=none;
        d=google.com; s=arc-20160816;
        b=QGafhxnIXWE+Tt97n9wwgfyjbmfS8YkXWsyAjPaUKC27PPZ7pFQeszoEoZ+jydqJQZ
         QqlaBgALqXBdiUxnEwVlodHC49zh5q8bMAWuKdT9Qjh0N/SM7JfKmtX+jqXoG3iwbRxO
         D5bFhR9fCsIFWEhsoXocDR809vuE/up282XpX+aKB0W8Qw1EgXADqJIFxKqzu+dgb3Jk
         kPu2cQQSknMB7nYIuuGlN4Gd/GGPZkYmuhJSjkGlTq4yEpx4Ewmiv02rQiSSQu5dlT/d
         KlAeBBTGLPH/Og8SCyH9PhbjqM+T+dmkc220LHxSeA0oMu6SM+D+s8i99vXboqtKXUnQ
         ftZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V+s7Ur1cmG5XqfTGOC/3u1pEc/MJLj9wk8CuInHNfl0=;
        b=XA2JXs60vQ07e7Y4fy0ngKXsjpFVfEDNUv4kf+cZg+MdFkkJFjDPVcTVM6HjYa89qW
         V7uuUnAh8um+mgkUGrCeWchvpy5gQbMEkghinPFcjt0piW+lZaE4vIQ1QigJ1pwGSYiw
         Pkk6MISrWa3XTnpGD9xDtromg5wFpfIcv2BJ6v4rB07mudMvClLV03gqVcXfqql32rSZ
         V/upvSxoxD7OPP7LCi8OT8uLTULGZeQ5Ni9rvS/A6XKeeeozaJoNsQ05TMsTne33kKqY
         noVBOE/ehfnBevcW/O7qYgP/ag9+CuLPXDznkSuHWkZ4OTPn3AWIWE4EuiBPOvjm+zp4
         6j1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u9o+ks4L;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id a7si229660oie.4.2020.10.21.13.23.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 13:23:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id b26so2173403pff.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 13:23:21 -0700 (PDT)
X-Received: by 2002:a62:1613:0:b029:152:743c:355c with SMTP id
 19-20020a6216130000b0290152743c355cmr5213068pfw.15.1603311800680; Wed, 21 Oct
 2020 13:23:20 -0700 (PDT)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com> <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
In-Reply-To: <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Oct 2020 13:23:08 -0700
Message-ID: <CAKwvOd=y4joNkmpvRNTiyRZuqqk1NrXXhAoSsh3e=PmGMsoC6A@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
	X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=u9o+ks4L;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Wed, Oct 21, 2020 at 12:07 PM Joe Perches <joe@perches.com> wrote:
>
> On Wed, 2020-10-21 at 21:02 +0200, Ard Biesheuvel wrote:
> > On Wed, 21 Oct 2020 at 20:58, Joe Perches <joe@perches.com> wrote:
> > > Like the __section macro, the __alias macro uses
> > > macro # stringification to create quotes around
> > > the section name used in the __attribute__.
> > >
> > > Remove the stringification and add quotes or a
> > > stringification to the uses instead.
> > >
> >
> > Why?
>
> Using quotes in __section caused/causes differences
> between clang and gcc.
>
> https://lkml.org/lkml/2020/9/29/2187
>
> Using common styles for details like this is good.

Luckily, there's no difference/issue here with alias as there exist
with section: https://godbolt.org/z/eWxc7P
So it's just a stylistic cleanup, not a bugfix.
Acked-by: Nick Desaulniers <ndesaulniers@google.com>

$ grep -rn __attribute__ | grep alias

didn't turn up any other cases that look like they don't use strings.
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3Dy4joNkmpvRNTiyRZuqqk1NrXXhAoSsh3e%3DPmGMsoC6A%40mail.gmail.com.
