Return-Path: <kasan-dev+bncBD7LZ45K3ECBBMEQ2XXAKGQEYUV4T3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F382A103CEC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 15:05:36 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id f20sf3403009lfh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 06:05:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574258736; cv=pass;
        d=google.com; s=arc-20160816;
        b=eElMsvItICDAyFgMeCAgnINkuEm0f6XazPtuj8o6Rw2AAEGW15GzJROi2H7M45gShF
         iXuunfPZx2PWdULxE3JkX5vdXh7fQClYG3GmHAakYdeWB5Vey1dVv+sd5v4vfYv3j9cN
         FMJyak2khEtuzrP8oHI7c3sCFusCpHgl+ItTVtWd/+DlO6sJPb7KqqSYFKk22B+ydj4C
         rVNB55Qp4FOkdvKWNlNG8MpZay8owzJV3dCWmNBPhC10tp6lqDTSZnxTVsEXapay3uJU
         BBJluA6MlMXq3cjQvC3RmhyrFX/es0fqc8VBikEANtjvUciZ6UipCUNSHLVlcanV205t
         1Y0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qXklArKCqYSKp/ysGEj73u4H+Qht/cpoBluCAMoA2u8=;
        b=M5uoLXHQaF2TcewknOCUVzYSlVf8M/mbUx1BetbIZ7AdIc623bRXgc1icfeXLj+KZi
         tKj1f11mMavMe171dOC/ah86+Yn2q+TxTb3UkIjaVGqm4kvlWOhuTksLTH/QSS6bL6H/
         MHWEH3VF156Jm0Yy+aGLQ1TTiZmPlz2cxpbLiEiG8r3EQYgCZS0uHX9mxcr3Xtlmx5Qr
         JbtMgZTBkSDe4Zy3Hh1cyTs3z5vQUZzY40nmFIEXKsQJZDdzwVoDmNBBlbba6d6gDLZI
         yjdXVeQ2yBprctqG5HSD95ESGNWDSF/70wmls57MdlccsDG27UShguRPaYr41luVXmUr
         3h+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="kR6ot/Wz";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qXklArKCqYSKp/ysGEj73u4H+Qht/cpoBluCAMoA2u8=;
        b=b/lMKZogY6Dgz7Xyp1zrjre+8iMG5YesSJ4FI3t5cBXCuY40PWEbMsAZOD8pZR6Zsf
         anRZauEp6UJiEjk2mnM1k4/slGTQJnH+rL5WdjnRRsiapBXWW7tiFQEKrMUrRE1rzOC8
         RGDhPEgjdBEaaa/fsv9nxHvmBiskNHcs/MZVOXpmRa0HHbr1O05HNlsb4OP7bq1svPxv
         +R/q4Vy5+ZkHLjRjPtuzGhGGKOSIo6UrCUHeSlcBXKEwYQ505OXv2ZyaAXZEYWYirdUR
         6O2Fe1Yk6xyZ4eHKz/KRjyRuPPIHBt2Xk9rxQ+oFxNkWR/SFnkYnWxNOOcGKyUaKBX4a
         hxnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qXklArKCqYSKp/ysGEj73u4H+Qht/cpoBluCAMoA2u8=;
        b=HjVkNGEjUQ3HxA6tWz8Y0Jvwak3Xlk8bEJ6GVYN5Rk/sH1IdvXuhO+GhUgJYjo8Ixr
         q/1QF0cMeCaTkSiZwZ6mfZwjCzJ/9CNTv20tkl9CcAvakJSs/w3jEbesLIbfD4oefWp3
         akhQBBMywkwqN6ERuaBY9wT/Ljgo+M+21XB/1MRT0yFJGN7VPdLselLFvOg+Wf+lacYJ
         2+4RlG9YCFmat5vLA6n3TbUH3geqqwbP5XPVYfhmgOOgXd1DZ0+CQqqagYGaqvdRAsXl
         L2/BnH48hb2CjtkXAjOD1hNqAKj6ljIvln/V6zmdMPlUM0bG04B8IGTJRzZImqzilEe0
         pWyg==
X-Gm-Message-State: APjAAAVJeFdvXYQ2wS862GN+z1QTdJnplR8eRm4NLQsZ5Jcr5cSKpDUO
	itpGd44V6trmKWCR78953Rg=
X-Google-Smtp-Source: APXvYqy36ECm1gmU1glOIZw/hqLaM8z60grN7qmmy7fzHTT4PbT0whoFUuHheiI6qawInyTK+1S+iQ==
X-Received: by 2002:a19:751a:: with SMTP id y26mr3139757lfe.78.1574258736596;
        Wed, 20 Nov 2019 06:05:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4465:: with SMTP id y5ls235678lfl.16.gmail; Wed, 20 Nov
 2019 06:05:35 -0800 (PST)
X-Received: by 2002:ac2:5967:: with SMTP id h7mr2917038lfp.119.1574258735705;
        Wed, 20 Nov 2019 06:05:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574258735; cv=none;
        d=google.com; s=arc-20160816;
        b=iY9libeKL5HN0YHHwVUvOaCyaZDMVl1/0nIhsquur4QfC+xaVjJBe/eXO3dbPIlXuG
         s+xb/iaDupSh9rbGJJQQ9tspSeytAbXxFLzAULmEcLE1IDl4SzJZNrIac+Os+6jTDajN
         KeROrCFILpxbWNYE18054g3XZrQtZlWeXmNb4DzCpi3aYr1x4z4mFPVfHpHxNiuRyB7x
         0k8RNJKvVzgQVuNvKWvFxAlalTBJ4xK1zCdm1k/k6QKWULJdznKxLfZt/7fXFkIMe2/z
         4Wd+/gCiDERjgC6aJ9GdAYjYSpu4k5B7/FwB5rh4eD9HRQ2ybwymap8aWjhllqwo0HW4
         AdwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=atKc4wFg2avE5ihR53QhLHb9twQIjMQuT8kQFJO4FJc=;
        b=Tttit+xngyXaatIuoVPk+Cuyyi/fEqKuyYpCIDZvtQ4dbflry0+33rsYMiiwoUFO6O
         ouVx0WuIYYcO3GGzVIiQo7sbkKvc8zTrq6aotFeqMErLijs1/exhLPbJT4RzZt93BQyl
         rydjUvpm98vA7q0J3DhVyqc6b/vu1kwiomQRWAWqUTzEScZMd+toTBQP8ys59jEUCtN5
         QZ2CY5m+3+ogAUpehvmV6zTLYxkg5HgUqBjnd43rvQDz2QLn/8IuhF7+lvmjBDhewsF5
         R3Oq8zJ+olTAB/qycxvjNIuFGGz/oL+tllS4DS7Vzec64HwU76jROC3DptAiiZa76KQ4
         S7JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="kR6ot/Wz";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id h21si1597603lja.5.2019.11.20.06.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 06:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id z3so1399055wru.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 06:05:35 -0800 (PST)
X-Received: by 2002:a5d:4645:: with SMTP id j5mr3708406wrs.329.1574258735195;
        Wed, 20 Nov 2019 06:05:35 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id g4sm30102476wru.75.2019.11.20.06.05.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 06:05:34 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 15:05:32 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Jann Horn <jannh@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120140532.GA12695@gmail.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <20191120112408.GC2634@zn.tnic>
 <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
 <20191120131627.GA54414@gmail.com>
 <CAG48ez0KscmTLf2_-tYPuoAxRjJtzUO8kmAPQ_SZTP1zvqvTtA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez0KscmTLf2_-tYPuoAxRjJtzUO8kmAPQ_SZTP1zvqvTtA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="kR6ot/Wz";       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Jann Horn <jannh@google.com> wrote:

> On Wed, Nov 20, 2019 at 2:16 PM Ingo Molnar <mingo@kernel.org> wrote:
> > * Jann Horn <jannh@google.com> wrote:
> >
> > > On Wed, Nov 20, 2019 at 12:24 PM Borislav Petkov <bp@alien8.de> wrote:
> > > > On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> > > > > How was this maximum string length of '90' derived? In what way will
> > > > > that have to change if someone changes the message?
> > > >
> > > > That was me counting the string length in a dirty patch in a previous
> > > > thread. We probably should say why we decided for a certain length and
> > > > maybe have a define for it.
> > >
> > > Do you think something like this would be better?
> > >
> > > char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
> >
> > I'd much prefer this for, because it's a big honking warning for people
> > to not just assume things but double check the limits.
> 
> Sorry, I can't parse the start of this sentence. I _think_ you're
> saying you want me to make the change to "char desc[sizeof(GPFSTR) +
> 50 + 2*sizeof(unsigned long) + 1]"?

Yeah, correct. There was an extra 'for' in my first sentence:

> > I'd much prefer this, because it's a big honking warning for people
> > to not just assume things but double check the limits.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120140532.GA12695%40gmail.com.
