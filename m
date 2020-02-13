Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBCMNSTZAKGQEHKT4VAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 91E3915BAAC
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 09:19:21 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id y24sf1812439ljc.19
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 00:19:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581581961; cv=pass;
        d=google.com; s=arc-20160816;
        b=hHKiWYw5RGP3dCnercEa0tvG82IwSHK+0htcXd4creulnDMfum0kzsffCD1+mZXEdW
         2fcVconN2Trzww7vuuS/R2xHvo+c83tOq6k77cLImPEkLTtEz9FUJiWIFifm8lfk7tAU
         ETKYAu230RzAWiA85R4BCL7HAWYEmsbE5DnzyVBJV0bE2BzekcZ7HJ2DN9SvJkIvAyEC
         MjB0jwhFqifcvwNlqvvIuNxiK0NYTCaiKcsK29N08r3KD3mqdgfaH9uhXj8IzSiMze0F
         sxkW5MlBMW8kMvwYZZweJgbbb09N3ctTM8ezUMT3/6krsNs7E479erzBIKKi5rSBDYP9
         1D3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=IWAmtFpedMimA8OtWTBqyATzkICg/fAFKDYiJ5gPyRI=;
        b=oLZzCWRlJ+h14FebbDwWm4gDmb2/MssVYHOeIetu8BJTpTXzFYL0v2O8gRy5YVRSMt
         AaTJ3K6ny6KfDljNgeWqKVc9ZwgJ+e0/C09rpnXrz0CuV5rw1yGjdUkI+aOsKG6NZwp+
         qpLU5QjiZFKeBIRcSHBXwoz71yU67caxAvq3U/E8W4IL8bhGhF4QLDXfDxzZSmVGCS5n
         eSdnofjrhfgcHBgDMwKw6/zJ8eGgK7wDbQNGS+6jjQGpiv7tceSCZqGfeC2Gsy8Cookq
         LgzydYW/kXC18K9EsNApLYGMdFJI66gkcWMlHP6B8LMgKpENQnX04el7l/3O3zCSMWq8
         xtgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IWAmtFpedMimA8OtWTBqyATzkICg/fAFKDYiJ5gPyRI=;
        b=P6ijdkF+wQprHhk154/JD4y5CYxWNmsqKeHcpMhJ7xsSEm9EY/ujJE/nqMFUkMneN5
         yQ6sshas4ivnb4XXrjx+IdCCH0qJvyoJYcLcuXgNhvBkAv0a0+yfHyeJBWhoDMrH/eQ0
         XkshvvSe283S09wkaQVQMoSqwEiGFgO6EeozTtLpLQYiqAlsOzZcl5Bb13XUfq6AOXu7
         q3Px2+XfFNFky9/6E0O3QgOAZtV2oKn4HuO9LVl8FdFwb2hKf8odvU/ah+vpiNk3YSa6
         B3T6jZuH78Up4kp2eKuMcVRq9snzfT5d/joBinwEKdl+XikcmC+KTSrTCPkH2XFxcyap
         Qgcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IWAmtFpedMimA8OtWTBqyATzkICg/fAFKDYiJ5gPyRI=;
        b=MoVdncL5I8EoDjsMBNJ3aarLhk9fFevDI2KePWQvenwVyYborqenKMfjJ8qxSUOCzk
         S1YoOefCjcRJ1Rj0g/BYV30U/4FcqS5HXHTr90GCJsw5YMzkz/eVUbfCm/+kdzPCuNKZ
         LevSCBCVO/FXs2+HYLpU4qdsGcPUqM8u1LViy1gIhr88HSi6Mi96ytqIq7m3DOvpCrgm
         f8GlgsFWeJHHfL1RZiplxMaOM2RvmW8Q2tDHEFUeeo8Oml3O+Ti6AI7H1rpSBbzJMLWk
         AbGA0uiF/QBq2H0kjQLbeKaYbh4K4T/2FMMJHey79ExCo7Fpb6jYVDOF4ANSxzSXIkQp
         fv5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWw82nmTbB84/r8m4sdTC0Acfk53lEk1NTQsvqf2XmG1jhMGHNP
	vJLp8Vgr9MQg84QLKJQ6YaI=
X-Google-Smtp-Source: APXvYqxH5yDfUVEKwwctzhkuVaVnbL56AESRgNY9xdisrNIPCjOJ4yJQX592JhwmTssejUNW3fgVtQ==
X-Received: by 2002:ac2:5467:: with SMTP id e7mr8429929lfn.74.1581581961130;
        Thu, 13 Feb 2020 00:19:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b2:: with SMTP id v18ls2569482lfp.8.gmail; Thu, 13
 Feb 2020 00:19:20 -0800 (PST)
X-Received: by 2002:ac2:5509:: with SMTP id j9mr8678277lfk.135.1581581960546;
        Thu, 13 Feb 2020 00:19:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581581960; cv=none;
        d=google.com; s=arc-20160816;
        b=cCclHz2caxSoIWp+6IZFEHddQowR3tKoBeuecamDpVLVQvqseoikBpoikDBKVVfcdW
         8ceOyoe0HCW0HBZ6nMOFoX9FZG/b+u/luL2wnR5NUt+KWb15YWdmSPaPUURcQGEhT5BI
         /xeEuBUJRbDErjekajBUkFzvjkmLUeUWUQRXEw8F+tqS8ZCeS1VPzPSvbitBfhTAqlj+
         3o1bAFqYGuRDhNyqr5BJV8z3J0ueWzSo6zYPjQ9wPe1yMQsdC2LmdHCyILeqMrjdqodp
         xqSRlkVyRnIId2OcguGqiXNsY4OVibNSyoTX674YJlDT4IE3wMeMmYTc6W7yXYm63lS2
         qrIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=XYlYFpq/uEAtFeQWSEqRoXkTiLjY20HZwxOhR/Qz9Bg=;
        b=NoWAVV5mi3gj3Meo52k87emugrlBtetnjug/4gJCQVPsahMTjxl00ghVy85WpKxYMV
         XJjkJl7A8TNm01a1Qfb+yvVY2ZuPn/HFPtTKQEz+s9OSQDXhKOvUBwq8je8Gh8eByFaH
         lFXQJQtarTY9mbO7bnAxpxh/ikYA1ZxAOO/0vUPNaANAiBFItIJOU9f2FbuFkwp0eYW0
         q/9kYtoisK/324BiTz2Hu++MnzfSPFCg+fXzwKu5Me1cJJyaK980zhp26tzfxYoODzza
         fYWCrJLyUph9bHHZq6zp1XCsG6d+xZxi+j5Y50MAP11lEDpMQEvFGMxeFzxPaiUVIReD
         YMog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id a11si83288lff.0.2020.02.13.00.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2020 00:19:20 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1j29iF-0089Y1-N7; Thu, 13 Feb 2020 09:19:08 +0100
Message-ID: <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
  Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>,
 Brendan Higgins <brendanhiggins@google.com>,  kasan-dev
 <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
 linux-um@lists.infradead.org
Date: Thu, 13 Feb 2020 09:19:06 +0100
In-Reply-To: <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com> (sfid-20200213_013812_463819_2E8172A0)
References: <20200210225806.249297-1-trishalfonso@google.com>
	 <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
	 <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com>
	 (sfid-20200213_013812_463819_2E8172A0)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Wed, 2020-02-12 at 16:37 -0800, Patricia Alfonso wrote:
> 
> > That also means if I have say 512MB memory allocated for UML, KASAN will
> > use an *additional* 64, unlike on a "real" system, where KASAN will take
> > about 1/8th of the available physical memory, right?
> > 
> Currently, the amount of shadow memory allocated is a constant based
> on the amount of user space address space in x86_64 since this is the
> host architecture I have focused on.

Right, but again like below - that's just mapped, not actually used. But
as far as I can tell, once you actually start running and potentially
use all of your mem=1024 (MB), you'll actually also use another 128MB on
the KASAN shadow, right?

Unlike, say, a real x86_64 machine where if you just have 1024 MB
physical memory, the KASAN shadow will have to fit into that as well.

> > > +# With these files removed from instrumentation, those reports are
> > > +# eliminated, but KASAN still repeatedly reports a bug on syscall_stub_data:
> > > +# ==================================================================
> > > +# BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x299/0x2bf
> > > +# Read of size 128 at addr 0000000071457c50 by task swapper/1
> > 
> > So that's actually something to fix still? Just trying to understand,
> > I'll test it later.
> > 
> Yes, I have not found a fix for these issues yet and even with these
> few files excluded from instrumentation, the syscall_stub_data error
> occurs(unless CONFIG_STACK is disabled, but CONFIG_STACK is enabled by
> default when using gcc to compile). It is unclear whether this is a
> bug that KASAN has found in UML or it is a mismatch of KASAN error
> detection on UML.

Right, ok, thanks for the explanation. I guess then stack
instrumentation should be disabled for this patch initially.

> > Heh, you *actually* based it on my patch, in git terms, not just in code
> > terms. I think you should just pick up the few lines that you need from
> > that patch and squash them into this one, I just posted that to
> > demonstrate more clearly what I meant :-)
> > 
> I did base this on your patch. I figured it was more likely to get
> merged before this patch anyway. To clarify, do you want me to include
> your constructors patch with this one as a patchset?

Well I had two patches:
 (1) the module constructors one - I guess we need to test it, but you
     can include it here if you like. I'm kinda swamped with other
     things right now, no promises I can actually test it soon, though I
     really do want to because that's the case I need :)
 (2) the [DEMO] patch - you should just take the few lines you need from
     that (in the linker script) and stick it into this patch. Don't
     even credit me for that, I only wrote it as a patch instead of a
     normal text email reply because I couldn't figure out how to word
     things in an understandable way...

Then we end up with 2 patches again, the (1) and your KASAN one. There's
no point in keeping the [DEMO] separate, and 

> > > +     if (mmap(start,
> > > +              len,
> > > +              PROT_READ|PROT_WRITE,
> > > +              MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> > > +              -1,
> > > +              0) == MAP_FAILED)
> > > +             os_info("Couldn't allocate shadow memory %s", strerror(errno));
> > 
> > If that fails, can we even continue?
> > 
> Probably not, but with this executing before main(), what is the best
> way to have an error occur? Or maybe there's a way we can just
> continue without KASAN enabled and print to the console that KASAN
> failed to initialize?

You can always "exit(17)" or something.

I'm not sure you can continue without KASAN?

Arguably it's better to fail loudly anyway if something as simple as the
mmap() here fails - after all, that probably means the KASAN offset in
Kconfig needs to be adjusted?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e8a45358b273f0d62c42f83d99c1b50a1608929d.camel%40sipsolutions.net.
