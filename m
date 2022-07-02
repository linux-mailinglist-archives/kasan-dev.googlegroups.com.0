Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBIX6QGLAMGQED7IPIMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D47965641D5
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Jul 2022 19:23:47 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id k12-20020a05651c10ac00b0025a73553415sf920306ljn.5
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Jul 2022 10:23:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656782627; cv=pass;
        d=google.com; s=arc-20160816;
        b=VTD6ZTK8+ni3o0Ipd4qADpZltYZu7oCKMUMoTRuoKiPy2bopr925kZY4+mRgdHJHVL
         XWXw5E7f1n+lcB7LegZcsUDFYOKrInENblsZYDUYLYJQVboUyfUTnLSULtpMDUA6+laX
         XzbVJU0V/YprF+KnLhSymVeOLO3RqviV3WxbLnGaXMu2O/SHQe7pW6b71BKd9SGljK7O
         NuKFWG/MHPeF+I4u3iOHYUZIVOVgicsp99nBhNbXGBhO16EW/yW+C4DuUlZ/a/Eu3qp2
         HKg8ahQhSWaZsH+hO5653iUxC06pmTtHCFLsOj5a+VKbDR4JClcJ3RxSg00JcaBKa/6c
         iVww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=o7gjfzpAHsiR3rBTMVwn65JJgtz+Trd2+5AYR/uFguE=;
        b=sPjDhxSB7peUY7XSUouvCZFMEUQf+jYfJDNfWpQlJUj0nfXPgCEQHllrc9zSTIrnNw
         EooS8spcIUX7rDgs2C7xuQDQJA8d2dKml7GZPWZW6Mg5xniFO1OrLDodaSHsbHZhvS+C
         zUZXpfFqCph1WLEdBOrP+NzRUnJIU6jbbGzEr4o+69ykrcPufc6nUfmQubfvHKq8yEaH
         6/GBSuH5nYyD1WGEzHYLgWEiUGF9tZL+P5UoQtqp0SNNZ7oWivbeFAT++rfKhBXAy2ns
         v7l/czItYKjYdvJZ/6h+cIKawoGrlU2OTr7+iJODOuPSowwwD8eoDNwq3CJmz9AxLpUM
         vnsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=AvpeJ2y3;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o7gjfzpAHsiR3rBTMVwn65JJgtz+Trd2+5AYR/uFguE=;
        b=SOlEaiCrSBoXQ+nVZ7KewB1dC9MGd8xL4i2qeRpKebPM3DNkjvUjdd+oJg1l4avNDh
         UXjl78/ETwh09LUGSgtVIRmJ47uNMch2eWeYRkyuSBmZO28TC1hG4+/k9Hp1g2+PgGJl
         Q5dpYwueaeCx8HJqe2Qr/IFm3lE13dBq72Gw64iwY0OLwpwZnuPRzsFV/jTR6tZRtgeW
         i6lpW/rGKUeLoyLfrcuDMxItD+Kjshkt6ezG1UTTKw1gnP0ZWo7FKndM7uV8d9Bce/bU
         9L+BPt9A04xqnwy8wX2Kl76EAx1GJSRn90x9lYksVtpDUm82eMBcbrMSbWSNYKbGAlrC
         hEHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o7gjfzpAHsiR3rBTMVwn65JJgtz+Trd2+5AYR/uFguE=;
        b=XPYpndrxJdNiO8AayXzM95Kc8IsK8gfJ/6BtnOy5G+lcwB5O9XEg/SEhfP1hO9kfj3
         jvyk3DoLLqmj3JyGiZ7aqCoIRfVp+6ig/7x5LRhKeLGMYQ+AXwaFuHdaMvflOu3Cy4cO
         hrNQZiLZ5uVmTiM+uTrbom/U1Zxjt2sQ5Fn4hxL3mHXDdsgYVsLryC9e++aIdTP+Gc1n
         gnO8xjW8lfnWi5FVwQCi1PEIz/4zsSqJTQhxRqWloDq73kxCGGMw0PXTWhSLbqfMzsYM
         uHtSkfD5vIqB254mi8wcOgaKPBvEzYcxKfSwI17Hp5nY1GVE2py6JznUaV8rUPCkLsmh
         Q9uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/aIdE4pUJpIf7xOc8oERWFIXx73uvGKgQdm2tSw0/GkEmZDBjS
	Qe5hMlVi26Uw7UeyZIOtzGQ=
X-Google-Smtp-Source: AGRyM1tmnEi6OoRo8gPrx0xiuHC6u7fDu0dk6bwH3oZ3fACcwCR9/u/A6rjnR5brqFfSqGOYyipJ5Q==
X-Received: by 2002:a05:6512:23a4:b0:47f:79df:2ea9 with SMTP id c36-20020a05651223a400b0047f79df2ea9mr13003869lfv.498.1656782626844;
        Sat, 02 Jul 2022 10:23:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls1658658lfn.2.gmail;
 Sat, 02 Jul 2022 10:23:45 -0700 (PDT)
X-Received: by 2002:ac2:48b5:0:b0:482:a0bb:7602 with SMTP id u21-20020ac248b5000000b00482a0bb7602mr2723556lfg.61.1656782625447;
        Sat, 02 Jul 2022 10:23:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656782625; cv=none;
        d=google.com; s=arc-20160816;
        b=JA1B/vXwQZXLTcEY6elRLawi422cHfjmY7rUPJs7hhAyDgYglWbVhlr2WaodG/aryc
         s6Cr5/ayp1QhOyawP4htOsSkA1hGHVbdRFDbkklpCUuixFOwjWCrqE3DCBmkZFEggRsP
         uV0MGmNf9HWf6bnmi6gRIX3suSJe/R7bLeBUD01RNrS/FbrG7Pk+053RHvN3NYvTkWGV
         5Qs/YF3NsYFsZni9bKAN+kA7e77MRxY34hIebD14HNMmdCnsa6NLegU7QtKBWW52oL0E
         ErfbD6abVkQuNgsR0kT3mb0wzbj5APWVPigLzGuLpDzMyNsTvwoda4E94tW/gK7o0Iv9
         luKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=il+ZyDBxn0EXlULxf75c3oKM6Oz9Nzs2kT9ulcG3ntg=;
        b=IMFYfzLzwLEM7gceXMyl4T9xVF54nlTfoD1cj63tEqm4SpHyCOQ2bgamf1gPAZqrsD
         YLNE7jtM40QcvBl3GyJh/X340m7q/OzwjAMOI2PAnhoaEHLj8dRRKrqdY4EcNGaBp31x
         hFGzdEg0+bhUtQAzR3g8Lhb4lPKQk/rHJFRYp3eVsHodyB0BmbH6HZdRzEP+WoWMGEQV
         gpfdMhRQ3t0qFFhag+agoQjwHO4yzsI5mHf67sXDrqwUMGBGgvZ3vqymnLhouV5HVUxX
         L/n1DzkGrvFI8bKf07YC2o3ct44sIbOAJNxRj5IMb1X9tzVn17SMZR9JDxYezpDJyKxQ
         GI8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=AvpeJ2y3;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id bj25-20020a2eaa99000000b0024da01a8c6dsi893791ljb.1.2022.07.02.10.23.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Jul 2022 10:23:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id j21so8897525lfe.1
        for <kasan-dev@googlegroups.com>; Sat, 02 Jul 2022 10:23:45 -0700 (PDT)
X-Received: by 2002:ac2:4a70:0:b0:47f:a18e:ae6c with SMTP id q16-20020ac24a70000000b0047fa18eae6cmr12325468lfp.344.1656782624497;
        Sat, 02 Jul 2022 10:23:44 -0700 (PDT)
Received: from mail-lf1-f50.google.com (mail-lf1-f50.google.com. [209.85.167.50])
        by smtp.gmail.com with ESMTPSA id s4-20020a056512214400b0048109845ab8sm804546lfr.50.2022.07.02.10.23.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Jul 2022 10:23:44 -0700 (PDT)
Received: by mail-lf1-f50.google.com with SMTP id z13so8779004lfj.13
        for <kasan-dev@googlegroups.com>; Sat, 02 Jul 2022 10:23:43 -0700 (PDT)
X-Received: by 2002:a5d:64e7:0:b0:21b:ad72:5401 with SMTP id
 g7-20020a5d64e7000000b0021bad725401mr18424110wri.442.1656782613069; Sat, 02
 Jul 2022 10:23:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
In-Reply-To: <20220701142310.2188015-44-glider@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Sat, 2 Jul 2022 10:23:16 -0700
X-Gmail-Original-Message-ID: <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
Message-ID: <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=AvpeJ2y3;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Fri, Jul 1, 2022 at 7:25 AM Alexander Potapenko <glider@google.com> wrote:
>
> Under certain circumstances initialization of `unsigned seq` and
> `struct inode *inode` passed into step_into() may be skipped.
> In particular, if the call to lookup_fast() in walk_component()
> returns NULL, and lookup_slow() returns a valid dentry, then the
> `seq` and `inode` will remain uninitialized until the call to
> step_into() (see [1] for more info).

So while I think this needs to be fixed, I think I'd really prefer to
make the initialization and/or usage rules stricter or at least
clearer.

For example, looking around, I think "handle_dotdot()" has the exact
same kind of issue, where follow_dotdot[_rcu|() doesn't initialize
seq/inode for certain cases, and it's *really* hard to see exactly
what the rules are.

It turns out that the rules are that seq/inode only get initialized if
these routines return a non-NULL and non-error result.

Now, that is true for all of these cases - both follow_dotdot*() and
lookup_fast(). Possibly others.

But the reason follow_dotdot*() doesn't cause the same issue is that
the caller actually does the checks that avoid it, and doesn't pass
down the uninitialized cases.

Now, the other part of the rule is that they only get _used_ for
LOOKUP_RCU cases, where they are used to validate the lookup after
we've finalized things.

Of course, sometimes the "only get used for LOOKUP_RCU" is very very
unclear, because even without being an RCU lookup, step_into() will
save it into nd->inode/seq. So the values were "used", and
initializing them makes them valid, but then *that* copy must not then
be used unless RCU was set.

Also, sometimes the LOOKUP_RCU check is in the caller, and has
actually been cleared, so by the time the actual use comes around, you
just have to trust that it was a RCU lookup (ie
legitimize_links/root()).

So it all seems to work, and this patch then gets rid of one
particular odd case, but I think this patch basically hides the
compiler warning without really clarifying the code or the rules.

Anyway, what I'm building up to here is that I think we should
*document* this a bit more. and then make those initializations then
be about that documentation. I also get the feeling that
"nd->inode/nd->seq" should also be initialized.

Right now we have those quite subtle rules about "set vs use", and
while a lot of the uses are conditional on LOOKUP_RCU, that makes the
code correct, but doesn't solve the "pass uninitialized values as
arguments" case.

I also think it's very unclear when nd->inode/nd->seq are initialized,
and the compiler warning only caught the case where they were *set*
(but by arguments that weren't initialized), but didn't necessarily
catch the case where they weren't set at all in the first place and
then passed around.

End result:

 - I think I'd like path_init() (or set_nameidata) to actually
initialize nd->inode and nd->seq unconditionally too.

   Right now, they get initialized only for that LOOKUP_RCU case.
Pretty much exactly the same issue as the one this patch tries to
solve, except the compiler didn't notice because it's all indirect
through those structure fields and it just didn't track far enough.

 - I suspect it would be good to initialize them to actual invalid
values (rather than NULL/0 - particularly the sequence number)

 - I look at that follow_dotdot*() caller case, and think "that looks
very similar to the lookup_fast() case, but then we have *very*
different initialization rules".

Al - can you please take a quick look?

                    Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwgbpot7nt966qvnSR25iea3ueO90RwC2DwHH%3D7ZyeZzvQ%40mail.gmail.com.
