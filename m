Return-Path: <kasan-dev+bncBCMIZB7QWENRB54PY73QKGQEHA3KD7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5654A204DA0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 11:14:33 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id v63sf969700pfb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:14:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592903672; cv=pass;
        d=google.com; s=arc-20160816;
        b=USm0/+Qq0SgArM9VMcB2XAGVJNYUH0zHDAqH1Dn9UXRj9LfgE+UolzIB5t8+2C07o1
         lXE8fWRGqg0bij091PO+iLkquWUUR7wr8NY2Ig7rVLgGWy7NLWJTTN1Z1PCntT2nMplr
         7knuCS0gaph5u5t1XTUjHn7mv8V4OfHg7LPGk0DBrIMXx0aeXlvlKK9YBW9y9dopeqpP
         yBHmgaY5hcKd+/j94/Nk20OXX5FKvzo/l3nSKsJnjde2JPouF1qaGKkC4afYkGjW4V71
         Ebx44FdkRlPcyuEMpM43MCvW45Xjts2uCLrEel7EVePqCR87hvAMiqy9tyKC/gkKxNen
         lOTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3ran9JfRdYnaMANomVUSUan6C6/LWwxlyfJMOLjgnQc=;
        b=hTHKytJPZ4hPt6D7t/tJoYG2mwowWYn/XWC3lY/kemIh99G4idJyQ6yUaFQnFGXh20
         Ox2+bw9iYZiPzS5d+Kcp7tdlY8pDzRwWM1D8niKRYHkQS3LFOE2M/6wUSyUSo5QHPmcI
         i/hNE6PTULOoNzaBLdTIm8wYkmwTXnItBSdJ0aXmOfrBdIOiRUCHy8AChHIKghqm8l2X
         HXduuBlHn1s5+SMJod0j++n5j6gLFPgpNnAaq6c8U8QxXmm1V09mMP7YVeMzAjUxOYOw
         bqAxtG8Cy0bojVVBpcN3QksdXbUXqZmyWLInhjtpQ+DU4SkdqwLipFnwlTMw7mKl04kl
         r+Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RgLw0dY+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3ran9JfRdYnaMANomVUSUan6C6/LWwxlyfJMOLjgnQc=;
        b=laK2AbyGfUWkGzxw9EcIMRHeujrS9Q5y97r0onPn/de3alMPs93XlxzaFpzLUDHBIP
         DibHJtxdHLp1R4yILdORR1A8PlO071NVb5gyLbnl0aU1WC3IwSHoqiBldzXWpRZ3JCzl
         bswnWTHay2/RfSesaG9TktJ7Wwvms2HkgLHYdOTim8hppBA+selGCM173JxE9MUHgh7b
         HYHKjCJts+qBUhLNPGeFvFTm1gQWqTin7LK/aiNFN8E0L5o7jAr1sWgmOAnZV9OtAEsX
         nkHYkmA+FO47DUqNPEmYf7C7SfeqBh3lvKDbQTt4bV1buRi8HOKaJzDOl3iQTqcaz7xF
         QCpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3ran9JfRdYnaMANomVUSUan6C6/LWwxlyfJMOLjgnQc=;
        b=Q5YXr9YebejFYcDctr3iDdCUycJFfMx6UHMol6s5uJOyny1nU54ICWsZZkb+TXaMN1
         fIjqTxvVaCYeY0CIlvPcIZZZNth+RI6sg1mBjJlmk5Blsd5P4Y4ZndjFg4KS960fjhLF
         Ar6rQUjUh/zJ66zbj2VmO3bOh8VuR21301KXiZyE/DXfdyMsr0Iv0vt02O0+6H8DjbV0
         7+4Jps561CPnDN7fPtj/ZP8TnoCMSQnIAzY+YEVQ0As4IQDx4ac7t9gynYlXpKtKURFs
         HDieSxj4R0Ojp3RaJIzN3qHZ5GEWYP9T66g6uUqDxB3tcDwfLVoM2WmL6fFbCoeJozci
         gAqQ==
X-Gm-Message-State: AOAM532pIrk5UDoQCpDFP1D34R44XpTJykSUhBfS0Bx8ifXjtcqdDkCi
	2I/w+CDgIVtXRRBcLDnClyE=
X-Google-Smtp-Source: ABdhPJxmpe0Ti2em3Rebq2QL1uj7ZsDo+TW6oODF6uDRdLvKyzot5BLOlV0hbI/aAEzCoHHh0sntYw==
X-Received: by 2002:a17:90a:fe10:: with SMTP id ck16mr23444072pjb.147.1592903671980;
        Tue, 23 Jun 2020 02:14:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8306:: with SMTP id h6ls3548334pfe.1.gmail; Tue, 23 Jun
 2020 02:14:31 -0700 (PDT)
X-Received: by 2002:aa7:9384:: with SMTP id t4mr23740117pfe.162.1592903671550;
        Tue, 23 Jun 2020 02:14:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592903671; cv=none;
        d=google.com; s=arc-20160816;
        b=y4d3+pUAKpNxZBfbLHr+XjHwa4FtUcbbqbpBQg1tvDQSnC3A1WRMhEkeUYmbYEec6c
         10Fkpw9dntrpY4rZfIUy7cG7aK/Rr/KspWCDDg889JqpadeBE5F3B/ythXpW1Q/WBziI
         AehXw+okXwtRz1M2HmdXSAzefVgwh05x5E4hFBYYf7UH1ZquF+bAjOsShAAKi+XdSy9k
         3fTJrV+lE1KznYNiRQCS9A6lJ3Lm3E5t+LzA9fgJjuiiqUhsynuFwDrKz+1ncedRFXrR
         lWYB/5coNbjNGaUKCLoMA4UTj9CJ6uiN3/ySK7DvBHGKrXZxBm6oaUTdIcHa+L8Y1q6D
         i3Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vtk9OVdWBIKNADV6/am2r3iuDJGvWTfkOXH+NORoJEE=;
        b=yLObo4s8p7WGvNLZfNjoV3MDTjwmi1M+1IdRKDhyVawe1gFYBTni+LviG1b6Dp9i2W
         iJXLw4WTIUyVmGVXHhLDWm/r9440vJEJcCuv/vAtnAEb1YI51ZphRU3scD0AhcG7xDAw
         1liIgzTLjHhArxHNpqm9vSeUOEpDO3pNqHW9KjrXCyFe/r8bSxhzvi/NIhNRTfNthkpE
         binl014nqLcllwKbkjdnaUpf5oSEtsyE8BYY+xznXOPH7s85O/WiHwPmGJvceYkJ9Hw4
         4LCpIrpzNEaICz59TXn22003j8q8enY555nU/T9R+XNJ6E2evROIDNBmsCdgcQv5teZU
         vxpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RgLw0dY+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id l137si989881pfd.3.2020.06.23.02.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 02:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id u17so14869433qtq.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 02:14:31 -0700 (PDT)
X-Received: by 2002:ac8:41c7:: with SMTP id o7mr110428qtm.257.1592903670569;
 Tue, 23 Jun 2020 02:14:30 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
 <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
 <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com>
 <CACT4Y+ZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg@mail.gmail.com> <CAG_fn=VEb7XYwi0ZnOXRx-Yss++OhnpKCO-7tFvCOp4pi4MLcA@mail.gmail.com>
In-Reply-To: <CAG_fn=VEb7XYwi0ZnOXRx-Yss++OhnpKCO-7tFvCOp4pi4MLcA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 11:14:19 +0200
Message-ID: <CACT4Y+ZHoQ5ZPfsvaiQMXrrTxv9-LgP+v_o5Ah2gFBwqQjv-+g@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Jann Horn <jannh@google.com>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RgLw0dY+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jun 23, 2020 at 10:38 AM Alexander Potapenko <glider@google.com> wr=
ote:
> > > KFENCE also has to ignore both TYPESAFE_BY_RCU and ctors.
> > > For ctors it should be pretty straightforward to fix (and won't
> > > require any changes to SL[AU]B). Not sure if your proposal for RCU
> > > will also work for KFENCE.
> >
> > Does it work for objects freed by call_rcu in normal slabs?
> > If yes, then I would assume it will work for TYPESAFE_BY_RCU after
> > this change, or is there a difference?
>
> If my understanding is correct, TYPESAFE_BY_RCU means that the object
> may be used after it has been freed, that's why we cannot further
> reuse or wipe it before ensuring they aren't used anymore.

Yes, but only within an rcu grace period.
And this proposal will take care of this: from the point of view of
slab, the object is freed after an additional rcu grace period. So
when it reaches slab free, it must not be used anymore.

> Objects allocated from normal slabs cannot be used after they've been
> freed, so I don't see how this change applies to them.
>
> > > Another beneficiary of RCU/ctor normalization would be
> > > init_on_alloc/init_on_free, which also ignore such slabs.
> > >
> > > On Tue, Jun 23, 2020 at 9:18 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> wr=
ote:
> > > > >
> > > > > On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrot=
e:
> > > > > >
> > > > > > Hi!
> > > > > >
> > > > > > Here's a project idea for the kernel-hardening folks:
> > > > > >
> > > > > > The slab allocator interface has two features that are problema=
tic for
> > > > > > security testing and/or hardening:
> > > > > >
> > > > > >  - constructor slabs: These things come with an object construc=
tor
> > > > > > that doesn't run when an object is allocated, but instead when =
the
> > > > > > slab allocator grabs a new page from the page allocator. This i=
s
> > > > > > problematic for use-after-free detection mechanisms such as HWA=
SAN and
> > > > > > Memory Tagging, which can only do their job properly if the add=
ress of
> > > > > > an object is allowed to change every time the object is
> > > > > > freed/reallocated. (You can't change the address of an object w=
ithout
> > > > > > reinitializing the entire object because e.g. an empty list_hea=
d
> > > > > > points to itself.)
> > > > > >
> > > > > >  - RCU slabs: These things basically permit use-after-frees by =
design,
> > > > > > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't w=
ork on
> > > > > > them.
> > > > > >
> > > > > >
> > > > > > It would be nice to have a config flag or so that changes the S=
LUB
> > > > > > allocator's behavior such that these slabs can be instrumented
> > > > > > properly. Something like:
> > > > > >
> > > > > >  - Let calculate_sizes() reserve space for an rcu_head on each =
object
> > > > > > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > > > > > call_rcu() for these slabs, and remove most of the other
> > > > > > special-casing, so that KASAN can instrument these slabs.
> > > > > >  - For all constructor slabs, let slab_post_alloc_hook() call t=
he
> > > > > > ->ctor() function on each allocated object, so that Memory Tagg=
ing and
> > > > > > HWASAN will work on them.
> > > > >
> > > > > Hi Jann,
> > > > >
> > > > > Both things sound good to me. I think we considered doing the cto=
r's
> > > > > change with KASAN, but we did not get anywhere. The only argument
> > > > > against it I remember now was "performance", but it's not that
> > > > > important if this mode is enabled only with KASAN and other debug=
ging
> > > > > tools. Performance is definitely not as important as missing bugs=
. The
> > > > > additional code complexity for ctors change should be minimal.
> > > > > The rcu change would also be useful, but I would assume it will b=
e larger.
> > > > > Please add them to [1], that's KASAN laundry list.
> > > > >
> > > > > +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/=
rcu
> > > > > affect KFENCE? Will we need any special handling for KFENCE?
> > > > > I assume it will also be useful for KMSAN b/c we can re-mark obje=
cts
> > > > > as uninitialized only after they have been reallocated.
> > > >
> > > > Yes, we definitely need to handle TYPESAFE_BY_RCU.
> > > >
> > > > > [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__=
&component=3DSanitizers&list_id=3D1063981&product=3DMemory%20Management
> > > > > [2] https://github.com/google/kasan/commits/kfence
> > >
> > >
> > >
> > > --
> > > Alexander Potapenko
> > > Software Engineer
> > >
> > > Google Germany GmbH
> > > Erika-Mann-Stra=C3=9Fe, 33
> > > 80636 M=C3=BCnchen
> > >
> > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > Registergericht und -nummer: Hamburg, HRB 86891
> > > Sitz der Gesellschaft: Hamburg
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZHoQ5ZPfsvaiQMXrrTxv9-LgP%2Bv_o5Ah2gFBwqQjv-%2Bg%40mail.=
gmail.com.
