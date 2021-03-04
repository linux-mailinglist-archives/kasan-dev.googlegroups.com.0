Return-Path: <kasan-dev+bncBDYJPJO25UGBB4F5QSBAMGQEVNRS5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A6F3032D908
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 18:54:56 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id w16sf3976532edc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 09:54:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614880496; cv=pass;
        d=google.com; s=arc-20160816;
        b=QxZ/udQmy/ndDbnEhabgX5BScBiDr5GIDl9dp4ZTi59Om9CX/XdGsyfwaDfPd/KVSu
         wc8grYgpymRM7NyXx9w7Jb+Q6Va7n4ST3nCje7vnFsZwylhVXSNt15yemepYbuWqJ3Eb
         dqi1erUc78GxyrvIPEe+3vlZaOkzqE57uWRzzQGtWMP3ZsrdBEZ+weuy22rw7w6q+5xK
         i0F/oketaX7iYw1JROjeU5w6up58J3AjUFjipUggFMVfQQOPPzm88/tr1LtJuKX0Dmeu
         ikLrNU8Pv4lKhZEaqPqQ4Egs+noZAShpzOMHvQLnyynH6UGHXp46WdpIL5r7gShGQ8Hx
         JXLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z0CdHF/BYk65YVrNfvHMKbxUl9jAOdSiZn+dPIyC/ts=;
        b=e2S2PNXU8kaec6kdIZCfZpWJxHs/g+RWfMC0XkA4pG66vYd3Nm3BQD+BdMqwo3zn9/
         oGg76aTTIjlX4JG+2VmpgdaO6OFLB4DEf7n2yZDNvsGgdWsPZqFQrHSaZcjzGsAL/1Gy
         wEVAEt6NLdlprIYi49uaG05v3MaFMHmnNdQ+dgdxNuIVk3l15ORZDp9Z1PfcyjfOikYz
         A7m8XWzE3r76ufVyXJCe7fSiuV5RPyOMNlR6Duv/6DU09TcuS1ywlfCllhakz79/gfpA
         0h4F+jsopiykijf9LLRewxkvfncQ6Q/sNZL9EajFYvc0yte9tG4Jbnh/O9GcUsTT1ESX
         XH1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U51rv4zp;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0CdHF/BYk65YVrNfvHMKbxUl9jAOdSiZn+dPIyC/ts=;
        b=AF6OFeILNBsdmax1iTsP6SaZHhQn1S3BzO+Wodqx3LLYpQo6A/1l94sSjCuMsAcK5D
         gsNgo8J26UNyfmNi8xGmhDai8DqCzBAolYAA89GTVSt8d94LofSTO8H+8yUAbHZZHv8e
         9u7mmc9jU9KfBMS+rorXufBPPcVPp2Br6vAIG8a01/3SYBLaFMMmTKXtSOKTUSVbD7vl
         0bL2kLRyNK14DZugs5ZTwPT/79d7RvAf5heBrsNl6OG+1aW4MNoLAnxl61RB8+C+yjBX
         1LSCjN+vSzaJhpU6rO8BA5K/98BqMyTSUjxfo6D8mXAiJ6krQgFBjt3WruzSAVzqS9qb
         q46g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0CdHF/BYk65YVrNfvHMKbxUl9jAOdSiZn+dPIyC/ts=;
        b=GaM9/kkweOUSEnNsdY00jt3tpbVt+CLeZRfjlsoN1pEVVeEEo+gYZXDgrjyL04U2qv
         DaLkWPhEL1b+b7loGun0nh6nuk85hLh268Z4bcGSkR22RYj8DgYaerrCsL72NXGSRt8w
         RMNv1WA6b8HDvJB9ey74WWOe4jYYAaBHoXN8LrnN5I+BPKMoMYm7yIHqkdcwMkJvnnNM
         RgfBWpq7Z2R9bWPSGTrsazrH3LCUdyc5zmRqLSbJgLahX+LVhpKRLBvD3z6DZj6b2R+N
         b7jnIHJtVbbVCs9IuvO018VjLkSO8xrZDVm/3YbLJ/pCvQvmBn8Q0oDa7+uhX/ZDyEzA
         cTlg==
X-Gm-Message-State: AOAM531Y5JXv5UPNbCX4l+kGQb5snsOqEFkbhMztlJXAeK7uEcQ1mxOf
	/I1Mbo7FrFrdN6eo8TN98U4=
X-Google-Smtp-Source: ABdhPJwMlkGJkykJIFCyYCWWNaH57NShPsYxK1eYXWYJWuXw/wpn98O6aKe14PAKMOzhfk1z+oQ/BQ==
X-Received: by 2002:a17:907:216b:: with SMTP id rl11mr5554734ejb.147.1614880496464;
        Thu, 04 Mar 2021 09:54:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls1360774edx.0.gmail; Thu,
 04 Mar 2021 09:54:55 -0800 (PST)
X-Received: by 2002:aa7:db4f:: with SMTP id n15mr5743345edt.12.1614880495658;
        Thu, 04 Mar 2021 09:54:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614880495; cv=none;
        d=google.com; s=arc-20160816;
        b=xCL739yWxX2szdfmXRw4WwRQPmfQVQsad2xmLFTAQ0EiHKbHaaNQEK+Nez1FpaERuH
         LoqSf9p9v+poBcAz1uz8TRWUZXikZtGptn5noae88z03W4N3LuUFDFUzOwbo9jo0Oofd
         0zIoi+oUOxjIoAod2wX2k8ChKXJS640iOzeU6rb6C1kUKjEc8Nz5hPKg8s6aMwU2abMM
         NAgmLF82uwVFm1hJ1b/yh1/0trljfM+eXJyjFD0JYFg0L1onHrORcfCnf6ZBkPIxB/E+
         dw5O9Zyt5XUOw4zFfYIZ1twiJXJKYKiU5Rt5t+hv0+cg3bOtjGquhToTSupezsnWtQgy
         gr5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FYzGpTewhxHxL7CpcepbC9L9ykWvrUtL+K0xz4SbvmU=;
        b=WEbUqW4fIeulLX+sF7/4V47Q7aCc3qzD3zUhd34P1VGAzD9P5d7bcc5z+XXNgBhIOs
         /GvYaOITGR8ynsqnJcxJ7oSFoufpp9mpYzQZxsaZZ10nm5bGQDe/XzBcWXLs4rLcJYt6
         UFXEEMhS1L3hfrhkCGpo9hYq8wVFsE3YtWGCc9njIU0uKYpUQi2Q36ePUURDsoDh5RnW
         sf56Bk8kvQ2GPMyXCkczVDqP44mQ47u23dcE058o/Xy6BHTKtSw/lLj2aYWqIXUAsG7P
         7yoA2sxMtmEYloOQt8alDhYfwNJQcgMHLh/soM0rWWOCJXjqqem5ehqGFJ6mJPyPHqiW
         0KGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U51rv4zp;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id jz19si10915ejb.0.2021.03.04.09.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 09:54:55 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id u4so44698139lfs.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 09:54:55 -0800 (PST)
X-Received: by 2002:ac2:532c:: with SMTP id f12mr3178752lfh.73.1614880495105;
 Thu, 04 Mar 2021 09:54:55 -0800 (PST)
MIME-Version: 1.0
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local> <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local> <YEEYDSJeLPvqRAHZ@elver.google.com>
In-Reply-To: <YEEYDSJeLPvqRAHZ@elver.google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 09:54:44 -0800
Message-ID: <CAKwvOd=wBArMwvtDC8zV-QjQa5UuwWoxksQ8j+hUCZzbEAn+Fw@mail.gmail.com>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Mark Brown <broonie@kernel.org>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U51rv4zp;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133
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

On Thu, Mar 4, 2021 at 9:42 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> > On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > [adding Mark Brown]
> > > >
> > > > The bigger problem here is that skipping is dodgy to begin with, and
> > > > this is still liable to break in some cases. One big concern is that
> > > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > > or outline functions, causing the skipp value to be too large or too
> > > > small. That's liable to happen to callers, and in theory (though
> > > > unlikely in practice), portions of arch_stack_walk() or
> > > > stack_trace_save() could get outlined too.
> > > >
> > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > can guarantee a specific function acts boundary for unwinding (and
> > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > need some invasive rework.
> > >
> > > Will LTO and friends respect 'noinline'?
> >
> > I hope so (and suspect we'd have more problems otherwise), but I don't
> > know whether they actually so.
> >
> > I suspect even with 'noinline' the compiler is permitted to outline
> > portions of a function if it wanted to (and IIUC it could still make
> > specialized copies in the absence of 'noclone').
> >
> > > One thing I also noticed is that tail calls would also cause the stack
> > > trace to appear somewhat incomplete (for some of my tests I've
> > > disabled tail call optimizations).
> >
> > I assume you mean for a chain A->B->C where B tail-calls C, you get a
> > trace A->C? ... or is A going missing too?
>
> Correct, it's just the A->C outcome.
>
> > > Is there a way to also mark a function non-tail-callable?
> >
> > I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> > on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> > function-local optimization options), but I don't expect there's any way
> > to mark a callee as not being tail-callable.
>
> I don't think this is reliable. It'd be
> __attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
> work if applied to the function we do not want to tail-call-optimize,
> but would have to be applied to the function that does the tail-calling.
> So it's a bit backwards, even if it worked.
>
> > Accoding to the GCC documentation, GCC won't TCO noreturn functions, but
> > obviously that's not something we can use generally.
> >
> > https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes

include/linux/compiler.h:246:
prevent_tail_call_optimization

commit a9a3ed1eff36 ("x86: Fix early boot crash on gcc-10, third try")

>
> Perhaps we can ask the toolchain folks to help add such an attribute. Or
> maybe the feature already exists somewhere, but hidden.
>
> +Cc linux-toolchains@vger.kernel.org
>
> > > But I'm also not sure if with all that we'd be guaranteed the code we
> > > want, even though in practice it might.
> >
> > True! I'd just like to be on the least dodgy ground we can be.
>
> It's been dodgy for a while, and I'd welcome any low-cost fixes to make
> it less dodgy in the short-term at least. :-)
>
> Thanks,
> -- Marco



-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3DwBArMwvtDC8zV-QjQa5UuwWoxksQ8j%2BhUCZzbEAn%2BFw%40mail.gmail.com.
