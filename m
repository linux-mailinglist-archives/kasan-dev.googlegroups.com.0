Return-Path: <kasan-dev+bncBCA2BG6MWAHBBNOS3PTQKGQEYYWGS3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CDDE35260
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jun 2019 23:57:11 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id f24sf173144lfj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2019 14:57:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559685429; cv=pass;
        d=google.com; s=arc-20160816;
        b=iiBM0Ft9Z7FeiAPw62EbDxqywHWD7o2zyJOYC2Qj3Y/hwqniJwdTF6VwBhbBh6uqXz
         MzFdduNiE7GGx/UqHJI2YY7pSsais+NQzXPreyoY0slfFrF1j1K/nylxUa46kAlbltpp
         ZdhDAxr8coQUAnAdj7QRh/hQ4ArASWdUQ2HPLy597paNFQ0Sewzge15mDkesoA45nmxK
         xJsS+v3T+UVS6EOuDSQpoSYNaO9vP+KDpUBmSiM3/b3o2qWQUwAi4JAVQwDI0HE4ACK8
         CknHkRDi8RQRU0zQEYZCU3S7GZW2U/eE672Vq0iV/GCEEeIrCO+oBJvFZq5lxFVJ52k0
         a1hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0X9K0QW1qi6x841ay4tH1/KSIIMcOkUAefP7KSpYKjg=;
        b=0GJZAGHDLszlf0ZcyhwcnpJm9IHhm6DWotoAWHCSDz+dwU+ZQ1bwAkg7vZ6ltGoWKw
         LPQqsMkPX5OaVbYmA0SuJYFUuIurmFky5Ua+VIcUKk7HrrgEmYb07D/lC02qbZj8+LaM
         gyYjqvmuGLsn1Hs62ROtSGW1q54IZ2dPyevWzc80O3Cok5NnBgqKXT4xCkPyWcaWrN7k
         pxDJrb9eNDnvrzKiW8WCIuv/UEaGrceXvMH+JjjvYY8z8HQkUVJ+ndGnOoJbwHDVe2sG
         P7GZYcWXfqrs/iscigA9aQFQGxJo37bcp1AdTgBvcN5/9u39USGW6Aw68fpucVjQ6vWk
         iMLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nLRStuQz;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0X9K0QW1qi6x841ay4tH1/KSIIMcOkUAefP7KSpYKjg=;
        b=Vexqe408oSdkjEgJDqil2S8MJIv8x/yI028SK5jycyaj7ttLZvccpNTWlI4KVn54ri
         MmwpIVvVARC9E6oUSsUX/hHknSG5AVqEju/UvIjLHuq631pGf4XOFrFpUA+7feBEMzjP
         vdcuMyAdbXOSksaUncQejNRNXX8KC1mMf0QG4YuYBtHa68xPFNH4x5LypvhTvSRHnkh9
         mug2AHFtkGvKlS7VgNGG8vGa2awgvrtuQ9aVMKlwHkfyPELa4VlparNoCj005LmmTKHl
         myZDWl6pZLodkom/0UiHd2F6rqERpep/Hrz9mdgVsQJscluVFddI/Mn6JIPSnrEvbLEo
         XW7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0X9K0QW1qi6x841ay4tH1/KSIIMcOkUAefP7KSpYKjg=;
        b=swKh/Fpui+P48g1uVb9biroY2jtjwyy7AKMYzc4/VqRMcliHXJ5XFeXYqCfR3MM/Yc
         O5KJFP+FU4iFHO0Qc28wrSLk9p94IdYAJo0f8x5MaSNaye4lqJN0HlkWqL8rMIqPscAh
         1F4MmoIzyvk7r3DjNHVF8sbcjgokAAPqPWaWyDe31JwSn8UXLHwivZILAHOwiRZrNEsQ
         a7zdTeojSywGWWHqF4faLKhuple7b3+TOMHuAjlISksbXFsDtVQDlsiMNnRtVveTcBU+
         VYN8z2ZiuZ3veJk/eko+nhVbLEhs0cm+1Y5ZbFsJAusItM/gfhQ4cmKdSaJjXE0SDh4i
         CK6A==
X-Gm-Message-State: APjAAAXWMsnpoIqMVchjqyVXrgiPDhUsg123+QrDUrlOaJUAdkdif1j1
	CQnlN/84ztzBbrescoVfHIQ=
X-Google-Smtp-Source: APXvYqx84FbBw//omVachySad4KzHC+OoP2ITPqxgLwcPorMHkvmc5n0/fl1ekeIf+I1YS4/UFM0Hg==
X-Received: by 2002:ac2:546a:: with SMTP id e10mr17964101lfn.75.1559685429756;
        Tue, 04 Jun 2019 14:57:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8917:: with SMTP id d23ls21455lji.14.gmail; Tue, 04 Jun
 2019 14:57:09 -0700 (PDT)
X-Received: by 2002:a05:651c:87:: with SMTP id 7mr528155ljq.184.1559685429210;
        Tue, 04 Jun 2019 14:57:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559685429; cv=none;
        d=google.com; s=arc-20160816;
        b=Bdpbc0ZIL7hgIillaKkue1lW95RRY2rU6IL4WEDph/DUiGfeBMxoNKcAf8yO2viX/Y
         Cca5oQXHucMte46SNeyQ39EKfoYDJM/9Yu/CnwfM/4WmQxRMxxxGsdFuYtWCKYe3fQED
         Sb2ooMj8R3Ey7Lkt20dcoE3SuRraLw4Qe9/jNi+aOvuP85SxJwXHacfNhQHzbaJYcDR/
         AGBdse0n+CFxCRxsrj/1XsjxsU+97yYy/hkDqUtB3mcPXRqQ14qBf/LFmj24XXk3YAGV
         5i7n4g3+uDAWxUnSqSdXbUrMaGxlYvBtuhTgVA/VyPykp0bSASBO7dCxX4fFcb0bCRni
         X5Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nm6nxsfvdF1NlydS0vPcNG8Czdz9QMNoM/DaRUKeru8=;
        b=zUXSPSd/4vvGhrqHHNIJy0xgxFOKneBZij7xQUd2DpoOEWfVPYhdm5bX6Z4Phu3M/Z
         gBCtzyt+uGbTN11/jynt9EKdwQJ2eb9gfYwL2/iyHJUcYd/lnsP8vGyBF2WalqyvuLdY
         pFDB2cMFT57XJV4u2rN2KpAicLf2DSYvM09cdBhTt+e5iyWGZ+WIQ5QhLHgylOWCT44l
         Svk8VFTeUzQCTPVDvHF2cH4Cvlw5xpZvBECoWHnuKKYT+qkP1WKqg+zyQCNbO1fQq0Kk
         n/3/RiU9VqsSgb6mvu0u/zNQ2uv3Wb7yw37XVILBxL6l3opA0yZCdLEl/eDClTcwkK5E
         dmJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nLRStuQz;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id a20si1027239ljb.3.2019.06.04.14.57.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Jun 2019 14:57:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id a21so5998964ljh.7
        for <kasan-dev@googlegroups.com>; Tue, 04 Jun 2019 14:57:09 -0700 (PDT)
X-Received: by 2002:a2e:a318:: with SMTP id l24mr6354112lje.36.1559685428378;
 Tue, 04 Jun 2019 14:57:08 -0700 (PDT)
MIME-Version: 1.0
References: <20190514054251.186196-1-brendanhiggins@google.com>
 <20190514054251.186196-16-brendanhiggins@google.com> <20190514073422.4287267c@lwn.net>
 <20190514180810.GA109557@google.com> <20190514121623.0314bf07@lwn.net>
 <20190514231902.GA12893@google.com> <20190515074546.07700142@lwn.net>
In-Reply-To: <20190515074546.07700142@lwn.net>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Jun 2019 14:56:57 -0700
Message-ID: <CAFd5g44XatHJnNvRdqBGLnwcvOxTUAKM-tjKH94NGbyXGVVatQ@mail.gmail.com>
Subject: Re: [PATCH v3 15/18] Documentation: kunit: add documentation for KUnit
To: Jonathan Corbet <corbet@lwn.net>
Cc: Frank Rowand <frowand.list@gmail.com>, Greg KH <gregkh@linuxfoundation.org>, 
	Kees Cook <keescook@google.com>, Kieran Bingham <kieran.bingham@ideasonboard.com>, 
	Luis Chamberlain <mcgrof@kernel.org>, Rob Herring <robh@kernel.org>, Stephen Boyd <sboyd@kernel.org>, 
	shuah <shuah@kernel.org>, "Theodore Ts'o" <tytso@mit.edu>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, devicetree <devicetree@vger.kernel.org>, 
	dri-devel <dri-devel@lists.freedesktop.org>, kunit-dev@googlegroups.com, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-fsdevel@vger.kernel.org, 
	linux-kbuild <linux-kbuild@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, linux-nvdimm <linux-nvdimm@lists.01.org>, 
	linux-um@lists.infradead.org, Sasha Levin <Alexander.Levin@microsoft.com>, 
	"Bird, Timothy" <Tim.Bird@sony.com>, Amir Goldstein <amir73il@gmail.com>, 
	Dan Carpenter <dan.carpenter@oracle.com>, Dan Williams <dan.j.williams@intel.com>, 
	Daniel Vetter <daniel@ffwll.ch>, Jeff Dike <jdike@addtoit.com>, Joel Stanley <joel@jms.id.au>, 
	Julia Lawall <julia.lawall@lip6.fr>, Kevin Hilman <khilman@baylibre.com>, 
	Knut Omang <knut.omang@oracle.com>, Logan Gunthorpe <logang@deltatee.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Petr Mladek <pmladek@suse.com>, 
	Randy Dunlap <rdunlap@infradead.org>, Richard Weinberger <richard@nod.at>, 
	David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, wfg@linux.intel.com, 
	Felix Guo <felixguoxiuping@gmail.com>, Gilles.Muller@lip6.fr, nicolas.palix@imag.fr, 
	michal.lkml@markovi.net, oberpar@linux.ibm.com, aryabinin@virtuozzo.com, 
	glider@google.com, Dmitry Vyukov <dvyukov@google.com>, jason.wessel@windriver.com, 
	daniel.thompson@linaro.org, catalin.marinas@arm.com, ast@kernel.org, 
	daniel@iogearbox.net, kafai@fb.com, songliubraving@fb.com, yhs@fb.com, 
	cocci@systeme.lip6.fr, kasan-dev@googlegroups.com, 
	kgdb-bugreport@lists.sourceforge.net, netdev@vger.kernel.org, 
	bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nLRStuQz;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

Sorry, to email so many people, but there are a lot of maintainers in
this directory.

On Wed, May 15, 2019 at 6:45 AM Jonathan Corbet <corbet@lwn.net> wrote:
>
> On Tue, 14 May 2019 16:19:02 -0700
> Brendan Higgins <brendanhiggins@google.com> wrote:
>
> > Hmmm...probably premature to bring this up, but Documentation/dev-tools=
/
> > is kind of thrown together.
>
> Wait a minute, man... *I* created that directory, are you impugning my
> work? :)

What?! I would never! ;-)

Context for the people I just added: I proposed documentation for a
new development tool. Jon very reasonably suggested it should go in
Documentation/dev-tools/, which is not very well organized. This in
turn prompted a discussion about cleaning it up.

> But yes, "kind of thrown together" is a good description of much of
> Documentation/.  A number of people have been working for years to make
> that better, with some success, but there is a long way to go yet.  The
> dev-tools directory is an improvement over having that stuff scattered al=
l
> over the place =E2=80=94 at least it's actually thrown together =E2=80=94=
 but it's not the
> end point.
>
> > It would be nice to provide a coherent overview, maybe provide some
> > basic grouping as well.
> >
> > It would be nice if there was kind of a gentle introduction to the
> > tools, which ones you should be looking at, when, why, etc.
>
> Total agreement.  All we need is somebody to write it!  :)

I wouldn't mind taking a stab at it in a later patchset.

My initial idea: there is a bunch more stuff that needs to be added
here, so probably don't want to do it all at once.

I am thinking the first step is just to categorize things in a
sensible manner so somebody doesn't look at the index and see *all the
tools* immediately causing their eyes to glaze over. From first
glances it looks like the users of these tools is going to be somewhat
disjoint.

Maybe break things apart by who and how someone would use the tool. For exa=
mple,

It looks like Coccinelle is going to be used primarily by people doing
code janitor work and large scale changes.

Sparse seems like a presubmit tool.

gdb and kdb are likely used by everyone for debugging.

kselftest (and, if I get my way, KUnit) are used primarily people
contributing new features (this is one I have more of a vested
interest in, so I will leave it at that, but the point is: I think
they would go together).

Most of the remaining tools (except gcov) look like the kind of long
running tests that you point at a stable tree and let it sit and catch
bugs. Super useful, but I don't think your average kernel dev is going
to be trying to set it up or run it. Please correct me if I am wrong.

So that leaves gcov. I think it is awesome, but I am not sure how to
categorize it. Definitely want some advice here.

Once everything is appropriately categorized by shape, in (a)
subsequent patchset(s) we can tie each one in with a guide, not just
on how to use the tool, but how the workflow looks for someone who
uses that tool. For example, we might want to a guide on how to do
large scale changes in the Linux kernel and have that tie in with
Coccinelle. For kselftest and KUnit, we might want to provide a guide
on how to test Linux kernel code, which would cover when and how to
use each.

Anyway, just a vague sketch. Looking forward to hear what everyone thinks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFd5g44XatHJnNvRdqBGLnwcvOxTUAKM-tjKH94NGbyXGVVatQ%40mail.gmail.=
com.
For more options, visit https://groups.google.com/d/optout.
