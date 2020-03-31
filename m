Return-Path: <kasan-dev+bncBC6OLHHDVUOBB357RP2AKGQEE42Y2CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A5C41198C1F
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 08:15:11 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id w191sf8487174lff.13
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 23:15:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585635311; cv=pass;
        d=google.com; s=arc-20160816;
        b=EdVjT6mu1bSbJ8LgZF75Zs4opgddwEWm0zdn8W7i27U5Jfby6HQD2/63OgSWFw2jy8
         FPj/lFDpXCADAxPgl2dPpGrGZ6FwdM6dbqKq/JDh7fzke/oIKqp/NaMXQNx7g51J1six
         r6Zzqs81j8K9b+8NP6nZ+2q3APGSmrA+h/0sFSdN6zLm3gc7S8GjHI5Re/fpHRAkfeSv
         WKlbDBY4hC7uCzaHZIBrRCoLcf+H8IvrFJlorfj5/E+KeU/574AYFNFNyyZG4q/HbLFD
         Uwbkz+laNEXBsaERiIgv9c5NXtFTAR2Orz6PMpz/RC06JOp6uuO9fL8gRz9F0gK/duMF
         a1mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Qy63f2IX/Bu7Yior56LyCzeh4zv+QSgvdwL0lO5n8WM=;
        b=UNb54VijLO9mcw3R1ZvIC2DGBYLr4yPVuMse5UlQYSLPe0e5dZ461Vmlm3MiwYTKiF
         hC2X95Zh78w+9FBz/Q2Am5WBpnBfDKMkbatQZjTyORAnCKphjyg6H1ayEz4aU62yX7NB
         BaSNJpurdPFtAI4xdpMJhgJDhXoUiuGyGsBSQUCz+9anYSbcAGX215np6LgnOkKm9b2v
         ASNc2noOGZJ8/6/lRNAhRTT0IEcEFLOYWmhotJjZMI0tyoXJMrU2Oy4hTulPPEdNaxYE
         bwlQhbd5RCAT/F0ign4bjhFkKFtxk+jGYNJ4QMsh1nN/3q22gr2qfHP8np8rw9VxqRSc
         F1Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jb1SXjJu;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qy63f2IX/Bu7Yior56LyCzeh4zv+QSgvdwL0lO5n8WM=;
        b=Xu7mLwKCpV2dJpZ6qmHaxJrkIIjhP2ODra2jGpzoUm3THkjiJowyGUpEmfSJ0is/kC
         MxyrDgCZvWdme5rmIE8VMddggzfvr2Cw2P8bo6nAnjGrdwYypgEHWBlztyOgOM4Ghw06
         1qLfU60m9HVXd944u78FD9mFLmmDPKZINzLUHkh9FISLEidO/eihI3iDXXD35e+91dMb
         h/V8K0lcmp/gwUeDO+P0LRGOYVd25J8M0WFsmcw2P+cn9yzbZn9WfPZ4D7CUfR5mUNXS
         LJEHmrd4DOsg3EhMItFIi2fCTHjAEmrlEmKsFxthgaMxsvy64huhUNEQLa7ivuLU6C1c
         YUkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qy63f2IX/Bu7Yior56LyCzeh4zv+QSgvdwL0lO5n8WM=;
        b=bwhtx0gb4vhYAONIRK3lT+fi41svHiTQPL7uFDFwAR2OUZUkoq+hVyr0yiVYnXlGwo
         vg05xPDv1gkipZJGeg5zlxGYHyv5WJyNiffipOm+ItwSiRgDth7yi2q11N2leTRcNI2s
         WwTv3N/ALPzg2N2piCOnfVEvf5+Z0A/A7Z/LJSkquKvRUT68t1qSAiuARtA8umgBX6za
         kxFhs/y3b1Iqs4l5974teH+wpi6IY4fjlXRB21WRcA7jzaEFjta88d5Wh2SNBzz0/RPw
         cEqDa7ykOws9a+dpo3y058Xl3lC8uSAbOdpwR/8pU3p0YOBMaDYRuVpd7Dyv7HurNrJ4
         WoKg==
X-Gm-Message-State: AGi0PuZcEP2du9t1bQuUOAyQJIyNHZtWZX7J3kys5A3XtCbMpVe2VKrk
	fFKoIFSVAB4s3BlYh83ZLRQ=
X-Google-Smtp-Source: APiQypKwRZsyHyhfiJ35O+QSHE3ecPZfD+lWiAWwAHUGg/udj1Zeak/3gVJnEY4aftJcCrbrFcDZGA==
X-Received: by 2002:a2e:8699:: with SMTP id l25mr9239491lji.156.1585635311129;
        Mon, 30 Mar 2020 23:15:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:41d5:: with SMTP id d21ls3547872lfi.11.gmail; Mon, 30
 Mar 2020 23:15:10 -0700 (PDT)
X-Received: by 2002:a19:74c:: with SMTP id 73mr10094512lfh.56.1585635310327;
        Mon, 30 Mar 2020 23:15:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585635310; cv=none;
        d=google.com; s=arc-20160816;
        b=ew6oFG4gaT6sCgOFXy8rKjKfaNlJNWTf0Z9Kc8ORPPPuoacFYM18uiWiR3/L4EyNr6
         gj9vEMxrzvL3RyupWWtdvj/CxqdUJru56CWlXpu0RWWeVguy94wr++TagpkaaYwQd7O6
         EWmiiOsVFI8YyGimHjpZBSmTU998DKp2Si4CEIvgPU+B8sKQadzPMwLB66z34NJuUnK4
         xq+vyLcGdjICSAx3bnAjt/Lzq2q/hdydFEp+p4a8xSI69pYfq0EMjMjRvoUokvZt0w+S
         EPXJOKR+I1ml3QLyIfHIDnmax9x5Uq6A66h3MmBbX02w80o5eqnPNN1/VoZW7Z/LnDLD
         FUqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QVzfoFaKAZ/NhukugEE1GHIPdiqQUasFPo75mtc4njo=;
        b=kSIj+so/Ww4sMbMzL9fKUayzWeCnOhzuB9TTewrgdYACq21nm2LRhkpS896lLzGVkh
         FbbPyWrRxGcQXlWYDzmG6hpK4BHFrK2q1ZsSs0lM+ZdB+3YuMCoBKu9epTCRoJoFNjdI
         7WgN8IOHde6nGpRrcc3yOF05NEVAduw9T0NTJkWvxHdNzlh+JZqGAXUOf2BRjDx7RiYf
         1YcGVcrYLhfgNC2Ngizgj12ll5/X2MlUKkSqBuO2NJDDvmrWhqb++SDgS9Uu8oP15UyW
         vZJ1aF+fi71Auwgk10gsaitVuLuQS9Q13LFW3pg4K6zyHoZZOiCmBuixDPUpQt6oiRek
         0ppQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jb1SXjJu;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id e4si747536ljn.1.2020.03.30.23.15.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Mar 2020 23:15:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id h9so24345654wrc.8
        for <kasan-dev@googlegroups.com>; Mon, 30 Mar 2020 23:15:10 -0700 (PDT)
X-Received: by 2002:adf:9b96:: with SMTP id d22mr19832564wrc.249.1585635309395;
 Mon, 30 Mar 2020 23:15:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
 <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
 <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com> <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
In-Reply-To: <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 23:14:57 -0700
Message-ID: <CABVgOSnz2heYvXytvhwA3RO_3dX=8vKrC+b8a6GLZV8eD3Fcow@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Dmitry Vyukov <dvyukov@google.com>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um <linux-um@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000064aa3305a2207df2"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jb1SXjJu;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

--00000000000064aa3305a2207df2
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Mon, Mar 30, 2020 at 1:41 AM Johannes Berg <johannes@sipsolutions.net> w=
rote:
>
> On Mon, 2020-03-30 at 10:38 +0200, Dmitry Vyukov wrote:
> > On Mon, Mar 30, 2020 at 9:44 AM Johannes Berg <johannes@sipsolutions.ne=
t> wrote:
> > > On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
> > > > > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I thi=
nk you
> > > > > confused the values - because I see, on userspace, the following:
> > > >
> > > > Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000.
> > >
> > > Right, ok.
> > >
> > > > Then I would expect 0x1000 0000 0000 to work, but you say it doesn'=
t...
> > >
> > > So it just occurred to me - as I was mentioning this whole thing to
> > > Richard - that there's probably somewhere some check about whether so=
me
> > > space is userspace or not.
> > >
> > > I'm beginning to think that we shouldn't just map this outside of the
> > > kernel memory system, but properly treat it as part of the memory tha=
t's
> > > inside. And also use KASAN_VMALLOC.
> > >
> > > We can probably still have it at 0x7fff8000, just need to make sure w=
e
> > > actually map it? I tried with vm_area_add_early() but it didn't reall=
y
> > > work once you have vmalloc() stuff...
> >
> > But we do mmap it, no? See kasan_init() -> kasan_map_memory() -> mmap.
>
> Of course. But I meant inside the UML PTE system. We end up *unmapping*
> it when loading modules, because it overlaps vmalloc space, and then we
> vfree() something again, and unmap it ... because of the overlap.
>
> And if it's *not* in the vmalloc area, then the kernel doesn't consider
> it valid, and we seem to often just fault when trying to determine
> whether it's valid kernel memory or not ... Though I'm not really sure I
> understand the failure part of this case well yet.
>
> johannes
>

I spent a little time playing around with this, and was able to get
mac80211 loading if I force-enabled CONFIG_KASAN_VMALLOC (alongside
bumping up the shadow memory address).
The test-bpf module was still failing, though =E2=80=94 which may or may no=
t
have been related to how bpf uses vmalloc().

Simply adding code to unpoison the region on vmalloc() doesn't seem to
do anything, which lends credence to the idea that the memory is
actually being unmapped or is not considered kernel memory.

I do like the idea of trying to push the shadow memory allocation
through UML's PTE code, but confess to not understanding it
particularly well. I imagine it'd require pushing the KASAN
initialisation back until after init_physmem, and having the shadow
memory be backed by the physmem file? Unless there's a clever way of
allocating the shadow memory early, and then hooking it into the page
tables/etc when those are initialised (akin to how on x86 there's a
separate early shadow memory stage while things are still being set
up, maybe?)

Food for thought, perhaps.

-- David

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CABVgOSnz2heYvXytvhwA3RO_3dX%3D8vKrC%2Bb8a6GLZV8eD3Fcow%40mail.gm=
ail.com.

--00000000000064aa3305a2207df2
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIPCgYJKoZIhvcNAQcCoIIO+zCCDvcCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggxtMIIEkjCCA3qgAwIBAgINAewckktV4F6Q7sAtGDANBgkqhkiG9w0BAQsFADBMMSAwHgYDVQQL
ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMK
R2xvYmFsU2lnbjAeFw0xODA2MjAwMDAwMDBaFw0yODA2MjAwMDAwMDBaMEsxCzAJBgNVBAYTAkJF
MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSEwHwYDVQQDExhHbG9iYWxTaWduIFNNSU1FIENB
IDIwMTgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUeobu8FdB5oJg6Fz6SFf8YsPI
dNcq4rBSiSDAwqMNYbeTpRrINMBdWuPqVWaBX7WHYMsKQwCOvAF1b7rkD+ROo+CCTJo76EAY25Pp
jt7TYP/PxoLesLQ+Ld088+BeyZg9pQaf0VK4tn23fOCWbFWoM8hdnF86Mqn6xB6nLsxJcz4CUGJG
qAhC3iedFiCfZfsIp2RNyiUhzPAqalkrtD0bZQvCgi5aSNJseNyCysS1yA58OuxEyn2e9itZJE+O
sUeD8VFgz+nAYI5r/dmFEXu5d9npLvTTrSJjrEmw2/ynKn6r6ONueZnCfo6uLmP1SSglhI/SN7dy
L1rKUCU7R1MjAgMBAAGjggFyMIIBbjAOBgNVHQ8BAf8EBAMCAYYwJwYDVR0lBCAwHgYIKwYBBQUH
AwIGCCsGAQUFBwMEBggrBgEFBQcDCTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRMtwWJ
1lPNI0Ci6A94GuRtXEzs0jAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDA+BggrBgEF
BQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMw
NgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBn
BgNVHSAEYDBeMAsGCSsGAQQBoDIBKDAMBgorBgEEAaAyASgKMEEGCSsGAQQBoDIBXzA0MDIGCCsG
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
KwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMFEGCCsGAQUF
BwEBBEUwQzBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
Z3NzbWltZWNhMjAxOC5jcnQwHwYDVR0jBBgwFoAUTLcFidZTzSNAougPeBrkbVxM7NIwPwYDVR0f
BDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9jYS9nc3NtaW1lY2EyMDE4LmNy
bDANBgkqhkiG9w0BAQsFAAOCAQEAI1k/FZLjynK3T71qfFDJJ0mERIlOlCjL3bnt5v9PXoUMRZnN
ppwKQaME7VtKNg34GBClPIA/UMA8JrNX6IKvoEj56VrZyWvblQfp2x1+9A1BOlHPiiZ42u3yCy/+
GpomPPMiGYbL9forGWUf2MdipfoIdYxzEkQCGv5FiIYmcOWFbAAPRu4s+YZwUovGOB8R8c+U5vQm
wh59TBzK2z6RbJp5MlFbA4IEsiskOiuEyiG+yFnmY2qRa4xzEK8U1+7jgvfwWQlrxxCvWRyEOqkU
gB8R5VkSx0bbt77BiMbu8N+eu7L5+o7yhJRw9pGvlPLXV/pAD3W6hkobaXAM1/RuUjGCAmEwggJd
AgEBMF8wSzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExITAfBgNVBAMT
GEdsb2JhbFNpZ24gU01JTUUgQ0EgMjAxOAIQARqRBq4Y7b8zPUaKehJMZTANBglghkgBZQMEAgEF
AKCB1DAvBgkqhkiG9w0BCQQxIgQgs5xObdLR7d1s45wTIlqn3RPE9XgIP5qmt7qqldlsXP4wGAYJ
KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwMzMxMDYxNTA5WjBpBgkq
hkiG9w0BCQ8xXDBaMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqG
SIb3DQMHMAsGCSqGSIb3DQEBCjALBgkqhkiG9w0BAQcwCwYJYIZIAWUDBAIBMA0GCSqGSIb3DQEB
AQUABIIBAF9zVJS0sc2++7Ue0ckrBZsySd7QOR4qbP4V+4AeMg1EIWkJG9l2bqgqKMeXicftf/qU
i5bHu9gcRPHbeqGBnkfvSz5Gk43XfR0rwvzfrfYcQto44zlQ6GiqJ4406VrQDx+Pska9s+984RRw
0wVD0D4DqA9LapWLM7OiP4g3JibkRZNnfy5U28RyKbfMhwFLJzo/KlUYp/l5V0dVnlZsrRgJGIIz
6uDx883CJbPty1rIxL7vXVLr13KQKDTAnKXSWIZANIe+EeIPci+wN3vjJaj3s758Fsr9C80Y3CxV
gYGS8rbYtZ/bQj+dsArfDRdwXpTbM2WzPeYb5D/AISH7QIQ=
--00000000000064aa3305a2207df2--
