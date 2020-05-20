Return-Path: <kasan-dev+bncBD4NDKWHQYDRBTFUSL3AKGQE2WSP7QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F2A1DA833
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 04:47:42 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id q143sf1358233pfc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 19:47:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589942861; cv=pass;
        d=google.com; s=arc-20160816;
        b=ctwLyuD1bwkhyWltNVqmsI3SQ5UmeG6hvSclFf9mQm6TH2tjLg2tO9mZEKMatio2eq
         AfhEnkeALpNaNnrbaHi0kaRTxGxMDexZ3O0EMwMYJLhaMi80Edn+c3H5v9ZaiLyMVWiE
         seJuvjtfgugsGcoWJ13SCN8NKGB7h7dl4c7EuDuznf8AtTPGOJBIqvIZ1df5JLJIPCmm
         2tutHbyqIFwtNO5pPJleXG/OpQO+bBEGZkJ4UgBe5nQNetjCQHKeQl0KwHVOFoZyfpji
         GAjTG0C8zhZWE4/61ZMgalqKnoZgHUlTF6oh/LaZgWRG+S9mUe//9JzgbZCi+Lmax2Qi
         HSTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=eZm7Y01KXY342hIuqVOB208sH3rw2QdBOhN7/NaKdqY=;
        b=tlresm/la3hmswNrZmu/LeMTA5oAvczO+laBLkTwvtnleWqzdMhr5Ks4XKei9x0NNd
         sCi21UrawXJHyAlQdAX5Vdtfez9bXloVk03N4ifCsMKwyDgSYrXRgD74nMN2XzAw5FU+
         /msV/6XkLzRf9UNFrWdEtTSk+7hmxcbCkno6rsBIRmiZulxXLk6Qlljh+/xW+U6Klb/v
         YzZNDJf7Ym9vER3eZaMfuHRXtaVyjBcFkJstefyi4FNhSHycptxg99eGGkswNm/boKR3
         bnypGmv90bqPNh0Sf385aK+SrkcYAJEGWgmqPP+MFkNXbPo4/9ZQHRNXq7K3CfTrLC8u
         2mZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=slokoVWJ;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eZm7Y01KXY342hIuqVOB208sH3rw2QdBOhN7/NaKdqY=;
        b=GydolNLwTIoupcN6b87vcJQLYgHlUl3JH+mVP5a9V+ogNLA+qBHnWEAfF/jg5uULtl
         PL+4Sxd84HLtsqZK1lW9aT+QdCH9Z6WeZyMIqB7AJyucl7IdZ92Z3ZFO5MMiMC+LZL02
         lp+o89+pG8/pxzULomd78Oa1QeijCL9hgGS4L/eI1tUySsjB0F4WF5iCtlyVSs0hezk9
         dYxAE3GXLtD5QXEu2O8DyFlJHQjVXB7PSeXHYVOpls4KvgCMPUNfbQUE8UrZGlOpNgHS
         w+wL4HluCexJzP/lOOju3r9qSTwzA3djHG04cu8l3yrqw0QzwO96VxnPRWCGHIRrRIy/
         lYCA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eZm7Y01KXY342hIuqVOB208sH3rw2QdBOhN7/NaKdqY=;
        b=s8TTDa5/2zZ4cS9fJQQwgK9j3wD+8qZ5aQeE/TUf7FyexP5djxbvycYmaqrgJsX+HH
         qaoCbboV5npTgEr2C6VGfIBHrIkqvJwfytsz2wb63/tIfcOiOJRepbGpk1r4wFeo+IDP
         BT0mJk/h/cpFCStRy1ICMdd3Ny0IEBXArg9GqUTyuINh9afUEBWcm/AjtAn3q5uchKFh
         5GA67oMQmXh6Fx1SSat4P+pwU748um1gOesduSAoRThlAFwuc/r7gsEF4KClejAOWYnw
         6pJjBCo2Tuc9etaJJZ1XdGDA9r6GFpKlZIS2X+cqHrUj7fW/MIdDxcjTxSH6iDFglv+h
         d8pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eZm7Y01KXY342hIuqVOB208sH3rw2QdBOhN7/NaKdqY=;
        b=j4ZVRsNDAM2AaGx66cXAgyXgt9VG82C7iKRPAdmqsf76sYIM+pIDQf6atExLjcbqNX
         tCFI/Cm+iFMa+oFbuHirHceWNI7bRpzt7IHslr1APS5gLu1m6ngOc+gG+//ts1O++tCh
         vKmPMBXx5772ydrojF0rDfCUwo2kSi9tyrlDyy1bh15evBrL4Z1NqlqJEPVMwe0CWEIs
         ksbYUiZ8w9bNkZIKvp065O+1WgxsR9bGl1sqYvbVBEwMvYABh3Uoj9PZMXyKO1bEwJ5e
         ImY+ShL0GWnD3PFGYMqVnXhxwU6tkECD/ZNwtZzcgAcVacAIbSTVsYOdAqaJwWW7h3c1
         dRpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532p8HB1jcNO44k3uuA41xTSSyH3z1fMZ3Py3d8/oB4daH/dHNH4
	YNkC8c78pRDzVGQ3sRTmFNg=
X-Google-Smtp-Source: ABdhPJyblntPVhGZZgJ6jQCKpka7zhzVBvm5HfuB8JsWdji53WDN67hIWlblHwVxzntKfqKyA7dPzQ==
X-Received: by 2002:a65:568d:: with SMTP id v13mr2020781pgs.436.1589942861074;
        Tue, 19 May 2020 19:47:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5649:: with SMTP id m9ls219838pgs.7.gmail; Tue, 19 May
 2020 19:47:40 -0700 (PDT)
X-Received: by 2002:a65:6703:: with SMTP id u3mr2025545pgf.179.1589942860168;
        Tue, 19 May 2020 19:47:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589942860; cv=none;
        d=google.com; s=arc-20160816;
        b=LvxMWVs5t7+Bodnq9hURY4Y8Y51OwSg4QHdoIJIrb/oGLIs988Ht12IbWnDeQ3BGiX
         JrVQTG6MMMw2Bvf7pZuHCGqy8g+TYWH6mWNBsDoZApXWp74OiZRsO1/PDx3s4r+NEsT0
         lfaHpj7vCxJEbJUZhQkX50Kh6d0TD2C8aocSyGgkk2ucsZ3uQN8kU5vkSTSqFuAB0J4S
         eY5gKBpS/2rbg6NnGxu8oxpRyqJ6/wwmVl/yAoisYtdCIMfgTvB13vkZ6dKESLTy3Eq7
         va5WGJHbmXkkmZr3VTLDnS57wsA5ALg4+pVBVG7VAOI8l3AEgqEv7SrljSLYKPRGq1u3
         JPSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=U3JxxfWABjzw+muWBftLLoPg5L7tniD/yZsXvBpXo+8=;
        b=i+2fHgDDmXocI84r9OTKVisjA5AQEuLxaA0hDG0k6dwR9vDJz/pd31AgaB9dXVQA7d
         Gh/TzbRK+SElGNS9HJQrhaGI+KGmCX0VJycQH38EEYf/3fQJfl93ZQfpL3mMBVn+A0AS
         hNMntebJI3AsLJR3P/B+mlKBHpA5lIwIOC5A5k4f90mrisgNYb9sIhtzZlvwW4k6yI1l
         dcNN6EOvYcJm2eTiLjyu+sPB3X8IeXp1ZX/L2yGzrVZgliiLUsVa1leqQT6aRmXZVgLN
         S7pJPdT/rlVdEfV4HvVf+5bXJRdjpIIVpDQr5x27AdV6ljO1pQxZv5XjkgO2sTptUffK
         JC/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=slokoVWJ;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id b8si456005pjk.2.2020.05.19.19.47.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 19:47:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id z15so1820916pjb.0;
        Tue, 19 May 2020 19:47:40 -0700 (PDT)
X-Received: by 2002:a17:90b:110d:: with SMTP id gi13mr2587365pjb.131.1589942859725;
        Tue, 19 May 2020 19:47:39 -0700 (PDT)
Received: from ubuntu-s3-xlarge-x86 ([2604:1380:4111:8b00::1])
        by smtp.gmail.com with ESMTPSA id a2sm670964pfl.28.2020.05.19.19.47.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 May 2020 19:47:39 -0700 (PDT)
Date: Tue, 19 May 2020 19:47:36 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Qian Cai <cai@lca.pw>
Cc: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, clang-built-linux@googlegroups.com
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE
 variants
Message-ID: <20200520024736.GA854786@ubuntu-s3-xlarge-x86>
References: <87y2pn60ob.fsf@nanos.tec.linutronix.de>
 <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=slokoVWJ;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
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

On Tue, May 19, 2020 at 10:28:41PM -0400, Qian Cai wrote:
>=20
>=20
> > On May 19, 2020, at 6:05 PM, Thomas Gleixner <tglx@linutronix.de> wrote=
:
> >=20
> > Yes, it's unfortunate, but we have to stop making major concessions jus=
t
> > because tools are not up to the task.
> >=20
> > We've done that way too much in the past and this particular problem
> > clearly demonstrates that there are limits.
> >=20
> > Making brand new technology depend on sane tools is not asked too
> > much. And yes, it's inconvenient, but all of us have to build tools
> > every now and then to get our job done. It's not the end of the world.
> >=20
> > Building clang is trivial enough and pointing the make to the right
> > compiler is not rocket science either.
>=20
> Yes, it all make sense from that angle. On the other hand, I want to be f=
ocus on kernel rather than compilers by using a stable and rocket-solid ver=
sion. Not mentioned the time lost by compiling and properly manage my own t=
oolchain in an automated environment, using such new version of compilers m=
eans that I have to inevitably deal with compiler bugs occasionally. Anyway=
, it is just some other more bugs I have to deal with, and I don=E2=80=99t =
have a better solution to offer right now.

Hi Qian,

Shameless plug but I have made a Python script to efficiently configure
then build clang specifically for building the kernel (turn off a lot of
different things that the kernel does not need).

https://github.com/ClangBuiltLinux/tc-build

I added an option '--use-good-revision', which uses an older master
version (basically somewhere between clang-10 and current master) that
has been qualified against the kernel. I currently update it every
Linux release but I am probably going to start doing it every month as
I have written a pretty decent framework to ensure that nothing is
breaking on either the LLVM or kernel side.

$ ./build-llvm.py --use-good-revision

should be all you need to get off the ground and running if you wanted
to give it a shot. The script is completely self contained by default so
it won't mess with the rest of your system. Additionally, leaving off
'--use-good-revision' will just use the master branch, which can
definitely be broken but not as often as you would think (although I
totally understand wanting to focus on kernel regressions only).

Cheers,
Nathan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200520024736.GA854786%40ubuntu-s3-xlarge-x86.
