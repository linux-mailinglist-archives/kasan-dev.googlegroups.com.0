Return-Path: <kasan-dev+bncBC7OD3FKWUERBCP5RGYAMGQECJHIKSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09EEB88BBB0
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 08:51:39 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-69057317d23sf89738266d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 00:51:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711439498; cv=pass;
        d=google.com; s=arc-20160816;
        b=MYp+JuvmKzzKK/J8c/qem++C+8Tqf6rINbbw0/mFc1QXwFa2wcBpRzDTbt5WuQKsNc
         +ako8H39u+yFBjs+RIu6Uvh/Z5xgGpL6FhxBJDUuy8rSOGXxIMA2xFFHCgjhOUg3kA9U
         RdMQt6bWNyu4uFMHDLOxpiCkLtdCmhdoFx7uP5vZS3Nu8zbxZQP5f8dT7lKUCbVQcJif
         1t/7Gxq7qJu9qZZm5LfzaZK/D3E4mWB/ne6fdB/aEIQmHfMVkFikaqwzU5H51BTU4SzR
         D424qVPJpcYLQKYnK525QPbanKN2BVQBWA+wpjPqYY/yBPinKWIwzqg1pRFJ8LS3GW2g
         aI+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=73mrfRRLy+7fZV/UYqOAizXUspVHUshQv5yZSgjnpXs=;
        fh=oDYBANqs07XnGDXtiNVnBqJ/AEJz3uocpC4SmezbijM=;
        b=t7qQsgvQ8UrS/ceaxgAjHVYyK4wEyqenvXyDZmm2ABW/+AU832NPKC3lvxit4tdU9C
         XbWfBqTlQwE+KJs6RLhz4ID3P1HYtDRdMTboVvNxpd/GvaAFxR3DfGuXvHsbSL9LQGjO
         KCb/KYznQKrkblsF5rqK2IKP3tkxrECRb75k56vNAXN+2Hh1EF+4lwj476WqLqZ0k9mP
         XxPLNwAECZcPfAxEe6FfUJ7y02McK+WUPgPh9j6lAV5YnZ/LO+kG3PL0ZmhskAZ+jMYr
         RE2+qELqKW2bddN7kYKL83srjPG1CcfBGEy54MFzV3u2FwGjq7wZJINlmJnP7duHqQKR
         gi2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NIHgQut6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711439498; x=1712044298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=73mrfRRLy+7fZV/UYqOAizXUspVHUshQv5yZSgjnpXs=;
        b=CNcp9IiQfNzXyVV9zK5vIBR4XdUdg8OJWGYuUkPok1la1fAWPyTe0UqG7UL/Z9+2W8
         ocLsSZ/tCga80al6By744+IYg2gWQWn4vR8f8nvR1r20CVN/JCLQzE9x1Zy47tuj/X8i
         /8LCKFeHowWDM69WNLYamfbsJmjgtcTmTm/vmgyVp3oSdBF0k5pyYGYp0xUvRvb5afax
         LPTSfeQuRhmxIxxDkwUBKtGrdPUnLuaFXfNuL+DJHamTHeLrksB1lSijkot/8SyoGHBH
         BD4IJBUHqfXNpm6R8M+Eznndelju2iTM5/PXBu/uck8/OKNDAfRJAR769OMZrtzsBq/B
         3SoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711439498; x=1712044298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=73mrfRRLy+7fZV/UYqOAizXUspVHUshQv5yZSgjnpXs=;
        b=tU4D0xg//F41OlKQJ2dqjK7E62aL2qanLbMHFkm7NQwvY0cSBguYPf+ch4HM/BwRWr
         0yNDAj+Ij+pzcKe4GWFZptvpvyplEPNBt1S0eNaz5CsHH221sus48nDoqA0RP3bmvsnA
         7Ur6ymOTtP5vetCvHpMJiuzggCJaW4LYEVer67c/6uf9n9HkQu3GyldWZrz8xf8m3MEc
         8p+yUK3HIO+vXUlbid6zP9ZmhhugNTbaJHGI1vssm8yqMwzJCx6pEhh/WXFlr6TU43ZX
         PS/Aj9gjmawBgZv6ychQqQE2XcNxM6OgPZhEVgFZN2Tm5BXmeQVtUJs3ytrgbICGXQo6
         EUgg==
X-Forwarded-Encrypted: i=2; AJvYcCUSblNyXjQy1xwJnEVM/nS7i9JR4wtupoFpqUXbyGt5qdMqiHJlerzRny8kPbz0rsN+eB6hUlhBOPY+ce0k+xmaL6f4hzaROg==
X-Gm-Message-State: AOJu0Yz+27zOFLhbphH9Pn3xpQNlyNYatmsD+xjN91y79HU/v5onnIed
	eZfqesThyaHK6pcKLpPBSJd8h2T6CnQTUJKwUXRPAFOIzWry3VDw
X-Google-Smtp-Source: AGHT+IFPGTDbUF5uYdSbotlctqrBQv/7x28AidS6U2+V2gp77nneavk3MMCiOsAs9xVPigHBOxHVQg==
X-Received: by 2002:ad4:5f0d:0:b0:696:8505:1945 with SMTP id fo13-20020ad45f0d000000b0069685051945mr8342505qvb.36.1711439497841;
        Tue, 26 Mar 2024 00:51:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:20c8:b0:696:78dc:ab6a with SMTP id
 8-20020a05621420c800b0069678dcab6als3165697qve.0.-pod-prod-06-us; Tue, 26 Mar
 2024 00:51:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVWMQw5xw3z34Y7MEbUqN7Bu1nOv0WCEPPSiH+AqWz1YyZvA3+VgyrHdAS6IjhBLDjjyC6ftTE2y/b+HIbpndFfr4Ij8S33erIdg==
X-Received: by 2002:a05:6122:e6c:b0:4d3:3b1b:aa92 with SMTP id bj44-20020a0561220e6c00b004d33b1baa92mr5310347vkb.11.1711439495543;
        Tue, 26 Mar 2024 00:51:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711439495; cv=none;
        d=google.com; s=arc-20160816;
        b=CsMl1uamCLEUBmOAz/KwmUaVXipmklkpoJrZPJIqClDW4jLRvrKQ6rxYzbdvrqEisB
         /RIX1ERMJ4Sr7nTN387vmm5sYIISSDrfiDWFPtptWPM7RdUaxBXSMZ/ywq59le7H8qaC
         oqANBZ54R8xA/F22XLKZcKjaPO/Ldr0FjLyGILGDSfcIIKYdtkbB8JE+AL50kwRDcF2G
         KgtCB3YTDQhoX1slMLGR1TdIaHEIO3cJIlFUUhWnlBdlmrtImiRSd28ePBxkyE8tXRQn
         C0ELRbUj+pacvcBQ0OyRZQIv3CNO0bU1hBFCiqxfeSXHtwcPh2Eu3I9tx7K0KhxQREav
         ezQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=shklYWkLA2oyBqnlJsmv6lUxL/P85ZOYE2ckd/gba5w=;
        fh=KhwAbKrsMXc+SvExhUQCX1yPC6agnwktKhmSJ/dj+RQ=;
        b=mUYyGa+18MEDcoLhuEdY0FrEtBpHFeH8NnMP7/EcRUAMRJ42j1upD9iiPdRsxNs0Fx
         8dORpX7hdwDmskC5vCBh/oGcA5eEeCjSf0GNBLbhMlKlL5orblrzKYU+P/+R/IllCMTv
         lyR0E+Zi2H21FxKrYE5d23Xhogvt0tiY0dIyuuez59Yl1RY3RvV+W5j6p+CwkaxU5zeY
         jtCAPn/C9NgQ1J3vcIK5hk1KUC35H2lqj4Go9mGcrkQnmtYLzDOQLWjM8Piqr66+tenY
         WEaKTJPYJLOA/atTLZf2uW536ufT++4v+7hV53WHwYUffqSkSN4TPj9lcC6j7AtO612p
         ohgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NIHgQut6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id n190-20020a1fd6c7000000b004d3c4a37c63si1032865vkg.2.2024.03.26.00.51.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 00:51:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 3f1490d57ef6-dcc80d6004bso5109631276.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 00:51:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVEw/FU3VQfH/OSf0KKm5TQ9uMja9UkpvzYmESCJb2XhHCoF4tB/Z8XyVqhNF2ESMaT54qXchY1PqjZqwZLGxAdIrqVoWt6nTRW+A==
X-Received: by 2002:a5b:181:0:b0:dce:2e9:a637 with SMTP id r1-20020a5b0181000000b00dce02e9a637mr7603025ybl.20.1711439494844;
 Tue, 26 Mar 2024 00:51:34 -0700 (PDT)
MIME-Version: 1.0
References: <CAJuCfpGiuCnMFtViD0xsoaLVO_gJddBQ1NpL6TpnsfN8z5P6fA@mail.gmail.com>
 <20240325182007.233780-1-sj@kernel.org>
In-Reply-To: <20240325182007.233780-1-sj@kernel.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Mar 2024 00:51:21 -0700
Message-ID: <CAJuCfpGwLRBWKegYq5XY++fCPWO4mpzrhifw9QGvzJ5Uf9S4jw@mail.gmail.com>
Subject: Re: [PATCH v6 30/37] mm: vmalloc: Enable memory allocation profiling
To: SeongJae Park <sj@kernel.org>
Cc: vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NIHgQut6;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Mar 25, 2024 at 11:20=E2=80=AFAM SeongJae Park <sj@kernel.org> wrot=
e:
>
> On Mon, 25 Mar 2024 10:59:01 -0700 Suren Baghdasaryan <surenb@google.com>=
 wrote:
>
> > On Mon, Mar 25, 2024 at 10:49=E2=80=AFAM SeongJae Park <sj@kernel.org> =
wrote:
> > >
> > > On Mon, 25 Mar 2024 14:56:01 +0000 Suren Baghdasaryan <surenb@google.=
com> wrote:
> > >
> > > > On Sat, Mar 23, 2024 at 6:05=E2=80=AFPM SeongJae Park <sj@kernel.or=
g> wrote:
> > > > >
> > > > > Hi Suren and Kent,
> > > > >
> > > > > On Thu, 21 Mar 2024 09:36:52 -0700 Suren Baghdasaryan <surenb@goo=
gle.com> wrote:
> > > > >
> > > > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > > >
> > > > > > This wrapps all external vmalloc allocation functions with the
> > > > > > alloc_hooks() wrapper, and switches internal allocations to _no=
prof
> > > > > > variants where appropriate, for the new memory allocation profi=
ling
> > > > > > feature.
> > > > >
> > > > > I just noticed latest mm-unstable fails running kunit on my machi=
ne as below.
> > > > > 'git-bisect' says this is the first commit of the failure.
> > > > >
> > > > >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out=
/
> > > > >     [10:59:53] Configuring KUnit Kernel ...
> > > > >     [10:59:53] Building KUnit Kernel ...
> > > > >     Populating config with:
> > > > >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> > > > >     Building with:
> > > > >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> > > > >     ERROR:root:/usr/bin/ld: arch/um/os-Linux/main.o: in function =
`__wrap_malloc':
> > > > >     main.c:(.text+0x10b): undefined reference to `vmalloc'
> > > > >     collect2: error: ld returned 1 exit status
> > > > >
> > > > > Haven't looked into the code yet, but reporting first.  May I ask=
 your idea?
> > > >
> > > > Hi SeongJae,
> > > > Looks like we missed adding "#include <linux/vmalloc.h>" inside
> > > > arch/um/os-Linux/main.c in this patch:
> > > > https://lore.kernel.org/all/20240321163705.3067592-2-surenb@google.=
com/.
> > > > I'll be posing fixes for all 0-day issues found over the weekend an=
d
> > > > will include a fix for this. In the meantime, to work around it you
> > > > can add that include yourself. Please let me know if the issue stil=
l
> > > > persists after doing that.
> > >
> > > Thank you, Suren.  The change made the error message disappears.  How=
ever, it
> > > introduced another one.
> >
> > Ok, let me investigate and I'll try to get a fix for it today evening.
>
> Thank you for this kind reply.  Nonetheless, this is not blocking some re=
al
> thing from me.  So, no rush.  Plese take your time :)

I posted a fix here:
https://lore.kernel.org/all/20240326073750.726636-1-surenb@google.com/
Please let me know if this resolves the issue.
Thanks,
Suren.

>
>
> Thanks,
> SJ
>
> > Thanks,
> > Suren.
> >
> > >
> > >     $ git diff
> > >     diff --git a/arch/um/os-Linux/main.c b/arch/um/os-Linux/main.c
> > >     index c8a42ecbd7a2..8fe274e9f3a4 100644
> > >     --- a/arch/um/os-Linux/main.c
> > >     +++ b/arch/um/os-Linux/main.c
> > >     @@ -16,6 +16,7 @@
> > >      #include <kern_util.h>
> > >      #include <os.h>
> > >      #include <um_malloc.h>
> > >     +#include <linux/vmalloc.h>
> > >
> > >      #define PGD_BOUND (4 * 1024 * 1024)
> > >      #define STACKSIZE (8 * 1024 * 1024)
> > >     $
> > >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
> > >     [10:43:13] Configuring KUnit Kernel ...
> > >     [10:43:13] Building KUnit Kernel ...
> > >     Populating config with:
> > >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> > >     Building with:
> > >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> > >     ERROR:root:In file included from .../arch/um/kernel/asm-offsets.c=
:1:
> > >     .../arch/x86/um/shared/sysdep/kernel-offsets.h:9:6: warning: no p=
revious prototype for =E2=80=98foo=E2=80=99 [-Wmissing-prototypes]
> > >         9 | void foo(void)
> > >           |      ^~~
> > >     In file included from .../include/linux/alloc_tag.h:8,
> > >                      from .../include/linux/vmalloc.h:5,
> > >                      from .../arch/um/os-Linux/main.c:19:
> > >     .../include/linux/bug.h:5:10: fatal error: asm/bug.h: No such fil=
e or directory
> > >         5 | #include <asm/bug.h>
> > >           |          ^~~~~~~~~~~
> > >     compilation terminated.
> > >
> > >
> > > Thanks,
> > > SJ
> > >
> > > [...]
> >
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGwLRBWKegYq5XY%2B%2BfCPWO4mpzrhifw9QGvzJ5Uf9S4jw%40mail.gm=
ail.com.
