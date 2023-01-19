Return-Path: <kasan-dev+bncBCMIZB7QWENRBPW6USPAMGQEC4ZT5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E591067377C
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 12:53:34 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id j10-20020a05640211ca00b0049e385d5830sf1468400edw.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 03:53:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674129214; cv=pass;
        d=google.com; s=arc-20160816;
        b=RwyeStEq1ENpvFFJ5BxScL8MTDhsBTFVxkTn4Wy+0QFQ8jhkYkRsEXXvrUDB/BlKEw
         zJd1cCAlcA9ULRSrer79wruDVkfoyFuUjOBmkwhEa9KVdkiOCohQq6HNkyrlU9mWTrt1
         +jnKZtVtDnyyYUUrBu79qNxqlPUF/6r/nG7FNpUHHWAckCV7KuzgO05Jf0a4zJv4wuKb
         9WaiaphKvN7mHPYsebRIWf/Asy+b8TsO419U3cA4MhBm1+vqZJ/8W47K7qj5fBUm8UTE
         xGLAWICDFH0jYiXoGKb/Lt0qea528A8BMxXA016FvMDVxlj50d1mZIkbbcoVEzjIPSoS
         dYBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vuaR4Vs/QeiKZbA6hYpRZJR6ztLCTKPJSv566FlPVP0=;
        b=qHUsBtSlHyeiiCqlnAJlc98e9/NfD/DIh43M45XhjHDT0cxz/dBWQBMXMTedNVSpiD
         +40bG6iE5x6IjAy9PDs1ufy1ajGT3gtvRvfj0lz7OVCS4YSuVvdoRnIZKuNI7NniKV17
         2HKQLU6SUBr5Weivi1QG7N5nMFmwAAzgaWl+12WIPlWhaq8wkhulqldHDmT3TceyehEf
         np/MFdyJ+QcF9ZdRWY+HrB5gEhqLTmbd0iD4aBPqXkr+2jW4pKQ1NRqpdQrpRmVIb4S5
         O0qEHTNwntsGga1nFllFcNKy+HfMDyVFmHSCZ7XGqUZRuE0Iui8F/0PaaY1gSulVG44Z
         Lpog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F81i1ksn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vuaR4Vs/QeiKZbA6hYpRZJR6ztLCTKPJSv566FlPVP0=;
        b=IfDHP5UYyroEz3YM3o+3fU7ShrfxbFAH5vVtsi1KEz3SPiTARJR8wSK4HvmE+c0eYC
         oC7oVNaXP983EqWaM0pzE7Uzobyn9dpr6ASkNDO2KTGl9AOWAMpvc/YOxjIwLg1N/ANH
         dwixGmBuxJWs6sdxf2gzVaLqxbT7ysC+W/fQtwJeq6ttZqgMWgfoG69V05hmw5uooj8x
         cIU/b0i9Tz0xEftE8nL/6zaOLJH/cyBddr9ZiyqH6RcpwStCB+Og5K20xRsaUAWTPqrU
         a8RoznDveeTbjrXmXYxsCoNZ2yovShZqrbGc0RG39x6N39O+xmjNqgQeDv+0VO3OkXM5
         CgtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vuaR4Vs/QeiKZbA6hYpRZJR6ztLCTKPJSv566FlPVP0=;
        b=MNK06uW4xxOXvguEBKSjw5YTa1ssTUOHEdy3n123KBE+1fAL6bub3et2GrQSTaDsOd
         t+yzKBZ4IKiSTQ41q/atS9rp42sSsqrhQ6UaIKIacS7fLadMLV7gscwv63yz/D1WAbIa
         jNFqLZizSZ4PkTLY8sLGH96jK1Jvwg+h8idzj308N6pex/+TuZtd8H5qbKCo5K0yREvG
         L6fGtRLLB1h8Ytilf52FY54SqezrwE7YaUOSb570xl8tBw/cvG9coNCW70W5/kEdnjPm
         pWeyew2kbYJaTi4hFuB2VBETAIkNl6di189YkM9IASsBOx48X2/4m3qSgBbnYIjrBPKx
         c8IA==
X-Gm-Message-State: AFqh2krUUtZbQnDBwkRt5O6JOpUdQ1QL7h9UHHtPHSEAfmdo+MP9HNFz
	Ku9dx0ySWJNu3F3nm+lHdHU=
X-Google-Smtp-Source: AMrXdXuXJMyU7CTj/TsI6NURI9uz5pCZW0x4Bp/4LyQ2WEVyqX0z2k6Tgb1ORXW0xbJWEtW9MoonJQ==
X-Received: by 2002:a17:907:918d:b0:7c0:8711:7a4 with SMTP id bp13-20020a170907918d00b007c0871107a4mr1432754ejb.667.1674129214259;
        Thu, 19 Jan 2023 03:53:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1247:b0:869:2189:ba11 with SMTP id
 u7-20020a170906124700b008692189ba11ls857245eja.9.-pod-prod-gmail; Thu, 19 Jan
 2023 03:53:33 -0800 (PST)
X-Received: by 2002:a17:906:7188:b0:7c1:eb:b2a7 with SMTP id h8-20020a170906718800b007c100ebb2a7mr23949946ejk.13.1674129213091;
        Thu, 19 Jan 2023 03:53:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674129213; cv=none;
        d=google.com; s=arc-20160816;
        b=v1IFBvg1v5HGjJdw90w3P4ze6ct69AM3RePorX6it4Ulqus3uylw13HLc7iPlEGxJj
         EUu+mct6sv5LOdVmCC2+ElGhuL+RlKa84c3d13XxCZkCpszI7cKe24/cKWDfQM3B2992
         dXbk5+QKtf9e1JFCKlUG94AZsqAasykySmakX41Ht57BBS5R1P9MWYhDaC72uRxEW7GD
         n73+kVqiTOIJghcgRb0u9sitszRzEpdgaiq2zqTJkLYitq4q3xlWFrf1rN3ppysETmnq
         eEZooFUH3fKtMTix5bmWsk1Gd7Zm/PhVVqTrGEfP6PwzLidXA6wnRaIEwYJUH41k8cti
         OYlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0rULqcw0JS4uzQ/A4LlvLlup3KmAGiln26QhsUT554w=;
        b=OAhbf9d4tTJ5qqY00egCglbfp3I63bOp+4IXiAPzB8VPrjPgoTyfn6UQlGpt83PgPU
         lKKgE48sZGzWGQlj/GSdFj+sM6MmryPM3SFiupBfSRwrWrJlxfflO/+RtB1amEbFwuKW
         UuZN36dXxtWCv7M93G8P4KO0EKzhyKMs54G/+n6ftDoKGjVoaXNl0PIpo+K1vOmOs+3s
         sU6csJw788iwaLFCgp6u/9Zz8WCdOmwHo8mUUA8CXPk+kratDn9y5aCHgpXuUWHrY4SV
         fE6Fq8Ddp1BnavvJXZ+axzepoiMxgi+y57iSTGE2FUukxf3n7mrNlyireomnmnioKdMF
         C+NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F81i1ksn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id gv11-20020a1709072bcb00b0086728259fb3si728900ejc.1.2023.01.19.03.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 03:53:33 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id bn6so1804856ljb.13
        for <kasan-dev@googlegroups.com>; Thu, 19 Jan 2023 03:53:33 -0800 (PST)
X-Received: by 2002:a2e:bba1:0:b0:28b:75e7:c551 with SMTP id
 y33-20020a2ebba1000000b0028b75e7c551mr481161lje.463.1674129212241; Thu, 19
 Jan 2023 03:53:32 -0800 (PST)
MIME-Version: 1.0
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com>
 <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
 <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
 <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com> <CACT4Y+YYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV+ob_A@mail.gmail.com>
 <42499854-b0ca-9efc-80a1-8d6dc0c968ea@redhat.com>
In-Reply-To: <42499854-b0ca-9efc-80a1-8d6dc0c968ea@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Jan 2023 12:53:18 +0100
Message-ID: <CACT4Y+ZA_Up4Hn_qcTczuUh0RHdm0seUPGKxf-Eh09n34PcoXA@mail.gmail.com>
Subject: Re: kpatch and kasan
To: Joe Lawrence <joe.lawrence@redhat.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	address-sanitizer <address-sanitizer@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F81i1ksn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Wed, 18 Jan 2023 at 17:10, Joe Lawrence <joe.lawrence@redhat.com> wrote:
>
> On 1/18/23 10:21, Dmitry Vyukov wrote:
> > On Wed, 18 Jan 2023 at 14:45, Joe Lawrence <joe.lawrence@redhat.com> wrote:
> >>
> >> On 1/18/23 02:21, Dmitry Vyukov wrote:
> >>> On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
> >>>>
> >>>> +kernel-dynamic-tools
> >>>>
> >>>> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
> >>>>>
> >>>>> Hi Kostya,
> >>>>>
> >>>>> I work on the kernel livepatching Kpatch project [1] and was hoping to
> >>>>> learn some info about compiler-generated (k)asan ELF sections.  If you
> >>>>> can point me to any references or folks who might entertain questions,
> >>>>> we would be much appreciated.
> >>>>>
> >>>>> The tl/dr; is that we would like to build kasan-enabled debug kernels
> >>>>> and then kpatches for them to help verify CVE mitigations.
> >>>>>
> >>>>> If you are unfamiliar with kpatch, it accepts an input .patch file,
> >>>>> builds a reference and patched kernel (with -ffunction-sections and
> >>>>> -fdata-sections) ... then performs a binary comparison between
> >>>>> reference/patched ELF sections.  New or changed ELF sections are
> >>>>> extracted into a new object file.  Boilerplate code is then added to
> >>>>> create a livepatch kernel module from that.
> >>>>>
> >>>>> The devil is in details, of course, so our kpatch-build tool needs to
> >>>>> know whether it should omit, copy, or re-generate an ELF section
> >>>>> depending on its purpose.  The kernel is rife with interesting sections
> >>>>> like para-virt instructions, jump labels, static call sites, etc.
> >>>>>
> >>>>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
> >>>>> data..LASAN0 from the gcc source code, I was wondering if these were
> >>>>> documented somewhere?
> >>>>>
> >>>>>
> >>>>> Regards,
> >>>>>
> >>>>> [1] https://github.com/dynup/kpatch
> >>>>> --
> >>>>> Joe
> >>>
> >>> +kasan-dev
> >>>
> >>> Hi Joe,
> >>>
> >>> But why not just build a new KASAN kernel and re-test? This looks so
> >>> much simpler.
> >>>
> >>
> >> Hi Dmitry,
> >>
> >> Well yes, testing an ordinary (fixed) kernel build is much easier, however:
> >>
> >> 1 - Sometimes kpatches deviate from their kernel counterparts.  Examples
> >> include ABI changes, fixups in initialization code, etc.
> >
> > This does not prevent testing in a normal way, right? In fact I would
> > send the patch to the normal CI as the first thing.
> >
>
> Exactly.  At Red Hat, we typically wait for a corresponding kernel fix
> to pass tests before starting on our kpatch conversion (emergency CVEs
> aside) ... that way we're usually confident with the overall changes
> before we even start our work.
>
> In cases where the kernel fixes are verified via reproducer and KASAN
> enabled config, as long as our version is mostly 1:1 we can still be
> confident.  Giving our QA team a similar obvious verification with KASAN
> enabled kpatch would be bonus.

I meant the source patch used to create the kpatch, not some other patch.
Kpatch is also based on some normal source code patch, right? If so,
that exact patch used to create kpatch can be testing as a normal
patch, right?

Back to your actual question. I think sections like .data..LASANLOC1
and data..LASAN0 should be treated just as normal .data/.rodata
sections. git grep "ASANLOC" in llvm does not give me anything, but I
would assume these contain string descriptions used in KASAN reports.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZA_Up4Hn_qcTczuUh0RHdm0seUPGKxf-Eh09n34PcoXA%40mail.gmail.com.
