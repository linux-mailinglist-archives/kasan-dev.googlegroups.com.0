Return-Path: <kasan-dev+bncBCMIZB7QWENRB7E4UCPAMGQE5AGBI2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 20907672113
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 16:21:34 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id y9-20020a05651c154900b0028571631915sf7747680ljp.18
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 07:21:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674055293; cv=pass;
        d=google.com; s=arc-20160816;
        b=sUTG4k/lSuHcBRns76KbuxkrIg1T3driQKgnS29gPLVLgXBTd2KJXBYFuReqAi/LUv
         1+DpeTPwi9+tEfE5OjwXZWB0WWx4ZThcbGst0IO4C7UZOLQ/0Oi33oEyfr6L9zoY8ldV
         xBnx0p2K4JQivvLhRt2nifSJ65+vBTp/KRzgOM5lTxIGLrcSAWHkW3rZnpQHOQQhYhaT
         uYJzuL1+auIGik5DWIA+Fp1y3Pq7UzbYgh+HalqbsJcvJ1TcKei2s44Y0LWnufJPN7EY
         l5ZOL+EUhIwsCgGFtDbauLvsxZg4QpMnGhW41GZFdPKY9JPqfkim66AVnjWPeGiIAPrp
         ejpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pGE2NZuhQORFUKXZnO7uUPrAs81JFAoWyjTV7bcr5Z4=;
        b=AItmTocxZaeKynSLGZ0eVCDCsaBUwWXp+8CTdeA2U7DT4JTpDBZcklVWhXg130Uclc
         TZQ7j2TTz5im+5fWPqa5K+PDW2chu3HsMbeYOwY8s7OK7qi+ckIs/+F354UB4m3Slep9
         d4wmEcFjA6pd+VpbN5RCzo/qjHxkFnzeJzmJ77nbHjuLoDCKBT6pMeynU8Icaev2ilTa
         j+M6n4c0+xLawuUUz3/yHz9rfGjUg72bQ/zPr1dY6q+NXRX7Rel+/QhMlqpSGfWbFeik
         p2knvxiHqFe2m24+oKr8SKNR11OVe6b+Il2jiVn+Ho48T8FHdaAgoy6//I3l0WFk13j/
         FPfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZLFwbdFn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pGE2NZuhQORFUKXZnO7uUPrAs81JFAoWyjTV7bcr5Z4=;
        b=XXwoK5rbdIINsmqXufhNMXZYs+cHlhxC0gt6qsSilZctMukyacoUzsUQ/AAkarVEMK
         LiYRFrwpuEnaNzzoYb+WNEA2uU4g66ZlolPwxpB3BO5DrCzfLkR1eoIOkZyTFDtJe1Xg
         N9D+38o65HvkXjeHBlnyAt4bYNWsLp/f0z2HG7eqg+9WwQATBjS2LOSKgJHmPvriw7vl
         KiE3LdddgpAv8SwT5x/pAvWfSttHOd7sYIro54Z94tiqext1IXQUxyNQyfV17RdM0bz4
         amHeQydQivo4b98/NkliQXk1OCS7I9ErYqQe2cYuF/DEuOTVgNwh0AxyN6doVjENU/09
         4UqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pGE2NZuhQORFUKXZnO7uUPrAs81JFAoWyjTV7bcr5Z4=;
        b=uMVJchYTK+n4EOuIDqwWkzv4AEkP4HaxOcj3pyULv0GjM9D9wRfFylaT2rawA//GwE
         8K1U+tQn9D7LrqHKRtBEjgvIoyTpmbLsqHXf0CLiMXdPjaUJqvrYiPGHYhcQJ6KE0+nb
         /DvZt33qmIdw8nYhdxljXFA3cNyKYB5ZHu6oWNL1tSN/101XHOYIH5XTuxh+n3bBViec
         /tbKP0bdKCaOU15vMDc2wSXZ3ptBeYJSPt2whl53Ks0AmaREydkAY1KzAJkzd+fFQP2J
         9yNPbbtfcyfG74xOs8HZ1b131mS2ER9bOzU+6e6iIXHPUk56JhsMVqVmtvGRqrWaFBSd
         dqkw==
X-Gm-Message-State: AFqh2kr5SfHfQepkZHBN0A6Nx66eGhwRrfeJZLb+ijCly9FOFJyfDWf6
	2+s/s8hWnkRNSh91OQrFSCE=
X-Google-Smtp-Source: AMrXdXusvRf8PStBB0r9CXfhfh5I16pFaEXeh7MDk9d5D9EW1fqYQRik3GBC9EAhUnHizt41Ms/ncA==
X-Received: by 2002:a05:6512:e87:b0:4b5:9189:9a4f with SMTP id bi7-20020a0565120e8700b004b591899a4fmr474218lfb.557.1674055293195;
        Wed, 18 Jan 2023 07:21:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3244:b0:4d5:7ca1:c92f with SMTP id
 c4-20020a056512324400b004d57ca1c92fls5577734lfr.2.-pod-prod-gmail; Wed, 18
 Jan 2023 07:21:32 -0800 (PST)
X-Received: by 2002:ac2:5636:0:b0:4cc:586b:1837 with SMTP id b22-20020ac25636000000b004cc586b1837mr1908403lff.16.1674055291989;
        Wed, 18 Jan 2023 07:21:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674055291; cv=none;
        d=google.com; s=arc-20160816;
        b=HMlj2xs0FP+09o2plbrApwgdTP4UPZHt0mkZQYXU2EeVr4VVNwjaYoPc3I+1NTKt2j
         J74bsGyIseRu4jBQtHff+qS8Z3Fz9ScTinwk9/i8HrRq1XITU9Iir5hF27BvG3iHYV9Q
         e2HNwGsbudJVQ4Dfrd+qh2OntNyEY9rIaCLHsEvHOUQKnR0e6qFJdTU3FjGtTXPLjjUB
         E48rdsoksx6fWvP9aW2Kn+HdD09O0kMTvrvwXMweLF9znllVi1MrxjfXCGksa6klM4AV
         96pmT9nHZNjhhOv/xfJVOz8DEBesZUdBWyWsto935f3BHieZBqNqiPQaUoQsmQmgYAw9
         9eKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bUZ7/JArP8z+4rS4rnPgS23ZvWHAJFne9obwi4+cVxA=;
        b=InBgrdTczoJLFkz86yIWVSz7T1DntH1H1hHtiWJQuea2+rKsPNp1am5lcM5Xsh1Lgd
         cMLi7xZ2GGn+9cczAbhPUQST1uAKIl0MvvSCB084Id1qNQNm5oluCsjtGygzzsZPMu5K
         h9k40zD2ZMTuKuGmq3xyYos7XxUusQpobCXR0xe2xBdZg2lL9pSpkL2mIVgnsenE78ZI
         1sNLlv9TvVxaNpBmteZldn3jfxsebgQ/jBz9irDFWcsfTV1drUej95Gtu0cRub906e5w
         7syj0jNAn4eBTsPiPM7VGg3vNjVWrucipLwSU942WU3OyRrqJ51aFY/CrD9NRwhug7zr
         qH6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZLFwbdFn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004b59c9b7fbdsi1476958lfi.7.2023.01.18.07.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 07:21:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id e16so10112740ljn.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 07:21:31 -0800 (PST)
X-Received: by 2002:a2e:a278:0:b0:276:4462:2d20 with SMTP id
 k24-20020a2ea278000000b0027644622d20mr414439ljm.19.1674055291581; Wed, 18 Jan
 2023 07:21:31 -0800 (PST)
MIME-Version: 1.0
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com>
 <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
 <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com> <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com>
In-Reply-To: <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Jan 2023 16:21:19 +0100
Message-ID: <CACT4Y+YYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV+ob_A@mail.gmail.com>
Subject: Re: kpatch and kasan
To: Joe Lawrence <joe.lawrence@redhat.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZLFwbdFn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d
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

On Wed, 18 Jan 2023 at 14:45, Joe Lawrence <joe.lawrence@redhat.com> wrote:
>
> On 1/18/23 02:21, Dmitry Vyukov wrote:
> > On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
> >>
> >> +kernel-dynamic-tools
> >>
> >> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
> >>>
> >>> Hi Kostya,
> >>>
> >>> I work on the kernel livepatching Kpatch project [1] and was hoping to
> >>> learn some info about compiler-generated (k)asan ELF sections.  If you
> >>> can point me to any references or folks who might entertain questions,
> >>> we would be much appreciated.
> >>>
> >>> The tl/dr; is that we would like to build kasan-enabled debug kernels
> >>> and then kpatches for them to help verify CVE mitigations.
> >>>
> >>> If you are unfamiliar with kpatch, it accepts an input .patch file,
> >>> builds a reference and patched kernel (with -ffunction-sections and
> >>> -fdata-sections) ... then performs a binary comparison between
> >>> reference/patched ELF sections.  New or changed ELF sections are
> >>> extracted into a new object file.  Boilerplate code is then added to
> >>> create a livepatch kernel module from that.
> >>>
> >>> The devil is in details, of course, so our kpatch-build tool needs to
> >>> know whether it should omit, copy, or re-generate an ELF section
> >>> depending on its purpose.  The kernel is rife with interesting sections
> >>> like para-virt instructions, jump labels, static call sites, etc.
> >>>
> >>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
> >>> data..LASAN0 from the gcc source code, I was wondering if these were
> >>> documented somewhere?
> >>>
> >>>
> >>> Regards,
> >>>
> >>> [1] https://github.com/dynup/kpatch
> >>> --
> >>> Joe
> >
> > +kasan-dev
> >
> > Hi Joe,
> >
> > But why not just build a new KASAN kernel and re-test? This looks so
> > much simpler.
> >
>
> Hi Dmitry,
>
> Well yes, testing an ordinary (fixed) kernel build is much easier, however:
>
> 1 - Sometimes kpatches deviate from their kernel counterparts.  Examples
> include ABI changes, fixups in initialization code, etc.

This does not prevent testing in a normal way, right? In fact I would
send the patch to the normal CI as the first thing.

> 2 - AFAICT, Kasan is the only part of our distro -debug kernel config
> that kpatch doesn't currently support.
>
> We could certainly live w/o it, but investigating how it works is the
> first step in scoping the effort.
>
> --
> Joe
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV%2Bob_A%40mail.gmail.com.
