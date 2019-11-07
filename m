Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDH3SDXAKGQEFRFWRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 84320F33C9
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 16:51:42 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id c17sf2116055pgm.14
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2019 07:51:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573141901; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBKPfSi63u16evsKu05Mxt0k+3E0RO3rI7AhEjmy1xbzN4S/m+jDF4xD0NS1zoNzt8
         k02lTIIiGivZjm5L0K1NOt/Nrff+KLAY3z9emjLfwbD17eZARrB1v2CgAADeDW0U9yNk
         QdUcAVCPV65PqjYKAIQwW35CkJsc+YeLhcBnMF4TK86jgWjFxg0A27MMR/h0yi4tqLuy
         taIYQVSidIzdOoE/ytxLOwy/CKWBVvSJ2bOxak2vUPCu3DlYkwgCHYdMW/EJqjGvYygX
         Z2NDWseyF8hA4s0aXH2bwhx7/ge6nBn4uEkdB/FhdjzUDIXh3MMpkwoVYXsXMu5i4mdU
         IZYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O+nA2XcNOOJFJkDYdQ7pHD9C1dnKRSjUrhzG2aDrCzs=;
        b=HgGitdj9n5b7DOoJ+aJhbKAxC1lRQbN0rTcYlkAkeB/io1KiN5neudJQu3h76H5FSC
         WhXzKb+lalydR9Rq7TtDLFfMQYtIb0wQ50+kvXuWodziEH5ac4wM0IdHoimhlHSVSSXn
         I/G3r381JXU7HAmMOtyST/ki+J11W5eP7IlFZ7F/9Cj09XhSjbKXI/15nhjmhWFnXJdK
         GuJjG35lGF2ABKf+hsT36AfykWQXyMVCMSiR0/JUBgOUF+Po+/SwIwGRu6Anmd94U7Uy
         i3gF5AeFA7gjAYtimKQXZYE9RwRSMh0oxMmHiPrg6TKcpNcXOYKQiZbxeu9zT/dmKYGT
         sacg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9sweo99;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O+nA2XcNOOJFJkDYdQ7pHD9C1dnKRSjUrhzG2aDrCzs=;
        b=WEDN1Bif6R+k91d3srwUsXw2FDayqGydmbBfXoYCdS0HXzYFVzJBpSOFbCjlXkCsFE
         bjnAPsGKav+TQkdqpYYaRfbDAVBJCHzTXWfiAT5lbNbn5sKIdhWtd/Fgk2HVeOtoDOHW
         bfQe9/27vcyKl5JUllPcKmzCiML2+/c7R5taiaoPWSOrHQqVy/Hbimq/dv8NnYRy28nc
         44uL/ylrr+JGzM1RjJ2SV5hC98JSwVxLGqJ4HcWo6OOJbSZNa93BbeJ+ZP72zRlkhp9J
         n7T7/R8N09Q2has1ZaagFg9hkr2xy4ecORQv+51f8ecFbl+AmIkfnuNduZOA/3aZvk7T
         hgPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O+nA2XcNOOJFJkDYdQ7pHD9C1dnKRSjUrhzG2aDrCzs=;
        b=KR7oP5BXPSD6BzIRYBeu4ZcrnZNfBz9b3gIi93dF76FIA4SQPxY7lwJ6IBsdekZOpN
         TyO9Pwz9zePCuPPbVj+wzoeoh955AZAeI4z9tw2qlOvMFnPtYnxbDftU9sNRVW1jdAiW
         GCcRhbl+5bqjSjlijsU5sZAo4c87+mVboc+BLiWRUmzfFe19ZBKF3vy02y7EnZH9NLT/
         xBSyRcD8lyna2a+Dit72UiKvsdIOs+PK+fxZjN4sg58ECBC4ErqwB+CCcJ4fHfsgIr6f
         3mO0Gayf6S20ueuMcT4PZbpdPdK24OvPaascN40yLmwg798dBHMeiTU0g5xpaW71vd+z
         LgZw==
X-Gm-Message-State: APjAAAW8av987nXgXhMScGiTJH5C/oiSZ+3Xb3sWQQGFAGDLjV+O45k7
	6rIAQrMwxtT4Fdio6RFtYZM=
X-Google-Smtp-Source: APXvYqyiqK/ZjX7i4nwfQLYgLw3zxL1Q5xlTUaO0E2pgfcFO1S1Y8Zu7fUKNviwEmnQZcc8K8Fp6jQ==
X-Received: by 2002:a63:d308:: with SMTP id b8mr5351694pgg.246.1573141900794;
        Thu, 07 Nov 2019 07:51:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa91:: with SMTP id d17ls1527840plr.2.gmail; Thu, 07
 Nov 2019 07:51:40 -0800 (PST)
X-Received: by 2002:a17:902:b713:: with SMTP id d19mr4465399pls.245.1573141900343;
        Thu, 07 Nov 2019 07:51:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573141900; cv=none;
        d=google.com; s=arc-20160816;
        b=uJCi/xjVm9d4oSEK774YFy0T80dZEVmE+Q1IyyquNXAxuDgnjcNysfmgyHsVMd2L9U
         RPt2dwBCNnEJAa2iFcuS+3KsUYZSRW4sqveBmuGIh5OqVagc3e2UA721lOfaHtC50hko
         QV5uX2X8d5wpDAJmxA0bbrZ9ZqyafwpDS3z3AuC1rZxX+MrcA428ICF52HhKP+XEY9EK
         s4pgbdbOGaGM7g0U5SDH/1RFssccI7J9ixnCcfOloPE0IwS18NWHMWOsVpQByp3RrxKA
         wFiK8/huL5B0TsPuNTshGaG+oThlIomYlZa8/pgACxmjHbU/55SuAkIvWkBf4Tial6QS
         Mcwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jOTezglOaklVHlvkULhknz7GAhfjNSPSn0bPm/UWWmk=;
        b=xlfI8g60e8J1MAVziVUKsr/Ig/mnwJ95vryebCEpHWw4oHXLOcw6ydPwFN9l/E/zLi
         Ulse1mn/atvi/FxdnqvcpEuL9ubXz7WtKzUM8ObajFHDdJ4/ENIpNFYadjTn5yKAV0xP
         IE2+mGKPpCiBOE1BNRtfFzcuzcqMmxyew1VmKLfLO47dIYDhWNLGzd2Fa4HLBPZZpKho
         QB1lsOZem0e1KLc64nGs0ZPhFm+pvkFB0J/V5UEFZVwoM1UfMXXgZariISTXgJA4Z/YP
         6O+Ne+91HctlrMMsbJhydsB/Z7PbuFBFCTAWRpiPb/dUhAr3yOy5gIFWoh54pmaNyi9N
         Qy8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9sweo99;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id g15si174071plq.0.2019.11.07.07.51.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2019 07:51:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id f19so2333696pgk.11
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2019 07:51:40 -0800 (PST)
X-Received: by 2002:a62:53c6:: with SMTP id h189mr1817597pfb.93.1573141899602;
 Thu, 07 Nov 2019 07:51:39 -0800 (PST)
MIME-Version: 1.0
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
 <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
 <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com> <e5ff9f02-42aa-2515-29ed-837f8c299d26@arm.com>
In-Reply-To: <e5ff9f02-42aa-2515-29ed-837f8c299d26@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2019 16:51:28 +0100
Message-ID: <CAAeHK+zEg9a=TuObFNgPsyo+uidut4p5Xw2Xoy8x9m35Do=SAg@mail.gmail.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
To: Matthew Malcomson <Matthew.Malcomson@arm.com>, Evgenii Stepanov <eugenis@google.com>
Cc: "kcc@google.com" <kcc@google.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>, Martin Liska <mliska@suse.cz>, 
	Richard Earnshaw <Richard.Earnshaw@arm.com>, Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, 
	"dodji@redhat.com" <dodji@redhat.com>, "jakub@redhat.com" <jakub@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K9sweo99;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Nov 7, 2019 at 1:48 PM Matthew Malcomson
<Matthew.Malcomson@arm.com> wrote:
>
> On 05/11/2019 13:11, Andrey Konovalov wrote:
> > On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson
> > <Matthew.Malcomson@arm.com> wrote:
> >>
> >> NOTE:
> >> ------
> >> I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
> >> automatically defined when compiling with hwasan.  This is analogous to
> >> __SANITIZE_ADDRESS__ which is defined when compiling with asan.
> >>
> >> Users in the kernel have expressed an interest in using
> >> __SANITIZE_ADDRESS__ for both
> >> (https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/690703.html).
> >>
> >> One approach to do this could be to define __SANITIZE_ADDRESS__ with
> >> different values depending on whether we are compiling with hwasan or
> >> asan.
> >>
> >> Using __SANITIZE_ADDRESS__ for both means that code like the kernel
> >> which wants to treat the two sanitizers as alternate implementations of
> >> the same thing gets that automatically.
> >>
> >> My preference is to use __SANITIZE_HWADDRESS__ since that means any
> >> existing code will not be predicated on this (and hence I guess less
> >> surprises), but would appreciate feedback on this given the point above.
> >
> > +Evgenii Stepanov
> >
> > (A repost from my answer from the mentioned thread):
> >
> >> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan
> >> equivalent of no_sanitize_address, which will require an update in the
> >> kernel given it seems you want KASAN to be used the same whether using
> >> tags or not.
> >
> > We have intentionally reused the same macros to simplify things. Is
> > there any reason to use separate macros for GCC? Are there places
> > where we need to use specifically no_sanitize_hwaddress and
> > __SANITIZE_HWADDRESS__, but not no_sanitize_address and
> > __SANITIZE_ADDRESS__?
> >
> >
>
> I've just looked through some open source repositories (via github
> search) that used the existing __SANITIZE_ADDRESS__ macro.
>
> There are a few repos that would want to use a feature macro for hwasan
> or asan in the exact same way as each other, but of the 31 truly
> different uses I found, 11 look like they would need to distinguish
> between hwasan and asan (where 4 uses I found I couldn't easily tell)
>
> NOTE
> - This is a count of unique uses, ignoring those repos which use a file
> from another repo.
> - I'm just giving links to the first of the relevant kind that I found,
> not putting effort into finding the "canonical" source of each repository.
>
>
> Places that need distinction (and their reasons):
>
> There are quite a few that use the ASAN_POISON_MEMORY_REGION and
> ASAN_UNPOISON_MEMORY_REGION macros to poison/unpoison memory themselves.
>   This abstraction doesn't quite make sense in a hwasan environment, as
> there is not really a "poisoned/unpoisoned" concept.
>
> https://github.com/laurynas-biveinis/unodb
> https://github.com/darktable-org/rawspeed
> https://github.com/MariaDB/server
> https://github.com/ralfbrown/framepac-ng
> https://github.com/peters/aom
> https://github.com/pspacek/knot-resolver-docker-fix
> https://github.com/harikrishnan94/sheap
>
>
> Some use it to record their compilation "type" as `-fsanitize=address`
> https://github.com/wallix/redemption
>
> Or to decide to set the environment variable ASAN_OPTIONS
> https://github.com/dephonatine/VBox5.2.18
>
> Others worry about stack space due to asan's redzones (hwasan has a much
> smaller stack memory overhead).
> https://github.com/fastbuild/fastbuild
> https://github.com/scylladb/seastar
> (n.b. seastar has a lot more conditioned code that would be the same
> between asan and hwasan).
>
>
> Each of these needs to know the difference between compiling with asan
> and hwasan, so I'm confident that having some way to determine that in
> the source code is a good idea.
>
>
> I also believe there could be code in the wild that would need to
> distinguish between hwasan and asan where the existence of tags could be
> problematic:
>
> - code already using the top-byte-ignore feature may be able to be used
> with asan but not hwasan.
> - Code that makes assumptions about pointer ordering (e.g. the autoconf
> program that looks for stack growth direction) could break on hwasan but
> not on asan.
> - Code looking for the distance between two objects in memory would need
> to account for tags in pointers.
>
>
> Hence I think this distinction is needed.

Evgenii, how does clang-compiled code dististinguishes whether it's
being compiled with ASAN or HWASAN?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzEg9a%3DTuObFNgPsyo%2Buidut4p5Xw2Xoy8x9m35Do%3DSAg%40mail.gmail.com.
