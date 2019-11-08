Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6PHSXXAKGQEQR2XFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 69DA0F4D98
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2019 14:56:11 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id w16sf4981775pfq.14
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2019 05:56:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573221369; cv=pass;
        d=google.com; s=arc-20160816;
        b=F27HaLkgkZAdmarw/mIMClc/ML+9x0DofrrRrsqV+T0nBiIAGE7TgReGyXue+Z6ao3
         7M4zJcUYz3B0wM3Y8ussZn0B0Q99v5FbmyQ6uDDeZXRaWsOsvk9B3oHataKFU6VU5w5N
         9RxmcGI4plqfkiadK3k2PruJ3dwrNXiY61wTIxAcFphCN5q2eAX5iviQVXoQ3qEnAfjo
         /4Z6o/ZW/mifkvASZdAtADxnHRpzLP9DZkT1/gXBdaZRhpsmPMG6cSpvJJlMb/4sdjJ4
         Wr4uY6MpXjrnc9Py6HSyGZ9xqyEUn34bUDHd9eDMTorcZ0HKzrKEzPf7e0h7IksRawHg
         x9PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yu1sZwHukFIflBBCsDvNguMLK2V9uLs2C8zSn/DEomU=;
        b=jpBXQjNpLaK/NlBxRT2VGJjkDF58gGQz7fOTAmWapinnc7QUxLV0rCVt8mYk55frEr
         XoaMxYzfj4DZomgd5e08IFldZpLNbBjXrAjPoePy3CENJ7DAk/o8XkspGLNlSz+zoCml
         nx/T4TcWW14i0+Npfw8c2CBFMjvY3sbBTOFbk4rf/G7h0NapszSvxC8o0ZmXnJG420zc
         k5/oic8e5xQhWCxaDMe2bWe89Gxt6ZU8DHj70ZCBCEdoQst5l48l9JTiUUPW+KHQ5T+S
         SdKSRbu+zmEx39i42jA3Ihz1S4YhCNUmXTgT6G9Gmemzc0W7UCi/M+6qkgPEH/fVdnXP
         9POw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqyxkQrc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Yu1sZwHukFIflBBCsDvNguMLK2V9uLs2C8zSn/DEomU=;
        b=h6HTf5htLbRKhqp55NNV4dGAZTxqhWg/zh1e/ys4yoAai2xpugWW/17ooAAZyt1ONf
         hWj0IInKWlcR0dVKY5Id6Lyco2nMtdOf/guW71v9WSvIJkPV2nqrDGH+bNsq86ZXP3S8
         DQSthZNfJ28+Emtgoe+CxZn9FSI7pJmZ89ImxJO84e1421lncZWPRX1bqHiIf+6/s9lG
         slEF78Kjx3/FFrUoEcnkJf0KzQzgSzjn1uymyzZauS8EJXm8gZnGPk9jJriQb+Ue9Y2+
         dech0vHMuyj/sCJY6epkyrpCwElRKH0N3X3DTqCX5FYT8wklbRNaph8MxCGRv6uBbGkI
         HodQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yu1sZwHukFIflBBCsDvNguMLK2V9uLs2C8zSn/DEomU=;
        b=Ke8/a82Q3qj6FqOjG1b0S3UWYU3E9XgRlFwCxA2wse4lkoCAIpT/dpvmuDbBUPyNJW
         JUdX4k5liVf7EJ935XUvBkUOs+QZP52ToikpE9w0VP+VVPAbMgXoKo5RoLGznm5ODnSw
         qL1L4qSsq2/A0itf8cXjb+3GiSfH/qxeMl25Wu+neRRZdka8jeAO/d8JtEZWqa91ZjST
         TWztwnJlkFBdmcyZbxxsYXJGACFcXZHA3iHvc1fN70W/hLAZHWvt+2PqptIYHNC7Pwu8
         aEhH4minmd7UFesXm4n/H0txBaKSY4J0ZsfY9JP29bLuDedIPbPKxU1Hx92xPRgKANmt
         3N8Q==
X-Gm-Message-State: APjAAAVta+BbJ4j5hRNzqoKohZfFEKI4wrtWaA3BnMhdscLSSbJhtr0e
	QwIOkKJzQgE0ulrLuLBtk2c=
X-Google-Smtp-Source: APXvYqz1eWMroiTLVqjBh4Nwmg9p4A7fnspobVedFClBxw8EdiPNL53RzPTkhVZxL7cBRshmDS9HkQ==
X-Received: by 2002:a17:902:ac84:: with SMTP id h4mr10889003plr.171.1573221369534;
        Fri, 08 Nov 2019 05:56:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb07:: with SMTP id z7ls2473334pjt.2.gmail; Fri, 08
 Nov 2019 05:56:09 -0800 (PST)
X-Received: by 2002:a17:90a:7109:: with SMTP id h9mr10506761pjk.54.1573221369132;
        Fri, 08 Nov 2019 05:56:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573221369; cv=none;
        d=google.com; s=arc-20160816;
        b=piq17ahqp6dgBruyGMlBgBQ0RGtXwCUGb8Zip8+KItObVcQxdyW1GjCVDlbGCU3SjY
         B8F/QiYXObBqGOZ2fpX0ec4r5T2B/VhC+RN2X5CDz+sI/nmHJJISzKCMJ+Dw78oW0enZ
         58WqTfSLHwGwmdAsJhZhNaguaZdrDoSJr+ecFTeC6mP62f5pYXhLKWzmCR1/08bZEIbu
         G1/SsbCFga6AWfF8mCIrMpVHG5lDUQTDEEP41JaG/qvNy4SvkFMQp3wmYqYfNWFieiDc
         G+vMG+ryirux32ue1an7VSAq2fBYy5cK7IA8lHy6tI1K8aniIEWRRol0LPoldToC7X+P
         NKug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tsoFT3PjW0gh+daJazovt0eZFUdwVUuxR2oYujqJlbY=;
        b=RHvzwcb5r/5rrgR15d13ICqvGO9ef1lqwc04XXC8WMuevHh5xjAXeWn+HHdGcVOeAK
         upXcpY7+kihGjEylDHYUyfbcqUqEL51mwnSjLz+wTMfREfbO2wuBrWnAUXqECNuNF5VQ
         +5zYrWaLI7K/hVZfw2ajzmdUaU8REvX5zeN54tM4tFtvVKIC6FH/asZnac3TW/J+s1gU
         npuG9HQEhOT6/3BHx7B7loiCzzldDlYZJtpOa72ONKVlLYaWpd/r9cy/eWxY4GDmztCe
         +XD9UGUV8hvymosvXZz2nOkRMw7dXQnu0w45JmGB7f7WdG8yB8zEmQ/T949jURGPyMDc
         Jc4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqyxkQrc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id t17si226644pgk.0.2019.11.08.05.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Nov 2019 05:56:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id p26so4607935pfq.8
        for <kasan-dev@googlegroups.com>; Fri, 08 Nov 2019 05:56:09 -0800 (PST)
X-Received: by 2002:a17:90a:1f4b:: with SMTP id y11mr13640979pjy.123.1573221368375;
 Fri, 08 Nov 2019 05:56:08 -0800 (PST)
MIME-Version: 1.0
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
 <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
 <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com>
 <e5ff9f02-42aa-2515-29ed-837f8c299d26@arm.com> <CAAeHK+zEg9a=TuObFNgPsyo+uidut4p5Xw2Xoy8x9m35Do=SAg@mail.gmail.com>
 <CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB+LF2uMdMd7AK8w@mail.gmail.com>
In-Reply-To: <CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB+LF2uMdMd7AK8w@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Nov 2019 14:55:57 +0100
Message-ID: <CAAeHK+xTSamsj6MonzEcc6mijwHcEb=kNPSu8ncaCDOVBf3Mzg@mail.gmail.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
To: Evgenii Stepanov <eugenis@google.com>
Cc: Matthew Malcomson <Matthew.Malcomson@arm.com>, "kcc@google.com" <kcc@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>, 
	Martin Liska <mliska@suse.cz>, Richard Earnshaw <Richard.Earnshaw@arm.com>, 
	Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, "dodji@redhat.com" <dodji@redhat.com>, 
	"jakub@redhat.com" <jakub@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eqyxkQrc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
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

OK, let's keep the macros district then. In the kernel it doesn't give
you a lot, since you actually know which ASAN you're using based on
the kernel CONFIG_ values, but looks like it's important for
userspace. Thanks!

On Thu, Nov 7, 2019 at 7:01 PM Evgenii Stepanov <eugenis@google.com> wrote:
>
> Clang has a function level attribute,
>   __attribute__((no_sanitize("hwaddress")))
> a feature macro
>   #if __has_feature(hwaddress_sanitizer)
> and a blacklist section
>   [hwaddress]
>   https://clang.llvm.org/docs/SanitizerSpecialCaseList.html
>
> I think it makes sense for the compiler to err on the side of not losing =
information and provide distinct macros for these two sanitizers. If the ke=
rnel does not care about the difference, they can add a simple #ifdef. They=
 would need to, anyway, because gcc does not have feature macros and clang =
does not define __SANITIZE_ADDRESS__.
>
>
> On Thu, Nov 7, 2019 at 7:51 AM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>>
>> On Thu, Nov 7, 2019 at 1:48 PM Matthew Malcomson
>> <Matthew.Malcomson@arm.com> wrote:
>> >
>> > On 05/11/2019 13:11, Andrey Konovalov wrote:
>> > > On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson
>> > > <Matthew.Malcomson@arm.com> wrote:
>> > >>
>> > >> NOTE:
>> > >> ------
>> > >> I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
>> > >> automatically defined when compiling with hwasan.  This is analogou=
s to
>> > >> __SANITIZE_ADDRESS__ which is defined when compiling with asan.
>> > >>
>> > >> Users in the kernel have expressed an interest in using
>> > >> __SANITIZE_ADDRESS__ for both
>> > >> (https://lists.infradead.org/pipermail/linux-arm-kernel/2019-Octobe=
r/690703.html).
>> > >>
>> > >> One approach to do this could be to define __SANITIZE_ADDRESS__ wit=
h
>> > >> different values depending on whether we are compiling with hwasan =
or
>> > >> asan.
>> > >>
>> > >> Using __SANITIZE_ADDRESS__ for both means that code like the kernel
>> > >> which wants to treat the two sanitizers as alternate implementation=
s of
>> > >> the same thing gets that automatically.
>> > >>
>> > >> My preference is to use __SANITIZE_HWADDRESS__ since that means any
>> > >> existing code will not be predicated on this (and hence I guess les=
s
>> > >> surprises), but would appreciate feedback on this given the point a=
bove.
>> > >
>> > > +Evgenii Stepanov
>> > >
>> > > (A repost from my answer from the mentioned thread):
>> > >
>> > >> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasa=
n
>> > >> equivalent of no_sanitize_address, which will require an update in =
the
>> > >> kernel given it seems you want KASAN to be used the same whether us=
ing
>> > >> tags or not.
>> > >
>> > > We have intentionally reused the same macros to simplify things. Is
>> > > there any reason to use separate macros for GCC? Are there places
>> > > where we need to use specifically no_sanitize_hwaddress and
>> > > __SANITIZE_HWADDRESS__, but not no_sanitize_address and
>> > > __SANITIZE_ADDRESS__?
>> > >
>> > >
>> >
>> > I've just looked through some open source repositories (via github
>> > search) that used the existing __SANITIZE_ADDRESS__ macro.
>> >
>> > There are a few repos that would want to use a feature macro for hwasa=
n
>> > or asan in the exact same way as each other, but of the 31 truly
>> > different uses I found, 11 look like they would need to distinguish
>> > between hwasan and asan (where 4 uses I found I couldn't easily tell)
>> >
>> > NOTE
>> > - This is a count of unique uses, ignoring those repos which use a fil=
e
>> > from another repo.
>> > - I'm just giving links to the first of the relevant kind that I found=
,
>> > not putting effort into finding the "canonical" source of each reposit=
ory.
>> >
>> >
>> > Places that need distinction (and their reasons):
>> >
>> > There are quite a few that use the ASAN_POISON_MEMORY_REGION and
>> > ASAN_UNPOISON_MEMORY_REGION macros to poison/unpoison memory themselve=
s.
>> >   This abstraction doesn't quite make sense in a hwasan environment, a=
s
>> > there is not really a "poisoned/unpoisoned" concept.
>> >
>> > https://github.com/laurynas-biveinis/unodb
>> > https://github.com/darktable-org/rawspeed
>> > https://github.com/MariaDB/server
>> > https://github.com/ralfbrown/framepac-ng
>> > https://github.com/peters/aom
>> > https://github.com/pspacek/knot-resolver-docker-fix
>> > https://github.com/harikrishnan94/sheap
>> >
>> >
>> > Some use it to record their compilation "type" as `-fsanitize=3Daddres=
s`
>> > https://github.com/wallix/redemption
>> >
>> > Or to decide to set the environment variable ASAN_OPTIONS
>> > https://github.com/dephonatine/VBox5.2.18
>> >
>> > Others worry about stack space due to asan's redzones (hwasan has a mu=
ch
>> > smaller stack memory overhead).
>> > https://github.com/fastbuild/fastbuild
>> > https://github.com/scylladb/seastar
>> > (n.b. seastar has a lot more conditioned code that would be the same
>> > between asan and hwasan).
>> >
>> >
>> > Each of these needs to know the difference between compiling with asan
>> > and hwasan, so I'm confident that having some way to determine that in
>> > the source code is a good idea.
>> >
>> >
>> > I also believe there could be code in the wild that would need to
>> > distinguish between hwasan and asan where the existence of tags could =
be
>> > problematic:
>> >
>> > - code already using the top-byte-ignore feature may be able to be use=
d
>> > with asan but not hwasan.
>> > - Code that makes assumptions about pointer ordering (e.g. the autocon=
f
>> > program that looks for stack growth direction) could break on hwasan b=
ut
>> > not on asan.
>> > - Code looking for the distance between two objects in memory would ne=
ed
>> > to account for tags in pointers.
>> >
>> >
>> > Hence I think this distinction is needed.
>>
>> Evgenii, how does clang-compiled code dististinguishes whether it's
>> being compiled with ASAN or HWASAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2BxTSamsj6MonzEcc6mijwHcEb%3DkNPSu8ncaCDOVBf3Mzg%40mail.gm=
ail.com.
