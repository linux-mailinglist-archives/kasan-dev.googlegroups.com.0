Return-Path: <kasan-dev+bncBCJZXCHARQJRB7VXSHXAKGQE2GGWUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3B6F3681
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 19:01:35 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id q78sf2610158oic.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2019 10:01:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573149694; cv=pass;
        d=google.com; s=arc-20160816;
        b=N5cT8rmbpXOjZntFfgkDAz9cMSshMWIjyItGkCnQM1Y2HYHNUX7B9gEur7+TbSkTG4
         XjuJeAQeKqaEuJ6PoIRqCemCxUXMvpuLBy9PzefVYAh/6S3Wkq44GjgJSuvy1uY7JPdV
         uYFaZMJVpNQe6kcbNOxojEVzzmdCeItIsKOIobn+N575QzVNRkYCMcia5MxUjDV5/6Cc
         RvUQehvShkQfYnfPoM3ATujh6KRX5ctPbG9daEwpym/Jl5D0JlHkx3cI8wXoFkVE0ud4
         AGc5yyjoTHM/U6tAqaYWeOkexagQV2UrzHFg3ffetpbtNzaGey5+urwjJMlgA1ibrOdq
         3byg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lm2V3BrGF5cI/nb6+iGHnSHU4eGVgYlUfCKV0mYtrx0=;
        b=YLKat09JqJwKGp6Df+Tm3AkqfGWyG+QLuHfZ/OE1ccNK/1+pWk9x8xZ/0u2Oniakng
         tdMGS1g2Y6N0+opPkQnVa+lwS/j1KgNW6RwYfUw3jWN0/74/1KhtkK3ZGeQ13xtKbTwB
         ZXOCadnAgzfAfgGiKrm1YawIfEx9kWrnTs0PtGeFlGTJCe5fJJyep//c7HIxpA27PdD0
         wCFvYWJvuCvmdKB975WVwsHnwwdq516J93RyYvacrcnIrkkXNRQq82rb4u9eLHix65E6
         wyWbfPRCVKOxyrjvg1+3CKzgWKjWCLXntuwZLnsWOxSalGK3h9H6ZHFjSJX14yAhzSdU
         7SQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kuJMfhYI;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::a43 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lm2V3BrGF5cI/nb6+iGHnSHU4eGVgYlUfCKV0mYtrx0=;
        b=ORDr4nzP354PuiqpoDa49nzKXRSJDN8SIzWkd/fGvV9FRpOi9055RbhQ52hZEJF3BA
         DDrzMHZqMtvxQa9P1D93IrCtpJQ30r0k40AuPRvQ2KLbDOSvz2YEGm/LBk8UXrIFtlDo
         kk5+bi9xR3se+IjPzHB2T1Hve1jSPUxxlMTlR20k2y85KYBaKv5DZ1zljgNifE/gaSn0
         lRg5D/fKUSTOB04TuYUX2Tc3mA79xYkVonX9iZcRJAJHWspY515fT20CR3h3YQ/dREP2
         uz4+l/nEY8xIimpGBxfk+/XTsIcsHfqAIqtMOLRT42LOaSDJmxdrjwOUKD+fBIqXSqNo
         wZbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lm2V3BrGF5cI/nb6+iGHnSHU4eGVgYlUfCKV0mYtrx0=;
        b=rylAwk7lf+Pru8YULWytlZ9X4nKwfkcU4lwag7tj1zAYNWwgqiic23TYKGw4i1e9vj
         WAHm1XRdg1pMnRYY5DNPSgSW3G9X3duxRNvpT9hVSrBoZqB6hAlq0wkSxuOn3QjAstJy
         6y7vMX6PvoX/d4I+na1FgvReWzlLgIWN4zsOy8oub2D1mOlHNh4CxY+C1POGdf6/6NY+
         q5LjwCr+0nEpxqQClJT5M4bQoGxHut9UOsZRHhFC1jFu1TbE4xXS2elZfLng+h8spkJn
         rUAJFsyUYVqC0728mg9qQLWIZ6ogHp9bDBrlOlpM+ZtBJs0qw7Jq3pA7xwyfHeOtObG1
         rvPg==
X-Gm-Message-State: APjAAAX6uJTbt9iYeYX1JbDuJEQQCbl9PEG/2fUQOfvGtkVzLGAuPJdR
	/NMexHmM+W2mWFUVJmqzaCM=
X-Google-Smtp-Source: APXvYqy91J8UDbuH8MMv4fn5qtdm/DTln7RD9hnpIYNG7uTn3MlC3qPDogItNLZx3iwcuVriVjcgRg==
X-Received: by 2002:aca:1e14:: with SMTP id m20mr2917531oic.20.1573149694379;
        Thu, 07 Nov 2019 10:01:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3843:: with SMTP id f64ls1651706oia.12.gmail; Thu, 07
 Nov 2019 10:01:34 -0800 (PST)
X-Received: by 2002:aca:2417:: with SMTP id n23mr590742oic.25.1573149693927;
        Thu, 07 Nov 2019 10:01:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573149693; cv=none;
        d=google.com; s=arc-20160816;
        b=tYB3HCYZO10rDlImgvcyGze3QNWDOx6k2yTkuv+0vKpaSLSwK0bP9rNSHZHH3/Fzv0
         /05MsshptKhScCzUmzEmB3jLdaXM1nANP7nhaLImay1Ll5Rs6C9p7WfsgBWyrK8MwO/y
         SG8YR5BYcI3WtEt+cFQyA8htk2P8+l8P6uT/bh5qAsXW0znv3K04PRpqLyJfTnCwHBfn
         UAqezh7V0OTgL1RS2ZYgwa1LiN4wD69X03ANv+XKzSf73UJIOv9D72EcDySwQO/05rIw
         pUGWteO3fAyEGoQu4k/6vONSocxqba88XDiisISAxcT8Zl77tTNcdk80Q0VusBzcO1td
         Tzwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=00c7aI1GTxx4fN3tEHNQPwx1grQE0QkxZu7uXBYDJTU=;
        b=xZxEOv22B91Z46Cal9fCLh/n1VRz20g08itPCkMW+0iK69ef7uuSuybYMyqU/gS9hK
         Zfc2ayreztmjr9CL9QMxDipw+jKC+MaXVm2DU/E5fTgVoKyk7zRoRON9O0jYzEAGevZA
         5b1874Bq0zD+LHmAFGQ+jnhzCBxXpRzYoXOL7nBqAw4VPLbLr9blFz/FpdJkxYZc4OrT
         b/nWkAhrhF0TPGofSrLYCNvlIjZvPmH9PrKiyHR0i49vZOlsyzNoE3lZ2ysZYN//+sy9
         S+pJ1pQkIThx2v/3qRqZbvRRb226fGcgRfbfP3a3tZHa/0RoGxdJUDl0U3EmfVTRbw0Y
         nNGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kuJMfhYI;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::a43 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa43.google.com (mail-vk1-xa43.google.com. [2607:f8b0:4864:20::a43])
        by gmr-mx.google.com with ESMTPS id m23si189353oic.1.2019.11.07.10.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2019 10:01:33 -0800 (PST)
Received-SPF: pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::a43 as permitted sender) client-ip=2607:f8b0:4864:20::a43;
Received: by mail-vk1-xa43.google.com with SMTP id o198so797033vko.11
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2019 10:01:33 -0800 (PST)
X-Received: by 2002:a1f:c441:: with SMTP id u62mr3768978vkf.88.1573149692822;
 Thu, 07 Nov 2019 10:01:32 -0800 (PST)
MIME-Version: 1.0
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
 <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
 <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com>
 <e5ff9f02-42aa-2515-29ed-837f8c299d26@arm.com> <CAAeHK+zEg9a=TuObFNgPsyo+uidut4p5Xw2Xoy8x9m35Do=SAg@mail.gmail.com>
In-Reply-To: <CAAeHK+zEg9a=TuObFNgPsyo+uidut4p5Xw2Xoy8x9m35Do=SAg@mail.gmail.com>
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2019 10:01:21 -0800
Message-ID: <CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB+LF2uMdMd7AK8w@mail.gmail.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Matthew Malcomson <Matthew.Malcomson@arm.com>, "kcc@google.com" <kcc@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>, 
	Martin Liska <mliska@suse.cz>, Richard Earnshaw <Richard.Earnshaw@arm.com>, 
	Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, "dodji@redhat.com" <dodji@redhat.com>, 
	"jakub@redhat.com" <jakub@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="0000000000009efb120596c57434"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kuJMfhYI;       spf=pass
 (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::a43
 as permitted sender) smtp.mailfrom=eugenis@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

--0000000000009efb120596c57434
Content-Type: text/plain; charset="UTF-8"

Clang has a function level attribute,
  __attribute__((no_sanitize("hwaddress")))
a feature macro
  #if __has_feature(hwaddress_sanitizer)
and a blacklist section
  [hwaddress]
  https://clang.llvm.org/docs/SanitizerSpecialCaseList.html

I think it makes sense for the compiler to err on the side of not losing
information and provide distinct macros for these two sanitizers. If the
kernel does not care about the difference, they can add a simple #ifdef.
They would need to, anyway, because gcc does not have feature macros and
clang does not define __SANITIZE_ADDRESS__.


On Thu, Nov 7, 2019 at 7:51 AM Andrey Konovalov <andreyknvl@google.com>
wrote:

> On Thu, Nov 7, 2019 at 1:48 PM Matthew Malcomson
> <Matthew.Malcomson@arm.com> wrote:
> >
> > On 05/11/2019 13:11, Andrey Konovalov wrote:
> > > On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson
> > > <Matthew.Malcomson@arm.com> wrote:
> > >>
> > >> NOTE:
> > >> ------
> > >> I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
> > >> automatically defined when compiling with hwasan.  This is analogous
> to
> > >> __SANITIZE_ADDRESS__ which is defined when compiling with asan.
> > >>
> > >> Users in the kernel have expressed an interest in using
> > >> __SANITIZE_ADDRESS__ for both
> > >> (
> https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/690703.html
> ).
> > >>
> > >> One approach to do this could be to define __SANITIZE_ADDRESS__ with
> > >> different values depending on whether we are compiling with hwasan or
> > >> asan.
> > >>
> > >> Using __SANITIZE_ADDRESS__ for both means that code like the kernel
> > >> which wants to treat the two sanitizers as alternate implementations
> of
> > >> the same thing gets that automatically.
> > >>
> > >> My preference is to use __SANITIZE_HWADDRESS__ since that means any
> > >> existing code will not be predicated on this (and hence I guess less
> > >> surprises), but would appreciate feedback on this given the point
> above.
> > >
> > > +Evgenii Stepanov
> > >
> > > (A repost from my answer from the mentioned thread):
> > >
> > >> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan
> > >> equivalent of no_sanitize_address, which will require an update in the
> > >> kernel given it seems you want KASAN to be used the same whether using
> > >> tags or not.
> > >
> > > We have intentionally reused the same macros to simplify things. Is
> > > there any reason to use separate macros for GCC? Are there places
> > > where we need to use specifically no_sanitize_hwaddress and
> > > __SANITIZE_HWADDRESS__, but not no_sanitize_address and
> > > __SANITIZE_ADDRESS__?
> > >
> > >
> >
> > I've just looked through some open source repositories (via github
> > search) that used the existing __SANITIZE_ADDRESS__ macro.
> >
> > There are a few repos that would want to use a feature macro for hwasan
> > or asan in the exact same way as each other, but of the 31 truly
> > different uses I found, 11 look like they would need to distinguish
> > between hwasan and asan (where 4 uses I found I couldn't easily tell)
> >
> > NOTE
> > - This is a count of unique uses, ignoring those repos which use a file
> > from another repo.
> > - I'm just giving links to the first of the relevant kind that I found,
> > not putting effort into finding the "canonical" source of each
> repository.
> >
> >
> > Places that need distinction (and their reasons):
> >
> > There are quite a few that use the ASAN_POISON_MEMORY_REGION and
> > ASAN_UNPOISON_MEMORY_REGION macros to poison/unpoison memory themselves.
> >   This abstraction doesn't quite make sense in a hwasan environment, as
> > there is not really a "poisoned/unpoisoned" concept.
> >
> > https://github.com/laurynas-biveinis/unodb
> > https://github.com/darktable-org/rawspeed
> > https://github.com/MariaDB/server
> > https://github.com/ralfbrown/framepac-ng
> > https://github.com/peters/aom
> > https://github.com/pspacek/knot-resolver-docker-fix
> > https://github.com/harikrishnan94/sheap
> >
> >
> > Some use it to record their compilation "type" as `-fsanitize=address`
> > https://github.com/wallix/redemption
> >
> > Or to decide to set the environment variable ASAN_OPTIONS
> > https://github.com/dephonatine/VBox5.2.18
> >
> > Others worry about stack space due to asan's redzones (hwasan has a much
> > smaller stack memory overhead).
> > https://github.com/fastbuild/fastbuild
> > https://github.com/scylladb/seastar
> > (n.b. seastar has a lot more conditioned code that would be the same
> > between asan and hwasan).
> >
> >
> > Each of these needs to know the difference between compiling with asan
> > and hwasan, so I'm confident that having some way to determine that in
> > the source code is a good idea.
> >
> >
> > I also believe there could be code in the wild that would need to
> > distinguish between hwasan and asan where the existence of tags could be
> > problematic:
> >
> > - code already using the top-byte-ignore feature may be able to be used
> > with asan but not hwasan.
> > - Code that makes assumptions about pointer ordering (e.g. the autoconf
> > program that looks for stack growth direction) could break on hwasan but
> > not on asan.
> > - Code looking for the distance between two objects in memory would need
> > to account for tags in pointers.
> >
> >
> > Hence I think this distinction is needed.
>
> Evgenii, how does clang-compiled code dististinguishes whether it's
> being compiled with ASAN or HWASAN?
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB%2BLF2uMdMd7AK8w%40mail.gmail.com.

--0000000000009efb120596c57434
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Clang has a function level attribute,<div>=C2=A0 __attribu=
te__((no_sanitize(&quot;hwaddress&quot;)))</div><div>a feature macro</div><=
div>=C2=A0 #if __has_feature(hwaddress_sanitizer)</div><div>and a blacklist=
 section</div><div>=C2=A0 [hwaddress]</div><div>=C2=A0=C2=A0<a href=3D"http=
s://clang.llvm.org/docs/SanitizerSpecialCaseList.html">https://clang.llvm.o=
rg/docs/SanitizerSpecialCaseList.html</a><br></div><div><br></div><div>I th=
ink it makes sense for the compiler to err on the side of not losing inform=
ation and provide distinct macros for these two sanitizers. If the kernel d=
oes not care about the difference, they can add a simple #ifdef. They would=
 need to, anyway, because gcc does not have feature macros and clang does n=
ot define __SANITIZE_ADDRESS__.</div><div><br></div></div><br><div class=3D=
"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, Nov 7, 2019 at =
7:51 AM Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com">andre=
yknvl@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" =
style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);pa=
dding-left:1ex">On Thu, Nov 7, 2019 at 1:48 PM Matthew Malcomson<br>
&lt;<a href=3D"mailto:Matthew.Malcomson@arm.com" target=3D"_blank">Matthew.=
Malcomson@arm.com</a>&gt; wrote:<br>
&gt;<br>
&gt; On 05/11/2019 13:11, Andrey Konovalov wrote:<br>
&gt; &gt; On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson<br>
&gt; &gt; &lt;<a href=3D"mailto:Matthew.Malcomson@arm.com" target=3D"_blank=
">Matthew.Malcomson@arm.com</a>&gt; wrote:<br>
&gt; &gt;&gt;<br>
&gt; &gt;&gt; NOTE:<br>
&gt; &gt;&gt; ------<br>
&gt; &gt;&gt; I have defined a new macro of __SANITIZE_HWADDRESS__ that get=
s<br>
&gt; &gt;&gt; automatically defined when compiling with hwasan.=C2=A0 This =
is analogous to<br>
&gt; &gt;&gt; __SANITIZE_ADDRESS__ which is defined when compiling with asa=
n.<br>
&gt; &gt;&gt;<br>
&gt; &gt;&gt; Users in the kernel have expressed an interest in using<br>
&gt; &gt;&gt; __SANITIZE_ADDRESS__ for both<br>
&gt; &gt;&gt; (<a href=3D"https://lists.infradead.org/pipermail/linux-arm-k=
ernel/2019-October/690703.html" rel=3D"noreferrer" target=3D"_blank">https:=
//lists.infradead.org/pipermail/linux-arm-kernel/2019-October/690703.html</=
a>).<br>
&gt; &gt;&gt;<br>
&gt; &gt;&gt; One approach to do this could be to define __SANITIZE_ADDRESS=
__ with<br>
&gt; &gt;&gt; different values depending on whether we are compiling with h=
wasan or<br>
&gt; &gt;&gt; asan.<br>
&gt; &gt;&gt;<br>
&gt; &gt;&gt; Using __SANITIZE_ADDRESS__ for both means that code like the =
kernel<br>
&gt; &gt;&gt; which wants to treat the two sanitizers as alternate implemen=
tations of<br>
&gt; &gt;&gt; the same thing gets that automatically.<br>
&gt; &gt;&gt;<br>
&gt; &gt;&gt; My preference is to use __SANITIZE_HWADDRESS__ since that mea=
ns any<br>
&gt; &gt;&gt; existing code will not be predicated on this (and hence I gue=
ss less<br>
&gt; &gt;&gt; surprises), but would appreciate feedback on this given the p=
oint above.<br>
&gt; &gt;<br>
&gt; &gt; +Evgenii Stepanov<br>
&gt; &gt;<br>
&gt; &gt; (A repost from my answer from the mentioned thread):<br>
&gt; &gt;<br>
&gt; &gt;&gt; Similarly, I&#39;m thinking I&#39;ll add no_sanitize_hwaddres=
s as the hwasan<br>
&gt; &gt;&gt; equivalent of no_sanitize_address, which will require an upda=
te in the<br>
&gt; &gt;&gt; kernel given it seems you want KASAN to be used the same whet=
her using<br>
&gt; &gt;&gt; tags or not.<br>
&gt; &gt;<br>
&gt; &gt; We have intentionally reused the same macros to simplify things. =
Is<br>
&gt; &gt; there any reason to use separate macros for GCC? Are there places=
<br>
&gt; &gt; where we need to use specifically no_sanitize_hwaddress and<br>
&gt; &gt; __SANITIZE_HWADDRESS__, but not no_sanitize_address and<br>
&gt; &gt; __SANITIZE_ADDRESS__?<br>
&gt; &gt;<br>
&gt; &gt;<br>
&gt;<br>
&gt; I&#39;ve just looked through some open source repositories (via github=
<br>
&gt; search) that used the existing __SANITIZE_ADDRESS__ macro.<br>
&gt;<br>
&gt; There are a few repos that would want to use a feature macro for hwasa=
n<br>
&gt; or asan in the exact same way as each other, but of the 31 truly<br>
&gt; different uses I found, 11 look like they would need to distinguish<br=
>
&gt; between hwasan and asan (where 4 uses I found I couldn&#39;t easily te=
ll)<br>
&gt;<br>
&gt; NOTE<br>
&gt; - This is a count of unique uses, ignoring those repos which use a fil=
e<br>
&gt; from another repo.<br>
&gt; - I&#39;m just giving links to the first of the relevant kind that I f=
ound,<br>
&gt; not putting effort into finding the &quot;canonical&quot; source of ea=
ch repository.<br>
&gt;<br>
&gt;<br>
&gt; Places that need distinction (and their reasons):<br>
&gt;<br>
&gt; There are quite a few that use the ASAN_POISON_MEMORY_REGION and<br>
&gt; ASAN_UNPOISON_MEMORY_REGION macros to poison/unpoison memory themselve=
s.<br>
&gt;=C2=A0 =C2=A0This abstraction doesn&#39;t quite make sense in a hwasan =
environment, as<br>
&gt; there is not really a &quot;poisoned/unpoisoned&quot; concept.<br>
&gt;<br>
&gt; <a href=3D"https://github.com/laurynas-biveinis/unodb" rel=3D"noreferr=
er" target=3D"_blank">https://github.com/laurynas-biveinis/unodb</a><br>
&gt; <a href=3D"https://github.com/darktable-org/rawspeed" rel=3D"noreferre=
r" target=3D"_blank">https://github.com/darktable-org/rawspeed</a><br>
&gt; <a href=3D"https://github.com/MariaDB/server" rel=3D"noreferrer" targe=
t=3D"_blank">https://github.com/MariaDB/server</a><br>
&gt; <a href=3D"https://github.com/ralfbrown/framepac-ng" rel=3D"noreferrer=
" target=3D"_blank">https://github.com/ralfbrown/framepac-ng</a><br>
&gt; <a href=3D"https://github.com/peters/aom" rel=3D"noreferrer" target=3D=
"_blank">https://github.com/peters/aom</a><br>
&gt; <a href=3D"https://github.com/pspacek/knot-resolver-docker-fix" rel=3D=
"noreferrer" target=3D"_blank">https://github.com/pspacek/knot-resolver-doc=
ker-fix</a><br>
&gt; <a href=3D"https://github.com/harikrishnan94/sheap" rel=3D"noreferrer"=
 target=3D"_blank">https://github.com/harikrishnan94/sheap</a><br>
&gt;<br>
&gt;<br>
&gt; Some use it to record their compilation &quot;type&quot; as `-fsanitiz=
e=3Daddress`<br>
&gt; <a href=3D"https://github.com/wallix/redemption" rel=3D"noreferrer" ta=
rget=3D"_blank">https://github.com/wallix/redemption</a><br>
&gt;<br>
&gt; Or to decide to set the environment variable ASAN_OPTIONS<br>
&gt; <a href=3D"https://github.com/dephonatine/VBox5.2.18" rel=3D"noreferre=
r" target=3D"_blank">https://github.com/dephonatine/VBox5.2.18</a><br>
&gt;<br>
&gt; Others worry about stack space due to asan&#39;s redzones (hwasan has =
a much<br>
&gt; smaller stack memory overhead).<br>
&gt; <a href=3D"https://github.com/fastbuild/fastbuild" rel=3D"noreferrer" =
target=3D"_blank">https://github.com/fastbuild/fastbuild</a><br>
&gt; <a href=3D"https://github.com/scylladb/seastar" rel=3D"noreferrer" tar=
get=3D"_blank">https://github.com/scylladb/seastar</a><br>
&gt; (n.b. seastar has a lot more conditioned code that would be the same<b=
r>
&gt; between asan and hwasan).<br>
&gt;<br>
&gt;<br>
&gt; Each of these needs to know the difference between compiling with asan=
<br>
&gt; and hwasan, so I&#39;m confident that having some way to determine tha=
t in<br>
&gt; the source code is a good idea.<br>
&gt;<br>
&gt;<br>
&gt; I also believe there could be code in the wild that would need to<br>
&gt; distinguish between hwasan and asan where the existence of tags could =
be<br>
&gt; problematic:<br>
&gt;<br>
&gt; - code already using the top-byte-ignore feature may be able to be use=
d<br>
&gt; with asan but not hwasan.<br>
&gt; - Code that makes assumptions about pointer ordering (e.g. the autocon=
f<br>
&gt; program that looks for stack growth direction) could break on hwasan b=
ut<br>
&gt; not on asan.<br>
&gt; - Code looking for the distance between two objects in memory would ne=
ed<br>
&gt; to account for tags in pointers.<br>
&gt;<br>
&gt;<br>
&gt; Hence I think this distinction is needed.<br>
<br>
Evgenii, how does clang-compiled code dististinguishes whether it&#39;s<br>
being compiled with ASAN or HWASAN?<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB%2BLF2uMdMd7AK8w%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAFKCwriA3RD9Sz9fAwdTHe9_siV83qxZ-TOB%2BLF2uMdMd7=
AK8w%40mail.gmail.com</a>.<br />

--0000000000009efb120596c57434--
