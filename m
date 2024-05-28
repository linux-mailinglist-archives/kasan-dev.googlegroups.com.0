Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV4D26ZAMGQEO6TJP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B988D19BD
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 13:36:57 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f488f665c6sf4769925ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 04:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716896216; cv=pass;
        d=google.com; s=arc-20160816;
        b=UzBEmQtX03ETIOrMCXvw84Y1kGTbt+yWtn/ky4nr0N8EN6GaCzW6TsJ53wllcIS32V
         7hkZGHIBEW7dH7SOFdLWBPAtbtXTR7BRCxL3Q8CLEFp8pTtQcOvKrPnjViKBtrLl0GDX
         2L0sb2pXyh0eJies7B7G61/IOas+YovJsEEdoPsouqVQUvABjaXnKkx/VX04SleAwTOE
         //RdbMUCIxfbmROyZ+DnlGKw35hV6psPfls9mlWcalVTl703HPnPF3x62JuFILzhKvhQ
         JalxbVYRRJ2sM9W+WicHAvP7K45Ewhww8WvnYc9oCI3NpdhnSPNDHtUwRvH1rrZ1fvWB
         6MDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bd6YX7WCRcaSQ5k28Tc7NDVmceYR9xt1cQfyYiCSQg4=;
        fh=QFgjGUaBTUzxkyOtq1+Sx/MspFqsgB3Dd0WW89P8cwg=;
        b=aO6L37dj8NgrsNblk1LxM2qp15UJ3kqPYpE3VQuHdMTW9NWU8PMEYhUGP0cJjTQlDn
         X4HNn6lBy0op7LvXD4jESsVwXcwbs4Oab0FzhCXN2MFbv+peIlEQpLomYdHroEtLcdm1
         pJrFMdpB8Cyv/o2GkKm5QMkkqOsuIQ0HPi4i7ZNQwmdLesCuaBBYwYSHwzrD7TPtbPuD
         pYRAsBpATp84UyvO1UxxLbN6r0+dePE+StH+RCEm0J8DORnC5ak3moRIs/h/7iQLfWkY
         EwCok/EX3/g737st33hEkjzxCM2eK1W77V80r3Am+Lsy6BzGCvIwP9E83qZeQ5gCUTYt
         ytdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WdKvygey;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716896216; x=1717501016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bd6YX7WCRcaSQ5k28Tc7NDVmceYR9xt1cQfyYiCSQg4=;
        b=MrEhjgo99SK0yKUMfojjs7hVLxNV5bwwopeTkO+M4vP3L0gWWK+t+IBEm1T1LPMbJK
         vr98sU7vnQ/C6Ipji8VyOslLarXCmNdY2qciux6Ue3qV+/f87jHxnXXt7mag7vPiBjdw
         NghfzFaI+tFri8PM+qc6B+NUn5b4S5gX80dshmuOk9XhevZFHqyIU5dRRYFLDzWt12VU
         /35qndLKVOEjhwwveSGyUnusfcWnVxgd5FbQYC76qxxyRTRFg1SQfWeCDETiqownv2SW
         zNGZX2XL32fIyyygvIn+YfSz5lDMOn+C+/W7OhFEasZ1b12M2mJbaqe6CJT/7ftTCI8c
         byMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716896216; x=1717501016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Bd6YX7WCRcaSQ5k28Tc7NDVmceYR9xt1cQfyYiCSQg4=;
        b=TD8L3sNHHX0cDRlwqJ8KRyhlXgcNPurqImoebiv1VcJ5wIRnF8IyjB9Ics5SE0vTZ8
         o1PaMiMPPVyXQwp1scTIS0Lx0IHTme6wfHVnP4yODy1+RIbv8GTdMJjrG/iIQKZ2wX+Y
         bzuB2UBzM+de9cHFdI2PMAQ9UBEmiM+U9km8xl3EAJogxoWs+mOp/8EigfPJYAOsMQTm
         Ke9WQeEvlYcTnbvvaGq2g1CqglnQIy9NG/C4uAZVYprHaHbryEXsCRbWH5/SaM3pXyS/
         GXNESYJo9Pqjs/jW0V9DjwSm48cGW5+/xRnv4gzVnCJeBjNGkg12opD01yHjWgAJF5uG
         3JEg==
X-Forwarded-Encrypted: i=2; AJvYcCWDDn2xLNaCaC6y1K1cFh/57M6CLGMR1xk8PjyVK8uVWq+8/9/s6G5BVL41XA7EIeY+AhkbQaiQl0rOCDsVXBU7AHn7sQbwJw==
X-Gm-Message-State: AOJu0Yy3pEv1k+gfCwJWe8E4cOr03q5Q0n/lFZnZH7IMTCNX8k6k5EcJ
	2xgctRPaN5JPaiE+gAM9xAys7I/iDyRr3bMqSYXyndMPp/xyp0p3
X-Google-Smtp-Source: AGHT+IEji0i6T083aN9P7A5Lx9bbUhY1hBB9xaHJ+0T/FlvHXFDN1qyx5ahxqr4z/vZNQR2E6k0MnQ==
X-Received: by 2002:a17:902:b098:b0:1e4:3a10:5944 with SMTP id d9443c01a7336-1f466c6686amr5313905ad.14.1716896216012;
        Tue, 28 May 2024 04:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d80a:b0:2bd:8e26:660b with SMTP id
 98e67ed59e1d1-2bf6425c3b3ls1151418a91.1.-pod-prod-02-us; Tue, 28 May 2024
 04:36:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVi0V4zo7iYq0XUx7GkxsBRUDtrmLSRRcw4GP1uGaUG8DsDorVneRD3EGm93iB97rLjMAFSdTITjER9QlQYz+0HMYTWy86z6Nj9jw==
X-Received: by 2002:a05:6a21:2787:b0:1af:cbd3:ab4c with SMTP id adf61e73a8af0-1b212d48843mr11120469637.35.1716896214346;
        Tue, 28 May 2024 04:36:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716896214; cv=none;
        d=google.com; s=arc-20160816;
        b=ZLp2tddNdQgiE151pGj5isWR58zuUXaQmVlGIYCcrVgKQOVyRflbNulIv+rezldAgU
         46NZCb6bZt5oOpuo3zQf9fOqwdw0cUymOT9n9cj2YQTCqYLnQ2MWzOR51CigrSoPUsdo
         s0wXWMMCMzEjFkiV3MS34dL1q0UakYmVKbVxSLfA/4N/e+Jyn9OU5TFOHrcZ+jpb9DW9
         1aXHJCgaWqCyUCPmI6WEV3N4QQp9X8y36zuZnAge6gMnRtFxBlOzRTe93+54UC4R1Ik/
         lmNnCWJix3ueyA1L+sMuxhjc3FnEvbOOzlT6SxDiVJkZiJ373lBCuHJM4Yp2R0ttNkQK
         +Zcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5+fy7bxhmTSYRqmL4m3IRHCvKHkrSDKxVpOHKJ74CWc=;
        fh=gf3ELCAR+DiISwMK+RIWLFKnJs35I5utlvylqjBRtkU=;
        b=cvp2ZcK0wrbqrnpLMa+U2k2VLaqaDCjRjdt1j+sO47MICkthCT/c0HmAZgh7Gb+4KZ
         gj77aZBn4VxBdAz4DsN7Yj8jRf3Ko7Vs0mWlejMTjJzktlc6kGj3L43Rxy2TVTcRhwT0
         VH5jzroTY9G3tnvyWHuCXyhwOCcSz0lvShZyFpJbpW3zteN0HbheyxsCBQ6aLkxvtwxj
         9+Fhvsc4WMA7xEWazeCY4NFOJa1wJqRAsmj63b4ydN2oskmhdPZD9QzvbA0B8ucj/olG
         GDq52z3dh20kpRG3F4s62NHnAE830XAAt2VfeUx7MX//ToRO33UiAS69+bDwBXpobw9W
         UN2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WdKvygey;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f482151096si2267305ad.13.2024.05.28.04.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 04:36:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-6ad9162c960so3589966d6.2
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 04:36:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsyemHzjEfXmkdGWYgVzmby2oSYPuCEs8vepy/Rm/Kwm25R8eTyVW7zpmKqmKacegqfpUJ4VDUxQPC8F8DE0Az7Z/iD/Kn6TWREQ==
X-Received: by 2002:a05:6214:4602:b0:6ab:92b7:5903 with SMTP id
 6a1803df08f44-6abbbcb0b35mr137433736d6.21.1716896213239; Tue, 28 May 2024
 04:36:53 -0700 (PDT)
MIME-Version: 1.0
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
 <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com> <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
 <jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7@6cetkluh4ehl>
In-Reply-To: <jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7@6cetkluh4ehl>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 May 2024 13:36:11 +0200
Message-ID: <CAG_fn=Vp+WoxWw_aA9vr9yf_4qRvu1zqfLDWafR8J41Zd9tX5g@mail.gmail.com>
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
To: Kent Overstreet <kent.overstreet@linux.dev>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Brian Foster <bfoster@redhat.com>, Kees Cook <keescook@chromium.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>, linux-bcachefs@vger.kernel.org, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WdKvygey;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, May 24, 2024 at 7:30=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Fri, May 24, 2024 at 12:04:11PM -0400, Mathieu Desnoyers wrote:
> > On 2024-05-24 11:35, Mathieu Desnoyers wrote:
> > > [ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]
> > >
> > > On 2024-05-24 11:28, Kent Overstreet wrote:
> > > > On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wrote:
> > > > > Hi Kent,
> > > > >
> > > > > Looking around in the bcachefs code for possible causes of this K=
MSAN
> > > > > bug report:
> > > > >
> > > > > https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@google.=
com/
> > > > >
> > > > > I notice the following pattern in the bcachefs structures: zero-l=
ength
> > > > > arrays members are inserted in structures (not always at the end)=
,
> > > > > seemingly to achieve a result similar to what could be done with =
a
> > > > > union:
> > > > >
> > > > > fs/bcachefs/bcachefs_format.h:
> > > > >
> > > > > struct bkey_packed {
> > > > >          __u64           _data[0];
> > > > >
> > > > >          /* Size of combined key and value, in u64s */
> > > > >          __u8            u64s;
> > > > > [...]
> > > > > };
> > > > >
> > > > > likewise:
> > > > >
> > > > > struct bkey_i {
> > > > >          __u64                   _data[0];
> > > > >
> > > > >          struct bkey     k;
> > > > >          struct bch_val  v;
> > > > > };

I took a glance at the LLVM IR for fs/bcachefs/bset.c, and it defines
struct bkey_packed and bkey_i as:

    %struct.bkey_packed =3D type { [0 x i64], i8, i8, i8, [0 x i8], [37 x i=
8] }
    %struct.bkey_i =3D type { [0 x i64], %struct.bkey, %struct.bch_val }

, which more or less looks as expected, so I don't think it could be
causing problems with KMSAN right now.
Moreover, there are cases in e.g. include/linux/skbuff.h where
zero-length arrays are used for the same purpose, and KMSAN handles
them just fine.

Yet I want to point out that even GCC discourages the use of
zero-length arrays in the middle of a struct:
https://gcc.gnu.org/onlinedocs/gcc/Zero-Length.html, so Clang is not
unique here.

Regarding the original KMSAN bug, as noted in
https://lore.kernel.org/all/0000000000009f9447061833d477@google.com/T/,
we might be missing the event of copying data from the disk to
bcachefs structs.
I'd appreciate help from someone knowledgeable about how disk I/O is
implemented in the kernel.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVp%2BWoxWw_aA9vr9yf_4qRvu1zqfLDWafR8J41Zd9tX5g%40mail.gm=
ail.com.
