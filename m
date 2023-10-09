Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHPHR6UQMGQE63KI5OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 84F727BDC37
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 14:35:42 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-d814634fe4bsf6080709276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 05:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696854941; cv=pass;
        d=google.com; s=arc-20160816;
        b=PeL0Ag9Mp3Q9D/LxiAWy9QmGIh/P/bWS2VIm+VYEoUDzycVr+rlvHYTcNatN/4eDit
         OI4XcwVmayDVAdlfSih7O10sN+mXZH+Tu7GP1l9MF432PUe5ipSQRVNiQhhPwMpF4bl/
         Lsmb+uhMOlDlJWNP5AdNVOpKjKAexmEQdRN7Yvu3sv0OcS9Ev6WRu4apm4r8Wn6FU99e
         z2lGhdVNMGGqZSWiVgl58UImxDyWMJVmjRHn7HiJbWjHBo/LnJ4qpwmALNmqKmfisrlo
         xorQ6CTfuKLPrhjTD7TZ4tKZTf2/UHyMnTXAJ5iKEkSfECVWneU//17FYoR9i55iVbTX
         Mm1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WLLvfGEOma7h4r1YnZSAuAXy78Iz9IbxvrJ3wZn+x9I=;
        fh=V/PGgQ38PLjy/jSt8FbdZZv04WrFFf9tmvU0C3LWpo8=;
        b=pJRFng3JJ4+zpJtrsDcb6mP3XLpjcNgAsadBNOUscsgje1A7OM1HxH4hY4xqXLc7R6
         flgXcNLDzMF10QJoEhEY1CvhcFhikL6t8Qo0hG2HxiK2NpgVuULKHvR52Wmz6RRDiQV3
         sQh/mk0vxrpa3MinNRgZsO4niFXDfff1m9Un2D5Nqi/UI7yvDP4Wekf0zNJXj54SmoKp
         ba/Q+EwUZgcx48rn5HiDduEBYTIOkgcO+GDIGLVi0TImV0vexnKo6oD0iL6iMj4Yum7K
         eKNVmcHD2h7JX8CmdUJMrHO3XD61E125oLT9tVOF+i3FoT1idZH1yTBSSGhAeFaxco/w
         qXGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HfmGK+DP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696854941; x=1697459741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WLLvfGEOma7h4r1YnZSAuAXy78Iz9IbxvrJ3wZn+x9I=;
        b=CNFncc3q2bt8I0mxO0OQC9+bPY1/I9ZJrWMUWktHP5B4Ns1SmJODU9667q1j1MKqCI
         BagZWV/8Qi8v7TV7OVKQSAiMh3O+SS3V6jmdjuPtYpAq4+8yo6WrwgRRMyO/ParAdmni
         UNtHec+LVWSwCrE6ZIkt9r+OQsKxr6LemvH/v7X0XtiUYI2m9H4vuV0fYtpnBQVDO+Kv
         95ClfLslF0+2L7x6fzOlxA8OLIdT7qEfRnHY1cZdMMm2ppd97ivf/zqRjVwm8Qjfjbe3
         2bDLTnZsDYIWLYBcGD0bPVGOUEOK654xKscFz+ScQyskCEORgjNCLyU4P+MEf56VWJpF
         pwFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696854941; x=1697459741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WLLvfGEOma7h4r1YnZSAuAXy78Iz9IbxvrJ3wZn+x9I=;
        b=PbMR6l/6x+XKdZKhCBB3Z5Is7gkwNEiQdVgf7b99jpNJfWbSsIvmzMlWaT8SHuBg7i
         ERwhuv6Ls6UgG3c2KKvjG7Nn4IOSIMr780H9SZDlXznThCuCAieFs6sfFzws2ZGDzGYv
         TPdQlXDIN/X76P0HLA+7nuQ15vjaFMCJob2Q/ekngF2ZqaGQcinQ3UVaCDiaAUUSCHJG
         9H7SyQjiEMPfJ4FTaTZLuGfzIPtnx8bOApoBc5jw3qybGIzgixmVjz1A17Pf+G6DlBdq
         zgUOcehllJZoBIiyhvSWEoL6MmOi9EB19dNleHgw1DT+xFloEgvOMWdb0oWjEe/REN5g
         TrOQ==
X-Gm-Message-State: AOJu0YwilrgqwbvzaMMWaAq/cy3IVPoJx3ktL/gpT4monu/2eAIZ5phU
	sNzDqjYbB6bJHU/pnWz7osM=
X-Google-Smtp-Source: AGHT+IEJeRlitULjUMoULB2321MCiASlzYhYjNaxwT58O7ogOXRnyBVFirZOZz9NY5ne0gAHeUfsxw==
X-Received: by 2002:a25:6b4e:0:b0:d85:b09e:b9c9 with SMTP id o14-20020a256b4e000000b00d85b09eb9c9mr16377719ybm.52.1696854941119;
        Mon, 09 Oct 2023 05:35:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e502:0:b0:65b:13b5:cbdd with SMTP id l2-20020a0ce502000000b0065b13b5cbddls4616383qvm.2.-pod-prod-01-us;
 Mon, 09 Oct 2023 05:35:40 -0700 (PDT)
X-Received: by 2002:a05:6102:34ce:b0:44e:9a71:279e with SMTP id a14-20020a05610234ce00b0044e9a71279emr12583013vst.31.1696854939818;
        Mon, 09 Oct 2023 05:35:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696854939; cv=none;
        d=google.com; s=arc-20160816;
        b=ac9DIME6okA1TMkXPbmudm9RhIqcKdjSeyHZo5SH+JxxAusYUDXK9+xnCbZKoo9uoB
         GN/B7eFOvYQ9wGwp2zBT3/G51S+5vgSpFLUC7RvFzQ/l7YqgDh6VS4AtOjOpKhDEbKp7
         /jagOeap6pFif6RHIEtb9gGph8ZVU0rBr3E32kBNN/Zz9XgXAg1IW+RNNPosQusfQS+o
         Fppd8KWqf+JbTa+UdtSWtz2a95UuxjDaONz6B4zf2u2qPx3PJ9Srh2b9/ExqQIlkZHbs
         qbL/aGuVd1UjujQPiSSXKc7jvh+uNIewWAYAQoElBmVAVzwElt2Wz4XZ1AL47oJZqLhW
         1bjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wOKyQdcpzYH1S2DyazYIOAoD7VFJ1kfohupYEjtWCjA=;
        fh=V/PGgQ38PLjy/jSt8FbdZZv04WrFFf9tmvU0C3LWpo8=;
        b=xHTZETsmOYPcX8ELFiozrhzh2G9SewJkjQVZpaEUdMqvu6+B0KvbqV/G7EQCjhlbxD
         VrU8nO+zEwOHwq47xUhdzb5QBsPiV91t3DH/hwNLylIb9AHRRkuZX7UpqNO/WilhfB9e
         hshsDtfVgxg8xg7lF1+rXWOVKSGPsuovaj7AKoaP1v6vREhBw4ytP8cKpm9Dx45G4rhN
         RcpII7PO2PTDSPz68dpjQohKsgXo+xoOpy/FXIPWtiY1NtqGe0F26iP9PPSihGYBdS3d
         VjYufMgNGmPavchq8mYNyXlUXtkJ/xz6z0b+rZXxVSOwpiE3BXBsLO5Z9aT4nn0FL8Q/
         edlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HfmGK+DP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id ev4-20020a0561302e8400b007a5003d1b38si730608uab.1.2023.10.09.05.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 05:35:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id ada2fe7eead31-4577c37392eso357941137.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 05:35:39 -0700 (PDT)
X-Received: by 2002:a05:6102:7c2:b0:44e:98d8:c62e with SMTP id
 y2-20020a05610207c200b0044e98d8c62emr12922722vsg.33.1696854939344; Mon, 09
 Oct 2023 05:35:39 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <CA+fCnZckOM0ycja3-=08=B3jwoWrYgn1w91eT=b6no9EN0UWLw@mail.gmail.com>
In-Reply-To: <CA+fCnZckOM0ycja3-=08=B3jwoWrYgn1w91eT=b6no9EN0UWLw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 14:35:03 +0200
Message-ID: <CANpmjNNoBuNCf5+ETLOgMbjjYFT0ssfb4yyYL21XRrOgMc_mfg@mail.gmail.com>
Subject: Re: [PATCH v2 00/19] stackdepot: allow evicting stack traces
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HfmGK+DP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 5 Oct 2023 at 22:36, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Sep 13, 2023 at 7:14=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Currently, the stack depot grows indefinitely until it reaches its
> > capacity. Once that happens, the stack depot stops saving new stack
> > traces.
> >
> > This creates a problem for using the stack depot for in-field testing
> > and in production.
> >
> > For such uses, an ideal stack trace storage should:
> >
> > 1. Allow saving fresh stack traces on systems with a large uptime while
> >    limiting the amount of memory used to store the traces;
> > 2. Have a low performance impact.
> >
> > Implementing #1 in the stack depot is impossible with the current
> > keep-forever approach. This series targets to address that. Issue #2 is
> > left to be addressed in a future series.
> >
> > This series changes the stack depot implementation to allow evicting
> > unneeded stack traces from the stack depot. The users of the stack depo=
t
> > can do that via new stack_depot_save_flags(STACK_DEPOT_FLAG_GET) and
> > stack_depot_put APIs.
> >
> > Internal changes to the stack depot code include:
> >
> > 1. Storing stack traces in fixed-frame-sized slots; the slot size is
> >    controlled via CONFIG_STACKDEPOT_MAX_FRAMES (vs precisely-sized
> >    slots in the current implementation);
> > 2. Keeping available slots in a freelist (vs keeping an offset to the n=
ext
> >    free slot);
> > 3. Using a read/write lock for synchronization (vs a lock-free approach
> >    combined with a spinlock).
> >
> > This series also integrates the eviction functionality in the tag-based
> > KASAN modes.
> >
> > Despite wasting some space on rounding up the size of each stack record=
,
> > with CONFIG_STACKDEPOT_MAX_FRAMES=3D32, the tag-based KASAN modes end u=
p
> > consuming ~5% less memory in stack depot during boot (with the default
> > stack ring size of 32k entries). The reason for this is the eviction of
> > irrelevant stack traces from the stack depot, which frees up space for
> > other stack traces.
> >
> > For other tools that heavily rely on the stack depot, like Generic KASA=
N
> > and KMSAN, this change leads to the stack depot capacity being reached
> > sooner than before. However, as these tools are mainly used in fuzzing
> > scenarios where the kernel is frequently rebooted, this outcome should
> > be acceptable.
> >
> > There is no measurable boot time performance impact of these changes fo=
r
> > KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
> > depot without performance optimizations is not suitable for intended us=
e
> > of those anyway), but I expect a similar result. Obtaining and copying
> > stack trace frames when saving them into stack depot is what takes the
> > most time.
> >
> > This series does not yet provide a way to configure the maximum size of
> > the stack depot externally (e.g. via a command-line parameter). This wi=
ll
> > be added in a separate series, possibly together with the performance
> > improvement changes.
>
> Hi Marco and Alex,
>
> Could you PTAL at the not-yet-reviewed patches in this series when you
> get a chance?

There'll be a v3 with a few smaller still-pending fixes, right? I
think I looked at it a while back and the rest that I didn't comment
on looked fine, just waiting for v3.

Feel free to send a v3 by end of week. I'll try to have another look
today/tomorrow just in case I missed something, but if there are no
more comments please send v3 later in the week.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNoBuNCf5%2BETLOgMbjjYFT0ssfb4yyYL21XRrOgMc_mfg%40mail.gmai=
l.com.
