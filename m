Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6GRUP3AKGQEDJI5WRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CF7E1DF633
	for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 11:12:25 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id n23sf10842086pjv.2
        for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 02:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590225144; cv=pass;
        d=google.com; s=arc-20160816;
        b=v/PjLKoQIat0pqAVCYs/9mvsl3IZ8ZzsxhTueBxwQtEp/aghhLOQiw+cPidG9bjlGW
         n4PgE7z6j9zPmcbWuNX7nY2dMYjcuP+JorbNMYMaTbADaegvu7RoL+4Vd5Nm8T0DtVqd
         bVlTaK5IO9XnzxRsWSooo8NfmhiCpGdF6VcHCeGP2v1rArY7swWb5nbY6Qfy9g1dErOL
         02aPSQ7DNHyaTtVngCy2o5fanhmjr2NQldwa4wRFdYlx+yrgLBAlFjtQf5JmcDWA+X1n
         InZgY5hJfcctxsNF4gthBnULdcs/A/O4UUjZvXvfR6wMTeglO5Kid+Mga2SoQTifhaFy
         2x1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d4N8LNOsFtmnW5NrljqaE3gmeKBMWfihubDiS52tN2o=;
        b=o/wDL9XWfZkRk33KdKcrJJ3YLG2sNL+elc3YbkMkic7r1s0mCSdrfhW+SyXgUBr1vF
         Xxzy2d+gzwXUEtvJRf+qB6EbqVTxChieb9L9UwWo2BDq3Mmzmalf64zwxk62LYHA8LXw
         xc4thgsogR5i2aaydnI++ibS0SI3UZdt4vCGSvOr65kDcvESECp0e06jTFu49cx75FS9
         Q3T+EEySNCLtJHfMaJePJwQk4wOzb1I79p6uX5h/jn3p3nF8eOmHrKe2HhAHun9L7bre
         o4xgbMQ4C5dfOprzJCoHQ1rGDSjRgB6HrksyRDzO6vJvFVjLYwAcBtiSixXLH5oKLBlN
         4dAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rZRgirog;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d4N8LNOsFtmnW5NrljqaE3gmeKBMWfihubDiS52tN2o=;
        b=U1EtV0JVrAy4FeGkVxAhuzzzZrN5dsLr2P6dA5np7936B5HS24Cf47yQG8S+5o+vEf
         wDBg/eHcdr1A0XQgtM6WGsw35CpXuONXjokR9UeQyZPxBsn0d5ZOfHw6Yb/Q/oN920W3
         NA6H71BitoFOAVjyymt3omn61MqJ0gVLsUUXbRJHg+Z9PKNSoKLc6Fl23tqJr9GfC430
         78V2wIJpHB3O2YCa4Nb15SFv5F3Cio8LKIAQvpUK0F/LaJCE+Ao/AanX+UaNWb+sKJ+B
         2YLUW60yfSOB+A+S9qsojig6F9HlwYD3Bx9pxWzdwMDP61sc6REpGYCsjOyMiNo8sOCu
         8s0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d4N8LNOsFtmnW5NrljqaE3gmeKBMWfihubDiS52tN2o=;
        b=aN2/FdBxrRh0nxIwVZnLih+OwEmtQyYMAE+WkU0c5kr04EDNYVqsWMqUWvQcy5U++D
         Ra9goCyiP/EHk0o68lDa92ayy/IMipmC6ALUYdO0LDtWSyHpL03aBc4T0zDwzNioIiH0
         ChEnHBlmJN1+M96fZgC9QjbtJXJLL+hlWzXjZ3o9rinXmPvp3STMCjzmvN+rUBqilhms
         dfjjwMMRh1BQDKMgsXUnl2i4rPrDbEq1OdwsDQQ3aq68nBAh3t5gnUC1MfANPuUyJcTy
         E5b9xdKIb/ztV5N83u4RzI2c+sRWL2BRbTPi0tRVIlhbKGZEVdQGDZ0TadSZpd2eKIF0
         bRdw==
X-Gm-Message-State: AOAM532tYQ9m+A9m5tFk9vwRpdgtZOFx3Yen2B7urfNhghnJktrT+FbA
	Rm6bxrpyvVZeR+A0EUCdXYo=
X-Google-Smtp-Source: ABdhPJxo7x0/qzDK2ABpyZFZOjSTIUsWa9dqhKBYgnb+sjgMplp1O/kffr1ZEP4dd7kmzAaxKhVywA==
X-Received: by 2002:a62:1b84:: with SMTP id b126mr7919283pfb.123.1590225144131;
        Sat, 23 May 2020 02:12:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b219:: with SMTP id x25ls985906pge.8.gmail; Sat, 23 May
 2020 02:12:23 -0700 (PDT)
X-Received: by 2002:a62:9244:: with SMTP id o65mr1405902pfd.138.1590225143657;
        Sat, 23 May 2020 02:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590225143; cv=none;
        d=google.com; s=arc-20160816;
        b=ZBwiDvmCMa62d/t5R1deB90nHEYZkfr0KPXpfzaGYudmASy7+rZsFxXM8zNNpNUhxg
         Kj3yflrFu/XW9uLXGD2Kk+RtEIj09mdrcogO4HkL3B18qTWqBBr4xqaHV3KVmQFJqr3Q
         5hl7y1J2i1smJAQtEvvx5UNCOZgJ+CRIR0YNVdHafjiLnO/BAB0+932liwfAOdoHxRdz
         vhsaeZsBdZFdKcKWxXMKBxd+cfpIq1xMX4cDg662Eho91kinBEPKRBG5uaSRzUuEKnOb
         jI+ka0l+q+LhNdHl7Iu6IgjJP+fNBRb2qil934XhYzyox0jx2iJ5addlrdRrE3V1FjEa
         djQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BPw5LvQcTEsfBp2CGXcAmOXUYeI1dGSO14K+bI7ak8k=;
        b=KZpufhoYTB44vrRvybhgddwAfwcdb9+ZkXyq5DhVtqAOX3rnDV3JzHQvgGxJegb9eO
         94U1Ehu1NXVstbS9jkWP8bL7wSSj87WwTZ3KmKJTgV4sPttmPxxTNPqPzWq4iv3NhlHE
         0beQwNH+uNioW2EVJ6r3n6Q/h+B+SpfHAfmJ/hEOt28rKvt7P07tCvOCOl01r8htiycY
         x8F2qJA8Kta71nywhSXxFtGkTUhpI0c3DX3h/w5fIyabgA58wO1ZMQC8KCLr5/K9LJ3N
         Rc2x8ojM7xAHEg4uhhA8LAkNYINgA8MvkFi+x2t5VKg/z/Eot0Ui8wLhGSOQl9R8KlAL
         vg/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rZRgirog;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id q12si65756pfu.4.2020.05.23.02.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 May 2020 02:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id 69so10147527otv.2
        for <kasan-dev@googlegroups.com>; Sat, 23 May 2020 02:12:23 -0700 (PDT)
X-Received: by 2002:a9d:518a:: with SMTP id y10mr14870284otg.17.1590225142785;
 Sat, 23 May 2020 02:12:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200522075207.157349-1-elver@google.com> <20200522164247.4a88aed496f0feb458d8bca0@linux-foundation.org>
In-Reply-To: <20200522164247.4a88aed496f0feb458d8bca0@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 23 May 2020 11:12:09 +0200
Message-ID: <CANpmjNPVp0Orzm_MT4pjX_U_JwqskWbnXERRwFebFfnCbhJXLw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Disable branch tracing for core runtime
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Qian Cai <cai@lca.pw>, 
	kernel test robot <rong.a.chen@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rZRgirog;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Sat, 23 May 2020 at 01:42, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Fri, 22 May 2020 09:52:07 +0200 Marco Elver <elver@google.com> wrote:
>
> > During early boot, while KASAN is not yet initialized, it is possible to
> > enter reporting code-path and end up in kasan_report(). While
> > uninitialized, the branch there prevents generating any reports,
> > however, under certain circumstances when branches are being traced
> > (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> > reboots without warning.
> >
> > To prevent similar issues in future, we should disable branch tracing
> > for the core runtime.
> >
> > Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
> > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> I assume this affects 5.6 and perhaps earlier kernels?
>
> I also assume that a cc:stable is appropriate for this fix?

Yes, it does. On the other hand, the workaround is simple enough
(disable any kind of branch profiling).

Note, the patch won't cleanly apply to 5.6 and early without this:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8a16c09edc58982d56c49ab577fdcdf830fbc3a5

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPVp0Orzm_MT4pjX_U_JwqskWbnXERRwFebFfnCbhJXLw%40mail.gmail.com.
