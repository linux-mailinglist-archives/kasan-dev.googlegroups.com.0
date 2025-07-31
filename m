Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPNOVXCAMGQEHFE6WFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C44CFB1707E
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:45:03 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-76bd2543889sf432315b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:45:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962302; cv=pass;
        d=google.com; s=arc-20240605;
        b=e/ORASAaqS6+nvyZ065BRHcwQNorr2xYD6aX9iaxmZb9hg+O/wIcUOlpTpT12Ce8C0
         xQ6Sio1HKGiiwom4x6Ijd5kNnurUYAw32F8mgbsN5kMaB/RytNJpqGpp1kuv5lXziP8M
         J5i+JlsaUdtXpvTEJEL13w4kc3i9O4Yx7O9eX2kCerx9tiRPtlRr0fkPZgdiwmu/ncOT
         4V4c8dptNq+P1SyjawI+FG1b48u1UwX0IYI9olwOuT9BJ4Mgq2IeKLaCHCHDbwHG/6Un
         S6o7uN7kITDj8rtbY00LokGPnT1QhLVpa2MDiaK2Lns5qmH+xVKddbO3J4NzuRnE40v+
         r3tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gdVRD3hte9de+d5wH1nXdzjBSAkvyXcCnbSH7IZEsuY=;
        fh=0PlYzxBjRN6GARmejkK7hX01vqCys06unKUZeFY7w6c=;
        b=HE5+FdymNOmqHyLSoyrOMtO+liuuVWWJj7C15JdmhhRqhJhAZ51WA1JufUCh98mIyI
         JAyBc+CTigUVaBt2O0rY/wInHhqZ/JAQnHxYp9XpSMIJRQRNd2uBgfZhPFJohDB5+Dwp
         qXTJCt87FWI14hpbwqG+zWGYRO0wqAXYut3AR4cNP3Rfggltp6fLTPMcVaCLlVcDmCyk
         4/xhZ/7cy7dSAJRoKSBKD57nV2ypbgkA1fpr6oVmPGQ8HYqHZIC93PoOHNOE8aKV3R5J
         D/NOZbM1QJGtnKE0r9IXIyGjGuZu81rdHQBcQJ/3N9p5ImrBvKYjf6g5+h7K5Ilvb6w/
         jGUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Af5ggWi8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962302; x=1754567102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gdVRD3hte9de+d5wH1nXdzjBSAkvyXcCnbSH7IZEsuY=;
        b=S3ejXBX4YqPCdPbngDcdPGb4o2rnHkA8mvM8SxdWvcxIXNfJnGckJLmMOdg/8PSJir
         8xH/1gby5tKAUu1I4oVt49sVg1MKIjt6/Gf2hzMgli095fDCmF8hwrlS5ek4ymKMAyYR
         6eBlCI3DMvy/CzXCLLgtpCG3ZTwzzOYhStRrh/BPF26EBfcVdV9XO7AgwrYwk/z5OI9O
         +2qZ1R1+AQOZnpnqCUvQh9ZV18aEj1d7ZHzG4txlHnp2S35p1cHlPBAksDzpfdIf9oDt
         EWqt7LMV5SMibfCejdPhZXFQmmLebuSdCnUMGQbuSBaoAGkUK0mkbiMcv/FzVzTJ70lS
         JY4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962302; x=1754567102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gdVRD3hte9de+d5wH1nXdzjBSAkvyXcCnbSH7IZEsuY=;
        b=cV5NTf12XQsC2cl09SiULd3SYIdFSvxmw06Zh2rEcnmN7DlCz2h3Gt7dYDvlJqeY1o
         VQ3w/cuRiz5B2GxCxXHBziRD6/BYYhDSKFbRoQcnC7+qoiMHPZphUbKsG54HGaOeg/q3
         6JDanLu+NGU36quBJyyEQDvvlhUq7jk56aJ1f04ER05h8rjkJcjlxmIaMsB40wU6i6Oy
         jbIZi1KCwiumE4k/LfwkUmL+1EcDbMP/OP0HsH7S6PLx0Y3XCPQbVZXIRzucKwfykhUv
         32kdsoC7R1clCcK379kqDZw9OnphjBfyN1urtYRoJBj5F7ogTMPGImvvBMVfRpIitkho
         YVyA==
X-Forwarded-Encrypted: i=2; AJvYcCUqsEWM5OaWO81CG/uSc4ipBveshs1jFsNNNPrE9CXskZDz25d1Ce8Cf9OyXVKeuNf3yClpxw==@lfdr.de
X-Gm-Message-State: AOJu0YxQOkrbc971i1insgPGH0dus2YclpPgf31HlyQMiJQlxwrVzYGe
	R2zXh1812OWKtFro9SGd0PBUvNPHpfAYZogJLWjnIm+Y7cQzRiW+KCST
X-Google-Smtp-Source: AGHT+IET2jh502rO2tzpNafJ6BRG0hiCm7ETkXXiQOkG2AS05oXcYRI3+s0tI562lLjQF9VoUzXdbg==
X-Received: by 2002:a05:6a00:7481:b0:76a:9b3a:4b85 with SMTP id d2e1a72fcca58-76ab2f5c01bmr7440550b3a.14.1753962302065;
        Thu, 31 Jul 2025 04:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZflO4rg6NbYQRanuua0SNkBv5hYauoBEYUyYmkjkaM9hQ==
Received: by 2002:a05:6a00:1818:b0:730:8b18:e9ff with SMTP id
 d2e1a72fcca58-76bc79d7d7cls1432299b3a.0.-pod-prod-06-us; Thu, 31 Jul 2025
 04:44:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsR6NojiiwXzI0Vt09XnZ5SzUccOOjg76ah/k96dzNgP9sOKXSbJ8lXYhbm1sa6CfbC8nV7cvxEr0=@googlegroups.com
X-Received: by 2002:a05:6a20:7489:b0:233:bbcf:749e with SMTP id adf61e73a8af0-23dc0d595d3mr12362834637.8.1753962299269;
        Thu, 31 Jul 2025 04:44:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962299; cv=none;
        d=google.com; s=arc-20240605;
        b=W/wn/1IsGB5kK1EyKl++QMvBa1NAnWGFr6o07a/I/eqIC5lgtYwE4EzerAYM7EFBJr
         X+kP84F/3bCws/54mDjlJTwHf/KCFXlwwqv+d+iQAyCuqcNRvJvO+U9OLTdM0Grva9yj
         1/0XFaE6Uq40UkmoOpLTLuRl995c/FKzs5wNB369T5FoLen77H4O72ucubTA0/LiAffA
         VyfSb1mPajFKFtyBbaImYU5Mf2fpOSUUxnrnz3hMOAtCHgJBqqJvAaLs0ghJun3sS7ym
         Pwn8DyEx3Ki6xba4pRqvZr8U2ZVsEmTJrrpfcdSKw5V355HACRWnGLkH7aoQxex2DyXV
         4Mtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3PKLSjCjZPYymf2Az68ZABMj828kp1cj/gOiTB6pG/w=;
        fh=mLvGoyKUjg4JaJ/YYjC3OMZZ9Fkr7A4FkWVgdB9ZurQ=;
        b=RhZhXOEcwfeQ97/B6UmAhmSfCgktggmVsrJkdFNYKI7O42ti+pHTyFTHPxTF0Hh5LL
         DU0FJyvg0/DveoePuarT86yd6OZZ/bLjDY7FvqaTF0wgqmkiUVOdPYkXQDFsrkDEpeSN
         p+5ElJ/TEAm0vZrcI/oNCULIXk4ttKiM27UGgEvQo9spaMeV8n7isuijiB792NVTAxa7
         fXI7ltGIQmnt6XiyFyNcAv0CEFeHH3pokAm3oagFwc6T6tUt9Z599frh7FQX3STJLrbi
         xQHGCtyo0kWQpyfipK3iEpcLCSQR/Q6/nAq6Ptp8BoodrLyCCgJbsTiiA0y6PTj5t6yM
         5A4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Af5ggWi8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b422b7beb9bsi36371a12.1.2025.07.31.04.44.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:44:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-4ab8e2c85d7so3726311cf.2
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:44:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSKXK4LiVIJ9ogY+nnRtVQjuw9y/jiOXfVA0EsVtJfNK3Ip1aQqrLgUg6hblqtpaPMux4jS/pZFjM=@googlegroups.com
X-Gm-Gg: ASbGncvvE2QBZ+crMJrXvSvqtBaOMXUXpATU0EJ5ojAJfiwCaXbtFPQX4CB/yfEKTua
	BzoA4Bvl+LPFRiHToEDJJbyhYjUTGIwYTk/T0xUlokKPZ14pmV+Z4nMZouCOjQHP4b6e3uBHj9m
	cSmZia6dHBfS/Q64vqxaA3mUtnsnovkFK/vG4AszZoguOhdX/6z/KJ+qgGM6uaNXqCMxr+PbsSy
	auPcCZP9Qvl9IH+ueTnzRNNiry3NIDESkw=
X-Received: by 2002:a05:622a:1107:b0:4aa:ea4a:eddf with SMTP id
 d75a77b69052e-4aedbbf7a26mr121102461cf.27.1753962298094; Thu, 31 Jul 2025
 04:44:58 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-5-glider@google.com> <202507291913.UMbUQv95-lkp@intel.com>
In-Reply-To: <202507291913.UMbUQv95-lkp@intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Jul 2025 13:44:21 +0200
X-Gm-Features: Ac12FXw3MWIiorLqfBfwnfmq8Ic-Jw62GS99_ubxKh9VEDUg3SBKoiWcbSpLn60
Message-ID: <CAG_fn=Xs+gctrJUhA7GCF37N3CyMFMdu1PX1EpaP4reCRQJa5w@mail.gmail.com>
Subject: Re: [PATCH v3 04/10] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
To: kernel test robot <lkp@intel.com>
Cc: oe-kbuild-all@lists.linux.dev, quic_jiangenj@quicinc.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Af5ggWi8;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 29, 2025 at 1:44=E2=80=AFPM kernel test robot <lkp@intel.com> w=
rote:
>
> Hi Alexander,
>
> kernel test robot noticed the following build warnings:
>
> [auto build test WARNING on tip/x86/core]
> [also build test WARNING on akpm-mm/mm-everything shuah-kselftest/next sh=
uah-kselftest/fixes linus/master v6.16 next-20250729]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Potapenk=
o/x86-kcov-disable-instrumentation-of-arch-x86-kernel-tsc-c/20250728-232935
> base:   tip/x86/core
> patch link:    https://lore.kernel.org/r/20250728152548.3969143-5-glider%=
40google.com
> patch subject: [PATCH v3 04/10] mm/kasan: define __asan_before_dynamic_in=
it, __asan_after_dynamic_init
> config: powerpc-allmodconfig (https://download.01.org/0day-ci/archive/202=
50729/202507291913.UMbUQv95-lkp@intel.com/config)
> compiler: powerpc64-linux-gcc (GCC) 15.1.0
> reproduce (this is a W=3D1 build): (https://download.01.org/0day-ci/archi=
ve/20250729/202507291913.UMbUQv95-lkp@intel.com/reproduce)
>
> If you fix the issue in a separate patch/commit (i.e. not just a new vers=
ion of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202507291913.UMbUQv95-lkp=
@intel.com/
>
> All warnings (new ones prefixed by >>):
>
>    In file included from mm/kasan/kasan_test_c.c:32:
> >> mm/kasan/kasan.h:585:6: warning: conflicting types for built-in functi=
on '__asan_before_dynamic_init'; expected 'void(const void *)' [-Wbuiltin-d=
eclaration-mismatch]
>      585 | void __asan_before_dynamic_init(const char *module_name);
>          |      ^~~~~~~~~~~~~~~~~~~~~~~~~~
>

For some reason GCC declares this function as a `void(const void *)`,
whereas LLVM goes with `void @__asan_before_dynamic_init(i64)` (not to
mention that ASan userspace runtime expects a const char * parameter).
I'll change the prototype to match that from GCC, because Clang does
not care much.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXs%2BgctrJUhA7GCF37N3CyMFMdu1PX1EpaP4reCRQJa5w%40mail.gmail.com.
