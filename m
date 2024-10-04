Return-Path: <kasan-dev+bncBDAOJ6534YNBB4GC763QMGQEK647LZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9828299030E
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 14:37:05 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-42cb5f6708asf12307605e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 05:37:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728045425; cv=pass;
        d=google.com; s=arc-20240605;
        b=k6MJST+Ibhk8TRgqT5yNGbg2AS64GNi2DW/ogMVgsJMwsb5SoV23QSEHWexDV4RJ6g
         pjPtlw9Y0B8UIVEL0bHpcNfG0DGY1XUNySQbAY57dgG1s1M0LeXQLGY5+zF7gcRo9FUO
         gtO6ZvrCQV4DxYXmQHystVx5qQDHVl5HimPxzqo94yOb/Bb5iQjYM8WF/XQbjiDBn3j2
         qS3dqwP++pJGLKfN7LLpqLWSFTHHH78curdkusMsAUgKJvmAJPwi48KBUPvKVvltiOmL
         xzEH2ToMM8p9LMkfh41DcmRad8843WdlKC19Ko5hJ1cUoT+p4q/vnMv9UfBFOAMODiPd
         mzjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wbPXLXPpKVzefCROo05hCT3GU61imhFAeOfSXEwXei8=;
        fh=AlCOLj4qImKio0UCiFmGLeBKgrx3atItqa+wHCSERgs=;
        b=epfM7ajgGilamT6SbrdNER1YQo1RH3cymkx6uI5UFOZWHKjVbM5atPR82Sy5YJPrZH
         tapEfrarzoTuyX8FlcgOkmFEY8nBY5rlHxKacWZJtIZeVPCQ/3CNIWB+7rSu/yW9Xo0D
         PGH89T4SQfdySVcMqTJliv9Is7EmT9X7dYMpLo82E2glX1C3srzZDq1VTX+xSeP2IRKS
         MFF/XEaj1dRgmfIQIUFFUrZlXmF0PvP/CQ6Fu/o01fMlUyX6CiFwLHryx4rWPT+3KVP9
         +Sd4U9HkZoKgd3RBLrOkck8S18Pte6rQTCmcoWE5CHTSomAyNCgk1suAumNywtIEoq8p
         kFFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JTu3p+2V;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728045425; x=1728650225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wbPXLXPpKVzefCROo05hCT3GU61imhFAeOfSXEwXei8=;
        b=XpTYFnuz13J0D8YPNMQtjfCggVIhBOMEwws2uCY0lJQupbQW03AlDJwlTzwW/NzFDx
         V6GDx+IL0ER+9tcLpyofxnh3TpLy3ePrcrG0RixekSXq2Vg3UYEbgu2XrJRU7ct4wgDQ
         ycVlGn+ib0eOpTdlH+1+hjNC62KiUjR7+bxQoSBUxVKQ/basZ+AkTmKLyauLmH2eyMly
         /0DuIYJTY+Xz8RSalm+qzk9G6F0FwYum8vd0E5Z/gcR/XPgeMMAZuHc2vg5yClN0FsV0
         4GJwBeLg11ZAS8AYVbE1Xnc7pcYdbJ+isHnFMaUMARRpeSGnew5NKIC6F1IYxA7YIpHz
         9V6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728045425; x=1728650225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wbPXLXPpKVzefCROo05hCT3GU61imhFAeOfSXEwXei8=;
        b=lKPXCSXZ/mSKRQGXvkueWgn18duX/5YrKz44cUJTvsg+e4oEbdpgxFAt41N5r7ziGQ
         lpoE4KXGAkYlG/2ziURLXKeDSTEdlYxvg6idHZd0Z6YAjzmC35cm3swx1s0LMtVEAWqK
         O3dt/OfvsWBKa9jxF8BQBicA1S0eNzkO0K46L5wUZwoocZHxEavYfmjA7zCcptLyUaSI
         yp2zabNQw+kzeoohkOk1cI8Tc/WaDhWqzTBQb+GeBdPVyh1d/oLpgOlkRI9sL3S5hL2J
         CURa5bhC4v92LbjGO4wLPAeBGZNEo3O0hiUGNbUz2hdACpuRQ1sUo7uixefJQ7GnnelF
         CfEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728045425; x=1728650225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wbPXLXPpKVzefCROo05hCT3GU61imhFAeOfSXEwXei8=;
        b=GJoml7WauINczeOQqnsL9f5TVrG/FsR5m6EI20/SLWM5mxwmmv1nQ/dIhMaTIHhswI
         Kd5rCtKC4Kp1tfi7+IfvzfIZVlDclNWP66KtrLpYf97KG3s0JufsFZs63iOH1cy7nn65
         WyP9T4PUUrRfhevD0eTdKv5BQ6BXHyFgE8lTtYqoWUqEXo+xM8REQ1XiQ+CdsAnqgKGG
         ZtKZ1iS7xCdfcphblOzhqLfBiEIqqCATdFiyDWvD2WU2E3JY+BbsuwZWDCoKrAJOfPAL
         M6ZoHCHjrCbklVG6HeurugmlqXoNTJDiEVbPkBDBBzf2GDl2FPmcUDi6t2qVB2Zqpb/G
         +HvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/r+PZmGT25Sm11Gskf7gMPbX2yTT1QItw63haSz3z5fim042g+N0nxXUulrkQeHZWC6enXw==@lfdr.de
X-Gm-Message-State: AOJu0YyHADOd9aboHYYIWgNn4JEv8AceYDo47+lKCoIF0qGX+HXeFZai
	YEbhkc+8SE5IMeHyNxY9Nz+cWpnYnai5xcaqXmsnHU1/wPmZHbFY
X-Google-Smtp-Source: AGHT+IEp7SOEeWZZeu+V9rQOUZYV/vHmRljgQ0pZ0CYNCRK+v4JPhCS2487X3O3X0kM6XcKIHl3jLA==
X-Received: by 2002:a05:600c:45c6:b0:426:51dc:f6cd with SMTP id 5b1f17b1804b1-42f85abebdcmr16633425e9.18.1728045424447;
        Fri, 04 Oct 2024 05:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c10:b0:42c:ad31:384a with SMTP id
 5b1f17b1804b1-42f7deb8820ls1452115e9.0.-pod-prod-06-eu; Fri, 04 Oct 2024
 05:37:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWioTBTyR87k1xsKmzX1AlTu98AmNooaSqt3zXiBwn/PFGG29ByFfuiSl7s7XSfM6Kqb8RQpkReyUA=@googlegroups.com
X-Received: by 2002:a05:600c:6b18:b0:428:10ec:e5ca with SMTP id 5b1f17b1804b1-42f866b546dmr15734415e9.14.1728045422487;
        Fri, 04 Oct 2024 05:37:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728045422; cv=none;
        d=google.com; s=arc-20240605;
        b=ceiMRPeSf/d491ukn5nli27seAFME3CBYvgrQ5SUFQ+M3rV/itW4EyluW384dRwmpL
         8VqN3Dz8I9L115mpaI2YyM98LcXna5FQ8nDxBWM3SksQ5mjerwjTVkT9GpHvE1pVrQeI
         AMenDmWlYbnayVzh8F5/aXiaA6oOtN0y5ymwfOeInNz9OULToPfVYDyAu1r6nbDDSAql
         iSEo6dO5FAAdXc50vHWxhHujW2S4uWx0EZPdMBtTHXnWLo/BaQVX9kUcEdasDs8d70KI
         QpoAuFS0ogWPbVAyRZxrLRlgwouB+t+Z3wakrf4lJnUYJl1c+x1VWybVzCxeskxlT4tm
         deiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zkQGIL5EVYPHu1HndHhTEW+Z6R2TaJeNi0ejVqgiqaI=;
        fh=vSAPUGXp081dKnH4q/sGatCwnZHyAMWnAWBnifhcWBM=;
        b=fl5bKZQSd0IbtWgy+Q0pbcGhRqL8XSSWbLLOLT6BsOOK1CQcT+qBDSMqQNB7+jiEAE
         Wfk1A8QIXGx+NcpOt1XoFuaL8k3plZ80dTHo83Dit3Q9KV+toYj6y6hsbRXipnwsqe50
         1oWQm5y5uuXDlRC1PA1xsFZjh++lN/P0NFY54VMuJhYbgHo1t6S4to7HFwgLYTGWJawg
         kAmOynaXytkup198kQJpqxhpJKAt5V5m8HcBYUt41n0clXAOsdZwAaVBhO01FfGZPxah
         Wk+hwTe/FPAXO3ks4us7TubVNK3FrrVLl63HLCKuhN9lacPTIK/4O4frkZ5K1q1JVwCv
         8cVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JTu3p+2V;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f86b45031si284415e9.2.2024.10.04.05.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2024 05:37:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id 4fb4d7f45d1cf-5c87c7d6ad4so2829056a12.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2024 05:37:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDAvafsyYVwjZKvT9bJUTOfAlTng8rl6Xek3381boJ/T0Z4NPDF1i+Mm2COPv8dRRmJXAcllzg0PQ=@googlegroups.com
X-Received: by 2002:a05:6402:348e:b0:5c8:9696:bae8 with SMTP id
 4fb4d7f45d1cf-5c8d2ed2ed0mr1700748a12.32.1728045421608; Fri, 04 Oct 2024
 05:37:01 -0700 (PDT)
MIME-Version: 1.0
References: <20240927151438.2143936-1-snovitoll@gmail.com> <CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com>
 <CACzwLxhjvJ5WmgB-yxZt3x5YQss9dLhL7KoHra0T-E2jm=vEAQ@mail.gmail.com> <CANpmjNMBJJ4e8EGkfFB2LmtPNEtzx2K7xLhK8PXdRsO=KiAS0Q@mail.gmail.com>
In-Reply-To: <CANpmjNMBJJ4e8EGkfFB2LmtPNEtzx2K7xLhK8PXdRsO=KiAS0Q@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 4 Oct 2024 17:37:45 +0500
Message-ID: <CACzwLxinN_tJ9_M3uXipwME8QA+1DLC9-Ps59ecSv=6SneOBvA@mail.gmail.com>
Subject: Re: [PATCH] mm: instrument copy_from/to_kernel_nofault
To: Marco Elver <elver@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JTu3p+2V;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 4, 2024 at 11:55=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 2 Oct 2024 at 18:40, Sabyrzhan Tasbolatov <snovitoll@gmail.com> w=
rote:
> >
> > On Wed, Oct 2, 2024 at 9:00=E2=80=AFPM Marco Elver <elver@google.com> w=
rote:
> > >
> > > On Fri, 27 Sept 2024 at 17:14, Sabyrzhan Tasbolatov <snovitoll@gmail.=
com> wrote:
> > > >
> > > > Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault()
> > > > with instrument_memcpy_before() for KASAN, KCSAN checks and
> > > > instrument_memcpy_after() for KMSAN.
> > >
> > > There's a fundamental problem with instrumenting
> > > copy_from_kernel_nofault() - it's meant to be a non-faulting helper,
> > > i.e. if it attempts to read arbitrary kernel addresses, that's not a
> > > problem because it won't fault and BUG. These may be used in places
> > > that probe random memory, and KASAN may say that some memory is
> > > invalid and generate a report - but in reality that's not a problem.
> > >
> > > In the Bugzilla bug, Andrey wrote:
> > >
> > > > KASAN should check both arguments of copy_from/to_kernel_nofault() =
for accessibility when both are fault-safe.
> > >
> > > I don't see this patch doing it, or at least it's not explained. By
> > > looking at the code, I see that it does the instrument_memcpy_before(=
)
> > > right after pagefault_disable(), which tells me that KASAN or other
> > > tools will complain if a page is not faulted in. These helpers are
> > > meant to be usable like that - despite their inherent unsafety,
> > > there's little that I see that KASAN can help with.
> >
> > Hello, thanks for the comment!
> > instrument_memcpy_before() has been replaced with
> > instrument_read() and instrument_write() in
> > commit 9e3f2b1ecdd4("mm, kasan: proper instrument _kernel_nofault"),
> > and there are KASAN, KCSAN checks.
> >
> > > What _might_ be useful, is detecting copying faulted-in but
> > > uninitialized memory to user space. So I think the only
> > > instrumentation we want to retain is KMSAN instrumentation for the
> > > copy_from_kernel_nofault() helper, and only if no fault was
> > > encountered.
> > >
> > > Instrumenting copy_to_kernel_nofault() may be helpful to catch memory
> > > corruptions, but only if faulted-in memory was accessed.
> >
> > If we need to have KMSAN only instrumentation for
> > copy_from_user_nofault(), then AFAIU, in mm/kasan/kasan_test.c
>
> Did you mean s/copy_from_user_nofault/copy_from_kernel_nofault/?
Yes, typo, sorry for the confusion.

>
> > copy_from_to_kernel_nofault_oob() should have only
> > copy_to_kernel_nofault() OOB kunit test to trigger KASAN.
> > And copy_from_user_nofault() kunit test can be placed in mm/kmsan/kmsan=
_test.c.
>
> I think in the interest of reducing false positives, I'd proceed with
> making copy_from_kernel_nofault() KMSAN only.

Here is my current upcoming patch that I will send separately
once it's tested, it's slowly being compiled on my laptop (away from PC).
I've moved copy_from_kernel_nofault() to kmsan_test.c and added
kmsan_check_memory() _before_ pagefault_disable() to check
kernel src address if it's initialized.
For copy_to_kernel_nofault() , I've left instrument_write() for memory
corruption check but before pagefault_disable() again, if I understood the =
logic
correctly. I will adjust kmsan kunit test once I can run it and send a PATC=
H.
Meanwhile, please let me know if the order of instrumentation before
pagefault_disable()
is correct.

> By looking at the code, I see that it does the instrument_memcpy_before()
> right after pagefault_disable(), which tells me that KASAN or other
> tools will complain if a page is not faulted in. These helpers are
> meant to be usable like that - despite their inherent unsafety,
> there's little that I see that KASAN can help with.
---
 mm/kasan/kasan_test_c.c |  8 ++------
 mm/kmsan/kmsan_test.c   | 16 ++++++++++++++++
 mm/maccess.c            |  5 +++--
 3 files changed, 21 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 0a226ab032d..5cff90f831d 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,7 +1954,7 @@ static void rust_uaf(struct kunit *test)
  KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }

-static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+static void copy_to_kernel_nofault_oob(struct kunit *test)
 {
  char *ptr;
  char buf[128];
@@ -1973,10 +1973,6 @@ static void
copy_from_to_kernel_nofault_oob(struct kunit *test)
  KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
  }

- KUNIT_EXPECT_KASAN_FAIL(test,
- copy_from_kernel_nofault(&buf[0], ptr, size));
- KUNIT_EXPECT_KASAN_FAIL(test,
- copy_from_kernel_nofault(ptr, &buf[0], size));
  KUNIT_EXPECT_KASAN_FAIL(test,
  copy_to_kernel_nofault(&buf[0], ptr, size));
  KUNIT_EXPECT_KASAN_FAIL(test,
@@ -2057,7 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
  KUNIT_CASE(match_all_not_assigned),
  KUNIT_CASE(match_all_ptr_tag),
  KUNIT_CASE(match_all_mem_tag),
- KUNIT_CASE(copy_from_to_kernel_nofault_oob),
+ KUNIT_CASE(copy_to_kernel_nofault_oob),
  KUNIT_CASE(rust_uaf),
  {}
 };
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 13236d579eb..fc50d0aef47 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -640,6 +640,21 @@ static void test_unpoison_memory(struct kunit *test)
  KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }

+static void test_copy_from_kernel_nofault(struct kunit *test)
+{
+ long ret;
+ volatile char src[4], dst[4];
+
+ EXPECTATION_UNINIT_VALUE_FN(expect, "test_copy_from_kernel_nofault");
+ kunit_info(
+ test,
+ "testing copy_from_kernel_nofault with src uninitialized memory\n");
+
+ ret =3D copy_from_kernel_nofault(dst, src, sizeof(src));
+ USE(ret);
+ KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] =3D {
  KUNIT_CASE(test_uninit_kmalloc),
  KUNIT_CASE(test_init_kmalloc),
@@ -664,6 +679,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
  KUNIT_CASE(test_long_origin_chain),
  KUNIT_CASE(test_stackdepot_roundtrip),
  KUNIT_CASE(test_unpoison_memory),
+ KUNIT_CASE(test_copy_from_kernel_nofault),
  {},
 };

diff --git a/mm/maccess.c b/mm/maccess.c
index f752f0c0fa3..a91a39a56cf 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -31,8 +31,9 @@ long copy_from_kernel_nofault(void *dst, const void
*src, size_t size)
  if (!copy_from_kernel_nofault_allowed(src, size))
  return -ERANGE;

+ /* Make sure uninitialized kernel memory isn't copied. */
+ kmsan_check_memory(src, size);
  pagefault_disable();
- instrument_read(src, size);
  if (!(align & 7))
  copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
  if (!(align & 3))
@@ -63,8 +64,8 @@ long copy_to_kernel_nofault(void *dst, const void
*src, size_t size)
  if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
  align =3D (unsigned long)dst | (unsigned long)src;

- pagefault_disable();
  instrument_write(dst, size);
+ pagefault_disable();
  if (!(align & 7))
  copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
  if (!(align & 3))
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxinN_tJ9_M3uXipwME8QA%2B1DLC9-Ps59ecSv%3D6SneOBvA%40mail.gm=
ail.com.
